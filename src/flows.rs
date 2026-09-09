//! Packets -> conversations.
//!
//! A capture is a list of packets, but nobody thinks in packets. People think
//! in connections: who talked to whom, for how long, how much moved, and how it
//! ended. This module folds the packet stream into that second table while the
//! file is being read, so both views come out of a single pass.
//!
//! Direction matters and the wire does not label it, so the client is taken to
//! be whichever side sent the initial SYN. When no handshake is in the capture
//! — it started mid-conversation, or it is UDP — the first packet's sender is
//! used instead, and `state` says the handshake was never seen.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use datafusion::arrow::array::{
    ArrayRef, Float64Builder, StringBuilder, UInt16Builder, UInt64Builder,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;

use crate::decode::PacketRow;

pub fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("proto", DataType::Utf8, false),
        Field::new("client_ip", DataType::Utf8, false),
        Field::new("client_port", DataType::UInt16, true),
        Field::new("server_ip", DataType::Utf8, false),
        Field::new("server_port", DataType::UInt16, true),
        Field::new("host", DataType::Utf8, true),
        Field::new("app", DataType::Utf8, true),
        Field::new("start", DataType::Float64, false),
        Field::new("end", DataType::Float64, false),
        Field::new("duration", DataType::Float64, false),
        Field::new("packets", DataType::UInt64, false),
        Field::new("bytes", DataType::UInt64, false),
        Field::new("c2s_bytes", DataType::UInt64, false),
        Field::new("s2c_bytes", DataType::UInt64, false),
        Field::new("state", DataType::Utf8, false),
    ]))
}

pub const DOCS: &[(&str, &str)] = &[
    ("proto", "TCP | UDP | ICMP"),
    ("client_ip", "side that opened the connection"),
    ("client_port", "its port"),
    ("server_ip", "side that was connected to"),
    ("server_port", "its port"),
    ("host", "hostname seen on this connection, if any"),
    ("app", "DNS | TLS | HTTP seen on this connection"),
    ("start", "timestamp of the first packet"),
    ("end", "timestamp of the last packet"),
    ("duration", "end - start, seconds"),
    ("packets", "packets in both directions"),
    ("bytes", "wire bytes in both directions"),
    ("c2s_bytes", "bytes client -> server"),
    ("s2c_bytes", "bytes server -> client"),
    (
        "state",
        "refused | no-reply | established | closed | reset | no-handshake",
    ),
];

/// Endpoints in a fixed order, so both directions land on the same flow.
#[derive(PartialEq, Eq, Hash, Clone)]
struct Key {
    proto: &'static str,
    a_ip: String,
    a_port: u16,
    b_ip: String,
    b_port: u16,
}

impl Key {
    fn new(row: &PacketRow) -> Option<Self> {
        let (src, dst) = (row.src_ip.as_ref()?, row.dst_ip.as_ref()?);
        let (sp, dp) = (row.src_port.unwrap_or(0), row.dst_port.unwrap_or(0));
        // Canonical ordering: the lexicographically smaller endpoint goes first.
        // Which one is the client is decided separately, from the handshake.
        let forward = (src.as_str(), sp) <= (dst.as_str(), dp);
        let (a_ip, a_port, b_ip, b_port) = if forward {
            (src.clone(), sp, dst.clone(), dp)
        } else {
            (dst.clone(), dp, src.clone(), sp)
        };
        Some(Key {
            proto: row.proto,
            a_ip,
            a_port,
            b_ip,
            b_port,
        })
    }
}

struct State {
    /// True when endpoint `a` of the key is the client.
    client_is_a: bool,
    client_known: bool,
    start: f64,
    end: f64,
    packets: u64,
    bytes: u64,
    c2s: u64,
    s2c: u64,
    host: Option<String>,
    app: Option<&'static str>,
    saw_syn: bool,
    saw_synack: bool,
    saw_fin: bool,
    saw_rst: bool,
}

impl State {
    fn state_name(&self) -> &'static str {
        if self.saw_rst && !self.saw_synack {
            // SYN went out, RST came back, no handshake ever completed.
            "refused"
        } else if self.saw_rst {
            "reset"
        } else if self.saw_fin {
            "closed"
        } else if self.saw_synack {
            "established"
        } else if self.saw_syn {
            // A SYN that was never answered: a filtered port or a dead host.
            // Not the same finding as a refusal, and not the same fix.
            "no-reply"
        } else {
            "no-handshake"
        }
    }
}

#[derive(Default)]
pub struct Tracker {
    flows: HashMap<Key, State>,
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Fold one packet into its conversation. Non-IP frames have no endpoints
    /// and are skipped — they belong to the packet table, not to this one.
    pub fn observe(&mut self, row: &PacketRow) {
        let Some(key) = Key::new(row) else { return };

        let flags = row.tcp_flags.as_deref().unwrap_or("");
        let syn = flags.contains("SYN");
        let ack = flags.contains("ACK");
        let src_is_a = row.src_ip.as_deref() == Some(key.a_ip.as_str())
            && row.src_port.unwrap_or(0) == key.a_port;

        let e = self.flows.entry(key).or_insert_with(|| State {
            // Provisional: the first sender is assumed to be the client until a
            // SYN says otherwise.
            client_is_a: src_is_a,
            client_known: false,
            start: row.ts,
            end: row.ts,
            packets: 0,
            bytes: 0,
            c2s: 0,
            s2c: 0,
            host: None,
            app: None,
            saw_syn: false,
            saw_synack: false,
            saw_fin: false,
            saw_rst: false,
        });

        // A bare SYN identifies the client for certain; a SYN+ACK identifies
        // the server. Either settles the direction for the whole flow.
        if syn && !ack && !e.client_known {
            e.client_is_a = src_is_a;
            e.client_known = true;
        } else if syn && ack && !e.client_known {
            e.client_is_a = !src_is_a;
            e.client_known = true;
        }

        e.saw_syn |= syn && !ack;
        e.saw_synack |= syn && ack;
        e.saw_fin |= flags.contains("FIN");
        e.saw_rst |= flags.contains("RST");

        if row.ts < e.start {
            e.start = row.ts;
        }
        if row.ts > e.end {
            e.end = row.ts;
        }
        e.packets += 1;
        e.bytes += row.len as u64;
        if src_is_a == e.client_is_a {
            e.c2s += row.len as u64;
        } else {
            e.s2c += row.len as u64;
        }

        // The first hostname seen on a connection names the whole connection:
        // a TLS session carries its SNI once, in the Client Hello.
        if e.host.is_none() {
            if let Some(h) = &row.host {
                e.host = Some(h.clone());
            }
        }
        if e.app.is_none() {
            e.app = row.app;
        }
    }

    pub fn finish(self) -> Result<Vec<RecordBatch>> {
        let n = self.flows.len();
        let mut proto = StringBuilder::new();
        let mut client_ip = StringBuilder::new();
        let mut client_port = UInt16Builder::with_capacity(n);
        let mut server_ip = StringBuilder::new();
        let mut server_port = UInt16Builder::with_capacity(n);
        let mut host = StringBuilder::new();
        let mut app = StringBuilder::new();
        let mut start = Float64Builder::with_capacity(n);
        let mut end = Float64Builder::with_capacity(n);
        let mut duration = Float64Builder::with_capacity(n);
        let mut packets = UInt64Builder::with_capacity(n);
        let mut bytes = UInt64Builder::with_capacity(n);
        let mut c2s = UInt64Builder::with_capacity(n);
        let mut s2c = UInt64Builder::with_capacity(n);
        let mut state = StringBuilder::new();

        for (k, v) in self.flows {
            let (cip, cport, sip, sport) = if v.client_is_a {
                (&k.a_ip, k.a_port, &k.b_ip, k.b_port)
            } else {
                (&k.b_ip, k.b_port, &k.a_ip, k.a_port)
            };
            proto.append_value(k.proto);
            client_ip.append_value(cip);
            server_ip.append_value(sip);
            // Port 0 is the placeholder for protocols that have none.
            if cport == 0 && sport == 0 {
                client_port.append_null();
                server_port.append_null();
            } else {
                client_port.append_value(cport);
                server_port.append_value(sport);
            }
            host.append_option(v.host.as_deref());
            app.append_option(v.app);
            start.append_value(v.start);
            end.append_value(v.end);
            duration.append_value(v.end - v.start);
            packets.append_value(v.packets);
            bytes.append_value(v.bytes);
            c2s.append_value(v.c2s);
            s2c.append_value(v.s2c);
            state.append_value(v.state_name());
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(proto.finish()),
            Arc::new(client_ip.finish()),
            Arc::new(client_port.finish()),
            Arc::new(server_ip.finish()),
            Arc::new(server_port.finish()),
            Arc::new(host.finish()),
            Arc::new(app.finish()),
            Arc::new(start.finish()),
            Arc::new(end.finish()),
            Arc::new(duration.finish()),
            Arc::new(packets.finish()),
            Arc::new(bytes.finish()),
            Arc::new(c2s.finish()),
            Arc::new(s2c.finish()),
            Arc::new(state.finish()),
        ];
        Ok(vec![RecordBatch::try_new(schema(), cols)?])
    }
}
