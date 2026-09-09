//! Packet decoding: raw bytes off the wire -> one flat row of typed fields.
//!
//! Deliberately lossy. We keep the fields a question can be asked about
//! (who, where, how much, when, in what state) and drop the payload. That is
//! what lets a 10 GB capture answer a query in milliseconds instead of minutes.

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::app::{dissect, AppInfo};

/// One decoded packet, flattened. Every field here becomes a column.
#[derive(Debug, Default)]
pub struct PacketRow {
    /// Capture timestamp, epoch seconds.
    pub ts: f64,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// TCP / UDP / ICMP / ARP / OTHER
    pub proto: &'static str,
    /// Bytes on the wire (not the truncated capture length).
    pub len: u32,
    /// Transport payload size, i.e. bytes of actual data.
    pub payload_len: u32,
    /// Comma-joined TCP flags, e.g. "SYN,ACK". None for non-TCP.
    pub tcp_flags: Option<String>,
    pub ttl: Option<u8>,
    /// Application protocol recognised from the payload: DNS / TLS / HTTP.
    pub app: Option<&'static str>,
    /// Hostname the payload carried in the clear, if any.
    pub host: Option<String>,
    /// One-line summary of what this packet is saying.
    pub info: Option<String>,
}

/// What the bytes of a frame start with. A capture file declares this once,
/// and assuming Ethernet is wrong for some of the most ordinary sources there
/// are: `tcpdump -i any` writes Linux SLL, VPN and tunnel interfaces write bare
/// IP, and a loopback capture writes its own four-byte family header. Decoding
/// any of those as Ethernet does not fail — it quietly yields a capture where
/// every packet looks like a non-IP frame with no addresses at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Link {
    Ethernet,
    /// A bare IPv4 or IPv6 packet, no link header.
    RawIp,
    /// Linux "cooked" capture, 16-byte header.
    LinuxSll,
    /// Its v2 form, 20 bytes.
    LinuxSll2,
    /// BSD loopback: a 4-byte address family in host byte order.
    Null,
    /// Recognised as something we do not strip; reported rather than guessed at.
    Unsupported,
}

impl Link {
    /// The payload after the link header, or None when this frame carries no
    /// network layer we can reach.
    pub fn network<'a>(self, data: &'a [u8]) -> Option<SlicedPacket<'a>> {
        match self {
            Link::Ethernet => SlicedPacket::from_ethernet(data).ok(),
            Link::RawIp => SlicedPacket::from_ip(data).ok(),
            // The family / protocol fields in the headers below are redundant
            // here: `from_ip` reads the version nibble of the packet itself, so
            // it sorts IPv4 from IPv6 without them, and anything that is
            // neither simply fails to parse.
            Link::LinuxSll => SlicedPacket::from_ip(data.get(16..)?).ok(),
            Link::LinuxSll2 => SlicedPacket::from_ip(data.get(20..)?).ok(),
            Link::Null => SlicedPacket::from_ip(data.get(4..)?).ok(),
            Link::Unsupported => None,
        }
    }
}

/// Decode one frame. Returns a row even when upper layers fail to parse — a
/// malformed packet is still a fact about the capture, and dropping it would
/// silently skew every count.
pub fn decode(ts: f64, wire_len: u32, data: &[u8], link: Link) -> PacketRow {
    let mut row = PacketRow {
        ts,
        len: wire_len,
        proto: "OTHER",
        ..Default::default()
    };

    let Some(sliced) = link.network(data) else {
        return row;
    };

    match sliced.net {
        Some(NetSlice::Ipv4(ip)) => {
            let h = ip.header();
            row.src_ip = Some(fmt_v4(h.source()));
            row.dst_ip = Some(fmt_v4(h.destination()));
            row.ttl = Some(h.ttl());
        }
        Some(NetSlice::Ipv6(ip)) => {
            let h = ip.header();
            row.src_ip = Some(fmt_v6(h.source()));
            row.dst_ip = Some(fmt_v6(h.destination()));
            row.ttl = Some(h.hop_limit());
        }
        _ => {}
    }

    match sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            row.proto = "TCP";
            row.src_port = Some(tcp.source_port());
            row.dst_port = Some(tcp.destination_port());
            row.payload_len = tcp.payload().len() as u32;
            row.tcp_flags = Some(tcp_flags(&tcp));
            apply(
                &mut row,
                dissect(
                    true,
                    tcp.source_port(),
                    tcp.destination_port(),
                    tcp.payload(),
                ),
            );
        }
        Some(TransportSlice::Udp(udp)) => {
            row.proto = "UDP";
            row.src_port = Some(udp.source_port());
            row.dst_port = Some(udp.destination_port());
            row.payload_len = udp.payload().len() as u32;
            apply(
                &mut row,
                dissect(
                    false,
                    udp.source_port(),
                    udp.destination_port(),
                    udp.payload(),
                ),
            );
        }
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => {
            row.proto = "ICMP";
        }
        _ => {
            // No transport layer parsed. If we did not see IP either, it is
            // most likely ARP or another link-layer protocol.
            if row.src_ip.is_none() {
                row.proto = "NON-IP";
            }
        }
    }

    row
}

fn apply(row: &mut PacketRow, a: AppInfo) {
    row.app = a.app;
    row.host = a.host;
    row.info = a.info;
}

/// Flags in the order a TCP session presents them, so "SYN,ACK" reads the way
/// people say it out loud rather than in header bit order.
fn tcp_flags(tcp: &etherparse::TcpSlice<'_>) -> String {
    let mut out = String::with_capacity(16);
    let mut push = |on: bool, name: &str| {
        if on {
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(name);
        }
    };
    push(tcp.syn(), "SYN");
    push(tcp.ack(), "ACK");
    push(tcp.psh(), "PSH");
    push(tcp.fin(), "FIN");
    push(tcp.rst(), "RST");
    push(tcp.urg(), "URG");
    push(tcp.ece(), "ECE");
    push(tcp.cwr(), "CWR");
    out
}

fn fmt_v4(o: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

fn fmt_v6(o: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(o).to_string()
}
