//! Capture file -> Arrow record batches.
//!
//! The whole point of the project lives here: packets go in one at a time and
//! come out as columns. A query touching two fields then reads two contiguous
//! arrays instead of walking every packet in the file — which is why a 10 GB
//! capture answers in milliseconds where a row-oriented reader takes minutes.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use datafusion::arrow::array::{
    ArrayRef, Float64Builder, StringBuilder, UInt16Builder, UInt32Builder, UInt8Builder,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;

use crate::decode::{decode, PacketRow};
use crate::flows::Tracker;

/// Rows per batch. Small enough that per-batch statistics stay selective,
/// large enough that per-batch overhead stays negligible.
const BATCH_ROWS: usize = 65_536;

pub fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Float64, false),
        Field::new("src_ip", DataType::Utf8, true),
        Field::new("dst_ip", DataType::Utf8, true),
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dst_port", DataType::UInt16, true),
        Field::new("proto", DataType::Utf8, false),
        Field::new("len", DataType::UInt32, false),
        Field::new("payload_len", DataType::UInt32, false),
        Field::new("tcp_flags", DataType::Utf8, true),
        Field::new("ttl", DataType::UInt8, true),
        Field::new("app", DataType::Utf8, true),
        Field::new("host", DataType::Utf8, true),
        Field::new("info", DataType::Utf8, true),
    ]))
}

/// What each column means, for `falconet schema`.
pub const DOCS: &[(&str, &str)] = &[
    ("ts", "capture timestamp, epoch seconds"),
    ("src_ip", "source address; null for non-IP frames"),
    ("dst_ip", "destination address"),
    ("src_port", "TCP/UDP source port; null otherwise"),
    ("dst_port", "TCP/UDP destination port"),
    ("proto", "TCP | UDP | ICMP | NON-IP | OTHER"),
    ("len", "bytes on the wire"),
    ("payload_len", "transport payload bytes"),
    ("tcp_flags", "e.g. 'SYN,ACK'; null for non-TCP"),
    ("ttl", "IPv4 TTL or IPv6 hop limit"),
    ("app", "DNS | TLS | HTTP, recognised from the payload"),
    (
        "host",
        "hostname in the clear: DNS name, TLS SNI or HTTP Host",
    ),
    (
        "info",
        "one-line summary, e.g. 'Client Hello TLS 1.3 (github.com)'",
    ),
];

/// Accumulates rows and flushes fixed-size Arrow batches.
struct Batcher {
    ts: Float64Builder,
    src_ip: StringBuilder,
    dst_ip: StringBuilder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    proto: StringBuilder,
    len: UInt32Builder,
    payload_len: UInt32Builder,
    tcp_flags: StringBuilder,
    ttl: UInt8Builder,
    app: StringBuilder,
    host: StringBuilder,
    info: StringBuilder,
    rows: usize,
    out: Vec<RecordBatch>,
    /// Conversations are folded up in the same pass over the file.
    tracker: Tracker,
}

/// Both views of one capture, built together.
pub struct Capture {
    pub packets: Vec<RecordBatch>,
    pub flows: Vec<RecordBatch>,
    pub packet_count: usize,
    pub flow_count: usize,
}

impl Batcher {
    fn new() -> Self {
        Self {
            ts: Float64Builder::with_capacity(BATCH_ROWS),
            src_ip: StringBuilder::new(),
            dst_ip: StringBuilder::new(),
            src_port: UInt16Builder::with_capacity(BATCH_ROWS),
            dst_port: UInt16Builder::with_capacity(BATCH_ROWS),
            proto: StringBuilder::new(),
            len: UInt32Builder::with_capacity(BATCH_ROWS),
            payload_len: UInt32Builder::with_capacity(BATCH_ROWS),
            tcp_flags: StringBuilder::new(),
            ttl: UInt8Builder::with_capacity(BATCH_ROWS),
            app: StringBuilder::new(),
            host: StringBuilder::new(),
            info: StringBuilder::new(),
            rows: 0,
            out: Vec::new(),
            tracker: Tracker::new(),
        }
    }

    fn push(&mut self, r: PacketRow) -> Result<()> {
        self.tracker.observe(&r);
        self.ts.append_value(r.ts);
        self.src_ip.append_option(r.src_ip);
        self.dst_ip.append_option(r.dst_ip);
        self.src_port.append_option(r.src_port);
        self.dst_port.append_option(r.dst_port);
        self.proto.append_value(r.proto);
        self.len.append_value(r.len);
        self.payload_len.append_value(r.payload_len);
        self.tcp_flags.append_option(r.tcp_flags);
        self.ttl.append_option(r.ttl);
        self.app.append_option(r.app);
        self.host.append_option(r.host);
        self.info.append_option(r.info);
        self.rows += 1;

        if self.rows >= BATCH_ROWS {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.rows == 0 {
            return Ok(());
        }
        let cols: Vec<ArrayRef> = vec![
            Arc::new(self.ts.finish()),
            Arc::new(self.src_ip.finish()),
            Arc::new(self.dst_ip.finish()),
            Arc::new(self.src_port.finish()),
            Arc::new(self.dst_port.finish()),
            Arc::new(self.proto.finish()),
            Arc::new(self.len.finish()),
            Arc::new(self.payload_len.finish()),
            Arc::new(self.tcp_flags.finish()),
            Arc::new(self.ttl.finish()),
            Arc::new(self.app.finish()),
            Arc::new(self.host.finish()),
            Arc::new(self.info.finish()),
        ];
        self.out.push(RecordBatch::try_new(schema(), cols)?);
        self.rows = 0;
        Ok(())
    }

    fn finish(mut self) -> Result<Capture> {
        self.flush()?;
        let packet_count = self.out.iter().map(|b| b.num_rows()).sum();
        let flow_count = self.tracker.len();
        let flows = self.tracker.finish()?;
        Ok(Capture {
            packets: self.out,
            flows,
            packet_count,
            flow_count,
        })
    }
}

/// Read a `.pcap` or `.pcapng` file.
///
/// The format is detected from the magic bytes rather than the extension —
/// Wireshark writes `.pcapng` by default and people rename files.
pub fn read_capture(path: &Path) -> Result<Capture> {
    let mut probe = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    probe
        .read_exact(&mut magic)
        .context("file is too short to be a capture")?;
    probe.seek(SeekFrom::Start(0))?;

    let reader = BufReader::with_capacity(1 << 20, probe);
    match u32::from_be_bytes(magic) {
        0x0a0d_0d0a => read_pcapng(reader),
        0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1 => read_pcap(reader),
        other => {
            anyhow::bail!("not a capture file: magic {other:#010x} is neither pcap nor pcapng")
        }
    }
}

fn read_pcap(reader: BufReader<File>) -> Result<Capture> {
    use pcap_file::pcap::PcapReader;

    let mut rdr = PcapReader::new(reader).context("reading pcap header")?;
    let mut b = Batcher::new();
    while let Some(pkt) = rdr.next_packet() {
        let pkt = pkt.context("reading packet")?;
        b.push(decode(pkt.timestamp.as_secs_f64(), pkt.orig_len, &pkt.data))?;
    }
    b.finish()
}

fn read_pcapng(reader: BufReader<File>) -> Result<Capture> {
    use pcap_file::pcapng::{Block, PcapNgReader};

    let mut rdr = PcapNgReader::new(reader).context("reading pcapng header")?;
    let mut b = Batcher::new();
    while let Some(block) = rdr.next_block() {
        match block.context("reading block")? {
            Block::EnhancedPacket(p) => {
                b.push(decode(p.timestamp.as_secs_f64(), p.original_len, &p.data))?;
            }
            // A simple packet block carries no timestamp by design.
            Block::SimplePacket(p) => {
                b.push(decode(0.0, p.original_len, &p.data))?;
            }
            // Section headers, interface descriptions and name resolution carry
            // no packets — skipping them is correct, not a gap.
            _ => {}
        }
    }
    b.finish()
}
