//! Decoder correctness.
//!
//! A packet decoded into the wrong columns still aggregates cleanly: the counts
//! add up, the table renders, and every number in it is wrong. These tests pin
//! the fields against frames whose bytes are written out by hand, so a silent
//! misparse fails here instead of in a report someone trusts.

use std::process::Command;

/// Build a raw Ethernet + IPv4 + TCP frame with known values.
fn tcp_frame(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&1u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&2u32.to_be_bytes()); // ack
    tcp.push(5 << 4); // data offset, 5 words, no options
    tcp.push(flags);
    tcp.extend_from_slice(&64240u16.to_be_bytes()); // window
    tcp.extend_from_slice(&[0, 0, 0, 0]); // checksum + urgent
    tcp.extend_from_slice(payload);

    let total = 20 + tcp.len();
    let mut ip = Vec::new();
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0]); // id, flags/frag
    ip.push(64); // ttl
    ip.push(6); // TCP
    ip.extend_from_slice(&[0, 0]); // checksum
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(&tcp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0xaa; 6]);
    eth.extend_from_slice(&[0xbb; 6]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

/// Write a minimal pcap holding the given frames.
fn write_pcap(path: &std::path::Path, frames: &[Vec<u8>]) {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_be_bytes());
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&65535u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes()); // Ethernet
    for (i, f) in frames.iter().enumerate() {
        out.extend_from_slice(&(1_700_000_000u32 + i as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    std::fs::write(path, out).unwrap();
}

fn falconet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_falconet"))
}

fn query(path: &std::path::Path, sql: &str) -> String {
    let out = falconet().arg("query").arg(path).arg(sql).output().unwrap();
    assert!(
        out.status.success(),
        "query failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn fields_land_in_the_right_columns() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fields.pcap");

    // SYN, then SYN+ACK back, then a push with 100 bytes of payload.
    write_pcap(
        &path,
        &[
            tcp_frame([192, 168, 1, 10], [93, 184, 216, 34], 51000, 443, 0x02, &[]),
            tcp_frame([93, 184, 216, 34], [192, 168, 1, 10], 443, 51000, 0x12, &[]),
            tcp_frame(
                [192, 168, 1, 10],
                [93, 184, 216, 34],
                51000,
                443,
                0x18,
                &[7u8; 100],
            ),
        ],
    );

    let out = query(
        &path,
        "SELECT src_ip, dst_ip, src_port, dst_port, proto, tcp_flags, payload_len, ttl
         FROM packets ORDER BY ts, src_port",
    );

    assert!(
        out.contains("192.168.1.10"),
        "source address missing:\n{out}"
    );
    assert!(
        out.contains("93.184.216.34"),
        "destination address missing:\n{out}"
    );
    assert!(out.contains("51000"), "source port missing:\n{out}");
    assert!(out.contains("443"), "destination port missing:\n{out}");
    assert!(out.contains("TCP"), "protocol missing:\n{out}");
    assert!(out.contains("SYN,ACK"), "SYN+ACK not spelled out:\n{out}");
    assert!(out.contains("100"), "payload length missing:\n{out}");
    assert!(out.contains("64"), "ttl missing:\n{out}");
}

#[test]
fn every_packet_is_counted() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("count.pcap");

    // Deliberately more than one batch would hold if BATCH_ROWS were tiny, and
    // an odd number so an off-by-one in the flush shows up.
    let frames: Vec<_> = (0..1001)
        .map(|i| {
            tcp_frame(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                1000 + (i % 7) as u16,
                80,
                0x10,
                &[],
            )
        })
        .collect();
    write_pcap(&path, &frames);

    let out = query(&path, "SELECT COUNT(*) AS n FROM packets");
    assert!(out.contains("1001"), "expected 1001 packets:\n{out}");
}

#[test]
fn a_truncated_file_is_an_error_not_an_empty_table() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("garbage.pcap");
    std::fs::write(&path, b"this is not a capture at all").unwrap();

    let out = falconet().arg("stat").arg(&path).output().unwrap();
    assert!(!out.status.success(), "garbage input should fail loudly");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("neither pcap nor pcapng"),
        "error should name the problem:\n{err}"
    );
}

// ─── flows ──────────────────────────────────────────────────────────────────

/// The wire does not label direction, so it is inferred from the handshake.
/// Getting this backwards silently swaps every c2s/s2c figure in a report.
#[test]
fn the_client_is_whoever_sent_the_syn() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("direction.pcap");

    // The server speaks first in the file order, but the client is the side
    // whose packet carries a bare SYN.
    write_pcap(
        &path,
        &[
            tcp_frame([10, 0, 0, 9], [10, 0, 0, 1], 443, 51000, 0x10, &[1u8; 50]),
            tcp_frame([10, 0, 0, 1], [10, 0, 0, 9], 51000, 443, 0x02, &[]),
            tcp_frame([10, 0, 0, 9], [10, 0, 0, 1], 443, 51000, 0x12, &[]),
        ],
    );

    let out = query(
        &path,
        "SELECT client_ip, client_port, server_ip, server_port, state FROM flows",
    );
    let line = out
        .lines()
        .find(|l| l.contains("10.0.0.1"))
        .unwrap_or_else(|| panic!("no flow row:\n{out}"));
    let client = line.find("10.0.0.1").unwrap();
    let server = line.find("10.0.0.9").unwrap();
    assert!(client < server, "the SYN sender must be the client:\n{out}");
    assert!(out.contains("established"), "handshake completed:\n{out}");
}

#[test]
fn a_syn_answered_by_rst_is_refused() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("refused.pcap");

    write_pcap(
        &path,
        &[
            tcp_frame([10, 0, 0, 1], [10, 0, 4, 7], 51000, 5432, 0x02, &[]),
            tcp_frame([10, 0, 4, 7], [10, 0, 0, 1], 5432, 51000, 0x14, &[]),
        ],
    );

    let out = query(&path, "SELECT server_ip, server_port, state FROM flows");
    assert!(out.contains("refused"), "expected a refused flow:\n{out}");
    assert!(
        out.contains("5432"),
        "server port should be reported:\n{out}"
    );
}

/// Both directions of one conversation must fold into a single row, or every
/// connection count in the tool doubles.
#[test]
fn both_directions_are_one_flow() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("onedir.pcap");

    let frames: Vec<_> = (0..20)
        .map(|i| {
            if i % 2 == 0 {
                tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 51000, 443, 0x10, &[0u8; 10])
            } else {
                tcp_frame([10, 0, 0, 2], [10, 0, 0, 1], 443, 51000, 0x10, &[0u8; 10])
            }
        })
        .collect();
    write_pcap(&path, &frames);

    let out = query(&path, "SELECT COUNT(*) AS flows FROM flows");
    let n: Vec<&str> = out.lines().filter(|l| l.contains('|')).collect();
    assert!(
        out.contains("| 1 "),
        "20 packets between two endpoints are one conversation, got:\n{out}\n{n:?}"
    );
}

// ─── triage ─────────────────────────────────────────────────────────────────

/// A rule that finds nothing must stay silent, and a rule that finds something
/// must name it. Both halves matter: a diagnosis that fires on every capture is
/// noise, and one that never fires is decoration.
#[test]
fn triage_reports_a_refusal_and_stays_quiet_otherwise() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();

    let refused = dir.join("triage_refused.pcap");
    write_pcap(
        &refused,
        &[
            tcp_frame([10, 0, 0, 1], [10, 0, 4, 7], 51000, 5432, 0x02, &[]),
            tcp_frame([10, 0, 4, 7], [10, 0, 0, 1], 5432, 51000, 0x14, &[]),
        ],
    );
    let out = falconet().arg("triage").arg(&refused).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("refused by 10.0.4.7:5432"),
        "the refusal should be named:\n{text}"
    );

    let clean = dir.join("triage_clean.pcap");
    write_pcap(
        &clean,
        &[
            tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 51000, 443, 0x02, &[]),
            tcp_frame([10, 0, 0, 2], [10, 0, 0, 1], 443, 51000, 0x12, &[]),
            tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 51000, 443, 0x11, &[]),
        ],
    );
    let out = falconet().arg("triage").arg(&clean).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains(" x "),
        "a healthy capture should raise no problems:\n{text}"
    );
    assert!(
        text.contains("No refused or unanswered connections"),
        "checks that passed should be stated:\n{text}"
    );
}
