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

// ─── pcapng ─────────────────────────────────────────────────────────────────

/// Wireshark saves `.pcapng` by default, so this is the format most captures
/// people actually have arrive in. It shares no reader code with `.pcap`,
/// which makes it exactly the sort of path that works in theory until someone
/// opens a real file.
fn write_pcapng(path: &std::path::Path, frames: &[Vec<u8>]) {
    write_pcapng_res(path, frames, None, 1_000_000)
}

/// `tsresol` is the raw `if_tsresol` byte; `units_per_second` says how the
/// timestamps below are actually scaled, so the two can be made to agree — or
/// deliberately not.
fn write_pcapng_res(
    path: &std::path::Path,
    frames: &[Vec<u8>],
    tsresol: Option<u8>,
    units_per_second: u64,
) {
    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        // Every block is length-prefixed and length-suffixed, and the total
        // includes both of those plus the type: 12 bytes of frame.
        let total = 12 + body.len() as u32;
        let mut b = Vec::new();
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(body);
        b.extend_from_slice(&total.to_le_bytes());
        b
    }

    let mut out = Vec::new();

    // Section Header: byte-order magic, version 1.0, unspecified length.
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    out.extend_from_slice(&block(0x0A0D_0D0A, &shb));

    // Interface Description: Ethernet, 64 KiB snaplen.
    let mut idb = Vec::new();
    idb.extend_from_slice(&1u16.to_le_bytes()); // LINKTYPE_ETHERNET
    idb.extend_from_slice(&0u16.to_le_bytes()); // reserved
    idb.extend_from_slice(&65535u32.to_le_bytes());
    if let Some(r) = tsresol {
        // option 9 = if_tsresol, one byte of payload, padded to four
        idb.extend_from_slice(&9u16.to_le_bytes());
        idb.extend_from_slice(&1u16.to_le_bytes());
        idb.extend_from_slice(&[r, 0, 0, 0]);
        idb.extend_from_slice(&0u32.to_le_bytes()); // opt_endofopt
    }
    out.extend_from_slice(&block(0x0000_0001, &idb));

    for (i, f) in frames.iter().enumerate() {
        // A bare counter in the interface's own units, split across two
        // 32-bit halves. One second apart, whatever the unit is.
        let ts: u64 = 1_700_000_000 * units_per_second + i as u64 * units_per_second;
        let mut epb = Vec::new();
        epb.extend_from_slice(&0u32.to_le_bytes()); // interface 0
        epb.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(ts as u32).to_le_bytes());
        epb.extend_from_slice(&(f.len() as u32).to_le_bytes()); // captured
        epb.extend_from_slice(&(f.len() as u32).to_le_bytes()); // original
        epb.extend_from_slice(f);
        // Packet data is padded to a 4-byte boundary; the padding is not
        // counted in the captured length but is part of the block.
        while epb.len() % 4 != 0 {
            epb.push(0);
        }
        out.extend_from_slice(&block(0x0000_0006, &epb));
    }

    std::fs::write(path, out).unwrap();
}

#[test]
fn a_pcapng_file_reads_the_same_as_a_pcap() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();

    let frames = vec![
        tcp_frame([192, 168, 1, 10], [93, 184, 216, 34], 51000, 443, 0x02, &[]),
        tcp_frame([93, 184, 216, 34], [192, 168, 1, 10], 443, 51000, 0x12, &[]),
        tcp_frame(
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            51000,
            443,
            0x18,
            &[9u8; 64],
        ),
    ];

    let ng = dir.join("same.pcapng");
    write_pcapng(&ng, &frames);

    let sql = "SELECT src_ip, dst_ip, src_port, dst_port, proto, tcp_flags, payload_len
               FROM packets ORDER BY ts";
    let from_ng = query(&ng, sql);

    // The same frames through the other reader must produce the same table.
    let plain = dir.join("same.pcap");
    write_pcap(&plain, &frames);
    let from_pcap = query(&plain, sql);

    assert_eq!(
        from_ng, from_pcap,
        "the two readers disagree about identical frames"
    );
    assert!(from_ng.contains("192.168.1.10"), "{from_ng}");
    assert!(from_ng.contains("SYN,ACK"), "{from_ng}");
    assert!(from_ng.contains("64"), "payload length missing:\n{from_ng}");
}

/// Timestamps come from a different field and a different unit in pcapng, so
/// they are the most likely thing to be silently wrong.
#[test]
fn pcapng_timestamps_are_read_in_the_right_unit() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ts.pcapng");

    // Three frames one second apart.
    let frames: Vec<_> = (0..3)
        .map(|_| tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 4000, 80, 0x10, &[]))
        .collect();
    write_pcapng(&path, &frames);

    let out = query(
        &path,
        "SELECT ROUND(MAX(ts) - MIN(ts), 3) AS span, ROUND(MIN(ts), 0) AS first FROM packets",
    );
    assert!(
        out.contains("2.0") || out.contains("2 "),
        "three frames one second apart span two seconds:\n{out}"
    );
    assert!(
        out.contains("1700000000"),
        "the epoch second should survive the 64-bit split:\n{out}"
    );
}

/// pcapng stores a bare counter and lets each interface declare its unit.
/// The library underneath reads the counter but not the unit, so this is the
/// conversion falconet has to do itself — and getting it wrong scales every
/// timestamp in the file by a constant, which looks entirely plausible.
#[test]
fn every_timestamp_resolution_lands_on_the_same_instant() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();

    let frames: Vec<_> = (0..3)
        .map(|_| tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 4000, 80, 0x10, &[]))
        .collect();

    // Each pair is (if_tsresol byte, units per second it implies).
    let cases: &[(Option<u8>, u64)] = &[
        (None, 1_000_000),          // absent: the spec says microseconds
        (Some(6), 1_000_000),       // microseconds, stated
        (Some(3), 1_000),           // milliseconds
        (Some(9), 1_000_000_000),   // nanoseconds
        (Some(0x80 | 20), 1 << 20), // top bit set: a power of two
    ];

    for (resol, units) in cases {
        let path = dir.join(format!("res_{}.pcapng", units));
        write_pcapng_res(&path, &frames, *resol, *units);
        let out = query(
            &path,
            "SELECT ROUND(MIN(ts), 3) AS first, ROUND(MAX(ts) - MIN(ts), 3) AS span
             FROM packets",
        );
        assert!(
            out.contains("1700000000"),
            "resolution {resol:?}: the instant should be the same:
{out}"
        );
        assert!(
            out.contains("2.0"),
            "resolution {resol:?}: three frames one second apart span two:
{out}"
        );
    }
}

// ─── shapes that are legal but unusual ──────────────────────────────────────

/// A capture with a valid header and no packets is a normal thing to be handed
/// — a filter that matched nothing — and must not be confused with a broken
/// file, which is a different message and a different exit code.
#[test]
fn an_empty_capture_is_empty_not_broken() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();

    for (name, write) in [
        (
            "empty.pcap",
            &write_pcap as &dyn Fn(&std::path::Path, &[Vec<u8>]),
        ),
        ("empty.pcapng", &write_pcapng),
    ] {
        let path = dir.join(name);
        write(&path, &[]);

        let out = falconet().arg("stat").arg(&path).output().unwrap();
        assert!(out.status.success(), "{name} should be read, not rejected");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("no packets"), "{name}:\n{text}");

        // And a query against it must still plan and return nothing.
        let out = query(&path, "SELECT COUNT(*) AS n FROM packets");
        assert!(out.contains("| 0 "), "{name} should count zero:\n{out}");
    }
}

/// Build an Ethernet + IPv6 + TCP frame. IPv6 has a fixed 40-byte header and
/// puts the payload length in a different place than IPv4 does.
fn tcp6_frame(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&1u32.to_be_bytes());
    tcp.extend_from_slice(&2u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&64240u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0, 0, 0]);

    let mut ip = Vec::new();
    ip.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6
    ip.extend_from_slice(&(tcp.len() as u16).to_be_bytes()); // payload length
    ip.push(6); // next header: TCP
    ip.push(64); // hop limit
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(&tcp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0xaa; 6]);
    eth.extend_from_slice(&[0xbb; 6]);
    eth.extend_from_slice(&0x86DDu16.to_be_bytes()); // IPv6
    eth.extend_from_slice(&ip);
    eth
}

/// IPv6 addresses are formatted by a different path than IPv4 ones, and the
/// hop limit lands in the same column as the IPv4 TTL. Both are easy to leave
/// blank without anything failing.
#[test]
fn ipv6_packets_are_decoded_and_grouped() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v6.pcap");

    let mut client = [0u8; 16];
    client[0..2].copy_from_slice(&[0x20, 0x01]);
    client[15] = 0x10;
    let mut server = [0u8; 16];
    server[0..2].copy_from_slice(&[0x26, 0x06]);
    server[15] = 0x01;

    write_pcap(
        &path,
        &[
            tcp6_frame(client, server, 51000, 443, 0x02),
            tcp6_frame(server, client, 443, 51000, 0x12),
        ],
    );

    let out = query(
        &path,
        "SELECT src_ip, dst_ip, proto, ttl FROM packets ORDER BY ts",
    );
    assert!(out.contains("2001::10"), "IPv6 source not read:\n{out}");
    assert!(out.contains("2606::1"), "IPv6 destination not read:\n{out}");
    assert!(out.contains("TCP"), "transport not read over IPv6:\n{out}");
    assert!(
        out.contains("64"),
        "hop limit should fill the ttl column:\n{out}"
    );

    // The two directions must still fold into one conversation over IPv6.
    let out = query(&path, "SELECT client_ip, server_ip, state FROM flows");
    assert!(out.contains("established"), "handshake over IPv6:\n{out}");
    let rows = out.lines().filter(|l| l.contains("2001::10")).count();
    assert_eq!(rows, 1, "one conversation, not two:\n{out}");
}

/// Captures get cut off constantly — Ctrl+C during a capture, a full disk, a
/// file copied while it was still being written. Refusing the whole file
/// throws away every packet that did arrive; reading it silently would make
/// every count in every later answer quietly short. So: read what is there,
/// and say what was lost.
#[test]
fn a_capture_cut_mid_packet_keeps_what_it_has_and_says_so() {
    let dir = std::env::temp_dir().join("falconet_decode_test");
    std::fs::create_dir_all(&dir).unwrap();

    let frames: Vec<_> = (0..3)
        .map(|_| tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 51000, 443, 0x10, &[7u8; 200]))
        .collect();

    let whole = dir.join("whole.pcap");
    write_pcap(&whole, &frames);
    let bytes = std::fs::read(&whole).unwrap();

    let cut = dir.join("cut.pcap");
    std::fs::write(&cut, &bytes[..bytes.len() - 100]).unwrap();

    let out = falconet()
        .arg("query")
        .arg(&cut)
        .arg("SELECT COUNT(*) AS n FROM packets")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "a truncated capture is readable, not fatal"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("| 2 "),
        "the two intact packets should survive:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("warning") && stderr.contains("mid-packet"),
        "the loss must be reported:\n{stderr}"
    );
}
