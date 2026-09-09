//! One packet, taken apart field by field.
//!
//! The columnar tables answer questions about a capture; this answers the other
//! question — "what is actually in this packet" — and it is the one thing a
//! person reaches for Wireshark to do. It runs on a single packet fetched back
//! from the file on demand, so nothing here costs anything until it is asked
//! for.

use etherparse::{NetSlice, TransportSlice};

use crate::app::dissect as app_layer;
use crate::decode::Link;

/// One line of the tree. `depth` is nesting, not indentation in characters, so
/// the renderer decides how wide a level is.
pub struct Field {
    pub depth: u8,
    pub label: String,
    pub value: String,
}

fn f(depth: u8, label: &str, value: impl Into<String>) -> Field {
    Field {
        depth,
        label: label.to_string(),
        value: value.into(),
    }
}

/// Take a frame apart. Layers that fail to parse stop the walk and say so
/// rather than being skipped: "we could not read this" is information, and
/// silently showing fewer rows is not.
pub fn tree(data: &[u8], link: Link) -> Vec<Field> {
    let mut out = Vec::new();
    out.push(f(0, "Frame", format!("{} bytes captured", data.len())));

    match link {
        Link::Ethernet => ethernet(data, &mut out),
        Link::RawIp => out.push(f(0, "Raw IP", "no link-layer header")),
        Link::LinuxSll => out.push(f(0, "Linux cooked", "16-byte header")),
        Link::LinuxSll2 => out.push(f(0, "Linux cooked v2", "20-byte header")),
        Link::Null => out.push(f(0, "Loopback", "4-byte address family")),
        Link::Unsupported => {
            out.push(f(
                0,
                "Link",
                "framing not recognised — nothing below is readable",
            ));
            return out;
        }
    }

    let Some(sliced) = link.network(data) else {
        out.push(f(0, "Network", "no IP header could be read"));
        return out;
    };

    let mut is_tcp = false;
    match &sliced.net {
        Some(NetSlice::Ipv4(ip)) => {
            let h = ip.header();
            out.push(f(
                0,
                "IPv4",
                format!("{} → {}", fmt4(h.source()), fmt4(h.destination())),
            ));
            out.push(f(1, "version", "4"));
            out.push(f(1, "header length", format!("{} bytes", h.ihl() * 4)));
            out.push(f(1, "total length", format!("{} bytes", h.total_len())));
            out.push(f(
                1,
                "identification",
                format!("0x{:04x}", h.identification()),
            ));
            let mut flags = Vec::new();
            if h.dont_fragment() {
                flags.push("don't fragment");
            }
            if h.more_fragments() {
                flags.push("more fragments");
            }
            out.push(f(
                1,
                "flags",
                if flags.is_empty() {
                    "none".to_string()
                } else {
                    flags.join(", ")
                },
            ));
            out.push(f(
                1,
                "fragment offset",
                h.fragments_offset().value().to_string(),
            ));
            out.push(f(1, "time to live", h.ttl().to_string()));
            out.push(f(1, "protocol", format!("{}", h.protocol().0)));
            out.push(f(
                1,
                "header checksum",
                format!("0x{:04x}", h.header_checksum()),
            ));
        }
        Some(NetSlice::Ipv6(ip)) => {
            let h = ip.header();
            out.push(f(
                0,
                "IPv6",
                format!("{} → {}", fmt6(h.source()), fmt6(h.destination())),
            ));
            out.push(f(1, "version", "6"));
            out.push(f(1, "traffic class", h.traffic_class().to_string()));
            out.push(f(
                1,
                "flow label",
                format!("0x{:05x}", h.flow_label().value()),
            ));
            out.push(f(
                1,
                "payload length",
                format!("{} bytes", h.payload_length()),
            ));
            out.push(f(1, "next header", format!("{}", h.next_header().0)));
            out.push(f(1, "hop limit", h.hop_limit().to_string()));
        }
        _ => out.push(f(0, "Network", "not IP")),
    }

    let mut payload: &[u8] = &[];
    let (mut sport, mut dport) = (0u16, 0u16);
    match &sliced.transport {
        Some(TransportSlice::Tcp(t)) => {
            is_tcp = true;
            sport = t.source_port();
            dport = t.destination_port();
            payload = t.payload();
            out.push(f(0, "TCP", format!("{sport} → {dport}")));
            out.push(f(1, "sequence", t.sequence_number().to_string()));
            out.push(f(
                1,
                "acknowledgement",
                t.acknowledgment_number().to_string(),
            ));
            out.push(f(
                1,
                "header length",
                format!("{} bytes", t.data_offset() * 4),
            ));
            out.push(f(1, "flags", tcp_flags(t)));
            out.push(f(1, "window", t.window_size().to_string()));
            out.push(f(1, "checksum", format!("0x{:04x}", t.checksum())));
            out.push(f(1, "payload", format!("{} bytes", payload.len())));
        }
        Some(TransportSlice::Udp(u)) => {
            sport = u.source_port();
            dport = u.destination_port();
            payload = u.payload();
            out.push(f(0, "UDP", format!("{sport} → {dport}")));
            out.push(f(1, "length", format!("{} bytes", u.length())));
            out.push(f(1, "checksum", format!("0x{:04x}", u.checksum())));
            out.push(f(1, "payload", format!("{} bytes", payload.len())));
        }
        Some(TransportSlice::Icmpv4(i)) => {
            out.push(f(0, "ICMPv4", format!("{:?}", i.icmp_type())));
        }
        Some(TransportSlice::Icmpv6(i)) => {
            out.push(f(0, "ICMPv6", format!("{:?}", i.icmp_type())));
        }
        _ => {}
    }

    // The application layer is read by the same code the columns use, so the
    // detail view and the `info` column can never disagree about a packet.
    let a = app_layer(is_tcp, sport, dport, payload);
    if let Some(name) = a.app {
        out.push(f(
            0,
            name,
            a.info.clone().unwrap_or_else(|| "recognised".into()),
        ));
        if let Some(h) = a.host {
            out.push(f(1, "host", h));
        }
    }

    out
}

fn tcp_flags(t: &etherparse::TcpSlice<'_>) -> String {
    let mut v = Vec::new();
    for (on, name) in [
        (t.syn(), "SYN"),
        (t.ack(), "ACK"),
        (t.psh(), "PSH"),
        (t.fin(), "FIN"),
        (t.rst(), "RST"),
        (t.urg(), "URG"),
        (t.ece(), "ECE"),
        (t.cwr(), "CWR"),
    ] {
        if on {
            v.push(name);
        }
    }
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

fn ethernet(data: &[u8], out: &mut Vec<Field>) {
    if data.len() < 14 {
        out.push(f(0, "Ethernet", "truncated before the header ends"));
        return;
    }
    let mac = |b: &[u8]| {
        b.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    out.push(f(
        0,
        "Ethernet",
        format!("{} → {}", mac(&data[6..12]), mac(&data[0..6])),
    ));
    out.push(f(1, "destination", mac(&data[0..6])));
    out.push(f(1, "source", mac(&data[6..12])));
    out.push(f(
        1,
        "ethertype",
        match ethertype {
            0x0800 => "0x0800 IPv4".to_string(),
            0x86DD => "0x86DD IPv6".to_string(),
            0x0806 => "0x0806 ARP".to_string(),
            0x8100 => "0x8100 VLAN".to_string(),
            other => format!("0x{other:04x}"),
        },
    ));
}

fn fmt4(o: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

fn fmt6(o: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(o).to_string()
}

/// Sixteen bytes a line, offset on the left, printable characters on the right.
/// The layout is the one every tool uses, because it is the one people can read
/// without being taught it.
pub fn hex_dump(data: &[u8], max_bytes: usize) -> Vec<String> {
    let shown = &data[..data.len().min(max_bytes)];
    let mut lines = Vec::new();
    for (i, chunk) in shown.chunks(16).enumerate() {
        let mut hex = String::with_capacity(50);
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
        }
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        lines.push(format!("{:04x}  {:<49} {}", i * 16, hex, ascii));
    }
    if data.len() > shown.len() {
        lines.push(format!("      … {} more bytes", data.len() - shown.len()));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet + IPv4 + TCP with values chosen so a misread shows up as a
    /// wrong number rather than a missing line.
    fn frame() -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&51000u16.to_be_bytes());
        tcp.extend_from_slice(&443u16.to_be_bytes());
        tcp.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // seq
        tcp.extend_from_slice(&0x0000_0009u32.to_be_bytes()); // ack
        tcp.push(5 << 4);
        tcp.push(0x18); // PSH + ACK
        tcp.extend_from_slice(&64240u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(b"hello");

        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&0xbeefu16.to_be_bytes()); // identification
        ip.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
        ip.push(64); // ttl
        ip.push(6); // TCP
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(&[192, 168, 1, 10]);
        ip.extend_from_slice(&[93, 184, 216, 34]);
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0x11; 6];
        eth.extend_from_slice(&[0x22; 6]);
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    fn find<'a>(fields: &'a [Field], label: &str) -> Option<&'a str> {
        fields
            .iter()
            .find(|f| f.label == label)
            .map(|f| f.value.as_str())
    }

    #[test]
    fn every_layer_is_taken_apart() {
        let t = tree(&frame(), Link::Ethernet);

        assert_eq!(find(&t, "destination"), Some("11:11:11:11:11:11"));
        assert_eq!(find(&t, "source"), Some("22:22:22:22:22:22"));
        assert_eq!(find(&t, "ethertype"), Some("0x0800 IPv4"));
        assert_eq!(find(&t, "time to live"), Some("64"));
        assert_eq!(find(&t, "identification"), Some("0xbeef"));
        assert_eq!(find(&t, "flags"), Some("don't fragment"));
        assert_eq!(find(&t, "sequence"), Some("305419896")); // 0x12345678
        assert_eq!(find(&t, "window"), Some("64240"));
        assert_eq!(find(&t, "payload"), Some("5 bytes"));

        // Flags are listed in a fixed order — SYN, ACK, PSH, … — the same one
        // the `tcp_flags` column uses, so the two never read differently.
        assert!(
            t.iter().any(|f| f.value == "ACK, PSH"),
            "TCP flags missing: {:?}",
            t.iter().map(|f| (&f.label, &f.value)).collect::<Vec<_>>()
        );
    }

    /// A frame this build cannot frame must say so instead of listing a
    /// plausible-looking tree read out of the wrong offsets.
    #[test]
    fn an_unreadable_framing_is_admitted() {
        let t = tree(&frame(), Link::Unsupported);
        assert!(t.iter().any(|f| f.value.contains("not recognised")));
        assert_eq!(t.len(), 2, "nothing should be invented below it");
    }

    #[test]
    fn a_truncated_frame_does_not_panic() {
        let full = frame();
        for n in 0..full.len() {
            let _ = tree(&full[..n], Link::Ethernet);
            let _ = hex_dump(&full[..n], 64);
        }
    }

    #[test]
    fn the_hex_dump_reads_the_way_every_tool_writes_it() {
        let lines = hex_dump(b"ABCDEFGHIJKLMNOP\x00\x01", 64);
        assert!(lines[0].starts_with("0000  41 42 43 44 45 46 47 48  49 4a"));
        assert!(lines[0].ends_with("ABCDEFGHIJKLMNOP"));
        assert!(lines[1].starts_with("0010  00 01"));
        // Unprintable bytes become dots, never blanks that hide their width.
        assert!(lines[1].ends_with(".."));
    }

    #[test]
    fn the_dump_is_capped_and_says_how_much_it_left() {
        let lines = hex_dump(&[0u8; 100], 32);
        assert_eq!(lines.len(), 3, "two rows of sixteen plus the note");
        assert!(lines[2].contains("68 more bytes"));
    }
}
