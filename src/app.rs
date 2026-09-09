//! Application-layer dissection: the part that turns addresses into names.
//!
//! A capture without this holds only IPs, and every interesting question —
//! "which domains cost me the most traffic", "what resolved slowly" — cannot be
//! asked at all. Three protocols carry a hostname in the clear and cover the
//! overwhelming majority of it: DNS questions, the TLS Client Hello's SNI
//! extension, and the HTTP `Host` header.
//!
//! Every parser here reads attacker-controlled bytes, so all of them are total:
//! any malformed, truncated or hostile input yields `None` rather than a panic.
//! None of them index without checking first.

/// What the payload turned out to be.
pub struct AppInfo {
    /// DNS / TLS / HTTP, or None when the payload was not recognised.
    pub app: Option<&'static str>,
    /// Hostname carried in the clear, whichever protocol carried it.
    pub host: Option<String>,
    /// One-line human summary, in the spirit of Wireshark's Info column.
    pub info: Option<String>,
}

impl AppInfo {
    const fn none() -> Self {
        Self {
            app: None,
            host: None,
            info: None,
        }
    }
}

/// A hostname longer than this is either malformed or an attack; DNS itself
/// caps names at 253 characters.
const MAX_NAME: usize = 253;

pub fn dissect(is_tcp: bool, src_port: u16, dst_port: u16, payload: &[u8]) -> AppInfo {
    if payload.is_empty() {
        return AppInfo::none();
    }
    if !is_tcp {
        if src_port == 53 || dst_port == 53 || src_port == 5353 || dst_port == 5353 {
            return dns(payload);
        }
        return AppInfo::none();
    }
    // TCP. Try TLS first: it is identified by its own bytes rather than by a
    // port, so HTTPS on a non-standard port is still recognised.
    if let Some(a) = tls(payload) {
        return a;
    }
    if let Some(a) = http(payload) {
        return a;
    }
    if src_port == 53 || dst_port == 53 {
        // DNS over TCP prefixes the message with a two-byte length.
        if payload.len() > 2 {
            return dns(&payload[2..]);
        }
    }
    AppInfo::none()
}

// ─── DNS ────────────────────────────────────────────────────────────────────

fn dns(p: &[u8]) -> AppInfo {
    if p.len() < 12 {
        return AppInfo::none();
    }
    let flags = u16::from_be_bytes([p[2], p[3]]);
    let is_response = flags & 0x8000 != 0;
    let rcode = flags & 0x000F;
    let qdcount = u16::from_be_bytes([p[4], p[5]]);
    if qdcount == 0 {
        return AppInfo {
            app: Some("DNS"),
            host: None,
            info: Some("DNS message, no question".into()),
        };
    }

    let Some((name, after)) = read_name(p, 12) else {
        return AppInfo {
            app: Some("DNS"),
            host: None,
            info: Some("DNS, unreadable question".into()),
        };
    };
    let qtype = p
        .get(after..after + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .unwrap_or(0);

    let kind = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        _ => "?",
    };
    let info = if is_response {
        match rcode {
            0 => format!("response {kind} {name}"),
            3 => format!("response NXDOMAIN {name}"),
            n => format!("response rcode {n} {name}"),
        }
    } else {
        format!("query {kind} {name}")
    };

    AppInfo {
        app: Some("DNS"),
        host: Some(name),
        info: Some(info),
    }
}

/// Read a DNS name starting at `at`. Returns the name and the offset just past
/// it. Compression pointers are followed once — enough for real messages, and
/// bounded so a pointer loop cannot hang the parser.
fn read_name(p: &[u8], at: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut i = at;
    let mut end = None;
    let mut jumps = 0;

    loop {
        let len = *p.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Pointer: two bytes, and the name continues at the target.
            let b2 = *p.get(i + 1)? as usize;
            let target = ((len & 0x3F) << 8) | b2;
            if jumps >= 1 || target >= p.len() {
                return None;
            }
            jumps += 1;
            end.get_or_insert(i + 2);
            i = target;
            continue;
        }
        let label = p.get(i + 1..i + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        if out.len() + label.len() > MAX_NAME {
            return None;
        }
        // Label bytes are not guaranteed to be UTF-8; anything that is not is
        // not a hostname worth reporting.
        out.push_str(std::str::from_utf8(label).ok()?);
        i += 1 + len;
    }

    Some((out, end.unwrap_or(i)))
}

// ─── TLS ────────────────────────────────────────────────────────────────────

/// Pull the SNI out of a Client Hello. Anything else TLS-shaped is reported
/// without a host, which is still useful: it marks the packet as TLS.
fn tls(p: &[u8]) -> Option<AppInfo> {
    // Record: content type 0x16 = handshake, then the protocol version.
    if *p.first()? != 0x16 || p.len() < 6 {
        return None;
    }
    let version = match (p.get(9)?, p.get(10)?) {
        // The handshake's own version field, which is what actually negotiates.
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2",
        (3, 4) => "TLS 1.3",
        _ => "TLS",
    };
    if *p.get(5)? != 0x01 {
        // A handshake message, but not a Client Hello.
        return Some(AppInfo {
            app: Some("TLS"),
            host: None,
            info: Some("TLS handshake".into()),
        });
    }

    let host = client_hello_sni(p);
    let info = match &host {
        Some(h) => format!("Client Hello {version} ({h})"),
        None => format!("Client Hello {version}"),
    };
    Some(AppInfo {
        app: Some("TLS"),
        host,
        info: Some(info),
    })
}

fn client_hello_sni(p: &[u8]) -> Option<String> {
    // 5 record header + 4 handshake header + 2 version + 32 random
    let mut i = 5 + 4 + 2 + 32;
    let sid_len = *p.get(i)? as usize;
    i += 1 + sid_len;

    let cs_len = be16(p, i)? as usize;
    i += 2 + cs_len;

    let comp_len = *p.get(i)? as usize;
    i += 1 + comp_len;

    let ext_total = be16(p, i)? as usize;
    i += 2;
    let end = (i + ext_total).min(p.len());

    while i + 4 <= end {
        let ext_type = be16(p, i)?;
        let ext_len = be16(p, i + 2)? as usize;
        let body = p.get(i + 4..i + 4 + ext_len)?;
        if ext_type == 0x0000 {
            // server_name: list length, then entries of (type, length, name).
            let name_type = *body.get(2)?;
            if name_type != 0 {
                return None;
            }
            let name_len = be16(body, 3)? as usize;
            if name_len > MAX_NAME {
                return None;
            }
            let name = body.get(5..5 + name_len)?;
            return std::str::from_utf8(name).ok().map(str::to_owned);
        }
        i += 4 + ext_len;
    }
    None
}

fn be16(p: &[u8], at: usize) -> Option<u16> {
    let b = p.get(at..at + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

// ─── HTTP ───────────────────────────────────────────────────────────────────

const METHODS: &[&str] = &[
    "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
];

fn http(p: &[u8]) -> Option<AppInfo> {
    // Only the head of the message is worth scanning; a body can be megabytes
    // and holds no headers.
    let head = &p[..p.len().min(2048)];
    let text = std::str::from_utf8(head).ok()?;

    if text.starts_with("HTTP/1.") {
        let line = text.lines().next()?;
        return Some(AppInfo {
            app: Some("HTTP"),
            host: None,
            info: Some(line.trim().to_string()),
        });
    }

    if !METHODS.iter().any(|m| text.starts_with(m)) {
        return None;
    }
    let request_line = text.lines().next()?.trim().to_string();
    let host = text
        .lines()
        .skip(1)
        .find_map(|l| l.strip_prefix("Host:").or_else(|| l.strip_prefix("host:")))
        .map(|h| h.trim())
        .filter(|h| !h.is_empty() && h.len() <= MAX_NAME)
        .map(str::to_owned);

    Some(AppInfo {
        app: Some("HTTP"),
        host,
        info: Some(request_line),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_question_yields_the_name() {
        // id, flags(query), qd=1, an/ns/ar=0, then 3www 7example 3com 0, A, IN
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(b"\x03www\x07example\x03com\x00");
        p.extend_from_slice(&[0, 1, 0, 1]);
        let a = dns(&p);
        assert_eq!(a.host.as_deref(), Some("www.example.com"));
        assert_eq!(a.info.as_deref(), Some("query A www.example.com"));
    }

    #[test]
    fn truncated_dns_does_not_panic() {
        for n in 0..14 {
            let p = vec![0u8; n];
            let _ = dns(&p);
        }
        // A length byte that runs off the end of the buffer.
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(&[0x40, b'a']);
        assert!(dns(&p).host.is_none());
    }

    #[test]
    fn a_dns_pointer_loop_terminates() {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(&[0xC0, 0x0C]); // points at itself
        assert!(dns(&p).host.is_none());
    }

    #[test]
    fn http_request_yields_host_and_line() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let a = http(req).unwrap();
        assert_eq!(a.host.as_deref(), Some("example.com"));
        assert_eq!(a.info.as_deref(), Some("GET /index.html HTTP/1.1"));
    }

    /// Build a Client Hello the way a real client would, so the offset maths in
    /// `client_hello_sni` is pinned against the actual wire layout.
    fn hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sni_body = Vec::new();
        sni_body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_body.push(0); // name type: host_name
        sni_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(name);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_body);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // client version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // no session id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // one compression method
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn client_hello_yields_the_sni() {
        let a = tls(&hello("api.github.com")).unwrap();
        assert_eq!(a.app, Some("TLS"));
        assert_eq!(a.host.as_deref(), Some("api.github.com"));
        assert_eq!(
            a.info.as_deref(),
            Some("Client Hello TLS 1.2 (api.github.com)")
        );
    }

    #[test]
    fn a_truncated_client_hello_does_not_panic() {
        let full = hello("example.com");
        for n in 0..full.len() {
            let _ = tls(&full[..n]);
        }
    }

    #[test]
    fn non_http_tcp_payload_is_not_claimed() {
        assert!(http(&[0u8; 40]).is_none());
        assert!(http(b"\x16\x03\x01 not http").is_none());
    }
}
