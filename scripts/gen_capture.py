#!/usr/bin/env python3
"""Generate a synthetic .pcap so the decoder can be exercised without a real
capture (which cannot be committed: real traffic carries real addresses).

The payloads are the genuine wire formats — a DNS question, a TLS Client Hello
carrying SNI, an HTTP request with a Host header — because a fixture made of
random bytes proves only that the parser does not crash, never that it reads
the right field.

The traffic is also shaped to contain what `triage` will look for: connections
refused with RST, DNS answers that arrive far too late, a bulk transfer.

    python scripts/gen_capture.py test.pcap --packets 200000
"""

import argparse
import random
import struct

ETH_IPV4 = 0x0800
PROTO_TCP, PROTO_UDP = 6, 17

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

DOMAINS = [
    "example.com",
    "api.github.com",
    "cdn.jsdelivr.net",
    "gateway.discord.gg",
    "telemetry.internal.corp",
]


# ─── framing ────────────────────────────────────────────────────────────────

def eth(payload: bytes) -> bytes:
    return (b"\xaa\xbb\xcc\x00\x00\x01" + b"\xaa\xbb\xcc\x00\x00\x02"
            + struct.pack("!H", ETH_IPV4) + payload)


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), random.randint(0, 0xFFFF), 0, ttl, proto, 0,
        bytes(int(x) for x in src.split(".")),
        bytes(int(x) for x in dst.split(".")),
    )
    return hdr + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        sport, dport, random.getrandbits(32), random.getrandbits(32),
        5 << 4, flags, 64240, 0, 0,
    ) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


# ─── real application payloads ──────────────────────────────────────────────

def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"


def dns_query(name: str, qid: int, qtype: int = 1) -> bytes:
    return (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            + dns_name(name) + struct.pack("!HH", qtype, 1))


def dns_response(name: str, qid: int, qtype: int = 1, rcode: int = 0) -> bytes:
    answers = 0 if rcode else 1
    out = (struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, answers, 0, 0)
           + dns_name(name) + struct.pack("!HH", qtype, 1))
    if answers:
        # Pointer back to the question name, then an A record.
        out += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, 4) + bytes([93, 184, 216, 34])
    return out


def client_hello(sni: str) -> bytes:
    """A TLS 1.2 record carrying a Client Hello with the server_name extension."""
    name = sni.encode()
    sni_body = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    exts = struct.pack("!HH", 0x0000, len(sni_body)) + sni_body

    body = (struct.pack("!H", 0x0303)              # client version
            + bytes(32)                            # random
            + b"\x00"                              # no session id
            + struct.pack("!H", 2) + b"\x13\x01"   # one cipher suite
            + b"\x01\x00"                          # one compression method: null
            + struct.pack("!H", len(exts)) + exts)

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def http_get(host: str, path: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: falconnet-fixture/1.0\r\nAccept: */*\r\n\r\n").encode()


# ─── writer ─────────────────────────────────────────────────────────────────

class Writer:
    def __init__(self, path):
        self.f = open(path, "wb")
        # magic, v2.4, no tz correction, no sigfigs, snaplen, Ethernet
        self.f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.n = 0

    def write(self, ts: float, frame: bytes):
        sec, usec = int(ts), int((ts % 1) * 1_000_000)
        self.f.write(struct.pack("!IIII", sec, usec, len(frame), len(frame)))
        self.f.write(frame)
        self.n += 1

    def close(self):
        self.f.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--packets", type=int, default=50_000)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    random.seed(args.seed)
    w = Writer(args.out)
    ts = 1_700_000_000.0

    clients = [f"192.168.1.{i}" for i in range(10, 40)]
    servers = ["93.184.216.34", "104.18.32.7", "142.250.74.14", "10.0.4.7"]
    resolver = "192.168.1.1"

    while w.n < args.packets:
        ts += random.expovariate(2000.0)  # ~2k packets/sec
        c, s = random.choice(clients), random.choice(servers)
        sport = random.randint(49152, 65535)
        roll = random.random()

        # 10.0.4.7:5432 refuses every connection — the planted "connection refused"
        if s == "10.0.4.7":
            w.write(ts, eth(ipv4(c, s, PROTO_TCP, tcp(sport, 5432, SYN))))
            w.write(ts + 0.0004, eth(ipv4(s, c, PROTO_TCP, tcp(5432, sport, RST | ACK))))

        elif roll < 0.25:
            # DNS, with one answer in twenty arriving far too late
            name = random.choice(DOMAINS)
            qid = random.getrandbits(16)
            w.write(ts, eth(ipv4(c, resolver, PROTO_UDP,
                                 udp(sport, 53, dns_query(name, qid)))))
            slow = random.random() < 0.05
            delay = 1.4 if slow else random.uniform(0.005, 0.03)
            # telemetry.internal.corp does not resolve
            rcode = 3 if name.endswith(".corp") else 0
            w.write(ts + delay, eth(ipv4(resolver, c, PROTO_UDP,
                                         udp(53, sport, dns_response(name, qid, rcode=rcode)))))

        elif roll < 0.35:
            # Plain HTTP: handshake, request, response headers
            host = random.choice(DOMAINS)
            w.write(ts, eth(ipv4(c, s, PROTO_TCP, tcp(sport, 80, SYN))))
            w.write(ts + 0.012, eth(ipv4(s, c, PROTO_TCP, tcp(80, sport, SYN | ACK))))
            w.write(ts + 0.013, eth(ipv4(c, s, PROTO_TCP,
                                         tcp(sport, 80, PSH | ACK, http_get(host, "/index.html")))))
            w.write(ts + 0.05, eth(ipv4(s, c, PROTO_TCP, tcp(
                80, sport, PSH | ACK,
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\nhello world\n"))))

        else:
            # HTTPS: handshake, Client Hello with SNI, then bulk data
            sni = random.choice(DOMAINS)
            w.write(ts, eth(ipv4(c, s, PROTO_TCP, tcp(sport, 443, SYN))))
            w.write(ts + 0.012, eth(ipv4(s, c, PROTO_TCP, tcp(443, sport, SYN | ACK))))
            w.write(ts + 0.013, eth(ipv4(c, s, PROTO_TCP, tcp(sport, 443, ACK))))
            w.write(ts + 0.014, eth(ipv4(c, s, PROTO_TCP,
                                         tcp(sport, 443, PSH | ACK, client_hello(sni)))))
            for i in range(random.randint(2, 20)):
                body = bytes(random.getrandbits(8) for _ in range(random.randint(200, 1400)))
                w.write(ts + 0.02 + i * 0.001,
                        eth(ipv4(s, c, PROTO_TCP, tcp(443, sport, PSH | ACK, body))))
            w.write(ts + 0.2, eth(ipv4(c, s, PROTO_TCP, tcp(sport, 443, FIN | ACK))))

    w.close()
    print(f"{w.n} packets -> {args.out}")


if __name__ == "__main__":
    main()
