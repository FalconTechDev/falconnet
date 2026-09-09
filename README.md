<div align="center">

# falconet

**Ask a packet capture a question, in SQL — and get an answer, not twenty thousand rows.**

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust&logoColor=white)](https://rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

Wireshark shows you everything and explains nothing. To use it you must already
know what the problem looks like: most people open a capture, see a wall of
packets, and close it again. And there is one question it cannot answer at all —
*which program sent this?* — because by the time bytes reach the wire, the
process that produced them is gone from the picture.

falconet does not try to replace Wireshark's three thousand protocol dissectors.
It does the three things Wireshark is bad at:

```bash
falconet query dump.pcap "SELECT host, SUM(bytes) FROM flows GROUP BY host"
falconet triage dump.pcap     # what is broken, in words
falconet who                  # who on this machine is connected to what, by process
```

---

## Why SQL

The real questions about traffic are analytical — *who sent the most*, *what
failed*, *which lookups were slow* — and a display filter cannot aggregate.
In Wireshark, "top ten talkers with byte counts" is a menu, a dialog and a
scroll. Here it is a line you can also put in a script:

```bash
falconet query capture.pcap "
  SELECT COALESCE(host, server_ip) AS peer,
         COUNT(*) AS conns, SUM(bytes) AS bytes
  FROM flows
  GROUP BY peer ORDER BY bytes DESC LIMIT 10"
```

Packets are stored as **columns**, not rows: `ts`, `src_ip`, `len` and the rest
each live in their own contiguous array. A query touching two fields reads two
arrays instead of walking every packet in the file, which is why aggregating a
whole capture takes milliseconds. Wireshark stores packets one after another and
structurally cannot do this.

## Speed

Measured on an **Intel i7-13700H, Windows 11**, release build, against a
synthetic capture from `scripts/gen_capture.py`.

| | 1 000 006 packets · 530 MB |
|---|---|
| Parse, dissect and build both tables | **≈ 1.0 s** |
| `SELECT COUNT(*) … WHERE tcp_flags LIKE '%RST%'` | **5 ms** |
| Top hosts by bytes, `GROUP BY` over `flows` | **16 ms** |
| Top talkers by bytes, `GROUP BY` over 1 M packets | **16 ms** |
| Full `triage` — all ten rules, end to end | **1.15 s** |

The first row is the one that costs: a second to read and decode the file, and
everything after it in milliseconds. That ratio is the whole argument for the
columnar layout — once a capture is in columns, asking it another question is
nearly free, which is what makes exploring one practical rather than a chore.

These are not a comparison against Wireshark. Measuring a command-line
aggregation against a GUI's click path would flatter this tool and mean
nothing; the honest claim is the one above, in absolute terms.

## Two tables

One pass over the file produces both.

**`packets`** — one row per frame: `ts`, `src_ip`, `dst_ip`, `src_port`,
`dst_port`, `proto`, `len`, `payload_len`, `tcp_flags`, `ttl`, `app`, `host`,
`info`.

**`flows`** — one row per conversation: `client_ip`, `server_ip`, `host`, `app`,
`start`, `duration`, `packets`, `bytes`, `c2s_bytes`, `s2c_bytes`, `state`.

Conversations are what people actually think in, and assembling them by eye is
most of the work of reading a capture. Direction is taken from the handshake —
the client is whoever sent the bare SYN, not whoever appears first in the file —
and `state` says how it ended: `established`, `closed`, `reset`, `refused`,
`no-reply`, or `no-handshake` when the capture began mid-conversation.

`refused` and `no-reply` are deliberately separate. A RST means the port is
closed; silence means a firewall dropped it or the host is down. Different
findings, different fixes.

Run `falconet schema` for both tables with every column documented.

## Names, not addresses

A capture holds IP addresses, and every interesting question is about names.
falconet reads the three protocols that carry a hostname in the clear:

| | what it yields |
|---|---|
| **DNS** | queried name, record type, and `NXDOMAIN` when the name does not exist |
| **TLS** | the SNI from the Client Hello, plus the negotiated version |
| **HTTP** | the `Host` header and the request line |

So a capture reports `api.github.com` where Wireshark reports `140.82.114.25`.

## Triage

```
$ falconet triage capture.pcap
200022 packets in 22308 conversations, 12.5 s of traffic

  x 5617 connections refused by 10.0.4.7:5432 — the port is closed, nothing is listening
  x DNS for telemetry.internal.corp returned NXDOMAIN 849 times — the name does not exist
  ! 192 DNS lookups took longer than 0.5 s (worst 1.4 s) — the resolver is slow
  ! 1661 connections carried cleartext HTTP — anyone on the path can read the content
```

Every rule is **one SQL query over the two tables above**, producing one line of
prose. Adding a rule means writing a query — no new Rust, no new type — and any
rule can be checked by running it by hand. Checks that pass are also stated, so
silence is never ambiguous.

## Who is talking

```
$ falconet who
PROCESS                      PID     SOCKETS  TALKING TO
firefox.exe                  5496    4        140.82.114.25:443, 127.0.0.1:55369 +1 more
Telegram.exe                 8432    3        149.154.167.41:443, 149.154.175.50:443
zerotier-one_x64.exe         23528   16       127.0.0.1:2160, 127.0.0.1:2161
```

This is the part no packet capture can reconstruct. The socket-to-process
mapping lives in the kernel's connection table, so falconet asks the running
system for it. `--sockets` shows every socket instead of one line per program.

Because the table is a snapshot of this instant, a connection that has already
closed cannot be attributed after the fact. That is a property of the data, not
a gap in the implementation.

## Browsing

```bash
falconet tui capture.pcap
```

Two views — conversations and packets — switched with `Tab`. `/` opens a filter
that takes a SQL condition (`state = 'refused'`, `info LIKE '%NXDOMAIN%'`), so
whatever you work out while looking around pastes straight into
`falconet query`. `q` quits.

## Install

```bash
git clone https://github.com/<you>/falconet
cd falconet
cargo build --release
```

No system libraries, no SDK, no driver: reading capture files needs nothing but
Rust. `.pcap` and `.pcapng` are both read, and the format is detected from the
file's magic bytes rather than its extension, because Wireshark writes `.pcapng`
by default and people rename files.

No capture of your own? Generate one:

```bash
python scripts/gen_capture.py test.pcap --packets 200000
```

It writes genuine wire formats — a real DNS question, a real Client Hello
carrying SNI, a real HTTP request — because a fixture made of random bytes
proves only that the parser does not crash, never that it reads the right field.
The traffic is shaped to contain findings for `triage` to catch.

## Correctness

A packet decoded into the wrong column still aggregates cleanly: the counts add
up, the table renders, and every number in it is wrong. The test suite is built
around that failure mode rather than around coverage.

- **Fields are pinned against frames written byte by byte**, so a misparse fails
  in the suite instead of in a report someone trusts.
- **Direction is tested explicitly.** Swapping client and server would silently
  invert every `c2s`/`s2c` figure in the tool while everything kept running.
- **Both directions must fold into one flow**, or every connection count doubles.
- **Malformed input is fuzzed by hand**: truncated DNS at every length, a DNS
  compression-pointer loop, a Client Hello cut at every offset. Each parser reads
  attacker-controlled bytes and must return `None`, never panic.
- **The TUI's queries are planned against the real schemas** in a test, so a
  renamed column breaks the build rather than the browsing.
- **A bad filter must fail loudly.** Silently ignoring one would show unfiltered
  data to someone who believes it is filtered.

```bash
cargo test
```

## Known limits

Stated plainly, because a tool that hides these is worse than one that lacks
them.

| Limit | Consequence |
|---|---|
| The capture is held in memory | A file larger than RAM cannot be loaded yet; streaming and spill-to-disk are the next structural step |
| Flows have no idle timeout | Two exchanges that reuse a source port merge into one conversation, overstating its duration. `triage` works around this where it matters by measuring only two-packet DNS exchanges, where the duration *is* the response time |
| No live capture yet | `who` reads the connection table; capturing packets off an interface needs Npcap and is not implemented |
| Only DNS, TLS and HTTP are dissected | Anything else is visible as addresses, ports and sizes only |
| No TCP stream reassembly | A header split across segments is not seen; `payload_len` is per packet |
| IPv6 is parsed but untested against real traffic | Addresses and ports are read; extension-header chains have had no exercise |
| Retransmissions are not detected | Sequence numbers are not tracked, so `triage` cannot report packet loss |

## Roadmap

1. Live capture off an interface, joined to the process table so the live view
   names programs rather than addresses.
2. Streaming load, so capture size stops being bounded by memory.
3. Flow idle timeout, removing the port-reuse caveat above.
4. TCP reassembly, which unlocks retransmission and loss reporting.
5. A GUI.

## License

MIT
