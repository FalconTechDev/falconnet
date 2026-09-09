<div align="center">

# falconnet

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

falconnet does not try to replace Wireshark's three thousand protocol dissectors.
It does the three things Wireshark is bad at:

```bash
falconnet query dump.pcap "SELECT host, SUM(bytes) FROM flows GROUP BY host"
falconnet triage dump.pcap     # what is broken, in words
falconnet who                  # who on this machine is connected to what, by process

falconnet tui dump.pcap        # browse it in the terminal
falconnet serve dump.pcap      # or in a browser
```

---

## Why SQL

The real questions about traffic are analytical — *who sent the most*, *what
failed*, *which lookups were slow* — and a display filter cannot aggregate.
In Wireshark, "top ten talkers with byte counts" is a menu, a dialog and a
scroll. Here it is a line you can also put in a script:

```bash
falconnet query capture.pcap "
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

Run `falconnet schema` for both tables with every column documented.

## Names, not addresses

A capture holds IP addresses, and every interesting question is about names.
falconnet reads the three protocols that carry a hostname in the clear:

| | what it yields |
|---|---|
| **DNS** | queried name, record type, and `NXDOMAIN` when the name does not exist |
| **TLS** | the SNI from the Client Hello, plus the negotiated version |
| **HTTP** | the `Host` header and the request line |

So a capture reports `api.github.com` where Wireshark reports `140.82.114.25`.

## Triage

```
$ falconnet triage capture.pcap
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
$ falconnet who
PROCESS                      PID     SOCKETS  TALKING TO
firefox.exe                  5496    4        140.82.114.25:443, 127.0.0.1:55369 +1 more
Telegram.exe                 8432    3        149.154.167.41:443, 149.154.175.50:443
zerotier-one_x64.exe         23528   16       127.0.0.1:2160, 127.0.0.1:2161
```

This is the part no packet capture can reconstruct. The socket-to-process
mapping lives in the kernel's connection table, so falconnet asks the running
system for it. `--sockets` shows every socket instead of one line per program.

Because the table is a snapshot of this instant, a connection that has already
closed cannot be attributed after the fact. That is a property of the data, not
a gap in the implementation.

## Browsing

```bash
falconnet tui capture.pcap
```

```
 falconnet  conversations   1 / 22308
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ client                server                host                  app   pkts      bytes      secs state       │
│▌192.168.1.12:51000    140.82.114.25:443     api.github.com        TLS    1843   13.5 MB     2.117 closed      │
│ 192.168.1.12:51204    10.0.4.7:5432                                          2     108 B     0.000 refused     │
│ 192.168.1.12:51301    93.184.216.34:80      example.com           HTTP     18     9.0 KB     0.204 closed      │
│ 192.168.1.31:52880    10.0.9.2:8080                                          1      60 B     0.000 no-reply    │
│ 192.168.1.12:51410    162.159.130.234:443   gateway.discord.gg    TLS     402   800.9 KB    31.900 established │
└──────────────────────────────────────────────────────────────────────────────────────────┘
┌filter — press / to edit──────────────────────────────────────────────────────────────────┐
│state = 'refused'   ·   bytes > 100000   ·   host LIKE '%github%'                          │
└──────────────────────────────────────────────────────────────────────────────────────────┘
 Tab switch view   / filter   j k ↑ ↓ move   g G top bottom   q quit
```

Two views — conversations and packets — switched with `Tab`. `/` opens a filter
that takes a SQL condition, so whatever you work out while looking around pastes
straight into `falconnet query`. `q` quits.

The screen does what reading it would otherwise cost you: columns are sized to
what they hold rather than split evenly, byte counts are scaled so they can be
compared at a glance, timestamps are wall-clock, and `state` is coloured —
`refused` red, `no-reply` yellow, `established` green — because that one field
is what the eye is looking for. `HTTP` is coloured too, since cleartext is worth
noticing.

That frame is not a mock-up: the layout is rendered to a text buffer in a test,
so it is checked on every run — headings present, no column truncated away, no
line spilling past the terminal width.

## In a browser

```bash
falconnet serve capture.pcap        # http://127.0.0.1:8080
```

The same two tables and the same rules, as a page: the diagnosis at the top, a
SQL box under it, results below. There is no build step, no `npm install` and no
bundled runtime — the page is compiled into the binary. One executable and a
port is the whole deployment, which also means a machine where installing
Wireshark is not an option can still read the capture.

## Install

```bash
git clone https://github.com/<you>/falconnet
cd falconnet
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

Two bugs were found by writing those tests rather than by using the tool, which
is the point of them:

**pcapng timestamps were wrong by a factor of a thousand.** A pcapng timestamp
is a bare counter whose unit each interface declares in `if_tsresol`; the
`pcap-file` crate hands back the raw counter inside a `Duration` built with
`from_nanos` and never reads the option, so every capture Wireshark writes —
Wireshark uses microseconds — arrived scaled by 1000. Nothing looked broken:
the packets were all there, in the right order, with plausible times. falconnet
now reads `if_tsresol` itself, including its power-of-two form, and a test pins
five resolutions to the same instant.

**Every capture that was not Ethernet decoded to nothing.** A capture file
declares its link-layer type and this read none of it, framing every frame as
Ethernet. `tcpdump -i any` writes Linux SLL; tunnels and VPN interfaces write
bare IP; loopback writes a four-byte address family. All of them produced a
table where every packet was a non-IP frame with no addresses — which reads
exactly like a capture that held nothing worth seeing. Ethernet, raw IP, Linux
SLL and SLL2, and loopback are now stripped according to what the file says,
per interface in pcapng, and a framing this build does not know is named on
stderr rather than passed off as empty.

**A capture cut off mid-packet was rejected whole.** Captures get truncated
constantly — Ctrl+C, a full disk, a file copied while still being written — and
throwing away every packet that did arrive is the wrong answer. So is reading
it silently, which would make every count quietly short. It now reads what is
there and says on stderr what was lost.

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
| Timestamps are `f64` seconds | At present-day epoch values that leaves about a quarter-microsecond of resolution, so nanosecond captures lose their last digits |
| Five link-layer types are handled | Ethernet, raw IP, Linux SLL and SLL2, loopback. Anything else is read but reports no addresses, and says so |
| Only DNS, TLS and HTTP are dissected | Anything else is visible as addresses, ports and sizes only |
| No TCP stream reassembly | A header split across segments is not seen; `payload_len` is per packet |
| IPv6 is parsed but untested against real traffic | Addresses and ports are read; extension-header chains have had no exercise |
| Retransmissions are not detected | Sequence numbers are not tracked, so `triage` cannot report packet loss |

## Roadmap

1. Live capture off an interface, joined to the process table so the live view
   names programs rather than addresses. This is the one piece that needs a
   system dependency — Npcap on Windows, libpcap elsewhere — which is why it is
   not in the tree yet: everything above builds with nothing but Rust.
2. Streaming load, so capture size stops being bounded by memory.
3. Flow idle timeout, removing the port-reuse caveat above.
4. TCP reassembly, which unlocks retransmission and loss reporting.
5. A desktop window. `serve` already renders the whole interface, so this is a
   wrapper around it rather than a second UI to maintain.

## License

MIT
