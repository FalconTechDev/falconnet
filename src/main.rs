//! falconet — ask a packet capture a question, in SQL.
//!
//! Two tables come out of one pass over the file: `packets`, one row per frame,
//! and `flows`, one row per conversation. Wireshark shows you the first and
//! makes you assemble the second in your head.

mod app;
mod capture;
mod decode;
mod flows;
mod procs;
mod serve;
mod triage;
mod tui;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use clap::{Parser, Subcommand};
use datafusion::arrow::array::Array;
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;

#[derive(Parser)]
#[command(
    name = "falconet",
    about = "Ask a packet capture a question, in SQL",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run SQL against a capture. Tables: `packets` and `flows`.
    Query {
        /// .pcap or .pcapng file
        file: PathBuf,
        /// e.g. "SELECT host, SUM(bytes) FROM flows GROUP BY host"
        sql: String,
    },
    /// One screen of everything you always look at first.
    Stat { file: PathBuf },
    /// Diagnose the capture: what is broken, and what is worth knowing.
    Triage { file: PathBuf },
    /// Browse a capture interactively in the terminal.
    Tui { file: PathBuf },
    /// Serve the capture as a page in your browser.
    Serve {
        file: PathBuf,
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
    /// Who on this machine is connected to what, right now, by process.
    Who {
        /// Show every socket instead of one line per process.
        #[arg(long)]
        sockets: bool,
    },
    /// Print the columns a query can name.
    Schema,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Schema => {
            println!("packets — one row per frame\n");
            print_schema(&capture::schema(), capture::DOCS);
            println!("\nflows — one row per conversation\n");
            print_schema(&flows::schema(), flows::DOCS);
            Ok(())
        }
        Cmd::Query { file, sql } => {
            let (ctx, loaded) = load(&file).await?;
            let t = Instant::now();
            ctx.sql(&sql).await?.show().await?;
            eprintln!(
                "\n{} packets, {} flows, loaded in {:.0} ms · query {:.1} ms",
                loaded.packets,
                loaded.flows,
                loaded.ms,
                t.elapsed().as_secs_f64() * 1000.0
            );
            Ok(())
        }
        Cmd::Stat { file } => stat(&file).await,
        Cmd::Who { sockets } => who(sockets),
        Cmd::Serve { file, port } => {
            let (ctx, loaded) = load(&file).await?;
            let name = file
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| file.display().to_string());
            serve::run(ctx, name, loaded.packets, loaded.flows, port).await
        }
        Cmd::Tui { file } => {
            let (ctx, _) = load(&file).await?;
            tui::run(&ctx).await
        }
        Cmd::Triage { file } => {
            let (ctx, loaded) = load(&file).await?;
            println!(
                "{} packets in {} conversations, {:.1} s of traffic\n",
                loaded.packets,
                loaded.flows,
                span(&ctx).await.unwrap_or(0.0)
            );
            let found = triage::run(&ctx).await?;
            if found > 0 {
                eprintln!("\n{found} findings");
            }
            Ok(())
        }
    }
}

fn print_schema(schema: &datafusion::arrow::datatypes::SchemaRef, docs: &[(&str, &str)]) {
    for ((name, doc), f) in docs.iter().zip(schema.fields()) {
        println!("  {name:<12} {:<8} {doc}", f.data_type().to_string());
    }
}

struct Loaded {
    packets: usize,
    flows: usize,
    ms: f64,
}

/// Read a capture and register both tables.
async fn load(file: &Path) -> Result<(SessionContext, Loaded)> {
    let t = Instant::now();
    let cap = capture::read_capture(file)?;
    let loaded = Loaded {
        packets: cap.packet_count,
        flows: cap.flow_count,
        ms: t.elapsed().as_secs_f64() * 1000.0,
    };

    // Said once, on stderr, before any answer is printed. A short capture that
    // looks complete would make every count below it quietly wrong.
    if let Some(why) = &cap.truncated {
        eprintln!(
            "warning: {why}. {} packets were read; anything after the break is missing.",
            loaded.packets
        );
    }

    let ctx = SessionContext::new();
    ctx.register_table(
        "packets",
        Arc::new(MemTable::try_new(capture::schema(), vec![cap.packets])?),
    )?;
    ctx.register_table(
        "flows",
        Arc::new(MemTable::try_new(flows::schema(), vec![cap.flows])?),
    )?;
    Ok((ctx, loaded))
}

/// The live connection table, attributed to the programs that own it.
fn who(sockets: bool) -> Result<()> {
    let conns = procs::connections()?;
    if conns.is_empty() {
        println!("No connections.");
        return Ok(());
    }

    if sockets {
        println!(
            "{:<24} {:<7} {:<6} {:<22} {:<22} STATE",
            "PROCESS", "PID", "PROTO", "LOCAL", "REMOTE"
        );
        for c in conns {
            let local = format!("{}:{}", c.local_addr, c.local_port);
            let remote = if c.remote_port == 0 {
                "-".to_string()
            } else {
                format!("{}:{}", c.remote_addr, c.remote_port)
            };
            println!(
                "{:<24} {:<7} {:<6} {:<22} {:<22} {}",
                trunc(&c.process, 23),
                c.pid,
                c.proto,
                local,
                remote,
                c.state
            );
        }
        return Ok(());
    }

    println!("{:<28} {:<7} {:<8} TALKING TO", "PROCESS", "PID", "SOCKETS");
    for (name, pid, count, group) in procs::by_process(conns) {
        // Only established peers are worth listing: a listening socket has no
        // remote end, and showing 0.0.0.0 for it would be noise.
        let mut peers: Vec<String> = group
            .iter()
            .filter(|c| c.remote_port != 0 && c.state == "ESTABLISHED")
            .map(|c| format!("{}:{}", c.remote_addr, c.remote_port))
            .collect();
        peers.sort();
        peers.dedup();
        let shown = if peers.is_empty() {
            "(listening only)".to_string()
        } else {
            let extra = peers.len().saturating_sub(3);
            let mut s = peers[..peers.len().min(3)].join(", ");
            if extra > 0 {
                s.push_str(&format!(" +{extra} more"));
            }
            s
        };
        println!("{:<28} {:<7} {:<8} {}", trunc(&name, 27), pid, count, shown);
    }
    Ok(())
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

/// Length of the capture in seconds, for the triage header.
async fn span(ctx: &SessionContext) -> Option<f64> {
    let b = ctx
        .sql("SELECT MAX(ts) - MIN(ts) AS s FROM packets")
        .await
        .ok()?
        .collect()
        .await
        .ok()?;
    let arr = b
        .first()?
        .column(0)
        .as_any()
        .downcast_ref::<datafusion::arrow::array::Float64Array>()?;
    (!arr.is_null(0)).then(|| arr.value(0))
}

/// The questions everyone asks first, so nobody has to type them.
async fn stat(file: &Path) -> Result<()> {
    let (ctx, loaded) = load(file).await?;
    if loaded.packets == 0 {
        println!("Capture holds no packets.");
        return Ok(());
    }
    println!(
        "{} packets in {} conversations, loaded in {:.0} ms",
        loaded.packets, loaded.flows, loaded.ms
    );

    for (title, sql) in [
        (
            "Span and volume",
            "SELECT ROUND(MAX(ts) - MIN(ts), 3) AS seconds,
                    SUM(len)                    AS bytes,
                    ROUND(AVG(len))             AS avg_packet
             FROM packets",
        ),
        (
            "Protocols",
            "SELECT proto, COUNT(*) AS packets, SUM(len) AS bytes
             FROM packets GROUP BY proto ORDER BY packets DESC",
        ),
        (
            "Who was talked to",
            "SELECT COALESCE(host, server_ip) AS peer,
                    COUNT(*)   AS connections,
                    SUM(bytes) AS bytes
             FROM flows GROUP BY peer ORDER BY bytes DESC LIMIT 10",
        ),
        (
            "How connections ended",
            "SELECT state, COUNT(*) AS connections
             FROM flows GROUP BY state ORDER BY connections DESC",
        ),
        (
            "Refused connections",
            "SELECT server_ip, server_port, COUNT(*) AS attempts
             FROM flows WHERE state = 'refused'
             GROUP BY server_ip, server_port ORDER BY attempts DESC LIMIT 5",
        ),
    ] {
        println!("\n{title}");
        ctx.sql(sql).await?.show().await?;
    }
    Ok(())
}
