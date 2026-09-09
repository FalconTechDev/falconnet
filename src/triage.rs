//! Diagnosis instead of a wall of packets.
//!
//! Wireshark shows everything and explains nothing: to use it you must already
//! know what the problem looks like. Most people open it, see twenty thousand
//! rows, and close it again. This module encodes what an experienced pair of
//! eyes would look for, so the capture reports its own problems.
//!
//! Every rule is one SQL query producing a single `line` column. Keeping the
//! whole rule in SQL means adding one is a matter of writing a query — no Rust,
//! no new type — and that each rule can be checked by running it by hand.

use anyhow::Result;
use datafusion::arrow::array::{Array, StringArray};
use datafusion::prelude::SessionContext;

#[derive(Clone, Copy, PartialEq)]
pub enum Level {
    /// Something is broken.
    Problem,
    /// Working, but worth knowing about.
    Warning,
    /// Stated so the reader knows it was checked, not skipped.
    Ok,
}

impl Level {
    fn mark(self) -> &'static str {
        match self {
            Level::Problem => "x",
            Level::Warning => "!",
            Level::Ok => "+",
        }
    }
}

pub struct Rule {
    pub level: Level,
    /// Produces zero or more rows, each with one text column named `line`.
    pub sql: &'static str,
}

/// Ordered by how much the reader needs to know: broken first.
pub const RULES: &[Rule] = &[
    // ─── things that are broken ─────────────────────────────────────────────
    Rule {
        level: Level::Problem,
        sql: "SELECT concat(CAST(n AS VARCHAR), ' connections refused by ', server_ip, ':',
                            CAST(server_port AS VARCHAR),
                            ' — the port is closed, nothing is listening') AS line
              FROM (SELECT server_ip, server_port, COUNT(*) AS n
                    FROM flows WHERE state = 'refused'
                    GROUP BY server_ip, server_port)
              WHERE n > 0 ORDER BY n DESC LIMIT 5",
    },
    Rule {
        level: Level::Problem,
        sql: "SELECT concat(CAST(n AS VARCHAR), ' connection attempts to ', server_ip, ':',
                            CAST(server_port AS VARCHAR),
                            ' were never answered — filtered by a firewall, or the host is down') AS line
              FROM (SELECT server_ip, server_port, COUNT(*) AS n
                    FROM flows WHERE state = 'no-reply'
                    GROUP BY server_ip, server_port)
              WHERE n > 0 ORDER BY n DESC LIMIT 5",
    },
    Rule {
        level: Level::Problem,
        sql: "SELECT concat('DNS for ', host, ' returned NXDOMAIN ', CAST(n AS VARCHAR),
                            ' times — the name does not exist') AS line
              FROM (SELECT host, COUNT(*) AS n
                    FROM packets
                    WHERE info LIKE 'response NXDOMAIN%' AND host IS NOT NULL
                    GROUP BY host)
              WHERE n > 0 ORDER BY n DESC LIMIT 5",
    },
    Rule {
        level: Level::Problem,
        sql: "SELECT concat(CAST(n AS VARCHAR), ' established connections were killed by RST',
                            ' — one side hung up mid-conversation') AS line
              FROM (SELECT COUNT(*) AS n FROM flows WHERE state = 'reset')
              WHERE n > 0",
    },
    // ─── things worth knowing ───────────────────────────────────────────────
    Rule {
        level: Level::Warning,
        sql: "SELECT concat(CAST(n AS VARCHAR), ' DNS lookups took longer than 0.5 s',
                            ' (worst ', CAST(worst AS VARCHAR), ' s) — the resolver is slow') AS line
              FROM (SELECT COUNT(*) AS n, ROUND(MAX(duration), 2) AS worst
                    FROM flows
                    -- Exactly two packets means one question and one answer, so
                    -- the flow's duration IS the response time. Longer flows are
                    -- retries, or separate exchanges that reused a source port,
                    -- and their duration would overstate the delay.
                    WHERE server_port = 53 AND packets = 2 AND duration > 0.5)
              WHERE n > 0",
    },
    Rule {
        level: Level::Warning,
        sql: "SELECT concat(CAST(n AS VARCHAR), ' connections carried cleartext HTTP',
                            ' — anyone on the path can read the content') AS line
              FROM (SELECT COUNT(*) AS n FROM flows WHERE app = 'HTTP')
              WHERE n > 0",
    },
    Rule {
        level: Level::Warning,
        sql: "SELECT concat(CAST(n AS VARCHAR), ' TLS handshakes negotiated 1.0 or 1.1',
                            ' — both are deprecated') AS line
              FROM (SELECT COUNT(*) AS n FROM packets
                    WHERE info LIKE 'Client Hello TLS 1.0%'
                       OR info LIKE 'Client Hello TLS 1.1%')
              WHERE n > 0",
    },
    Rule {
        level: Level::Warning,
        sql: "SELECT concat(peer, ' accounts for ', CAST(pct AS VARCHAR),
                            '% of all traffic') AS line
              FROM (SELECT COALESCE(host, server_ip) AS peer,
                           ROUND(100.0 * SUM(bytes) / (SELECT SUM(bytes) AS total FROM flows), 1) AS pct
                    FROM flows GROUP BY COALESCE(host, server_ip))
              WHERE pct > 40 ORDER BY pct DESC LIMIT 3",
    },
    // ─── checks that passed, stated so silence is not ambiguous ─────────────
    Rule {
        level: Level::Ok,
        sql: "SELECT 'No cleartext HTTP: everything was encrypted' AS line
              FROM (SELECT COUNT(*) AS n FROM flows WHERE app = 'HTTP')
              WHERE n = 0",
    },
    Rule {
        level: Level::Ok,
        sql: "SELECT 'No refused or unanswered connections' AS line
              FROM (SELECT COUNT(*) AS n FROM flows
                    WHERE state IN ('refused', 'no-reply'))
              WHERE n = 0",
    },
];

/// Run every rule and print what it found.
pub async fn run(ctx: &SessionContext) -> Result<usize> {
    let mut findings = 0;

    for rule in RULES {
        let batches = ctx.sql(rule.sql).await?.collect().await?;
        for batch in batches {
            let Some(col) = batch.column(0).as_any().downcast_ref::<StringArray>() else {
                // A rule whose query does not produce text is a bug in the rule,
                // not in the capture — say so rather than skipping in silence.
                anyhow::bail!("a triage rule returned a non-text column");
            };
            for i in 0..col.len() {
                if col.is_null(i) {
                    continue;
                }
                println!("  {} {}", rule.level.mark(), col.value(i));
                if rule.level != Level::Ok {
                    findings += 1;
                }
            }
        }
    }

    if findings == 0 {
        println!("  + Nothing stood out.");
    }
    Ok(findings)
}
