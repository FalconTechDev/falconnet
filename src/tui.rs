//! A terminal browser over a capture.
//!
//! The SQL commands answer questions you already know how to ask. This is for
//! the other half of the job: looking around. Two views — conversations and
//! packets — with a filter box that takes a SQL condition, so what you learn
//! here transfers straight into `falconnet query`.
//!
//! The layout does the reading for you where it can: columns are sized to what
//! they hold rather than split evenly, byte counts are scaled to something a
//! person can compare at a glance, and the one field that says whether a
//! connection worked is coloured so the eye finds it without being told.

use std::io;
use std::time::Duration;

use anyhow::Result;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::display::{ArrayFormatter, FormatOptions};
use datafusion::prelude::SessionContext;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
    TableState,
};

/// Rows pulled into memory for browsing. The point of the tool is that a
/// capture can be far larger than what fits on a screen or in a string table,
/// so the view is capped and says so rather than trying to hold everything.
const MAX_ROWS: usize = 50_000;

/// How a cell should be rendered. The query returns raw values — a byte count
/// is a number, a timestamp is epoch seconds — because those are what a person
/// would go on to write in `falconnet query`. Presentation happens here.
#[derive(Clone, Copy)]
enum Fmt {
    Text,
    /// Right-aligned, thousands separated.
    Num,
    /// Right-aligned, scaled to KB/MB/GB.
    Bytes,
    /// Epoch seconds shown as a wall clock.
    Clock,
    /// Coloured by whether the connection worked.
    State,
    Proto,
}

struct Col {
    title: &'static str,
    width: Constraint,
    fmt: Fmt,
}

#[derive(Clone, Copy, PartialEq)]
enum View {
    Flows,
    Packets,
}

impl View {
    fn title(self) -> &'static str {
        match self {
            View::Flows => "conversations",
            View::Packets => "packets",
        }
    }

    /// Column widths are chosen for what each field actually holds: an address
    /// with a port needs 21 characters and never more, a state name 12, and
    /// everything left over goes to the hostname, which is the field with
    /// something to say.
    fn columns(self) -> &'static [Col] {
        match self {
            View::Flows => &[
                Col {
                    title: "client",
                    width: Constraint::Length(21),
                    fmt: Fmt::Text,
                },
                Col {
                    title: "server",
                    width: Constraint::Length(21),
                    fmt: Fmt::Text,
                },
                Col {
                    title: "host",
                    width: Constraint::Min(16),
                    fmt: Fmt::Text,
                },
                Col {
                    title: "app",
                    width: Constraint::Length(5),
                    fmt: Fmt::Proto,
                },
                Col {
                    title: "pkts",
                    width: Constraint::Length(8),
                    fmt: Fmt::Num,
                },
                Col {
                    title: "bytes",
                    width: Constraint::Length(10),
                    fmt: Fmt::Bytes,
                },
                Col {
                    title: "secs",
                    width: Constraint::Length(9),
                    fmt: Fmt::Num,
                },
                Col {
                    title: "state",
                    width: Constraint::Length(13),
                    fmt: Fmt::State,
                },
            ],
            View::Packets => &[
                Col {
                    title: "time",
                    width: Constraint::Length(13),
                    fmt: Fmt::Clock,
                },
                Col {
                    title: "source",
                    width: Constraint::Length(21),
                    fmt: Fmt::Text,
                },
                Col {
                    title: "destination",
                    width: Constraint::Length(21),
                    fmt: Fmt::Text,
                },
                Col {
                    title: "proto",
                    width: Constraint::Length(7),
                    fmt: Fmt::Proto,
                },
                Col {
                    title: "len",
                    width: Constraint::Length(7),
                    fmt: Fmt::Num,
                },
                Col {
                    title: "flags",
                    width: Constraint::Length(13),
                    fmt: Fmt::Text,
                },
                Col {
                    title: "info",
                    width: Constraint::Min(20),
                    fmt: Fmt::Text,
                },
            ],
        }
    }

    fn sql(self, filter: &str) -> String {
        let where_clause = if filter.trim().is_empty() {
            String::new()
        } else {
            format!("WHERE {filter} ")
        };
        match self {
            // Address and port are joined here rather than shown apart: it is
            // one identity, and splitting it wastes a column on four digits.
            View::Flows => format!(
                "SELECT concat(client_ip, ':', COALESCE(CAST(client_port AS VARCHAR), '-')) AS client,
                        concat(server_ip, ':', COALESCE(CAST(server_port AS VARCHAR), '-')) AS server,
                        COALESCE(host, '') AS host, COALESCE(app, '') AS app,
                        packets, bytes, ROUND(duration, 3) AS secs, state
                 FROM flows {where_clause}ORDER BY bytes DESC LIMIT {MAX_ROWS}"
            ),
            View::Packets => format!(
                "SELECT ts,
                        concat(COALESCE(src_ip, '?'), ':', COALESCE(CAST(src_port AS VARCHAR), '-')) AS source,
                        concat(COALESCE(dst_ip, '?'), ':', COALESCE(CAST(dst_port AS VARCHAR), '-')) AS destination,
                        proto, len, COALESCE(tcp_flags, '') AS flags,
                        COALESCE(info, '') AS info
                 FROM packets {where_clause}ORDER BY ts LIMIT {MAX_ROWS}"
            ),
        }
    }

    /// Shown in the filter box when it is empty, so the syntax is never a guess.
    fn hint(self) -> &'static str {
        match self {
            View::Flows => "state = 'refused'   ·   bytes > 100000   ·   host LIKE '%github%'",
            View::Packets => "proto = 'UDP'   ·   info LIKE '%NXDOMAIN%'   ·   len > 1400",
        }
    }
}

struct App {
    view: View,
    filter: String,
    /// Set while the filter box has focus; Esc or Enter closes it.
    editing: bool,
    rows: Vec<Vec<String>>,
    state: TableState,
    status: String,
    /// Set when the last filter was rejected, so the box can say so in place.
    error: Option<String>,
}

pub async fn run(ctx: &SessionContext) -> Result<()> {
    let mut app = App {
        view: View::Flows,
        filter: String::new(),
        editing: false,
        rows: Vec::new(),
        state: TableState::default().with_selected(0),
        status: String::new(),
        error: None,
    };
    app.reload(ctx).await;

    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;

    let result = event_loop(&mut term, &mut app, ctx).await;

    // Restore the terminal whatever happened: leaving a user in raw mode with
    // no echo is worse than any error we could report.
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    result
}

async fn event_loop<B: Backend>(
    term: &mut Terminal<B>,
    app: &mut App,
    ctx: &SessionContext,
) -> Result<()> {
    loop {
        term.draw(|f| draw(f, app))?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if app.editing {
            match key.code {
                KeyCode::Enter => {
                    app.editing = false;
                    app.reload(ctx).await;
                }
                KeyCode::Esc => {
                    app.editing = false;
                    app.filter.clear();
                    app.error = None;
                    app.reload(ctx).await;
                }
                KeyCode::Backspace => {
                    app.filter.pop();
                }
                KeyCode::Char(c) => app.filter.push(c),
                _ => {}
            }
            continue;
        }

        // Two lines of chrome above the table and four below it.
        let page = term.size()?.height.saturating_sub(8).max(1) as usize;
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Tab => {
                app.view = match app.view {
                    View::Flows => View::Packets,
                    View::Packets => View::Flows,
                };
                // A filter written for one table rarely means anything in the
                // other, so it is dropped rather than silently failing.
                app.filter.clear();
                app.error = None;
                app.reload(ctx).await;
            }
            KeyCode::Char('/') => app.editing = true,
            KeyCode::Down | KeyCode::Char('j') => app.move_by(1),
            KeyCode::Up | KeyCode::Char('k') => app.move_by(-1),
            KeyCode::PageDown | KeyCode::Char(' ') => app.move_by(page as isize),
            KeyCode::PageUp => app.move_by(-(page as isize)),
            KeyCode::Home | KeyCode::Char('g') => app.state.select(Some(0)),
            KeyCode::End | KeyCode::Char('G') => {
                app.state.select(Some(app.rows.len().saturating_sub(1)))
            }
            _ => {}
        }
    }
}

impl App {
    fn move_by(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let cur = self.state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, self.rows.len() as isize - 1);
        self.state.select(Some(next as usize));
    }

    async fn reload(&mut self, ctx: &SessionContext) {
        let sql = self.view.sql(&self.filter);
        match ctx.sql(&sql).await {
            Ok(df) => match df.collect().await {
                Ok(batches) => {
                    let (_, rows) = to_strings(&batches);
                    self.rows = rows;
                    self.state.select(Some(0));
                    self.error = None;
                    // The row count is already in the position readout; this
                    // line is for news, and silence means nothing is amiss.
                    self.status = if self.rows.len() >= MAX_ROWS {
                        format!("capped at {} — narrow the filter", n(MAX_ROWS))
                    } else {
                        String::new()
                    };
                }
                Err(e) => self.error = Some(first_line(&e.to_string())),
            },
            // An invalid filter is normal while typing; the previous rows stay
            // on screen and the box says what was wrong with it.
            Err(e) => self.error = Some(first_line(&e.to_string())),
        }
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or(s).to_string()
}

/// Thousands separated with thin spaces, which stay readable at a glance
/// without the comma/point ambiguity between locales.
fn n(v: usize) -> String {
    let s = v.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Byte counts are compared, not read digit by digit, so they are scaled.
fn bytes(raw: &str) -> String {
    let Ok(v) = raw.parse::<f64>() else {
        return raw.to_string();
    };
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = v;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{v:.0} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Epoch seconds as a wall clock. UTC, not local: a capture is usually read on
/// a different machine than it was taken on, and silently shifting the times
/// to the reader's zone would make two people disagree about one file.
fn clock(raw: &str) -> String {
    let Ok(v) = raw.parse::<f64>() else {
        return raw.to_string();
    };
    let secs = v as i64;
    let day = secs.rem_euclid(86_400);
    let millis = ((v - v.floor()) * 1000.0) as i64;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        day / 3600,
        (day % 3600) / 60,
        day % 60,
        millis
    )
}

fn state_style(s: &str) -> Style {
    match s {
        // The two that mean something is wrong, and mean different things.
        "refused" => Style::new().fg(Color::Red).bold(),
        "no-reply" => Style::new().fg(Color::Yellow).bold(),
        "reset" => Style::new().fg(Color::Magenta),
        "established" => Style::new().fg(Color::Green),
        "closed" => Style::new().fg(Color::Gray),
        _ => Style::new().fg(Color::DarkGray),
    }
}

fn proto_style(s: &str) -> Style {
    match s {
        "TLS" | "TCP" => Style::new().fg(Color::Cyan),
        "DNS" | "UDP" => Style::new().fg(Color::Blue),
        // Cleartext, and worth noticing as such.
        "HTTP" => Style::new().fg(Color::Yellow),
        "ICMP" => Style::new().fg(Color::Magenta),
        _ => Style::new().fg(Color::DarkGray),
    }
}

/// Render batches into displayable strings, using Arrow's own formatting so a
/// value looks the same here as it does in `falconnet query`.
pub fn to_strings(batches: &[RecordBatch]) -> (Vec<String>, Vec<Vec<String>>) {
    let Some(first) = batches.first() else {
        return (Vec::new(), Vec::new());
    };
    let headers = first
        .schema()
        .fields()
        .iter()
        .map(|f| f.name().clone())
        .collect();

    let opts = FormatOptions::default().with_null("");
    let mut rows = Vec::new();
    for batch in batches {
        let formatters: Vec<_> = batch
            .columns()
            .iter()
            .filter_map(|c| ArrayFormatter::try_new(c.as_ref(), &opts).ok())
            .collect();
        if formatters.len() != batch.num_columns() {
            continue;
        }
        for r in 0..batch.num_rows() {
            rows.push(formatters.iter().map(|f| f.value(r).to_string()).collect());
        }
    }
    (headers, rows)
}

fn cell(col: &Col, raw: &str) -> Cell<'static> {
    match col.fmt {
        Fmt::Text => Cell::from(raw.to_string()),
        Fmt::Num => Cell::from(Line::from(raw.to_string()).right_aligned()),
        Fmt::Bytes => Cell::from(Line::from(bytes(raw)).right_aligned()),
        Fmt::Clock => Cell::from(clock(raw)),
        Fmt::State => Cell::from(raw.to_string()).style(state_style(raw)),
        Fmt::Proto => Cell::from(raw.to_string()).style(proto_style(raw)),
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Min(1),    // table
        Constraint::Length(3), // filter
        Constraint::Length(1), // keys
    ])
    .split(f.area());

    let cols = app.view.columns();
    let position = if app.rows.is_empty() {
        String::new()
    } else {
        format!(
            "  {} / {}",
            n(app.state.selected().unwrap_or(0) + 1),
            n(app.rows.len())
        )
    };

    // ── title ───────────────────────────────────────────────────────────────
    let title = Line::from(vec![
        Span::styled(
            " falconnet ",
            Style::new().bold().bg(Color::Cyan).fg(Color::Black),
        ),
        Span::styled(
            format!(" {} ", app.view.title()),
            Style::new().bold().fg(Color::Cyan),
        ),
        Span::styled(position, Style::new().fg(Color::DarkGray)),
        Span::styled(
            if app.status.is_empty() {
                String::new()
            } else {
                format!("   {}", app.status)
            },
            Style::new().fg(Color::Yellow),
        ),
    ]);
    f.render_widget(Paragraph::new(title), chunks[0]);

    // ── table ───────────────────────────────────────────────────────────────
    let header = Row::new(cols.iter().map(|c| {
        let t = Line::from(c.title);
        Cell::from(match c.fmt {
            Fmt::Num | Fmt::Bytes => t.right_aligned(),
            _ => t,
        })
    }))
    .style(Style::new().bold().fg(Color::White))
    .bottom_margin(0);

    let body: Vec<Row> = app
        .rows
        .iter()
        .map(|r| {
            Row::new(
                cols.iter()
                    .enumerate()
                    .map(|(i, c)| cell(c, r.get(i).map(String::as_str).unwrap_or(""))),
            )
        })
        .collect();

    let widths: Vec<Constraint> = cols.iter().map(|c| c.width).collect();
    let table = Table::new(body, widths)
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(Color::DarkGray)),
        )
        .row_highlight_style(Style::new().bg(Color::Rgb(38, 45, 56)))
        .highlight_symbol("▌");
    f.render_stateful_widget(table, chunks[1], &mut app.state);

    // A scrollbar is the only thing that says how much is below the fold — and
    // showing one when nothing is below the fold says the opposite.
    let visible = chunks[1].height.saturating_sub(3) as usize; // borders + header
    if app.rows.len() > visible {
        let mut sb =
            ScrollbarState::new(app.rows.len()).position(app.state.selected().unwrap_or(0));
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_style(Style::new().fg(Color::DarkGray)),
            chunks[1].inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut sb,
        );
    }

    // ── filter ──────────────────────────────────────────────────────────────
    let (body, style, border, title) = if let Some(e) = &app.error {
        (
            e.clone(),
            Style::new().fg(Color::Red),
            Color::Red,
            "filter — rejected, showing the previous rows",
        )
    } else if app.editing {
        (
            format!("{}█", app.filter),
            Style::new(),
            Color::Cyan,
            "filter — Enter applies, Esc clears",
        )
    } else if app.filter.is_empty() {
        (
            app.view.hint().to_string(),
            Style::new().fg(Color::DarkGray),
            Color::DarkGray,
            "filter — press / to edit",
        )
    } else {
        (
            app.filter.clone(),
            Style::new().fg(Color::Green),
            Color::DarkGray,
            "filter — active",
        )
    };
    f.render_widget(
        Paragraph::new(body).style(style).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(border))
                .title(title),
        ),
        chunks[2],
    );

    // ── keys ────────────────────────────────────────────────────────────────
    let key = Style::new().fg(Color::Cyan).bold();
    let dim = Style::new().fg(Color::DarkGray);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" Tab", key),
            Span::styled(" switch view   ", dim),
            Span::styled("/", key),
            Span::styled(" filter   ", dim),
            Span::styled("j k ↑ ↓", key),
            Span::styled(" move   ", dim),
            Span::styled("g G", key),
            Span::styled(" top bottom   ", dim),
            Span::styled("q", key),
            Span::styled(" quit", dim),
        ])),
        chunks[3],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::datasource::MemTable;
    use std::sync::Arc;

    /// The views name columns by hand, so a rename in `capture` or `flows`
    /// would break browsing while every other command kept working. Planning
    /// both queries against the real schemas catches that at test time — no
    /// terminal, no capture file needed.
    async fn plan(view: View, filter: &str) -> Result<()> {
        let ctx = SessionContext::new();
        ctx.register_table(
            "packets",
            Arc::new(MemTable::try_new(crate::capture::schema(), vec![vec![]])?),
        )?;
        ctx.register_table(
            "flows",
            Arc::new(MemTable::try_new(crate::flows::schema(), vec![vec![]])?),
        )?;
        ctx.sql(&view.sql(filter)).await?;
        Ok(())
    }

    #[tokio::test]
    async fn both_views_plan_against_the_real_schemas() {
        plan(View::Flows, "")
            .await
            .expect("the flows view must plan");
        plan(View::Packets, "")
            .await
            .expect("the packets view must plan");
    }

    #[tokio::test]
    async fn a_filter_is_spliced_in_as_a_condition() {
        // Each view is filtered on a column its own table actually has.
        plan(View::Packets, "len > 0")
            .await
            .expect("packets filter must plan");
        plan(View::Flows, "state = 'refused'")
            .await
            .expect("flows filter must plan");
    }

    #[tokio::test]
    async fn a_nonsense_filter_fails_instead_of_being_ignored() {
        // Silently dropping a bad filter would show the user unfiltered data
        // and let them believe it was filtered.
        assert!(plan(View::Flows, "no_such_column = 1").await.is_err());
        assert!(plan(View::Packets, "no_such_column = 1").await.is_err());
    }

    /// A filter meant for one table is dropped when switching views, because
    /// it would otherwise fail on every reload with no way to clear it.
    #[tokio::test]
    async fn a_flows_filter_would_not_plan_against_packets() {
        assert!(plan(View::Packets, "state = 'refused'").await.is_err());
    }

    /// Every column the layout declares must exist in the projection, or the
    /// table silently renders blank cells under real headings.
    #[tokio::test]
    async fn each_view_projects_exactly_the_columns_it_lays_out() {
        for view in [View::Flows, View::Packets] {
            let ctx = SessionContext::new();
            ctx.register_table(
                "packets",
                Arc::new(MemTable::try_new(crate::capture::schema(), vec![vec![]]).unwrap()),
            )
            .unwrap();
            ctx.register_table(
                "flows",
                Arc::new(MemTable::try_new(crate::flows::schema(), vec![vec![]]).unwrap()),
            )
            .unwrap();
            let df = ctx.sql(&view.sql("")).await.unwrap();
            assert_eq!(
                df.schema().fields().len(),
                view.columns().len(),
                "{} projects a different number of columns than it draws",
                view.title()
            );
        }
    }

    #[test]
    fn byte_counts_are_scaled_for_comparison() {
        assert_eq!(bytes("512"), "512 B");
        assert_eq!(bytes("2048"), "2.0 KB");
        assert_eq!(bytes("1048576"), "1.0 MB");
        // A value that is not a number is shown as it came, not as zero.
        assert_eq!(bytes("n/a"), "n/a");
    }

    #[test]
    fn timestamps_render_as_a_wall_clock() {
        // 1700000000 is 2023-11-14 22:13:20 UTC.
        assert_eq!(clock("1700000000"), "22:13:20.000");
        assert_eq!(clock("1700000000.5"), "22:13:20.500");
        assert_eq!(clock("not a time"), "not a time");
    }

    /// Render a real frame to a text buffer. A terminal is not needed for this,
    /// and it is the only way the layout gets checked at all: every other test
    /// here covers the data behind the screen, not the screen.
    fn render_to_text(app: &mut App, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn demo_app() -> App {
        App {
            view: View::Flows,
            filter: String::new(),
            editing: false,
            rows: vec![
                row(&[
                    "192.168.1.12:51000",
                    "140.82.114.25:443",
                    "api.github.com",
                    "TLS",
                    "1843",
                    "14203914",
                    "2.117",
                    "closed",
                ]),
                row(&[
                    "192.168.1.12:51204",
                    "10.0.4.7:5432",
                    "",
                    "",
                    "2",
                    "108",
                    "0.000",
                    "refused",
                ]),
                row(&[
                    "192.168.1.12:51301",
                    "93.184.216.34:80",
                    "example.com",
                    "HTTP",
                    "18",
                    "9214",
                    "0.204",
                    "closed",
                ]),
                row(&[
                    "192.168.1.31:52880",
                    "10.0.9.2:8080",
                    "",
                    "",
                    "1",
                    "60",
                    "0.000",
                    "no-reply",
                ]),
                row(&[
                    "192.168.1.12:51410",
                    "162.159.130.234:443",
                    "gateway.discord.gg",
                    "TLS",
                    "402",
                    "820104",
                    "31.900",
                    "established",
                ]),
            ],
            state: TableState::default().with_selected(0),
            status: String::new(),
            error: None,
        }
    }

    fn row(cells: &[&str]) -> Vec<String> {
        cells.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_layout_draws_and_fits_its_width() {
        let mut app = demo_app();
        let text = render_to_text(&mut app, 118, 14);
        println!(
            "
{text}"
        );

        // Headings, data and chrome all have to survive the widths chosen.
        for expected in [
            "falconnet",
            "conversations",
            "client",
            "server",
            "host",
            "state",
        ] {
            assert!(
                text.contains(expected),
                "missing {expected}:
{text}"
            );
        }
        assert!(
            text.contains("api.github.com"),
            "hostname truncated away:
{text}"
        );
        assert!(
            text.contains("refused"),
            "state column lost:
{text}"
        );
        // Byte counts are scaled, not printed raw.
        assert!(
            text.contains("13.5 MB"),
            "bytes not scaled:
{text}"
        );
        assert!(
            !text.contains("14203914"),
            "raw byte count leaked:
{text}"
        );
        // The key line is the only documentation a first-time user gets.
        assert!(
            text.contains("switch view") && text.contains("quit"),
            "keys missing:
{text}"
        );
        // Nothing may spill past the terminal width.
        for line in text.lines() {
            assert!(line.chars().count() <= 118, "line overflows: {line:?}");
        }
    }

    #[test]
    fn the_packets_view_and_a_rejected_filter_both_draw() {
        let mut app = demo_app();
        app.view = View::Packets;
        app.rows = vec![row(&[
            "1700000000.523",
            "192.168.1.12:51000",
            "140.82.114.25:443",
            "TCP",
            "1454",
            "PSH,ACK",
            "Client Hello TLS 1.2 (api.github.com)",
        ])];
        app.error = Some("No field named nope.".into());
        let text = render_to_text(&mut app, 118, 10);
        println!(
            "
{text}"
        );

        assert!(
            text.contains("22:13:20.523"),
            "timestamp not a clock:
{text}"
        );
        assert!(
            text.contains("rejected"),
            "a bad filter must say so:
{text}"
        );
        assert!(
            text.contains("Client Hello"),
            "info column lost:
{text}"
        );
    }

    #[test]
    fn thousands_are_separated() {
        assert_eq!(n(7), "7");
        assert_eq!(n(1234), "1 234");
        assert_eq!(n(1234567), "1 234 567");
    }
}
