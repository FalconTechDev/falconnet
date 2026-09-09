//! A terminal browser over a capture.
//!
//! The SQL commands answer questions you already know how to ask. This is for
//! the other half of the job: looking around. Two views — conversations and
//! packets — with a filter box that takes a SQL condition, so what you learn
//! here transfers straight into `falconet query`.

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
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};

/// Rows pulled into memory for browsing. The point of the tool is that a
/// capture can be far larger than what fits on a screen or in a string table,
/// so the view is capped and says so rather than trying to hold everything.
const MAX_ROWS: usize = 50_000;

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

    /// The projection each view shows. Written out rather than `SELECT *` so
    /// the columns are ordered for reading, widest-meaning first.
    fn sql(self, filter: &str) -> String {
        let where_clause = if filter.trim().is_empty() {
            String::new()
        } else {
            format!("WHERE {filter} ")
        };
        match self {
            View::Flows => format!(
                "SELECT client_ip, client_port, server_ip, server_port,
                        COALESCE(host, '') AS host, COALESCE(app, '') AS app,
                        packets, bytes, ROUND(duration, 3) AS secs, state
                 FROM flows {where_clause}ORDER BY bytes DESC LIMIT {MAX_ROWS}"
            ),
            View::Packets => format!(
                "SELECT ROUND(ts, 6) AS ts, src_ip, dst_ip, proto, len,
                        COALESCE(tcp_flags, '') AS flags,
                        COALESCE(info, '') AS info
                 FROM packets {where_clause}ORDER BY ts LIMIT {MAX_ROWS}"
            ),
        }
    }
}

struct App {
    view: View,
    filter: String,
    /// Set while the filter box has focus; Esc or Enter closes it.
    editing: bool,
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    state: TableState,
    status: String,
}

pub async fn run(ctx: &SessionContext) -> Result<()> {
    let mut app = App {
        view: View::Flows,
        filter: String::new(),
        editing: false,
        headers: Vec::new(),
        rows: Vec::new(),
        state: TableState::default().with_selected(0),
        status: String::new(),
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

        let page = term.size()?.height.saturating_sub(6).max(1) as usize;
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
                app.reload(ctx).await;
            }
            KeyCode::Char('/') => app.editing = true,
            KeyCode::Down | KeyCode::Char('j') => app.move_by(1),
            KeyCode::Up | KeyCode::Char('k') => app.move_by(-1),
            KeyCode::PageDown => app.move_by(page as isize),
            KeyCode::PageUp => app.move_by(-(page as isize)),
            KeyCode::Home => app.state.select(Some(0)),
            KeyCode::End => app.state.select(Some(app.rows.len().saturating_sub(1))),
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
                    let (headers, rows) = to_strings(&batches);
                    self.headers = headers;
                    self.rows = rows;
                    self.state.select(Some(0));
                    self.status = if self.rows.len() >= MAX_ROWS {
                        format!(
                            "{} rows (capped at {MAX_ROWS} — narrow the filter)",
                            self.rows.len()
                        )
                    } else {
                        format!("{} rows", self.rows.len())
                    };
                }
                Err(e) => self.status = format!("query failed: {e}"),
            },
            // An invalid filter is normal while typing, so it is reported in
            // the status line and the previous rows stay on screen.
            Err(e) => self.status = format!("bad filter: {}", first_line(&e.to_string())),
        }
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or(s).to_string()
}

/// Render batches into displayable strings, using Arrow's own formatting so a
/// value looks the same here as it does in `falconet query`.
fn to_strings(batches: &[RecordBatch]) -> (Vec<String>, Vec<Vec<String>>) {
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

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(3),
    ])
    .split(f.area());

    let header = format!(
        " falconet — {} · {}   [Tab] switch view  [/] filter  [q] quit",
        app.view.title(),
        app.status
    );
    f.render_widget(
        Paragraph::new(header).style(Style::new().bold().fg(Color::Black).bg(Color::Cyan)),
        chunks[0],
    );

    let widths: Vec<Constraint> = app.headers.iter().map(|_| Constraint::Fill(1)).collect();

    let head = Row::new(
        app.headers
            .iter()
            .map(|h| Cell::from(h.as_str()).style(Style::new().bold())),
    );
    let body: Vec<Row> = app
        .rows
        .iter()
        .map(|r| Row::new(r.iter().map(|c| Cell::from(c.as_str()))))
        .collect();

    let table = Table::new(body, widths)
        .header(head)
        .block(Block::default().borders(Borders::ALL))
        .row_highlight_style(Style::new().bg(Color::DarkGray))
        .highlight_symbol("> ");
    f.render_stateful_widget(table, chunks[1], &mut app.state);

    let filter_title = if app.editing {
        "filter (Enter to apply, Esc to clear)"
    } else {
        "filter — press / to edit"
    };
    let shown = if app.filter.is_empty() && !app.editing {
        match app.view {
            View::Flows => "e.g.  state = 'refused'   ·   bytes > 100000".to_string(),
            View::Packets => "e.g.  proto = 'UDP'   ·   info LIKE '%NXDOMAIN%'".to_string(),
        }
    } else {
        app.filter.clone()
    };
    let style = if app.filter.is_empty() && !app.editing {
        Style::new().fg(Color::DarkGray)
    } else {
        Style::new()
    };
    f.render_widget(
        Paragraph::new(shown)
            .style(style)
            .block(Block::default().borders(Borders::ALL).title(filter_title)),
        chunks[2],
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
}
