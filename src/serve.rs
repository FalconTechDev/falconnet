//! The capture, in a browser.
//!
//! The same two tables and the same triage rules as the command line, behind a
//! page served by the binary itself. There is no build step and no bundled
//! runtime: one executable, one port, and any machine with a browser can read
//! the capture — including the ones where installing Wireshark is not an option.

use std::net::SocketAddr;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use datafusion::prelude::SessionContext;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::triage;
use crate::tui::to_strings;

#[derive(Clone)]
struct App {
    ctx: SessionContext,
    file: String,
    packets: usize,
    flows: usize,
}

/// Built separately from `run` so the routes can be exercised in tests without
/// binding a port or waiting on a real socket.
fn router(app: App) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/api/summary", get(summary))
        .route("/api/triage", get(findings))
        .route("/api/query", post(query))
        .with_state(app)
}

#[derive(Deserialize)]
struct QueryBody {
    sql: String,
}

pub async fn run(
    ctx: SessionContext,
    file: String,
    packets: usize,
    flows: usize,
    port: u16,
) -> Result<()> {
    let router = router(App {
        ctx,
        file,
        packets,
        flows,
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("falconet is serving the capture at http://{addr}");
    println!("Press Ctrl+C to stop.");
    axum::serve(listener, router).await?;
    Ok(())
}

async fn page() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

async fn summary(State(app): State<App>) -> Json<Value> {
    Json(json!({
        "file": app.file,
        "packets": app.packets,
        "flows": app.flows,
    }))
}

/// Run every triage rule and return the lines with their severity, so the page
/// can style them without re-deriving what is a problem and what is not.
async fn findings(State(app): State<App>) -> Result<Json<Value>, ApiError> {
    let mut out = Vec::new();
    for rule in triage::RULES {
        let batches = app.ctx.sql(rule.sql).await?.collect().await?;
        let (_, rows) = to_strings(&batches);
        for row in rows {
            if let Some(line) = row.first() {
                out.push(json!({
                    "level": match rule.level {
                        triage::Level::Problem => "problem",
                        triage::Level::Warning => "warning",
                        triage::Level::Ok => "ok",
                    },
                    "line": line,
                }));
            }
        }
    }
    Ok(Json(json!({ "findings": out })))
}

async fn query(
    State(app): State<App>,
    Json(body): Json<QueryBody>,
) -> Result<Json<Value>, ApiError> {
    let started = std::time::Instant::now();
    let batches = app.ctx.sql(&body.sql).await?.collect().await?;
    let (columns, rows) = to_strings(&batches);
    Ok(Json(json!({
        "columns": columns,
        "rows": rows,
        "elapsed_ms": started.elapsed().as_secs_f64() * 1000.0,
    })))
}

/// A failed query is the user mistyping SQL, not the server breaking, so it
/// comes back as a readable message the page can print next to the box.
struct ApiError(String);

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, Json(json!({ "error": self.0 }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use datafusion::datasource::MemTable;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// An empty capture with the real schemas: enough to prove every route is
    /// wired and every rule still plans, which is what silently breaks when a
    /// column is renamed.
    fn app() -> App {
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
        App {
            ctx,
            file: "t.pcap".into(),
            packets: 0,
            flows: 0,
        }
    }

    async fn call(req: Request<Body>) -> (StatusCode, String) {
        let res = router(app()).oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn get_req(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    fn post_sql(sql: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/query")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                "{{\"sql\":{}}}",
                serde_json::json!(sql)
            )))
            .unwrap()
    }

    #[tokio::test]
    async fn the_page_is_served() {
        let (status, body) = call(get_req("/")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("<title>falconet</title>"), "not the UI page");
    }

    #[tokio::test]
    async fn summary_reports_the_capture() {
        let (status, body) = call(get_req("/api/summary")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("t.pcap"), "{body}");
    }

    /// Every triage rule has to plan against the real schemas. A rule that
    /// errors would otherwise take the whole diagnosis panel down with it.
    #[tokio::test]
    async fn every_rule_runs() {
        let (status, body) = call(get_req("/api/triage")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("findings"), "{body}");
    }

    #[tokio::test]
    async fn a_query_returns_columns_and_rows() {
        let (status, body) = call(post_sql("SELECT 1 AS one")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"columns\":[\"one\"]"), "{body}");
        assert!(body.contains("elapsed_ms"), "{body}");
    }

    /// A mistyped query is the user's, not the server's: it must come back as a
    /// readable message rather than a 500 with nothing to act on.
    #[tokio::test]
    async fn bad_sql_is_a_readable_client_error() {
        let (status, body) = call(post_sql("SELECT no_such_column FROM flows")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("no_such_column"),
            "the message must name it: {body}"
        );
    }
}
