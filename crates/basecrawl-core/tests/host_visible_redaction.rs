//! Host-visible log / metric / error redaction through the basecrawl CLI
//! (VAL-CONF-018, 019, 020, 031).
//!
//! Runs real scrapes (happy + error paths) with distinctive markers and greps
//! every host-visible stream (stdout is the sealed/canonical ScrapeProof which
//! intentionally carries request.url for the validator; we only assert that
//! *logs / stderr / metric-style lines* stay free of markers for confidentiality).

use basecrawl_seal::{task_id_ref, url_path_query_ref};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

/// Path + query bound into the fixture URL (VAL-CONF-018).
const PATH: &str = "/secret/canary-path";
const PATH_QUERY: &str = "/secret/canary-path?token=val-conf-018-marker&session=xyz";

/// Request markers (VAL-CONF-019).
const HEADER_MARKER: &str = "custom-header-secret-marker-val-conf-019";
const COOKIE_MARKER: &str = "cookie-secret-marker-val-conf-019";
const AUTH_MARKER: &str = "auth-header-secret-marker-val-conf-019";

/// Result canary (VAL-CONF-020).
const RESULT_CANARY: &str = "KNOWN-RESULT-CANARY-VAL-CONF-020-9f3a2c";

/// Task id for host-safe correlation.
const TASK_ID: &str = "task-host-redaction-VAL-CONF";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

/// Local fixture that echoes request markers into a body containing RESULT_CANARY.
/// Returns (base_url_without_path, captured request text).
fn fixture_server() -> (String, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let captured = Arc::new(Mutex::new(String::new()));
    let captured_thread = Arc::clone(&captured);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 8192];
                    if let Ok(n) = stream.read(&mut buf) {
                        let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                        *captured_thread.lock().expect("capture mutex") = req;
                    }
                    let body = format!("<!doctype html><html><body>{RESULT_CANARY}</body></html>");
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}"), captured)
}

/// Local server that always 302-redirects to itself (error path).
fn redirect_loop_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: {PATH_QUERY}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    // Give the acceptor a tick.
    thread::sleep(Duration::from_millis(20));
    format!("http://{addr}{PATH_QUERY}")
}

fn host_visible_streams(out: &Output) -> String {
    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    // stdout for failure paths must be empty; for success, scrape proof lives there and is
    // intentionally content-bearing for validators — confidentiality greps are on stderr only.
    s
}

fn assert_no_markers(surface: &str, ctx: &str) {
    for marker in [
        PATH_QUERY,
        PATH,
        "token=val-conf-018-marker",
        HEADER_MARKER,
        COOKIE_MARKER,
        AUTH_MARKER,
        RESULT_CANARY,
        TASK_ID,
    ] {
        assert!(
            !surface.contains(marker),
            "{ctx}: host-visible surface leaked {marker:?}:\n{surface}"
        );
    }
}

// ---------------------------------------------------------------------------
// VAL-CONF-018 + 019 + 020 happy path (verbose log)
// ---------------------------------------------------------------------------

#[test]
fn val_conf_018_019_020_verbose_logs_redact_path_headers_and_result() {
    let (base, _captured) = fixture_server();
    let url = format!("{base}{PATH_QUERY}");
    let out = run(&[
        &url,
        "--formats",
        "rawHtml",
        "--no-js",
        "--verbose",
        "--robots",
        "ignore",
        "--task-id",
        TASK_ID,
        "--header",
        &format!("X-Canary: {HEADER_MARKER}"),
        "--header",
        &format!("Cookie: session={COOKIE_MARKER}"),
        "--header",
        &format!("Authorization: Bearer {AUTH_MARKER}"),
    ]);
    assert!(
        out.status.success(),
        "happy-path scrape must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = host_visible_streams(&out);
    assert!(
        stderr.contains("scrape_completed"),
        "verbose completion event missing: {stderr}"
    );
    // Task id appears only as digest.
    let expected_task = task_id_ref(Some(TASK_ID));
    assert!(
        stderr.contains(&expected_task),
        "verbose log must bind redacted task id {expected_task}, got: {stderr}"
    );
    assert_no_markers(&stderr, "verbose happy-path stderr");

    // Result canary is allowed in the *ScrapeProof* on stdout (validator-bound), but never
    // in host logs. Confirm it was produced, then confirm logs lack it.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(RESULT_CANARY),
        "fixture must produce the result canary so the log redaction check is meaningful"
    );
    assert!(!stderr.contains(RESULT_CANARY));
}

// ---------------------------------------------------------------------------
// VAL-CONF-031: error paths (redirect loop embeds path in error historically)
// ---------------------------------------------------------------------------

#[test]
fn val_conf_031_redirect_loop_error_redacts_path_and_query() {
    let url = redirect_loop_server();
    let out = run(&[
        &url,
        "--formats",
        "rawHtml",
        "--no-js",
        "--robots",
        "ignore",
        "--timeout",
        "5",
        "--task-id",
        TASK_ID,
    ]);
    assert!(!out.status.success(), "redirect loop must fail");
    assert!(out.stdout.is_empty(), "no partial ScrapeProof on failure");

    let stderr = host_visible_streams(&out);
    let err: Value = serde_json::from_str(stderr.trim()).unwrap_or_else(|e| {
        panic!("stderr must be a single JSON error envelope: {e}; was: {stderr}")
    });
    assert_eq!(err["error"]["kind"], "too_many_redirects");
    assert_eq!(err["error"]["max_redirects"], 20);
    assert!(
        err["error"]["message"]
            .as_str()
            .is_some_and(|m| m.to_lowercase().contains("too many redirects")),
        "message must stay informative: {}",
        err["error"]["message"]
    );
    // Host-safe task + url refs present; raw path/query absent.
    assert_eq!(err["error"]["task_id"], task_id_ref(Some(TASK_ID)));
    assert!(err["error"]["url_ref"].as_str().is_some());
    assert_no_markers(&stderr, "redirect-loop error stderr");
}

#[test]
fn val_conf_031_invalid_url_error_never_echoes_raw_input() {
    let bad = format!("https://target.example{PATH_QUERY}");
    // Force invalid by embedding spaces into an otherwise path-bearing input via
    // a clearly unparseable form that still carries the marker characters as text.
    let crafted = format!("not a url but contains {PATH_QUERY} and {HEADER_MARKER}");
    let out = run(&[&crafted, "--task-id", TASK_ID]);
    assert!(!out.status.success());
    let stderr = host_visible_streams(&out);
    let err: Value = serde_json::from_str(stderr.trim()).expect("structured JSON error on stderr");
    assert_eq!(err["error"]["kind"], "invalid_url");
    assert_no_markers(&stderr, "invalid-url error stderr");
    // Also ensure the crafted raw input itself (including the benign host URL we built) is gone.
    assert!(!stderr.contains(&bad));
    assert!(!stderr.contains("not a url but contains"));
}

#[test]
fn val_conf_031_lookup_failure_error_omits_hostname_path() {
    // Non-resolvable host with distinctive path/query; failure is transport/DNS.
    let url = format!("https://no-such-host-val-conf-031.invalid{PATH_QUERY}");
    let out = run(&[
        &url,
        "--formats",
        "rawHtml",
        "--no-js",
        "--robots",
        "ignore",
        "--timeout",
        "3",
        "--task-id",
        TASK_ID,
        "--header",
        &format!("X-Canary: {HEADER_MARKER}"),
    ]);
    assert!(!out.status.success(), "unresolvable host must fail");
    let stderr = host_visible_streams(&out);
    assert_no_markers(&stderr, "dns/transport error stderr");
    // Host name itself is expected residual leakage only if SNI path mirrors it;
    // path/query must still be gone (checked by assert_no_markers).
    let err: Value = serde_json::from_str(stderr.lines().next().unwrap_or(stderr.trim()))
        .unwrap_or_else(|_| json_from_stderr(&stderr));
    assert!(
        err["error"]["kind"].as_str().is_some(),
        "error kind must be present: {stderr}"
    );
}

fn json_from_stderr(stderr: &str) -> Value {
    serde_json::from_str(stderr.trim())
        .unwrap_or_else(|e| panic!("expected JSON error, got {e}: {stderr}"))
}

#[test]
fn val_conf_018_url_path_query_ref_stable_helper_matches_cli_surface() {
    // Sanity: the digest the CLI embeds is the same primitive the contract greps against.
    let digest = url_path_query_ref(&format!("https://example.com{PATH_QUERY}"));
    assert!(digest.starts_with("url:sha256:"));
    assert!(!digest.contains("secret"));
}
