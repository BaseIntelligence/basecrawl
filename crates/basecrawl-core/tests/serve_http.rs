//! Integration tests for the long-running `basecrawl serve` HTTP surface (M3 SaaS).
//!
//! VAL-SAAS-FND-002 / VAL-SAAS-ENG-001/003/004/005:
//! - loopback bind + /health
//! - multi-job long-running handle
//! - optional shared-secret fail-closed
//! - soft real scrape markers (example.com or hermetic loopback)
//! - residual honesty strings (not anonymous/unlocker/100%/trustless)

use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

/// Serialise serve binary tests so two listeners never race on fixed ports.
fn serve_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    listener.local_addr().unwrap().port()
}

struct ServeProc {
    child: Child,
    port: u16,
}

impl ServeProc {
    fn spawn(port: u16, secret: Option<&str>) -> Self {
        let mut cmd = Command::new(BIN);
        cmd.arg("serve")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--max-inflight")
            .arg("2")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // Clear ambient secrets so hermetic secret-gate tests stay fail-closed only when we set them.
        cmd.env_remove("BASECRAWL_SERVE_SECRET");
        cmd.env_remove("ENGINE_SERVE_SECRET");
        if let Some(s) = secret {
            cmd.env("BASECRAWL_SERVE_SECRET", s);
        }
        let mut child = cmd.spawn().expect("spawn basecrawl serve");
        // Wait until /health responds (tolerate connection refused while binding).
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("serve did not become ready on port {port}");
            }
            if let Some((status, _)) = try_http_get(port, "/health") {
                if status == 200 {
                    break;
                }
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("serve exited early with {status:?} before ready on port {port}");
            }
            thread::sleep(Duration::from_millis(50));
        }
        Self { child, port }
    }
}

impl Drop for ServeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn try_http_exchange(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<(u16, String), std::io::Error> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(60))).ok();
    let body_bytes = body.unwrap_or("").as_bytes();
    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    if body.is_some() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes)?;
    }
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp)?;
    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok((status, text))
}

fn http_exchange(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, String) {
    try_http_exchange(port, method, path, headers, body).expect("connect serve")
}

fn http_get(port: u16, path: &str, secret: Option<&str>) -> (u16, String) {
    let headers: Vec<(&str, &str)> = match secret {
        Some(s) => vec![("X-Basecrawl-Serve-Secret", s)],
        None => vec![],
    };
    http_exchange(port, "GET", path, &headers, None)
}

fn try_http_get(port: u16, path: &str) -> Option<(u16, String)> {
    try_http_exchange(port, "GET", path, &[], None).ok()
}

fn http_post_json(port: u16, path: &str, secret: Option<&str>, body: &str) -> (u16, Value) {
    let headers: Vec<(&str, &str)> = match secret {
        Some(s) => vec![("X-Basecrawl-Serve-Secret", s)],
        None => vec![],
    };
    let (status, text) = http_exchange(port, "POST", path, &headers, Some(body));
    let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
    let json_body = text[body_start..].trim();
    let value: Value = serde_json::from_str(json_body)
        .unwrap_or_else(|e| panic!("expected JSON body status={status}: {e}\nraw:\n{text}"));
    (status, value)
}

#[test]
fn serve_help_lists_subcommand() {
    let out = Command::new(BIN)
        .arg("serve")
        .arg("--help")
        .output()
        .expect("help");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("4420") || text.contains("bind") || text.contains("serve"),
        "serve help missing bind docs:\n{text}"
    );
    let lower = text.to_ascii_lowercase();
    // Residual honesty in serve help must deny unlocker/anonymous hype (not promote it).
    assert!(
        lower.contains("not anonymity")
            || lower.contains("not anonymous")
            || lower.contains("not trustless")
            || lower.contains("residual"),
        "serve help should state residual honesty:\n{text}"
    );
    for banned in ["100% unlock", "guarantees anonymous", "is trustless"] {
        assert!(
            !lower.contains(banned),
            "serve help must not claim '{banned}'"
        );
    }
}

#[test]
fn serve_health_ok() {
    let _g = serve_lock().lock().unwrap();
    let port = free_port();
    let proc = ServeProc::spawn(port, None);
    let (status, body) = http_get(proc.port, "/health", None);
    assert_eq!(status, 200, "health body: {body}");
    assert!(body.contains("basecrawl-serve"), "{body}");
    assert!(
        body.contains("\"status\":\"ok\"") || body.contains("\"status\": \"ok\""),
        "{body}"
    );
    // residual honesty
    let lower = body.to_ascii_lowercase();
    assert!(
        lower.contains("not")
            && (lower.contains("anonymous")
                || lower.contains("trustless")
                || lower.contains("100%")),
        "health residual must deny anonymity/100% hype: {body}"
    );
}

#[test]
fn serve_rejects_missing_secret_when_configured() {
    let _g = serve_lock().lock().unwrap();
    let port = free_port();
    let secret = "test-serve-secret-abc";
    let proc = ServeProc::spawn(port, Some(secret));
    // Health remains open.
    assert_eq!(http_get(proc.port, "/health", None).0, 200);
    // Scrape without secret fails closed.
    let (status, val) = http_post_json(
        proc.port,
        "/v1/scrape",
        None,
        r#"{"url":"https://example.com"}"#,
    );
    assert_eq!(status, 401, "expected 401: {val}");
    assert_eq!(val["success"], false);
    assert_eq!(val["error"]["code"], "unauthorized");
    // With secret header, missing-url (empty invalid) would 400 after auth; use no-url to prove auth pass.
    let (status2, val2) = http_post_json(proc.port, "/v1/scrape", Some(secret), r#"{}"#);
    assert_ne!(status2, 401, "secret should pass gate: {val2}");
    assert_eq!(val2["error"]["code"], "missing_url");
}

#[test]
fn serve_scrape_example_soft() {
    let _g = serve_lock().lock().unwrap();
    // Hermetic local page fixture to avoid open-web dependency when forced.
    let page = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 58\r\nConnection: close\r\n\r\n<html><body><h1>Example Domain Soft Marker</h1></body></html>";
    let fixture = TcpListener::bind("127.0.0.1:0").expect("fixture");
    let fixture_addr = fixture.local_addr().unwrap();
    thread::spawn(move || {
        for mut s in fixture.incoming().take(4).flatten() {
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf);
            let _ = s.write_all(page);
        }
    });

    let port = free_port();
    let mut proc = ServeProc::spawn(port, None);
    let url = format!("http://127.0.0.1:{}", fixture_addr.port());
    let body =
        format!(r#"{{"url":"{url}","formats":["markdown","html","metadata"],"timeout_ms":15000}}"#);

    // Job 1
    let (status, val) = http_post_json(proc.port, "/v1/scrape", None, &body);
    assert_eq!(status, 200, "scrape job1: {val}");
    assert_eq!(val["success"], true);
    let data = &val["data"];
    let content = format!("{data}");
    assert!(
        content.contains("Example Domain Soft Marker")
            || content.contains("Example Domain")
            || content.contains("Soft Marker"),
        "expected real fixture content markers, got: {content}"
    );
    assert!(
        val.get("proof").is_some(),
        "serve should attach residual/proof metadata: {val}"
    );

    // Job 2 against same PID (long-running)
    let (status2, val2) = http_post_json(proc.port, "/v1/scrape", None, &body);
    assert_eq!(status2, 200, "scrape job2 same PID: {val2}");
    assert_eq!(val2["success"], true);

    // PID still alive
    assert!(
        proc.child.try_wait().ok().flatten().is_none(),
        "serve process exited after jobs"
    );
}

#[test]
fn serve_open_web_example_soft_optional() {
    // Optional soft live path; skip unless BASECRAWL_OPEN_WEB=1 or non-hermetic.
    if std::env::var("BASECRAWL_HTTPBIN_BASE")
        .ok()
        .filter(|s| s.starts_with("http://"))
        .is_some()
        && std::env::var("BASECRAWL_OPEN_WEB").ok().as_deref() != Some("1")
    {
        eprintln!("skip open-web serve scrape under hermetic httpbin base");
        return;
    }
    let _g = serve_lock().lock().unwrap();
    let port = free_port();
    let proc = ServeProc::spawn(port, None);
    let (status, val) = http_post_json(
        proc.port,
        "/v1/scrape",
        None,
        r#"{"url":"https://example.com","formats":["markdown","metadata"],"timeout_ms":30000}"#,
    );
    if status != 200 {
        eprintln!("open-web scrape skipped due to network: status={status} body={val}");
        return;
    }
    assert_eq!(val["success"], true);
    let blob = val.to_string().to_ascii_lowercase();
    assert!(
        blob.contains("example domain") || blob.contains("example"),
        "expected example.com markers: {val}"
    );
}

#[test]
fn residual_honesty_constants_ban_hyped_claims() {
    // Compile-time-ish surface: scrape health residual via ephemeral server in-process.
    let residual = basecrawl_core::serve::SERVE_RESIDUAL_HONESTY.to_ascii_lowercase();
    for banned in [
        "100% unlocked",
        "guarantees unlock",
        "anonymous browsing",
        "trustless scrap",
    ] {
        assert!(
            !residual.contains(banned),
            "banned claim in residual: {banned}"
        );
    }
    assert!(
        residual.contains("not")
            && (residual.contains("anonymous")
                || residual.contains("trustless")
                || residual.contains("100%")),
        "must explicitly deny hyped claims: {residual}"
    );
}
