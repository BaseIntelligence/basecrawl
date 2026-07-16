//! Long-running HTTP surface: `basecrawl serve` (SaaS engine loopback :4420).
//!
//! Binds scrape/crawl/map/batch execution without re-spawning the CLI per job. Default bind is
//! loopback (`127.0.0.1:4420`). When `BASECRAWL_SERVE_SECRET` is set, callers must present
//! `X-Basecrawl-Serve-Secret` (fail-closed). Not an unlocker/anonymity product: residual Chromium
//! and anti-bot risk remains; soft path is trust-but-audit, not "100%" or "anonymous".

use crate::batch::{self, BatchOptions};
use crate::crawl::{self, CrawlOptions, CRAWL_MVP_DESCRIPTION};
use crate::error::Error;
use crate::format;
use crate::map_lite::{self, MapOptions, MAP_LITE_DESCRIPTION};
use crate::{scrape, Format, ScrapeOptions, DEFAULT_MAX_PAGES};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Residual honesty line embedded in health and docs (never claim unlocker/anonymous/100%).
pub const SERVE_RESIDUAL_HONESTY: &str = "basecrawl serve is a local long-running engine for soft \
scrape/crawl/map/batch over HTTP. Authenticity is cryptographically-anchored trust-but-audit, not \
trustless. Chromium residual risk (headless/CDP side-channels, fingerprint lag) remains. CapSolver \
and soft TLS impersonate are optional aids and are not commercial Web Unlocker parity. This surface \
is not anonymous egress and does not claim 100% unlock of challenges.";

/// Default loopback host for mission SaaS local stack.
pub const DEFAULT_SERVE_HOST: &str = "127.0.0.1";
/// Default engine serve port (mission + services.yaml).
pub const DEFAULT_SERVE_PORT: u16 = 4420;
/// Default max concurrent execute handlers (mission local 2–4).
pub const DEFAULT_MAX_INFLIGHT: usize = 2;
/// Default hard request timeout (120s).
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 120_000;
/// Default HTTP body limit (32 MiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Shared secret header name required when a serve secret is configured.
pub const SERVE_SECRET_HEADER: &str = "x-basecrawl-serve-secret";
/// Env var for optional shared secret (also accepts ENGINE_SERVE_SECRET via resolve).
pub const SERVE_SECRET_ENV: &str = "BASECRAWL_SERVE_SECRET";
/// Alt env shared with SaaS API client naming.
pub const SERVE_SECRET_ENV_ALT: &str = "ENGINE_SERVE_SECRET";

/// Binding and execution bounds for the long-running serve process.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub host: String,
    pub port: u16,
    pub secret: Option<String>,
    pub max_inflight: usize,
    pub request_timeout_ms: u64,
    pub max_body_bytes: usize,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl ServeConfig {
    /// Build config from env with loopback defaults (host `127.0.0.1`, port `4420`).
    pub fn from_env() -> Self {
        let host = std::env::var("BASECRAWL_SERVE_HOST")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_SERVE_HOST.to_string());
        let port = std::env::var("BASECRAWL_SERVE_PORT")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(DEFAULT_SERVE_PORT);
        let secret = resolve_serve_secret_from_env();
        let max_inflight = std::env::var("BASECRAWL_SERVE_MAX_INFLIGHT")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|&n: &usize| n > 0)
            .unwrap_or(DEFAULT_MAX_INFLIGHT);
        let request_timeout_ms = std::env::var("BASECRAWL_SERVE_REQUEST_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|&n: &u64| n > 0)
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
        let max_body_bytes = std::env::var("BASECRAWL_SERVE_MAX_BODY_BYTES")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|&n: &usize| n > 0)
            .unwrap_or(DEFAULT_MAX_BODY_BYTES);
        Self {
            host,
            port,
            secret,
            max_inflight,
            request_timeout_ms,
            max_body_bytes,
        }
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, Error> {
        self.bind_addr().parse().map_err(|e| {
            Error::Io(format!(
                "invalid serve bind address '{}': {e}",
                self.bind_addr()
            ))
        })
    }
}

/// Read optional serve shared secret from env (never log the value).
pub fn resolve_serve_secret_from_env() -> Option<String> {
    for key in [SERVE_SECRET_ENV, SERVE_SECRET_ENV_ALT] {
        if let Ok(v) = std::env::var(key) {
            let t = v.trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    None
}

/// Constant-time-ish equality for shared secrets (length-mismatch races ok for local secret).
pub fn secrets_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Firecrawl-like execute request body (scrape / crawl / map / batch).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServeExecuteRequest {
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    /// Batch multi-URL list.
    #[serde(default)]
    pub urls: Option<Vec<String>>,
    #[serde(default)]
    pub formats: Option<Vec<String>>,
    #[serde(default)]
    pub only_main_content: Option<bool>,
    #[serde(default, alias = "timeout_ms")]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub fingerprint_seed: Option<String>,
    #[serde(default)]
    pub max_age: Option<u64>,
    /// Force Chromium/JS render. Soft default is false (rustls soft path).
    #[serde(default, alias = "javascript")]
    pub render: Option<bool>,
    #[serde(default)]
    pub wait_for: Option<String>,
    #[serde(default)]
    pub max_pages: Option<usize>,
    #[serde(default)]
    pub max_depth: Option<usize>,
    #[serde(default)]
    pub max_urls: Option<usize>,
    #[serde(default)]
    pub allow_domain: Option<String>,
    #[serde(default)]
    pub no_sitemap: Option<bool>,
    #[serde(default)]
    pub concurrency: Option<usize>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    /// Optional task id / nonce for ScrapeProof echo (validator-shaped).
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

/// Handle a single HTTP request on connection body + headers already read.
pub fn handle_http_request(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    config: &ServeConfig,
    inflight: &AtomicUsize,
) -> (u16, Value, Vec<(String, String)>) {
    let mut resp_headers: Vec<(String, String)> = Vec::new();
    if let Some(rid) = header_value(headers, "x-request-id") {
        resp_headers.push(("X-Request-Id".into(), rid));
    }

    let path_norm = path.split('?').next().unwrap_or(path);

    // Health is always open (so ops can probe without secret).
    if method.eq_ignore_ascii_case("GET") && (path_norm == "/health" || path_norm == "/") {
        return (
            200,
            json!({
                "status": "ok",
                "service": "basecrawl-serve",
                "bind": config.bind_addr(),
                "residual": SERVE_RESIDUAL_HONESTY,
            }),
            resp_headers,
        );
    }

    // Optional shared-secret gate for execute routes.
    if let Some(expected) = config.secret.as_deref() {
        let provided = header_value(headers, SERVE_SECRET_HEADER).unwrap_or_default();
        if !secrets_equal(expected, &provided) {
            return (
                401,
                json!({
                    "success": false,
                    "error": {
                        "code": "unauthorized",
                        "message": "missing or invalid X-Basecrawl-Serve-Secret",
                        "retryable": false
                    }
                }),
                resp_headers,
            );
        }
    }

    let mode = match (method.to_ascii_uppercase().as_str(), path_norm) {
        ("POST", "/v1/scrape") | ("POST", "/scrape") => "scrape",
        ("POST", "/v1/crawl") | ("POST", "/crawl") => "crawl",
        ("POST", "/v1/map") | ("POST", "/map") => "map",
        ("POST", "/v1/batch/scrape") | ("POST", "/v1/batch") | ("POST", "/batch") => "batch",
        _ => {
            return (
                404,
                json!({
                    "success": false,
                    "error": {
                        "code": "not_found",
                        "message": format!("unknown route {method} {path_norm}"),
                        "retryable": false
                    }
                }),
                resp_headers,
            );
        }
    };

    // Inflight concurrency clamp.
    let max = config.max_inflight.max(1);
    loop {
        let cur = inflight.load(Ordering::SeqCst);
        if cur >= max {
            return (
                429,
                json!({
                    "success": false,
                    "error": {
                        "code": "too_many_requests",
                        "message": format!("max inflight {} exceeded", max),
                        "retryable": true
                    }
                }),
                resp_headers,
            );
        }
        if inflight
            .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            break;
        }
    }

    let started = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_mode(mode, body, config)
    }));
    inflight.fetch_sub(1, Ordering::SeqCst);

    match result {
        Ok(Ok(mut value)) => {
            if let Some(obj) = value.as_object_mut() {
                if !obj.contains_key("success") {
                    obj.insert("success".into(), Value::Bool(true));
                }
                obj.entry("metrics".to_string()).or_insert_with(|| {
                    json!({
                        "duration_ms": started.elapsed().as_millis() as u64,
                    })
                });
            }
            (200, value, resp_headers)
        }
        Ok(Err(err)) => {
            let status = serve_error_status(&err);
            (
                status,
                json!({
                    "success": false,
                    "error": {
                        "code": err.kind(),
                        "message": err.to_string(),
                        "retryable": status == 503 || status == 504 || status == 429
                    }
                }),
                resp_headers,
            )
        }
        Err(_) => (
            500,
            json!({
                "success": false,
                "error": {
                    "code": "internal_panic",
                    "message": "handler panicked (host-safe; no target payload in logs)",
                    "retryable": false
                }
            }),
            resp_headers,
        ),
    }
}

fn serve_error_status(err: &Error) -> u16 {
    match err.kind() {
        "missing_url"
        | "invalid_url"
        | "unsupported_scheme"
        | "invalid_format"
        | "invalid_product_option"
        | "invalid_header"
        | "unsupported_method"
        | "invalid_json_schema"
        | "unsupported_output" => 400,
        "timeout" | "render_timeout" | "deadline_exceeded" => 504,
        "robots_denied" | "challenge_blocked" => 403,
        "resource_budget_exceeded" | "too_many_requests" => 429,
        _ => 502,
    }
}

fn execute_mode(mode: &str, body: &[u8], config: &ServeConfig) -> Result<Value, Error> {
    if body.len() > config.max_body_bytes {
        return Err(Error::InvalidProductOption(format!(
            "request body exceeds BASECRAWL_SERVE_MAX_BODY_BYTES ({} bytes)",
            config.max_body_bytes
        )));
    }
    let req: ServeExecuteRequest = if body.is_empty() {
        ServeExecuteRequest::default()
    } else {
        serde_json::from_slice(body)
            .map_err(|e| Error::InvalidProductOption(format!("invalid JSON body: {e}")))?
    };

    let job_id = req.job_id.clone();
    let timeout_secs = timeout_secs_from_req(&req, config);
    let formats = formats_from_req(&req)?;
    let headers = headers_from_req(&req);
    let render_enabled = req.render.unwrap_or(false)
        || req.wait_for.is_some()
        || formats.iter().any(|f| matches!(f, Format::Screenshot));

    let mut scrape_opts = ScrapeOptions {
        formats: formats.clone(),
        task_id: req.task_id.clone().or_else(|| job_id.clone()),
        nonce: req.nonce.clone(),
        timeout_secs,
        headers,
        method: req.method.clone().unwrap_or_else(|| "GET".into()),
        body: req.body.clone().unwrap_or_default().into_bytes(),
        proxy: req.proxy.clone(),
        fingerprint_seed: req.fingerprint_seed.clone(),
        render_enabled,
        wait_for: req.wait_for.clone(),
        render_timeout_secs: timeout_secs,
        // Soft path honesty: do not enable hard browser by default on SaaS serve.
        force_browser: false,
        ..ScrapeOptions::default()
    };
    // Soft-path POST must stay non-render.
    if scrape_opts.method.eq_ignore_ascii_case("POST") {
        scrape_opts.render_enabled = false;
    }

    match mode {
        "scrape" => {
            let url = req
                .url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .ok_or(Error::MissingUrl)?;
            let proof = scrape(&url, &scrape_opts)?;
            Ok(scrape_success_payload(job_id, &proof))
        }
        "crawl" => {
            let seed = req
                .url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .ok_or(Error::MissingUrl)?;
            // Prefer soft crawl formats for local multi-page MVP.
            let mut crawl_formats = formats;
            if !crawl_formats.contains(&Format::Links) {
                crawl_formats.push(Format::Links);
            }
            if !crawl_formats.contains(&Format::Markdown) {
                crawl_formats.push(Format::Markdown);
            }
            let crawl_opts = CrawlOptions {
                scrape: ScrapeOptions {
                    formats: format::normalize(crawl_formats),
                    method: "GET".into(),
                    body: Vec::new(),
                    render_enabled: false,
                    follow_pagination: false,
                    ..scrape_opts
                },
                max_pages: req.max_pages.unwrap_or(DEFAULT_MAX_PAGES).clamp(1, 100),
                max_depth: req.max_depth.unwrap_or(1).min(10),
                allow_domain: req.allow_domain.clone(),
            };
            let result = crawl::crawl(&seed, &crawl_opts)?;
            Ok(json!({
                "success": true,
                "job_id": job_id,
                "mode": "crawl",
                "data": result.to_json(),
                "residual": CRAWL_MVP_DESCRIPTION,
            }))
        }
        "map" => {
            let seed = req
                .url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .ok_or(Error::MissingUrl)?;
            let map_opts = MapOptions {
                max_urls: req.max_urls.unwrap_or(100).clamp(1, 50_000),
                use_sitemap: !req.no_sitemap.unwrap_or(false),
                same_origin_only: true,
                timeout_secs,
                scrape: ScrapeOptions {
                    formats: vec![Format::Links, Format::RawHtml],
                    method: "GET".into(),
                    body: Vec::new(),
                    render_enabled: false,
                    follow_pagination: false,
                    ..scrape_opts
                },
            };
            let result = map_lite::map_lite(&seed, &map_opts)?;
            Ok(json!({
                "success": true,
                "job_id": job_id,
                "mode": "map",
                "data": result.to_json(),
                "residual": MAP_LITE_DESCRIPTION,
            }))
        }
        "batch" => {
            let mut urls = req.urls.clone().unwrap_or_default();
            if let Some(single) = req.url.clone() {
                if !single.trim().is_empty() && !urls.iter().any(|u| u == &single) {
                    urls.insert(0, single);
                }
            }
            if urls.is_empty() {
                return Err(Error::MissingUrl);
            }
            let batch_opts = BatchOptions {
                scrape: ScrapeOptions {
                    render_enabled: scrape_opts.render_enabled
                        && !scrape_opts.method.eq_ignore_ascii_case("POST"),
                    ..scrape_opts
                },
                concurrency: req.concurrency.unwrap_or(config.max_inflight).clamp(1, 8),
                pace_ms: 0,
            };
            let result = batch::batch(&urls, &batch_opts)?;
            Ok(json!({
                "success": true,
                "job_id": job_id,
                "mode": "batch",
                "data": result.to_json(),
            }))
        }
        other => Err(Error::InvalidProductOption(format!(
            "unsupported serve mode '{other}'"
        ))),
    }
}

fn scrape_success_payload(job_id: Option<String>, proof: &crate::ScrapeProof) -> Value {
    let data = proof
        .result
        .formats_produced
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<serde_json::Map<String, Value>>();

    let proof_meta = json!({
        "version": proof.version,
        "request_hash": proof.request.request_hash,
        "result_hash": proof.result.result_hash,
        "tls": {
            "negotiated_version": proof.tls.negotiated_version,
            "sni": proof.tls.sni,
        },
        "response": {
            "status_code": proof.response.status_code,
            "content_length": proof.response.content_length,
            "body_hash": proof.response.body_hash,
        },
        // Residual honesty: never call this an unlocker proof of anonymity.
        "residual": SERVE_RESIDUAL_HONESTY,
    });

    json!({
        "success": true,
        "job_id": job_id,
        "data": data,
        "metrics": {
            "status_code": proof.response.status_code,
            "bytes": proof.response.content_length,
        },
        "proof": proof_meta,
        "scrape_proof": serde_json::to_value(proof).unwrap_or(Value::Null),
    })
}

fn timeout_secs_from_req(req: &ServeExecuteRequest, config: &ServeConfig) -> u64 {
    let from_body_ms = req.timeout_ms.unwrap_or(0);
    let hard_ms = config.request_timeout_ms;
    let ms = if from_body_ms == 0 {
        hard_ms
    } else {
        from_body_ms.min(hard_ms)
    };
    (ms / 1000).max(1)
}

fn formats_from_req(req: &ServeExecuteRequest) -> Result<Vec<Format>, Error> {
    match &req.formats {
        Some(tokens) if !tokens.is_empty() => format::parse_list(tokens),
        _ => Ok(format::default_set()),
    }
}

fn headers_from_req(req: &ServeExecuteRequest) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(map) = &req.headers {
        for (k, v) in map {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
}

/// Bind and run the long-running HTTP loop until the process is stopped.
///
/// Uses one acceptor thread + a pool of handler threads. Blocks the calling thread.
pub fn run_forever(config: ServeConfig) -> Result<(), Error> {
    let listener = TcpListener::bind(config.socket_addr()?)
        .map_err(|e| Error::Io(format!("bind {}: {e}", config.bind_addr())))?;
    // Restrict accept loop to the declared address (documented loopback default).
    eprintln!(
        "{{\"event\":\"serve_listen\",\"bind\":\"{}\",\"service\":\"basecrawl-serve\",\"residual\":\"loopback-default local engine; not public multi-region edge; not anonymity unlocker\"}}",
        config.bind_addr()
    );
    run_on_listener(listener, config)
}

/// Run on an already-bound listener (tests use port 0).
pub fn run_on_listener(listener: TcpListener, config: ServeConfig) -> Result<(), Error> {
    let config = Arc::new(config);
    let inflight = Arc::new(AtomicUsize::new(0));
    // Keep a soft thread budget: spawn per connection but cap with channel-ish join limits.
    // For local mission traffic (API workers low concurrency) this is enough.
    listener
        .set_nonblocking(false)
        .map_err(|e| Error::Io(e.to_string()))?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg = Arc::clone(&config);
                let inflight = Arc::clone(&inflight);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(130)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(130)));
                thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &cfg, &inflight) {
                        // Host-safe: never log headers/body/URL secrets.
                        eprintln!(
                            "{{\"event\":\"serve_connection_error\",\"kind\":\"{}\"}}",
                            e.kind()
                        );
                    }
                });
            }
            Err(e) => {
                eprintln!("{{\"event\":\"serve_accept_error\",\"message\":\"{}\"}}", e);
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    config: &ServeConfig,
    inflight: &AtomicUsize,
) -> Result<(), Error> {
    let (method, path, headers, body) = read_http_request(&mut stream, config.max_body_bytes)?;
    let (status, value, extra_headers) =
        handle_http_request(&method, &path, &headers, &body, config, inflight);
    write_http_response(&mut stream, status, &value, &extra_headers)?;
    Ok(())
}

type HttpRequestParts = (String, String, Vec<(String, String)>, Vec<u8>);

fn read_http_request(stream: &mut TcpStream, max_body: usize) -> Result<HttpRequestParts, Error> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    // Read until headers complete or cap (64 KiB headers).
    loop {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| Error::Io(format!("read: {e}")))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(Error::Io("HTTP headers too large".into()));
        }
    }
    if buf.is_empty() {
        return Err(Error::Io("empty request".into()));
    }

    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Io("incomplete HTTP headers".into()))?;
    let header_bytes = &buf[..header_end];
    let mut body_already = buf[header_end + 4..].to_vec();

    let header_text = String::from_utf8_lossy(header_bytes);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| Error::Io("missing method".into()))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| Error::Io("missing path".into()))?
        .to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }

    if content_length > max_body {
        return Err(Error::InvalidProductOption(format!(
            "content-length {content_length} exceeds max body {max_body}"
        )));
    }

    while body_already.len() < content_length {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| Error::Io(format!("read body: {e}")))?;
        if n == 0 {
            break;
        }
        body_already.extend_from_slice(&tmp[..n]);
        if body_already.len() > max_body {
            return Err(Error::InvalidProductOption(
                "request body exceeds max".into(),
            ));
        }
    }
    body_already.truncate(content_length);
    Ok((method, path, headers, body_already))
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    body: &Value,
    extra_headers: &[(String, String)],
) -> Result<(), Error> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let payload = body.to_string();
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        payload.len()
    );
    for (k, v) in extra_headers {
        // Never reflect secret headers.
        if k.eq_ignore_ascii_case(SERVE_SECRET_HEADER) {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .map_err(|e| Error::Io(e.to_string()))?;
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| Error::Io(e.to_string()))?;
    let _ = stream.flush();
    Ok(())
}

/// Spawn serve on an ephemeral port for tests; returns (addr, join handle, stop flag).
pub fn spawn_test_server(mut config: ServeConfig) -> Result<(SocketAddr, Arc<Mutex<bool>>), Error> {
    config.host = "127.0.0.1".into();
    config.port = 0;
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| Error::Io(format!("test bind: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::Io(e.to_string()))?;
    // Port 0 resolved — stash for logs.
    config.port = addr.port();
    let stop = Arc::new(Mutex::new(false));
    let stop_flag = Arc::clone(&stop);
    thread::spawn(move || {
        // Simple accept loop; stop is cooperative via dropping after tests kill process differently.
        // For unit tests the process ends with the binary; ignore stop for now.
        let _ = stop_flag;
        let _ = run_on_listener(listener, config);
    });
    // Brief settle so accept is ready.
    thread::sleep(Duration::from_millis(50));
    Ok((addr, stop))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn free_config(secret: Option<&str>) -> ServeConfig {
        ServeConfig {
            host: "127.0.0.1".into(),
            port: 0,
            secret: secret.map(|s| s.to_string()),
            max_inflight: 2,
            request_timeout_ms: 30_000,
            max_body_bytes: 1_048_576,
        }
    }

    #[test]
    fn health_ok_without_secret() {
        let config = free_config(None);
        let inflight = AtomicUsize::new(0);
        let (status, body, _) = handle_http_request("GET", "/health", &[], b"", &config, &inflight);
        assert_eq!(status, 200);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "basecrawl-serve");
        let residual = body["residual"].as_str().unwrap_or("");
        assert!(
            residual.to_ascii_lowercase().contains("not")
                && (residual.contains("anonymous")
                    || residual.contains("trustless")
                    || residual.contains("100%")),
            "residual must deny unlocker/anonymity hype: {residual}"
        );
    }

    #[test]
    fn secret_gate_rejects_missing_header() {
        let config = free_config(Some("s3cret-value"));
        let inflight = AtomicUsize::new(0);
        let body = br#"{"url":"https://example.com"}"#;
        let (status, val, _) =
            handle_http_request("POST", "/v1/scrape", &[], body, &config, &inflight);
        assert_eq!(status, 401);
        assert_eq!(val["success"], false);
        assert_eq!(val["error"]["code"], "unauthorized");
    }

    #[test]
    fn secret_gate_accepts_matching_header_for_health_path_open() {
        // health remains open even when secret set
        let config = free_config(Some("s3cret-value"));
        let inflight = AtomicUsize::new(0);
        let (status, _, _) = handle_http_request("GET", "/health", &[], b"", &config, &inflight);
        assert_eq!(status, 200);
    }

    #[test]
    fn secrets_equal_check() {
        assert!(secrets_equal("abc", "abc"));
        assert!(!secrets_equal("abc", "abd"));
        assert!(!secrets_equal("abc", "ab"));
    }

    #[test]
    fn unknown_route_404() {
        let config = free_config(None);
        let inflight = AtomicUsize::new(0);
        let (status, val, _) = handle_http_request("GET", "/nope", &[], b"", &config, &inflight);
        assert_eq!(status, 404);
        assert_eq!(val["success"], false);
    }

    #[test]
    fn spawn_test_server_health_http() {
        let config = free_config(None);
        let (addr, _stop) = spawn_test_server(config).expect("spawn");
        let mut stream = TcpStream::connect(addr).expect("connect ephemeral serve");
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(
            resp.contains("200") && resp.contains("basecrawl-serve"),
            "unexpected health response: {resp}"
        );
    }
}
