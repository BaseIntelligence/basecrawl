//! Hard Chromium path: CapSolver solve-or-block (M23 / VAL-SOLVE-007 / VAL-HARD-003 /
//! VAL-CROSS-HARD-001 / VAL-CROSS-HARD-006).
//!
//! Hermetic only: mission ports 21000–21099, mock CapSolver + challenge canaries.
//! Never requires live CAPSOLVER_API_KEY balance. Soft CI stays green without keys.

use basecrawl_core::captcha_solver::{
    armed_solver_apply_actions, human_like_pacing_delays, residual_after_applied_token,
    turnstile_token_inject_expression, CAPSOLVER_API_BASE_ENV, CAPSOLVER_API_KEY_ENV,
    CAPTCHA_SOLVER_ENV, HUMAN_PACE_HONESTY,
};
use basecrawl_core::proxy::{ComposerOriginDialer, ProxyConfig, UsernameTemplateOptions};
use basecrawl_seal::{
    NameResolver, OriginDialer, ResolverEndpoint, SealError, SealedSocksProxy, DEFAULT_DOH_ENDPOINT,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const SECRET_KEY: &str = "CAP-HARDPATH-HERMETIC-KEY-000000000000001";
const SECRET_PROXY_PASSWORD: &str = "xstealth-solvemock-pxy-9f1d4c";

fn bind_mission_port() -> TcpListener {
    for port in 21050u16..=21099 {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            let _ = l.set_nonblocking(true);
            return l;
        }
    }
    panic!("no free mission port in 21050-21099");
}

fn strip_solver_env(cmd: &mut Command) {
    for key in [
        "CAPSOLVER_API_KEY",
        "BASECRAWL_CAPSOLVER_API_KEY",
        "BASECRAWL_CAPTCHA_SOLVER",
        "BASECRAWL_CAPSOLVER_API_BASE",
        "BASECRAWL_LIVE_PROXY",
        "BASECRAWL_HTTP_PROXY",
        "BASECRAWL_HTTPS_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "TWOCAPTCHA_API_KEY",
        "ANTICAPTCHA_API_KEY",
        "BASECRAWL_COMPOSER_FAIL_START",
    ] {
        cmd.env_remove(key);
    }
}

fn run_cli_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    strip_solver_env(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn basecrawl")
}

fn err_kind(out: &Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr);
    if let Some(idx) = stderr.find('{') {
        if let Ok(v) = serde_json::from_str::<Value>(&stderr[idx..]) {
            if let Some(k) = v["error"]["kind"].as_str() {
                return k.to_string();
            }
        }
    }
    stderr.to_string()
}

fn spawn_html_origin(body: &str, status_line: &str) -> String {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let body = body.to_string();
    let status = status_line.to_string();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.read(&mut buf);
                let _ = write!(
                    stream,
                    "{status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    format!("http://{addr}/challenge")
}

fn turnstile_canary_html() -> &'static str {
    r##"<!doctype html>
<html data-basecrawl-canary-unlock="1">
<head><title>challenge canary</title></head>
<body>
  <div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>
  <form id="captcha-form" data-basecrawl-captcha-form="1">verify you are human</form>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
</body>
</html>"##
}

fn cf_managed_html() -> &'static str {
    r#"<!doctype html><html><head><title>Just a moment...</title></head>
<body><span>cloudflare</span> challenge-platform Checking your Browser</body></html>"#
}

/// Minimal CapSolver createTask / getTaskResult mock (mission ports).
struct CapSolverMock {
    addr: String,
    create_count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl CapSolverMock {
    fn start(force_empty_token: bool, force_auth_error: bool) -> Self {
        let listener = bind_mission_port();
        let addr = listener.local_addr().expect("addr");
        let create_count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let cc = Arc::clone(&create_count);
        let stop_t = Arc::clone(&stop);
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(90);
            while Instant::now() < deadline && !stop_t.load(Ordering::SeqCst) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = vec![0u8; 16384];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.lines().next().unwrap_or("");
                    let (status, payload) = if path.contains("createTask") {
                        cc.fetch_add(1, Ordering::SeqCst);
                        if force_auth_error {
                            (
                                "HTTP/1.1 401 Unauthorized",
                                json!({
                                    "errorId": 1,
                                    "errorCode": "ERROR_KEY_DENIED",
                                    "errorDescription": "invalid key"
                                }),
                            )
                        } else {
                            (
                                "HTTP/1.1 200 OK",
                                json!({"errorId": 0, "taskId": "hardpath-task-1"}),
                            )
                        }
                    } else if path.contains("getTaskResult") {
                        let token = if force_empty_token {
                            ""
                        } else {
                            "tok-hardpath-applied-xyz"
                        };
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "errorId": 0,
                                "status": "ready",
                                "taskId": "hardpath-task-1",
                                "solution": { "token": token, "type": "turnstile" }
                            }),
                        )
                    } else {
                        (
                            "HTTP/1.1 404 Not Found",
                            json!({"errorId": 1, "errorCode": "NOT_FOUND"}),
                        )
                    };
                    let raw = payload.to_string();
                    let _ = write!(
                        stream,
                        "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{raw}",
                        raw.len()
                    );
                } else {
                    thread::sleep(Duration::from_millis(5));
                }
            }
        });
        Self {
            addr: format!("http://{addr}"),
            create_count,
            stop,
        }
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Unit-level apply/pacing residual honesty
// ---------------------------------------------------------------------------

#[test]
fn val_solve_007_empty_token_and_no_apply_refuse_forge() {
    assert!(turnstile_token_inject_expression("").is_err());
    assert!(armed_solver_apply_actions("", 1).is_err());
    assert!(human_like_pacing_delays(false, 1).is_empty());
    assert!(!human_like_pacing_delays(true, 1).is_empty());
    let residual = residual_after_applied_token(
        r#"<html><body class="cf-turnstile">verify you are human</body></html>"#,
        403,
        "t",
    )
    .expect("unapplied");
    assert_ne!(residual.kind(), "ok");
    let honesty = HUMAN_PACE_HONESTY.to_ascii_lowercase();
    assert!(honesty.contains("not") || honesty.contains("do not claim"));
    assert!(!honesty.contains("100% guaranteed"));
}

// ---------------------------------------------------------------------------
// VAL-HARD-003 force-browser finite challenge residual (no hang, no content_success)
// ---------------------------------------------------------------------------

#[test]
fn val_hard_003_force_browser_challenge_finite_non_success() {
    let url = spawn_html_origin(turnstile_canary_html(), "HTTP/1.1 403 Forbidden");
    let start = Instant::now();
    let out = run_cli_env(
        &[
            &url,
            "--formats",
            "html,markdown",
            "--force-browser",
            "--difficulty",
            "hard",
            "--robots",
            "ignore",
            "--timeout",
            "45",
            "--render-timeout",
            "25",
        ],
        &[],
    );
    assert!(
        start.elapsed() < Duration::from_secs(50),
        "force-browser must terminate finite; elapsed={:?}",
        start.elapsed()
    );
    assert!(
        !out.status.success(),
        "must not silent-success on challenge"
    );
    let kind = err_kind(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        kind == "challenge_blocked"
            || stderr.contains("challenge_blocked")
            || stderr.contains("challenge"),
        "expected challenge residual; kind={kind} stderr={stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    if let Ok(v) = serde_json::from_str::<Value>(&stdout) {
        let md = v["result"]["formats_produced"]["markdown"]
            .as_str()
            .unwrap_or("");
        assert!(
            !md.contains("unlocked-content-basecrawl"),
            "without solver must not unlock canary content"
        );
    }
}

// ---------------------------------------------------------------------------
// VAL-SOLVE-007 solver present but empty/error: typed residual, no content_success
// ---------------------------------------------------------------------------

#[test]
fn val_solve_007_mock_empty_token_cli_fail_closed() {
    let mock = CapSolverMock::start(true, false);
    let url = spawn_html_origin(turnstile_canary_html(), "HTTP/1.1 403 Forbidden");
    let out = run_cli_env(
        &[
            &url,
            "--formats",
            "html",
            "--force-browser",
            "--difficulty",
            "hard",
            "--captcha-solver",
            "capsolver",
            "--robots",
            "ignore",
            "--timeout",
            "45",
            "--render-timeout",
            "20",
            "--captcha-solve-timeout",
            "15",
        ],
        &[
            (CAPSOLVER_API_KEY_ENV, SECRET_KEY),
            (CAPTCHA_SOLVER_ENV, "capsolver"),
            (CAPSOLVER_API_BASE_ENV, &mock.addr),
        ],
    );
    mock.stop();
    assert!(!out.status.success());
    let kind = err_kind(&out);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!combined.contains(SECRET_KEY));
    assert!(
        kind == "solver_error"
            || kind == "solver_auth_error"
            || kind == "solver_apply_failed"
            || kind == "challenge_blocked"
            || combined.contains("solver"),
        "empty token must fail closed typed residual; kind={kind}"
    );
    assert!(!combined.contains("unlocked-content-basecrawl"));
    assert!(mock.create_count.load(Ordering::SeqCst) >= 1);
}

#[test]
fn val_solve_007_mock_auth_fail_closed() {
    let mock = CapSolverMock::start(false, true);
    let url = spawn_html_origin(turnstile_canary_html(), "HTTP/1.1 403 Forbidden");
    let out = run_cli_env(
        &[
            &url,
            "--formats",
            "html",
            "--force-browser",
            "--difficulty",
            "hard",
            "--captcha-solver",
            "capsolver",
            "--robots",
            "ignore",
            "--timeout",
            "45",
            "--render-timeout",
            "20",
            "--captcha-solve-timeout",
            "10",
        ],
        &[
            (CAPSOLVER_API_KEY_ENV, SECRET_KEY),
            (CAPSOLVER_API_BASE_ENV, &mock.addr),
        ],
    );
    mock.stop();
    assert!(!out.status.success());
    let kind = err_kind(&out);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!combined.contains(SECRET_KEY));
    assert_eq!(kind, "solver_auth_error");
    assert!(mock.create_count.load(Ordering::SeqCst) >= 1);
}

// ---------------------------------------------------------------------------
// Armed path: solve + apply + unlock canary (ordering proof for content_success)
// ---------------------------------------------------------------------------

#[test]
fn val_solve_armed_solve_inject_unlocks_canary_only_with_token() {
    let mock = CapSolverMock::start(false, false);
    let url = spawn_html_origin(turnstile_canary_html(), "HTTP/1.1 200 OK");
    let out = run_cli_env(
        &[
            &url,
            "--formats",
            "html,markdown",
            "--force-browser",
            "--difficulty",
            "hard",
            "--captcha-solver",
            "capsolver",
            "--robots",
            "ignore",
            "--timeout",
            "60",
            "--render-timeout",
            "30",
            "--captcha-solve-timeout",
            "20",
        ],
        &[
            (CAPSOLVER_API_KEY_ENV, SECRET_KEY),
            (CAPSOLVER_API_BASE_ENV, &mock.addr),
            (CAPTCHA_SOLVER_ENV, "capsolver"),
        ],
    );
    mock.stop();
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!combined.contains(SECRET_KEY), "key must never leak");
    assert!(
        mock.create_count.load(Ordering::SeqCst) >= 1,
        "createTask must run when armed"
    );
    assert!(
        out.status.success(),
        "armed canary unlock should succeed after applied token; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let proof: Value = serde_json::from_slice(&out.stdout).expect("proof json");
    let html = proof["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap_or("");
    let md = proof["result"]["formats_produced"]["markdown"]
        .as_str()
        .unwrap_or("");
    assert!(
        html.contains("unlocked-content-basecrawl")
            || html.contains("data-basecrawl-content-unlocked")
            || md.contains("unlocked-content-basecrawl"),
        "applied solution must surface unlocked primary content"
    );
}

// ---------------------------------------------------------------------------
// Unsupported CF managed class remains detect-not-solve even with key (no forge)
// ---------------------------------------------------------------------------

#[test]
fn val_solve_cf_managed_with_key_still_blocked() {
    let mock = CapSolverMock::start(false, false);
    let url = spawn_html_origin(cf_managed_html(), "HTTP/1.1 403 Forbidden");
    let out = run_cli_env(
        &[
            &url,
            "--formats",
            "html",
            "--force-browser",
            "--difficulty",
            "hard",
            "--captcha-solver",
            "capsolver",
            "--robots",
            "ignore",
            "--timeout",
            "40",
            "--render-timeout",
            "20",
        ],
        &[
            (CAPSOLVER_API_KEY_ENV, SECRET_KEY),
            (CAPSOLVER_API_BASE_ENV, &mock.addr),
        ],
    );
    mock.stop();
    assert!(!out.status.success());
    let kind = err_kind(&out);
    assert!(
        kind == "challenge_blocked" || kind == "solver_unsupported",
        "unsupported CF shell must fail closed; kind={kind}"
    );
    assert_eq!(
        mock.create_count.load(Ordering::SeqCst),
        0,
        "unsupported class must not createTask"
    );
}

// ---------------------------------------------------------------------------
// VAL-CROSS-HARD-001 + 006: residential Chromium composer DoH + sticky hops
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct StickyLog {
    hops: Vec<StickyHop>,
    session_map: HashMap<String, String>,
    next_hop: u32,
}

#[derive(Debug, Clone)]
struct StickyHop {
    session: Option<String>,
    hop_id: String,
    target: String,
}

fn decode_basic_auth(header_value: &str) -> Option<(String, String)> {
    use base64::Engine;
    let raw = header_value
        .strip_prefix("Basic ")
        .or_else(|| header_value.strip_prefix("basic "))?
        .trim();
    let decoded = base64::engine::general_purpose::STANDARD.decode(raw).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

fn parse_session(username: &str) -> Option<String> {
    // Match proxy_composer_chromium: full session token may itself contain hyphens
    // (e.g. HARD-MULTI-S1, HARD-DOH-S1). Cut only at known subsequent provider markers.
    username
        .split("-sessid-")
        .nth(1)
        .map(|rest| {
            rest.split('-')
                .take_while(|p| !p.eq_ignore_ascii_case("cc") && !p.eq_ignore_ascii_case("sessid"))
                .collect::<Vec<_>>()
                .join("-")
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

fn spawn_sticky_tunnel_mock() -> (String, Arc<Mutex<StickyLog>>, Arc<AtomicBool>) {
    let listener = bind_mission_port();
    let addr = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(StickyLog::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let log_t = Arc::clone(&log);
    let stop_t = Arc::clone(&stop);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline && !stop_t.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut client, _)) => {
                    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = client.set_write_timeout(Some(Duration::from_secs(5)));
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1];
                    let hdr_deadline = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < hdr_deadline {
                        match client.read(&mut tmp) {
                            Ok(0) => break,
                            Ok(_) => {
                                buf.push(tmp[0]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                                if buf.len() > 16 * 1024 {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let req = String::from_utf8_lossy(&buf);
                    let first = req.lines().next().unwrap_or("");
                    let mut parts = first.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    let target = parts.next().unwrap_or("").to_string();
                    if method != "CONNECT" {
                        let _ = client.write_all(
                            b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n",
                        );
                        continue;
                    }
                    let (host, port) = match target.rsplit_once(':') {
                        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(0)),
                        None => (target.clone(), 0),
                    };
                    let auth_header = req
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:"))
                        .map(|l| {
                            l.split_once(':')
                                .map(|(_, v)| v.trim().to_string())
                                .unwrap_or_default()
                        });
                    let presented = auth_header.as_ref().and_then(|h| decode_basic_auth(h));
                    if let Some((_u, p)) = &presented {
                        if p != SECRET_PROXY_PASSWORD {
                            let _ = client.write_all(
                                b"HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n",
                            );
                            continue;
                        }
                    }
                    let username = presented
                        .as_ref()
                        .map(|(u, _)| u.clone())
                        .unwrap_or_default();
                    let session = parse_session(&username);
                    let hop_id = {
                        let mut g = log_t.lock().expect("log");
                        let hop = if let Some(sess) = session.as_ref() {
                            if let Some(existing) = g.session_map.get(sess) {
                                existing.clone()
                            } else {
                                g.next_hop += 1;
                                let hop = format!("203.0.113.{}", g.next_hop);
                                g.session_map.insert(sess.clone(), hop.clone());
                                hop
                            }
                        } else {
                            g.next_hop += 1;
                            format!("198.51.100.{}", g.next_hop)
                        };
                        g.hops.push(StickyHop {
                            session: session.clone(),
                            hop_id: hop.clone(),
                            target: target.clone(),
                        });
                        hop
                    };
                    let target_stream = match TcpStream::connect((host.as_str(), port)) {
                        Ok(s) => s,
                        Err(_) => {
                            let _ = client.write_all(
                                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
                            );
                            continue;
                        }
                    };
                    let _ = write!(
                        client,
                        "HTTP/1.1 200 Connection Established\r\nX-Mock-Exit-Hop: {hop_id}\r\n\r\n"
                    );
                    let _ = client.set_nonblocking(false);
                    let _ = target_stream.set_nonblocking(false);
                    let mut c = client;
                    let mut t = target_stream;
                    let mut c2 = c.try_clone().ok();
                    let mut t2 = t.try_clone().ok();
                    let th = thread::spawn(move || {
                        if let (Some(mut a), Some(mut b)) = (c2.take(), t2.take()) {
                            let _ = std::io::copy(&mut a, &mut b);
                        }
                    });
                    let _ = std::io::copy(&mut t, &mut c);
                    let _ = th.join();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}"), log, stop)
}

fn multipage_canary_origin() -> String {
    let listener = bind_mission_port();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/");
                let body = if path.contains("page2") {
                    b"<!doctype html><html><body><h1 id='page-b'>page-B-ok</h1>\
                      <div id='stealth-canary'>inject-coherent</div></body></html>"
                        .to_vec()
                } else {
                    format!(
                        "<!doctype html><html><body><h1 id='page-a'>page-A-ok</h1>\
                         <a rel='next' href='http://{addr}/page2'>next</a>\
                         <div id='stealth-canary'>inject-coherent</div></body></html>"
                    )
                    .into_bytes()
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(&body);
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    format!("http://{addr}/page1")
}

#[test]
fn val_cross_hard_001_sealed_doh_connect_by_ip() {
    // Composer sealed DoH → CONNECT by IP (confidential origin QNAME never on host DNS path;
    // commercial mock sees IP:port only).
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_addr = upstream.local_addr().unwrap();
    let up_thread = thread::spawn(move || {
        if let Ok((mut s, _)) = upstream.accept() {
            let mut buf = [0u8; 64];
            if let Ok(n) = s.read(&mut buf) {
                let _ = s.write_all(&buf[..n]);
            }
        }
    });
    let (proxy_base, log, stop) = spawn_sticky_tunnel_mock();
    let cfg = ProxyConfig::parse(&format!(
        "http://customer-USER:{SECRET_PROXY_PASSWORD}@{}",
        proxy_base.trim_start_matches("http://")
    ))
    .unwrap()
    .with_username_template(&UsernameTemplateOptions {
        country: Some("US".into()),
        session: Some("HARD-DOH-S1".into()),
        template: None,
    })
    .unwrap();

    struct Fixed(IpAddr);
    impl NameResolver for Fixed {
        fn resolve_host(
            &self,
            host: &str,
            port: u16,
            _deadline: Instant,
        ) -> Result<Vec<SocketAddr>, SealError> {
            assert_eq!(host, "confid-hardpath-target.basecrawl.test");
            Ok(vec![SocketAddr::new(self.0, port)])
        }
        fn endpoint(&self) -> &ResolverEndpoint {
            &DEFAULT_DOH_ENDPOINT
        }
    }

    let dialer: Arc<dyn OriginDialer> = Arc::new(ComposerOriginDialer::new(cfg));
    let composer =
        SealedSocksProxy::start_composed(Arc::new(Fixed(IpAddr::V4(Ipv4Addr::LOCALHOST))), dialer)
            .expect("composed socks");

    let mut client = TcpStream::connect(composer.addr()).unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp, [0x05, 0x00]);
    let host = b"confid-hardpath-target.basecrawl.test";
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host);
    req.extend_from_slice(&up_addr.port().to_be_bytes());
    client.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(
        reply[1], 0x00,
        "composed CONNECT must succeed after sealed DoH pin"
    );
    client.write_all(b"ping-hardpath-doh").unwrap();
    let mut echo = [0u8; 64];
    let n = client.read(&mut echo).expect("echo");
    assert_eq!(&echo[..n], b"ping-hardpath-doh");
    let _ = up_thread.join();
    stop.store(true, Ordering::SeqCst);

    let g = log.lock().unwrap();
    assert!(!g.hops.is_empty(), "commercial mock must see CONNECT hop");
    assert!(
        g.hops[0].target.starts_with("127.0.0.1:") || g.hops[0].target.starts_with("[::1]:"),
        "CONNECT after sealed DoH must target IP not QNAME, got {}",
        g.hops[0].target
    );
    assert_eq!(g.hops[0].session.as_deref(), Some("HARD-DOH-S1"));
}

#[test]
fn val_cross_hard_006_sticky_multipage_hop_identity() {
    // Same-session multipage must preserve sticky hop under residential composer path.
    let origin = multipage_canary_origin();
    let (proxy_base, log, stop) = spawn_sticky_tunnel_mock();
    let proxy = format!(
        "http://customer-USER:{SECRET_PROXY_PASSWORD}@{}",
        proxy_base.trim_start_matches("http://")
    );
    let out = run_cli_env(
        &[
            &origin,
            "--proxy",
            &proxy,
            "--proxy-session",
            "HARD-MULTI-S1",
            "--proxy-country",
            "US",
            "--proxy-class",
            "residential",
            "--robots",
            "ignore",
            "--formats",
            "html,markdown",
            "--follow-pagination",
            "--max-pages",
            "2",
            "--timeout",
            "70",
            "--render-timeout",
            "35",
            "--actions",
            r#"[{"type":"wait","milliseconds":80}]"#,
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!combined.contains(SECRET_PROXY_PASSWORD));
    assert!(!combined.contains(SECRET_KEY));

    let g = log.lock().expect("log");
    assert!(
        !g.hops.is_empty(),
        "residential multipage must dial CONNECT hops, status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let multipage_hops: Vec<_> = g
        .hops
        .iter()
        .filter(|h| h.session.as_deref() == Some("HARD-MULTI-S1"))
        .collect();
    assert!(
        multipage_hops.len() >= 2,
        "expect multi CONNECT under multipage sticky, got {}, log={g:?}",
        multipage_hops.len()
    );
    let first = multipage_hops[0].hop_id.clone();
    for hop in &multipage_hops {
        assert_eq!(
            hop.hop_id, first,
            "sticky session must not rotate mid multipage; log={g:?}"
        );
    }
    if out.status.success() {
        let proof: Value = serde_json::from_slice(&out.stdout).expect("proof");
        let html = proof["result"]["formats_produced"]["html"]
            .as_str()
            .unwrap_or("");
        assert!(
            html.contains("inject-coherent") || html.contains("page-"),
            "multipage content present"
        );
    }
}
