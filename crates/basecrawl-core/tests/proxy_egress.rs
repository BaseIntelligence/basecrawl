//! Universal proxy foundation hermetic matrix (VAL-PROXY-001..009, 020, 023, 024).
//!
//! All fixtures listen on mission-safe loopback ports in **21000–21099**. Live residential is
//! never required (`BASECRAWL_LIVE_PROXY` remains unset). Credentials stay out of ScrapeProof and
//! host-visible stderr.

use base64::Engine;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

/// High-entropy proxy password used only for redaction + auth checks (never Oxylabs).
const SECRET_PASSWORD: &str = "pxy-secret-VALPROXY023-9f3a2c7e1b44";
const SECRET_USER: &str = "mockuser";

/// Bind a free port inside the mission mock range 21000–21099.
fn bind_mission_port() -> TcpListener {
    for port in 21000u16..=21099 {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            listener
                .set_nonblocking(true)
                .expect("set nonblocking mock listener");
            return listener;
        }
    }
    panic!("no free mock proxy port in 21000-21099");
}

fn run_proxy_scrape(args: &[&str], env: &[(&str, Option<&str>)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    // Ensure live gate off and clear ambient proxy pollution between cases.
    cmd.env_remove("BASECRAWL_LIVE_PROXY");
    for key in [
        "BASECRAWL_HTTP_PROXY",
        "BASECRAWL_HTTPS_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        cmd.env_remove(key);
    }
    for (k, v) in env {
        match v {
            Some(val) => {
                cmd.env(k, val);
            }
            None => {
                cmd.env_remove(k);
            }
        }
    }
    cmd.output().expect("spawn basecrawl")
}

fn origin_fixture() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_t = Arc::clone(&hits);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    hits_t.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let body = b"<!doctype html><html><body>proxy-origin-ok</body></html>";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(body);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}/proxy-origin"), hits)
}

#[derive(Default, Debug)]
struct HopLog {
    connects: Vec<(String, u16)>,
    auths: Vec<String>, // usernames that presented a password/auth material
    auth_ok: usize,
    auth_fail: usize,
}

fn spawn_http_connect_mock(
    require_auth: bool,
    expected_user: Option<&str>,
    expected_pass: Option<&str>,
) -> (String, String, Arc<Mutex<HopLog>>, Arc<AtomicBool>) {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let log = Arc::new(Mutex::new(HopLog::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let log_t = Arc::clone(&log);
    let stop_t = Arc::clone(&stop);
    let expected_user = expected_user.map(str::to_string);
    let expected_pass = expected_pass.map(str::to_string);
    thread::spawn(move || {
        while !stop_t.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut client, _)) => {
                    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = client.set_write_timeout(Some(Duration::from_secs(5)));
                    handle_http_connect(
                        &mut client,
                        require_auth,
                        expected_user.as_deref(),
                        expected_pass.as_deref(),
                        &log_t,
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (
        format!("http://{addr}"),
        format!("https://{addr}"),
        log,
        stop,
    )
}

fn handle_http_connect(
    client: &mut TcpStream,
    require_auth: bool,
    expected_user: Option<&str>,
    expected_pass: Option<&str>,
    log: &Arc<Mutex<HopLog>>,
) {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1];
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match client.read(&mut tmp) {
            Ok(0) => return,
            Ok(_) => {
                buf.push(tmp[0]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 16 * 1024 {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    let req = String::from_utf8_lossy(&buf);
    let first = req.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "CONNECT" {
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
        return;
    }
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(0)),
        None => (target.to_string(), 0),
    };
    {
        let mut g = log.lock().expect("log");
        g.connects.push((host.clone(), port));
    }

    let auth_header = req
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:"))
        .map(|l| {
            l.split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default()
        });

    let presented = auth_header.as_ref().and_then(|h| decode_basic_auth(h));
    if let Some((u, has_pass)) = presented.as_ref().map(|(u, p)| (u.clone(), !p.is_empty())) {
        let mut g = log.lock().expect("log");
        if has_pass {
            g.auths.push(u);
        }
    }

    if require_auth {
        match (presented, expected_user, expected_pass) {
            (Some((u, p)), Some(eu), Some(ep)) if u == eu && p == ep => {
                log.lock().expect("log").auth_ok += 1;
            }
            _ => {
                log.lock().expect("log").auth_fail += 1;
                let _ = client.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"mock\"\r\n\
                      Connection: close\r\n\r\n",
                );
                return;
            }
        }
    }

    let target_stream = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let _ = client.set_nonblocking(false);
    let _ = target_stream.set_nonblocking(false);
    relay(client, target_stream);
}

fn decode_basic_auth(header: &str) -> Option<(String, String)> {
    let mut parts = header.split_whitespace();
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let token = parts.next()?;
    let raw = base64::prelude::BASE64_STANDARD.decode(token).ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (u, p) = text.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

fn spawn_socks5_mock(
    require_auth: bool,
    expected_user: Option<&str>,
    expected_pass: Option<&str>,
) -> (String, Arc<Mutex<HopLog>>, Arc<AtomicBool>) {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let log = Arc::new(Mutex::new(HopLog::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let log_t = Arc::clone(&log);
    let stop_t = Arc::clone(&stop);
    let expected_user = expected_user.map(str::to_string);
    let expected_pass = expected_pass.map(str::to_string);
    thread::spawn(move || {
        while !stop_t.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut client, _)) => {
                    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = client.set_write_timeout(Some(Duration::from_secs(5)));
                    handle_socks5(
                        &mut client,
                        require_auth,
                        expected_user.as_deref(),
                        expected_pass.as_deref(),
                        &log_t,
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (format!("socks5://{addr}"), log, stop)
}

fn handle_socks5(
    client: &mut TcpStream,
    require_auth: bool,
    expected_user: Option<&str>,
    expected_pass: Option<&str>,
    log: &Arc<Mutex<HopLog>>,
) {
    let mut head = [0u8; 2];
    if client.read_exact(&mut head).is_err() || head[0] != 0x05 {
        return;
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if client.read_exact(&mut methods).is_err() {
        return;
    }
    if require_auth {
        if !methods.contains(&0x02) {
            let _ = client.write_all(&[0x05, 0xFF]);
            return;
        }
        let _ = client.write_all(&[0x05, 0x02]);
        // username/password subnegotiation
        let mut ver = [0u8; 1];
        if client.read_exact(&mut ver).is_err() || ver[0] != 0x01 {
            return;
        }
        let mut ulen = [0u8; 1];
        if client.read_exact(&mut ulen).is_err() {
            return;
        }
        let mut user = vec![0u8; ulen[0] as usize];
        if client.read_exact(&mut user).is_err() {
            return;
        }
        let mut plen = [0u8; 1];
        if client.read_exact(&mut plen).is_err() {
            return;
        }
        let mut pass = vec![0u8; plen[0] as usize];
        if client.read_exact(&mut pass).is_err() {
            return;
        }
        let u = String::from_utf8_lossy(&user).into_owned();
        let p = String::from_utf8_lossy(&pass).into_owned();
        {
            let mut g = log.lock().expect("log");
            if !p.is_empty() {
                g.auths.push(u.clone());
            }
        }
        let ok = expected_user.map(|eu| eu == u).unwrap_or(true)
            && expected_pass.map(|ep| ep == p).unwrap_or(true);
        if ok {
            log.lock().expect("log").auth_ok += 1;
            let _ = client.write_all(&[0x01, 0x00]);
        } else {
            log.lock().expect("log").auth_fail += 1;
            let _ = client.write_all(&[0x01, 0x01]);
            return;
        }
    } else {
        let _ = client.write_all(&[0x05, 0x00]);
    }

    // CONNECT request
    let mut req_head = [0u8; 4];
    if client.read_exact(&mut req_head).is_err() {
        return;
    }
    if req_head[0] != 0x05 || req_head[1] != 0x01 {
        let _ = client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        return;
    }
    let (host, port) = match req_head[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            let mut p = [0u8; 2];
            if client.read_exact(&mut ip).is_err() || client.read_exact(&mut p).is_err() {
                return;
            }
            (
                format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                u16::from_be_bytes(p),
            )
        }
        0x03 => {
            let mut len = [0u8; 1];
            if client.read_exact(&mut len).is_err() {
                return;
            }
            let mut name = vec![0u8; len[0] as usize];
            let mut p = [0u8; 2];
            if client.read_exact(&mut name).is_err() || client.read_exact(&mut p).is_err() {
                return;
            }
            (
                String::from_utf8_lossy(&name).into_owned(),
                u16::from_be_bytes(p),
            )
        }
        0x04 => {
            let mut ip = [0u8; 16];
            let mut p = [0u8; 2];
            if client.read_exact(&mut ip).is_err() || client.read_exact(&mut p).is_err() {
                return;
            }
            ("::1".to_string(), u16::from_be_bytes(p))
        }
        _ => return,
    };
    {
        log.lock().expect("log").connects.push((host.clone(), port));
    }
    let target = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };
    let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let _ = client.write_all(&reply);
    let _ = client.set_nonblocking(false);
    let _ = target.set_nonblocking(false);
    relay(client, target);
}

fn relay(a: &mut TcpStream, mut b: TcpStream) {
    let Ok(mut a_clone) = a.try_clone() else {
        return;
    };
    let Ok(mut b_clone) = b.try_clone() else {
        return;
    };
    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut a_clone, &mut b_clone);
        let _ = b_clone.shutdown(Shutdown::Both);
    });
    let _ = std::io::copy(&mut b, a);
    let _ = a.shutdown(Shutdown::Both);
    let _ = t1.join();
}

fn assert_scrape_ok(out: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstderr={stderr}\nstdout={stdout}",
        out.status.code()
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout not ScrapeProof JSON: {e}\nstdout={stdout}"))
}

fn assert_no_secret(text: &str) {
    assert!(
        !text.contains(SECRET_PASSWORD),
        "host-visible stream leaked proxy password: {text}"
    );
    assert!(
        !text.contains(&format!("{SECRET_USER}:{SECRET_PASSWORD}")),
        "host-visible stream leaked credential pair"
    );
    // Full user:pass@ form must never appear.
    assert!(
        !text.contains(&format!("{SECRET_USER}:{SECRET_PASSWORD}@")),
        "host-visible stream leaked user:pass@ URL form"
    );
}

// ---------------------------------------------------------------------------
// VAL-PROXY-001 / 007 / 009 — HTTP CONNECT via CLI, provider-agnostic mock
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_001_007_009_http_connect_cli_through_mock() {
    assert!(
        std::env::var("BASECRAWL_LIVE_PROXY").ok().as_deref() != Some("1"),
        "VAL-PROXY-009 requires live gate off in this hermetic matrix"
    );
    let (origin, origin_hits) = origin_fixture();
    let (proxy_url, _https_url, log, stop) = spawn_http_connect_mock(false, None, None);

    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy_url,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    let proof = assert_scrape_ok(&out);
    let hops = log.lock().expect("log");
    assert!(
        !hops.connects.is_empty(),
        "mock must record CONNECT hop, log={hops:?}"
    );
    assert!(
        origin_hits.load(Ordering::SeqCst) >= 1,
        "origin must be reached via proxy"
    );
    let body = proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .unwrap_or("");
    assert!(
        body.contains("proxy-origin-ok"),
        "response body not from origin via CONNECT"
    );
}

// ---------------------------------------------------------------------------
// VAL-PROXY-002 — https:// proxy scheme is accepted (not schema-rejected)
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_002_https_scheme_proxy_url_accepted() {
    let (origin, _) = origin_fixture();
    let (_http_url, https_url, log, stop) = spawn_http_connect_mock(false, None, None);
    // https:// scheme pointing at the plain hermetic CONNECT mock is the acceptance surface:
    // dial + CONNECT, no hard scheme reject (TLS-to-proxy is optional depth beyond this leaf).
    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &https_url,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    assert!(
        out.status.success(),
        "https:// proxy URL must not be scheme-rejected, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hops = log.lock().expect("log");
    assert!(
        !hops.connects.is_empty(),
        "https:// proxy URL must still dial the mock CONNECT gateway"
    );
}

// ---------------------------------------------------------------------------
// VAL-PROXY-003 / 008 — SOCKS5 provider-agnostic
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_003_008_socks5_through_mock() {
    let (origin, origin_hits) = origin_fixture();
    let (proxy_url, log, stop) = spawn_socks5_mock(false, None, None);
    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy_url,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    let proof = assert_scrape_ok(&out);
    let hops = log.lock().expect("log");
    assert!(
        !hops.connects.is_empty(),
        "SOCKS5 mock must record destination, log={hops:?}"
    );
    assert!(origin_hits.load(Ordering::SeqCst) >= 1);
    let body = proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .unwrap_or("");
    assert!(body.contains("proxy-origin-ok"));
}

// ---------------------------------------------------------------------------
// VAL-PROXY-004 — user:pass presented; wrong auth fails closed
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_004_user_pass_auth_and_wrong_auth_fails_closed() {
    let (origin, origin_hits) = origin_fixture();
    let (proxy_url, _https, log, stop) =
        spawn_http_connect_mock(true, Some(SECRET_USER), Some(SECRET_PASSWORD));

    let good = format!("http://{SECRET_USER}:{SECRET_PASSWORD}@{}", {
        let bare = proxy_url.strip_prefix("http://").unwrap();
        bare
    });
    let out_ok = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &good,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[],
    );
    let proof = assert_scrape_ok(&out_ok);
    {
        let hops = log.lock().expect("log");
        assert!(
            hops.auths.iter().any(|u| u == SECRET_USER),
            "mock must see username with password material, hops={hops:?}"
        );
        assert!(hops.auth_ok >= 1, "expected auth accept, hops={hops:?}");
    }
    assert!(origin_hits.load(Ordering::SeqCst) >= 1);
    assert!(proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .unwrap_or("")
        .contains("proxy-origin-ok"));

    // Wrong password: fail closed (non-zero), no silent direct success.
    let hits_before = origin_hits.load(Ordering::SeqCst);
    let bad = format!(
        "http://{SECRET_USER}:WRONG-PASSWORD-not-the-secret@{}",
        proxy_url.strip_prefix("http://").unwrap()
    );
    let out_bad = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &bad,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "10",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    assert!(
        !out_bad.status.success(),
        "wrong proxy auth must fail closed; got exit {:?}\nstdout={}\nstderr={}",
        out_bad.status.code(),
        String::from_utf8_lossy(&out_bad.stdout),
        String::from_utf8_lossy(&out_bad.stderr)
    );
    // Origin must not gain a new direct hit after the failed proxy auth.
    assert_eq!(
        origin_hits.load(Ordering::SeqCst),
        hits_before,
        "wrong proxy auth must not fall back to direct origin dial"
    );
    let hops = log.lock().expect("log");
    assert!(hops.auth_fail >= 1, "mock must record auth failure");
}

// ---------------------------------------------------------------------------
// VAL-PROXY-005 — env-only config works without --proxy
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_005_env_only_config() {
    let (origin, origin_hits) = origin_fixture();
    let (proxy_url, _, log, stop) = spawn_http_connect_mock(false, None, None);
    let out = run_proxy_scrape(
        &[
            &origin,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[("BASECRAWL_HTTP_PROXY", Some(&proxy_url))],
    );
    stop.store(true, Ordering::SeqCst);
    assert_scrape_ok(&out);
    let hops = log.lock().expect("log");
    assert!(!hops.connects.is_empty(), "env proxy must dial CONNECT");
    assert!(origin_hits.load(Ordering::SeqCst) >= 1);

    // Also accept generic ALL_PROXY.
    let (origin2, _) = origin_fixture();
    let (socks_url, log2, stop2) = spawn_socks5_mock(false, None, None);
    let out2 = run_proxy_scrape(
        &[
            &origin2,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[("ALL_PROXY", Some(&socks_url))],
    );
    stop2.store(true, Ordering::SeqCst);
    assert_scrape_ok(&out2);
    assert!(!log2.lock().expect("log").connects.is_empty());
}

// ---------------------------------------------------------------------------
// VAL-PROXY-006 — explicit CLI overrides ambient env
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_006_cli_overrides_env() {
    let (origin, _) = origin_fixture();
    let (proxy_a, _, log_a, stop_a) = spawn_http_connect_mock(false, None, None);
    let (proxy_b, _, log_b, stop_b) = spawn_http_connect_mock(false, None, None);
    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy_b,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[("BASECRAWL_HTTP_PROXY", Some(&proxy_a))],
    );
    stop_a.store(true, Ordering::SeqCst);
    stop_b.store(true, Ordering::SeqCst);
    assert_scrape_ok(&out);
    assert!(
        log_a.lock().expect("log").connects.is_empty(),
        "env proxy A must not see traffic when CLI B is set"
    );
    assert!(
        !log_b.lock().expect("log").connects.is_empty(),
        "CLI proxy B must record the hop"
    );
}

// ---------------------------------------------------------------------------
// VAL-PROXY-008 auth SOCKS5 + VAL-PROXY-023/024 redaction
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_008_023_024_socks_auth_and_credential_redaction() {
    let (origin, _) = origin_fixture();
    let (proxy_base, log, stop) = spawn_socks5_mock(true, Some(SECRET_USER), Some(SECRET_PASSWORD));
    let proxy_url = format!(
        "socks5://{SECRET_USER}:{SECRET_PASSWORD}@{}",
        proxy_base.strip_prefix("socks5://").unwrap()
    );
    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy_url,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
            "--verbose",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    let proof = assert_scrape_ok(&out);
    {
        let hops = log.lock().expect("log");
        assert!(
            hops.auths.iter().any(|u| u == SECRET_USER),
            "SOCKS5 must present credentials, hops={hops:?}"
        );
        assert!(hops.auth_ok >= 1);
    }
    let proof_s = proof.to_string();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_no_secret(&proof_s);
    assert_no_secret(&stderr);
    assert_no_secret(&stdout);

    // Auth failure path must also redact.
    let (proxy_base2, log2, stop2) =
        spawn_socks5_mock(true, Some(SECRET_USER), Some(SECRET_PASSWORD));
    let bad_proxy = format!(
        "socks5://{SECRET_USER}:wrong-not-{SECRET_PASSWORD}@{}",
        proxy_base2.strip_prefix("socks5://").unwrap()
    );
    let out_bad = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &bad_proxy,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "10",
        ],
        &[],
    );
    stop2.store(true, Ordering::SeqCst);
    assert!(!out_bad.status.success());
    assert_no_secret(&String::from_utf8_lossy(&out_bad.stderr));
    assert_no_secret(&String::from_utf8_lossy(&out_bad.stdout));
    assert!(log2.lock().expect("log").auth_fail >= 1);
}

// ---------------------------------------------------------------------------
// VAL-PROXY-020 — dead proxy fails closed
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_020_dead_proxy_fails_closed_no_direct() {
    let (origin, origin_hits) = origin_fixture();
    // Pick a closed port in range by binding then dropping after capturing the port.
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let dead = format!("http://{addr}");
    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &dead,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "5",
        ],
        &[],
    );
    assert!(
        !out.status.success(),
        "dead proxy must fail closed, exit {:?}",
        out.status.code()
    );
    assert_eq!(
        origin_hits.load(Ordering::SeqCst),
        0,
        "must not fall back to direct origin when proxy is dead"
    );
}
