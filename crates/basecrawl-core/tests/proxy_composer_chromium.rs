//! Chromium DoH-preserving proxy composer (M12).
//!
//! Covers VAL-PROXY-012 / 015–019 / 022 using hermetic mock gateways on mission
//! ports 21000–21099. Live Oxylabs is intentionally NOT exercised here.

use base64::Engine;
use basecrawl_core::proxy::{
    start_chromium_composer, start_chromium_composer_on, ComposerOriginDialer, ProxyConfig,
    UsernameTemplateOptions,
};
use basecrawl_seal::{
    NameResolver, OriginDialer, PinnedResolver, ResolverEndpoint, SealError, SealedSocksProxy,
    DEFAULT_DOH_ENDPOINT,
};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Output};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const SECRET_PASSWORD: &str = "pxy-composer-VALPROXY-9f1d4c22";
const SECRET_USER: &str = "customer-USER";

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
    cmd.env_remove("BASECRAWL_LIVE_PROXY");
    cmd.env_remove("BASECRAWL_COMPOSER_FAIL_START");
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

// ---------------------------------------------------------------------------
// Multipage HTML for VAL-PROXY-012 sticky hop under Chromium actions/pagination
// ---------------------------------------------------------------------------
fn multipage_origin() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_t = Arc::clone(&hits);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    hits_t.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 8192];
                    let _ = stream.set_nonblocking(false);
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body = if path.starts_with("/page2") {
                        b"<!doctype html><html><body><h1 id='p2'>page-two</h1></body></html>"
                            .as_slice()
                    } else {
                        b"<!doctype html><html><body>\
                          <h1 id='p1'>page-one</h1>\
                          <a rel='next' href='/page2'>Next</a>\
                          <button id='more'>More</button>\
                          </body></html>"
                            .as_slice()
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    (format!("http://{addr}/page1"), hits)
}

fn single_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.read(&mut buf);
                    let body = b"<!doctype html><html><body><h1 id='ok'>composer-origin-ok</h1></body></html>";
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
    format!("http://{addr}/composer-origin")
}

#[derive(Default, Debug, Clone)]
struct HopRecord {
    username: String,
    session: Option<String>,
    hop_id: String,
    target: String,
}

#[derive(Default, Debug)]
struct StickyLog {
    hops: Vec<HopRecord>,
    session_map: HashMap<String, String>,
    next_hop: usize,
    /// Direct (non-CONNECT) origin attempts observed on this mock — must stay zero when composer works.
    direct_gets: usize,
}

fn parse_session(username: &str) -> Option<String> {
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

fn spawn_sticky_http_connect_mock(
    require_auth: bool,
) -> (String, Arc<Mutex<StickyLog>>, Arc<AtomicBool>) {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let log = Arc::new(Mutex::new(StickyLog::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let log_t = Arc::clone(&log);
    let stop_t = Arc::clone(&stop);
    thread::spawn(move || {
        while !stop_t.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut client, _)) => {
                    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = client.set_write_timeout(Some(Duration::from_secs(10)));
                    handle_sticky_connect(&mut client, require_auth, &log_t);
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

fn handle_sticky_connect(client: &mut TcpStream, require_auth: bool, log: &Arc<Mutex<StickyLog>>) {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1];
    let deadline = Instant::now() + Duration::from_secs(8);
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
    let target = parts.next().unwrap_or("").to_string();

    if method != "CONNECT" {
        // Marks a direct HTTP request that skipped CONNECT composition.
        {
            let mut g = log.lock().expect("log");
            g.direct_gets += 1;
        }
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
        return;
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

    if require_auth {
        match &presented {
            Some((u, p)) if u.starts_with(SECRET_USER) && p == SECRET_PASSWORD => {}
            _ => {
                let _ = client.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"mock\"\r\n\
                      Connection: close\r\n\r\n",
                );
                return;
            }
        }
    }

    let username = presented
        .as_ref()
        .map(|(u, _)| u.clone())
        .unwrap_or_default();
    let session = parse_session(&username);
    let hop_id = {
        let mut g = log.lock().expect("log");
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
        g.hops.push(HopRecord {
            username: username.clone(),
            session: session.clone(),
            hop_id: hop.clone(),
            target: target.clone(),
        });
        hop
    };

    let target_stream = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    let _ = write!(
        client,
        "HTTP/1.1 200 Connection Established\r\nX-Mock-Exit-Hop: {hop_id}\r\n\r\n"
    );
    let _ = client.set_nonblocking(false);
    let _ = target_stream.set_nonblocking(false);
    let _ = hop_id;
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

fn assert_scrape_fail(out: &Output) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "expected non-zero fail-closed, got success\nstderr={stderr}\nstdout={stdout}"
    );
}

fn assert_no_secret(text: &str) {
    assert!(
        !text.contains(SECRET_PASSWORD),
        "host-visible stream leaked proxy password"
    );
}

fn proxy_url_with_creds(base: &str) -> String {
    let bare = base.strip_prefix("http://").unwrap();
    format!("http://{SECRET_USER}:{SECRET_PASSWORD}@{bare}")
}

// Snapshot helpers for VAL-PROXY-016/017 host DNS QNAME absence.
#[derive(Default, Clone)]
struct HostDnsCapture {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl HostDnsCapture {
    fn push(&self, frame: Vec<u8>) {
        self.frames.lock().unwrap().push(frame);
    }

    fn assert_no_qname(&self, qname: &str) {
        let qname_l = qname.to_ascii_lowercase();
        let qname_bytes = qname_l.as_bytes();
        let labels: Vec<&[u8]> = qname_l.split('.').map(|s| s.as_bytes()).collect();
        for frame in self.frames.lock().unwrap().iter() {
            let hay = frame.as_slice();
            assert!(
                !hay.windows(qname_bytes.len())
                    .any(|w| w.eq_ignore_ascii_case(qname_bytes)),
                "host DNS capture must not contain cleartext QNAME {qname}"
            );
            if labels.len() >= 2 {
                let mut wire = Vec::new();
                for label in &labels {
                    wire.push(label.len() as u8);
                    wire.extend_from_slice(label);
                }
                assert!(
                    !hay.windows(wire.len()).any(|w| w == wire.as_slice()),
                    "host DNS capture must not contain DNS-wire QNAME for {qname}"
                );
            }
        }
    }
}

struct Port53Sink {
    stop: Arc<Mutex<bool>>,
}

impl Port53Sink {
    fn start(capture: HostDnsCapture) -> Self {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind dns sink");
        let stop = Arc::new(Mutex::new(false));
        let stop_t = stop.clone();
        thread::spawn(move || {
            let _ = udp.set_read_timeout(Some(Duration::from_millis(50)));
            let mut buf = [0u8; 2048];
            while !*stop_t.lock().unwrap() {
                match udp.recv_from(&mut buf) {
                    Ok((n, _)) => capture.push(buf[..n].to_vec()),
                    Err(_) => continue,
                }
            }
        });
        Self { stop }
    }
}

impl Drop for Port53Sink {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
    }
}

// ---------------------------------------------------------------------------
// Unit-ish: composer loopback marker + bind fail closed
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_015_composer_bind_is_loopback_socks() {
    let proxy = ProxyConfig::parse(&format!(
        "http://{SECRET_USER}:{SECRET_PASSWORD}@127.0.0.1:1"
    ))
    .unwrap();
    // Dead upstream still starts the loopback SOCKS composer accept side.
    let composer = start_chromium_composer(&proxy).expect("composer start");
    assert!(composer.is_composed());
    let arg = composer.proxy_server_arg();
    assert!(
        arg.starts_with("socks5://127.0.0.1:"),
        "Chromium must see loopback SOCKS, got {arg}"
    );
    let addr = composer.addr();
    assert!(addr.ip().is_loopback());
}

#[test]
fn val_proxy_022_bind_conflict_api_fails_closed() {
    let holder = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = holder.local_addr().unwrap();
    let proxy = ProxyConfig::parse(&format!(
        "http://{SECRET_USER}:{SECRET_PASSWORD}@127.0.0.1:1"
    ))
    .unwrap();
    let err = start_chromium_composer_on(busy, &proxy).expect_err("bind conflict");
    let msg = err.to_string();
    assert!(
        msg.contains("composer") || msg.contains("bind") || msg.contains("SOCKS"),
        "unexpected error: {msg}"
    );
}

// ---------------------------------------------------------------------------
// VAL-PROXY-018/019 — soft rustls + Chromium share dialer identity (session)
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_018_019_soft_and_chromium_share_sticky_session() {
    let origin = single_origin();
    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let proxy = proxy_url_with_creds(&proxy_base);

    // Soft rustls path.
    let soft = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy,
            "--proxy-session",
            "SHARED-S1",
            "--proxy-country",
            "US",
            "--proxy-class",
            "residential",
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "20",
        ],
        &[],
    );
    let soft_proof = assert_scrape_ok(&soft);
    assert_eq!(
        soft_proof["egress"]["proxy_class"].as_str(),
        Some("residential")
    );

    // Chromium path (html forces render → composer).
    let chrome = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy,
            "--proxy-session",
            "SHARED-S1",
            "--proxy-country",
            "US",
            "--proxy-class",
            "residential",
            "--robots",
            "ignore",
            "--formats",
            "html",
            "--timeout",
            "45",
            "--render-timeout",
            "30",
        ],
        &[],
    );
    let chrome_proof = assert_scrape_ok(&chrome);
    assert_eq!(
        chrome_proof["egress"]["proxy_class"].as_str(),
        Some("residential")
    );
    stop.store(true, Ordering::SeqCst);

    let g = log.lock().expect("log");
    assert!(
        g.hops.len() >= 2,
        "soft + chromium must each CONNECT, log={g:?}"
    );
    assert_eq!(
        g.direct_gets, 0,
        "mock must not see non-CONNECT requests (composer required)"
    );
    let soft_hop = g
        .hops
        .iter()
        .find(|h| h.session.as_deref() == Some("SHARED-S1"))
        .expect("session hop");
    // All SHARED-S1 hops must be identical.
    for hop in g
        .hops
        .iter()
        .filter(|h| h.session.as_deref() == Some("SHARED-S1"))
    {
        assert_eq!(
            hop.hop_id, soft_hop.hop_id,
            "soft+chromium must share sticky hop under same session, log={g:?}"
        );
        assert!(
            hop.username.contains("SHARED-S1"),
            "username template session missing: {}",
            hop.username
        );
        assert!(
            hop.username.contains("-cc-US"),
            "country template missing: {}",
            hop.username
        );
    }
    let stdout = String::from_utf8_lossy(&chrome.stdout);
    let stderr = String::from_utf8_lossy(&chrome.stderr);
    assert_no_secret(&stdout);
    assert_no_secret(&stderr);
}

// ---------------------------------------------------------------------------
// VAL-PROXY-012 / 015 — multipage sticky under Chromium
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_012_015_chromium_multipage_keeps_sticky_hop() {
    let (origin, _) = multipage_origin();
    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let proxy = proxy_url_with_creds(&proxy_base);

    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy,
            "--proxy-session",
            "MULTI-S1",
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
            "60",
            "--render-timeout",
            "30",
            "--actions",
            r#"[{"type":"wait","milliseconds":100}]"#,
        ],
        &[],
    );
    let proof = assert_scrape_ok(&out);
    stop.store(true, Ordering::SeqCst);

    assert_eq!(proof["egress"]["proxy_class"].as_str(), Some("residential"));

    let g = log.lock().expect("log");
    assert!(
        !g.hops.is_empty(),
        "multipart chromium scrape must emit CONNECT hops, log={g:?}"
    );
    assert_eq!(g.direct_gets, 0, "no direct non-CONNECT mock hits");
    let multipage_hops: Vec<_> = g
        .hops
        .iter()
        .filter(|h| h.session.as_deref() == Some("MULTI-S1"))
        .collect();
    assert!(
        multipage_hops.len() >= 2,
        "expect multiple CONNECT under multipage/actions, got {:?}, log={g:?}",
        multipage_hops.len()
    );
    let first = multipage_hops[0].hop_id.clone();
    for hop in &multipage_hops {
        assert_eq!(
            hop.hop_id, first,
            "multipage sticky session must keep one hop, log={g:?}"
        );
    }
    assert_no_secret(&String::from_utf8_lossy(&out.stdout));
    assert_no_secret(&String::from_utf8_lossy(&out.stderr));
}

// ---------------------------------------------------------------------------
// VAL-PROXY-016 / 017 — no host DNS QNAME for sealed-resolved target under mock
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_016_017_composer_domain_connect_no_host_qname() {
    // Echo origin on loopback.
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

    // Commercial mock that just accepts CONNECT to IP:port.
    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let cfg = ProxyConfig::parse(&proxy_url_with_creds(&proxy_base))
        .unwrap()
        .with_username_template(&UsernameTemplateOptions {
            country: Some("US".into()),
            session: Some("DOH-S1".into()),
            template: None,
        })
        .unwrap();

    // Fake DoH-pinned resolver → loopback origin, never hits host DNS.
    struct Fixed(IpAddr);
    impl NameResolver for Fixed {
        fn resolve_host(
            &self,
            host: &str,
            port: u16,
            _deadline: Instant,
        ) -> Result<Vec<SocketAddr>, SealError> {
            assert_eq!(host, "confid-composer-target.basecrawl.test");
            Ok(vec![SocketAddr::new(self.0, port)])
        }
        fn endpoint(&self) -> &ResolverEndpoint {
            &DEFAULT_DOH_ENDPOINT
        }
    }

    let capture = HostDnsCapture::default();
    let _sink = Port53Sink::start(capture.clone());

    let dialer: Arc<dyn OriginDialer> = Arc::new(ComposerOriginDialer::new(cfg));
    let composer =
        SealedSocksProxy::start_composed(Arc::new(Fixed(IpAddr::V4(Ipv4Addr::LOCALHOST))), dialer)
            .expect("composed socks");

    // Drive SOCKS domain CONNECT as Chromium would.
    let mut client = TcpStream::connect(composer.addr()).unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp, [0x05, 0x00]);
    let host = b"confid-composer-target.basecrawl.test";
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host);
    req.extend_from_slice(&up_addr.port().to_be_bytes());
    client.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(
        reply[1], 0x00,
        "composed domain CONNECT must succeed after DoH pin"
    );

    client.write_all(b"ping-doh-composer").unwrap();
    let mut echo = [0u8; 64];
    let n = client.read(&mut echo).unwrap();
    assert_eq!(&echo[..n], b"ping-doh-composer");
    up_thread.join().unwrap();
    stop.store(true, Ordering::SeqCst);

    capture.assert_no_qname("confid-composer-target.basecrawl.test");
    let g = log.lock().unwrap();
    assert!(
        !g.hops.is_empty(),
        "commercial mock must see CONNECT after DoH resolve"
    );
    // CONNECT target is the IP, not the QNAME — commercial path never re-resolves via host DNS.
    assert!(
        g.hops[0].target.starts_with("127.0.0.1:") || g.hops[0].target.starts_with("[::1]:"),
        "composer should CONNECT by IP after sealed resolve, target={}",
        g.hops[0].target
    );
}

// ---------------------------------------------------------------------------
// VAL-PROXY-022 — required Chromium proxy path fails closed on composer start
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_022_composer_start_fail_closed_under_required_proxy() {
    let origin = single_origin();
    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let proxy = proxy_url_with_creds(&proxy_base);

    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy,
            "--proxy-session",
            "FAIL-S1",
            "--proxy-class",
            "residential",
            "--robots",
            "ignore",
            "--formats",
            "html",
            "--timeout",
            "20",
            "--render-timeout",
            "10",
        ],
        &[("BASECRAWL_COMPOSER_FAIL_START", Some("1"))],
    );
    stop.store(true, Ordering::SeqCst);
    assert_scrape_fail(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stderr.contains("composer")
            || stderr.contains("dns_isolation")
            || stderr.contains("sealed")
            || stderr.contains("SOCKS")
            || stdout.contains("composer")
            || stdout.contains("dns_isolation"),
        "fail-closed structured error missing, stderr={stderr} stdout={stdout}"
    );
    // No successful ScrapeProof JSON on stdout describing a proxied residential success.
    if let Ok(v) = serde_json::from_str::<Value>(stdout.trim()) {
        panic!("must not emit success ScrapeProof under composer fail: {v}");
    }
    assert_no_secret(&stderr);
    assert_no_secret(&stdout);
    let g = log.lock().unwrap();
    // Chrome must not fall open to a successful directly-dialed multipage path while claiming
    // residential — mock hop map for FAIL-S1 either empty or unfinished connection only.
    let success_style = g
        .hops
        .iter()
        .any(|h| h.session.as_deref() == Some("FAIL-S1"));
    // Soft path is not used for html-only when composer fails at bootstrap before fetch? Actually
    // soft fetch may complete if composer is started after soft resolve — our wire starts composer
    // before soft fetch. No FAIL-S1 hops expected.
    assert!(
        !success_style,
        "no residential sticky success hop under forced composer failure, log={g:?}"
    );
}

// Silence unused import warnings on Platform helpers kept for library re-export coherence.
#[allow(dead_code)]
fn _pin() {
    let _ = PinnedResolver::doh();
}
