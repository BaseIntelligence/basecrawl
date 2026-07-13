//! Universal egress proxy configuration and dialer (HTTP CONNECT, HTTPS-scheme proxy URLs, SOCKS5).
//!
//! Provider-agnostic: any standard `http(s)://[user:pass@]host:port` or
//! `socks5://[user:pass@]host:port` upstream works. Credentials are zeroized on drop and never
//! appear in Display/Debug, ScrapeProof, or host-visible error messages (VAL-PROXY-023/024).

use crate::error::Error;
use base64::Engine;
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use url::Url;
use zeroize::Zeroizing;

/// Upstream proxy protocol family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    /// Plain-text HTTP CONNECT (`http://…`).
    Http,
    /// HTTPS-scheme proxy URL (`https://…`). Accepted without schema-reject; dials the proxy
    /// endpoint and speaks CONNECT (TLS-to-proxy is optional product depth for later milestones).
    Https,
    /// SOCKS5 (`socks5://…` / `socks5h://…`).
    Socks5,
}

impl ProxyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyKind::Http => "http",
            ProxyKind::Https => "https",
            ProxyKind::Socks5 => "socks5",
        }
    }
}

/// Parsed, redaction-safe proxy configuration for the soft (rustls) egress path.
#[derive(Clone)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// Zeroized on drop so stack dumps and long-lived process memory hold the secret less.
    pub password: Option<Zeroizing<String>>,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username.as_deref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted_url())
    }
}

impl ProxyConfig {
    /// Parse a standard proxy URL. Password material is retained only on this struct (never logged).
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidProxy(
                "proxy URL must not be empty".to_string(),
            ));
        }
        let url = Url::parse(trimmed).map_err(|_| {
            Error::InvalidProxy("proxy URL is not a valid absolute URL".to_string())
        })?;
        let kind = match url.scheme() {
            "http" => ProxyKind::Http,
            "https" => ProxyKind::Https,
            "socks5" | "socks5h" => ProxyKind::Socks5,
            other => {
                return Err(Error::InvalidProxy(format!(
                    "unsupported proxy scheme '{other}' (supported: http, https, socks5)"
                )))
            }
        };
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidProxy("proxy URL is missing a host".to_string()))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error::InvalidProxy("proxy URL is missing a port".to_string()))?;
        // url crate percent-decodes userinfo; preserve empty username as None only if absent.
        let username = {
            let u = url.username();
            if u.is_empty() {
                None
            } else {
                Some(u.to_string())
            }
        };
        let password = url.password().map(|p| Zeroizing::new(p.to_string()));
        Ok(Self {
            kind,
            host,
            port,
            username,
            password,
        })
    }

    /// Operator-safe description: scheme + host:port, optional username only (never password).
    pub fn redacted_url(&self) -> String {
        match &self.username {
            Some(user) => format!(
                "{}://{}:***@{}:{}",
                self.kind.as_str(),
                user,
                self.host,
                self.port
            ),
            None => format!("{}://{}:{}", self.kind.as_str(), self.host, self.port),
        }
    }

    /// True when any credential material is present.
    pub fn has_credentials(&self) -> bool {
        self.username.is_some() || self.password.is_some()
    }

    /// Dial the origin through this upstream. Failures do **not** fall back to a direct kernel dial.
    pub fn connect_to_target(
        &self,
        target_host: &str,
        target_port: u16,
        deadline: Instant,
    ) -> Result<TcpStream, Error> {
        let remaining = remaining(deadline)?;
        let proxy_addr = resolve_proxy_endpoint(&self.host, self.port, remaining)?;
        let stream =
            TcpStream::connect_timeout(&proxy_addr, remaining).map_err(classify_proxy_io)?;
        apply_stream_timeouts(&stream, deadline)?;
        match self.kind {
            ProxyKind::Http | ProxyKind::Https => {
                http_connect(stream, self, target_host, target_port, deadline)
            }
            ProxyKind::Socks5 => socks5_connect(stream, self, target_host, target_port, deadline),
        }
    }
}

/// Resolve the effective proxy for a scrape.
///
/// Precedence (VAL-PROXY-005 / VAL-PROXY-006):
/// 1. Explicit CLI/config URL (wins over all ambient env).
/// 2. Scheme-specific env (`BASECRAWL_HTTPS_PROXY` / `HTTPS_PROXY` for https targets;
///    `BASECRAWL_HTTP_PROXY` / `HTTP_PROXY` for http targets).
/// 3. Cross-scheme fallbacks (`BASECRAWL_HTTP_PROXY` / `HTTP_PROXY` when target is https).
/// 4. `ALL_PROXY` / `all_proxy`.
///
/// Empty values are ignored. Host-visible surfaces never print raw passwords from these URLs.
pub fn resolve_proxy(explicit: Option<&str>, target: &Url) -> Result<Option<ProxyConfig>, Error> {
    if let Some(raw) = explicit {
        let raw = raw.trim();
        if !raw.is_empty() {
            return Ok(Some(ProxyConfig::parse(raw)?));
        }
    }

    let scheme = target.scheme();
    let candidates: &[&str] = match scheme {
        "https" => &[
            "BASECRAWL_HTTPS_PROXY",
            "HTTPS_PROXY",
            "https_proxy",
            "BASECRAWL_HTTP_PROXY",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ],
        "http" => &[
            "BASECRAWL_HTTP_PROXY",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ],
        _ => &["ALL_PROXY", "all_proxy"],
    };

    for key in candidates {
        if let Ok(value) = std::env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(Some(ProxyConfig::parse(value)?));
            }
        }
    }
    Ok(None)
}

fn resolve_proxy_endpoint(host: &str, port: u16, timeout: Duration) -> Result<SocketAddr, Error> {
    // IP literals and localhost short-circuit without host DNS (keeps hermetic loopback mocks
    // working without DoH). Remote proxy hostnames use system resolution here because the dial
    // target is the commercial/mock *proxy* itself, not the origin (origin remains CONNECT/SOCKS).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if host.eq_ignore_ascii_case("localhost") || host.eq_ignore_ascii_case("localhost.") {
        return Ok(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
    }
    let start = Instant::now();
    loop {
        let result = std::net::ToSocketAddrs::to_socket_addrs(&(host, port));
        match result {
            Ok(mut iter) => {
                if let Some(addr) = iter.next() {
                    return Ok(addr);
                }
                if start.elapsed() >= timeout {
                    return Err(Error::Transport(
                        "proxy endpoint resolution failed: proxy host resolved to no addresses"
                            .to_string(),
                    ));
                }
            }
            Err(e) => {
                if start.elapsed() >= timeout {
                    return Err(Error::Transport(format!(
                        "proxy endpoint resolution failed: {e}"
                    )));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn http_connect(
    mut stream: TcpStream,
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    deadline: Instant,
) -> Result<TcpStream, Error> {
    apply_stream_timeouts(&stream, deadline)?;
    let authority = format!("{target_host}:{target_port}");
    let mut req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(auth) = basic_proxy_authorization(proxy) {
        req.push_str("Proxy-Authorization: ");
        req.push_str(&auth);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(classify_proxy_io)?;
    stream.flush().map_err(classify_proxy_io)?;

    let response = read_http_head(&mut stream, deadline)?;
    let status = parse_status_code(&response).ok_or_else(|| {
        Error::Transport("proxy CONNECT returned an unreadable status line".to_string())
    })?;
    if status == 200 {
        return Ok(stream);
    }
    if status == 407 {
        return Err(Error::Transport(
            "proxy authentication required or rejected (CONNECT 407)".to_string(),
        ));
    }
    Err(Error::Transport(format!(
        "proxy CONNECT failed with HTTP status {status}"
    )))
}

fn basic_proxy_authorization(proxy: &ProxyConfig) -> Option<String> {
    if !proxy.has_credentials() {
        return None;
    }
    let user = proxy.username.as_deref().unwrap_or("");
    let pass = proxy.password.as_ref().map(|p| p.as_str()).unwrap_or("");
    let token = base64::prelude::BASE64_STANDARD.encode(format!("{user}:{pass}"));
    Some(format!("Basic {token}"))
}

fn read_http_head(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while Instant::now() < deadline {
        apply_stream_timeouts(stream, deadline)?;
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(Error::Transport(
                    "proxy closed the connection during CONNECT".to_string(),
                ))
            }
            Ok(_) => {
                buf.push(byte[0]);
                if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
                    return Ok(buf);
                }
                if buf.len() > 16 * 1024 {
                    return Err(Error::Transport(
                        "proxy CONNECT response headers exceeded limit".to_string(),
                    ));
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    break;
                }
                continue;
            }
            Err(e) => return Err(classify_proxy_io(e)),
        }
    }
    Err(Error::Timeout(
        "proxy CONNECT response timed out".to_string(),
    ))
}

fn parse_status_code(response: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(response).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    let _version = parts.next()?;
    parts.next()?.parse().ok()
}

fn socks5_connect(
    mut stream: TcpStream,
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    deadline: Instant,
) -> Result<TcpStream, Error> {
    apply_stream_timeouts(&stream, deadline)?;
    let want_auth = proxy.has_credentials();
    // Greeting: VER=5, methods (no-auth and/or user/pass).
    let greeting: Vec<u8> = if want_auth {
        vec![0x05, 0x02, 0x00, 0x02]
    } else {
        vec![0x05, 0x01, 0x00]
    };
    stream.write_all(&greeting).map_err(classify_proxy_io)?;
    let mut method = [0u8; 2];
    read_exact_deadline(&mut stream, &mut method, deadline)?;
    if method[0] != 0x05 {
        return Err(Error::Transport(
            "SOCKS5 greeting returned unexpected version".to_string(),
        ));
    }
    match method[1] {
        0x00 => {
            // No authentication required.
        }
        0x02 => {
            socks5_userpass_auth(&mut stream, proxy, deadline)?;
        }
        0xFF => {
            return Err(Error::Transport(
                "SOCKS5 proxy rejected all offered authentication methods".to_string(),
            ));
        }
        other => {
            return Err(Error::Transport(format!(
                "SOCKS5 proxy selected unsupported auth method {other}"
            )));
        }
    }

    // CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(Error::Transport(
            "SOCKS5 target hostname exceeds 255 bytes".to_string(),
        ));
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.push(0x05); // VER
    req.push(0x01); // CONNECT
    req.push(0x00); // RSV
    if let Ok(ip) = target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        req.push(0x03); // DOMAIN
        req.push(host_bytes.len() as u8);
        req.extend_from_slice(host_bytes);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).map_err(classify_proxy_io)?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    read_exact_deadline(&mut stream, &mut head, deadline)?;
    if head[0] != 0x05 {
        return Err(Error::Transport(
            "SOCKS5 reply returned unexpected version".to_string(),
        ));
    }
    if head[1] != 0x00 {
        let msg = match head[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "SOCKS5 CONNECT failed",
        };
        return Err(Error::Transport(msg.to_string()));
    }
    // Drain bound address from the reply so the byte stream starts at origin traffic.
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 4 + 2];
            read_exact_deadline(&mut stream, &mut skip, deadline)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_deadline(&mut stream, &mut len, deadline)?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            read_exact_deadline(&mut stream, &mut skip, deadline)?;
        }
        0x04 => {
            let mut skip = [0u8; 16 + 2];
            read_exact_deadline(&mut stream, &mut skip, deadline)?;
        }
        other => {
            return Err(Error::Transport(format!(
                "SOCKS5 reply used unsupported address type {other}"
            )));
        }
    }
    Ok(stream)
}

fn socks5_userpass_auth(
    stream: &mut TcpStream,
    proxy: &ProxyConfig,
    deadline: Instant,
) -> Result<(), Error> {
    let user = proxy.username.as_deref().unwrap_or("");
    let pass = proxy.password.as_ref().map(|p| p.as_str()).unwrap_or("");
    if user.len() > 255 || pass.len() > 255 {
        return Err(Error::Transport(
            "SOCKS5 username/password exceeds 255 bytes".to_string(),
        ));
    }
    let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
    msg.push(0x01); // subnegotiation version
    msg.push(user.len() as u8);
    msg.extend_from_slice(user.as_bytes());
    msg.push(pass.len() as u8);
    msg.extend_from_slice(pass.as_bytes());
    stream.write_all(&msg).map_err(classify_proxy_io)?;
    let mut status = [0u8; 2];
    read_exact_deadline(stream, &mut status, deadline)?;
    if status[0] != 0x01 || status[1] != 0x00 {
        return Err(Error::Transport(
            "SOCKS5 username/password authentication failed".to_string(),
        ));
    }
    Ok(())
}

fn read_exact_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), Error> {
    let mut filled = 0;
    while filled < buf.len() {
        if Instant::now() >= deadline {
            return Err(Error::Timeout("proxy I/O timed out".to_string()));
        }
        apply_stream_timeouts(stream, deadline)?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(Error::Transport(
                    "proxy closed the connection unexpectedly".to_string(),
                ))
            }
            Ok(n) => filled += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(classify_proxy_io(e)),
        }
    }
    Ok(())
}

fn apply_stream_timeouts(stream: &TcpStream, deadline: Instant) -> Result<(), Error> {
    let left = remaining(deadline)?;
    stream
        .set_read_timeout(Some(left))
        .map_err(classify_proxy_io)?;
    stream
        .set_write_timeout(Some(left))
        .map_err(classify_proxy_io)?;
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| Error::Timeout("proxy deadline exceeded".to_string()))
}

fn classify_proxy_io(error: std::io::Error) -> Error {
    // Never include peer data or user-supplied payload. Map timeout vs transport only.
    if error.kind() == std::io::ErrorKind::TimedOut
        || error.kind() == std::io::ErrorKind::WouldBlock
    {
        Error::Timeout("proxy I/O timed out".to_string())
    } else {
        Error::Transport(format!("proxy transport error: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_https_socks5_urls() {
        let http = ProxyConfig::parse("http://127.0.0.1:21010").unwrap();
        assert_eq!(http.kind, ProxyKind::Http);
        assert_eq!(http.host, "127.0.0.1");
        assert_eq!(http.port, 21010);

        let https = ProxyConfig::parse("https://proxy.example:8443").unwrap();
        assert_eq!(https.kind, ProxyKind::Https);
        assert_eq!(https.port, 8443);

        let socks = ProxyConfig::parse("socks5://u:secret@127.0.0.1:1080").unwrap();
        assert_eq!(socks.kind, ProxyKind::Socks5);
        assert_eq!(socks.username.as_deref(), Some("u"));
        assert_eq!(
            socks.password.as_deref().map(|s| s.as_str()),
            Some("secret")
        );
    }

    #[test]
    fn redacted_url_never_contains_password() {
        let proxy = ProxyConfig::parse("http://user:supersecret@10.0.0.5:8080").unwrap();
        let redacted = proxy.redacted_url();
        assert!(!redacted.contains("supersecret"));
        assert!(redacted.contains("user"));
        assert!(redacted.contains("***"));
        let dbg = format!("{proxy:?}");
        assert!(!dbg.contains("supersecret"));
        let disp = format!("{proxy}");
        assert!(!disp.contains("supersecret"));
    }

    #[test]
    fn rejects_unknown_scheme() {
        let err = ProxyConfig::parse("ftp://127.0.0.1:21").unwrap_err();
        assert_eq!(err.kind(), "invalid_proxy");
    }

    #[test]
    fn explicit_cli_proxy_beats_env() {
        // Note: this unit test only checks parse path; COM integration covers env/CLI override.
        let cfg = ProxyConfig::parse("socks5://127.0.0.1:1").unwrap();
        assert_eq!(cfg.kind, ProxyKind::Socks5);
    }
}
