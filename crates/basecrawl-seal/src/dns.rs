//! In-enclave DNS resolution over DoH (and DoT) to a pinned resolver.
//!
//! Confidentiality requirement (architecture §5.2 / §7, VAL-CONF-013):
//! the host's cleartext resolver / port-53 path must NEVER see an A/AAAA query
//! for a scrape target hostname. All name resolution for non-literal hosts goes
//! over TLS to a digest-pinned DoH (or DoT) endpoint whose destination IP is
//! known a priori — so the host only observes encrypted TLS records to the
//! resolver IP (expected leakage: VAL-CONF-023), not the QNAME in cleartext.
//!
//! There is intentionally **no fallback** to the system stub resolver when the
//! pinned path fails: a fallback would re-introduce cleartext port-53 leakage.

use crate::error::SealError;
use rustls::client::ClientConnection;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Domain-separated marker that appears only on the privacy-safe DoH path.
/// Tests (and log redaction) can key on this token; it never embeds QNAMEs.
pub const DOH_PATH_MARKER: &str = "basecrawl-seal/doh-v1";

/// Cloudflare public DoH service, pinned by destination IP + SNI.
/// Default for enclave resolution; the host sees only a TLS connection to
/// `1.1.1.1:443` (resolver destination; VAL-CONF-023 expected leakage).
pub const DEFAULT_DOH_ENDPOINT: ResolverEndpoint = ResolverEndpoint {
    ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    port: 443,
    sni: "cloudflare-dns.com",
    path: "/dns-query",
    mode: ResolverMode::Doh,
};

/// Cloudflare public DoT service on port 853 (TLS, length-prefixed DNS).
pub const DEFAULT_DOT_ENDPOINT: ResolverEndpoint = ResolverEndpoint {
    ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    port: 853,
    sni: "cloudflare-dns.com",
    path: "",
    mode: ResolverMode::Dot,
};

/// Transport mode used by the pinned resolver endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverMode {
    /// DNS-over-HTTPS (RFC 8484) — POST `application/dns-message`.
    Doh,
    /// DNS-over-TLS (RFC 7858) — TLS on 853 with 2-byte length frames.
    Dot,
}

/// A fully-specified, pinable recursive resolver destination.
///
/// Bias toward connecting by **IP address** and validating TLS with the declared
/// `sni`, so the host's stub resolver is never consulted for the target name
/// *or* for looking up the resolver hostname itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverEndpoint {
    pub ip: IpAddr,
    pub port: u16,
    pub sni: &'static str,
    pub path: &'static str,
    pub mode: ResolverMode,
}

impl ResolverEndpoint {
    /// Socket the enclave connects to for every lookup.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

/// Result of a single A/AAAA lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveResult {
    /// Answers returned by the pinned resolver (deduplicated, stable order).
    pub addresses: Vec<IpAddr>,
    /// Endpoint that answered (IP/port/mode of the pin).
    pub via: ResolverEndpoint,
    /// Wire protocol label for host-safe telemetry (`doh` / `dot`).
    pub protocol: &'static str,
}

/// Trait used by crawl/fetch code to inject a resolver (production DoH, or a
/// fixture for unit tests that cannot reach the open internet).
pub trait NameResolver: Send + Sync {
    /// Resolve `host` (a hostname, never an IP literal) to socket addresses for
    /// the given `port`. Must not consult the host stub resolver.
    fn resolve_host(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<Vec<SocketAddr>, SealError>;

    /// Which pinned endpoint this resolver is configured to use.
    fn endpoint(&self) -> &ResolverEndpoint;
}

/// Production in-enclave resolver: DoH (or DoT) to a pin, never port 53.
#[derive(Debug, Clone)]
pub struct PinnedResolver {
    endpoint: ResolverEndpoint,
}

impl Default for PinnedResolver {
    fn default() -> Self {
        Self::doh()
    }
}

impl PinnedResolver {
    /// Pin to the default Cloudflare DoH endpoint.
    pub fn doh() -> Self {
        Self {
            endpoint: DEFAULT_DOH_ENDPOINT,
        }
    }

    /// Pin to the default Cloudflare DoT endpoint.
    pub fn dot() -> Self {
        Self {
            endpoint: DEFAULT_DOT_ENDPOINT,
        }
    }

    /// Pin to a fully-specified endpoint (for tests / alternative resolvers).
    pub fn with_endpoint(endpoint: ResolverEndpoint) -> Self {
        Self { endpoint }
    }

    /// Resolve `name` to A + AAAA addresses using the pin only.
    pub fn lookup(&self, name: &str, deadline: Instant) -> Result<ResolveResult, SealError> {
        let name = normalize_name(name)?;
        // Prefer A first (IPv4-first connectivity for origin fetch); then AAAA.
        let mut addresses = lookup_type(&self.endpoint, &name, QTYPE_A, deadline)?;
        let aaaa = lookup_type(&self.endpoint, &name, QTYPE_AAAA, deadline).unwrap_or_default();
        for ip in aaaa {
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        if addresses.is_empty() {
            return Err(SealError::Dns {
                detail: "pinned resolver returned no A/AAAA answers".into(),
            });
        }
        Ok(ResolveResult {
            addresses,
            via: self.endpoint.clone(),
            protocol: match self.endpoint.mode {
                ResolverMode::Doh => "doh",
                ResolverMode::Dot => "dot",
            },
        })
    }
}

impl NameResolver for PinnedResolver {
    fn resolve_host(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<Vec<SocketAddr>, SealError> {
        let result = self.lookup(host, deadline)?;
        Ok(result
            .addresses
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    fn endpoint(&self) -> &ResolverEndpoint {
        &self.endpoint
    }
}

/// Resolve a scrape-target host for the confidential fetch path.
///
/// * IP literals are used as-is (no lookup).
/// * Well-known loopback names (`localhost`) map to `127.0.0.1` so local
///   fixtures keep working without consulting either DoH or the stub resolver.
/// * Every other hostname is resolved exclusively via `resolver` (DoH/DoT).
///   There is no `getaddrinfo` / port-53 fallback.
pub fn resolve_for_connect(
    host: &str,
    port: u16,
    resolver: &dyn NameResolver,
    deadline: Instant,
) -> Result<SocketAddr, SealError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if is_loopback_name(host) {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    let addresses = resolver.resolve_host(host, port, deadline)?;
    addresses.into_iter().next().ok_or_else(|| SealError::Dns {
        detail: "pinned resolver returned an empty address list".into(),
    })
}

/// True for names that must never leave the local host and never hit DoH.
pub fn is_loopback_name(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
}

/// Build a standard DNS query message (RFC 1035) for `name` / `qtype`.
///
/// Public so tests can inspect the cleartext DNS payload that is allegedly
/// only ever carried inside a TLS record (VAL-CONF-013).
pub fn build_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>, SealError> {
    let name = normalize_name(name)?;
    let labels = encode_name(&name)?;
    let mut msg = Vec::with_capacity(12 + labels.len() + 4);
    msg.extend_from_slice(&id.to_be_bytes());
    // Standard query, recursion desired.
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    msg.extend_from_slice(&labels);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    Ok(msg)
}

/// Parse A/AAAA answers out of a DNS response message for the given qtype.
pub fn parse_answers(message: &[u8], expected_qtype: u16) -> Result<Vec<IpAddr>, SealError> {
    if message.len() < 12 {
        return Err(SealError::Dns {
            detail: "DNS response shorter than header".into(),
        });
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let rcode = flags & 0x000f;
    if rcode != 0 {
        // NXDOMAIN / SERVFAIL etc: not a transport failure, just empty answers.
        return Ok(Vec::new());
    }
    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = skip_name(message, offset)?;
        offset = offset.checked_add(4).ok_or_else(|| SealError::Dns {
            detail: "DNS question overrun".into(),
        })?;
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err(SealError::Dns {
                detail: "DNS answer header overrun".into(),
            });
        }
        let rtype = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let _rclass = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        // TTL spans offset+4..+8
        let rdlength = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > message.len() {
            return Err(SealError::Dns {
                detail: "DNS rdata overrun".into(),
            });
        }
        let rdata = &message[offset..offset + rdlength];
        if rtype == expected_qtype {
            match rtype {
                QTYPE_A if rdata.len() == 4 => {
                    answers.push(IpAddr::V4(Ipv4Addr::new(
                        rdata[0], rdata[1], rdata[2], rdata[3],
                    )));
                }
                QTYPE_AAAA if rdata.len() == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(rdata);
                    answers.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        offset += rdlength;
    }
    Ok(answers)
}

/// QTYPE A.
pub const QTYPE_A: u16 = 1;
/// QTYPE AAAA.
pub const QTYPE_AAAA: u16 = 28;

fn lookup_type(
    endpoint: &ResolverEndpoint,
    name: &str,
    qtype: u16,
    deadline: Instant,
) -> Result<Vec<IpAddr>, SealError> {
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1)
        & 0xffff) as u16;
    let query = build_query(name, qtype, id.max(1))?;
    let response = match endpoint.mode {
        ResolverMode::Doh => exchange_doh(endpoint, &query, deadline)?,
        ResolverMode::Dot => exchange_dot(endpoint, &query, deadline)?,
    };
    parse_answers(&response, qtype)
}

fn exchange_doh(
    endpoint: &ResolverEndpoint,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, SealError> {
    let mut tls = connect_tls(endpoint, deadline)?;
    let host_header = if endpoint.port == 443 {
        endpoint.sni.to_string()
    } else {
        format!("{}:{}", endpoint.sni, endpoint.port)
    };
    // RFC 8484 §4.1 — POST is preferred so the query never enters a URI
    // (and therefore never an intermediate host HTTP log sensors might read).
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: {}\r\n\r\n",
        endpoint.path,
        host_header,
        query.len(),
        DOH_PATH_MARKER,
    );
    tls.write_all(request.as_bytes())
        .map_err(|e| map_io("DoH request write", e))?;
    tls.write_all(query)
        .map_err(|e| map_io("DoH query write", e))?;
    tls.flush().map_err(|e| map_io("DoH flush", e))?;

    let mut raw = Vec::new();
    // Bound the DoH response; a healthy response is a few hundred bytes.
    let mut buf = [0u8; 4096];
    loop {
        if Instant::now() >= deadline {
            return Err(SealError::Dns {
                detail: "DoH exchange exceeded deadline".into(),
            });
        }
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 64 * 1024 {
                    return Err(SealError::Dns {
                        detail: "DoH response exceeded size bound".into(),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(SealError::Dns {
                    detail: "DoH read timed out".into(),
                });
            }
            Err(e) => return Err(map_io("DoH read", e)),
        }
    }
    split_http_body(&raw)
}

fn exchange_dot(
    endpoint: &ResolverEndpoint,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, SealError> {
    let mut tls = connect_tls(endpoint, deadline)?;
    let len = u16::try_from(query.len()).map_err(|_| SealError::Dns {
        detail: "DNS query exceeds DoT length frame".into(),
    })?;
    tls.write_all(&len.to_be_bytes())
        .map_err(|e| map_io("DoT length write", e))?;
    tls.write_all(query)
        .map_err(|e| map_io("DoT query write", e))?;
    tls.flush().map_err(|e| map_io("DoT flush", e))?;

    let mut len_buf = [0u8; 2];
    read_exact_deadline(&mut tls, &mut len_buf, deadline)?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 64 * 1024 {
        return Err(SealError::Dns {
            detail: "DoT response length out of bounds".into(),
        });
    }
    let mut resp = vec![0u8; resp_len];
    read_exact_deadline(&mut tls, &mut resp, deadline)?;
    Ok(resp)
}

fn connect_tls(
    endpoint: &ResolverEndpoint,
    deadline: Instant,
) -> Result<rustls::StreamOwned<ClientConnection, TcpStream>, SealError> {
    let remaining = remaining(deadline)?;
    let tcp = TcpStream::connect_timeout(&endpoint.socket_addr(), remaining)
        .map_err(|e| map_io("resolver TCP connect", e))?;
    tcp.set_read_timeout(Some(remaining))
        .map_err(|e| map_io("resolver set_read_timeout", e))?;
    tcp.set_write_timeout(Some(remaining))
        .map_err(|e| map_io("resolver set_write_timeout", e))?;

    let config = rustls_client_config()?;
    let server_name =
        ServerName::try_from(endpoint.sni.to_string()).map_err(|_| SealError::Dns {
            detail: format!("invalid resolver SNI '{}'", endpoint.sni),
        })?;
    let conn =
        ClientConnection::new(Arc::new(config), server_name).map_err(|e| SealError::Dns {
            detail: format!("rustls client init failed: {e}"),
        })?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    // Drive the handshake eagerly so later HTTP/DNS writes run under TLS 1.3.
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|e| map_io("resolver TLS handshake", e))?;
        if Instant::now() >= deadline {
            return Err(SealError::Dns {
                detail: "resolver TLS handshake exceeded deadline".into(),
            });
        }
    }
    // TLS 1.3 is preferred by rustls default proto list; reject legacy stacking
    // so the DoH/DoT path itself matches the in-enclave TLS 1.3 posture.
    match stream.conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => Ok(stream),
        Some(other) => Err(SealError::Dns {
            detail: format!("resolver negotiated non-TLS-1.3 version {other:?}"),
        }),
        None => Err(SealError::Dns {
            detail: "resolver TLS version not negotiated".into(),
        }),
    }
}

fn rustls_client_config() -> Result<ClientConfig, SealError> {
    // Install once; ignore AlreadyInstalled so concurrent tests share state.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    // DoH is plain HTTP/1.1 over TLS; DoT has no ALPN requirement (we still
    // restrict to TLS 1.3 via the protocol-versions list above).
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn split_http_body(raw: &[u8]) -> Result<Vec<u8>, SealError> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| SealError::Dns {
            detail: "DoH response missing header terminator".into(),
        })?;
    let headers = &raw[..sep];
    let body = &raw[sep + 4..];
    // Status line must be 2xx.
    let status_ok = headers.starts_with(b"HTTP/1.1 2") || headers.starts_with(b"HTTP/1.0 2");
    if !status_ok {
        return Err(SealError::Dns {
            detail: "DoH endpoint returned a non-2xx status".into(),
        });
    }
    // Handle Content-Length when present; otherwise take the remainder (Connection: close).
    if let Some(len) = content_length(headers) {
        if body.len() < len {
            return Err(SealError::Dns {
                detail: "DoH body shorter than Content-Length".into(),
            });
        }
        return Ok(body[..len].to_vec());
    }
    Ok(body.to_vec())
}

fn content_length(headers: &[u8]) -> Option<usize> {
    for line in headers.split(|b| *b == b'\n') {
        let line = trim_cr(line);
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if let Some(rest) = lower.strip_prefix(b"content-length:") {
            let text = std::str::from_utf8(trim_ws(rest)).ok()?;
            return text.trim().parse().ok();
        }
    }
    None
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_ws(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn read_exact_deadline<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), SealError> {
    let mut filled = 0;
    while filled < buf.len() {
        if Instant::now() >= deadline {
            return Err(SealError::Dns {
                detail: "DNS read exceeded deadline".into(),
            });
        }
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(SealError::Dns {
                    detail: "DNS stream closed before full frame".into(),
                });
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(SealError::Dns {
                    detail: "DNS read timed out".into(),
                });
            }
            Err(e) => return Err(map_io("DNS read", e)),
        }
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, SealError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| SealError::Dns {
            detail: "DNS deadline already elapsed".into(),
        })
}

fn map_io(context: &str, error: std::io::Error) -> SealError {
    SealError::Dns {
        detail: format!("{context}: {error}"),
    }
}

fn normalize_name(name: &str) -> Result<String, SealError> {
    let trimmed = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.contains("..")
        || trimmed.starts_with('.')
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(SealError::Dns {
            detail: "hostname is not a valid DNS name".into(),
        });
    }
    Ok(trimmed)
}

fn encode_name(name: &str) -> Result<Vec<u8>, SealError> {
    let mut out = Vec::new();
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(SealError::Dns {
                detail: "hostname has an empty or overlong DNS label".into(),
            });
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root
    Ok(out)
}

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize, SealError> {
    let mut jumps = 0usize;
    loop {
        if offset >= message.len() {
            return Err(SealError::Dns {
                detail: "DNS name overrun".into(),
            });
        }
        let len = message[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer — consume 2 bytes and stop (name ends here).
            if offset + 1 >= message.len() {
                return Err(SealError::Dns {
                    detail: "DNS compression pointer overrun".into(),
                });
            }
            return Ok(offset + 2);
        }
        if len & 0xc0 != 0 {
            return Err(SealError::Dns {
                detail: "DNS name uses unsupported label type".into(),
            });
        }
        offset = offset
            .checked_add(1 + len as usize)
            .ok_or_else(|| SealError::Dns {
                detail: "DNS name length overflow".into(),
            })?;
        jumps += 1;
        if jumps > 128 {
            return Err(SealError::Dns {
                detail: "DNS name too long".into(),
            });
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn build_query_embeds_qname_labels() {
        let q = build_query("www.example.com", QTYPE_A, 0x1234).unwrap();
        assert_eq!(&q[0..2], &0x1234u16.to_be_bytes());
        // Labels: 3www 7example 3com 0
        let labels = &q[12..];
        assert_eq!(&labels[..4], b"\x03www");
        assert!(labels.windows(8).any(|w| w == b"\x07example"));
        assert!(labels.windows(4).any(|w| w == b"\x03com"));
    }

    #[test]
    fn parse_answers_reads_a_record() {
        // Craft a minimal DNS response with one A answer for 93.184.216.34.
        let mut msg = build_query("example.com", QTYPE_A, 0x9999).unwrap();
        // Flip to response, no error, 1 answer.
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[6] = 0x00;
        msg[7] = 0x01; // ANCOUNT = 1
                       // Answer: pointer to name at offset 12, type A, class IN, TTL 60, rdlength 4, rdata.
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&QTYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[93, 184, 216, 34]);
        let answers = parse_answers(&msg, QTYPE_A).unwrap();
        assert_eq!(answers, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }

    #[test]
    fn resolve_for_connect_short_circuits_ip_literals() {
        struct NeverCalled;
        impl NameResolver for NeverCalled {
            fn resolve_host(
                &self,
                _host: &str,
                _port: u16,
                _deadline: Instant,
            ) -> Result<Vec<SocketAddr>, SealError> {
                panic!("resolver must not be consulted for IP literals");
            }
            fn endpoint(&self) -> &ResolverEndpoint {
                &DEFAULT_DOH_ENDPOINT
            }
        }
        let addr = resolve_for_connect(
            "127.0.0.1",
            443,
            &NeverCalled,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443));
    }

    #[test]
    fn resolve_for_connect_maps_localhost_without_doh() {
        struct NeverCalled;
        impl NameResolver for NeverCalled {
            fn resolve_host(
                &self,
                _host: &str,
                _port: u16,
                _deadline: Instant,
            ) -> Result<Vec<SocketAddr>, SealError> {
                panic!("localhost must not hit DoH");
            }
            fn endpoint(&self) -> &ResolverEndpoint {
                &DEFAULT_DOH_ENDPOINT
            }
        }
        let addr = resolve_for_connect(
            "LocalHost",
            8080,
            &NeverCalled,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn default_endpoint_pins_cloudflare_doh_by_ip() {
        let ep = DEFAULT_DOH_ENDPOINT;
        assert_eq!(ep.ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(ep.port, 443);
        assert_eq!(ep.mode, ResolverMode::Doh);
        assert_eq!(ep.sni, "cloudflare-dns.com");
        // The pin must not require a hostname lookup of the resolver itself.
        assert!(ep.socket_addr().ip().is_ipv4());
    }
}
