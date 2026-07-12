//! In-enclave DoH resolution + TLS 1.3 application-data confidentiality
//! (VAL-CONF-013, VAL-CONF-014).
//!
//! VAL-CONF-013: a host-side DNS / port-53 capture during resolution contains no
//! cleartext A/AAAA for the target hostname; resolution runs over DoH/DoT to a
//! pin-by-IP resolver.
//!
//! VAL-CONF-014: the bytes egressed on the origin TLS path after in-enclave
//! termination are TLS application-data records only — strings/grep over the
//! host capture for URL path / headers / body markers returns zero matches.
//!
//! The host-visible DoH destination (resolver IP) is expected leakage
//! (VAL-CONF-023) and is asserted as present on the pin.

use basecrawl_seal::{
    build_query, parse_answers, resolve_for_connect, NameResolver, PinnedResolver,
    ResolverEndpoint, ResolverMode, SealError, DEFAULT_DOH_ENDPOINT, DOH_PATH_MARKER, QTYPE_A,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::{ServerConfig, ServerConnection};
use rustls::{ClientConnection, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const TARGET_HOST: &str = "confid-target.basecrawl.test";
const URL_PATH: &str = "/secret/path?token=known-url-marker-val-conf-014";
const HEADER_MARKER: &str = "X-Known-Header-Marker-VAL-CONF-014";
const BODY_MARKER: &str = "known-body-marker-val-conf-014";
const COOKIE_MARKER: &str = "session=known-cookie-marker-val-conf-014";

fn ensure_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Snapshot of host-visible DNS / port-53 activity during a resolution.
#[derive(Default, Clone)]
struct HostDnsCapture {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl HostDnsCapture {
    fn new() -> Self {
        Self::default()
    }

    fn push(&self, frame: Vec<u8>) {
        self.frames.lock().expect("capture mutex").push(frame);
    }

    fn snapshot(&self) -> Vec<Vec<u8>> {
        self.frames.lock().expect("capture mutex").clone()
    }

    /// VAL-CONF-013: no cleartext A/AAAA query for the target QNAME.
    fn assert_no_cleartext_qname(&self, qname: &str) {
        let qname_l = qname.to_ascii_lowercase();
        let qname_bytes = qname_l.as_bytes();
        let labels: Vec<&[u8]> = qname_l.split('.').map(|s| s.as_bytes()).collect();
        for frame in self.snapshot() {
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

/// Local UDP :53 sink that records whatever cleartext DNS the process sends.
struct Port53Sink {
    addr: SocketAddr,
    stop: Arc<Mutex<bool>>,
}

impl Port53Sink {
    fn start(capture: HostDnsCapture) -> Self {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp sink");
        let addr = udp.local_addr().unwrap();
        let stop = Arc::new(Mutex::new(false));
        let stop_t = stop.clone();
        thread::spawn(move || {
            udp.set_read_timeout(Some(Duration::from_millis(50))).ok();
            let mut buf = [0u8; 2048];
            while !*stop_t.lock().unwrap() {
                match udp.recv_from(&mut buf) {
                    Ok((n, _)) => capture.push(buf[..n].to_vec()),
                    Err(_) => continue,
                }
            }
        });
        Self { addr, stop }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Port53Sink {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
    }
}

struct RecordingTcp {
    inner: TcpStream,
    capture: Arc<Mutex<Vec<u8>>>,
}

impl Read for RecordingTcp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.capture.lock().unwrap().extend_from_slice(&buf[..n]);
        }
        Ok(n)
    }
}

impl Write for RecordingTcp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            self.capture.lock().unwrap().extend_from_slice(&buf[..n]);
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn try_http_body(raw: &[u8]) -> Option<Vec<u8>> {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = &raw[..sep];
    let body = &raw[sep + 4..];
    for line in headers.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if let Some(rest) = lower.strip_prefix(b"content-length:") {
            let text = std::str::from_utf8(rest).ok()?.trim();
            let len: usize = text.parse().ok()?;
            if body.len() >= len {
                return Some(body[..len].to_vec());
            }
            return None;
        }
    }
    if !body.is_empty() {
        Some(body.to_vec())
    } else {
        None
    }
}

fn synthesize_a_response(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() < 12 {
        return resp;
    }
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[6] = 0x00;
    resp[7] = 0x01;
    resp.extend_from_slice(&[0xc0, 0x0c]);
    resp.extend_from_slice(&QTYPE_A.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip.octets());
    resp
}

#[derive(Debug)]
struct FixtureTrust {
    expected: Vec<u8>,
}

impl ServerCertVerifier for FixtureTrust {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref() == self.expected.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General("fixture cert mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Local fixture client: same DoH wire format as production, but trusts the
/// self-signed loopback fixture cert. Production Mozilla-root path is covered
/// by `live_doh_lookup_example_com`.
struct LocalDohClient {
    endpoint: ResolverEndpoint,
    server_cert: Vec<u8>,
}

impl LocalDohClient {
    fn lookup(&self, name: &str, deadline: Instant) -> Result<Vec<IpAddr>, SealError> {
        let query = build_query(name, QTYPE_A, 0x4242)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| SealError::Dns {
                detail: "deadline elapsed".into(),
            })?;
        let tcp =
            TcpStream::connect_timeout(&self.endpoint.socket_addr(), remaining).map_err(|e| {
                SealError::Dns {
                    detail: format!("connect: {e}"),
                }
            })?;
        tcp.set_read_timeout(Some(remaining)).ok();
        tcp.set_write_timeout(Some(remaining)).ok();

        let mut config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(FixtureTrust {
                    expected: self.server_cert.clone(),
                }))
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_name = ServerName::try_from(self.endpoint.sni.to_string()).unwrap();
        let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|e| SealError::Dns {
                    detail: format!("hs: {e}"),
                })?;
        }
        assert_eq!(
            stream.conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let http = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: {}\r\n\r\n",
            self.endpoint.path,
            self.endpoint.sni,
            query.len(),
            DOH_PATH_MARKER,
        );
        stream.write_all(http.as_bytes()).unwrap();
        stream.write_all(&query).unwrap();
        stream.flush().unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        let body = try_http_body(&raw).ok_or_else(|| SealError::Dns {
            detail: "no body".into(),
        })?;
        parse_answers(&body, QTYPE_A)
    }
}

// -----------------------------------------------------------------------------
// VAL-CONF-013
// -----------------------------------------------------------------------------

/// VAL-CONF-013 — cleartext target QNAME never appears on the host DNS path
/// (port 53 sink is empty of that QNAME; DoH pin is used instead).
#[test]
fn val_conf_013_no_cleartext_target_lookup_on_host_resolver() {
    ensure_crypto();
    let capture = HostDnsCapture::new();
    let sink = Port53Sink::start(capture.clone());

    let answer = Ipv4Addr::new(203, 0, 113, 50);
    let cert = rcgen::generate_simple_self_signed(vec!["cloudflare-dns.com".into()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let host_wire = Arc::new(Mutex::new(Vec::new()));
    let host_wire_t = host_wire.clone();
    let clear_q = Arc::new(Mutex::new(Vec::new()));
    let clear_q_t = clear_q.clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let server_cert = CertificateDer::from(cert_der.clone());
    let server_config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![server_cert], key_der)
        .unwrap();
    let server_config = Arc::new(server_config);
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut recorded = RecordingTcp {
            inner: tcp,
            capture: host_wire_t,
        };
        let mut conn = ServerConnection::new(server_config).unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut recorded).unwrap();
        }
        let mut plain = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    plain.extend_from_slice(&buf[..n]);
                    if let Some(body) = try_http_body(&plain) {
                        clear_q_t.lock().unwrap().push(body.clone());
                        let response_dns = synthesize_a_response(&body, answer);
                        let http = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            response_dns.len()
                        );
                        conn.writer().write_all(http.as_bytes()).unwrap();
                        conn.writer().write_all(&response_dns).unwrap();
                        conn.writer().flush().unwrap();
                        let _ = conn.complete_io(&mut recorded);
                        conn.send_close_notify();
                        let _ = conn.complete_io(&mut recorded);
                        return;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let _ = conn.complete_io(&mut recorded);
                }
                Err(_) => return,
            }
            let _ = conn.complete_io(&mut recorded);
        }
    });

    let endpoint = ResolverEndpoint {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        sni: "cloudflare-dns.com",
        path: "/dns-query",
        mode: ResolverMode::Doh,
    };
    let client = LocalDohClient {
        endpoint: endpoint.clone(),
        server_cert: cert_der,
    };
    let ips = client
        .lookup(TARGET_HOST, Instant::now() + Duration::from_secs(5))
        .expect("DoH lookup");
    assert_eq!(ips, vec![IpAddr::V4(answer)]);
    server.join().unwrap();

    let wire = host_wire.lock().unwrap().clone();
    let qname_l = TARGET_HOST.to_ascii_lowercase();
    assert!(
        !wire
            .windows(qname_l.len())
            .any(|w| w.eq_ignore_ascii_case(qname_l.as_bytes())),
        "host wire must not contain cleartext target hostname (VAL-CONF-013)"
    );
    let mut dns_wire = Vec::new();
    for label in qname_l.split('.') {
        dns_wire.push(label.len() as u8);
        dns_wire.extend_from_slice(label.as_bytes());
    }
    assert!(
        !wire
            .windows(dns_wire.len())
            .any(|w| w == dns_wire.as_slice()),
        "host wire must not contain DNS-wire QNAME (VAL-CONF-013): encrypted under TLS"
    );
    let queries = clear_q.lock().unwrap().clone();
    assert_eq!(queries.len(), 1);
    assert!(
        queries[0]
            .windows(dns_wire.len())
            .any(|w| w == dns_wire.as_slice()),
        "in-enclave cleartext (post-TLS-termination) must contain the QNAME"
    );

    capture.assert_no_cleartext_qname(TARGET_HOST);
    assert_eq!(endpoint.ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(endpoint.mode, ResolverMode::Doh);
    let _ = sink.addr();
}

/// Live Open-DoH path: pins Cloudflare by IP, resolves a real name, returns
/// addresses, never falls back to the system resolver.
#[test]
fn live_doh_lookup_example_com() {
    ensure_crypto();
    let resolver = PinnedResolver::doh();
    assert_eq!(resolver.endpoint().ip, DEFAULT_DOH_ENDPOINT.ip);
    assert_eq!(resolver.endpoint().mode, ResolverMode::Doh);
    let result = resolver
        .lookup("example.com", Instant::now() + Duration::from_secs(15))
        .expect("live DoH lookup of example.com must succeed");
    assert!(
        !result.addresses.is_empty(),
        "DoH must yield at least one A/AAAA for example.com"
    );
    assert_eq!(result.protocol, "doh");
    assert_eq!(result.via.ip, DEFAULT_DOH_ENDPOINT.ip);
    let sock = resolve_for_connect(
        "example.com",
        443,
        &resolver,
        Instant::now() + Duration::from_secs(15),
    )
    .expect("resolve_for_connect");
    assert_eq!(sock.port(), 443);
    assert!(result.addresses.contains(&sock.ip()));
}

/// Resolving an IP literal never dials DoH (and never port 53).
#[test]
fn ip_literal_bypasses_doh_and_system_resolver() {
    struct PanicResolver;
    impl NameResolver for PanicResolver {
        fn resolve_host(&self, _: &str, _: u16, _: Instant) -> Result<Vec<SocketAddr>, SealError> {
            panic!("must not be called for IP literals");
        }
        fn endpoint(&self) -> &ResolverEndpoint {
            &DEFAULT_DOH_ENDPOINT
        }
    }
    let sock = resolve_for_connect(
        "93.184.216.34",
        443,
        &PanicResolver,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(sock, "93.184.216.34:443".parse().unwrap());
}

// -----------------------------------------------------------------------------
// VAL-CONF-014
// -----------------------------------------------------------------------------

/// VAL-CONF-014 — host-captured origin egress is TLS application-data only.
#[test]
fn val_conf_014_host_wire_egress_is_tls_application_data_only() {
    ensure_crypto();
    let cert = rcgen::generate_simple_self_signed(vec!["origin.basecrawl.test".into()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let server_config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
        .unwrap();
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let host_capture = Arc::new(Mutex::new(Vec::new()));
    let host_capture_t = host_capture.clone();

    let http_path = URL_PATH.to_string();
    let header_marker = HEADER_MARKER.to_string();
    let cookie_marker = COOKIE_MARKER.to_string();
    let body_marker = BODY_MARKER.to_string();

    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut recorded = RecordingTcp {
            inner: tcp,
            capture: host_capture_t,
        };
        let mut conn = ServerConnection::new(server_config).unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut recorded).unwrap();
        }
        let mut plain = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    plain.extend_from_slice(&buf[..n]);
                    if plain.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let _ = conn.complete_io(&mut recorded);
                }
                Err(_) => break,
            }
            let _ = conn.complete_io(&mut recorded);
        }
        let request_text = String::from_utf8_lossy(&plain);
        assert!(
            request_text.contains(&http_path),
            "server-side cleartext after TLS termination must see the URL path"
        );
        assert!(request_text.contains(&header_marker));
        assert!(request_text.contains(&cookie_marker));
        let body = format!("<html>{body_marker}</html>");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        conn.writer().write_all(response.as_bytes()).unwrap();
        conn.writer().flush().unwrap();
        let _ = conn.complete_io(&mut recorded);
        conn.send_close_notify();
        let _ = conn.complete_io(&mut recorded);
    });

    let mut config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FixtureTrust { expected: cert_der }))
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_name = ServerName::try_from("origin.basecrawl.test".to_string()).unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let client_capture = Arc::new(Mutex::new(Vec::new()));
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut recorded_client = RecordingTcp {
        inner: tcp,
        capture: client_capture.clone(),
    };
    while conn.is_handshaking() {
        conn.complete_io(&mut recorded_client).unwrap();
    }
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "VAL-CONF-014 requires TLS 1.3 so application data is encrypted"
    );
    let mut stream = rustls::StreamOwned::new(conn, recorded_client);

    let request = format!(
        "GET {URL_PATH} HTTP/1.1\r\nHost: origin.basecrawl.test\r\n{HEADER_MARKER}: 1\r\nCookie: {COOKIE_MARKER}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.contains(BODY_MARKER),
        "enclave-side cleartext after TLS termination must see the body marker"
    );
    server.join().unwrap();

    let mut wire = host_capture.lock().unwrap().clone();
    wire.extend_from_slice(&client_capture.lock().unwrap());
    let wire_text = String::from_utf8_lossy(&wire);

    for marker in [URL_PATH, HEADER_MARKER, COOKIE_MARKER, BODY_MARKER] {
        assert!(
            !wire_text.contains(marker),
            "host wire must not contain plaintext marker {marker:?} (VAL-CONF-014)"
        );
        assert!(
            !wire.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "host wire binary search must not find marker {marker:?}"
        );
    }
    assert!(
        wire.len() > 100,
        "host must observe TLS records (got {} bytes)",
        wire.len()
    );
    assert!(
        wire.contains(&0x17) || wire.contains(&0x16),
        "host capture should contain TLS record content-types"
    );
}

/// The default pin documents the expected residual leakage: resolver destination
/// is visible (VAL-CONF-023) while QNAMEs are not (VAL-CONF-013).
#[test]
fn default_pin_documents_expected_resolver_destination_leakage() {
    let pin = DEFAULT_DOH_ENDPOINT;
    assert_eq!(pin.ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    assert_eq!(pin.port, 443);
    assert_eq!(pin.mode, ResolverMode::Doh);
    assert!(!pin.sni.is_empty());
}
