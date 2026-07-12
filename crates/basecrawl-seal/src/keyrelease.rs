//! Enclave-side RA-TLS key-release CLIENT.
//!
//! Wire contract (matches `relay.keyrelease.server`):
//! * `GET|POST /nonce` → `{"nonce": "..."}`
//! * `POST /release` with `{nonce, quote, ra_tls_pubkey, event_log?}` and the
//!   `X-RA-TLS-Peer-Key` header →
//!   `{"released": true, "key": "<base64 sealed-to-session>"}` or
//!   `{"released": false, "reason": "<code>"}` (no `key` field on deny).
//!
//! The response `key` is **session-sealed** (libsodium sealed-box to the enclave
//! RA-TLS X25519 public key). The client opens it with the matching private key
//! before the bytes can be used as a task-decryption secret (VAL-CONF-030).
//! Successful release is available as a [`ReleasedTaskKey`] held only in enclave
//! memory (never logged).

use crate::error::SealError;
use crate::identity::{hex_encode, EnclaveIdentity};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Domain-separation tag bound into the key-release quote's `report_data`.
/// Must match `relay.keyrelease.report_data.KEY_RELEASE_TAG`. Distinct from
/// the ScrapeProof result-attestation tag.
pub const KEY_RELEASE_TAG: &[u8] = b"basecrawl-keyrelease-v1";

/// HTTP header carrying the RA-TLS session peer public key (lowercase hex).
pub const RA_TLS_PEER_HEADER: &str = "X-RA-TLS-Peer-Key";

/// Default per-request timeout for the key-release HTTP exchange.
pub const DEFAULT_KEY_RELEASE_TIMEOUT: Duration = Duration::from_secs(30);

/// TDX `report_data` field width.
pub const REPORT_DATA_LEN: usize = 64;

/// Compute the 32-byte key-release binding digest
/// `SHA256(KEY_RELEASE_TAG ∥ nonce ∥ ra_tls_pubkey)`.
pub fn key_release_report_data(nonce: &str, ra_tls_pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_RELEASE_TAG);
    hasher.update(nonce.as_bytes());
    hasher.update(ra_tls_pubkey);
    hasher.finalize().into()
}

/// Left-align a 32-byte binding into the 64-byte TDX report_data field (lowercase hex).
pub fn to_report_data_field(binding: &[u8]) -> String {
    let mut field = [0u8; REPORT_DATA_LEN];
    let copy = binding.len().min(REPORT_DATA_LEN);
    field[..copy].copy_from_slice(&binding[..copy]);
    hex_encode(&field)
}

/// Held-only-in-enclave task key (zeroized on drop; never Display/log).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ReleasedTaskKey {
    bytes: Vec<u8>,
}

impl ReleasedTaskKey {
    /// Construct from opened session-sealed key material.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SealError> {
        if bytes.is_empty() {
            return Err(SealError::KeyReleaseProtocol {
                detail: "released key is empty".into(),
            });
        }
        Ok(Self { bytes })
    }

    /// Borrow the raw key bytes (enclave-only; never log this).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of key bytes (safe to surface; not the material itself).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when no key material is held.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for ReleasedTaskKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleasedTaskKey")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Source of TDX quotes for the key-release exchange.
///
/// Production implementations call the in-CVM dstack guest agent. Tests inject
/// a static fixture quote that already binds the expected `report_data`.
pub trait QuoteProvider: Send + Sync {
    /// Produce a quote for the given 64-byte (hex) `report_data` field.
    fn get_quote(&self, report_data_hex: &str) -> Result<QuoteBundle, SealError>;
}

/// Material returned by a quote provider for the `/release` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteBundle {
    /// TDX quote bytes encoded as hex (as required by the Python wire contract).
    pub quote_hex: String,
    /// Optional RTMR3 event log forwarded to the measurement gate.
    #[serde(default)]
    pub event_log: Option<Value>,
    /// Optional vm_config passthrough (never trusted for measurement).
    #[serde(default)]
    pub vm_config: Option<Value>,
}

/// Transport for the key-release HTTP wire. Injectable for tests / mTLS.
pub trait KeyReleaseTransport: Send + Sync {
    /// Perform `GET|POST path` with an optional JSON body and headers.
    fn request_json(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<(u16, Value), SealError>;
}

/// Stdlib HTTP client against a base `http://host:port` endpoint (dev fixture).
///
/// Production RA-TLS traffic uses a terminator that injects
/// `X-RA-TLS-Peer-Key`; this transport still **sends** that header so the
/// measurement-gated server can bind the session. TLS terminator identity is
/// out of scope for this module (see RA-TLS guest stack).
#[derive(Debug, Clone)]
pub struct HttpKeyReleaseTransport {
    host: String,
    port: u16,
    timeout: Duration,
    /// Force `POST` optionally for /nonce (server accepts both).
    pub post_nonce: bool,
}

impl HttpKeyReleaseTransport {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            timeout: DEFAULT_KEY_RELEASE_TIMEOUT,
            post_nonce: false,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl KeyReleaseTransport for HttpKeyReleaseTransport {
    fn request_json(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<(u16, Value), SealError> {
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let addr: std::net::SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|_| SealError::KeyReleaseUnreachable)?;
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|_| SealError::KeyReleaseUnreachable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| SealError::Transport {
                detail: e.to_string(),
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| SealError::Transport {
                detail: e.to_string(),
            })?;

        let body_bytes = body
            .map(|v| {
                serde_json::to_vec(v).map_err(|e| SealError::Transport {
                    detail: e.to_string(),
                })
            })
            .transpose()?
            .unwrap_or_default();

        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: close\r\n",
            method = method,
            path = path,
            host = self.host,
            port = self.port,
        );
        if body.is_some() {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
        }
        for (name, value) in headers {
            // Never print header values to host-visible logs from this path.
            req.push_str(name);
            req.push_str(": ");
            req.push_str(value);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");

        stream
            .write_all(req.as_bytes())
            .map_err(|_| SealError::KeyReleaseUnreachable)?;
        if !body_bytes.is_empty() {
            stream
                .write_all(&body_bytes)
                .map_err(|_| SealError::KeyReleaseMidExchange)?;
        }
        stream
            .flush()
            .map_err(|_| SealError::KeyReleaseMidExchange)?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|_| SealError::KeyReleaseMidExchange)?;
        parse_http_json_response(&raw)
    }
}

fn parse_http_json_response(raw: &[u8]) -> Result<(u16, Value), SealError> {
    let text = std::str::from_utf8(raw).map_err(|_| SealError::KeyReleaseProtocol {
        detail: "response is not UTF-8".into(),
    })?;
    let (header, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or(SealError::KeyReleaseProtocol {
            detail: "response missing header terminator".into(),
        })?;
    let status_line = header.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(SealError::KeyReleaseProtocol {
            detail: "response status line is malformed".into(),
        })?;
    // Handle Content-Length / body as-returned. Empty body is a protocol error.
    let body = body.trim_start_matches('\u{feff}');
    if body.is_empty() {
        return Err(SealError::KeyReleaseProtocol {
            detail: "response body is empty".into(),
        });
    }
    let value: Value = serde_json::from_str(body).map_err(|_| SealError::KeyReleaseProtocol {
        detail: "response body is not JSON".into(),
    })?;
    Ok((status, value))
}

/// Enclave-side key-release client. Fail-closed on every non-canonical condition.
pub struct KeyReleaseClient<T: KeyReleaseTransport, Q: QuoteProvider> {
    transport: T,
    quote_provider: Q,
    identity: EnclaveIdentity,
    /// Timeout is owned by the transport; retained for tests that want to surface it.
    pub timeout: Duration,
}

impl<T: KeyReleaseTransport, Q: QuoteProvider> KeyReleaseClient<T, Q> {
    pub fn new(transport: T, quote_provider: Q, identity: EnclaveIdentity) -> Self {
        Self {
            transport,
            quote_provider,
            identity,
            timeout: DEFAULT_KEY_RELEASE_TIMEOUT,
        }
    }

    /// Borrow the enclave identity used for RA-TLS peer binding / sealed-box open.
    pub fn identity(&self) -> &EnclaveIdentity {
        &self.identity
    }

    /// Full nonce → quote → `/release` exchange. Returns the released task key
    /// (session-unsealed) or a typed deny / transport error. Never returns key
    /// material on any deny path.
    pub fn obtain_task_key(&self) -> Result<ReleasedTaskKey, SealError> {
        let nonce = self.request_nonce()?;
        let ra_tls_pubkey = self.identity.public_key_bytes();
        let binding = key_release_report_data(&nonce, ra_tls_pubkey);
        let report_data_hex = to_report_data_field(&binding);
        let quote = self.quote_provider.get_quote(&report_data_hex)?;

        let mut body = json!({
            "nonce": nonce,
            "quote": quote.quote_hex,
            "ra_tls_pubkey": hex_encode(ra_tls_pubkey),
        });
        if let Some(event_log) = quote.event_log {
            body["event_log"] = event_log;
        }
        if let Some(vm_config) = quote.vm_config {
            body["vm_config"] = vm_config;
        }

        let peer_header = hex_encode(ra_tls_pubkey);
        let headers = vec![(RA_TLS_PEER_HEADER, peer_header)];
        let (status, response) = self
            .transport
            .request_json("POST", "/release", &headers, Some(&body))
            .map_err(|e| match e {
                SealError::KeyReleaseUnreachable => SealError::KeyReleaseMidExchange,
                other => other,
            })?;

        if !(200..300).contains(&status) {
            // Reachable but refused: fail closed.
            let reason = response
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("http_error")
                .to_string();
            return Err(SealError::KeyReleaseDenied { reason });
        }

        parse_release_response(&response, &self.identity)
    }

    fn request_nonce(&self) -> Result<String, SealError> {
        let method = "GET";
        let (status, response) = self.transport.request_json(method, "/nonce", &[], None)?;
        if !(200..300).contains(&status) {
            return Err(SealError::KeyReleaseDenied {
                reason: format!("nonce_http_{status}"),
            });
        }
        let nonce = response.get("nonce").and_then(|v| v.as_str()).ok_or(
            SealError::KeyReleaseProtocol {
                detail: "nonce response missing nonce field".into(),
            },
        )?;
        if nonce.is_empty() {
            return Err(SealError::KeyReleaseProtocol {
                detail: "nonce response is empty".into(),
            });
        }
        Ok(nonce.to_string())
    }
}

/// Parse a `/release` JSON body, unsealing a success response to the session identity.
pub fn parse_release_response(
    response: &Value,
    identity: &EnclaveIdentity,
) -> Result<ReleasedTaskKey, SealError> {
    let released = response.get("released").and_then(|v| v.as_bool()).ok_or(
        SealError::KeyReleaseProtocol {
            detail: "release response missing released flag".into(),
        },
    )?;
    if !released {
        // Deny path: no key field may be accepted. Reason is host-safe code.
        if response.get("key").is_some() {
            return Err(SealError::KeyReleaseProtocol {
                detail: "deny response must not include key material".into(),
            });
        }
        let reason = response
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("denied")
            .to_string();
        return Err(SealError::KeyReleaseDenied { reason });
    }

    let key_b64 =
        response
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or(SealError::KeyReleaseProtocol {
                detail: "success response missing key field".into(),
            })?;
    let sealed = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        key_b64.as_bytes(),
    )
    .map_err(|_| SealError::KeyReleaseProtocol {
        detail: "success response key is not valid base64".into(),
    })?;
    if sealed.is_empty() {
        return Err(SealError::KeyReleaseProtocol {
            detail: "success response key is empty".into(),
        });
    }

    // Open the session-sealed envelope with the enclave private key. A response
    // sealed to any other session cannot be opened (VAL-CONF-030).
    let opened = identity
        .secret_key()
        .unseal(&sealed)
        .map_err(|_| SealError::AuthenticationFailed)?;
    let opened = Zeroizing::new(opened);
    ReleasedTaskKey::from_bytes(opened.to_vec())
}

/// Convenience: when key-release is denied (or no key is held), sealed-task
/// decrypt always fails closed. Models VAL-CONF-011 for the host/forked path.
pub fn decrypt_requires_released_key(key: Option<&ReleasedTaskKey>) -> Result<(), SealError> {
    match key {
        Some(k) if !k.is_empty() => Ok(()),
        _ => Err(SealError::KeyNotReleased),
    }
}
