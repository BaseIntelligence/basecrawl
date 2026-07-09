//! Minimal HTTP(S) fetch feeding the ScrapeProof `response` block.
//!
//! This is the foundational fetch path for the M1 envelope. Deeper HTTP semantics (content
//! decoding, redirect-hop capture, timeout tuning, transport-vs-status error classification)
//! are layered on by later crawler features; the in-process TLS 1.3 termination that populates
//! the `tls` block replaces this transport in the TLS-capture feature.

use crate::error::Error;
use sha2::{Digest, Sha256};
use std::time::Duration;
use url::Url;

/// A browser-plausible User-Agent so origins are not served a bare library fingerprint.
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Outcome of a single HTTP fetch.
pub struct Fetched {
    pub status_code: u16,
    pub headers_hash: String,
    pub body_hash: String,
    pub content_length: u64,
}

/// Perform a blocking HTTP GET against a validated URL.
pub fn fetch(url: &Url) -> Result<Fetched, Error> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(DEFAULT_USER_AGENT)
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()
        .map_err(|e| Error::Fetch(e.to_string()))?;

    let response = client
        .get(url.clone())
        .send()
        .map_err(|e| Error::Fetch(e.to_string()))?;

    let status_code = response.status().as_u16();
    let headers_hash = hash_headers(response.headers());
    let body = response.bytes().map_err(|e| Error::Fetch(e.to_string()))?;
    let body_hash = sha256_hex(&body);
    let content_length = body.len() as u64;

    Ok(Fetched {
        status_code,
        headers_hash,
        body_hash,
        content_length,
    })
}

fn hash_headers(headers: &reqwest::header::HeaderMap) -> String {
    let mut lines: Vec<String> = headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}: {}",
                name.as_str(),
                String::from_utf8_lossy(value.as_bytes())
            )
        })
        .collect();
    lines.sort();
    sha256_hex(lines.join("\n").as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_lowercase_and_64_wide() {
        let h = sha256_hex(b"");
        assert_eq!(h.len(), 64);
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
