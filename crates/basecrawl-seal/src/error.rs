//! Fail-closed error surface for enclave-side unsealing and key release.
//!
//! Errors never carry task plaintext, key bytes, or partial decrypt leftovers.
//! Callers may log `kind()` only; the Display form stays free of secret material.

use thiserror::Error;

/// Typed failure for key-release / sealed-task decrypt paths.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The key-release authority refused to release the task key (deny path).
    #[error("key release denied: {reason}")]
    KeyReleaseDenied { reason: String },

    /// The key-release endpoint was unreachable before a key could be obtained.
    #[error("key release endpoint unreachable")]
    KeyReleaseUnreachable,

    /// The connection failed after a nonce was issued but before a key arrived.
    #[error("key release failed mid-exchange")]
    KeyReleaseMidExchange,

    /// The authority's response violated the key-release wire contract.
    #[error("key release protocol error: {detail}")]
    KeyReleaseProtocol { detail: String },

    /// Required for every sealed-task open; no key material is available yet.
    #[error("task decryption key has not been released")]
    KeyNotReleased,

    /// Sealed-box / AEAD authentication failed (tamper, truncate, wrong key).
    #[error("sealed task authentication failed")]
    AuthenticationFailed,

    /// Envelope shape is malformed / unsupported (no attempt at recover).
    #[error("sealed task envelope is invalid: {detail}")]
    InvalidEnvelope { detail: String },

    /// Plaintext recovered by AEAD but failed structural / identity checks.
    #[error("sealed task plaintext is malformed")]
    MalformedPlaintext,

    /// Enclave identity material is invalid.
    #[error("enclave identity is invalid: {detail}")]
    InvalidIdentity { detail: String },

    /// Quote provider failed to produce a key-release quote.
    #[error("quote generation failed: {detail}")]
    QuoteFailed { detail: String },

    /// I/O or JSON transport failure boundary (no secret leakage).
    #[error("transport error: {detail}")]
    Transport { detail: String },

    /// In-enclave DoH/DoT resolution failed (no cleartext port-53 fallback).
    ///
    /// `detail` is host-safe: never contains the QNAME (target hostname) as raw
    /// text beyond coarse status codes, so host logs of this path stay free of
    /// scrape-target content. The variant is separate so VAL-CONF-013 tests can
    /// assert "pinned DNS failed closed" without system-resolver fallback.
    #[error("pinned DNS resolution failed: {detail}")]
    Dns { detail: String },
}

impl SealError {
    /// Stable machine-readable kind for host-safe error logging / metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::KeyReleaseDenied { .. } => "key_release_denied",
            Self::KeyReleaseUnreachable => "key_release_unreachable",
            Self::KeyReleaseMidExchange => "key_release_mid_exchange",
            Self::KeyReleaseProtocol { .. } => "key_release_protocol",
            Self::KeyNotReleased => "key_not_released",
            Self::AuthenticationFailed => "authentication_failed",
            Self::InvalidEnvelope { .. } => "invalid_envelope",
            Self::MalformedPlaintext => "malformed_plaintext",
            Self::InvalidIdentity { .. } => "invalid_identity",
            Self::QuoteFailed { .. } => "quote_failed",
            Self::Transport { .. } => "transport",
            Self::Dns { .. } => "dns",
        }
    }

    /// True when the failure is an authenticated-decryption reject (no plaintext).
    pub fn is_auth_failure(&self) -> bool {
        matches!(
            self,
            Self::AuthenticationFailed | Self::KeyNotReleased | Self::MalformedPlaintext
        )
    }
}
