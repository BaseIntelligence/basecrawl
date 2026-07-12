//! In-enclave authenticated decryption of sealed scrape tasks.
//!
//! Wire envelope (must match `relay.seal.tasks`):
//! ```json
//! {
//!   "version": 1,
//!   "suite": "libsodium-sealed-box-x25519-xsalsa20-poly1305",
//!   "recipient_key_id": "sha256:<hex>",
//!   "enc": null,
//!   "ciphertext": "<base64url>"
//! }
//! ```
//!
//! Ciphertext is a libsodium sealed box over `aad || 0x00 || json_task` where
//! `aad = domain|task_id=...|nonce=...|recipient_key_id=...`. Opening requires
//! the enclave private key. Tamper/truncate fails AEAD authentication with
//! zero partial plaintext emitted (VAL-CONF-027). Without that private key /
//! released identity nothing recovers plaintext (VAL-CONF-011).

use crate::error::SealError;
use crate::identity::{hex_encode, EnclaveIdentity, TASK_SEAL_DOMAIN};
use crypto_box::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Suite identifier for the sealed-task construction (must match relay).
pub const TASK_SEAL_SUITE: &str = "libsodium-sealed-box-x25519-xsalsa20-poly1305";

/// Minimum sealed-box ciphertext length: 32-byte ephemeral pubkey + 16-byte MAC.
const MIN_SEALED_CIPHERTEXT_LEN: usize = 48;

/// Host-visible sealed-task envelope (ciphertext only + non-sensitive routing ids).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedTaskEnvelope {
    pub version: u32,
    pub suite: String,
    pub recipient_key_id: String,
    #[serde(default)]
    pub enc: Option<Value>,
    pub ciphertext: String,
}

/// Result of a successful in-enclave unseal: the full task object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecryptedTask {
    /// Raw JSON task recovered from the authenticated plaintext.
    pub task: Value,
    pub task_id: String,
    pub nonce: String,
}

/// Decrypt and authenticate a sealed task with the enclave private key.
///
/// On any authentication or parse failure this returns a typed [`SealError`] and
/// **never** yields partial plaintext. Callers must treat every `Err` as
/// "reject the task; emit nothing".
pub fn decrypt_sealed_task(
    envelope: &SealedTaskEnvelope,
    identity: &EnclaveIdentity,
) -> Result<DecryptedTask, SealError> {
    validate_envelope_shape(envelope, Some(identity.key_id()))?;
    let ciphertext = decode_b64url(&envelope.ciphertext)?;
    if ciphertext.len() <= MIN_SEALED_CIPHERTEXT_LEN {
        return Err(SealError::AuthenticationFailed);
    }

    let secret = identity.secret_key();
    let authenticated = open_sealed_box(&secret, &ciphertext)?;
    // Scope the Zeroizing so the decrypted plaintext is wiped on every exit path
    // (including validation failures) and never left around as "partial" bytes.
    let authenticated = Zeroizing::new(authenticated);

    let (aad, plaintext) = split_aad_plaintext(&authenticated)?;
    let (task_id, nonce, bound_key_id) = parse_aad(aad)?;

    let expected_aad = build_aad(&task_id, &nonce, identity.key_id())?;
    if !constant_time_eq(aad, &expected_aad) || bound_key_id != identity.key_id() {
        return Err(SealError::AuthenticationFailed);
    }
    if bound_key_id != envelope.recipient_key_id {
        return Err(SealError::AuthenticationFailed);
    }

    let task: Value =
        serde_json::from_slice(plaintext).map_err(|_| SealError::MalformedPlaintext)?;
    let task_obj = task.as_object().ok_or(SealError::MalformedPlaintext)?;
    let recovered_id = task_obj
        .get("task_id")
        .and_then(|v| v.as_str())
        .ok_or(SealError::MalformedPlaintext)?;
    let recovered_nonce = task_obj
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or(SealError::MalformedPlaintext)?;
    if recovered_id != task_id || recovered_nonce != nonce {
        return Err(SealError::MalformedPlaintext);
    }

    Ok(DecryptedTask {
        task,
        task_id,
        nonce,
    })
}

/// Attempt host/forked-image decryption *without* a released enclave private key.
///
/// Always fails with an authentication error for a well-formed sealed envelope:
/// neither the host nor a non-allowlisted image holds the private key the
/// ciphertext was sealed to (VAL-CONF-011).
pub fn decrypt_without_released_key(
    envelope: &SealedTaskEnvelope,
) -> Result<DecryptedTask, SealError> {
    validate_envelope_shape(envelope, None)?;
    // No key is held. Decline without inventing a candidate private key, and
    // without ever attempting to surface ciphertext-as-plaintext.
    let _ = envelope;
    Err(SealError::KeyNotReleased)
}

/// Attempt unsealing with an unrelated secret. Always fails for a genuine
/// enclave-sealed envelope — models the "forked image" / wrong-measurement path.
pub fn decrypt_with_foreign_key(
    envelope: &SealedTaskEnvelope,
    foreign: &EnclaveIdentity,
) -> Result<DecryptedTask, SealError> {
    decrypt_sealed_task(envelope, foreign)
}

/// Build the authenticated AAD the relay embeds inside the sealed message.
pub fn build_aad(task_id: &str, nonce: &str, recipient_key_id: &str) -> Result<Vec<u8>, SealError> {
    if task_id.is_empty() || nonce.is_empty() || !is_key_id(recipient_key_id) {
        return Err(SealError::InvalidEnvelope {
            detail: "task sealing metadata is malformed".into(),
        });
    }
    Ok(format!(
        "{}|task_id={}|nonce={}|recipient_key_id={}",
        std::str::from_utf8(TASK_SEAL_DOMAIN).expect("static ASCII domain"),
        task_id,
        nonce,
        recipient_key_id
    )
    .into_bytes())
}

/// Content-address a 32-byte public key (`sha256:<hex>`).
pub fn recipient_key_id(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("sha256:{}", hex_encode(&digest))
}

fn validate_envelope_shape(
    envelope: &SealedTaskEnvelope,
    expected_key_id: Option<&str>,
) -> Result<(), SealError> {
    if envelope.version != 1 {
        return Err(SealError::InvalidEnvelope {
            detail: "unsupported version".into(),
        });
    }
    if envelope.suite != TASK_SEAL_SUITE {
        return Err(SealError::InvalidEnvelope {
            detail: "unsupported suite".into(),
        });
    }
    if !is_key_id(&envelope.recipient_key_id) {
        return Err(SealError::InvalidEnvelope {
            detail: "recipient_key_id is malformed".into(),
        });
    }
    if let Some(expected) = expected_key_id {
        if envelope.recipient_key_id != expected {
            return Err(SealError::InvalidEnvelope {
                detail: "recipient_key_id does not match enclave identity".into(),
            });
        }
    }
    if envelope.enc.is_some() && envelope.enc != Some(Value::Null) {
        return Err(SealError::InvalidEnvelope {
            detail: "envelope contains unsupported ephemeral key material".into(),
        });
    }
    if envelope.ciphertext.is_empty() {
        return Err(SealError::InvalidEnvelope {
            detail: "ciphertext is empty".into(),
        });
    }
    Ok(())
}

fn open_sealed_box(secret: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, SealError> {
    secret
        .unseal(ciphertext)
        .map_err(|_| SealError::AuthenticationFailed)
}

fn split_aad_plaintext(authenticated: &[u8]) -> Result<(&[u8], &[u8]), SealError> {
    let pos = authenticated
        .iter()
        .position(|&b| b == 0)
        .ok_or(SealError::MalformedPlaintext)?;
    let (aad, rest) = authenticated.split_at(pos);
    // rest starts with the null separator.
    Ok((aad, &rest[1..]))
}

fn parse_aad(aad: &[u8]) -> Result<(String, String, String), SealError> {
    let text = std::str::from_utf8(aad).map_err(|_| SealError::MalformedPlaintext)?;
    let mut parts = text.split('|');
    let domain = parts.next().ok_or(SealError::MalformedPlaintext)?;
    if domain.as_bytes() != TASK_SEAL_DOMAIN {
        return Err(SealError::AuthenticationFailed);
    }
    let mut task_id = None;
    let mut nonce = None;
    let mut key_id = None;
    for part in parts {
        if let Some(v) = part.strip_prefix("task_id=") {
            task_id = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("nonce=") {
            nonce = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("recipient_key_id=") {
            key_id = Some(v.to_string());
        }
    }
    match (task_id, nonce, key_id) {
        (Some(t), Some(n), Some(k)) if !t.is_empty() && !n.is_empty() && is_key_id(&k) => {
            Ok((t, n, k))
        }
        _ => Err(SealError::MalformedPlaintext),
    }
}

fn is_key_id(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        && hex == hex.to_ascii_lowercase()
}

fn decode_b64url(value: &str) -> Result<Vec<u8>, SealError> {
    if value.is_empty() {
        return Err(SealError::InvalidEnvelope {
            detail: "ciphertext is empty".into(),
        });
    }
    if !value
        .bytes()
        .all(|c| matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        || value.len() % 4 == 1
    {
        return Err(SealError::InvalidEnvelope {
            detail: "ciphertext is not valid base64url".into(),
        });
    }
    // Restore standard padding rules required by base64 crate max decoding.
    let mut padded = value.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE,
        padded.as_bytes(),
    )
    .map_err(|_| SealError::InvalidEnvelope {
        detail: "ciphertext is not valid base64url".into(),
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn aad_builder_matches_domain_pipe_layout() {
        let aad = build_aad(
            "task-1",
            "nonce-1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let s = String::from_utf8(aad).unwrap();
        assert!(s.starts_with("relay/task-seal/v1|task_id=task-1|"));
        assert!(s.contains("|nonce=nonce-1|"));
        assert!(s.contains("|recipient_key_id=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }
}
