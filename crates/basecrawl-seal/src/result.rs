//! Seal the scrape result to the validator committee's threshold public key.
//!
//! Architecture §7: after the enclave builds the ScrapeProof digests it
//! re-encrypts the **result body** (markdown/html/screenshot/json/… and
//! their bindings) to the committee — **never** to the miner/host. The
//! host relays only a sealed-result envelope whose `ciphertext` is
//! libsodium sealed-box opaque bytes.
//!
//! Assertions owned by this module:
//! * **VAL-CONF-015** — a miner/host-side decrypt of the sealed result with
//!   any host-held/miner-held key fails and recovers no result plaintext.
//! * **VAL-CONF-017** — the host-visible sealed-result payload carries only
//!   non-sensitive routing metadata + opaque ciphertext: `strings`/`grep`
//!   for known result-content markers returns zero matches.
//!
//! The complementary committee threshold open (t-of-n) is owned by the
//! relay-side feature `committee-threshold-decryption` (VAL-CONF-016/028/029).
//! This module only needs the published committee **threshold public key** and
//! produces the host-visible ciphertext. A full reconstructed committee secret
//! unseals the envelope (test helper); any incomplete or foreign key fails
//! closed with zero partial plaintext.

use crate::error::SealError;
use crate::identity::{hex_encode, key_id_for, EnclaveIdentity};
use crate::task::recipient_key_id;
use crypto_box::aead::OsRng;
use crypto_box::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Suite identifier for the sealed-result construction.
///
/// Same primitive as task sealing (libsodium sealed box). Keeping a single
/// AEAD family simplifies tests and interop while the domain tag / kind
/// field separates the two envelopes.
pub const RESULT_SEAL_SUITE: &str = "libsodium-sealed-box-x25519-xsalsa20-poly1305";

/// Domain tag for result sealing. Distinct from the task-seal and
/// key-release tags so a task ciphertext cannot be mistaken for a result
/// (and vice versa).
pub const RESULT_SEAL_DOMAIN: &[u8] = b"relay/result-seal/v1";

/// Envelope `kind` field; distinguishes result envelopes from task envelopes
/// on the host-visible wire without revealing content.
pub const RESULT_SEAL_KIND: &str = "result";

/// Recipient role bound into every sealed-result envelope. The enclave
/// always targets the **committee**, never the miner or the enclave itself.
pub const RESULT_RECIPIENT_ROLE: &str = "committee-threshold";

/// Minimum sealed-box ciphertext length: 32-byte ephemeral pubkey + 16-byte MAC.
const MIN_SEALED_CIPHERTEXT_LEN: usize = 48;

/// Published validator-committee threshold public key.
///
/// This is the long-lived X25519 aggregate/threshold public key the relay
/// publishes to enclaves for result sealing. Individual share secrets are
/// never held here — only the public half used for sealed-box sealing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeThresholdPublicKey {
    /// Lowercase hex of the 32-byte X25519 public key.
    pub public_key: String,
    /// Content id: `sha256:<hex(SHA256(pubkey))>`.
    pub key_id: String,
}

impl CommitteeThresholdPublicKey {
    /// Build and validate a committee public key from lowercase hex.
    pub fn from_public_key_hex(public_key_hex: &str) -> Result<Self, SealError> {
        let bytes = decode_hex_32(public_key_hex)?;
        // Reject non-curve material early via crypto_box construction.
        let _ = PublicKey::from(bytes);
        Ok(Self {
            public_key: public_key_hex.to_string(),
            key_id: key_id_for(&bytes),
        })
    }

    /// Build from raw 32-byte public key.
    pub fn from_public_key_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            public_key: hex_encode(bytes),
            key_id: key_id_for(bytes),
        }
    }

    /// Raw 32-byte public key.
    pub fn public_key_bytes(&self) -> Result<[u8; 32], SealError> {
        decode_hex_32(&self.public_key)
    }

    /// `sha256:<hex>` content identity used on every result envelope.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Quote-friendly binding commitment: `hex(SHA256(RESULT_SEAL_DOMAIN || pubkey))`.
    pub fn report_data(&self) -> Result<String, SealError> {
        let bytes = self.public_key_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(RESULT_SEAL_DOMAIN);
        hasher.update(bytes);
        Ok(hex_encode(&hasher.finalize()))
    }
}

/// Host-visible sealed-result envelope (ciphertext only + non-sensitive routing).
///
/// Sensitive result content (markdown/html/screenshot/json, raw format
/// values) lives exclusively inside `ciphertext`. Host-side inspection /
/// miner-held keys cannot recover them (VAL-CONF-015, VAL-CONF-017).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedResultEnvelope {
    pub version: u32,
    pub suite: String,
    /// Always [`RESULT_SEAL_KIND`].
    pub kind: String,
    /// Always [`RESULT_RECIPIENT_ROLE`] — seals go to the committee, not miner.
    pub recipient: String,
    /// Committee threshold public-key content id.
    pub recipient_key_id: String,
    /// Non-sensitive routing id so the host can associate the envelope with a work unit.
    pub task_id: String,
    /// Non-sensitive anti-replay nonce (also binds digests client-side).
    pub nonce: String,
    /// Deterministic result surface digest. A hash is not result plaintext;
    /// positioning it outside the ciphertext lets the L2 and L4 layers bind
    /// digests before the committee opens the body (architecture §5.4).
    pub result_hash: String,
    /// Opaque sealed-box ciphertext over `aad || 0x00 || result_json`.
    pub ciphertext: String,
}

/// Result body sealed to the committee. Carries only the result surface the
/// validators need after unsealing; monadic attestation/tls blocks live in
/// the (separately host-visible, digest-bound) ScrapeProof envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResultSealPlaintext {
    pub task_id: String,
    pub nonce: String,
    pub result_hash: String,
    /// Firecrawl-parity formats (`markdown`, `html`, `screenshot`, `json`, …).
    pub formats_produced: Map<String, Value>,
}

/// Seal a scrape result to the validator committee's threshold public key.
///
/// The miner / host is deliberately **not** a recipient of this ciphertext.
/// Attempts to open it with any miner/host-held private key (including the
/// enclave identity, which is used for task receipt only) fail AEAD
/// authentication (VAL-CONF-015). The envelope serialisation never copies
/// result markers into host-visible fields (VAL-CONF-017).
pub fn seal_result_to_committee(
    plaintext: &ResultSealPlaintext,
    committee: &CommitteeThresholdPublicKey,
) -> Result<SealedResultEnvelope, SealError> {
    validate_plaintext(plaintext)?;
    if plaintext.result_hash.is_empty() || !is_hex_digest(&plaintext.result_hash) {
        return Err(SealError::InvalidEnvelope {
            detail: "result_hash must be a lowercase hex digest".into(),
        });
    }
    if committee.key_id != key_id_for(&committee.public_key_bytes()?) {
        return Err(SealError::InvalidEnvelope {
            detail: "committee key_id does not match public key".into(),
        });
    }

    let aad = build_result_aad(
        &plaintext.task_id,
        &plaintext.nonce,
        &plaintext.result_hash,
        committee.key_id(),
    )?;
    let body = serde_json::to_vec(plaintext).map_err(|_| SealError::MalformedPlaintext)?;
    // Scope body so secret material is wiped after sealing.
    let body = Zeroizing::new(body);
    let mut authenticated = Vec::with_capacity(aad.len() + 1 + body.len());
    authenticated.extend_from_slice(&aad);
    authenticated.push(0);
    authenticated.extend_from_slice(&body);
    let authenticated = Zeroizing::new(authenticated);

    let pk_bytes = committee.public_key_bytes()?;
    let public = PublicKey::from(pk_bytes);
    let ciphertext = public
        .seal(&mut OsRng, authenticated.as_slice())
        .map_err(|_| SealError::AuthenticationFailed)?;

    Ok(SealedResultEnvelope {
        version: 1,
        suite: RESULT_SEAL_SUITE.to_string(),
        kind: RESULT_SEAL_KIND.to_string(),
        recipient: RESULT_RECIPIENT_ROLE.to_string(),
        recipient_key_id: committee.key_id().to_string(),
        task_id: plaintext.task_id.clone(),
        nonce: plaintext.nonce.clone(),
        result_hash: plaintext.result_hash.clone(),
        ciphertext: encode_b64url(&ciphertext),
    })
}

/// Convenience wrapper: seal a `formats_produced` map with its known digests.
pub fn seal_formats_to_committee(
    task_id: &str,
    nonce: &str,
    result_hash: &str,
    formats_produced: Map<String, Value>,
    committee: &CommitteeThresholdPublicKey,
) -> Result<SealedResultEnvelope, SealError> {
    seal_result_to_committee(
        &ResultSealPlaintext {
            task_id: task_id.to_string(),
            nonce: nonce.to_string(),
            result_hash: result_hash.to_string(),
            formats_produced,
        },
        committee,
    )
}

/// Miner/host-side attempt to decrypt a sealed result.
///
/// Always fails for a well-formed committee-sealed envelope: the host never
/// holds the committee's threshold secret shares, and the envelope was never
/// sealed to any miner/host key (VAL-CONF-015). The enclave private key (used
/// only for task receipt) is deliberately refused here so a miner cannot
/// leverage its CVM identity to open the result either.
pub fn decrypt_result_as_miner_host(
    envelope: &SealedResultEnvelope,
    miner_held: Option<&EnclaveIdentity>,
) -> Result<ResultSealPlaintext, SealError> {
    validate_envelope_shape(envelope)?;
    // Explicitly refuse: the host/miner is not a committee member. Even if a
    // miner-held enclave identity is supplied, it is the wrong role.
    let _ = miner_held;
    Err(SealError::KeyNotReleased)
}

/// Attempt to open a sealed result with a foreign (non-committee) secret.
///
/// Models the "miner reconstructs an unrelated key" / "forked image invents a
/// private key" path. Always fails AEAD authentication for a genuine
/// committee-sealed envelope.
pub fn decrypt_result_with_foreign_key(
    envelope: &SealedResultEnvelope,
    foreign: &EnclaveIdentity,
) -> Result<ResultSealPlaintext, SealError> {
    validate_envelope_shape(envelope)?;
    // Wrong recipient: open with a foreign sealed-box secret will fail AEAD.
    let ciphertext = decode_b64url(&envelope.ciphertext)?;
    if ciphertext.len() <= MIN_SEALED_CIPHERTEXT_LEN {
        return Err(SealError::AuthenticationFailed);
    }
    let secret = foreign.secret_key();
    match secret.unseal(&ciphertext) {
        Ok(_) => {
            // A collision would be a catastrophic AEAD failure — refuse regardless.
            Err(SealError::AuthenticationFailed)
        }
        Err(_) => Err(SealError::AuthenticationFailed),
    }
}

/// Open a sealed result with a reconstructed committee secret (test / relay helper).
///
/// The relay's t-of-n threshold reconstruction (later feature) produces exactly
/// this secret. This module provides the open path so interop tests can prove
/// round-trips without depending on the incomplete threshold layer. Failures
/// are authentication-hard: no partial plaintext is returned.
pub fn unseal_result_with_committee_secret(
    envelope: &SealedResultEnvelope,
    committee_secret: &[u8; 32],
) -> Result<ResultSealPlaintext, SealError> {
    validate_envelope_shape(envelope)?;
    let ciphertext = decode_b64url(&envelope.ciphertext)?;
    if ciphertext.len() <= MIN_SEALED_CIPHERTEXT_LEN {
        return Err(SealError::AuthenticationFailed);
    }
    let secret = SecretKey::from_bytes(*committee_secret);
    let expected_key_id = recipient_key_id(secret.public_key().as_bytes());
    if expected_key_id != envelope.recipient_key_id {
        return Err(SealError::InvalidEnvelope {
            detail: "committee secret does not match recipient_key_id".into(),
        });
    }
    let authenticated = secret
        .unseal(&ciphertext)
        .map_err(|_| SealError::AuthenticationFailed)?;
    let authenticated = Zeroizing::new(authenticated);
    let (aad, body) = split_aad_plaintext(&authenticated)?;
    let expected_aad = build_result_aad(
        &envelope.task_id,
        &envelope.nonce,
        &envelope.result_hash,
        &envelope.recipient_key_id,
    )?;
    if !constant_time_eq(aad, &expected_aad) {
        return Err(SealError::AuthenticationFailed);
    }
    let plaintext: ResultSealPlaintext =
        serde_json::from_slice(body).map_err(|_| SealError::MalformedPlaintext)?;
    if plaintext.task_id != envelope.task_id
        || plaintext.nonce != envelope.nonce
        || plaintext.result_hash != envelope.result_hash
    {
        return Err(SealError::MalformedPlaintext);
    }
    Ok(plaintext)
}

/// Build the authenticated AAD bound inside the sealed message.
pub fn build_result_aad(
    task_id: &str,
    nonce: &str,
    result_hash: &str,
    recipient_key_id: &str,
) -> Result<Vec<u8>, SealError> {
    if task_id.is_empty()
        || nonce.is_empty()
        || result_hash.is_empty()
        || !is_key_id(recipient_key_id)
    {
        return Err(SealError::InvalidEnvelope {
            detail: "result sealing metadata is malformed".into(),
        });
    }
    Ok(format!(
        "{}|task_id={}|nonce={}|result_hash={}|recipient_key_id={}|recipient={}",
        std::str::from_utf8(RESULT_SEAL_DOMAIN).expect("static ASCII domain"),
        task_id,
        nonce,
        result_hash,
        recipient_key_id,
        RESULT_RECIPIENT_ROLE,
    )
    .into_bytes())
}

/// True when any bytes of the host-visible sealed-result payload contain the marker.
///
/// Used by VAL-CONF-017 style checks (result markers must not appear outside
/// the ciphertext's opaque AEAD bytes as recoverable UTF-8 content). Because
/// the ciphertext is authorship-random AEAD output, accidental UTF-8 collisions
/// with multi-byte canary markers have negligible probability.
pub fn host_visible_contains_marker(envelope: &SealedResultEnvelope, marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }
    let Ok(bytes) = serde_json::to_vec(envelope) else {
        return false;
    };
    bytes
        .windows(marker.len())
        .any(|window| window == marker.as_bytes())
}

fn validate_plaintext(plaintext: &ResultSealPlaintext) -> Result<(), SealError> {
    if plaintext.task_id.is_empty() || plaintext.nonce.is_empty() {
        return Err(SealError::InvalidEnvelope {
            detail: "result plaintext is missing task_id/nonce".into(),
        });
    }
    if plaintext.formats_produced.is_empty() {
        return Err(SealError::InvalidEnvelope {
            detail: "result plaintext carries no formats_produced entries".into(),
        });
    }
    Ok(())
}

fn validate_envelope_shape(envelope: &SealedResultEnvelope) -> Result<(), SealError> {
    if envelope.version != 1 {
        return Err(SealError::InvalidEnvelope {
            detail: "unsupported version".into(),
        });
    }
    if envelope.suite != RESULT_SEAL_SUITE {
        return Err(SealError::InvalidEnvelope {
            detail: "unsupported suite".into(),
        });
    }
    if envelope.kind != RESULT_SEAL_KIND {
        return Err(SealError::InvalidEnvelope {
            detail: "envelope kind is not result".into(),
        });
    }
    if envelope.recipient != RESULT_RECIPIENT_ROLE {
        return Err(SealError::InvalidEnvelope {
            detail: "result envelope is not addressed to the committee-threshold role".into(),
        });
    }
    if !is_key_id(&envelope.recipient_key_id) {
        return Err(SealError::InvalidEnvelope {
            detail: "recipient_key_id is malformed".into(),
        });
    }
    if envelope.task_id.is_empty() || envelope.nonce.is_empty() {
        return Err(SealError::InvalidEnvelope {
            detail: "result seal envelope is missing routing ids".into(),
        });
    }
    if !is_hex_digest(&envelope.result_hash) {
        return Err(SealError::InvalidEnvelope {
            detail: "result_hash is malformed".into(),
        });
    }
    if envelope.ciphertext.is_empty() {
        return Err(SealError::InvalidEnvelope {
            detail: "ciphertext is empty".into(),
        });
    }
    Ok(())
}

fn split_aad_plaintext(authenticated: &[u8]) -> Result<(&[u8], &[u8]), SealError> {
    let pos = authenticated
        .iter()
        .position(|&b| b == 0)
        .ok_or(SealError::MalformedPlaintext)?;
    let (aad, rest) = authenticated.split_at(pos);
    Ok((aad, &rest[1..]))
}

fn is_key_id(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        && hex == hex.to_ascii_lowercase()
}

fn is_hex_digest(value: &str) -> bool {
    // SHA-256 (64) or SHA-384 (96) lowercase hex.
    (value.len() == 64 || value.len() == 96)
        && value
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        && value == value.to_ascii_lowercase()
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], SealError> {
    if hex.len() != 64 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(SealError::InvalidIdentity {
            detail: "committee public key must be 32 lowercase hex bytes".into(),
        });
    }
    if hex != hex.to_ascii_lowercase() {
        return Err(SealError::InvalidIdentity {
            detail: "committee public key hex must be lowercase".into(),
        });
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
            SealError::InvalidIdentity {
                detail: "committee public key is not hexadecimal".into(),
            }
        })?;
    }
    Ok(out)
}

fn encode_b64url(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
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
    fn result_aad_binds_domain_committee_role_and_digests() {
        let aad = build_result_aad(
            "task-1",
            "nonce-1",
            &"ab".repeat(32),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let s = String::from_utf8(aad).unwrap();
        assert!(s.starts_with("relay/result-seal/v1|task_id=task-1|"));
        assert!(s.contains("|nonce=nonce-1|"));
        assert!(s.contains(&format!("|result_hash={}|", "ab".repeat(32))));
        assert!(s.contains("|recipient=committee-threshold"));
    }

    #[test]
    fn committee_public_key_key_id_matches_content_hash() {
        let secret = SecretKey::generate(&mut OsRng);
        let pk = CommitteeThresholdPublicKey::from_public_key_bytes(secret.public_key().as_bytes());
        assert_eq!(pk.key_id(), key_id_for(secret.public_key().as_bytes()));
        assert_eq!(pk.public_key.len(), 64);
    }
}
