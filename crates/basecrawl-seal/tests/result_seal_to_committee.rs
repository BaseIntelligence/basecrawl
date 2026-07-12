//! Result sealing to the validator committee threshold public key
//! (VAL-CONF-015, VAL-CONF-017).
//!
//! After a scrape completes inside the enclave the ScrapeProof result body is
//! sealed to the committee — never to the miner. These tests exercise the
//! host-visible envelope with distinctive content markers so a miner/host
//! decrypt (any host-held key) recovers no plaintext (VAL-CONF-015) and a
//! strings/grep over the host-relayed payload finds zero content markers
//! (VAL-CONF-017). Round-trip open with the reconstructed committee secret
//! confirms the ciphertext is well-formed and available to the later relay
//! threshold path, without exposing that secret on the miner/host side.

use basecrawl_seal::{
    decrypt_result_as_miner_host, decrypt_result_with_foreign_key, host_visible_contains_marker,
    seal_formats_to_committee, seal_result_to_committee, unseal_result_with_committee_secret,
    CommitteeThresholdPublicKey, EnclaveIdentity, ResultSealPlaintext, SealError,
    SealedResultEnvelope, RESULT_RECIPIENT_ROLE, RESULT_SEAL_KIND, RESULT_SEAL_SUITE,
};
use crypto_box::aead::OsRng;
use crypto_box::SecretKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// Distinctive markdown content that must never appear host-side after sealing.
const MARKDOWN_CANARY: &str = "KNOWN-RESULT-MARKDOWN-CANARY-9f3a2c";
/// Distinctive html content.
const HTML_CANARY: &str = "KNOWN-RESULT-HTML-CANARY-<main>hidden-body</main>";
/// Distinctive screenshot b64 fragment.
const SCREENSHOT_CANARY: &str = "KNOWN-RESULT-SCREENSHOT-b64-Zx7mQ";
/// Distinctive json-extract field.
const JSON_CANARY: &str = "KNOWN-RESULT-JSON-TITLE-canary-alpha";

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Publish a synthetic committee threshold public key whose secret is known
/// only to the test (models "reconstructed committee secret" for the open path).
/// Production relay distributes share-secrets, never this full secret, to miners.
fn fixture_committee() -> (CommitteeThresholdPublicKey, [u8; 32]) {
    let secret = SecretKey::generate(&mut OsRng);
    let secret_bytes = secret.to_bytes();
    let pk = CommitteeThresholdPublicKey::from_public_key_bytes(secret.public_key().as_bytes());
    (pk, secret_bytes)
}

fn fixture_result_plaintext() -> ResultSealPlaintext {
    let mut formats = Map::new();
    formats.insert("markdown".into(), Value::String(MARKDOWN_CANARY.into()));
    formats.insert("html".into(), Value::String(HTML_CANARY.into()));
    formats.insert(
        "screenshot".into(),
        json!({"b64": SCREENSHOT_CANARY, "mime": "image/png"}),
    );
    formats.insert(
        "json".into(),
        json!({"title": JSON_CANARY, "items": [1, 2, 3]}),
    );
    // Deterministic result_hash over the markdown surface only (matches M1
    // contract; non-deterministic screenshot/json are excluded from the
    // digest). Tests only need a well-formed lowercase hex digest field.
    let result_hash = sha256_hex(MARKDOWN_CANARY.as_bytes());
    ResultSealPlaintext {
        task_id: "task-result-seal-015".into(),
        nonce: "nonce-result-seal-015".into(),
        result_hash,
        formats_produced: formats,
    }
}

fn all_result_markers() -> [&'static str; 4] {
    [MARKDOWN_CANARY, HTML_CANARY, SCREENSHOT_CANARY, JSON_CANARY]
}

// ---------------------------------------------------------------------------
// VAL-CONF-015: result sealed to the committee, NOT to the miner
// ---------------------------------------------------------------------------

#[test]
fn val_conf_015_miner_host_held_key_cannot_decrypt_sealed_result() {
    let (committee, _committee_secret) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let envelope =
        seal_result_to_committee(&plaintext, &committee).expect("enclave seals to committee");

    // Envelope is addressed to the committee threshold role, never "miner".
    assert_eq!(envelope.recipient, RESULT_RECIPIENT_ROLE);
    assert_eq!(envelope.kind, RESULT_SEAL_KIND);
    assert_eq!(envelope.suite, RESULT_SEAL_SUITE);
    assert_eq!(envelope.recipient_key_id, committee.key_id());

    // Miner/host attempt with no key material.
    let err = decrypt_result_as_miner_host(&envelope, None).expect_err("host has no key");
    assert_eq!(err, SealError::KeyNotReleased);
    assert!(err.is_auth_failure());
    assert_eq!(err.kind(), "key_not_released");

    // Even if the miner supplies its enclave identity (used for task sealed-
    // box receipt only), the result cannot be opened: it was sealed to the
    // committee, never to the enclave.
    let miner_enclave = EnclaveIdentity::generate();
    let err = decrypt_result_as_miner_host(&envelope, Some(&miner_enclave))
        .expect_err("enclave identity is not the committee");
    assert!(err.is_auth_failure());

    // Foreign invented key (miner inventing a private key) fails AEAD.
    let foreign = EnclaveIdentity::generate();
    let err = decrypt_result_with_foreign_key(&envelope, &foreign)
        .expect_err("foreign key cannot open committee-sealed result");
    assert!(matches!(err, SealError::AuthenticationFailed));

    // Error messages / kinds never leak result content markers.
    for marker in all_result_markers() {
        let rendered = format!("{err}");
        assert!(
            !rendered.contains(marker),
            "error leak for marker {marker}: {rendered}"
        );
        assert!(!err.kind().contains(marker));
    }

    // No recovered plaintext object for either path means no markdown/html/
    // screenshot/json is available host-side (VAL-CONF-015).
}

#[test]
fn val_conf_015_enclave_identity_is_not_a_result_recipient() {
    // The enclave identity is used only for receiving sealed *tasks*. Sealing
    // a result to the enclave identity would leak it back to the miner-held
    // private key. The architectural contract forbids that: recipient is
    // always committee-threshold.
    let (committee, _) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let envelope = seal_result_to_committee(&plaintext, &committee).unwrap();
    assert_ne!(
        envelope.recipient, "miner",
        "result must never be addressed to the miner role"
    );
    assert_ne!(
        envelope.recipient, "enclave",
        "result must never be addressed to the enclave role"
    );
    assert_eq!(envelope.recipient, "committee-threshold");

    // key_id on the envelope equals the published committee key, not an
    // enclave-generated one.
    let enclave = EnclaveIdentity::generate();
    assert_ne!(envelope.recipient_key_id, enclave.key_id());
    assert_eq!(envelope.recipient_key_id, committee.key_id());
}

// ---------------------------------------------------------------------------
// VAL-CONF-017: host-visible sealed result is opaque ciphertext only
// ---------------------------------------------------------------------------

#[test]
fn val_conf_017_host_visible_sealed_result_has_no_result_markers() {
    let (committee, _) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let envelope =
        seal_result_to_committee(&plaintext, &committee).expect("enclave seals to committee");

    // Host-visible JSON/bytes represent only the envelope; no result content.
    let host_json = serde_json::to_string(&envelope).expect("serialize host payload");
    let host_bytes = serde_json::to_vec(&envelope).expect("serialize host payload");

    for marker in all_result_markers() {
        assert!(
            !host_json.contains(marker),
            "host-visible JSON leaked marker: {marker}"
        );
        assert!(
            !host_bytes
                .windows(marker.len())
                .any(|w| w == marker.as_bytes()),
            "host-visible bytes leaked marker: {marker}"
        );
        assert!(
            !host_visible_contains_marker(&envelope, marker),
            "helper flags marker present: {marker}"
        );
        // `strings`-style: every printable ASCII window of the host bytes must
        // not equal the canary. The AEAD ciphertext is authentic-random, so a
        // multi-byte canary collision would be a cryptographic failure case.
        let host_text = String::from_utf8_lossy(&host_bytes);
        assert!(
            !host_text.contains(marker),
            "strings over host payload found marker: {marker}"
        );
    }

    // Host-visible fields are non-sensitive routing only.
    assert_eq!(envelope.task_id, plaintext.task_id);
    assert_eq!(envelope.nonce, plaintext.nonce);
    assert_eq!(envelope.result_hash, plaintext.result_hash);
    assert!(!envelope.ciphertext.is_empty());
    // Ciphertext itself hard-fails a naive UTF-8 decode of all markers.
    for marker in all_result_markers() {
        assert!(!envelope.ciphertext.contains(marker));
    }
}

#[test]
fn val_conf_017_seal_formats_helper_also_opaque() {
    let (committee, _) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let envelope = seal_formats_to_committee(
        &plaintext.task_id,
        &plaintext.nonce,
        &plaintext.result_hash,
        plaintext.formats_produced.clone(),
        &committee,
    )
    .expect("helper seals");
    for marker in all_result_markers() {
        assert!(!host_visible_contains_marker(&envelope, marker));
    }
}

// ---------------------------------------------------------------------------
// Round-trip availability (committee path exclusively) + tamper fail-closed
// ---------------------------------------------------------------------------

#[test]
fn committee_secret_round_trip_recovers_result_plaintext() {
    // Confirms the sealed payload is available to the reconstructed committee
    // secret (relay-side later feature) while remaining opaque to miners. This
    // is not VAL-CONF-016 (threshold share cardinality) — it only proves the
    // enclave-side seal is openable with the threshold public key's secret.
    let (committee, committee_secret) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let envelope = seal_result_to_committee(&plaintext, &committee).unwrap();

    let recovered =
        unseal_result_with_committee_secret(&envelope, &committee_secret).expect("committee opens");
    assert_eq!(recovered, plaintext);
    assert_eq!(
        recovered
            .formats_produced
            .get("markdown")
            .and_then(|v| v.as_str()),
        Some(MARKDOWN_CANARY)
    );
    assert_eq!(
        recovered
            .formats_produced
            .get("html")
            .and_then(|v| v.as_str()),
        Some(HTML_CANARY)
    );
    assert_eq!(
        recovered
            .formats_produced
            .get("screenshot")
            .and_then(|v| v.get("b64"))
            .and_then(|v| v.as_str()),
        Some(SCREENSHOT_CANARY)
    );
    assert_eq!(
        recovered
            .formats_produced
            .get("json")
            .and_then(|v| v.get("title"))
            .and_then(|v| v.as_str()),
        Some(JSON_CANARY)
    );
    // Bind against the digest the enclave advertised out of band.
    assert_eq!(recovered.result_hash, plaintext.result_hash);
    assert_eq!(
        sha256_hex(MARKDOWN_CANARY.as_bytes()),
        recovered.result_hash
    );
}

#[test]
fn bitflip_of_sealed_result_fails_authenticated_open() {
    let (committee, committee_secret) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let mut envelope = seal_result_to_committee(&plaintext, &committee).unwrap();

    // Flip one byte of the base64url ciphertext.
    let mut chars: Vec<char> = envelope.ciphertext.chars().collect();
    let idx = chars.len() / 2;
    chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
    envelope.ciphertext = chars.into_iter().collect();

    let err = unseal_result_with_committee_secret(&envelope, &committee_secret)
        .expect_err("bitflip must fail AEAD");
    assert!(matches!(err, SealError::AuthenticationFailed));
    // No partial markers in errors.
    for marker in all_result_markers() {
        assert!(!format!("{err}").contains(marker));
    }
}

#[test]
fn truncated_sealed_result_fails_closed() {
    let (committee, committee_secret) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let mut envelope = seal_result_to_committee(&plaintext, &committee).unwrap();
    // Truncate ciphertext below the sealed-box minimum.
    envelope.ciphertext = "AAAA".into();
    let err = unseal_result_with_committee_secret(&envelope, &committee_secret)
        .expect_err("truncate must fail");
    assert!(err.is_auth_failure() || matches!(err, SealError::InvalidEnvelope { .. }));
}

#[test]
fn wrong_committee_secret_cannot_open() {
    let (committee, _) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let envelope = seal_result_to_committee(&plaintext, &committee).unwrap();
    let other = SecretKey::generate(&mut OsRng).to_bytes();
    let err = unseal_result_with_committee_secret(&envelope, &other)
        .expect_err("other committee secret denied");
    assert!(matches!(
        err,
        SealError::AuthenticationFailed | SealError::InvalidEnvelope { .. }
    ));
}

#[test]
fn sealed_envelope_shape_refuses_miner_recipient() {
    // Defensive: a hand-crafted envelope with recipient="miner" is rejected.
    let (committee, committee_secret) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let mut envelope = seal_result_to_committee(&plaintext, &committee).unwrap();
    envelope.recipient = "miner".into();
    let err = unseal_result_with_committee_secret(&envelope, &committee_secret)
        .expect_err("miner-role envelope is invalid");
    assert!(matches!(err, SealError::InvalidEnvelope { .. }));
    // Also rejected by the miner-side path.
    let err = decrypt_result_as_miner_host(&envelope, None).expect_err("shape rejected");
    assert!(matches!(
        err,
        SealError::InvalidEnvelope { .. } | SealError::KeyNotReleased
    ));
}

#[test]
fn host_payload_deserializes_as_envelope_without_formats() {
    // The host places the sealed result on the wire as JSON; deserializing it
    // never yields a formats_produced / markdown field.
    let (committee, _) = fixture_committee();
    let plaintext = fixture_result_plaintext();
    let envelope = seal_result_to_committee(&plaintext, &committee).unwrap();
    let host_json = serde_json::to_string(&envelope).unwrap();
    let reparsed: SealedResultEnvelope = serde_json::from_str(&host_json).unwrap();
    let as_value: Value = serde_json::from_str(&host_json).unwrap();
    assert!(as_value.get("formats_produced").is_none());
    assert!(as_value.get("markdown").is_none());
    assert!(as_value.get("html").is_none());
    assert!(as_value.get("screenshot").is_none());
    assert!(as_value.get("json").is_none());
    assert_eq!(reparsed, envelope);
}
