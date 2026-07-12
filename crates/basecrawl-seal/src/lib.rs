//! `basecrawl-seal` — enclave-side confidentiality primitives.
//!
//! Owns:
//! * the enclave X25519 identity used for sealed-box task receipt and the
//!   RA-TLS peer binding presented to the key-release server;
//! * the key-release CLIENT that obtains a session-sealed task key from the
//!   validator-operated measurement gate (architecture §7);
//! * authenticated (AEAD sealed-box) decryption of sealed scrape tasks in
//!   enclave memory — zero partial plaintext on tamper/truncate.
//!
//! Assertions satisfied by this crate for M3:
//! * **VAL-CONF-011** — without a released / enclave-held key the sealed task
//!   stays opaque; host and forked-image decrypts fail closed.
//! * **VAL-CONF-027** — bit-flip or truncation of the sealed-task ciphertext
//!   fails authenticated decryption; no partial plaintext is emitted or acted on.

#![forbid(unsafe_code)]

pub mod error;
pub mod identity;
pub mod keyrelease;
pub mod task;

pub use error::SealError;
pub use identity::{
    hex_decode_32, key_id_for, task_seal_report_data_for, EnclaveIdentity, TASK_SEAL_DOMAIN,
};
pub use keyrelease::{
    decrypt_requires_released_key, key_release_report_data, parse_release_response,
    to_report_data_field, HttpKeyReleaseTransport, KeyReleaseClient, KeyReleaseTransport,
    QuoteBundle, QuoteProvider, ReleasedTaskKey, DEFAULT_KEY_RELEASE_TIMEOUT, KEY_RELEASE_TAG,
    RA_TLS_PEER_HEADER, REPORT_DATA_LEN,
};
pub use task::{
    build_aad, decrypt_sealed_task, decrypt_with_foreign_key, decrypt_without_released_key,
    recipient_key_id, DecryptedTask, SealedTaskEnvelope, TASK_SEAL_SUITE,
};
