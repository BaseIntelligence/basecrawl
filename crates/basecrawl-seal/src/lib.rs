//! `basecrawl-seal` — enclave-side confidentiality primitives.
//!
//! Owns:
//! * the enclave X25519 identity used for sealed-box task receipt and the
//!   RA-TLS peer binding presented to the key-release server;
//! * the key-release CLIENT that obtains a session-sealed task key from the
//!   validator-operated measurement gate (architecture §7);
//! * authenticated (AEAD sealed-box) decryption of sealed scrape tasks in
//!   enclave memory — zero partial plaintext on tamper/truncate;
//! * **in-enclave DoH/DoT resolution** against a pin-by-IP recursive resolver
//!   so the host stub resolver / port 53 never sees a cleartext QNAME for the
//!   scrape target (VAL-CONF-013), complementing the in-process rustls TLS 1.3
//!   terminator that already keeps HTTP application data off the host wire
//!   (VAL-CONF-014).
//!
//! Assertions satisfied by this crate for M3:
//! * **VAL-CONF-011** — without a released / enclave-held key the sealed task
//!   stays opaque; host and forked-image decrypts fail closed.
//! * **VAL-CONF-013** — DNS for scrape targets is resolved only over DoH/DoT to
//!   a pin-by-IP endpoint; no cleartext A/AAAA for the target on the host.
//! * **VAL-CONF-014** — application traffic is TLS 1.3 application-data only
//!   (enforced jointly with `basecrawl-core`'s rustls terminator).
//! * **VAL-CONF-027** — bit-flip or truncation of the sealed-task ciphertext
//!   fails authenticated decryption; no partial plaintext is emitted or acted on.

#![forbid(unsafe_code)]

pub mod dns;
pub mod error;
pub mod identity;
pub mod keyrelease;
pub mod task;

pub use dns::{
    build_query, is_loopback_name, parse_answers, resolve_for_connect, NameResolver,
    PinnedResolver, ResolveResult, ResolverEndpoint, ResolverMode, DEFAULT_DOH_ENDPOINT,
    DEFAULT_DOT_ENDPOINT, DOH_PATH_MARKER, QTYPE_A, QTYPE_AAAA,
};
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
