//! Enclave X25519 identity used for task sealing and RA-TLS peer binding.
//!
//! Matches the relay-side `AttestedEnclavePublicKey` contract:
//! * public key = 32 raw X25519 bytes (lowercase hex on the wire)
//! * `key_id`  = `sha256:<hex(SHA256(pubkey))>`
//! * `report_data` (task-seal binding) = `hex(SHA256(TASK_SEAL_DOMAIN || pubkey))`

use crate::error::SealError;
use crypto_box::aead::OsRng;
use crypto_box::SecretKey;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain tag for the task-seal quote/report_data key-binding commitment.
/// Must match `relay.seal.tasks.TASK_SEAL_DOMAIN`.
pub const TASK_SEAL_DOMAIN: &[u8] = b"relay/task-seal/v1";

/// Enclave holder of the sealed-box private key and RA-TLS peer identity.
///
/// The secret key never leaves the enclave and is zeroized on drop. Host-side
/// code never constructs this from a settings file; generators exist for tests
/// and for production key material derived inside the CVM.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EnclaveIdentity {
    secret: [u8; 32],
    public: [u8; 32],
    #[zeroize(skip)]
    key_id: String,
    #[zeroize(skip)]
    report_data: String,
}

impl EnclaveIdentity {
    /// Generate a fresh random enclave identity (tests / enclave bootstrap).
    pub fn generate() -> Self {
        let secret_key = SecretKey::generate(&mut OsRng);
        Self::from_secret_bytes(secret_key.to_bytes())
            .expect("random X25519 secret always forms a valid identity")
    }

    /// Build an identity from a fixed 32-byte X25519 secret (enclave provisioned).
    pub fn from_secret_bytes(secret: [u8; 32]) -> Result<Self, SealError> {
        let secret_key = SecretKey::from_bytes(secret);
        let public = *secret_key.public_key().as_bytes();
        let key_id = key_id_for(&public);
        let report_data = task_seal_report_data_for(&public);
        Ok(Self {
            secret,
            public,
            key_id,
            report_data,
        })
    }

    /// Hex-encode the 32-byte public key (lowercase) as required by relay settings.
    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.public)
    }

    /// Raw 32-byte X25519 public key (for sealed-box / RA-TLS peer fields).
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    /// Content identity used on every sealed-task envelope (`sha256:<hex>`).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Quote-bound key commitment the relay stores as `enclave_report_data`.
    pub fn report_data(&self) -> &str {
        &self.report_data
    }

    /// Borrow the sealed-box secret as a `crypto_box::SecretKey`.
    pub(crate) fn secret_key(&self) -> SecretKey {
        SecretKey::from_bytes(self.secret)
    }
}

impl std::fmt::Debug for EnclaveIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnclaveIdentity")
            .field("key_id", &self.key_id)
            .field("public_key_hex", &self.public_key_hex())
            .finish_non_exhaustive()
    }
}

/// `key_id = sha256:<hex(SHA256(pubkey))>` matching relay.seal.tasks.
pub fn key_id_for(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("sha256:{}", hex_encode(&digest))
}

/// Task-seal report_data commitment matching relay.seal.tasks.
pub fn task_seal_report_data_for(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TASK_SEAL_DOMAIN);
    hasher.update(public_key);
    hex_encode(&hasher.finalize())
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a 32-byte public/secret key from lowercase hex (enclave bootstrap helper).
pub fn hex_decode_32(hex: &str) -> Result<[u8; 32], SealError> {
    if hex.len() != 64 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(SealError::InvalidIdentity {
            detail: "key must be 32 lowercase hex bytes".into(),
        });
    }
    if hex != hex.to_ascii_lowercase() {
        return Err(SealError::InvalidIdentity {
            detail: "key hex must be lowercase".into(),
        });
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
            SealError::InvalidIdentity {
                detail: "key is not hexadecimal".into(),
            }
        })?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity_has_matching_key_id_and_report_data() {
        let id = EnclaveIdentity::generate();
        assert_eq!(id.key_id(), key_id_for(id.public_key_bytes()));
        assert_eq!(
            id.report_data(),
            task_seal_report_data_for(id.public_key_bytes())
        );
        assert_eq!(id.public_key_hex().len(), 64);
        assert_eq!(
            id.public_key_hex(),
            id.public_key_hex().to_ascii_lowercase()
        );
    }
}
