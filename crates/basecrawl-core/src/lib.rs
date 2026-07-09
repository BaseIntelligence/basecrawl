//! `basecrawl` crawler core.
//!
//! At milestone M1 this crate owns the CLI/SDK entrypoint and the assembly of the canonical,
//! non-attestation [`ScrapeProof`] envelope: input validation (URL scheme + output format),
//! a foundational fetch, and construction of the top-level proof shape. Deeper capabilities
//! (TLS 1.3 capture, format producers, canonicalization, egress/geo, attestation) are layered
//! on by subsequent features.

pub mod error;
pub mod fetch;
pub mod format;
pub mod url_validation;

use basecrawl_proof::{
    Attestation, Egress, Request, Response, ResultBlock, ScrapeProof, SdkSignature, Tls,
    SCRAPE_PROOF_VERSION,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub use error::Error;
pub use format::Format;

/// The default HTTP method for a scrape.
pub const DEFAULT_METHOD: &str = "GET";

/// Options controlling a single scrape.
#[derive(Debug, Clone)]
pub struct ScrapeOptions {
    /// Requested formats (canonical order). Empty means "use the documented default set".
    pub formats: Vec<Format>,
    /// Validator-issued task id, echoed verbatim into the proof.
    pub task_id: Option<String>,
    /// Validator-issued anti-replay nonce, echoed verbatim into the proof.
    pub nonce: Option<String>,
}

impl Default for ScrapeOptions {
    fn default() -> Self {
        Self {
            formats: format::default_set(),
            task_id: None,
            nonce: None,
        }
    }
}

/// Validate `raw_url`, fetch it, and assemble the canonical [`ScrapeProof`].
///
/// URL/scheme validation happens before any network access, so a non-HTTP scheme or malformed
/// URL is refused without a fetch and without emitting a proof.
pub fn scrape(raw_url: &str, options: &ScrapeOptions) -> Result<ScrapeProof, Error> {
    let url = url_validation::validate_url(raw_url)?;
    let fetched = fetch::fetch(&url)?;

    let formats = if options.formats.is_empty() {
        format::default_set()
    } else {
        format::normalize(options.formats.clone())
    };

    let formats_produced: BTreeMap<String, Value> = formats
        .iter()
        .map(|f| (f.as_str().to_string(), Value::Null))
        .collect();

    Ok(ScrapeProof {
        version: SCRAPE_PROOF_VERSION,
        task_id: options.task_id.clone(),
        nonce: options.nonce.clone(),
        request: Request {
            method: DEFAULT_METHOD.to_string(),
            url: url.as_str().to_string(),
            headers_hash: None,
            body_hash: None,
            formats: formats.iter().map(|f| f.as_str().to_string()).collect(),
        },
        tls: Tls::default(),
        response: Response {
            status_code: Some(fetched.status_code),
            headers_hash: Some(fetched.headers_hash),
            body_hash: Some(fetched.body_hash),
            content_length: Some(fetched.content_length),
        },
        result: ResultBlock {
            formats_produced,
            result_hash: None,
            completeness_manifest: Value::Object(serde_json::Map::new()),
        },
        egress: Egress::default(),
        attestation: Attestation::default(),
        sdk_signature: SdkSignature::default(),
    })
}
