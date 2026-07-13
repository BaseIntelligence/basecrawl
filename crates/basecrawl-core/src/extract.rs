//! Structured JSON extraction honesty gate (VAL-CRAWLPROD-024..029).
//!
//! The product accepts `--formats json` with optional `--json-schema` / `--json-prompt` so
//! callers can request schema extract, but this engine never fabricates LLM-looking success.
//! Without a configured extractor/provider key the path fails closed with a structured
//! `structured_extraction_unsupported` error. An optional env key path exists for a future
//! real provider call; when a key is present but no extractor is wired, the outcome is still
//! an explicit failure (never empty/fake `json` success).

use crate::error::{Error, ExtractRefuseReason};
use serde_json::Value;
use std::env;

/// Env vars that can supply an optional LLM/provider key for structured extraction.
/// First non-empty wins. Secrets never go into ScrapeProof or host-safe error payloads.
pub const EXTRACT_API_KEY_ENVS: &[&str] = &[
    "BASECRAWL_EXTRACT_API_KEY",
    "BASECRAWL_LLM_API_KEY",
    "OPENAI_API_KEY",
];

/// Optional provider base URL. When unset, even a present key cannot run extraction.
pub const EXTRACT_BASE_URL_ENV: &str = "BASECRAWL_EXTRACT_BASE_URL";

/// Optional model id for a future provider path (documented; unused until extractor ships).
pub const EXTRACT_MODEL_ENV: &str = "BASECRAWL_EXTRACT_MODEL";

/// Resolved optional prison of extract configuration (redacted; never logs secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractProviderConfig {
    /// Which env var supplied the key (name only; value never retained after check).
    pub key_source: String,
    pub base_url: Option<String>,
    pub model: Option<String>,
}

/// Return true when the stack has a non-empty provider key (value never returned).
pub fn provider_key_is_configured() -> bool {
    resolve_provider_config().is_some()
}

/// Snapshot of non-secret extract configuration for diagnostics and tests.
pub fn resolve_provider_config() -> Option<ExtractProviderConfig> {
    let key_source = EXTRACT_API_KEY_ENVS.iter().find_map(|name| {
        env::var(name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(|_| (*name).to_string())
    })?;
    let base_url = env::var(EXTRACT_BASE_URL_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let model = env::var(EXTRACT_MODEL_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    Some(ExtractProviderConfig {
        key_source,
        base_url,
        model,
    })
}

/// Validate an optional JSON Schema document.
///
/// - `None` / empty is permitted (bare `--formats json` is still a request).
/// - Non-empty input must parse as a JSON object (draft-agnostic structural gate).
/// - Invalid JSON or non-object schemas fail with [`Error::InvalidJsonSchema`].
pub fn validate_schema_text(schema: Option<&str>) -> Result<Option<Value>, Error> {
    let Some(raw) = schema.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(raw).map_err(|e| Error::InvalidJsonSchema {
        detail: format!("schema is not valid JSON: {e}"),
    })?;
    if !value.is_object() {
        return Err(Error::InvalidJsonSchema {
            detail: "schema must be a JSON object (e.g. {\"type\":\"object\",...})".into(),
        });
    }
    Ok(Some(value))
}

/// Gate the `json` structured-extraction format before any fetch/proof success.
///
/// Never returns `Ok(())` for a productive local/LLM extract in this build: either schema is
/// invalid, the provider is missing, or the extractor is not available / call failed. Callers
/// must surface the structured error — success with empty `json` is forbidden.
pub fn gate_structured_extraction(
    schema: Option<&str>,
    _prompt: Option<&str>,
) -> Result<(), Error> {
    // Invalid schema always wins over missing-key so operators get a precise fix (VAL-025).
    let _validated = validate_schema_text(schema)?;

    match resolve_provider_config() {
        None => Err(Error::StructuredExtractionUnsupported {
            reason: ExtractRefuseReason::ProviderNotConfigured,
        }),
        Some(cfg) => {
            // Optional real extract path: only when both key and base URL are present AND a
            // future live client is enabled. This build does not ship a working remote extractor
            // that returns model-like prose; keep fail-closed honesty (VAL-024/027).
            if cfg.base_url.is_none() {
                return Err(Error::StructuredExtractionUnsupported {
                    reason: ExtractRefuseReason::ExtractorNotAvailable,
                });
            }
            // Key + base URL present: still no in-tree HTTP LLM client that invents fields.
            // Attempt would go here; until wired, refuse without fabricating success.
            Err(Error::StructuredExtractionUnsupported {
                reason: ExtractRefuseReason::ExtractorNotAvailable,
            })
        }
    }
}

/// Human wording for CLI/help about the gated extract path (VAL-CRAWLPROD-028).
pub const EXTRACT_HONESTY_HELP: &str =
    "Structured json extract is gated: requires a configured extractor/provider key \
     (BASECRAWL_EXTRACT_API_KEY or OPENAI_API_KEY) and still fails closed when no live \
     extractor is available. This build never fabricates schema results or always-extract claims.";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize env mutation across unit tests in this process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_extract_env() {
        for name in EXTRACT_API_KEY_ENVS {
            env::remove_var(name);
        }
        env::remove_var(EXTRACT_BASE_URL_ENV);
        env::remove_var(EXTRACT_MODEL_ENV);
    }

    #[test]
    fn invalid_schema_json_is_rejected() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_extract_env();
        let err = validate_schema_text(Some("{not-json")).unwrap_err();
        assert!(matches!(err, Error::InvalidJsonSchema { .. }));
    }

    #[test]
    fn non_object_schema_is_rejected() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_extract_env();
        let err = validate_schema_text(Some(r#""just-a-string""#)).unwrap_err();
        assert!(matches!(err, Error::InvalidJsonSchema { .. }));
    }

    #[test]
    fn valid_object_schema_parses() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_extract_env();
        let v = validate_schema_text(Some(r#"{"type":"object","properties":{}}"#))
            .unwrap()
            .expect("object");
        assert_eq!(v["type"], "object");
    }

    #[test]
    fn gate_without_key_is_provider_not_configured() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_extract_env();
        let err =
            gate_structured_extraction(Some(r#"{"type":"object"}"#), Some("title")).unwrap_err();
        match err {
            Error::StructuredExtractionUnsupported { reason } => {
                assert_eq!(reason, ExtractRefuseReason::ProviderNotConfigured);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn gate_with_key_still_refuses_without_forging_success() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_extract_env();
        env::set_var(
            "BASECRAWL_EXTRACT_API_KEY",
            "test-key-not-a-secret-for-unit",
        );
        let err = gate_structured_extraction(None, None).unwrap_err();
        env::remove_var("BASECRAWL_EXTRACT_API_KEY");
        match err {
            Error::StructuredExtractionUnsupported { reason } => {
                assert_eq!(reason, ExtractRefuseReason::ExtractorNotAvailable);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn gate_never_returns_ok_for_json_extract() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_extract_env();
        assert!(gate_structured_extraction(None, None).is_err());
        env::set_var("OPENAI_API_KEY", "x");
        env::set_var(EXTRACT_BASE_URL_ENV, "https://example.invalid/v1");
        assert!(gate_structured_extraction(None, None).is_err());
        clear_extract_env();
    }
}
