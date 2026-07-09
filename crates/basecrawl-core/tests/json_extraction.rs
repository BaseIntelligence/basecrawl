//! Structured JSON extraction assertions (VAL-CRAWL-127).
//!
//! This build deliberately has no LLM extraction backend. JSON extraction must therefore fail
//! explicitly and structurally, rather than reporting a null `json` value as if it had produced
//! the requested output.

use serde_json::Value;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const TARGET: &str = "https://example.com";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn assert_explicit_unsupported(output: Output) {
    assert!(
        !output.status.success(),
        "json extraction must not report success when no extraction backend is built"
    );
    assert!(
        output.stdout.is_empty(),
        "unsupported extraction must not emit a partial ScrapeProof"
    );
    let error: Value = serde_json::from_slice(&output.stderr).unwrap_or_else(|parse_error| {
        panic!("stderr must be a structured JSON error: {parse_error}")
    });
    assert_eq!(
        error["error"]["kind"], "structured_extraction_unsupported",
        "unsupported extraction must have a stable error kind: {error}"
    );
    assert_eq!(error["error"]["format"], "json");
    assert_eq!(error["error"]["capability"], "structured_extraction");
}

// VAL-CRAWL-127: schema/prompt requests must not be silently dropped or mis-reported.
#[test]
fn json_extraction_with_schema_and_prompt_is_explicitly_unsupported() {
    assert_explicit_unsupported(run(&[
        TARGET,
        "--formats",
        "json",
        "--schema",
        r#"{"type":"object","properties":{"title":{"type":"string"}}}"#,
        "--prompt",
        "Extract the page title.",
    ]));
}

// VAL-CRAWL-127: a bare json request must not retain the historical successful `json: null` output.
#[test]
fn bare_json_extraction_is_explicitly_unsupported() {
    assert_explicit_unsupported(run(&[TARGET, "--formats", "json"]));
}
