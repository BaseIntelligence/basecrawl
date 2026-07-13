//! Structured JSON extraction honesty (VAL-CRAWL-127, VAL-CRAWLPROD-024..030).
//!
//! Without a configured extractor/provider key the path must fail structurely. With a key still
//! present, this build must not invent success payloads. Invalid schemas fail separately.
//! Help must list breadth flags and admit the gated extract residual.

mod common;

use serde_json::Value;
use std::process::{Command, Output};
use std::sync::Mutex;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

/// Serialize env mutation across extract CLI tests (process-global env).
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn run_with_env(args: &[&str], env: &[(&str, Option<&str>)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    // Baseline: clear extract-related keys so hermetic hosts with ambient OPENAI_API_KEY do not
    // accidentally change the missing-key path. Tests that need a key reintroduce it below.
    for name in [
        "BASECRAWL_EXTRACT_API_KEY",
        "BASECRAWL_LLM_API_KEY",
        "OPENAI_API_KEY",
        "BASECRAWL_EXTRACT_BASE_URL",
        "BASECRAWL_EXTRACT_MODEL",
    ] {
        cmd.env_remove(name);
    }
    for (k, v) in env {
        match v {
            Some(val) => {
                cmd.env(k, val);
            }
            None => {
                cmd.env_remove(k);
            }
        }
    }
    cmd.output().expect("failed to spawn basecrawl binary")
}

fn run(args: &[&str]) -> Output {
    run_with_env(args, &[])
}

fn assert_explicit_unsupported(output: Output, expected_reason: &str) {
    assert!(
        !output.status.success(),
        "json extraction must not report success when extraction is unavailable"
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
    assert_eq!(
        error["error"]["reason"], expected_reason,
        "reason must match gate path: {error}"
    );
}

// VAL-CRAWL-127 / VAL-CRAWLPROD-024: schema/prompt without key → unsupported, never success.
#[test]
fn json_extraction_with_schema_and_prompt_is_explicitly_unsupported() {
    let _g = ENV_LOCK.lock().unwrap();
    let target = common::fixture_url("/example/");
    assert_explicit_unsupported(
        run(&[
            &target,
            "--formats",
            "json",
            "--schema",
            r#"{"type":"object","properties":{"title":{"type":"string"}}}"#,
            "--prompt",
            "Extract the page title.",
        ]),
        "provider_not_configured",
    );
}

// VAL-CRAWL-127 / VAL-CRAWLPROD-024: bare json request must not retain successful `json: null`.
#[test]
fn bare_json_extraction_is_explicitly_unsupported() {
    let _g = ENV_LOCK.lock().unwrap();
    let target = common::fixture_url("/example/");
    assert_explicit_unsupported(
        run(&[&target, "--formats", "json"]),
        "provider_not_configured",
    );
}

// VAL-CRAWLPROD-025: malformed schema fails structured (not empty success, not silent drop).
#[test]
fn invalid_json_schema_fails_structured() {
    let _g = ENV_LOCK.lock().unwrap();
    let target = common::fixture_url("/example/");
    let out = run(&[
        &target,
        "--formats",
        "json",
        "--schema",
        "{this-is-not-valid-json",
    ]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let error: Value = serde_json::from_slice(&out.stderr).expect("stderr JSON");
    assert_eq!(error["error"]["kind"], "invalid_json_schema");
    assert_eq!(error["error"]["format"], "json");
    assert_eq!(error["error"]["capability"], "structured_extraction");
    assert!(
        error["error"]["schema_error"]
            .as_str()
            .unwrap_or("")
            .contains("valid JSON")
            || error["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("json schema"),
        "must name the schema problem: {error}"
    );
}

// VAL-CRAWLPROD-025: non-object schema rejected.
#[test]
fn non_object_json_schema_fails_structured() {
    let _g = ENV_LOCK.lock().unwrap();
    let target = common::fixture_url("/example/");
    let out = run(&[
        &target,
        "--formats",
        "json",
        "--schema",
        r#""not-an-object""#,
    ]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let error: Value = serde_json::from_slice(&out.stderr).expect("stderr JSON");
    assert_eq!(error["error"]["kind"], "invalid_json_schema");
}

// VAL-CRAWLPROD-027: key present path is distinct and still not forged success.
#[test]
fn extract_with_provider_key_still_fails_closed_not_fake_success() {
    let _g = ENV_LOCK.lock().unwrap();
    let target = common::fixture_url("/example/");
    let out = run_with_env(
        &[
            &target,
            "--formats",
            "json",
            "--schema",
            r#"{"type":"object"}"#,
        ],
        &[("BASECRAWL_EXTRACT_API_KEY", Some("unit-test-key-not-real"))],
    );
    assert_explicit_unsupported(out, "extractor_not_available");
}

// VAL-CRAWLPROD-027: OPENAI_API_KEY is accepted as an alternate env, and still not success.
#[test]
fn openai_env_key_is_recognized_but_does_not_forge_success() {
    let _g = ENV_LOCK.lock().unwrap();
    let target = common::fixture_url("/example/");
    let out = run_with_env(
        &[&target, "--formats", "json"],
        &[("OPENAI_API_KEY", Some("sk-unit-test-not-real"))],
    );
    assert_explicit_unsupported(out, "extractor_not_available");
}

// VAL-CRAWLPROD-029: markdown+json with unsupported extract cleanly rejects the whole request
// (documented unit reject) rather than silencing all formats or emitting a half proof.
#[test]
fn markdown_plus_json_is_clean_unit_reject_when_extract_unsupported() {
    let _g = ENV_LOCK.lock().unwrap();
    let target = common::fixture_url("/example/");
    let out = run(&[&target, "--formats", "markdown,json", "--no-js"]);
    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "unit reject must leave stdout empty, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let error: Value = serde_json::from_slice(&out.stderr).expect("stderr JSON");
    assert_eq!(error["error"]["kind"], "structured_extraction_unsupported");
}

// VAL-CRAWLPROD-028: help admits gated extract residual (no magic always-extract claim).
#[test]
fn help_admits_gated_extract_honesty() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("json") && (lower.contains("gated") || lower.contains("provider")),
        "help must admit gated/provider extract residual:\n{text}"
    );
    // Honesty scanners forbid absolute always-extract claims.
    assert!(
        !lower.contains("always extracts any schema"),
        "help must not claim universal structured intelligence"
    );
}

// VAL-CRAWLPROD-030: product breadth flags that are implemented appear in CLI help.
#[test]
fn help_lists_product_breadth_flags() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--method",
        "--body",
        "--mode",
        "--urls",
        "--max-crawl-pages",
        "--max-depth",
        "--max-urls",
        "--concurrency",
        "--formats",
        "--json-schema",
        "--json-prompt",
        "--proxy",
        "--proxy-class",
        "--proxy-session",
        "--proxy-country",
        "--force-browser",
        "--difficulty",
    ] {
        assert!(
            text.contains(flag),
            "help must list implemented flag {flag}:\n{text}"
        );
    }
    // Mode values for crawl/map/batch are documented.
    assert!(text.contains("crawl"), "help should mention crawl mode");
    assert!(text.contains("map"), "help should mention map mode");
    assert!(text.contains("batch"), "help should mention batch mode");
}
