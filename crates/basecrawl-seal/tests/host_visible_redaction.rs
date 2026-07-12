//! Host-visible log / metric redaction (VAL-CONF-018, 019, 020, 031).
//!
//! These tests assert the black-box contract: given distinctive path/query,
//! header/cookie/token/body, and result canary markers, every host-visible
//! surface (log line, metric label, structured error JSON, panic summary)
//! contains zero matches. Only redacted task IDs / hashes appear.

use basecrawl_seal::{
    host_safe_digest, host_safe_panic_message, install_host_safe_panic_hook, redact_json_value,
    redact_markers, task_id_ref, url_path_query_ref, url_ref, HostSafeLabels, SealError,
    REDACTED_TOKEN,
};
use serde_json::json;

/// Distinctive URL path + query that must never appear host-side (VAL-CONF-018).
const PATH_QUERY: &str = "/secret/canary-path?token=val-conf-018-marker&session=xyz";
const FULL_URL: &str =
    "https://target.example/secret/canary-path?token=val-conf-018-marker&session=xyz";

/// Distinctive request markers (VAL-CONF-019).
const HEADER_MARKER: &str = "x-canary-header-VAL-CONF-019-secret";
const COOKIE_MARKER: &str = "session=val-conf-019-cookie-marker";
const AUTH_TOKEN: &str = "Bearer val-conf-019-auth-token-7f3a";
const BODY_MARKER: &str = "val-conf-019-request-body-marker";

/// Distinctive result canary (VAL-CONF-020).
const RESULT_CANARY: &str = "KNOWN-RESULT-CANARY-VAL-CONF-020-9f3a2c";

/// Task id plaintext that must only appear as a digest on host surfaces.
const TASK_ID_PLAIN: &str = "task-host-safe-VAL-CONF-018";

fn all_request_markers() -> [&'static str; 5] {
    [
        PATH_QUERY,
        HEADER_MARKER,
        COOKIE_MARKER,
        AUTH_TOKEN,
        BODY_MARKER,
    ]
}

fn all_markers() -> Vec<&'static str> {
    let mut m = all_request_markers().to_vec();
    m.push(RESULT_CANARY);
    m.push("/secret/canary-path");
    m.push("token=val-conf-018-marker");
    m.push(TASK_ID_PLAIN);
    m
}

// ---------------------------------------------------------------------------
// VAL-CONF-018: no plaintext URL path / query in host-visible logs or metrics
// ---------------------------------------------------------------------------

#[test]
fn val_conf_018_url_refs_and_labels_hide_path_and_query() {
    let path_ref = url_path_query_ref(FULL_URL);
    let full_ref = url_ref(FULL_URL);
    let labels = HostSafeLabels::scrape_completed(
        Some(TASK_ID_PLAIN),
        Some(200),
        Some("deadbeef"),
        Some("cafebabe"),
    );
    let surfaces = [
        path_ref.clone(),
        full_ref.clone(),
        labels.to_json_string(),
        task_id_ref(Some(TASK_ID_PLAIN)),
    ];
    for surface in &surfaces {
        assert!(
            !surface.contains(PATH_QUERY),
            "host-visible surface leaked path+query: {surface}"
        );
        assert!(
            !surface.contains("/secret/canary-path"),
            "host-visible surface leaked path: {surface}"
        );
        assert!(
            !surface.contains("token=val-conf-018-marker"),
            "host-visible surface leaked query: {surface}"
        );
        assert!(
            !surface.contains(TASK_ID_PLAIN),
            "host-visible surface leaked raw task id: {surface}"
        );
    }
    assert!(path_ref.starts_with("url:sha256:"));
    assert!(full_ref.contains("target.example")); // host is expected residual leakage
    assert!(!full_ref.contains("secret"));
    assert!(labels.task_id.starts_with("task:sha256:"));
}

// ---------------------------------------------------------------------------
// VAL-CONF-019: no request headers / cookies / tokens / body in logs/metrics
// ---------------------------------------------------------------------------

#[test]
fn val_conf_019_markers_never_appear_in_labels_or_redacted_text() {
    let noisy = format!(
        "req {HEADER_MARKER} cookie={COOKIE_MARKER} auth={AUTH_TOKEN} body={BODY_MARKER} url={FULL_URL}"
    );
    let clean = redact_markers(&noisy, &all_request_markers());
    for marker in all_request_markers() {
        assert!(
            !clean.contains(marker),
            "redacted text still contains {marker}: {clean}"
        );
    }
    assert!(clean.contains(REDACTED_TOKEN));

    let labels = HostSafeLabels::scrape_failed(Some(TASK_ID_PLAIN), "transport_error");
    assert!(
        labels.is_free_of(&all_request_markers()),
        "metric labels must not bind request markers: {}",
        labels.to_json_string()
    );
}

// ---------------------------------------------------------------------------
// VAL-CONF-020: no result plaintext / canary in host-visible logs or metrics
// ---------------------------------------------------------------------------

#[test]
fn val_conf_020_result_canary_never_in_host_safe_surfaces() {
    let labels =
        HostSafeLabels::scrape_completed(Some(TASK_ID_PLAIN), Some(200), Some("aa"), Some("bb"));
    let failed = HostSafeLabels::scrape_failed(Some(TASK_ID_PLAIN), "render_error");
    for surface in [
        labels.to_json_string(),
        failed.to_json_string(),
        host_safe_panic_message(),
    ] {
        assert!(
            !surface.contains(RESULT_CANARY),
            "host-visible surface leaked result canary: {surface}"
        );
    }
    // Even a crafted free-form string that embeds the canary is scrubbed.
    let noisy = format!("scraped body included {RESULT_CANARY}");
    let scrubbed = redact_markers(&noisy, &[RESULT_CANARY]);
    assert!(!scrubbed.contains(RESULT_CANARY));
    assert!(scrubbed.contains(REDACTED_TOKEN));
}

// ---------------------------------------------------------------------------
// VAL-CONF-031: error / exception / panic paths use the same host-safe standard
// ---------------------------------------------------------------------------

#[test]
fn val_conf_031_seal_error_kinds_are_host_safe() {
    // All SealError Display / kind forms stay free of sample markers.
    let samples = [
        SealError::KeyReleaseDenied {
            reason: "measurement_not_allowlisted".into(),
        },
        SealError::KeyReleaseUnreachable,
        SealError::KeyReleaseMidExchange,
        SealError::KeyReleaseProtocol {
            detail: "missing key field".into(),
        },
        SealError::KeyNotReleased,
        SealError::AuthenticationFailed,
        SealError::InvalidEnvelope {
            detail: "truncated ciphertext".into(),
        },
        SealError::MalformedPlaintext,
        SealError::InvalidIdentity {
            detail: "bad key length".into(),
        },
        SealError::QuoteFailed {
            detail: "socket missing".into(),
        },
        SealError::Transport {
            detail: "connection reset".into(),
        },
        SealError::Dns {
            detail: "pinned resolver returned no A/AAAA answers".into(),
        },
    ];
    for err in samples {
        let kind = err.kind();
        let display = err.to_string();
        let labels = HostSafeLabels::scrape_failed(Some(TASK_ID_PLAIN), kind);
        for marker in all_markers() {
            assert!(
                !kind.contains(marker) && !display.contains(marker),
                "SealError leaked marker {marker} via kind={kind} display={display}"
            );
            assert!(
                labels.is_free_of(&[marker]),
                "failure labels leaked {marker}: {}",
                labels.to_json_string()
            );
        }
    }
}

#[test]
fn val_conf_031_json_redaction_scrubs_error_payloads() {
    let mut payload = json!({
        "kind": "robots_denied",
        "message": format!("robots policy denied {FULL_URL}"),
        "robots": {
            "targetUrl": FULL_URL,
            "matched_rule": { "path": "/secret/canary-path", "directive": "disallow" },
            "note": format!("cookie was {COOKIE_MARKER}"),
        },
        "canary": RESULT_CANARY,
    });
    redact_json_value(
        &mut payload,
        &[COOKIE_MARKER, RESULT_CANARY, AUTH_TOKEN],
        &["targetUrl", "path", "url", "robotsUrl"],
    );
    let rendered = payload.to_string();
    for marker in all_markers() {
        assert!(
            !rendered.contains(marker),
            "redacted JSON error still contains {marker}: {rendered}"
        );
    }
    assert_eq!(payload["kind"], "robots_denied");
    assert_eq!(payload["robots"]["matched_rule"]["directive"], "disallow");
}

#[test]
fn val_conf_031_panic_message_is_host_safe_constant() {
    // Install is idempotent; exercises the process-level hook registration.
    install_host_safe_panic_hook();
    let msg = host_safe_panic_message();
    for marker in all_markers() {
        assert!(
            !msg.contains(marker),
            "panic message leaked {marker}: {msg}"
        );
    }
    assert!(msg.contains("internal_error"));
    assert!(msg.contains("panicked"));
}

#[test]
fn digests_are_stable_and_domain_separated() {
    let a = host_safe_digest(b"dom-a", "same");
    let b = host_safe_digest(b"dom-a", "same");
    let c = host_safe_digest(b"dom-b", "same");
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert!(a.starts_with("sha256:"));
    assert_eq!(a.len(), "sha256:".len() + 64);
}
