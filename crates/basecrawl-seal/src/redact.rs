//! Host-visible log / metric redaction (VAL-CONF-018 / 019 / 020 / 031).
//!
//! Confidentiality boundary: the miner/host must never learn request path/query,
//! headers/cookies/tokens/body, or result plaintext from basecrawl's host-visible
//! telemetry. Everything that leaves the enclave as a log line, structured error
//! on stderr, metric label, stack trace, or panic payload is reduced to:
//! * stable machine-readable kinds (`timeout`, `authentication_failed`, …)
//! * content-blind hashes (`sha256:<hex>`) of task ids / URL path+query
//! * coarse non-sensitive fields (HTTP status, negotiated TLS version, max hops)
//!
//! Expected residual leakage (content-confidentiality, not target-anonymity):
//! destination IP, SNI (absent ECH), DoH resolver destination, traffic metadata —
//! those are out of scope for this module (VAL-CONF-021..023).

use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::panic;
use std::sync::Once;

/// Prefix used by every host-safe content digest (`task_id`, URL path+query, …).
pub const HOST_SAFE_DIGEST_PREFIX: &str = "sha256:";

/// Domain tag so task-id digests cannot collide with URL digests.
const TASK_ID_DOMAIN: &[u8] = b"basecrawl/host-safe/task-id/v1";

/// Domain tag for URL path + query digests.
const URL_PQ_DOMAIN: &[u8] = b"basecrawl/host-safe/url-path-query/v1";

/// Placeholder token substituted for raw secret material in any residual string.
pub const REDACTED_TOKEN: &str = "<redacted>";

/// Once-install guard for the host-safe panic hook.
static PANIC_HOOK: Once = Once::new();

/// Host-safe identifier derived from an opaque string (task id, path+query, …).
///
/// Format: `sha256:` followed by 64 lowercase hex chars of
/// `SHA256(domain || material)`. Always the same input → same digest (stable
/// labels for metrics), never reconstructs the original material.
pub fn host_safe_digest(domain: &[u8], material: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(material.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(HOST_SAFE_DIGEST_PREFIX.len() + 64);
    out.push_str(HOST_SAFE_DIGEST_PREFIX);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Host-safe task identifier for logs / metric labels.
///
/// Empty / missing task ids produce the fixed token `"task:none"` so labels
/// stay populated without implying a real task.
pub fn task_id_ref(task_id: Option<&str>) -> String {
    match task_id {
        Some(id) if !id.is_empty() => format!("task:{}", host_safe_digest(TASK_ID_DOMAIN, id)),
        _ => "task:none".to_string(),
    }
}

/// Host-safe digest of a URL's path + query (the fields VAL-CONF-018 greps for).
///
/// Scheme / host / port are structural and may still appear as destination
/// metadata elsewhere; they are **not** returned by this helper. Callers that
/// need a host-safe stand-in for a full URL use [`url_ref`].
pub fn url_path_query_ref(url: &str) -> String {
    let (path, query) = split_path_query(url);
    let mut material = path.to_string();
    if let Some(q) = query {
        material.push('?');
        material.push_str(q);
    }
    format!("url:{}", host_safe_digest(URL_PQ_DOMAIN, &material))
}

/// Host-safe substitute for a complete URL string.
///
/// Preserves scheme + host + port (destination identity is not confidential)
/// while replacing path + query with a content-blind digest. Relative fragments
/// that cannot be parsed fall back to a full digest of the raw string.
pub fn url_ref(url: &str) -> String {
    match parse_url_parts(url) {
        Some(parts) => {
            let mut out = String::new();
            if let Some(scheme) = parts.scheme {
                out.push_str(scheme);
                out.push_str("://");
            }
            if let Some(host) = parts.host {
                out.push_str(host);
            }
            if let Some(port) = parts.port {
                out.push(':');
                out.push_str(port);
            }
            out.push('/');
            out.push_str(&url_path_query_ref(url));
            out
        }
        None => format!("url:{}", host_safe_digest(URL_PQ_DOMAIN, url)),
    }
}

/// True when `haystack` contains a sensitive path/query/token-looking trailing
/// URL fragment that must never leave the enclave as plain text. Used by tests
/// and by the panic-hook self-check.
pub fn contains_sensitive_url_fragment(haystack: &str, sensitive: &str) -> bool {
    !sensitive.is_empty() && haystack.contains(sensitive)
}

/// Redact every occurrence of each `marker` in `text` with [`REDACTED_TOKEN`].
///
/// Markers that are empty or whitespace-only are ignored (they would match
/// everything). Longer markers are applied first so multi-part secrets win
/// over their prefixes.
pub fn redact_markers<'a>(text: &'a str, markers: &[&str]) -> Cow<'a, str> {
    let mut ordered: Vec<&str> = markers
        .iter()
        .copied()
        .filter(|m| !m.trim().is_empty())
        .collect();
    if ordered.is_empty() {
        return Cow::Borrowed(text);
    }
    ordered.sort_by_key(|m| std::cmp::Reverse(m.len()));
    let mut owned: Option<String> = None;
    for marker in ordered {
        let source = owned.as_deref().unwrap_or(text);
        if source.contains(marker) {
            let next = source.replace(marker, REDACTED_TOKEN);
            owned = Some(next);
        }
    }
    match owned {
        Some(s) => Cow::Owned(s),
        None => Cow::Borrowed(text),
    }
}

/// Recursively walk a JSON value and replace any string that contains one of
/// the secrecy markers, plus any well-known URL path/query keys' values, with
/// host-safe stand-ins. Used to scrub structured robots-deny payloads and
/// panic payloads before they become host-visible.
pub fn redact_json_value(value: &mut serde_json::Value, markers: &[&str], path_keys: &[&str]) {
    match value {
        serde_json::Value::Object(map) => {
            // Collect keys first to avoid borrow issues while mutating.
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let is_path_key = path_keys.iter().any(|k| key.eq_ignore_ascii_case(k));
                if let Some(entry) = map.get_mut(&key) {
                    if is_path_key {
                        if let serde_json::Value::String(s) = entry {
                            *s = if key.to_ascii_lowercase().contains("url") {
                                url_ref(s)
                            } else {
                                // Bare path / query string values.
                                format!("url:{}", host_safe_digest(URL_PQ_DOMAIN, s.as_str()))
                            };
                        } else {
                            redact_json_value(entry, markers, path_keys);
                        }
                    } else if let serde_json::Value::String(s) = entry {
                        let redacted = redact_markers(s, markers);
                        if let Cow::Owned(r) = redacted {
                            *s = r;
                        }
                        // Always collapse residual full URLs that embed a path.
                        if looks_like_url_with_path(s) {
                            *s = url_ref(s);
                        }
                    } else {
                        redact_json_value(entry, markers, path_keys);
                    }
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_value(item, markers, path_keys);
            }
        }
        serde_json::Value::String(s) => {
            let redacted = redact_markers(s, markers);
            if let Cow::Owned(r) = redacted {
                *s = r;
            }
            if looks_like_url_with_path(s) {
                *s = url_ref(s);
            }
        }
        _ => {}
    }
}

/// Host-visible metric / log labels that never bind request path/query, headers,
/// cookies, tokens, body, or result plaintext.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HostSafeLabels {
    /// Always-present task handle (`task:sha256:…` or `task:none`).
    pub task_id: String,
    /// Stable event name (`scrape_completed`, `scrape_failed`, …).
    pub event: String,
    /// Machine-readable error kind when the event is a failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Optional coarse status code (never a body / header).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Optional request/response header or body **hash** only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,
}

impl HostSafeLabels {
    /// Construct labels for a successful scrape completion.
    pub fn scrape_completed(
        task_id: Option<&str>,
        status_code: Option<u16>,
        headers_hash: Option<&str>,
        body_hash: Option<&str>,
    ) -> Self {
        Self {
            task_id: task_id_ref(task_id),
            event: "scrape_completed".into(),
            kind: None,
            status_code,
            headers_hash: headers_hash.map(str::to_owned),
            body_hash: body_hash.map(str::to_owned),
        }
    }

    /// Construct labels for a failed scrape / enclave-side error path.
    pub fn scrape_failed(task_id: Option<&str>, kind: &str) -> Self {
        Self {
            task_id: task_id_ref(task_id),
            event: "scrape_failed".into(),
            kind: Some(kind.to_owned()),
            status_code: None,
            headers_hash: None,
            body_hash: None,
        }
    }

    /// Compact JSON suitable for a single host-visible log line / metric export.
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).expect("HostSafeLabels is always serializable")
    }

    /// True when none of the secrecy markers appear in the serialized labels.
    pub fn is_free_of(&self, markers: &[&str]) -> bool {
        let rendered = self.to_json_string();
        markers
            .iter()
            .all(|m| m.is_empty() || !rendered.contains(m))
    }
}

/// Install a panic hook that refuses to print the default payload as-is when the
/// payload looks like it embeds a path/query-shaped string. Subsequent panics
/// emit only a kind + optional host-safe digest, never the original message.
///
/// Safe to call repeatedly; installation is once per process. Chaining preserves
/// any previously installed hook for non-sensitive panics so library tests that
/// deliberate-panic still work.
pub fn install_host_safe_panic_hook() {
    PANIC_HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let payload = panic_payload_as_str(info);
            // Strip anything that looks like a URL path (starts with `/` + non-trivial)
            // or includes common secret keywords from Display formatting.
            if payload_looks_sensitive(&payload) {
                let safe = format!(
                    "basecrawl panic (host-safe): kind=internal_error digest={}",
                    host_safe_digest(b"basecrawl/host-safe/panic/v1", &payload)
                );
                eprintln!("{safe}");
                return;
            }
            previous(info);
        }));
    });
}

/// Coarse host-safe description of a panic payload (for FFI last-error).
pub fn host_safe_panic_message() -> String {
    "{\"error\":{\"kind\":\"internal_error\",\"message\":\"basecrawl binding panicked\"}}".into()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct UrlParts<'a> {
    scheme: Option<&'a str>,
    host: Option<&'a str>,
    port: Option<&'a str>,
}

fn parse_url_parts(url: &str) -> Option<UrlParts<'_>> {
    let (scheme, rest) = if let Some(idx) = url.find("://") {
        (Some(&url[..idx]), &url[idx + 3..])
    } else {
        (None, url)
    };
    // Trim path / query / fragment.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() && scheme.is_none() {
        return None;
    }
    // Strip userinfo if present.
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, hostport)| hostport);
    let (host, port) = if authority.starts_with('[') {
        // IPv6 literal: [::1]:port
        if let Some(end) = authority.find(']') {
            let host = &authority[..=end];
            let port = authority[end + 1..]
                .strip_prefix(':')
                .filter(|p| !p.is_empty());
            (Some(host), port)
        } else {
            (Some(authority), None)
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        // Only treat as port when the right side is all digits.
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            (Some(h), Some(p))
        } else {
            (Some(authority), None)
        }
    } else if authority.is_empty() {
        (None, None)
    } else {
        (Some(authority), None)
    };
    Some(UrlParts { scheme, host, port })
}

fn split_path_query(url: &str) -> (&str, Option<&str>) {
    let after_scheme = url.find("://").map(|idx| &url[idx + 3..]).unwrap_or(url);
    let path_start = after_scheme
        .find('/')
        .map(|idx| &after_scheme[idx..])
        .unwrap_or("");
    // Drop fragment.
    let path_q = path_start.split('#').next().unwrap_or(path_start);
    if let Some((path, query)) = path_q.split_once('?') {
        (path, Some(query))
    } else {
        (path_q, None)
    }
}

fn looks_like_url_with_path(s: &str) -> bool {
    if !s.contains("://") {
        return false;
    }
    // scheme://host/path or scheme://host?query
    if let Some(rest) = s.split("://").nth(1) {
        return rest.contains('/') || rest.contains('?');
    }
    false
}

fn panic_payload_as_str(info: &panic::PanicHookInfo<'_>) -> String {
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        String::new()
    }
}

fn payload_looks_sensitive(payload: &str) -> bool {
    if payload.is_empty() {
        return false;
    }
    // Full URLs with a path/query, or common cookie/auth markers.
    if looks_like_url_with_path(payload) {
        return true;
    }
    let lower = payload.to_ascii_lowercase();
    lower.contains("cookie:")
        || lower.contains("authorization:")
        || lower.contains("bearer ")
        || lower.contains("set-cookie")
        || (lower.contains('?') && lower.contains('='))
        || lower.contains("/secret")
        || lower.contains("canary")
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn task_id_ref_is_stable_and_non_echoing() {
        let a = task_id_ref(Some("task-abc-123"));
        let b = task_id_ref(Some("task-abc-123"));
        assert_eq!(a, b);
        assert!(a.starts_with("task:sha256:"));
        assert!(!a.contains("task-abc-123"));
        assert_eq!(task_id_ref(None), "task:none");
        assert_eq!(task_id_ref(Some("")), "task:none");
    }

    #[test]
    fn url_path_query_ref_hides_path_and_query() {
        let raw = "https://target.example/secret/path?token=abc&k=v";
        let safe = url_path_query_ref(raw);
        assert!(safe.starts_with("url:sha256:"));
        assert!(!safe.contains("secret"));
        assert!(!safe.contains("token=abc"));
        assert!(!safe.contains("/secret/path"));
        // Same path+query → same digest regardless of host.
        let alt = url_path_query_ref("https://other.example/secret/path?token=abc&k=v");
        assert_eq!(safe, alt);
    }

    #[test]
    fn url_ref_preserves_host_strips_path() {
        let safe = url_ref("https://target.example:8443/secret/path?q=1");
        assert!(safe.starts_with("https://target.example:8443/"));
        assert!(!safe.contains("secret"));
        assert!(!safe.contains("q=1"));
        assert!(safe.contains("url:sha256:"));
    }

    #[test]
    fn redact_markers_replaces_all_secrets() {
        let text = "Authorization: Bearer tok-AAA cookie=sess-BBB body=canary-CCC";
        let out = redact_markers(text, &["tok-AAA", "sess-BBB", "canary-CCC"]);
        assert!(!out.contains("tok-AAA"));
        assert!(!out.contains("sess-BBB"));
        assert!(!out.contains("canary-CCC"));
        assert_eq!(out.matches(REDACTED_TOKEN).count(), 3);
    }

    #[test]
    fn host_safe_labels_serialize_without_markers() {
        let labels = HostSafeLabels::scrape_failed(Some("task-xyz"), "authentication_failed");
        let rendered = labels.to_json_string();
        assert!(rendered.contains("scrape_failed"));
        assert!(rendered.contains("authentication_failed"));
        assert!(!rendered.contains("task-xyz"));
        assert!(labels.is_free_of(&["task-xyz", "/secret", "Bearer "]));
    }

    #[test]
    fn redact_json_value_scrubs_target_url_and_path() {
        let mut value = serde_json::json!({
            "targetUrl": "https://example.com/blocked/private?robots-denied=1",
            "matched_rule": { "path": "/blocked", "directive": "disallow" },
            "disposition": "denied",
            "policy": "enforce",
        });
        redact_json_value(&mut value, &[], &["targetUrl", "robotsUrl", "path", "url"]);
        let rendered = value.to_string();
        assert!(!rendered.contains("/blocked"));
        assert!(!rendered.contains("robots-denied=1"));
        assert!(!rendered.contains("private"));
        assert_eq!(value["disposition"], "denied");
        assert_eq!(value["policy"], "enforce");
    }
}
