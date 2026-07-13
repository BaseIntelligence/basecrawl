//! HTTP method + request body surface for product breadth (VAL-CRAWLPROD-001..007).
//!
//! Soft path: POST transmits bytes and records honest integrity hashes.
//! Hard Chromium path: refuses POST with a structured error — never silent empty-body success.

use crate::error::Error;

/// Supported methods for a single soft-path scrape as of M15.
pub const DEFAULT_METHOD: &str = "GET";

/// Normalize and validate a caller-supplied method. Default is GET.
///
/// Rejects free-form garbage (`FOO` with spaces, empty, control chars) with
/// [`Error::UnsupportedMethod`]. Restricted product vocabulary is `GET` and `POST` on the soft path.
pub fn normalize_method(raw: Option<&str>) -> Result<String, Error> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(DEFAULT_METHOD.to_string());
    };
    let upper = raw.to_ascii_uppercase();
    if !is_token(&upper) {
        return Err(Error::UnsupportedMethod(raw.to_string()));
    }
    match upper.as_str() {
        "GET" | "POST" => Ok(upper),
        other => Err(Error::UnsupportedMethod(other.to_string())),
    }
}

/// RFC 9110 token check (letters / digits / a short set of tchars).
fn is_token(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Decode a body argument supplied as a raw string or `@file-path` (CLI convenience).
pub fn parse_body_arg(raw: Option<&str>) -> Result<Vec<u8>, Error> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if let Some(path) = raw.strip_prefix('@') {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::InvalidProductOption(format!("could not read body file: {e}")))?;
        return Ok(bytes);
    }
    Ok(raw.as_bytes().to_vec())
}

/// Body may only accompany POST. GET with a non-empty body fails closed.
pub fn validate_method_body(method: &str, body: &[u8]) -> Result<(), Error> {
    if method.eq_ignore_ascii_case("GET") && !body.is_empty() {
        return Err(Error::InvalidProductOption(
            "request body requires --method POST".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_method_is_get() {
        assert_eq!(normalize_method(None).unwrap(), "GET");
        assert_eq!(normalize_method(Some("")).unwrap(), "GET");
        assert_eq!(normalize_method(Some("get")).unwrap(), "GET");
    }

    #[test]
    fn post_is_accepted() {
        assert_eq!(normalize_method(Some("POST")).unwrap(), "POST");
        assert_eq!(normalize_method(Some("post")).unwrap(), "POST");
    }

    #[test]
    fn absurd_method_fails() {
        let err = normalize_method(Some("FOO")).unwrap_err();
        assert!(matches!(err, Error::UnsupportedMethod(_)));
        assert_eq!(err.kind(), "unsupported_method");
    }

    #[test]
    fn get_with_body_fails_closed() {
        let err = validate_method_body("GET", b"payload").unwrap_err();
        assert!(matches!(err, Error::InvalidProductOption(_)));
    }
}
