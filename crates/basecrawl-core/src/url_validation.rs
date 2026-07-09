//! URL parsing and scheme validation, performed before any network fetch.

use crate::error::Error;
use url::Url;

/// Parse and validate a requested URL.
///
/// A scheme-less input (e.g. `example.com`) is treated as `https://`. Only `http`/`https` are
/// accepted; any other scheme (`file`, `ftp`, `gopher`, ...) is refused here, before any fetch,
/// so a non-HTTP scheme can never trigger a file read or SSRF-style request.
pub fn validate_url(raw: &str) -> Result<Url, Error> {
    let parsed = match Url::parse(raw) {
        Ok(url) => url,
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            Url::parse(&format!("https://{raw}")).map_err(|_| Error::InvalidUrl(raw.to_string()))?
        }
        Err(_) => return Err(Error::InvalidUrl(raw.to_string())),
    };

    match parsed.scheme() {
        "http" | "https" => {
            if parsed.host_str().is_none_or(str::is_empty) {
                return Err(Error::InvalidUrl(raw.to_string()));
            }
            Ok(parsed)
        }
        other => Err(Error::UnsupportedScheme(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https() {
        let u = validate_url("https://example.com").unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), Some("example.com"));
    }

    #[test]
    fn accepts_http() {
        assert_eq!(validate_url("http://example.com").unwrap().scheme(), "http");
    }

    #[test]
    fn prepends_https_for_schemeless() {
        let u = validate_url("example.com").unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.as_str(), "https://example.com/");
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            validate_url("not a url"),
            Err(Error::InvalidUrl(_))
        ));
    }

    #[test]
    fn rejects_file_scheme() {
        match validate_url("file:///etc/passwd") {
            Err(Error::UnsupportedScheme(s)) => assert_eq!(s, "file"),
            other => panic!("expected UnsupportedScheme(file), got {other:?}"),
        }
    }

    #[test]
    fn rejects_ftp_and_gopher() {
        assert!(matches!(
            validate_url("ftp://example.com/x"),
            Err(Error::UnsupportedScheme(_))
        ));
        assert!(matches!(
            validate_url("gopher://example.com/x"),
            Err(Error::UnsupportedScheme(_))
        ));
    }
}
