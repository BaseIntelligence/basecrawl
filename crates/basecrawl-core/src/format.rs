//! Firecrawl-parity output formats: parsing, validation, and canonical ordering.

use crate::error::Error;

/// A supported output format. Declaration order is the canonical (order-normalized) order used
/// when echoing `request.formats` and keying `result.formats_produced`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    Markdown,
    Html,
    RawHtml,
    Links,
    Metadata,
    Screenshot,
    Json,
}

/// Every supported format, in canonical order.
pub const ALL: [Format; 7] = [
    Format::Markdown,
    Format::Html,
    Format::RawHtml,
    Format::Links,
    Format::Metadata,
    Format::Screenshot,
    Format::Json,
];

impl Format {
    /// Canonical wire token for this format (Firecrawl-parity spelling).
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Markdown => "markdown",
            Format::Html => "html",
            Format::RawHtml => "rawHtml",
            Format::Links => "links",
            Format::Metadata => "metadata",
            Format::Screenshot => "screenshot",
            Format::Json => "json",
        }
    }

    /// Parse a single format token (exact, case-sensitive match).
    pub fn from_token(token: &str) -> Option<Format> {
        ALL.into_iter().find(|f| f.as_str() == token)
    }
}

/// Comma/space separated list of all supported tokens, for error messages and help text.
pub fn supported_list() -> String {
    ALL.iter()
        .map(|f| f.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The fixed, documented default format set used when no `--formats` flag is supplied.
pub fn default_set() -> Vec<Format> {
    vec![Format::Markdown, Format::Metadata]
}

/// Return `formats` sorted into canonical order with duplicates removed.
pub fn normalize(mut formats: Vec<Format>) -> Vec<Format> {
    formats.sort();
    formats.dedup();
    formats
}

/// Parse and canonicalize a list of format tokens. The first unknown token yields
/// [`Error::UnknownFormat`] naming the offending value; no partial result is produced.
pub fn parse_list(tokens: &[String]) -> Result<Vec<Format>, Error> {
    let mut parsed = Vec::with_capacity(tokens.len());
    for token in tokens {
        let trimmed = token.trim();
        match Format::from_token(trimmed) {
            Some(f) => parsed.push(f),
            None => {
                return Err(Error::UnknownFormat {
                    invalid: trimmed.to_string(),
                    supported: supported_list(),
                })
            }
        }
    }
    Ok(normalize(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_order() {
        let got = parse_list(&["metadata".into(), "links".into(), "markdown".into()]).unwrap();
        assert_eq!(got, vec![Format::Markdown, Format::Links, Format::Metadata]);
    }

    #[test]
    fn deduplicates() {
        let got = parse_list(&["markdown".into(), "markdown".into()]).unwrap();
        assert_eq!(got, vec![Format::Markdown]);
    }

    #[test]
    fn rejects_unknown_naming_the_token() {
        let err = parse_list(&["markdown".into(), "bogusfmt".into()]).unwrap_err();
        match err {
            Error::UnknownFormat { invalid, .. } => assert_eq!(invalid, "bogusfmt"),
            other => panic!("expected UnknownFormat, got {other:?}"),
        }
    }

    #[test]
    fn default_set_is_markdown_and_metadata() {
        assert_eq!(default_set(), vec![Format::Markdown, Format::Metadata]);
    }

    #[test]
    fn raw_html_token_is_camel_case() {
        assert_eq!(Format::RawHtml.as_str(), "rawHtml");
        assert_eq!(Format::from_token("rawHtml"), Some(Format::RawHtml));
        assert_eq!(Format::from_token("rawhtml"), None);
    }
}
