//! Firecrawl-parity link extraction for the `links` format.
//!
//! Anchors (`<a href>`) are resolved to absolute URLs against the document base (honoring a
//! `<base href>` when one is declared, otherwise the document's own post-redirect URL),
//! de-duplicated while preserving document order, and restricted to navigational http(s) targets.
//! Non-navigational schemes (`mailto:`/`tel:`/`javascript:` etc.) are categorized under `excluded`
//! with their scheme rather than being resolved into bogus http URLs. `<link rel="canonical">` and
//! `<link rel="alternate" hreflang>` are surfaced alongside the anchor list so downstream consumers
//! (and the `relay` completeness verifier) can see them without a separate metadata pass. The
//! caller appends discovered sitemap URL seeds to the same `links` surface.

use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::HashSet;
use url::Url;

/// The extracted `links` surface produced for the `links` format.
///
/// Serialization key order is fixed by declaration order (`links`, `canonical`, `alternates`,
/// `excluded`), and every field is always emitted (an absent canonical serializes as `null`, and
/// the list fields serialize as empty arrays) so the shape is stable across pages.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Links {
    /// De-duplicated, absolute navigational (http/https) anchor URLs, in document order.
    pub links: Vec<String>,
    /// Absolute `rel="canonical"` URL, or `null` when the document declares none.
    pub canonical: Option<String>,
    /// `rel="alternate" hreflang` locale alternates, in document order.
    pub alternates: Vec<Alternate>,
    /// Non-navigational anchor targets (e.g. mailto/tel/javascript), categorized by scheme and
    /// preserved verbatim rather than resolved into an http URL.
    pub excluded: Vec<ExcludedLink>,
    /// Absolute URL seeds discovered from the origin's default or robots-referenced sitemap(s).
    pub sitemap: Vec<String>,
}

/// A `rel="alternate" hreflang` locale alternate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alternate {
    pub hreflang: String,
    pub href: String,
}

/// A non-navigational anchor target, categorized by its URL scheme.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExcludedLink {
    pub scheme: String,
    pub href: String,
}

/// Extract the `links` surface from an HTML document.
///
/// `page_url` is the document's own (post-redirect) URL; a `<base href>` in the document overrides
/// it as the resolution base. Anchor targets that resolve to http/https are emitted as absolute
/// URLs in `links` (de-duplicated, document order); anything else is categorized under `excluded`
/// with its scheme and never rewritten into an http URL.
pub fn extract(html: &str, page_url: &Url) -> Links {
    let document = Html::parse_document(html);
    let base = base_href(&document)
        .and_then(|href| page_url.join(&href).ok())
        .unwrap_or_else(|| page_url.clone());

    let mut links: Vec<String> = Vec::new();
    let mut seen_links: HashSet<String> = HashSet::new();
    let mut excluded: Vec<ExcludedLink> = Vec::new();
    let mut seen_excluded: HashSet<String> = HashSet::new();

    if let Ok(selector) = Selector::parse("a[href]") {
        for el in document.select(&selector) {
            let Some(raw) = el.value().attr("href") else {
                continue;
            };
            let href = raw.trim();
            if href.is_empty() {
                continue;
            }
            match base.join(href) {
                Ok(url) if is_navigational(url.scheme()) => {
                    let abs = url.to_string();
                    if seen_links.insert(abs.clone()) {
                        links.push(abs);
                    }
                }
                // A resolvable but non-navigational scheme (mailto/tel/javascript/...): categorize
                // by scheme, preserving the original href verbatim rather than rewriting it.
                Ok(url) => push_excluded(&mut excluded, &mut seen_excluded, url.scheme(), href),
                // Unresolvable target: never fabricate an http URL. If it carries a recognizable
                // scheme, categorize it; otherwise drop it.
                Err(_) => {
                    if let Some(scheme) = sniff_scheme(href) {
                        push_excluded(&mut excluded, &mut seen_excluded, &scheme, href);
                    }
                }
            }
        }
    }

    Links {
        links,
        canonical: extract_canonical(&document, &base),
        alternates: extract_alternates(&document, &base),
        excluded,
        sitemap: Vec::new(),
    }
}

/// Whether `scheme` denotes a navigational web link (the only schemes emitted as absolute URLs).
fn is_navigational(scheme: &str) -> bool {
    matches!(scheme, "http" | "https")
}

/// Record a non-navigational link once (de-duplicated by `scheme` + `href`).
fn push_excluded(
    excluded: &mut Vec<ExcludedLink>,
    seen: &mut HashSet<String>,
    scheme: &str,
    href: &str,
) {
    let key = format!("{scheme}\u{0}{href}");
    if seen.insert(key) {
        excluded.push(ExcludedLink {
            scheme: scheme.to_ascii_lowercase(),
            href: href.to_string(),
        });
    }
}

/// Best-effort scheme sniff for an href the URL parser rejected: the leading run matching the URL
/// scheme grammar (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`) before the first `:`.
fn sniff_scheme(href: &str) -> Option<String> {
    let (candidate, _rest) = href.split_once(':')?;
    let mut chars = candidate.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        Some(candidate.to_ascii_lowercase())
    } else {
        None
    }
}

/// Extract a document `<base href>` value, if the document declares one.
fn base_href(document: &Html) -> Option<String> {
    let selector = Selector::parse("base[href]").ok()?;
    document
        .select(&selector)
        .next()
        .and_then(|el| el.value().attr("href"))
        .map(str::to_string)
}

/// Surface the first `<link rel="canonical">` as an absolute URL, if present.
fn extract_canonical(document: &Html, base: &Url) -> Option<String> {
    let selector = Selector::parse("link[rel][href]").ok()?;
    for el in document.select(&selector) {
        if !rel_has(el.value().attr("rel").unwrap_or_default(), "canonical") {
            continue;
        }
        let href = el.value().attr("href").unwrap_or_default().trim();
        if href.is_empty() {
            continue;
        }
        if let Ok(url) = base.join(href) {
            return Some(url.to_string());
        }
    }
    None
}

/// Surface every `<link rel="alternate" hreflang="...">` locale alternate, in document order,
/// de-duplicated by `(hreflang, href)`.
fn extract_alternates(document: &Html, base: &Url) -> Vec<Alternate> {
    let mut out: Vec<Alternate> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let Ok(selector) = Selector::parse("link[rel][hreflang][href]") else {
        return out;
    };
    for el in document.select(&selector) {
        let element = el.value();
        if !rel_has(element.attr("rel").unwrap_or_default(), "alternate") {
            continue;
        }
        let hreflang = element.attr("hreflang").unwrap_or_default().trim();
        let href = element.attr("href").unwrap_or_default().trim();
        if hreflang.is_empty() || href.is_empty() {
            continue;
        }
        let abs = base
            .join(href)
            .map(String::from)
            .unwrap_or_else(|_| href.to_string());
        let key = format!("{hreflang}\u{0}{abs}");
        if seen.insert(key) {
            out.push(Alternate {
                hreflang: hreflang.to_string(),
                href: abs,
            });
        }
    }
    out
}

/// Whether the space-separated `rel` token list contains `token` (HTML `rel` is case-insensitive).
fn rel_has(rel: &str, token: &str) -> bool {
    rel.split_whitespace()
        .any(|t| t.eq_ignore_ascii_case(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> Url {
        Url::parse("https://example.com/dir/page.html").unwrap()
    }

    fn extract_html(html: &str) -> Links {
        extract(html, &page())
    }

    #[test]
    fn resolves_relative_and_root_relative_anchors_to_absolute() {
        let html = "<a href=\"../other.html\">a</a><a href=\"/tag/x/\">b</a>\
            <a href=\"https://elsewhere.test/z\">c</a>";
        let links = extract_html(html).links;
        assert!(links.contains(&"https://example.com/other.html".to_string()));
        assert!(links.contains(&"https://example.com/tag/x/".to_string()));
        assert!(links.contains(&"https://elsewhere.test/z".to_string()));
        assert!(
            links.iter().all(|l| l.starts_with("http")),
            "all links must be absolute http(s): {links:?}"
        );
    }

    #[test]
    fn resolves_against_base_href_when_present() {
        let html = "<head><base href=\"https://cdn.test/base/\"></head>\
            <body><a href=\"rel.html\">rel</a></body>";
        let links = extract_html(html).links;
        assert_eq!(links, vec!["https://cdn.test/base/rel.html".to_string()]);
    }

    #[test]
    fn captures_canonical_url_absolute() {
        let html = "<head><link rel=\"canonical\" href=\"/canonical-page\"></head>\
            <body><a href=\"/x\">x</a></body>";
        let out = extract_html(html);
        assert_eq!(
            out.canonical,
            Some("https://example.com/canonical-page".to_string())
        );
    }

    #[test]
    fn canonical_is_none_when_absent() {
        let out = extract_html("<a href=\"/x\">x</a>");
        assert_eq!(out.canonical, None);
    }

    #[test]
    fn captures_hreflang_alternates() {
        let html = "<head>\
            <link rel=\"alternate\" hreflang=\"en\" href=\"https://example.com/en\">\
            <link rel=\"alternate\" hreflang=\"fr\" href=\"/fr\">\
            </head>";
        let alts = extract_html(html).alternates;
        assert!(alts.contains(&Alternate {
            hreflang: "en".to_string(),
            href: "https://example.com/en".to_string(),
        }));
        assert!(alts.contains(&Alternate {
            hreflang: "fr".to_string(),
            href: "https://example.com/fr".to_string(),
        }));
    }

    #[test]
    fn deduplicates_repeated_hrefs() {
        let html = "<a href=\"/dup\">1</a><a href=\"/dup\">2</a><a href=\"/dup\">3</a>";
        let links = extract_html(html).links;
        assert_eq!(links, vec!["https://example.com/dup".to_string()]);
    }

    #[test]
    fn preserves_document_order() {
        let html = "<a href=\"/a\">a</a><a href=\"/b\">b</a><a href=\"/c\">c</a>";
        let links = extract_html(html).links;
        assert_eq!(
            links,
            vec![
                "https://example.com/a".to_string(),
                "https://example.com/b".to_string(),
                "https://example.com/c".to_string(),
            ]
        );
    }

    #[test]
    fn excludes_non_navigational_schemes_without_mangling() {
        let html = "<a href=\"mailto:hi@example.com\">mail</a>\
            <a href=\"tel:+15551234\">call</a>\
            <a href=\"javascript:void(0)\">js</a>\
            <a href=\"/real\">real</a>";
        let out = extract_html(html);
        // The navigational list carries only the real link.
        assert_eq!(out.links, vec!["https://example.com/real".to_string()]);
        // Non-navigational targets are never resolved into http URLs.
        assert!(
            out.links.iter().all(|l| l.starts_with("http")),
            "a non-navigational scheme leaked into links: {:?}",
            out.links
        );
        // They are categorized under `excluded` with the original href preserved verbatim.
        let schemes: Vec<&str> = out.excluded.iter().map(|e| e.scheme.as_str()).collect();
        assert!(schemes.contains(&"mailto"), "excluded: {:?}", out.excluded);
        assert!(schemes.contains(&"tel"), "excluded: {:?}", out.excluded);
        assert!(
            schemes.contains(&"javascript"),
            "excluded: {:?}",
            out.excluded
        );
        assert!(out
            .excluded
            .iter()
            .any(|e| e.href == "mailto:hi@example.com"));
        assert!(out.excluded.iter().any(|e| e.href == "javascript:void(0)"));
    }

    #[test]
    fn skips_empty_and_whitespace_hrefs() {
        let html = "<a href=\"\">empty</a><a href=\"   \">ws</a><a href=\"/ok\">ok</a>";
        let links = extract_html(html).links;
        assert_eq!(links, vec!["https://example.com/ok".to_string()]);
    }

    #[test]
    fn no_anchors_yields_empty_but_valid_surface() {
        let out = extract_html("<p>no links here</p>");
        assert!(out.links.is_empty());
        assert!(out.canonical.is_none());
        assert!(out.alternates.is_empty());
        assert!(out.excluded.is_empty());
    }

    #[test]
    fn rel_matching_is_case_insensitive_and_token_aware() {
        let html = "<head>\
            <link rel=\"CANONICAL\" href=\"/c\">\
            <link rel=\"alternate stylesheet\" hreflang=\"de\" href=\"/de\">\
            </head>";
        let out = extract_html(html);
        assert_eq!(out.canonical, Some("https://example.com/c".to_string()));
        assert!(out.alternates.contains(&Alternate {
            hreflang: "de".to_string(),
            href: "https://example.com/de".to_string(),
        }));
    }

    #[test]
    fn emitted_surface_has_explicit_null_canonical_and_empty_arrays() {
        // Mirror the emission path in `scrape()`: the struct is converted to a `serde_json::Value`
        // before being embedded in the ScrapeProof, so assert on that same form.
        let out = extract_html("<a href=\"/x\">x</a>");
        let value = serde_json::to_value(&out).unwrap();
        assert!(
            value["canonical"].is_null(),
            "canonical must be explicit null when absent"
        );
        assert_eq!(value["alternates"].as_array().unwrap().len(), 0);
        assert_eq!(value["excluded"].as_array().unwrap().len(), 0);
        assert_eq!(value["links"].as_array().unwrap().len(), 1);
        // The serialized form is byte-stable across runs (deterministic key order).
        let first = serde_json::to_string(&serde_json::to_value(&out).unwrap()).unwrap();
        let again = serde_json::to_string(
            &serde_json::to_value(extract_html("<a href=\"/x\">x</a>")).unwrap(),
        )
        .unwrap();
        assert_eq!(first, again);
    }

    #[test]
    fn deterministic_across_runs() {
        let html = "<a href=\"/a\">a</a><a href=\"/b\">b</a><a href=\"mailto:x@y.z\">m</a>";
        assert_eq!(extract_html(html), extract_html(html));
    }
}
