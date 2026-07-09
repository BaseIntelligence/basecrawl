//! "Next page" discovery for pagination following.
//!
//! When pagination following is requested, the crawler needs to locate the link to the next page of
//! a paginated listing. [`find_next`] surfaces that link from a page's (rendered or served) HTML:
//! it prefers an explicit `rel="next"` relationship (`<a rel="next">` / `<link rel="next">`) and
//! otherwise falls back to an anchor whose visible text reads like a "next" control. The href is
//! resolved to an absolute http(s) URL against the page's base so the caller can fetch it directly.

use scraper::{Html, Selector};
use url::Url;

/// Find the next-page URL linked from `html`, resolved absolutely against `base`.
///
/// Returns the `rel="next"` target when present; otherwise the first anchor whose normalized text is
/// a "next" control (e.g. `next`, `next »`, `next page`, `»`, `→`). Only http/https targets are
/// returned. `None` means no next page was found (the end of the pagination chain).
pub fn find_next(html: &str, base: &Url) -> Option<Url> {
    let doc = Html::parse_document(html);
    // Honor a document <base href> for relative resolution, matching the other format producers.
    let doc_base = base_href(&doc, base);

    let selector = Selector::parse("a[href], link[href]").ok()?;
    let mut text_fallback: Option<Url> = None;

    for el in doc.select(&selector) {
        let href = el.value().attr("href").unwrap_or("").trim();
        if href.is_empty() {
            continue;
        }
        let rel_is_next = el
            .value()
            .attr("rel")
            .map(|rel| {
                rel.split_whitespace()
                    .any(|token| token.eq_ignore_ascii_case("next"))
            })
            .unwrap_or(false);

        let text = el.text().collect::<String>();
        let norm = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let text_is_next = is_next_text(&norm);

        if !rel_is_next && !text_is_next {
            continue;
        }
        let Ok(resolved) = doc_base.join(href) else {
            continue;
        };
        if resolved.scheme() != "http" && resolved.scheme() != "https" {
            continue;
        }
        // rel="next" is authoritative; a text-only match is only a fallback.
        if rel_is_next {
            return Some(resolved);
        }
        if text_fallback.is_none() {
            text_fallback = Some(resolved);
        }
    }

    text_fallback
}

/// Whether the (whitespace-normalized) anchor text reads like a "next page" control.
fn is_next_text(norm: &str) -> bool {
    let lower = norm.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "next" | "next »" | "next >" | "next ›" | "next page" | "»" | "›" | "→" | "next →"
    ) || lower.starts_with("next ")
}

/// Resolve the base used for relative links: a document `<base href>` if present and absolute, else
/// the page URL.
fn base_href(doc: &Html, page_url: &Url) -> Url {
    if let Ok(sel) = Selector::parse("base[href]") {
        if let Some(el) = doc.select(&sel).next() {
            if let Some(href) = el.value().attr("href") {
                if let Ok(resolved) = page_url.join(href) {
                    return resolved;
                }
            }
        }
    }
    page_url.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://books.example/catalogue/page-1.html").unwrap()
    }

    #[test]
    fn prefers_rel_next() {
        let html = r#"<a href="p2.html">next</a><a rel="next" href="real-next.html">go</a>"#;
        let next = find_next(html, &base()).unwrap();
        assert_eq!(
            next.as_str(),
            "https://books.example/catalogue/real-next.html"
        );
    }

    #[test]
    fn falls_back_to_next_text() {
        let html = r#"<li class="next"><a href="page-2.html">next</a></li>"#;
        let next = find_next(html, &base()).unwrap();
        assert_eq!(next.as_str(), "https://books.example/catalogue/page-2.html");
    }

    #[test]
    fn resolves_root_relative_against_base() {
        let html = r#"<a rel="next" href="/catalogue/page-2.html">next</a>"#;
        let next = find_next(html, &base()).unwrap();
        assert_eq!(next.as_str(), "https://books.example/catalogue/page-2.html");
    }

    #[test]
    fn honors_document_base_href() {
        let html = r#"<head><base href="https://books.example/other/"></head>
            <body><a rel="next" href="page-9.html">next</a></body>"#;
        let next = find_next(html, &base()).unwrap();
        assert_eq!(next.as_str(), "https://books.example/other/page-9.html");
    }

    #[test]
    fn none_when_no_next_link() {
        let html = r#"<a href="p2.html">previous</a><a href="p3.html">home</a>"#;
        assert!(find_next(html, &base()).is_none());
    }

    #[test]
    fn ignores_non_http_next() {
        let html = r#"<a rel="next" href="javascript:void(0)">next</a>"#;
        assert!(find_next(html, &base()).is_none());
    }
}
