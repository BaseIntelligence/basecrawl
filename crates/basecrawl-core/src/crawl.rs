//! Bounded Crawl MVP (VAL-CRAWLPROD-008..013).
//!
//! Seed + max pages + max depth + same-origin / allow-domain filter. This is intentionally **not**
//! a hosted Firecrawl Cloud crawl SaaS: no search index, no scheduled monitor, no agent research.
//! Bounds fail closed — invalid caps are refused rather than crawling unbounded.

use crate::error::Error;
use crate::fetch;
use crate::links;
use crate::pagination;
use crate::{scrape, Format, ScrapeOptions, ScrapeProof};
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use url::Url;

/// Self-description for help / residual honesty (VAL-CRAWLPROD-013).
pub const CRAWL_MVP_DESCRIPTION: &str = "Bounded crawl MVP: seed URL + max pages/depth + domain \
filter. Not a hosted crawl SaaS (no search index, scheduled monitor, or cloud agent research).";

/// Options that bound a crawl run. Defaults fail closed (low caps).
#[derive(Debug, Clone)]
pub struct CrawlOptions {
    /// Shared scrape options applied to every page.
    pub scrape: ScrapeOptions,
    /// Inclusive cap on pages fetched (seed counts as 1). Minimum 1.
    pub max_pages: usize,
    /// Maximum link depth from the seed (seed depth=0). Depth=1 fetches seed + one-hop neighbors.
    pub max_depth: usize,
    /// Optional allow-domain host filter (case-insensitive). When `None`, same-origin as the seed
    /// is enforced (scheme+host+port).
    pub allow_domain: Option<String>,
}

impl Default for CrawlOptions {
    fn default() -> Self {
        Self {
            scrape: ScrapeOptions {
                // Soft crawl uses raw source / lightweight formats to avoid per-page Chromium cost.
                formats: vec![Format::Markdown, Format::Links],
                render_enabled: false,
                follow_pagination: false,
                ..ScrapeOptions::default()
            },
            max_pages: 5,
            max_depth: 1,
            allow_domain: None,
        }
    }
}

/// One successfully fetched page in the crawl.
#[derive(Debug, Clone, Serialize)]
pub struct CrawlPage {
    pub url: String,
    pub depth: usize,
    pub result_hash: Option<String>,
    pub status_code: Option<u16>,
    pub proof: ScrapeProof,
}

/// A URL discovered but not fetched (filter / bound).
#[derive(Debug, Clone, Serialize)]
pub struct CrawlSkipped {
    pub url: String,
    pub reason: String,
}

/// Multi-page crawl result surface (VAL-CRAWLPROD-008/012).
#[derive(Debug, Clone, Serialize)]
pub struct CrawlResult {
    /// Stable product mode marker.
    pub mode: String,
    pub seed: String,
    pub pages: Vec<CrawlPage>,
    pub skipped: Vec<CrawlSkipped>,
    /// Residual honesty: bounded MVP wording.
    pub residual: String,
    pub max_pages: usize,
    pub max_depth: usize,
}

impl CrawlResult {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).expect("CrawlResult is always serializable")
    }

    pub fn to_canonical_json(&self) -> String {
        self.to_json().to_string()
    }
}

/// Validate crawl bounds (fail-closed: zero or absurd values are rejected).
pub fn validate_bounds(max_pages: usize, max_depth: usize) -> Result<(), Error> {
    if max_pages == 0 {
        return Err(Error::InvalidProductOption(
            "crawl --max-pages must be >= 1".into(),
        ));
    }
    if max_pages > 10_000 {
        return Err(Error::InvalidProductOption(
            "crawl --max-pages exceeds hard safety cap (10000)".into(),
        ));
    }
    if max_depth > 32 {
        return Err(Error::InvalidProductOption(
            "crawl --max-depth exceeds hard safety cap (32)".into(),
        ));
    }
    Ok(())
}

/// Run a bounded same-origin (or allow-domain) crawl from `seed`.
pub fn crawl(seed: &str, options: &CrawlOptions) -> Result<CrawlResult, Error> {
    validate_bounds(options.max_pages, options.max_depth)?;
    let seed_url = crate::url_validation::validate_url(seed)?;
    let seed_origin = seed_url.clone();
    let allow_host = options
        .allow_domain
        .as_deref()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty());

    let mut pages: Vec<CrawlPage> = Vec::new();
    let mut skipped: Vec<CrawlSkipped> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: VecDeque<(Url, usize)> = VecDeque::new();
    frontier.push_back((seed_url, 0));

    while let Some((url, depth)) = frontier.pop_front() {
        if pages.len() >= options.max_pages {
            break;
        }
        let key = normalize_visit_key(&url);
        if !visited.insert(key) {
            continue;
        }
        if !is_allowed(&url, &seed_origin, allow_host.as_deref()) {
            skipped.push(CrawlSkipped {
                url: url.to_string(),
                reason: "outside_allow_domain".into(),
            });
            continue;
        }
        if depth > options.max_depth {
            skipped.push(CrawlSkipped {
                url: url.to_string(),
                reason: "depth_exceeded".into(),
            });
            continue;
        }

        // Per-page scrape: soft, bounded. force GET (crawl discovers by link, not POST).
        let mut page_opts = options.scrape.clone();
        page_opts.method = "GET".into();
        page_opts.body = Vec::new();
        // Avoid pagination follow inside each page; the crawl BFS owns link expansion.
        page_opts.follow_pagination = false;

        let proof = scrape(url.as_str(), &page_opts)?;
        let result_hash = proof.result.result_hash.clone();
        let status_code = proof.response.status_code;
        pages.push(CrawlPage {
            url: proof.request.url.clone(),
            depth,
            result_hash,
            status_code,
            proof,
        });

        if depth >= options.max_depth || pages.len() >= options.max_pages {
            continue;
        }

        // Discover same-origin outlinks from formats.links or raw HTML next-page heuristics.
        let discovered = discover_links_from_page(pages.last().unwrap());
        for next in discovered {
            if !is_allowed(&next, &seed_origin, allow_host.as_deref()) {
                skipped.push(CrawlSkipped {
                    url: next.to_string(),
                    reason: "outside_allow_domain".into(),
                });
                continue;
            }
            let nkey = normalize_visit_key(&next);
            if visited.contains(&nkey) {
                continue;
            }
            frontier.push_back((next, depth + 1));
        }
    }

    Ok(CrawlResult {
        mode: "crawl_mvp".into(),
        seed: seed_origin.to_string(),
        pages,
        skipped,
        residual: CRAWL_MVP_DESCRIPTION.into(),
        max_pages: options.max_pages,
        max_depth: options.max_depth,
    })
}

fn normalize_visit_key(url: &Url) -> String {
    let mut u = url.clone();
    u.set_fragment(None);
    u.to_string()
}

fn is_allowed(url: &Url, seed: &Url, allow_host: Option<&str>) -> bool {
    if let Some(host) = allow_host {
        return url
            .host_str()
            .map(|h| h.eq_ignore_ascii_case(host))
            .unwrap_or(false);
    }
    fetch::same_origin(url, seed)
}

fn discover_links_from_page(page: &CrawlPage) -> Vec<Url> {
    let mut out = Vec::new();
    let formats = &page.proof.result.formats_produced;
    if let Some(links_val) = formats.get("links") {
        if let Some(arr) = links_val.get("links").and_then(Value::as_array) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if let Ok(u) = Url::parse(s) {
                        out.push(u);
                    }
                }
            }
        }
    }
    // Fallback: scan markdown/html sources for rel=next style links when links format absent.
    if out.is_empty() {
        if let Some(html) = formats
            .get("html")
            .and_then(Value::as_str)
            .or_else(|| formats.get("rawHtml").and_then(Value::as_str))
        {
            if let Ok(base) = Url::parse(&page.url) {
                if let Some(next) = pagination::find_next(html, &base) {
                    out.push(next);
                }
                let extracted = links::extract(html, &base);
                for s in extracted.links {
                    if let Ok(u) = Url::parse(&s) {
                        out.push(u);
                    }
                }
            }
        }
    }
    out
}

/// Summary JSON shape used by the CLI when `--summary-only` is wanted (kept N/A; full result).
pub fn help_text() -> String {
    CRAWL_MVP_DESCRIPTION.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_max_pages_fails_closed() {
        assert!(validate_bounds(0, 1).is_err());
    }

    #[test]
    fn residual_describes_mvp_not_saas() {
        let t = CRAWL_MVP_DESCRIPTION.to_ascii_lowercase();
        assert!(t.contains("mvp") || t.contains("bounded"));
        assert!(!t.contains("hosted search index"));
        assert!(!t.contains("schedule monitor"));
    }
}
