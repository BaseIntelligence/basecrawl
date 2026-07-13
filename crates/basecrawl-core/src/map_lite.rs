//! Map-lite URL inventory (VAL-CRAWLPROD-014..018).
//!
//! Harvests same-origin links from a seed page and optionally incorporates sitemap URL seeds.
//! This is an inventory helper — **not** a guaranteed complete site graph or full search index.

use crate::error::Error;
use crate::fetch::{self, FetchConfig};
use crate::links;
use crate::robots::{self, RobotsPolicy};
use crate::{scrape, Format, ScrapeOptions};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use url::Url;

/// Help / residual honesty (VAL-CRAWLPROD-018).
pub const MAP_LITE_DESCRIPTION: &str = "Map-lite inventory helper: same-origin link harvest and \
optional sitemap-first discovery. Not a guaranteed complete site graph or full search index.";

/// Options for a map-lite run.
#[derive(Debug, Clone)]
pub struct MapOptions {
    /// Inclusive cap on returned inventory URLs.
    pub max_urls: usize,
    /// When true, consult robots-declared / default sitemaps (best-effort).
    pub use_sitemap: bool,
    /// When true (default), only same-origin URLs enter the inventory.
    pub same_origin_only: bool,
    /// Whole-request timeout for seed + sitemap discovery.
    pub timeout_secs: u64,
    /// Optional extra scrape options (headers, proxy, robots policy).
    pub scrape: ScrapeOptions,
}

impl Default for MapOptions {
    fn default() -> Self {
        Self {
            max_urls: 100,
            use_sitemap: true,
            same_origin_only: true,
            timeout_secs: 30,
            scrape: ScrapeOptions {
                formats: vec![Format::Links, Format::RawHtml],
                render_enabled: false,
                follow_pagination: false,
                ..ScrapeOptions::default()
            },
        }
    }
}

/// Map-lite inventory result.
#[derive(Debug, Clone, Serialize)]
pub struct MapResult {
    pub mode: String,
    pub seed: String,
    pub urls: Vec<String>,
    pub from_seed_links: usize,
    pub from_sitemap: usize,
    pub residual: String,
    pub max_urls: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sitemap_discovery: Option<String>,
}

impl MapResult {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).expect("MapResult is always serializable")
    }

    pub fn to_canonical_json(&self) -> String {
        self.to_json().to_string()
    }
}

pub fn validate_max_urls(max_urls: usize) -> Result<(), Error> {
    if max_urls == 0 {
        return Err(Error::InvalidProductOption(
            "map --max-urls must be >= 1".into(),
        ));
    }
    if max_urls > 50_000 {
        return Err(Error::InvalidProductOption(
            "map --max-urls exceeds hard safety cap (50000)".into(),
        ));
    }
    Ok(())
}

/// Inventories same-origin (or documented) URLs from the seed without a full recursive crawl.
pub fn map_lite(seed: &str, options: &MapOptions) -> Result<MapResult, Error> {
    validate_max_urls(options.max_urls)?;
    let seed_url = crate::url_validation::validate_url(seed)?;
    let deadline = Instant::now() + Duration::from_secs(options.timeout_secs);

    // Scrape the seed for link inventory (soft, no render required).
    let mut scrape_opts = options.scrape.clone();
    scrape_opts.timeout_secs = options.timeout_secs;
    scrape_opts.method = "GET".into();
    scrape_opts.body = Vec::new();
    if scrape_opts.formats.is_empty() {
        scrape_opts.formats = vec![Format::Links, Format::RawHtml];
    } else if !scrape_opts.formats.contains(&Format::Links)
        && !scrape_opts.formats.contains(&Format::RawHtml)
    {
        scrape_opts.formats.push(Format::Links);
    }
    scrape_opts.render_enabled = false;
    scrape_opts.follow_pagination = false;

    let proof = scrape(seed_url.as_str(), &scrape_opts)?;
    let page_base = Url::parse(
        proof
            .response
            .final_url
            .as_deref()
            .unwrap_or(seed_url.as_str()),
    )
    .unwrap_or_else(|_| seed_url.clone());

    let mut ordered: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Always include the seed itself first.
    push_url(&mut ordered, &mut seen, seed_url.as_str(), options.max_urls);

    let mut from_seed_links = 0usize;
    if let Some(links_val) = proof.result.formats_produced.get("links") {
        if let Some(arr) = links_val.get("links").and_then(Value::as_array) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if admit(s, &seed_url, options.same_origin_only)
                        && push_url(&mut ordered, &mut seen, s, options.max_urls)
                    {
                        from_seed_links += 1;
                    }
                }
            }
        }
    } else if let Some(html) = proof
        .result
        .formats_produced
        .get("rawHtml")
        .and_then(Value::as_str)
        .or_else(|| {
            proof
                .result
                .formats_produced
                .get("html")
                .and_then(Value::as_str)
        })
    {
        let extracted = links::extract(html, &page_base);
        for s in extracted.links {
            if admit(&s, &seed_url, options.same_origin_only)
                && push_url(&mut ordered, &mut seen, &s, options.max_urls)
            {
                from_seed_links += 1;
            }
        }
    }

    let mut from_sitemap = 0usize;
    let mut sitemap_note: Option<String> = None;
    if options.use_sitemap && ordered.len() < options.max_urls && Instant::now() < deadline {
        // Reuse robots/sitemap discovery (best-effort).
        let config = FetchConfig {
            timeout: Duration::from_secs(options.timeout_secs),
            crawl_delay: Duration::from_millis(scrape_opts.crawl_delay_ms),
            user_agent: fetch::DEFAULT_USER_AGENT.to_string(),
            credential_origin: Some(seed_url.clone()),
            headers: scrape_opts.headers.clone(),
            max_body_bytes: scrape_opts.max_body_bytes,
            ..FetchConfig::default()
        };
        let _ = RobotsPolicy::Ignore; // robots policy applies inside scrape; sitemap is best-effort.
        match robots::discover_sitemap_urls(&seed_url, &config, &[], deadline) {
            Ok(sitemap_urls) => {
                if sitemap_urls.is_empty() {
                    sitemap_note = Some("sitemap discovery ran; no same-origin seeds found".into());
                } else {
                    sitemap_note = Some(format!(
                        "sitemap discovery ran; {} candidate URL(s)",
                        sitemap_urls.len()
                    ));
                }
                for s in sitemap_urls {
                    if admit(&s, &seed_url, options.same_origin_only)
                        && push_url(&mut ordered, &mut seen, &s, options.max_urls)
                    {
                        from_sitemap += 1;
                    }
                }
            }
            Err(_) => {
                // Best-effort: map-lite never fails solely because a sitemap was unavailable.
                sitemap_note = Some("sitemap discovery unavailable; seed links only".into());
            }
        }
    }

    // Cap enforcement (already applied by push_url).
    ordered.truncate(options.max_urls);

    Ok(MapResult {
        mode: "map_lite".into(),
        seed: seed_url.to_string(),
        urls: ordered,
        from_seed_links,
        from_sitemap,
        residual: MAP_LITE_DESCRIPTION.into(),
        max_urls: options.max_urls,
        sitemap_discovery: sitemap_note,
    })
}

fn push_url(out: &mut Vec<String>, seen: &mut HashSet<String>, raw: &str, max: usize) -> bool {
    if out.len() >= max {
        return false;
    }
    if seen.insert(raw.to_string()) {
        out.push(raw.to_string());
        true
    } else {
        false
    }
}

fn admit(raw: &str, seed: &Url, same_origin_only: bool) -> bool {
    let Ok(u) = Url::parse(raw) else {
        return false;
    };
    if u.scheme() != "http" && u.scheme() != "https" {
        return false;
    }
    if same_origin_only {
        return fetch::same_origin(&u, seed);
    }
    true
}

pub fn help_text() -> String {
    MAP_LITE_DESCRIPTION.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_max_urls_fails_closed() {
        assert!(validate_max_urls(0).is_err());
    }

    #[test]
    fn residual_not_full_site_claim() {
        let t = MAP_LITE_DESCRIPTION.to_ascii_lowercase();
        assert!(t.contains("inventory") || t.contains("helper"));
        // Wording must *deny* completeness, not omit the phrases entirely.
        assert!(
            t.contains("not a guaranteed complete") || t.contains("not") && t.contains("complete")
        );
        assert!(!t.contains("absolute site completeness"));
    }
}
