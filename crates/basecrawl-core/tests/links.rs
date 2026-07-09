//! End-to-end `links`-format assertions (VAL-CRAWL-042, VAL-CRAWL-048) exercised through the
//! shipped CLI against the real catalogue targets named in the validation contract.
//!
//! The extraction rules (base-href resolution, canonical/hreflang capture, de-duplication, and the
//! per-policy handling of non-navigational schemes) are unit-tested in `src/links.rs`; these tests
//! confirm the same behavior end-to-end on a live, link-rich catalogue page and cross-check the
//! link count against an independent `curl` ground truth.

use serde_json::Value;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const BOOKS_HOME: &str = "https://books.toscrape.com/";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn scrape_json(args: &[&str]) -> Value {
    let out = run(args);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not a single strict-JSON object: {e}\n{stdout}"))
}

fn link_list(v: &Value) -> Vec<String> {
    v["result"]["formats_produced"]["links"]["links"]
        .as_array()
        .expect("links.links is an array")
        .iter()
        .map(|l| l.as_str().expect("each link is a string").to_string())
        .collect()
}

/// Total `<a href=...>` occurrences in the raw served HTML, as an independent ground truth for the
/// plausible-band comparison (VAL-CRAWL-048).
fn curl_anchor_href_count(url: &str) -> usize {
    let out = Command::new("curl")
        .args(["-s", "-m", "20", url])
        .output()
        .expect("curl available");
    let body = String::from_utf8_lossy(&out.stdout);
    body.match_indices("<a ")
        .filter(|(i, _)| {
            body[*i..]
                .split('>')
                .next()
                .is_some_and(|tag| tag.contains("href="))
        })
        .count()
}

// VAL-CRAWL-042: links extracts anchors as absolute product/category URLs resolved against base.
#[test]
fn books_home_links_are_absolute_product_and_category_urls() {
    let v = scrape_json(&[BOOKS_HOME, "--formats", "links"]);
    let links = link_list(&v);
    assert!(
        !links.is_empty(),
        "link-rich catalogue page yielded no links"
    );
    assert!(
        links.iter().all(|l| l.starts_with("https://")),
        "every extracted link must be an absolute https URL: {links:?}"
    );
    assert!(
        links
            .iter()
            .any(|l| l.contains("catalogue/category/books/")),
        "expected category URLs resolved against base:\n{links:?}"
    );
    assert!(
        links.iter().any(|l| l.contains("catalogue/")
            && l.ends_with("index.html")
            && !l.contains("category")),
        "expected product URLs resolved against base:\n{links:?}"
    );
    // No relative fragments should survive into the links list.
    assert!(
        !links
            .iter()
            .any(|l| l.starts_with("catalogue") || l.starts_with("/")),
        "found an unresolved relative link:\n{links:?}"
    );
}

// VAL-CRAWL-048: link count for a known catalogue page is plausible and comparable to grepping
// href= from curl output.
#[test]
fn books_home_link_count_is_plausible() {
    let v = scrape_json(&[BOOKS_HOME, "--formats", "links"]);
    let count = link_list(&v).len();

    // Absolute plausibility band: the home page has ~20 book tiles + ~50 category nav links, so a
    // de-duplicated count in the tens is expected. Zero or an order-of-magnitude miss fails.
    assert!(
        (30..=200).contains(&count),
        "link count {count} outside the plausible band (30..=200)"
    );

    // Comparable to an independent curl grep of anchor href= occurrences. De-duplication means our
    // count is <= the raw occurrence count but within the same order of magnitude.
    let raw = curl_anchor_href_count(BOOKS_HOME);
    assert!(raw > 0, "curl ground truth found no anchors");
    assert!(
        count <= raw && count * 4 >= raw,
        "de-duplicated link count {count} is not comparable to curl anchor count {raw}"
    );
}
