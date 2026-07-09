//! End-to-end markdown-format assertions (VAL-CRAWL-027..035) exercised through the shipped CLI
//! against the real open-web targets named in the validation contract.
//!
//! The converter's structural rules (GFM tables, fenced code, nested-list depth, heading levels,
//! absolute links/images, boilerplate stripping, empty-but-valid output) are unit-tested in
//! `src/markdown.rs`; these tests confirm the same behavior end-to-end on live pages.

mod common;

use serde_json::Value;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const QUOTES: &str = "https://quotes.toscrape.com/";
const BOOK: &str = "https://books.toscrape.com/catalogue/a-light-in-the-attic_1000/index.html";

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

fn markdown_of(v: &Value) -> &str {
    v["result"]["formats_produced"]["markdown"]
        .as_str()
        .expect("markdown format present as a string")
}

// VAL-CRAWL-027
#[test]
fn quote_page_markdown_is_nonempty_with_visible_quote_text() {
    let v = scrape_json(&[QUOTES, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(!md.trim().is_empty(), "markdown was empty for a rich page");
    assert!(
        md.contains("The world as we have created it is a process of our thinking"),
        "visible quote text missing from markdown:\n{md}"
    );
}

// VAL-CRAWL-032 (inline links absolute, on a real page)
#[test]
fn quote_page_links_are_absolute() {
    let v = scrape_json(&[QUOTES, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains("](https://quotes.toscrape.com/"),
        "expected absolute link targets resolved against the page base:\n{md}"
    );
    // No markdown link should point at a bare relative path like `](/tag/...)`.
    assert!(
        !md.contains("](/"),
        "found an unresolved relative markdown link:\n{md}"
    );
}

// VAL-CRAWL-033
#[test]
fn product_page_markdown_centers_on_main_content() {
    let v = scrape_json(&[BOOK, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains("A Light in the Attic"),
        "product title missing:\n{md}"
    );
    assert!(
        md.contains("It's hard to imagine a world without"),
        "product description missing:\n{md}"
    );
    // The repeated site header/chrome must be stripped (it lives outside <article>).
    assert!(
        !md.contains("Books to Scrape"),
        "site chrome (header) leaked into main-content markdown:\n{md}"
    );
}

// VAL-CRAWL-028 (GFM table on a real page)
#[test]
fn product_page_renders_gfm_table() {
    let v = scrape_json(&[BOOK, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains("| --- |"),
        "expected a GFM header-separator row:\n{md}"
    );
    assert!(
        md.contains("| UPC |"),
        "expected the product-information table rows as pipe-delimited cells:\n{md}"
    );
}

// VAL-CRAWL-031 (heading hierarchy on a real page)
#[test]
fn product_page_preserves_heading_hierarchy() {
    let v = scrape_json(&[BOOK, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains("# A Light in the Attic"),
        "h1 title not mapped to a level-1 heading:\n{md}"
    );
    assert!(
        md.contains("## Product Description"),
        "h2 not mapped to a level-2 heading:\n{md}"
    );
}

// VAL-CRAWL-035
#[test]
fn product_page_image_is_markdown_with_absolute_src() {
    let v = scrape_json(&[BOOK, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains("![A Light in the Attic](https://books.toscrape.com/media/"),
        "image not rendered as markdown with a resolved absolute src:\n{md}"
    );
}

// VAL-CRAWL-034
#[test]
fn empty_204_page_yields_empty_but_valid_markdown() {
    let base = common::httpbin_base();
    let url = format!("{base}/status/204");
    let v = scrape_json(&[&url, "--formats", "markdown"]);
    assert_eq!(
        v["response"]["status_code"], 204,
        "expected a 204 status to be captured faithfully"
    );
    let md = markdown_of(&v);
    assert_eq!(
        md, "",
        "a 204/empty body must yield empty-but-valid markdown"
    );
    assert_eq!(
        v["version"],
        serde_json::json!(1),
        "proof still well-formed"
    );
}
