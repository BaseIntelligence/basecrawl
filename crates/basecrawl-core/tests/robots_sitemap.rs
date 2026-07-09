//! End-to-end robots.txt and sitemap discovery assertions (VAL-CRAWL-123/124).
//!
//! A local origin gives every test deterministic ownership of the robots policy and sitemap
//! documents. The CLI is exercised directly so the tests cover both the configured enforcement
//! policy and the observable ScrapeProof surfaces.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

struct FixtureServer {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn successful_scrape(args: &[&str]) -> Value {
    let output = run(args);
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .expect("crawler stdout must contain exactly one ScrapeProof JSON object")
}

fn write_response(mut stream: TcpStream, status: &str, content_type: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
Connection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write fixture response");
    stream.flush().expect("flush fixture response");
}

fn handle_connection(stream: TcpStream, base: &str, requests: &Arc<Mutex<Vec<String>>>) {
    let peer = stream.try_clone().expect("clone stream");
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let mut line = String::new();
    while reader
        .read_line(&mut line)
        .map(|count| count > 0)
        .unwrap_or(false)
    {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    requests
        .lock()
        .expect("fixture request log mutex")
        .push(target.clone());
    let path = target.split('?').next().unwrap_or("/");

    match path {
        "/robots.txt" => write_response(
            peer,
            "200 OK",
            "text/plain; charset=utf-8",
            &format!(
                "User-agent: *\nDisallow: /blocked\nAllow: /blocked/open\nSitemap: {base}/robots-sitemap.xml\n"
            ),
        ),
        "/robots-sitemap.xml" => write_response(
            peer,
            "200 OK",
            "application/xml",
            &format!(
                "<?xml version=\"1.0\"?><sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><sitemap><loc>{base}/nested-sitemap.xml</loc></sitemap></sitemapindex>"
            ),
        ),
        "/nested-sitemap.xml" => write_response(
            peer,
            "200 OK",
            "application/xml",
            &format!(
                "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>{base}/from-robots-a</loc></url><url><loc>{base}/from-robots-b</loc></url></urlset>"
            ),
        ),
        "/sitemap.xml" => write_response(
            peer,
            "200 OK",
            "application/xml",
            &format!(
                "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>{base}/fallback-a</loc></url><url><loc>{base}/fallback-b</loc></url></urlset>"
            ),
        ),
        "/blocked/open" | "/allowed" | "/sitemap-page" | "/blocked/private" => write_response(
            peer,
            "200 OK",
            "text/html; charset=utf-8",
            &format!("<!doctype html><html><body><main>fixture {path}</main></body></html>"),
        ),
        _ => write_response(peer, "404 Not Found", "text/plain; charset=utf-8", "not found"),
    }
}

fn fixture_server() -> &'static FixtureServer {
    static SERVER: OnceLock<FixtureServer> = OnceLock::new();
    SERVER.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
        let base = format!("http://{}", listener.local_addr().expect("local address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_base = base.clone();
        let server_requests = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let base = server_base.clone();
                let requests = Arc::clone(&server_requests);
                thread::spawn(move || handle_connection(stream, &base, &requests));
            }
        });
        FixtureServer { base, requests }
    })
}

// VAL-CRAWL-123: an allowed robots rule is recorded and the requested page proceeds normally.
#[test]
fn allowed_path_records_an_honored_robots_disposition() {
    let server = fixture_server();
    let url = format!("{}/blocked/open", server.base);
    let proof = successful_scrape(&[&url, "--formats", "metadata", "--no-js"]);
    let robots = &proof["result"]["formats_produced"]["metadata"]["robotsPolicy"];

    assert_eq!(proof["response"]["status_code"], 200);
    assert_eq!(robots["policy"], "enforce");
    assert_eq!(robots["disposition"], "allowed");
    assert_eq!(robots["fetched"], true);
    assert_eq!(robots["matched_rule"]["directive"], "allow");
    assert_eq!(robots["matched_rule"]["path"], "/blocked/open");
    assert!(
        server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/robots.txt"),
        "the crawler must consult /robots.txt before crawling the page"
    );
}

// VAL-CRAWL-123: the default enforcement policy blocks a covered denied path before its page fetch.
#[test]
fn denied_path_is_blocked_with_an_observable_policy_error() {
    let server = fixture_server();
    let url = format!("{}/blocked/private?robots-denied=1", server.base);
    let output = run(&[&url, "--formats", "metadata", "--no-js"]);

    assert!(
        !output.status.success(),
        "a robots-denied path must not succeed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stdout.is_empty(),
        "no partial ScrapeProof is emitted"
    );
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("stderr must expose structured policy JSON");
    assert_eq!(error["error"]["kind"], "robots_denied");
    assert_eq!(error["error"]["robots"]["policy"], "enforce");
    assert_eq!(error["error"]["robots"]["disposition"], "denied");
    assert_eq!(error["error"]["robots"]["matched_rule"]["path"], "/blocked");
    assert!(
        !server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/blocked/private?robots-denied=1"),
        "the denied resource itself must never be fetched"
    );
}

// VAL-CRAWL-123: observe mode retains a correct denied disposition but deliberately permits fetch.
#[test]
fn observe_policy_surfaces_denial_while_permitting_the_page() {
    let server = fixture_server();
    let url = format!("{}/blocked/private?robots-observe=1", server.base);
    let proof = successful_scrape(&[
        &url,
        "--formats",
        "metadata",
        "--robots",
        "observe",
        "--no-js",
    ]);
    let robots = &proof["result"]["formats_produced"]["metadata"]["robotsPolicy"];

    assert_eq!(proof["response"]["status_code"], 200);
    assert_eq!(robots["policy"], "observe");
    assert_eq!(robots["disposition"], "denied");
    assert_eq!(robots["matched_rule"]["directive"], "disallow");
    assert_eq!(robots["matched_rule"]["path"], "/blocked");
}

// VAL-CRAWL-124: default /sitemap.xml and robots-referenced sitemap indexes become URL seed sets.
#[test]
fn discovers_default_and_robots_referenced_sitemaps_on_the_links_surface() {
    let server = fixture_server();
    let url = format!("{}/sitemap-page", server.base);
    let proof = successful_scrape(&[&url, "--formats", "links", "--no-js"]);
    let sitemap = proof["result"]["formats_produced"]["links"]["sitemap"]
        .as_array()
        .expect("links.sitemap must be a URL array")
        .iter()
        .map(|value| value.as_str().expect("sitemap URL is a string"))
        .collect::<Vec<_>>();

    for expected in [
        format!("{}/fallback-a", server.base),
        format!("{}/fallback-b", server.base),
        format!("{}/from-robots-a", server.base),
        format!("{}/from-robots-b", server.base),
    ] {
        assert!(
            sitemap.contains(&expected.as_str()),
            "sitemap URL '{expected}' was not surfaced: {sitemap:?}"
        );
    }
    assert!(
        server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/nested-sitemap.xml"),
        "the robots-referenced sitemap index must be followed and parsed"
    );
}
