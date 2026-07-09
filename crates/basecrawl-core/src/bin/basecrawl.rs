//! `basecrawl` CLI: scrape a URL and emit exactly one canonical ScrapeProof JSON object.
//!
//! On success the ScrapeProof is written to stdout (nothing else). On failure a structured
//! `{"error": {...}}` object is written to stderr and the process exits non-zero, so a failed
//! run never emits a partial ScrapeProof on stdout.

use basecrawl_core::error::Error;
use basecrawl_core::{format, scrape, ScrapeOptions};
use clap::Parser;

/// basecrawl: verifiable web crawler that emits a canonical ScrapeProof.
#[derive(Parser, Debug)]
#[command(name = "basecrawl", version, about, long_about = None)]
struct Cli {
    /// URL to scrape (http/https only).
    #[arg(value_name = "URL")]
    url: Option<String>,

    /// Comma-separated output formats: markdown, html, rawHtml, links, metadata, screenshot, json
    /// [default: markdown,metadata].
    #[arg(long, value_delimiter = ',', value_name = "FORMATS")]
    formats: Option<Vec<String>>,

    /// Validator-issued task identifier, echoed verbatim into the ScrapeProof.
    #[arg(long, value_name = "TASK_ID")]
    task_id: Option<String>,

    /// Validator-issued anti-replay nonce, echoed verbatim into the ScrapeProof.
    #[arg(long, value_name = "NONCE")]
    nonce: Option<String>,

    /// Output format for the emitted proof (only "json" is supported).
    #[arg(long, default_value = "json", value_name = "OUTPUT")]
    output: String,
}

fn run(cli: Cli) -> Result<String, Error> {
    if cli.output != "json" {
        return Err(Error::UnsupportedOutput(cli.output));
    }

    let raw_url = cli.url.ok_or(Error::MissingUrl)?;

    // Validate formats before any fetch so an unknown format never triggers a network request.
    let formats = match &cli.formats {
        Some(tokens) if !tokens.is_empty() => format::parse_list(tokens)?,
        _ => format::default_set(),
    };

    let options = ScrapeOptions {
        formats,
        task_id: cli.task_id,
        nonce: cli.nonce,
    };

    let proof = scrape(&raw_url, &options)?;
    Ok(proof.to_canonical_json())
}

fn main() {
    let cli = Cli::parse();
    match run(cli) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("{}", err.to_json_string());
            std::process::exit(err.exit_code());
        }
    }
}
