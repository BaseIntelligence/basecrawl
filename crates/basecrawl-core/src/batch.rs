//! Multi-URL batch surface (VAL-CRAWLPROD-019..023).
//!
//! Processes a list of URLs with per-URL isolation of failures, optional concurrency pacing, and
//! the same format options as a single scrape. One bad URL never fabricates success or collapses
//! sibling success results.

use crate::error::Error;
use crate::{scrape, ScrapeOptions, ScrapeProof};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Default in-flight concurrency when batch concurrency is left at the product default.
pub const DEFAULT_BATCH_CONCURRENCY: usize = 2;

/// Options that pad a multi-URL batch.
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Shared scrape options applied independently to every URL.
    pub scrape: ScrapeOptions,
    /// Maximum concurrent scrapes. Fail-closed if zero.
    pub concurrency: usize,
    /// Optional inter-start delay for modest pacing (ms).
    pub pace_ms: u64,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            scrape: ScrapeOptions {
                render_enabled: false,
                ..ScrapeOptions::default()
            },
            concurrency: DEFAULT_BATCH_CONCURRENCY,
            pace_ms: 0,
        }
    }
}

/// One batch item: either a successful ScrapeProof or a structured error.
#[derive(Debug, Clone, Serialize)]
pub struct BatchItem {
    pub index: usize,
    pub url: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<ScrapeProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_hash: Option<String>,
}

/// Full batch result list (length == input URL count, stable order).
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    pub mode: String,
    pub items: Vec<BatchItem>,
    pub concurrency: usize,
}

impl BatchResult {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).expect("BatchResult is always serializable")
    }

    pub fn to_canonical_json(&self) -> String {
        self.to_json().to_string()
    }

    /// True if every item succeeded.
    pub fn all_ok(&self) -> bool {
        self.items.iter().all(|i| i.ok)
    }
}

pub fn validate_batch(urls: &[String], concurrency: usize) -> Result<(), Error> {
    if urls.is_empty() {
        return Err(Error::InvalidProductOption(
            "batch requires at least one URL".into(),
        ));
    }
    if concurrency == 0 {
        return Err(Error::InvalidProductOption(
            "batch --concurrency must be >= 1".into(),
        ));
    }
    if concurrency > 64 {
        return Err(Error::InvalidProductOption(
            "batch --concurrency exceeds hard safety cap (64)".into(),
        ));
    }
    if urls.len() > 1_000 {
        return Err(Error::InvalidProductOption(
            "batch URL count exceeds hard safety cap (1000)".into(),
        ));
    }
    Ok(())
}

/// Run scrapes for each URL with per-item error isolation.
pub fn batch(urls: &[String], options: &BatchOptions) -> Result<BatchResult, Error> {
    validate_batch(urls, options.concurrency)?;
    let concurrency = options.concurrency.min(urls.len()).max(1);
    let scrape_opts = Arc::new(options.scrape.clone());
    let pace = options.pace_ms;

    // Fill results by index so order matches input even when work is concurrent.
    let results: Arc<Mutex<Vec<Option<BatchItem>>>> =
        Arc::new(Mutex::new((0..urls.len()).map(|_| None).collect()));

    // Simple worker pool without external deps.
    let work: Arc<Mutex<VecDequeWork>> = Arc::new(Mutex::new(VecDequeWork {
        next: 0,
        urls: urls.to_vec(),
    }));

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let work = Arc::clone(&work);
        let results = Arc::clone(&results);
        let scrape_opts = Arc::clone(&scrape_opts);
        let pace_ms = pace;
        handles.push(thread::spawn(move || loop {
            let job = {
                let mut guard = work.lock().expect("batch work mutex");
                if guard.next >= guard.urls.len() {
                    None
                } else {
                    let idx = guard.next;
                    guard.next += 1;
                    Some((idx, guard.urls[idx].clone()))
                }
            };
            let Some((idx, url)) = job else {
                break;
            };
            if pace_ms > 0 {
                thread::sleep(Duration::from_millis(pace_ms));
            }
            let item = match scrape(&url, &scrape_opts) {
                Ok(proof) => BatchItem {
                    result_hash: proof.result.result_hash.clone(),
                    index: idx,
                    url: url.clone(),
                    ok: true,
                    proof: Some(proof),
                    error: None,
                },
                Err(err) => BatchItem {
                    index: idx,
                    url: url.clone(),
                    ok: false,
                    proof: None,
                    error: Some(err.to_json()),
                    result_hash: None,
                },
            };
            let mut guard = results.lock().expect("batch results mutex");
            guard[idx] = Some(item);
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }

    let items = results
        .lock()
        .expect("batch results mutex")
        .iter()
        .enumerate()
        .map(|(idx, slot)| {
            slot.clone().unwrap_or(BatchItem {
                index: idx,
                url: urls[idx].clone(),
                ok: false,
                proof: None,
                error: Some(json!({
                    "error": {
                        "kind": "batch_worker_failed",
                        "message": "batch worker did not produce a per-item result",
                    }
                })),
                result_hash: None,
            })
        })
        .collect();

    Ok(BatchResult {
        mode: "batch".into(),
        items,
        concurrency,
    })
}

struct VecDequeWork {
    next: usize,
    urls: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_urls_fails_closed() {
        assert!(validate_batch(&[], 2).is_err());
    }

    #[test]
    fn zero_concurrency_fails_closed() {
        assert!(validate_batch(&[String::from("http://x")], 0).is_err());
    }
}
