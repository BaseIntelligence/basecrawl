//! Packaging regression: load-bearing fork surfaces required by basecrawl-render.
//! These APIs are missing from stock crates.io headless_chrome 1.0.22.

use std::sync::Arc;
use std::time::{Duration, Instant};

use headless_chrome::browser::tab::RequestPausedDecision;
use headless_chrome::{Browser, LaunchOptions};

#[test]
fn request_paused_decision_deferred_variant_exists() {
    // Deferred must be constructible so basecrawl-render can meter response bodies
    // without blocking the CDP target event loop.
    let decision = RequestPausedDecision::Deferred(Arc::new(|_transport, _session, _event| {}));
    match decision {
        RequestPausedDecision::Deferred(handler) => {
            // Arc must be cloneable for multi-worker handoff.
            let _ = Arc::clone(&handler);
        }
        RequestPausedDecision::Fulfill(_)
        | RequestPausedDecision::Fail(_)
        | RequestPausedDecision::Continue(_) => {
            panic!("expected Deferred variant for basecrawl fork surface")
        }
    }
}

#[test]
fn browser_new_with_deadline_symbol_compiles() {
    // Do not launch Chromium here (root + sandbox noise in vendor standalone tests).
    // Symbol presence is the packaging contract; hard-path suites exercise real launch.
    let deadline = Instant::now() + Duration::from_millis(1);
    let options = LaunchOptions::default_builder()
        .headless(true)
        .build()
        .expect("default launch options");
    // Calling with an already-passed deadline may fail open/closed at OS level; either
    // path must not be a link error (symbol present).
    let _ = Browser::new_with_deadline(options, deadline);
}

#[test]
fn process_embeds_headless_new_flag_source() {
    // Keep launch flag residual honest for stealth: sources must prefer --headless=new.
    let process_src = include_str!("../src/browser/process.rs");
    assert!(
        process_src.contains("--headless=new"),
        "fork must launch with --headless=new"
    );
    assert!(
        !process_src.contains("args.extend([\"--headless\"])"),
        "must not fall back to legacy --headless without =new"
    );
}

#[test]
fn package_ships_upstream_mit_license() {
    let license = include_str!("../LICENSE.md");
    assert!(
        license.contains("Permission is hereby granted, free of charge"),
        "upstream MIT grant text must remain in LICENSE.md"
    );
    assert!(
        license.to_lowercase().contains("mit") || license.contains("THE SOFTWARE IS PROVIDED"),
        "MIT license notice required for crates.io redistrib"
    );
}
