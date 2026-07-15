use std::env;

use headless_chrome::Browser;

use anyhow::Result;

// Manual focused harness: requires a pre-running Chrome debug WS URL as argv[1].
// Not for hermetic CI (`cargo test --workspace`); basecrawl hard-path suites cover
// Browser::connect-equivalent behavior with controlled LaunchOptions.
#[test]
#[ignore = "manual: requires debug_ws_url argv; not part of hermetic CI"]
fn connect_to_url() -> Result<()> {
    let debug_ws_url = env::args().nth(1).expect("Must provide debug_ws_url");

    let browser = Browser::connect(debug_ws_url);

    assert!(browser.is_ok());

    Ok(())
}
