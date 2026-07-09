//! `html` format production: the cleaned, post-render DOM serialization.
//!
//! Unlike `rawHtml` (the unmodified served source, produced straight from the HTTP fetch), `html`
//! is obtained by driving headless Chromium: the page is fetched, its scripts run, and the
//! resulting DOM is serialized. This is what makes `html` reflect JS-injected content on a
//! JS-rendered page while `rawHtml` continues to reflect the source. Rendering only happens when
//! `html` is actually requested, so a `rawHtml`-only scrape never launches a browser.

use std::time::Duration;

use basecrawl_render::{render, RenderConfig};
use url::Url;

use crate::error::Error;

/// Render `url` with headless Chromium and return its cleaned, post-render DOM serialization.
///
/// A render failure (no browser available, navigation/eval failure, empty DOM) is surfaced as a
/// structured [`Error`] so the scrape fails loudly rather than emitting a misleading `html` value.
pub fn render_html(url: &Url, user_agent: &str, timeout: Duration) -> Result<String, Error> {
    let config = RenderConfig {
        timeout,
        user_agent: user_agent.to_string(),
    };
    let rendered = render(url, &config).map_err(|e| Error::Render(e.to_string()))?;
    Ok(rendered.html)
}
