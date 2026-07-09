//! Headless-Chromium page rendering: the post-render DOM that feeds the `html` and `markdown`
//! formats.
//!
//! Unlike `rawHtml` (the unmodified served source, produced straight from the HTTP fetch), the
//! rendered DOM is obtained by driving headless Chromium: the page is fetched, its scripts run, the
//! smart network-idle wait (or an explicit `wait_for` selector) lets JS-injected content settle,
//! and the resulting DOM is serialized. This is what makes `html`/`markdown` reflect JS-injected
//! content on a JS-rendered page while `rawHtml` continues to reflect the source. A single render is
//! shared by both `html` and `markdown`, so producing both never launches more than one browser.

use std::time::Duration;

use basecrawl_render::{render, Action, RenderConfig, RenderError};
use url::Url;

use crate::error::Error;
use crate::fetch::MAX_REDIRECTS;

/// Render `url` with headless Chromium and return its cleaned, post-render DOM serialization.
///
/// `wait_for`, when supplied, blocks capture until an element matching that CSS selector exists;
/// otherwise the render smart-waits for network idle while following (and bounding) any client-side
/// redirect (meta-refresh / `window.location`). The render also collects infinite-scroll content,
/// dismisses cookie/consent overlays, executes the supplied `actions` in order, and inlines
/// iframe/shadow-DOM content before serializing. Client-side redirects share the HTTP redirect hop
/// cap ([`MAX_REDIRECTS`]) and a loop is surfaced as [`Error::TooManyRedirects`]. The render is
/// bounded by `timeout`; any other failure is surfaced as a structured [`Error`] so the scrape
/// fails loudly rather than emitting misleading output.
pub fn render_page(
    url: &Url,
    user_agent: &str,
    timeout: Duration,
    wait_for: Option<&str>,
    actions: &[Action],
) -> Result<String, Error> {
    let config = RenderConfig {
        timeout,
        user_agent: user_agent.to_string(),
        wait_for: wait_for.map(str::to_string),
        actions: actions.to_vec(),
        max_redirects: MAX_REDIRECTS,
        ..RenderConfig::default()
    };
    match render(url, &config) {
        Ok(rendered) => Ok(rendered.html),
        Err(RenderError::TooManyRedirects { max }) => Err(Error::TooManyRedirects {
            max,
            url: url.to_string(),
        }),
        Err(e) => Err(Error::Render(e.to_string())),
    }
}
