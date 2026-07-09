//! Headless-Chromium (CDP) rendering for `basecrawl`.
//!
//! This crate drives a headless Chromium instance over the Chrome DevTools Protocol to obtain the
//! **post-render** DOM of a page: the browser fetches the document, executes its scripts, and the
//! resulting DOM is serialized back to HTML. This is what lets the `html` format reflect
//! JS-injected content (that a plain HTTP fetch of the source never contains).
//!
//! Rendering is deliberately kept separate from the HTTP fetch path so that formats which only need
//! the served source (e.g. `rawHtml`) never pay for, or depend on, a browser launch.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use headless_chrome::{Browser, LaunchOptions};
use url::Url;

/// Default render timeout (seconds) when the caller does not specify one.
pub const DEFAULT_RENDER_TIMEOUT_SECS: u64 = 30;

/// Candidate Chromium executables searched (in order) when `CHROME` is unset.
const CHROME_CANDIDATES: &[&str] = &[
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
];

/// A failure while rendering a page with headless Chromium.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("chrome executable not found (set the CHROME env var to a Chromium binary)")]
    ChromeNotFound,
    #[error("failed to launch headless browser: {0}")]
    Launch(String),
    #[error("failed to render page: {0}")]
    Render(String),
    #[error("browser returned no serialized DOM")]
    NoContent,
}

/// Configuration for a single render.
#[derive(Debug, Clone)]
pub struct RenderConfig {
    /// Whole-render timeout (navigation + evaluation). A page that never settles aborts near this.
    pub timeout: Duration,
    /// User-Agent presented to the origin (kept in parity with the HTTP fetch path).
    pub user_agent: String,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_RENDER_TIMEOUT_SECS),
            user_agent: String::new(),
        }
    }
}

/// The product of a render: the serialized post-render DOM.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The cleaned, post-render DOM serialization (see [`render`] for the cleaning policy).
    pub html: String,
}

/// Resolve a Chromium executable: prefer `$CHROME`, then the well-known system locations.
fn resolve_chrome() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CHROME") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    CHROME_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// In-page cleaning + serialization script.
///
/// Executed *after* the page has loaded and its scripts have run, so any JS-injected content is
/// already in the DOM. It then removes `<script>`/`<style>`/`<noscript>` nodes (making `html` a
/// cleaned serialization that is deterministically script/style-free and clearly distinct from the
/// raw served source) and returns `document.documentElement.outerHTML`. It never rewrites element
/// URL attributes, so relative asset/link URLs are preserved exactly as authored (consistent,
/// no-rewrite policy).
const CLEAN_AND_SERIALIZE: &str = "(function(){\
var nodes=document.querySelectorAll('script,style,noscript');\
for(var i=0;i<nodes.length;i++){var n=nodes[i];if(n.parentNode){n.parentNode.removeChild(n);}}\
return document.documentElement.outerHTML;\
})()";

/// Render `url` with headless Chromium and return its cleaned, post-render DOM serialization.
///
/// The browser is launched with `--no-sandbox --disable-dev-shm-usage --disable-gpu` (headless),
/// navigated to `url`, and allowed to finish loading (so JS-injected content is present) before the
/// DOM is serialized. The spawned browser is terminated when this function returns (its `Browser`
/// handle is dropped), so no browser process is leaked.
pub fn render(url: &Url, config: &RenderConfig) -> Result<Rendered, RenderError> {
    let chrome = resolve_chrome().ok_or(RenderError::ChromeNotFound)?;

    let args: Vec<&OsStr> = vec![
        OsStr::new("--disable-dev-shm-usage"),
        OsStr::new("--disable-gpu"),
        OsStr::new("--hide-scrollbars"),
    ];
    let options = LaunchOptions::default_builder()
        .path(Some(chrome))
        .headless(true)
        .sandbox(false)
        .window_size(Some((1280, 800)))
        .args(args)
        .idle_browser_timeout(config.timeout)
        .build()
        .map_err(|e| RenderError::Launch(e.to_string()))?;

    let browser = Browser::new(options).map_err(|e| RenderError::Launch(e.to_string()))?;
    let tab = browser
        .new_tab()
        .map_err(|e| RenderError::Launch(e.to_string()))?;
    tab.set_default_timeout(config.timeout);
    if !config.user_agent.is_empty() {
        tab.set_user_agent(&config.user_agent, None, None)
            .map_err(|e| RenderError::Render(e.to_string()))?;
    }

    tab.navigate_to(url.as_str())
        .map_err(|e| RenderError::Render(e.to_string()))?;
    tab.wait_until_navigated()
        .map_err(|e| RenderError::Render(e.to_string()))?;

    let evaluated = tab
        .evaluate(CLEAN_AND_SERIALIZE, false)
        .map_err(|e| RenderError::Render(e.to_string()))?;

    match evaluated.value {
        Some(serde_json::Value::String(html)) if !html.is_empty() => Ok(Rendered { html }),
        _ => Err(RenderError::NoContent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_script_targets_script_style_noscript() {
        assert!(CLEAN_AND_SERIALIZE.contains("script,style,noscript"));
        assert!(CLEAN_AND_SERIALIZE.contains("outerHTML"));
    }

    #[test]
    fn default_config_uses_default_timeout() {
        let cfg = RenderConfig::default();
        assert_eq!(
            cfg.timeout,
            Duration::from_secs(DEFAULT_RENDER_TIMEOUT_SECS)
        );
    }

    #[test]
    fn resolve_chrome_prefers_env_override() {
        // A non-existent override falls through to the system candidates rather than being returned.
        std::env::set_var("CHROME", "/definitely/not/a/real/chrome/binary");
        let resolved = resolve_chrome();
        std::env::remove_var("CHROME");
        if let Some(path) = resolved {
            assert_ne!(path, PathBuf::from("/definitely/not/a/real/chrome/binary"));
        }
    }
}
