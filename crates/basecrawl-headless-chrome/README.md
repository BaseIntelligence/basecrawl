# basecrawl-headless-chrome

MIT-licensed **fork** of [`headless_chrome`](https://crates.io/crates/headless_chrome) **1.0.22**
(VCS sha `0a5c307a85debc450378a1f19e4dac1838d7b22d`) used by the
[basecrawl](https://github.com/BaseIntelligence/basecrawl) hard-path Chromium driver.

## Why this fork exists

Upstream crates.io `headless_chrome` 1.0.22 does not expose APIs basecrawl needs for one absolute
scrape deadline, non-blocking Fetch body metering, and modern headless:

| Load-bearing surface | Purpose |
| --- | --- |
| `Browser::new_with_deadline` (+ process/transport/tab deadline plumbing) | Bound Chrome launch + CDP WebSocket upgrade by a caller absolute deadline |
| `RequestPausedDecision::Deferred` | Response-stage body metering without blocking the target event loop |
| Launch flag `--headless=new` | Prefer Chromium's new headless mode for stealth residual honesty |

Library crate name remains **`headless_chrome`** so dependents can keep:

```toml
headless_chrome = { package = "basecrawl-headless-chrome", version = "0.1" }
```

```rust
use headless_chrome::{Browser, LaunchOptions};
```

## License

Original upstream is **MIT** (see `LICENSE.md`). This package redistributes that license notice and
documents BaseIntelligence basecrawl modifications on top of 1.0.22.

## Upstream

- Upstream project: <https://github.com/rust-headless-chrome/rust-headless-chrome>
- This packaging lives under the basecrawl monorepo for coordinated release with `basecrawl-render`.
