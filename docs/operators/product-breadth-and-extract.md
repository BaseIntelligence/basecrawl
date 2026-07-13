# Operator guide: product breadth and extract honesty

POST/body, crawl MVP, map-lite, batch multi-URL, and the gated structured `json` path.

Companions: [Proxy and egress](proxy-and-egress.md), [Architecture](../architecture.md), [Security](../SECURITY.md).

## CLI product modes

| `--mode` | Behavior |
| --- | --- |
| `scrape` (default) | Single URL ScrapeProof on stdout |
| `crawl` | Bounded multi-page MVP from a seed (max pages/depth + domain filter) |
| `map` | Map-lite same-origin / sitemap inventory (not a full site index) |
| `batch` | Multi-URL list with per-item isolation |

### Request breadth (single scrape)

```bash
# GET (default)
basecrawl https://example.com/

# POST with literal body (soft path). Body hash recorded in ScrapeProof.
basecrawl --method POST --body 'q=hello' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --no-js https://httpbin.org/post

# POST body from file
basecrawl --method POST --body @/tmp/payload.json \
  --header 'Content-Type: application/json' --no-js https://example.com/api
```

Hard Chromium path **refuses POST** with a structured `post_not_supported_on_hard_path` error (no silent empty body). Prefer `--no-js` soft path when POST is required.

### Crawl MVP

Bounded local crawl, not a hosted multi-tenant crawl SaaS:

```bash
basecrawl --mode crawl \
  --max-crawl-pages 5 \
  --max-depth 1 \
  --allow-domain example.com \
  --formats markdown,metadata \
  https://example.com/
```

### Map-lite

```bash
basecrawl --mode map --max-urls 100 https://example.com/
# skip sitemap discovery:
basecrawl --mode map --no-sitemap --max-urls 50 https://example.com/
```

Inventory is best-effort within bounds. It does not claim complete site coverage.

### Batch

```bash
basecrawl --mode batch \
  --urls https://example.com/,https://example.org/ \
  --concurrency 2 \
  --pace-ms 100 \
  --formats markdown,metadata
```

Each item carries its own ok/error envelope; consumers must check per-item status.

## Structured JSON extract (honesty gate)

`--formats json` with optional `--json-schema` / `--schema` and `--json-prompt` / `--prompt` is how callers **request** schema extract. The engine **never forges** empty or LLM-looking success when no extractor is available.

| Situation | Outcome |
| --- | --- |
| No provider key | Structured error `structured_extraction_unsupported`, reason `provider_not_configured` |
| Key set, no live extractor in this build | Structured error, reason `extractor_not_available` (key path is distinct, still not fake success) |
| Malformed / non-object schema | Structured error `invalid_json_schema` naming the schema problem |
| `markdown,json` without extract backend | Clean **unit refuse** of the whole request (no half proof with markdown dropped silently) |

### Optional provider env (never commit)

```bash
# Prefer product-specific names; OPENAI_API_KEY is also recognized
export BASECRAWL_EXTRACT_API_KEY='...'
# Optional for a future live wire:
export BASECRAWL_EXTRACT_BASE_URL='https://api.example/v1'
export BASECRAWL_EXTRACT_MODEL='...'
```

Secrets stay out of ScrapeProof, help text screenshots, and git. Without a live extractor implementation that returns real structured results for your provider, setting a key alone still fails closed on purpose.

```bash
# Expect structured unsupported / invalid_schema — not a success payload
basecrawl https://example.com/ --formats json \
  --schema '{"type":"object","properties":{"title":{"type":"string"}}}' \
  --prompt 'Extract the title'
```

`json` / extract contents sit **outside** the deterministic `result_hash` quorum surface (like `screenshot`), so optional extract noise does not corrupt miner/validator questions.

## Residual wording

- Structured extract is **gated**, not universal intelligent extraction of arbitrary pages.
- Crawl and map bounds are product features, not completeness goods.
- Proxy and stealth residuals: see [proxy-and-egress.md](proxy-and-egress.md) and [SECURITY.md](../SECURITY.md).
