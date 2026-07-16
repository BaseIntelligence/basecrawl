# `basecrawl serve` — local long-running engine HTTP

Local SaaS control-plane path: keep one engine process alive and dispatch scrape/crawl/map/batch
over HTTP so the API never re-spawns the CLI per job.

## Bind (loopback default)

```bash
cargo run -p basecrawl -- serve --bind 127.0.0.1:4420
# or
basecrawl serve --host 127.0.0.1 --port 4420
```

| Setting | Default | Env |
| --- | --- | --- |
| Host | `127.0.0.1` | `BASECRAWL_SERVE_HOST` |
| Port | `4420` | `BASECRAWL_SERVE_PORT` |
| Max inflight | `2` | `BASECRAWL_SERVE_MAX_INFLIGHT` |
| Request timeout hard | `120000` ms | `BASECRAWL_SERVE_REQUEST_TIMEOUT_MS` |
| Body size limit | `32 MiB` | `BASECRAWL_SERVE_MAX_BODY_BYTES` |
| Shared secret | unset (open on loopback) | `BASECRAWL_SERVE_SECRET` or `ENGINE_SERVE_SECRET` |

Default bind is **loopback-only**. Do not treat a non-loopback bind as a multi-region public edge.

## Endpoints

| Method | Path | Auth when secret set | Notes |
| --- | --- | --- | --- |
| `GET` | `/health` | open | `{ "status":"ok","service":"basecrawl-serve", residual… }` |
| `POST` | `/v1/scrape` | yes | Firecrawl-like body → real soft scrape |
| `POST` | `/v1/crawl` | yes | Bounded crawl MVP |
| `POST` | `/v1/map` | yes | Map-lite inventory |
| `POST` | `/v1/batch/scrape` | yes | Multi-URL batch |

When a secret is configured, execute routes require header:

```http
X-Basecrawl-Serve-Secret: <same value as BASECRAWL_SERVE_SECRET>
```

Unmatched secret → **401** fail-closed. Health remains open for probes.

### SaaS API pairing (local)

The private SaaS API (`Basecrawl/api` on `:4410`) must use the **same** env value
(`ENGINE_SERVE_SECRET` or `BASECRAWL_SERVE_SECRET`) when calling this process.
Mismatch / only-one-side-set causes API `/v1/scrape|crawl|map|batch` to surface
**HTTP 502** with error code **`engine_unauthorized`**. Leave **both** API and
serve unset for open loopback dev. See `basecrawl-api` README "Shared engine serve
secret" and mission `services.yaml` (`saas-api` + `engine-serve`).

## Soft scrape example

```bash
curl -sS -X POST http://127.0.0.1:4420/v1/scrape \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","formats":["markdown","metadata"]}'
```

Response carries `success`, `data` (formats), `metrics`, and a residual-honest `proof` metadata
object (hashes / TLS markers). Full ScrapeProof may also appear under `scrape_proof`.

## Residual honesty (required)

`basecrawl serve` is **not**:

- an anonymous / residential unlocker product by default
- “trustless” authenticity
- a claim of **100%** challenge unlock
- substitute for host tee/attested CVM measurement checks in the subnet path

Residual risks remain: Chromium headless / CDP side-channels, fingerprint pin lag, soft TLS
impersonate ≠ hard Chromium wire, CapSolver (when configured) ≠ commercial Web Unlocker parity.

Authenticity remains **cryptographically-anchored trust-but-audit** (see architecture + ScrapeProof
docs). Soft open-web success on example.com proves the engine wire works; it does not erase residual
anti-bot risk on harder targets.

## Cargo feature

The thin `basecrawl` crate documents feature `serve` as intent documentation; the serve module always
builds with basecrawl-core (stdlib HTTP, no extra runtime). Operators may still pass
`--features serve` when shipping documented compose commands.
