# Operator guide: deploy basecrawl (local + GHCR + Phala CVM)

How to run **basecrawl** as a local miner binary, pull the digest-pinned CVM image from
**GHCR**, and place it on a Phala / dstack TDX guest. Companion docs:
[Install & publish](install-and-publish.md), [Proxy & egress](proxy-and-egress.md),
[Breadth & extract](product-breadth-and-extract.md), [Security](../SECURITY.md),
[Trust model](../TRUST_MODEL.md), [Image rotation on CVE](../image-rotation-on-cve.md),
[TCB inventory](../tcb-inventory.md).

This guide is **operator procedure**, not a claim of absolute authenticity, anonymity, or
defeat of every bot vendor. Authenticity remains **cryptographically-anchored trust-but-audit**.

## Choose a deploy path

| Path | When to use | Attestation |
| --- | --- | --- |
| **Local CLI / binary** | Miners and operators developing or scraping without TEE | No TDX quote; fail closed if you pass `--attest` outside a CVM |
| **GHCR image on host Docker** | Smoke the product image without Phala | No guest dstack socket unless you mount one |
| **Phala TDX CVM (dstack)** | Production attested scrapes for validators / relay | L1 allowlist + L2 `report_data` via `/var/run/dstack.sock` |

```mermaid
flowchart TB
  Op[Operator]
  Local[Local cargo binary]
  GHCR[ghcr.io/baseintelligence/basecrawl-cvm]
  Host[Host Docker poke]
  Phala[Phala TDX / dstack 0.5.9]
  Sock["/var/run/dstack.sock"]
  Proof[ScrapeProof JSON]

  Op --> Local
  Op --> GHCR
  GHCR --> Host
  GHCR --> Phala
  Phala --> Sock
  Local --> Proof
  Host --> Proof
  Sock --> Proof
```

## 1. Local miner deploy (no TEE)

Use this path for soft scrapes, hermetic tests, proxy wiring, and optional CapSolver without a CVM.

### 1.1 Install or build

Rust toolchain is pinned in `rust-toolchain.toml` (`1.96.0`).

**Preferred install after a public crates.io release** (thin packaging crate):

```bash
cargo install basecrawl --locked
```

From the repository root (pre-publish, patches, or local engineering):

```bash
cargo build --release --locked --package basecrawl-core --bin basecrawl
# binary: target/release/basecrawl

# PATH install from monorepo path (thin crate preferred):
cargo install --path crates/basecrawl --locked
# alternate:
cargo install --path crates/basecrawl-core --locked --bin basecrawl
```

Published package list, Node `@basecrawl/sdk` linux-x64 residual, Chromium residual, and the
tag `v*` → `publish.yml` release story: [install-and-publish.md](install-and-publish.md).

### 1.2 Minimal scrape

```bash
./target/release/basecrawl \
  --formats markdown,metadata \
  --timeout 60 \
  https://example.com/
```

Stdout is **exactly one** ScrapeProof JSON object on success. Failures write `{"error": ...}` to
stderr and exit non-zero (no partial truth on stdout).

### 1.3 Proxy / residential (optional)

Secrets stay in a **gitignored** `.env` (mode `600`). Never paste passwords into shells, tickets, or
this doc.

```bash
# .env (mode 600) — names only; set real values offline
# BASECRAWL_HTTPS_PROXY=http://user:pass@provider-host:port
# BASECRAWL_HTTP_PROXY=http://user:pass@provider-host:port

set -a; . ./.env; set +a

./target/release/basecrawl \
  --proxy-class residential \
  --proxy-session s1 \
  --proxy-country US \
  --formats markdown,metadata \
  https://example.com/
```

- Universal proxy: any `http(s)://user:pass@host:port` CONNECT or `socks5://…` URL.
- Oxylabs is a **live residential fixture**, not a hard product dependency. Prefer sticky country
  templates documented in [proxy-and-egress.md](proxy-and-egress.md).
- Live commercial dialing: keep **max 1 concurrent** residential family when
  `BASECRAWL_LIVE_PROXY=1` is set. Proxy class honesty is fail-closed (no fake residential on a
  direct dial).
- Full flag table and composer behavior: [proxy-and-egress.md](proxy-and-egress.md).

### 1.4 Optional CapSolver

Default challenge posture is **detect-not-solve** (`challenge_blocked` without unlocking forged
content). CapSolver is optional:

```bash
# .env (mode 600)
# CAPSOLVER_API_KEY=…                # or BASECRAWL_CAPSOLVER_API_KEY
# BASECRAWL_CAPTCHA_SOLVER=capsolver

./target/release/basecrawl \
  --captcha-solver capsolver \
  --formats markdown,metadata \
  --force-browser \
  https://example.com/
```

Without a key or provider selection the product stays detect-only. CapSolver does **not** equal
commercial Web Unlocker parity. Details: [proxy-and-egress.md](proxy-and-egress.md#optional-capsolver-operator-and-miner-key-fail-closed).

### 1.5 Attest without a CVM

```bash
./target/release/basecrawl --attest https://example.com/
# fails closed: no fabricated TDX quote outside /var/run/dstack.sock
```

## 2. GHCR image name and pull

**Primary auto-publish path** (GitHub Actions `Image` workflow):

```text
ghcr.io/baseintelligence/basecrawl-cvm
```

| Tag / pin style | Use |
| --- | --- |
| `@sha256:<digest>` | **Required for verification / allowlist / production Phala pin** |
| `sha-<full-git-sha>` | Immutable commit tag from Actions |
| `sha-<short>` | Convenience immutable short form |
| `:latest` | Convenience only on default-branch publishes; **do not** use for verification |

### 2.1 Authenticate (private or org packages)

Public pulls may work after package visibility is set. For private packages or rate limits:

```bash
# GitHub CLI (preferred when logged in)
gh auth token | docker login ghcr.io -u USERNAME --password-stdin

# Or PAT with read:packages (never commit the token)
echo "$GITHUB_TOKEN" | docker login ghcr.io -u USERNAME --password-stdin
```

### 2.2 Pull

```bash
# Prefer an immutable tag from Actions, then re-pin by digest for compose
docker pull ghcr.io/baseintelligence/basecrawl-cvm:sha-<full-git-sha>

# Or pull latest for a quick poke only (not for verification)
docker pull ghcr.io/baseintelligence/basecrawl-cvm:latest

# Resolve the content digest for allowlists / compose pin
docker image inspect ghcr.io/baseintelligence/basecrawl-cvm:sha-<full-git-sha> \
  --format '{{index .RepoDigests 0}}'
```

Digest pin form used everywhere verification matters:

```text
ghcr.io/baseintelligence/basecrawl-cvm@sha256:<digest>
```

Rebuild policy and allowlist rotation: [image-rotation-on-cve.md](../image-rotation-on-cve.md).

### 2.3 Host smoke without Phala

```bash
docker run --rm \
  ghcr.io/baseintelligence/basecrawl-cvm@sha256:<digest> \
  --help
```

Attested scrapes still need a dstack guest agent socket (next section).

### 2.4 Where the image is built

| Artifact | Path / URL |
| --- | --- |
| Dockerfile | [`image/Dockerfile`](../../image/Dockerfile) |
| Example compose | [`image/docker-compose.yml`](../../image/docker-compose.yml) |
| Actions workflow | [`.github/workflows/image.yml`](../../.github/workflows/image.yml) |
| Cargo quality gate | [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) (fmt / clippy / tests; unchanged by image publish) |
| Image workflow runs | [Actions → Image](https://github.com/BaseIntelligence/basecrawl/actions/workflows/image.yml) |

Historic alternate pin (may lag GHCR auto path; still digest-only for verification):

```text
docker.io/mathiiss/basecrawl-cvm@sha256:<digest>
```

GHCR is the **primary auto-publish** target (`packages: write` + `GITHUB_TOKEN` on `main` /
`workflow_dispatch`). Cargo gate CI remains independent of registry software.

## 3. Phala / dstack CVM path

Production attestation uses Phala managed TDX and guest OS **dstack `0.5.9`** family
(slug family `dstack-0.5.9-bd369a8c`). The guest must expose:

```text
/var/run/dstack.sock
```

used by `Info`, `GetQuote`, and related dstack endpoints. Outside that socket, `--attest` fails closed.

### 3.1 Preconditions

1. Phala account / CLI authenticated (`phala status` succeeds). Never print API keys.
2. Capacity for a **linux/amd64** TDX guest using product dstack `0.5.9` (not a floating OS tag).
3. An **immutable image digest** (`ghcr.io/baseintelligence/basecrawl-cvm@sha256:…`, or the
   documented docker.io alternate pin after you verified it matches the intended measurement).
4. Validator / key-release **measurement allowlist** path ready for rotation when remapping
   measurements ([image-rotation-on-cve.md](../image-rotation-on-cve.md)).

### 3.2 Pin compose to a digest

Edit [`image/docker-compose.yml`](../../image/docker-compose.yml) (or your operator-owned compose
fork) so `services.basecrawl.image` is digest-pinned:

```yaml
services:
  basecrawl:
    image: "ghcr.io/baseintelligence/basecrawl-cvm@sha256:<YOUR_VERIFIED_DIGEST>"
    # … entrypoint binds /var/run/dstack.sock and runs the attested scrape command …
    volumes:
      - type: "bind"
        source: "/var/run/dstack.sock"
        target: "/var/run/dstack.sock"
```

Rules:

- Prefer `@sha256:…` over any floating tag for production and allowlists.
- After changing the image line, recompute **compose_hash** / measurement tuples offline with the
  pinned `dstack-mr` tooling described in [tcb-inventory.md](../tcb-inventory.md) and
  [image-rotation-on-cve.md](../image-rotation-on-cve.md).
- Product app-compose examples also live under [`image/phala-app-compose.json`](../../image/phala-app-compose.json)
  (features include `kms` / gateway surface as configured for Phala).

### 3.3 Deploy steps (numbered)

1. **Select digest** from a successful [Image Actions run](https://github.com/BaseIntelligence/basecrawl/actions/workflows/image.yml)
   (`sha-<gitsha>` tag → content digest) or from a local reproducible rebuild pair
   (`python3 image/reproducibility.py` path).
2. **Re-pin** `image/docker-compose.yml` (and Phala app-compose if you embed compose text) to
   `ghcr.io/baseintelligence/basecrawl-cvm@sha256:<digest>`.
3. **Allow GHCR pull** for the CVM pre-launch path if the package is private: supply registry pull
   credentials through Phala/dstack secure env surfaces only (`DSTACK_DOCKER_*` style). Never commit
   registry passwords. Public packages skip this login.
4. **Create the CVM** with Phala CLI / console on dstack `0.5.9`, TDX instance class, compose from
   `image/`, `kms_type: phala` (product placement). Prefer automatic placement only when capacity
   documentation for your account allows it.
5. **Wait for** `/var/run/dstack.sock` and a healthy guest pull of the pinned digest.
6. **Run an attested scrape** inside the guest (example pattern already baked into product compose for readiness):

```bash
basecrawl --attest \
  --task-id YOUR-TASK \
  --nonce YOUR-NONCE \
  --formats markdown,metadata,rawHtml \
  --timeout 60 \
  https://example.com/
```

7. **Verify** offline with `dcap-qvl` (quote verify/decode) and check L1 measurement against the
   current allowlist (`image/allowlist.json` / relay platform allowlist file). L2 must bind
   `report_data` hashes as documented in [architecture.md](../architecture.md) and
   [TRUST_MODEL.md](../TRUST_MODEL.md).
8. **On Chromium/OS CVE or deliberate TCB change**: rebuild, publish **new immutable digest**,
   path-rotate allowlist (**new in, old out**). Follow
   [image-rotation-on-cve.md](../image-rotation-on-cve.md) exactly; never float `:latest` as the
   verification pin and never leave vulnerable measurements accepted by default indefinitely.
9. **Tear down** mission/test CVMs when finished. Do not leave orphaned billed guests.

### 3.4 Measurement honesty

A verifying quote matching an allowlisted measurement is strong evidence the scrape ran in the
pinned image with bound hashes. It is **not** absolute authenticity: residual risk includes TEE.fail
on self-hosted DDR5, measured-but-exploited guest software, proxy ≠ anonymity, and headless/CDP
detector residual. See [SECURITY.md](../SECURITY.md).

## 4. Secrets inventory (names only)

Values never belong in git, ScrapeProof, measurements, CI logs, or this table. Use a gitignored
`.env` (mode `600`) or your platform secret store.

| Name | Purpose |
| --- | --- |
| `BASECRAWL_HTTP_PROXY` | Soft/hard ambient HTTP CONNECT / proxy URL |
| `BASECRAWL_HTTPS_PROXY` | Soft/hard ambient HTTPS proxy URL (preferred for HTTPS origins) |
| `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` | Standard ambient proxies (product resolution when `BASECRAWL_*` unset) |
| `BASECRAWL_LIVE_PROXY` | `1` arms live residential dials (max 1 concurrent family) |
| `OXYLABS_USERNAME` / `OXYLABS_PASSWORD` | Optional Oxylabs credential split if your operator scripts use them (prefer full proxy URL form) |
| `CAPSOLVER_API_KEY` | Optional CapSolver client key |
| `BASECRAWL_CAPSOLVER_API_KEY` | Optional CapSolver alias under the `BASECRAWL_*` namespace |
| `BASECRAWL_CAPTCHA_SOLVER` | `capsolver` when the optional solver is selected |
| `BASECRAWL_CAPSOLVER_API_BASE` | Optional CapSolver API base override (defaults to product endpoint) |
| `BASECRAWL_EXTRACT_API_KEY` | Optional structured extract provider key |
| `OPENAI_API_KEY` | Optional extract provider key (alias surface) |
| `FIRECRAWL_API_KEY` | Benchmark / comparison harness only; never required for scrapes |
| `GITHUB_TOKEN` / GHCR deploy token | Actions image publish uses `GITHUB_TOKEN` with `packages: write`; operator pulls use `read:packages` PAT or `gh` when private |
| `CARGO_REGISTRY_TOKEN` | Tag-driven crates.io publish secret name only (see [install-and-publish](install-and-publish.md)); never commit values |
| `NPM_TOKEN` | Optional `@basecrawl/sdk` residual npm publish secret name only; never commit values |
| Phala CLI profile / API key | Phala account auth for CVM lifecycle; use local CLI profile; never commit |
| `DSTACK_DOCKER_USERNAME` / `DSTACK_DOCKER_PASSWORD` / `DSTACK_DOCKER_REGISTRY` | Guest pre-launch registry login when pulling private packages into the CVM |
| `CHALLENGE_MEASUREMENT_ALLOWLIST_FILE` / `CHALLENGE_KEY_RELEASE_ALLOWLIST_FILE` | Validator-side allowlist paths (relay / challenge host), not crawler secrets |

Redact credentials to username + `***` at most in logs. Product proof and attestation surfaces never
include proxy passwords or CapSolver keys.

## 5. Residual honesty (required reading)

| Residual | Guidance |
| --- | --- |
| Authenticity | Cryptographically-anchored trust-but-audit; not absolute certainty |
| Proxy / residential | Topology and success-rate tool; **not anonymity** |
| CapSolver | Optional Turnstile path; **not** Web Unlocker parity; default is detect-not-solve |
| Headless Chromium | Hard-path identity baseline only; host and CVM need Chromium/Chrome; detector residual remains |
| Soft TLS vs hard path | Soft chrome-TLS impersonate is not Chromium document TLS |
| npm `@basecrawl/sdk` | Published package line is **linux-x64 only**; not multi-OS without multi-arch artifacts |
| TEE.fail / hardware | Self-hosted DDR5 residual; managed Phala reduces but does not erase all TEE risk |
| Image tags | `:latest` is convenience; **digests** pin verification and allowlists |
| Registry releases | Tags `v*` drive `publish.yml`; secrets by name only |

Product claims **must never** use absolute-trust wording. The following are **forbidden claims** (not claims this product makes): absolute-trust "trustless" language, "100%" authenticity, "guaranteed" unlock, "anonymous" egress, and "undetectable" browsing.

## 6. Quick links

| Topic | Link |
| --- | --- |
| Install / crates / npm / `v*` publish | [install-and-publish.md](install-and-publish.md) |
| Proxy / CapSolver / Oxylabs | [proxy-and-egress.md](proxy-and-egress.md) |
| POST / crawl / map / batch / extract | [product-breadth-and-extract.md](product-breadth-and-extract.md) |
| CVE image rotation | [image-rotation-on-cve.md](../image-rotation-on-cve.md) |
| Security residuals | [SECURITY.md](../SECURITY.md) |
| Trust model | [TRUST_MODEL.md](../TRUST_MODEL.md) |
| Publish workflow | [Actions → Publish](https://github.com/BaseIntelligence/basecrawl/actions/workflows/publish.yml) |
| Image workflow | [Actions → Image](https://github.com/BaseIntelligence/basecrawl/actions/workflows/image.yml) |
| Cargo quality workflow | [Actions → CI](https://github.com/BaseIntelligence/basecrawl/actions/workflows/ci.yml) |
