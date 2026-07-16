# Install and release publish surface

Product install paths for the public registry surface (crates.io + optional npm), residual
constraints, and how version tags drive release automation. Companion guides:
[Deploy](deploy.md), [Proxy & egress](proxy-and-egress.md), [Security](../SECURITY.md),
[Architecture](../architecture.md).

Authenticity remains **cryptographically-anchored trust-but-audit**. Install convenience does not
change the trust model: a bare host binary or SDK outside an allowlisted TEE proves nothing about
hardware attestation.

## Preferred CLI install (crates.io)

After a public release of the thin install crate, the preferred command is:

```bash
cargo install basecrawl --locked
```

That installs the `basecrawl` CLI binary onto your cargo bin path. The thin crate re-exports the
engine binary; library code lives in the workspace crates listed below.

### Alternatives

| Path | Command | When |
| --- | --- | --- |
| Preferred (published) | `cargo install basecrawl --locked` | After crates.io publish for matching version |
| Core package bin | `cargo install basecrawl-core --bin basecrawl --locked` | Same binary, library package surface |
| From monorepo checkout | `cargo install --path crates/basecrawl --locked` or `cargo build --release -p basecrawl-core --bin basecrawl` | Pre-publish, patches, or local development |
| CVM image | Digest-pinned pull from GHCR (see [deploy](deploy.md)) | Attested guest runs |

Soft scrapes need only the binary and a network path. Hard-path / JS / screenshot scrapes need a
local Chromium (or Chrome) runtime residual; see [Chromium residual](#chromium-runtime-residual).

### Quick check

```bash
basecrawl --help
basecrawl --formats markdown,metadata --timeout 60 --no-js https://example.com/
```

Stdout is one canonical ScrapeProof JSON object on success. Failures emit structured stderr and
exit non-zero.

## Published crates (crates.io)

Packages intended for crates.io (workspace version `0.1.0` family unless a later tag ships a bump):

| Package | Role |
| --- | --- |
| `basecrawl-headless-chrome` | Publishable fork of headless Chromium CDP tooling used by render (MIT upstream + basecrawl patches) |
| `basecrawl-proof` | Canonical ScrapeProof types and serialization |
| `basecrawl-fp` | Seeded fingerprint generator |
| `basecrawl-seal` | Confidentiality helpers (RA-TLS, DoH, seal/redact) |
| `basecrawl-render` | Headless Chromium render path |
| `basecrawl-core` | Engine library + optional `basecrawl` binary target |
| `basecrawl-ffi` | Stable C ABI substrate for language bindings |
| `basecrawl` | **Thin CLI install package** (preferred `cargo install basecrawl`) |

In-tree Cargo crates `basecrawl-sdk` (Node native) and `basecrawl-python` stay private to the
monorepo (`publish = false` on Cargo). They are not crates.io products.

Registry consumers resolve versions from crates.io. They do **not** inherit monorepo path patches
or git-only vendor trees.

## Node SDK install (`@basecrawl/sdk`)

```bash
npm install @basecrawl/sdk
# or: pnpm add @basecrawl/sdk
```

Package name: **`@basecrawl/sdk`**. Details for API surface live in
[`bindings/node/README.md`](../../bindings/node/README.md).

### Linux-x64 residual (this package line)

The published npm tarball currently ships a **single native binary** produced on Linux x86_64:

| Constraint | Value |
| --- | --- |
| `package.json` `os` | `["linux"]` |
| `package.json` `cpu` | `["x64"]` |
| Native artifact | `basecrawl_sdk.node` (ELF linux-x64) |

- **linux-x64 only.** Multi-OS / multi-arch napi optional packages (Darwin, Windows, arm64) are
  **not** part of this release line.
- Installs on other platforms are expected to fail platform matching or fail loading the native
  addon. That is intentional honesty, not a silent universal Node SDK claim.
- Local monorepo rebuild of the native addon on other hosts is a **development** path only and is
  distinct from the npm registry tarball.

Python and C consumers can still build from the monorepo bindings tree; they are outside this npm
surface.

## Chromium runtime residual

Hard path (residential/mobile class, `--difficulty hard`, `--force-browser`, JS render, screenshots)
drives real Chromium via CDP. Product costs of that choice:

| Surface | Residual |
| --- | --- |
| Host CLI / SDK (outside CVM) | A compatible Chromium or Chrome binary must be available on the scraper's host for hard/JS paths. Soft rustls scrapes (`--no-js`) do not need Chromium. |
| CVM image | Image pin supplies Chromium major (see [TCB inventory](../tcb-inventory.md)); digest republish + allowlist rotation after CVE / pin bumps. |
| Detection | Headless / CDP / Runtime residual remains. Product language **must never** claim absolute cross-detector stealth. Forbidden claim tokens for product marketing include absolute-trust wording such as "undetectable" (and peer absolute-trust terms barred elsewhere). |

Measured image identity is not a free pass on Chromium 0-day risk. See [SECURITY.md](../SECURITY.md).

## Tag-driven release (`v*` → `publish.yml`)

Public registry publishes are driven by **git tags** matching `v*` (for example `v0.1.0`).

| Piece | Role |
| --- | --- |
| `.github/workflows/publish.yml` | Tag (and optional `workflow_dispatch` dry-run) path for crates.io ordered publish + residual npm |
| `.github/workflows/ci.yml` | Continuous cargo quality gate (fmt / clippy / tests); publish reuses equivalent quality steps |
| `.github/workflows/image.yml` | Separate GHCR CVM image publishes (not crates/npm) |

### Version match (required)

Tag `vX.Y.Z` must match:

1. Workspace package version in root `Cargo.toml` (`[workspace.package] version`)
2. Node package version in `bindings/node/package.json` when the npm job runs

Mismatch fails before live publish.

### Ordered crates.io topology

Bottom-up publish order (lower crates live before upper dependents resolve from the public index):

1. `basecrawl-headless-chrome`
2. `basecrawl-proof`
3. `basecrawl-fp`
4. `basecrawl-seal`
5. `basecrawl-render`
6. `basecrawl-core`
7. `basecrawl-ffi`
8. thin `basecrawl`

Live publish uses secret name **`CARGO_REGISTRY_TOKEN`** (never committed, never printed). Product
docs list secret **names only**.

### Residual npm job (Trusted Publishing / OIDC)

After a green crates path, the same workflow may build and publish `@basecrawl/sdk` with
`--access public` on `ubuntu-latest` (**linux-x64** host only; multi-OS napi matrix is out of scope).

**Primary auth:** [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/) via GitHub Actions
OIDC. The npm job sets `permissions: id-token: write`, keeps `setup-node` `registry-url`, gates
**Node ≥22.14** and **npm CLI ≥11.5.1**, and runs `npm publish` **without** requiring a bypass-2FA
`NPM_TOKEN` / `NODE_AUTH_TOKEN`. The CLI exchanges a short-lived OIDC token with the registry.

**Soft typed residuals** (crates job stays green):

| Class | When |
| --- | --- |
| `package_not_on_registry` | `@basecrawl/sdk` not yet present on the public registry (first create needed) |
| `npm_trusted_publisher_missing` | Package exists, but Trusted Publisher is not bound for this workflow / OIDC exchange fails |

#### Path B: first package create (human, interactive OTP)

Trusted Publishing attaches to an **existing** package. If the registry still returns 404 for
`@basecrawl/sdk`, an owner (account that owns the `@basecrawl` org, e.g. **echobt1**) creates
`@basecrawl/sdk@0.1.0` once from a **linux x64** host:

```bash
cd bindings/node
pnpm install
pnpm run prepack
pnpm run smoke:linux
npm login          # interactive; complete OTP / 2FA when prompted
npm publish --access public   # interactive OTP when prompted
```

Do **not** paste long-lived write tokens into scripts, tickets, or logs. Prefer interactive login + OTP
for this one-time create.

Verify:

```bash
curl -sf https://registry.npmjs.org/@basecrawl%2fsdk >/dev/null
npm view @basecrawl/sdk version
```

#### Then: configure Trusted Publisher on npmjs.com

On the package page → Settings → Trusted Publisher → GitHub Actions:

| Field | Value |
| --- | --- |
| Organization or user | `BaseIntelligence` |
| Repository | `basecrawl` |
| Workflow filename | `publish.yml` (filename only, not full path) |
| Allowed actions | **npm publish** |

After that binding exists, re-run Actions → Publish with `workflow_dispatch` and `dry_run=false`
(or cut the next `v*` tag). The crates job **skips already-live** `0.1.0` versions; the npm job uses
OIDC. Secret name `NPM_TOKEN` is **not** required for the Trusted Publishing path (legacy residual
only if an operator still injects it elsewhere).

### Operator checklist (release)

1. Bump versions consistently (workspace + npm when touching Node).
2. Keep quality green on `ci.yml`.
3. For first npm create only: complete Path B local OTP publish, then Trusted Publisher setup above.
4. Push annotated or lightweight tag `vX.Y.Z` (or `workflow_dispatch` with `dry_run=false`).
5. Watch [Actions → Publish](https://github.com/BaseIntelligence/basecrawl/actions/workflows/publish.yml).
6. Prefer `cargo install basecrawl --locked` for consumers; GHCR digests for CVMs.
7. Never put registry token values into git, tickets, ScrapeProof, or this doc.

## Secret names (never values)

| Name | Use |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` | Ordered `cargo publish` on tag |
| `NPM_TOKEN` | **Optional legacy only.** Primary npm path is Trusted Publishing (OIDC); no bypass-2FA token required for CI `npm publish` |
| `GITHUB_TOKEN` | Existing GHCR / Actions package auth for **image** workflow only |

Proxy / CapSolver / extract environment names remain in [deploy](deploy.md#4-secrets-inventory-names-only).

## What this surface is not

- Not a monorepo-only install story after public registries ship a version.
- Not multi-arch npm prebuilds while only linux-x64 `.node` is published.
- Not a guarantee of headless Chromium cloaking or commercial unlocker parity.
- Not absolute authenticity; authenticity is **cryptographically-anchored trust-but-audit**.

Product claims **must never** use absolute-trust wording. The following are **forbidden claims** (not claims this product makes): absolute-trust "trustless" language, "100%" authenticity, "guaranteed" unlock, "anonymous" egress, and "undetectable" browsing.

## Related links

| Topic | Link |
| --- | --- |
| Local + CVM deploy | [deploy.md](deploy.md) |
| Node residual packaging | [bindings/node/README.md](../../bindings/node/README.md) |
| Security residuals | [SECURITY.md](../SECURITY.md) |
| Publish workflow | [Actions → Publish](https://github.com/BaseIntelligence/basecrawl/actions/workflows/publish.yml) |
| Cargo quality | [Actions → CI](https://github.com/BaseIntelligence/basecrawl/actions/workflows/ci.yml) |
| GHCR image | [Actions → Image](https://github.com/BaseIntelligence/basecrawl/actions/workflows/image.yml) |
