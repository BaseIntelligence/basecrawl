# Runbook: reproducible CVM image rotation on Chromium/OS CVE

This runbook is the concrete **image-rotation-on-CVE** policy for `basecrawl`.
It implements the TCB residual described in `docs/tcb-inventory.md` and must be
followed whenever a Chromium or OS vulnerability requires a measured-image change.

Goal: produce a **new digest-pinned, reproducibly measurable image**, then
**atomically** rotate the validator allowlist so the new measurement is pinned
and the vulnerable measurement is **removed** (never default-accepted both
indefinitely).

## Preconditions

1. CVE details and a patched Chromium (or OS/runtime) pin are available as
   digest-addressable artifacts.
2. `dstack-mr` and the pinned dstack / meta-dstack revisions from the mission
   environment are available for offline measurement reproduction.
3. Validators can reload the measurement allowlist used by L1
   (`CHALLENGE_MEASUREMENT_ALLOWLIST_FILE` / `CHALLENGE_KEY_RELEASE_ALLOWLIST_FILE`).
4. Registry publish authorization (if pushing a new immutable image digest) is
   explicit and limited to the authorized repository.

## Procedure (operator)

### 1. Record the retired measurement

Capture the currently allowlisted six-field TDX tuple from `image/allowlist.json`
(and the relay platform entry that includes `key_provider` when used for L1):

```text
mrtd, rtmr0, rtmr1, rtmr2, compose_hash, os_image_hash
```

Tag this set as **retired** in your operator log. Do not leave it active after
rotation completes.

### 2. Apply the CVE patch as pinned inputs

Update only pinnable surfaces:

1. Bump `CHROMIUM_VERSION` / Chrome path and, when required, the digest-pinned
   Puppeteer/runtime `FROM` line in `image/Dockerfile`.
2. If OS cookies change, they must arrive **only** through the new digest-pinned
   runtime image (no floating `apt install` at build).
3. Keep `SOURCE_DATE_EPOCH` and locked toolchains. Do **not** introduce
   unpinned tags or `playwright install --with-deps`.

### 3. Reproducible rebuild (two independent builds)

From the repository root:

```bash
python3 image/reproducibility.py build --count 2
# or the equivalent BuildKit command pair used by image/reproducibility.py
```

PASS criteria:

- Two independent builds of the **same patched source + pins** yield the
  **same** image digest / digest-pinned identity and the **same** offline
  `dstack-mr` measurement (MRTD/RTMR0-2 for the fixed VM shape).
- Publish only an immutable `@sha256:…` digests (never floating tags as the
  persistence path).
- Re-pin `image/docker-compose.yml` and Phala app-compose to the new digest;
  recompute `compose_hash`.

Programmatic helper for measurement identity (offline / CI, no live CVM
required for the gate itself):

```bash
python3 image/cve_rotation.py measure --materials <json-or-flags>
python3 image/cve_rotation.py rebuild-check --materials-a A.json --materials-b B.json
```

### 4. Atomic allowlist rotation (new pinned, old removed)

**Policy:** rotation is atomic. The post-rotation allowlist for the TDX platform
contains the **new** measurement and **does not** contain the retired vulnerable
measurement. Dual-pin windows are never the default and must not become an
indefinite state.

```bash
# basecrawl image allowlist (six-field)
python3 image/cve_rotation.py rotate \
  --allowlist image/allowlist.json \
  --new-entry new-measurement.json \
  --retire-entry retired-measurement.json

# relay L1 / key-release allowlist (platform-namespaced)
# Write only the new pin; retired entry is stripped in the same write.
cd relay && PYTHONPATH=src python -m relay.keyrelease.allowlist_rotate rotate \
  --allowlist path/to/validator-allowlist.json \
  --new-entry new-l1-entry.json \
  --retire-entry retired-l1-entry.json
```

Implementation requirement: write via a temporary file in the same directory and
`os.replace` onto the destination so readers never observe a half-written file.
There is no long-lived "accept either" mode unless an operator explicitly
invokes a **time-boxed dual-pin** tool (not this default path).

### 5. Post-rotation verification (L1)

After validators reload the allowlist:

1. A quote / proof whose measurement equals the **retired** tuple must fail L1
   with reason `measurement_not_allowlisted`.
2. A quote / proof whose measurement equals the **new** tuple must L1 `pass`
   (crypto-valid + UpToDate TCB assumed).
3. Empty allowlist still fails closed (`allowlist_empty`); never stay dual-open.

Executable simulation (no CVM required for the policy gate):

```bash
python3 image/cve_rotation.py verify-rotation \
  --before retired.json --after new.json --allowlist image/allowlist.json
# relay side:
cd relay && PYTHONPATH=src uv run pytest tests/test_cve_image_rotation.py -q
```

### 6. Residual remains until patch lands everywhere

Even after rotation, a *future* 0-day inside the new pin is still a residual —
the enclave may still be **measured-but-exploited** while L1 attests cleanly.
Replay-audit sampling remains the continuous backstop (`relay.scoring.replay_audit`).
Document the CVE ID, new digest, new measurement, retirement time, and operator
in the evidence log.

## Policy summary

| Property | Rule |
| --- | --- |
| Determinism | Same patched sources + pins → same digest + same measurement |
| Rotation atomicity | New pin written together with retired pin removed |
| Dual-accept | Not the default; never leave both indefinitely |
| L1 outcome | Retired → `measurement_not_allowlisted`; new → pass |
| Residual | Measured-but-exploited 0-day acknowledged; replay-audit backstop |
