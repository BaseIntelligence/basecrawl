# Security and residual risks (basecrawl)

This is the miner-facing **threat / security** document for the `basecrawl`
crawler image and SDK. It states the trust model honestly and documents the
**TEE.fail** residual with the managed-cloud mitigation used by the `relay`
challenge. Companion: `docs/tcb-inventory.md` and `docs/image-rotation-on-cve.md`.

## Trust model

Authenticity is **cryptographically-anchored trust-but-audit**. A scrape is
authentic under:

`{TEE vendor honest AND host not physically compromised}`
`OR {honest witness + clean network path}`
`OR {honest-majority audit + slashing}`.

No basecrawl docs, code comments, CLI/API strings, or UI copy may claim absolute
authenticity for this engine (never the absolute-trust vocabulary prohibited by
`VAL-HARDEN-023`). Security enforcement is the validator (L1 measurement
allowlist + L2 report_data binding), not merely shipping this binary. A bare
SDK outside an allowlisted TEE proves nothing.

## Absolute TEE claims are forbidden

Absolute TEE security claims are forbidden across this repository and the
companion `relay` repository (never the absolute-TEE vocabulary prohibited by
`VAL-HARDEN-004`).

## TEE.fail residual (explicit)

**Residual:** a self-hosted DDR5 bus interposer can **forge quotes** and
**read enclave memory**. There is **no vendor fix**. When miners self-host the
CVM, a physical interposer adversary can therefore undermine both quote
authenticity and content-confidentiality.

**Managed-cloud mitigation:** run high-reward and confidential workloads on a
managed-cloud TEE (e.g. Phala TDX) where the miner does not control bus access.
`relay` enforces this residual economically: managed-cloud submissions earn
strictly more weight, self-hosted submissions are audited harder, and
confidential/high-reward tasks admit only managed-cloud for full payout. This
does not make the TEE absolute; it is the operational answer to the residual
while authenticity remains cryptographically-anchored trust-but-audit.

## Measured TCB and Chromium 0-day residual

The measured TCB is minimized and enumerated in `docs/tcb-inventory.md`.
Measurement matching proves *image identity*, not that Chromium/OS code is free
of unknown vulnerabilities. A measured-but-exploited residual is acknowledged;
the backstop is replay-audit sampling plus the image-rotation-on-CVE runbook in
`docs/image-rotation-on-cve.md`.

## Content-confidentiality only

When run in the sealed/TEE path, basecrawl aims for **content-confidentiality**
(host does not see path/query/headers/cookies/body/result plaintext), not
target-anonymity. Destination IP, SNI (absent ECH), DoH resolver destination,
and traffic metadata remain expected residual leakage to a proxy-operating host.

## Operator checklist

1. Prefer managed-cloud placement for confidential scrapes (relay will down-weight
   and over-audit self-hosted otherwise).
2. Keep image contractions reproducible and digest-pinned; rotate on CVE per
   `docs/image-rotation-on-cve.md`.
3. Never advertise absolute trust language in miner tooling wrap-up or docs.
