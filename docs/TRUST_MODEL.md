# Trust model (basecrawl)

Authenticity is **cryptographically-anchored trust-but-audit**.

This document exists so the honest model is greppable in the basecrawl
repository alongside the detailed residual write-up in `docs/SECURITY.md`.

## What a ScrapeProof means

A ScrapeProof whose quote verifies and whose measurement is on the validator
allowlist is evidence that the scrape ran inside software matching a pinned CVM
image, with request/cert/transcript/response/result hashes bound into
`report_data`. Combined with L2 certificate checks and (on the relay side)
quorum + audit + scoring, that is a **cryptographic anchor**, not absolute
certainty.

A scrape is authentic under:

- TEE vendor honest **and** host not physically compromised; **or**
- honest witness + clean network path; **or**
- honest-majority audit + slashing.

## Forbidden language

Do not write absolute trust or absolute TEE wording about basecrawl or its TEE
path. Absolute-trust vocabulary and absolute-TEE vocabulary are prohibited
(`VAL-HARDEN-023`, `VAL-HARDEN-004`); the model is only
cryptographically-anchored trust-but-audit.

## Residuals called out elsewhere

- TEE.fail (self-hosted DDR5 interposer can forge quotes / read enclave memory;
  no vendor fix) + managed-cloud mitigation → `docs/SECURITY.md`
- Measured-but-exploited Chromium/OS 0-day + rotation runbook →
  `docs/tcb-inventory.md`, `docs/image-rotation-on-cve.md`
