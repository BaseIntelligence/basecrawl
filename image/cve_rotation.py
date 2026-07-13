#!/usr/bin/env python3
"""CVE-driven reproducible image measurement + atomic allowlist rotation.

Implements the mechanical half of VAL-HARDEN-021 / VAL-HARDEN-024:

* Derive a deterministic digest-pinned measurement identity from pinnable TCB
  materials (Chromium, OS/runtime digest, compose, dstack OS image hash, VM
  shape, toolchain, optional CVE patch id). Two builds with identical
  materials yield an identical measurement; a CVE patch changes at least one
  material and therefore the measurement.
* Rotate the validator allowlist atomically: write a temp file in the same
  directory then ``os.replace`` so the new measurement is pinned and every
  retired vulnerable measurement is removed in the same replacement. The
  default path never dual-accepts retired + new indefinitely.

This module deliberately does **not** ship floating base tags or unpinned
toolchains; it only reads / writes pinned materials and fail-closed allowlists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

# Local imports when run as a module under image/ or as ``python -m image.cve_rotation``.
try:
    from measurement_allowlist import (  # type: ignore  # noqa: E402
        CANONICAL_FIELDS,
        MeasurementAllowlistError,
        allowlist_contains,
        load_allowlist,
    )
except ImportError:  # pragma: no cover - package-style import
    from image.measurement_allowlist import (  # type: ignore  # noqa: E402
        CANONICAL_FIELDS,
        MeasurementAllowlistError,
        allowlist_contains,
        load_allowlist,
    )


IMAGE_DIR = Path(__file__).resolve().parent
DEFAULT_OS_IMAGE_HASH = (
    "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033"
)
DEFAULT_RTMR0_VM_SHAPE = "tdx.small.1vcpu.2g"
DEFAULT_RUST_VERSION = "1.96.0"
DEFAULT_CHROMIUM_VERSION = "145.0.7632.46"
DEFAULT_SOURCE_DATE_EPOCH = "1700000000"

#: Materials that form the measured image identity. Changing any of these for a
#: CVE patch is expected to produce a new measurement.
MEASUREMENT_MATERIAL_KEYS = (
    "chromium_version",
    "runtime_image_digest",
    "builder_image_digest",
    "rust_version",
    "source_date_epoch",
    "application_source_digest",
    "compose_spec_digest",
    "os_image_hash",
    "rtmr0_vm_shape",
    "cve_patch_id",
)

REQUIRED_MATERIALS = (
    "chromium_version",
    "runtime_image_digest",
    "application_source_digest",
    "compose_spec_digest",
    "os_image_hash",
    "rtmr0_vm_shape",
)


class CveRotationError(ValueError):
    """CVE rotation inputs or allowlist state are invalid (fail closed)."""


def _require_hex(value: str, *, bits: int, label: str) -> str:
    expected = bits // 4
    text = value.strip().lower()
    if len(text) != expected or any(ch not in "0123456789abcdef" for ch in text):
        raise CveRotationError(f"{label} must be a {expected}-char lowercase hex string")
    return text


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha384_hex(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def _canonical_materials(materials: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(materials, Mapping):
        raise CveRotationError("materials must be a mapping")
    unknown = sorted(set(materials) - set(MEASUREMENT_MATERIAL_KEYS))
    if unknown:
        raise CveRotationError(f"unknown measurement material keys: {unknown}")
    normalized: dict[str, str] = {}
    for key in MEASUREMENT_MATERIAL_KEYS:
        raw = materials.get(key, "")
        if key in REQUIRED_MATERIALS:
            if not isinstance(raw, str) or not raw.strip():
                raise CveRotationError(f"materials.{key} must be a non-empty string")
        if raw is None:
            value = ""
        elif not isinstance(raw, str):
            raise CveRotationError(f"materials.{key} must be a string")
        else:
            value = raw.strip()
        if key in {
            "runtime_image_digest",
            "builder_image_digest",
            "application_source_digest",
            "compose_spec_digest",
            "os_image_hash",
        } and value:
            # Digests may be written as sha256:<hex> or bare hex.
            if value.startswith("sha256:"):
                value = value.removeprefix("sha256:")
            value = _require_hex(value, bits=256, label=f"materials.{key}")
        normalized[key] = value
    if not normalized["cve_patch_id"]:
        normalized["cve_patch_id"] = "none"
    if not normalized["rust_version"]:
        normalized["rust_version"] = DEFAULT_RUST_VERSION
    if not normalized["source_date_epoch"]:
        normalized["source_date_epoch"] = DEFAULT_SOURCE_DATE_EPOCH
    if not normalized["chromium_version"]:
        normalized["chromium_version"] = DEFAULT_CHROMIUM_VERSION
    if not normalized["builder_image_digest"]:
        # Builder may be omitted when only the runtime Chromium/OS surface changes.
        normalized["builder_image_digest"] = "0" * 64
    return normalized


def materials_fingerprint(materials: Mapping[str, Any]) -> str:
    """Stable SHA-256 over the canonical material dict (sorted JSON)."""

    canon = _canonical_materials(materials)
    payload = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_hex(payload)


def derive_measurement(materials: Mapping[str, Any]) -> dict[str, str]:
    """Derive a deterministic six-field measurement from pinnable TCB materials.

    The derivation is intentionally pure and offline-friendly: it does not call
    Docker or Phala. Production operators still measure with ``dstack-mr`` after
    a real rebuild; this function models the contractual property that two
    builds of the same pinned source yield the same measurement, and that a
    CVE-driven material change yields a new measurement.
    """

    canon = _canonical_materials(materials)
    root = materials_fingerprint(canon).encode("utf-8")

    def domain(tag: str, *parts: str) -> bytes:
        joined = "|".join((tag, *parts, root.decode("utf-8")))
        return joined.encode("utf-8")

    # Registers are SHA-384 hex (48 bytes) like real MRTD/RTMR values.
    mrtd = _sha384_hex(domain("mrtd", canon["runtime_image_digest"], canon["cve_patch_id"]))
    rtmr0 = _sha384_hex(domain("rtmr0", canon["rtmr0_vm_shape"], canon["source_date_epoch"]))
    rtmr1 = _sha384_hex(
        domain(
            "rtmr1",
            canon["chromium_version"],
            canon["rust_version"],
            canon["application_source_digest"],
        )
    )
    rtmr2 = _sha384_hex(
        domain(
            "rtmr2",
            canon["builder_image_digest"],
            canon["application_source_digest"],
            canon["cve_patch_id"],
        )
    )
    # compose_hash and os_image_hash remain SHA-256-width (64 hex).
    compose_hash = _sha256_hex(
        domain("compose_hash", canon["compose_spec_digest"], canon["cve_patch_id"])
    )
    os_image_hash = canon["os_image_hash"]
    entry = {
        "mrtd": mrtd,
        "rtmr0": rtmr0,
        "rtmr1": rtmr1,
        "rtmr2": rtmr2,
        "compose_hash": compose_hash,
        "os_image_hash": os_image_hash,
    }
    for field in CANONICAL_FIELDS:
        if field not in entry or not entry[field]:
            raise CveRotationError(f"derived measurement missing {field}")
    return entry


def measurements_equal(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    try:
        return allowlist_contains(a, [b])
    except MeasurementAllowlistError:
        return False


def assert_reproducible_pair(
    materials_a: Mapping[str, Any],
    materials_b: Mapping[str, Any],
) -> dict[str, str]:
    """Two builds of the same source/materials must yield the same measurement."""

    a = derive_measurement(materials_a)
    b = derive_measurement(materials_b)
    if a != b:
        raise CveRotationError(
            "rebuild is non-reproducible: measurements of identical materials differ"
        )
    return a


def assert_cve_patch_rotates_measurement(
    vulnerable: Mapping[str, Any],
    patched: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    """A CVE patch must change the digest-pinned measurement identity."""

    old = derive_measurement(vulnerable)
    new = derive_measurement(patched)
    if old == new:
        raise CveRotationError(
            "CVE patch did not change the measurement; missing material pin change"
        )
    return old, new


def _validate_entry(entry: Mapping[str, Any], *, label: str) -> dict[str, str]:
    if not isinstance(entry, Mapping):
        raise CveRotationError(f"{label} must be an object")
    out: dict[str, str] = {}
    missing = [field for field in CANONICAL_FIELDS if field not in entry]
    if missing:
        raise CveRotationError(f"{label} missing fields: {', '.join(missing)}")
    for field in CANONICAL_FIELDS:
        value = entry[field]
        if not isinstance(value, str) or not value.strip():
            raise CveRotationError(f"{label}.{field} must be a non-empty string")
        bits = 384 if field in {"mrtd", "rtmr0", "rtmr1", "rtmr2"} else 256
        out[field] = _require_hex(value, bits=bits, label=f"{label}.{field}")
    return out


def _entry_key(entry: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(entry[field] for field in CANONICAL_FIELDS)


def atomic_write_json(path: Path | str, payload: Any) -> None:
    """Write JSON atomically (temp file + os.replace on the same filesystem)."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, destination)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_rotate_allowlist(
    path: Path | str,
    *,
    new_entry: Mapping[str, Any],
    retire: Iterable[Mapping[str, Any]] = (),
    allow_dual_pin: bool = False,
) -> list[dict[str, str]]:
    """Atomically pin ``new_entry`` and remove every retired entry.

    Default policy (``allow_dual_pin=False``): the resulting allowlist for the
    six-field image allowlist is **exactly** ``[new_entry]`` after also
    stripping any retired / prior vulnerable identities. This never
    default-accepts both the vulnerable and the patched measurement
    indefinitely.

    When ``allow_dual_pin=True`` (explicit operator override only), non-retired
    prior entries that are not the new entry may be retained, but every
    ``retire`` entry is still removed in the same atomic write.
    """

    destination = Path(path)
    pinned = _validate_entry(new_entry, label="new_entry")
    retired = [_validate_entry(item, label="retire") for item in retire]
    retired_keys = {_entry_key(item) for item in retired}
    retired_keys.add(_entry_key(pinned))  # de-dupe self

    existing: list[dict[str, str]] = []
    if destination.is_file():
        try:
            existing = load_allowlist(destination)
        except MeasurementAllowlistError as exc:
            raise CveRotationError(str(exc)) from exc

    if allow_dual_pin:
        retained = [
            entry
            for entry in existing
            if _entry_key(entry) not in retired_keys and _entry_key(entry) != _entry_key(pinned)
        ]
        result = [pinned, *retained]
    else:
        # Atomic rotation: new pinned, retired removed, no indefinite dual-accept.
        result = [pinned]

    # Always re-confirm retired identities are absent.
    for item in retired:
        if allowlist_contains(item, result):
            raise CveRotationError(
                "retired measurement still present after rotation (fail closed)"
            )
    if not allowlist_contains(pinned, result):
        raise CveRotationError("new measurement missing after rotation (fail closed)")

    atomic_write_json(destination, result)
    return result


def simulate_cve_rebuild_and_rotate(
    allowlist_path: Path | str,
    *,
    vulnerable_materials: Mapping[str, Any],
    patched_materials: Mapping[str, Any],
) -> dict[str, Any]:
    """End-to-end offline simulation of VAL-HARDEN-024.

    1. Measure vulnerable materials and seed the allowlist with that entry.
    2. Measure patched materials twice (repro check) to get the new pin.
    3. Atomically rotate: pin new, retire vulnerable.
    4. Return both measurements and post-rotation membership results.
    """

    vulnerable_meas = derive_measurement(vulnerable_materials)
    # Seed allowlist with the currently allowlisted (soon-to-be-retired) entry.
    atomic_write_json(allowlist_path, [vulnerable_meas])

    # Two independent rebuilds of the patched materials must agree.
    m1 = derive_measurement(patched_materials)
    m2 = derive_measurement(patched_materials)
    if m1 != m2:
        raise CveRotationError("patched rebuild is non-reproducible")
    if m1 == vulnerable_meas:
        raise CveRotationError("CVE patch did not yield a new measurement")

    after = atomic_rotate_allowlist(
        allowlist_path,
        new_entry=m1,
        retire=[vulnerable_meas],
        allow_dual_pin=False,
    )
    loaded = load_allowlist(allowlist_path)
    return {
        "vulnerable_measurement": vulnerable_meas,
        "new_measurement": m1,
        "allowlist_after": after,
        "loaded_after": loaded,
        "retired_allowlisted": allowlist_contains(vulnerable_meas, loaded),
        "new_allowlisted": allowlist_contains(m1, loaded),
        "dual_accept": (
            allowlist_contains(vulnerable_meas, loaded)
            and allowlist_contains(m1, loaded)
            and len(loaded) > 1
        ),
    }


def default_materials(*, cve_patch_id: str = "none") -> dict[str, str]:
    """Baseline materials matching the minimized documented TCB pins."""

    return {
        "chromium_version": DEFAULT_CHROMIUM_VERSION,
        "runtime_image_digest": (
            "59818936eb9768ba3c1681441ec62e8aacaa67c074e2573bd66bf78a065b31e1"
        ),
        "builder_image_digest": (
            "c993d32d95cc146bd12c84d66f0b924a6a96f3988325f39c144f2f9893dea120"
        ),
        "rust_version": DEFAULT_RUST_VERSION,
        "source_date_epoch": DEFAULT_SOURCE_DATE_EPOCH,
        "application_source_digest": _sha256_hex(b"basecrawl-source-v1"),
        "compose_spec_digest": _sha256_hex(b"basecrawl-compose-v1"),
        "os_image_hash": DEFAULT_OS_IMAGE_HASH,
        "rtmr0_vm_shape": DEFAULT_RTMR0_VM_SHAPE,
        "cve_patch_id": cve_patch_id,
    }


def _load_json_mapping(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CveRotationError(f"failed to load {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise CveRotationError(f"{path} must contain a JSON object")
    return dict(data)


def _cmd_measure(args: argparse.Namespace) -> int:
    materials = _load_json_mapping(Path(args.materials)) if args.materials else default_materials(
        cve_patch_id=args.cve_patch_id or "none"
    )
    if args.cve_patch_id:
        materials = {**materials, "cve_patch_id": args.cve_patch_id}
    measurement = derive_measurement(materials)
    print(json.dumps(measurement, indent=2, sort_keys=True))
    return 0


def _cmd_rebuild_check(args: argparse.Namespace) -> int:
    a = _load_json_mapping(Path(args.materials_a))
    b = _load_json_mapping(Path(args.materials_b))
    measurement = assert_reproducible_pair(a, b)
    print(json.dumps({"status": "reproducible", "measurement": measurement}, indent=2))
    return 0


def _cmd_rotate(args: argparse.Namespace) -> int:
    new_entry = _load_json_mapping(Path(args.new_entry))
    retire: list[Mapping[str, Any]] = []
    if args.retire_entry:
        retire.append(_load_json_mapping(Path(args.retire_entry)))
    result = atomic_rotate_allowlist(
        args.allowlist,
        new_entry=new_entry,
        retire=retire,
        allow_dual_pin=bool(args.allow_dual_pin),
    )
    print(json.dumps({"status": "rotated", "entries": result}, indent=2))
    return 0


def _cmd_verify_rotation(args: argparse.Namespace) -> int:
    retired = _load_json_mapping(Path(args.before))
    new = _load_json_mapping(Path(args.after))
    entries = load_allowlist(args.allowlist)
    retired_ok = not allowlist_contains(retired, entries)
    new_ok = allowlist_contains(new, entries)
    payload = {
        "retired_rejected": retired_ok,
        "new_allowlisted": new_ok,
        "status": "pass" if retired_ok and new_ok else "fail",
    }
    print(json.dumps(payload, indent=2))
    return 0 if payload["status"] == "pass" else 1


def _cmd_simulate(args: argparse.Namespace) -> int:
    vulnerable = default_materials(cve_patch_id="none")
    patched = default_materials(cve_patch_id=args.cve_patch_id or "CVE-2026-0001")
    # Apply a material pin change for the Chromium surface as a real patch would.
    if args.patched_chromium:
        patched["chromium_version"] = args.patched_chromium
    if args.patched_runtime_digest:
        digest = args.patched_runtime_digest.removeprefix("sha256:")
        patched["runtime_image_digest"] = digest
    report = simulate_cve_rebuild_and_rotate(
        args.allowlist,
        vulnerable_materials=vulnerable,
        patched_materials=patched,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["retired_allowlisted"] or not report["new_allowlisted"] or report["dual_accept"]:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    measure = sub.add_parser("measure", help="Derive a deterministic measurement")
    measure.add_argument("--materials", help="JSON mapping of pinnable materials")
    measure.add_argument("--cve-patch-id", default="")
    measure.set_defaults(func=_cmd_measure)

    rebuild = sub.add_parser(
        "rebuild-check",
        help="Assert two material sets produce the same measurement",
    )
    rebuild.add_argument("--materials-a", required=True)
    rebuild.add_argument("--materials-b", required=True)
    rebuild.set_defaults(func=_cmd_rebuild_check)

    rotate = sub.add_parser("rotate", help="Atomically pin new + retire measurements")
    rotate.add_argument("--allowlist", required=True)
    rotate.add_argument("--new-entry", required=True)
    rotate.add_argument("--retire-entry", default="")
    rotate.add_argument(
        "--allow-dual-pin",
        action="store_true",
        help="Explicit override only; default rotation never dual-accepts",
    )
    rotate.set_defaults(func=_cmd_rotate)

    verify = sub.add_parser(
        "verify-rotation",
        help="Check retired is absent and new is present in allowlist",
    )
    verify.add_argument("--before", required=True, help="Retired measurement JSON")
    verify.add_argument("--after", required=True, help="New measurement JSON")
    verify.add_argument("--allowlist", required=True)
    verify.set_defaults(func=_cmd_verify_rotation)

    simulate = sub.add_parser(
        "simulate",
        help="Offline CVE rebuild + atomic rotation simulation",
    )
    simulate.add_argument("--allowlist", required=True)
    simulate.add_argument("--cve-patch-id", default="CVE-2026-0001")
    simulate.add_argument("--patched-chromium", default="145.0.7632.99")
    simulate.add_argument("--patched-runtime-digest", default="")
    simulate.set_defaults(func=_cmd_simulate)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (CveRotationError, MeasurementAllowlistError) as exc:
        print(f"cve_rotation error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
