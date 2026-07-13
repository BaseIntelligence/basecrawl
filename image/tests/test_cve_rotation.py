"""CVE image rotation: VAL-HARDEN-021 / VAL-HARDEN-024.

Offline, deterministic coverage for:

* minimized TCB materials → deterministic measurement identity
* two builds of the same source yield the same measurement
* a CVE patch yields a new measurement
* atomic allowlist rotation pins the new entry and removes the retired one
* post-rotation membership: retired absent, new present (never dual-accept default)
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# ruff: noqa: E402

IMAGE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = IMAGE_DIR.parent
sys.path.insert(0, str(IMAGE_DIR))

import cve_rotation as rot  # noqa: E402
import measurement_allowlist as measurements  # noqa: E402


class DeterministicRebuildTests(unittest.TestCase):
    def test_two_builds_of_same_materials_yield_same_measurement(self) -> None:
        materials = rot.default_materials(cve_patch_id="none")
        left = rot.derive_measurement(materials)
        right = rot.derive_measurement(dict(materials))
        self.assertEqual(left, right)
        # All six canonical fields present and well-formed.
        for field in measurements.CANONICAL_FIELDS:
            self.assertIn(field, left)
            self.assertTrue(left[field])

    def test_assert_reproducible_pair_accepts_identical_materials(self) -> None:
        materials = rot.default_materials()
        shared = rot.assert_reproducible_pair(materials, materials)
        self.assertEqual(shared, rot.derive_measurement(materials))

    def test_cve_patch_changes_measurement(self) -> None:
        vulnerable = rot.default_materials(cve_patch_id="none")
        patched = rot.default_materials(cve_patch_id="CVE-2026-0001")
        patched["chromium_version"] = "145.0.7632.99"
        patched["runtime_image_digest"] = "a" * 64
        old, new = rot.assert_cve_patch_rotates_measurement(vulnerable, patched)
        self.assertNotEqual(old, new)
        self.assertEqual(old["os_image_hash"], new["os_image_hash"])

    def test_cve_patch_without_material_change_fails_closed(self) -> None:
        base = rot.default_materials(cve_patch_id="none")
        # cve_patch_id alone is a material; set both identical to prove the check.
        with self.assertRaises(rot.CveRotationError):
            rot.assert_cve_patch_rotates_measurement(base, dict(base))


class AtomicAllowlistRotationTests(unittest.TestCase):
    def test_atomic_rotate_pins_new_and_removes_retired(self) -> None:
        vulnerable = rot.derive_measurement(rot.default_materials(cve_patch_id="none"))
        patched_materials = rot.default_materials(cve_patch_id="CVE-2026-0001")
        patched_materials["chromium_version"] = "145.0.7632.99"
        new = rot.derive_measurement(patched_materials)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "allowlist.json"
            path.write_text(json.dumps([vulnerable]), encoding="utf-8")
            after = rot.atomic_rotate_allowlist(
                path,
                new_entry=new,
                retire=[vulnerable],
                allow_dual_pin=False,
            )
            self.assertEqual(after, [new])
            loaded = measurements.load_allowlist(path)
            self.assertEqual(loaded, [new])
            self.assertTrue(measurements.allowlist_contains(new, loaded))
            self.assertFalse(measurements.allowlist_contains(vulnerable, loaded))

    def test_default_rotation_never_dual_accepts_indefinitely(self) -> None:
        vulnerable = rot.derive_measurement(rot.default_materials(cve_patch_id="none"))
        other = rot.derive_measurement(
            {
                **rot.default_materials(),
                "application_source_digest": "b" * 64,
            }
        )
        patched_materials = rot.default_materials(cve_patch_id="CVE-2026-0002")
        patched_materials["chromium_version"] = "145.0.7632.100"
        new = rot.derive_measurement(patched_materials)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "allowlist.json"
            # Pre-state with two entries that might tempt a dual-open window.
            path.write_text(json.dumps([vulnerable, other]), encoding="utf-8")
            after = rot.atomic_rotate_allowlist(
                path,
                new_entry=new,
                retire=[vulnerable],
                allow_dual_pin=False,
            )
            self.assertEqual(len(after), 1)
            self.assertEqual(after[0], new)
            self.assertFalse(measurements.allowlist_contains(vulnerable, after))
            self.assertFalse(measurements.allowlist_contains(other, after))

    def test_simulate_end_to_end_cve_rotation(self) -> None:
        vulnerable = rot.default_materials(cve_patch_id="none")
        patched = rot.default_materials(cve_patch_id="CVE-2026-0001")
        patched["chromium_version"] = "145.0.7632.99"
        patched["runtime_image_digest"] = "c" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "allowlist.json"
            report = rot.simulate_cve_rebuild_and_rotate(
                path,
                vulnerable_materials=vulnerable,
                patched_materials=patched,
            )
            self.assertFalse(report["retired_allowlisted"])
            self.assertTrue(report["new_allowlisted"])
            self.assertFalse(report["dual_accept"])
            self.assertNotEqual(
                report["vulnerable_measurement"],
                report["new_measurement"],
            )

    def test_atomic_write_replaces_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "out.json"
            rot.atomic_write_json(path, [{"ok": True}])
            self.assertTrue(path.is_file())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data, [{"ok": True}])


class TcbDocumentationTests(unittest.TestCase):
    def test_tcb_inventory_and_rotation_runbook_exist(self) -> None:
        inventory = REPO_ROOT / "docs" / "tcb-inventory.md"
        runbook = REPO_ROOT / "docs" / "image-rotation-on-cve.md"
        self.assertTrue(inventory.is_file(), "docs/tcb-inventory.md missing")
        self.assertTrue(runbook.is_file(), "docs/image-rotation-on-cve.md missing")
        inventory_text = inventory.read_text(encoding="utf-8")
        runbook_text = runbook.read_text(encoding="utf-8")
        # Minimized TCB: pinned Chromium + OS, no floating tags / unpinned toolchains.
        for needle in (
            "CHROMIUM_VERSION",
            "digest-pinned",
            "playwright install --with-deps",
            "floating",
            "measured-but-exploited",
            "replay-audit",
        ):
            self.assertIn(needle, inventory_text)
        # Concrete rotation runbook steps + residual statement.
        for needle in (
            "image-rotation-on-CVE",
            "atomic",
            "measurement_not_allowlisted",
            "replay-audit",
            "measured-but-exploited",
            "never default-accept",
        ):
            self.assertIn(needle, runbook_text)

    def test_dockerfile_reflects_minimized_tcb_pins(self) -> None:
        text = (IMAGE_DIR / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("CHROMIUM_VERSION=145.0.7632.46", text)
        self.assertIn("@sha256:", text)
        self.assertIn("cargo build --release --locked", text)
        self.assertNotIn("playwright install --with-deps", text.lower())


if __name__ == "__main__":
    unittest.main()
