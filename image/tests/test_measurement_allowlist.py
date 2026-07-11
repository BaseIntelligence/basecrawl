from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

# ruff: noqa: E402

IMAGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGE_DIR))

import measurement_allowlist as measurements


ALLOWLIST_PATH = IMAGE_DIR / "allowlist.json"
APP_COMPOSE_PATH = IMAGE_DIR / "phala-app-compose.json"
RECONCILIATION_PATH = IMAGE_DIR / "measurement-reconciliation.json"


class MeasurementAllowlistTests(unittest.TestCase):
    def test_allowlist_is_the_exact_six_field_live_tuple(self) -> None:
        entries = measurements.load_allowlist(ALLOWLIST_PATH)
        self.assertEqual(len(entries), 1)
        self.assertEqual(
            set(entries[0]),
            {"mrtd", "rtmr0", "rtmr1", "rtmr2", "compose_hash", "os_image_hash"},
        )
        self.assertTrue(measurements.allowlist_contains(entries[0], entries))

    def test_every_pinned_field_drift_denies(self) -> None:
        entry = measurements.load_allowlist(ALLOWLIST_PATH)[0]
        for field in entry:
            with self.subTest(field=field):
                candidate = copy.deepcopy(entry)
                candidate[field] = "0" * len(candidate[field])
                self.assertFalse(measurements.allowlist_contains(candidate, [entry]))

    def test_phala_app_compose_hash_is_the_allowlisted_compose_hash(self) -> None:
        entry = measurements.load_allowlist(ALLOWLIST_PATH)[0]
        self.assertEqual(
            measurements.phala_app_compose_hash(APP_COMPOSE_PATH),
            entry["compose_hash"],
        )

    def test_phala_normalization_ignores_nulls_and_order_but_not_content(self) -> None:
        source = {"z": {"b": 2, "a": 1}, "null_value": None, "list": [3, 2, 1]}
        reordered = json.dumps(
            {"list": [3, 2, 1], "z": {"a": 1, "b": 2}, "null_value": None},
            indent=2,
        )
        self.assertEqual(
            measurements.phala_app_compose_hash(source),
            measurements.phala_app_compose_hash(reordered),
        )
        changed = copy.deepcopy(source)
        changed["z"]["a"] = 9
        self.assertNotEqual(
            measurements.phala_app_compose_hash(source),
            measurements.phala_app_compose_hash(changed),
        )

    def test_reconciliation_record_is_complete_and_reconciled(self) -> None:
        result = measurements.validate_reconciliation(
            RECONCILIATION_PATH,
            allowlist_path=ALLOWLIST_PATH,
            app_compose_path=APP_COMPOSE_PATH,
        )
        self.assertEqual(result["status"], "reconciled")
        self.assertEqual(
            result["canonical_measurement"]["compose_hash"],
            "ac95f779827adb9a8f10b45fa0906e37b31148e6ea1e69e703b9afde13321104",
        )

    def test_missing_reconciliation_artifact_fails_closed(self) -> None:
        with self.assertRaises(measurements.MeasurementAllowlistError):
            measurements.validate_reconciliation(
                RECONCILIATION_PATH.with_name("does-not-exist.json"),
                allowlist_path=ALLOWLIST_PATH,
                app_compose_path=APP_COMPOSE_PATH,
            )


if __name__ == "__main__":
    unittest.main()
