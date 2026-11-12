#!/usr/bin/env python3
"""Unit tests for tools/derive_metrics.py."""

from __future__ import annotations

import csv
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Allow running this file directly from inside tools/.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from tools.derive_metrics import main


SCRATCH_ROOT = Path(os.environ.get("TEMP", os.getcwd())) / "opencode" / "derive_metrics_tests"
ANALYSIS_PATH = Path(_PROJECT_ROOT) / "data" / "analysis.json"


def make_cells(rows: int, cols: int, offset: float = 0.0, z_override: dict | None = None):
    """Build a V-fastest cell list.  u increases with cols, v increases with rows."""
    z_override = z_override or {}
    cells = []
    for idx in range(rows * cols):
        iu = idx // rows
        iv = idx % rows
        u = -cols + 1 + 2 * iu + offset  # simple increasing integers
        v = -rows + 1 + 2 * iv + offset
        cell = {
            "u": float(u),
            "v": float(v),
            "id_x": float(iu),
            "id_y": float(iv),
            "red": [1.0 + u, 2.0 + v, 10.0],
            "green": [1.5 + u, 2.5 + v, 20.0],
            "blue": [2.0 + u, 3.0 + v, 30.0],
        }
        if (iu, iv, "red") in z_override:
            cell["red"][2] = 0.0
        cells.append(cell)
    return cells


def build_analysis(profiles: dict) -> dict:
    data = {"schema_version": 1, "profiles": {}}
    for pname, pdata in profiles.items():
        data["profiles"][pname] = {}
        for eye, eye_data in pdata.items():
            data["profiles"][pname][eye] = {
                "rows": eye_data["rows"],
                "cols": eye_data["cols"],
                "width_px": eye_data["cols"] * 48,
                "height_px": eye_data["rows"] * 48,
                "ipd_mm": 62.0,
                "cells": eye_data["cells"],
            }
    return data


def run_cli(analysis_path: Path, out_dir: Path, *, profile: str = "both", eye: str = "both"):
    """Run derive_metrics main and return its exit code."""
    try:
        return main([
            "--analysis", str(analysis_path),
            "--out", str(out_dir),
            "--profile", profile,
            "--eye", eye,
        ])
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1


class TestDeriveMetrics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=str(SCRATCH_ROOT)))

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    @classmethod
    def tearDownClass(cls):
        # Keep the top-level scratch dir but nuke per-test dirs; also clean pycache.
        pycache = Path(_PROJECT_ROOT) / "tools" / "__pycache__"
        if pycache.exists():
            shutil.rmtree(pycache)

    def _write_analysis(self, data: dict) -> Path:
        path = self.tmp / "analysis.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return path

    def test_non_square_v_fastest(self):
        rows, cols = 2, 3
        cells = make_cells(rows, cols)
        data = build_analysis({"factory": {"left": {"rows": rows, "cols": cols, "cells": cells}}})
        analysis_path = self._write_analysis(data)
        out_dir = self.tmp / "out"
        code = run_cli(analysis_path, out_dir, profile="factory", eye="left")
        self.assertEqual(code, 0)

        csv_path = out_dir / "left_factory_cells.csv"
        self.assertTrue(csv_path.exists())
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows_read = list(reader)
        self.assertEqual(len(rows_read), rows * cols)

        ius = {int(r["iu"]) for r in rows_read}
        ivs = {int(r["iv"]) for r in rows_read}
        us = {float(r["u"]) for r in rows_read}
        vs = {float(r["v"]) for r in rows_read}
        self.assertEqual(ius, set(range(cols)))
        self.assertEqual(ivs, set(range(rows)))
        self.assertEqual(len(us), cols)
        self.assertEqual(len(vs), rows)

        with open(out_dir / "summary.json", encoding="utf-8") as fh:
            summary = json.load(fh)
        gv = summary["results"]["left"]["factory"]["grid_validation"]
        self.assertTrue(gv["cell_count_ok"])
        self.assertTrue(gv["unique_counts_ok"])
        self.assertEqual(gv["duplicate_uv_pairs"], 0)
        self.assertTrue(gv["ordering_ok"])

    def test_z_zero_handling(self):
        cells = make_cells(2, 2, z_override={(0, 0, "red")})
        data = build_analysis({"factory": {"left": {"rows": 2, "cols": 2, "cells": cells}}})
        analysis_path = self._write_analysis(data)
        out_dir = self.tmp / "out"
        code = run_cli(analysis_path, out_dir, profile="factory", eye="left")
        self.assertEqual(code, 0)

        csv_path = out_dir / "left_factory_cells.csv"
        with open(csv_path, newline="", encoding="utf-8") as fh:
            text = fh.read()
        lowered = text.lower()
        self.assertNotIn("inf", lowered)
        self.assertNotIn("nan", lowered)

        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            singularity_rows = [
                r for r in reader
                if r["red_rx"] == "" and r["red_ry"] == "" and r["red_ratio_mag"] == ""
            ]
        self.assertEqual(len(singularity_rows), 1)

        with open(out_dir / "summary.json", encoding="utf-8") as fh:
            summary = json.load(fh)
        self.assertEqual(summary["results"]["left"]["factory"]["singularity_count"], 1)

    def test_identical_factory_vendor_delta_zero(self):
        cells = make_cells(2, 2)
        data = build_analysis({
            "factory": {"left": {"rows": 2, "cols": 2, "cells": cells}},
            "vendor": {"left": {"rows": 2, "cols": 2, "cells": [dict(c) for c in cells]}},
        })
        analysis_path = self._write_analysis(data)
        out_dir = self.tmp / "out"
        code = run_cli(analysis_path, out_dir, eye="left")
        self.assertEqual(code, 0)

        with open(out_dir / "summary.json", encoding="utf-8") as fh:
            summary = json.load(fh)
        delta = summary["factory_vendor_delta"]["left"]
        for ch in ("red", "green", "blue"):
            self.assertAlmostEqual(delta[ch]["raw_xyz_euclidean"]["rms"], 0.0, places=10)
            self.assertEqual(delta[ch]["raw_xyz_euclidean"]["max"], 0.0)
            self.assertEqual(delta[ch]["raw_xyz_euclidean"]["median"], 0.0)
            self.assertAlmostEqual(delta[ch]["ratio_magnitude_delta"]["rms"], 0.0, places=10)
            self.assertEqual(delta[ch]["ratio_magnitude_delta"]["max"], 0.0)
            self.assertEqual(delta[ch]["ratio_magnitude_delta"]["median"], 0.0)

    def test_mismatched_uv_rejected(self):
        factory_cells = make_cells(2, 2)
        vendor_cells = make_cells(2, 2, offset=10.0)
        data = build_analysis({
            "factory": {"left": {"rows": 2, "cols": 2, "cells": factory_cells}},
            "vendor": {"left": {"rows": 2, "cols": 2, "cells": vendor_cells}},
        })
        analysis_path = self._write_analysis(data)
        out_dir = self.tmp / "out"
        code = run_cli(analysis_path, out_dir, eye="left")
        self.assertNotEqual(code, 0)
        self.assertFalse((out_dir / "summary.json").exists())

    def test_refuses_overwrite(self):
        cells = make_cells(2, 2)
        data = build_analysis({"factory": {"left": {"rows": 2, "cols": 2, "cells": cells}}})
        analysis_path = self._write_analysis(data)
        out_dir = self.tmp / "out"
        out_dir.mkdir()
        protected = out_dir / "left_factory_cells.csv"
        protected.write_text("do not overwrite", encoding="utf-8")
        code = run_cli(analysis_path, out_dir, profile="factory", eye="left")
        self.assertNotEqual(code, 0)
        self.assertEqual(protected.read_text(encoding="utf-8"), "do not overwrite")

    def test_real_data_smoke(self):
        if not ANALYSIS_PATH.exists():
            self.skipTest("real analysis.json not present")
        out_dir = self.tmp / "real"
        code = run_cli(ANALYSIS_PATH, out_dir)
        self.assertEqual(code, 0)

        expected = [
            "left_factory_cells.csv",
            "left_vendor_cells.csv",
            "right_factory_cells.csv",
            "right_vendor_cells.csv",
        ]
        for name in expected:
            path = out_dir / name
            self.assertTrue(path.exists(), f"missing {name}")
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.reader(fh)
                rows = list(reader)
            self.assertEqual(len(rows), 5768, f"{name} should have header + 5767 data lines")

        summary_path = out_dir / "summary.json"
        self.assertTrue(summary_path.exists())
        with open(summary_path, encoding="utf-8") as fh:
            summary = json.load(fh)

        # Attach numbers to the test so the test runner can report them.
        for eye in ("left", "right"):
            for profile in ("factory", "vendor"):
                block = summary["results"][eye][profile]
                for ch in ("red", "green", "blue"):
                    ang = block["channels"][ch]["angle_pinhole_deg"]
                    self.assertIsNotNone(ang["min"])
                    self.assertIsNotNone(ang["max"])
        self._real_summary = summary

    @classmethod
    def suite(cls):
        return unittest.TestLoader().loadTestsFromTestCase(cls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
