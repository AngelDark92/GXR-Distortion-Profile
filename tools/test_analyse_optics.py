#!/usr/bin/env python3
"""Unit tests for analyse_optics.py using compact 2x2 fixtures.

Run with:
    python -m unittest test_analyse_optics -v
Assumes python3.13+ and that analyse_optics.py sits beside this file.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

import analyse_optics as ao


COMPACT_ROWS = 2
COMPACT_COLS = 2
COMPACT_WIDTH = 4.0
COMPACT_HEIGHT = 4.0
COMPACT_IPD = 60.0


def _cell(u: float, v: float, rx: float, ry: float, rz: float,
          gx: float, gy: float, gz: float,
          bx: float, by: float, bz: float,
          id_x: int | None = None, id_y: int | None = None) -> Dict[str, Any]:
    c: Dict[str, Any] = {
        "u": u, "v": v,
        "red_x": rx, "red_y": ry, "red_z": rz,
        "green_x": gx, "green_y": gy, "green_z": gz,
        "blue_x": bx, "blue_y": by, "blue_z": bz,
    }
    if id_x is not None:
        c["id_x"] = id_x
    if id_y is not None:
        c["id_y"] = id_y
    return c


def _lut_block_textproto(cells: List[Dict[str, Any]]) -> str:
    lines = ["      luts {"]
    for c in cells:
        lines.append("        cells {")
        for k, v in c.items():
            if isinstance(v, float):
                if math.isinf(v):
                    lines.append(f"          {k}: inf")
                elif math.isnan(v):
                    lines.append(f"          {k}: nan")
                else:
                    lines.append(f"          {k}: {v}")
            else:
                lines.append(f"          {k}: {v}")
        lines.append("        }")
    lines.append("      }")
    return "\n".join(lines)


def _eye_textproto(rows: int, cols: int, width: float, height: float, ipd: float,
                   cells: List[Dict[str, Any]], extra_empty_lut: bool = False,
                   extra_populated_lut: bool = False, include_right: bool = True) -> str:
    lines = [
        "    left_display_profile {",
        f"      lut_rows: {rows}",
        f"      lut_cols: {cols}",
        f"      calibrated_width_px: {width}",
        f"      calibrated_height_px: {height}",
        f"      device_ipd_in_mm: {ipd}",
    ]
    lines.append(_lut_block_textproto(cells))
    if extra_empty_lut:
        lines.append("      luts { } // intentionally empty")
    if extra_populated_lut:
        # Extra populated block with different values to trigger ambiguity.
        dup = []
        for c in cells:
            cc = dict(c)
            cc["red_x"] = c["red_x"] + 10.0
            dup.append(cc)
        lines.append(_lut_block_textproto(dup))
    lines.append("    }")
    if not include_right:
        return "\n".join(lines)
    # Mirror right eye with identical grid and a tiny offset.
    right_cells = []
    for c in cells:
        rc = dict(c)
        rc["red_x"] = c["red_x"] + 0.01
        rc["green_x"] = c["green_x"] + 0.01
        rc["blue_x"] = c["blue_x"] + 0.01
        right_cells.append(rc)
    lines.append("    right_display_profile {")
    lines.append(f"      lut_rows: {rows}")
    lines.append(f"      lut_cols: {cols}")
    lines.append(f"      calibrated_width_px: {width}")
    lines.append(f"      calibrated_height_px: {height}")
    lines.append(f"      device_ipd_in_mm: {ipd}")
    lines.append(_lut_block_textproto(right_cells))
    if extra_empty_lut:
        lines.append("      luts { } // intentionally empty")
    lines.append("    }")
    return "\n".join(lines)


def _profile_textproto(eye_block: str) -> str:
    # Capture files must contain only the optical block, no extra top-level fields.
    return f"""display_profile_v2 {{
{eye_block}
}}
"""


def _manifest_textproto(factory_path: Path, vendor_path: Path) -> str:
    _, fac_block_hash, fac_source_hash = ao.extract_optical_block_hashes(factory_path)
    _, ven_block_hash, ven_source_hash = ao.extract_optical_block_hashes(vendor_path)
    return f"""display_only: true
failures: []
factory_path: {json.dumps(str(factory_path.resolve()))}
factory_original_path: "/mnt/vendor/efs/device_profile.textproto"
factory_sha256: {json.dumps(fac_source_hash)}
factory_block_sha256: {json.dumps(fac_block_hash)}
vendor_path: {json.dumps(str(vendor_path.resolve()))}
vendor_original_path: "/vendor/etc/calibration_service/device_profile.textproto"
vendor_sha256: {json.dumps(ven_source_hash)}
vendor_block_sha256: {json.dumps(ven_block_hash)}
"""


def _run_cli(tmp: Path, factory: Path, vendor: Path, manifest: Path,
             extra_args: List[str] | None = None) -> subprocess.CompletedProcess:
    out = tmp / "analysis.json"
    cmd = [
        sys.executable, str(Path(__file__).with_name("analyse_optics.py")),
        "--factory", str(factory),
        "--vendor", str(vendor),
        "--manifest", str(manifest),
        "--output", str(out),
    ]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(cmd, capture_output=True, text=True)


class TestAnalyseOptics(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_factory_vendor(self, fac_cells: List[Dict[str, Any]],
                             ven_cells: List[Dict[str, Any]] | None = None,
                             fac_empty: bool = True,
                             ven_empty: bool = False) -> tuple[Path, Path, Path]:
        if ven_cells is None:
            # Vendor same grid, slightly different values.
            ven_cells = []
            for c in fac_cells:
                vc = dict(c)
                vc["red_y"] = c["red_y"] + 0.05
                vc["green_y"] = c["green_y"] + 0.05
                vc["blue_y"] = c["blue_y"] + 0.05
                ven_cells.append(vc)
        eye_fac = _eye_textproto(COMPACT_ROWS, COMPACT_COLS,
                                  COMPACT_WIDTH, COMPACT_HEIGHT, COMPACT_IPD,
                                  fac_cells, extra_empty_lut=fac_empty)
        eye_ven = _eye_textproto(COMPACT_ROWS, COMPACT_COLS,
                                  COMPACT_WIDTH, COMPACT_HEIGHT, COMPACT_IPD,
                                  ven_cells, extra_empty_lut=ven_empty)
        fac_path = self.tmp_path / "factory.textproto"
        ven_path = self.tmp_path / "vendor.textproto"
        fac_path.write_text(_profile_textproto(eye_fac), encoding="utf-8")
        ven_path.write_text(_profile_textproto(eye_ven), encoding="utf-8")
        manifest_path = self.tmp_path / "manifest.textproto"
        manifest_path.write_text(_manifest_textproto(fac_path, ven_path), encoding="utf-8")
        return fac_path, ven_path, manifest_path

    def _load_output(self) -> Dict[str, Any]:
        out = self.tmp_path / "analysis.json"
        return json.loads(out.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # Success cases
    # ------------------------------------------------------------------

    def test_compact_success(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0, 0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0, 1),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0, 1, 0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0, 1, 1),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        result = _run_cli(self.tmp_path, fac, ven, manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load_output()
        self.assertEqual(data["schema_version"], 1)
        expected_blocks = {"factory": 2, "vendor": 1}
        expected_empty = {"factory": 1, "vendor": 0}
        for role in ("factory", "vendor"):
            for eye in ("left", "right"):
                e = data["profiles"][role][eye]
                self.assertEqual(e["rows"], COMPACT_ROWS)
                self.assertEqual(e["cols"], COMPACT_COLS)
                self.assertEqual(e["width_px"], COMPACT_WIDTH)
                self.assertEqual(e["height_px"], COMPACT_HEIGHT)
                self.assertEqual(e["ipd_mm"], COMPACT_IPD)
                self.assertEqual(e["lut_block_count"], expected_blocks[role])
                self.assertEqual(e["empty_lut_blocks"], expected_empty[role])
                self.assertEqual(len(e["cells"]), COMPACT_ROWS * COMPACT_COLS)
        self.assertEqual(
            data["profiles"]["factory"]["left"]["cells"][0]["red"],
            [0.1, 0.2, 0.0]
        )
        comp = data["comparisons"]["left"]
        self.assertEqual(comp["matched_cells"], 4)
        self.assertEqual(comp["mismatched_cells"], 0)
        self.assertGreater(comp["per_channel_euclidean_difference"]["red"]["rms"], 0)

    def test_vendor_single_lut(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells, fac_empty=True, ven_empty=False)
        result = _run_cli(self.tmp_path, fac, ven, manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load_output()
        self.assertEqual(data["profiles"]["vendor"]["left"]["empty_lut_blocks"], 0)
        self.assertEqual(data["profiles"]["vendor"]["left"]["lut_block_count"], 1)

    def test_manifest_json_format(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        # Convert to JSON manifest
        manifest_json = self.tmp_path / "manifest.json"
        manifest_json.write_text(
            json.dumps(ao.load_manifest(manifest)), encoding="utf-8"
        )
        result = _run_cli(self.tmp_path, fac, ven, manifest_json)
        self.assertEqual(result.returncode, 0, result.stderr)

    # ------------------------------------------------------------------
    # Rejection cases
    # ------------------------------------------------------------------

    def test_expect_device_rejects_compact(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        result = _run_cli(self.tmp_path, fac, ven, manifest, ["--expect-device"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expect-device", result.stderr)

    def test_ambiguous_populated_luts_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        eye_fac = _eye_textproto(COMPACT_ROWS, COMPACT_COLS,
                                  COMPACT_WIDTH, COMPACT_HEIGHT, COMPACT_IPD,
                                  cells, extra_empty_lut=False, extra_populated_lut=True)
        eye_ven = _eye_textproto(COMPACT_ROWS, COMPACT_COLS,
                                  COMPACT_WIDTH, COMPACT_HEIGHT, COMPACT_IPD,
                                  cells, extra_empty_lut=False)
        fac_path = self.tmp_path / "factory.textproto"
        ven_path = self.tmp_path / "vendor.textproto"
        fac_path.write_text(_profile_textproto(eye_fac), encoding="utf-8")
        ven_path.write_text(_profile_textproto(eye_ven), encoding="utf-8")
        manifest_path = self.tmp_path / "manifest.textproto"
        manifest_path.write_text(_manifest_textproto(fac_path, ven_path), encoding="utf-8")
        result = _run_cli(self.tmp_path, fac_path, ven_path, manifest_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ambiguous", result.stderr.lower())

    def test_duplicate_uv_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -2, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),  # duplicate
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        result = _run_cli(self.tmp_path, fac, ven, manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stderr.lower())

    def test_nonfinite_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, float('inf'), 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        result = _run_cli(self.tmp_path, fac, ven, manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-finite", result.stderr.lower())

    def test_missing_channel_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            {"u": -1, "v": -1, "red_x": 0.4, "red_y": 0.5, "green_x": 0.6,
             "green_y": 0.7, "green_z": 0.0, "blue_x": 0.8, "blue_y": 0.9, "blue_z": 0.0},
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        result = _run_cli(self.tmp_path, fac, ven, manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing required field", result.stderr)

    def test_missing_eye_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        eye_no_right = _eye_textproto(COMPACT_ROWS, COMPACT_COLS,
                                       COMPACT_WIDTH, COMPACT_HEIGHT, COMPACT_IPD,
                                       cells, include_right=False)
        eye_full = _eye_textproto(COMPACT_ROWS, COMPACT_COLS,
                                   COMPACT_WIDTH, COMPACT_HEIGHT, COMPACT_IPD,
                                   cells)
        fac_path = self.tmp_path / "factory.textproto"
        ven_path = self.tmp_path / "vendor.textproto"
        fac_path.write_text(_profile_textproto(eye_no_right), encoding="utf-8")
        ven_path.write_text(_profile_textproto(eye_full), encoding="utf-8")
        manifest_path = self.tmp_path / "manifest.textproto"
        manifest_path.write_text(_manifest_textproto(fac_path, ven_path), encoding="utf-8")
        result = _run_cli(self.tmp_path, fac_path, ven_path, manifest_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("right_display_profile", result.stderr)

    def test_coordinate_order_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),  # v fastest violated
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        result = _run_cli(self.tmp_path, fac, ven, manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ordering", result.stderr.lower())

    def test_all_empty_luts_rejected(self) -> None:
        eye = _eye_textproto(COMPACT_ROWS, COMPACT_COLS,
                              COMPACT_WIDTH, COMPACT_HEIGHT, COMPACT_IPD,
                              [], extra_empty_lut=False)
        fac_path = self.tmp_path / "factory.textproto"
        ven_path = self.tmp_path / "vendor.textproto"
        fac_path.write_text(_profile_textproto(eye), encoding="utf-8")
        ven_path.write_text(_profile_textproto(eye), encoding="utf-8")
        manifest_path = self.tmp_path / "manifest.textproto"
        manifest_path.write_text(_manifest_textproto(fac_path, ven_path), encoding="utf-8")
        result = _run_cli(self.tmp_path, fac_path, ven_path, manifest_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("empty", result.stderr.lower())

    def test_hash_mismatch_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        # Corrupt the manifest with wrong hashes but keep the correct paths.
        text = (
            "display_only: true\n"
            "failures: []\n"
            f"factory_path: {json.dumps(str(fac.resolve()))}\n"
            "factory_original_path: \"/mnt/vendor/efs/device_profile.textproto\"\n"
            "factory_sha256: \"0000000000000000000000000000000000000000000000000000000000000000\"\n"
            "factory_block_sha256: \"0000000000000000000000000000000000000000000000000000000000000000\"\n"
            f"vendor_path: {json.dumps(str(ven.resolve()))}\n"
            "vendor_original_path: \"/vendor/etc/calibration_service/device_profile.textproto\"\n"
            "vendor_sha256: \"0000000000000000000000000000000000000000000000000000000000000000\"\n"
            "vendor_block_sha256: \"0000000000000000000000000000000000000000000000000000000000000000\"\n"
        )
        manifest.write_text(text, encoding="utf-8")
        result = _run_cli(self.tmp_path, fac, ven, manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mismatch", result.stderr.lower())

    def test_path_mismatch_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        _, fac_block_hash, fac_source_hash = ao.extract_optical_block_hashes(fac)
        _, ven_block_hash, ven_source_hash = ao.extract_optical_block_hashes(ven)
        # Swap paths but keep correct hashes to exercise path verification first.
        text = (
            "display_only: true\n"
            "failures: []\n"
            f"factory_path: {json.dumps(str(ven.resolve()))}\n"
            "factory_original_path: \"/mnt/vendor/efs/device_profile.textproto\"\n"
            f"factory_sha256: {json.dumps(fac_source_hash)}\n"
            f"factory_block_sha256: {json.dumps(fac_block_hash)}\n"
            f"vendor_path: {json.dumps(str(fac.resolve()))}\n"
            "vendor_original_path: \"/vendor/etc/calibration_service/device_profile.textproto\"\n"
            f"vendor_sha256: {json.dumps(ven_source_hash)}\n"
            f"vendor_block_sha256: {json.dumps(ven_block_hash)}\n"
        )
        manifest.write_text(text, encoding="utf-8")
        result = _run_cli(self.tmp_path, fac, ven, manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("path mismatch", result.stderr.lower())

    # ------------------------------------------------------------------
    # Collector manifest schema and non-square fixtures
    # ------------------------------------------------------------------

    def _collector_manifest_json(self, fac: Path, ven: Path) -> str:
        fac_block, fac_block_hash, fac_file_hash = ao.extract_optical_block_hashes(fac)
        ven_block, ven_block_hash, ven_file_hash = ao.extract_optical_block_hashes(ven)
        fac_size = len(fac.read_bytes())
        ven_size = len(ven.read_bytes())
        fac_block_size = len(fac_block)
        ven_block_size = len(ven_block)
        manifest = {
            "display_only": True,
            "failures": [],
            "identity_before": {"fingerprint": "stable"},
            "identity_after": {"fingerprint": "stable"},
            "verified": [
                {
                    "local_path": str(fac.resolve()),
                    "original_path": "/mnt/vendor/efs/device_profile.textproto",
                    "status": "verified",
                    "selected_capture_not_full_file": True,
                    "selected_block_start": 0,
                    "selected_block_end": fac_block_size,
                    "selected_block_size": fac_block_size,
                    "selected_block_sha256": fac_block_hash,
                    "sha256": fac_file_hash,
                    "size": fac_size,
                    "original_sha_before": "abc",
                    "original_sha_after": "abc",
                },
                {
                    "local_path": str(ven.resolve()),
                    "original_path": "/vendor/etc/calibration_service/device_profile.textproto",
                    "status": "verified",
                    "selected_capture_not_full_file": True,
                    "selected_block_start": 0,
                    "selected_block_end": ven_block_size,
                    "selected_block_size": ven_block_size,
                    "selected_block_sha256": ven_block_hash,
                    "sha256": ven_file_hash,
                    "size": ven_size,
                    "original_sha_before": "def",
                    "original_sha_after": "def",
                },
            ],
        }
        return json.dumps(manifest)

    def test_collector_manifest_success(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, _ = self._make_factory_vendor(cells)
        manifest_path = self.tmp_path / "manifest.json"
        manifest_path.write_text(self._collector_manifest_json(fac, ven), encoding="utf-8")
        result = _run_cli(self.tmp_path, fac, ven, manifest_path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_collector_manifest_tampered_block_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, -1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(-1, -2, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(-1, -1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
        ]
        fac, ven, _ = self._make_factory_vendor(cells)
        manifest = json.loads(self._collector_manifest_json(fac, ven))
        manifest["verified"][0]["selected_block_sha256"] = "0" * 64
        manifest_path = self.tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        result = _run_cli(self.tmp_path, fac, ven, manifest_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected block", result.stderr.lower())

    def test_non_square_2x3_success(self) -> None:
        # rows=2, cols=3 -> 3 unique u (cols), 2 unique v (rows), v fastest.
        cells = [
            _cell(-2, -1, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
            _cell(-2, 1, 0.2, 0.3, 0.0, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0),
            _cell(0, -1, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0),
            _cell(0, 1, 0.4, 0.5, 0.0, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0),
            _cell(2, -1, 0.5, 0.6, 0.0, 0.7, 0.8, 0.0, 0.9, 1.0, 0.0),
            _cell(2, 1, 0.6, 0.7, 0.0, 0.8, 0.9, 0.0, 1.0, 1.1, 0.0),
        ]
        eye = _eye_textproto(2, 3, 6.0, 4.0, 60.0, cells)
        fac_path = self.tmp_path / "factory.textproto"
        ven_path = self.tmp_path / "vendor.textproto"
        fac_path.write_text(_profile_textproto(eye), encoding="utf-8")
        ven_path.write_text(_profile_textproto(eye), encoding="utf-8")
        manifest_path = self.tmp_path / "manifest.textproto"
        manifest_path.write_text(_manifest_textproto(fac_path, ven_path), encoding="utf-8")
        result = _run_cli(self.tmp_path, fac_path, ven_path, manifest_path)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load_output()
        self.assertEqual(data["profiles"]["factory"]["left"]["rows"], 2)
        self.assertEqual(data["profiles"]["factory"]["left"]["cols"], 3)
        self.assertEqual(len(data["profiles"]["factory"]["left"]["cells"]), 6)

    def test_nonzero_z_accepted(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, -1000.0, 0.3, 0.4, -2000.0, 0.5, 0.6, -3000.0),
            _cell(-2, -1, 0.2, 0.3, -1000.0, 0.4, 0.5, -2000.0, 0.6, 0.7, -3000.0),
            _cell(-1, -2, 0.3, 0.4, -1000.0, 0.5, 0.6, -2000.0, 0.7, 0.8, -3000.0),
            _cell(-1, -1, 0.4, 0.5, -1000.0, 0.6, 0.7, -2000.0, 0.8, 0.9, -3000.0),
        ]
        fac, ven, manifest = self._make_factory_vendor(cells)
        result = _run_cli(self.tmp_path, fac, ven, manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load_output()
        self.assertEqual(
            data["profiles"]["factory"]["left"]["cells"][0]["red"][2],
            -1000.0
        )

    def test_float_row_rejected(self) -> None:
        cells = [
            _cell(-2, -2, 0.1, 0.2, 0.0, 0.3, 0.4, 0.0, 0.5, 0.6, 0.0),
        ]
        eye = _eye_textproto(2, 2, 4.0, 4.0, 60.0, cells)
        eye_bad = eye.replace("lut_rows: 2", "lut_rows: 2.5")
        fac_path = self.tmp_path / "factory.textproto"
        ven_path = self.tmp_path / "vendor.textproto"
        fac_path.write_text(_profile_textproto(eye_bad), encoding="utf-8")
        ven_path.write_text(_profile_textproto(eye), encoding="utf-8")
        manifest_path = self.tmp_path / "manifest.textproto"
        manifest_path.write_text(_manifest_textproto(fac_path, ven_path), encoding="utf-8")
        result = _run_cli(self.tmp_path, fac_path, ven_path, manifest_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("integer", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
