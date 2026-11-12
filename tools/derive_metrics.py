#!/usr/bin/env python3
"""Derive per-cell ratios and summary metrics from an Android XR Link distortion analysis.

All math uses the Python 3.13 standard library only.  No smoothing or fitting is
performed.  Every derived scalar is documented in the output with the assumption
that produced it.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
import sys
from pathlib import Path


SCHEMA_VERSION = 1
CHANNELS = ("red", "green", "blue")

# Notes attached to derived quantities so that the output is self-describing.
PROVENANCE = {
    "rx_ry": "rx = x/z, ry = y/z.  Guarded: z==0 leaves these cells empty.",
    "ratio_mag": "hypot(rx, ry).  Empty when z==0.",
    "angle_pinhole_deg": (
        "atan(ratio_mag) converted to degrees.  This assumes a pinhole camera "
        "mapping from the stored XYZ ray directions; that model is unproven for "
        "this dataset."
    ),
    "radial_symmetry": (
        "Diagnostic only.  Each cell is paired with the diametrically opposite "
        "cell (180-degree rotation about the grid centre).  Even symmetry compares "
        "ratio-magnitude equality; odd symmetry compares whether the ratio vector "
        "reverses.  Non-zero values are expected for asymmetric data."
    ),
    "corner_vs_mid_edge": (
        "Diagnostic only.  Compares the mean ratio magnitude at the four image "
        "corners with the mean at the centre of each image edge."
    ),
    "factory_vendor_delta": (
        "Per matched cell (same eye, iu, iv).  Raw XYZ Euclidean distance uses "
        "the stored x/y/z components directly.  Ratio-magnitude delta uses the "
        "absolute difference of the per-channel ratio magnitudes derived above."
    ),
}


def load_analysis(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema version {data.get('schema_version')!r}; "
            f"expected {SCHEMA_VERSION}"
        )
    if "profiles" not in data:
        raise ValueError("analysis JSON is missing 'profiles'")
    return data


def parse_profile_cells(cells: list[dict], rows: int, cols: int) -> list[dict]:
    """Annotate each cell with grid indices assuming V-fastest ordering."""
    expected = rows * cols
    parsed: list[dict] = []
    for idx, cell in enumerate(cells):
        iu = idx // rows
        iv = idx % rows
        parsed.append(
            {
                "iu": iu,
                "iv": iv,
                "u": float(cell["u"]),
                "v": float(cell["v"]),
                "id_x": cell.get("id_x"),
                "id_y": cell.get("id_y"),
                "red": tuple(float(v) for v in cell["red"]),
                "green": tuple(float(v) for v in cell["green"]),
                "blue": tuple(float(v) for v in cell["blue"]),
            }
        )
    return parsed


def validate_grid(parsed: list[dict], rows: int, cols: int) -> dict:
    """Return a dict describing basic grid sanity."""
    n = len(parsed)
    unique_u = sorted({c["u"] for c in parsed})
    unique_v = sorted({c["v"] for c in parsed})

    seen: set[tuple[float, float]] = set()
    duplicates = 0
    for c in parsed:
        key = (c["u"], c["v"])
        if key in seen:
            duplicates += 1
        seen.add(key)

    ordering_ok = True
    # Within a column (fixed iu) v must increase with iv.
    by_iu: dict[int, list[dict]] = {}
    by_iv: dict[int, list[dict]] = {}
    for c in parsed:
        by_iu.setdefault(c["iu"], []).append(c)
        by_iv.setdefault(c["iv"], []).append(c)
    for iu in range(cols):
        group = sorted(by_iu.get(iu, []), key=lambda c: c["iv"])
        if len(group) != rows:
            ordering_ok = False
            continue
        if any(group[i]["v"] >= group[i + 1]["v"] for i in range(rows - 1)):
            ordering_ok = False
    # Within a row (fixed iv) u must increase with iu.
    for iv in range(rows):
        group = sorted(by_iv.get(iv, []), key=lambda c: c["iu"])
        if len(group) != cols:
            ordering_ok = False
            continue
        if any(group[i]["u"] >= group[i + 1]["u"] for i in range(cols - 1)):
            ordering_ok = False

    return {
        "cell_count": n,
        "expected_cell_count": rows * cols,
        "cell_count_ok": n == rows * cols,
        "unique_u_count": len(unique_u),
        "unique_v_count": len(unique_v),
        "expected_u_count": cols,
        "expected_v_count": rows,
        "unique_counts_ok": len(unique_u) == cols and len(unique_v) == rows,
        "duplicate_uv_pairs": duplicates,
        "ordering_ok": ordering_ok,
    }


def derive_channel(x: float, y: float, z: float) -> dict:
    """Return derived columns for one channel.  z==0 produces empty strings."""
    if z == 0.0:
        return {
            "rx": "",
            "ry": "",
            "ratio_mag": "",
            "angle_pinhole_deg": "",
            "singularity": True,
        }
    rx = x / z
    ry = y / z
    mag = math.hypot(rx, ry)
    angle = math.degrees(math.atan(mag))
    return {
        "rx": rx,
        "ry": ry,
        "ratio_mag": mag,
        "angle_pinhole_deg": angle,
        "singularity": False,
    }


def build_row(cell: dict) -> dict:
    """Flatten one cell into the CSV row dict."""
    row: dict = {
        "iu": cell["iu"],
        "iv": cell["iv"],
        "u": cell["u"],
        "v": cell["v"],
        "id_x": "" if cell["id_x"] is None else cell["id_x"],
        "id_y": "" if cell["id_y"] is None else cell["id_y"],
    }
    singularities = 0
    for ch in CHANNELS:
        x, y, z = cell[ch]
        row[f"{ch}_x"] = x
        row[f"{ch}_y"] = y
        row[f"{ch}_z"] = z
        derived = derive_channel(x, y, z)
        row[f"{ch}_rx"] = derived["rx"]
        row[f"{ch}_ry"] = derived["ry"]
        row[f"{ch}_ratio_mag"] = derived["ratio_mag"]
        row[f"{ch}_angle_pinhole_deg"] = derived["angle_pinhole_deg"]
        if derived["singularity"]:
            singularities += 1
    return row, singularities


def csv_header() -> list[str]:
    header = ["eye", "profile", "iu", "iv", "u", "v", "id_x", "id_y"]
    for ch in CHANNELS:
        header.extend(
            [
                f"{ch}_x",
                f"{ch}_y",
                f"{ch}_z",
                f"{ch}_rx",
                f"{ch}_ry",
                f"{ch}_ratio_mag",
                f"{ch}_angle_pinhole_deg",
            ]
        )
    return header


def write_csv(
    path: Path, eye: str, profile: str, parsed: list[dict]
) -> tuple[int, list[dict]]:
    """Write a per-cell CSV and return (singularity_count, derived_rows)."""
    rows_out: list[dict] = []
    singularities = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=csv_header())
        writer.writeheader()
        for cell in parsed:
            row, sing = build_row(cell)
            row["eye"] = eye
            row["profile"] = profile
            writer.writerow(row)
            rows_out.append(row)
            singularities += sing
    return singularities, rows_out


def _floats(values: list[float]) -> dict:
    if not values:
        return {"min": None, "median": None, "max": None, "count": 0}
    return {
        "min": min(values),
        "median": statistics.median(values),
        "max": max(values),
        "count": len(values),
    }


def radial_symmetry(parsed: list[dict]) -> dict:
    """Compare each cell with its diametric opposite."""
    by_index = {(c["iu"], c["iv"]): c for c in parsed}
    rows = max(c["iv"] for c in parsed) + 1
    cols = max(c["iu"] for c in parsed) + 1
    result: dict = {}
    for ch in CHANNELS:
        even_diffs: list[float] = []
        odd_residuals: list[float] = []
        processed: set[tuple[int, int]] = set()
        for c in parsed:
            iu, iv = c["iu"], c["iv"]
            if (iu, iv) in processed:
                continue
            oiu, oiv = cols - 1 - iu, rows - 1 - iv
            processed.add((iu, iv))
            processed.add((oiu, oiv))
            opp = by_index.get((oiu, oiv))
            if opp is None:
                continue
            x1, y1, z1 = c[ch]
            x2, y2, z2 = opp[ch]
            if z1 == 0.0 or z2 == 0.0:
                continue
            rx1, ry1 = x1 / z1, y1 / z1
            rx2, ry2 = x2 / z2, y2 / z2
            mag1 = math.hypot(rx1, ry1)
            mag2 = math.hypot(rx2, ry2)
            avg_mag = (mag1 + mag2) / 2.0
            if avg_mag == 0.0:
                continue
            even_diffs.append(abs(mag1 - mag2) / avg_mag)
            odd_residuals.append(math.hypot(rx1 + rx2, ry1 + ry2) / avg_mag)
        result[ch] = {
            "radial_even_median_relative_diff": (
                statistics.median(even_diffs) if even_diffs else None
            ),
            "radial_odd_median_relative_residual": (
                statistics.median(odd_residuals) if odd_residuals else None
            ),
            "paired_cells": len(even_diffs),
            "note": PROVENANCE["radial_symmetry"],
        }
    return result


def corner_vs_mid_edge(parsed: list[dict]) -> dict:
    """Compare mean ratio magnitude at the four corners with the four edge centres."""
    rows = max(c["iv"] for c in parsed) + 1
    cols = max(c["iu"] for c in parsed) + 1
    by_index = {(c["iu"], c["iv"]): c for c in parsed}
    corners = [(0, 0), (cols - 1, 0), (0, rows - 1), (cols - 1, rows - 1)]
    iu_mid = (cols - 1) // 2
    iv_mid = (rows - 1) // 2
    edges = [(iu_mid, 0), (iu_mid, rows - 1), (0, iv_mid), (cols - 1, iv_mid)]
    result: dict = {}
    for ch in CHANNELS:
        corner_mags: list[float] = []
        mid_mags: list[float] = []
        for iu, iv in corners:
            c = by_index.get((iu, iv))
            if c is None:
                continue
            x, y, z = c[ch]
            if z != 0.0:
                corner_mags.append(math.hypot(x / z, y / z))
        for iu, iv in edges:
            c = by_index.get((iu, iv))
            if c is None:
                continue
            x, y, z = c[ch]
            if z != 0.0:
                mid_mags.append(math.hypot(x / z, y / z))
        corner_mean = statistics.mean(corner_mags) if corner_mags else None
        mid_mean = statistics.mean(mid_mags) if mid_mags else None
        ratio = (
            corner_mean / mid_mean
            if corner_mean is not None and mid_mean is not None and mid_mean != 0.0
            else None
        )
        result[ch] = {
            "corner_mean_ratio_mag": corner_mean,
            "mid_edge_mean_ratio_mag": mid_mean,
            "corner_to_mid_edge_ratio": ratio,
            "note": PROVENANCE["corner_vs_mid_edge"],
        }
    return result


def profile_summary(
    parsed: list[dict], singularities: int
) -> dict:
    """Compute the per-profile summary block."""
    ratio_mag_by_ch: dict[str, list[float]] = {ch: [] for ch in CHANNELS}
    angle_by_ch: dict[str, list[float]] = {ch: [] for ch in CHANNELS}
    for row in parsed:
        for ch in CHANNELS:
            x, y, z = row[ch]
            if z == 0.0:
                continue
            rx = x / z
            ry = y / z
            mag = math.hypot(rx, ry)
            ratio_mag_by_ch[ch].append(mag)
            angle_by_ch[ch].append(math.degrees(math.atan(mag)))

    channels: dict = {}
    for ch in CHANNELS:
        channels[ch] = {
            "ratio_magnitude": _floats(ratio_mag_by_ch[ch]),
            "angle_pinhole_deg": _floats(angle_by_ch[ch]),
        }

    return {
        "channels": channels,
        "singularity_count": singularities,
        "radial_symmetry": radial_symmetry(parsed),
        "corner_vs_mid_edge": corner_vs_mid_edge(parsed),
        "provenance": {
            "rx_ry": PROVENANCE["rx_ry"],
            "ratio_mag": PROVENANCE["ratio_mag"],
            "angle_pinhole_deg": PROVENANCE["angle_pinhole_deg"],
        },
    }


def require_matching_grids(
    parsed_by_profile: dict[str, dict[str, list[dict]]], eyes: list[str]
) -> None:
    """Raise ValueError if factory and vendor grids do not line up."""
    if "factory" not in parsed_by_profile or "vendor" not in parsed_by_profile:
        return
    factory = parsed_by_profile["factory"]
    vendor = parsed_by_profile["vendor"]
    for eye in eyes:
        if eye not in factory or eye not in vendor:
            continue
        f_cells = {(c["iu"], c["iv"]): c for c in factory[eye]}
        for vc in vendor[eye]:
            key = (vc["iu"], vc["iv"])
            fc = f_cells.get(key)
            if fc is None:
                raise ValueError(
                    f"factory/vendor grid mismatch in {eye}: vendor has "
                    f"({vc['iu']},{vc['iv']}) missing from factory"
                )
            if not (fc["u"] == vc["u"] and fc["v"] == vc["v"]):
                raise ValueError(
                    f"factory/vendor grid mismatch in {eye} at "
                    f"({vc['iu']},{vc['iv']}): factory ("
                    f"{fc['u']},{fc['v']}) != vendor ({vc['u']},{vc['v']})"
                )


def factory_vendor_delta(
    factory_parsed: list[dict], vendor_parsed: list[dict]
) -> dict:
    """Return RMS/max/median of raw XYZ distance and ratio-magnitude delta."""
    f_by = {(c["iu"], c["iv"]): c for c in factory_parsed}
    v_by = {(c["iu"], c["iv"]): c for c in vendor_parsed}
    keys = sorted(set(f_by) & set(v_by))
    result: dict = {}
    for ch in CHANNELS:
        raw_dists: list[float] = []
        mag_deltas: list[float] = []
        for key in keys:
            fx, fy, fz = f_by[key][ch]
            vx, vy, vz = v_by[key][ch]
            raw_dists.append(math.sqrt((fx - vx) ** 2 + (fy - vy) ** 2 + (fz - vz) ** 2))
            if fz != 0.0 and vz != 0.0:
                f_mag = math.hypot(fx / fz, fy / fz)
                v_mag = math.hypot(vx / vz, vy / vz)
                mag_deltas.append(abs(f_mag - v_mag))
        result[ch] = {
            "raw_xyz_euclidean": {
                "rms": math.sqrt(statistics.mean([d ** 2 for d in raw_dists]))
                if raw_dists
                else None,
                "max": max(raw_dists) if raw_dists else None,
                "median": statistics.median(raw_dists) if raw_dists else None,
                "matched_cells": len(raw_dists),
            },
            "ratio_magnitude_delta": {
                "rms": math.sqrt(statistics.mean([d ** 2 for d in mag_deltas]))
                if mag_deltas
                else None,
                "max": max(mag_deltas) if mag_deltas else None,
                "median": statistics.median(mag_deltas) if mag_deltas else None,
                "matched_cells": len(mag_deltas),
            },
            "note": PROVENANCE["factory_vendor_delta"],
        }
    return result


def write_summary_json(path: Path, summary: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")


def write_summary_md(path: Path, summary: dict) -> None:
    lines: list[str] = []
    lines.append("# Derived Metrics Summary\n")
    lines.append(
        "**Global provenance note:** All ratio and angle columns are derived from "
        "the stored XYZ ray components only.  `rx = x/z`, `ry = y/z`, "
        "`ratio_mag = hypot(rx, ry)`, and `angle_pinhole_deg = degrees(atan(ratio_mag))`. "
        "The angle column explicitly assumes a pinhole projection; this assumption is "
        "unproven for the captured data.  Values where `z == 0` are emitted as empty "
        "cells and counted as singularities.  No smoothing, fitting, or optical-quality "
        "claims are made.\n"
    )

    for eye in summary["results"]:
        lines.append(f"## Eye: {eye}\n")
        for profile in summary["results"][eye]:
            block = summary["results"][eye][profile]
            lines.append(f"### Profile: {profile}\n")
            gv = block["grid_validation"]
            lines.append("**Grid validation**\n")
            lines.append(
                f"- cells: {gv['cell_count']} (expected {gv['expected_cell_count']}, "
                f"ok={gv['cell_count_ok']})\n"
            )
            lines.append(
                f"- unique u: {gv['unique_u_count']} (expected {gv['expected_u_count']}, "
                f"ok={gv['unique_counts_ok']})\n"
            )
            lines.append(
                f"- unique v: {gv['unique_v_count']} (expected {gv['expected_v_count']}, "
                f"ok={gv['unique_counts_ok']})\n"
            )
            lines.append(
                f"- duplicate (u,v) pairs: {gv['duplicate_uv_pairs']}; "
                f"ordering_ok={gv['ordering_ok']}\n"
            )
            lines.append(f"- z==0 singularities: {block['singularity_count']}\n")
            lines.append("**Per-channel ratio magnitude and pinhole angle (degrees)**\n")
            lines.append("| channel | ratio_mag min | median | max | angle min | max |\n")
            lines.append("|---------|--------------|--------|-----|-----------|-----|\n")
            for ch in CHANNELS:
                rm = block["channels"][ch]["ratio_magnitude"]
                ang = block["channels"][ch]["angle_pinhole_deg"]
                lines.append(
                    f"| {ch} | {rm['min']} | {rm['median']} | {rm['max']} | "
                    f"{ang['min']} | {ang['max']} |\n"
                )
            lines.append("**Radial symmetry diagnostic**\n")
            lines.append("| channel | even median rel. diff | odd median rel. residual | pairs |\n")
            lines.append("|---------|----------------------|--------------------------|-------|\n")
            for ch in CHANNELS:
                rs = block["radial_symmetry"][ch]
                lines.append(
                    f"| {ch} | {rs['radial_even_median_relative_diff']} | "
                    f"{rs['radial_odd_median_relative_residual']} | {rs['paired_cells']} |\n"
                )
            lines.append("**Corner vs mid-edge ratio magnitude diagnostic**\n")
            lines.append(
                "| channel | corner mean | mid-edge mean | corner / mid-edge |\n"
            )
            lines.append("|---------|-------------|---------------|-------------------|\n")
            for ch in CHANNELS:
                ce = block["corner_vs_mid_edge"][ch]
                lines.append(
                    f"| {ch} | {ce['corner_mean_ratio_mag']} | "
                    f"{ce['mid_edge_mean_ratio_mag']} | {ce['corner_to_mid_edge_ratio']} |\n"
                )
            lines.append("\n")

    if summary.get("factory_vendor_delta"):
        lines.append("## Factory vs Vendor deltas (matched cells)\n")
        lines.append(
            "Raw XYZ Euclidean distance and absolute ratio-magnitude delta, "
            "aggregated over all matched cells per eye and channel.\n\n"
        )
        for eye in summary["factory_vendor_delta"]:
            lines.append(f"### Eye: {eye}\n")
            lines.append(
                "| channel | raw rms | raw max | raw median | "
                "mag delta rms | mag delta max | mag delta median |\n"
            )
            lines.append(
                "|---------|---------|---------|------------|---------------|---------------|------------------|\n"
            )
            for ch in CHANNELS:
                d = summary["factory_vendor_delta"][eye][ch]
                raw = d["raw_xyz_euclidean"]
                mag = d["ratio_magnitude_delta"]
                lines.append(
                    f"| {ch} | {raw['rms']} | {raw['max']} | {raw['median']} | "
                    f"{mag['rms']} | {mag['max']} | {mag['median']} |\n"
                )
            lines.append("\n")

    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive ratio/angle metrics from an Android XR Link analysis.json."
    )
    parser.add_argument("--analysis", required=True, help="path to analysis.json")
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument(
        "--profile",
        choices=("factory", "vendor", "both"),
        default="both",
        help="which profile to export",
    )
    parser.add_argument(
        "--eye",
        choices=("left", "right", "both"),
        default="both",
        help="which eye to export",
    )
    args = parser.parse_args(argv)

    data = load_analysis(args.analysis)
    profiles_arg = ["factory", "vendor"] if args.profile == "both" else [args.profile]
    eyes_arg = ["left", "right"] if args.eye == "both" else [args.eye]

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Parse everything selected first so we can validate grids before writing.
    parsed_by_profile: dict[str, dict[str, list[dict]]] = {}
    grid_validations: dict[str, dict[str, dict]] = {}
    for profile in profiles_arg:
        parsed_by_profile[profile] = {}
        grid_validations[profile] = {}
        profile_data = data["profiles"][profile]
        for eye in eyes_arg:
            eye_data = profile_data[eye]
            parsed = parse_profile_cells(
                eye_data["cells"], eye_data["rows"], eye_data["cols"]
            )
            parsed_by_profile[profile][eye] = parsed
            grid_validations[profile][eye] = validate_grid(
                parsed, eye_data["rows"], eye_data["cols"]
            )

    # If both profiles are requested, ensure they share a common grid.
    try:
        require_matching_grids(parsed_by_profile, eyes_arg)
    except ValueError as exc:
        parser.error(str(exc))

    # Determine output filenames and check for overwrites.
    csv_paths: dict[tuple[str, str], Path] = {}
    for profile in profiles_arg:
        for eye in eyes_arg:
            path = out_dir / f"{eye}_{profile}_cells.csv"
            if path.exists():
                parser.error(
                    f"refusing to overwrite existing output file: {path}"
                )
            csv_paths[(eye, profile)] = path

    summary_json_path = out_dir / "summary.json"
    summary_md_path = out_dir / "summary.md"
    if summary_json_path.exists():
        parser.error(
            f"refusing to overwrite existing output file: {summary_json_path}"
        )
    if summary_md_path.exists():
        parser.error(
            f"refusing to overwrite existing output file: {summary_md_path}"
        )

    # Write CSVs and collect per-profile summaries.
    summary: dict = {
        "provenance": {
            "global": (
                "Derived from stored XYZ under a pinhole assumption; see "
                "per-field notes."
            ),
            "rx_ry": PROVENANCE["rx_ry"],
            "ratio_mag": PROVENANCE["ratio_mag"],
            "angle_pinhole_deg": PROVENANCE["angle_pinhole_deg"],
        },
        "args": vars(args),
        "results": {},
    }
    for eye in eyes_arg:
        summary["results"][eye] = {}
    for profile in profiles_arg:
        for eye in eyes_arg:
            path = csv_paths[(eye, profile)]
            parsed = parsed_by_profile[profile][eye]
            singularities, derived_rows = write_csv(path, eye, profile, parsed)
            block = profile_summary(parsed, singularities)
            block["grid_validation"] = grid_validations[profile][eye]
            block["csv_path"] = str(path)
            summary["results"][eye][profile] = block

    # Factory/vendor delta when both profiles are present.
    if "factory" in profiles_arg and "vendor" in profiles_arg:
        summary["factory_vendor_delta"] = {}
        for eye in eyes_arg:
            summary["factory_vendor_delta"][eye] = factory_vendor_delta(
                parsed_by_profile["factory"][eye],
                parsed_by_profile["vendor"][eye],
            )

    write_summary_json(summary_json_path, summary)
    write_summary_md(summary_md_path, summary)

    return 0


if __name__ == "__main__":
    sys.exit(main())
