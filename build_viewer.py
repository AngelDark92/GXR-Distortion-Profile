#!/usr/bin/env python3
"""Build a standalone, offline Galaxy XR optical LUT viewer.

Usage:
    python build_viewer.py <analysis.json>

The script reads viewer_template.html from the same directory, validates the
analysis JSON, embeds it safely, and writes optics-viewer.html next to the input.
No network requests or external dependencies are required.
"""

import argparse
import html
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_SCHEMA_VERSION = 1
PROFILE_NAMES = ("factory", "vendor")
EYES = ("left", "right")
CHANNELS = ("red", "green", "blue")


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def finite(n) -> bool:
    return isinstance(n, (int, float)) and not isinstance(n, bool) and math.isfinite(n)


def positive_finite_int(n) -> bool:
    return finite(n) and isinstance(n, int) and n > 0


def nonnegative_int(n) -> bool:
    return isinstance(n, int) and not isinstance(n, bool) and n >= 0


def validate_side(profile_name: str, eye: str, side: dict, errors: list) -> None:
    if not isinstance(side, dict):
        errors.append(f"profiles.{profile_name}.{eye}: not an object")
        return

    dims = ("rows", "cols", "width_px", "height_px")
    for key in dims:
        v = side.get(key)
        if not positive_finite_int(v):
            errors.append(f"profiles.{profile_name}.{eye}.{key}: must be a positive finite integer")

    ipd = side.get("ipd_mm")
    if not finite(ipd) or ipd <= 0:
        errors.append(f"profiles.{profile_name}.{eye}.ipd_mm: must be a positive finite number")

    for key in ("lut_block_count", "empty_lut_blocks"):
        v = side.get(key)
        if not nonnegative_int(v):
            errors.append(f"profiles.{profile_name}.{eye}.{key}: must be a non-negative integer")

    cells = side.get("cells")
    if not isinstance(cells, list):
        errors.append(f"profiles.{profile_name}.{eye}.cells: must be a list")
        return

    rows = side.get("rows", 0)
    cols = side.get("cols", 0)
    expected = rows * cols
    if expected <= 0:
        errors.append(f"profiles.{profile_name}.{eye}: rows and cols must be positive")
        return

    if len(cells) != expected:
        errors.append(
            f"profiles.{profile_name}.{eye}.cells: length {len(cells)} != rows*cols ({expected}); every populated LUT cell must be present"
        )
        return

    seen_uv = {}
    for idx, cell in enumerate(cells):
        if not isinstance(cell, dict):
            errors.append(f"profiles.{profile_name}.{eye}.cells[{idx}]: not an object")
            continue
        for coord in ("u", "v"):
            if not finite(cell.get(coord)):
                errors.append(
                    f"profiles.{profile_name}.{eye}.cells[{idx}]: {coord} must be finite"
                )
        uv_key = f"{cell.get('u')},{cell.get('v')}"
        if uv_key in seen_uv:
            errors.append(f"profiles.{profile_name}.{eye}.cells[{idx}]: duplicate UV {uv_key} (first at index {seen_uv[uv_key]})")
        else:
            seen_uv[uv_key] = idx
        for ch in CHANNELS:
            arr = cell.get(ch)
            if not isinstance(arr, list) or len(arr) != 3:
                errors.append(
                    f"profiles.{profile_name}.{eye}.cells[{idx}]: {ch} must be [x,y,z]"
                )
                continue
            for ci, comp in enumerate(arr):
                if not finite(comp):
                    errors.append(
                        f"profiles.{profile_name}.{eye}.cells[{idx}]: {ch}[{ci}] must be finite"
                    )


def validate_profile(profile_name: str, profile: dict, errors: list) -> None:
    if not isinstance(profile, dict):
        errors.append(f"profiles.{profile_name}: not an object")
        return
    for key in ("source_path", "source_sha256", "block_sha256"):
        val = profile.get(key)
        if not isinstance(val, str) or not val:
            errors.append(f"profiles.{profile_name}.{key}: missing or not a non-empty string")
    for eye in EYES:
        side = profile.get(eye)
        if side is None:
            errors.append(f"profiles.{profile_name}.{eye}: missing")
            continue
        validate_side(profile_name, eye, side, errors)


def validate_analysis(data: dict) -> list:
    errors = []
    if not isinstance(data, dict):
        return ["root: not a JSON object"]
    if data.get("schema_version") != REQUIRED_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {REQUIRED_SCHEMA_VERSION}, got {data.get('schema_version')}"
        )
    profiles = data.get("profiles")
    if not isinstance(profiles, dict):
        errors.append("profiles: missing or not an object")
        return errors

    if "factory" not in profiles:
        errors.append("profiles.factory: required profile is missing")
    for name in PROFILE_NAMES:
        prof = profiles.get(name)
        if prof is None:
            continue
        validate_profile(name, prof, errors)

    limitations = data.get("limitations")
    if limitations is not None and not isinstance(limitations, list):
        errors.append("limitations: must be a list of strings")

    comparisons = data.get("comparisons")
    if comparisons is not None and not isinstance(comparisons, dict):
        errors.append("comparisons: must be a dict")

    if not isinstance(data.get("profiles"), dict):
        return errors
    factory = data["profiles"].get("factory")
    if not factory:
        errors.append("profiles.factory: required profile is missing")
        return errors
    # Metadata-only empty block is valid: empty_lut_blocks may report extra blocks,
    # but every populated cell must be present and complete.
    return errors


def compute_presentation_stats(data: dict) -> dict:
    stats = {}
    profiles = data.get("profiles", {})
    for pname, profile in profiles.items():
        prof_stats = {}
        for eye in EYES:
            side = profile.get(eye)
            if not side or not isinstance(side.get("cells"), list):
                continue
            us, vs, xs, ys, zs = [], [], [], [], []
            for cell in side["cells"]:
                u = cell.get("u")
                v = cell.get("v")
                if finite(u) and finite(v):
                    us.append(u)
                    vs.append(v)
                for ch in CHANNELS:
                    arr = cell.get(ch)
                    if isinstance(arr, list) and len(arr) == 3:
                        if finite(arr[0]):
                            xs.append(arr[0])
                        if finite(arr[1]):
                            ys.append(arr[1])
                        if finite(arr[2]):
                            zs.append(arr[2])
            prof_stats[eye] = {
                "u": _min_max_count(us),
                "v": _min_max_count(vs),
                "x": _min_max_count(xs),
                "y": _min_max_count(ys),
                "z": _min_max_count(zs),
            }
        stats[pname] = prof_stats
    return stats


def _min_max_count(values: list):
    if not values:
        return None
    return {"min": min(values), "max": max(values), "count": len(values)}


def embed_json(data: dict) -> str:
    """Serialize data for safe embedding inside an HTML script block.

    The output is valid JSON. '<' is escaped as \\u003c so that any embedded
    string cannot prematurely close the surrounding script element.
    """
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    # Keep line separators as JSON escapes so the parser never sees raw U+2028/U+2029.
    text = text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    # Prevent any literal '<' from being interpreted as markup.
    text = text.replace("<", "\\u003c")
    return text


def build(input_path: Path, output_path: Path, template_path: Path) -> None:
    if not input_path.is_file():
        log(f"Input file not found: {input_path}")
        sys.exit(1)

    try:
        with open(input_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except Exception as exc:
        log(f"Failed to parse {input_path}: {exc}")
        sys.exit(1)

    errors = validate_analysis(data)
    if errors:
        for e in errors:
            log(f"VALIDATION: {e}")
        log("Refusing to build viewer from malformed data.")
        sys.exit(1)

    data["__presentation_stats"] = compute_presentation_stats(data)
    data["__generated_at"] = datetime.now(timezone.utc).isoformat()
    data["__generator"] = "build_viewer.py"

    if not template_path.is_file():
        log(f"Template not found: {template_path}")
        sys.exit(1)
    template = template_path.read_text(encoding="utf-8")
    marker = "{{ANALYSIS_DATA}}"
    if marker not in template:
        log(f"Template missing placeholder {marker}")
        sys.exit(1)

    embedded = embed_json(data)
    output = template.replace(marker, embedded, 1)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(output)

    profiles = list(data.get("profiles", {}).keys())
    log(f"Wrote {output_path}")
    log(f"Profiles: {profiles}")
    log(f"Limitations: {len(data.get('limitations', []))}")


def main() -> None:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Embed an analysis JSON into a standalone offline optics viewer HTML."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=str(here / "analysis.json"),
        help="Path to analysis.json (default: analysis.json next to this script)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output HTML path (default: optics-viewer.html next to input)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_name("optics-viewer.html")
    template_path = here / "viewer_template.html"

    build(input_path, output_path, template_path)


if __name__ == "__main__":
    main()
