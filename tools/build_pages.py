#!/usr/bin/env python3
"""Build the public GitHub Pages allowlist for GXR-Distortion-Profile.

Usage:
    python -B tools/build_pages.py --output _site
    python -B tools/build_pages.py --assets-only viewer

The site is deliberately a closed allowlist: an index.html rendered from
viewer_template.html plus five download files.  No repository source, capture
manifest, consumer binary, archive or deployment record is copied.  The two
retained textprotos are copied byte-for-byte and their known subtree hashes are
enforced.  Every payload is scanned for private paths and identifiers before the
output directory is touched, and an output directory holding any file outside
the allowlist is rejected without deleting or overwriting anything (expected
site files may be rewritten on rebuild).

--assets-only writes only the downloads/ folder into the given package
directory, which keeps the local viewer launcher working with the same links
and the same bytes while leaving build_viewer.py standalone behaviour intact.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import build_viewer  # noqa: E402  (repository-root module)
import publication  # noqa: E402  (same tools directory)

DEFAULT_OUTPUT = REPO_ROOT / "_site"
TEMPLATE_PATH = REPO_ROOT / "viewer_template.html"
DOWNLOADS_DIRNAME = "downloads"

ANALYSIS_DOWNLOAD = "analysis.json"
FACTORY_DOWNLOAD = "factory-display-profile-v2.textproto"
VENDOR_DOWNLOAD = "vendor-display-profile-v2.textproto"
PROVENANCE_DOWNLOAD = "provenance.json"
SUMS_DOWNLOAD = "SHA256SUMS"


class BuildError(Exception):
    """The requested publication build cannot be completed safely."""


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise BuildError(f"cannot read {label} ({path}): {exc}") from exc


def _manifest_entry(manifest: Dict[str, Any], role: str) -> Dict[str, Any]:
    return publication.manifest_entry(manifest, role)


def build_provenance(
    analysis: Dict[str, Any], manifest: Dict[str, Any]
) -> Dict[str, Any]:
    """Curate provenance from the sanitized manifest and analysis.

    Only Android source paths and download-relative paths are emitted; local
    filesystem paths and the device serial are never copied.
    """
    profiles: Dict[str, Any] = {}
    for role, download in (
        ("factory", FACTORY_DOWNLOAD),
        ("vendor", VENDOR_DOWNLOAD),
    ):
        entry = _manifest_entry(manifest, role)
        profiles[role] = {
            "original_source_path": entry["original_path"],
            "download": f"{DOWNLOADS_DIRNAME}/{download}",
            "original_full_file": {
                "sha256": entry.get("original_sha_before"),
                "size_bytes": entry.get("original_size"),
                "note": (
                    "Capture-time hash of the full device_profile.textproto container. "
                    "The full container is not retained or published."
                ),
            },
            "retained_subtree": {
                "sha256": entry.get("selected_block_sha256"),
                "size_bytes": entry.get("selected_block_size"),
                "byte_start": entry.get("selected_block_start"),
                "byte_end": entry.get("selected_block_end"),
                "extracted_from_full_file": True,
                "note": (
                    "Only the display_profile_v2 subtree is retained, byte-preserved "
                    "in original textproto form. It is not flashable firmware."
                ),
            },
            "capture_evidence": {
                "status": entry.get("status"),
                "transport": entry.get("transport"),
                "selected_capture_not_full_file": entry.get(
                    "selected_capture_not_full_file"
                ),
                "original_sha_before": entry.get("original_sha_before"),
                "original_sha_after": entry.get("original_sha_after"),
            },
        }

    identity = manifest.get("identity_before") or manifest.get("identity_after") or {}
    device = {
        "build_fingerprint": identity.get("fingerprint"),
        "kernel": identity.get("kernel"),
        "uid": identity.get("uid"),
    }

    return {
        "schema_version": 1,
        "project": "GXR-Distortion-Profile",
        "scope": (
            "Public metadata for the retained display_profile_v2 subtrees and the "
            "derived analysis JSON. No full device_profile.textproto, consumer "
            "binary, capture manifest, deployment record or archive is published."
        ),
        "sources": {
            role: profiles[role]["original_source_path"] for role in profiles
        },
        "profiles": profiles,
        "device": device,
        "build": {
            "analysis_download": f"{DOWNLOADS_DIRNAME}/{ANALYSIS_DOWNLOAD}",
            "analysis_schema_version": analysis.get("schema_version"),
            "analysis_generator": "tools/analyse_optics.py",
            "viewer_template": "viewer_template.html",
            "site_builder": "tools/build_pages.py",
            "known_subtree_hashes_enforced": True,
            "factory_subtree_sha256": publication.FACTORY_SUBTREE_SHA256,
            "vendor_subtree_sha256": publication.VENDOR_SUBTREE_SHA256,
        },
        "limits": list(analysis.get("limitations", [])),
        "privacy": (
            "Local filesystem paths and device identifiers are removed. "
            "Android source paths and capture-time build metadata are retained as "
            "provenance, not as claims about the running compositor."
        ),
    }


def build_index_html(analysis: Dict[str, Any], template_path: Path = TEMPLATE_PATH) -> str:
    data = copy.deepcopy(analysis)
    errors = build_viewer.validate_analysis(data)
    if errors:
        raise BuildError("analysis JSON failed viewer validation: " + "; ".join(errors))

    data["__presentation_stats"] = build_viewer.compute_presentation_stats(data)
    data["__generator"] = "tools/build_pages.py"

    template = _read_bytes(template_path, "viewer template").decode("utf-8")
    marker = "{{ANALYSIS_DATA}}"
    if marker not in template:
        raise BuildError(f"viewer template is missing {marker}")
    return template.replace(marker, build_viewer.embed_json(data), 1)


def download_payloads(
    analysis: Dict[str, Any],
    manifest: Dict[str, Any],
    factory_bytes: bytes,
    vendor_bytes: bytes,
) -> List[Tuple[str, bytes]]:
    """Return download name/payload pairs plus the SHA256SUMS manifest."""
    files: List[Tuple[str, bytes]] = [
        (ANALYSIS_DOWNLOAD, publication.dump_json(analysis).encode("utf-8")),
        (FACTORY_DOWNLOAD, factory_bytes),
        (VENDOR_DOWNLOAD, vendor_bytes),
        (PROVENANCE_DOWNLOAD, publication.dump_json(build_provenance(analysis, manifest)).encode("utf-8")),
    ]
    sums_lines = [
        f"{publication.sha256_bytes(payload)}  {name}"
        for name, payload in sorted(files, key=lambda item: item[0])
    ]
    files.append((SUMS_DOWNLOAD, ("\n".join(sums_lines) + "\n").encode("utf-8")))
    return files


def site_payloads(
    analysis: Dict[str, Any],
    manifest: Dict[str, Any],
    factory_bytes: bytes,
    vendor_bytes: bytes,
) -> Dict[str, bytes]:
    """Build every site file in memory, keyed by POSIX relative path."""
    payloads = {"index.html": build_index_html(analysis).encode("utf-8")}
    for name, payload in download_payloads(
        analysis, manifest, factory_bytes, vendor_bytes
    ):
        payloads[f"{DOWNLOADS_DIRNAME}/{name}"] = payload
    return payloads


def assert_closed_output(output_dir: Path, expected: Iterable[str]) -> None:
    """Refuse to publish over a directory that holds extra files.

    Nothing is deleted: the caller must pick an empty destination or remove its
    own stale files.  Expected site files may be overwritten for rebuilds.
    """
    if output_dir.exists():
        resolved = output_dir.resolve()
        if resolved == REPO_ROOT or resolved in REPO_ROOT.parents:
            raise BuildError(
                f"refusing to publish into the repository root or an ancestor: {output_dir}"
            )
    if not output_dir.exists():
        return
    if not output_dir.is_dir():
        raise BuildError(f"output path exists and is not a directory: {output_dir}")

    expected_set = set(expected)
    unexpected = sorted(
        relative
        for path in output_dir.rglob("*")
        if path.is_file()
        for relative in (path.relative_to(output_dir).as_posix(),)
        if relative not in expected_set
    )
    if unexpected:
        shown = ", ".join(unexpected[:10])
        more = "" if len(unexpected) <= 10 else f" (+{len(unexpected) - 10} more)"
        raise BuildError(
            f"output directory {output_dir} contains non-allowlisted files: "
            f"{shown}{more}. Refusing to publish; nothing was deleted or overwritten."
        )


def write_payloads(output_dir: Path, payloads: Dict[str, bytes]) -> List[Path]:
    written: List[Path] = []
    for relative in sorted(payloads):
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payloads[relative])
        written.append(target)
    return written


def prepare_inputs() -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    analysis = publication.load_json(publication.ANALYSIS_PATH)
    manifest = publication.load_json(publication.CAPTURE_MANIFEST_PATH)
    factory_bytes = _read_bytes(publication.FACTORY_SOURCE_PATH, "factory textproto")
    vendor_bytes = _read_bytes(publication.VENDOR_SOURCE_PATH, "vendor textproto")

    canonical_bytes = publication.dump_json(analysis).encode("utf-8")
    if canonical_bytes != publication.ANALYSIS_PATH.read_bytes():
        raise BuildError(
            "data/analysis.json is not in canonical sanitized form; rerun "
            "python -B tools/analyse_optics.py or python -B tools/publication.py --write"
        )

    violations = publication.sanitized_analysis_violations(analysis)
    violations += publication.capture_manifest_violations(manifest)
    violations += publication.find_serial_violations(analysis, max_depth=3)
    violations += publication.find_serial_violations(manifest)
    if violations:
        raise BuildError(
            "canonical data is not sanitized; run python -B tools/publication.py --write: "
            + "; ".join(violations)
        )

    publication.verify_known_hashes(analysis, manifest, factory_bytes, vendor_bytes)
    return analysis, manifest, factory_bytes, vendor_bytes


def build_site(output_dir: Path) -> List[Path]:
    analysis, manifest, factory_bytes, vendor_bytes = prepare_inputs()

    # Assemble and scan everything first; the output directory is only touched
    # after every payload passes the privacy checks and the closed allowlist.
    payloads = site_payloads(analysis, manifest, factory_bytes, vendor_bytes)
    for relative, payload in payloads.items():
        publication.assert_public_bytes(payload, relative)
    assert_closed_output(output_dir, payloads)

    output_dir.mkdir(parents=True, exist_ok=True)
    return write_payloads(output_dir, payloads)


def build_assets_only(package_dir: Path) -> List[Path]:
    analysis, manifest, factory_bytes, vendor_bytes = prepare_inputs()
    payloads = {
        f"{DOWNLOADS_DIRNAME}/{name}": payload
        for name, payload in download_payloads(
            analysis, manifest, factory_bytes, vendor_bytes
        )
    }
    for relative, payload in payloads.items():
        publication.assert_public_bytes(payload, relative)

    package_dir.mkdir(parents=True, exist_ok=True)
    return write_payloads(package_dir, payloads)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the allowlisted GitHub Pages site or local download assets."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--output",
        type=Path,
        default=None,
        help=f"site output directory (default: {DEFAULT_OUTPUT})",
    )
    mode.add_argument(
        "--assets-only",
        type=Path,
        default=None,
        metavar="DIR",
        help="write only DIR/downloads for the local viewer package",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        if args.assets_only is not None:
            written = build_assets_only(args.assets_only.resolve())
        else:
            output = (args.output or DEFAULT_OUTPUT).resolve()
            written = build_site(output)
    except (BuildError, publication.PublicationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    for path in written:
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
