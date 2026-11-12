#!/usr/bin/env python3
"""Shared helpers for the public Pages allowlist and data sanitation.

Stdlib only.  The canonical analysis JSON and capture manifest keep their
evidence, hashes, Android source paths and build metadata, but never expose a
local filesystem path or the capture device serial.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]

ANALYSIS_PATH = REPO_ROOT / "data" / "analysis.json"
CAPTURE_MANIFEST_PATH = (
    REPO_ROOT / "data" / "captures" / "optical-capture-verified" / "capture_manifest.json"
)
CAPTURE_DIR = CAPTURE_MANIFEST_PATH.parent

FACTORY_SOURCE_PATH = (
    CAPTURE_DIR
    / "originals"
    / "mnt"
    / "vendor"
    / "efs"
    / "device_profile.textproto.display_profile_v2.textproto"
)
VENDOR_SOURCE_PATH = (
    CAPTURE_DIR
    / "originals"
    / "vendor"
    / "etc"
    / "calibration_service"
    / "device_profile.textproto.display_profile_v2.textproto"
)

# Retained display_profile_v2 subtree hashes.  These are enforced at build time.
FACTORY_SUBTREE_SHA256 = (
    "1c6103652760ab2c8cf9521c6cf0f9cffc327e8988c8becebbdf203c834be991"
)
VENDOR_SUBTREE_SHA256 = (
    "3247e01abfc0a4f26211364dcb3627a7eab4f33c796006d09e38c337dc1fd773"
)

SERIAL_REDACTION = "[redacted]"
ADB_PLACEHOLDER = "adb"

# Text that must never appear in a published file.  Android source paths and
# the public repository author are allowed; local filesystem roots, home
# directories and local adb install paths are not.  Device identifiers are
# caught structurally by find_serial_violations(), never by hardcoding one.
PRIVATE_TEXT_PATTERNS = (
    ("local_windows_path", re.compile(r"(?i)\b[A-Z]:[\\/]")),
    ("local_unix_home", re.compile(r"/(?:home|Users)/[^/\s]+")),
    ("local_adb_path", re.compile(r"(?i)adb(?:\.exe)?\b.*(?:platform-tools|AndroidSdk)")),
)

SERIAL_KEY_PATTERN = re.compile(r"(?i)^serial(?:$|[_-])")


class PublicationError(Exception):
    """A published artifact would expose private data or wrong hashes."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def portable_path(value: Any) -> Any:
    """Return a repository-relative POSIX path for an in-repo local path.

    Non-path values and paths outside the repository are returned unchanged.
    """
    if not isinstance(value, str) or not value:
        return value
    raw = value.replace("\\", "/")
    candidate = Path(raw)
    if not candidate.is_absolute():
        return raw
    try:
        relative = candidate.resolve().relative_to(REPO_ROOT)
    except (OSError, ValueError):
        return value
    return relative.as_posix()


def sanitize_analysis(data: Dict[str, Any]) -> Dict[str, Any]:
    """Copy analysis data with local profile source paths made portable."""
    out = copy.deepcopy(data)
    profiles = out.get("profiles")
    if isinstance(profiles, dict):
        for profile in profiles.values():
            if isinstance(profile, dict) and "source_path" in profile:
                profile["source_path"] = portable_path(profile["source_path"])
    return out


def sanitize_capture_manifest(data: Dict[str, Any]) -> Dict[str, Any]:
    """Copy a capture manifest with local paths and device serial removed.

    Hashes, byte spans, sizes, Android source paths, identities and build
    metadata are preserved.
    """
    out = copy.deepcopy(data)
    if "adb" in out:
        out["adb"] = ADB_PLACEHOLDER
    if "serial" in out:
        out["serial"] = SERIAL_REDACTION
    if "output" in out:
        out["output"] = portable_path(out["output"])
    for key in ("verified", "sources"):
        entries = out.get(key)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and "local_path" in entry:
                    entry["local_path"] = portable_path(entry["local_path"])
    return out


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_json(data), encoding="utf-8", newline="\n")


def load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def find_private_text(text: str) -> List[str]:
    """Return human-readable names of private tokens found in text."""
    hits: List[str] = []
    for name, pattern in PRIVATE_TEXT_PATTERNS:
        if pattern.search(text):
            hits.append(name)
    return hits


def assert_public_text(text: str, label: str) -> None:
    hits = find_private_text(text)
    if hits:
        raise PublicationError(f"{label}: private tokens present: {', '.join(hits)}")


def assert_public_bytes(payload: bytes, label: str) -> None:
    """Scan a would-be published payload before it is written."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = payload.decode("latin-1")
    assert_public_text(text, label)


def find_serial_violations(
    data: Any, path: str = "$", depth: int = 0, max_depth: Optional[int] = None
) -> List[str]:
    """Return serial-named fields that are not the redaction sentinel.

    This is structural: public code never learns or hardcodes a real device
    identifier, it only requires every serial-like key to be redacted.
    """
    if max_depth is not None and depth >= max_depth:
        return []
    violations: List[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            here = f"{path}.{key}"
            if isinstance(key, str) and SERIAL_KEY_PATTERN.match(key):
                if value != SERIAL_REDACTION:
                    violations.append(f"{here} is not redacted")
            violations.extend(
                find_serial_violations(value, here, depth + 1, max_depth)
            )
    elif isinstance(data, list):
        for index, value in enumerate(data):
            violations.extend(
                find_serial_violations(value, f"{path}[{index}]", depth + 1, max_depth)
            )
    return violations


def assert_public_tree(paths: Iterable[Path]) -> None:
    for path in paths:
        data = path.read_bytes()
        for encoding in ("utf-8", "latin-1"):
            try:
                text = data.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:  # pragma: no cover - binary files are checksum-only artifacts
            continue
        assert_public_text(text, str(path))


def expected_hashes() -> Dict[str, str]:
    return {
        "factory": FACTORY_SUBTREE_SHA256,
        "vendor": VENDOR_SUBTREE_SHA256,
    }


def manifest_entry(manifest: Dict[str, Any], role: str) -> Dict[str, Any]:
    entries = manifest.get("verified")
    if not isinstance(entries, list):
        raise PublicationError("capture manifest has no 'verified' list")
    matches = [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("original_path", "").endswith(
            "/efs/device_profile.textproto"
            if role == "factory"
            else "/calibration_service/device_profile.textproto"
        )
    ]
    if len(matches) != 1:
        raise PublicationError(
            f"capture manifest must contain exactly one {role} entry, found {len(matches)}"
        )
    return matches[0]


def verify_known_hashes(
    analysis: Dict[str, Any],
    manifest: Dict[str, Any],
    factory_bytes: bytes,
    vendor_bytes: bytes,
) -> None:
    """Fail closed unless the retained subtree bytes and metadata agree."""
    expected = expected_hashes()

    if sha256_bytes(factory_bytes) != expected["factory"]:
        raise PublicationError("factory textproto hash does not match the known subtree hash")
    if sha256_bytes(vendor_bytes) != expected["vendor"]:
        raise PublicationError("vendor textproto hash does not match the known subtree hash")

    profiles = analysis.get("profiles", {})
    for role in ("factory", "vendor"):
        profile = profiles.get(role, {})
        if profile.get("source_sha256") != expected[role]:
            raise PublicationError(f"analysis {role}.source_sha256 is not the known subtree hash")
        if profile.get("block_sha256") != expected[role]:
            raise PublicationError(f"analysis {role}.block_sha256 is not the known subtree hash")
        entry = manifest_entry(manifest, role)
        if entry.get("selected_block_sha256") != expected[role]:
            raise PublicationError(
                f"capture manifest {role}.selected_block_sha256 is not the known subtree hash"
            )
        if entry.get("sha256") != expected[role]:
            raise PublicationError(f"capture manifest {role}.sha256 is not the known subtree hash")
        if entry.get("status") != "verified":
            raise PublicationError(f"capture manifest {role} status is not verified")


def sanitized_analysis_violations(data: Dict[str, Any]) -> List[str]:
    """Return local-path violations in analysis metadata."""
    violations: List[str] = []
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        return ["profiles is not an object"]
    for role, profile in profiles.items():
        if not isinstance(profile, dict):
            continue
        source = profile.get("source_path")
        if not isinstance(source, str):
            violations.append(f"{role}.source_path is missing")
            continue
        if re.match(r"(?i)^[A-Z]:[\\/]", source) or source.startswith("/"):
            violations.append(f"{role}.source_path is not repository-relative")
    if "__generated_at" in data:
        violations.append("analysis contains __generated_at")
    return violations


def capture_manifest_violations(data: Dict[str, Any]) -> List[str]:
    violations: List[str] = []
    if data.get("adb") != ADB_PLACEHOLDER:
        violations.append("adb path is not the generic placeholder")
    if data.get("serial") != SERIAL_REDACTION:
        violations.append("serial is not redacted")
    output = data.get("output")
    if isinstance(output, str) and (re.match(r"(?i)^[A-Z]:[\\/]", output) or output.startswith("/")):
        violations.append("output is not repository-relative")
    for key in ("verified", "sources"):
        entries = data.get(key)
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            local = entry.get("local_path")
            if isinstance(local, str) and (
                re.match(r"(?i)^[A-Z]:[\\/]", local) or local.startswith("/")
            ):
                violations.append(f"{key}[{index}].local_path is not repository-relative")
    return violations


def public_artifact_paths(root: Path) -> List[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
    )


def _main(argv: Optional[Iterable[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Check the canonical public data files for local paths/serial."
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite data/analysis.json and capture_manifest.json with sanitized metadata",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    analysis = load_json(ANALYSIS_PATH)
    manifest = load_json(CAPTURE_MANIFEST_PATH)

    if args.write:
        write_json(ANALYSIS_PATH, sanitize_analysis(analysis))
        write_json(CAPTURE_MANIFEST_PATH, sanitize_capture_manifest(manifest))
        analysis = load_json(ANALYSIS_PATH)
        manifest = load_json(CAPTURE_MANIFEST_PATH)

    violations = sanitized_analysis_violations(analysis)
    violations += capture_manifest_violations(manifest)
    violations += find_private_text(dump_json(analysis))
    violations += find_private_text(dump_json(manifest))
    if violations:
        for violation in violations:
            print(f"ERROR: {violation}")
        return 1
    print("OK: canonical analysis and capture manifest are sanitized")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
