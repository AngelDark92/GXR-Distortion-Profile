#!/usr/bin/env python3
"""Parse DISPLAY-ONLY textproto optical profiles and emit numeric analysis.json.

Stdlib only.  Does not install drivers, talk to devices, or alter source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class OpticsError(Exception):
    """Recoverable validation failure with a concise message."""


# ---------------------------------------------------------------------------
# Generic textproto parser (stdlib only)
# ---------------------------------------------------------------------------

class _Token:
    __slots__ = ("kind", "value", "start")

    def __init__(self, kind: str, value: Any = None, start: int = -1):
        self.kind = kind
        self.value = value
        self.start = start

    def __repr__(self) -> str:  # pragma: no cover
        return f"_Token({self.kind!r}, {self.value!r}, {self.start})"


class TextProtoParser:
    """Tiny recursive-descent parser for the subset of textproto used here.

    Supports:
      - C++-style comments (// and /* */)
      - double-quoted strings with common escapes
      - signed integers, floats, exponents
      - repeated scalar fields and repeated message fields
      - compact scalar lists: key: [1, 2, 3]
      - message values in either braces or angle brackets

    The returned structure is intentionally uniform: every field name maps to a
    list of values.  Use the helper functions below to read scalar/repeated
    fields.
    """

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.tokens = self._tokenize()
        self.idx = 0

    def _peek(self, offset: int = 0) -> _Token:
        i = self.idx + offset
        if i >= len(self.tokens):
            return _Token("EOF")
        return self.tokens[i]

    def _consume(self, expected: Optional[str] = None) -> _Token:
        tok = self._peek()
        if expected and tok.kind != expected:
            raise OpticsError(
                f"Expected token {expected!r}, got {tok.kind} at token {self.idx}"
            )
        self.idx += 1
        return tok

    def _tokenize(self) -> List[_Token]:
        tokens: List[_Token] = []
        s = self.text
        n = len(s)
        i = 0
        while i < n:
            c = s[i]
            if c.isspace():
                i += 1
                continue
            if c == "#":
                end = s.find("\n", i + 1)
                i = n if end == -1 else end
                continue
            if c == "/" and i + 1 < n:
                if s[i + 1] == "/":
                    end = s.find("\n", i + 2)
                    i = n if end == -1 else end
                    continue
                if s[i + 1] == "*":
                    end = s.find("*/", i + 2)
                    if end == -1:
                        raise OpticsError("Unterminated block comment")
                    i = end + 2
                    continue
            if c == '"':
                j = i + 1
                chunks = []
                while j < n:
                    ch = s[j]
                    if ch == '"':
                        break
                    if ch == "\\":
                        if j + 1 >= n:
                            raise OpticsError("Unterminated string escape")
                        esc = s[j + 1]
                        if esc == 'n':
                            chunks.append('\n')
                        elif esc == 'r':
                            chunks.append('\r')
                        elif esc == 't':
                            chunks.append('\t')
                        elif esc == '\\':
                            chunks.append('\\')
                        elif esc == '"':
                            chunks.append('"')
                        elif esc == "'":
                            chunks.append("'")
                        elif esc == 'x':
                            if j + 3 >= n:
                                raise OpticsError("Invalid \\x escape")
                            code = int(s[j + 2:j + 4], 16)
                            chunks.append(chr(code))
                            j += 2
                        elif esc == 'u':
                            if j + 5 >= n:
                                raise OpticsError("Invalid \\u escape")
                            code = int(s[j + 2:j + 6], 16)
                            chunks.append(chr(code))
                            j += 4
                        elif esc == 'U':
                            if j + 9 >= n:
                                raise OpticsError("Invalid \\U escape")
                            code = int(s[j + 2:j + 10], 16)
                            chunks.append(chr(code))
                            j += 8
                        else:
                            chunks.append(esc)
                        j += 2
                    else:
                        chunks.append(ch)
                        j += 1
                if j >= n:
                    raise OpticsError("Unterminated string")
                tokens.append(_Token("STRING", "".join(chunks), i))
                i = j + 1
                continue
            if c.isalpha() or c == "_":
                j = i + 1
                while j < n and (s[j].isalnum() or s[j] in "_.-"):
                    j += 1
                ident = s[i:j]
                tokens.append(_Token("IDENT", ident, i))
                i = j
                continue
            if c.isdigit() or (c in "-+" and i + 1 < n and (s[i + 1].isdigit() or s[i + 1] == ".")):
                j = i + 1
                has_dot = False
                has_exp = False
                while j < n:
                    ch = s[j]
                    if ch.isdigit():
                        j += 1
                    elif ch == "." and not has_dot and not has_exp:
                        has_dot = True
                        j += 1
                    elif ch in "eE" and not has_exp and j > i + 1:
                        has_exp = True
                        if j + 1 < n and s[j + 1] in "-+":
                            j += 2
                        else:
                            j += 1
                    else:
                        break
                num_str = s[i:j]
                try:
                    if has_dot or has_exp:
                        value = float(num_str)
                    else:
                        value = int(num_str)
                except ValueError as exc:
                    raise OpticsError(f"Invalid numeric literal {num_str!r}") from exc
                tokens.append(_Token("NUMBER", value, i))
                i = j
                continue
            if c in "{}[]:;,<>":
                tokens.append(_Token(c, start=i))
                i += 1
                continue
            raise OpticsError(f"Unexpected character {c!r} at position {i}")
        return tokens

    def parse(self) -> Dict[str, List[Any]]:
        root: Dict[str, List[Any]] = {}
        while self._peek().kind != "EOF":
            self._parse_field(root)
        return root

    def _parse_field(self, container: Dict[str, List[Any]]) -> None:
        name_tok = self._consume("IDENT")
        name = name_tok.value
        # Optional colon
        if self._peek().kind == ":":
            self._consume(":")
        value = self._parse_value()
        container.setdefault(name, []).append(value)
        # Optional separator
        if self._peek().kind in (";", ","):
            self._consume()

    def _parse_value(self) -> Any:
        tok = self._peek()
        if tok.kind == "{":
            return self._parse_message("{", "}")
        if tok.kind == "<":
            return self._parse_message("<", ">")
        if tok.kind == "[":
            return self._parse_list()
        self._consume()
        if tok.kind == "STRING":
            return tok.value
        if tok.kind == "NUMBER":
            return tok.value
        if tok.kind == "IDENT":
            low = tok.value.lower()
            if low == "true":
                return True
            if low == "false":
                return False
            if low == "null":
                return None
            return tok.value
        raise OpticsError(f"Unexpected value token {tok.kind}")

    def _parse_message(self, open_tok: str, close_tok: str) -> Dict[str, List[Any]]:
        self._consume(open_tok)
        msg: Dict[str, List[Any]] = {}
        while self._peek().kind != close_tok:
            if self._peek().kind == "EOF":
                raise OpticsError(f"Unterminated message, expected {close_tok!r}")
            self._parse_field(msg)
        self._consume(close_tok)
        return msg

    def _parse_list(self) -> List[Any]:
        self._consume("[")
        items: List[Any] = []
        while self._peek().kind != "]":
            if self._peek().kind == "EOF":
                raise OpticsError("Unterminated list")
            items.append(self._parse_value())
            if self._peek().kind == ",":
                self._consume(",")
        self._consume("]")
        return items


def get_scalar(container: Dict[str, List[Any]], name: str) -> Any:
    values = container.get(name)
    if not values:
        raise OpticsError(f"Missing required field {name!r}")
    if len(values) > 1:
        raise OpticsError(f"Field {name!r} expected once, found {len(values)} times")
    return values[0]


def get_repeated(container: Dict[str, List[Any]], name: str) -> List[Any]:
    return container.get(name, [])


def scalar_str(container: Dict[str, List[Any]], name: str) -> str:
    v = get_scalar(container, name)
    if not isinstance(v, str):
        raise OpticsError(f"Field {name!r} must be a string")
    return v


def scalar_number(container: Dict[str, List[Any]], name: str) -> float:
    v = get_scalar(container, name)
    if not isinstance(v, (int, float)):
        raise OpticsError(f"Field {name!r} must be numeric")
    return float(v)


# ---------------------------------------------------------------------------
# Source hashing and manifest verification
# ---------------------------------------------------------------------------

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_optical_block_hashes(path: Path) -> Tuple[bytes, str, str]:
    """Return (block_bytes, block_sha256, source_sha256).

    Uses the textproto tokenizer so comments/strings cannot spoof the brace
    matching.  Rejects files with duplicate top-level display_profile_v2
    fields or any non-whitespace content outside the single optical block.
    """
    text = path.read_text(encoding="utf-8", newline="")
    parser = TextProtoParser(text)
    tokens = parser._tokenize()
    display_indices = [
        i for i, t in enumerate(tokens)
        if t.kind == "IDENT" and t.value == "display_profile_v2"
    ]
    if len(display_indices) != 1:
        raise OpticsError(
            f"{path}: expected exactly one top-level display_profile_v2, "
            f"found {len(display_indices)}"
        )
    field_idx = display_indices[0]
    brace_idx = field_idx + 1
    if brace_idx < len(tokens) and tokens[brace_idx].kind == ":":
        brace_idx += 1
    if brace_idx >= len(tokens) or tokens[brace_idx].kind != "{":
        raise OpticsError(f"{path}: display_profile_v2 not followed by '{{'")
    depth = 0
    close_idx: int | None = None
    for i in range(brace_idx, len(tokens)):
        tok = tokens[i]
        if tok.kind == "{":
            depth += 1
        elif tok.kind == "}":
            depth -= 1
            if depth == 0:
                close_idx = i
                break
    if close_idx is None:
        raise OpticsError(f"{path}: unclosed display_profile_v2 block")
    start = tokens[field_idx].start
    end = tokens[close_idx].start + 1
    outside = text[:start] + text[end:]
    if not re.fullmatch(r"\s*", outside):
        raise OpticsError(
            f"{path}: capture file must contain only the display_profile_v2 block"
        )
    block_text = text[start:end]
    block_bytes = block_text.encode("utf-8")
    data = path.read_bytes()
    return block_bytes, _sha256_bytes(block_bytes), _sha256_bytes(data)


_REPO_ROOT = Path(__file__).resolve().parents[1]


def _resolve_local_path(value: Any) -> Path:
    if not isinstance(value, str):
        raise OpticsError("Manifest local_path must be a string")
    p = Path(value)
    if p.is_absolute():
        return p.resolve()
    # Published manifests store repository-relative paths.  Resolve them from
    # the repository root as well as the caller's cwd so the file stays portable.
    for base in (Path.cwd(), _REPO_ROOT):
        resolved = (base / p).resolve()
        if resolved.exists():
            return resolved
    raise OpticsError(
        f"Relative manifest local_path {value!r} cannot be resolved "
        f"from cwd {Path.cwd()} or repository root {_REPO_ROOT}"
    )


def _portable_source_path(path: Path) -> str:
    """Return a stable repository-relative POSIX path when the file is in-repo."""
    resolved = path.resolve()
    for base in (_REPO_ROOT, Path.cwd().resolve()):
        try:
            return resolved.relative_to(base).as_posix()
        except ValueError:
            continue
    return resolved.as_posix()


def _flatten(obj: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                out.update(_flatten(v, p))
            else:
                out[p] = v
    return out


def _normalize_path(value: Any) -> Path:
    return _resolve_local_path(value)


def load_manifest(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise OpticsError(f"Invalid JSON manifest: {exc}") from exc
    parsed = TextProtoParser(text).parse()
    # Unwrap single-value fields for easier access.
    return {k: (v[0] if len(v) == 1 else v) for k, v in parsed.items()}


def _check_manifest_top_level(manifest: Dict[str, Any]) -> None:
    if manifest.get("display_only") not in (True, "true", 1, "1"):
        raise OpticsError("Manifest display_only must be true")
    failures = manifest.get("failures", [])
    if failures:
        raise OpticsError(f"Manifest reports failures: {failures}")
    before = manifest.get("identity_before")
    after = manifest.get("identity_after")
    if before is not None and after is not None and before != after:
        raise OpticsError(
            "Identity unstable: identity_before != identity_after "
            "(capture-time provenance only)"
        )


def _find_source_entry(
    manifest: Dict[str, Any], role: str, source_path: Path
) -> Dict[str, Any]:
    """Locate the manifest source entry for this role/source file."""
    for list_key in ("verified", "sources"):
        entries = manifest.get(list_key)
        if isinstance(entries, list):
            matches: List[Dict[str, Any]] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                entry_role = entry.get("role")
                local_path = entry.get("local_path")
                resolved: Path | None = None
                if isinstance(local_path, str):
                    try:
                        resolved = _resolve_local_path(local_path)
                    except OpticsError:
                        resolved = None
                by_role = (
                    isinstance(entry_role, str)
                    and entry_role.lower() == role.lower()
                )
                by_path = resolved is not None and resolved == source_path.resolve()
                if by_role or by_path:
                    matches.append(entry)
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise OpticsError(
                    f"Manifest has multiple source entries matching {role!r}"
                )
            raise OpticsError(
                f"Manifest {list_key!r} list missing entry for {role!r}"
            )

    # Legacy schemas: nested role dict or role-prefixed root keys.
    role_node = manifest.get(role)
    if isinstance(role_node, dict):
        return {
            "local_path": role_node.get("path"),
            "original_path": role_node.get("original_path"),
            "sha256": role_node.get("sha256"),
            "selected_block_sha256": role_node.get("block_sha256"),
            "status": role_node.get("status", "verified"),
            "selected_capture_not_full_file": role_node.get(
                "selected_capture_not_full_file", True
            ),
        }

    flat = _flatten(manifest)

    def pick(*suffixes: str) -> Any:
        for suffix in suffixes:
            key = f"{role}_{suffix}"
            if key in manifest:
                return manifest[key]
            if key in flat:
                return flat[key]
        raise OpticsError(
            f"Manifest missing {role!r} entry (tried {', '.join(suffixes)})"
        )

    return {
        "local_path": pick("path", "local_path"),
        "original_path": pick("original_path"),
        "sha256": pick("sha256", "file_sha256"),
        "selected_block_sha256": pick("block_sha256", "selected_block_sha256"),
        "status": manifest.get(f"{role}_status", "verified"),
        "selected_capture_not_full_file": manifest.get(
            f"{role}_selected_capture_not_full_file", True
        ),
    }


def _verify_source_entry(
    role: str, source_path: Path, entry: Dict[str, Any]
) -> Tuple[str, str]:
    """Verify the local captured block against the manifest entry.

    Does NOT claim verification of the original full source file; only the
    local captured block and capture-time provenance fields are checked.
    """
    if entry.get("status") != "verified":
        raise OpticsError(f"{role}: manifest status is not 'verified'")
    if entry.get("selected_capture_not_full_file") is not True:
        raise OpticsError(
            f"{role}: selected_capture_not_full_file must be true"
        )

    before = entry.get("original_sha_before")
    after = entry.get("original_sha_after")
    if before is not None and after is not None and before != after:
        raise OpticsError(
            f"{role}: original identity unstable (before != after)"
        )

    local_path_raw = entry.get("local_path")
    if not isinstance(local_path_raw, str):
        raise OpticsError(f"{role}: manifest missing local_path")
    resolved_local = _resolve_local_path(local_path_raw)
    if resolved_local != source_path.resolve():
        raise OpticsError(
            f"{role} path mismatch: manifest local_path resolves to "
            f"{resolved_local}, CLI provided {source_path.resolve()}"
        )

    original_path = entry.get("original_path")
    if not isinstance(original_path, str) or not original_path:
        raise OpticsError(f"{role}: manifest missing original_path")
    if not original_path.startswith("/"):
        raise OpticsError(
            f"{role}: original_path must be absolute: {original_path}"
        )

    # Extract the optical block and the full local-file hash separately.
    # A trailing newline/whitespace is allowed outside the block, so the
    # selected-block hash and the full-file hash may legitimately differ.
    block_bytes, block_hash, file_hash = extract_optical_block_hashes(source_path)
    block_size_actual = len(block_bytes)
    file_size = len(source_path.read_bytes())

    manifest_file_hash = entry.get("sha256")
    if isinstance(manifest_file_hash, str) and manifest_file_hash != file_hash:
        raise OpticsError(
            f"{role}: local file SHA-256 mismatch: "
            f"computed {file_hash}, manifest {manifest_file_hash}"
        )

    start = entry.get("selected_block_start")
    end = entry.get("selected_block_end")
    block_size = entry.get("selected_block_size")
    manifest_block_hash = entry.get("selected_block_sha256")

    # Coherence checks for the byte span recorded at capture time.
    if (
        isinstance(start, int)
        and isinstance(end, int)
        and isinstance(block_size, int)
    ):
        if end - start != block_size:
            raise OpticsError(
                f"{role}: selected_block_end - start ({end - start}) != "
                f"selected_block_size ({block_size})"
            )
        if block_size != block_size_actual:
            raise OpticsError(
                f"{role}: selected_block_size ({block_size}) != "
                f"extracted block size ({block_size_actual})"
            )

    if isinstance(manifest_block_hash, str) and manifest_block_hash != block_hash:
        raise OpticsError(
            f"{role}: selected block SHA-256 mismatch: "
            f"computed {block_hash}, manifest {manifest_block_hash}"
        )

    manifest_size = entry.get("size")
    if isinstance(manifest_size, int) and manifest_size != file_size:
        raise OpticsError(
            f"{role}: manifest size ({manifest_size}) != "
            f"local file size ({file_size})"
        )

    return block_hash, file_hash


def verify_source_against_manifest(
    role: str, source_path: Path, manifest_path: Path
) -> Tuple[str, str]:
    manifest = load_manifest(manifest_path)
    _check_manifest_top_level(manifest)
    entry = _find_source_entry(manifest, role, source_path)
    return _verify_source_entry(role, source_path, entry)


# ---------------------------------------------------------------------------
# Optical profile analysis
# ---------------------------------------------------------------------------

REQUIRED_SCALAR_FIELDS = {
    "u", "v",
    "red_x", "red_y", "red_z",
    "green_x", "green_y", "green_z",
    "blue_x", "blue_y", "blue_z",
}
OPTIONAL_SCALAR_FIELDS = {"id_x", "id_y"}
CHANNELS = ("red", "green", "blue")
TOL = 1e-6


def _finite(value: Any) -> bool:
    return isinstance(value, (int, float)) and math.isfinite(value)


def _read_cell(raw: Dict[str, List[Any]], idx: int, block: str, eye: str) -> Dict[str, Any]:
    cell: Dict[str, Any] = {}
    for name in REQUIRED_SCALAR_FIELDS:
        v = get_scalar(raw, name)
        if not _finite(v):
            raise OpticsError(
                f"{block}/{eye} cell {idx}: {name} is non-finite ({v!r})"
            )
        cell[name] = float(v)
    for name in OPTIONAL_SCALAR_FIELDS:
        values = raw.get(name)
        if values:
            if len(values) > 1:
                raise OpticsError(f"{name} repeated in cell {idx}")
            v = values[0]
            if not _finite(v):
                raise OpticsError(
                    f"{block}/{eye} cell {idx}: {name} is non-finite ({v!r})"
                )
            cell[name] = float(v)
    return cell


def _channel_vector(cell: Dict[str, Any], channel: str) -> List[float]:
    return [cell[f"{channel}_x"], cell[f"{channel}_y"], cell[f"{channel}_z"]]


def _euclidean(a: List[float], b: List[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def _validate_grid(
    cells: List[Dict[str, Any]],
    rows: int,
    cols: int,
    width_px: float,
    height_px: float,
    label: str,
) -> None:
    expected = rows * cols
    if len(cells) != expected:
        raise OpticsError(
            f"{label}: expected {expected} cells ({rows}x{cols}), got {len(cells)}"
        )
    uv_set = set((c["u"], c["v"]) for c in cells)
    if len(uv_set) != expected:
        raise OpticsError(f"{label}: duplicate or missing (u,v) coordinates")
    u_vals = sorted({c["u"] for c in cells})
    v_vals = sorted({c["v"] for c in cells})
    # Live capture: 73 unique u == cols, 79 unique v == rows; v is fastest.
    if len(u_vals) != cols:
        raise OpticsError(
            f"{label}: expected {cols} unique u values, got {len(u_vals)}"
        )
    if len(v_vals) != rows:
        raise OpticsError(
            f"{label}: expected {rows} unique v values, got {len(v_vals)}"
        )
    for i, cell in enumerate(cells):
        u_exp = u_vals[i // rows]
        v_exp = v_vals[i % rows]
        if cell["u"] != u_exp or cell["v"] != v_exp:
            raise OpticsError(
                f"{label}: cell {i} ordering mismatch "
                f"(u={cell['u']},v={cell['v']}; expected u={u_exp},v={v_exp}). "
                "u must ascend with v fastest."
            )
    half_w = width_px / 2.0
    half_h = height_px / 2.0
    if u_vals[0] < -half_w - TOL or u_vals[-1] > half_w + TOL:
        raise OpticsError(
            f"{label}: u range [{u_vals[0]}, {u_vals[-1]}] outside "
            f"expected [-{half_w}, {half_w}]"
        )
    if v_vals[0] < -half_h - TOL or v_vals[-1] > half_h + TOL:
        raise OpticsError(
            f"{label}: v range [{v_vals[0]}, {v_vals[-1]}] outside "
            f"expected [-{half_h}, {half_h}]"
        )


def _check_id_grid(cells: List[Dict[str, Any]], rows: int, cols: int, label: str) -> Tuple[bool, List[str]]:
    if not cells or "id_x" not in cells[0]:
        return False, []
    warnings: List[str] = []
    try:
        ix_vals = sorted({c["id_x"] for c in cells})
        iy_vals = sorted({c["id_y"] for c in cells})
        # u has cols unique values and varies slowest; id grid follows the same layout.
        if len(ix_vals) != cols or len(iy_vals) != rows:
            warnings.append(
                f"{label}: id grid dimensions ({len(ix_vals)}x{len(iy_vals)}) "
                f"do not match lut dimensions ({rows}x{cols})"
            )
            return False, warnings
        ok = True
        for i, c in enumerate(cells):
            ix_exp = ix_vals[i // rows]
            iy_exp = iy_vals[i % rows]
            if c["id_x"] != ix_exp or c["id_y"] != iy_exp:
                ok = False
                warnings.append(
                    f"{label}: id ordering mismatch at cell {i}"
                )
                break
        return ok, warnings
    except KeyError as exc:
        warnings.append(f"{label}: incomplete id fields: {exc}")
        return False, warnings


def _read_fov(fov_msg: Dict[str, List[Any]]) -> Dict[str, float]:
    left = scalar_number(fov_msg, "left_radians")
    right = scalar_number(fov_msg, "right_radians")
    top = scalar_number(fov_msg, "top_radians")
    bottom = scalar_number(fov_msg, "bottom_radians")
    horizontal = left + right
    vertical = top + bottom
    return {
        "left_radians": left,
        "right_radians": right,
        "top_radians": top,
        "bottom_radians": bottom,
        "horizontal_radians": horizontal,
        "vertical_radians": vertical,
        "horizontal_degrees": math.degrees(horizontal),
        "vertical_degrees": math.degrees(vertical),
    }


def _process_eye(
    profile: Dict[str, List[Any]],
    eye_name: str,
    source_path: Path,
    block_hash: str,
    expect_device: bool,
) -> Dict[str, Any]:
    eye_msg = get_scalar(profile, eye_name)
    if not isinstance(eye_msg, dict):
        raise OpticsError(f"{eye_name} is not a message")
    rows_raw = scalar_number(eye_msg, "lut_rows")
    cols_raw = scalar_number(eye_msg, "lut_cols")
    if not isinstance(rows_raw, int) and not float(rows_raw).is_integer():
        raise OpticsError(f"{eye_name}: lut_rows must be an integer, got {rows_raw!r}")
    if not isinstance(cols_raw, int) and not float(cols_raw).is_integer():
        raise OpticsError(f"{eye_name}: lut_cols must be an integer, got {cols_raw!r}")
    rows = int(rows_raw)
    cols = int(cols_raw)
    if rows <= 0 or cols <= 0:
        raise OpticsError(
            f"{eye_name}: lut_rows/lut_cols must be positive, got {rows}x{cols}"
        )
    width_px = scalar_number(eye_msg, "calibrated_width_px")
    height_px = scalar_number(eye_msg, "calibrated_height_px")
    for name, value in (("calibrated_width_px", width_px), ("calibrated_height_px", height_px)):
        if not math.isfinite(value) or value <= 0 or not float(value).is_integer():
            raise OpticsError(f"{eye_name}: {name} must be a positive finite integer, got {value!r}")
    width_px = int(width_px)
    height_px = int(height_px)
    ipd_mm = scalar_number(eye_msg, "device_ipd_in_mm")

    if expect_device:
        if rows != 79 or cols != 73:
            raise OpticsError(
                f"--expect-device requires 79x73 LUT, got {rows}x{cols}"
            )
        if abs(ipd_mm - 62.0) > TOL:
            raise OpticsError(
                f"--expect-device requires ipd_mm=62, got {ipd_mm}"
            )
        if abs(width_px - 3552.0) > TOL or abs(height_px - 3840.0) > TOL:
            raise OpticsError(
                f"--expect-device requires 3552x3840, got {width_px}x{height_px}"
            )

    luts = get_repeated(eye_msg, "luts")
    if not luts:
        raise OpticsError(f"{eye_name}: no luts blocks")
    populated: List[Tuple[int, Dict[str, List[Any]]]] = []
    for idx, lut in enumerate(luts):
        if not isinstance(lut, dict):
            raise OpticsError(f"{eye_name}: lut block {idx} is not a message")
        cells_raw = get_repeated(lut, "cells")
        if cells_raw:
            populated.append((idx, lut))
    if len(populated) == 0:
        raise OpticsError(f"{eye_name}: all lut blocks are empty")
    if len(populated) > 1:
        raise OpticsError(
            f"{eye_name}: ambiguous populated LUTs: "
            f"{len(populated)} non-empty blocks (cannot silently select one)"
        )
    lut_index, lut = populated[0]
    cells_raw = get_repeated(lut, "cells")
    cells = [_read_cell(c, i, source_path.name, eye_name) for i, c in enumerate(cells_raw)]
    empty_lut_blocks = len(luts) - 1

    label = f"{source_path.name}/{eye_name}"
    _validate_grid(cells, rows, cols, width_px, height_px, label)
    id_ok, id_warnings = _check_id_grid(cells, rows, cols, label)

    fov_metadata: Dict[str, Any] = {}
    green_fov = lut.get("green_fov")
    if green_fov and isinstance(green_fov[0], dict):
        fov_metadata["green_fov"] = _read_fov(green_fov[0])
    optical_fov = eye_msg.get("optical_fov")
    if optical_fov and isinstance(optical_fov[0], dict):
        fov_metadata["optical_fov"] = _read_fov(optical_fov[0])
    verified_fov = eye_msg.get("verified_fov")
    if verified_fov and isinstance(verified_fov[0], dict):
        fov_metadata["verified_fov"] = _read_fov(verified_fov[0])

    return {
        "rows": rows,
        "cols": cols,
        "width_px": width_px,
        "height_px": height_px,
        "ipd_mm": ipd_mm,
        "lut_block_count": len(luts),
        "selected_lut_block_index": lut_index,
        "empty_lut_blocks": empty_lut_blocks,
        "cells": cells,
        "fov": fov_metadata,
        "validation": {
            "id_grid_consistent": id_ok,
            "id_grid_warnings": id_warnings,
        },
    }


def _extract_profile(
    source_path: Path,
    block_hash: str,
    source_hash: str,
    expect_device: bool,
) -> Dict[str, Any]:
    text = source_path.read_text(encoding="utf-8")
    parsed = TextProtoParser(text).parse()
    dv = get_scalar(parsed, "display_profile_v2")
    if not isinstance(dv, dict):
        raise OpticsError("display_profile_v2 is not a message")
    left = _process_eye(dv, "left_display_profile", source_path, block_hash, expect_device)
    right = _process_eye(dv, "right_display_profile", source_path, block_hash, expect_device)
    return {
        "source_path": _portable_source_path(source_path),
        "source_sha256": source_hash,
        "block_sha256": block_hash,
        "left": left,
        "right": right,
    }


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def _component_bounds(cells: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    bounds: Dict[str, Dict[str, float]] = {}
    for channel in CHANNELS:
        xs = [c[f"{channel}_x"] for c in cells]
        ys = [c[f"{channel}_y"] for c in cells]
        zs = [c[f"{channel}_z"] for c in cells]
        bounds[channel] = {
            "x": {"min": min(xs), "max": max(xs)},
            "y": {"min": min(ys), "max": max(ys)},
            "z": {"min": min(zs), "max": max(zs)},
        }
    return bounds


def _rgb_separation_stats(cells: List[Dict[str, Any]]) -> Dict[str, Any]:
    rg = []
    rb = []
    gb = []
    for c in cells:
        rg.append(_euclidean(_channel_vector(c, "red"), _channel_vector(c, "green")))
        rb.append(_euclidean(_channel_vector(c, "red"), _channel_vector(c, "blue")))
        gb.append(_euclidean(_channel_vector(c, "green"), _channel_vector(c, "blue")))
    def stats(vals: List[float]) -> Dict[str, float]:
        return {
            "min": min(vals),
            "max": max(vals),
            "mean": sum(vals) / len(vals),
            "rms": math.sqrt(sum(v * v for v in vals) / len(vals)),
        }
    return {
        "red_green": stats(rg),
        "red_blue": stats(rb),
        "green_blue": stats(gb),
    }


def _ratio_singularities(cells: List[Dict[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for channel in CHANNELS:
        xz_total = yz_total = 0
        xz_sing = yz_sing = 0
        for c in cells:
            z = c[f"{channel}_z"]
            if abs(z) <= TOL:
                xz_sing += 1
                yz_sing += 1
            xz_total += 1
            yz_total += 1
        result[channel] = {
            "xz_ratio_singularities": xz_sing,
            "yz_ratio_singularities": yz_sing,
            "total_cells": xz_total,
        }
    return result


def _eye_statistics(eye: Dict[str, Any]) -> Dict[str, Any]:
    cells = eye["cells"]
    validation = eye.get("validation", {})
    fov_stats: Dict[str, Any] = {}
    for name, fov in eye.get("fov", {}).items():
        fov_stats[name] = {
            "horizontal_degrees": fov["horizontal_degrees"],
            "vertical_degrees": fov["vertical_degrees"],
        }
    return {
        "component_bounds": _component_bounds(cells),
        "rgb_separation": _rgb_separation_stats(cells),
        "ratio_singularities": _ratio_singularities(cells),
        "fov_degrees": fov_stats,
        "validation": {
            "id_grid_consistent": validation.get("id_grid_consistent", False),
            "id_grid_warnings": validation.get("id_grid_warnings", []),
        },
    }


def _compare_eyes(fac: Dict[str, Any], ven: Dict[str, Any]) -> Dict[str, Any]:
    fcells = { (c["u"], c["v"]): c for c in fac["cells"] }
    vcells = { (c["u"], c["v"]): c for c in ven["cells"] }
    common = sorted(set(fcells) & set(vcells))
    f_only = sorted(set(fcells) - set(vcells))
    v_only = sorted(set(vcells) - set(fcells))
    diffs: Dict[str, List[float]] = {channel: [] for channel in CHANNELS}
    for uv in common:
        fc = fcells[uv]
        vc = vcells[uv]
        for channel in CHANNELS:
            diffs[channel].append(
                _euclidean(_channel_vector(fc, channel), _channel_vector(vc, channel))
            )
    per_channel: Dict[str, Any] = {}
    for channel in CHANNELS:
        vals = diffs[channel]
        per_channel[channel] = {
            "count": len(vals),
            "rms": math.sqrt(sum(v * v for v in vals) / len(vals)) if vals else None,
            "max": max(vals) if vals else None,
            "mean": sum(vals) / len(vals) if vals else None,
        }
    return {
        "matched_cells": len(common),
        "factory_only_cells": len(f_only),
        "vendor_only_cells": len(v_only),
        "mismatched_cells": len(f_only) + len(v_only),
        "per_channel_euclidean_difference": per_channel,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_analysis(
    factory_path: Path,
    vendor_path: Path,
    manifest_path: Path,
    expect_device: bool,
) -> Dict[str, Any]:
    fac_block_hash, fac_source_hash = verify_source_against_manifest(
        "factory", factory_path, manifest_path
    )
    ven_block_hash, ven_source_hash = verify_source_against_manifest(
        "vendor", vendor_path, manifest_path
    )

    factory = _extract_profile(factory_path, fac_block_hash, fac_source_hash, expect_device)
    vendor = _extract_profile(vendor_path, ven_block_hash, ven_source_hash, expect_device)

    stats: Dict[str, Any] = {
        "factory": {
            "left": _eye_statistics(factory["left"]),
            "right": _eye_statistics(factory["right"]),
        },
        "vendor": {
            "left": _eye_statistics(vendor["left"]),
            "right": _eye_statistics(vendor["right"]),
        },
    }
    comparisons: Dict[str, Any] = {
        "left": _compare_eyes(factory["left"], vendor["left"]),
        "right": _compare_eyes(factory["right"], vendor["right"]),
    }

    limitations = [
        "RGB XYZ units and display coordinate-frame origin are not established.",
        "No degrees, micrometers, FOV, or optical-improvement claims are made.",
        "Values are preserved exactly as parsed; no smoothing or rewriting.",
        "X/-Z and Y/-Z ratio singularity counts are raw diagnostics, not ray angles.",
        "Raw X/Y projected-grid topology labels are exploratory, not foldover proof.",
        "Z components are treated as ordinary 3D geometry; non-zero values are not defects.",
        "Original full-source SHA-256 is capture-time provenance, not locally recomputed.",
    ]

    analysis: Dict[str, Any] = {
        "schema_version": 1,
        "profiles": {
            "factory": factory,
            "vendor": vendor,
        },
        "statistics": stats,
        "comparisons": comparisons,
        "limitations": limitations,
    }
    return analysis


def _cells_for_json(cells: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in cells:
        item: Dict[str, Any] = {
            "u": c["u"],
            "v": c["v"],
            "red": [c["red_x"], c["red_y"], c["red_z"]],
            "green": [c["green_x"], c["green_y"], c["green_z"]],
            "blue": [c["blue_x"], c["blue_y"], c["blue_z"]],
        }
        if "id_x" in c:
            item["id_x"] = c["id_x"]
        if "id_y" in c:
            item["id_y"] = c["id_y"]
        out.append(item)
    return out


def _prepare_for_output(analysis: Dict[str, Any]) -> Dict[str, Any]:
    # Convert internal cell representation to the fixed JSON contract.
    out = json.loads(json.dumps(analysis))  # deep copy
    contract_fields = {
        "rows", "cols", "width_px", "height_px", "ipd_mm",
        "lut_block_count", "empty_lut_blocks", "cells", "fov",
    }
    for role in ("factory", "vendor"):
        for eye in ("left", "right"):
            eye_obj = out["profiles"][role][eye]
            eye_obj["cells"] = _cells_for_json(eye_obj["cells"])
            for key in list(eye_obj.keys()):
                if key not in contract_fields:
                    del eye_obj[key]
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Parse DISPLAY-ONLY optical textprotos and emit analysis.json."
    )
    parser.add_argument("--factory", required=True, type=Path, help="Factory textproto")
    parser.add_argument("--vendor", required=True, type=Path, help="Vendor textproto")
    parser.add_argument("--manifest", required=True, type=Path, help="Manifest file")
    parser.add_argument("--output", required=True, type=Path, help="Output JSON path")
    parser.add_argument(
        "--expect-device",
        action="store_true",
        help="Require 79x73 LUT, ipd 62 mm, 3552x3840 resolution",
    )
    args = parser.parse_args(argv)

    for p in (args.factory, args.vendor, args.manifest):
        if not p.exists():
            print(f"ERROR: input not found: {p}", file=sys.stderr)
            return 2

    try:
        analysis = build_analysis(
            args.factory, args.vendor, args.manifest, args.expect_device
        )
    except OpticsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    out_data = _prepare_for_output(analysis)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out_data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    # Concise stdout report
    prof = out_data["profiles"]
    print(f"schema_version: {out_data['schema_version']}")
    for role in ("factory", "vendor"):
        for eye in ("left", "right"):
            e = prof[role][eye]
            print(
                f"{role}.{eye}: {e['rows']}x{e['cols']} "
                f"blocks={e['lut_block_count']} "
                f"empty={e['empty_lut_blocks']} "
                f"cells={len(e['cells'])}"
            )
    for eye in ("left", "right"):
        c = out_data["comparisons"][eye]
        print(
            f"factory-vs-vendor.{eye}: matched={c['matched_cells']} "
            f"mismatched={c['mismatched_cells']}"
        )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
