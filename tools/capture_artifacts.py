#!/usr/bin/env python3
"""Binary-safe targeted optical-artifact collector.

CLI: python -B capture_artifacts.py --adb PATH --serial SERIAL --output NEW_CAPTURE_DIR path [path ...]
       [--display-only]

* root read-only via `adb -s SERIAL shell -T "su -c 'COMMAND'"`
* validates absolute safe Android paths
* verifies identity (uid0, fingerprint, kernel) before/after
* binary probe with NUL/FF/CRLF before/after
* per-file stat, remote SHA256 before, binary cat, local SHA256,
  remote SHA256 after, atomic .partial publication
* --display-only extracts only the top-level `display_profile_v2 { ... }`
  subtree from mixed protobuf text files; no raw mixed bytes are persisted
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from typing import Optional, Tuple

MAX_FILE_SIZE = 128 * 1024 * 1024  # 128 MiB
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./+-]+$")
PROBE_BYTES = bytes(range(256))  # deterministic; contains NUL, FF, CRLF


class TextProtoError(Exception):
    """Raised by the protobuf-text display_profile_v2 extractor."""


class DisplayBlockNotFound(TextProtoError):
    pass


class DisplayBlockDuplicate(TextProtoError):
    pass


class DisplayBlockMalformed(TextProtoError):
    pass


def _abort(message: str, code: int = 1) -> None:
    print(message, file=sys.stderr)
    sys.exit(code)


def _su_command(inner: str) -> str:
    """Wrap inner shell command for `su -c '...'` argument."""
    escaped = inner.replace("'", "'\\''")
    return f"su -c '{escaped}'"


def run_adb_command(
    adb_path: str, serial: str, inner_command: str, timeout: float = 300.0
) -> Tuple[int, bytes, bytes]:
    """Run one adb shell -T su command. Returns (rc, stdout, stderr)."""
    args = [
        adb_path,
        "-s",
        serial,
        "shell",
        "-T",
        _su_command(inner_command),
    ]
    result = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _parse_sha256_line(stdout: bytes) -> Optional[str]:
    if not stdout:
        return None
    token = stdout.split()[0]
    if len(token) != 64:
        return None
    try:
        return token.decode("ascii").lower()
    except UnicodeDecodeError:
        return None


def validate_remote_path(path: str) -> None:
    if not path or not path.startswith("/"):
        raise ValueError(f"path must be absolute: {path!r}")
    if not SAFE_PATH_RE.fullmatch(path):
        raise ValueError(f"path contains disallowed characters: {path!r}")
    if "//" in path:
        raise ValueError(f"path contains empty segment: {path!r}")
    segments = [s for s in path.split("/") if s]
    for seg in segments:
        if seg == "..":
            raise ValueError(f"path contains parent reference: {path!r}")
        if seg == ".":
            raise ValueError(f"path contains current segment: {path!r}")
    if path.endswith("/") or path.endswith("."):
        raise ValueError(f"path has trailing separator/dot: {path!r}")


def ensure_output_dir(output_dir: str) -> None:
    if os.path.exists(output_dir):
        raise ValueError(f"output directory already exists: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)


def collect_identity(adb_path: str, serial: str) -> dict:
    rc, stdout, stderr = run_adb_command(adb_path, serial, "id -u")
    if rc != 0:
        raise RuntimeError(f"id -u failed: rc={rc} stderr={stderr!r}")
    try:
        uid = int(stdout.strip())
    except ValueError as exc:
        raise RuntimeError(f"id -u returned non-integer: {stdout!r}") from exc
    if uid != 0:
        raise RuntimeError(f"not running as uid0: uid={uid}")

    rc2, fp_out, fp_err = run_adb_command(
        adb_path, serial, "getprop ro.build.fingerprint"
    )
    if rc2 != 0:
        raise RuntimeError(f"getprop fingerprint failed: rc={rc2} stderr={fp_err!r}")

    rc3, uname_out, uname_err = run_adb_command(adb_path, serial, "uname -a")
    if rc3 != 0:
        raise RuntimeError(f"uname failed: rc={rc3} stderr={uname_err!r}")

    return {
        "uid": uid,
        "fingerprint": fp_out.strip().decode("utf-8", errors="replace"),
        "kernel": uname_out.strip().decode("utf-8", errors="replace"),
    }


def probe_binary_transfer(
    adb_path: str, serial: str, transport: str = "raw"
) -> dict:
    """Decode PROBE_BYTES on device and compare the returned bytes.

    In base64 transport the bytes are decoded on-device, re-encoded with
    base64, transferred as ASCII, then strict-decoded on the host after
    stripping CR/LF line noise.
    """
    b64 = base64.b64encode(PROBE_BYTES).decode("ascii")
    if transport == "base64":
        inner = f"printf '%s' {shlex.quote(b64)} | base64 -d | base64"
    else:
        inner = f"printf '%s' {shlex.quote(b64)} | base64 -d"
    rc, stdout, stderr = run_adb_command(adb_path, serial, inner)
    expected_hash = hashlib.sha256(PROBE_BYTES).hexdigest()
    result = {
        "command": inner,
        "returncode": rc,
        "transport": transport,
        "stderr": stderr.decode("utf-8", errors="replace"),
        "expected_length": len(PROBE_BYTES),
        "expected_sha256": expected_hash,
    }
    if rc != 0:
        result["status"] = "failed"
        result["reason"] = "probe command failed"
        return result

    if transport == "base64":
        result["encoded_length"] = len(stdout)
        result["encoded_sha256"] = hashlib.sha256(stdout).hexdigest()
        try:
            decoded = _decode_base64_transport(stdout)
        except Exception as exc:
            result["status"] = "failed"
            result["reason"] = f"base64 decode failed: {exc}"
            return result
        compare = decoded
    else:
        compare = stdout

    result["stdout_length"] = len(compare)
    result["stdout_sha256"] = hashlib.sha256(compare).hexdigest()
    if len(compare) != len(PROBE_BYTES):
        result["status"] = "failed"
        result["reason"] = (
            f"probe length mismatch expected={len(PROBE_BYTES)} got={len(compare)}"
        )
        return result
    if compare != PROBE_BYTES:
        result["status"] = "failed"
        result["reason"] = "probe byte content mismatch"
        return result
    result["status"] = "verified"
    return result


def _is_ident_start(b: int) -> bool:
    return (
        (ord("A") <= b <= ord("Z"))
        or (ord("a") <= b <= ord("z"))
        or b == ord("_")
        or b == ord(".")
    )


def _is_ident_char(b: int) -> bool:
    return _is_ident_start(b) or (ord("0") <= b <= ord("9"))


_WS_BYTES = {ord(" "), ord("\t"), ord("\n"), ord("\r")}


def _skip_ws(data: bytes, i: int) -> int:
    n = len(data)
    while i < n and data[i] in _WS_BYTES:
        i += 1
    return i


def _skip_comment(data: bytes, i: int) -> int:
    """Skip a comment starting at i. Supports #, // and /* ... */."""
    n = len(data)
    if data[i] == ord("#") or (i + 1 < n and data[i] == ord("/") and data[i + 1] == ord("/")):
        while i < n and data[i] not in (ord("\n"), ord("\r")):
            i += 1
        return i
    if i + 1 < n and data[i] == ord("/") and data[i + 1] == ord("*"):
        i += 2
        while i + 1 < n and not (data[i] == ord("*") and data[i + 1] == ord("/")):
            i += 1
        if i + 1 >= n:
            raise DisplayBlockMalformed("unterminated block comment")
        return i + 2
    return i


def _skip_ws_and_comments(data: bytes, i: int) -> int:
    n = len(data)
    while i < n:
        if data[i] in _WS_BYTES:
            i = _skip_ws(data, i)
            continue
        if data[i] == ord("#") or (
            data[i] == ord("/") and i + 1 < n and data[i + 1] in (ord("/"), ord("*"))
        ):
            i = _skip_comment(data, i)
            continue
        break
    return i


def _parse_string(data: bytes, i: int) -> int:
    """Parse a single or double quoted string with backslash escapes."""
    n = len(data)
    quote = data[i]
    i += 1
    while i < n:
        if data[i] == ord("\\") and i + 1 < n:
            i += 2
            continue
        if data[i] == quote:
            return i + 1
        i += 1
    raise DisplayBlockMalformed("unterminated string literal")


def extract_display_profile_v2(data: bytes) -> Tuple[int, int, bytes]:
    """
    Extract the top-level display_profile_v2 { ... } block from protobuf text.

    Returns (start_offset, end_offset, block_bytes).
    Raises DisplayBlockNotFound, DisplayBlockDuplicate, DisplayBlockMalformed.
    """
    n = len(data)
    i = 0
    depth = 0
    found_block: Optional[Tuple[int, int, bytes]] = None
    block_start: Optional[int] = None

    while i < n:
        i = _skip_ws_and_comments(data, i)
        if i >= n:
            break

        b = data[i]

        if b == ord('"') or b == ord("'"):
            i = _parse_string(data, i)
            continue

        if _is_ident_start(b):
            start = i
            while i < n and _is_ident_char(data[i]):
                i += 1
            ident = data[start:i]

            if ident == b"display_profile_v2" and depth == 0:
                j = _skip_ws_and_comments(data, i)
                if j < n and data[j] == ord(":"):
                    j += 1
                    j = _skip_ws_and_comments(data, j)
                if j < n and data[j] == ord("{"):
                    if found_block is not None:
                        raise DisplayBlockDuplicate(
                            "multiple top-level display_profile_v2 blocks"
                        )
                    block_start = start
                    i = j + 1
                    depth = 1
                    continue
            continue

        if b == ord("{"):
            depth += 1
            i += 1
            continue

        if b == ord("}"):
            depth -= 1
            i += 1
            if depth < 0:
                raise DisplayBlockMalformed("unbalanced closing brace")
            if depth == 0 and block_start is not None:
                found_block = (block_start, i, data[block_start:i])
                block_start = None
            continue

        # any other character
        i += 1

    if depth != 0:
        raise DisplayBlockMalformed("unbalanced braces at end of file")

    if found_block is None:
        raise DisplayBlockNotFound("display_profile_v2 block not found")

    return found_block


def remote_stat_size(adb_path: str, serial: str, path: str) -> Tuple[Optional[int], dict]:
    inner = f"stat -c %s {shlex.quote(path)}"
    rc, stdout, stderr = run_adb_command(adb_path, serial, inner)
    record = {
        "command": inner,
        "returncode": rc,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }
    if rc != 0:
        return None, record
    try:
        size = int(stdout.strip())
    except ValueError:
        return None, record
    return size, record


def remote_is_regular(adb_path: str, serial: str, path: str) -> Tuple[bool, dict]:
    inner = f"test -f {shlex.quote(path)}"
    rc, stdout, stderr = run_adb_command(adb_path, serial, inner)
    return rc == 0, {
        "command": inner,
        "returncode": rc,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }


def remote_sha256(adb_path: str, serial: str, path: str) -> Tuple[Optional[str], dict]:
    inner = f"sha256sum {shlex.quote(path)}"
    rc, stdout, stderr = run_adb_command(adb_path, serial, inner)
    record = {
        "command": inner,
        "returncode": rc,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }
    if rc != 0:
        return None, record
    return _parse_sha256_line(stdout), record


def _local_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_base64_transport(stdout: bytes) -> bytes:
    """Strip CR/LF line noise and strict-decode base64 transport output."""
    stripped = stdout.replace(b"\r", b"").replace(b"\n", b"")
    return base64.b64decode(stripped, validate=True)


def _local_path_for(output_dir: str, remote_path: str) -> str:
    parts = [p for p in remote_path.split("/") if p]
    return os.path.join(output_dir, "originals", *parts)


def _display_local_path(local_path: str) -> str:
    return local_path + ".display_profile_v2.textproto"


def _atomic_write_bytes(path: str, data: bytes) -> None:
    partial = path + ".partial"
    with open(partial, "xb") as fh:
        fh.write(data)
    os.replace(partial, path)


def _atomic_write_json(path: str, obj: dict) -> None:
    data = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8")
    _atomic_write_bytes(path, data)


def _remove_partial(path: str) -> None:
    partial = path + ".partial"
    try:
        os.unlink(partial)
    except FileNotFoundError:
        pass


def capture_file(
    adb_path: str,
    serial: str,
    remote_path: str,
    output_dir: str,
    identity: dict,
    display_only: bool = False,
    transport: str = "raw",
) -> dict:
    entry: dict = {
        "original_path": remote_path,
        "identity": identity,
        "transport": transport,
        "status": "failed",
        "commands": {},
    }

    try:
        validate_remote_path(remote_path)
    except ValueError as exc:
        entry["reason"] = str(exc)
        return entry

    local_path = _local_path_for(output_dir, remote_path)
    if display_only:
        local_path = _display_local_path(local_path)

    if os.path.exists(local_path):
        entry["reason"] = f"local target already exists: {local_path}"
        return entry

    # stat + regular check
    size, stat_rec = remote_stat_size(adb_path, serial, remote_path)
    entry["commands"]["stat"] = stat_rec
    if size is None:
        entry["reason"] = "remote stat failed"
        return entry
    if size > MAX_FILE_SIZE:
        entry["reason"] = f"remote size {size} exceeds {MAX_FILE_SIZE}"
        return entry

    is_reg, reg_rec = remote_is_regular(adb_path, serial, remote_path)
    entry["commands"]["test_f"] = reg_rec
    if not is_reg:
        entry["reason"] = "remote path is not a regular file"
        return entry

    sha_before, sha_before_rec = remote_sha256(adb_path, serial, remote_path)
    entry["commands"]["sha256_before"] = sha_before_rec
    entry["original_sha_before"] = sha_before
    if sha_before is None:
        entry["reason"] = "remote sha256 before transfer failed"
        return entry

    # binary read over shell -T (raw or base64 transport)
    if transport == "base64":
        cat_inner = f"base64 {shlex.quote(remote_path)}"
    else:
        cat_inner = f"cat {shlex.quote(remote_path)}"
    cat_rc, cat_stdout, cat_stderr = run_adb_command(adb_path, serial, cat_inner)
    cat_record: dict = {
        "command": cat_inner,
        "returncode": cat_rc,
        "transport": transport,
        "stderr": cat_stderr.decode("utf-8", errors="replace"),
    }
    if transport == "base64":
        cat_record["encoded_length"] = len(cat_stdout)
        cat_record["encoded_sha256"] = hashlib.sha256(cat_stdout).hexdigest()
    entry["commands"]["cat"] = cat_record
    if cat_rc != 0:
        entry["reason"] = "cat/base64 command failed"
        return entry
    if transport == "base64":
        try:
            cat_stdout = _decode_base64_transport(cat_stdout)
        except Exception as exc:
            entry["reason"] = f"base64 decode failed: {exc}"
            return entry
    if len(cat_stdout) != size:
        entry["reason"] = (
            f"byte count mismatch: remote stat {size} vs transferred {len(cat_stdout)}"
        )
        return entry

    local_full_hash = _local_sha256(cat_stdout)
    if local_full_hash != sha_before:
        entry["reason"] = (
            f"local sha256 does not match remote before: "
            f"local={local_full_hash} remote={sha_before}"
        )
        return entry

    sha_after, sha_after_rec = remote_sha256(adb_path, serial, remote_path)
    entry["commands"]["sha256_after"] = sha_after_rec
    entry["original_sha_after"] = sha_after
    if sha_after is None:
        entry["reason"] = "remote sha256 after transfer failed"
        return entry
    if sha_after != sha_before:
        entry["reason"] = (
            f"remote file changed during capture: before={sha_before} after={sha_after}"
        )
        return entry

    data_to_publish = cat_stdout
    publish_sha = local_full_hash
    publish_size = size

    if display_only:
        try:
            block_start, block_end, block_bytes = extract_display_profile_v2(cat_stdout)
        except TextProtoError as exc:
            entry["reason"] = f"display-only extraction failed: {exc}"
            return entry

        publish_size = len(block_bytes)
        publish_sha = _local_sha256(block_bytes)
        data_to_publish = block_bytes
        entry.update(
            {
                "original_size": size,
                "selected_block_start": block_start,
                "selected_block_end": block_end,
                "selected_block_size": publish_size,
                "selected_block_sha256": publish_sha,
                "selected_capture_not_full_file": True,
            }
        )
    else:
        entry.update(
            {
                "original_size": size,
                "selected_block_start": 0,
                "selected_block_end": size,
                "selected_block_size": publish_size,
                "selected_block_sha256": publish_sha,
                "selected_capture_not_full_file": False,
            }
        )

    # publish atomically
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    partial = local_path + ".partial"
    try:
        with open(partial, "xb") as fh:
            fh.write(data_to_publish)
        os.replace(partial, local_path)
    except Exception:
        _remove_partial(local_path)
        raise

    entry["size"] = publish_size
    entry["sha256"] = publish_sha
    entry["local_path"] = local_path
    entry["status"] = "verified"
    return entry


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Binary-safe targeted optical-artifact collector"
    )
    parser.add_argument("--adb", required=True, help="path to adb executable")
    parser.add_argument("--serial", required=True, help="adb device serial")
    parser.add_argument(
        "--output", required=True, help="new capture directory (must not exist or be empty)"
    )
    parser.add_argument(
        "--display-only",
        action="store_true",
        help="extract only top-level display_profile_v2 block from protobuf text files",
    )
    parser.add_argument(
        "--transport",
        choices=["raw", "base64"],
        default="raw",
        help="transport mode: raw binary cat (default) or base64 ASCII transfer",
    )
    parser.add_argument("paths", nargs="+", help="absolute remote file paths")
    args = parser.parse_args(argv)

    invalid_paths = []
    for path in args.paths:
        try:
            validate_remote_path(path)
        except ValueError as exc:
            invalid_paths.append(str(exc))
    if invalid_paths:
        _abort(f"invalid remote path(s): {'; '.join(invalid_paths)}")

    try:
        ensure_output_dir(args.output)
    except ValueError as exc:
        _abort(f"refusing output directory: {exc}")

    # identity before
    try:
        identity_before = collect_identity(args.adb, args.serial)
    except RuntimeError as exc:
        failure_manifest = {
            "phase": "identity",
            "error": str(exc),
            "failures": [],
        }
        _atomic_write_json(
            os.path.join(args.output, "failure_manifest.json"), failure_manifest
        )
        _abort(f"identity verification failed: {exc}")

    probe_before = probe_binary_transfer(args.adb, args.serial, transport=args.transport)
    if probe_before["status"] != "verified":
        failure_manifest = {
            "phase": "probe_before",
            "transport": args.transport,
            "identity": identity_before,
            "probe": probe_before,
            "failures": [],
            "error": probe_before.get("reason", "binary probe failed"),
        }
        _atomic_write_json(
            os.path.join(args.output, "failure_manifest.json"), failure_manifest
        )
        _abort(f"binary probe failed: {probe_before.get('reason')}")

    verified = []
    failures = []
    for path in args.paths:
        entry = capture_file(
            args.adb,
            args.serial,
            path,
            args.output,
            identity_before,
            display_only=args.display_only,
            transport=args.transport,
        )
        if entry["status"] == "verified":
            verified.append(entry)
        else:
            failures.append(entry)

    # identity after + stability
    try:
        identity_after = collect_identity(args.adb, args.serial)
    except RuntimeError as exc:
        failures.append(
            {
                "original_path": "__identity_after__",
                "status": "failed",
                "reason": str(exc),
            }
        )
        identity_after = None

    if identity_after is not None and identity_after != identity_before:
        failures.append(
            {
                "original_path": "__identity_stable__",
                "status": "failed",
                "reason": "device identity changed during capture",
                "identity_before": identity_before,
                "identity_after": identity_after,
            }
        )

    probe_after = probe_binary_transfer(args.adb, args.serial, transport=args.transport)
    if probe_after["status"] != "verified":
        failures.append(
            {
                "original_path": "__probe_after__",
                "status": "failed",
                "reason": probe_after.get("reason", "binary probe after capture failed"),
                "probe": probe_after,
            }
        )

    manifest = {
        "adb": args.adb,
        "serial": args.serial,
        "output": args.output,
        "transport": args.transport,
        "display_only": args.display_only,
        "identity_before": identity_before,
        "identity_after": identity_after,
        "probe_before": probe_before,
        "probe_after": probe_after,
        "verified": verified,
        "failures": failures,
    }
    _atomic_write_json(os.path.join(args.output, "capture_manifest.json"), manifest)

    if failures:
        failure_manifest = {
            "adb": args.adb,
            "serial": args.serial,
            "output": args.output,
            "transport": args.transport,
            "display_only": args.display_only,
            "identity_before": identity_before,
            "identity_after": identity_after,
            "failures": failures,
        }
        _atomic_write_json(
            os.path.join(args.output, "failure_manifest.json"), failure_manifest
        )
        _abort(
            f"capture completed with {len(failures)} failure(s); "
            "see failure_manifest.json",
            code=1,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
