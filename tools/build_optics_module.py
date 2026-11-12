#!/usr/bin/env python3
"""Build a PRIVATE, disabled KernelSU module for identity-only optical-profile reapplication.

Scope (v0.1):
  * Package the ORIGINAL stock display_profile_v2 block bytes plus a pinned stock
    source SHA-256/size and the exact byte span inside the mixed static profile.
  * At runtime `action.sh prepare` reconstructs the full original file INSIDE the
    module directory by byte splicing (stock prefix + packaged block + stock
    suffix) and requires the full SHA-256 to equal the pinned stock source hash.
    That equality is the identity no-op proof: the packaged block is the original
    bytes, not an edited calibration.
  * `apply` is manual, token-gated, prechecked, and bind-mounts only the prepared
    payload onto the fixed target. It never writes EFS, never remounts, never
    restarts services, never changes properties or SELinux policy.
  * The module ships disabled with skip_mount and has NO boot-stage activation.
    `service.sh` only reports "activation-required".

Trust boundary: the generator cannot read the stock source; the caller must
supply verified collector outputs. Do not guess offsets, hashes, sizes,
fingerprint or kernel release. Any mismatch at runtime fails closed, nonzero,
without mounting.

CLI:
  build_optics_module.py --block PATH --source-sha256 HEX64 --source-size N \
      --start N --end N --output NEW_ZIP [--fingerprint STR] [--kernel-release STR]

Optional identity pins default to the values recorded in the project
diagnostics ledger (2026-11-11). Runtime apply re-verifies them; stale values
fail closed. Pass empty strings to deliberately produce a non-apply-capable
package.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

MODULE_ID = "gxr_optical_profile"
MODULE_NAME = "Galaxy XR optical profile identity (disabled, manual)"
MODULE_VERSION = "v0.1-identity"
MODULE_VERSION_CODE = 1
MODULE_AUTHOR = "GalaxyXR-Link"
TARGET_PATH = "/mnt/vendor/efs/device_profile.textproto"
SELINUX_CONTEXT = "u:object_r:perceptionhost_efs_file:s0"
APPLY_TOKEN = "APPROVED_IDENTICAL_PROFILE"
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

# Documented observed headset identity from the project diagnostics ledger.
# Serial is intentionally NOT embedded or checked at runtime.
DEFAULT_FINGERPRINT = (
    "samsung/xrvst2ue/xrvst2:14/UML2.260301.001/"
    "I610UEU2AZF3:user/release-keys"
)
DEFAULT_KERNEL_RELEASE = "5.10.240-android12-9-perf-33775878-abI610UEU2AZF3"

ZIP_ORDER = (
    "module.prop",
    "disable",
    "skip_mount",
    "action.sh",
    "service.sh",
    "payload/manifest.env",
    "payload/display_profile.block",
    "README.md",
)

FORBIDDEN_SCRIPT_PATTERNS = (
    (r"\bremount\b", "remount"),
    (r"\bsetenforce\b", "setenforce"),
    (r"\bsetprop\b", "setprop"),
    (r"\bresetprop\b", "resetprop"),
    (r"\binsmod\b", "insmod"),
    (r"\bmodprobe\b", "modprobe"),
    (r"\bkillall\b", "killall"),
    (r"\bsvc\b", "svc"),
    (r"\bsettings\s+put\b", "settings put"),
    (r"\bam\s+force-stop\b", "am force-stop"),
    (r"\bcurl\b", "curl"),
    (r"\bwget\b", "wget"),
    (r"\bnc\b", "nc"),
    (r"\beval\b", "eval"),
    (r"rm\s+-rf\b", "rm -rf"),
    (r"rm\s+-r\s", "rm -r"),
    (r"mount\s+-t\b", "mount -t"),
    (r"mount\s+-o\s+remount", "mount -o remount"),
    (r">\s*/dev/block\b", "write to block device"),
    (r'of="?\$TARGET', "dd write to target"),
    (r"umount\s+-l\b", "lazy umount"),
    (r"umount\s+--lazy\b", "lazy umount"),
    (r">>\s*\"?\$TARGET", "append to target"),
)


class BuildError(Exception):
    """Invalid input or unsafe generated content."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _uint(name: str, value: str) -> int:
    if not re.fullmatch(r"[0-9]+", value or ""):
        raise BuildError(f"{name} must be a non-negative decimal integer")
    return int(value, 10)


def _identity_value(name: str, value: str) -> str:
    if any(ch in value for ch in "\r\n"):
        raise BuildError(f"{name} must not contain newlines")
    if len(value) > 256:
        raise BuildError(f"{name} is too long")
    return value


def _module_prop() -> str:
    description = (
        "Identity-only reapplication of the original stock "
        "/mnt/vendor/efs/device_profile.textproto block. Ships disabled with "
        "skip_mount; no boot activation; manual prepare/apply with explicit token; "
        "never writes EFS."
    )
    return (
        f"id={MODULE_ID}\n"
        f"name={MODULE_NAME}\n"
        f"version={MODULE_VERSION}\n"
        f"versionCode={MODULE_VERSION_CODE}\n"
        f"author={MODULE_AUTHOR}\n"
        f"description={description}\n"
    )


def _manifest(
    source_sha: str,
    source_size: int,
    block_sha: str,
    start: int,
    end: int,
    fingerprint: str,
    kernel_release: str,
) -> str:
    lines = [
        f"module_id={MODULE_ID}",
        f"module_version={MODULE_VERSION}",
        "identity_scope=stock-original-only",
        f"target_path={TARGET_PATH}",
        f"selinux_context={SELINUX_CONTEXT}",
        "payload_owner=0:0",
        "payload_mode=0644",
        f"source_sha256={source_sha}",
        f"source_size={source_size}",
        f"block_sha256={block_sha}",
        f"block_start={start}",
        f"block_end={end}",
        f"expected_fingerprint={fingerprint}",
        f"expected_kernel_release={kernel_release}",
    ]
    return "\n".join(lines) + "\n"


def _readme() -> str:
    return """# gxr_optical_profile - identity-only, manual, disabled

PRIVATE. KernelSU-only headset module. It is not a Driver package and does not
improve optics. Generated from verified collector output for the original
stock optical profile.

## What it does

- Ships disabled (`disable`) and with `skip_mount`: no overlay mount and no
  boot-stage activation.
- Holds the original `display_profile_v2` block in
  `payload/display_profile.block` plus the pinned stock identity in
  `payload/manifest.env`.
- `action.sh prepare` rebuilds the full original file inside the module
  directory by byte splicing: stock prefix + packaged original block + stock
  suffix, using the pinned start/end offsets. It then requires the full
  generated SHA-256 to equal the pinned stock source SHA-256 (identity no-op)
  and the block region to equal the pinned block SHA-256.
- `action.sh apply APPROVED_IDENTICAL_PROFILE` performs explicit prechecks and
  one file bind mount of the prepared payload onto
  `/mnt/vendor/efs/device_profile.textproto`, then verifies the mount and the
  consumer view. No EFS write, no remount, no service restart, no property or
  SELinux policy change.
- `action.sh off` unmounts only the verified module-owned mount.
- `service.sh` is report-only. It never prepares or mounts.

## Identity-only scope (v0.1)

The packaged block is byte-identical to the stock span. A successful full-file
hash match proves the splice pipeline is correct; it does not change
calibration and does not improve optics. Do not edit the block: an edited
block fails closed. Replacing calibration requires a new pinned expected full
SHA-256 plus an independent semantic validator; neither is implemented here.
Altered profiles are explicitly unsupported and must never be shipped under
this identity token.

## Limits of evidence

- The shipped `disable` flag is advisory only. Official KernelSU material notes
  that installers may enable modules regardless of the previous disable state,
  so the flag alone is not an activation guarantee. No script here mounts at
  boot: `service.sh` is inert and the explicit apply token from a root shell is
  the only activation gate.
- A successful `apply` proves only that a namespace-visible file bind exists
  and hashes to the pinned stock bytes. It does NOT prove that the compositor
  or perceptionhost reloaded or is consuming the file. A true consumer reload
  requires a separately approved lifecycle action.
- An empty `cpm.lut_distortion_from_opx_calibration` property does not mean the
  profile is absent, false, or default. The active consumer source remains
  unproven until separately demonstrated.
- Read-only live evidence recorded on 2026-11-11: `/proc/1`, `/proc/1213`
  (perceptionhost), `/proc/1290` (surfaceflinger) and the current su process
  shared mnt:[4026532460]. The target was root:root 0644, inode 23, dev 2054,
  context `u:object_r:perceptionhost_efs_file:s0`, on ext4
  `/dev/block/by-name/efs`. Inode and device are observations only and are not
  pinned at runtime.

## Requirements

- KernelSU with root. Enable the module manually before `apply`; the shipped
  `disable` flag is required by this package but is advisory only.
- Pinned fingerprint and kernel release must be present and match the running
  device. Rebuild with `--fingerprint` and `--kernel-release` from verified
  collector output if the defaults are not current. Empty pins fail closed.
- The stock source must match the pinned size, SHA-256 and SELinux context;
  otherwise `prepare` and `apply` fail nonzero without mounting.
- Do not use SELinux permissive mode, policy changes or remounts to force this
  module. If the KernelSU su domain cannot relabel the payload to the EFS type
  or the bind mount is denied, `prepare`/`apply` fail closed.
- `prepare`, `apply` and `off` each verify the current mount namespace against
  `/proc/1/ns/mnt` and require exactly one `android.hardware.perceptionhost`
  and exactly one `surfaceflinger` process (exact names, `/system/bin/ps`)
  before writing or unmounting. Duplicate or missing matches fail closed.
- Mount ownership derivation also checks the containing mount's
  `/proc/self/mountinfo` root field. If the payload's underlying mount root is
  not `/`, ownership resolution is refused rather than guessing a mapping.
- The payload directory must be a non-symlink root-owned directory, and the
  temporary payload is created with noclobber after refusing any existing or
  dangling path.

## Operator sequence

1. Confirm the offline evidence inputs (block bytes, source SHA-256/size, byte
   start/end) come from the verified collector. Do not guess.
2. Build with `build_optics_module.py` and record the printed summary.
3. Install the ZIP in KernelSU. Do not flash it as a Driver package.
4. Enable the module explicitly, then run Action -> `status`.
5. From a root shell, run `prepare`. Expect "identity payload ready (not
   applied)". The manager Action button only runs `status`; the other actions
   need their argument and are run as root, for example
   `su -c 'sh /data/adb/modules/gxr_optical_profile/action.sh prepare'`.
6. From a root shell, run `apply APPROVED_IDENTICAL_PROFILE` (exact literal).
7. Verify the consumer, then run `off` to restore the stock view.
8. Disable the module again before uninstall.

## Apply preconditions (all must pass)

- exact token, root, `disable` absent, `skip_mount` present
- pinned fingerprint and kernel release match (`getprop`, `uname -r`)
- current mount namespace equals `/proc/1/ns/mnt` and the namespaces of
  `perceptionhost` and `surfaceflinger`
- no existing mount at the target path
- target path components are not symlinks; stock target is a regular file
- stock target size, SHA-256 and SELinux context match the pinned original
- prepared payload size, SHA-256, block-region SHA-256, uid/gid 0:0, mode 0644
  and context `u:object_r:perceptionhost_efs_file:s0` match
- after mount: exactly one target mount, uniquely owned by the payload
  (device and root), target hash and perceptionhost consumer-view hash equal
  the pinned stock SHA-256

If a postcheck fails, only the verified owned mount is removed with a regular
`umount`; no lazy unmount and no foreign unmount.

## Uninstall / rollback

There is deliberately no `uninstall.sh`: the module never unmounts or deletes
the live payload automatically. Run `off`, confirm `status` reports no mount,
then disable the module and remove it in KernelSU. A KernelSU uninstall deletes
the module directory (including the prepared payload) without consulting this
module; do it only after `off`.

## Logs

`last_action.txt` contains only action/status words. `service.sh` writes
nothing. No calibration bytes, offsets or hashes are logged.

## Not included

No network access, no watchers, no kernel module loading, no mount option or
remount changes, no service restarts, no property writes, no SELinux
permissive/enforcement changes, no runtime serial hardcode.
"""


def _action_script() -> str:
    return r"""#!/system/bin/sh
# gxr_optical_profile action.sh
# Identity-only and manual-only. Never writes EFS. Never starts/stops services.
# Default action: status (read-only).

set -u

TARGET=/mnt/vendor/efs/device_profile.textproto
MODULE_ID=gxr_optical_profile
APPLY_TOKEN=APPROVED_IDENTICAL_PROFILE
CONTEXT=u:object_r:perceptionhost_efs_file:s0
PERCEPTION_NAME=android.hardware.perceptionhost
SURFACEFLINGER_NAME=surfaceflinger

if [ -z "${MODDIR:-}" ]; then
  case "${0:-}" in
    */*) MODDIR=${0%/*} ;;
    *) MODDIR=. ;;
  esac
fi
if ! MODDIR=$(cd "$MODDIR" 2>/dev/null && pwd -P); then
  echo "ERROR: module directory unavailable" >&2
  exit 1
fi

PAYLOAD="$MODDIR/payload/device_profile.textproto"
BLOCK="$MODDIR/payload/display_profile.block"
MANIFEST="$MODDIR/payload/manifest.env"
STATUS="$MODDIR/last_action.txt"
DISABLE_FLAG="$MODDIR/disable"
SKIP_MOUNT_FLAG="$MODDIR/skip_mount"
TMP=
TMP_OWNED=0

cleanup() {
  # Only remove a temp path this process created exclusively. A preexisting or
  # dangling path that made an earlier check fail must never be deleted.
  if [ "$TMP_OWNED" = 1 ] && [ -n "$TMP" ] && [ ! -L "$TMP" ] && [ -f "$TMP" ]; then
    rm -f "$TMP" 2>/dev/null || true
  fi
  TMP_OWNED=0
}
trap cleanup EXIT HUP INT TERM

fail() {
  echo "ERROR: $1" >&2
  exit "${2:-4}"
}

note() {
  printf '%s\n' "$1"
}

record() {
  printf '%s\n' "$1" > "$STATUS" 2>/dev/null || true
}

is_uint() {
  case "${1:-}" in
    ''|*[!0-9]*) return 1 ;;
  esac
  return 0
}

is_sha() {
  case "${1:-}" in
    ''|*[!0-9a-f]*) return 1 ;;
  esac
  [ "${#1}" -eq 64 ] || return 1
  return 0
}

sha_of() {
  sha256sum "$1" 2>/dev/null | awk 'NR==1 {print $1}'
}

size_of() {
  wc -c < "$1" 2>/dev/null | awk 'NR==1 {print $1}'
}

mget() {
  [ -f "$MANIFEST" ] || return 1
  awk -v k="$1" '
    {
      pos=index($0,"=")
      if (pos>0 && substr($0,1,pos-1)==k) {
        print substr($0,pos+1)
        found=1
        exit
      }
    }
    END { if (!found) exit 1 }
  ' "$MANIFEST"
}

load_config() {
  SRC_SHA=$(mget source_sha256) || fail "manifest: missing source_sha256"
  SRC_SIZE=$(mget source_size) || fail "manifest: missing source_size"
  BLK_SHA=$(mget block_sha256) || fail "manifest: missing block_sha256"
  START=$(mget block_start) || fail "manifest: missing block_start"
  END=$(mget block_end) || fail "manifest: missing block_end"
  M_TARGET=$(mget target_path) || fail "manifest: missing target_path"
  M_CONTEXT=$(mget selinux_context) || fail "manifest: missing selinux_context"
  FP=$(mget expected_fingerprint) || FP=
  KREL=$(mget expected_kernel_release) || KREL=

  is_sha "$SRC_SHA" || fail "manifest: source_sha256 malformed"
  is_sha "$BLK_SHA" || fail "manifest: block_sha256 malformed"
  is_uint "$SRC_SIZE" || fail "manifest: source_size malformed"
  is_uint "$START" || fail "manifest: block_start malformed"
  is_uint "$END" || fail "manifest: block_end malformed"
  [ "$M_TARGET" = "$TARGET" ] || fail "manifest: target_path mismatch"
  [ "$M_CONTEXT" = "$CONTEXT" ] || fail "manifest: selinux_context mismatch"
  [ "$START" -lt "$END" ] || fail "manifest: empty or inverted block span"
  [ "$END" -le "$SRC_SIZE" ] || fail "manifest: block span exceeds source"
  [ "$(size_of "$BLOCK")" = "$((END - START))" ] || fail "payload: block size mismatch"
}

verify_context() {
  ctx=$(ls -lZ "$1" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i ~ /^u:object_r:/) {print $i; exit}}')
  [ "$ctx" = "$CONTEXT" ]
}

verify_owner_mode() {
  om=$(stat -c '%u:%g:%a' "$1" 2>/dev/null)
  [ "$om" = "0:0:644" ]
}

pid_of_unique() {
  name=$1
  dump=$(ps_dump) || return 1
  [ -n "$dump" ] || return 1
  pids=$(printf '%s\n' "$dump" | awk -v n="$name" '$2==n {print $1}')
  count=$(printf '%s\n' "$pids" | awk 'NF {c++} END {print c+0}')
  [ "$count" -eq 1 ] || return 1
  pid=$(printf '%s\n' "$pids" | awk 'NF {print; exit}')
  is_uint "$pid" || return 1
  printf '%s\n' "$pid"
}

ps_dump() {
  /system/bin/ps -A -o PID=,NAME= 2>/dev/null
}

ns_of() {
  readlink "/proc/$1/ns/mnt" 2>/dev/null
}

check_namespace() {
  self_ns=$(ns_of self)
  init_ns=$(ns_of 1)
  [ -n "$self_ns" ] || fail "namespace: cannot read self mount namespace"
  [ "$self_ns" = "$init_ns" ] || fail "namespace: action not in init mount namespace"
  PERCEPTION_PID=$(pid_of_unique "$PERCEPTION_NAME") || fail "namespace: no unique perceptionhost pid"
  SURFACEFLINGER_PID=$(pid_of_unique "$SURFACEFLINGER_NAME") || fail "namespace: no unique surfaceflinger pid"
  [ "$(ns_of "$PERCEPTION_PID")" = "$self_ns" ] || fail "namespace: perceptionhost mount namespace differs"
  [ "$(ns_of "$SURFACEFLINGER_PID")" = "$self_ns" ] || fail "namespace: surfaceflinger mount namespace differs"
}

mount_count() {
  awk -v t="$TARGET" '$5==t {c++} END {print c+0}' /proc/self/mountinfo 2>/dev/null
}

owned_count() {
  awk -v t="$TARGET" -v r="$P_ROOT" -v d="$P_DEV" '$5==t && $4==r && $3==d {c++} END {print c+0}' /proc/self/mountinfo 2>/dev/null
}

payload_mount() {
  # Ownership mapping is only defined when the containing mount's mountinfo
  # root is "/". A rooted subtree is refused rather than guessed.
  awk -v p="$PAYLOAD" '
    BEGIN { best=-1; dev=""; mp=""; root="" }
    {
      m=$5
      if (m=="/" || (index(p,m)==1 && (length(p)==length(m) || substr(p,length(m)+1,1)=="/"))) {
        if (length(m)>best) { best=length(m); dev=$3; mp=m; root=$4 }
      }
    }
    END {
      if (best<0 || dev=="" || mp=="" || root!="/") exit 1
      print dev, mp
    }
  ' /proc/self/mountinfo 2>/dev/null
}

resolve_payload_identity() {
  pm=$(payload_mount) || return 1
  [ -n "$pm" ] || return 1
  P_DEV=${pm%% *}
  P_MP=${pm#* }
  [ -n "$P_DEV" ] || return 1
  [ -n "$P_MP" ] || return 1
  if [ "$P_MP" = "/" ]; then
    P_ROOT=$PAYLOAD
  else
    P_ROOT=${PAYLOAD#"$P_MP"}
    [ -n "$P_ROOT" ] || P_ROOT=/
  fi
  [ -n "$P_ROOT" ] || return 1
  return 0
}

check_module_paths() {
  [ -d "$MODDIR" ] || fail "module directory missing"
  [ ! -L "$MODDIR" ] || fail "module directory is a symlink"
  [ -d "$MODDIR/payload" ] || fail "payload directory missing"
  [ ! -L "$MODDIR/payload" ] || fail "payload directory is a symlink"
  [ "$(stat -c '%u' "$MODDIR/payload" 2>/dev/null)" = 0 ] || fail "payload directory is not root-owned"
  [ -f "$BLOCK" ] && [ ! -L "$BLOCK" ] || fail "packaged block file missing or a symlink"
  [ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || fail "manifest missing or a symlink"
  [ ! -L "$STATUS" ] || fail "status log path is a symlink"
  if [ -e "$PAYLOAD" ] || [ -L "$PAYLOAD" ]; then
    [ -f "$PAYLOAD" ] && [ ! -L "$PAYLOAD" ] || fail "prepared payload is not a regular file"
  fi
  return 0
}

check_target_path() {
  for p in /mnt /mnt/vendor /mnt/vendor/efs "$TARGET"; do
    [ -L "$p" ] && fail "path component is a symlink: $p"
  done
  [ -d /mnt/vendor/efs ] || fail "target directory missing"
  return 0
}

build_payload() {
  block_len=$((END - START))
  suffix_len=$((SRC_SIZE - END))
  TMP_OWNED=0
  TMP="$MODDIR/payload/.device_profile.tmp.$$"
  if [ -e "$TMP" ] || [ -L "$TMP" ]; then
    TMP=
    fail "temporary payload path already exists or is a symlink"
  fi
  if ! ( set -C; : > "$TMP" ) 2>/dev/null; then
    TMP=
    fail "cannot create temporary payload exclusively"
  fi
  # From here the path was created exclusively by this process.
  TMP_OWNED=1
  [ -f "$TMP" ] && [ ! -L "$TMP" ] || fail "temporary payload is not a regular file"
  if [ "$START" -gt 0 ]; then
    dd if="$TARGET" of="$TMP" bs=1 count="$START" conv=notrunc 2>/dev/null || fail "prefix splice failed"
  fi
  dd if="$BLOCK" of="$TMP" bs=1 seek="$START" count="$block_len" conv=notrunc 2>/dev/null || fail "block splice failed"
  if [ "$suffix_len" -gt 0 ]; then
    dd if="$TARGET" of="$TMP" bs=1 skip="$END" seek="$END" count="$suffix_len" conv=notrunc 2>/dev/null || fail "suffix splice failed"
  fi
  [ "$(size_of "$TMP")" = "$SRC_SIZE" ] || fail "generated payload size mismatch"
  [ "$(sha_of "$TMP")" = "$SRC_SHA" ] || fail "generated payload does not match pinned stock identity"
  region=$(dd if="$TMP" bs=1 skip="$START" count="$block_len" 2>/dev/null | sha256sum | awk 'NR==1 {print $1}')
  [ "$region" = "$BLK_SHA" ] || fail "generated payload block region mismatch"
  chown 0:0 "$TMP" 2>/dev/null || fail "cannot set payload owner"
  chmod 0644 "$TMP" 2>/dev/null || fail "cannot set payload mode"
  chcon "$CONTEXT" "$TMP" 2>/dev/null || /system/bin/chcon "$CONTEXT" "$TMP" 2>/dev/null || fail "cannot set payload SELinux context"
  verify_owner_mode "$TMP" || fail "payload owner/mode verification failed"
  verify_context "$TMP" || fail "payload SELinux context verification failed"
  mv -f "$TMP" "$PAYLOAD" 2>/dev/null || fail "cannot publish payload"
  TMP=
  TMP_OWNED=0
  [ -f "$PAYLOAD" ] && [ ! -L "$PAYLOAD" ] || fail "published payload is not a regular file"
}

do_prepare() {
  [ "$(id -u)" = 0 ] || fail "prepare requires root" 3
  check_namespace
  check_module_paths
  load_config
  check_target_path
  [ -f "$TARGET" ] && [ ! -L "$TARGET" ] || fail "stock target is not a regular file"
  [ "$(mount_count)" = 0 ] || fail "target already mounted; run off first"
  [ "$(sha_of "$BLOCK")" = "$BLK_SHA" ] || fail "packaged block hash mismatch"
  [ "$(size_of "$TARGET")" = "$SRC_SIZE" ] || fail "stock source size mismatch"
  [ "$(sha_of "$TARGET")" = "$SRC_SHA" ] || fail "stock source hash mismatch"
  verify_context "$TARGET" || fail "stock source SELinux context unexpected"
  build_payload
  record "prepare ok: identity payload generated; not mounted"
  note "prepare: module-local identity payload ready (not applied)"
}

do_status() {
  note "module: $MODULE_ID"
  if [ -f "$MANIFEST" ]; then
    if ( load_config ) >/dev/null 2>&1; then
      note "manifest: pinned identity present"
    else
      note "manifest: INVALID or incomplete"
    fi
  else
    note "manifest: missing"
  fi
  if [ -e "$DISABLE_FLAG" ]; then
    note "disabled: yes (no boot-stage activation; actions are manual)"
  else
    note "disabled: no"
  fi
  if [ -e "$SKIP_MOUNT_FLAG" ]; then
    note "skip_mount: present"
  else
    note "skip_mount: MISSING"
  fi
  if [ -f "$TARGET" ] && [ ! -L "$TARGET" ]; then
    if ( load_config && [ "$(sha_of "$TARGET")" = "$SRC_SHA" ] && [ "$(size_of "$TARGET")" = "$SRC_SIZE" ] ) >/dev/null 2>&1; then
      note "stock target: matches pinned original identity"
    else
      note "stock target: differs from pinned identity or manifest invalid"
    fi
  else
    note "stock target: missing or not a regular file"
  fi
  if [ -f "$PAYLOAD" ] && [ ! -L "$PAYLOAD" ]; then
    if ( load_config && [ "$(sha_of "$PAYLOAD")" = "$SRC_SHA" ] ) >/dev/null 2>&1; then
      note "payload: prepared and identity-verified"
    else
      note "payload: present but not identity-verified"
    fi
  else
    note "payload: not prepared"
  fi
  if ( check_namespace ) >/dev/null 2>&1; then
    note "namespace: init and consumer mounts match"
  else
    note "namespace: NOT verified; prepare/apply/off will fail closed"
  fi
  if [ -f /proc/self/mountinfo ]; then
    count=$(mount_count)
    if [ "$count" = 0 ]; then
      note "mount: none (stock file visible)"
    elif [ "$count" = 1 ]; then
      if resolve_payload_identity && [ "$(owned_count)" = 1 ]; then
        note "mount: module-owned identity bind mount active (namespace-visible only; consumer load not proven)"
      else
        note "mount: unverified or foreign mount at target (not owned)"
      fi
    else
      note "mount: unexpected multiple entries at target"
    fi
  fi
  note "apply: manual token required; fingerprint and kernel must match pinned values"
  note "actions: run from a root shell; the manager Action button shows status only"
  note "uninstall: run off and verify no mount before removing the module"
  note "sequence: prepare -> apply -> verify consumer -> off"
}

rollback_owned() {
  [ "$(mount_count)" = 1 ] || return 1
  resolve_payload_identity || return 1
  [ "$(owned_count)" = 1 ] || return 1
  umount "$TARGET" 2>/dev/null || return 1
  [ "$(mount_count)" = 0 ] || return 1
  return 0
}

do_apply() {
  token=${1:-}
  [ "$token" = "$APPLY_TOKEN" ] || fail "apply requires explicit token $APPLY_TOKEN" 2
  [ "$(id -u)" = 0 ] || fail "apply requires root" 3
  [ ! -e "$DISABLE_FLAG" ] || fail "module is disabled; enable it explicitly before apply"
  [ -f "$SKIP_MOUNT_FLAG" ] || fail "skip_mount flag missing; refusing unexpected package state"
  check_namespace
  check_module_paths
  load_config
  [ -n "$FP" ] || fail "build fingerprint is not pinned; rebuild with --fingerprint"
  [ -n "$KREL" ] || fail "kernel release is not pinned; rebuild with --kernel-release"
  [ "$(getprop ro.build.fingerprint 2>/dev/null)" = "$FP" ] || fail "build fingerprint mismatch"
  [ "$(uname -r 2>/dev/null)" = "$KREL" ] || fail "kernel release mismatch"
  check_target_path
  [ -f "$TARGET" ] && [ ! -L "$TARGET" ] || fail "stock target is not a regular file"
  [ "$(mount_count)" = 0 ] || fail "target already mounted; run off first"
  [ "$(size_of "$TARGET")" = "$SRC_SIZE" ] || fail "stock source size mismatch"
  [ "$(sha_of "$TARGET")" = "$SRC_SHA" ] || fail "stock source hash mismatch"
  verify_context "$TARGET" || fail "stock source SELinux context unexpected"
  [ -f "$PAYLOAD" ] && [ ! -L "$PAYLOAD" ] || fail "payload missing; run prepare first"
  [ "$(size_of "$PAYLOAD")" = "$SRC_SIZE" ] || fail "payload size mismatch"
  [ "$(sha_of "$PAYLOAD")" = "$SRC_SHA" ] || fail "payload identity hash mismatch"
  region=$(dd if="$PAYLOAD" bs=1 skip="$START" count="$((END - START))" 2>/dev/null | sha256sum | awk 'NR==1 {print $1}')
  [ "$region" = "$BLK_SHA" ] || fail "payload block region mismatch"
  verify_owner_mode "$PAYLOAD" || fail "payload owner/mode mismatch"
  verify_context "$PAYLOAD" || fail "payload SELinux context mismatch"
  resolve_payload_identity || fail "cannot resolve payload filesystem identity (missing mount or non-/ underlying root)"
  mount -o bind "$PAYLOAD" "$TARGET" 2>/dev/null || fail "bind mount failed" 5
  post_ok=1
  [ "$(mount_count)" = 1 ] || post_ok=0
  [ "$(owned_count)" = 1 ] || post_ok=0
  [ "$(sha_of "$TARGET")" = "$SRC_SHA" ] || post_ok=0
  consumer="/proc/$PERCEPTION_PID/root$TARGET"
  if [ -r "$consumer" ]; then
    [ "$(sha_of "$consumer")" = "$SRC_SHA" ] || post_ok=0
  else
    post_ok=0
  fi
  if [ "$post_ok" != 1 ]; then
    if rollback_owned; then
      fail "postcheck failed; owned mount rolled back" 5
    fi
    fail "postcheck failed; rollback not completed; inspect mount state before further action" 5
  fi
  record "apply ok: namespace-visible identity bind active; consumer load not proven"
  note "apply: namespace-visible identity bind active; compositor load not proven; no service restart performed"
}

do_off() {
  [ "$(id -u)" = 0 ] || fail "off requires root" 3
  check_namespace
  check_module_paths
  load_config
  count=$(mount_count)
  if [ "$count" = 0 ]; then
    record "off ok: nothing mounted"
    note "off: target is not mounted; stock view already active"
    return 0
  fi
  [ "$count" = 1 ] || fail "off: multiple mounts at target; refusing"
  resolve_payload_identity || fail "off: cannot resolve payload filesystem identity (missing mount or non-/ underlying root)"
  [ "$(owned_count)" = 1 ] || fail "off: mount is not the module-owned payload; refusing"
  umount "$TARGET" 2>/dev/null || fail "off: unmount failed" 5
  [ "$(mount_count)" = 0 ] || fail "off: target still mounted after unmount" 5
  record "off ok: owned identity mount removed"
  note "off: module-owned mount removed; stock file visible again"
  if [ "$(sha_of "$TARGET")" != "$SRC_SHA" ]; then
    note "WARNING: stock hash differs from pinned identity; investigate"
  fi
}

action=${1:-status}
case "$action" in
  status) do_status ;;
  prepare) do_prepare ;;
  apply) shift; do_apply "${1:-}" ;;
  off) do_off ;;
  *)
    echo "usage: action.sh status|prepare|apply $APPLY_TOKEN|off" >&2
    exit 2
    ;;
esac
"""


def _service_script() -> str:
    return r"""#!/system/bin/sh
# gxr_optical_profile service.sh
# REPORT ONLY and inert. Never prepares, mounts, unmounts, writes EFS or files,
# or changes properties/SELinux. The module ships disabled, but the KernelSU
# installer may enable modules regardless of that flag, so this script must
# remain harmless even when the module is enabled. Activation requires the
# explicit apply token from a root shell.

set -u

if [ -z "${MODDIR:-}" ]; then
  case "${0:-}" in
    */*) MODDIR=${0%/*} ;;
    *) MODDIR=. ;;
  esac
fi
[ -d "$MODDIR" ] || exit 0
echo "gxr_optical_profile: disabled/manual; activation-required; no automatic action performed"
exit 0
"""


def _check_scripts(action: str, service: str) -> None:
    for label, script in (("action.sh", action), ("service.sh", service)):
        if "\r" in script:
            raise BuildError(f"{label} must use LF line endings")
        if not script.startswith("#!/system/bin/sh\n"):
            raise BuildError(f"{label} must start with the Android shell shebang")
        for line in script.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            for pattern, reason in FORBIDDEN_SCRIPT_PATTERNS:
                if re.search(pattern, line):
                    raise BuildError(f"{label} contains forbidden construct ({reason}): {line.strip()}")

    code = "\n".join(
        line for line in action.splitlines() if not line.lstrip().startswith("#")
    )
    service_code = "\n".join(
        line for line in service.splitlines() if not line.lstrip().startswith("#")
    )
    if re.search(r"(?m)^\s*(mount|umount)\b", service_code):
        raise BuildError("service.sh must not mount or unmount")
    if ">" in service_code:
        raise BuildError("service.sh must be inert and must not write files")
    if "action=${1:-status}" not in action:
        raise BuildError("action.sh must default to status")
    if APPLY_TOKEN not in action:
        raise BuildError("action.sh must gate apply with the explicit token")
    if code.count("mount -o bind") != 1:
        raise BuildError("action.sh must perform exactly one bind mount")
    if code.count('umount "$TARGET"') != 2:
        raise BuildError("action.sh must only unmount the target in rollback and off")
    if action.count('sha256sum') < 3:
        raise BuildError("action.sh must verify hashes with sha256sum")
    if "ns_of 1" not in action or "init_ns" not in action:
        raise BuildError("action.sh must verify the init mount namespace")
    if "resolve_payload_identity" not in action or "P_ROOT" not in action or "P_DEV" not in action:
        raise BuildError("action.sh must verify mount ownership by device and root")
    if 'root!="/"' not in action:
        raise BuildError("action.sh must refuse non-root underlying mount roots")
    if "/system/bin/ps" not in action or "pid_of_unique" not in action:
        raise BuildError("action.sh must resolve unique PIDs with /system/bin/ps")
    if "android.hardware.perceptionhost" not in action:
        raise BuildError("action.sh must use the exact perceptionhost process name")
    if '[ "$count" -eq 1 ]' not in action:
        raise BuildError("action.sh must require a unique PID match")
    if "check_module_paths" not in action or "set -C" not in action:
        raise BuildError("action.sh must check payload paths and create temp files exclusively")
    if '[ -e "$TMP" ] || [ -L "$TMP" ]' not in action:
        raise BuildError("action.sh must refuse existing or dangling temporary payloads")
    if "TMP_OWNED=0" not in action or '[ "$TMP_OWNED" = 1 ]' not in action:
        raise BuildError("action.sh cleanup must only remove a temp file it exclusively created")
    if "perceptionhost" not in action or "surfaceflinger" not in action:
        raise BuildError("action.sh must verify consumer mount namespaces")
    if SELINUX_CONTEXT not in action:
        raise BuildError("action.sh must set the documented SELinux context")


def _build_zip(entries: List[Tuple[str, bytes, int]]) -> bytes:
    names = [name for name, _data, _mode in entries]
    if tuple(names) != ZIP_ORDER:
        raise BuildError("internal ZIP entry order mismatch")
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # Unix metadata
            info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def build(args: argparse.Namespace) -> Dict[str, object]:
    block_path = Path(args.block)
    if not block_path.is_file():
        raise BuildError(f"--block is not a regular file: {block_path}")
    block = block_path.read_bytes()
    if not block:
        raise BuildError("--block is empty")

    source_sha = (args.source_sha256 or "").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", source_sha):
        raise BuildError("--source-sha256 must be 64 lowercase hex characters")

    source_size = _uint("--source-size", args.source_size)
    start = _uint("--start", args.start)
    end = _uint("--end", args.end)

    if source_size <= 0:
        raise BuildError("--source-size must be greater than zero")
    if end <= start:
        raise BuildError("--end must be greater than --start")
    if end > source_size:
        raise BuildError("--end must not exceed --source-size")
    if len(block) != end - start:
        raise BuildError(
            f"--block is {len(block)} bytes but --end - --start is {end - start}"
        )

    output = Path(args.output)
    if output.exists():
        raise BuildError(f"refusing to overwrite existing --output: {output}")
    if not output.parent.is_dir():
        raise BuildError(f"--output parent directory does not exist: {output.parent}")

    fingerprint = _identity_value(
        "--fingerprint",
        DEFAULT_FINGERPRINT if args.fingerprint is None else args.fingerprint,
    )
    kernel_release = _identity_value(
        "--kernel-release",
        DEFAULT_KERNEL_RELEASE if args.kernel_release is None else args.kernel_release,
    )

    block_sha = _sha256(block)
    action = _action_script()
    service = _service_script()
    _check_scripts(action, service)

    manifest = _manifest(
        source_sha, source_size, block_sha, start, end, fingerprint, kernel_release
    )
    readme = _readme()
    module_prop = _module_prop()

    entries: List[Tuple[str, bytes, int]] = [
        ("module.prop", module_prop.encode("utf-8"), 0o644),
        ("disable", b"", 0o644),
        ("skip_mount", b"", 0o644),
        ("action.sh", action.encode("utf-8"), 0o755),
        ("service.sh", service.encode("utf-8"), 0o755),
        ("payload/manifest.env", manifest.encode("utf-8"), 0o644),
        ("payload/display_profile.block", block, 0o644),
        ("README.md", readme.encode("utf-8"), 0o644),
    ]
    blob = _build_zip(entries)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(output), flags, 0o644)
    except OSError as exc:
        raise BuildError(f"cannot create --output: {exc}") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
    except OSError:
        try:
            output.unlink()
        except OSError:
            pass
        raise

    return {
        "apply_capable": bool(fingerprint and kernel_release),
        "block_sha256": block_sha,
        "block_span": [start, end],
        "block_size": len(block),
        "identity_scope": "stock-original-only",
        "module_id": MODULE_ID,
        "module_version": MODULE_VERSION,
        "output": str(output),
        "output_sha256": _sha256(blob),
        "output_size": len(blob),
        "pinned_fingerprint": fingerprint,
        "pinned_kernel_release": kernel_release,
        "source_sha256": source_sha,
        "source_size": source_size,
        "target_path": TARGET_PATH,
        "zip_entries": [name for name, _data, _mode in entries],
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_optics_module.py",
        description=(
            "Build a private, disabled KernelSU identity-only optical-profile module. "
            "No device access; verified collector inputs required."
        ),
    )
    parser.add_argument("--block", required=True, help="file with the original block bytes")
    parser.add_argument("--source-sha256", required=True, help="pinned full stock SHA-256")
    parser.add_argument("--source-size", required=True, help="pinned full stock size in bytes")
    parser.add_argument("--start", required=True, help="first byte offset of the block")
    parser.add_argument("--end", required=True, help="exclusive end byte offset of the block")
    parser.add_argument("--output", required=True, help="new ZIP path (must not exist)")
    parser.add_argument(
        "--fingerprint",
        default=None,
        help="pinned ro.build.fingerprint (default: documented ledger value; empty disables apply)",
    )
    parser.add_argument(
        "--kernel-release",
        default=None,
        help="pinned uname -r (default: documented ledger value; empty disables apply)",
    )
    args = parser.parse_args(argv)

    try:
        summary = build(args)
    except BuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
