#!/usr/bin/env python3
"""Offline focused tests for build_optics_module.py.

No device, ADB, mount or network access is used. The runtime splice algorithm is
mirrored in Python against the generated manifest so identity and tamper
behaviour can be checked without a headset.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_optics_module as bom  # noqa: E402

_OMIT = object()

PREFIX = b"# mixed static profile fixture\n" + bytes(range(1, 41))
BLOCK = (
    b"display_profile_v2 {\n"
    b"  version: 2\n"
    b"  left_eye: { k1: 0.100 k2: -0.200 }\n"
    b"  right_eye: { k1: 0.300 k2: -0.400 }\n"
    b"  mesh_rows: 33\n"
    b"  mesh_cols: 33\n"
    b"}\n"
)
SUFFIX = b"\n# end of mixed static profile fixture\n" + b"Z" * 24
STOCK = PREFIX + BLOCK + SUFFIX
START = len(PREFIX)
END = START + len(BLOCK)
SOURCE_SHA = hashlib.sha256(STOCK).hexdigest()
SOURCE_SIZE = len(STOCK)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def code_lines(script: str) -> str:
    return "\n".join(
        line for line in script.splitlines() if not line.lstrip().startswith("#")
    )


def function_body(script: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n(.*?)\n\}}", script, re.MULTILINE | re.DOTALL
    )
    if not match:
        raise AssertionError(f"function not found: {name}")
    return match.group(1)


def parse_manifest(text: str) -> dict:
    values = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise AssertionError(f"blank manifest line {number}")
        if "=" not in line:
            raise AssertionError(f"manifest line {number} has no '='")
        key, value = line.split("=", 1)
        if key in values:
            raise AssertionError(f"duplicate manifest key: {key}")
        values[key] = value
    return values


class OpticsModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        scratch_root = Path(tempfile.gettempdir()) / "opencode"
        scratch_root.mkdir(parents=True, exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(
            prefix="gxr-optics-test-", dir=str(scratch_root)
        )
        self.dir = Path(self._tmp.name)
        self._counter = 0

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def build(
        self,
        *,
        block: bytes | None = None,
        source_sha: str | None = None,
        source_size: int | None = None,
        start: int | None = None,
        end: int | None = None,
        output_name: str = "module.zip",
        fingerprint: object = _OMIT,
        kernel: object = _OMIT,
    ):
        self._counter += 1
        block_bytes = BLOCK if block is None else block
        sha_value = SOURCE_SHA if source_sha is None else source_sha
        size_value = SOURCE_SIZE if source_size is None else source_size
        start_value = START if start is None else start
        end_value = END if end is None else end

        block_path = self.dir / f"block-{self._counter}.bin"
        block_path.write_bytes(block_bytes)
        output = self.dir / output_name
        argv = [
            "--block",
            str(block_path),
            "--source-sha256",
            str(sha_value),
            "--source-size",
            str(size_value),
            "--start",
            str(start_value),
            "--end",
            str(end_value),
            "--output",
            str(output),
        ]
        if fingerprint is not _OMIT:
            argv.extend(["--fingerprint", str(fingerprint)])
        if kernel is not _OMIT:
            argv.extend(["--kernel-release", str(kernel)])

        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = bom.main(argv)
        return code, stdout.getvalue(), stderr.getvalue(), output

    def build_ok(self, **kwargs):
        code, stdout, stderr, output = self.build(**kwargs)
        self.assertEqual(code, 0, stderr)
        self.assertTrue(output.is_file())
        summary = json.loads(stdout)
        return output, summary

    # ------------------------------------------------------------------ layout

    def test_zip_layout_and_metadata(self) -> None:
        output, _summary = self.build_ok()
        with zipfile.ZipFile(output) as zf:
            self.assertEqual(zf.namelist(), list(bom.ZIP_ORDER))
            self.assertEqual(zf.read("disable"), b"")
            self.assertEqual(zf.read("skip_mount"), b"")
            self.assertEqual(zf.read("payload/display_profile.block"), BLOCK)
            for info in zf.infolist():
                self.assertEqual(info.date_time, bom.ZIP_EPOCH)
                self.assertEqual(info.create_system, 3)
                mode = (info.external_attr >> 16) & 0o777
                expected = 0o755 if info.filename.endswith(".sh") else 0o644
                self.assertEqual(mode, expected, info.filename)
                self.assertFalse(info.filename.startswith("/"))
                self.assertNotIn("\\", info.filename)
                self.assertNotIn("..", info.filename.split("/"))
                if info.filename.endswith(".sh") or info.filename in {
                    "module.prop",
                    "README.md",
                    "payload/manifest.env",
                }:
                    data = zf.read(info.filename)
                    self.assertNotIn(b"\r", data, info.filename)
                    self.assertTrue(data.endswith(b"\n"), info.filename)
            self.assertFalse(any(name.startswith("META-INF") for name in zf.namelist()))
            self.assertNotIn("post-fs-data.sh", zf.namelist())
            self.assertNotIn("uninstall.sh", zf.namelist())
            self.assertFalse(any(name.startswith("system/") for name in zf.namelist()))

    def test_module_prop_identity_and_disabled_flags(self) -> None:
        output, _summary = self.build_ok()
        with zipfile.ZipFile(output) as zf:
            prop = parse_manifest(zf.read("module.prop").decode("utf-8"))
        self.assertEqual(prop["id"], bom.MODULE_ID)
        self.assertEqual(prop["version"], bom.MODULE_VERSION)
        self.assertEqual(prop["versionCode"], str(bom.MODULE_VERSION_CODE))
        self.assertIn("disabled", prop["description"].lower())
        self.assertIn("identity", prop["description"].lower())
        self.assertIn("manual", prop["description"].lower())

    def test_manifest_pins_exact_identity(self) -> None:
        output, summary = self.build_ok(
            fingerprint="test/fingerprint:14/TEST/1234:user/release-keys",
            kernel="1.2.3-test-kernel",
        )
        with zipfile.ZipFile(output) as zf:
            manifest = parse_manifest(
                zf.read("payload/manifest.env").decode("utf-8")
            )
        self.assertEqual(manifest["module_id"], bom.MODULE_ID)
        self.assertEqual(manifest["identity_scope"], "stock-original-only")
        self.assertEqual(manifest["target_path"], bom.TARGET_PATH)
        self.assertEqual(manifest["selinux_context"], bom.SELINUX_CONTEXT)
        self.assertEqual(manifest["source_sha256"], SOURCE_SHA)
        self.assertEqual(manifest["source_size"], str(SOURCE_SIZE))
        self.assertEqual(manifest["block_sha256"], sha(BLOCK))
        self.assertEqual(manifest["block_start"], str(START))
        self.assertEqual(manifest["block_end"], str(END))
        self.assertEqual(
            manifest["expected_fingerprint"],
            "test/fingerprint:14/TEST/1234:user/release-keys",
        )
        self.assertEqual(manifest["expected_kernel_release"], "1.2.3-test-kernel")
        self.assertEqual(summary["block_span"], [START, END])
        self.assertTrue(summary["apply_capable"])

    def test_identity_pins_default_and_empty_fail_closed(self) -> None:
        _out, summary = self.build_ok(output_name="default.zip")
        self.assertEqual(summary["pinned_fingerprint"], bom.DEFAULT_FINGERPRINT)
        self.assertEqual(summary["pinned_kernel_release"], bom.DEFAULT_KERNEL_RELEASE)
        self.assertTrue(summary["apply_capable"])

        empty_out, empty_summary = self.build_ok(
            output_name="empty.zip", fingerprint="", kernel=""
        )
        self.assertFalse(empty_summary["apply_capable"])
        with zipfile.ZipFile(empty_out) as zf:
            manifest = parse_manifest(
                zf.read("payload/manifest.env").decode("utf-8")
            )
        self.assertEqual(manifest["expected_fingerprint"], "")
        self.assertEqual(manifest["expected_kernel_release"], "")

    # ------------------------------------------------------------- script safety

    def _scripts(self) -> tuple[str, str]:
        output, _summary = self.build_ok()
        with zipfile.ZipFile(output) as zf:
            return (
                zf.read("action.sh").decode("utf-8"),
                zf.read("service.sh").decode("utf-8"),
            )

    def test_scripts_forbid_dangerous_constructs(self) -> None:
        action, service = self._scripts()
        for label, script in (("action.sh", action), ("service.sh", service)):
            executable = code_lines(script)
            self.assertNotIn("\r", script)
            for pattern, reason in bom.FORBIDDEN_SCRIPT_PATTERNS:
                self.assertIsNone(
                    re.search(pattern, executable),
                    f"{label} uses forbidden construct: {reason}",
                )
            self.assertNotRegex(executable, r"(?m)^\s*(curl|wget|nc)\b")

    def test_action_defaults_to_read_only_status(self) -> None:
        action, _service = self._scripts()
        self.assertIn("action=${1:-status}", action)
        self.assertRegex(action, r"(?m)^  status\) do_status ;;$")
        status_body = function_body(action, "do_status")
        self.assertNotIn("record", status_body)
        self.assertNotIn("$STATUS", status_body)
        self.assertNotIn("mount -o bind", status_body)
        self.assertNotIn("umount", status_body)

    def test_prepare_only_splices_into_module_payload(self) -> None:
        action, _service = self._scripts()
        body = function_body(action, "do_prepare")
        self.assertNotIn("mount -o bind", body)
        self.assertNotIn("umount", body)
        splice = function_body(action, "build_payload")
        self.assertIn('TMP="$MODDIR/payload/', splice)
        self.assertIn('[ -e "$TMP" ] || [ -L "$TMP" ]', splice)
        self.assertIn("set -C", splice)
        self.assertIn('dd if="$TARGET" of="$TMP" bs=1 count="$START" conv=notrunc', splice)
        self.assertIn('dd if="$BLOCK" of="$TMP" bs=1 seek="$START"', splice)
        self.assertIn('dd if="$TARGET" of="$TMP" bs=1 skip="$END"', splice)
        self.assertIn('mv -f "$TMP" "$PAYLOAD"', splice)
        self.assertIn('sha_of "$TMP"', splice)
        self.assertIn('chcon "$CONTEXT"', splice)
        self.assertIn("check_module_paths", body)
        self.assertNotIn('of="$TARGET"', action)

    def test_prepare_and_off_check_namespace_before_mutation(self) -> None:
        action, _service = self._scripts()
        prepare = function_body(action, "do_prepare")
        off = function_body(action, "do_off")
        self.assertLess(prepare.index("check_namespace"), prepare.index("build_payload"))
        self.assertLess(prepare.index("check_module_paths"), prepare.index("load_config"))
        self.assertLess(off.index("check_namespace"), off.index("umount"))
        self.assertLess(off.index("check_namespace"), off.index("record"))
        self.assertIn("check_module_paths", off)

    def test_apply_preconditions_and_manual_token(self) -> None:
        action, _service = self._scripts()
        body = function_body(action, "do_apply")
        required = [
            '[ "$token" = "$APPLY_TOKEN" ]',
            '[ ! -e "$DISABLE_FLAG" ]',
            '[ -f "$SKIP_MOUNT_FLAG" ]',
            "check_namespace",
            "check_module_paths",
            'getprop ro.build.fingerprint',
            'uname -r',
            "check_target_path",
            '[ "$(mount_count)" = 0 ]',
            'sha_of "$TARGET"',
            'sha_of "$PAYLOAD"',
            'verify_owner_mode "$PAYLOAD"',
            'verify_context "$PAYLOAD"',
            "resolve_payload_identity",
            'mount -o bind "$PAYLOAD" "$TARGET"',
            'consumer="/proc/$PERCEPTION_PID/root$TARGET"',
            "rollback_owned",
        ]
        for token in required:
            self.assertIn(token, body)
        self.assertEqual(action.count('mount -o bind "$PAYLOAD" "$TARGET"'), 1)
        self.assertEqual(action.count('umount "$TARGET"'), 2)
        self.assertNotRegex(action, r"umount\s+(-l|--lazy)")
        namespace = function_body(action, "check_namespace")
        self.assertIn("ns_of 1", namespace)
        self.assertIn("init_ns", namespace)
        self.assertIn("pid_of_unique", namespace)
        self.assertIn("/system/bin/ps", action)
        self.assertIn("android.hardware.perceptionhost", action)
        self.assertIn("surfaceflinger", namespace)

    def test_off_only_unmounts_owned_mount(self) -> None:
        action, _service = self._scripts()
        body = function_body(action, "do_off")
        self.assertIn("resolve_payload_identity", body)
        self.assertIn("owned_count", body)
        self.assertIn('umount "$TARGET"', body)
        self.assertIn("not the module-owned payload; refusing", body)
        self.assertNotIn("rm ", body)
        rollback = function_body(action, "rollback_owned")
        self.assertIn("owned_count", rollback)
        self.assertIn("resolve_payload_identity", rollback)
        self.assertIn('[ "$(mount_count)" = 1 ]', rollback)

    def test_payload_root_derivation_matches_mountinfo_semantics(self) -> None:
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        action, _service = self._scripts()
        payload_mount = function_body(action, "payload_mount").replace(
            "/proc/self/mountinfo", '"$GXR_MOUNTINFO"'
        )
        resolve = function_body(action, "resolve_payload_identity")
        payload = "/data/adb/modules/gxr_optical_profile/payload/device_profile.textproto"
        target = "/mnt/vendor/efs/device_profile.textproto"

        cases = {
            "data_mount": (
                "1 0 253:1 / / rw,relatime - ext4 /dev/root rw\n"
                "2 1 259:5 / /data rw,relatime - f2fs /dev/block/dm-5 rw\n"
                "3 1 259:6 / /mnt/vendor rw,relatime - ext4 /dev/block/dm-6 rw\n",
                "259:5",
                "/adb/modules/gxr_optical_profile/payload/device_profile.textproto",
            ),
            "root_mount": (
                "1 0 253:1 / / rw,relatime - ext4 /dev/root rw\n",
                "253:1",
                payload,
            ),
            "non_root_underlying": (
                "1 0 253:1 / / rw,relatime - ext4 /dev/root rw\n"
                "2 1 259:5 /userdata /data rw,relatime - f2fs /dev/block/dm-5 rw\n",
                None,
                None,
            ),
            "non_root_longest_prefix": (
                "1 0 253:1 / / rw,relatime - ext4 /dev/root rw\n"
                "2 1 259:5 / /data rw,relatime - f2fs /dev/block/dm-5 rw\n"
                "3 2 259:5 /subtree /data/adb rw,relatime - f2fs /dev/block/dm-5 rw\n",
                None,
                None,
            ),
        }
        for name, (mountinfo, expected_dev, expected_root) in cases.items():
            with self.subTest(name=name):
                info_path = self.dir / f"mountinfo-{name}.txt"
                info_path.write_text(mountinfo, encoding="utf-8", newline="\n")
                harness = "\n".join(
                    [
                        "set -u",
                        f"TARGET={shlex.quote(target)}",
                        f"PAYLOAD={shlex.quote(payload)}",
                        'GXR_MOUNTINFO=$(cygpath -u "$GXR_MOUNTINFO_WIN") || exit 9',
                        f"payload_mount() {{\n{payload_mount}\n}}",
                        f"resolve_payload_identity() {{\n{resolve}\n}}",
                        "resolve_payload_identity || exit 1",
                        'printf "%s\\n" "$P_DEV"',
                        'printf "%s\\n" "$P_ROOT"',
                    ]
                )
                proc = subprocess.run(
                    [bash],
                    input=harness,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    env={**os.environ, "GXR_MOUNTINFO_WIN": str(info_path)},
                )
                if proc.returncode != 0:
                    detail = (proc.stderr or "").strip()
                    if "windows subsystem" in detail.lower() or "wsl" in detail.lower():
                        self.skipTest(f"bash launcher unusable here: {detail[:120]}")
                    if expected_root is None:
                        self.assertEqual(proc.stdout, "")
                        continue
                    self.fail(f"{name} ownership derivation failed: {detail}")
                if expected_root is None:
                    self.fail(f"{name} should have refused a non-/ underlying root")
                lines = proc.stdout.splitlines()
                self.assertEqual(lines, [expected_dev, expected_root])

    def test_pid_resolution_requires_unique_exact_names(self) -> None:
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        action, _service = self._scripts()
        pid_of_unique = function_body(action, "pid_of_unique")
        is_uint = function_body(action, "is_uint")
        perception = "android.hardware.perceptionhost"

        cases = {
            "unique_perception": (
                f"1213 {perception}\n1290 surfaceflinger\n",
                perception,
                "1213",
            ),
            "unique_surfaceflinger": (
                f"1213 {perception}\n1290 surfaceflinger\n",
                "surfaceflinger",
                "1290",
            ),
            "short_name_rejected": (
                "1213 perceptionhost\n",
                perception,
                None,
            ),
            "ambiguous_rejected": (
                f"1213 {perception}\n1291 {perception}\n",
                perception,
                None,
            ),
            "suffix_name_rejected": (
                f"1213 {perception}.extra\n",
                perception,
                None,
            ),
            "nonnumeric_pid_rejected": (
                f"abc {perception}\n",
                perception,
                None,
            ),
        }
        for name, (dump, query, expected) in cases.items():
            with self.subTest(name=name):
                fixture = self.dir / f"ps-{name}.txt"
                fixture.write_text(dump, encoding="utf-8", newline="\n")
                harness = "\n".join(
                    [
                        "set -u",
                        'PS_FIXTURE=$(cygpath -u "$PS_FIXTURE_WIN") || exit 9',
                        'ps_dump() { cat "$PS_FIXTURE"; }',
                        f"is_uint() {{\n{is_uint}\n}}",
                        f"pid_of_unique() {{\n{pid_of_unique}\n}}",
                        f"pid_of_unique {shlex.quote(query)}",
                    ]
                )
                proc = subprocess.run(
                    [bash],
                    input=harness,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    env={**os.environ, "PS_FIXTURE_WIN": str(fixture)},
                )
                detail = (proc.stderr or "").strip()
                if "windows subsystem" in detail.lower() or "wsl" in detail.lower():
                    self.skipTest(f"bash launcher unusable here: {detail[:120]}")
                if expected is None:
                    self.assertNotEqual(proc.returncode, 0, name)
                    self.assertEqual(proc.stdout.strip(), "", name)
                else:
                    self.assertEqual(proc.returncode, 0, detail)
                    self.assertEqual(proc.stdout.strip(), expected, name)

    def test_temp_cleanup_is_ownership_scoped(self) -> None:
        action, _service = self._scripts()
        cleanup = function_body(action, "cleanup")
        splice = function_body(action, "build_payload")
        self.assertIn('[ "$TMP_OWNED" = 1 ]', cleanup)
        self.assertIn('rm -f "$TMP"', cleanup)
        self.assertNotIn('elif', cleanup)
        self.assertLess(splice.index("TMP_OWNED=0"), splice.index("TMP="))
        self.assertLess(
            splice.index('[ -e "$TMP" ] || [ -L "$TMP" ]'),
            splice.index("TMP_OWNED=1"),
        )
        self.assertLess(splice.index("TMP_OWNED=1"), splice.index("dd if="))
        self.assertLess(
            splice.index('mv -f "$TMP" "$PAYLOAD"'), splice.rindex("TMP_OWNED=0")
        )
        self.assertLess(
            splice.index('mv -f "$TMP" "$PAYLOAD"'), splice.rindex("TMP=")
        )

    def test_temp_cleanup_never_deletes_an_unowned_path(self) -> None:
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        action, _service = self._scripts()
        bodies = {
            "cleanup": function_body(action, "cleanup"),
            "fail": function_body(action, "fail"),
            "sha_of": function_body(action, "sha_of"),
            "size_of": function_body(action, "size_of"),
            "build_payload": function_body(action, "build_payload"),
        }

        block = b"display_profile_v2 { identity_fixture: true }\n"

        cases = {
            "preexisting_regular_file": (
                'TMP="$MODDIR/payload/.device_profile.tmp.$$"\n'
                'printf %s "preexisting-sentinel" > "$TMP"\n',
                len(block),
                sha(block),
                sha(block),
                "preexisting_regular_file",
            ),
            "preexisting_dangling_symlink": (
                'TMP="$MODDIR/payload/.device_profile.tmp.$$"\n'
                'ln -s missing-target "$TMP" 2>/dev/null || exit 8\n'
                '[ -L "$TMP" ] || exit 7\n',
                len(block),
                sha(block),
                sha(block),
                "preexisting_dangling_symlink",
            ),
            "own_temp_removed_on_late_failure": (
                "",
                len(block) + 1,
                sha(block),
                sha(block),
                None,
            ),
            "own_temp_published_then_reset": (
                "",
                len(block),
                sha(block),
                sha(block),
                "published",
            ),
        }

        for name, (prelude, size, src_sha, blk_sha, expect) in cases.items():
            with self.subTest(name=name):
                module_dir = self.dir / f"module-{name}"
                payload_dir = module_dir / "payload"
                payload_dir.mkdir(parents=True)
                (payload_dir / "display_profile.block").write_bytes(block)
                (module_dir / "stock.bin").write_bytes(block)

                harness = "\n".join(
                    [
                        "set -u",
                        'MODDIR=$(cygpath -u "$GXR_MODDIR_WIN") || exit 9',
                        'PAYLOAD="$MODDIR/payload/device_profile.textproto"',
                        'BLOCK="$MODDIR/payload/display_profile.block"',
                        'TARGET="$MODDIR/stock.bin"',
                        'STATUS="$MODDIR/last_action.txt"',
                        "CONTEXT=u:object_r:perceptionhost_efs_file:s0",
                        "START=0",
                        f"END={len(block)}",
                        f"SRC_SIZE={size}",
                        f"SRC_SHA={src_sha}",
                        f"BLK_SHA={blk_sha}",
                        "TMP=",
                        "TMP_OWNED=0",
                        f"cleanup() {{\n{bodies['cleanup']}\n}}",
                        "trap cleanup EXIT",
                        f"fail() {{\n{bodies['fail']}\n}}",
                        f"sha_of() {{\n{bodies['sha_of']}\n}}",
                        f"size_of() {{\n{bodies['size_of']}\n}}",
                        "verify_owner_mode() { return 0; }",
                        "verify_context() { return 0; }",
                        "chown() { return 0; }",
                        "chmod() { return 0; }",
                        "chcon() { return 0; }",
                        f"build_payload() {{\n{bodies['build_payload']}\n}}",
                        prelude,
                        "build_payload",
                        'echo "UNEXPECTED_SUCCESS"',
                    ]
                )
                proc = subprocess.run(
                    [bash],
                    input=harness,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    env={
                        **os.environ,
                        "GXR_MODDIR_WIN": str(module_dir),
                        "MSYS": "winsymlinks:nativestrict",
                    },
                )
                detail = (proc.stderr or "").strip()
                if "windows subsystem" in detail.lower() or "wsl" in detail.lower():
                    self.skipTest(f"bash launcher unusable here: {detail[:120]}")
                if proc.returncode in (7, 8):
                    self.skipTest("bash cannot create symlinks in this environment")
                if expect != "published" and "UNEXPECTED_SUCCESS" in proc.stdout:
                    self.fail(f"{name}: build_payload unexpectedly succeeded")

                temps = sorted(p.name for p in payload_dir.iterdir() if p.name.startswith(".device_profile.tmp."))
                if expect is None:
                    self.assertNotEqual(proc.returncode, 0, detail)
                    self.assertEqual(temps, [], f"{name}: own temp file was not removed")
                elif expect == "published":
                    self.assertEqual(proc.returncode, 0, detail)
                    self.assertEqual(temps, [], f"{name}: temp survived publish")
                    self.assertTrue((payload_dir / "device_profile.textproto").is_file())
                elif expect == "preexisting_regular_file":
                    self.assertNotEqual(proc.returncode, 0, detail)
                    self.assertEqual(len(temps), 1, f"{name}: preexisting temp path vanished")
                    self.assertEqual(
                        (payload_dir / temps[0]).read_bytes(), b"preexisting-sentinel"
                    )
                else:
                    self.assertNotEqual(proc.returncode, 0, detail)
                    self.assertEqual(len(temps), 1, f"{name}: preexisting symlink vanished")
                    self.assertTrue((payload_dir / temps[0]).is_symlink())

    def test_service_reports_only(self) -> None:
        _action, service = self._scripts()
        executable = code_lines(service)
        self.assertNotRegex(executable, r"(?m)^\s*(mount|umount)\b")
        self.assertNotIn("action.sh", executable)
        self.assertNotIn("do_prepare", executable)
        self.assertNotIn("do_apply", executable)
        self.assertNotIn("sha256sum", executable)
        self.assertNotIn(">", executable)
        self.assertNotIn("printf", executable)
        self.assertIn("activation-required", executable)
        self.assertIn("exit 0", executable)

    def test_status_and_logs_never_emit_hashes_or_calibration(self) -> None:
        action, service = self._scripts()
        for line in (action + "\n" + service).splitlines():
            if any(word in line for word in ("printf", "note ", "echo ")):
                self.assertNotIn("SRC_SHA", line)
                self.assertNotIn("BLK_SHA", line)
                self.assertNotIn("base64", line)
        self.assertNotIn("xxd", action)

    def test_scripts_have_no_bashisms(self) -> None:
        action, service = self._scripts()
        forbidden = [
            (r"\[\[", "[[ test"),
            (r"\]\]", "]] test"),
            (r"(?m)^\s*function\s+", "function keyword"),
            (r"<<<", "here-string"),
            (r"\bdeclare\b", "declare"),
            (r"\bmapfile\b", "mapfile"),
            (r"\blocal\s+-a\b", "array local"),
            (r"\$\{[A-Za-z_][A-Za-z0-9_]*//", "pattern substitution"),
        ]
        for label, script in (("action.sh", action), ("service.sh", service)):
            for pattern, reason in forbidden:
                self.assertIsNone(
                    re.search(pattern, script), f"{label} uses {reason}"
                )

    def test_shell_syntax_with_available_bash(self) -> None:
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        action, service = self._scripts()
        for name, script in (("action.sh", action), ("service.sh", service)):
            proc = subprocess.run(
                [bash, "-n"],
                input=script,
                text=True,
                capture_output=True,
                timeout=30,
            )
            if proc.returncode != 0:
                detail = (proc.stderr or "").strip()
                lowered = detail.lower()
                if "windows subsystem" in lowered or "wsl" in lowered:
                    self.skipTest(f"bash launcher unusable here: {detail[:120]}")
                self.fail(f"{name} syntax error: {detail}")

    # ---------------------------------------------------------------- identity

    def test_splice_identity_matches_pinned_source(self) -> None:
        output, _summary = self.build_ok()
        with zipfile.ZipFile(output) as zf:
            manifest = parse_manifest(
                zf.read("payload/manifest.env").decode("utf-8")
            )
            block = zf.read("payload/display_profile.block")
        start = int(manifest["block_start"])
        end = int(manifest["block_end"])
        self.assertEqual(block, STOCK[start:end])
        payload = STOCK[:start] + block + STOCK[end:]
        self.assertEqual(len(payload), int(manifest["source_size"]))
        self.assertEqual(sha(payload), manifest["source_sha256"])
        self.assertEqual(sha(block), manifest["block_sha256"])
        self.assertEqual(payload, STOCK)

    def test_tamper_rejected_by_identity_and_region_hashes(self) -> None:
        output, _summary = self.build_ok()
        with zipfile.ZipFile(output) as zf:
            manifest = parse_manifest(
                zf.read("payload/manifest.env").decode("utf-8")
            )
            block = zf.read("payload/display_profile.block")
        start = int(manifest["block_start"])
        end = int(manifest["block_end"])

        bad_block = bytearray(block)
        bad_block[len(bad_block) // 2] ^= 0x01
        spliced_bad_block = STOCK[:start] + bytes(bad_block) + STOCK[end:]
        self.assertNotEqual(sha(spliced_bad_block), manifest["source_sha256"])
        self.assertNotEqual(
            sha(spliced_bad_block[start:end]), manifest["block_sha256"]
        )

        bad_suffix = bytearray(STOCK)
        bad_suffix[-1] ^= 0xFF
        self.assertNotEqual(sha(bytes(bad_suffix)), manifest["source_sha256"])

        bad_prefix = bytearray(STOCK)
        bad_prefix[0] ^= 0xFF
        self.assertNotEqual(sha(bytes(bad_prefix)), manifest["source_sha256"])

    def test_build_is_deterministic(self) -> None:
        first, summary_one = self.build_ok(output_name="one.zip")
        second, summary_two = self.build_ok(output_name="two.zip")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(summary_one["output_sha256"], summary_two["output_sha256"])

    # ------------------------------------------------------------------ rejects

    def test_invalid_inputs_fail_nonzero_without_output(self) -> None:
        cases = {
            "end_equal_start": {"start": START, "end": START},
            "end_before_start": {"start": END, "end": START},
            "span_too_long_for_block": {"end": END + 1},
            "end_beyond_source": {"end": SOURCE_SIZE + 1},
            "start_beyond_source": {"start": SOURCE_SIZE + 5, "end": SOURCE_SIZE + 10},
            "zero_source_size": {"source_size": 0},
            "negative_start": {"start": -1},
            "non_numeric_start": {"start": "1x"},
            "uppercase_sha": {"source_sha": SOURCE_SHA.upper()},
            "short_sha": {"source_sha": "a" * 63},
            "non_hex_sha": {"source_sha": "g" * 64},
            "empty_block": {"block": b""},
        }
        for name, overrides in cases.items():
            with self.subTest(name=name):
                output_name = f"reject-{name}.zip"
                code, _stdout, stderr, output = self.build(
                    output_name=output_name, **overrides
                )
                self.assertEqual(code, 2, stderr)
                self.assertIn("ERROR:", stderr)
                self.assertFalse(output.exists())

    def test_missing_block_file_rejected(self) -> None:
        output = self.dir / "missing.zip"
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = bom.main(
                [
                    "--block",
                    str(self.dir / "does-not-exist.bin"),
                    "--source-sha256",
                    SOURCE_SHA,
                    "--source-size",
                    str(SOURCE_SIZE),
                    "--start",
                    str(START),
                    "--end",
                    str(END),
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("--block", stderr.getvalue())
        self.assertFalse(output.exists())

    def test_existing_output_is_not_overwritten(self) -> None:
        first, _summary = self.build_ok(output_name="existing.zip")
        original = first.read_bytes()
        code, _stdout, stderr, output = self.build(output_name="existing.zip")
        self.assertEqual(code, 2)
        self.assertIn("overwrite", stderr)
        self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
