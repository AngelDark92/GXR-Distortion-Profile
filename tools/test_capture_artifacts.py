#!/usr/bin/env python3
"""Fixture tests for capture_artifacts.py.

Run with: python -B -m unittest test_capture_artifacts -v
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import capture_artifacts as ca


ADB = "/adb"
SERIAL = "abc123"
PROBE_HASH = hashlib.sha256(ca.PROBE_BYTES).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identity_responses(fingerprint: bytes = b"oculus/fingerprint:1.0\n"):
    return [
        (lambda c: c == "id -u", (0, b"0\n", b"")),
        (lambda c: c == "getprop ro.build.fingerprint", (0, fingerprint, b"")),
        (lambda c: c == "uname -a", (0, b"Linux localhost 5.0\n", b"")),
    ]


def _base64_with_crlf(data: bytes, width: int = 76) -> bytes:
    encoded = base64.b64encode(data)
    lines = [encoded[i : i + width] for i in range(0, len(encoded), width)]
    return b"\r\n".join(lines) + b"\r\n"


def _probe_response(inner: str):
    if "printf '%s'" in inner and inner.rstrip().endswith("| base64"):
        # base64-mode probe: decode known bytes then re-encode for transport
        return (0, _base64_with_crlf(ca.PROBE_BYTES), b"")
    if "printf '%s'" in inner and "| base64 -d" in inner:
        return (0, ca.PROBE_BYTES, b"")
    return None


def make_adb_runner(responses):
    """Return a run_adb_command replacement driven by ordered predicates."""
    def runner(adb_path, serial, inner_command, timeout=300.0):
        self = runner
        # probe always handled if no earlier predicate matched
        probe = _probe_response(inner_command)
        if probe is not None:
            return probe
        for pred, resp in responses:
            if pred(inner_command):
                return resp
        raise AssertionError(f"unexpected adb command: {inner_command!r}")
    return runner


class TestGenericCollector(unittest.TestCase):
    def test_successful_binary_capture(self):
        content = b"bin\x00\xff\r\n!extra"
        remote_hash = _sha256(content)
        path = "/data/foo.bin"

        responses = _identity_responses() + [
            (lambda c, p=path: f"stat -c %s {p}" in c, (0, str(len(content)).encode() + b"\n", b"")),
            (lambda c, p=path: f"test -f {p}" in c, (0, b"", b"")),
            (lambda c, p=path: f"sha256sum {p}" in c and "cat " not in c, (0, (remote_hash + "  " + path + "\n").encode(), b"")),
            (lambda c, p=path: c == f"cat {p}", (0, content, b"")),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = ["--adb", ADB, "--serial", SERIAL, "--output", out, path]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                rc = ca.main(argv)
            self.assertEqual(rc, 0)
            local = os.path.join(out, "originals", "data", "foo.bin")
            self.assertTrue(os.path.exists(local))
            with open(local, "rb") as fh:
                self.assertEqual(fh.read(), content)
            with open(os.path.join(out, "capture_manifest.json"), "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            self.assertEqual(len(manifest["verified"]), 1)
            self.assertEqual(manifest["verified"][0]["sha256"], remote_hash)
            self.assertFalse(manifest["verified"][0]["selected_capture_not_full_file"])

    def test_hash_mismatch_leaves_no_file(self):
        content = b"original"
        remote_hash = _sha256(content)
        path = "/data/foo.bin"

        responses = _identity_responses() + [
            (lambda c, p=path: f"stat -c %s {p}" in c, (0, str(len(content)).encode() + b"\n", b"")),
            (lambda c, p=path: f"test -f {p}" in c, (0, b"", b"")),
            (lambda c, p=path: f"sha256sum {p}" in c and "cat " not in c, (0, (remote_hash + "  " + path + "\n").encode(), b"")),
            (lambda c, p=path: c == f"cat {p}", (0, b"mangled!", b"")),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = ["--adb", ADB, "--serial", SERIAL, "--output", out, path]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                with self.assertRaises(SystemExit) as cm:
                    ca.main(argv)
                self.assertEqual(cm.exception.code, 1)
            local = os.path.join(out, "originals", "data", "foo.bin")
            self.assertFalse(os.path.exists(local))
            self.assertFalse(os.path.exists(local + ".partial"))
            with open(os.path.join(out, "failure_manifest.json"), "r", encoding="utf-8") as fh:
                fail = json.load(fh)
            self.assertEqual(len(fail["failures"]), 1)
            self.assertIn("sha256", fail["failures"][0]["reason"])

    def test_remote_identity_failure(self):
        responses = [
            (lambda c: c == "id -u", (1, b"", b"permission denied")),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = ["--adb", ADB, "--serial", SERIAL, "--output", out, "/data/x"]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                with self.assertRaises(SystemExit) as cm:
                    ca.main(argv)
                self.assertEqual(cm.exception.code, 1)
            self.assertTrue(os.path.isdir(out))
            self.assertFalse(os.path.exists(os.path.join(out, "capture_manifest.json")))
            self.assertTrue(os.path.exists(os.path.join(out, "failure_manifest.json")))
            with open(os.path.join(out, "failure_manifest.json"), "r", encoding="utf-8") as fh:
                fail = json.load(fh)
            self.assertEqual(fail["phase"], "identity")

    def test_rejected_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = ["--adb", ADB, "--serial", SERIAL, "--output", out, "/data/../x"]
            with patch("capture_artifacts.run_adb_command") as mock_run:
                with self.assertRaises(SystemExit) as cm:
                    ca.main(argv)
                self.assertEqual(cm.exception.code, 1)
            mock_run.assert_not_called()
            self.assertFalse(os.path.exists(out))

    def test_preexisting_output_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            os.makedirs(out)
            with open(os.path.join(out, "sentinel"), "w", encoding="utf-8") as fh:
                fh.write("x")
            argv = ["--adb", ADB, "--serial", SERIAL, "--output", out, "/data/x"]
            with patch("capture_artifacts.run_adb_command") as mock_run:
                with self.assertRaises(SystemExit) as cm:
                    ca.main(argv)
                self.assertEqual(cm.exception.code, 1)
            mock_run.assert_not_called()

    def test_empty_existing_output_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            os.makedirs(out)
            argv = ["--adb", ADB, "--serial", SERIAL, "--output", out, "/data/x"]
            with patch("capture_artifacts.run_adb_command") as mock_run:
                with self.assertRaises(SystemExit) as cm:
                    ca.main(argv)
                self.assertEqual(cm.exception.code, 1)
            mock_run.assert_not_called()
            self.assertEqual(os.listdir(out), [])

    def test_contaminated_raw_probe(self):
        def runner(adb_path, serial, inner_command, timeout=300.0):
            if inner_command == "id -u":
                return (0, b"0\n", b"")
            if inner_command == "getprop ro.build.fingerprint":
                return (0, b"oculus/fingerprint:1.0\n", b"")
            if inner_command == "uname -a":
                return (0, b"Linux localhost 5.0\n", b"")
            if "printf '%s'" in inner_command and "| base64 -d" in inner_command:
                # corrupt probe: wrong length and bytes
                return (0, b"\x00" + ca.PROBE_BYTES[1:] + b"\xff", b"")
            raise AssertionError(f"unexpected adb command: {inner_command!r}")

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = ["--adb", ADB, "--serial", SERIAL, "--output", out, "/data/x"]
            with patch("capture_artifacts.run_adb_command", side_effect=runner):
                with self.assertRaises(SystemExit) as cm:
                    ca.main(argv)
                self.assertEqual(cm.exception.code, 1)
            self.assertTrue(os.path.isdir(out))
            with open(os.path.join(out, "failure_manifest.json"), "r", encoding="utf-8") as fh:
                fail = json.load(fh)
            self.assertEqual(fail["phase"], "probe_before")
            self.assertIn("probe", fail)
            # raw binary must not be in the JSON manifest
            raw = json.dumps(fail)
            self.assertNotIn(ca.PROBE_BYTES.decode("latin-1"), raw)
            self.assertIn("stdout_length", fail["probe"])


class TestDisplayOnlyExtractor(unittest.TestCase):
    def test_quoted_brace_and_comment_ambiguity(self):
        data = (
            b"# header { comment }\n"
            b'camera_profile { name: "front" }\n'
            b"display_profile_v2 {\n"
            b'  panel: "left\\"right"\n'
            b'  geometry: "{not_a#block}"\n'
            b"  nested { value: 1 }\n"
            b"}\n"
            b'imu_profile { name: "back" }\n'
        )
        start, end, block = ca.extract_display_profile_v2(data)
        self.assertEqual(start, data.find(b"display_profile_v2"))
        self.assertEqual(end, start + len(block))
        self.assertTrue(block.startswith(b"display_profile_v2"))
        self.assertTrue(block.endswith(b"}"))
        self.assertIn(b"nested", block)
        self.assertNotIn(b"camera_profile", block)
        self.assertNotIn(b"imu_profile", block)

    def test_preserve_offsets(self):
        prefix = b"# prefix\n"
        block_src = b"display_profile_v2 { a: 1 }"
        suffix = b"# suffix\n"
        data = prefix + block_src + suffix
        start, end, block = ca.extract_display_profile_v2(data)
        self.assertEqual(start, len(prefix))
        self.assertEqual(end, start + len(block_src))
        self.assertEqual(block, block_src)

    def test_duplicate_block_rejected(self):
        data = (
            b"display_profile_v2 { a: 1 }\n"
            b"camera_profile { }\n"
            b"display_profile_v2 { b: 2 }\n"
        )
        with self.assertRaises(ca.DisplayBlockDuplicate):
            ca.extract_display_profile_v2(data)

    def test_unbalanced_block_rejected(self):
        data = b"display_profile_v2 { a: 1\n"
        with self.assertRaises(ca.DisplayBlockMalformed):
            ca.extract_display_profile_v2(data)

    def test_missing_block_rejected(self):
        data = b"camera_profile { name: \"front\" }\n"
        with self.assertRaises(ca.DisplayBlockNotFound):
            ca.extract_display_profile_v2(data)


class TestDisplayOnlyCapture(unittest.TestCase):
    def _build_mixed_content(self) -> bytes:
        return (
            b"# device profile\n"
            b"camera_profile {\n"
            b'  name: "front"\n'
            b"  intrinsics: { fx: 1 fy: 1 cx: 0 cy: 0 }\n"
            b"}\n"
            b"\n"
            b"display_profile_v2: {\n"
            b'  panel: "single_fast"\n'
            b'  label: "\\"not a #brace\\""\n'
            b"  geometry { width: 1440 height: 1600 }\n"
            b"}\n"
            b"\n"
            b"imu_profile {\n"
            b"  # comment with } brace\n"
            b"  accel_bias: [0.1, 0.2, 0.3]\n"
            b"}\n"
        )

    def test_display_only_publishes_block_not_full_file(self):
        content = self._build_mixed_content()
        full_hash = _sha256(content)
        path = "/mnt/vendor/efs/device_profile.textproto"

        responses = _identity_responses() + [
            (lambda c, p=path: f"stat -c %s {p}" in c, (0, str(len(content)).encode() + b"\n", b"")),
            (lambda c, p=path: f"test -f {p}" in c, (0, b"", b"")),
            (lambda c, p=path: f"sha256sum {p}" in c and "cat " not in c, (0, (full_hash + "  " + path + "\n").encode(), b"")),
            (lambda c, p=path: c == f"cat {p}", (0, content, b"")),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = [
                "--adb", ADB, "--serial", SERIAL,
                "--output", out, "--display-only", path,
            ]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                rc = ca.main(argv)
            self.assertEqual(rc, 0)
            local = os.path.join(
                out,
                "originals",
                "mnt",
                "vendor",
                "efs",
                "device_profile.textproto.display_profile_v2.textproto",
            )
            self.assertTrue(os.path.exists(local))
            with open(local, "rb") as fh:
                block = fh.read()
            self.assertTrue(block.startswith(b"display_profile_v2"))
            self.assertTrue(block.endswith(b"}"))
            self.assertNotIn(b"camera_profile", block)
            self.assertNotIn(b"imu_profile", block)

            with open(os.path.join(out, "capture_manifest.json"), "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            entry = manifest["verified"][0]
            self.assertTrue(entry["selected_capture_not_full_file"])
            self.assertEqual(entry["original_size"], len(content))
            self.assertEqual(entry["original_sha_before"], full_hash)
            self.assertEqual(entry["original_sha_after"], full_hash)
            self.assertEqual(entry["selected_block_size"], len(block))
            self.assertEqual(entry["selected_block_sha256"], _sha256(block))
            self.assertGreater(entry["selected_block_start"], 0)
            self.assertEqual(entry["selected_block_end"], entry["selected_block_start"] + entry["selected_block_size"])

            # verify no raw mixed bytes in failure manifest (none should exist)
            self.assertFalse(os.path.exists(os.path.join(out, "failure_manifest.json")))

    def test_display_only_duplicate_leaves_no_mixed_output(self):
        content = (
            b"display_profile_v2 { a: 1 }\n"
            b"camera_profile { }\n"
            b"display_profile_v2 { b: 2 }\n"
        )
        full_hash = _sha256(content)
        path = "/vendor/etc/calibration_service/device_profile.textproto"

        responses = _identity_responses() + [
            (lambda c, p=path: f"stat -c %s {p}" in c, (0, str(len(content)).encode() + b"\n", b"")),
            (lambda c, p=path: f"test -f {p}" in c, (0, b"", b"")),
            (lambda c, p=path: f"sha256sum {p}" in c and "cat " not in c, (0, (full_hash + "  " + path + "\n").encode(), b"")),
            (lambda c, p=path: c == f"cat {p}", (0, content, b"")),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = [
                "--adb", ADB, "--serial", SERIAL,
                "--output", out, "--display-only", path,
            ]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                with self.assertRaises(SystemExit) as cm:
                    ca.main(argv)
                self.assertEqual(cm.exception.code, 1)
            local = os.path.join(
                out,
                "originals",
                "vendor",
                "etc",
                "calibration_service",
                "device_profile.textproto.display_profile_v2.textproto",
            )
            self.assertFalse(os.path.exists(local))
            self.assertFalse(os.path.exists(local + ".partial"))
            with open(os.path.join(out, "failure_manifest.json"), "r", encoding="utf-8") as fh:
                fail = json.load(fh)
            self.assertTrue(
                any("multiple" in f.get("reason", "") for f in fail["failures"]),
                fail["failures"],
            )
            # cat command record must not contain stdout (raw mixed bytes)
            cat_rec = fail["failures"][0]["commands"]["cat"]
            self.assertNotIn("stdout", cat_rec)


class TestBase64Transport(unittest.TestCase):
    def _stat_and_sha_responses(self, path: str, content: bytes):
        remote_hash = _sha256(content)
        return _identity_responses() + [
            (lambda c, p=path: f"stat -c %s {p}" in c, (0, str(len(content)).encode() + b"\n", b"")),
            (lambda c, p=path: f"test -f {p}" in c, (0, b"", b"")),
            (lambda c, p=path: f"sha256sum {p}" in c and "cat " not in c and "base64 " not in c, (0, (remote_hash + "  " + path + "\n").encode(), b"")),
        ]

    def _base64_response(self, path: str, encoded: bytes):
        return (lambda c, p=path: c.startswith("base64 ") and p in c, (0, encoded, b""))

    def test_base64_crlf_encoded_file_capture(self):
        content = b"\x00\x01\x02\xff\r\noptics"
        path = "/data/optics.bin"
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = [
                "--adb", ADB, "--serial", SERIAL,
                "--output", out, "--transport", "base64", path,
            ]
            responses = self._stat_and_sha_responses(path, content) + [
                self._base64_response(path, _base64_with_crlf(content)),
            ]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                rc = ca.main(argv)
            self.assertEqual(rc, 0)
            local = os.path.join(out, "originals", "data", "optics.bin")
            with open(local, "rb") as fh:
                self.assertEqual(fh.read(), content)
            with open(os.path.join(out, "capture_manifest.json"), "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            self.assertEqual(manifest["transport"], "base64")
            entry = manifest["verified"][0]
            self.assertEqual(entry["transport"], "base64")
            self.assertEqual(entry["sha256"], _sha256(content))
            self.assertIn("encoded_length", entry["commands"]["cat"])
            self.assertIn("encoded_sha256", entry["commands"]["cat"])

    def test_base64_invalid_contamination_fails(self):
        path = "/data/optics.bin"
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = [
                "--adb", ADB, "--serial", SERIAL,
                "--output", out, "--transport", "base64", path,
            ]
            responses = self._stat_and_sha_responses(path, b"original") + [
                self._base64_response(path, b"invalid#data\r\n"),
            ]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                with self.assertRaises(SystemExit) as cm:
                    ca.main(argv)
                self.assertEqual(cm.exception.code, 1)
            local = os.path.join(out, "originals", "data", "optics.bin")
            self.assertFalse(os.path.exists(local))
            self.assertFalse(os.path.exists(local + ".partial"))
            with open(os.path.join(out, "failure_manifest.json"), "r", encoding="utf-8") as fh:
                fail = json.load(fh)
            self.assertTrue(any("base64 decode" in f.get("reason", "") for f in fail["failures"]))

    def test_base64_decoded_hash_mismatch_fails(self):
        content = b"original"
        path = "/data/optics.bin"
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = [
                "--adb", ADB, "--serial", SERIAL,
                "--output", out, "--transport", "base64", path,
            ]
            responses = self._stat_and_sha_responses(path, content) + [
                self._base64_response(path, _base64_with_crlf(b"mangled!")),
            ]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                with self.assertRaises(SystemExit) as cm:
                    ca.main(argv)
                self.assertEqual(cm.exception.code, 1)
            local = os.path.join(out, "originals", "data", "optics.bin")
            self.assertFalse(os.path.exists(local))
            with open(os.path.join(out, "failure_manifest.json"), "r", encoding="utf-8") as fh:
                fail = json.load(fh)
            self.assertTrue(any("sha256" in f.get("reason", "") for f in fail["failures"]))

    def test_base64_transport_propagates_to_both_probes_and_capture(self):
        content = b"\x00\x01\x02\xff\r\noptics"
        path = "/data/optics.bin"
        responses = self._stat_and_sha_responses(path, content) + [
            self._base64_response(path, _base64_with_crlf(content)),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = [
                "--adb", ADB, "--serial", SERIAL,
                "--output", out, "--transport", "base64", path,
            ]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                rc = ca.main(argv)
            self.assertEqual(rc, 0)
            with open(os.path.join(out, "capture_manifest.json"), "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            self.assertEqual(manifest["transport"], "base64")
            self.assertEqual(manifest["probe_before"]["transport"], "base64")
            self.assertEqual(manifest["probe_after"]["transport"], "base64")
            self.assertEqual(manifest["verified"][0]["transport"], "base64")

    def test_base64_display_only_extracts_block(self):
        content = (
            b"camera_profile { name: \"front\" }\n"
            b"display_profile_v2 { panel: \"single\" }\n"
            b"imu_profile { name: \"back\" }\n"
        )
        path = "/mnt/vendor/efs/device_profile.textproto"
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            argv = [
                "--adb", ADB, "--serial", SERIAL,
                "--output", out, "--transport", "base64",
                "--display-only", path,
            ]
            responses = self._stat_and_sha_responses(path, content) + [
                self._base64_response(path, _base64_with_crlf(content)),
            ]
            with patch("capture_artifacts.run_adb_command", side_effect=make_adb_runner(responses)):
                rc = ca.main(argv)
            self.assertEqual(rc, 0)
            local = os.path.join(
                out,
                "originals",
                "mnt",
                "vendor",
                "efs",
                "device_profile.textproto.display_profile_v2.textproto",
            )
            with open(local, "rb") as fh:
                block = fh.read()
            self.assertTrue(block.startswith(b"display_profile_v2"))
            self.assertNotIn(b"camera_profile", block)
            with open(os.path.join(out, "capture_manifest.json"), "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            self.assertEqual(manifest["transport"], "base64")
            self.assertTrue(manifest["verified"][0]["selected_capture_not_full_file"])


if __name__ == "__main__":
    unittest.main()
