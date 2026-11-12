#!/usr/bin/env python3
"""Focused tests for the public Pages allowlist, privacy and download hashes."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Dict

import analyse_optics as ao
import build_pages
import publication

EXPECTED_FILES = {
    "index.html",
    "downloads/analysis.json",
    "downloads/factory-display-profile-v2.textproto",
    "downloads/provenance.json",
    "downloads/SHA256SUMS",
    "downloads/vendor-display-profile-v2.textproto",
}


def _file_hashes(root: Path) -> Dict[str, str]:
    return {
        path.relative_to(root).as_posix(): publication.sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class BuildPagesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)
        cls.site = cls.tmp / "site"
        cls.written = build_pages.build_site(cls.site)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_site_is_a_closed_allowlist(self) -> None:
        self.assertEqual(set(_file_hashes(self.site)), EXPECTED_FILES)
        self.assertEqual(
            {path.relative_to(self.site).as_posix() for path in self.written},
            EXPECTED_FILES,
        )

    def test_analysis_download_is_exact_sanitized_canonical_json(self) -> None:
        download = self.site / "downloads" / "analysis.json"
        self.assertEqual(download.read_bytes(), publication.ANALYSIS_PATH.read_bytes())

        data = json.loads(download.read_text(encoding="utf-8"))
        self.assertNotIn("__generated_at", data)
        self.assertEqual(
            publication.sanitized_analysis_violations(data), []
        )
        for role, expected in publication.expected_hashes().items():
            profile = data["profiles"][role]
            self.assertEqual(profile["source_sha256"], expected)
            self.assertEqual(profile["block_sha256"], expected)
            self.assertTrue(profile["source_path"].startswith("data/captures/"))

    def test_textproto_downloads_are_byte_identical_originals(self) -> None:
        pairs = {
            "factory-display-profile-v2.textproto": (
                publication.FACTORY_SOURCE_PATH,
                publication.FACTORY_SUBTREE_SHA256,
            ),
            "vendor-display-profile-v2.textproto": (
                publication.VENDOR_SOURCE_PATH,
                publication.VENDOR_SUBTREE_SHA256,
            ),
        }
        for name, (source, expected) in pairs.items():
            payload = (self.site / "downloads" / name).read_bytes()
            self.assertEqual(payload, source.read_bytes())
            self.assertEqual(publication.sha256_bytes(payload), expected)

    def test_sha256sums_covers_four_downloads_and_not_itself(self) -> None:
        lines = (self.site / "downloads" / "SHA256SUMS").read_text(
            encoding="utf-8"
        ).splitlines()
        self.assertEqual(len(lines), 4)
        entries = {}
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            entries[name] = digest
        self.assertEqual(
            set(entries),
            {
                "analysis.json",
                "factory-display-profile-v2.textproto",
                "provenance.json",
                "vendor-display-profile-v2.textproto",
            },
        )
        self.assertNotIn("SHA256SUMS", entries)
        for name, digest in entries.items():
            self.assertEqual(
                publication.sha256_file(self.site / "downloads" / name), digest
            )

    def test_provenance_keeps_evidence_and_drops_private_paths(self) -> None:
        provenance = json.loads(
            (self.site / "downloads" / "provenance.json").read_text(encoding="utf-8")
        )
        analysis = json.loads(publication.ANALYSIS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(provenance["limits"], analysis["limitations"])
        self.assertEqual(
            provenance["sources"],
            {
                "factory": "/mnt/vendor/efs/device_profile.textproto",
                "vendor": "/vendor/etc/calibration_service/device_profile.textproto",
            },
        )
        factory = provenance["profiles"]["factory"]
        self.assertEqual(
            factory["retained_subtree"]["sha256"],
            publication.FACTORY_SUBTREE_SHA256,
        )
        self.assertEqual(factory["retained_subtree"]["size_bytes"], 3932405)
        self.assertEqual(factory["retained_subtree"]["byte_start"], 293453)
        self.assertEqual(factory["retained_subtree"]["byte_end"], 4225858)
        vendor = provenance["profiles"]["vendor"]
        self.assertEqual(
            vendor["retained_subtree"]["sha256"],
            publication.VENDOR_SUBTREE_SHA256,
        )
        self.assertEqual(vendor["retained_subtree"]["size_bytes"], 3513265)
        self.assertEqual(vendor["retained_subtree"]["byte_start"], 297092)
        self.assertEqual(vendor["retained_subtree"]["byte_end"], 3810357)
        self.assertTrue(provenance["build"]["known_subtree_hashes_enforced"])

        text = json.dumps(provenance)
        self.assertEqual(publication.find_private_text(text), [])
        self.assertEqual(publication.find_serial_violations(provenance), [])
        self.assertNotIn("local_path", text)
        self.assertNotIn("D:\\\\", text)

    def test_index_links_resolve_and_embedded_data_is_sanitized(self) -> None:
        index = (self.site / "index.html").read_text(encoding="utf-8")
        # The template keeps one literal marker in a JS guard that detects an
        # unbuilt template; the data slot itself must be filled.
        self.assertEqual(index.count("{{ANALYSIS_DATA}}"), 1)
        self.assertIn("raw === '{{ANALYSIS_DATA}}'", index)
        links = set(re.findall(r'href="(downloads/[^"]+)"', index))
        self.assertEqual(
            links,
            {
                "downloads/factory-display-profile-v2.textproto",
                "downloads/vendor-display-profile-v2.textproto",
                "downloads/analysis.json",
                "downloads/provenance.json",
                "downloads/SHA256SUMS",
            },
        )
        for link in links:
            self.assertTrue((self.site / link).is_file(), link)

        match = re.search(
            r'<script type="application/json" id="analysis-data">\s*(.*?)\s*</script>',
            index,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        embedded = json.loads(match.group(1))
        self.assertNotIn("__generated_at", embedded)
        self.assertEqual(publication.sanitized_analysis_violations(embedded), [])
        self.assertEqual(publication.find_private_text(index), [])

    def test_build_is_deterministic(self) -> None:
        second = self.tmp / "site-second"
        build_pages.build_site(second)
        self.assertEqual(_file_hashes(self.site), _file_hashes(second))

    def test_assets_only_writes_downloads_without_index(self) -> None:
        package = self.tmp / "local-package"
        written = build_pages.build_assets_only(package)
        self.assertEqual(
            {path.relative_to(package).as_posix() for path in written},
            {name for name in EXPECTED_FILES if name.startswith("downloads/")},
        )
        self.assertFalse((package / "index.html").exists())
        self.assertEqual(
            (package / "downloads" / "analysis.json").read_bytes(),
            publication.ANALYSIS_PATH.read_bytes(),
        )

    def test_known_hash_enforcement_rejects_wrong_bytes(self) -> None:
        analysis = publication.load_json(publication.ANALYSIS_PATH)
        manifest = publication.load_json(publication.CAPTURE_MANIFEST_PATH)
        vendor = publication.VENDOR_SOURCE_PATH.read_bytes()
        with self.assertRaises(publication.PublicationError):
            publication.verify_known_hashes(analysis, manifest, b"tampered", vendor)

    def test_capture_manifest_is_sanitized_and_preserves_evidence(self) -> None:
        manifest = publication.load_json(publication.CAPTURE_MANIFEST_PATH)
        self.assertEqual(publication.capture_manifest_violations(manifest), [])
        self.assertEqual(manifest["adb"], "adb")
        self.assertEqual(manifest["serial"], publication.SERIAL_REDACTION)
        self.assertEqual(manifest["output"], "data/captures/optical-capture-verified")
        factory = publication.manifest_entry(manifest, "factory")
        self.assertEqual(factory["original_path"], "/mnt/vendor/efs/device_profile.textproto")
        self.assertEqual(factory["local_path"].startswith("data/"), True)
        self.assertEqual(
            factory["selected_block_sha256"], publication.FACTORY_SUBTREE_SHA256
        )
        self.assertEqual(factory["original_sha_before"], factory["original_sha_after"])
        self.assertEqual(
            manifest["identity_before"], manifest["identity_after"]
        )

    def test_analyse_optics_reproduces_canonical_sanitized_metadata(self) -> None:
        analysis = ao.build_analysis(
            publication.FACTORY_SOURCE_PATH,
            publication.VENDOR_SOURCE_PATH,
            publication.CAPTURE_MANIFEST_PATH,
            expect_device=True,
        )
        output = ao._prepare_for_output(analysis)
        text = json.dumps(output, indent=2, ensure_ascii=False) + "\n"
        self.assertEqual(text, publication.ANALYSIS_PATH.read_text(encoding="utf-8"))
        for role in ("factory", "vendor"):
            self.assertEqual(
                output["profiles"][role]["source_path"],
                f"data/captures/optical-capture-verified/originals/"
                f"{'mnt/vendor/efs' if role == 'factory' else 'vendor/etc/calibration_service'}"
                f"/device_profile.textproto.display_profile_v2.textproto",
            )


    def test_private_text_patterns_are_generic(self) -> None:
        # The public author name is allowed; only local paths are flagged.
        self.assertEqual(
            publication.find_private_text("GXR-Distortion-Profile by AngelDark92"), []
        )
        self.assertIn(
            "local_windows_path",
            publication.find_private_text(r"capture log C:\somewhere\capture.txt"),
        )
        self.assertIn(
            "local_unix_home",
            publication.find_private_text("copy to /home/someone/capture"),
        )

    def test_serial_fields_are_checked_structurally(self) -> None:
        sentinel = "SYNTHETIC-SERIAL-0001"
        self.assertEqual(
            publication.find_serial_violations({"serial": publication.SERIAL_REDACTION}),
            [],
        )
        self.assertTrue(publication.find_serial_violations({"serial": sentinel}))
        self.assertTrue(
            publication.find_serial_violations({"nested": [{"Serial": sentinel}]})
        )

    def test_stale_file_in_output_directory_is_rejected(self) -> None:
        stale = self.tmp / "stale-site"
        stale.mkdir()
        keep = stale / "keep-me.txt"
        keep.write_text("user file\n", encoding="utf-8")

        with self.assertRaises(build_pages.BuildError) as caught:
            build_pages.build_site(stale)

        self.assertIn("keep-me.txt", str(caught.exception))
        self.assertTrue(keep.is_file())
        self.assertEqual(keep.read_text(encoding="utf-8"), "user file\n")
        self.assertFalse((stale / "index.html").exists())
        self.assertFalse((stale / "downloads").exists())

    def test_rebuild_overwrites_expected_site_files_only(self) -> None:
        target = self.tmp / "rebuild-site"
        build_pages.build_site(target)
        expected_hashes = _file_hashes(target)

        (target / "index.html").write_text("stale", encoding="utf-8")
        (target / "downloads" / "analysis.json").write_bytes(b"{}")
        build_pages.build_site(target)

        self.assertEqual(_file_hashes(target), expected_hashes)

    def test_repository_root_output_is_refused(self) -> None:
        with self.assertRaises(build_pages.BuildError) as caught:
            build_pages.build_site(publication.REPO_ROOT)
        self.assertIn("repository root", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
