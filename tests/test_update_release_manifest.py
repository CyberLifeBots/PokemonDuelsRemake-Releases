import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("publisher", Path(__file__).resolve().parents[1] / "tools/update_release_manifest.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)
REPO = "CyberLifeBots/PokemonDuelsRemake-Releases"


def package(target="1.0.4"):
    return {"version": target, "url": publisher.asset_url(REPO, target),
            "sha256": publisher.MIGRATION_SHA256 if target == "1.0.4" else "a" * 64,
            "size_bytes": publisher.MIGRATION_SIZE if target == "1.0.4" else 1024}


def release(target="1.0.4"):
    p = package(target)
    return {"tag_name": "v" + target, "draft": False, "prerelease": False,
            "assets": [{"name": publisher.asset_name(target), "state": "uploaded",
                        "size": p["size_bytes"], "browser_download_url": p["url"]}]}


def base():
    return publisher.update_manifest({"schema": 1, "latest_version": "1.0.3", "mandatory": False}, package(), REPO)


def pck(path, payload=b"test resource", entry_flags=0, global_flags=0):
    name = b"res://scripts/example.gdc\0"
    name += b"\0" * ((-len(name)) % 4)
    directory = struct.pack("<II", 1, len(name)) + name
    offset = 96 + len(directory) + 8 + 8 + 16 + 4
    directory += struct.pack("<QQ", offset, len(payload)) + hashlib.md5(payload).digest() + struct.pack("<I", entry_flags)
    header = struct.pack("<6IQ", 0x43504447, 2, 4, 7, 1, global_flags, 0).ljust(96, b"\0")
    path.write_bytes(header + directory + payload)
    return path


class ManifestTests(unittest.TestCase):
    def test_migration_removes_obsolete_bridge_and_full_placeholder(self):
        old = {"schema": 1, "latest_version": "1.0.3", "base_version": "0.1.0", "mandatory": False,
               "full": {"version": "0.1.0"}, "current_base_version": "0.4.0"}
        result = publisher.update_manifest(old, package(), REPO)
        self.assertEqual(result, base())
        self.assertNotIn("full", result)
        self.assertEqual(old["current_base_version"], "0.4.0")
        self.assertEqual(result["base_version"], "1.0.0")
        self.assertEqual(result["patch_chain_v2"]["packages"][0]["requires_version"], "1.0.0")

    def test_append_five_six_seven_preserves_bridge(self):
        current = base()
        for target in ("1.0.5", "1.0.6", "1.0.7"):
            previous = current["latest_version"]
            result = publisher.update_manifest(current, package(target), REPO)
            self.assertEqual(result["patch_chain_v2"]["packages"][-1]["requires_version"], previous)
            self.assertFalse(result["patch_chain_v2"]["packages"][-1]["cumulative"])
            for field in ("patch", "legacy_bridge", "current_patch"):
                self.assertEqual(result[field], package())
            self.assertEqual(current["latest_version"], previous)
            current = result
        self.assertEqual(len(current["patch_chain_v2"]["packages"]), 4)

    def test_repeated_and_old_runs_preserve_later_packages(self):
        current = publisher.update_manifest(base(), package("1.0.5"), REPO)
        current = publisher.update_manifest(current, package("1.0.6"), REPO)
        for target in ("1.0.4", "1.0.5", "1.0.6"):
            with self.subTest(target=target):
                self.assertEqual(publisher.update_manifest(current, package(target), REPO), current)

    def test_missing_release_rejected_without_mutating_input(self):
        current = base()
        snapshot = copy.deepcopy(current)
        with self.assertRaisesRegex(ValueError, "Missing previous"):
            publisher.update_manifest(current, package("1.0.6"), REPO)
        self.assertEqual(current, snapshot)

    def test_future_without_migration_rejected(self):
        with self.assertRaisesRegex(ValueError, "Publish the 1.0.4"):
            publisher.update_manifest({"latest_version": "1.0.3"}, package("1.0.5"), REPO)

    def test_changed_published_dependency_rejected(self):
        current = publisher.update_manifest(base(), package("1.0.5"), REPO)
        changed = package("1.0.5")
        for field, value in (("sha256", "b" * 64), ("size_bytes", 2048)):
            with self.subTest(field=field):
                candidate = dict(changed, **{field: value})
                with self.assertRaisesRegex(ValueError, "published dependency changed"):
                    publisher.update_manifest(current, candidate, REPO)

    def test_bad_existing_chains_rejected(self):
        mutations = [
            lambda x: x.update(base_version="0.9.8"),
            lambda x: x.update(current_base_version="0.4.0"),
            lambda x: x.update(latest_version="1.0.5"),
            lambda x: x.update(patch_chain={"schema": 1}),
            lambda x: x.update(mandatory="false"),
            lambda x: x["patch_chain_v2"].update(schema=2),
            lambda x: x["patch_chain_v2"].update(packages=[]),
            lambda x: x["patch_chain_v2"]["packages"][0].update(requires_version="0.9.8"),
            lambda x: x["patch_chain_v2"]["packages"][0].update(cumulative=False),
            lambda x: x["patch_chain_v2"]["packages"][0].update(sha256="b" * 64),
        ]
        for field in ("patch", "legacy_bridge", "current_patch"):
            mutations.append(lambda x, field=field: x[field].update(version="1.0.5"))
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                current = base()
                mutate(current)
                with self.assertRaises(ValueError):
                    publisher.update_manifest(current, package("1.0.5"), REPO)

    def test_migration_cannot_reset_newer_manifest(self):
        with self.assertRaisesRegex(ValueError, "reset a newer"):
            publisher.update_manifest({"latest_version": "1.0.6"}, package(), REPO)

    def test_malformed_package_rejected(self):
        for field, value in (("url", "http://example.com/bad.pck"), ("sha256", "bad"),
                             ("size_bytes", True), ("size_bytes", 0), ("size_bytes", 2 * 1024**3)):
            with self.subTest(field=field, value=value):
                candidate = dict(package("1.0.5"), **{field: value})
                with self.assertRaises(ValueError):
                    publisher.update_manifest(base(), candidate, REPO)

    def test_valid_minor_and_major_transitions(self):
        self.assertTrue(publisher.next_version("1.0.6", "1.1.0"))
        self.assertTrue(publisher.next_version("1.0.6", "2.0.0"))
        self.assertFalse(publisher.next_version("1.0.6", "1.2.0"))
        self.assertFalse(publisher.next_version("1.0.6", "1.1.1"))

    def test_numeric_versions_not_lexicographic(self):
        self.assertTrue(publisher.next_version("1.0.9", "1.0.10"))
        for bad in ("1.0.05", "1.0", "1.0.5-beta", "v1.0.5", None):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                publisher.version(bad)


class AssetTests(unittest.TestCase):
    def test_compatibility_and_future_names(self):
        for target in ("1.0.4", "1.0.5", "1.0.6"):
            self.assertEqual(publisher.select_asset(release(target), REPO)[1]["name"], publisher.asset_name(target))

    def test_bad_releases_rejected(self):
        mutations = [lambda x: x.update(draft=True), lambda x: x.update(prerelease=True),
                     lambda x: x.update(tag_name="v1.0.3"), lambda x: x.update(tag_name="v1.0.5; echo bad"),
                     lambda x: x.update(assets=[]), lambda x: x["assets"].append(dict(x["assets"][0])),
                     lambda x: x["assets"][0].update(name="PokemonDuelsRemake_1.0.4_patch.pck"),
                     lambda x: x["assets"][0].update(state="new"), lambda x: x["assets"][0].update(size=0),
                     lambda x: x["assets"][0].update(browser_download_url="https://example.com/wrong.pck")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                current = release()
                mutate(current)
                with self.assertRaises(ValueError):
                    publisher.select_asset(current, REPO)

    def test_other_release_assets_ignored(self):
        current = release()
        current["assets"].append({"name": "PokemonDuelsRemake.apk"})
        self.assertEqual(publisher.select_asset(current, REPO)[0], "1.0.4")


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = pck(Path(self.temp.name) / "patch.pck")
        self.release = release("1.0.5")
        self.release["assets"][0]["size"] = self.path.stat().st_size
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_valid_pck_and_digest(self):
        self.release["assets"][0]["digest"] = "sha256:" + self.sha
        result = publisher.verify_package(self.release, REPO, self.path)
        self.assertEqual(result["sha256"], self.sha)
        self.assertEqual(publisher.verify_pck(self.path), 1)

    def test_size_and_digest_mismatch_rejected(self):
        for field, value in (("size", 1), ("digest", "sha256:" + "b" * 64)):
            with self.subTest(field=field):
                current = copy.deepcopy(self.release)
                current["assets"][0][field] = value
                with self.assertRaises(ValueError):
                    publisher.verify_package(current, REPO, self.path)

    def test_migration_rejects_unverified_package(self):
        current = release()
        current["assets"][0]["size"] = self.path.stat().st_size
        with self.assertRaisesRegex(ValueError, "exact compatibility package"):
            publisher.verify_package(current, REPO, self.path)

    def test_godot_four_directory_at_end(self):
        payload = b"resource before its directory"
        name = b"res://scripts/example.gdc\0"
        name += b"\0" * ((-len(name)) % 4)
        directory_offset = 96 + len(payload)
        directory = struct.pack("<II", 1, len(name)) + name
        directory += struct.pack("<QQ", 96, len(payload)) + hashlib.md5(payload).digest() + struct.pack("<I", 0)
        header = struct.pack("<6IQQ", 0x43504447, 4, 4, 7, 1, 0, 0, directory_offset).ljust(96, b"\0")
        self.path.write_bytes(header + payload + directory)
        self.assertEqual(publisher.verify_pck(self.path), 1)

    def test_payload_overlapping_directory_rejected(self):
        contents = bytearray(self.path.read_bytes())
        name_size = struct.unpack("<I", contents[100:104])[0]
        contents[104 + name_size:112 + name_size] = struct.pack("<Q", 96)
        self.path.write_bytes(contents)
        with self.assertRaisesRegex(ValueError, "overlaps its directory"):
            publisher.verify_pck(self.path)

    def test_corrupt_payload_rejected(self):
        payload = bytearray(self.path.read_bytes())
        payload[-1] ^= 1
        self.path.write_bytes(payload)
        with self.assertRaisesRegex(ValueError, "checksum failed"):
            publisher.verify_pck(self.path)

    def test_binary_delta_and_encryption_rejected(self):
        for flags in (1, 4, 5, 8):
            with self.subTest(entry_flags=flags):
                pck(self.path, entry_flags=flags)
                with self.assertRaises(ValueError):
                    publisher.verify_pck(self.path)
            with self.subTest(global_flags=flags):
                pck(self.path, global_flags=flags)
                with self.assertRaises(ValueError):
                    publisher.verify_pck(self.path)

    def test_truncated_or_non_pck_rejected(self):
        for contents in (b"", b"not a pack" * 20, self.path.read_bytes()[:-1]):
            with self.subTest(length=len(contents)):
                self.path.write_bytes(contents)
                with self.assertRaises(ValueError):
                    publisher.verify_pck(self.path)

    def test_failed_cli_leaves_manifest_and_candidate_unchanged(self):
        root = Path(self.temp.name)
        manifest, event, output = root / "manifest.json", root / "release.json", root / "candidate.json"
        manifest.write_text(json.dumps(base()))
        current = release("1.0.6")
        current["assets"][0]["size"] = self.path.stat().st_size
        event.write_text(json.dumps(current))
        output.write_text("existing candidate")
        before = manifest.read_bytes()
        process = subprocess.run([sys.executable, SPEC.origin, "generate", "--repository", REPO,
                                  "--release", str(event), "--pck", str(self.path),
                                  "--manifest", str(manifest), "--output", str(output)], capture_output=True, text=True)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("Missing previous release", process.stderr)
        self.assertEqual(manifest.read_bytes(), before)
        self.assertEqual(output.read_text(), "existing candidate")


if __name__ == "__main__":
    unittest.main()
