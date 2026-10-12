"""Verify released PCKs and generate the permanent 1.0.4 migration/patch chain."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct

MINIMUM = "1.0.0"
MIGRATION = "1.0.4"
MIGRATION_SHA256 = "5047495f774da54796ec3367ddd96ba8b37282e2d8b5550238e9aba986b8a9a9"
MIGRATION_SIZE = 18067316
PACKAGE_KEYS = ("version", "url", "sha256", "size_bytes")


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value):
        raise ValueError("Use a numeric major.minor.patch version, for example 1.0.5.")
    return tuple(map(int, value.split(".")))


def next_version(previous, target):
    major, minor, patch = version(previous)
    return version(target) in ((major, minor, patch + 1), (major, minor + 1, 0), (major + 1, 0, 0))


def asset_name(target):
    suffix = "compatibility" if target == MIGRATION else "patch"
    return f"PokemonDuelsRemake_{target}_{suffix}.pck"


def asset_url(repository, target):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid owner/repository.")
    return f"https://github.com/{repository}/releases/download/v{target}/{asset_name(target)}"


def select_asset(release, repository):
    tag = release.get("tag_name", "")
    target = tag.removeprefix("v")
    version(target)
    if tag != "v" + target or version(target) < version(MIGRATION):
        raise ValueError("This workflow publishes v1.0.4 and later only; older manifests are never rewritten.")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise ValueError("Publish a stable release before updating the public manifest.")
    candidates = [a for a in release.get("assets", []) if isinstance(a, dict)
                  and str(a.get("name", "")).endswith(("_patch.pck", "_compatibility.pck"))]
    if len(candidates) != 1 or candidates[0].get("name") != asset_name(target):
        raise ValueError(f"Attach exactly one patch asset, named {asset_name(target)}.")
    asset = candidates[0]
    if asset.get("state") != "uploaded" or type(asset.get("size")) is not int or not 0 < asset["size"] < 2 * 1024**3:
        raise ValueError("The patch asset is not fully uploaded or exceeds the supported asset size.")
    if asset.get("browser_download_url") != asset_url(repository, target):
        raise ValueError("The patch URL does not match this repository, tag and filename.")
    return target, asset


def verify_pck(path):
    """Reject invalid/encrypted/binary-delta PCKs and verify every complete payload."""
    path = Path(path)
    length = path.stat().st_size
    with path.open("rb") as stream:
        def read(size):
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("Truncated PCK.")
            return data
        def u32():
            return struct.unpack("<I", read(4))[0]
        def u64():
            return struct.unpack("<Q", read(8))[0]
        if u32() != 0x43504447:
            raise ValueError("The asset is not a standalone Godot PCK.")
        fmt = u32()
        major, minor, patch = u32(), u32(), u32()
        flags, file_base = u32(), u64()
        if fmt not in (2, 3, 4) or major != 4 or flags & ~2:
            raise ValueError("Unsupported/encrypted PCK. Export complete files with Delta Encoding disabled.")
        directory = u64() if fmt >= 3 else 96
        if directory < 96 or directory + 4 > length:
            raise ValueError("Invalid PCK directory.")
        stream.seek(directory)
        count = u32()
        if not 0 < count <= 100000:
            raise ValueError("Invalid PCK resource count.")
        entries = {}
        for _ in range(count):
            name_size = u32()
            if not 0 < name_size <= 16384:
                raise ValueError("Invalid PCK resource name.")
            name = read(name_size).rstrip(b"\0").decode("utf-8").removeprefix("res://")
            offset, size = u64(), u64()
            md5, entry_flags = read(16), u32()
            if not name or name in entries:
                raise ValueError("Empty/duplicate PCK resource name.")
            if entry_flags & ~2:
                raise ValueError("Encrypted/binary-delta PCK entry. Disable Delta Encoding.")
            absolute = offset + file_base
            if not entry_flags & 2 and absolute + size > length:
                raise ValueError("Truncated PCK resource: " + name)
            entries[name] = (absolute, size, md5, entry_flags)
        directory_end = stream.tell()
        for name, (offset, size, expected, entry_flags) in entries.items():
            if entry_flags & 2:
                continue
            if offset < 96 or (offset < directory_end and offset + size > directory):
                raise ValueError("PCK resource overlaps its directory: " + name)
            stream.seek(offset)
            digest = hashlib.md5()
            remaining = size
            while remaining:
                chunk = read(min(1024 * 1024, remaining))
                digest.update(chunk)
                remaining -= len(chunk)
            if digest.digest() != expected:
                raise ValueError("PCK resource checksum failed: " + name)
    return len(entries)


def verify_package(release, repository, path):
    target, asset = select_asset(release, repository)
    path = Path(path)
    if path.stat().st_size != asset["size"]:
        raise ValueError("Downloaded patch size differs from the GitHub asset.")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    sha = digest.hexdigest()
    github_digest = asset.get("digest")
    if github_digest is not None and github_digest != "sha256:" + sha:
        raise ValueError("Downloaded patch SHA-256 differs from GitHub's asset digest.")
    if target == MIGRATION and (sha != MIGRATION_SHA256 or asset["size"] != MIGRATION_SIZE):
        raise ValueError("1.0.4 must use the exact compatibility package that passed the release audit.")
    verify_pck(path)
    return {"version": target, "url": asset["browser_download_url"], "sha256": sha, "size_bytes": asset["size"]}


def validate_package(package, repository):
    if not isinstance(package, dict):
        raise ValueError("Invalid manifest package.")
    target = package.get("version")
    version(target)
    if (package.get("url") != asset_url(repository, target)
            or not isinstance(package.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", package["sha256"])
            or type(package.get("size_bytes")) is not int
            or not 0 < package["size_bytes"] < 2 * 1024**3):
        raise ValueError("Invalid package URL, checksum or size.")
    if target == MIGRATION and (package["sha256"] != MIGRATION_SHA256 or package["size_bytes"] != MIGRATION_SIZE):
        raise ValueError("The permanent 1.0.4 package must retain its audited checksum/size.")


def validate_chain(manifest, repository):
    if (manifest.get("schema") != 1 or manifest.get("base_version") != MINIMUM
            or manifest.get("current_base_version") != MIGRATION
            or type(manifest.get("mandatory")) is not bool):
        raise ValueError("The existing compatibility manifest has invalid base settings.")
    if "patch_chain" in manifest:
        raise ValueError("Use patch_chain_v2 only; the old public chain field is unsafe for 1.0.3 loaders.")
    chain = manifest.get("patch_chain_v2", {})
    rows = chain.get("packages") if isinstance(chain, dict) else None
    if not isinstance(chain, dict) or chain.get("schema") != 1 or not isinstance(rows, list) or not rows:
        raise ValueError("The manifest has no valid patch_chain_v2.")
    previous = MINIMUM
    for index, row in enumerate(rows):
        validate_package(row, repository)
        if row.get("requires_version") != previous or row.get("cumulative") is not (index == 0):
            raise ValueError("The patch chain has a missing/invalid dependency.")
        if (index == 0 and row["version"] != MIGRATION) or (index > 0 and not next_version(previous, row["version"])):
            raise ValueError("The patch chain is unordered or skips a release.")
        previous = row["version"]
    if manifest.get("latest_version") != previous:
        raise ValueError("latest_version does not match the last chained package.")
    bridge = {key: rows[0][key] for key in PACKAGE_KEYS}
    for field in ("patch", "legacy_bridge", "current_patch"):
        if manifest.get(field) != bridge:
            raise ValueError(f"{field} must remain pinned to the permanent 1.0.4 package.")
    return rows


def update_manifest(manifest, package, repository):
    """Pure transformation: no writes on errors, no downgrades or dependency replacement."""
    validate_package(package, repository)
    target = package["version"]
    if version(target) < version(MIGRATION):
        raise ValueError("Older releases cannot replace the compatibility manifest.")
    if "patch_chain_v2" not in manifest:
        if target != MIGRATION:
            raise ValueError("Publish the 1.0.4 compatibility release before future patches.")
        if version(manifest.get("latest_version", MINIMUM)) > version(MIGRATION):
            raise ValueError("Refusing to reset a newer manifest to 1.0.4.")
        if type(manifest.get("mandatory", False)) is not bool:
            raise ValueError("mandatory must be true or false.")
        bridge = {key: package[key] for key in PACKAGE_KEYS}
        entry = dict(bridge, requires_version=MINIMUM, cumulative=True)
        return {"schema": 1, "latest_version": MIGRATION, "base_version": MINIMUM,
                "mandatory": manifest.get("mandatory", False), "patch": bridge.copy(),
                "legacy_bridge": bridge.copy(), "current_base_version": MIGRATION,
                "current_patch": bridge.copy(), "patch_chain_v2": {"schema": 1, "packages": [entry]}}
    rows = validate_chain(manifest, repository)
    for row in rows:
        if row["version"] == target:
            if {key: row[key] for key in PACKAGE_KEYS} != package:
                raise ValueError("A published dependency changed. Never replace an existing patch asset.")
            return copy.deepcopy(manifest)
    if version(target) < version(manifest["latest_version"]):
        raise ValueError("The older requested release is absent from the chain; refusing to downgrade.")
    if not next_version(manifest["latest_version"], target):
        raise ValueError("Missing previous release. Publish patches in order and wait for each manifest run.")
    result = copy.deepcopy(manifest)
    result["patch_chain_v2"]["packages"].append(dict(package, requires_version=manifest["latest_version"], cumulative=False))
    result["latest_version"] = target
    validate_chain(result, repository)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("select", "generate"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release", required=True, type=Path)
    parser.add_argument("--pck", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        release = json.loads(args.release.read_text(encoding="utf-8-sig"))
        if args.command == "select":
            print(select_asset(release, args.repository)[1]["name"])
            return
        if any(value is None for value in (args.pck, args.manifest, args.output)):
            raise ValueError("generate requires --pck, --manifest and --output.")
        if args.output.resolve() == args.manifest.resolve() or args.output.resolve() == args.pck.resolve():
            raise ValueError("Write a separate candidate manifest before committing.")
        package = verify_package(release, args.repository, args.pck)
        manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
        updated = update_manifest(manifest, package, args.repository)
        args.output.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
        print(f"Verified {package['version']}: {package['size_bytes']} bytes, SHA-256 {package['sha256']}")
        print(f"Latest: {updated['latest_version']}; permanent bridge: {updated['legacy_bridge']['version']}")
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        parser.exit(1, f"Manifest not changed: {error}\n")


if __name__ == "__main__":
    main()
