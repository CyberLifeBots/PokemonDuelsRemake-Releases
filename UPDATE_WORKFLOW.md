# Automatic patch manifest updates

The workflow runs after a stable release is published. Keep **Update Patch Manifest** enabled under Actions. Upload the patch before publishing the release, then wait for the workflow to succeed before publishing the next version. APKs, EXEs and other release assets may also be attached.

## One-time v1.0.4 compatibility release

1. Create the **v1.0.4** release.
2. Attach **PokemonDuelsRemake_1.0.4_compatibility.pck** unchanged (18,067,316 bytes).
3. Publish the release and check its **Update Patch Manifest** run.

The workflow verifies the exact audited SHA-256 `5047495f774da54796ec3367ddd96ba8b37282e2d8b5550238e9aba986b8a9a9`, asset size and PCK payloads, then generates the prepared compatibility manifest automatically. No manual manifest replacement is needed after a successful run. The public manifest is not advanced until the published asset downloads and verifies successfully.

The oldest supported native build is full **1.0.0**. `patch`, `legacy_bridge`, `current_patch` and `current_base_version` stay pinned to **1.0.4** permanently. The public chain key is **patch_chain_v2**, which safely migrates older loaders before later dependent patches are installed.

## Future releases

- **v1.0.5:** attach `PokemonDuelsRemake_1.0.5_patch.pck`; it is added with `requires_version: 1.0.4`.
- **v1.0.6:** attach `PokemonDuelsRemake_1.0.6_patch.pck`; it is added with `requires_version: 1.0.5`.
- Continue in order. Every earlier package and its URL must remain available.

Export complete-file patches with **Delta Encoding disabled**. Base Packs must contain the full native 1.0.0 platform baseline followed by every released patch from 1.0.4 onward, oldest first. Preserve Windows/Android texture routes in shared packages. Update the project version before exporting. The workflow verifies the published package's structure and checksums; it cannot prove that an incorrectly exported patch contains all platform/gameplay dependencies.

Exactly one `_patch.pck` or `_compatibility.pck` asset may be attached. The filename must match the release version and pattern above. Never replace the bytes of a published dependency. The workflow rejects skipped patch versions, invalid chains, changed existing dependencies, drafts/prereleases, encrypted/delta packs and incomplete downloads. Numeric minor/major transitions such as 1.0.6 -> 1.1.0 or 2.0.0 are supported.

## Preview or retry

Use Actions -> Update Patch Manifest -> Run workflow, enter the published tag, and optionally select **dry_run**. A dry run verifies and previews without committing. A normal retry is idempotent: it does not duplicate packages, reset the latest version or discard later patches. To recover from a skipped release, run the missing tags in order.

Publishing is serialized. If main changes during publishing, the workflow fetches it and regenerates the manifest, rather than rebasing an outdated generated file. It never force pushes. An invalid/conflicting update fails while the last valid public manifest stays in place.
