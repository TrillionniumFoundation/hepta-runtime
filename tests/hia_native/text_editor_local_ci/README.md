# Final private Local four-command gateway: complete source CI recipe

This package runs the existing final 75-owner private HIA graph and the exact original Rust gateway across seven preserved normal fixture profiles. It also provides a read-only verifier for the complete retained observations. The package itself has not executed Rust, HIA, or native runtime code during preparation.

## Source custody

The inputs are the final prepared `source` tree (142 files), the original reference closure (35 files), two observation readers, and five portable top-level files. All 184 input files are copied without byte changes and pinned in `source-pins/inputs.json`.

The old fixed-path `qualify_complete_v2.py` and `build_reference.py`, precompiled `build` / `native-build` directories, and local process receipts are not included. Their roles are fulfilled by the provided portable entries; no previous executable or compiler image is an input to this recipe.

The native source pins identify the final private graph whose expected ELF SHA-256 is `493650ca0adaa0f319f086df2395599d1e1f3a4db7cb6606e7ac86e6fa92a0b1` (17,178,624 bytes). These are expected byte identities from the supplied final source; the CI run must compile all 75 owners again, run the HIA linker and image packer, and independently check those bytes.

The original Rust target is `TrillionniumFoundation/hepta-runtime` commit `d3d75c30719db966b004756f610007a7c723729e`, tree `612e145513961556ac8844b5cc978f9b5175e4d4`. The reference contains 14 exact original target files and 106 exact original fragments, each bound by byte range, SHA-256, and Git blob identity. `verify_reference.py` is preserved unchanged. The independent workflow checkout compares every original target file again.

Hepta is commit `d3e2c90173cf733e42b299d0c4274df4b593a12f`, tree `8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49`. CI creates a new development bootstrap and requires B1 = B2 = B3 with SHA-256 `bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`. This is a development fixed point, with independent cold qualification still false.

Rust is exactly 1.95.0. The preserved reference builder fetches the frozen fixture lock, verifies its registry packages against the full current target lock, checks every extracted source against its crate archive, and builds into a fresh target directory with `--locked --offline`. The driver retains those exact crate archives so the later read-only verifier can check the recorded source hashes without the original Cargo cache.

## Unchanged normal comparison domain

| Profile | Cases | Focus inherited from the preserved qualifier |
|---|---:|---|
| `smoke` | 6 | Create, cross-session replace, delete, undo delete, undo replace, exhausted undo |
| `body` | 78 | Four Local commands, ordinary text forms, shared history and locks, cache state, file bytes and metadata |
| `baseline` | 60 | Typed inputs, Create and cache/session behavior, ordinary local path and file conditions |
| `capabilities` | 33 | Actual client metadata, first session context application, later context behavior |
| `configured` | 60 | Installed configuration with the fixture workspace admitted |
| `denied` | 60 | Installed configuration with an empty admitted workspace set |
| `fence_required` | 60 | The existing required-fence profile |
| **Total** | **357** | **1,428 native fixture response records when every profile completes** |

Every case generator, observer reader, and comparison function remains unchanged. `source-pins/ast-preservation.json` records all 12 function/class definitions. The only normalized difference from the fixed-path predecessor is `main` reading the supplied build manifest. Case-source fingerprints are computed using an in-memory placeholder path; no filesystem or native owner is invoked to prepare them.

The existing `qualify_portable.py` performs the actual comparison. It executes each native process and each original process with its original **60-second** limit. The reference builder retains its **180-second limit per step**. The new driver does not add an outer subprocess timeout: the inner programs create their own sessions, so an outer `killpg` could not correctly account for those descendants. The workflow's overall job timeout remains the outer CI control.

## Execution

Static source checking uses Python 3.12, matching the frozen AST representation, and does not run a compiler or runtime owner:

```bash
python3 -I -B PACKAGE/scripts/run_ci.py --source PACKAGE --check-only
```

The complete execution entry is CI-only and requires `CI=true`:

```bash
python3 -I -B PACKAGE/scripts/run_ci.py \
  --source PACKAGE \
  --output NEW_OUTPUT \
  --hepta PINNED_HEPTA_CHECKOUT \
  --rust-bin RUST_1_95_BIN
```

`NEW_OUTPUT` must not exist. The driver copies the package to `NEW_OUTPUT/input`, makes a fresh 75-owner build and a fresh original reference build, and invokes the seven preserved profiles in the order above. Each profile has its own directory and effects tree. Independent profiles continue after a profile process failure, but no aggregate PASS is possible unless all seven complete and the read-only verification also passes. Build failures retain their logs and prevent profile execution.

The directly installable template is `ci/workflow.text-editor-local.yml`. It uses a first step to derive temporary paths from the runner environment and write `GITHUB_ENV`; there is no job-level `runner` expression. It performs pinned source checkouts, builds, executes the domain, verifies bounded completion flags, and archives success or failure evidence. Only the parent publication flow should add a temporary branch trigger or select a final source directory.

## Read-only verification of retained originals

After extracting the CI archive, verification is independent of the original absolute execution path:

```bash
python3 -I -B EXTRACTED/recipe-source/scripts/verify_complete.py \
  --source EXTRACTED/recipe-source \
  --evidence EXTRACTED/run
```

This verifier performs no subprocess launch, imports no native loader, maps no executable code, calls no original Rust function, and writes no file. It reads the original saved inputs and outputs. Its stdout is the verification result.

The verifier checks the source manifests and 106 original fragments; all 75 fresh module source/image pairs; the three bootstrap images; the HIA link and pack inputs, outputs, and receipts; the final ELF; the original executable and five build process receipts; and every retained registry archive and source-file hash.

For each profile it reconstructs only the frozen Python case data using the recorded fixture path, checks the exact saved original stdin, and reads the complete typed-call capture. Every typed capture record is checked against its index, source bytes, input/output capacities, growth continuation, and recorded workspace. The resulting captured native values are used only to verify the saved request framing; no owner is re-executed.

The verifier then selects the existing qualifier's pure comparison AST, removes its one `observations.json` write, and rejects process/runtime calls in that selected code. It rechecks the complete original and native stdout through the unchanged readers, including both session/cache states, the shared history, the lock allocator/map state, every captured file byte, filesystem metadata, and recorded hardlink groups. The recomputed observations and summary must match the saved originals byte for byte. Counts come from those retained records, not from a synthesized success summary.

## Evidence retention and status

The archive includes the exact recipe source, copied runtime/reference inputs, fresh native images and compiler bootstrap, original executable, verified crate archives, all process streams, all seven complete profile captures, both filesystem snapshots, and the live task-owned fixture files. The only omitted run files are Rust intermediate build-cache files; the original executable is retained even if a failure occurred before its final successful build receipt. Relative fixture symlinks are recorded without dereferencing them. Every archived member is read back and checked.

An archive read-back PASS means that the archive retained its bytes. It does not imply that the comparison passed. `RECIPE.json`, `verification.json`, and the original profile `SUMMARY.json` files retain their own status; failures remain failures.

Preparation provides source and syntax checks only. Full private-domain qualification requires fresh CI results. The public TextEditor route, production handler and activation, whole runtime replacement, old-path removal, full SDK, all 136 routes, full async/task/future behavior, cancellation/fence timing, and independent cold qualification remain outside this package's successful claim. The separately prepared ninth catalog and public eight-tool SDK loop are not installed here.
