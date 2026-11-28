# Shared RMCP 3.9 text constructor and public 80-image qualification

This package adds one shared HIA text-result constructor and connects it to the actual nine-tool public frontend and owned publication path. It is based on the frozen public-nine source from commit `93cf79f582eb46a1dab7fd846e456eb3a6f4d7f8`, not the evolving main branch.

The target application dependency declarations are exact bytes from `d3d75c30719db966b004756f610007a7c723729e`. The new reference executes RMCP 3.9.0's actual `CallToolResult::success/error`, `ContentBlock::text`, legacy result-type stripping and modern cache-hint policy. It does not reproduce those methods in Python or Rust.

## Qualification at source freeze

The locally retained development run compiled the constructor and typed serializer, then completed 65 ordinary constructor cases, 258 native calls and 63 full typed-serializer comparisons. Its actual public graph built one changed frontend with 79 strictly checked module reuses and completed four public processes and 90 responses. These are limited native development results.

This source package itself is **not a fresh80 or new Rust PASS**. `run_ci.py` is the new recipe that must be executed in CI. No local Rust build was performed. The earlier complete 79-image, five-original SDK, and private TextEditor results retain their original identities.

## Actual integration

| Boundary | Binding |
| --- | --- |
| Shared constructor | Global slot 46; frontend local child 10; frontend phase 11 |
| Public engine | 47 slots, numbered 0 through 46; slot 41 remains empty |
| Input | HRTCRQ01, 64-byte descriptor followed by the complete UTF-8 text |
| Output | Entry returns 64 for HRTCRS01; complete extent is 64 plus the wire length at byte 40 |
| Growth | HGRWS002 requests real workspace or output allocation growth; repeat the entire unchanged input |
| Constructor policy | 0 current constructor, 1 legacy complete-discriminator removal, 2 modern cache policy |
| Public delivery | Whole JSON-RPC wire is imported into the existing owned publisher in raw format 0, then the original START/PULL/write/ACK/DROP sequence delivers it |
| Existing context fields | Process hub at engine +400 and TextEditor context at +408 are unchanged |

The constructor source SHA-256 is `3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d`. Its actual development image SHA-256 is `beaec81c8006ab98e31e0ab72d01311a0cd51ee4ead074bbd5b7742679e033cf`. The source and ABI are shared with the separately qualified Scope annotation owner. See `source/native/text_result_constructor_abi.md`.

The nine public tools remain host_list, effective_config, execution_shadow_admit, view, workdir, directory_create, file_move, directory_move and text_editor. The catalog is unchanged from the frozen nine-tool input. Reserved later Batch slots are not installed by this package.

## Fresh recipe

Use Python 3.11 or newer, Linux x86-64, GNU binutils, build-essential, git and Rust 1.95.0. The Hepta checkout must be commit `d3e2c90173cf733e42b299d0c4274df4b593a12f`, tree `8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49`. The retained SDK source must be `tests/hia_native/sdk_target_ci` at `b4054165e9b7be63e9309c8223d04131ec4fe31e`; its 247-file manifest hash is checked by the retained builder.

First verify without executing native or Rust code:

```sh
python3 -I -B "$PACKAGE/drivers/run_ci.py" --source "$PACKAGE" --check-only
```

In CI, with a new output directory:

```sh
python3 -I -B "$PACKAGE/drivers/run_ci.py" \
  --source "$PACKAGE" --sdk-source "$SDK_PACKAGE" \
  --hepta "$HEPTA" --rust-bin "$RUST_BIN" --output "$OUTPUT"
```

The full recipe requires the CI environment and performs these actual gates:

1. Fresh retained62 HIA compilation and the exact retained ELF identity.
2. Fresh80 HIA member compilation, link and pack, using the bootstrap built in the same invocation. No member image is supplied as an input.
3. Fresh constructor and retained typed-serializer component builds, followed by all 65 ordinary cases. The constructor uses real growth responses; the larger text and escaped-wire cases exceed 8 MiB and 64 MiB respectively.
4. Fresh Rust 1.95.0 reference: locked dependency prefetch from the exact seed, offline target-lock subset resolution, full registry archive/source checks, then a locked offline build. All 65 full HRTCRS01 outputs are compared byte for byte with the actual native capture.
5. Four actual stdio public processes, legacy and modern sessions, 32 retained-eight and 52 nine-tool tool responses, plus protocol/catalog responses for 90 lines total. Complete file snapshots, TextEditor create/replace/delete/undo effects and same-session View/cache behavior are retained.
6. An independent read-only verifier reads the source closure, module and ELF bytes, constructor buffers, actual original outputs, registry archives, public streams and filesystem snapshots.

Each native call and original reference call keeps its 60-second limit; each Rust preparation/build step keeps 180 seconds. Public exchanges keep 60 seconds. There is no newly added outer process timeout: a process-group timeout cannot reliably terminate a descendant that has started a new session. The workflow's 90-minute job limit controls the complete job.

`ci/workflow.public-constructor.yml` is ready for a separate workflow entry. Runner temporary paths are set in the first step through GITHUB_ENV; runner context is not used in job-level env.

## Portable evidence and independent reread

The recipe keeps complete inputs, outputs, stderr, buffers, original executable, source locks, source verification, registry archives, compiler/module receipts, full public stdout and filesystem states. The exporter excludes only the rebuildable Rust target directory after preserving the actual executed binary.

```sh
python3 -I -B "$PACKAGE/drivers/export_artifact.py" \
  --source "$PACKAGE" --run "$OUTPUT" --output "$ARCHIVE_DIRECTORY"
```

This creates a gzip tar, a complete per-file artifact manifest, a module-path map and a readback receipt. It also retains partial failed runs without labeling them qualified. A successful recipe whose independent archive reader fails causes a nonzero exporter exit.

After extracting anywhere, read the retained evidence without executing native or Rust code:

```sh
python3 -I -B "$EXTRACT/recipe-source/drivers/verify_complete.py" \
  --source "$EXTRACT/recipe-source" --run "$EXTRACT/run" \
  --module-map "$EXTRACT/module-map.json" --require-recipe-pass
```

The independent reader derives counts from complete artifacts, checks the constructor image is identical in component and public graphs, and verifies every retained Cargo archive against the exact target lock. It does not promote the component comparison to an original public-handler comparison.

## Boundaries that remain false

General typed response-owner integration, target connection identity, actual AsyncRwTransport integration, full task/future behavior, complete asynchronous TextEditor scheduling, cancellation/fence timing, full wide Scope/Lease behavior, remote and multi-path branches, all 136 routes, production activation and old-stack removal remain outside this package. The public loop has no new original nine-handler comparison. The HIA bootstrap is built fresh in the recipe's declared fixed-point procedure; this is not an independent cold-bootstrap qualification.

The complete package manifest binds every source file. Public case AST preservation is recorded in `drivers/PUBLIC_CASE_AST.json`; no case was replaced with a success summary.

