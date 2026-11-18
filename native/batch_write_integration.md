# Batch-write integration

This is a focused addition to the published Local write foundation. The final
handoff contains only repository files; private authoring scripts, old
candidate sources, expanded fixtures, generated binaries and process outputs
are not repository deliverables. `batch_write_observation.json` indexes the
completed source-bound runs. The retained archive contains the full evidence.

## Register one component and eight required processes

Add a `MODULES` entry with key/builder `batch_write`, name `batch-write`, source
`native/batch_write.hepta`, primary test `test_batch_write_controller.py`, and
the seven remaining tests below as `additional_tests`. Its companion native
sources are `native/batch_render.hepta` and `native/batch_write_packer.hepta`.
The UTF-8 qualification sources stay under `tests/hia_native`; they are not
production images or additional component registrations.

| Order | Required native suite | Observed final process seconds |
| --- | --- | ---: |
| 1 | `test_batch_write_controller.py` | 2.909477 |
| 2 | `test_batch_render.py` | 7.063094 |
| 3 | `test_utf8_probe.py` | 3.928055 |
| 4 | `test_batch_write_files.py` | 4.923090 |
| 5 | `test_batch_write_kernel.py` | 1.095218 |
| 6 | `test_batch_write_concurrency.py` | 0.295209 |
| 7 | `test_batch_write_wide.py` | 66.342519 |
| 8 | `test_batch_write_evidence.py` | 7.010880 |

Use `build_batch_write(hepta, build_root, source_root=ROOT)` from
`scripts/hia_native_batch_write_build.py`. Register its actual returned
manifest, relative path and digest in `report['modules']['batch_write']`.
This performs seventeen HIA compilations: fourteen production images, two
qualification-only UTF-8 probes and the packer. It verifies compile/pack
receipts, exact images, the fixed ELF prefix/table, all embedded bytes,
compiler dependency and source composition before a cache may be returned.
It emits one real fourteen-image Linux x86-64 executable.

Use `hia_native_batch_write_pipeline.test_commands(ROOT, output, report)` for
the actual argv. These commands use explicit manifests/paths, `-I -B`, and
the repository containing the scripts. They do not depend on a sibling
checkout name. The file suite must retain `--large`. Run evidence controls
after all seven semantic suites. Place this component in the existing
`batch` partition, with its wide suite sequential with other large-memory
work. Keep every suite's existing 180-second outer process-group deadline.

Expose `batch_write_evidence(output, report)` as the pipeline helper's
`qualification_evidence(ROOT, output, report, completed_test_summary)`. Save
the result under `batch_write_evidence`. It validates every actual completed
stdout/stderr/argv and exact deadline record, all eight declared processes,
the artifact, complete corpus bytes and fifteen real damaged-evidence
refusals. Merely loading a retained report is not a fresh invocation.
Include this collector in finalization, restored shard checks, Rust preflight
and final evidence rechecks wherever the existing registry requires them.

## Required fresh original recipe

Add exactly one `RECIPES['batch_write']` entry, delegating to
`hia_native_batch_write_pipeline.compare_original(ROOT, output, report,
rustc, completed_test_summary, record_check, qualification_env())`. Its
mandatory actual check name is `batch-write-rust-compare`. Admit `batch_write`
to the specialized builder registry and component-to-recipe coverage checks.
Do not add a dummy Python recipe or classify this as a reference-free owner.

The driver freshly prepares two original projects, checks formatting, builds
the complete original Local body with locked Cargo dependencies and builds
the original renderer with `rustc`. It then performs all 7,909 original calls
in 84 processes: 6,738 renderer inputs plus 1,171 body requests in 83
processes. The body domain includes complete filesystem snapshots, 77 kernel
processes, four shared-state/concurrency processes and the full wide case.
The body replay also executes the same current native ELF against the same
owned fixtures. Both binaries, complete extracted original projects, all ten
actual compile/replay records, source/tool identities, input/output streams,
EOF, stderr summaries and every file byte are retained and rechecked.

Select actual Rust 1.95.0 and its adjacent Cargo/rustfmt. The current driver
requires release 1.95.0, commit
`59807616e1fa2540724bfbac14d7976d7e4a3860`. It clears inherited HIA overrides,
Rust compiler wrappers/bootstrap/flag/target overrides and records the exact
environment policy. All child processes inherit the owning aggregate process
group. The driver must stay inside the existing 180-second `record_check`
group supervisor; its standalone CLI is not a separate process-tree
cancellation owner. The observed fresh driver process completed in
103.251086 seconds; the remote qualification phase including the full
retained reinspection completed in 113.807683 seconds. These observations do
not grant a larger CI budget.

## Source closure and inventory

Add all final file paths to workflow path coverage and source inventory.
Merge `hia_native_batch_write_qualification.pins(ROOT)` into the aggregate
source map and reject conflicts. It currently binds 82 complete source
inputs, including all leaf functions, source compositions, references,
supervisor, fixed case plan, helpers, original modules and both dependency
locks. `build.source_pins(ROOT)` binds 51 artifact inputs. Keep complete
original Git blob pins for the seven original Rust files; use the existing
baseline `a0dcdda1991ec536d5e2d252c006a778993fa566`, without changing the old
bodies. The observation and ABI/integration docs are additional inventory
inputs; they are not counted as new compiler executions.

Register three new production HIA source files in `native/migration.json`
and retain the two test-only HIA files as qualification inputs. Recompute
total sources/components/tests/recipes/checks from declarations; this focused
delta adds one component, eight native suites and one required Rust recipe.
It does not replace the existing Local write, atomic, lock, history, cache,
plan, apply or renderer component qualifications. Every one of the 125
production handler records remains `not_ported`; production activation,
whole-runtime replacement and old-stack-removal flags remain false.

## Common-file change requires real integration qualification

The two common-file edits add only `batch-write.v1` with 512 MiB input,
2 GiB output and 3 GiB workspace, plus an explicit image-only restriction in
the builder. No old profile or fixed transport limit is changed.

| File | Required previous SHA-256 | New SHA-256 |
| --- | --- | --- |
| `scripts/hia_native_build.py` | `7b01d602d50835f2b73a2b7b39761c0cef08a372493985161d59184d52c0dcb2` | `02cc0f23764d3a2bc6c1325e2ed5beb7986a6b64b22827c6ddcb10d2799de7d1` |
| `scripts/hia_native_loader.py` | `331b1fdc693df44847723f7171a1338918d1558f1cdc48f558cd29b32f2971e2` | `58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06` |

Previously qualified atomic, file-lock, Write and authority profiles/helpers
bind the previous common-file identities. Their integration updates need
current source-bound builds, actual affected suites and fresh evidence. Do
not change a digest in old captured evidence and present it as a new run,
relax source checks, or reuse a historical ELF receipt as fresh. Historical
observations retain their original identities. The parent owns this common
dependency refresh and the mandatory exact-source cold/aggregate CI gate.

The capacity note was authored in the isolated candidate tree and mentions
its private authoring paths as provenance. Those directories are not copied
into the repository. The final profile, actual artifacts and exact two-file
delta above are the authoritative proposed integration inputs.

## Exact boundaries still open

This closes the internal Local `batch_edit_spec` body within the explicit
finite three-buffer/u32 ABI. Public parameter conversion, policy/effect
admission, request/session ownership, hints, typed SDK wrapping, audit and
durable result effects are separate caller responsibilities. Remote/SFTP
is not connected. Positive existing-cache behavior has actual HIA state
tests with explicitly synthetic filesystem completions; the static ELF has
not yet shared a populated view cache with a public view caller, so that
flag remains false. The existing wide response is fully retained and
compared; it is not evidence for all Rust `usize`/String sizes.

The component's actual runs are complete. The shared aggregate gate and
public production call chain for this new component remain pending.
