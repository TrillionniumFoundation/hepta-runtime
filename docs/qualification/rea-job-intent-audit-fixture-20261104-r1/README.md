# Job intent audit fixture isolation

## Corrected boundary

The positive `pending_publication_saves_frozen_intent_before_recoverable_identity` fixture now uses an owned private `state/audit/events.jsonl` hierarchy, matching the path produced by `prepare_audit`. Its previous `tempdir/audit.jsonl` path made `AuditBinding` treat the shared temporary-directory parent as the state directory. An unrelated temporary entry could therefore invalidate a real publication proof.

This changes only `src/mcp/runtime/jobs_start_io_tests.rs`. Production audit validation, redaction, file and directory barriers, executor admission, cancellation ownership, dependencies, and time limits are unchanged. A same-file review found only this positive test invokes the real append path with the flat hierarchy. The other flat `prepared(...audit.jsonl)` call belongs to the synthetic intent/identity rejection test and never opens an `AuditBinding`.

The regression performs a real `sync_data`, then creates one unrelated sibling under an owned simulated shared temporary parent. On Unix it asserts the actual `AuditDirectoryStamp` changed; the assertion uses the real namespace version as well as metadata and does not rely on a sleep or timestamp granularity. The nested fixture must still append the original frozen audit bytes before saving the original pending identity.

## Historical failure and controlled reproduction

The original all-features matrix failed this positive test with `Operation intent audit unavailable; no remote operation submitted` at `jobs_start_io_tests.rs:354`. The preserved raw log is:

`/home/qian-qi/work/hepta-rea-continuation-20261104-r2-evidence/full-rust-matrix-r1/07-nextest-all-features.stderr.log` (lines 918–935).

That production error intentionally hides its underlying audit failure. The historical log cannot uniquely prove which underlying condition occurred at that instant. In particular, this publication path has no audit deadline, so the reported 0.654-second test duration does not establish a timeout.

The controlled RED case keeps the old flat hierarchy and creates the owned sibling in the real synchronization callback. It selects exactly one real unit test. It must fail with both the underlying `audit directory publication binding changed` and the same sanitized intent error. A compile failure, zero selected tests, or a different error cannot qualify this reproduction. The diagnostic-only `inspect_err` in the test records the underlying cause without changing production error handling.

The audit line can already have been written and synchronized before the final binding check rejects publication. This evidence does not claim an absence of audit-file side effects. Existing negative tests separately preserve refusal to publish a recoverable job identity or submit an effect after an unsuccessful intent.

## Qualification

| Gate | Result | Evidence |
| --- | --- | --- |
| Controlled old flat fixture | Expected RED: exactly 1 failed test, cargo exit 101 | Both binding-change and sanitized intent errors; test 0.02 s, compilation plus test 933.746 s |
| Corrected start-publication module | 10 passed, 0 failed | Includes real changed-parent stamp, original audit-before-identity order and negative intent/effect test |
| Existing audit-publication boundaries | 14 passed, 0 failed | Includes real binding-change refusal, file/directory barrier errors and intent/effect refusal |
| Formatting | Passed | cargo fmt --all -- --check |

Both phases used Rust 1.95.0, all features, locked offline dependencies and `-j2`. The existing target `/home/qian-qi/hepta-runtime-rea-evidence-target-20261104-r2` belonged exclusively to this agent and was reused only as a build cache. Its old release qualifications are not reused as current evidence. Each phase records the current source manifest and the actual test executable SHA256. Cached executable paths may subsequently be rebuilt; the receipts bind each run to the bytes present during that run.

Base commit: `72976ad25897e08d5302e4556bbcfe5d3dbe5a06`.

The before/after hashes of the 306 selected source/build-configuration inputs matched within each phase. Production `src/mcp/runtime/jobs.rs` remained SHA256 `0fd54a135208a1bc492df5ff5d33a5b50e1075747d97ccb8b945bb09a3d8c642`. The corrected test retains the original frozen-line, publication-order, pending-identity and pre-admission assertions. There is no host profile switch or wider retry window in this fix; the GREEN receipt records the actual inherited temporary-directory environment and mount.

Full raw runs, source snapshots and selected input manifests are outside the repository:

`/home/qian-qi/work/hepta-rea-intent-audit-fix-20261104-r1-evidence/{red-r1,green-r1}`.

The committed compact receipts and logs retain the original expected failure and the subsequent results. `artifact-manifest.json` records original paths and hashes and the durable job terminal records. No whole matrix, release, external-engine, power-loss durability or full REA parity claim follows from these targeted tests.

## Reproduce in an isolated checkout

For RED, create a separate worktree at the base commit above and apply `red/diagnostic.patch`. Use the exact command and toolchain from `red/qualification.json`; the required result is test exit 101, exactly one selected failure and both named errors. The wrapper's exit 0 means that this expected failure was correctly observed, not that the positive test passed.

For GREEN, use a checkout containing this fixture fix and run the following from that checkout with its own Cargo target. Keep the feature, filter and observation settings as shown:

```sh
cargo +1.95.0 test --all-features --locked --offline -j2 --lib mcp::runtime::jobs::start_io_tests:: -- --nocapture --test-threads=1
cargo +1.95.0 test --all-features --locked --offline -j2 --lib mcp::runtime::jobs::tests::audit_publication -- --nocapture --test-threads=1
cargo +1.95.0 fmt --all -- --check
```

The first command must select 10 tests including the corrected positive publication case; the second must select 14 audit-publication tests, including binding-change refusal and the original intent/effect boundary. Do not count zero-test success as qualification. The main integration worktree will run its independent full matrix after merging this correction.
