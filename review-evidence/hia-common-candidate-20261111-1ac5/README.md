# Fixed Runtime / Hepta native-helper integration evidence

The tested pair is Runtime `9a43021137b72316f5345ce660c7f3d00ea93c02` and Hepta `8dae9d0b74f8520d1522548e0a04c0c077b3f074`. This evidence branch preserves the observations; its own commit is not the tested source.

## Actual results

Both original joint runs completed successfully:

- [Push 43005206791](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43005206791), job 130470843022.
- [PR 43005214726](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43005214726), job 130470870418.

Each retained report has 10 successful checks, 39 scripted HIA calls covering all 11 catalog tools, and 4 actual stdio MCP sessions. The workflow compiled the exact Runtime source, performed the unchanged 180-second plus 3-second cleanup cold replay on the fixed Hepta source, passed 1242 language checks and the separate 10 assertions, built the real HIA identity helper from the qualified compiler, and invoked the worker through real loopback OpenSSH and systemd.

The audit recomputed the original profile, request and mutation owner-key digests. It verified the original durable worker report, replay across Runtime restart without a new job, and the native consumer's generation and artifact identities across rollback. A retained generation-1 lease continued returning 16 after rollback; a new generation-0 lease used the restored artifact and returned 16; invoking the released lease failed with E_HIA_LEASE.

For the wrong-bundle-pin control, the worker's original job exited 2 with a confirmed terminal publication. Three observations retained the same original operation and UNKNOWN status. Cleanup errors were empty. The two independent runs had identical Runtime binary, worker/backend/catalog, helper bundle and helper image identities.

The final candidate's HIA-specific contract suite also passed 35 tests in each feature configuration with zero ignored tests. Those commands deliberately filter non-HIA tests. The complete original exact-head push CI has also passed: all-features ran 2400 tests, all passed, with 40 existing top-level skips; no-default-features ran 2371, all passed, with 28 existing top-level skips. Release build, the real JavaScript MCP cancellation/recovery gates, REA parser/syscall-denial checks and the independent Python ZIP-to-shipped-Rust checks all passed. The original PR exact-head and prospective-merge jobs have also completed successfully with the same counts in each feature configuration. The prospective merge's tree equals the fixed candidate tree; these are original attempt-1 results, with no requested rerun or manual cancellation.

## Execution boundary

The exercised path is Rust stdio MCP, the existing durable operation owner, a Python worker, and selected HIA native helpers and generated consumer images. JSON adaptation, journaling, service policy and recovery are still hosted. These runs do not establish a fully native worker, production activation, every possible crash interleaving, a fresh-model trial or net performance benefit. The current code changes are in [PR #118](https://github.com/TrillionniumFoundation/hepta-runtime/pull/118), stacked on `fix/unbounded-concurrency-20261109`.

## Complete original archive and reports

[joint-push/RAW_INDEX.json](joint-push/RAW_INDEX.json) indexes the raw push reports and image; [joint-pr/RAW_INDEX.json](joint-pr/RAW_INDEX.json) separately indexes the PR reports. Large original JSON/JSONL entries use lossless gzip. Derived audit records are explicitly labeled. [metadata](metadata/) retains the original GitHub run, job and artifact records.

The complete original push ZIP is retained as 16 raw binary parts. Its 64,587,283 original bytes recover all 1,581 original archive members. [ORIGINAL_ARCHIVE.json](joint-push/ORIGINAL_ARCHIVE.json) records each part's offset, size, SHA256 and Git blob SHA.

To restore from a checkout of this evidence directory:

```sh
cat joint-push/original-archive.zip.parts/part-*.bin > original-joint-artifact.zip
sha256sum original-joint-artifact.zip
```

The complete ZIP must have SHA256 `fddefa9bde25e03980e315acf5e2d04e06adb1d9a337c9a48d72f26e68a54ec1`. The untouched original GitHub ZIP was downloaded, its metadata digest verified, and every entry read for ZIP CRC and content-hash verification before these parts were saved.

## Full Runtime regression evidence

The [final full-CI index](full-ci/final/INDEX.json) retains all three complete original job logs, both runs' final metadata, five untouched release-gate ZIPs, artifact byte audits, and skip/source/merge audits. The full [push run](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43005206656) and [PR run](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43005214787) both succeeded on their first attempts.

| Original job | all-features | no-default-features |
| --- | --- | --- |
| Push exact head, 130470968608 | 2400 passed / 40 existing skips | 2371 passed / 28 existing skips |
| PR exact head, 130471009211 | 2400 passed / 40 existing skips | 2371 passed / 28 existing skips |
| PR prospective merge, 130471008689 | 2400 passed / 40 existing skips | 2371 passed / 28 existing skips |

All three release builds and all four JavaScript cancellation/recovery checks per job passed. The exact-head jobs also passed the REA parser/syscall-denial smoke and independent Python ZIP-to-shipped-Rust structural checks. The structural checks are not cryptographic signature verification. The prospective merge commit is `0632cef671c55c947bed872591bf9bd97c8cf7e0`, with tree `56784c9e064447acfc06e80a9cc235f98c8e91b2`, exactly the fixed source tree.

[full-push/INDEX.json](full-push/INDEX.json) retains the complete 1.16-million-character original job log, original run/job/artifact metadata, both complete release-gate artifacts and their independent byte audits. The added HIA controls and four parent-owned helper tests actually passed in both full configurations.

[Existing ignore inventory](full-ci/existing-ignore-inventory.json) records every original ignore reason and source identity. These files and the general CI configuration match the unchanged deployment base. The 40 entries include manual benchmarks, remote SSH/filesystem and external-oracle work; 12 are excluded from compilation without remote-fs, leaving 28. Four top-level ignored private helpers are deliberately launched by normal bounded parent tests; their parent PASS lines are retained, so top-level skipped is not a claim that those helpers never execute.

The unchanged search-worker Python suite separately reports 16 passed and one skipped test in each exact-head full job because the optional pypdf parser was unavailable. The [original skip audit](full-ci/final/runtime-9a43-existing-python-skip-audit.json) identifies the sole source skip site and original output; this is separate from Rust's 40/28 skips. The prospective-merge workflow does not run that ingress step. No skip condition or general CI workflow was changed.

## Earlier original outcomes

[initial-format-failure](initial-format-failure/) preserves the initial formatting failure. [contract](contract/) retains both the earlier and final exact-source targeted observations. [auto-cancelled](auto-cancelled/) preserves the earlier full-CI runs that the repository's pre-existing concurrency policy automatically cancelled when the successor was pushed. They are not counted as complete passing suites; no manual cancellation or rerun was used.

[SUMMARY.json](SUMMARY.json) records the candidate scope and final recorded gate status. [FILES.json](FILES.json) records the retained Git blob identities.
