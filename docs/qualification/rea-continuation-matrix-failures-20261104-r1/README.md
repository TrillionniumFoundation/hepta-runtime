# Continuation r1 matrix failures: preserved original evidence

This archive preserves two completed, unsuccessful qualification matrices from 2026-11-04. It is a failure record and does not grant a new release qualification. The original results remain failed. No test was rerun while creating this archive, and no test limit, source, fixture or expected result was changed.

## Frozen inputs and outcome

The matrices used the integrated source frozen at `b857dc7d646dc938e29a51fa82a5856d9b96f842`. The earlier unified release executable had SHA256 `0595fbf02e0f492bd151fec97eb90cb704a88810e9415b90582d348f3db99b6a` and size 18,437,832 bytes. Release-build qualification and the separately passing finite ASAR/JavaScript/Source Map gates do not override the failed full matrices. Later source fixes require a new release identity and new qualification.

| Recorded phase | Result | Tests run | Passed | Failed/errors | Skipped |
| --- | --- | ---: | ---: | ---: | ---: |
| Rust nextest, all features | exit 100 | 1932 | 1930 | 2 failures | 40 |
| Rust nextest, no default features | exit 100 | 1905 | 1904 | 1 failure | 28 |
| Python original 21 suites | 20 suites passed; 1 suite failed | 441 | 440 | 1 error | 0 |

The terminal outer Rust job `1a1a6c02669-fc05-2894` reports failed, exit 1, not timed out, not cancelled, terminal publication confirmed, and durable complete output. Its immutable original SDK status payload is retained in [provenance](provenance/rust-matrix-terminal-status.original-sdk.json); the controller operation result checksum is retained separately. The outer job included the earlier completed release-build phase. This archive does not relabel that phase or the full matrix.

Rust formatting and both Clippy configurations passed. The all-features nextest test duration was 1881.742 seconds; its entire Cargo stage, including preparation/build, was 2350.139976 seconds. No-default nextest took 1966.993 seconds of tests and 2438.056286 seconds for the complete Cargo stage. Both commands retain `--test-threads 1 --retries 0 --no-fail-fast --ignore-default-filter --no-tests fail`. The two configurations are distinct planned executions, not retries.

All-features failures were:

- `mcp::runtime::jobs::start_io_tests::pending_publication_saves_frozen_intent_before_recoverable_identity`.
- `mcp::server::server_tests::served_tool_schemas_carry_no_generator_noise`.

The no-default failure was `served_tool_schemas_carry_no_generator_noise`. Failure lines appear both when the test failed and in nextest's concluding summary; duplicated printed lines are not additional failing tests. Follow-up diagnosis and fixes are separate work and do not change these observations.

## Complete Python sequence

The original r3 plan is preserved byte for byte as [original-r3-plan.json](python-matrix-r1/original-r3-plan.json), SHA256 `5e967f1d2136d447615de1274384e968ef5b523008c3da5feb3a12e739705bd8`. The r1 runner selected the same 21 Python commands, used `python3 -B`, a private executable TMPDIR, and serial execution. The exact recorded commands, working directory and available environment metadata are in [recorded-commands.json](recorded-commands.json) and the unchanged original summaries. All 42 stage stdout/stderr streams, including empty streams, are retained.

| Order | Suite | Tests | Exit | Recorded status |
| --- | --- | ---: | ---: | --- |
| 01 | `python-file_capabilities` | 9 | 0 | passed |
| 02 | `python-runtime_registry_page_tests` | 29 | 0 | passed |
| 03 | `python-test_native_canary_resume` | 10 | 1 | failed |
| 04 | `python-chatgpt_v11_layered_read_tests` | 23 | 0 | passed |
| 05 | `python-chatgpt_v11_process_start_concurrency_tests` | 15 | 0 | passed |
| 06 | `python-chatgpt_v11_v4_session_binding_tests` | 14 | 0 | passed |
| 07 | `python-runtime_workflow_owner_tests` | 15 | 0 | passed |
| 08 | `python-chatgpt_v10_single_v4_effect_tests` | 8 | 0 | passed |
| 09 | `python-chatgpt_v10_stream_custody_tests` | 18 | 0 | passed |
| 10 | `python-test_computer_http` | 19 | 0 | passed |
| 11 | `python-full_operator_facade_tests` | 31 | 0 | passed |
| 12 | `python-full_operator_cancel_tests` | 26 | 0 | passed |
| 13 | `python-chatgpt_request_identity_tests` | 21 | 0 | passed |
| 14 | `python-full_operator_session_recovery_tests` | 17 | 0 | passed |
| 15 | `python-rea_browser_capture_tests` | 22 | 0 | passed |
| 16 | `python-rea_compatibility_ledger_tests` | 27 | 0 | passed |
| 17 | `python-native_rollout_tests` | 15 | 0 | passed |
| 18 | `python-recover_control_channel_tests` | 24 | 0 | passed |
| 19 | `python-x230-20261028` | 57 | 0 | passed |
| 20 | `python-x230-20261029` | 6 | 0 | passed |
| 21 | `python-x230-20261030` | 35 | 0 | passed |

The sole Python error was `CanaryResume.test_existing_receipt_never_gets_replaced_or_repeated`: its first `run_helper()` exceeded the existing outer 10-second `subprocess.run` timeout. The helper's driver-call timeout remained 2 seconds. This was not the separate 0.1-second negative timeout case. The suite ran 10 tests in 26.394 seconds; the recorded outer stage took 27.142351 seconds. The original failure traceback is preserved without editing in [the stderr wrapper](python-matrix-r1/03-python-test_native_canary_resume.stderr.log.json), original SHA256 `59dd2c11d65237e7b7c7bba8c9fa8efe4b6c6b102b6fb6871b807e565f3c722b`.

## Source stability and scope of evidence

| Matrix | Files in recorded input inventory | Input inventory tree SHA256 | Before/after file SHA256 |
| --- | ---: | --- | --- |
| Rust | 641 | `0ab735bb69893f88ea4f81c73d5d64d5220d234d3ead90cba88c55542eec9abb` | `df8a9aa57376335a93aaa90cbf091e6e6836ef9ebd872311752a54bf0d42afc7` |
| Python | 1109 | `754a7bbd01de1c6cd062d438ced414ca26796b03ea8f83289eb71a90d6b73568` | `3b5fbe83f516b8b154023e31761ed37b171e9f2eef8f579ff2d8a571a3e2eab7` |

These tree SHA256 values describe the inventory algorithm; they are not Git tree object IDs. Each matrix's before/after files are byte-identical. Both source-event records contain zero events, no errors and no truncation. The Python inventory additionally includes `tools/x230` and deployment inputs. Its summary records that `tools/x230` and `deploy/maintenance_20261017` had no code diff from `1d9ea7e7e7a1625c611d5f6e037a1ed9d57379d4`.

The Python runner observed docs commit `618e8638c84cd9c95fb08b52ea9354e982ee0154`; the source freeze remains the commit above. The archive did not modify the original evidence directories or ROOT. Source stability is asserted only over each recorded inventory and monitor coverage, which remain available for audit.

## Canary diagnosis: retained limits

The later, separately authorized single-case diagnostic passed once, with the original test body and unchanged 10-second / 2-second limits. It used `strace` on owned children and therefore incurred observation overhead. Its [original summary](canary-diagnostic/summary.json) is preserved; the complete trace, harness, per-call snapshots and unchanged original failure are also in the earlier [ASAR/JavaScript archive](../rea-asar-javascript-final-release-20261104-r2/README.md), introduced by commit `46d5f47e048d9ecc96312a5dd16112ccadf8baba`.

The diagnostic completed in 2.221339547 seconds. Its first helper call took 1.488682212 seconds, with six driver processes totaling 0.530455 seconds and 33 `fsync` calls totaling 0.723409 seconds (maximum single call 0.048730 seconds). The second helper invocation refused the already existing receipt as expected, left the driver count at six and preserved the receipt/report hashes.

That pass establishes only that the original timeout did not recur in this one later diagnostic. It does not establish the historical stall location, demonstrate a fix, or supersede the r1 failure. The failed r1 fixture was already cleaned up, and the original log lacks per-call and per-sync timing. Current or later pressure measurements cannot identify what delayed the earlier run.

Read-only code review found a successful helper path with six serial driver calls and durable checkpoint syncs. Sync, JSON work and process-creation overhead contribute to the outer 10-second limit; the 2-second per-driver deadline is not a promise that all six calls and checkpoint work fit that aggregate budget. No deterministic helper deadlock was established. Removing checkpoint or directory syncs would change the intended durability contract and was not used to make the test pass.

The preceding registry suite's real large-registry case creates 65,529 private records. Its stage ended 1.223431 seconds before the canary stage began. Later read-only filesystem inspection found the r1 TMPDIR, ROOT, Cargo target and diagnostic directory on the same ext4 mount, device 8:2 / st_dev 2050. This makes shared filesystem pressure a plausible risk to investigate; it does not prove the cause of the historical timeout. In particular, the archive does not claim that every short-lived registry file was physically written to disk or that the registry was the source of the stall.

## Read-only executable-tmpfs profile

The original probe job `1a1a70fbf06-fc05-2a08` was observed at `2026-11-04T14:56:31.743726+00:00`. Its full immutable native SDK payload and exact 2,231-byte stdout (plus empty stderr) are preserved. No payload was reconstructed from the findings below.

- Effective UID/GID: 1000/1000.
- `/run/user/1000`: non-symlink directory, owner UID/GID 1000/1000, mode 0700, effectively writable/searchable.
- Mount: tmpfs, device 0:49 / st_dev 49, `rw,nosuid,nodev,relatime`, no `noexec`.
- Available at that observation: 13,483,372,544 bytes and 3,293,707 inodes; system MemAvailable was 107,016,116 kB.
- `/dev/shm` was a shared mode-1777 tmpfs; a task-owned private directory under `/run/user/1000` is the more isolated candidate.

The probe did not create a directory, execute a program, mount or remount anything, or reserve capacity. It does not contain a later executable preflight. Future qualification must record its own private-directory execution check, live capacity and memory/cgroup profile. A tmpfs run can qualify the explicitly declared functional profile; it cannot demonstrate ext4 or power-loss durability, retroactively fix the r1 timeout, or substitute for repairing the independently identified Rust defects.

## Blocked Python r2 waiter

The parent recorded official SDK status and log reads for waiter job `1a1a6e879fa-fc05-296e`. The relayed observation is retained as [parent-observation.json](python-r2-precondition/parent-observation.json), explicitly normalized from that report; it is not an original SDK byte archive.

The waiter terminated with exit 1, not timed out or cancelled, and complete durable output. Its recorded stderr was `AssertionError: ('Rust predecessor not qualified', 'failed')`. This was a precondition refusal before the Python r2 suites ran. It is neither a passing r2 qualification nor a failing r2 test result. The original 21-suite failure above remains the actual Python matrix result in this archive.

## Preservation and verification

The archive contains all 20 regular files from `full-rust-matrix-r1` and all 46 regular files from `python-matrix-r1`, plus the pinned original plan, diagnostic summary, original controller payloads and provenance. The Python private `tmp` subtree, runtime binaries/configuration/state/tokens and owner databases are excluded.

Original JSON files are copied byte for byte. Every raw log is wrapped as JSON with its original byte count, SHA256, UTF-8 encoding and complete `text`; encoding `text` as UTF-8 reconstructs the original bytes, including trailing newlines and empty streams. The original native SDK payload files are byte-exact decoded controller snapshots, with their own verified SHA256 values. The derived command list, archive summary, README, manifest and normalized parent observation are labeled separately from originals.

[archive-sources.json](archive-sources.json) maps original files to archived representations. [manifest.json](manifest.json) lists every archived file other than itself with byte length and SHA256. Archive validation decodes each log wrapper, checks all original hashes and lengths, and re-reads the source evidence to verify it remained unchanged. No automatic retry or test rerun was performed by this archival work; future qualification must be retained as a separate cohort.
