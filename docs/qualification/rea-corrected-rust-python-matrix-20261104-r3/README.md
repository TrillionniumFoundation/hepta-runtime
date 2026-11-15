# Corrected Rust and Python functional matrix

The closed Rust r3 and Python r2 matrices passed on the unchanged code from
`ed74d9dbf04b97fad38112c2ac08127bf99b3590` under the documented private executable tmpfs profile.
The separately frozen release remains `aa580409a73bc2e0927ead93d32634239051a39fc951c3c2a92d5a1dece8347a`. Matrix test
artifacts and this release are distinct artifacts connected by the preserved
source/build evidence; this report does not claim that every unit test executed
the release executable.

## Observed results and preserved failure

| Run | Tests run | Passed | Failed | Skipped |
| --- | --- | --- | --- | --- |
| Rust r2 all-features | 1933 | 1929 | 4 | 40 |
| Rust r2 no-default-features | 1906 | 1902 | 4 | 28 |
| Rust r3 all-features | 1933 | 1933 | 0 | 40 |
| Rust r3 no-default-features | 1906 | 1906 | 0 | 28 |
| Python r2: 21 original commands | 441 unittest tests | 441 | 0 | 0 |

Fmt and both Clippy configurations passed with warnings denied. Rust retained
all targets, both feature sets, one test thread, zero retries, no fail-fast,
the original build arguments and child umask. Planned gate commands and the
runner's Rust override maps are identical between r2 and r3.

The complete r2 failure is retained. Both feature sets failed the same four
SSH fixtures with the specific OpenSSH temporary socket-publication path guard.
The original guard messages, all failing test names, and exact corresponding
PASS lines in r3 are preserved. The selected run and skip counts are unchanged.
Both schema regression tests passed in r2 and r3; no schema assertion was
removed to force a pass.

## Why the temporary-directory profile changed

The r2 TMPDIR was `/run/user/1000/rea-q2-iiiwx6_w`, 30 bytes. With the
observed seven-digit PID, the initial production control socket path was
91 bytes; the guard reserves 17 bytes for the OpenSSH temporary suffix plus
one NUL within the 108-byte socket capacity, leaving 90 bytes.

The new directory `/dev/shm/q` was created exclusively by the owning
qualification workflow, with uid 1000 and mode 0700. Its canonical path is 10 bytes. The conservative
production formula `L + 53 + D + S` gives 90 bytes for L=10, D=7 and a
20-digit u64 sequence. The fixture's distinct retired socket path gives
104 bytes and is bound directly by UnixListener after an `ssh -G`
configuration check, so it uses the final-path bound of 107 bytes; it does not
incur the OpenSSH temporary suffix. The static proof retains exact source
references, source/dependency hashes and the original failure-log hashes.

This changed the owned functional environment. Production path guards, source,
test assertions, retry policy and deadlines were retained. The original
functional-profile-r2 record and failure remain unchanged. The profile does not
qualify ext4 latency or power-loss durability.

## Source identity and the two selection scopes

All four Rust r2/r3 before/after snapshots are identical original bytes:
SHA-256 `a906c7844ea2641fd331768c40437b5aafa2656c33874ea494744f87990c64f2`.
They cover 641 files with tree digest
`4021ee22efdf2eac830e08afc45eddf37b264e7fd31a222c329b4950ef2d94b6`.

Python additionally selected `deploy` and `tools`, yielding
1109 files and tree digest
`3a2a3c8ecb68d58688326f84aea084a8dcf8a4e7344c7c14897b12d95cfb557d`.
Its before/after snapshots are identical, and every one of the Rust-selected
file records equals the corresponding Python record. Both scopes recorded
zero inotify events/errors and no event truncation. The different tree
digests reflect different selections.

The Python source commit `2623fad7a42e66ead9b4bc254a99d06a900e331b` adds documentation after the
frozen code. The archive verified no changes to src, tests, scripts,
Cargo.toml or Cargo.lock between it and the code commit. The historical
baseline check for tools/x230 and deploy/maintenance_20261017 is preserved.

## Python commands, sequencing and original timeout

The original 21 exact command vectors are preserved in the plan and raw
summary, and compared directly with the failed r1 summary. All 21 commands
completed with exit 0 and observed unittest OK; their counts sum to 441.

| Python suite | Observed tests | Duration |
| --- | --- | --- |
| python-file_capabilities | 9 | 1.219 s |
| python-runtime_registry_page_tests | 29 | 46.655 s |
| python-test_native_canary_resume | 10 | 2.437 s |
| python-chatgpt_v11_layered_read_tests | 23 | 0.533 s |
| python-chatgpt_v11_process_start_concurrency_tests | 15 | 0.489 s |
| python-chatgpt_v11_v4_session_binding_tests | 14 | 2.927 s |
| python-runtime_workflow_owner_tests | 15 | 0.453 s |
| python-chatgpt_v10_single_v4_effect_tests | 8 | 0.330 s |
| python-chatgpt_v10_stream_custody_tests | 18 | 0.364 s |
| python-test_computer_http | 19 | 1.985 s |
| python-full_operator_facade_tests | 31 | 10.754 s |
| python-full_operator_cancel_tests | 26 | 17.302 s |
| python-chatgpt_request_identity_tests | 21 | 4.186 s |
| python-full_operator_session_recovery_tests | 17 | 9.519 s |
| python-rea_browser_capture_tests | 22 | 1.005 s |
| python-rea_compatibility_ledger_tests | 27 | 0.475 s |
| python-native_rollout_tests | 15 | 0.468 s |
| python-recover_control_channel_tests | 24 | 0.368 s |
| python-x230-20261028 | 57 | 5.768 s |
| python-x230-20261029 | 6 | 0.296 s |
| python-x230-20261030 | 35 | 1.744 s |

The job `1a1a76107b5-fc05-2b38` ran serially after seven recorded
successful durable predecessors: Rust r3 and the six owned external gate
jobs. All seven status observations were complete and durable before this
matrix started. They remain in the original predecessor-terminals file.

The prior r1 canary timeout is retained with its summary and complete failing
stdout/stderr. The original test and helper Git blobs are byte-identical to
those used by Python r2. The case's 10-second timeout and driver's 2-second
budget were not changed. The new matrix qualifies this functional profile;
it does not establish the root cause of the historical ext4 timeout or
claim a production repair for it.

## Durable terminals and limits

Rust r2 job `1a1a73068c1-fc05-2a83` remains a complete durable exit-1
failure. Rust r3 job `1a1a7583b4c-fc05-2b11` and Python r2 job
`1a1a76107b5-fc05-2b38` each have authoritative successful exit-0
observations, confirmed terminal publication, complete durable output and
no timeout, cancellation or automatic retry. Their original requests,
exit/publication records, outer logs and full status observations are retained.

The 40 and 28 Rust skips remain skips. The runner explicitly ignores the
default filter while retaining nextest's default ignored-test policy.
Doctests are outside this matrix. The source monitor is local Linux inotify
plus content inventories, not a remote or same-UID adversarial proof. Cargo
cache is a trusted external input; the existing task-exclusive target is
runner-flocked. These finite functional results do not close the complete
229-tool REA parity ledger or external platform/licence qualifications.

## Complete original-byte archive

`raw-evidence.tar.gz` contains **133 files,
2,607,761 uncompressed bytes**. It includes
all 20 Rust r2 matrix files, all 20 Rust r3 matrix files, all 48 Python r2
matrix files, all source snapshots/events, complete logs and summaries,
environment records, durable job/publication records, original command
texts, retained prior failure evidence, and preparation/qualification helper
sources. No log was trimmed, normalized or rewritten.

`raw-file-manifest.json` binds every archive member's exact bytes and
SHA-256. Every gzip/tar member was read back and compared with that manifest
and the original retained copy. Raw data is losslessly compressed so that
preserving original log whitespace does not require changing its bytes.
Use ordinary `tar -xzf raw-evidence.tar.gz` in a separate directory to
inspect the complete material.

The top-level summary and comparison records are derived indexes. Preparation
receipts inside the archive truthfully retain their earlier pending/false/null
states; the final summary separately records the closed qualification. In
particular, the generic copier left Python's alternate source-field layout
unknown, and the dedicated comparison verifies its explicit before/after
digest fields and full Rust subset. No missing value was treated as a pass.

This docs-only archive was assembled after terminal completion. Its collector
and assembly did not run tests or modify ROOT, target, engine installations,
production policy, or any original evidence.
