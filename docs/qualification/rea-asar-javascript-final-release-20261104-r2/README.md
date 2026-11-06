# Final release qualification: native ASAR and existing JavaScript

This archive records the ASAR and existing JavaScript gates executed against the same integrated Linux release on 2026-11-04. All seven commands in the two fixed gate plans passed. This is evidence for these bounded workflows; it is not a claim of complete REA parity or a result for the separate full Python/Rust matrices.

## Frozen identity and unchanged inputs

- Release SHA256: `0595fbf02e0f492bd151fec97eb90cb704a88810e9415b90582d348f3db99b6a`.
- Release size: 18,437,832 bytes.
- Source freeze commit: `b857dc7d646dc938e29a51fa82a5856d9b96f842`; the observed integrated HEAD during these gates was docs-only descendant `618e8638c84cd9c95fb08b52ea9354e982ee0154`.
- The upstream frozen release was copied into the independent evidence directory and verified before use. Both qualification harnesses made and verified their own runtime copies.
- Source inventory: 308 files, SHA256 `64084b4dd57bbc04e53a0eb26eda6d70eea7bbe1b258bd79810b9aaa3e4c3871`.
- Verification inventory: 645 files, SHA256 `455b490f167deaa4e520ab29d9982d36730ca57c3b3542ae615279185b74f216`.
- Source and verification inventories are identical before and after both gate runs. The original gate scripts, test executables, fixture goldens and reference dependency pins were checked without recompilation or gate changes.

Original integrated checkout: `/home/qian-qi/hepta-runtime-rea-continuation-20261104-r2`.

Original evidence directory: `/home/qian-qi/work/hepta-rea-final-asar-js-20261104-r2-evidence`.

The preparation record, exact argv/environment plans, before/after inventories, per-command results, authoritative process statuses and final pin check are included. The independent command runner is the existing runner with SHA256 `f7f449dbcbd7705876c7cc953937411ad07d521117285db2159e646a1942dec1`.

## Results

| Gate | Result |
| --- | --- |
| Existing JavaScript MCP black-box test | 1/1 passed against the frozen release; original test executable was reused with its runtime override |
| Independent Babel 8.0.6 comparison | Imports 17/17, exports 16/16, Electron call sites 12/12, IPC candidate edges 4/4; no missing or extra rows |
| Existing manual golden | Both Babel and Rust matched the original export counts and corrected export observations |
| ASAR worker/MCP black-box tests | 2/2 passed against the frozen release |
| Independent @electron/asar 4.2.0 producer/consumer | All eight ASAR gates passed, including 24 packed-member range comparisons and whole selected-member hashes |
| ASAR owned stopped-worker cancellation | Worker terminated and was reaped in 0.032853785 s within the unchanged 5 s observation window; the same owner accepted the recovery call |
| ASAR owned stopped-worker deadline | Production 20 s deadline returned its error after 20.067488833 s measured from confirmed stop; the worker was reaped and the same owner recovered |
| Existing JavaScript owned stopped-worker cancellation | Worker terminated and was reaped in 0.030452669 s within the unchanged 5 s window; the same owner recovered |

The ASAR harness recorded 55 ordinary probe calls, including 23 expected refusals. All expected refusals and successful probes had their expected outcome. It checked malformed/conflicting headers, unsafe paths, stale identity pins, integrity mismatch, unsupported link/unpacked reads, non-UTF-8 JavaScript input and explicit ASAR graph acquisition. The archive-backed graph preserved the ordinary-source graph identity and observations for the same logical sources.

The cancellation passes required the original owner to remain alive, pidfd exit readiness, absence of the original worker from /proc and from every owner-task child list, followed by a successful request on that same owner. Neither harness used its manual worker kill fallback to obtain a pass. The owners then exited through stdin EOF, were reaped, and their reader threads joined without errors.

The existing JavaScript cancellation harness records the configured production deadline as metadata; it does not separately exercise a JavaScript deadline branch. Only the ASAR deadline branch is an independent deadline measurement in this archive.

Exact unchanged plans are `legacy-plan.json` and `lifecycle-plan.json`. The first contains the original pins-before, ordinary MCP, Babel/manual-golden and pins-after commands. The second serially executes ASAR external tests, the ASAR reference/lifecycle harness and the existing JavaScript cancellation harness. All output and TMPDIR paths are outside the integrated checkout. The parent waited for the first Python matrix to finish before authorizing these lifecycle gates.

## Canary failure and one targeted diagnostic

The first full Python matrix retained a real failure in `CanaryResume.test_existing_receipt_never_gets_replaced_or_repeated`. Its first helper invocation exceeded the unchanged outer 10 s timeout. The original suite reported 10 tests with one error; its raw stderr is retained with SHA256 `59dd2c11d65237e7b7c7bba8c9fa8efe4b6c6b102b6fb6871b807e565f3c722b`. It was not the separate 0.1 s timeout test.

Neither the test nor helper uses a Unix socket. A successful helper branch performs six serial fake-driver calls with an unchanged 2 s limit for each call, plus three file-creation fsync operations and 15 receipt saves. Each save synchronizes both a file and its directory: 33 fsync calls in total. File preparation and durable receipt writes are outside the individual driver-call timeout but inside the outer 10 s helper timeout. The original failed fixture was cleaned by the original test, so the original stderr does not locate the historical stall.

One explicitly diagnostic run used the same test body and the same 10 s / 2 s limits. An outside-repository subclass only captured each original run_helper result/state and copied the fixture before the original cleanup. Existing strace followed only its owned child process tree. This observation adds overhead and is not an unchanged formal gate run.

That diagnostic passed in 2.221339547 s. The first helper took 1.488682212 s: six driver observations totaled 0.530455 s, and the 33 measured fsync calls totaled 0.723409 s (maximum 0.048730 s). The expected second refusal took 0.336430085 s; driver calls remained at six and the completed receipt and original report remained byte-identical.

These timings describe the diagnostic run only. They do not establish the historical root cause and do not turn the first matrix into a pass. The original failure remains failed. A final complete Python21 run with original argv and limits must be reported separately. No timeout, source, assertion or golden was relaxed for this archive.

## Archive format and practical limits

`MANIFEST.json` maps each archived item to its original absolute path, byte count and SHA256, as well as its archive hash. JSON reports are copied byte-for-byte. Raw logs, JSONL streams, strace text and source snapshots use lossless JSON wrappers with `encoding`, `text` or `base64`, and original-byte hashes; this preserves empty files, terminal newlines and all original bytes without modifying the raw evidence.

Large runtime copies and generated input payloads remain in the external evidence directory. Their recorded hashes and sizes are retained in the qualification reports and the manifest omission list, alongside the unchanged producer/harness sources that generated the fixtures. No executable or multi-megabyte generated fixture is added to this docs-only archive.

The ASAR hash scopes remain distinct: native complete-Pickle-header identity, selected-member content/integrity, and any whole-archive identity are separate. An archive-provided integrity hash is self-consistency evidence, not publisher authentication. See [ASAR profile](../../rea-native/ASAR.md) for the bounded parser and acquisition contract.

The scripts create exclusive fresh workspaces. For a new run, choose new external output paths and a separately pinned runtime; the plans here preserve the exact paths used in this run and must not overwrite the first-run receipts.
