# Native Chrome qualification on the final release, 2026-11-04 r2

The three explicit qualification commands passed on the same frozen release executable, SHA-256 `4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d`. This archive preserves their original outputs and the underlying native/deadline job evidence. It establishes the bounded checks described here; it does not establish complete browser behavior or full REA parity.

## Actual environment and ownership

The outer tool call ran on the configured **desktop** operator host. The test controller and its native worker ran on that same Linux machine, with a generated harness host alias `main` and local SSH for the durable jobs. The native qualification's original `host_scope` string says `Linux main; controller and native worker on the same host`; that string is preserved unchanged and is not evidence of a separate machine or isolated-host run.

The observed engine was Chrome `156.0.8078.79` on Linux x86_64. The native capture worker is Rust and invokes external Chrome over the CDP pipe. The qualification drivers and existing durable operator owner/runner still use Python. These results do not establish an entirely Python-free HeptaRuntime or a browser engine rewritten in Rust. Process-level network isolation and changed-session descendant coverage are not claimed.

Capture enters through the native `hepta-runtime rea-browser-capture` CLI, owned by the existing durable process start/status/read/cancel path. No new browser-specific MCP tool is implied. Saved HAR inspection, comparison, and representation replay continue through their existing MCP interfaces.

## Three retained qualification gates

| Original command | Exit | Seconds | Result and evidence |
| --- | ---: | ---: | --- |
| `tests/rea_browser_external.py --native-capture` | 0 | 15.439 | 11 bounded checks; [qualification](native-workspace/qualification.json), [log](gate-evidence/00-native-browser.log) |
| `tests/rea_browser_native_differential.py` | 0 | 0.350 | 10 selected before/after resource pairs against the existing Python reference and an independently authored body oracle; [differential](gate-evidence/native-python-differential.json), [log](gate-evidence/01-native-python-differential.log) |
| `tests/rea_browser_deadline_external.py` | 0 | 4.987 | 6 checks of a deliberately failing native deadline run; [qualification](deadline-workspace/qualification.json), [log](gate-evidence/02-native-browser-deadline.log) |

The complete argv and workspace identities are in the original [plan](gate-evidence/plan.json). The [outer qualification](gate-evidence/qualification.json) has SHA-256 `250347cf667eaf7b9fa42fc662fcd9f3f7a2a80ebcc6e11ab54307f009fb9b5d`. Its `qualified: true` applies to these three commands. The original intermediate [progress](gate-evidence/progress.json) is retained without promotion or rewriting.

### Native capture and saved observations

The 11 recorded checks cover resource tampering before browser launch; original-job/same-key ownership; final receipt durability; a reachable second loopback origin receiving no browser requests; browser/profile cleanup; complete, empty, base64, missing and repeated-request observations; two true before/after response changes; controller restart with the same job and HAR hashes; saved-representation replay with zero requests at two owned live sentinels; changed input/HAR identity refusal; and cancellation of the original job without browser/profile relaunch.

The raw [capture receipt](native-workspace/capture-fixture/capture/capture-receipt.json) and [before](native-workspace/capture-fixture/capture/before.har)/[after](native-workspace/capture-fixture/capture/after.har) HAR files are preserved. The fixture serves fixed, explicitly owned HTTP resources. Input application scripts are fetched as data, not executed; input-page DOM inspection, complete application behavior recording, and general browser-state replay remain outside this qualification.

Saved replay returns the exact UTF-8 representation in HAR `content.text`. A base64 body stays encoded in that representation; the independent oracle also checks the separately decoded bytes. This is not HTTP wire capture or a request replay to a live site. The zero-request observation is limited to the two owned origins recorded by the harness.

### Finite independent differential

The comparator pairs observations by phase, URL path, and occurrence. All 10 selected pairs agree in status, recorded representation and decoded bytes/digests, body state, encoding, and truthful body metadata. Independent literal fixture expectations also pass. Missing observed content has no observed text/size and is never converted to an empty body; a real empty body has size 0.

Generated harness HTML, random loopback origins/ports, negative-probe incidental metadata, and transport/timing/header/order serialization details are outside equality. Their actual differences remain in the raw differential output. The two whole HAR byte sequences differ; full HAR, raw HTTP wire, and application-behavior equivalence are explicitly false.

The existing Python reference is identified by its original workspace and hashes inside the differential's `identity.python` and `arguments.python_qualification`; this reference was not rerun by the three-command plan. The independent comparator source is `tests/rea_browser_native_differential.py`, SHA-256 `c8afe9428510c347f7e62e4710fe5d46a22117a3c52dd5ec09ae8b9a50b50c24`, bound by the frozen verification inventory.

### Deadline is an expected failed capture

The driver fixes a one-second manifest deadline, 32 slow requests, two-second resource delays, and a separate 100-second outer job budget. The original capture job `1a1a5bc45d5-1451ad-1` failed with exit code 1 and explicit native-capture deadline stderr; it was not an outer timeout or unrelated startup failure. Exactly one original Chrome start was observed. Its process group had no live members afterward, its private profile was removed, and no HAR or success receipt was published. Reusing the same key returned the same failed job and unchanged logs without a new Chrome.

The driver observed about 2.267 seconds including completion/cleanup; this is not a claim that end-to-end cleanup finished within one wall-clock second. Deadline qualification passing must not be read as capture succeeding.

## Frozen source, original terminal records, and scope

The gate runner records the same source and verification inventories before and after all three commands:

| Group | Files | SHA-256 |
| --- | ---: | --- |
| Source | 295 | `9d08a4cc6b6c89f4db47eb300af5e54dd44092082434c93b1dee954c30b2209a` |
| Verification | 613 | `b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4` |

The inventories are copied verbatim. The [runner source](../rea-next-release-build-20261104-r2/run_frozen_commands.py) is pinned at SHA-256 `f7f449dbcbd7705876c7cc953937411ad07d521117285db2159e646a1942dec1`.

The outer original job is `1a1a5bbffde-fc05-2115`, request digest `69399691aa1ea901db01d9be13dd43d9d726ae7eda3cb4f6c74c1f74800f2132`. Its exact request, stdin, raw logs, and terminal/witness records are in `outer-job/`. The workspace job directories retain the capture success, tamper rejection, original cancellation, and expected deadline failure. All five exit witnesses and raw log lengths were checked against their exact original bytes.

This browser receipt is independent of the full Ubuntu 24 test matrix, release build, Ghidra/JADX, and JavaScript qualifications. It does not replace the earlier incomplete desktop 35-command run or change REA tool parity classifications.

## Archive policy and integrity

Every original JSON/HAR/log/fixture text file was copied byte for byte, without JSON reserialization or JavaScript numeric conversion. Raw `u64` representations and request identities remain intact. Generated README/validation/manifest files are identified separately.

The runtime executables and all four copies of the nine-byte binary fixture are excluded. The fixture's original SHA-256 `36552025d556393560d602350245f90dfc854dd668f607f06356f30f72ec358c` and independent literal `00fffe804845505441` are retained in the differential oracle and exclusion manifest, so no binary fixture needs to be committed. The outer supervisor implementation and empty lock files are outside the selected outer records/stdin/log scope.

[artifact-manifest.json](artifact-manifest.json) covers every archive file except itself, records source paths and hashes, and lists exclusions. [archive-validation.json](archive-validation.json) records the byte/hash, source binding, terminal witness and bounded credential/type checks. No executable, database, or detected usable credential is included. The only token-like JSON fields observed by the preflight were launch nonces belonging to the recorded terminated jobs; they are not account credentials. This bounded check is not a general secrets audit.

Archiving did not rerun qualification, alter source/tests/scripts/CI/compatibility data, stage files, or publish anything.
