# Native REA analysis increment — 2026-11-04

## Purpose and integration boundary

This increment brings three previously separate or limited analysis paths into HeptaRuntime: native JavaScript/TypeScript/Electron static observations, native bounded Chromium capture, and deeper Ghidra ELF analysis. All three use the runtime's admission, bounded input and execution, and cancellation controls. Ghidra and browser capture also use its existing durable jobs and retained results. The JavaScript graph is a request-scoped MCP response; its graph identity is a content/profile identity, not a durable job, recovery handle or REA Evidence identity.

This document qualifies the finite contracts described below. The frozen npm REA 6.8.0 catalog contains 229 tools in 18 families. The checked mapping currently classifies 16 as partial operations, 23 as related facilities and 190 as absent. No complete upstream tool contract has been declared equivalent: qualified_tools remains 0, open_tools remains 229, and the strict parity command deliberately returns 3.

## Implemented paths

| Area | Entry point and change | Explicit boundary |
| --- | --- | --- |
| Ghidra | Existing rea_static_profiles and rea_static_start/status/read/cancel gain bridge revision 2 operations functions, function, xrefs and decompile. | Rust owns the analysis admission/contract and static worker. Operator-mode durable launch still uses the existing Python launcher/runner; Ghidra 12.2, JDK 25 and the native decompiler remain external engines. Fixed analysis and output limits apply. |
| JavaScript | New rea_inspect_javascript_graph MCP tool and internal rea-javascript-worker CLI use pinned Oxc 0.144.0 AST and lexical bindings. | Explicit selected sources, imports/exports, Electron callsites and literal-channel candidate edges. No source execution, dependency traversal, Node/browser resolution or live Electron runtime is claimed. |
| Browser | Existing process_start/status/read/cancel owns the public rea-browser-capture CLI. The resulting HAR connects to existing inspect/compare/saved-body replay tools. | The producer is Rust and requires Chrome as an external engine. It fetches controlled local resources as data through a fixed harness; it does not execute an input application page or reproduce browser state. |

The JavaScript tool adds one MCP interface. Ghidra operations and browser capture reuse existing interfaces and lifecycle ownership. The operator-mode generic durable process launcher/runner still includes Python; the new native browser producer and JavaScript parser remove Python/Node from those producer/parser implementations, not from every surrounding execution layer.

## Fixed identities and final validation

| Identity or gate | Recorded result |
| --- | --- |
| Baseline commit | `310add6db47bcfbed3545432eb528a72f5eb6dcd` |
| Final source inventory | 295 files; `9d08a4cc6b6c89f4db47eb300af5e54dd44092082434c93b1dee954c30b2209a` |
| Final verification inventory | 613 files; `b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4` |
| Desktop release-only continuation | 4 commands passed; release 489.664 seconds; original job `1a1a5ae47bf-fc05-20a2` succeeded with durable complete output |
| Frozen desktop release | 17820288 bytes; SHA-256 `4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d` |
| Fixed five-second real MCP cancellation | Passed on this release in 0.022742728 seconds; stopped worker exited/reaped, original parent remained alive, all-task children empty, next call succeeded, no manual worker SIGKILL |
| Complete Ubuntu 24 functional matrix | 35/35 commands matched their original expected exits; job `1a1a5c82e93-fc05-216c` succeeded with complete durable output and unchanged input inventories. |
| Rust all-features | 1,886 passed; 39 existing skipped/ignored cases; 126.965 seconds execution. |
| Rust no-default-features | 1,861 passed; 27 existing skipped/ignored cases; 126.076 seconds execution. |
| Python | 441 reported tests across 21 unittest commands; every command passed. |
| Independent Ubuntu 24 release | 17,842,176 bytes; SHA-256 `2d021297b50af9eb35bd4d698a90991ec410b2922b707155a506e42125b87442`; release command 212.213 seconds. This is distinct from the desktop engine-qualified binary. |
| Normal JavaScript MCP and independent reference | 1 actual MCP integration test; Babel/manual-golden agreement on 17 imports, 16 exports, 12 Electron callsites and 4 candidate IPC edges. |
| Native Chrome capture | 11 actual MCP/job/Chrome checks passed, including post-sync publication confirmation and cancellation/recovery. |
| Browser finite differential | 10 selected phase/path/occurrence pairs agree with the Python reference and independent authored bytes/metadata; zero metadata findings. |
| Fixed browser deadline | 6 checks passed: the one-second native deadline causes the original job to fail as expected, with no successful HAR/receipt and confirmed cleanup; same-key observation does not relaunch Chrome. |
| Ghidra real provider | 8 checks passed, including independent GNU nm/objdump comparisons, native decompilation, original-job recovery and cancellation while the native decompiler was observed live. |
| Compatibility checks | Authenticated cached and offline mapping checks pass; strict parity returns the expected 3 because all 229 complete upstream contracts remain open. |


The Ubuntu 24 matrix records source and verification inventories before and after its complete command set and freezes its independent release, identified by SHA-256 `2d021297…` above. Separately, the desktop release-only continuation freezes `4da25b9b…` from the same final source and verification inventories. All final real MCP, browser and Ghidra external qualifications use that desktop binary. The two build outputs are not interchangeable evidence. Generated compatibility evidence is refreshed afterward and checked again.

The build command matrix includes formatting, both all-target feature configurations, strict Clippy in both configurations, zero-retry nextest suites, 21 Python commands, a cached upstream reference check, an offline mapping check, the expected strict-parity refusal, and the release binaries/examples build. Expected refusal is not counted as upstream parity.

## Qualification history and environment

The original desktop 35-command run preserved 34 completed gates: 1,885 all-feature Rust tests, 1,860 no-default Rust tests and 441 Python unittest tests across 21 commands passed. The final release build did not complete before the original two-hour outer limit. The job remains timed_out with exit 124. Its missing inputs-after.json and qualification.json were not reconstructed; a separately named terminal-observed-inputs.json verified the original source and verification inventories after termination and before the fixture correction.

An independent first run on the bare Ubuntu 26.04 host preserved 1,879 passed and six failed all-feature Rust tests. Two failures exposed fixtures that assumed admission order was timestamp order despite millisecond timestamps and random request IDs. Three affected fixtures now use explicit increasing timestamps, and a new three-record regression checks equal-millisecond reverse admission and independent hot-history cursors. The production audit implementation, random identity generation, original assertions and budgets are unchanged. Exact timestamp ties were not recorded in that failed run, so the diagnosis distinguishes the demonstrably unsupported fixture assumption from the unobserved original tie values.

The other four failures occurred at the existing SSH observation pool precondition: the Ubuntu 26.04 /usr/bin/false is a symlink to a multi-call executable with 116 hard links and a size above the existing 1 MiB admission ceiling. The fail-closed regular-file/no-symlink/root-owner/single-link contract was retained. The replacement functional matrix uses a pinned Ubuntu 24 image whose standalone GNU false, SSH and shell binaries match the qualified desktop identities. The bare Ubuntu 26.04 opt-in observation pool is still unsupported by that contract; a passing container run is not described as having repaired the host layout.

The first Ubuntu 24 container matrix (r2) passed the previous six failing cases and preserved a new result of 1,882 passed / 4 failed / 1,886 run (39 existing skips). Its temporary directory was mounted with noexec, so four tests could not execute their own temporary sudo/SSH fixtures. The original mount facts and errors establish this environment mismatch. A separately recorded r3 run changes only this qualification tmpfs to explicit exec, retaining nosuid/nodev and the original isolation/resource controls, and first executes a bounded owned shim as a precondition. It reuses the prior Cargo cache/target and is not a cold-build performance comparison. The r2 failure remains retained; no product test, expected exit, retry budget or production admission rule is relaxed.

The Ubuntu 24 functional matrix uses a dedicated target and Cargo cache, read-only source/toolchain mounts, four CPUs, 16 GiB memory, the default Docker syscall/capability boundaries and an explicit tmpfs for temporary test storage. This container run establishes functional results, not physical-filesystem performance. The earlier [physical-ext4 query-budget qualification](../qualification/rea-audit-ext4-20261103-r1/README.md) retains its own historical source/binary scope; no new speedup or latency guarantee is inferred from it here. A separate desktop release-only continuation builds and freezes the identical final source candidate for real local engine tests; neither original failed run is relabeled successful.

## Defects closed in this increment

| Blocker | Correction and bounded evidence |
| --- | --- |
| Ghidra dynamic-ELF import failed through the unnamed byte provider | Revision 2 uses a fixed named provider and an explicit versioned bridge. The final release passes real inventory, function, xref, decompile and lifecycle gates. Legacy bridge bytes remain independently pinned. |
| JavaScript worker input/node accounting and cancellation | Close stdin after sending the bounded request; enable real semantic-node accounting; propagate the MCP cancellation token and explicitly kill/wait for the owned worker. The unchanged five-second stopped-worker harness passes on the final release, with successful same-owner recovery. |
| Browser state could be finalized before all relevant observations and close processing | Require the exact request-occurrence set, terminal loading events and gate acknowledgments, observe the original target through browser close, drain the pipe and recheck settled state. The final native capture completes all 11 gates. |
| Missing HAR body was incorrectly assigned a known zero length | Omit both text and size when the representation is missing. All 10 selected native/Python observations match the independent authored body and metadata oracle. |
| Receipt could imply confirmation of its own later directory sync | Keep the receipt last and require the original successful durable job plus its post-sync complete event. The final real driver checks this explicitly. |
| Audit fixtures assumed admission order was a strict timestamp order | Supply explicit increasing timestamps in three fixtures; add a three-record equal-millisecond cursor regression. Production retention and original assertions/budgets are unchanged; both full Rust feature configurations pass. |
| Qualification environments did not meet existing execution preconditions | Retain the Ubuntu 26 standalone-tool rejection; use pinned Ubuntu 24 tool identities. Preserve the first container's noexec failure and run the complete corrected environment with an executable owned temporary shim preflight. No test is skipped or reclassified to make the matrix pass. |
| Local native success could be confused with full REA equivalence | Keep the frozen published catalog and source/test/receipt bindings, preserve pre-update snapshots, and continue rejecting full parity with expected exit 3. |


Historical failed runs remain in their original evidence directories. In particular, the old JavaScript v6 binary left the same pidfd-identified, SIGSTOP-stopped worker alive after an ordinary MCP cancellation notification. Its fixed five-second observation ended at 5.009520225 seconds with the worker still stopped. Finally-block manual cleanup is retained as cleanup evidence, not a successful cancellation result. The corrected release is tested by the unchanged harness.

## JavaScript contract

Admission accepts 1–16 explicitly named regular sources, at most 1 MiB each and 4 MiB in total. Parsing has a real 200,000-node per-source limit, 10,000 observation/edge limits, 256 rows per page, and a 1 MiB encoded response limit. The isolated worker receives the selected content over stdin with a cleared environment and root working directory; controller environment and credential configuration are not forwarded to the worker. Admitted source content and logical metadata remain the worker's input.

Worker limits include a 20-second absolute wall-clock deadline, 12 CPU seconds, a 768 MiB address-space limit, 64 descriptors and bounded stdout/stderr. Linux startup binds the worker to its parent lifetime and applies the existing syscall restrictions after reading input. These controls are not a claim of a complete namespace/UID sandbox.

Normal MCP cancellation propagates the request token through admission and worker collection. An already-started bounded file read keeps its semaphore permit until it completes. During parsing, cancellation or output/deadline failure explicitly kills and waits for the same owned Child before returning and releasing the permit. Arbitrary future drop or runtime exit retains the existing kill_on_drop/Tokio behavior and is not independently qualified as synchronous reaping.

The graph identity binds the sorted source set, source bytes, grammar/module selections, Oxc version and fixed graph profile. It does not hash every result row. Future changes to semantic extraction or ordering must revise the profile.

The independent Babel/manual-golden check covers the finite selected fixture projection. Candidate IPC edges are static observations, not proof of runtime IPC connectivity or complete JavaScript semantics.

## Ghidra contract

Absent bridge_revision preserves the exact legacy inventory bridge and old serialized profile identity. Analysis requires explicit revision 2. The legacy bridge byte digest is guarded independently.

Revision 2 admits functions, function, xrefs and decompile. Entry addresses must already use the admitted canonical lowercase form, analysis is limited to four fixed analyzers, function scanning is capped at 4,096 and output rows at 128. Analysis and decompilation have separate finite budgets; decompiler preview and retained output are bounded.

The final release qualification uses owned ELF fixtures and independently obtained GNU nm entries and objdump call sites. All eight real-provider gates passed, including native-decompiler cancellation and controller recovery. The earlier 141-input decompiled-C comparison remains a separate historical finite experiment; it was not rerun or counted as an additional final-release gate. A returned C listing remains a Ghidra observation: source_semantics_validated and REA Evidence compatibility are false. Engine installation identities are recorded and checked, but installed dependencies are not a sealed executable closure. Scratch sampling is not a filesystem quota.

## Native browser contract

The native CLI admits a hash-pinned manifest and snapshots explicitly named regular resources through descriptor-relative access. It launches one private Chrome with CDP pipe transport and an owned temporary profile, then captures two finite phases through owned loopback origins.

A phase completes only when the expected URL-occurrence multiset, loading terminal events and gate acknowledgments are settled. Browser.close keeps observing the original target, drains through a clean EOF under the original deadline, and rejects malformed/truncated protocol or unconfirmed state. Final fixture counters are read only after Chrome cleanup and fixture-thread joins.

Complete, empty, base64 and missing bodies remain distinct. Missing bodies omit both text and unknown size. Saved representation replay and the native/Python comparison qualify selected retained bytes; generated harness fields and random local origins are outside that equality projection.

The lifecycle retains exclusive ownership of the original waitable Chrome leader until its original process group has no live members, then reaps it. Default SIGCHLD, exclusive reaping and visible proc state are preconditions. Descendants that create another session are outside that ownership guarantee.

Publication uses create-only same-directory links and fsync, with the receipt published last. A receipt may attest already-synced HAR files and their directory. Its own directory-sync confirmation is the original job's successful terminal state plus the post-sync complete event, avoiding a receipt that claims to have already confirmed its own future publication. Visible but unconfirmed publication remains an error.

## Compatibility and remaining migration work

The reproducible ledger separates the published npm catalog, pinned Git source and later observed upstream source. Five source-only declarations are not silently added to the 229 published tools. A local mapping check validates the stored catalog projection, mapping, schemas, native handlers and source/test bindings; it explicitly does not reverify raw upstream authenticity. The cached full check performs that separate validation.

The 418 finite npm Evidence reference cases and 20 rejections do not establish behavioral parity for every tool. Existing preview records cannot acquire REA Evidence identity merely by changing their label.

Remaining full-migration work includes absent operations and incomplete contracts, semantic and retained-view compatibility, ASAR/source-map and broader JavaScript workflows, complete native workflows, and device/runtime families. Existing device and fixture observations must be reused accurately; a blanket claim that no hardware or corpus is available is incorrect. JEB licensing and unqualified engine/platform combinations remain separate constraints.

## Evidence

- [Final desktop release build and fixture application](../qualification/rea-next-release-build-20261104-r2/README.md).
- [Complete Ubuntu 24 r3 functional matrix](../qualification/rea-next-ubuntu24-matrix-r3-20261104-r1/).
- [Final JavaScript MCP and Babel/manual-golden qualification](../qualification/rea-javascript-final-release-20261104-r1/README.md).
- [Final fixed-budget MCP cancellation](../qualification/rea-js-cancellation-final-release-20261104-r2/README.md) and [earlier combined-debug evidence](../qualification/rea-js-cancellation-combined-debug-20261104-r1/README.md).
- [Final Ghidra provider qualification](../qualification/rea-ghidra-final-release-20261104-r2/README.md).
- [Final native browser, differential and deadline qualification](../qualification/rea-browser-final-release-20261104-r2/README.md); the [retained Python reference](../qualification/rea-native-browser-20261104-r1/python-reference-r1/qualification.json) is identified separately.
- [Original desktop partial matrix and timeout](../qualification/rea-next-desktop-partial-20261104-r1/), [bare-host ROG failure](../qualification/rea-next-rog-failure-20261104-r1/) and [Ubuntu 24 environment/dependency preparation plus r2 failure](../qualification/rea-next-ubuntu24-environment-r2-20261104-r1/).
- [Compatibility ledger and verification instructions](compatibility/README.md), with the [original prebuild inputs](../qualification/rea-next-compatibility-prebuild-20261104-r1/) retained independently.

Original on-disk job records, requests, output and terminal witnesses preserve their exact bytes, including JSON integer representations, and are checked through artifact manifests. Tool-return summaries are separately identified as derived observations. For the Ubuntu 24 archives, `original-jobs/` in the r3 bundle is the raw job-record authority, including the original r2 failed job; the [provenance index](../qualification/REA_UBUNTU24_EVIDENCE_SCOPE_20261104.md) distinguishes those records from derived tool observations. Compiled runtime/engine binaries and controller state databases are excluded from the repository evidence; their original paths, sizes and digests remain recorded. Cancellation of the Ghidra job left one private scratch directory that the harness removed after terminal confirmation; it is not claimed as automatic runtime scratch disposal.

## Publication verification

This source-bound local qualification report is committed before publication CI. [PR #84](https://github.com/TrillionniumFoundation/hepta-runtime/pull/84) records the actual published head, prospective-merge parents, checkout identities and terminal Actions links. A previous green head or a local native qualification does not substitute for those three current publication gates. CI results belong to their published Git identity and are recorded there without changing this source snapshot merely to insert its own later CI result.
