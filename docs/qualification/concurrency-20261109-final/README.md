# Final source concurrency audit — 2026-11-09

The supplemental implementation is committed as
[`09464736e815940ee4c5bf91d36f6c84a3faee2c`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/09464736e815940ee4c5bf91d36f6c84a3faee2c),
with Git tree `47d589e794d4cba3104b477af2ee752330231753`.
**The final ROG Rust gates, Mac build, both native acceptance probes and
activation of this commit have completed successfully. An independent read
verified the mapped runtime image and both healthy, unbounded tunnel clients.
Hosted CI was still in progress at its last observation.**

Recovered receipts also establish the separate history of the earlier
`826c462699a27ed6afa83298440acb732b726af5` release: two failed activation
attempts were followed by a successful recovery before this supplemental
release replaced it. Those earlier outcomes retain their own source and binary
scope. The final results below bind `09464736` directly.

[evidence.json](evidence.json) contains the compact source, artifact and outcome
bindings. Private configurations, authentication values, local paths and raw
receipts remain outside this public directory. The
[initial audit](../concurrency-20261109/README.md) and
[r4 source checkpoint](../rea-concurrency-source-projection-20261109-r4/README.md)
retain their original bytes and historical observations.

## Supplemental gates removed

The review following `826c462` found count gates that had been misclassified as
retention or per-job resource boundaries. Retained records can include active
work, and counting them can also prevent every later admission after enough
completed work. These gates were omissions from the original cleanup.

| Area | Former gate | Supplemental behavior |
| --- | --- | --- |
| Isolated systemd job | 64 processes/threads, including the supervisor | New units use `TasksMax=infinity`; DynamicUser, permissions, CPU, memory, timeouts and identity checks remain. |
| Isolated job registry | 128 retained directories, including active jobs | New admission neither counts nor removes other jobs' original records and terminal receipts. |
| Native and target Python searches | 1024 total retained receipts | The total-receipt admission gate is removed; existing receipts remain retained. |
| Resident weight sessions | 1024 retained session intents | New sessions are not refused because of retained-intent count. Original ownership intents remain intact. |
| Legacy Python facade requests | 4096 pending or retired IDs | Pending IDs and late-response tombstones remain complete without a count admission gate. |
| Unused retention module | Unregistered count-limit source and tests | The two dead files were removed. Historical qualification and source references were preserved. |

The commit also adds the native HTTP readiness probe and its regression tests.
The probe consumes the matching JSON-RPC result on a persistent SSE stream
without waiting for EOF. Acknowledgments and unrelated response identities do
not establish completion. The detailed execution contracts are in
[Concurrent execution](../../CONCURRENCY_POLICY.md).

## Verification of the supplemental source

| Gate | Observed result | Scope |
| --- | --- | --- |
| Final ROG all-features/all-targets suite | 2,395 passed, 0 failed, 40 skipped; 146.453 s test execution | Exact committed source; all 1,452 inputs unchanged before and after. |
| Actual repository jobctl sources, built with an isolated validation manifest | 53 passed, 0 failed, 0 ignored; test execution 2.54 s | Real helper and included source modules; no systemd deployment. Source hashes were unchanged before and after. |
| Target Python search worker | 17 passed; 26.276 s | Search receipt/admission regressions. |
| `full_operator_*tests.py` | 77 passed; 52.661 s | Facade cancellation, legacy request identity, session and recovery behavior. |
| Computer operator composition | 6 passed; 5.854 s | `chatgpt_computer_operator_tests.py`; these are composition tests. |
| Native HTTP readiness probe | 5 passed; 0.513 s | Matching response and persistent stream behavior. |
| REA ledger tests | 29 passed | Source mapping and qualification boundaries. |
| REA mapping / strict parity gate | Exit 0 / expected exit 3 | 229 OPEN, 0 qualified; raw-reference authenticity NOT_REVERIFIED. |

The three Python suites total **100 passing tests**. Their original executor
outputs were observed during this work, but separate raw log files were not
archived; this record asserts no invented log hashes. The five probe tests are
a separate observed result. The jobctl receipt and original test log were
retained and hashed: log SHA-256
`9bb7504d9fbd5be3f9fec6c93e38d3b550b7f183c6e34912159e2ffd32ae0766`.
The bound helper source is
`575e7b74f26f7ddada5f19ffafd6b9597307b565ac69de3c8091346fa516dc81`.

The cloud whole-crate check had **two failed attempts**. The first exited 101
with `No space left on device` (OS error 28); the second exited 101 after the
compiler received SIGKILL (signal 9). Their original status and log hashes are
recorded separately. Neither is a passing gate, and the SIGKILL is not assigned
an unobserved cause. The later ROG run provides a separate successful result:
1,452 inputs and all 425 source files matched before and after the run, with
zero source changes. Formatting, checking, strict Clippy and nextest all exited
0, taking 1.710 s, 33.899 s, 41.929 s and 554.175 s respectively. The last figure
includes compilation. The original summary records **2,395 tests run and
2,395 passed, with zero failures and 40 skipped**, across 19 binaries; test
execution took 146.453 s. The original validation job succeeded with exit 0
and complete, durable, confirmed output. The skipped cases retain their
existing qualification limits. The source manifest SHA-256 is
`91ffe46e62722e26e040c894e30f423052c5371db7efb14e343f5378441d2200`;
the canonical source-tree digest is
`776dfffdf19f6d4d3009e027166b7c5ec20739e29e0b7c906fd38af69a11f6b2`.

The earlier implementation's hosted
[CI run 42623379852](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42623379852)
completed successfully for `826c462`. It does not verify `09464736`. A passing
hosted CI result for the new commit is not attested by this checkpoint.
[Run 42634535094](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42634535094)
was queued at the earlier observations and had advanced to `in_progress`, with
no conclusion, at **15:02:13 UTC**. The subsequently observed jobs were at
“Test in isolated processes” for the prospective merge and “Install pinned
nextest” for the exact head. No failure was observed, and neither job was
reported as passed. This hosted CI result is the only remaining pending gate
in this record.

## Recovered deployment history of the earlier release

The original audit recorded activation as launched but unconfirmed when the
observation channel was unavailable. The subsequently recovered original
receipts establish this sequence without changing those earlier observations:

| Attempt | Retained result | Tunnel progress |
| --- | --- | --- |
| Original activation | `rollback_failed`; original job failed with exit 1, with complete, durable and confirmed terminal output | 0 touched, 0 verified. |
| Audited attempt | `rollback_failed`; `launchctl bootstrap` returned exit 5 | 1 touched, 0 verified. |
| Audited-r2 attempt | `completed` | Both tunnels touched and verified. |

The failed attempts remain failed. The later completion is a distinct attempt.
Their receipt hashes are:

- Original: `ee8daf764995b0c2437fb4c13754c67268f4f3f1d246408d0d4fd6df91eca359`.
- Audited: `a00eedc2df59095aa78863a659247fffe379158c3354f1bbcd2abd8f49e4874f`.
- Audited-r2: `d73530c10ccbf6763e4cead0cf7adf0a360aef93c5de1c7696c6153f4d80ccc7`.

The recovered build receipt binds the earlier runtime to SHA-256
`8969ebef564d162fdeb539be3b59fce9c511550f44eb4282655c3fc06d85f989`
(16,837,440 bytes), built successfully in 179.237 s with Rust 1.98.0 for
macOS arm64. The complete original Mac and ROG proof files were recovered and
their full-file hashes verified. Each contains 75 passing checks, 32 independent
jobs, a client peak of 32, no failures and zero new-key retries. These proofs
bind the same earlier runtime binary.

A separate read-only observation then verified the mapped runtime image,
controller service, unchanged runtime configuration, authentication token and
service definition. Both tunnel binaries matched SHA-256
`754bfa627d6fb2f779daa42e91782af85ce1b01a3bfbae99065ac82326e3f7e1`.
Both reported `live=true`, `ready=true`, dispatcher `state=accepting`,
`details.pool_limit=0` and `limited=false`; their control planes reported
`state=polling`, `status=ok` and `limited=false`.
The independent observation's SHA-256 is
`813f8331e120596255250400d20caf92ee4a6c10d35ffa702e87cef7ab3271fe`.

The post-switch preservation receipt counted 49,790 controller records and
10,028 worker requests, with zero original records missing or changed.
Only these counts and the artifact digest are published here.

## Linux helper deployment decision

The five configured Linux hosts use operator execution. A read-only inventory
used the existing noninteractive sudo authority and inspected each host as
UID 0. The helper executable, root job policy and helper sudoers file were
absent on all five. No helper processes or active isolated `hepta-job` units
were observed; the process scans had zero permission denials.

| Host | Architecture | System libc | Account default Rust | Existing helper / active isolated units |
| --- | --- | --- | --- | --- |
| rog | x86_64 | glibc 2.43 | 1.94.0 | Absent / 0 |
| pocket4 | x86_64 | glibc 2.43 | 1.95.0 | Absent / 0 |
| x230 | x86_64 | glibc 2.39 | 1.95.0 | Absent / 0 |
| desktop | x86_64 | glibc 2.39 | 1.95.0 | Absent / 0 |
| ai395 | x86_64 | glibc 2.43 | 1.99.1 | Absent / 0 |

These Rust versions are the versions selected by each account's ordinary
command environment, not an inventory of every private task toolchain. The
five original inspection jobs all succeeded with exit 0 and complete, durable,
confirmed output. Their original stdout byte hashes are retained in the JSON.

**The Linux helper deployment target set is empty, so deployment is a no-op.**
No unrelated helper, root policy or service was newly installed. Historical
registries on rog, pocket4 and x230 were preserved. Existing jobs and services
were left unchanged.

## Final native validation and live activation

The new Mac candidate for `09464736` built successfully in 151.05 s with exit
0. Its runtime SHA-256 is
`ad7850e6f07eb8311895602e684fc0fc89a40cad81b0b32ef1a08caddf2775af`.
The original build receipt has SHA-256
`b5c8b4ef69bcf7d3a1fc22a4d768b8bb66dfd763bcbcc1b2768e65e35344bb13`;
the build-and-acceptance receipt has SHA-256
`14bb4649b8f37a0a59bcc3bc4bfc6838abf33e9df54a8b5a7b40f35665d14f15`.
The candidate receipt's `activated=false` records its state before rollout;
the later activation receipt establishes completion separately.

| Original native report | Passing checks | Independent jobs | Client peak | Original SSH child peak | New-key retries |
| --- | --- | --- | --- | --- | --- |
| Mac | 75 | 32 | 32 | 32 | 0 |
| ROG | 75 | 32 | 32 | 32 | 0 |

Both complete original reports were recovered, their full-file hashes verified
and their fields parsed directly. Both report completion, no failures and
`live_state_opened_by_candidate=false`, and bind the same `ad7850e6` runtime.
Their exact counts and peaks were also independently reread on the host.
The report hashes are:

- Mac, 730,553 bytes: `eb1506c632314bf39ec05e1213e9e710cee16627fe09357b8c1bcfb8b37c78b2`.
- ROG, 720,597 bytes: `34c85285e497340c1d74550c696dd0d4e3e6a01fd3a3be4e1b69806d3a3ec465`.

The first new Mac preparation attempt failed during `git fetch` (subprocess
exit 128) before compilation. Its original durable job failed with exit 1 and
complete, durable, confirmed output. Those failed receipts remain separate
from the later successful build.

**Activation completed at 14:59:04 UTC**, using the reviewed plan with SHA-256
`931b5632f379e450253524b4bb0ce2ee7ffb7048f6ccf8838f5b65df228ff6ce`.
The activation receipt binds `09464736` to the mapped `ad7850e6` runtime and
records all three service replacements as graceful, with no forced replacement
after a grace timeout. Its SHA-256 is
`9e124160a1afd3243bfdf5037ae367b00bce2ba2238d2b44984fa731c3935ab6`.

The initial activation request encountered an MCP transport error. Repeating
the admission lookup with the **same idempotency key** returned the original
job with `reused=true` and `retried_launch=false`; no second activation effect
was created. That original job then had `state=succeeded`, exit 0, complete
and durable output, and confirmed terminal publication. The reconciliation
receipt has SHA-256
`8585ccec3bd6589a33c766d87500f9505665f2ef41d9f7f22849911e93fab713`.
The build, stage and independent postcheck jobs also have successful original
terminal receipts.

An independent read-only postcheck verified the mapped runtime image and the
manifests and three binaries for both releases. Runtime configuration,
authentication material, service definitions, tunnel configurations and the
tunnel binary retained their original bytes. All **49,790 controller records
and 10,028 worker requests** were individually checked, with **zero missing
and zero changed**. Both tunnels were live and ready, with dispatcher
`state=accepting`, `pool_limit=0`, `limited=false`, zero failures and zero
timeouts. Their control planes were `state=polling`, `status=ok`,
`limited=false`, with zero consecutive failures. The postcheck receipt has
SHA-256 `8f84dbc926ed03d6203eba27712078754f8e213132cbe15d23b78ca24c6948a9`.

A separate real connector readback reported
`limits.concurrent_execution=unbounded_by_runtime` and all seven configured
host aliases in operator mode. Its retained tool-result wrapper has SHA-256
`063e4bddaa4913eb5d79292989bbd967a48a0eeaca42a3eb3ff6489a798fa632`.
The source and binary identity come from the activation and mapped-image
observations; the configuration response alone does not establish that identity.

The final source and deployed binary are therefore directly verified by this
record. Hosted CI remains unattested pending its own conclusion. The 40 skipped
Rust cases and all 229 OPEN REA entries retain their existing boundaries;
no REA operation has been promoted to qualified.
