# Candidate C2: finite P0–P5 observations, 2026-11-06

## Decision

The fresh C2 runtime completed the finite regression, public Evidence, Provider,
recovery and checkpoint profiles recorded below. Full REA replacement and
production qualification remain **HOLD / NO_GO**: **0 of 229 published operations**
has complete replacement qualification. The source mapping is **23 partial
operations, 19 related facilities and 187 absent implementations** across 18
families. The 35 discovered native source interfaces are a separate denominator.

The original target is the authenticated `rea-agents@6.8.0` npm archive
`8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`.
Its 229 published operations and the pinned upstream Git source's 234 declarations
remain distinct; package/source equivalence is not established. The complete
mapping and individual open gates remain in
[the capability map](compatibility/REA_6_8_0_CAPABILITY_MAP.json) and
[the qualification ledger](compatibility/REA_6_8_0_LEDGER.json).

This document records fresh C2 results. [Candidate B2](B2_OBSERVATIONS_20261106_679CCF.md)
and the earlier [integration record](P0P5_CONTINUATION_20261106_679CCF.md) preserve
their own source/binary combinations and failures. Publication commits containing
this report and the evidence archive do not relabel the runtime's build commit.

During publication preparation, the shared PR independently advanced to
`b3bac9e47fd09ee2c6bb0d62802bd55b7662f366`, diverging from the C2 source.
The isolated C3 integration preserves both source histories. Its changes and any
future results are separate from C2; neither this report nor C2's tests qualify
that merged source. The C2 evidence publication is first retained on its own branch.

## Frozen source, runtime and execution inputs

| Input | Exact identity |
| --- | --- |
| Runtime source commit | `249639e5ef33de444abb5c506cb089de31e20fce` |
| Runtime source tree | `51bac4e4095f35bae0149523f773a081f184bda4` |
| Runtime | 51,604,432 bytes; SHA-256 `c02d4b9ede2206cf8abb6603ca59fab05acb13e54a2d2be339a52140e9126ec4` |
| Binding | 5,047 bytes; SHA-256 `00a28a67d0cb3bb12acd3ebc1200f67f149159c37ffd8a0cefb48d3be3b196c7` |
| Selected source | 1,455 files / 87,374,819 bytes; manifest identity `43760e83948f24f6d8c233bf41104a0efddcea0ad4a5a8ec5b858c7e52234957` |
| Toolchain/build | Rust/Cargo 1.95.0, offline, dev profile, optimization level 1, debug assertions and overflow checks enabled, debuginfo 0, nonincremental |
| Matrix summary | 55,388 bytes; SHA-256 `a2b731a340d230139c08bb4766aefbf7fea18e4be222b10e546f997185c03792` |
| Original matrix outer | 17,328 bytes; SHA-256 `485a8c804f2b4ed1e29b155cb8cf6bff0fa525de46190fef150c99237b5417c7` |

The source repository stayed clean at the frozen commit. Selected file contents,
modes, compiler artifacts and source monitors were consumed again after the
relevant runs. The matrix's elapsed time is a regression execution observation;
it is not a performance comparison. This dev build cannot establish release-build
or production cost behavior.

## Fresh regression and core/Evidence gates

| Gate | Actual C2 observation | Interpretation |
| --- | --- | --- |
| Strict Rust matrix | Nine stages passed, including formatting and strict Clippy under both feature configurations | Original terminal successful/0, complete and durable |
| All features | 2,350 passed / 40 skipped | Skips are unexecuted gates |
| No default features | 2,320 passed / 28 skipped | Separate configuration and actual terminal |
| Original corpus gates | Four separately invoked selected tests passed | Original generated identity, finite numeric corpus, fractional Evidence and rejected schema |
| Python regressions | 621 passed across 20 groups; zero skips/expected failures | Independent consumer verified all 40 original logs, source inputs and original outer |
| Public replay | 116/116 parsed responses, Evidence states and complete CallToolResult objects equal | Raw transport frames: 0/116 equal |
| Import profile | 118/118 comparisons passed; all 38 JSON errors matched exact UTF-8 text and member order | Four plain SDK exceptions matched separately; JSON ordering is not applicable to those four |
| Strict overflow profile | 22/22 comparisons passed; both overflow errors matched exact UTF-8 and member order | B2's 20/22 failure remains preserved |
| JavaScript declarations | Seven cases matched both actual Node and unmodified REA; seven runtime contracts and seven additional raw workers completed | Finite declaration profile |
| Explicit local GNU tests | Two separately selected ignored tests each executed once and passed, with zero ignored tests in those invocations | Actual bound library-test artifact; no fresh Cargo build in the gate |

The core gate handoff is
`c2-public-gates-handoff-r1.json` (9,062 bytes, SHA-256
`4ee78324379a708ba812b169c5b1d8751967402a8602e33540de597b08009e33`).
Its original per-gate outer records include the actual execution working directory
and limits. The independent Python qualification is 830,622 bytes, SHA-256
`215cd9c08b86995cf844947d9e727b414465439ef87f28e63288579bf6c06849`.

These finite profiles establish their declared comparisons. They do not establish
all possible schema inputs, numeric bit patterns, full raw-protocol equality,
complete cancellation behavior or all 229 operations.

## New source changes and their evidence boundaries

C2 integrates the UTF-16 source-map correction, bounded Ghidra instruction
operation, exact observed overflow-error projection, and the reviewed checkpoint
upgrade and multihost recovery runners. The initial C1 strict Clippy failure is
retained; C2 contains its narrow comparison repair and has its own complete matrix.

The source-map work adds explicit CRLF, CR, LF, U+2028/U+2029, astral-character
and embedded-content-budget handling. The component evidence retains 26 actual
producer maps and 133 observation points: 121 exact matches, six shared refusals
and six explicit surrogate gaps. Eleven direct offset observations comprise
seven admitted and four outside-range cases. The 23 focused Rust tests and
producer provenance retain their own identities; their historical executions
are not relabeled as fresh C2 runtime processes.

The overflow projection recognizes only the observed operation, limit, shape,
message and identifier contract. Unknown forms retain the existing fallback.
The two original/native error captures remain byte-pinned with the implementation.

## Ghidra instruction comparison and launch deviation

The actual unmodified REA Ghidra bridge and C2 native adapter were compared on
two windows of an owned ELF. Both windows agreed on addresses, instruction text,
function symbol and function body: 22 rows covering 56 instruction bytes, with
a separate GNU nm/objdump cross-check. Native execution included three original
jobs, five selector refusals and two restart readbacks.

The limitation arrays agreed in **0/2** windows. Native output carries three
bounded-analysis limitations; the distinct original/native outer representations
also remain recorded. The all-category comparison therefore remains false.
The reference was the unmodified REA launcher/bridge, not its public MCP/Evidence
path. Borland SEH, terminal-call heuristics, disjoint/multispace bodies, the actual
maximum row/text limits and cancellation-specific cases remain unobserved.

There was an execution-contract deviation: the original run used the frozen
preparation directory as its cwd and included nice=10, while the predeclared
launch used the checkpoint evidence directory without that added setting. The strict original consumer failed. A separately
reviewed, post-run consumer then pinned that one actual original job and outer
SHA-256, retained all semantic and cleanup checks, and reported finite observations
with `predeclared_launch_contract_passed=false` and `qualified=false`.
No engine rerun or rewritten original receipt was used to turn that failure into
a predeclared pass.

The post-run independent report is
`ghidra-instructions-c2-consumed-r3.json` (25,665 bytes, SHA-256
`069f1f7e5c205a15373e24d946685b962c7068297447fb5688eb8b8941a18010`).

## Fresh Provider and host lifecycle observations

| Profile | Actual C2 result |
| --- | --- |
| Ghidra Provider | 11/11 checks; nine original job terminals |
| JADX | 8/8 checks; three original job terminals |
| Chrome | 14/14 checks; four original job terminals, eight environment negatives and ten receipt-schema controls |
| APK three-way fixtures | 19 positive, one forged and four malformed cases |
| APK public MCP | 6/6 checks; two controller cleanups |
| Actual AAPT2/signing/malformed-input generation | 14 checks and 14 original child terminals: 12 successful exits and two expected ordinary refusals |
| Desktop/x230 recovery | 13 phases, 45 RPC pairs, two original jobs and three private controllers |
| Persistent GNU session | 12/12 checks; four real GNU jobs plus one synthetic lifecycle job; three controllers and five complete original terminals |
| Actual GDB cores | Two cores of 636,680 bytes each; two complete payload matches and five native boundary checks; zero of two whole-helper envelope matches |

The Provider composition is `candidate-c-r2/provider-gates-c2-final-r1.json`
(5,771 bytes, SHA-256
`1c71edd2aae977daf82e725410ba8c58930902306f16abc9fb526b15e5667e2d`).
Recovery is `candidate-c-r2/multihost-recovery-c2-final-r1.json`
(7,764 bytes, SHA-256
`e09568fac9c8d693fd7de513c6e89c7d5e4c204c67800e418a72f3a9f9c6943b`).
The independent GNU report is 3,940 bytes, SHA-256
`ddd2c92c956f43f7cf6e296b520e69c8f237b30cbf65ee127310da0fc54b4531`;
the independent GDB report is 68,465 bytes, SHA-256
`0a3edda8dc05134a5f9f1e491d27497d48191a75d14ec35934de744249365fe5`.

Chrome's injected constructor observations establish that injected run's exec
boundary. The uninjected capture and cancellation executions remain separately
identified. Releasing these owned workloads establishes that these task processes
ended; it does not establish that the entire host had no background activity.

The six Provider groups ran against the fixed C2 binary and their pinned installed
engine/JDK inputs. Their independent consumer retained the actual original logs,
job identity, ordinary errors, cancellation/timeout/crash observations and cleanup
within each profile's declared scope. Installed inputs are bounded inventories;
they do not attest every operating-system loader dependency.

Multihost recovery used task-owned desktop and x230 roots. Actual network partition,
host reboot, storage failure and a real engine workload across both hosts remain
outside the observed profile. The GNU synthetic job is lifecycle evidence only;
it is not counted as GNU semantic execution.

Recorded-core validation used task-owned generated cores. It did not attach to an
existing user process or change global core-pattern/ASLR settings. Two whole-helper
envelope comparisons remain false. Public GDB routing, optional enrichment,
complete debugger parity and production qualification remain open.

## Checkpoint upgrade, rollback and authorization

The actual sequence was candidate A → C2 → A → C2, under one generated operator
credential and complete policy binding. Four original server instances processed
17 HTTP tool calls. The independent consumer closed eight facts and rehashed
1,712 input files. Its publication contains 220 indexed members and two index
metadata files, or 222 actual regular files.

The sequence preserved default-empty sessions, explicit recovery, three Unknown
history entries and five mixed-origin records, unchanged checkpoint identities
and bytes through rollback, real -9/wait/pidfd/group-exit observations, and the
absence of the generated token in retained public outputs. Three task-owned source inputs
were actually deleted after the old/new server lifecycle conditions were met.
There were no failed readiness polls in this C2 run.

Observed private HTTP whole-server catalogs contained 100/103/100/103 entries
across the four instances. These counts are distinct from the 35 native source
interfaces and the 229 original public tools. This profile did not observe a stdio
catalog. The finite sequence does not qualify every version transition, storage
failure, deployment or rollback procedure.

The final handoff is `checkpoint-upgrade-r1-handoff.json` (5,781 bytes, SHA-256
`85b888bfb12425c753554317761768cfd7d34d8a36ad4fe50aded588b01c959f`).

## Cost profile and its limits

The fixed **512 MiB preflight failed and is closed**. The original outer
`1a1b09e56c8-fc05-71c3` ended with exit 1; its complete durable stdout/stderr
and source-guard result are retained. Three of four planned units started.
Both small-session units locally completed five calls. The first original REA
large-workflow call, `import_evidence_bundle`, returned an application-level
`resource_constraint` error. The native large-workflow unit did not start.

| Count | Actual observation |
| --- | --- |
| Planned behavior preflight | Four units / 40 calls |
| Started units | Three |
| Actual tools/call requests | 11: ten locally successful calls and one original application error |
| Independent F5 invocations | Zero |
| Measured units / calls / performance samples | Zero / zero / zero |

The original response reported **50,437,404 authentication bytes** and
**40,351,424 available heap bytes** for the 6,298,301-byte seed file, with
12,622,100 projected value bytes and 12,596,602 serialized-JSON UTF-16 bytes.
It refused the import before successful authentication because of insufficient
heap headroom. No OOM was observed, and this observation does not isolate the
cgroup budget as the sole cause. It establishes the original application's
refusal under this exact profile; it does not compare successful large-workflow
behavior or establish a native performance advantage.

The failed request was actually sent and flushed and its 990-byte response was
retained. The worker asserted success before appending its success record, so its
empty `calls` array is not evidence of zero issued calls. The retained wire record,
completed write and original response establish the eleventh request.

The actual worker was reaped with exit 1. The supervisor rejected that terminal;
the adapter subsequently reached its deadline while awaiting the success-specific
pre-cleanup marker. This later timeout does not replace the application error.
The owned original server was killed and waited, its pidfd exited, its process
group disappeared and its readers stopped. Adapter and outer records confirm
cleanup of the exact original unit and unchanged source inputs. The outer job
itself was neither timed out nor cancelled; no automatic retry occurred.

The closed failure handoff is `limited-cost-c2-r2/preflight-failure-handoff.json`
(9,887 bytes, SHA-256
`db32b5d8241a6b74fc022a95f2ce2ea2a11a57cf0c167079f0c84b8aa048b3bf`).
Its original outer is 6,278 bytes, SHA-256
`288655c3d25450155e0a8123e690f39599d81ca28d4ae8a772d10fe98b90ebcf`.
The original response is 990 bytes, SHA-256
`fbb848720fe562c147dd5207ed8ef4f9445363c26a4fc9b576cf3b1457a44e64`.
Thresholds, denominators and budgets were not changed. Any later run with a new
memory budget or new candidate is a separate profile and cannot replace this
failed attempt.

Before that preflight, the third generic lifecycle trial closed both declared
local-fixture cases. The crash case authenticated both original control processes,
stopped and killed them through their held pidfds, and required independent
cleanup to stop the surviving original invocation exactly once. The strict consumer
and final publisher succeeded. All retained trial files total **8,049,925 bytes**
within the 64 MiB limit. These two lifecycle cases contain zero application calls
and zero cost samples. The original controller's SIGKILL terminal remains
`failed/-9`; the publisher's own original terminal is retained separately from
its pre-publication seal.

The first lifecycle trial's delayed start-receipt handoff and the second trial's
unexercised independent active-stop path remain failed attempts with closed
failure audits. Their failures were not reclassified by the third trial.

The declared application workflows contain five small-session calls and fifteen
large-import/export/pagination calls. The behavior preflight plan comprises 40 calls;
the measurement plan comprises 24 fresh slots and 240 calls in three R–N–N–R blocks
per workflow. Here R is the original REA/Node reference and N is the native C2 Rust runtime. There are no automatic retries. Each unit retains its fixed
512 MiB memory, zero swap, 64-task, 100% CPU and 180-second limits.

The accounting scope includes the client, server and descendants, initialization,
startup, shutdown and observed whole-group exit. CPU comes from the original
cgroup's cpu.stat; memory.peak is charged cgroup peak memory, not RSS. Wall time
includes exit-observation delay. Hashing, source guards, compiler/launcher and
independent consumers remain outside the measured group. Hashing warms filesystem
cache, so there is no cold-cache claim. wait4 block-operation counters are not byte
I/O; unavailable io.stat data is not replaced with ancestor counters.

A bounded pre-run desktop observation recorded 48 visible logical CPUs and
ongoing browser/Python background activity. No recognizable Rust compilation was
seen within the observed current-user process set; this does not prove an idle or
exclusive host, exclude other users, or guarantee the entire future run window.
The original observations remain attached to the finite comparison.

Artifact limits are postflight acceptance limits, not filesystem hard quotas.
The accepted aggregate application-run limit is 2 GiB, with the fixed per-slot
reserves. The preceding generic lifecycle trial contains only local fixture events
and zero REA, MCP or candidate calls; it does not add performance samples.

Even a successful finite comparison covers only these two workflows and this dev
build on the recorded host. It cannot establish full REA cost benefit, release-build
performance, device performance or production qualification.

## Preserved evidence and remaining work

The [C2 evidence archive](../qualification/rea-p0p5-679ccf-20261106/candidate-c2/README.md)
is closed and independently verified. It contains **8,356 tar members /
909,550,361 uncompressed bytes**, stored in **three gzip-stream parts /
158,213,599 compressed bytes**. The complete compressed-stream SHA-256 is
`42babdf174ece0ec10cb642374197aa9a69b5b6760b6b7cfc6ea0bbf1703cbb6`.
The [parts manifest](../qualification/rea-p0p5-679ccf-20261106/candidate-c2/parts-manifest.json)
fixes their order and each part's bytes and digest. Each part is at most 60 MiB.

The frozen delivery contains **58 files / 179,522,013 bytes**. Publication adds
two unchanged custody witnesses—the flattened delivery list and the finalizer's
original outer—in `publication-custody/`, giving **60 archive/custody files /
179,539,537 bytes**. These filesystem counts are separate from tar-member counts.
The [flattened list](../qualification/rea-p0p5-679ccf-20261106/candidate-c2/publication-custody/delivery-files.flat.json)
is 11,928 bytes, SHA-256
`59041df8666920c7ca5ce29ecb88c960385b063734b1056a7ed1e4dff3621662`.

The independent consumer verified the exact member set, every member's full
bytes and digest, all parts and the final gzip EOF. It rehashed 7,491 desktop
original/provenance objects, including the 7,443 fixed desktop selection objects;
the separate x230 postflight rechecked all 31 selected original identities and
the exact owned file set. No candidate or engine was executed by archiving.
The [file index](../qualification/rea-p0p5-679ccf-20261106/candidate-c2/file-index.json)
maps original host paths to member names, duplicates and explicit omissions.

| Archive custody role | Actual original job | Complete durable terminal |
| --- | --- | --- |
| Producer | `1a1b0e42514-fc05-73b4` | succeeded / 0; stdout 350 bytes, stderr 0 |
| x230 postflight | `1a1b0e711f8-fc05-73d7` | succeeded / 0; stdout 12,141 bytes, stderr 0 |
| Independent consumer | `1a1b0e88003-fc05-73e3` | succeeded / 0; stdout 289 bytes, stderr 0 |
| Delivery finalizer | `1a1b0ee68b3-fc05-741c` | succeeded / 0; stdout 882 bytes, stderr 0 |

The [completion record](../qualification/rea-p0p5-679ccf-20261106/candidate-c2/completion.json)
is 9,727 bytes, SHA-256
`c33e2dbdf0a2d328c928e7c90f6f00de93a7b8e7f100cc69005d605bce40e89f`.
The independent verification is 50,611 bytes, SHA-256
`7648b3c3bf4d4254927092908103c910193d11425faf8fbc439ca9613510bc33`.
The finalizer's own original terminal is retained separately; its required proof
is not replaced by a pre-publication success claim.

The C2 libtest is preserved as an independent 98,541,896-byte regular file,
SHA-256 `a3769d9ca9453fc03a70f7d026ae4c5e559c3c47afeb122621ca6f04d8856191`,
with nlink=1 and mode 0555. Source bytes before/after copying, full hashes and
file/directory fsync were checked. The copy was not executed. Archive source comes
from fixed `249639e5` Git objects and external evidence; no active BASE or TARGET
file is an archive input. C3 can therefore use the active worktree and TARGET
without changing the preserved C2 observations.

Credentials, generated tokens, signing private keys and whole records containing
their values are omitted from public payloads. Their index entries retain path,
size, digest and omission reason. The original records remain private; no redacted
copy is presented as an original. Binary payload deduplication keeps all original
identity-to-member mappings. The 23 historical pin references across six paths
retain the referenced prior-version bytes, including the deliberate negative
fixture; their old pins are not rewritten to current file contents.

The initial archive `shell_start` request was rejected during argument validation
before any child was submitted. The retained revision then predeclared the actual
`process_start` request and full resource contract, and the strict consumer
verified those exact requests. Both the rejected request and earlier plan remain
in the archive. The unchanged split implementation retains legacy
`candidate-b2-observations.tar.gz.0001`–`.0003` names; the plan, completion and
member index explicitly bind their payload to **C2 `249639e5`**.

Archive integrity leaves the functional and cost decisions unchanged:
**0/229 fully qualified operations; full replacement and production NO_GO;
C2 cost CLOSED / FAILED_INCOMPLETE, 11 actual calls and zero performance samples.**

The remaining full-product conditions include the 187 absent implementations,
the incomplete contracts of the 42 partial/related mappings, the package/Git source
boundary, broader real format/architecture corpora, complete engine operation
coverage, IDA/Hopper and other unavailable or unqualified integrations, real device
authority/disconnection/crash behavior, and all applicable deployment and recovery
conditions. Current bounded inventory does not establish that licensed tools are
absent from every possible host.

The PR remains a draft review. These observations do not authorize production
cutover or merge.
