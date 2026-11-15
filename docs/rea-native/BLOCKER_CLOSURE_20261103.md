# REA blocker closure — 2026-11-03

This continuation starts from PR #84 head
`23246a5313957e9e97e324303bc47a91808f1ea8` and preserves the adopted native
runtime and #83 publication correction. The review base remains
`work/native-runtime-convergence-20261030`.
[Integration scope](FULL_INTEGRATION.md) describes the complete implemented
routes; the [historical qualification index](QUALIFICATION_20261103.md)
preserves the earlier source-bound outcomes.

## Changes and completed main-host qualification

| Concern | Change | Completed evidence |
| --- | --- | --- |
| Ext4 audit query budget | Keep one actual store admission through a warm usage snapshot; release it before cold/capacity/busy waits | Candidate 4/4 original concurrent-publication runs and 15/15 exact regressions on physical ext4, unchanged three-second query budget |
| Native client CPU and repeated parsing | Full-byte streaming SHA-256 through the existing ring dependency; return the validated response frame and success flag without parsing it again | 240 fixed ABBA identity/large-frame samples, 300 real-worker/MCP samples, ten native-client tests in each feature mode |
| Browser producer and shared lifecycle | A finite local-resource capture helper under the existing durable process owner, reusing private Chromium lifecycle | Real Chrome → HAR → REA inspection/comparison/replay, restart/reuse, tamper refusal and original-job cancellation; 22 unit regressions and ten real PDF regressions |
| Static-provider tool description | Describe the actual admitted GNU/JADX/Ghidra operations | Description now states class/source observations and ELF import inventory; auto-analysis and decompilation remain disabled |

These outcomes cover the named contracts and workloads. General Python/PyTorch
compute, mature Java engines and explicit native-client selection remain
intentional integration choices. This report does not claim complete upstream
REA parity, a zero-Python runtime or a production cutover.

## Audit admission: preserve the original deadline

The audit store already had a FIFO queue. The former warm usage path released
and reacquired it between hot metadata, slot lookup, ready-state observation
and final content projection. New durable writer turns could enter between
those admissions, consuming the same absolute three-second query budget.

`SnapshotAdmission` now owns the actual guard across the warm path and final
original-content verification. Cold preparation, capacity waits and busy-worker
waits explicitly release it. Existing namespace, owner, pending-cohort,
original-stamp, cancellation and deadline checks remain. The fix neither renews
an expired deadline nor relaxes a durability barrier.

The deterministic `warm_usage_keeps_its_admitted_store_turn` regression pauses
a real admitted reader, queues a real writer behind it and checks exact usage,
cache state, admission tickets and final idle state. It also checks that an
expired held admission cannot renew its deadline. This directly tests the
handoff behavior that the fix changes.

### Actual ext4 result

The [ext4 qualification](../qualification/rea-audit-ext4-20261103-r1/README.md)
uses pinned test executables and the fixed **ABBA BAAB** schedule: four original
64-publication invocations per variant, followed by 15 candidate regressions.
There are zero retries, two explicit test listings and no Cargo invocation
inside this qualification.

| Variant/case | Scheduled | Passed | Failed |
| --- | ---: | ---: | ---: |
| Historical baseline, original publication case | 4 | 4 | 0 |
| Candidate, original publication case | 4 | 4 | 0 |
| Candidate, deadline/cancellation/content/cache/owner regressions | 15 | 15 | 0 |

The original outer owner `1a1a2dc9e85-96a-7539` reached exit 0 with complete
output and no timeout, cancellation, truncation or log error. The summary
reports `qualified=true`, a complete schedule and valid integrity. Both fixed
executables were rehashed after execution; source and dirty-tree bindings
remained unchanged. Child umask was observed as 0022. The private fixture root
was `/home/qian-qi/work/ha-7nj3v_07` on the original main-host ext4 mount/device.

Summary SHA-256:
`317e98fd4a33974a5354bb1a7d547b817cbefbb42cae25d34fb48334a1fed2ae`.

The historical baseline passed in this later window. The run therefore does
not reproduce the older failure or establish a speedup. The
[original 263/264 focused result](../qualification/rea-final-focused-20261103-r1/README.md)
and [single traced failure](../qualification/rea-audit-budget-diagnostic-20261103-r1/README.md)
remain unchanged. The deterministic regression and the observed ext4 candidate
results qualify the admission correction; they do not guarantee an arbitrary
load or a production latency SLA.

Baseline `metadata_drain` starts after readiness. Candidate
`metadata_snapshot` starts at initial admission and includes warm-stage work.
Those trace scopes differ and are not used to calculate a percentage gain.

## Native client: measured CPU benefit, explicit transport choice

Full executable, worker and package content still participates in identity.
The implementation keeps the same descriptor and metadata checks, frame and
response-ID bounds, duplicate-key rejection, exact response bytes and error
semantics. It introduces no path/mtime shortcut, new dependency or automatic
resend on an unknown outcome.

The [client report](../weight-runtime/BENCHMARK_CLIENTS_CLOSURE_20261103.md)
retains all 540 new measurements and exact build bindings. The 240-sample
fixed-binary cohort includes four pre-send exits and two real private-socket
large-response cases. The 300-sample formal cohort includes 120 fresh helper
calls, 60 direct resident-socket calls and 120 complete MCP calls.

Median native CPU fell from approximately 128–130 ms to 76–78 ms on the
principal cumulative identity paths, and from approximately 152 ms to 91 ms
on both large-response paths. These intervals include full process work.
They do not isolate a parser-only or hash-only cost.

For the actual F32 64 × 64 identity Linear model and resident Python/PyTorch
backend, mean helper CPU was:

| Operation | Candidate native | Python compatibility |
| --- | ---: | ---: |
| inspect | 80.33 ms | 96.07 ms |
| probe | 78.31 ms | 95.72 ms |
| query | 80.97 ms | 96.58 ms |

Each cell has 20 samples. CPU is summed as user + system time per sample
before computing a distribution. All three helper wall-time medians were
lower. Complete MCP medians and tails remained mixed, so native transport
remains opt-in. Lifetime peak RSS does not establish post-exec or steady-state
memory savings. OS file caches were warm and uncontrolled.

Both native revisions already used Tokio `current_thread` for WeightClient.
The report does not attribute this gain to removing a host-sized Tokio pool.
Both compute routes retain the same Python/PyTorch engine.

The retained traces verify all 300 measured response hashes, 100 expected query
arrays and forward counters of 61 / 21 / 21. Same-ID replay, worker errors and
idempotency conflicts preserve exact bytes. Original benchmark and resident
owners reached their recorded terminal states; no benchmark was rerun while
preparing its report.

## Browser observation under the existing owner

The [local capture contract](LOCAL_BROWSER_CAPTURE.md) admits a bounded
content-pinned resource manifest through a finite helper launched by the
existing durable process owner. The helper reuses the private Chromium
lifecycle already used for PDF rendering. It adds no REA daemon, controller
ledger or independently recoverable execution system.

The browser runs a fixed owned loopback harness. Supplied HTML and JavaScript
are resource data; application scripts and input-page DOM are not executed
or analyzed. The implementation does not attach to an existing browser.
A document-generation bootstrap prevents an already-completed old page from
being mistaken for the new capture phase without changing observed URLs or
resource bytes.

Actual Chrome 156.0.8078.79 qualification used pinned runtime SHA-256
`201fa5df3559bb4c22a9d5745ef3a086343e40c74298e1a3903d4d8a41c7131a`.
The original outer job `1a1a2ba8ad3-96a-7501` succeeded.

| Actual check | Observation |
| --- | --- |
| Content-tampered resource | Original native job failed before browser start; no successful output; same key returned the same failed job |
| Capture | One private browser start; seven HAR entries in each phase |
| Body accounting | Per phase: complete 3, empty 1, base64 1, missing 2; truncated and denied requests remain missing |
| REA compare | Two changed repeated responses; zero added and zero removed |
| Controller restart | Original job and content-bound HAR recovered without restarting Chrome |
| Saved-representation replay | Exact recorded representation bytes; zero accepted connections and zero HTTP requests at two positive-controlled owned origins |
| Cancellation | Original job reached cancelled; original process group had no live members, private profile was removed, same key did not restart it |

Replay's observed origin counts do not establish process-wide network isolation
or full browser-state replay. HAR bodies are CDP response representations,
not raw HTTP wire bytes.

The shared lifecycle retains the original waitable leader with `waitid` and
`WNOWAIT` until its original group has no live members, then performs the final
reap. It requires exclusive child-reaping ownership, default SIGCHLD handling
and visible proc state. A fixed finite `/bin/true` preflight verifies custody
before Chrome starts. Lost ownership or unconfirmed group termination remains
an error. Descendants that create another session are outside this contract.

Capture cancellation is deferred through setup and cleanup. A cleanup error
retains its unconfirmed status. Publication is create-only, with file and
directory fsync, and the success receipt is published last.

[Browser evidence](../qualification/rea-browser-closure-20261103-r1/final-summary.json)
retains the actual HAR/REA results and original owners. Its final summary
SHA-256 is
`1cb0c88e5242887bcd0d3fa74566c7f9bdf8b164234a837a3846e713ab39cb71`.
The 22 non-browser regressions passed. The original ten-test PDF suite also
passed, including actual geometry, page selection, text, pixels, transparent
background, local assets, page insertion and the existing to-thread path.

The first PDF run passed nine of ten tests. Its old launch spy assumed every
Popen was Chrome and rejected the new fixed custody preflight. The correction
adds explicit probe assertions while retaining the single-Chrome/profile
assertions; production helper code was unchanged. Both the initial failure and
the subsequent complete ten-test pass remain in the archive.

## Build identity and final publication gates

[Build evidence](../qualification/rea-blocker-build-20261103-r1/README.md)
preserves the original commands, outputs, artifact records and full source
inventories. The candidate Rust build is baseline 23246 plus exactly six
reviewed Rust changes, inventory
`0d4d316c6ea9de52276e359e711749a404d3e60191c4d37d7fcd8dcb2c39a28c`,
diff
`79cef8bff8213a1f159c310a98ce5fdf29505113745a93b07debd2f61ef651ec`.
It is not relabeled as a clean base commit or final publication-head build.

| Artifact | SHA-256 |
| --- | --- |
| Clean baseline release | `adaf8c26d3e4cbcc34699cbfeca6d678cc3f2f40d148babab9d4224424e1e820` |
| Candidate release | `201fa5df3559bb4c22a9d5745ef3a086343e40c74298e1a3903d4d8a41c7131a` |
| Candidate all-feature test library | `924180ac166d07051d2aae8ffb349a99c086ad4964f420ddb5f089fbefedcd91` |
| Candidate no-default test library | `816c47eb0a5b8960ceb15e4d4a59d058f644bc22571da367cd740c072a3fa201` |
| Historical ext4 baseline library | `7ec5383c2f5f56006564fb2eb3f8f7c72027c73f94f7c5e524cf7567ab8f90ed` |

The historical ext4 executable predates 23246. Its relevant audit source/config
closure matches the recorded base, but the whole executable is not described
as a 23246 build.

Two build-wrapper failures remain explicit: r1 failed before Cargo after
stripping a Git porcelain status column; r2 compiled and passed the warm test
but failed its enclosing overescaped summary regex. R3 reuses the verified
successful r2 artifact and completes the remaining build/test stages. These
harness corrections do not weaken product assertions.

After Rust builds, the extended integration tree was preserved by a Git
worktree move to
`/home/qian-qi/hepta-runtime-rea-blockers-integration-20261103-r1`.
The original build path was restored as a frozen 23246-plus-six-file worktree;
all 7,902 recorded source paths were rechecked against the build inventory
before ext4 execution. Existing receipts and embedded build paths were not
rewritten.

The final publication must independently pass push exact-head CI, PR
exact-head CI and PR prospective-merge CI. Both CI source views include the
new browser regression script. They run formatting, both all-target feature
configurations, strict Clippy, zero-retry Rust suites, Python regressions and
release builds; exact-head jobs also run release parser/syscall/ZIP checks.
The [PR checks](https://github.com/TrillionniumFoundation/hepta-runtime/pull/84/checks)
and PR description bind those results to the actual new head and synthetic
merge. Earlier 23246 green checks do not qualify this continuation.
