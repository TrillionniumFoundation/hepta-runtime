# X230 R9: observation throughput, bounded reads, and recovery custody

## Validation status

Source qualification, both local release comparisons, all eight native stages, and both forwarded-agent leases have completed successfully. R9 is retained as a qualified submission candidate for immutable command preparation, bounded blocking reads, and original-owner custody. The complete measurements do not establish a uniform throughput improvement. Ordinary retained-result reads are approximately 2.5% slower at C1 and C8, while paged inventory at C8 uses 7.38% more median whole-child peak RSS in the combined comparison. Six-host file throughput changes are C1 -1.86%, C4 -0.93%, and C8 +0.38%. Those costs and mixed results are retained alongside the component-level preparation savings.

The comparison baseline is accepted R7b, Git commit `cdb0b0fb4dd25f9990d650468527f0118ae82098`. Its 200 compiler inputs match the retained source map `d7770688369f0f60406bddf499519efd045b5bd0864f596a343760d37a07d59a`. The R9 candidate has 203 compiler inputs, pinned by source-map SHA-256 `532ac14b129501a7d054591da326bd247ebbf15a4826cabc9afe3d77600394a8`.

The patch has been checked and applied to an isolated R7b source copy; every resulting compiler input matches R9.

## Code changes

| Area | Change | Intended effect |
| --- | --- | --- |
| SSH observation preparation | Cache fixed compiled commands and the digest of the immutable installed configuration | Avoid repeated quoting, serialization and hashing |
| Retained result reads | Share four owned semaphore permits across queued and active blocking lookups | Prevent caller cancellation from admitting excess physical read work |
| Paged inventory | Reuse a raw byte buffer within each fully validated scan | Avoid repeated buffer allocation for similarly sized receipts |
| Observation owner shutdown | Keep the original Core in the process-wide Proxy until confirmed cleanup; publish Proxy before spawning owner | Retain unconfirmed child ownership and permits after owner-thread failure |

The command cache keeps an owned command copy per request. The inventory buffer may retain the largest receipt seen until the scan ends. Neither change adds a cross-request cache of mutable job or credential data.

## Correctness evidence

Rust 1.95.0, offline locked dependencies, all targets and all features were used on X230. Formatting, Clippy with warnings denied, test compilation, the isolated full suite, the exact-case audit, and the release build have passed. All 203 compiler inputs remained unchanged during qualification. The full suite selected 1,613 cases: 1,584 passed, 0 failed, and 29 were marked ignored. No test was automatically retried. The additional ignored case is the explicitly invoked SSH preparation component measurement.

The retained-result routing harness passed ten pure-memory self-checks before execution. The completed release comparison includes all 24 fresh controllers and all 6,144 measured calls, with no failed or unexecuted calls. Both public read tools validate the original retained bytes and native ownership semantics. All 24 controllers reported unchanged original retained files and clean EOF shutdown with the original child reaped. The separate inventory comparison includes all 48 controllers and 1,954 protocol requests, with no failed requests, forced shutdown signals, or automatic retries. The measurement sections distinguish their workloads and resource accounting.

The first formatting attempt failed on a missing delimiter in the new manual benchmark. The second attempt stopped at Clippy because two fault-injection fixtures deliberately held a real synchronous record lock while their current-thread async harness observed blocked workers. The delimiter was fixed and only those two fixtures received documented, function-local lint annotations. Both failed attempts remain separate from the successful test evidence.

## Performance review rules

Keep all original attempts and the fixed ABBA order. Any failed or missing attempt invalidates the complete comparison. Repeated throughput drops above 5%, or CPU/RSS increases above 10%, in both blocks trigger investigation. These are engineering review flags, not statistical significance thresholds or automatic adoption rules.

Distinguish optimized test-binary component timing from release end-to-end RPC timing. Distinguish measured CPU ticks and RSS endpoints from whole-child wait4 totals, and disclose native resource-sampling errors. Host, transport, and workload limits belong beside measured values.

## Measured performance

A denotes the accepted R7b release and B denotes the qualified R9 release in the two native read comparisons. Each comparison retains both complete ABBA blocks. Pooled throughput is total successful measured calls divided by total measurement time in the matched cell; it is not an arithmetic average of controller rates. No round was discarded or replaced to improve the result.

The analysis files named under Evidence identities contain the complete round and attempt membership, formulas, verification boundaries, and unfavorable observations. Their offline reviews recompute the supplied reports; they do not claim to have independently reread every remote binary, raw wire archive, or retained-file map referenced by those reports.

### Retained request status and result reads

The workload uses the release binaries, native stdio, two Tokio worker threads, and fresh private state for every controller. Each controller creates 32 real successful `host_list` results, performs 16 warmups, and then issues 256 alternating `request_status` and `request_result` calls through a rolling window at C1, C4, or C8. Each concurrency has two complete ABBA blocks, totaling 24 controllers and 6,144 measured calls: 3,072 calls to each tool. Lookup dispatches themselves add audit records, so the audit history grows while the same 32 original result payloads are checked.

Latency runs from send start until the reader receives the complete JSON-RPC line. Throughput also includes client validation, logging, and window-refill gaps. Every payload is checked against the original persisted bytes and SHA-256. Clean shutdown, original-file identity, source/binary freshness, and all measured requests are included in the validity decision. This exercises the full public read route, including unchanged admission and audit work, rather than isolating the semaphore.

| Concurrency | A pooled calls/s | B pooled calls/s | Block 1 throughput change | Block 2 throughput change | Combined change |
| --- | ---: | ---: | ---: | ---: | ---: |
| C1 | 124.77 | 121.63 | -1.52% | -3.41% | -2.52% |
| C4 | 306.47 | 307.74 | -3.04% | +3.92% | +0.41% |
| C8 | 426.01 | 415.82 | -1.69% | -3.09% | -2.39% |

Each pooled arm contains 1,024 measured calls per concurrency. C1 and C8 decrease in both blocks; passing the investigation threshold is not evidence of zero regression. C4 changes direction between blocks and is close to flat when pooled. These results do not establish faster ordinary result reads.

CPU in the next table is the measurement-interval `/proc` CPU delta, divided by all measured calls. The clock resolution is 100 ticks per second. RSS is the median of actual `wait4` whole-child `max_rss_kib` values, not a before/after RSS sample or a measurement-only peak.

| C | A CPU ms/call | B CPU ms/call | CPU change, block 1 / block 2 | Combined CPU change | A median max RSS, KiB | B median max RSS, KiB | Combined RSS change |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| C1 | 4.5508 | 4.7949 | +5.58% / +5.18% | +5.36% | 26,026 | 26,034 | +0.03% |
| C4 | 3.0859 | 3.1348 | +1.91% / +1.26% | +1.58% | 26,140 | 26,064 | -0.29% |
| C8 | 2.9004 | 2.9297 | +1.34% / +0.68% | +1.01% | 26,098 | 26,118 | +0.08% |

Median max-RSS changes in blocks 1 and 2 are respectively +0.27% / +0.06% at C1, -0.29% / 0.00% at C4, and 0.00% / +0.05% at C8. The ordinary-read data provide no material memory-reduction result. The four-worker cancellation bound is established by its separate correctness tests, not by a claim that this ordinary-load run reproduced a cancellation storm.

Whole-child `wait4` CPU includes startup, all 32 seeds, the 16 warmups, the measured calls, and shutdown. Dividing it by measured calls amortizes those other phases; it must not be labeled measurement-only CPU.

| C | A whole-child CPU range per controller, s | B whole-child CPU range per controller, s | A whole-child CPU / measured call, ms | B whole-child CPU / measured call, ms | Change |
| --- | --- | --- | ---: | ---: | ---: |
| C1 | 1.163105-1.574693 | 1.262905-1.624959 | 5.4671 | 5.7680 | +5.50% |
| C4 | 0.989552-1.030308 | 1.032290-1.042995 | 3.9462 | 4.0451 | +2.51% |
| C8 | 0.952545-0.980391 | 0.938971-0.980888 | 3.7860 | 3.7636 | -0.59% |

### Inventory and paged inventory

The inventory guard uses 1,024 warmed synthetic receipts per fresh state, totaling 34,041,856 bytes, with 32,768 private argument bytes per receipt. It compares `process_list` and `process_list_page` at C1/C4/C8, with four synchronized waves per controller and two ABBA blocks per tool/concurrency. Paged calls request the first page with a limit of 128; each first page rescans. One continuation is checked outside the measured calls. This differs from the rolling-window retained-result workload above.

All 48 original controllers and 1,954 protocol requests remain in the analysis: 48 initialization requests, 416 measured `process_list` calls, 416 measured `process_list_page` calls, 1,050 pings, and 24 continuations. Every controller was reaped, without a forced signal. Both arms use identical receipt content and warming; namespace-bound page/cursor hashes intentionally differ between fresh states.

| Tool | C | A pooled calls/s | B pooled calls/s | Block 1 throughput change | Block 2 throughput change | Combined change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `process_list` | 1 | 13.16 | 13.74 | -0.11% | +9.13% | +4.39% |
| `process_list` | 4 | 40.42 | 38.54 | -6.64% | -2.49% | -4.64% |
| `process_list` | 8 | 39.78 | 39.01 | -8.12% | +5.38% | -1.94% |
| `process_list_page` | 1 | 17.48 | 16.97 | +1.74% | -6.43% | -2.92% |
| `process_list_page` | 4 | 49.37 | 50.29 | +5.55% | -1.72% | +1.88% |
| `process_list_page` | 8 | 53.02 | 50.74 | -0.77% | -7.60% | -4.30% |

Each combined arm has 16, 64, or 128 measured calls per tool at C1, C4, or C8. `process_list` C4 and `process_list_page` C8 decline in both blocks. The adverse first-block C4/C8 list results and second-block C1/C8 page results are not discarded when the other block is better. The current evidence does not establish an inventory speedup.

Inventory CPU is whole-child `wait4` CPU divided by measured inventory calls, including initialization, all pings, continuation when present, and shutdown. The report contains no before/after `/proc` CPU or RSS snapshots, so neither measurement-only scan CPU nor isolated scan peak RSS is available. The ping count also varies with elapsed time; this metric is a broad resource guard rather than causal CPU attribution to the scan alone.

| Tool | C | A whole-child CPU ms/call | B whole-child CPU ms/call | CPU change, block 1 | CPU change, block 2 | Combined CPU change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `process_list` | 1 | 75.242 | 76.129 | +6.82% | -4.23% | +1.18% |
| `process_list` | 4 | 45.211 | 47.637 | +9.70% | +1.08% | +5.37% |
| `process_list` | 8 | 45.290 | 44.643 | +2.69% | -5.59% | -1.43% |
| `process_list_page` | 1 | 74.587 | 77.304 | -0.56% | +7.16% | +3.64% |
| `process_list_page` | 4 | 70.197 | 70.125 | -0.73% | +0.53% | -0.10% |
| `process_list_page` | 8 | 68.492 | 68.051 | -0.26% | -1.03% | -0.64% |

All list cells and page C1/C4 cells have median whole-child max RSS of 28,000 KiB in both arms and both blocks. Forty of the 48 individual values equal exactly 28,000 KiB. That is a plateau in the recorded lifetime high-water metric, not proof of identical scan allocation; the report does not identify its cause.

Paged inventory at C8 shows a measurable memory cost:

| Scope, page C8 | A median max RSS, KiB | B median max RSS, KiB | Change | A largest child max RSS, KiB | B largest child max RSS, KiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Block 1 | 35,886 | 37,298 | +3.93% | 37,520 | 37,724 |
| Block 2 | 34,542 | 38,278 | +10.82% | 35,220 | 39,912 |
| Combined | 34,736 | 37,298 | +7.38% | 37,520 | 39,912 |

The combined +7.38% median max-RSS change accompanies -4.30% pooled throughput at page C8. Block 2 alone has -7.60% throughput and +10.82% median max RSS; block 1 has -0.77% and +3.93%. The repeated two-block flag is not triggered, but those results remain relevant costs when judging the candidate.

Inventory timing uses the recorded outer measurement span. Independently reconstructed first-request/last-response spans are 3.87-13.41 microseconds shorter per controller, a difference of at most 0.0065%. Both calculations were retained and neither changes an investigation flag. Latency includes complete JSON-RPC decode and precedes validation, unlike the retained-result harness's receive-line boundary. The two latency definitions must not be pooled.

### Fixed SSH command preparation component

This experiment explicitly invokes one ignored component test in the optimized development/test profile: `opt-level = 1`, debug information disabled. It compares uncached command construction with cached construction plus the owned command copy inside the same candidate test executable. It is not a release benchmark, a network benchmark, or end-to-end RPC timing. SSH transport, runtime policy-digest preparation, remote execution, and remote resource use are excluded.

All 36 measurements are retained: one uncached/cached/cached/uncached block for each of three components and worker counts 1/4/8. Each round performs 2,000 operations per worker. Values below are elapsed wall time divided by total operations; at four or eight workers they are amortized wall time per operation, not individual-call latency.

| Preparation component | Workers | Uncached wall us/op | Cached wall us/op | Uncached / cached |
| --- | ---: | ---: | ---: | ---: |
| file | 1 | 210.636 | 2.566 | 82.10x |
| file | 4 | 85.990 | 0.745 | 115.44x |
| file | 8 | 88.463 | 0.743 | 119.11x |
| status | 1 | 144.742 | 1.405 | 102.99x |
| status | 4 | 59.031 | 0.413 | 142.92x |
| status | 8 | 59.431 | 0.443 | 134.19x |
| read | 1 | 70.368 | 0.501 | 140.53x |
| read | 4 | 26.424 | 0.135 | 195.52x |
| read | 8 | 26.750 | 0.149 | 179.14x |

These large ratios identify repeated local quoting and command construction that can be avoided. They are not service-level speedup factors. Each request still copies its owned command and serializes its dynamic input. The completed public-read comparisons above, with their mixed or adverse results, remain the appropriate evidence for those workloads.

### Review of the completed performance guards

None of the same matched metrics exceeds its investigation threshold in both ABBA blocks. This means no repeated flag was triggered under the predefined rule; it does not automatically accept the candidate, establish equivalence, erase single-block regressions, or waive correctness and native-recovery review. In particular, ordinary-read C1/C8 throughput costs, list C4 throughput costs, and page C8 throughput/RSS costs remain part of the engineering decision.

These are short, warmed, synthetic local-stdio experiments with two blocks and two controllers per arm per matched block. They provide no p99 significance claim, sustained production-load qualification, network-partition result, multi-host scaling result, or crash/power-loss proof. No cross-machine scheduling gain is inferred from command-preparation savings.

## Completed native validation

The native suite ran from 01:50:35 to 01:57:12 UTC on 2026-11-01. All eight stages executed exactly once and passed; none was omitted or automatically retried. Each original stage helper was reaped while custody remained held. The main and remote forwarded-agent leases each launched once, exited successfully and reaped their original child. Final input-integrity checks passed. Production services were unchanged.

| Native stage | Completed coverage | Interpretation |
| --- | --- | --- |
| Small archive ABBA | 4,096 measured calls; 4,424 total tool calls; all successful | One C1 hot-archive guard over usage statistics, history and archive queries |
| Inherited pipes | Seven expectations passed across Linux and macOS cases | Four jobs succeeded; two drain deadlines and one drain cancellation correctly retained `effect_unknown` |
| Six running jobs through controller SIGKILL | Six original jobs, six same-key lookups, 42 native calls and 30 inspection/setup SSH calls | Recovery preserved original identities and verified before/after payload bytes; no replacement job was introduced |
| Four six-host file ABBA arms | 1,152 measured calls, all successful, at C1/C4/C8 | Immutable 44-48 byte synthetic file outputs using `file_info`/`binary_read` |
| Candidate C8 soak | 27 cells, 2,592/2,592 measured successes, 122.097 measured seconds | Configured 120-second run completed with all cells included |

The pipe expectations are deliberately conservative: the three `effect_unknown` cases report exit 125, incomplete output and output not proven durable. Passing these checks means preserving uncertainty correctly; it does not turn all seven jobs into successful business effects. The six-job recovery scenario checks controller process loss and original-identity reconciliation. It does not establish target reboot, physical power-loss recovery, WAN-partition behavior, production owner transfer or transactional exactly-once external effects.

### Six-host file throughput and latency

All four original arms are included in one fixed ABBA block. Each arm contributes 96 measured calls per concurrency. Pooled throughput is total successful calls divided by summed measured cell time.

| Concurrency | R7b calls/s | R9 calls/s | R9 change | R7b reported cell p95 range, ms | R9 reported cell p95 range, ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| C1 | 4.044 | 3.969 | -1.86% | 298.47-328.90 | 332.02-342.76 |
| C4 | 15.448 | 15.305 | -0.93% | 312.42-359.07 | 344.86-356.55 |
| C8 | 21.776 | 21.859 | +0.38% | 436.38-476.57 | 424.86-469.43 |

Both R9 C1 cell p95 values exceed both baseline values; this unfavorable result remains part of the assessment. The local original reports contain cell percentile summaries, while their full measured call journals remain at the original host paths. Consequently, these are ranges of reported 96-call-cell percentiles, not a newly recomputed pooled p95. The workload establishes neither bulk bandwidth nor a general release throughput increase.

Reported local CPU per call is 128.073 to 130.208 ms at C1 (+1.67%), 77.188 to 76.615 ms at C4 (-0.74%), and 74.479 to 72.917 ms at C8 (-2.10%). Full-round waited CPU totals are 67.986 s for the two baseline arms and 67.822 s for the two candidate arms (-0.24%). These quantities have different intervals; full-round CPU includes preparation, warmup, rejection checks and shutdown. Remote-host CPU is excluded.

The final resource lists contain eight `/proc/<pid>/fd` sampling errors across the four file arms, in order 1/2/0/5. Median sampled process-tree RSS increased from 101,492 to 109,348 KiB (+7.74%), while sampled controller RSS medians were 17,884 and 17,652 KiB. These are two cumulative sampled peaks per arm, subject to missing observations and short-lived descendants, and do not establish a memory reduction or exact peak bound.

### C8 soak and small-archive guard

The C8 soak achieved 21.229 calls/s over 2,592 successful measured calls. All 27 cells remain in the totals, including iteration 19: its throughput fell to 17.907 calls/s and its p95 reached 1,006.921 ms. The reported cell p95 range is 428.321-1,006.921 ms; the cell p99 range is 443.842-1,192.250 ms. The helper's complete lifetime was 130.013 s and waited local process-tree CPU totaled 222.574 s. Twenty-one final resource sampling errors remain recorded. A two-minute soak does not establish long-duration memory stability or a 600-second soak result.

The separate small-archive C1 guard improved descriptively from 128.962 to 134.298 calls/s (+4.14%). Measured controller CPU per call changed from 6.729 to 6.426 ms (-4.50%), and whole-round max-RSS medians from 28,900 to 27,852 KiB (-3.63%). All 4,096 embedded measured-call timestamps were rechecked, yielding pooled p95 values of 11.708 and 11.648 ms. Other observations were unfavorable: measured-after controller RSS medians rose from 16,372 to 16,480 KiB (+0.66%), `usage_stats` and `request_history` p95 increased by 0.25% and 0.56%, and the maximum `request_archive` latency rose by 9.75%. Whole-round max-RSS ranges were broad: 22,436-35,364 KiB for R7b and 25,516-30,188 KiB for R9. This is one ABBA block with fresh identities, timestamps and cursor values per arm; normalized operation and page sequences match, but cross-arm records are not byte-identical. It provides a scoped regression guard and descriptive improvement, not statistical or universal speedup qualification.

Independent review rehashed all ten native report files and verified the main-lease to remote-lease to native-report to eight-stage hash chain. Embedded pipe and recovery receipt bytes were decoded and rehashed. Raw file-call journals, original wire streams, executable files and all referenced resource snapshots were not reread in that offline review; their original checks and artifact pins remain distinct from the independent report-level checks. The recovery shutdown also retained one resource-sampling error. No native correctness blocker was found within this scope.

## Recovery and ownership design

### Objectives and invariants

R9 targets repeated preparation, allocation churn, and blocking-read contention. The objective is greater useful throughput with predictable resource consumption while preserving operation identities and recovery evidence. A faster path must not change authorization, turn uncertainty into success, or submit an operation again.

The governing invariants are:

- Each accepted operation keeps its original host, request identity, deadline, and applicable owner binding.
- Resource permits follow work that can still consume resources, including work detached from a cancelled caller.
- Cached derived values are reusable only when every input is immutable for the cache lifetime.
- Successful cleanup requires confirmation from the original owners. Uncertain cleanup retains evidence and freezes admission.
- An unverified cache miss or unreadable, corrupt, conflicting, or concurrently changed registry cannot authorize a new effect.

These changes preserve existing transport limits. They introduce no automatic migration, replacement execution owner, or new retry policy.

### Preparation and read paths

Observation command preparation caches quoted commands derived exclusively from compiled script constants and the fixed interpreter name. Request fields, destinations, environment values, and observed results remain outside these caches. The policy digest is calculated lazily beside the exact immutable installed configuration, avoiding repeated serialization and hashing without allowing a later configuration to inherit an earlier digest. Live credential, file, socket, and ownership checks retain their responsibilities; a cached command or digest cannot substitute for them.

Retained request-result lookups share a process-wide budget of four blocking workers. Admission precedes submission to the blocking pool. The owned permit moves into the worker closure and remains there while queued, during filesystem work, and while waiting for a record lock. Cancelling the async caller cannot stop an already submitted closure and cannot return its permit early. This bounds those blocking lookups, not all asynchronous waiters or caller-retained responses. Result identity, policy binding, integrity checks, and bounded byte pagination remain unchanged.

Durable inventory pagination reuses one raw byte vector within a scan. Each record is freshly opened, validated, decoded, and checked against directory and file identities. Decoded records own their data; returned values do not borrow the scratch buffer. Reuse reduces allocation but does not convert a full scan into indexed lookup or eliminate memory held by decoded rows. Existing row, byte, and time bounds remain relevant.

### Transport custody and failures

The observation pool's process-wide proxy retains its original `Core` independently of the dedicated owner thread. The proxy is published before that thread can create children, and the core is registered before initialization can spawn a probe. A losing concurrent startup cannot create an unanchored owner. Custody is cleared only after child and socket cleanup, followed by validation-worker completion, succeeds and the original core identity still matches.

| Event | Required behavior |
| --- | --- |
| Cancellation before submission | Release unsubmitted capacity; create no replacement attempt. |
| Cancellation after blocking-read submission | Let the original closure retain its permit until it ends. |
| Cancellation after transport submission | Keep the original child under owner cleanup; a timeout establishes neither remote failure nor success. |
| Actor panic in an unwinding build | Freeze admission and run original-owner cleanup; do not replace the owner or replay. |
| Cleanup error, or cleanup panic with unwinding enabled | Retain the Core, remaining unresolved child entries and their permits, and required path identities in the proxy; report uncertainty. |
| Confirmed cleanup success | Release custody and permits and remove owned private resources without retaining a successful core indefinitely. |
| Release-build panic, process kill, power loss, or reboot | Use the existing durable recovery path; in-memory custody is unavailable. |

The existing release profile uses `panic = "abort"`. Panic-catching and poisoned-lock fixtures run in the unwinding test profile; they do not establish in-process panic recovery for the release binary. Ordinary returned cleanup errors can still preserve custody in a live release process.

Keeping a child handle does not guarantee process survival. Linux `PR_SET_PDEATHSIG` may terminate production SSH children when their creating owner thread or process exits. Custody must preserve the unresolved original wait/reap obligation regardless of that termination; a presumed signal proves neither reaping nor the remote outcome.

The lifecycle regression uses the real pool owner thread and shutdown path, but transfers a controlled pipe-blocked child created by the test thread into its ledger. It drops local strong core/child references before joining the owner, isolating implicit Drop and checking retained permits and successful release. It does not reproduce production SSH parent-death behavior or prove that production children survive owner-thread exit. Execution results belong in the validation report.

### Durable jobs and owner fencing

The existing durable job path publishes and synchronizes the original identity before external submission. Recovery must reconcile the original identity against its bound host, request digest, retained metadata, logs, and supervisor state before authorizing further effects. An interrupted transport may coexist with a continuing remotely supervised job. A restarted controller must observe and reconcile the original job before deciding what action is permitted.

Where configured, the shared execution-owner fence protects new-effect admission through durable intent and submission. Participating controllers must use the same intended authority; an unconfigured instance is not a qualified takeover. R9 implements no administrative owner-transfer protocol and expands no observation authority. R9 leaves the existing isolated/jobctl same-identity reconciliation path unchanged; it adds no automatic replay, new key, or replacement remote job.

Custody retention is an in-process safeguard. It adds no durable checkpoint or write-ahead log, changes no disk commit protocol, and supplies no power-loss qualification. Reboot and interrupted-publication claims require separate durable-path evidence. Unknown side effects remain unresolved until authoritative reconciliation; changing the idempotency key or moving the request to another host is not recovery.

### Further optimization and stopping conditions

Unknown idempotency keys can still require an O(N) registry scan. Buffer reuse and bounded concurrency reduce overhead and contention without removing that asymptotic risk. An index would require durable publication, crash-safe rebuilding, duplicate-owner detection, corruption handling, and agreement with the authoritative registry before an absent entry could permit execution.

Continue where comparable workloads expose a material bottleneck. Compare end-to-end throughput, tail latency, retained memory, worker occupancy, and recovery behavior under identical workloads and resource limits. Stop a candidate when gains are not repeatable, cost shifts unacceptably to another host, or identity, authorization, durability, or cancellation guarantees weaken. Stop the iteration when remaining improvements depend on unavailable evidence or a separately scoped persistence or scheduling change. This is a defensible stopping point, not global optimality.

## Qualified artifact identities

- Qualification report SHA-256: `724a894f2e345e27583c0a4f34a26259e5b722baeed53f133716b84e980480f7`
- Exact-case audit SHA-256: `57ec512706b46abfc2da662123df9c4a1bf7f6eb906d694d001ffca30024e1d5`
- Release runtime SHA-256: `c36ee1390d1755bfc371fba953489bd16825dd883e0592cd1ac4bbcb8e226183`


## Evidence identities

The public tables are derived from the following frozen evidence files. The analysis files retain all constituent attempts and distinguish recorded artifact pins from an independent reread of the referenced remote files. Names identify review artifacts; absolute host paths and operational account details are unnecessary for interpreting the measurements.

| Evidence | SHA-256 |
| --- | --- |
| `r9-result-read-analysis.json` | `fe6acefd849b04406c6cf16939bfac9db4cf1198cd8cabd07f5478cf5d070adf` |
| `r9-inventory-analysis.json` | `51f8b1bff9dc70a7ca54464869bc928dec5f3ed275c8e5539a5b74e68fc6b0e6` |
| `r9-ssh-component-evidence.json` | `2c9e443d1fb003db394298d83981e3733632402f2ec6d3cf875c974b10dba21d` |
| `r9-recovery-design-review.md` | `cb65bad689d8502aae097b8d94480b1f90fe60acc662bbe6e5a4b17eeae98b02` |
| `r9-native-analysis.json` | `c227a046e6cf5d138f3b4e53de8ffeb139cbbf119b8d7cb7d724bb1965d4321d` |
| Native original final report | `a35c98068b320e503eea1fa6a2e895b98b43517f46f2edb1edac25964a16a340` |
| Main forwarded-agent lease report | `b93c24c9ff949c0a4f8809939ef6d0aec231ba4c5e150e6bd268a0daf0225545` |
| Remote forwarded-agent lease report | `ca51fc325fb7606350cb250286909d35acba10bd2b2dba8e587c42b1493a9839` |

The accepted R7b release used in both public-read guards has SHA-256 `7c8207d38d89c34b18e07e91e2702bed99803365d90b4b06643d8d6e6d34cc5e`. The component test executable has SHA-256 `1fb5989c9b57ea415789080b3171ec8eed5f7ce3c4ad155251feffe274f27d87`; it must not be substituted for the R9 release artifact listed above.

## Reproduction and publication packaging

All runtime changes were qualified on the original X230 with Rust 1.95.0, locked offline dependencies, two build jobs, incremental compilation disabled, dev debug information disabled, one Rust test thread and two Tokio workers. The existing X230 qualification driver preserves each stage, isolates and enumerates every test case, audits the retained test logs, and copies the exact tested release artifacts. Its toolchain location is specific to the original X230 environment.

For a new qualification on that prepared environment, set the following task-specific variables to explicit absolute paths. The output must be a new directory with an existing parent; never overwrite an original evidence directory.

```sh
CARGO_PROFILE_DEV_DEBUG=0 python3 -I -B "$R9_SOURCE/tools/x230/20261028/qualify.py" \
  --source "$R9_SOURCE" --output "$R9_QUAL_OUT" \
  --target "$R9_TARGET" --cargo-home "$R9_CARGO_HOME" --jobs 2
```

The fixed-command component is opt-in: run the retained library test executable with `fixed_observation_preparation_abba --ignored --nocapture`. The result-read runner and its pinned helper are in `tools/x230/20261031/`; its `--help` documents required binary and full-source fingerprints. Those source fingerprints also cover tools, so a later publication copy containing additional tools must receive its own fingerprint for a new experiment. It must not be silently substituted for the original frozen source.

The publication copy additionally includes the exact original `run_inventory_concurrency_abba.py` and `run_inventory_rss_abba.py` used for the inventory comparison. They must remain adjacent and byte-identical: the concurrency runner checks its helper's SHA before loading it. Their SHA-256 values are `ccfb8ac3735e13a61cb37ed65ac558e30c30f6eb64c964f6182a307bf8cb042b` and `a9f840198a8d153862dd17732146039a50b45c969dad679173e5c447a79801ba`, respectively. The concurrency experiment creates 48 independent controllers and substantial synthetic evidence; its disk-space gate requires roughly 3.34 GiB. Both arms need complete qualification, source-map and exact-case-audit bindings, including the original files referenced by those reports. Moving a report to another host and editing its paths does not preserve that qualification.

Native validation used the host-specific historical paired driver with SHA-256 `98b9843bda87f17ce490e51328a85aa341f97db49c354f0d0c09e9bd076346fe`. It depends on a pinned protocol library, five pinned helpers, the original six-host fixture layout, trusted host profiles and one live forwarded-agent lease. Its raw operational inputs are retained separately. It is not packaged as a portable one-command native benchmark.

The original qualified source remains frozen. Two inventory tool copies and the report/evidence documents are added only in a separate publication source. The final patch is applied to an independent accepted R7b source copy; the entire resulting tree must match the publication copy and all 203 compiler-input hashes must match qualification. This verifies the submitted runtime while keeping the later noncompiler packaging additions explicit. The accompanying JSON records numeric aggregates and evidence hashes; full original wire, test, process and resource logs remain the authority for the experiment.
