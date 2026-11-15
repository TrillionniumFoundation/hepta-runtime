# x230 A26 qualification and experiment tools

This directory preserves the tools for the isolated x230 A26 experiment on
2026-10-24. The source proposal is suitable for a **draft PR about observation
availability and worker lifetimes**. The recorded series is not evidence of an
overall performance or resource-efficiency improvement, and these tools do not
deploy a production runtime.

Read the [A26 source and evidence record](../../../docs/X230_A26_20261024.md)
before using the scripts. The
[independent qualification receipt](../../../docs/evidence/x230-a26-qualification-20261024.json)
binds the qualified source and executables. Workload outcomes are recorded
separately in the [series review](../../../docs/evidence/x230-a26-r01/review.json),
[complete compressed summary](../../../docs/evidence/x230-a26-r01/summary.json.gz),
and [package manifest](../../../docs/evidence/x230-a26-r01/manifest.json).

## Scope and recorded outcome

The independent series review records `candidate_validation_passed=true` and
`comparison_valid=false`. Its C16 comparison retained **99 exact A20 capacity
refusals**. Under the plan declared before execution, those refusals permanently
invalidate the series' performance comparison. Subsequent A26-only coverage
does not repair that comparison, and successful standard cells must not be
selected to declare the full comparison successful.

The candidate-only fairness stage places the **same A26 executable in both A
and B slots**. Its 960 calls and admission gates passed; the labels describe
scheduling order, not different versions. The candidate-only C8 soak completed
16,956 of 16,956 calls in 570.732051 seconds, satisfying the predeclared
540-second measured-cell minimum. Its recorded controller CPU cost was about
47.39 ms per call. These are observations of this bounded workload, not an A/B
speedup claim. The recorded standard cells also retain A26's higher controller
CPU cost per call.

Keep the following evidence boundaries when using the results:

- The soak's normal resource summaries across controller lifetimes retain
  **34 `PermissionError` entries**. The enhanced receipt in
  `timeline_sampling[0]` reports **`error_count=145` and only the first 32 error
  details**, including `/proc/<pid>/fd` permission failures. Its
  4,980 sampling rounds and 545 timeline points are recorded,
  with `timeline_capped=false`. These are two views of the same resource
  sampling implementation, with potentially overlapping errors and controller
  coverage. Their counts must not be added; 34 is not the total number of
  sampling errors. Complete evidence preserves the producer's counters and
  retained details, not 145 individual error records. The last timeline point
  recorded 22 controller threads, `observed_master_count=6`, and cumulative
  `observed_master_generations=36`. The master classifier and generation counter
  cover sampled observations, not every possible renewal; these are not peak
  or steady-state claims. RPC completion and resource
  sampling coverage are different observations. Sampled resource peaks remain
  lower bounds; the sampling errors do not establish a cause for child-proof
  failures.
- Completed-original-job recovery passed, while **six old socket entries
  remained** and `abrupt_cleanup_complete=false`. Successful same-job recovery,
  orderly EOF shutdown, observed descendant exit, and removal of socket residue
  are separate outcomes. The tools do not delete that residue automatically.
- No spawn-proof failure event was recorded in the completed A26 series. There
  is no wait-entry or successful-wait counter in this evidence. Zero failure
  events therefore do **not** prove that the new empty-argv waiting branch was
  entered, or that it resolved a particular historical incident.
- Qualification records **1,123 runtime tests, 18 owner-control tests and 8
  job-control tests passing**, with 21 existing ignored tests. Nested helper
  results are not added again to parent suite counts.
- The source changes preserve complete authorization checks and give orderly
  shutdown an additional validation-worker lifetime barrier. Blocked kernel I/O
  can still delay that shutdown; SIGKILL can bypass the owner cleanup code.
  The running-job canaries do not establish recovery after host reboot,
  physical power loss, or arbitrary external side effects.

The existing 16 KiB validation read buffer remains in use. The separate
[hash microprobe](../../../docs/evidence/x230-a26-hash-probe-r02/summary.json)
exited zero and its independent publication recorded `verified=true`, with
every raw iteration checked and the results recomputed. Its median paired
CPU improvement was **0.920486%**, below the 3% gate; its median absolute
deviation was **1.356476 percentage points**, so the median did not exceed
twice that deviation; and only **five of eight** blocks improved CPU cost,
below the seven required. These CPU gates rejected a new runtime candidate.
They are measurements of the separate buffer microprobe, not an A20/A26
runtime speedup result. Finite experiments do not establish that all further
optimization is impossible.

## Exact environment required by the frozen runner

**Use these workload tools only with the isolated experiment's authorized
fixtures. Do not point their state, profiles, or canary paths at production.**
Recovery stages deliberately terminate directly owned test controllers, and
the lifecycle stages start new private canary jobs on the fixed host aliases.
This behavior is part of the experiment, not a generic production check.

The frozen scripts contain historical absolute paths and byte-hash gates:

| Input or location | Required layout |
| --- | --- |
| Development root | `/home/qian/hepta-runtime-optimization-20261023` |
| A26 qualified source | `source-a26-r01` beneath the development root |
| Accepted A20 source | `source-a20` beneath the development root |
| Qualification reports and copied executables | `qualification-a26-r01` and `qualification-a20-r01` beneath the development root |
| Original fixture base | `/home/qian/.local/state/hepta-runtime-native-dev-20261018/goal-20261023-a17-native-observation-r01` |
| Original input records | The fixture base's `frozen-originals`, containing the six exact completed-job records |
| Profile template | The fixture base's `ssh-profile/profile.json` and its pinned supporting files |
| Socket parent | `/home/qian/hx230-opt-20261023` |
| Credential authority | The operator's already held, account-owned `SSH_AUTH_SOCK` required by the exact profile |

All seven frozen workload helpers must be present under the development root
with the hashes embedded in `run_x230_a26_series_20261024.py`. A successful
independent qualification receipt labelled `A26` must bind the same raw
qualification, source map and executable. The runner rechecks source files,
executables, helpers, profiles and original records between stages. Several
helpers require output directories to be fresh **direct children** of that
historical development root.

The public evidence contains redacted receipts, not the private SSH authority
or original controller fixture. A repository checkout alone does not supply
the inputs needed to rerun the workload. These tools support this exact
experiment and its evidence verification; they are not portable load-testing
defaults. Changing paths, helpers, limits or acceptance rules defines a new
experiment and needs its own declared plan and qualification.

## Tool responsibilities

| Tool | Responsibility |
| --- | --- |
| `run_x230_a26_series_20261024.py` | Execute the frozen standard/capacity/fairness, calibration, sustained-observation and recovery plan once; retain every failed or unrun stage and separate candidate coverage from comparison validity. |
| `build_x230_a26_series_evidence.py` | Preserve the original publication implementation and its failed publication-attempt provenance. Its publication timeout is not a runtime-test failure. |
| `build_x230_a26_series_evidence_r02.py` | Publish the same recorded reports with equivalent bounded string-processing reuse; no workload is executed, retried or filtered. |
| `build_x230_a26_source_publication_manifest.py` | Preserve the first manifest attempt, which refused an incorrect assumption about the A20 source directory name. |
| `build_x230_a26_source_publication_manifest_r02.py` | Read the exact qualified A26 and accepted A20 source trees; record file bytes, SHA-256, Git blob SHA-1 and modes for publication review. The sole path correction selects `source-a20` for A20. |

The evidence publisher uses the exact `build_x230_evidence.py` and
`build_x230_six_running_evidence.py` dependencies identified in its receipts.
The source-manifest script is self-contained. It does not rehash the large test
executable or rerun qualification. Its output explicitly leaves repository-tree
verification and source adoption pending: compare all accepted A20 paths,
blobs and Git modes with the repository before using the A26 update.

The [package manifest](../../../docs/evidence/x230-a26-r01/manifest.json) lists
the preserved artifacts and their hashes. In particular,
[`series.complete.sanitized.json.gz`](../../../docs/evidence/x230-a26-r01/series.complete.sanitized.json.gz)
retains the complete series record, and each recorded stage has its complete
sanitized report archive. The compact review is an index into those retained
records, not a replacement for failed calls, sampling errors or raw verdicts.
For sampling arrays capped by their original producer, preservation means the
original total counter and the available limited details both remain; it does
not reconstruct error details that the producer did not record.

## Execution and evidence rules

The runner has no automatic trial or RPC retries. After a frozen driver exits
and its final report is collected, any unexpected A26 failure or uncertain
shared input/cleanup state prevents every following stage. The driver itself
may finish its entire predeclared stage after a failed call; the runner does
not claim to stop at the first failed RPC.

An attributable A20-only failure prevents any **new stage containing A20**
after that driver's exit. Missing candidate coverage can then use only the
predeclared single-B observation helper or same-A26 fairness slots. Exact A20
capacity refusals retain their capacity classification and are not relabelled
as child-proof failures. A failed baseline is never rerun until it passes.

Calibration is one fixed candidate-only C8 cell of 192 calls. The one ensuing
soak uses `ceil(successes / cell_seconds * 600 / 12) * 12`, subject to the
declared call bound. Its duration gate applies to the C8 cell itself; startup,
restart and total process lifetime do not count toward 540 seconds. A short
or failed soak is not extended or rerun to meet the gate. Each recovery and
running-job canary also has one declared invocation.

Existing r01 outputs are immutable evidence. A different output suffix creates
a different experiment; it is not permission to discard a failed baseline or
reopen a failed canary's jobs. Publication r02 only reprocesses retained
artifacts into a fresh output directory. It does not replay experiments.

These source and tool records are provided for draft-PR review. Production
deployment, a performance-adoption decision, and broader recovery guarantees
are outside the recorded result.
