# Canonical F64 owner qualification

This study keeps the current `rea_model` descriptor and `weight_artifact` owner.
The source patch adds exact F64 element support to its existing safetensors edit
path. It does not introduce another transaction owner or deploy a service.

The JSON bridge keeps every original JSON byte in a protected U8 tensor and
exposes only the 196 editable readout parameters as F64. The native semantic
adapter authenticates the existing stored law, complete initial state, schedule,
deadline, arithmetic identity, protected parameters and shared edit radius. The
qualification does not reinterpret endpoint READ/REPAIR as financial path/reset
semantics, and it provides no independent financial label or trading-profit claim.

## Public build and private execution

The final source policy is the only push trigger for the dedicated workflow.
The root library is compiled in both feature configurations. Eight synthetic
owner/tensor tests run in separate processes per configuration. The copied test
binaries have debug information stripped before those tests run. Their exact
bytes and hashes are retained for private execution.

The private root test is explicitly ignored. The public workflow verifies this
attribute and never runs it. Its artifact allowlist contains only the qualified
test binaries, source manifests, synthetic results, bounded-stage receipts and
diagnostic logs from a failed synthetic build step. Checkpoints, private case
files and owner state directories must never be added to that artifact or Git.

Private execution uses the predeclared fit 11 / Q_1 candidate from the separately
admitted C queue. A source-pinned helper creates the bridge and verifies the same
whole-model identity. The actual root owner then publishes the candidate into a
fresh private state root. The helper evaluates the **published artifact bytes**
against the same complete-state reference. The owner restores the original through
its existing persisted reverse patch, and the helper verifies every original
file byte, JSON byte and F64 parameter.

Three independent private state roots exercise rejection after successful
conformance, helper nonzero exit, and helper timeout. The latter two probes do not
execute a model or DP. Helpers have inner deadlines, are killed and reaped on
timeout, and leave time for canonical restoration. Both feature configurations
together reserve two complete native DPs and six private publish/restore cycles.
Failure before a conformance receipt leaves the actual DP count unknown.

The private test's exact name is:

`mcp::weight_artifact::private_tests::canonical_f64_private_reject_restores_all_source_bytes`

It requires a separately frozen local contract and the environment variables
`HEPTA_PRIVATE_F64_CASE`, `HEPTA_PRIVATE_F64_CASE_SHA256` and
`HEPTA_PRIVATE_F64_OUTPUT`, followed by an explicit `--ignored --exact` invocation.
Absence of the fixture is a failure when the test is explicitly selected.

## Resource and recovery limits

The CI stage admits one execution. Its process-group CPU monitor, single-core
affinity, per-process CPU hard guard and wall deadline have distinct meanings.
Bootstrap, checkout, upload and download costs are reported separately; the child
soft limit is not a complete platform cost bound. On a failed or killed stage,
reaped CPU and an observed lower bound are retained while the complete descendant
CPU total remains unknown. The supervisor adopts and reaps orphan descendants
and cleans residual members of its process group. Seven actual-process controls
qualify its success, failure, missing-receipt, orphan, aggregate-CPU, wall and
launch-exception paths.

The private lifecycle establishes persisted owner restoration after the tested
helper outcomes. It does not establish recovery after the outer parent receives
SIGKILL, production adoption, a full autonomous planner, arbitrary backend
compatibility, or compatibility with a separately evolving HIA branch. Original
source weights remain unchanged through copy-on-write publication, and KEEP / STOP
remain the recorded deployment decision.
