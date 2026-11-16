# Current SDK incoming request tasks

This independent candidate implements the incoming cancellation map and response
claim boundary in RMCP 3.9.0. It leaves the qualified public 91-owner graph intact.
The application source identity is `d3d75c30719db966b004756f610007a7c723729e`;
the exact target Cargo lock fixes RMCP 3.9.0 and Tokio 1.53.3.

The HIA author reads its DSL and lowering helper only. Neither the author nor the
native build reads expected SDK outputs. The current G1 HIA message projection
supplies typed IDs and typed cancellation parameters. The new state owner stores
canonical IDs, monotonic private generations, cancellation delivery, pending sends
and the SDK's distinct EOF and explicit-cancel drain deadlines.

## Actual reference boundary

`reference/oracle/main.rs` supplies an ordinary gated `Service<RoleServer>` and an
observable in-process `Transport<RoleServer>` to the unchanged
`serve_directly_with_ct`. Thus request registration, token propagation, response
claiming, cancellation notification routing, send futures and shutdown ordering
run in the actual current SDK. It uses actual `RequestContext.ct` values. Gates
let ordinary handlers finish in a controlled order; they do not implement the
SDK's task map. The full published SDK crate archives, retained fixture binary,
derived lock, build processes and exact upstream files are retained.

The 110 conversations cover nine ordinary ID representations, success and both
error results, targeted/unknown/absent/late cancellation, metadata notifications,
independent simultaneous tasks, sequential ID reuse, pending sends and normal
write failure. EOF and explicit cancellation each cover early completion, a
cancelled response, an actual handler deadline, a released pending send and an
actual pending-send deadline. All 537 explicit conversation actions remain fixed.
Completion barriers are real SDK ping requests and pass through G1 plus the HIA
registry as actual additional tasks. Their full wire remains in the evidence.

The observer records the outer token before consuming `RunningService::waiting`:
that consumption drops its `DropGuard` and can cancel the outer token later. The
later drop is recorded separately from EOF's five-second drain. Observed clocks
feed the native private deadline ABI; this does not qualify a native timer pump.

## Portable execution

From the source root, in an approved CI runner with Rust 1.95.0:

```sh
python3 -I -B scripts/run_ci.py --source "$SOURCE" --hepta "$HEPTA" \
  --rust-bin "$RUST_BIN" --output "$OUTPUT"
python3 -I -B scripts/verify_complete.py --source "$SOURCE" --run "$OUTPUT" \
  --require-recipe-pass
```

`workflow.request-tasks.yml` is directly publishable as an isolated workflow. Its
job deadline is 15 minutes. Each original/native conversation retains a 60-second
deadline; reference build steps retain 180 seconds. There is no new outer process
group wrapper. Native bootstrap inputs are built afresh in CI; this remains the
development fixed-point build, not an independent Hepta cold qualification.

The reader reopens every captured input and complete mutable buffer, checks
growth copies and actual address relocation, reconstructs every native request
from the fixed corpus, and compares the resulting task states and publish/drop
decisions with actual SDK observations. Eight physical evidence forks must be
rejected. The read-only guard blocks writes, metadata changes, process execution,
native mapping and foreign reads, with 11 actual refusal probes and complete
before/after metadata plus byte snapshots. Archive export retains all captures
and excludes only the reconstructible Cargo target directory.

## Scope still open

This source candidate has not yet completed its fresh CI comparison. Its private
tag/job binding checks use explicit fixture identities. They do not claim the
Bellman worker was executed. The real public event pump must still retain each
pending frontend input, workspace, output, slot-18 descriptor and generation;
translate registry cancellation into the actual private caller command; await
actual worker and transport completion; and retire each owned buffer correctly.

No outgoing-request registry, subscription registry, general HTTP runtime,
full async runtime, all-136-handler coverage, production activation or old-stack
removal is claimed. AsyncRwTransport retains its separate earlier qualification;
the task observer's custom transport does not replace it. The existing public
graph, historical profiles and their frozen evidence are unchanged.
