# A50 binder and narrowly scoped large-main custody change

The frozen binder is `../bind_a50_archive_experiments.py`: **30,725 bytes**,
SHA-256 `a9300316db52fff333c0bb6a5120a2e06f5de62c387cf02e39de6e1b8e44ece2`.
It derives from the exact 23,000-byte A48 binder,
SHA-256 `905f8ea48caa9c66ef4afb5fcfb5983ec3a95ee31172c1f0b820373bdde1c5cb`.
All five original A46 template hashes remain pinned and verified. A46 and A48
failed reports and helpers remain untouched. The retained A48 failed large
report SHA is `8c0377e52d930d93597f7b4e551d68101a29bffe6dd9aaa3d9bcdf22a036215f`.

## Binding scope

A48 labels/paths become A50 / `a50-record-batches`; templates still come from
`a46-bound`. The binder requires all three actual qualification, entry and
worker files and all three expected SHA-256 CLI arguments. It checks ordinary
six-stage qualification, fresh compiler artifacts, 168-file maps, original
stat9 cross-receipts, postqualification worker flags and the entry source map.
The actual small/large preflights copy and fence the entry and worker; the
small evaluator rechecks the captured body chain. Source-input and postformat
source maps stay distinct.

The qualifier owner confirmed unchanged schemas and these paths under the
existing fixed X230 BASE:

| Artifact | Relative path | Schema |
|---|---|---|
| Qualification | `qualification-a50-record-batches-r01/report.json` | `runtime-candidate-qualification/v1` |
| Entry | `a50-record-batches-entry-r01/entry-report.json` | `hepta-a50-record-batches-qualification-entry/v1` |
| Worker | `a50-record-batches-entry-r01/worker-report.json` | `hepta-a50-record-batches-guarded-qualifier-worker/v1` |

No actual A50 qualification was supplied to this review. Binder `main` has not
been called, no `a50-bound` directory has been created, and no formal binding or
benchmark result has been emitted. The diff's unbound template is solely an
in-memory review representation; it is never saved or run as a bound experiment.

## Concrete custody defect and correction

The frozen large `run_controller` writes its journal at the start of `finally`,
before `controller.close()`. A journal write/flush exception can therefore
skip the first original close. The frozen large main also wrote the same
journal before its final report bookkeeping. A49's independent outer adapter
provided the model for this narrowly scoped A50 correction.

Only the emitted **large `main`** gains the controller adapter and terminal
journal handling. Both arms use the same registered factory. Each original
controller is registered before its fallible `start`, and its bound original
close can be invoked at most once. A successful repeated wrapper call returns
that actual cached result; an attempted incomplete close is refused. There is
no second wait4, new signal sequence, restarted cleanup budget or reconstructed
wait evidence.

Each `run_controller` has an outer `finally` that handles an unattempted first
close **before** block host/source postchecks. A fallback always marks the
controller and complete comparison failed, even if that original close reaps
successfully. It records only actual startup/shutdown receipts and never fills
in missing CPU scopes, fixture proofs or slot outcomes. The enclosing main
also finalizes any remaining registered state before touching the journal.

Final row retention, flush, fsync, journal close and journal receipt errors are
retained separately. Any report error forces `complete=false`, `passed=false`
and failed phase. A device that also refuses report writes can still prevent
report persistence; original child cleanup now precedes those final writes.

The original **38 top-level measurement/custody helpers are AST-identical after
label substitution**, including `run_controller`, controller type/close,
wave handling, fixture logic, CPU scope and numeric summary. The fixed 80-call
ABBA inventory, 32 waves, 3-second product budget, 10-second client budget,
300-second controller budget, fixed idle, original cleanup/final-fixture
budgets and every numerical gate remain unchanged. The small measurement and
numeric evaluator algorithms retain their original AST guards. Large protocol
metadata describes the symmetric adapter; no workload or numerical condition
is added or relaxed. See `binder.diff` and the focused
`large-main-adapter.diff` (83 net lines in main).

## One local failure-control-flow check

`local-journal-fault-check.py` was executed **once**, successfully. Its result
is `local-journal-fault-check.json`, a separate local control-flow artifact;
`passed=true` means only this check passed. It is not qualification, native
runtime execution or benchmark evidence.

The check uses the exact original `run_controller` definition plus AST-extracted
new main factory/finally code. It starts one owned local Python stdin/EOF
process and injects one deterministic journal-flush I/O fault mode before any
MCP call. The original finally encounters the same fault and skips close; the
new outer finally invokes that process's close once and retains an actual
local wait4 exit-0 receipt. It checks cached-repeat and already-attempted
incomplete refusal without invoking the original close again. No CPU, fixture
or slot evidence is fabricated. The same fault is then used to verify that
independent final-journal errors force complete/passed false and still close
the journal. Synthetic control-flow flags stay inside this test.

The check also compares all 38 original helper ASTs. There were zero remote
actions, zero runtime ELF executions, zero MCP calls, zero qualification
bindings and zero formal benchmark executions. This does not certify successful
A50 qualification or archive performance; those require the later actual
three-report binding and original fixed experiments.
