# REA lifecycle v2 tooling and source projection checkpoint — 2026-11-09

This checkpoint preserves the intermediate ledger produced by the
[r1 source-only refresh](../rea-concurrency-source-projection-20261109-r1/README.md)
and recomputes the current projection after introducing the versioned
[parallel/cancellation lifecycle profile](../../rea-native/ELF_LIFECYCLE_QUALIFICATION.md).
No native binary, original npm provider or external lifecycle qualification was
executed for this checkpoint.

## Exact ledger continuity

[REA_6_8_0_LEDGER.before.json](REA_6_8_0_LEDGER.before.json) contains the exact
779,163-byte intermediate ledger, SHA-256
`0b52b1742d2bf6e7cf24c1214614e785b0c59034a2c07f53c4caa240ebe6d871`.
The r1 archive continues to preserve the original ledger with SHA-256
`489bf18663c8ff4cfae8d7ab81b143d0528bcf693033547d03b3d307de73fefa`.
Its records and receipts were not replaced.

The existing `published_pin`, `snapshot_rows` and `assemble_ledger` functions
were run again. The projection is **unchanged**: the existing runtime mapping
does not select the lifecycle producer, consumer, tests or profile document.
These execution inputs are separately included by the lifecycle producer's
complete source snapshot when that profile is actually run. The maintained
CAPABILITY_MAP was not broadened to make this checkpoint appear qualified.

All 229 tool rows and qualification fields, 34 native interfaces, other ledger
fields, INPUTS, MAP, ENVIRONMENT and generator bytes remain unchanged. The
current ledger retains 229 OPEN operations and 0 qualified operations.
[Mapping checks](mapping-checks.json) record actual exit 0 for `check-mapping`
and expected exit 3 for `check-mapping --require-parity`.
Raw upstream references were **NOT_REVERIFIED**.

## Versioned lifecycle behavior

The current producer emits `linux-owned-lifecycle/v2`. Its new
`worker-parallel-cancel` scenario holds two original workers with pidfds,
submits eight additional baseline requests, requires their original successful
responses while those same workers remain stopped, and then checks cancellation
and complete original reap/drain within five seconds. Two rounds exercise
16 additional responses and four distinct original workers.

The consumer preserves the original v1 capacity/cancellation branch byte for
byte. Its v1 profile retains its original session set and gates. A v1 receipt
cannot establish v2 parallel behavior by changing its profile label. The v2
profile still reports whole-operation qualification as false and leaves the
unimplemented original-provider deadline gate OPEN.

## Local tests and limitation

The complete `rea_*tests.py` suite ran **303 tests: 302 passed, one errored**.
The original output is retained as [rea-python-gate.log](rea-python-gate.log).
The single error is the actual owned-process descriptor/drain test: this cloud
environment lacks `/proc/<pid>/task/<pid>/children`. Missing process inventories
remain an error; the observer and test were not weakened or skipped.

The new parallel producer/consumer suite passes all 15 cases, including capacity
refusal, incomplete sample, late response, resumed or replaced worker, incomplete
inventory, omitted pidfd, zombie, delayed drain and extra process-control refusals.
Both versioned receipt/relocation suites pass all 20 cases. Their synthetic rows
exercise consumer logic and do not constitute native/provider qualification.

[The source checkpoint manifest](source-projection-refresh.json) binds the
modified lifecycle inputs, both ledger identities, r1 receipt identity, unchanged
inputs and exact test-log bytes. Linux process observation and the complete v2
native/reference profile require their own actual execution evidence.
