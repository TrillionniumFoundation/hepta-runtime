# Process-capture Evidence import validation

This module removes the process-capture payload validation gap for the frozen
REA 6.8.0 import contract. It validates the retained `normalized_result`
of an Evidence record whose predicate is `rea.process-capture`.
It does not run an observed target, implement a process adapter, or establish
that an imported observation is true.

## Boundary and retained data

The shared Evidence source layer performs the bundle schema, record identity,
unknown-history and canonical manifest checks before this domain check. Its
process submodule accepts a borrowed JSON value and an optional key-order
resolver. Validation issues use paths relative to the capture root. The parent
source layer prefixes the resolver's lookup with the record's
`records/index/normalized_result` location and wraps an invalid description
with the frozen bundle error message. Missing ordering metadata remains a
profile gap rather than a claim that the source is corrupt.

The check does not replace or normalize the retained payload. The frozen Zod
parser strips undeclared members of non-strict nested objects, and ignores an
own `__proto__` key in both records and strict objects. The validator applies
that parsed projection only while computing the relevant scenario, comparison
and normalization commitments. Ordinary unknown members, including
`constructor` and `toString`, keep their declared strictness.

## Checks

The implementation retains declaration-order structural diagnostics, including
nullable and optional fields, discriminated unions, safe-integer bounds,
strict-object unknown-key order, and the exact UTC ISO datetime calendar and
precision accepted by the frozen Zod dependency.

Its semantic checks cover:

- Scenario, comparison, normalization and selected-executable commitments.
- Contiguous frame/interaction sequences and ordered observation timestamps.
- Global event-journal order, reference bounds, uniqueness and completeness;
  an empty journal remains valid because the reference allows it.
- Initial/final filesystem checkpoints, deadline exit-code rules and the
  committed finalization interval, signal order, elapsed time and observed exit.
- Raw, rendered and normalized UTF-8 retention budgets, sampling coverage,
  filesystem enumeration and digest omission records, and aggregate truncation.

The explicit `z.int().safe()` checks in the frozen dependency emit two safe
range issues for an out-of-range integer. Fractional inputs abort once. The
native checks preserve that behavior because the public error description
includes the number of remaining issues.

## Verification retained for this change

The actual installed REA 6.8.0 parser under
`/home/qian-qi/work/hepta-rea-reference-20261103/install/node_modules/rea-agents`
was called by Node v22.23.4. The finite final corpus contains 7,307 synthetic
validation inputs: 416 accepted and 6,891 rejected. All native acceptance and
full error descriptions match. This includes every populated shape field,
adjacent primitive/number boundaries, all file-effect and coverage branches,
finalization failure precedence, UTF-16 object-key ordering, and strict-object
prototype-key behavior.

Seven Rust regression tests, strict all-target Clippy, and the isolated parser
driver build passed with Rust 1.95.0. The driver compiles the new production
modules against the production source validator and the exact production
canonical-number/streaming-canonicalizer functions. It is a parser boundary
test, not a final runtime binary or public MCP test.

The exact driver crate, lockfile, generated corpus, earlier failed receipts and
final output remain under:

`/home/qian-qi/work/hepta-rea-process-capture-evidence-ca464-20261105`

The final differential receipt is `differential-r3/summary.json`.
The repository's `tests/rea_process_capture_differential.mjs` can rerun this
corpus with explicit `--reference`, `--native-driver`, `--source` and a
new `--output` directory. It pins the six frozen reference modules and
checks the selected source, Node and driver identities before and after.

The complete process adapter, device observations and final combined-binary
MCP import qualification remain separate gates.
