# Native endpoint semantic replay

`weight_semantic_replay` is a read-only Rust MCP tool for one explicit renewal
endpoint contract. It reconstructs causal decision states, the public features,
posterior mass, endpoint bank, hidden vector, learned readout and finite-horizon
Bellman teacher from supplied checkpoint, schedule and trace bytes. It does not
accept a caller's hidden vector or teacher table as a substitute for execution.

The tool is visible in Runtime mode and uses the existing request-audit and
dispatch paths. The replay opens no files, starts no processes and edits no
weights. Normal Runtime request auditing remains active.

## Exact input boundary

The MCP envelope has exactly four required fields. Unknown fields and duplicate
fields are rejected by deserialization.

| Field | Meaning |
| --- | --- |
| `request_json` | Exact UTF-8 JSON text of the core request; 1 to 2,097,152 bytes |
| `expected_request_sha256` | Lowercase SHA-256 of the exact `request_json` bytes, including whitespace |
| `expected_core_source_sha256` | Lowercase SHA-256 of the compiled `src/mcp/weight_semantic/lib.rs` bytes |
| `expected_target_contract_sha256` | Lowercase SHA-256 of the compiled `src/mcp/weight_semantic/target_contract.json` bytes |

All three commitments are checked before the structured core request is parsed.
The target contract is a committed repository file, not a caller-selected
contract. Obtain its digest and the core digest from the exact built source
revision; a standalone source digest cannot be reused after porting or formatting
changes. The contract file is sorted-key compact JSON with one trailing newline;
the digest commits to those actual bytes.

The `request_json` object contains exactly:

- `profile`: `hepta.joint-renewal.endpoint-replay.v1`.
- `checkpoint_json`: exact JSON text of the supported checkpoint, at most 1 MiB.
- `expected_checkpoint_sha256`: lowercase SHA-256 of those checkpoint bytes.
- `public_json`: exact JSON text of the public schedule, at most 16 KiB.
- `expected_public_sha256`: lowercase SHA-256 of those schedule bytes.
- `traces`: 1 to 128 records with unique `source_row` values and up to six steps.

Each trace has `source_row` (an unsigned 32-bit identity) and `steps`. Each step
has `action` (an unsigned action ID) and `completion`. A completion is null when
no request becomes due; at a due boundary it contains `observation_tick`,
`failure`, and `observation`. Success uses observation 0 or 1; failure uses null.
Omitted optional completion fields deserialize as null. The requested end state
must be a decision state, so traces that stop or submit are rejected. A source-row
identity is not authenticated to an external dataset by this tool.

The checkpoint must declare `joint-policy-v1`, family `renewal`, 31 interior
coordinates followed by -1 and +1, 43 public features and dimensions 85/48/4. The
full checkpoint contains `schema`, `family`, `fit`, `public_dimensions`,
`head_dimensions`, `n_grid`, `coordinates`, `confusion`, `network`, `core`,
`target`, `bank_semantics`, `nominal_raw`, and `parameter_count`. The network has
`w1`, `b1`, `w2`, and `b2`. The core has `kind`, `tables`, `generators`, `raw`,
`physical`, and `optimizer_constraint`; each table has `dt`, `drive`, and `matrix`.
The nominal, generator and physical metadata are retained as supplied metadata,
not regenerated or authenticated. The transition matrices are the executed law.

The public schedule contains `schema`, `id`, `deadline`, `target_tick`,
`initial_budget`, `duration`, `drive`, `reliability`, `read_price`, `read_delay`,
`latency_price`, `repair_price`, `failure_probability`, `prior_distance`,
`packets`, and `packet_sha256`. The six packet identities are metadata only;
their files are neither opened nor authenticated. See the committed target
contract and preserved synthetic fixtures for the exact supported values.

## Target and numerical meaning

This profile predicts the strict endpoint event `X_deadline6 > 0`, including
early submissions. It uses the actual future scheduled drives and durations.
The nine bank values are strict-threshold probabilities at horizons
`min(t+1,6)`, `min(t+2,6)` and 6, each at thresholds -0.5, 0 and 0.5.

READ observes the latent state at the actual due boundary. Failure can break the
sensor; REPAIR fixes that sensor and charges the repair fee while leaving latent
mass intact. These are not First-Passage dynamics or latent Reset semantics.
The six action slots are STOP, WAIT, READ, REPAIR, SUBMIT0 and SUBMIT1. The learned
belief is the sigmoid of the fourth affine readout; the teacher instead uses the
analytic endpoint posterior under the supplied law.

Teacher utility is risk-neutral expected terminal reward minus future additive
read, repair and latency charges. STOP has zero terminal reward, a correct binary
submission earns +1, and an incorrect submission earns -1. Already sunk charges
remain in the encoder state but are omitted from future Bellman value. Selection
uses the first legal maximum in the fixed action order. Illegal scores carry an
explicit mask; zero-probability branches are skipped rather than renormalized.

Arithmetic is rounded binary64 with separate products and left-to-right sums.
The implementation uses platform `tanh` and `exp`; it is not an interval proof or
a declaration that two compiler/target builds have identical bits. It is not a
general NDU optimizer.

## Response and resource admission

The response preserves the core result's original top-level fields, including
`schema`, `profile`, `fit`, checkpoint/public identities,
`implementation_sha256`, scope flags, timing, cache diagnostics and `rows`.
It adds:

- `adapter_schema = hepta.weight-semantic-replay.mcp.v1`.
- Exact `request_sha256` and `request_bytes`.
- `core_source_sha256`, which must equal the core's `implementation_sha256`.
- `adapter_source_sha256` and `target_contract_sha256`.
- `maximum_concurrent_workers = 1`.
- False `weights_modified`, `independent_holdout_verified`,
  `task_value_improvement_qualified`, and `production_eligible` flags.

The response confirms native hidden and teacher re-execution for the supplied
law. `external_source_authenticated` remains false,
`supplied_checkpoint_law_only` remains true, and
`rounded_binary64_not_interval_proof` remains true.

A single owned semaphore permit admits the worker before structured parsing.
Additional calls fail as busy rather than forming an application work queue.
The blocking worker owns the permit until parsing, core execution and result
serialization finish. Cancelling the asynchronous waiter does not stop an
already running blocking task or release its permit early. A later request can
be admitted after that original worker actually finishes.

The core bounds traces to six steps, transition tables to 24, and each mass or
Bellman cache to 8192 states. Its cooperative deadline is 30 seconds beginning at
core entry; it is not a bound on transport delay or Tokio scheduling. Result
serialization is capped at 1 MiB and also respects Runtime's global result cap.
An over-limit result fails without returning a partial JSON success. Request
limits are measured in UTF-8 bytes, even though JSON Schema string lengths are
character counts.

## Qualification and certificate boundary

The port preserves the standalone r2 seven-test causal/numeric/rejection suite.
The port changes copyright/formatting and replaces the sole non-test `unwrap`
on the fixed prior-grid minimum with an explicit contextual error. The integrated strict Clippy gate also required a type alias for the mass-cache
key; its representation and algorithm are unchanged. These changes produce
a new source digest and require qualification of the integrated executable.

Additional tests cover raw-byte commitment, all envelope digest failures,
unknown/duplicate fields, exact byte limits, bounded output, released permits
after errors, retained permits after caller cancellation, an asymmetric readout
against an independent 70-decimal reference, and real MCP delivery/rejections.
The MCP test initializes Runtime in a separate child test process, so it does not
alter the global configuration of filesystem-only tests. Its synthetic host has
execution, PTY and write permission disabled and is never contacted.

Use `cargo test --all-features weight_semantic` for the focused suite. Full
qualification also requires both feature configurations, formatting and Clippy,
plus frozen corpus replay through the actual MCP binary. Preserve the Runtime
commit, lockfile, compiler, target, feature set, build flags, binary digest, raw
requests and raw responses. Record failures before interpreting them. A source
hash alone does not identify numerical execution.

This tool does not change `weight_continuation_certificate`'s provenance or
re-execution declarations. A caller-supplied semantic-result digest is not enough
to upgrade that verifier's trust claim. A later composite native operation must
invoke this core itself, or consume an authenticated Runtime-owned immutable
result, and join checkpoint, public schedule, core/contract, source row, legal
mask, target action and competitor action exactly. Newly reconstructed hidden
binary64 bytes form a new witnessed system. Recheck the frozen witness/radius;
never relabel an old proof.

Passing the engineering checks does not establish actual economic benefit,
negative-transfer bounds, OOD behavior, future-window value or live-trading
eligibility. No production model can be activated by this tool.
