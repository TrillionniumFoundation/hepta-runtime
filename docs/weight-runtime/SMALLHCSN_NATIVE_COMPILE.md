# Native shared proposal through the existing fixed session

This increment is based on the frozen stage2 overlay, whose manifest SHA-256 is `3eb84701030ae11cf4873ee2c39cf5bf068ea4bad888fff276a15f8665ac6c7f`. It adds no store, publisher, owner or model evaluator.

The new `smallhcsn_compile` variant retains the same fixed-profile authority and effect admission as preparation. Its input contains the original profile JSON and raw HCSNIN1 bytes, the existing pure compiler parameters, and 480 explicit `(query, choice, tick)` identities. Each target row follows its matching identity. The adapter rejects missing, duplicate, out-of-range and non-slow-tick rows, then reorders the complete table to slow tick 0/2/4 → query 0..79 → choice 0/1. A Python choice-major array cannot be silently treated as the Rust order.

The native REA admission supplies the source path; callers cannot supply a path, executable, state root or parent numeric words. Actual parent bytes, their complete SHA-256, the fixed canonical profile and actual raw-input SHA-256 produce an opaque BoundModel. The compiler reads the forty original F32 words from that bound model and derives normalized keys from the raw input using the unchanged normalization order.

The existing 10×4 shared solver uses fixed ridge 0.02, protected-key weight 0.25, bounded Cholesky systems and at most 128 multiplier bisections. Its floating-point KKT and surrogate objective evidence remains numerical. Actual represented-F32 updates pass the existing exact integer radius checker. The adapter then uses the original hidden layout parser and exact scope validator to produce a complete PlanParams, including all forty edits, complete candidate SHA-256 and native program/source commitments. It publishes no artifact and executes no six-tick model.

Targets, parent-correct masks and trace provenance remain declarations. Source admission does not turn them into measured correctness, calibrated NDU values or preserved future recurrent offsets. The preactivation surrogate does not independently preserve sender cost.

## Binding across requests

A preparation/roundtrip Input can carry the identical optional proposal. When present, native admission recompiles the proposal from its actual snapshot and raw bytes, then requires the complete caller PlanParams to match the native result. It does not trust a serialized compiler receipt as permission or evidence of execution. With no proposal, the original manually specified exact plan remains available, and native proposal qualification is false.

The normalized program commits the transport table and explicit row identities, canonical compiler request, profile/raw/parent, compiler and evaluator source bytes, fixed parameter count and five-second pure compilation cap. Its identity is included in the existing cohort binding. The complete original proposal, native compilation evidence and measured preparation cost enter the same original durable intent, with no new replay store. Recovery reads those old commitments and never recompiles a proposal.

## Cost accounting

A normal compile → prepare → roundtrip sequence performs three pure supervised quadratic fits, one in each request. Each phase reports its own count and actual compiler/materialization wall time. Preparation also reports complete source-admission time and the additional exact radius validations: one hidden plan global check, two cohort member checks and one cohort global check. The compiler separately reports every F32 realization radius check and the materialized-plan global check.

Zero model forwards means zero model forwards; it does not mean zero work or free optimization. The existing three nonrefundable model reservations and original sixty-second window remain unchanged. Original cost records are labeled as original when a later request reuses them; recovery and result reuse report zero new pure compiler invocations.

## Qualification status

The root's isolated pure math kernel has actual Rust 1.95 synthetic evidence: eight controls passed. Those bytes are copied unchanged here. The integrated wrapper, session variant, source admission and new controls have not yet been typechecked, compiled, run through MCP or exercised on a model by this agent.

New authored controls cover explicit row reordering and malformed rows; program identity changes under data/profile/evaluator changes; and actual session snapshot compilation followed by native preparation and a tampered-plan rejection. That last synthetic control intentionally invokes three pure compilers and zero model forwards. The existing actual-MCP fence control is extended to reject all five fixed-profile operations before their work. These are authored controls, not reported passes.

The optional `smallhcsn_plan` operation is described in `SMALLHCSN_FINITE_POLICY.md`. It recompiles the same native proposal once and runs the existing finite solver once. Additional planning/preparation requests therefore incur their own reported pure work; they are not included for free in the three-request example above. The original Python sender pilot uses slow/query/choice order; the noncanonical choice/tick/query test is a deliberate transport permutation control, not a claim about that pilot's layout.
