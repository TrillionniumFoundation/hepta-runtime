# Native weight programs and finite NDU planning

This standalone Rust research crate connects a semantic checkpoint snapshot,
constrained readout compiler, causal controls, finite resource planner, and the
existing journaled canonical-owner interface. It does not register a public MCP
method, maintain a second model store, or change a production model pointer.

## Six-layer contract

| Layer | Executable responsibility | Remaining inference boundary |
|---|---|---|
| Semantic snapshot | Authenticate the complete F64 bridge, original and effective JSON, reviewed profile source pins, task, stored law, protected frontend, layout and edit domain | The reviewing owner supplies trusted profile pins; matching hashes do not prove source meaning |
| Hypothesis and causal controls | KEEP, primary, half-dose, opposite, four predeclared matched-norm random directions; full-network neuron-permutation probe | These interventions become causal evidence only after independent task evaluation |
| EditProgram | Recompute the actual 85-to-48 tanh frontend from source bytes and solve bounded readout equations without gradient updates | Agent-supplied input origin and teacher truth remain declared evidence references |
| Independent evaluator | The recovery interface binds evaluator source, law, task, candidate and result identities | A supplied evaluator must actually perform complete task, occupancy, preservation and cost checks |
| Artifact owner and recovery | Prepare exact expected-byte requests and complete candidate hashes; call the existing journal engine and canonical owner traits | Filesystem authorization and artifact publication belong to the existing owner |
| NDU planner | Exact finite-law Bellman recursion with compute and feedback budgets, probe/edit/train/verify actions, KEEP and stop | Transition probabilities, reuse counts, costs and gains must be calibrated before real-world optimization claims |

`prepare_selected_analytic` recomputes the plan and refuses publication when the
chosen first action is probe, training, stop, or a different analytic action.
`execute_research` and `recover_research` use the same recovery implementation
qualified separately against the canonical root owner. Typed prepared values
have private fields and cannot be deserialized as execution authorization.

## Snapshot and arithmetic

The only supported model profile is the existing
`NeuronJointRenewalEndpointF64V1` profile and endpoint-binary-submission task.
The source adapter checks the 85/48/4 shape, public43/grid31 metadata,
parameter_count=4332 (including eight physics parameters), coordinates, target,
CTMC table structure, and the four network tensors. This crate additionally
requires non-null bank semantics and authenticates the exact bridge layout.

The readout is **192 row-major weights followed by four biases**, not four
interleaved 49-value rows. Q-only permits rows 0 through 2 and biases 192 through
194. Belief-only permits row 3 and bias 195. Joint permits all 196 values. The
4,128 frontend parameters and embedded physics/task data remain protected.
Negative zero is preserved when a coordinate does not change. No F32 cast occurs.

An edited bridge may retain its embedded original JSON. Snapshot authentication
therefore also rebuilds and checks the effective JSON using the current binary
head. Its semantic receipt commits to that effective model. A self-hashed
snapshot cannot bypass a fresh comparison with actual source and contract bytes.

The evaluation contract has schema
`hepta.weight-program-evaluation-contract.v1`, task_class
`endpoint_binary_submission`, a nonempty `task` object, a `profile_pin`, and
`profile_evidence` containing the exact UTF-8 sources for `forward_code`,
`task_code`, `arithmetic_code`, `planning_code`, `target_contract`, and
`checkpoint_fetch_receipt`. An optional `profile_sources_binding_sha256` is
checked. Pins must originate with the reviewing owner outside the proposed edit.

## Direct compiler

Programs contain continuation scores, continuation gaps, or belief logits at
explicit 85-dimensional inputs. Hidden activations are computed by Rust from the
authenticated protected frontend. The compiler solves

`delta = A^T (A A^T + ridge I)^(-1) (target - A theta)`

using Cholesky, with a domain mask applied to the correction coordinates. It
rejects an empty or oversized equation set, stale identity, wrong task role,
wrong channel, nonfinite arithmetic, failed radius, and failed final equation
tolerance. It does not silently clip an infeasible correction into the radius.
The accepted output contains actual old/new little-endian bytes and an inverse.
The result is a proposed research edit, not a task-quality acceptance.

The L2 check uses repeated `hypot` instead of squaring tiny displacements. Causal
controls check the **encoded candidate's** actual norm, so rounding away random
coordinates cannot be mislabeled as an equal-norm intervention. The equivalence
probe copies and permutes frontend rows/biases and the matching readout columns,
recomputes the complete network, and reports the intentionally broken-wiring
control separately. Source files are never modified by this probe.

Feature and teacher SHA fields are explicitly **declared references**, not
proof of input provenance or teacher correctness. Snapshot/byte authentication,
equation fitting, intervention evidence, and final task acceptance are separate
claims. A caller must not promote one into another.

## Finite NDU

The planner includes candidate verification cost before positive retained use.
Unverified candidates cannot have a positive use value. Every action consumes a
strictly positive compute budget; probability vectors, phase transitions and
dimensions are bounded. Dynamic programming enumerates finite compute/feedback
states, and ties prefer KEEP or the earlier declared action. The output binds
the full declared law and lists the reachable policy.

The finite-law optimum is conditional on the supplied law. LocalTrain is a
costed action in this planning model; this crate does not launch an unrestricted
training job. A real controller must account for observed costs and new evidence
before constructing another plan. It must not reselect on a sealed confirmation
set or treat a hypothetical reuse assumption as an observed market quantity.

## CLI

All output files are create-only. Individual JSON documents retain the existing
8 MiB limit and duplicate-key checks. Batch planning additionally permits a
32 MiB collection of at most 2,048 individually checked requests; it never sends
the entire collection through a single-document size exception. `BRIDGE` is a complete F64 safetensors bridge; `SHA` is its full SHA-256.

```text
snapshot BRIDGE SHA CONTRACT q|b|joint NEW_OUTPUT
compile SNAPSHOT PROGRAM BRIDGE CONTRACT NEW_OUTPUT
controls SNAPSHOT PROGRAM BRIDGE CONTRACT SEEDS NEW_OUTPUT
equivalence SNAPSHOT REQUEST BRIDGE CONTRACT NEW_OUTPUT
prepare SNAPSHOT PROGRAM BRIDGE CONTRACT EVALUATOR_SOURCE NEW_OUTPUT
plan REQUEST NEW_OUTPUT
batch-plan REQUESTS NEW_OUTPUT
```

`prepare` emits the canonical owner's existing `{path, expected_sha256,
tensor_name, edits}` request structure within a recovery intent, after deriving
the complete candidate hash in memory. It does not itself publish an artifact.
The source path is explicit and absolute; the canonical owner still validates
its filesystem boundary at execution time.

## Verification

Seventeen tests cover independent closed-form solutions, channel/layout masks,
exact inverse bytes, effective-head receipts, invalid freshly rehashed model
semantics, forged snapshots/profile bytes, norm underflow and encoded control
rounding and hard-radius rejection, bounded collection parsing, NDU information value/cost/resource stopping, and planner-to-owner
handoff refusal. Synthetic profile texts are marked as structural test fixtures.

Run `run_qualification.py --output NEW_DIRECTORY` with pinned Rust 1.95.0 and
the existing dependency cache. It records source pins, fmt, check/clippy/test in
both feature modes, executable build, command logs, CPU/wall and binary identity.
This is standalone qualification. The separate recovery PR builds the complete
root library and exercises real SIGKILL recovery with the real canonical owner.
Neither is a green full-project release claim.

The associated research studies separately compare five real shared heads,
matched-objective QP versus PGD, fixed causal interventions on exposed tasks, and
216 hypothetical finite NDU scenarios. Scientific result evidence is retained
with its original protocol, exact source identities, selection boundary and
measured cost scope; it is never inferred from this README or test count.
