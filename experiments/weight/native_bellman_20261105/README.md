# Native finite-DAG Bellman engineering replay

This increment implements a bounded Rust `weight_bellman_plan` method and
qualifies it together with the durable guarded-edit journal. The declared
public parent is Runtime PR #92, commit
`e7a2688acc5504412d45160a08d2bf864be6b650`. PR #92's trust-region source and
experiment remain immutable in that commit. All new receipts belong to this
increment.

The finite graph gives the planner an explicit **risk-neutral, additive**
global value problem. It can
then compute all state/action Q values without a gradient step, with fixed
arithmetic order and deterministic action selection. This is a bounded dynamic
programming primitive. It does not infer the actual environment law, reverse
engineer a neural network, edit a checkpoint, or certify a policy's performance
outside the declared graph. The exact input and response contract is in
`SCHEMA.md`.

The implementation covers this additive finite-DAG objective. It does not
implement entropic/exponential-moment or log-sum-exp value control, general
NDU/FBSDE optimization, or a general risk-sensitive recurrence for correlated
random fees. Declared branch-specific numeric costs are supported within the
additive expectation, including explicitly enumerated cost/successor dependence.
Generalization to correlated-cost tasks was not qualified in this replay.
Evidence for this increment must not be extended to a
later risk-sensitive or multimodal study without a new specification and
qualification.

## Why this replay uses two layers

The frozen Hepta experiment evaluates recursive values from canonical states
with zero sunk charges, while representative queries compute incremental fees
from their actual floating-point charge totals. Moving a fee outside the
probability sum or merging those numerical contexts can change a near tie.
The exported graph therefore contains canonical value nodes and representative
query nodes. Every successor precedes its parent, and queries point to the
canonical layer. The native tool receives only the graph, with no reference Q,
reference action, policy lookup table or truth field.

The corpus contains the same 320 already-exposed test worlds used by the
preceding scientific experiment: 246,160 graph nodes and 277,892 branches in
total. The largest world has 1,564 nodes, 1,824 branches and 418,509 canonical
Python parameter bytes. The export's largest probability-sum discrepancy is
approximately `1.961e-13`. These dimensions fit the native contract. This
migration replay is not a newly held-out scientific result.

## Frozen input and acceptance chain

`fixtures/requests` contains ten deterministic gzip request groups plus the
handoff receipt. The encoded request files total 2,988,116 bytes. The handoff
SHA256 is
`a895f3045db4b2e5d124f67448602782a1aa189904d04f5a1d02ef9fb68d6792`.
Each request contains only `request_id`, method name and `params.states`.
Request/reference separation was fixed before native execution.

The independent comparison protocol retains its predeclared gates: every legal
Q on both graph layers must satisfy absolute error at most
`2e-12 * (1 + abs(reference_Q))`; legal masks and actions must match exactly;
all 320 worlds remain in the denominator. The verifier also recomputes the
ordinary scalar graph recurrence and replays the already-frozen J trajectories
from native query-node Q values. A near-tie mismatch remains a failure. The
native runner never reads those references, labels, or verifier outputs.

`LOCAL_PROTOCOL.json` fixes the combined Rust gates and resource bounds.
`EXECUTION_PROTOCOL.json` is created only after the final source and executable
are frozen and before the corpus is executed. It binds the binary, qualified
source manifest, successful local qualification, request handoff, runner,
supervisor and helper source hashes. It is the input to the independently
frozen verifier.

## Execution and accounting

`run_native_corpus.py` executes the actual MCP tool for every request using a
private pinned executable and a runtime configuration with host execution
disabled. The corpus driver and transport use only Python's standard library;
the finite-DAG computation runs in Rust. Every attempted world retains its full response or explicit RPC
error. The record includes the canonical Python parameter hash, exact
transmitted-argument hash and complete JSON-RPC request-line hash. The native
typed-Serde commitment remains a separate field. No Python-policy fallback is
allowed.

`supervise_native_corpus.py` measures the entire driver process and its waited
descendants from spawn through termination. That interval includes Python
startup/imports, binary pinning, MCP startup, all calls, and the driver's final
output writes. Internal native/driver timers overlap it and must not be added.
The outer receipt explicitly identifies the small supervisor setup and receipt
publication work outside that interval. Original training, graph export,
independent verification/J replay, Rust compilation, LLM usage, transfer and
energy belong to separate cost records.

The corpus driver has a 600-second execution alarm after loading the bounded
request files; the supervisor applies a 660-second spawn-to-exit timeout and
bounded termination grace. The driver and MCP child receive separate 90- and
210-CPU-second limits, with 8-GiB address-space and 1,024-descriptor ceilings.
These CPU hard limits can terminate a process without running Python cleanup.
Previously flushed partial rows and the supervisor's termination evidence are
retained; arbitrary resource exhaustion is not claimed to produce a complete
internal receipt.

The final manifest binds all ten complete encoded output groups, their counts,
the internal and outer receipts, qualified source and local build receipts, and
the exact execution protocol. Larger groups use deterministic contiguous
chunks with a hash-checked parts manifest. Missing requests and tool errors are
retained as failed/missing evidence against the original 320-world denominator.

## Reproduction

Use the committed Rust toolchain/lockfile and an isolated target. The local
qualification runs formatting, all-features focused `weight_` tests, Clippy
with warnings denied, no-default-features focused tests, the all-features CLI
build, and a final format check. `--nocapture` preserves the journal tests'
actual subprocess SIGKILL/restart records. The earlier review-invalidated
journal compilation is preserved separately and is not counted as a pass.

After a successful local qualification, use
`prepare_execution_protocol.py --qualification <receipt> --requests <request-directory> --output <new-freeze-directory>/EXECUTION_PROTOCOL.json`
to create a new execution protocol bound to the reproduced executable and
source identities. The preparer also writes the qualified source manifest and
copies the local qualification receipt. Then invoke:

```sh
python3 experiments/weight/native_bellman_20261105/supervise_native_corpus.py \
  --binary /absolute/path/to/qualified/hepta-runtime \
  --inputs experiments/weight/native_bellman_20261105/fixtures/requests \
  --attempt /absolute/path/to/new-corpus-attempt \
  --protocol /absolute/path/to/frozen-execution-protocol.json \
  --qualified-source-manifest /absolute/path/to/source-manifest.json \
  --local-qualification /absolute/path/to/qualification.json
```

The resulting `corpus` subdirectory contains `NATIVE_CORPUS_MANIFEST.json` and
the complete output/provenance chain. Run the independently frozen scientific
verifier separately; successful RPC execution by itself is insufficient for
accepting Q values, actions, or task-value replay.

The same final executable is also used for the pre-existing seven-plan /
60-norm trust protocol and the journal's fresh-error/retry/tamper MCP contract
cases. Those regressions check new guard wiring and recovery compatibility.
They are engineering repetitions on exposed fixtures, not new model efficacy
evidence. A final source/executable check binds all phases back to the same
qualified implementation.

## Recorded outcome

The completed corpus and independent replay passed all 320 worlds, 246,160
nodes and 928,200 legal Q comparisons. Reference Q, independent scalar Q,
selected actions and all 320 known-world J utilities match exactly. See
`QUALIFICATION.md` for scope, full cost accounting, failed-attempt retention and
source/executable identities. `verify_records.py --repo /path/to/full-checkout`
checks published records and sources without launching a new experiment.
