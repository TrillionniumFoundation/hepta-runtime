# Native continuation policy research loop

This isolated Rust 1.95 crate extends the source authentication study from
`../weight_semantic_adapter_20261120`. It authenticates an original Hepta Neuron
gzip checkpoint, validates a finite policy compilation against that checkpoint's
stored law, executes an actual sparse policy, and restores independent research
state after failure or completion. It does not register a production MCP route.

## What executes in Rust

1. The existing adapter verifies original compressed and decoded checkpoint
   bytes, the complete 4324-coordinate F64 network directory, protected metadata,
   and reviewed source evidence. This crate also pins the exact reviewed task,
   forward, arithmetic and planning source digests it implements.
2. Rust independently propagates the checkpoint's original 33-by-33 transition
   tables and decoder confusion. It derives current belief, endpoint-six
   posterior and observation probabilities. It does not regenerate CTMC matrix
   exponentials from the eight raw physical parameters.
3. The capsule is bounded and complete: every legal continuation state and every
   structural outcome, including zero-probability outcomes, must be present.
   Rust checks the entire public schedule, complete state, action mask, pending
   request, completion, fee, topological order and reachability. Unknown graphs,
   states, observations and source bindings fail before admission.
4. Rust recomputes every Bellman score with ordered `f64` additions and selects
   the lowest action index on an exact tie. Candidate Q values and action arrays
   are witnesses to verify. They do not authenticate themselves.
5. Only the selected policy closure is retained in the executable native
   program. Each real step reconstructs the entire successor state. Snapshot
   restoration replays the saved trace and checks the final complete state;
   merely supplying a plausible saved state is insufficient.
6. A finite quality/resource gate can return `KEEP_ORIGINAL_AND_STOP` or return
   bytes for an independent candidate file. Unknown horizons, future cost bounds
   or utility conversion rates cause KEEP. A disposable byte slot stages the
   verified program and restores its original anchor after success, rejection,
   evaluator error or Rust panic unwinding. No original checkpoint file is
   opened for writing.

Automatic restoration across an execution callback is provided by
`ResearchByteSlot::run`. The public low-level `stage`/`finish` pair requires the
caller to finish its own manual staging; a bare `stage` does not install an
unwind guard. The guarantee covers Rust error returns and panic unwinding, not
process abort or forced termination. The byte slot is owned research memory,
so it is not a durable production transaction or an on-disk crash recovery
mechanism.

The six actions remain STOP, WAIT, READ, REPAIR, SUBMIT_0 and SUBMIT_1. READ
observes the completion boundary. The target remains `X_6 > 0`, including early
submission. REPAIR repairs the sensor; it does not reset latent state. There is
no independent financial Call/Put evaluator or first-passage objective here.

## Arithmetic and authority boundaries

Two numerical contracts are deliberately separate:

| Check | Contract |
|---|---|
| Native table propagation versus frozen Python posterior/probabilities | Absolute tolerance `2e-11`; no bitwise claim |
| Bellman scores from the recorded ordered graph edges | Every binary64 bit must match the frozen witness |
| Action selection from recorded graph Q | Exact lowest-index argmax |
| Full state transitions, fees, saved/loaded state and program | Exact, including all state fields |
| Independent native-law Bellman recomputation | Separate Q error, action difference and regret diagnostics; never substitutes a different candidate |

The graph's recorded numbers are accepted only after independent law and task
checks, and against separately reviewed source pins. A small permitted law
roundoff can still change a near-tie argmax; the independent diagnostics expose
that distinction. The implementation never treats numerical tolerance as
bitwise policy identity.

Pins are provided by the reviewing owner, separately from the candidate. Hashes
do not authenticate that owner, prove deployed code identity, certify independent
labels or prove the source program's mathematics. The finite NDU gate verifies
bindings and arithmetic of an externally reviewed evaluation contract. It does
not establish label custody or future hardware guarantees itself. Synthetic
tests cover its positive branch; actual Neuron replay defaults to KEEP because
the owner-pinned future contract is absent.

The policy capsule is an inference-program artifact, not a change to the
network's 4324 weight coordinates. Python remains responsible for enumerating
and emitting the sealed finite source graph. Rust now rechecks its stored-law
probabilities, complete task semantics and Bellman program, rather than trusting
an arbitrary caller-provided table. Native CTMC generator/exponential creation,
causal intervention planning, financial labels, weight editing and production
adoption remain outside this crate. The existing HeptaRuntime `rea_model` owner
remains the intended production owner; PR141 supplies prior fixed-anchor
composition research. This crate adds no competing owner or production route.

## Bounds

Default hard maxima are 8 MiB input JSON, 4096 full states, 36,864 edges,
100,000 original 33-by-33 matrix-vector products, six actions, three outcome
branches, three read requests and seven executed actions. Callers may reduce
these bounds but cannot increase them. Execution rejects an exhausted budget
without mutating the session. No wall-time guarantee is inferred from a work
counter or an observed benchmark.

## Reproduce

Keep this directory beside `weight_semantic_adapter_20261120`, using that reviewed
adapter source at PR143 commit `108b928d00fb56569731ac5a50235330dedb40ea`.
No private checkpoint fixtures are shipped in this public source directory.

```sh
cargo +1.95.0 fmt --all -- --check
cargo +1.95.0 check --locked --all-targets --all-features
cargo +1.95.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.95.0 test --locked --all-targets --all-features
cargo +1.95.0 check --locked --all-targets --no-default-features
cargo +1.95.0 clippy --locked --all-targets --no-default-features -- -D warnings
cargo +1.95.0 test --locked --all-targets --no-default-features
```

The real replay executable takes eight positional arguments:

```text
FIXTURE_MANIFEST MANIFEST_SHA256 FIT
CAPSULE_JSON CAPSULE_SHA256
COMPILER_SOURCE COMPILER_SHA256 NEW_REVIEW_DIRECTORY
```

The fixture manifest is the preceding adapter's original source capture. The
capsule follows `hepta-own-law-policy-capsule-v1`. `public_key` and `state_keys`
carry the Python text encoding; Rust verifies their decoded complete typed
values, and does not claim its own float formatting is Python canonical JSON.
The output directory must not exist. New files are explicitly marked `.review`
artifacts, not candidates admitted by the quality/cost gate.

`scripts/replay_fixed_dev.py` freezes the five original fit IDs and each fit's
first IID DEV capsule before replay. It records the binary/source hashes and
actual subprocess results. This is execution qualification of sealed artifacts,
not an additional efficacy holdout or a way to select candidates. The private
receipts preserve any earlier failed gate and every actual source replay.

The tests include fabricated Q, probabilities and posterior; altered full
state, masks, order, source and schedule; missing zero-probability branches;
delayed observations; exact ties; exhausted budgets; forged saved state; corrupted
native program; unknown NDU inputs; isolated positive save; and automatic
restoration after evaluator error or panic unwinding.

## Publication

Publish this README, Cargo manifest/lock, rustfmt configuration, `src/*.rs` and
the two source scripts only. Captured inputs, checkpoints, native programs,
session snapshots, logs, binary output and raw research receipts remain in the
private evidence package. This public directory alone does not constitute a
complete production HeptaRuntime qualification or a deployed trading result.
