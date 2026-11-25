# Reopened candidate fallback qualification — 2026-11-24

## Defect and change

The closed-interval planner can prefer a smaller exact threshold over a
profitable interior representative. Adding a scalar to serialized F64 biases
and then recomputing a neural forward pass need not produce the frozen score
plus that scalar. A single mathematical winner can therefore fail reopened
verification while an interior candidate would succeed. Verification alone
prevents a bad adoption but does not recover the discarded proposal.

The new bounded plan reserves the best original interior representative,
retains shifts with identical predicted policies, and supplies every plan
member to a selector that regenerates the plan and evaluates complete reopened
policies. KEEP remains the immutable parent choice. The old single-plan and
single-verifier interfaces remain compatible. No filesystem or durable owner
is added to the production policy module.

## Three distinct evidence classes

1. **Public synthetic rounding regression.** The frozen scalar readout is
   `constant = -0.06358258106565634`, `bias = 0.15391577434753906`, and the
   competing stop score is `0.09078237381574712`. The mathematical shift is
   `0.0004491805338644045`. After physically writing and reopening the three
   F64 bias elements, the continuation score is
   `0.09078237381574711`, below the stop score by
   `1.3877787807814457e-17`. The boundary retains the old policy, while the
   retained interior passes gains 0.7 and 0.6 on the explicitly synthetic
   two-state task. Both temporary files reverse to the full original SHA.
   This is an engineering counterexample, not a research-model result.

2. **A bounded real-checkpoint qualification.** One authenticated renewal
   checkpoint, fit 11, and one already exposed 701-state finite task were used
   with radius 0.125, fees [1, 1.25] and candidate limit 2. The native evaluator
   derives the representation and forward pass from the reviewed stored law;
   it performs no gradient training or raw CTMC refit. Both proposed
   candidates were produced by the existing canonical byte-patch planner,
   physically written, reopened, evaluated, inversely patched, and reopened
   again. Only the allowed 24 bias bytes changed. All original bytes and the
   complete source SHA were restored. The original root value was
   0.33209349031121554 and each reopened candidate had nominal value
   0.33309349031121555, with endpoint gains approximately [0.001, 0.00125].
   The original single-plan winner was already an interior: this case does
   **not** establish an incremental quality benefit from the new fallback.

3. **Negative natural search and explicit fault injection.** A frozen scan
   of 175 mathematical shifts (87 open-cell representatives), or 122,675
   state-by-shift pairs, found five forward/prediction mismatches. It found
   no state in that finite task where the mathematical winner failed strict
   realized gain and the retained best interior succeeded. This negative
   result is retained. A separate qualification intentionally corrupts the
   first candidate's verifier input after physical reopening; the actual
   native verifier rejects it, exact rollback succeeds, and the second
   complete candidate remains available. This is a fault-control result,
   not a naturally observed rounding gain.

No old 160-candidate campaign or fixed 288-state campaign is requalified here.
There is no new held-out generalization result and no comparison with gradient
training. Two-member reopening costs more validation work than a one-member
route; these receipts do not call unequal budgets equivalent. Real-checkpoint
bytes, detailed task records and machine paths are not included in this PR.

## Source and reproducibility

The original checkpoint is already publicly available at
[`hepta-private-ci@5669aa349fde9eb0b6692dbfaa55a1b9897f6e69`](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/5669aa349fde9eb0b6692dbfaa55a1b9897f6e69/tools/hcsn/wsp_native_value_20261105/value_edit/inputs/fit_11_C.json.gz).
An unauthenticated HTTPS fetch independently matched the authenticated gzip
SHA `fd4e8104066879320811d8276eb96ff524fcb224f80aab4dd20dacb4a9d628e9`
and 172,526-byte length. The input is not duplicated in this repository.

The private qualification inputs are source-bound by the example's exact
contract, bridge and law hashes. Its supplied directory contains
`fit_11_evaluation_contract.json`, `fit_11_C.json.gz`,
`original.safetensors`, and `fit11_world000_graph.json`.

```sh
rustc --edition=2021 -D warnings -O \
  qualification/weight_intervention_diagnostics_20261122/policy/advantage_veto.rs \
  -o /tmp/advantage-veto
python3 qualification/weight_intervention_diagnostics_20261122/policy/test_q_bias_reopened.py \
  /tmp/advantage-veto
cargo build --locked \
  --manifest-path qualification/weight_full_native_20261121/Cargo.toml \
  --example q_bias_reopen
# Pass explicit local source and fresh output directories; no service is started.
qualification/weight_full_native_20261121/target/debug/examples/q_bias_reopen \
  "$INPUT_DIRECTORY" "$NEW_OUTPUT_DIRECTORY" /tmp/advantage-veto
# Repeat into a different fresh directory for the declared engineering control:
qualification/weight_full_native_20261121/target/debug/examples/q_bias_reopen \
  "$INPUT_DIRECTORY" "$FAULT_OUTPUT_DIRECTORY" /tmp/advantage-veto \
  --inject-first-verifier-error
```

The example reuses `codec::edit`, exact radius checks, the reviewed source
authenticator, native hidden/readout functions and the same policy CLI. It
preserves the input checkpoint, restores all temporary candidate files, and
records each full SHA. It exercises offline selection and explicit rollback;
it does not exercise production adoption or durable crash recovery. Existing
production ownership and qualification requirements continue to apply.

The public CI runs the new entry-point test against both the standalone module
and the shipped Runtime command, preserves the 256-case closed-interval
oracle, and compiles/lints the real-checkpoint example. Full repository gates
remain separately defined by `ci.yml`; a path-filtered success alone is not
the full gate.
