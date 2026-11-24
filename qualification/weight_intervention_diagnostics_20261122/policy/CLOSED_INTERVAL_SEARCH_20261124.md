# Closed-interval continuation-bias search

The scalar planner at source `f4e0582e16284f54451bb3a15cc959ad68fb7aac` considers representable open-cell midpoints. That declared search omits feasible policies at exact action ties and at either endpoint of a closed coordinate radius. The revision includes those policies and charges their evaluations to the existing 50-million state-by-shift budget.

## Reproduced coverage gaps

The original source and revised source were compiled locally with the pinned official Rust 1.95.0 toolchain (`59807616e1fa2540724bfbac14d7976d7e4a3860`). Three synthetic finite decision graphs have a strictly preferable policy only at the indicated scalar. The original executable returns KEEP for all three; the revised executable finds each policy.

| Fixture | Scalar | Action vector | Gain at fee multiplier 1 | Gain at fee multiplier 2 |
|---|---:|---|---:|---:|
| Positive closed-radius endpoint | 0.125 | 14 | 0.7 | 0.6 |
| Negative closed-radius endpoint | -0.125 | 04 | 0.9 | 1.0 |
| Isolated shared threshold | 0.125 | 100 | 0.7 | 0.6 |

At a shared threshold, action 1 defeats stop action 4 in the first state, while stop action 0 defeats action 1 in the second. The resulting `100` policy differs from the policies in both neighboring open cells. Canonical ascending-action tie order is therefore part of the optimization domain.

The CLI fixtures are in `test_policy_ranges.py`; the compiled Rust tests additionally cover an adverse fee interval and rejection when the extra boundary evaluations would exceed the existing work budget. All 12 policy tests pass, including the nine unchanged baseline tests. Both compiled executables use the same production `src/weight_policy` modules through the existing standalone entry point.

## Independent finite oracle

`test_q_bias_cells.py` uses seed 20261124 to create 256 six-state graphs with dyadic scores. It enumerates a fixed complete scalar grid, selects among all six legal action scores directly, and computes incumbent-relative values with exact rational arithmetic. It does not reuse the Rust threshold enumeration or floating-point policy DP.

There are 74 graphs with strict available improvement. The original executable misses the best worst-endpoint gain on five graphs; the revised executable matches the oracle on all 256. The existing diagnostics workflow runs this check through both the standalone executable and the shipped `hepta-runtime weight-policy` entry. Local validation covered the standalone executable; hosted results must be checked for the new commit separately.

## Numerical and acceptance contract

Coverage is for the supplied scalar-switch model whose thresholds are computed from frozen binary64 score differences. Exact physical switching points after a serialized bias write and a full neural forward pass can differ. The output format retains `open_cell_count` in its fifth column, while the budget counts open-cell representatives, thresholds and radius endpoints together. The final gain tie break selects among these evaluated representatives.

The existing source/candidate identity binding, physical reopening, realized-action evaluation and inverse restoration remain necessary for an actual checkpoint. The fixtures establish a search improvement under their supplied finite laws. They supply no new checkpoint, unseen task, model training, production adoption or measured trading gain.

## Reproduction

From `qualification/weight_intervention_diagnostics_20261122`:

```sh
rustc --edition=2021 -D warnings --test policy/advantage_veto.rs -o policy-tests
./policy-tests
rustc --edition=2021 -D warnings -O policy/advantage_veto.rs -o advantage-veto
python3 policy/test_policy_ranges.py ./advantage-veto
python3 policy/test_q_bias_cells.py ./advantage-veto
```
