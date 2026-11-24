# Finite-task policy evaluation under uncertain fees and transitions

Build the versioned worker with `rustc --edition=2021 -D warnings -O policy/advantage_veto.rs -o advantage-veto`. The original input format and no-argument output remain available. Run `python3 policy/test_policy_ranges.py ./advantage-veto` to check the public CLI.

* `--fee-band MIN MAX` evaluates an interval for one fee multiplier shared by all edges. It prints the complete action vector and the two endpoint values for four policies. With fixed probabilities and rewards a fixed policy's value is affine in the multiplier. Both endpoint comparisons therefore cover the interval.
* `--uncertainty MIN MAX RADIUS` allows independent fee multipliers per edge in the closed interval and one independent tilt per state and action. The ordered branch scores are evenly spaced in [-1,1], or zero for a single branch. Multiply each probability by one plus tilt times its score, then normalize. The absolute tilt must be less than one. Fixed support, action masks, rewards, input order and the acyclic graph are part of this contract.
* The uncertainty output has five columns: name, minimum value, maximum value, a conservative lower bound on the change from BASE under a shared law, and action vector. BASE is the supplied incumbent. PROPOSAL evaluates the supplied candidate. MAXIMIN solves the worst-value objective by backward induction. DOMINANT refines decisions subject to a parent-relative bound. A positive minimum absolute value and a positive lower bound on change test different properties. An editor can keep the incumbent whenever a proposed change fails its required margin.
* These operators evaluate the supplied decision graph. Converting domain observations into a defensible graph, checkpoint localization, immutable edit receipts and model deployment belong to the caller.

The normal runtime entry point is now available from the installed binary:

```sh
hepta-runtime weight-policy --uncertainty 1 3 0.4 < graph.txt
hepta-runtime weight-policy --fee-band 1 2 < graph.txt
hepta-runtime weight-policy < graph.txt
```

An agent can call this command as a bounded job on an existing admitted host. Supply a frozen input graph and retain its hash with the source checkpoint and the proposal. A caller seeking strict improvement compares the PROPOSAL paired lower bound against its fixed margin, keeps the original on failure, and evaluates the materialized checkpoint before adopting it. The standalone research entry point calls the same Rust functions. The command takes no filesystem paths, uses no broker or model credentials and emits no parameter write.


## Planning a physical readout-bias proposal

Run `hepta-runtime weight-policy --plan-q-bias MIN_FEE MAX_FEE RADIUS`. Append the token `HEPTA_Q_SCORES_V1` to the existing graph, followed by six finite scores per state in graph order. The solver checks that the legal frozen argmax matches the incumbent. One shared scalar shifts the WAIT, READ and REPAIR readout biases. The other three scores and all relative rankings within each group are fixed. Radius is a coordinate bound; the three-coordinate Euclidean shift has magnitude sqrt(3) times the returned absolute scalar.

The program considers KEEP, the representable open-cell midpoints between distinct action thresholds, every exact threshold inside the scalar radius, and both endpoints of the closed radius interval. Exact thresholds matter: ascending-action tie order can produce a policy different from either neighboring open cell when multiple states share a threshold. Together these candidates cover every policy of the supplied scalar-switch model over the closed interval. It maximizes the smaller of the two root gains relative to the incumbent. A strict gain above 1e-10 is required for a proposal. Among evaluated gains within 1e-12 of the best admissible gain it chooses the smallest absolute scalar, then the smaller signed scalar. This tie break compares the evaluated representatives; it does not minimize the norm over every floating-point scalar in an open cell. The evaluator caps the product of states and all evaluated shifts, including thresholds and endpoints, at 50 million.

The single output row is `Q_BIAS_PLAN shift gain_at_min_fee gain_at_max_fee open_cell_count actions`. The fifth column retains the count of representable open-cell midpoints for interface compatibility; thresholds and radius endpoints are additional evaluated shifts. The graph fixes the transition law and rewards. Reopen the actual edited checkpoint and compare its full legal action vector with the returned vector before accepting its value. Physical rounding in a serialized neural readout can affect decisions at a score boundary, including a newly considered exact threshold or radius endpoint. The search covers the frozen scalar-switch model, not all representable serialized bias edits. Use the reopened verification below for the realized candidate. The separate uncertainty mode can then certify relative gain over independent transition and fee variations. The command only computes a proposal and reads its input from stdin.

### Verifying a reopened candidate

The scalar-switch thresholds above use the stored binary64 differences of the frozen scores. They are not a derivation of the exact switching points of a model's floating-point matrix multiplication and bias addition. `policy/test_q_bias_cells.py` checks coverage independently on 256 fixed dyadic-score graphs using direct six-action argmax on a complete grid and rational policy values. Run it with the same executable arguments as `test_policy_ranges.py`; both the standalone and shipped-command CI entries include it.

After independently binding the source and candidate to their file digests, recompute the complete candidate action vector from the reopened weights. Run `hepta-runtime weight-policy --verify-q-bias MIN_FEE MAX_FEE` with the same graph, setting its three action fields to incumbent, reopened candidate and predicted candidate respectively. Use plain graph input without a score table. The output gives the status, both **realized** candidate gains, count of planner/reopened disagreements and the final action vector. VERIFIED requires strict positive realized gains at both endpoints. KEEP indicates identical behavior, and REJECT returns the original vector when a change lacks strict relative gain. When rounding changes a proposed action, the decision uses the reopened gain. A caller must check graph and file identities and bind candidate promotion or rollback to the returned decision.
