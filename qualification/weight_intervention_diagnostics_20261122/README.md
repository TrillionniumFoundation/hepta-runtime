# Native intervention diagnostics for the Hepta research policy

The readout worker proposes a reversible correction from forward evidence. The policy worker vetoes an action change using the incumbent policy's continuation value under a supplied finite transition law. Both programs run independently of training and consume stdin. The persistent candidate/evaluate/restore owner remains the worker in the parent PR #150. These helpers produce research decisions; no model handle is promoted by either binary.

## Build and verify

Use Rust 1.95.0 and the standard library. From this directory:

```bash
rustc --edition=2021 -D warnings -O readout/localize.rs -o localize
python readout/test_entry.py ./localize
rustc --edition=2021 -D warnings -O policy/advantage_veto.rs -o advantage-veto
rustc --edition=2021 -D warnings --test policy/advantage_veto.rs -o veto-tests
./veto-tests
```

## Readout location

A 48-dimensional tanh activation and explicit bias form a 49-vector. Each support row contains either four unrounded reference-minus-observed preactivations (WSL1), or four lower and four upper drift bounds (WSL2). A little-endian packet begins with four magic bytes, a u32 case count, then a u32 probe count per case and row-major binary64 values. The worker receives no healthy weights or hidden fault indices. It enumerates the 196 one-coordinate hypotheses. The strict solver minimizes residual energy and requires a separated runner-up. The interval solver intersects scalar inequalities over all probes. It checks that every other output can admit zero drift. One feasible coordinate returns EDIT and a range in WSL2. Multiple feasible coordinates or an inconsistent model returns ABSTAIN. If the observation admits zero drift in all cells it returns KEEP. A rounded interval describes compatible corrections under the specified single-coordinate hypothesis. A multi-coordinate defect can be observationally indistinguishable.

On five real trained checkpoints each of the 196 coordinates was perturbed on a copy, with uniform absolute fault sizes from 0.1 to 0.5. On a new draw, the eight-probe strict baseline abstained on every rounded trace. With independent binary32 rounding at the two readouts the interval worker localized 980/980. For bfloat16 rounding it localized 978/980 with eight probes and 980/980 with 32. All accepted scalar intervals covered the true correction. At each precision/probe count 140 sham, two-coordinate, row-swap, wrong-reference or repeated-state controls yielded zero edits. The hidden activations in this experiment are double precision. The study changes output precision, not the arithmetic of the entire network. Exact file restoration requires the original bytes retained by the persistent owner.

## Conditional action changes

The policy binary consumes a complete finite graph, legal-action masks, rewards, transitions and fees, plus incumbent and two candidate action vectors. It evaluates the incumbent policy and implements one- and two-transition bounds, full incumbent-value vetoes, and a full one-step policy improvement reference. The external research evaluation reproduced all 298,664 actions and 640 values on 80 schedules. The action veto is a runtime action choice. It does not update a tensor. The proof of policy improvement is conditional on the supplied law and settlement fees.

## Evidence

The study uses the private finite-task inputs associated with hepta-private-ci PR #6956 and the reproducibility package from PR #6984. In this directory, records pin compiled results and input models; no model weights are distributed. For the interval experiment, install NumPy and point NEURON at the unpacked archive's neuron directory. The original archive SHA-256 is 8dff90e9af87e9c5dcfea9af47226856454d3bb449bef8fcb7b5dee865f4bc2b.

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python readout/precision_study.py "$NEURON" ./localize fresh-run --seed "$(python -c "import json; print(json.load(open('records/seed.json'))['seed'])")"
python readout/interval_summary.py fresh-run/results.json
```

The policy parity harness and raw per-world schedules are owned by the companion scientific study. Stored binary hashes and timings identify the measured executables; compiler paths and flags can change those hashes on rebuild.
