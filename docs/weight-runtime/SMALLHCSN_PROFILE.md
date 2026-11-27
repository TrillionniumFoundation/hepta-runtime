# Native SmallHCSN restricted profile

This isolated example computes the complete six-tick body from raw sequences and
an actual canonical Safetensors artifact. It uses the repository's existing
`anyhow`, `serde`, `serde_json` and `sha2` dependencies. No new dependency or
Python call is involved in native evaluation.

Install `weight-smallhcsn-research.rs` as a repository example. Install the six
other Rust files under `examples/native_smallhcsn_profile/`. Build and test using
the repository's approved commands/CI. The example takes seven positional
arguments, each path absolute:

```
weight-smallhcsn-research PROFILE_JSON PROFILE_SHA ARTIFACT ARTIFACT_SHA RAW_INPUT INPUT_SHA NEW_OUTPUT
```

The profile is an external, explicitly hashed manifest. Its declarations bind
the exact header, tensor shapes, immutable tensor bytes, input and source names.
They do not establish model semantics by themselves. A separate finite
differential qualification receipt must identify the producer and measured
errors. Actual checkpoint pins, raw inputs and experiment-specific reference
outputs belong in the private qualification evidence, not public source code.

Supported configuration is explicit and deliberately narrow: eight neurons,
six active bins, three refractory phases and one unused state; mixed F32 learned
arithmetic/F64 physical operators; QVI boundaries; centered boundary-only
messages; four receiving neurons with five features each. Centering subtracts
the fixed nominal boundary from the old boundary message. It is unrelated to
population normalization. Other modes, shapes and immutable body changes fail
closed. This version admits only readout-weight differences from the committed
body; the separate readout bias remains committed.

The physical body performs boundary-root bisection, remapping across the changed
boundary, marked-state writes, repeated-reset CTMC propagation, first-passage
probability and discounted reward resolvent calculations. The exponential uses
the degree-13 scaling/squaring method of [Higham (2005)](https://eprints.maths.manchester.ac.uk/634/1/high05e.pdf)
with partial-pivot linear solves. Physical mass, nonnegativity, mark dominance
and first-passage/event-count bounds are checked at every tick. There is no
post-hoc renormalization or repair of an invalid state.

F32 reductions use explicit sequential multiply/add; the implementation does not
request fast-math or fused multiply/add. Cross-language qualification therefore
checks fixed absolute tolerances and decisions, rather than asserting bitwise
agreement with a BLAS implementation. Within one native binary, a restored
original artifact must reproduce the canonical output bytes.

The binary input layout is little endian: `HCSNIN1\0`, four u32 dimensions
`queries,6,2,9`, nine F32 means, nine F32 standard deviations, one F32 baseline
scale, raw `[query,tick,choice,feature]` F32 values, raw final `[query,choice]`
baseline F32 values, and one i64 binary label per query. The limit is 80 queries.
Rust computes `(raw-mean)/sd` and `raw_baseline/scale` in F32.

Output is `HCSNOUT1`, u32 query count and feature width20, then F32 arrays
`[query,choice,20]` features, `[query,choice,2]` raw heads and `[query,choice]`
scores. Six F64 physical maxima follow in the receipt's stated order, followed by
F64 mean squared margin error and u32 correct count. Margin arithmetic is F32
head1-minus-head0, F32 baseline-plus-contrast, then F32 choice1-minus-choice0;
only the final squared target error and average use F64. This objective is a
finite diagnostic, not the NDU global objective.

The CLI captures admitted artifact bytes before computation and reopens all
named inputs afterward to verify unchanged identities. The result uses a new
output file and never activates, overwrites or publishes a model. Artifact
patch/rollback ownership remains with the Runtime transaction layer.

This explicit-path example is a standalone research CLI. Its path checks are not
MCP workspace admission, and it must not be exposed as an MCP operation without
the Runtime's workspace and artifact-owner policy layer. A shared 60-second
wall deadline covers file reads and the complete computation, with checks at
every query and tick. Admission or numerical failure produces no result file.
