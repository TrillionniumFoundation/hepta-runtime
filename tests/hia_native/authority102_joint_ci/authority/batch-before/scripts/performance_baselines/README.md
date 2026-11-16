# Exact source reproduction for bounded access optimizations

These two immutable baseline inputs are authoring provenance. Each runtime
graph contains only the final owner in `native/`; no fallback image is linked.
The whole baseline SHA is checked before generating a new result directory.

From the native source root, use the pinned Hepta checkout as `HEPTA`:

```sh
python3 -B scripts/author_constructor_fast.py --hepta "$HEPTA" --baseline scripts/performance_baselines/text_result_constructor.hepta --output /tmp/constructor-reproduction
python3 -B scripts/author_input_fixed.py --hepta "$HEPTA" --baseline scripts/performance_baselines/batch_plan_input.hepta --output /tmp/input-reproduction
```

The generated `.hepta` bytes must exactly equal the final corresponding
`native/` owner. The original constructor author remains the first-stage
producer of the exact retained baseline. Proof files record complete unchanged
function graphs, and the two authors perform their equality assertions again.
These source proofs do not claim native execution or original comparison.
