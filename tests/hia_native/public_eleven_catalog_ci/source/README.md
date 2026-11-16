# Current 11-tool catalog component

This package qualifies a fixed runtime-enabled catalog containing the nine
installed tools plus `batch_edit` and `weight_bellman_plan`. It preserves the
private slot 0 `HRMCD002` / `HRCATR02` ABI, including all 18 non-list branches.
It does not qualify tool bodies, the public async graph, all configuration
projections, or removal of the old runtime.

The implementation input is the current target's 136 raw Tool declarations.
The qualified HIA catalog policy is specialized by one installed-name mask;
the original visibility function and schema traversal remain intact. Actual
HIA policy → serde Value → SDK op 4 executions produce all 18 configuration
shapes. The two fixed slot 0 assets come only from that native pipeline.
Original expected responses are never an implementation input.

The static HIA catalog uses a deterministic LZSS constant stream, decoded by
HIA itself. Its 5,854 instructions fit the fixed 8,192 instruction limit. List
requests now require 6,960 workspace bytes, reported through the existing
`HGRWS002` workspace-growth frame. A successful entry still returns 32 and
publishes its complete fragment after the 32-byte response header. There is no
host decompressor, file data dependency, or second catalog semantic owner.

The current original handler sorts tool names and applies null/noise schema
normalization. Consequently, four retained tools' schemas differ from the
older nine-tool constant, and current modern cache hints use `public` instead
of that constant's `private`. Complete old/new per-tool fields are retained in
the static reader output. The native pipeline is compared to all 216 actual
original handler contexts, then to 432 freshly executed locked SDK projections
(typed serialization and the applicable peer policy). Disabled runtime policy
projects seven installed names; the unchanged slot 0 ABI itself has no config
bit and serves only the fixed runtime-enabled eleven.

## Qualification

`run_recipe.py --phase all` is CI-only because it freshly compiles the unchanged
target Rust source and the current SDK projection example. It preserves the
original capture's per-process deadlines. The new native pipeline and static
native domains each retain a 180-second process deadline; SDK projection
replay retains 60 seconds. Every HIA input, output, workspace and compiler
stream is kept in full. Eight physical, rehashed evidence mutations must be
rejected without executing native or Rust code.

`run_recipe.py --phase verify` and `verify_readonly.py` only read existing
evidence. They do not update reports, reconstruct mutation fixtures, execute
processes or invoke HIA images. The guard is a regression check for the fixed
Python reader, not a general filesystem sandbox. Its complete before/after
byte and metadata checks are retained separately.

All source comes from target `d3d75c30719db966b004756f610007a7c723729e`, locked
RMCP 3.9.0 and the pinned Hepta compiler
`d3e2c90173cf733e42b299d0c4274df4b593a12f`. Local development may reuse the
already qualified B3 cache; the CI recipe records its own fresh compilation.
