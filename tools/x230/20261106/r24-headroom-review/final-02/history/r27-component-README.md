# R27 observation serializer mechanism benchmark

This benchmark embeds the actual baseline and candidate `prepare_observation`
functions, their `JobObservation` / `ObservationScript` enums, their size guard,
and the candidate payload enum. The original snippets are copied byte for byte;
private functions are exposed by identical benchmark-only adapters.

`generate.py` records the SHA-256 of both complete source files and every excerpt,
then re-extracts the generated modules to check every embedded byte and hash.
It does not pin the complete source hashes, so later formatting can be regenerated.
It writes only `bench.rs`; there is no separate manifest or adoption gate.

```bash
python3 generate.py \
  --baseline /path/to/accepted-r24/src/mcp/runtime/ssh.rs \
  --candidate /path/to/r27/src/mcp/runtime/ssh.rs \
  --output bench.rs
```

The generated `bench.rs` is self-contained and can be copied to the X230 build
directory. No source-file access is needed at execution time. Do not rustfmt the
embedded excerpts: regenerate after formatting the actual source instead.

## Build using the existing dependency cache

Use the same Rust toolchain and target that produced the selected dependency
artifacts. Set these variables to the exact cache and artifact paths; if several
hashes exist, use the matching build's artifacts rather than taking the first glob.
The dependency directory must also contain the matching `serde_derive` proc macro.
The commands use `panic=abort` to match this repository's release dependency build.

```bash
R27_DEPS=/absolute/path/to/target/release/deps
R27_ANYHOW=$R27_DEPS/libanyhow-EXACT_HASH.rlib
R27_SERDE=$R27_DEPS/libserde-EXACT_HASH.rlib
R27_SERDE_JSON=$R27_DEPS/libserde_json-EXACT_HASH.rlib
R27_LIBC=$R27_DEPS/liblibc-EXACT_HASH.rlib
R27_COMMON=(--edition=2021 -C opt-level=3 -C debuginfo=0 -C panic=abort
  -L "dependency=$R27_DEPS"
  --extern "anyhow=$R27_ANYHOW" --extern "serde=$R27_SERDE"
  --extern "serde_json=$R27_SERDE_JSON" --extern "libc=$R27_LIBC")
rustc -Vv
rustc "${R27_COMMON[@]}" bench.rs -o r27-serializer-time
rustc "${R27_COMMON[@]}" --cfg count_allocations bench.rs -o r27-serializer-alloc
```

Once the coordinated X230 build/qualification work has finished, run the two
binaries serially in a quiet measurement slot:

```bash
./r27-serializer-time > r27-serializer-time.jsonl
./r27-serializer-alloc > r27-serializer-alloc.jsonl
```

## What is measured

Six fixed cases cover Python status/read, system status/read, escaped Unicode and
control characters, and a Python read exactly at the combined 64 KiB boundary
under the stub. Both versions use one identical static Python command stub; the
real function's command String allocation is retained. The real system jobctl
command and newline are retained. This isolates request preparation, not command
building, SSH, queues, remote execution, or application throughput.

Before measurement, all six command/payload/timeout/system tuples must match byte
for byte, and a separate assertion verifies lexicographic serde_json Map ordering.
Input construction, correctness checks, output formatting, and JSONL writes stay
outside all measured batches. Each call black-boxes input/output and drops the
output within the loop. Timing uses plain `System` with no allocation probe code,
two fixed ABBA rounds per case, 100,000 calls per small batch and 2,000 per near-limit
batch. Every raw CPU/wall sample is retained; summaries use all samples equally.

The separate `count_allocations` build counts `alloc`, `alloc_zeroed`, `realloc`,
`dealloc`, and requested bytes over 1,000 calls per case/version after warmup.
It reports no timings. Requested bytes sum allocation sizes and each realloc's
requested new size; they are not RSS, peak heap usage, or net live bytes.

This is a mechanism comparison, not a performance acceptance rule. Real-command
payload limits and error precedence have repository sibling tests, but those
tests have not been run as a Cargo qualification for this experiment.

## Recorded execution and disposition

The original attempt stopped before compilation or sampling because its R25 cache
fingerprint was absent. `run_component_02.py` preserves that failure and selects
the exact matching four third-party dependencies from the verified R26 cache;
it does not link a Hepta production library. The benchmark source, matrix, order
and counts were unchanged. The second attempt completed successfully on X230,
with all 48 timing records, 12 allocation records and both builds' six byte-exact
equivalence checks retained under [evidence](../evidence/component-02/).

The ordinary equal Python status/read mix saved 0.61852976 microseconds per call.
This remains a component CPU result, not an RPC throughput or RSS result. R27 was
not promoted to full qualification or six-host acceptance. See the
[experiment report](../../../../../docs/X230_OPTIMIZATION_20261105_R27.md) and
[evidence index](../README.md) for the complete result and limits.
