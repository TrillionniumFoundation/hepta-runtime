# Independent original reference for result publication

This is a test-only reference, not a production runtime or a serializer fallback.
It executes the frozen original `append_hints` function and the original locked
Rust JSON/MCP libraries. The production result owner and publisher remain HIA.

## Reference authority

`source_manifest.json` pins three complete original inputs from runtime commit
`2173a00ec314ebc0c5ada21e4cb60d8efdccb99a`: `src/mcp/server.rs`, `Cargo.toml`,
and `Cargo.lock`. `verify_sources.py` checks their current bytes, then extracts
the exact 258-byte original `append_hints` function into an isolated output
crate. The final harness does not carry a duplicate original Rust tree or a
second complete original dependency lock. Git history is not needed at runtime.

The 73 registry packages in the small oracle lock have the same versions and
checksums as the original lock. The serializers are `serde_json` 1.0.151 with
the original `float_roundtrip`/`raw_value` features and `rmcp` 3.4.1. The driver
calls `CallToolResult::success` / `CallToolResult::error`, wraps the result in
`ServerResult`, and calls the real SDK's
`ServerResult::strip_result_type_for_legacy_peer`. This is the normalization
used by `rmcp`'s server handler for the selected MCP protocol `2025-06-18`.

The tiny test-only `request_ctx::drain_hints` supplies the input list verbatim.
It deliberately models the **already drained** boundary. Empty and repeated
hints remain observable. Request-context collection, first-occurrence
deduplication, task scoping, and cache lifetimes are owned and tested separately.

Four modes are covered:

| Mode | Original reference operation |
|---:|---|
| 0 | Exact original `append_hints` text bytes |
| 1 | `serde_json` quotes the original composed string |
| 2 | Actual SDK serializes one text `CallToolResult`, after legacy protocol normalization |
| 3 | Preserve a supplied trusted native RPC prefix, quote the composed string with `serde_json`, append the actual SDK-derived result suffix and the RPC closing brace |

Mode 3 is a private composition boundary. This reference does not parse or
authorize that prefix. Modes 2 and 3 accept `is_error` as an envelope input;
this does not assert that the original filesystem handlers append hints to
their `Err` branches.

## Independent input and native evidence

`cases.py::iter_cases()` yields 90 complete logical inputs and does not compute
their expected output. They include all control escapes, embedded NULs,
normalization-distinct Unicode, all 1,112,064 Unicode scalar values, empty and
repeated hints, 4,097 distinct hints, byte boundaries around transfer windows,
base text over 8 MiB and 16 MiB, hint lists over 8 MiB, and JSON escaping that
crosses 8 MiB. Native tests split these logical strings across append calls.

Input binary framing is `HRPOI001`, then an LE u64 record count. Each record
starts with six LE u64 words: `case_id`, `mode`, `is_error`, `prefix_len`,
`base_len`, `hint_count`. The prefix and base follow, then each hint as an
LE u64 byte length and its complete UTF-8 bytes. A one-case file retains its
global case ID. Rust output is `HRPOO001`, an LE u64 count, then records of
`case_id`, `output_len`, and the complete output bytes.

The native corpus directory has `semantic-cases.jsonl`. Each row carries
`case_id`, `mode`, `is_error`, `input_path`, `output_path`, `output_bytes`, and
`output_sha256`; paths name complete gzip input/output files relative to that
directory. Optional descriptive metadata is preserved by the native suite.

`publisher-cases.jsonl` separately records complete successful stdout captures
from actual native ELF publisher runs. Each row has a unique `run_id`, a
`case_id` from the same logical corpus, `mode`, `is_error`, the complete gzip
`input_path` and `output_path`, their raw byte lengths and SHA256 values. A
supplied `returncode` must be zero. Repeated publications of the same logical
case may have distinct run IDs. Interrupted or failed writes do not enter this
success corpus.

`run.py` independently regenerates all logical inputs and compares every
captured native input byte before invoking the reference. It then compares
every original/native output byte, checks native output receipts, and records
all compressed artifact pins. It never accepts output hashes as a substitute
for byte comparison. It also indexes the fresh original output and compares
every actual successful ELF stdout byte. The complete driver requires both
semantic and publisher corpora; a direct-owner-only comparison is incomplete.
Native protocol refusals, private counter injection,
mapping growth, syscall partial writes, and ACK/cancel transitions are native
qualification domains, not synthetic original-Rust inputs.

## Reproduce

Run on the authorized build host or CI, with the native corpus already captured:

```sh
python3 tests/hia_native/result_publication_oracle/run.py \
  --runtime-root . \
  --corpus /absolute/native-publication-corpus \
  --output /absolute/fresh-original-replay
```

`--cargo /absolute/path/to/cargo` selects a Rust 1.95+ toolchain. `--offline`
is optional and only appropriate for a populated Cargo cache. The default
fresh CI build uses `cargo build --locked`; it may obtain pinned dependencies
from the registry. Every invocation requires a fresh output path and creates
its own fresh Cargo target.

The default expects both corpus manifests in the same directory. If the
successful ELF publication corpus is captured separately, pass its directory
as `--publisher-corpus`. Exploratory captures may be compared for diagnosis;
they do not replace the final native suite's source-bound qualification.

The output contains the materialized original function, small locked crate,
complete independent binary input, complete original binary output, actual
process stdout/stderr, and `RESULT.json` with source, binary, corpus, and byte
comparison evidence.

CI can import `run.py` and call `run(args, execute_callback, environment)`.
The callback receives keyword arguments `name`, `command`, `timeout`, `env`,
and `input_bytes` and returns `subprocess.CompletedProcess` with byte
stdout/stderr. The two real processes are recorded separately as
`result-publication-rust-compile` and `result-publication-rust-compare`.

## Scope of a pass

A pass establishes complete-byte equivalence for the recorded semantic corpus
against a fresh build of the actual original function and locked serializers.
The actual native publisher's syscall/ACK receipts remain a separate required
check. The finite corpus does not prove arbitrary-size behavior on its own;
the owner implementation and growing arena establish that design property.
This component does not replace the nine original filesystem tool callers or
establish a production concurrent request scheduler.
