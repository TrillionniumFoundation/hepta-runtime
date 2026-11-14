# HIA native runtime

This directory contains the current HIA implementation of deterministic runtime
components and a persistent native MCP stdio service. All implementation sources
in this directory use `.hepta` and are compiled by HIA to machine code. The Linux
executables have no Python, Rust, libc or dynamic-loader runtime dependency.

The complete existing runtime has **not** been replaced. Its 125 registered MCP
tool handlers and the durable/remote service owners remain in their original
implementation. This native service currently advertises two implemented tools:
`runtime_native_info` and `runtime_line_hash`. Production activation and deletion
of the original runtime remain incomplete.

## Fixed source baseline

| Input | Exact Git identity |
| --- | --- |
| Runtime source | `a0dcdda1991ec536d5e2d252c006a778993fa566` |
| Runtime tree | `98d96c88d54082637c27f1cbfae61a66d0dd81e7` |
| Hepta compiler | `f33d8da316de8fdf27b504371f1a5310997ff548` |
| Hepta tree | `378bc0dc613befc7006f1514bd2229357ae0d07c` |
| Native target | Linux x86-64, LP64, SysV AMD64 |

The runtime baseline is the head of the existing #118 → #119 → #120 integration
stack. The older `hepta-runtime-base` default branch does not contain that
complete functionality. This work preserves the integration stack as its base.
Hepta already uses the `.hepta` suffix; protocol names such as `hia-asm.v1`
continue to identify the language and are not filename extensions.

## Native components

| Source | Implemented behavior |
| --- | --- |
| [runtime_bytes.hepta](runtime_bytes.hepta) | Existing line hash/ID, strict and clamped line indices, log cursor/page arithmetic, name/digest/text predicates |
| [runtime_protocol.hepta](runtime_protocol.hepta) | Strict JSON, JSON-RPC IDs/errors, protocol negotiation, initialization lifecycle, native tool responses and line hashing |
| [text_budget.hepta](text_budget.hepta) | Original byte-based token estimate, binary64 boundary behavior, MiB formatting, line ranges and head/tail truncation |
| [line_endpoint.hepta](line_endpoint.hepta) | Original typed line-endpoint parsing, Unicode trim, integer boundaries, hash normalization and exact diagnostics |
| [delta.hepta](delta.hepta) | Original bounded Myers line diff, exact hunk rendering and deletion markers, CRLF normalization and Rust line splitting |
| [stdio_packer.hepta](stdio_packer.hepta) | ELF construction and persistent newline-delimited input/output transport |
| [filter_packer.hepta](filter_packer.hepta) | ELF construction for one complete binary input/output operation |

The byte ABI and all eight operations are specified in
[runtime_bytes_abi.md](runtime_bytes_abi.md). Text behavior is specified in
[text_budget_abi.md](text_budget_abi.md), and the typed endpoint boundary in
[line_endpoint_abi.json](line_endpoint_abi.json). Delta operations, exact ordering
and capacity rules are specified in [delta_abi.md](delta_abi.md). No native component falls back to
a Rust or Python implementation of its calculations. Endpoint JSON number
classification and compact display bytes remain explicit caller inputs; the
component does not claim to replace the serde parser itself.

The packers contain explicit Linux syscall adapter bytes for memory allocation
and descriptor I/O. HIA code constructs the ELF, relocates the call and installs
the HIA component image. These adapters do not supply a general filesystem,
network, SSH, database or process-management standard library.

## Build and verify

Use an ordinary checkout of the exact Hepta commit shown above. The builder
checks both the commit/tree and the actual tracked source bytes; changing the
dependency checkout, a source file, or a cached compiler image is rejected.
Python 3.11+ and a C toolchain are build/test dependencies for the initial seed.
Independent comparison also requires Rust 1.95.0 and Cargo; endpoint reference
dependencies are pinned in its Cargo.lock.
They are not dependencies of the emitted executable.

From this runtime checkout:

```sh
python3 -B scripts/qualify_hia_runtime_native.py \
  --hepta /absolute/path/to/pinned/Hepta \
  --output /absolute/path/to/new-native-result

python3 -B scripts/compare_hia_runtime_rust.py \
  --output /absolute/path/to/new-native-result \
  --rustc /absolute/path/to/rustc
```

The output directory must be new. Earlier reports are not overwritten. The
builder executes B0 → B1 → B2 → B3 and requires byte-identical B1, B2 and B3.
The resulting B3 compiles the runtime sources and both HIA transport packers.
This is development fixed-point evidence; the upstream complete cold
qualification is a separate requirement.
The pinned upstream cold check was also rerun with its unchanged 180-second
deadline. It timed out at 180.309 seconds, with 6/11 outer checks passing and
owned-process cleanup confirmed. The original result remains a failure; see
[compiler_cold_observation.json](compiler_cold_observation.json).

The main output files are:

```text
result.json
build/modules/runtime-protocol/runtime-protocol.elf
build/modules/runtime-protocol/manifest.json
build/modules/runtime-bytes/runtime-bytes.elf
build/modules/runtime-bytes/manifest.json
rust-oracle/input.bin.gz
rust-oracle/native-output.bin.gz
text-rust-oracle/native-corpus.json
endpoint-rust-oracle/native-corpus.json
delta-rust-oracle/native-corpus.json
```

The test driver runs actual native images and the standalone ELF. It retains
test stdout/stderr, source identities, compiler receipts and exact output
corpora. The CI workflow also compiles the original Rust function bodies and
compares their outputs against the retained native corpus. The aggregate
result is `NATIVE_COMPONENTS_PASS` after native tests and becomes `PASS` only
after all four independent Rust comparisons succeed. Timeouts retain partial
stdout/stderr and the failing check; they cannot be recorded as a pass.

## MCP stdio service

Launch `runtime-protocol.elf` directly with no arguments. It reads one JSON
message per LF-delimited frame and writes one LF-delimited response. A final
nonempty frame at EOF is processed once. Notifications produce no response.
The process retains its own initialization state and supports multiple calls
before stdin closes. Separate processes/sessions have separate state.

The supported protocol version is **2025-06-18**. An older or unknown client
proposal receives that supported version. The client decides whether it can
proceed. Batch requests are outside this profile. The service implements:

- `initialize`, followed by `notifications/initialized`;
- `ping` during and after initialization;
- `tools/list` and `tools/call` after initialization;
- `notifications/cancelled`, with no outstanding asynchronous tool to cancel;
- malformed-input, invalid-request, unknown-method, invalid-parameter and
  uninitialized-session responses.

`runtime_line_hash` accepts `{"text":"hello"}` and computes the original
runtime's FNV-1a32/XOR-fold8 hash over decoded UTF-8 bytes. Its result for this
example is `57`. Unicode and escape-equivalent JSON strings retain the same
underlying byte semantics as the original Rust `str` implementation.

Frames and outputs are bounded to 8 MiB; the native service has a 32 MiB private
workspace. JSON depth and node limits are 128 and 262,144. Buffer exhaustion is
an explicit refusal. Initialization state advances only after a complete
successful initialize response can be constructed. A closed output pipe may
terminate through inherited SIGPIPE; callers must observe the process exit.

## Verified behavior

The byte kernel has passed **22,509 direct native calls**, including **21,863
cases in the original Rust text/integer domain** and 646 extra byte-domain
controls. A separate Rust 1.95.0 execution of the unchanged original function
bodies produced exactly the same 601,173 output bytes for all 21,863 original
domain cases. The source and output identities are retained in
[original_rust_comparison.json](original_rust_comparison.json). That independent
recheck is not added to the native count as new functional coverage.

The text component has passed **26,869 valid native cases**, including full-u64
floating-point rounding boundaries, Unicode, line ranges and release-profile
integer wraparound. The unchanged original Rust functions produced identical
1,531,374 output bytes for those cases; see
[text_original_rust_comparison.json](text_original_rust_comparison.json). Invalid
UTF-8/frame controls, capacity atomicity, independent VM cases and direct static
ELF execution are checked separately.

The endpoint component has passed **6,366 native calls**, including 930 retained
Rust-generated vectors, 5,224 generated reference cases, invalid UTF-8, capacity
atomicity and an 8 MiB boundary. A separate execution of the original, included
`src/utils/line_hash.rs` with pinned serde dependencies matched **6,155 actual
native calls**. See [endpoint_original_rust_comparison.json](endpoint_original_rust_comparison.json).

The delta component has passed **9,101 valid native cases**, including exhaustive
short repeated-line inputs, independently checked minimum edit distances, exact
Myers tie ordering, context merging, Unicode, CRLF and distances 499/500/501.
The unchanged original Rust functions produced the same **2,530,734 output
bytes**; see [delta_original_rust_comparison.json](delta_original_rust_comparison.json).
It also passed 90 malformed-record controls, capacity and semantic-`None`
distinction, five VM cases and three standalone ELF calls. File access and
per-session view-cache state remain original caller owners.

The protocol tests cover randomized JSON formatting and field order, strict
Unicode, duplicate decoded keys, ID echo, invalid envelopes, initialization
ordering, response-capacity failure and recovery, concurrent isolated calls,
and actual fragmented pipe input. The transport tests check exact maximum
frames, plus-one refusal, final EOF framing, real descriptor failure, empty-PATH
execution, sealed RX code mappings and source/image/compiler drift refusal.

The native source profile and its limitations are recorded in the build
manifest and `result.json`. A passing component result is not a passing full
runtime migration result.

## Remaining migration work and cleanup

[migration.json](migration.json) is the single current source coverage inventory.
It enumerates every existing registered tool and the remaining system owners.
The native sources currently have no substituted production call sites.

| Existing tool family | Registered handlers still owned by the original runtime |
| --- | ---: |
| Filesystem and control | 28 |
| Hosts and processes | 24 |
| Durable requests | 10 |
| HIA Agent integration | 11 |
| REA analysis | 34 |
| Weights | 9 |
| Documents and worksheets | 9 |
| **Total** | **125** |

The remaining service work includes persistence/restart and unknown-outcome
recovery; identity and effect ownership; SSH/SFTP/HTTP/PTY; file editing and
delta state; REA parsers; documents and worksheets; model workers; deployment
gateways; and non-Linux-x86-64 targets. Those are implementation dependencies,
not tasks that can be closed by renaming Rust or Python files.

Check the inventory with:

```sh
python3 -B scripts/check_hia_native_inventory.py
python3 -B scripts/check_hia_native_inventory.py --require-complete
```

The second command currently returns 2 and reports `INCOMPLETE`. It cannot be
made successful by changing a JSON completion flag. Existing code, call sites
and their behavioral tests need actual replacements first.

Only the current native sources, ABI documentation, build tools and reproducible
tests are added to the repository. Development authoring scratch, intermediate
versions and local build outputs stay outside the tracked tree. The original
runtime and historical regression inputs remain: active workflows and tests
still read files under `docs/qualification` and `tools/x230`. Their cleanup must
follow replacement of those dependencies; their historical Git identities and
original failure results must remain traceable.
