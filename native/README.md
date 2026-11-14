# HIA native runtime

This directory contains the current HIA implementation of deterministic runtime
components, a read-only descriptor dependency and persistent native MCP stdio services. All implementation sources
in this directory use `.hepta` and are compiled by HIA to machine code. The Linux
executables have no Python, Rust, libc or dynamic-loader runtime dependency.

The complete existing runtime has **not** been replaced. Its 125 registered MCP
tool handlers and the durable/remote service owners remain in their original
implementation. The diagnostic native service advertises `runtime_native_info`
and `runtime_line_hash`. A separate, explicitly selected local read profile
provides `host_list` and `binary_read` through five native HIA images. It has
partial original-tool coverage; configured remote hosts and complete original
authorization behavior remain outside that profile. Production activation and
deletion of the original runtime remain incomplete.

## Fixed source baseline

| Input | Exact Git identity |
| --- | --- |
| Runtime source | `a0dcdda1991ec536d5e2d252c006a778993fa566` |
| Runtime tree | `98d96c88d54082637c27f1cbfae61a66d0dd81e7` |
| Hepta compiler | `d3e2c90173cf733e42b299d0c4274df4b593a12f` |
| Hepta tree | `8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49` |
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
| [binary_codec.hepta](binary_codec.hepta) | SHA256 raw/hex and resumable state; canonical Base64 encoding and explicit legacy, strict-padding and canonical decoding |
| [policy.hepta](policy.hepta) | Original deterministic permission/protection order, executable/environment policy, remote lexical paths and local path operations |
| [stat_version.hepta](stat_version.hepta) | Exact original five-field stat version text and canonical inverse over full integer/timestamp domains |
| [io_policy.hepta](io_policy.hepta) | Read-only descriptor custody, bounded read continuations, file versions and error/cleanup decisions |
| [io_packer.hepta](io_packer.hepta) | Static ELF construction with checked syscall records, opaque handles and persistent binary I/O framing |
| [local_service.hepta](local_service.hepta) | Persistent MCP controller for the explicit `native-local` profile, with `host_list` and bounded `binary_read` responses |
| [composition_packer.hepta](composition_packer.hepta) | Closed native image tables, fixed call authority, private workspaces and bounded child/OS continuations in one static ELF |
| [stdio_packer.hepta](stdio_packer.hepta) | ELF construction and persistent newline-delimited input/output transport |
| [filter_packer.hepta](filter_packer.hepta) | ELF construction for one complete binary input/output operation |

The byte ABI and all eight operations are specified in
[runtime_bytes_abi.md](runtime_bytes_abi.md). Text behavior is specified in
[text_budget_abi.md](text_budget_abi.md), and the typed endpoint boundary in
[line_endpoint_abi.json](line_endpoint_abi.json). Delta operations, exact ordering
and capacity rules are specified in [delta_abi.md](delta_abi.md). Hash/state layouts,
binary bounds and Base64 policies are specified in [binary_codec_abi.md](binary_codec_abi.md).
Policy operations and their caller boundaries are in [policy_abi.md](policy_abi.md).
The exact file-version boundary is specified in [stat_version_abi.md](stat_version_abi.md).
The read-only OS dependency, startup-root custody and exact wire records are
specified in [io.abi.json](io.abi.json).
The explicit local MCP profile is defined in [service_contract.md](service_contract.md),
and the closed native call boundary in [composition_abi.md](composition_abi.md).
No native component falls back to
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
Qualification clears inherited `HIA_*` development overrides before admitting
its own manifest, source, compiler and corpus inputs. Standalone suites retain
their explicit development overrides; these cannot silently substitute an
external loader or fault probe in the closed qualification.
Python 3.11+ and a C toolchain are build/test dependencies for the initial seed.
Independent comparison also requires Rust 1.95.0 and Cargo; endpoint and codec
reference dependencies are pinned in their Cargo.lock files.
The read-only I/O fault tests also require Linux seccomp user notification for
their own test child. The suite does not skip these controls when unavailable.
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
The resulting B3 compiles the runtime sources and their HIA transport packers.
Every invocation also runs the complete upstream cold replay in a new source-only
export, retaining the upstream 180-second qualification and separate 3-second
cleanup budgets. The outer process has 240 seconds only to allow cleanup and
report writing; it cannot extend the inner qualification deadline. The result
must contain all 11 original outer checks and all 5,049 nested checks, matching
source hashes, a successful owned-process receipt and B1/B2/B3 images identical
to the compiler used for these runtime modules. Only then can
`matching_source_full_cold_qualified` become true.

The earlier `f33d8da` compiler cold run timed out at 180.309 seconds with 6/11
outer checks. It remains recorded as a failure in
[compiler_cold_observation.json](compiler_cold_observation.json). The current
`d3e2c901` compiler changes final evidence serialization while preserving the
HIA compiler image. Its observed 11/11 and 5,049/5,049 cold pass in 173.029 seconds
is retained with original report/source digests in
[compiler_compact_cold_observation.json](compiler_compact_cold_observation.json).
That historical observation never substitutes for the fresh replay above.

The main output files are:

```text
result.json
compiler-cold.json
compiler-cold.cold/qualification.json
compiler-cold.cold/process-owner.json
build/modules/runtime-protocol/runtime-protocol.elf
build/modules/runtime-protocol/manifest.json
build/modules/runtime-bytes/runtime-bytes.elf
build/modules/runtime-bytes/manifest.json
rust-oracle/input.bin.gz
rust-oracle/native-output.bin.gz
text-rust-oracle/native-corpus.json
endpoint-rust-oracle/native-corpus.json
delta-rust-oracle/native-corpus.json
codec-rust-oracle/native-corpus.json
codec-rust-oracle/codec_cases.jsonl.gz
policy-rust-oracle/native-corpus.json
stat-version-python-reference/native-corpus.json
stat-version-python-reference/stat-version-cases.jsonl.gz
local-service-python-reference.json
build/composition/<source-key>/manifest.json
build/composition/<source-key>/native-local-read.elf
```

The test driver runs actual native images and the standalone ELF. It retains
test stdout/stderr, source identities, compiler receipts and exact output
corpora. The CI workflow compiles original Rust function bodies and independent
locked Rust reference crates, then compares their results with the retained
native corpus. The aggregate
result is `NATIVE_COMPONENTS_PASS` after the fresh full compiler cold gate,
native tests and retained-Python I/O/file-version/local-service comparisons. It becomes `PASS` only
after all six independent Rust comparisons succeed. The Python reference domain
is accounted separately and is never represented by a dummy Rust recipe. Timeouts retain partial
stdout/stderr and the failing check; they cannot be recorded as a pass.

The local-service receipt records live comparisons on temporary files whose
inode and timestamp values vary on each run. The original Python read helper
runs against those same fixtures, and the test compares the native MCP result
text byte for byte. This reference domain has no synthetic Rust recipe. The
closed image table and its generic continuation controls are reported separately
as new native adapter behavior. Qualification rechecks all five source/image
pairs, the HIA packer, exact call masks and capacities, packed-frame digest and
final executable identity before accepting this evidence.

## Explicit native local read service

Build the five-image service using the same pinned compiler:

```sh
python3 -I -B scripts/hia_native_composition_build.py \
  --hepta /absolute/path/to/pinned/Hepta \
  --build-root /absolute/path/to/native-build
```

The command returns a manifest path. Its directory contains the executable:

```sh
/absolute/path/to/native-build/composition/<source-key>/native-local-read.elf \
  --local-read-profile /administrator/selected/root
```

The explicit profile argument is required. The root is supplied by the operator
at startup and retained as an open directory capability. Client JSON cannot
change it or reinterpret an existing SSH alias. `host_list` returns one host
named `native-local`, with reads enabled and execution, PTY and writes disabled.
After initialization, `binary_read` accepts that host and an absolute path under
the selected root. It preserves the original read response fields, default and
clamped limits, Base64 bytes, SHA256, exact version text and successful MCP text
envelope on the tested shared domain. A noncanonical expected-version string
becomes a version mismatch after file/path/type admission and before cursor
checks, preserving the original error order.

The controller calls four fixed HIA owners: policy, binary codec, read-only I/O
and stat version. The executable contains all five images and the native
continuation adapter; it invokes no Python semantic dispatcher or dynamic module
loader. Call masks and region bounds constrain child calls. Private mappings,
an eight-level depth bound and a per-frame continuation budget constrain the
adapter. This is a closed set of trusted compiled HIA images, not a sandbox for
arbitrary uploaded machine code.

This profile deliberately retains root inode custody across requests, while the
original Python helper reopens pathnames. It also has explicit native path and
frame bounds. It does not replace configured host loading, SSH, remote platforms
or the complete original authorization model. Those differences keep the 125
production-handler migration rows and all completion/removal flags unchanged.

## Diagnostic MCP stdio service

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

The codec component has passed **22,517 direct native calls**, including SHA256
padding/block boundaries, portable state partitions and forks, a 9 MiB stream,
Base64 grammar/pad-bit controls and the exact binary payload bounds. The SHA
compression helpers are imported unchanged from the pinned upstream HIA source,
with function-index relocation checked by structural hashes. Independent locked
Rust `sha2`/`base64` crates matched **16,965 captured cases**. Actual desktop
CPython 3.12.3 matched **5,380 legacy-decode cases**; actual scratch CPython
3.12.14 matched **5,381 strict-padding cases**, including an additional input
bound control. Each run tests only its observed Python policy directly. Both
policies remain explicitly selectable in native code; the canonical profile
also rejects nonzero pad bits. See
[binary_codec_independent_comparison.json](binary_codec_independent_comparison.json).
These comparisons replay existing native calls and do not add new native
coverage. Filesystem publication, file-version checks and upload state remain
with their existing owners.

The policy component has passed **11,655 valid native cases** covering first-error
order, permission/protection precedence, environment checks, executable denial,
Unicode whitespace, arbitrary Unix path bytes and exact lexical normalization.
The unchanged original Rust policy functions produced the same **1,550,158
output bytes**. Its 188 malformed controls, buffer-capacity checks, independent
VM cases and actual static ELF calls are separate. See
[policy_original_rust_comparison.json](policy_original_rust_comparison.json).
This component does not load host configuration or resolve filesystem paths.

The file-version component has passed **10,624 native calls**. It directly
compares **5,236 formatting results** with the unchanged original Python
`binary_file.py:version` function, extracted from its pinned source through the
Python AST. Its new inverse has **5,236 canonical roundtrip cases**, with a
separate arbitrary-precision reference and exact reformatting through the
original function. Negative timestamps and signed-seconds extrema preserve
the original mathematical nanosecond value without fixed-width multiplication
overflow. The suite also checks 66 noncanonical inputs, 78 malformed frames,
five capacity controls, eight HIA VM cases and three static ELF executions.
The live Python-reference corpus captures 10,620 calls; one exact-capacity
success and three native comparison inputs for the ELF checks are separately
asserted. See [stat_version_original_python_comparison.json](stat_version_original_python_comparison.json).
This is a representation boundary; it does not open files or replace a tool.

The read-only I/O dependency has passed **14 test groups and 119 actual ELF
requests**, including **8 direct comparisons** with the retained Python
`binary_file.py` read helper. Both that helper and its `file_metadata.py`
dependency are bound to their original Git blobs. Tests exercise real short
reads, injected EINTR/EIO, version changes during reads, close failures, empty
PATH execution, broken output pipes, descriptor reuse and rejection of malformed
effect records. Its startup root inode remains in custody across requests;
the old helper reopens pathnames on every request. That distinction is tested
explicitly and prevents a claim of complete original authorization or tool
parity. The original 113-request observation remains in
[io_reference_proof.json](../tests/hia_native/io_reference_proof.json). The current
119-request extension adds guaranteed expected-version mismatch precedence;
its frozen observation is in [composition_observation.json](composition_observation.json).

The local service has passed **six suites with 234 actual ELF requests**,
including **118 live original Python read comparisons**, 20 protocol refusals
and 21 tool-domain refusals. Seven direct native controller calls separately
exercise response capacity and continuation acknowledgement. Their synthetic
startup acknowledgement isolates lifecycle state and is never counted as a
filesystem read. All real service processes execute with an empty `PATH`.
The frozen identities and counts are retained in
[local_service_observation.json](local_service_observation.json); the current
aggregate gate repeats them from its own source snapshot.

The generic composition suite adds **10 groups, 26 actual ELF executions and
39 frames**. It checks call-mask and depth refusal, recursion, overlapping
borrows, footer protection, nonprogressing continuations, exact maximum framing,
broken stdout, malformed packer inputs and cache-image mutation. It also packs
and runs an actual executable larger than 1 MiB. Its generic controller/leaf
fixtures remain under `tests/hia_native`; they are not production native owners.

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
