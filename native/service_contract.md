# Native local read service contract

Run the static executable as `native-local-read.elf --local-read-profile ROOT`.
The CLI must contain that explicit profile selector and one root argument.
Protocol input and output are newline-delimited JSON-RPC over stdin/stdout.
The root argument is copied into a read-only mapping before startup; the
controller never takes configuration from an MCP request.

This service is an explicit `native-local` read-only Linux profile. The
administrator supplies its absolute capability root at process startup, before
stdin is read. It does not load an SSH alias or reinterpret an original remote
host as the local machine. Its implementation owns `host_list`, `binary_read` and `read_multiple_files`
for this declared profile; remote host transport and the complete original
runtime remain separate migration owners.

## Original semantic sources

All original bodies refer to `TrillionniumFoundation/hepta-runtime` at commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`:

- `src/mcp/server.rs`: MCP tools, annotations and `Result<String, String>`.
- `src/mcp/runtime/inspect.rs`: empty `HostListParams` and `render_host_list`.
- `src/mcp/runtime/config.rs`: immutable installed policy, host lookup, operator
  mode and remote path checks.
- `src/mcp/runtime/binary.rs`: `BinaryReadParams`, operator-host admission,
  longest permitted root, default and clamped limit.
- `src/mcp/runtime/multi_read.rs`: complete typed batch validation and ordering.
- `src/mcp/runtime/multi_read_host.py`: strict complete UTF-8 reads, shared
  escaped response budget and original redacted batch errors.
- `src/mcp/runtime/binary_file.py`: descriptor-relative file admission, exact
  version comparison, cursor bounds, stable read, Base64 and SHA256.
- `src/mcp/runtime/ssh.rs`: remote subprocess errors are wrapped with SSH target,
  stdout and Python stderr; those remote diagnostics are not fabricated by a
  local native transport.

## Tool parameters and result ownership

`host_list` accepts an empty object. Its text content is the original pretty JSON
projection with `hosts` in configured-name order. The fixed local profile reports
`name: native-local`, `platform: linux`, `execution_mode: operator`,
`operator_tools: true`, all of `allow_execute`, `allow_pty`, `allow_write` false,
and `privileged_actions: []`. These are administrator-selected profile values;
request fields cannot change them or the capability root.

`binary_read` requires string `host` and `path`, with optional `offset: u64`,
`limit: u64` and `expected_version: string`. Unknown fields are refused.
Missing or JSON-null options mean `None`. Offset defaults to zero. Limit defaults
to 32768 and is clamped to 1..65536, including explicit zero and `u64::MAX`.
Floating point numbers, negative numbers and integers above `u64::MAX` do not
inhabit the parameter type.

The semantic order is:

1. Decode the complete parameter object.
2. Find the configured host by name; require operator mode.
3. Apply the original native policy owner to the exact decoded path.
4. Select the allowed root, then admit the path through the IO owner.
5. Open a regular file and obtain its descriptor version.
6. Compare `expected_version`, if present, with the exact original version
   string. A string with leading zeroes, signs or otherwise noncanonical spelling
   is a mismatch here; it is not a parameter error and does not preempt an open
   failure. This check precedes cursor bounds and file content reads.
7. Require `offset <= size`; read at most the clamped limit and remaining size.
8. Verify the file version after reading and complete descriptor cleanup.
9. Encode the actual returned bytes and their independent SHA256 digest.

The success text is a compact JSON object with exactly `path`, `size`, `version`,
`offset`, `next_offset`, `eof`, `data_base64`, and `chunk_sha256`. It is delivered
as one MCP text content item, with `isError: false`; tool-domain refusals use
the same text-content envelope and `isError: true`. Parameter and protocol
errors are JSON-RPC errors. No `structuredContent` is added to these original
string-returning tools.

## Component boundaries

The HIA service controller keeps the original request bytes and parsed JSON
graph stable while it invokes separately compiled, pinned HIA images. Policy
input is constructed from the immutable startup profile. Only the IO image can
request the bridge's closed OS primitives. The codec and stat-version images
receive typed byte frames and do not acquire filesystem authority.

Native stdio publishes a complete response only after the controller finishes.
Capacity refusal cannot advance MCP initialization or publish a partial body.
EOF invokes the IO owner's root-descriptor close path. No Python or Rust code
dispatches requests or computes results in the runtime executable.

The IO owner pins the opened root inode for the process lifetime. The original
Python helper reopens its root pathname per request. Root replacement semantics
therefore belong to this explicit local profile, and are not claimed as exact
remote transport parity. Administrator roots and `binary_read` paths are limited
to 4095 UTF-8 bytes. `read_multiple_files` retains its original 4096-byte
whole-path bound through component-relative opens.

## Complete UTF-8 batches

`read_multiple_files` requires `host: string` and `paths: array<string>`.
Missing or null `max_file_bytes` and `max_response_bytes` use 16384 and 65536.
Explicit bounds must be 1..65536 and 1024..262144; they are validated rather than
clamped. After complete type decoding, original validation order is path count,
file limit, response limit, non-aliased absolute paths and duplicate checks,
configured host, and all per-file policy checks. Every path is authorized before
any file is opened.

IO operation 2 reads a complete single-link regular file, checks its version and
length, validates strict UTF-8, and reopens its pathname through the retained
root to confirm identity. Symlinks, hardlinks, invalid UTF-8, oversized/changed
files and replaced paths refuse the batch. No earlier file content is published
on failure. Transport/helper errors retain the original generic redacted text.

Success text contains `files`, `atomic_snapshot: false`,
`snapshot_scope: independent_file`, `encoding: utf-8`, and `truncated: false`.
Files remain in request order; each has `path`, `size`, `version`, `sha256`,
`text`, and `eof: true`. The shared budget counts the complete escaped
`CallToolResult`, excluding the JSON-RPC ID envelope. Its boundary is compared
with the original helper at exact size and one byte on either side.

The catalog preserves title `Read Multiple UTF-8 Files` and
`openWorldHint: false`. Main routing forwards the unchanged entire request via
input region 0 and accepts the complete bounded response in output region 1.
The child does not initialize or close the shared IO root. Ordinary scratch calls
stay bounded at 131072 bytes; only unchanged-input forwarding permits 8 MiB.
The new IO workspace is 86016 bytes. The bridge entry ceiling is 262144 per
frame, covering the bounded deep walks of up to 16 files while remaining finite.

## HIA controller and continuation ABI

`local_service.hepta` exports the standard
`f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`. Its workspace is
32 MiB and both input and output capacities are at most 8 MiB. The immutable
bridge table admits these component identities:

| ID | Component | Calls it may request |
|---|---|---|
| 0 | Local service controller | 1, 2, 3, 4, 5 |
| 1 | Native configuration policy | None |
| 2 | Native binary codec | None |
| 3 | Native descriptor IO | Its closed OS effects only |
| 4 | Native stat-version codec | None |
| 5 | Complete UTF-8 batch handler | 1, 2, 3, 4 |

The controller returns `0xffffffe0` for a child call. Its descriptor starts at
`B = length(workspace) - 256`; every field below is a little-endian u64:

| Offset | Value |
|---|---|
| 0 | ASCII `HIACAL01` |
| 8 | Monotonically increasing sequence, starting at 1 |
| 16 | Child module ID |
| 24, 32, 40 | Input region, offset and extent |
| 48, 56, 64 | Output region, offset and capacity |
| 72 | Reserved zero |
| 80 | Returned child u32 status or output extent |
| 88, 96, 104 | Completed sequence, completed flag, bridge status |
| 120 | Bridge-owned invocation kind: 0 startup, 1 frame, 2 EOF, 3 child |
| 128, 136 | Bridge-owned current module ID and nesting depth |

Input region 0 is the unchanged current input, 1 the current output, 2 the
controller workspace, and 3 the immutable administrator root. Outputs may use
regions 1 or 2. The controller checks every completion sequence, flag and bridge
status before accepting any child output. Only bridge status zero is accepted.
The generic bridge independently checks target permission, region extents,
overlap, recursion and the footer reservation. It performs no tool-name or JSON
dispatch.

The decoded JSON graph remains below byte 25,165,824. Dedicated disjoint spans
hold child input at 25,165,824 (131,072 bytes), child output at 25,296,896
(131,072 bytes), retained file data at 25,427,968 (65,536 bytes), Base64 at
25,493,504 (87,384 bytes), version text at 25,583,616 (122 bytes), and the
administrator root at 26,214,400 (4,095 bytes). The final 4,096 workspace bytes
hold persistent protocol state, per-request continuation state and the bridge
footer. No parsed request is allowed to overwrite these spans.

Startup asks module 3 to admit the immutable root, then supplies the same
immutable root to module 5 through input region 3. Both must acknowledge startup.
Every nested invocation has kind 3; the batch handler retains its initialization
state to distinguish later requests. Only module 0 owns IO startup and shutdown. EOF asks module 3 to close that descriptor.
Per read, the controller calls policy operation 6, optional stat-version parsing,
IO operation 1, stat-version formatting, codec operation 7 and codec operation 2.
The additive IO expected-version flag 2 denotes a guaranteed mismatch, admitted
only with seven zero version words. Its check occurs after file admission and
fstat, before cursor bounds and reading. Thus noncanonical strings retain the
original error order without being normalized into accepted versions.

## Source and validation evidence

`local_service_composition.json` pins each relevant original source and proves
that the complete strict JSON decoder closure is unchanged from
`native/runtime_protocol.hepta`, after function-name and direct-call relocation.
Request routing, continuation state and result formatting are new HIA owners.

`test_local_service.py` requires `HIA_SERVICE_MANIFEST` and `HIA_HEPTA_DIR`.
Its default source/repository locations are relative to `tests/hia_native`.
Development may set `HIA_RUNTIME_REPO` and `HIA_SERVICE_SOURCE`; the aggregate
qualifier must supply its own admitted values. The controller manifest is read
from the same composition manifest as the tested ELF. Optional
`HIA_SERVICE_RESULT` records the exact observed manifest/executable identities.

The baseline suite preserves 234 actual ELF responses, 118 direct unchanged
original binary-read comparisons, 20 protocol refusals and 21 tool-domain
refusals. Its eight direct native controller calls cover both declared simulated
startup acknowledgements, replay refusal and initialization capacity. Those
simulations are not counted as file reads.

The separate `test_multi_service.py` suite directly loads the unchanged
`multi_read_host.py` and original descriptor helpers. It compares exact compact
result text, actual helper failures and `_wire_size` boundaries using the same
temporary files as the native ELF. It covers 16 files, 65536-byte ASCII/Unicode
files, embedded controls, empty content, defaults/nulls, an actual 4096-byte
component walk, policy-before-IO error order, redaction after an earlier good
file, and interleaving the two IO callers in one persistent process. Optional
`HIA_MULTI_SERVICE_RESULT` records its exact observed identities and counts.
Final combined evidence is retained in `local_service_observation.json`.
