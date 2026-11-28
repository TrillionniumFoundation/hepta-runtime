# Actual original `view` reference

This reference compiles the frozen original Rust regular-file `view` functions
and executes them against real files through their original Tokio I/O bodies.
It also runs a separate locked rmcp transport probe for the original
`ViewParams` derive and actual request-context capability resolution. It does
not provide a production implementation or claim that the whole `view` tool has
been migrated.

`source_manifest.json` pins all original source files, their source commit and
the complete extracted bodies. `verify_sources.py` refuses different source
bytes before materializing a fresh crate. Every registry package in the small
crate's lockfile must have the same name, version, registry and checksum as the
original runtime lockfile. The dependency versions include the actual rmcp
3.4.1 SDK, Tokio, Serde and serde_json; they are not replacement models.

## Separately counted domains

The 58 cases in `cases.py` exercise the original internal `McpToolCall` regular
file domain. The input generator contains file bytes, parameters, mutations and
observation points only. Expected output is produced by the compiled original
functions. The cases cover normal whole/range reads; CRLF, Unicode, NUL and
invalid UTF-8; the original 5 MiB metadata checks; independent first and second
range reads; symlink and hardlink cache identity; raw Unix paths; changes between
observations; and cache state after rendering, size errors and cancellation.

These cases call the actual original `execute_view`, range resolver, file
reader, line formatter, delta renderer, canonical cache-key functions and
request-local hint owner. The wrapper around each original I/O function runs
scheduled mutations immediately before or after that actual operation and
records its actual result. It never supplies a fabricated metadata or read
result. All scheduled hooks must fire. Raw Unix paths are explicitly a private
`PathSource` domain because public JSON strings cannot contain invalid UTF-8.
Directory, content-search, remote and background branches abort if reached;
this prevents an unsupported branch from receiving a fabricated success.

One cancellation case inserts a test-only pending point after the original
`execute_view` has finished and before the harness publishes its result. The
harness then aborts the actual Tokio task. This tests the already applied cache
state and original request-scope teardown. It does not assert that the original
server contains an await at that precise location, or that source computation
has been cancelled midway.

The 36 cases in `sdk_cases.py` form an independent SDK domain. The second binary
runs the real rmcp server over a Tokio duplex transport, with actual JSON-RPC
initialization and tool-call messages. A small probe handler deserializes the
unchanged original `ViewParams` derive and asks the actual SDK
`RequestContext::client_capabilities()` and `protocol_version()` for their
values. This verifies typed fields, ignored unknown fields, legacy handshake
fallback, request overrides and modern metadata admission. Its diagnostic
response envelope is test-only; it is not a claim about the original view
router's error envelope, first-capabilities latch, installed policy or workdir
update. These 36 cases are not added to the 58 regular-file cases.

The additional domains retain their own inputs and counters:

| Generator or driver | Cases | Executed original or SDK behavior |
| --- | ---: | --- |
| `parameter_sdk_cases.py` | 39 | Exact original `ViewParams` errors for floats, Rust Debug strings and field ordering |
| `wide_endpoint_case.py` | 1 | A small JSON array expands beyond 16 MiB; actual original endpoint error is retained in full |
| `router_sdk_cases.py` | 54 | Actual SDK `Parameters` extraction and `AsyncMethodAdapter`, with observed fixture method entry |
| `public_schema_driver.rs` | 2 schema values | SDK schema plus the unchanged original publication transforms |
| `info_sdk_cases.py` | 13 | Unchanged original `get_info`, cache-hint predicate and list-result tail over an empty catalog fixture |

The 63 native typed projections consist of the first 24 cases from the original
36-case SDK domain and the 39 additional inputs. The 54 adapter cases retain
actual outer `call_tool` and fixture body entry counts, including metadata
admission before parameter extraction. The fixture method is not the original
view handler or session method. The info fixture executes the original metadata
functions with an explicit empty catalog; it does not execute the complete
original tool catalog. The public schema uses the original `strip_null_variants`
and `strip_generator_noise` functions after the SDK schema generator.

Within the ordinary 58 cases, 56 execute the public path prelude and two execute
the explicit private raw `PathSource` entry. Case 51 also observes an unbound
request context, and case 52 uses the cancellation seam described above. These
fixtures are not a claim that every case is an ordinary public MCP request.

## Complete artifact formats

Filesystem input starts with `HVCOI001` and a little-endian u64 record count.
Each record is a u64 JSON length, u64 blob count, exact UTF-8 JSON metadata, then
each blob as u64 byte length followed by its complete bytes. Original output
uses `HVCOO001` and the same framing. Output metadata includes the visible
outcome, actual rendered base, full I/O observations, fired mutation hooks and
cache probes. Blob references retain complete read snapshots, cache values and
visible output. An empty result remains a zero-length blob.

SDK input and output are JSONL with stable case IDs. Output retains every actual
SDK reply, probe observation and service completion. The filesystem and SDK
inputs are independently regenerated during every reference run.

For a completed native comparison, `native-cases.jsonl` must contain exactly
one row for each of the 58 filesystem case IDs. Each row names a gzip input
artifact containing the complete one-record `HVCOI001` frame, a complete
`body_path`, a typed `cancelled` flag and, except for cancellation, a typed `ok`
flag. `cache_before` and `cache_after` contain ordered `path_hex`, `present` and
`content_path` probes. The ordered `io` list carries event names, occurrences,
actual result values and full `snapshot_path` artifacts for successful reads.
All paths are relative descendants of the corpus directory. The comparison
checks every input, visible output, after-render base, cache value and successful
read snapshot byte, as well as the observed error and metadata values. A cancellation has no
published body and is not counted as an original successful response.

## Fresh execution

Run the recipe with explicit compiler paths on the configured build host:

```text
python3 -I -B /absolute/runtime/tests/hia_native/view_call_oracle/run.py \
  --runtime-root /absolute/runtime --output /absolute/fresh-output \
  --cargo /absolute/toolchain/bin/cargo --rustc /absolute/toolchain/bin/rustc \
  --reference-only
```

The output must not already exist. The recipe creates a fresh crate and target
directory and executes nine actual processes: `rustc --version`, one locked
release build of five binaries, the 58-case filesystem run, the 36-case
SDK run, the 39-case parameter run, the separate wide filesystem run, the
54-case adapter run, the public schema run and the 13-case info run. Each actual subprocess has a 180-second
deadline and complete stdout, stderr and process receipts, including failures.
The report records exact harness inputs, compiled binaries, regenerated inputs
and original output identities, and verifies that the harness stayed unchanged.
The default build permits dependency downloads and always uses `--locked`.
`--offline` is available only as an explicit cached-host choice; the report also
retains the actual build environment, including `CARGO_NET_OFFLINE` if supplied.

`--reference-only` produces `REFERENCE_READY`, never native `PASS`. Replace it
with `--native-corpus /absolute/caller --params-corpus /absolute/params
--wide-corpus /absolute/wide` only after all three actual HIA/ELF corpora have
been produced. Native suites emit `NATIVE_COMPLETE_RUST_REPLAY_REQUIRED`; their
default operation needs no authoring-directory reference files. Optional
existing-reference checks are explicitly recorded and do not replace the fresh
recipe. Native SDK routing requires its own actual transport comparison;
the SDK reference alone does not establish that migration. Historical failed
or exploratory runs belong outside this final harness and retain their real
status and bytes.
