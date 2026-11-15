# HIA MCP ordinary-file view composition

This composition is the implemented stdio profile for the three existing
configuration tools and ordinary local-file `view`. All protocol decisions,
capability admission, typed parameters, session initialization, path policy,
view state, cache contents, rendering and JSON publication execute in the
31 compiled HIA images. The assembly boundary supplies fixed child addresses,
borrow validation, allocation, system calls and transport of HIA completions.

It is not the complete 125-tool runtime. Directory view, content search,
remote view, background resources, the complete SDK service surface and HTTP
dispatch remain unfinished. Input and gateway storage are a declared build
profile, not a proof that the original public success domain is bounded.

## Public executable

The actual HIA ELF linker emits `runtime-mcp.elf`. It has no interpreter or
libc dependency and does not load Python, Rust, a user-supplied image table or
an alternate semantic implementation.

```
runtime-mcp.elf [--runtime-config CONFIG] [--session-root DIRECTORY]
```

Without `--session-root`, the boundary supplies the actual current directory.
With `--runtime-config`, the existing configuration lifecycle admits the file,
initializes its real state and installs its authority once. Later policy
queries and configuration tool calls borrow that same owner workspace.
Without a config file the owner returns its original uninstalled diagnostic
(enum 9); this is a distinct mode, not a fabricated successful policy check.

The public line profile is 8 MiB. The gateway's result borrow is 64 MiB.
Resource/capacity refusal is not converted into a fabricated original business
error. The actual view engine and result-publication arena grow independently.
The profile has published a complete 19,000,091-byte endpoint error: the
ordinary successful-body limit does not truncate that original error branch.
Global arbitrary-size frontend and gateway storage is still unfinished.

Implemented protocol cases include legacy initialization (including the
original future-version downgrade), request metadata admission, modern first
requests, `tools/list`, `tools/call` and `server/discover`. This is not a claim
that all SDK method, cancellation, notification or concurrency rules are done.

## Admission before the method body

The outer frontend retains raw JSON subtrees and invokes the actual HIA
`serde_json` owner. Full `ClientCapabilities` validation is delegated to the
unchanged `client_context` HIA owner. A bad known sibling such as `roots:true`,
`sampling:0` or `elicitation:[]` invalidates the whole capabilities value.
Valid legacy request capabilities replace the handshake value; malformed
legacy request capabilities fall back only when metadata is optional.
Modern metadata requirements take precedence over typed parameter extraction.

The actual `view_params` owner consumes canonical arguments after admission.
Its typed diagnostic becomes `-32602` with the original SDK prefix
`failed to deserialize parameters: `. Only typed success invokes the session
initializer, workdir snapshot, installed path policy and view request scope.
The advertised `ViewParams` schema is not used as an input validator:
`Option<Value>` endpoints retain their actual arbitrary JSON admission domain.

The catalog asset is the actual 2,077-byte public schema after the two original
cleanup functions. The 2,398-byte raw generated schema is a separate reference.
`get_info` assets come from the original method and the actual SDK build info
(`rmcp/3.4.1`). The visible catalog presently contains four tools; neither the
empty-list reference fixture nor this profile stands in for the original 125.

## New private HIA interfaces

All integer fields are unsigned little-endian 64-bit values. These interfaces
are internal byte spans. Public JSON values cannot choose child addresses,
workspace instances, session tickets, request generations or output pointers.

### Frontend

`runtime_mcp.hepta` uses the existing config frontend borrowed-buffer entry.
Its composition proof records the exact imported function ASTs and call
relocation. The current config source's publication function `f7` is preserved
as an imported function (relocated to `f32`); the new wrapper only selects
modern result metadata before the same actual publisher path.

The private new child slots are 11 catalog, 12 admission and 13 view gateway.
Existing slots for configuration, execution, canonical JSON and publication
remain their original fixed owners. The source proof is
`runtime_mcp_composition.json`.

### Metadata admission

Request: `HCMADQ01 | op | a_len | b_len | a | b`.

| op | `a` | `b` |
|---|---|---|
| 1 | decoded initialize protocol version | complete raw capabilities JSON |
| 2 | complete request `_meta` JSON | empty |
| 3 | complete discovery `_meta` JSON | empty; metadata required |

Reply: `HCMADR01 | status | mode | experimental_present | payload_len |
effective_version | payload`. Status 0 accepts, 1 rejects capabilities, 2
rejects protocol-version metadata, 3 rejects both, and 4 reports an unsupported
version using its canonical JSON string payload. Mode 0 is uninitialized,
1 legacy and 2 inline request metadata. Effective versions 1–4 are the four
supported legacy versions; 5 is `2026-07-28`.

The two child slots are fixed to canonical Value and full client capabilities.
The source owns the retained legacy snapshot and decides fallback/precedence.

### Catalog

Request: `HRMCD001 | op | selector`, followed only by the quoted requested
version for op 4. Operations 1, 2, 3, 4 and 5 respectively emit tools-list,
initialize, missing-metadata error, unsupported-version error and discovery
suffixes. The output is the complete JSON-RPC result/error suffix. Literal
chunks and original schema bytes execute in the HIA image.

### View gateway

Request: `HVMGWQ01 | canonical_args_len | experimental_present |
experimental_len | reserved_zero | canonical_args | experimental`.

Reply: `HRCFGM01 | tag | reserved_zero | text_len | text`. Tag 0 is successful
String, 1 is original tool String error, and 2 is the typed Serde diagnostic.
The normal entry is `f0(readbuf, mutbuf, mutbuf) -> u32`.

The fixed local child edges are:

| Slot | Owner / operation |
|---|---|
| 0 | actual `view_params` |
| 1 | same session's `session_context` initialization |
| 2 | same `session_workdir`, current snapshot |
| 3 | installed `config_directory_owner`, queries 7/8 only |
| 4 | actual `path_source` |
| 5 | actual `local_path_policy` |
| 6 | same private actual `view_call` engine |

After the trimmed policy-root checks, the original raw path is retained for
actual resolution/view behavior. The ordinary engine receives `HVCLQ001` and
executes the public blank/exists/is-directory prelude. The private `HVCPI001`
fixture entry is never used here. Scope OPEN remains inside the real view
controller after typed, session and policy admission.

Return `0xffffffe0` asks the mechanical boundary to execute an admitted child.
`0xffffffff` is malformed private framing/continuation, `0xfffffffe` capacity,
`0xfffffffc` resource failure and `0xffffffc1` an explicitly unfinished route.
All borrowed continuations revalidate magic, sequence, child, region, offsets,
lengths, capacity and ACK fields before consuming a result.

The 256 MiB gateway workspace has request storage at 4,096, child reply storage
at 67,117,056, saved typed parameters at 134,225,920 and workdir at 201,334,784.
Its final 256 bytes contain the standard private HIACAL continuation footer.
These fixed storage regions are profile limitations, not new original quotas.

## Private engine and publication ownership

`runtime_mcp_extra_engine.S` installs only fixed images. The real view engine
is created lazily once per stdio session. Its fixed 12-slot descriptor table
uses the same cache arena across calls and across arena growth. Private fixture
ACK and binary receipt flags remain zero in production. The v6 read/key bridge
source checks the private trace flag after the real HIA completion; production
does not emit private binary controls on stderr.

The boundary copies the complete view result into the gateway borrow before
that caller output can be reused. The exact current config publication owner
then APPENDs the entire result into its private growing arena before START.
After START, publication no longer borrows the view caller output. Write
completions and ACKs return to the actual HIA publisher. EOF retires/releases
the session lease after completed publication, then destroys the retired
engine. This sequential stdio path does not establish a general asynchronous
writer, HTTP cancellation or concurrent dispatcher theorem.

## Reproducible evidence

`build_runtime_mcp(hepta, build_root, source_root=checkout)` compiles all 31
members by default and invokes the pinned upstream HIA ELF linker. CI supplies
an isolated `build/runtime_mcp-bundle` with the already independently admitted
compiler bootstrap. An explicit development manifest-reuse option is recorded
per member; formal qualification rejects any reused member.

`test_runtime_mcp.py` runs 7 actual groups. `test_runtime_mcp_evidence.py` runs
5 groups with 40 independent evidence refusals and no new native/Rust calls.
The native reader validates complete process streams, sparse private-state
captures, actual compile receipts, assembler object bytes, all 24 fixed child
address relocations and the full linked machine-text/program-header relation.

`compare_reference` reuses the same nine real processes admitted by the
`view_call_original` reference recipe. Its output separates complete SDK
protocol-error objects, explicit SDK/get-info/list projections, the exact raw
and cleaned schemas, 31 complete ordinary-file bodies (six in one cache
session), and the one complete large error. It does not compare fixture body
text with file text or label all 192 public replies complete original-server
equivalence. Only final source, readers, tests and assets belong in the final
repository; authoring scripts and development captures are not runtime inputs.
