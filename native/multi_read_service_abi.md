# Native batch-read MCP owner

`multi_read_service.hepta` owns `read_multiple_files` in the explicit
`native-local` read-only Linux profile. Original remote transport and general
runtime configuration remain separate migration owners.

## Composition

The entry is `f0(readbuf, mutbuf, mutbuf) -> u32`, with 8 MiB request/output
ceilings and 32 MiB private workspace. The fixed bridge invokes image 5 as a
child (`invocation_kind = 3`). Its first call receives the immutable startup
root through region 3; later calls receive unchanged MCP request bytes through
the parent's input region and return complete responses into its output region.
The main controller owns MCP lifecycle and the shared IO root descriptor.

Only the main controller may call image 5. Its child mask admits images 1
(policy), 2 (codec), 3 (IO) and 4 (stat version). Calls use checked disjoint spans,
private persistent state and exact sequence acknowledgements. The original
request graph remains stable across continuations. The strict JSON decoder's
imported HIA graph is checked structurally after function/call relocation;
see `multi_read_service_composition.json`.

## Original parameter and result behavior

Arguments require string `host` and an array of string `paths`. The only optional
fields are unsigned 64-bit or null `max_file_bytes` and `max_response_bytes`.
Missing/null defaults are 16,384 and 65,536. Unknown fields and wrong types are
parameter errors. After complete typed admission, the original ordering is:

1. Require 1..16 paths.
2. Require file limit 1..65,536 and response limit 1,024..262,144.
3. Require distinct absolute paths, at most 4,096 UTF-8 bytes, without NULs or
   empty, dot or parent components.
4. Resolve the immutable local host and check **all** paths against policy
   before opening any source.
5. Read each entire regular, single-link file, check before/after versions,
   validate strict UTF-8, and reopen the descriptor walk to confirm identity.
6. Compute the original version string and SHA256 with their native HIA owners.
7. Check the complete serialized MCP text-result budget after each file.

The result contains `atomic_snapshot: false`, `encoding: "utf-8"`, `files`,
`snapshot_scope: "independent_file"`, and `truncated: false`. Each file has exactly
`eof`, `path`, `sha256`, `size`, `text` and `version`. Compact sorted JSON is
returned as one MCP text content item with `isError: false`, without
`structuredContent`. The budget includes nested JSON escaping and the entire
MCP result object; it excludes the surrounding JSON-RPC ID/envelope.

Every helper failure uses the unchanged Rust `redacted_transport_error` text.
The error starts a fresh result, so no earlier source content or internal error
chain is published. The operation provides independent file snapshots, never a
cross-file atomic snapshot.

## IO operation 2

The existing 112-byte `HIARD001` request header contains correlation ID,
operation 2, offset zero, file ceiling, version flag zero, seven zero version
words and path byte count, followed by the exact path. Correlation is echoed;
the IO effect sequence is separate. A successful `HIARR001` response has the
existing 128-byte header plus complete data. Count, next offset and pre-read
stat size agree, offset is zero and EOF is true. IO checks strict UTF-8 before
path confirmation, preserving original operation ordering. The controller
rechecks UTF-8 as an invariant. Every nonzero IO status becomes a redacted error.

## Verification boundary

`test_multi_read_controller.py` runs actual HIA controller/policy/codec/stat
images with explicitly synthetic IO completions. It checks original validation
order, policy-before-effect ordering, exact nested JSON, original `_wire_size`
boundaries, UTF-8, full-file and 16-file limits, buffer canaries and stale
acknowledgements. Fixture IO is never counted as a filesystem observation.
Admission as a working service also requires the real composed-ELF suite and
direct comparisons with unchanged `multi_read_host.py` on real files, including
single-link, mutation, path confirmation and cleanup controls.
