# Native source-map declarations

`rea_inspect_source_map` reads an explicitly selected, regular UTF-8 JSON source
map inside the controller workspace roots. The shipped Rust binary decodes the
map in its own bounded one-shot worker. Node, Babel and REA are development
oracles; they are not dependencies of this runtime operation.

This is the `hepta.source-map-declarations.v1` native report. Its
`rea_evidence_compatible` field is always `false`. The operation does not create
an upstream `trace_web_source_location` Evidence record, acquire a browser script,
authenticate an Application Graph, resolve source URLs, or establish that the
declared originals produced the generated program.

## Request and identity

```json
{
  "path": "/absolute/admitted/workspace/generated.js.map",
  "collection": "mappings",
  "offset": 0,
  "limit": 64,
  "generated_position": {"line": 12, "column": 8}
}
```

The collections are `summary` (the default), `sources`, `names` and `mappings`.
Each response contains complete bounded counts and at most one selected page.
An optional query is independent of that page. Lines are one-based and columns
are zero-based. JavaScript and CSS columns count UTF-16 code units; WebAssembly
uses its source-map byte-offset convention.

`map_sha256` commits the complete admitted file, including whitespace and unknown
extension properties. `analysis_sha256` is SHA-256 of the UTF-8 decoder profile,
a NUL separator, and the lowercase map digest. An optional `expected_sha256`
precondition binds the complete selected file. A continuation (`offset > 0`)
requires the prior `expected_analysis_sha256`; a changed map or profile is an
error. A summary has no continuation. Each call reopens and revalidates the
selected file; a cold controller restart does not imply retained-result storage.

Source declarations retain their original names, `sourceRoot`, section paths,
local indexes and flattened indexes. Embedded `sourcesContent` contributes its
decoded UTF-8 byte count and hash, without returning its text. Missing or null
content differs from an embedded empty string. No source declaration is opened
as a file or fetched as a URL. An embedded-content hash commits supplied bytes;
it is not proof of the producer's claim.

## Decoding and point selection

The decoder accepts regular version-3 maps and embedded indexed sections.
Base64 VLQ values use the signed 32-bit convention in ECMA-426, including the
reserved signed-zero encoding for `-2^31`. Segments have one, four or five fields.
Source, original-line, original-column and name deltas persist across generated
lines; generated columns restart at zero. Negative generated-column deltas are
accepted when their cumulative coordinate remains nonnegative. Stable ordering
preserves all records at equal generated positions.

Section offsets compose recursively. A section column offset applies only to
its first generated line. Recorded mappings at or beyond the following section
start are rejected, including an exact boundary collision. External section
URLs, unordered sections and mixed regular/indexed fields are refused.

The optional query selects the greatest recorded generated position at or
before the requested position **across lines**, matching the point-selection
rule of the pinned REA producer. It returns the actual selected generated
position and every coincident record. An explicit unmapped segment remains
unmapped. There is no inferred original-column interpolation, generated span or
code execution. A query before every recorded mapping returns no mapping.

This rule is deliberately explicit: a generic consumer's same-line
`originalPositionFor` call alone does not establish REA's across-line contract.
The upstream differential script invokes the installed REA `traceSourceMap`
function and checks that projection separately.

## Bounds and ownership

| Resource | Bound |
| --- | ---: |
| Complete input file | 8 MiB |
| Escaped worker request | 64 MiB |
| Response | 1 MiB |
| Concurrent admitted inspections | 2 |
| Page rows | 1–256 |
| Source/name declarations | 16,384 each |
| Individual name/root/file declaration | 16 KiB |
| Mapping segments | 200,000 |
| Encoded generated lines | 1,000,000 |
| Indexed sections / nesting depth | 256 / 8 |
| Coincident records in a point query | 256 |
| Worker address-space / CPU budget | 768 MiB / 12 seconds |
| Worker wall-clock deadline | 20 seconds |

Capacity overflow is an error, not a shortened result with complete coverage.
Unknown JSON extension properties are ignored. Recognized duplicate contract
members, invalid UTF-8, invalid indexes, malformed VLQ and bounded-coordinate
overflow are errors.

The controller owns file admission and the parser process. The worker receives
the admitted bytes and request parameters, not the input path or runtime
credentials. It clears its environment and runs in `/`; Linux additionally
binds its lifetime to the controller and tightens seccomp after input admission.
The controller concurrently drains bounded stdout and stderr. Cancellation,
output refusal and the wall-clock deadline kill and reap the owned child before
the operation relinquishes ownership. The input-read permit stays held until
that read has actually completed.

## Reproducible qualification

The unit tests contain independently hand-decoded mappings, preserved
coincident records, cross-line queries, negative deltas, the minimum signed
integer encoding, nested offset composition, exact section-boundary collisions,
content identity, continuation identity and malformed/resource-boundary cases.

`scripts/rea-source-map-reference.mjs` produces eight fixtures with the pinned
Babel and gen-mapping packages and checks their decoded projection against
trace-mapping. It also executes negative cases through the actual shipped
worker entry point. The fixture generator records all package versions and
the script/binary hashes.

The direct trace-mapping 0.3.31 consumer differs on one retained nested fixture:
an outer `(line 2, column 9)` offset, inner `(line 1, column 3)` offset and leaf
`(line 0, column 1)` mapping yield zero-based `(line 3, column 4)` under ECMA-426
10.1, while the direct consumer yields column 13. The first failing differential
is retained. The script checks that exact discrepancy and uses an independently
authored flat equivalent for this one fixture; it reports seven direct consumer
agreements and one separately characterized divergence. Actual REA point
semantics are checked by the next script. No blanket eight-fixture direct
consumer agreement is claimed.

`scripts/rea-source-map-upstream-reference.mjs` uses those fixtures with the
actual authenticated `rea-agents@6.8.0` installation. It compares cross-line
point selection, all coincident records, source/name/section declarations and
embedded-content identities. It saves attempted comparisons before asserting,
so a mismatch remains visible. It does not claim parity for upstream URL
resolution, embedded-content offsets, browser acquisition or Evidence wrappers.

`tests/rea_source_map_mcp.py` initializes the actual stdio MCP server with an
owned isolated workspace and exercises file/root admission, stale identity,
paging, malformed input and recovery. On Linux it identifies the actual parser
with a pidfd, stops that child, sends an ordinary MCP cancellation and requires
the same owner to kill/reap it within an unchanged five-second observation
budget. A separately stopped worker must also be killed and reaped by the
runtime's unchanged 20-second wall deadline, without a cancellation request.
Manual cleanup is excluded from a passing result. Subsequent requests and
cold-process reinspection verify recovery.

Qualification receipts must name the exact tested binary. Earlier release
receipts and a successful `cargo test` invocation that selected zero tests do
not qualify a new binary or this operation.

## Primary references

- [ECMA-426 source-map format](https://tc39.es/ecma426/)
- [REA frozen source](https://github.com/morluto/rea/tree/93b8b82db70279e40f484114cff9dc1958dc14ee)
- [trace-mapping implementation](https://github.com/jridgewell/sourcemaps/tree/main/packages/trace-mapping)

The compatibility ledger tracks the remaining complete operation contract.
This native facility is not a declaration that all REA tools have been ported.
