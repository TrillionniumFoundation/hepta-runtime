# Native source-map declarations

`rea_inspect_source_map` reads an explicitly selected, regular UTF-8 JSON source
map inside the controller workspace roots. The shipped Rust binary decodes the
map in its own bounded one-shot worker. Node, Babel and REA are development
oracles; they are not dependencies of this runtime operation.

This is the `hepta.source-map-declarations.v2` native report. Its
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
decoded UTF-8 byte count and hash, UTF-16 code-unit length and line count, without
returning its text. Missing or null
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

## Embedded original positions

Each mapped row's `original` object retains its one-based `line` and zero-based
`column`, and adds an absolute UTF-16 `offset` plus `content_position`:

| `content_position` | `offset` | Meaning |
| --- | --- | --- |
| `content-unavailable` | `null` | The source has no retained `sourcesContent` string. |
| `outside-embedded-text` | `null` | Text is embedded, but the recorded line or column is outside it. |
| `verified-in-embedded-text` | Integer | The coordinate lies in the supplied text; this is its UTF-16 offset. |

`source_content_verified` is true only in the last case. This verifies the
coordinate against the embedded string. It does not authenticate that string
or establish a semantic relationship between generated and original programs.

Offsets count UTF-16 code units from the start of the entire decoded string,
including intervening line terminators. CRLF is one line break spanning two
units. Lone CR, LF, U+2028 and U+2029 each form a line break. U+0085 does not.
A column equal to the line's length is admitted; terminator units beyond that
line end are not. Empty text has a valid position at line 1, column 0, and a
trailing line break leaves a valid empty final line.

An astral character occupies two units. A numeric position between its two
units is admitted by the fixed original function and by this profile. These
offsets are neither UTF-8 byte offsets nor a restriction to Unicode scalar
boundaries. Isolated surrogate JSON strings remain outside the native scalar
text profile and are refused without replacing their contents.

The decoder constructs one bounded line index per embedded source, then answers
mapping rows and point queries without rescanning the text. The whole map,
including every indexed leaf and empty embedded string, shares a limit of
1,000,000 indexed lines. The index retains two 32-bit integers per line.
An overflow refuses the report before it can claim complete coverage; it never
substitutes `content-unavailable` or silently drops a source.

This new result and resource contract uses profile v2. A v1
`analysis_sha256` is stale even when the input map bytes are unchanged.

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
| Embedded original lines, across the complete map | 1,000,000 |
| Indexed sections / nesting depth | 256 / 8 |
| Coincident records in a point query | 256 |
| Worker address-space / CPU budget | 768 MiB / 12 seconds |
| Worker wall-clock deadline | 20 seconds |

Capacity overflow is an error, not a shortened result with complete coverage.
Unknown JSON extension properties are ignored. Recognized duplicate contract
members, invalid UTF-8, lone-surrogate JSON strings, invalid indexes, malformed
VLQ and bounded-coordinate overflow are errors. Decoded strings must be Unicode
scalar text; the native profile does not admit isolated UTF-16 surrogates.

The controller owns file admission and the parser process. The worker receives
the admitted bytes and request parameters, not the input path or runtime
credentials. It clears its environment and runs in `/`; Linux additionally
binds its lifetime to the controller and tightens seccomp after input admission.
The controller concurrently drains bounded stdout and stderr. Cancellation,
output refusal and the wall-clock deadline kill and reap the owned child before
the operation relinquishes ownership. Under the current cooperative MCP
cancellation lifecycle, the input-read permit stays held until that read has
actually completed. Arbitrary abort or drop by a direct Rust caller is outside
this qualified path: an already started blocking filesystem operation can
outlive the outer future and its permit. File admission and in-flight file I/O
do not have the parser worker's hard wall-clock deadline. Callers should request
cancellation through the token and await completion of the owned operation.

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
embedded-content identities, UTF-16 offsets and the three content-position
states. It saves attempted comparisons before asserting,
so a mismatch remains visible. It does not claim parity for upstream URL
resolution, browser acquisition or Evidence wrappers.

The additional `scripts/rea-source-map-content-reference.mjs` is an original
fixture producer. It parses authored inert sources with real Babel 8.0.6,
generates maps with Babel generator 8.1.0 and gen-mapping 0.4.0-beta.0, and
executes the fixed `rea-agents@6.8.0` `traceSourceMap` and `webSourceOffset`
functions. It emits each complete original observation before checking the
case and retains the final complete fixture. It does not execute generated
JavaScript or fetch declared URLs.

The checked fixture contains 26 maps and 133 original observations: 121 admitted
point controls, six malformed inputs refused by the original, and six original
successes involving isolated surrogates that remain explicit native profile
gaps. Eleven direct original offset controls are also retained; seven are in
the native coordinate domain and four demonstrate original rejection of
invalid or unrepresentable coordinates. This count is not a claim of 133
native parity successes.

The fixture preserves complete original result JSON strings and input map bytes.
Its provenance record binds the actual Node child, raw stdout/stderr hashes,
complete controller terminal, fixed original package identity and before/after
dependency inventories. The original independent oracle directory had lost its
installed packages; this run restored all 18 archives from the retained lock
using their exact SHA-512 integrity values into a fresh private directory.
No package install hooks ran and no existing package directory changed. The
initial capture's instrumentation failure is retained separately; the complete
accepted capture uses the corrected identity-record copy and a new output
directory.

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
