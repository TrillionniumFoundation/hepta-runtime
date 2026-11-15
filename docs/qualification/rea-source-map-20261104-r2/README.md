# Native Source Map qualification — 2026-11-04 r2

This directory qualifies the explicitly selected source-map declaration reader,
not the complete upstream trace_web_source_location contract. The native report
does not claim REA Evidence identity, browser acquisition, URL resolution,
embedded-text offset verification, retained views or source equivalence.

## Exact tested artifact

- Parent source: 1d9ea7e7e7a1625c611d5f6e037a1ed9d57379d4, plus the source-map implementation recorded in the input inventories.
- Frozen development binary SHA-256: 91090a9b4be97842bd76b5a3bcaf41a2e187fbc1a404be4336c8508cad2cb314.
- Binary size: 438,416,416 bytes. The binary itself is excluded from this source-control evidence.
- Full source/script inventory SHA-256 for the R3 development run: fe849334a4b1b20cced1aa0d680fd3a1c6f04fe6d4d45c2e3f0b6da6d0d4db5d.
- Native production inputs still match that build after the reference-script correction; see production-identity-check.json.

## Results

| Gate | Actual result |
| --- | --- |
| Native unit tests | 16 passed, zero failed/ignored in the selected module |
| Strict Clippy | all targets, all features, locked/offline, Rust 1.95.0, warnings denied |
| Independent production/decoding | 8 fixtures, 88 decoded mappings, 88 point queries, 5 malformed/unsupported refusals |
| Direct trace-mapping agreement | 7 fixtures agree; 1 nested-offset discrepancy is separately characterized |
| Actual npm REA point projection | All 8 original fixtures and all 217 queries agree, including the nested case |
| Actual public MCP | 7 lifecycle/admission/identity gates passed |
| Ordinary cancellation | Actual stopped child killed/reaped in 0.002273911 seconds under unchanged 5-second observation budget |
| Fixed worker deadline | Actual stopped child killed/reaped; 22.139320519 seconds from request admission under 20-second worker deadline and unchanged 25-second observation budget |
| Recovery | Same original MCP owner served the next request; cold-process reinspection matched the identity |

MCP output retains the exact bytes/profile identity, bound continuation,
five admission refusals, malformed and stale input recovery, and no manual child
cleanup used as a passing lifecycle observation. These are finite Linux fixture
observations, not platform-wide or latency guarantees.

## Preserved differential failure

The first development aggregate remains status=fail in development-r3. Its
independent consumer expected column 13 for a nested map where the native
decoder returned column 4. The actual MCP gate passed in that same run; the
dependent upstream stage was not counted as run.

The fixture has an outer zero-based offset (2,9), an inner offset (1,3), and a
leaf mapping at (0,1). ECMA-426 section 10.1 adds a parent's column only to a
decoded child mapping on line zero. The correct composed point is (3,4).
The authenticated REA implementation uses the same rule and its actual
traceSourceMap function agrees with the native result on this original fixture.

Independent-r4 preserves and asserts trace-mapping 0.3.31's direct column-13
observation, then uses an independently authored flat equivalent for this one
case. It reports seven direct agreements and one characterized divergence.
Nothing was changed in the native decoder to accommodate the discrepant oracle,
and the failed R3 aggregate was not rewritten as successful.

The separate upstream-r3 qualification invokes the actual installed
rea-agents@6.8.0 traceSourceMap, rather than importing the native algorithm into
the oracle. Its package/module hashes, queries and full attempted comparisons
are retained. The fixed REA publication tarball SHA-256 is
8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb.

## Build and evidence custody

The first offline build attempt selected an older Cargo cache without Oxc;
its dependency-resolution failure is retained as source-map-test-r1.log.json.
R2's initial 15 unit tests passed. R3 adds the independently checked across-line
lookup and exact section-boundary cases and passes 16 tests, then builds the
actual binary. R4 changes the reference script/documentation and passes strict
Clippy with the unchanged native production source.

Original durable requests, terminal records and logs are retained under
original-jobs. The R3 external aggregate exits 1 as originally observed;
the separate actual-upstream and corrected reference/Clippy jobs exit 0.
UTF-8 .log files are losslessly wrapped as .log.json with original path, byte
count, SHA-256 and complete text, including final blank lines. Other original
files are copied byte-for-byte. The artifact manifest identifies every stored
file; these are source-bound development receipts, not a final integration CI
or a qualification of a later binary.

The first packaging attempt failed when it required a nonexistent stdin.bin for
a shell_start job. Its failed terminal record is retained. The resumed packer
requires existing copied bytes to match, records absent optional stdin artifacts
explicitly, and never substitutes an empty file for them.

See [the native contract](../../rea-native/SOURCE_MAP.md) and the scripts
rea-source-map-reference.mjs, rea-source-map-upstream-reference.mjs and
tests/rea_source_map_mcp.py for exact reproducible checks.

Primary format reference: [ECMA-426](https://tc39.es/ecma426/).
