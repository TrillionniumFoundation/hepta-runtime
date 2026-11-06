# Final integrated release build and Source Map qualification

This archive preserves the completed unified release-build phase and the three final Source Map gates executed on 2026-11-04. It records phase-specific results. It does not attest to the terminal result of the outer Rust matrix job, and it does not qualify the complete REA `trace_web_source_location` tool or Evidence workflow.

## Immutable release and phase boundary

- Frozen executable SHA256: `0595fbf02e0f492bd151fec97eb90cb704a88810e9415b90582d348f3db99b6a`.
- Executable size: 18,437,832 bytes.
- Source commit: `b857dc7d646dc938e29a51fa82a5856d9b96f842`.
- Source input-tree SHA256: `0ab735bb69893f88ea4f81c73d5d64d5220d234d3ead90cba88c55542eec9abb`. This is the recorded source-inventory digest, not a Git tree object ID.
- Frozen executable path: `/home/qian-qi/work/hepta-rea-continuation-20261104-r2-evidence/final-release-r1/frozen/hepta-runtime`.

The release phase ran the exact command retained in `release/summary.json` and `commands.json`:

```text
/home/qian-qi/.cargo/bin/cargo +1.95.0 build --locked --offline --all-features --release --bins --examples -j4
```

It exited 0 after 440.455821 s and completed its frozen-binary summary at 2026-11-04T13:36:58.236169+00:00. Its recorded Cargo environment overrides and child umask 0022 are retained. The common helper's byte snapshot has SHA256 `2eca7f528d026e1deb6315148d3bd6ebc1188706edb6dad53f0f05e7a6eba1d0`.

The outer durable job `1a1a6c02669-fc05-2894` also runs the Rust matrix and was still running when this archive was requested. This package makes no claim about its eventual terminal status. Its growing aggregate log was neither read for qualification nor copied into this archive. Only the completed release phase's stable summary, per-stage logs, source snapshots and source-monitor report were selected.

## Three completed Source Map gates

The separate Source Map durable job `1a1a6d6925b-fc05-28fd` has authoritative `succeeded` / exit 0 status with complete, durable output. Its three commands all exited 0, using the same frozen executable and Node v22.23.4. The exact argv, cwd, child umask, stage times and original stdout/stderr hashes are retained.

| Gate | Result | Stage duration |
| --- | --- | --- |
| Independent producers and reference interpretation | 8 fixtures qualified under the stated split: 7 direct consumer agreements and 1 independently authored flattened-equivalent check with an explicit direct-consumer divergence | 1.002370 s |
| Actual installed REA 6.8.0 point-contract comparison | 8 fixtures / 217 queries matched the point projection and embedded-content identity | 3.834012 s |
| Public MCP and owned native worker | All 7 recorded admission, identity, recovery and lifecycle gates passed | 33.040736 s |

The complete original qualification receipts are in `source-map/independent/qualification.json`, `source-map/upstream/qualification.json` and `source-map/mcp/qualification.json`. The phase summary is `source-map/summary.json`.

### Independent producer/consumer scope and retained counterexample

Versions were @jridgewell/trace-mapping 0.3.31, @jridgewell/gen-mapping 0.4.0-beta.0, @babel/parser 8.0.6 and @babel/generator 8.1.0. The fixed harness records 88 decoded mappings, 88 position queries and 101 native-worker invocations. It also retained five expected malformed/unsupported-map refusals.

Seven original-map fixtures agree directly with the pinned trace-mapping consumer. The nested-index fixture does not. Its direct consumer projection reports generated position (line 4, column 13), while the independently authored flattened equivalent yields (line 4, column 4); the other recorded row remains (line 5, column 0). The retained divergence identifies propagation of a parent column offset into a nested section whose relative line is nonzero.

Both the original nested fixture and its independently authored equivalent are archived, together with `nested-index.consumer-divergence.json`. The native projection matches that equivalent; the receipt explicitly sets `direct_consumer_projection_equal: false` for the nested fixture. This is **7 direct agreements plus 1 separately qualified equivalent**, not 8/8 direct agreement.

The previous r3 failure remains a separate failed attempt. This new archive neither edits its artifacts nor retroactively relabels that direct-consumer failure as a pass. The final receipt preserves the disagreement explicitly and qualifies only its stated finite projection.

### Actual REA comparison

The upstream harness loaded installed `rea-agents@6.8.0` and its actual `dist/javascript/sourceMaps/TraceSourceMap.js` module:

- Package JSON SHA256: `b0fc212f6bea9b4ee6e2b3ab0b52dd95402c229da3b8652127e5f131c3445b39`.
- Module SHA256: `2bf3b1e6d022bffc2e931133275846188141ffa6bd6e5b636c24d54225986ea1`.

| Fixture | Queries |
| --- | ---: |
| babel-compact.map | 76 |
| babel-readable.map | 80 |
| empty-map.map | 4 |
| gen-mapping-unmapped-empty.map | 12 |
| indexed-offsets.map | 16 |
| negative-delta-coincident.map | 11 |
| nested-index.map | 10 |
| unknown-sources.map | 8 |
| **Total** | **217** |

Every recorded fixture matched the actual REA point projection and embedded-content identity. All eight original per-fixture `.comparisons.json` files are copied byte-for-byte; they retain each attempted query's position, actual REA response and native response. The original harness writes these records before asserting each comparison.

This contract covers finite-fixture point selection across generated lines, coincident mappings, source/name/section declarations and embedded-content identity. It does not qualify URL resolution, source-content offset verification, browser acquisition, Evidence envelopes or the complete upstream tools.

### Public MCP lifecycle scope

The seven recorded gates cover full-byte map identity, bound continuation, five admission/identity refusals, malformed/stale input followed by recovery, ordinary MCP cancellation, fixed worker deadline and stateless reinspection after a controller restart.

- Owned-worker cancellation/reap/recovery: 0.0022441649343818426 s within the unchanged 5 s cancellation budget.
- Fixed production deadline: 20.311579891014844 s measured from before request submission; the runtime deadline remains 20 s and the original observation budget remains 25 s.
- Both lifecycle pass records declare `manual_worker_cleanup_used_for_pass: false`.
- Restart coverage is fresh stateless inspection of the same admitted bytes, not a retained-result or Evidence handle.

The original MCP harness kept requests and parsed responses in memory. It persisted the qualification receipt, the stage stdout and two empty stderr files, but no raw request/response wire transcript. Those exact existing artifacts and the original harness are archived. Missing historical wire messages have not been reconstructed or represented as originals. Temporary policy/configuration files and owner state were cleaned by the original harness and are excluded from this archive.

## Input freeze, packaging and omissions

Both completed phases retain their complete before/after source inventories with the same source input-tree SHA256 above. Both source-monitor reports show zero events, no errors and no truncation. The snapshot selection and exclusions are recorded inside the inventory files; the two phases do not substitute for a later full-matrix result.

`MANIFEST.json` maps every archived item to its original absolute path, byte length and SHA256 and records the archive hash. JSON reports and per-query comparison files are copied byte-for-byte. Raw stdout/stderr, fixture/map text and harness sources use lossless JSON wrappers containing their exact UTF-8 text (or base64 where necessary) and original-byte hashes. Empty logs and all original newlines remain recoverable.

The executable is identified by hash and size but is not copied into the repository. No runtime configuration, state directory, token, temporary owner database or growing matrix log is included. This commit adds only this new documentation directory; it makes no production-code, test, assertion, timeout or golden changes.
