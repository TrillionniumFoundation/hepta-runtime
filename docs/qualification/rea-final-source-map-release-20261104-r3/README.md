# Corrected release and Source Map qualification

This archive preserves the corrected release build and three completed Source Map gates from 2026-11-04. It qualifies the stated finite native observations. Complete REA trace_web_source_location behavior, Evidence workflows and full upstream tool parity remain open.

## Artifact and source

- Frozen release SHA256: aa580409a73bc2e0927ead93d32634239051a39fc951c3c2a92d5a1dece8347a
- Size: 18,437,864 bytes.
- Production/test/script source commit: ed74d9dbf04b97fad38112c2ac08127bf99b3590
- Selected 641-file input-tree SHA256: 4021ee22efdf2eac830e08afc45eddf37b264e7fd31a222c329b4950ef2d94b6
- Build summary SHA256: 0541d43b62f631b3ebcda4895bafc5cdc087ac94460780191c0e61a4f043292d
- Source Map summary SHA256: 0ab55e837acdd3a9ea16147dabebc1e989da18d5e10616210de58d500889d14d

The build ran Cargo 1.95.0, locked/offline, all features, release, bins and examples, with four build jobs. It exited 0 after 427.922003 seconds. Both build and Source Map snapshots retained identical input trees before and after; their inotify monitors recorded zero changes and no errors. These are content inventories, not Git tree IDs.

This candidate includes the production registration repair placing rea_inspect_source_map in the runtime-only tool set. The source-selection identity remains explicit; this archive does not infer complete operation compatibility from that repair.

## Actual Source Map gates

| Gate | Recorded outcome | Duration |
| --- | --- | --- |
| Independent producers and consumer interpretation | Eight fixtures under the preserved seven-direct plus one-independent-equivalent interpretation below | 0.770544 s |
| Actual installed REA 6.8.0 comparison | Eight fixtures and 217 point queries match their selected projection and embedded-content identity | 2.121753 s |
| Public MCP and owned worker | Seven original admission, identity, recovery and lifecycle gates pass | 31.235444 s |

The separate Source Map job 1a1a737e99b-fc05-2a97 has authoritative succeeded / exit 0 status, complete durable output and confirmed terminal publication. There was no task timeout, cancellation or automatic retry. Original and corrected outer resource/deadline fields were compared from their actual durable requests; both original JSON inputs are retained in resource-profile/. The original four harness/helper inputs remain byte-identical and are preserved as lossless wrappers. Exact stage argv, cwd, exit codes, times and original log digests are retained in commands.json.

## Independent reference boundary

The same original harness uses Node 22.23.4, trace-mapping 0.3.31, gen-mapping 0.4.0-beta.0 and the pinned Babel producer. Seven original-map fixtures agree directly with trace-mapping. The nested-index fixture retains a genuine direct-consumer divergence: that consumer reports column 13, while native Rust and the actual REA point projection report column 4 for the selected fourth display line. An independently authored flattened-equivalent map supplies the eighth golden. The original divergence, equivalent input and actual REA comparisons are all copied; no native behavior was changed to fit the divergent consumer.

This distinction follows the recorded nested-offset rule: a parent section column offset applies only on the child's first generated line. See the [ECMA-426 section-offset algorithm](https://tc39.es/ecma426/) and the preserved original counterexample. A matching point projection and source-content identity do not prove an original source byte offset, full trace-tool schema, browser URL resolution, import maps, full application graph or operation-specific Evidence.

## Lifecycle boundary

The original public MCP harness checks owned worker cancellation within its unchanged five-second observation bound, the configured twenty-second worker wall deadline, same-owner recovery, cold restart and the stated admission/identity conditions. Worker kill/reap is observed without counting manual worker cleanup as a pass. The twenty-second deadline starts after source capture. Descriptor admission and an in-flight local filesystem read remain cooperative capture operations; this is not an end-to-end hard request-time bound or a general arbitrary-Rust-future-abort guarantee.

The harness did not write a raw MCP wire transcript. This archive does not reconstruct one from summaries. The original qualifier JSON files retain the exact observed times and outcome fields.

## Full-matrix boundary and failure history

The enclosing build-plus-Rust r2 job is a separate result. Its full Rust matrix is failed: both feature modes passed the repaired intent and runtime registration cases but rejected four SSH fixture paths under the longer TMPDIR. Its source inventory remained unchanged. That failure is not relabeled by these successful Source Map gates; the subsequent short-TMPDIR full matrix is qualified separately.

The prior 0595 release archive remains unchanged. All copied original input bytes were checked again after copying. JSON receipts are original bytes; logs, JavaScript source fixtures and harness files use reversible byte wrappers. The binary, runtime policy/configuration, owner databases, tokens and temporary working state are excluded. The source-map and release phase logs are stable completed logs; no growing aggregate log is used as a terminal attestation.
