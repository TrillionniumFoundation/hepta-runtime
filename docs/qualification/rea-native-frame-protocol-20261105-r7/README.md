# Native REA final STDIO frame qualification — r7

The frozen r7 runtime passed all **30 actual MCP calls and 4 additional invariants** in the final frame gate. This is a finite Linux transport result. It does not qualify a complete REA operation, HTTP transport, arbitrary unadmitted input, or all 229 frozen upstream tools.

## Frozen implementation and producer

- Runtime source checkpoint: `e32067bb10896e0d54a5b1e77c2ffe56a5ae9eef`; 796 selected source files, SHA256 `51f51c3baa4cf66e55e11189088fe7f527ae4b9028d2516907ddb98b4a1681ed`.
- Immutable runtime: 476,006,864 bytes, SHA256 `5d6c0cdbd21ac93084aac93a68d8b76b77ece34ac29e57bdc066c5718546e859`.
- Build receipt SHA256 `db6c4e18c3536f40e7e692fbd8e6c976897976d9b1b2d1c0aebb69aa1389a5f3`; freeze receipt SHA256 `f62edd6c2ac126d447abf210362c227f102f96b56314ffa7a6168e37946dacd1`.
- Frame implementation commit: `3b4916464f887a6599e5ffe30331578bc832ea4f`.
- Runner commits: `75d587687b64623a47948b11b08c23b6f9921c66`, then `957bcdd7e659c356e3f66ad2125d55438ba1c760`. The final committed runner and tests are byte-identical to the private r3 producer actually executed.
- Runner SHA256 `48db5a8559a9ad6c992a9ec30f9f80b56b4dd609711c6f9f1cf163c0be6b61d3`; tests SHA256 `55d942389a23486d902358e38bd57cabc5b4316a566a5426673e137b1e29da35`.

The actual gate used a private producer copy while other agents monitored the qualification checkout. Every unchanged dependency was compared with its Git blob at `75d5876` before copying. Its complete provenance is retained. Production source, npm package and private producer each have before/after snapshots and zero inotify events or lost-coverage errors.

## Why the service boundary matters

The wrapper surrounds the SDK `Service<RoleServer>`, outside its `ServerHandler` adapter. This covers SDK metadata/version refusals before tool dispatch as well as results after runtime audit/acknowledgement work and SDK protocol normalization. It uses private facts attached by the bounded raw STDIO transport, with no request-ID registry.

Accounting includes the exact legal ID, actual SDK result discriminator, final metadata, JSON-RPC framing and terminating LF. A too-large complete result produces a bounded native transport refusal; if that refusal cannot fit, the same ID is kept in a smaller RPC error. The smallest error is shorter than the smallest admitted tools/call envelope for these five names. The private input ceiling and minimum valid response ceiling are both 10 MiB. An invariant failure stops before returning a serializable oversized fallback.

The wrapper recognizes five exact names, including the future analysis-view route. Actual r7 tools exercised here are ELF notes, APK Evidence, bundle retrieval and export; r7 does not yet register the general analysis-view endpoint. Other names and transports without successful private raw admission pass through. Unexpected Task/InputRequired results are checked by the real SDK component tests; the four actual r7 operations are synchronous and did not produce those variants.

## Evidence chain, including failures

| Evidence directory | Actual outcome | Meaning |
| --- | --- | --- |
| `frame-service-r1` | Failed: 3 component tests passed, 7 failed | Initial test assumptions incorrectly treated initialize as the modern request lifecycle and `-0` as an admitted SDK i64 request ID. The unmodified failure is retained. |
| `frame-service-r2` | 10 component tests passed; strict Clippy passed | Actual rmcp 3.4.1 duplex transport and production wrapper, with an explicit default-budget shared-Failure support fixture. This is not the complete runtime. |
| `frame-native-r7` | Failed at the first positive fixture | A 16 KiB note owner exceeded the original image-derived text allowance. No long-ID case ran. |
| `frame-fixture-reference-r2` | Original npm MCP success and complete retention | 65,536 bytes of unreferenced ELF padding make the exact 82,088-byte fixture valid under the unchanged original allowance. Fixture SHA256: `4a4e52384c20cf7bfe23c13a97de163cbc4a6d08319379bfc703d09d73b890f6`. |
| `frame-native-r7-r2` | 29/30 calls and 4/4 invariants passed | The small SDK error case wrongly expected the requested version in the message. Its complete response put it in `error.data.requested`. This failed receipt remains unchanged. |
| `frame-sdk-control-r6` | Exact raw request and full RPC response matched r7 | The pre-wrapper frozen r6 runtime, with the same Cargo.lock, independently produced code -32022, message “Unsupported protocol version”, requested version and all five supported versions. The pinned SDK constructor confirms these fields. |
| `frame-native-r7-r3` | **30/30 calls, 4/4 invariants passed** | The corrected gate compares the entire SDK ErrorData object. All other cases and budgets are unchanged. |

The final authoritative job is `1a1a9d8b7f6-fc05-388f`: exit 0, no timeout, no automatic retry, complete and durable output. Its qualification receipt is 1,610,634 bytes, SHA256 `9635ac48cdaadc56b072197ade38e9a17cfddb5dc7a776868effc2aa444e1ff9`.

The original actual SDK component witness returned 10,485,809 bytes for a 10,485,760-byte admitted request before wrapping: 49 bytes too many. The wrapper returned 10,485,712 bytes with the same ID. Both observations and the zero handler-call witness are retained in the component stdout.

## Actual r7 coverage

The final process gate covers both legacy initialization and per-request modern metadata, three real complete-result producers exceeding the frame budget because of a long ID, precise maximum admitted string IDs, escaped Unicode/control IDs, i64 extremes, SDK pre-dispatch refusal, a runtime-only tool called without runtime configuration, completed same-ID reuse, subsequent successful requests, and natural EOF.

The three complete producers are ELF notes, APK Evidence and retained bundle retrieval. Their six legacy/modern refusals preserve the final metadata, correct operation context and completed Evidence references where applicable. Subsequent bundle reads contain both complete parent records unchanged. Normal and maximum-ID export calls publish complete retained bundle bytes; normal export responses remain target-content-free.

The two runtime sessions in the final gate both ended with return code 0, no manual or forced cleanup, a signalled owner pidfd, no remaining process group and a stopped reader. The fixed request deadline is 30 seconds, EOF allowance 15 seconds, line cap 16 MiB and received-transcript cap 256 MiB. The outer job is 900 seconds with no CPU or memory override and nice 0. No production limit, client limit or refusal predicate was relaxed.

Five producer negative tests additionally reject wrong IDs, over-budget or unterminated frames, false lower bounds, stale operation context, changed compressed logs and incomplete SDK errors.

## Inspecting the originals

`proofs.tar.gz` contains exact original bytes of receipts, source snapshots, build/freeze receipts, wire indexes and gzip members, target fixtures, completed exports, launch/close observations, durable job requests/stdout/stderr, and authoritative terminal responses. Terminal tool responses are retained as their original text in a JSON wrapper. Private runtime state directories and compiled artifacts are outside this compact proof pack.

Each `wire.jsonl` indexes individual `wire-NNNN-{sent,received}.json.gz` files. Decompressing one member reconstructs the original UTF-8 JSON-RPC line including its LF. The index records both compressed and original byte counts and SHA256 values; no ID or field is removed from these originals. The smaller qualification report replaces repeated large IDs with digest/size facts and refers back to the complete wires.

`manifest.json` binds every archive member. Archive creation read every member back and verified names, counts, exact byte lengths and hashes. Source/SDK bytes relevant to the component review are also retained. The original npm authentication covers the complete frozen package tarball, not its entire transitive dependency closure.

The executable runner remains `scripts/rea_frame_mcp_qualification.py`. Its original complete argv and resource profile are in the durable job request. A later replay needs the matching frozen source checkout because the runner rehashes every build-manifest source file; a newer working tree is intentionally refused. `qualified` remains false and status remains OPEN even for a finite PASS.

The first archive publication job, `1a1a9dd731f-fc05-38cb`, completed archive creation and member verification but could not stage files outside the sparse checkout. The following publication used Git's explicit `--sparse` option for these archive files; no checkout pattern, runtime source, test result or proof member was changed.
