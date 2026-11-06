# REA 6.8.0 operation protocol evidence — r4

This archive keeps the actual public MCP observations and the independent APK input component check. It does **not** qualify the complete upstream operation, or the remaining REA tool catalog.

## Artifact and producer binding

The finite dual MCP run used the immutable native-r4 binary, 465,372,680 bytes, SHA-256 `c53066ed5e0a4567e6f488ab1953a52217c9fdc446ed0dec8797b34502bf6e1e`. The same source was committed as `056288ac4951347980ba9e043048352635231a55`, with the 738-file source verification digest `9ed6e25d488ed5620cef0541fd561d21291786c1466a68da4f5e330f33451d73`. The recorded build summary SHA-256 is `1381f8c03f35a4b0210bcdb88fe9ec10bd649b96ca69a55f91b50d45f6415ca0`.

The reference is the complete installed npm `rea-agents@6.8.0` package authenticated against its retained tarball. The original package inventory, Node binary/version, exact launches and raw JSON-RPC lines are included. The fixed Node binary is v22.23.4, SHA-256 `94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90`.

## What actually passed

- Job `1a1a96aad82-fc05-350b`: 73 ELF note input/result comparisons, 19 retained-bundle query comparisons, and 2 cold-session checks passed. Registration schemas and annotations agreed. The native/source and producer monitors finished without source changes. Original receipt SHA-256: `efd7357d0806ea0ed42c334e6ab32f03b0c7e469c03e344832a931afaabdd994`.
- Job `1a1a97254b0-fc05-3548`: captured 297 actual original APK MCP calls. There were 241 schema-invalid and 56 schema-valid inputs. The latter reached the original file service on a deliberately absent fixture; they are not successful APK parsing claims.
- Job `1a1a975b1f1-fc05-3559`: rebound every APK request and response to its original wire ID and exact request bytes. All schema-invalid objects shared the same error template except their aggregate diagnostic string. The compact fixture preserves every input, the original JavaScript property order, and that diagnostic.
- Job `1a1a97dceda-fc05-3589`: the new production APK MCP validator matched all 297 recorded outcomes and complete error objects, plus an independent test proving incomplete/repeated private order hints cannot authorize unknown keys. Two Rust tests and all-targets Clippy with `-D warnings` passed using the existing locked versions, Rust 1.95.0, offline mode and a private target. This is component qualification; integrated native APK MCP qualification remains separate.

The APK validator source/test commit is `6343aa65210ae6429575927ad013b7857a61a94c`. It does not mutate defaults or open files. It checks the MCP schema before the existing service reads the artifact. Whole non-object arguments remain the raw MCP transport's responsibility.

## Real remaining failure: oversized result counters

Job `1a1a97fdb9c-fc05-3596` finished with **exit 1**, not a timeout, and complete durable output. It compared the same 16 MiB ELF file on both actual MCP processes. Its single note has a 3 MiB ASCII owner plus its NUL terminator; the rest is independent zero padding outside the declared table, so the parser text budget is sufficient.

| Flow | Original result | Native-r4 result |
| --- | --- | --- |
| Initial note response overflow | `response_bytes_at_least = response_code_units_at_least = 10587144` | Both counters `10484738` |
| Complete retained bundle overflow | Both counters `10587796` | Both counters `10484738` |
| Retained summary before/after rejected complete read | Full envelopes equal | Full envelopes equal |
| Next small operation and final two-record summary | Full Evidence/envelopes equal | Full Evidence/envelopes equal |

The only differences in these six comparisons were the two counter fields in the two oversized errors. They were not stripped or treated as equivalent. Both processes retained the original Evidence before returning the transport error. Both rejected the full bundle without deleting the retained record, accepted the next operation, and exited naturally after EOF with observed pidfd exit and no remaining process group. No manual cleanup was counted as success.

Receipt SHA-256: `a7e9834afccb0b0d9b2ad16efde7dd96d49f1868a08c4a7e5cac87f3bf0b8dfc`. Its `finite_gate_status` is FAIL and `qualified` is false. The immutable r4 binary, helper source, Node and reference package stayed unchanged. The mutable integration tree was not monitored or used as the source of this probe.

This probe demonstrates retained summary/recovery behavior; it does not prove that all oversized retained bytes can be exported through the still-separate export operation.

## Prior failures remain visible

The original dual-mcp-r2 receipt is included, SHA-256 `584a9d93c873e08e1438baac1dac22e88c06cb8615e9c66af52c638852f321b1`, with its actual failed terminal state. Its complete raw run remains at the recorded source path. That run exposed unknown-key order, non-object arguments, registration schema stripping and annotation differences. The r4 finite run closes those particular tested failures.

The first reference overflow attempt is also retained unchanged. Its unpadded fixture failed the parser text budget, and the final probe writer then collided with an existing `summary.json`; it is not a transport-overflow PASS. The second original-only probe corrected the fixture and established the real overflow/retention behavior before the dual run.

## Limits

All qualification receipts remain OPEN. Active cancellation/owner drain, complete format and compressed-name coverage, exact oversized delivery accounting/export recovery, and the remaining build/source qualification requirements must not be inferred from these finite comparisons. Known malformed-Zstd diagnostic differences are not erased. No complete REA catalog parity, cross-platform support, or external engine replacement is asserted.

MCP comparisons parse JSON text content into JSON values so object insertion order alone is not a false mismatch. Every semantic field, provider identity, Evidence ID, error diagnostic string and metadata object is retained. Non-JSON strings remain exact.

## Archive integrity

`proofs.tar.gz` is a lossless archive of the listed original bytes, including raw requests, responses, stderr/stdout, actual SDK terminal results, source hashes and the exact job request documents. `manifest.json` records each member's original source, byte length and SHA-256; archive creation independently read back and hashed every member. Binary executables, Cargo targets, runtime state and generated workspace files are deliberately not duplicated. Workspace identities and deterministic encoders are retained.

No new behavior tests were run while creating this archive. It is documentation only. Extract into a new directory with a standard tar implementation and verify the manifest before using the evidence.
