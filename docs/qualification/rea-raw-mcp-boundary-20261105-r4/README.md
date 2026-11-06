# REA raw MCP boundary component proof — 2026-11-05

This checkpoint adds `src/mcp/rea_mcp_transport.rs` and its sibling tests. It does not wire the integration server, change Cargo features, mark any operation qualified, or alter the original failing dual-MCP receipt.

## Contract and integration

Use `ReaMcpTransport::new(stdin, stdout)` in the STDIO server. In each selected handler, read `context.extensions.get::<ReaRawArguments>()`, return any `protocol_error()` as an RPC error before executing the provider, and pass `object_keys(&[])`, `object_keys(&["filters"])` or `object_keys(&["view"])` into the corresponding frozen input validator. The service visibility, owner policy and request audit remain the integration server's responsibility.

The explicit selected names are `rea_inspect_elf_notes`, `rea_get_evidence_bundle`, `rea_inspect_apk_signature_evidence`, `rea_inspect_analysis_view` and `rea_export_evidence_bundle`. This list does not claim that every selected handler already exists or has operation qualification. The old `rea_inspect_apk_signature` preview is unchanged.

The original rmcp AsyncRwTransport still parses frames and handles malformed JSON, notifications and outgoing writes. A reader returns no bytes beyond the first line ending, so the current raw frame has exactly one owner slot. No request-ID map exists. Partial input survives a dropped receive future. Request facts move into typed Extensions, cannot be supplied through client `_meta`, and drop with the request.

The adapter preserves JavaScript Object.keys behavior: canonical array indices 0 through 4294967294 sort numerically before other strings; duplicate property names retain their first position and last value. Null arguments remain distinct from omitted arguments. The original Node RPC messages for null/array/string arguments are reproduced, including formatting and absence of error data.

The extra raw copy is limited to 10485760 bytes, the observed frozen Node STDIO default receive-buffer limit. Selected REA frames exceeding this copy limit carry a private protocol failure. A typed call must reject it in the tool handler. An over-budget CustomRequest stays on the SDK rejection path (-32601 by default); an integration custom-request handler can read the same private failure without copying its parameters. Non-REA frames retain the original SDK behavior. This component proof does not certify an exact cross-producer oversized-input error/closure contract. HTTP transport is not adapted by this module. These boundaries must not be inferred as closed from the component tests.

## Actual verification

Final source commit in the isolated worktree: `b7a1db4ea80ba8211b384a497a98ccb74f4ac924`, following `7416a00603c4922845311233da7876ce19359572`.

- First job `1a1a95083f2-fc05-3424`: compile succeeded, 14 tests passed and 1 test failed. That negative test incorrectly assumed the SDK would deserialize an array-valued `_meta` as CustomRequest. The SDK rejects the frame earlier. The original logs, source identity and failing test source are retained under `r1/`.
- Corrected job `1a1a952f0d0-fc05-3448`: 15 tests passed, 0 failed, 0 ignored; all-targets Clippy with `-D warnings` passed. Authoritative status is terminal success, exit 0, non-timeout, complete durable output.
- The corrected negative test compares the actual error wire and next-frame behavior against the unmodified AsyncRwTransport. The production module did not change between these first two runs.
- The corrected mini harness uses exactly 73 registry package name/version/checksum entries from the integration Cargo.lock. Its manifest, resolved lock, logs and source digests are retained. It is a focused component build, not the whole runtime matrix.
- Independent review then identified an unnecessary deep copy of rejected CustomRequest arguments. The follow-up moves that argument out temporarily, validates remaining protocol fields by borrowing, restores the original value on failure, and leaves over-budget CustomRequests on the existing rejection path. It also retains APK static-view key order.
- Final job `1a1a95a6f05-fc05-3485`: 19 tests passed, 0 failed, 0 ignored; strict all-targets Clippy passed. Source hashes before and after are identical. Four added regressions cover actual input exceeding 10 MiB followed by a valid request, preservation of the original oversized argument allocation, rollback when another SDK field is invalid, and static-view integer/duplicate-key order. This is not a claim that the base SDK or all adapter allocations have a 10 MiB aggregate limit.
- Actual rmcp serve coverage proves Extensions reach RequestContext, invalid null input yields RPC -32602 without executing the test handler's successful-operation branch, and the next request succeeds.
- Other tests cover duplicated keys, integer-index ordering, repeated request IDs, ignored bad frames, forged metadata, partial-read cancellation plus concurrent response sending, BOM/CRLF/EOF behavior, non-REA parity, bounded copying and ownership release.

The test harness paths in the original logs are exact historical paths. To rerun in another checkout, use the archived Cargo manifest/lock with a lib.rs that imports that checkout's module, retain the dependency pins, and choose a private target directory. The integration owner must subsequently wire the server and rerun the actual Node-versus-native MCP operation runner on its new binary.

The original test stdout files end with intentional blank lines. Their byte-exact contents are retained in test.stdout.json lossless base64 wrappers, each with its original byte length and SHA256; the remote originals are unchanged.
