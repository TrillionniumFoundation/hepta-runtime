# Final release JavaScript MCP and independent AST gates

These are two finite, unchanged verification gates against the same frozen release binary: SHA-256 4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d, 17,820,288 bytes.

The pinned external Rust test executable ran its single actual stdio MCP integration test successfully. The unchanged test covers package declarations, tool discovery, import comparison, candidate edges, unknowns, identity-bound pagination, denied paths and symlinks, stale content, invalid syntax, byte/node budgets and recovery. It checks that fixture-side JavaScript is not executed. Its compiled test source is retained byte for byte and was matched to the checked-out source.

Separately, the unchanged Babel 8.0.6 reference extractor invoked the native parser worker directly and compared eight owned fixtures: imports 17/17, exports 16/16, Electron calls 12/12 and candidate IPC edges 4/4. Both Babel and Rust export results satisfied the unchanged manually counted golden file. The retained reference includes the independent AST nodes and source spans used by that golden check.

The direct worker comparison is not a substitute for MCP transport verification. The normal MCP test does not independently retain worker lifecycle telemetry or raw wire output; its stdout contains the test result. Real cancellation and kill/reap evidence is in the separate final-release cancellation archive. These gates do not prove full REA parity or runtime-observed Electron IPC.

Original gate inputs, results, logs, process request/stdin/terminal/witness records and raw process stdout/stderr are preserved as bytes. The process request has an empty explicit environment map; the frozen runner inherits its process environment and applies only the two HEPTA_JS_AST selection overrides recorded in plan.json. No secret environment values are collected.

The original 180-second process wrapper ran once; the test's existing reply timeout and Babel's existing worker timeout were unchanged. All four wrapper commands (input pins, MCP, Babel, post pins) exited zero, with no retry, truncation or timeout. Source and verification inventories before and after were identical and match the release build provenance. No compilation, source edit, fixture edit or golden correction was performed by this gate.

The archive contains text evidence only. Runtime and test executables are represented by their original paths, lengths and SHA-256 values. Databases and credentials are excluded. The top-level manifest covers all included files except itself; historical absolute paths in original records are preserved.
