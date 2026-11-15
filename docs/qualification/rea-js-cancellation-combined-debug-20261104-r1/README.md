# Historical combined-debug JavaScript cancellation evidence

This archive preserves one passing cancellation and same-owner recovery experiment against the combined **debug** runtime. It is not final release qualification and does not qualify all runtime behavior.

The original MCP owner remained alive while its actual direct JavaScript parser child was stopped with pidfd SIGSTOP. The harness then sent a normal MCP cancellation notification. The original owner terminated and reaped that child within the fixed five-second observation window; a subsequent call on the same owner succeeded. Harness fallback SIGKILL was not used. The parent later exited normally on stdin EOF. These observations are scoped to the recorded owned processes and fixture.

The copied qualification.json and original handoff retain their original qualified:true scoped result, unchanged. The immutable debug binary identity is SHA-256 4bac765313559a34933ee1885792dd61db18223bba402bcb7c6918a7eedcf0c0. No runtime executable, database or credential file is included.

The original-evidence/ group contains the original handoff, original manifest, raw captured job records and logs, harness, and source inventory. The workspace-evidence/ group contains the original external qualification workspace's fixture sources, wire logs, observations, configuration and qualification. Every retained original is copied byte for byte. Absolute path references in raw records are historical references; they are not rewritten to this archive.

The original manifest indexes 28 payload files, including a 44,369,480-byte runtime executable. This archive retains all 27 text payloads plus that original manifest and handoff. Its new top-level manifest records the executable exclusion explicitly and indexes only files actually present (excluding itself).

The tested historical source inventory has 295 source files with group SHA-256 4d2682eda938c49bdbbab45eed4117bbec0a2374477479246716fe749dbadacf, and 613 verification files with group SHA-256 b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4. The retained all-features test log is provenance from the original physical ext4 run, not an additional test execution by this archive operation.

No tests were rerun or expected results changed while importing this historical evidence. Separate final release evidence is required.
