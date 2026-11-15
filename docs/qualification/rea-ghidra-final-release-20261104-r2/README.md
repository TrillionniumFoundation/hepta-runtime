# Final release Ghidra analysis qualification

This archive preserves the original eight-gate Ghidra analysis qualification against the frozen release SHA-256 4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d (17,820,288 bytes). The qualification and release-wrapper-binding files are copied unchanged.

The original harness passed these eight checks:

1. Revision-two named byte provider fixes dynamic ELF import, with a distinct bridge/profile identity.
2. Actual dynamic-library ELF analysis and named function entries agree with independent GNU nm.
3. Analyzed incoming call references agree with independent GNU objdump.
4. The actual native Ghidra decompiler returns the selected function's complete C digest, and the original child cleanup is checked.
5. A controller restart returns the original retained decompilation without relaunch.
6. Changed content with the same key, invalid selectors and extra selectors are refused.
7. An interior address produces a real backend failure without successful facts.
8. Cancellation reaches a real native decompilation under the frozen original owner, without relaunch.

The qualification's eight checks are retained verbatim in workspace-evidence/qualification.json. Seven actual analysis jobs are retained under workspace-evidence/jobs/jobs/: five analysis results, the expected interior-address failure and the cancelled decompilation. Their original request/stdin, exit/witness, launch/owner records and complete stdout/stderr are included. Expected backend failure and cancellation are preserved with their original terminal values; they are not rewritten as successful process exits.

The original workspace also retains C fixture text, GNU nm/objdump output, saved MCP requests/results, controller stderr, the observed native decompiler record, authority ownership metadata and the complete installed-engine manifest. The original outer job has no stdin file: its Python wrapper was supplied as argv -c and is preserved in outer-job/request.json. Its complete 4,846-byte stdout and empty stderr are retained. The harness source is copied under harness/ with the original SHA-256 7932b234cd96decf2df522be161d4e03b11d4d129e50512f69949ce1eaa00c0a.

This was operator-mode local-SSH qualification. The generic launch/runner layer still uses Python; Ghidra 12.2, JDK 25 and the native decompiler remain external engines. isolated_host_qualification is false, targets_run_by_provider is 0 and rea_full_parity is false. Installation identities are evidence of this tested installation, not a sealed transitive executable closure.

The retained cancelled_private_scratch_removed_by_harness=1 records harness cleanup. It does not establish automatic runtime scratch deletion, a filesystem quota or source semantic equivalence. The previously recorded 141 finite C-input experiment was not rerun by this eight-gate harness and is not included as a current-release result.

The wrapper binds the frozen runtime and unchanged harness before and after the run. build-provenance/ contains the original release-build qualification and complete identical before/after source and verification inventories. The archive's independent import-time inventory observes that the current checkout still matches those build inputs; it is not presented as a new historical in-test observation.

Runtime binaries, both compiled ELF fixtures, controller state/databases and installed engine binaries are excluded. Their applicable identities and exclusion reasons remain in the top-level manifest. C fixture source, installation manifests and all retained raw records remain byte for byte, including original JSON integers and absolute paths. This archive operation reran no engine, test or build. The manifest covers every included file except itself.
