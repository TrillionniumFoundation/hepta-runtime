# Native ASAR qualification — 2026-11-04

This record qualifies the bounded native ASAR profile and explicit packed-member acquisition into the existing JavaScript graph. The two new public tools run in the shipped Rust runtime without Node. Node is used only by the independent test reference.

## Result and identity

- ASAR adversarial/controller unit tests: **13 passed**.
- Existing JavaScript graph unit tests: **8 passed**.
- Real descriptor-worker and shipped-MCP integration tests: **2 passed**.
- Independent producer/consumer and lifecycle qualification: **8 gates passed**, 24 packed-member range comparisons, 68.500 seconds.
- All-features offline/locked Clippy with warnings denied, formatting check and diff whitespace check: **passed**.
- Candidate binary SHA-256: `14824bcf9c1de687f5981d3966c31451e6428a30a83d540a0df1d040394f4646`.
- Snapshot of `src/**/*.rs`, `Cargo.toml` and `Cargo.lock`, SHA-256: `4377ba9bc6784cb2a9a9ca61d45ade3be07247935a153a08b8cf486cafbc14c6`; unchanged before and after external qualification.
- Source base: `1d9ea7e7e7a1625c611d5f6e037a1ed9d57379d4`. The source inventory includes the candidate's new and edited Rust files, before this evidence commit.
- Reference: `@electron/asar@4.2.0`, actual installed producer and consumer, independently checked against authored fixture bytes. Package/source hashes are in [the reference](external/inputs/upstream/reference.json).
- Produced fixture archive SHA-256: `8b760592d36d56332376dd65af86295cbbb8727aa3fdf2fde9527cff9b320e7a`.

[Commands and exit codes](final-r2.json), [external qualification](external/qualification.json), [environment](environment.json), and [source inventory](external/source-before.json) bind this result to the actual candidate. The candidate is a Linux x86-64 debug-profile runtime with optimized code and debug information. This evidence does not qualify a different assembled binary until that binary is checked again.

## Independent behavior and negative cases

The upstream reference produced and consumed 14 entries, including nine packed files, directories, links, one unpacked file, empty content, Unicode source, binary non-UTF8 payloads, an exact 4 MiB integrity block and a member crossing that boundary. Native sorted metadata, selected ranges and complete selected-member SHA-256 matched the reference and separately authored bytes.

The reference separately records the complete native Pickle-header digest and Electron's JSON-header-only digest. Native `header_sha256_scope` is `complete_pickle_header`; callers cannot substitute the Electron fuse byte scope. Header precondition matching, member integrity consistency and whole-archive identity remain distinct.

The shipped MCP rejects malformed/truncated Pickles, duplicate decoded JSON keys, invalid UTF-8, unsafe paths, floats/coerced offsets, overlaps, out-of-file spans, contradictory unpacked metadata, wrong integrity blocks, root escapes, symlink admissions, stale identities, duplicate member selection and binary-to-JavaScript admission. Real worker tests also reject a writable input descriptor and emit no partial malformed report.

The graph's ordinary-file and ASAR acquisitions have identical logical source identities, canonical graph hash, observations and counts. Only explicit ASAR acquisitions add archive provenance. The fixture's execution marker remains absent. A new MCP process can read the same pinned archive; replacing the descriptor with an identical-content new inode is refused by the Rust integration test.

## Actual child ownership

| Case | Observation |
| --- | --- |
| Cancellation | An observed original ASAR worker was stopped using its verified pidfd. Cancellation terminated and reaped it in 0.022983 seconds, within the fixed five-second observation window. |
| Wall deadline | A separately observed stopped ASAR worker was terminated and reaped by the production 20-second deadline; observed delay after confirmed stop was 20.089507 seconds. |
| Recovery | Both original MCP owners remained alive and served the next inventory request with the same source observation. |
| Cleanup | No manual harness worker kill counted as success. Both owners exited on stdin EOF, were reaped, and their output-reader threads joined without errors. |

The raw [cancel](external/cancel/qualification.json) and [deadline](external/deadline/qualification.json) receipts include original owner/child process identities. Their request/reply logs and the cancellation `/proc`/pidfd observations are preserved alongside them. A stopped child cannot satisfy this gate through ordinary completion.

The 24 successful member-range calls in this shared-host run took between 0.197 and 1.872 seconds each. These are fixture observations, not a general throughput or cold-start guarantee. Fixed parsing, memory, byte, entry and wall-time limits are documented in [ASAR.md](../../ASAR.md).

## Scope

This is a native acquisition profile, not full upstream REA JavaScript/Electron equivalence. It does not resolve links, read unpacked sidecars, execute target JavaScript or Electron, authenticate a publisher, claim a whole-archive content digest, or create retained REA Evidence/views. The wider compatibility ledger remains authoritative.

The committed evidence contains original text receipts, logs, source inventories and reference metadata. Generated binary fixtures and the 440,449,640-byte frozen runtime remain in the recorded qualification workspace; the fixture generator and SHA-256 manifest make their origin explicit without adding binary build products to the source repository.

Reproduce using `tests/rea_asar_qualification.py` and the command recorded in [external-r2-runner.json](external-r2-runner.json). Supply the exact candidate binary and an installed `@electron/asar@4.2.0`; use a new workspace. `tests/rea_asar_external.rs` also accepts `HEPTA_ASAR_TEST_RUNTIME` for checking a separately assembled candidate.

### Log encoding

Three Cargo logs include terminal blank lines. Their `.log.json` wrappers retain the exact UTF-8 text, original byte count and original SHA-256; decoding the `text` field reproduces every original byte. The original files are also retained at their recorded runner paths. This representation preserves the diagnostics while keeping the source commit whitespace-clean.
