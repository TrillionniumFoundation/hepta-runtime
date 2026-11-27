# PR 159 review fixes

## Additional async input preparation review

Review thread `PRRT_kwDOU4ANVc68rAw9` identified synchronous frame I/O inside
the async native filter. The follow-up moves the complete sealed input
construction and rewind into `tokio::task::spawn_blocking`, then awaits the
prepared descriptor before spawning the native filter. The native execution
timeout remains five seconds. The separate sibling regression
`native_filter_input_is_rewound_and_immutable_after_blocking_preparation`
reads the actual sealed descriptor from offset zero, preserves embedded NUL
and non-UTF-8 bytes, and requires write or flush to refuse mutation.

[The formatter receipt](async-frame-format.json) binds both exact files to
actual Rust 1.95 format and format-check exits of zero on Mac. The earlier
[formatter path failure](async-frame-format-initial-failure.json) is retained;
that attempt never started rustfmt. No Linux behavior or Rust compilation
result is inferred from formatting. The new sealed-descriptor regression must
run in the next full Linux CI matrix. The live `6815ec9a911d6accd593e580c5ee18ffb13452f7`
matrix completed before that follow-up was published. Its three complete
compressed logs and terminal job records are retained in [ci-6815](ci-6815/receipt.json).

## Completed CI for the five earlier review fixes

The exact `6815ec9a911d6accd593e580c5ee18ffb13452f7` source and prospective
merge passed all three actual Rust lanes. Each ran 2,656 all-features tests
and 2,614 no-default-features tests successfully, retaining 44 and 32 existing
skips. The five added HTTP, decoder, capture and executable-custody Rust tests
actually passed. Both Repository Hygiene jobs and the HIA helper contract job
also passed. All selected release, JavaScript lifecycle, syscall-denial and ZIP
checks completed successfully. The last exact-head job ended at
`2026-11-27T08:23:08Z`.

The unchanged old common workflow still failed its catalog-equality admission
against the old hosted Hepta candidate; that failure is retained and is not
counted as a pass. The native replacement workflow remains separate. This CI
receipt qualifies only `6815ec9` and its observed prospective merge, not the
later `spawn_blocking` fix or whole-native integration.

Reassembling the existing REA projection produces identical bytes for this
change: these two files do not alter its registered source records. The
mapping check passes with all 229 operations still OPEN and zero qualified;
raw reference authenticity is not reverified.

The implementation commit is `959c680f4280f42f48d34d26c921c0f7146b1bb0`, directly after the previously tested candidate `0ce79ce0e47225073fdc5394651df942eb6b98b1`. Its tree is `a0f762ee2b73721b6e9c0cbc05ef6d771fb932da`. This receipt fixes five review findings without changing the candidate's whole-native qualification status.

## Changes and boundaries

| Review finding | Change | Targeted evidence |
| --- | --- | --- |
| HTTP tools lacked native wire admission | Capture the authenticated POST body and pass its original bytes, SDK tool parameters and SDK request ID through the existing native observer. Stdio continues to use its original admission extension. | A real HTTP socket test covers successful passage to ordinary routing and tool, ID and argument mismatches. It awaits the next Linux CI run. Its fixed descriptor ELF isolates transport binding and does not qualify the HIA parser. |
| Symlinked venv interpreters were refused | Follow the selected executable entry, pin a safe regular ELF inode, compare the entry and target identities before and after reading, and seal the bytes. Preserve the original executable path as `argv[0]` and the original entry FD. | The exact embedded fixture executed a sealed interpreter and verified `sys.executable`, venv `sys.prefix`, arguments and entry inode. Thirteen permission, type, size, retargeting and mutation controls were refused without starting a workload. |
| Inline controller tests | Move the existing controller test into its sibling test module. | Existing assertions are retained; formatting passes. |
| Missing source notices | Add the repository's copyright and Apache-2.0 notices to the affected modules. | Included in the same reviewed implementation tree. |
| Production frame unwraps | Decode native words through checked ranges and fallible conversions, including the lifecycle facts. | New decoder overflow/truncation and bounded HTTP capture controls await Linux CI. |

The selected native interpreter path still uses the existing Python bootstrap. This compatibility repair does not establish removal of hosted runtime code.

## Observed validation

`targeted-local.json` records the exact formatted source hashes, commands, inputs, return codes and complete stdout/stderr. The venv fixture and all 13 refusal controls passed on Linux with Python 3.13.5. They execute the original production helper bytes and the exact Python fixture embedded in the new Rust test module. The Rust wrappers themselves were not executed in this container.

The existing mapping check passed, strict parity remained refused with its expected exit code 3, and all 29 ledger integrity tests passed. `source-projection.json` records the two registered source records that changed: `jobs.rs` and `server.rs`. All 229 tool rows, behavior gates and other ledger fields are unchanged; zero tools are promoted to qualified. Raw reference authenticity was not reverified in this projection refresh.

`macos-validation.json` is the original Mac receipt. Rust 1.95 formatting and the subsequent formatting check passed. The first locked offline compilation check exited 101 because the `oxc_ecmascript` dependency was absent from the local cache. That failure and its log are retained. A subsequent check uses the same lockfile with dependency downloads enabled; `macos-online-observation.json` records its actual captured state when this receipt was prepared and does not claim a terminal compiler result.

The five new Rust tests must run in the existing Linux CI matrix before this implementation is accepted:

- `authenticated_http_hia_tools_admit_original_wire_and_reject_mismatches`
- `native_word_and_span_decoding_refuse_truncation_and_overflow`
- `http_capture_retains_original_bytes_and_refuses_overflow_or_reuse`
- `native_workload_symlinked_venv_preserves_original_argv_prefix_and_entry_inode`
- `native_workload_refuses_unsafe_targets_and_mid_read_retargeting`

## Retained baseline and remaining qualification

The first new Linux matrix at `42cc6717430a4a14b526d5a4eba35c3bd943f0fb` found a real compile error in the added HTTP fixture: the locked SHA-256 output type does not implement `LowerHex`. `ci-42cc-compile-failure.json` and the complete compressed job log retain the original prospective-merge failure. Intermediate `c967e48b267edcc99c702450354b2802f485e647` attempted `hex::encode`, but that crate was only a transitive dependency; its actual E0433 failure is retained in `ci-c967-compile-failure.json` and its complete log. The corrected fixture now formats each digest byte using the standard library and explicitly collects a `String`, matching the existing `hia_contract.rs` implementation. Its actual Rust 1.95 format and format-check results are in `fixture-standard-hex-format.json`. Neither failed job executed the new Rust tests; the next matrix must establish their result. No dependency is added and no production gate or assertion is removed.

The adjacent `hia-v26-platform-ci-20261127/ci-terminal-rust-candidate.json` and its three complete compressed job logs preserve the actual all-features and no-default-features success for the old `0ce79ce0e47225073fdc5394651df942eb6b98b1` candidate and its prospective merge. Those results do not qualify these new changes.

The separate unpublished native-common integration preparation is not included here. The exact native source F and bootstrap distribution D have since been independently admitted as artifacts, while their separate native cold and common integration outcomes remain unqualified by this receipt. No common-native PASS, production activation, removal of the old stack, or whole-native delivery is claimed here.
