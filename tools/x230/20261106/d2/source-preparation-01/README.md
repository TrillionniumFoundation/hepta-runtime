# D2 validation-cost diagnostic source preparation

D2 divides the validation CPU identified by the completed D1 offline interpretation. It is a diagnostic source revision; it does not reduce validation, adopt a runtime candidate, or claim a performance improvement.

## Source and provenance

The parent is D1 documentary commit `8eb1a0af7a85768e374717d24848fd9798871cc9`. Both edited files were fetched at that exact commit and their complete SHA-256 values equal the actual D1 qualified 222-input map `98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133`. Accepted production behavior remains R24. The complete before/after maps have the same 222 keys; only `phase_cost.rs` and `ssh_observation_profile.rs` differ. No Cargo, test, embedded Python, pool, jobs, validation-worker or cleanup implementation changes.

The profile edit adds six synchronous guard sites, with two possible labels at the read-loop site. All nine added cfg statements can be removed independently to recover the original profile source byte for byte. The loop-label condition is inside a diagnostic-feature/Linux cfg statement, so ordinary builds do not evaluate it. The original `!Send` RAII span owns no validation permit, descriptor, request, subprocess or cleanup action. Original `?`, short-circuit and `check_current` order is unchanged.

## What the seven labels mean

| Label | Scope |
|---|---|
| `file_checked` | Original initial `checked_file`, including path walk, open, metadata and capability checks. |
| `file_read_reference` | Entire original read loop using the existing byte reference, including its cancellation/deadline checks and comparisons. |
| `file_read_hash` | The same whole loop using `hash.update`, including its checks. |
| `file_final_check` | Original `verify_read`, including final descriptor and reopened-path metadata. |
| `file_identity` | Existing `verify_identity` boundary method. |
| `shell_resolution` | Existing `verify_resolution` method and comparison of fixed shell components. |
| `profile_policy` | Existing policy, private-directory and agent-environment checks. |

The read labels combine I/O, checks and content processing. They do not isolate pure syscall time or pure comparison/hash time. Final `content_matches` and `hash.finish` remain in their original parent exclusive residual. No per-chunk, per-component or sampled spans are introduced. Parent inclusive CPU and immediate-child exclusive subtraction retain their original interpretation.

## Bounded capture and diagnostic perturbation

The event capacity changes from 32,768 to 131,072. Request capacity remains 2,048; output remains bounded at 32 MiB per controller. Drops, incomplete windows and output-limit errors remain failures with their original partial evidence. The bound is not raised or silently truncated at runtime.

D1 actually had 73 events per request, 72 full-file validations, 36 boundary identity checks, 18 shell checks and 18 policy checks. Under the same successful path, D2 adds 288 events per request: 361 total, or 80,142 for a first controller's 222 requests. This is capacity planning, not a universal bound on arbitrary executions. The conservative JSON-width calculation is recorded in `diagnostic-plan.json`: existing D1 phase counts, full integer widths, maximum original detail width, longest new read label, and 64 KiB reserves for each header/footer produce **31,223,726 bytes**, below the unchanged 33,554,432-byte output cap. Different runtime paths can still exceed a cap and must fail closed.

The actual D1 header reports 136 bytes per event slot and 184 per request slot. If the unchanged record shape retains those sizes after adding enum labels, D2's slot arrays total 18,202,624 bytes, an increase of 13,369,344 bytes (12.75 MiB). Both OFF and ON modes preallocate the same arrays. This is diagnostic memory overhead, not an RSS optimization. Actual D2 `size_of` remains unknown until a real build/run and is reported by the unchanged header fields.

The original D1 parser is preserved. The separate D2 parser changes only its three capacity literals and diagnostic preparation revision. AST parsing in this preparation did not import or execute it.

## Qualification and future measurement

The original eight qualification stages, 19 harness tools, jobs=2 and 3 GiB disk floor remain required. Future counts, final formatter map and job identity are null. These source files have not been formatted, compiled, tested or run.

A future diagnostic uses the same D2 feature ELF in OFF/ON order. D1's original parent/adapter failure remains a failure; its separately successful offline interpretation is evidence for choosing these labels, not adoption evidence. D2 driver/correlation packaging and all host execution remain separate work.

## Candidate package

`package-manifest.json` selects seven payloads plus itself: input, patch, complete before/after maps, the two source files and the D2 parser. References, edit ledger, static checker and this plan remain source-preparation evidence outside that minimal runtime candidate package. The parser is not a compile input and is not executed by the qualifier.
