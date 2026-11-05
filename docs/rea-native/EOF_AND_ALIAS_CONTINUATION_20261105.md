# Fixed REA 6.8.0 EOF and Electron alias continuation

Overall result remains **HOLD / NO_GO**. This candidate combines two bounded corrections on the sixpack base `57467bf38715853277e21b67a09865606464defa`. It does not promote any of the 229 original npm operations to full qualification.

## Source and original profiles

- EOF implementation: `fe5b43db5cd1ebead73cc11bbbbeeb65807d8ecc`; previous source/ledger freeze: `c5f6ff270e8352b1f1a73df60ec52773a297d972`.
- Combined implementation: `7eff96a5cc19c3ace590bb639342da5ca6174dc5`.
- Original npm `rea-agents@6.8.0` SHA256 `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`.
- Original Node 22.23.4 executable SHA256 `94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90`.
- Frozen Git source remains `93b8b82db70279e40f484114cff9dc1958dc14ee`: 234 static declarations, not a live Git-built catalog and not interchangeable with the 229 live npm tools.

## Corrections

The EOF reader change retains its existing UTF-8, descriptor, budget, hash, cancellation and large-file guards. It projects the pinned V8 diagnostic only for an otherwise grammatical unfinished small-file prefix after actual EOF and the independent value parser's EOF classification. The original 16-case regression now requires all 16 diagnostics; general JSON representation and non-EOF syntax gaps remain explicit. A separate independent public corpus contains 116 fixed inputs (89 EOF, 14 non-EOF invalid, 12 valid JSON and 1 valid Evidence bundle); its real public MCP comparison remains separately bound to the executed binary.

The Electron AST change resolves deferred lexical module/namespace aliases with a bounded monotone dependency queue, independent of declaration traversal order. Existing resolved values are retained. Both source and target mutations, shadowing, redeclarations and unseeded cycles are excluded. The fixed original window control yields one BrowserWindow and zero IPC, so this change does not newly propagate constructed BrowserWindow/WebContents instances.

The 13 inert CommonJS fixtures were actually run through the pinned original `analyze_javascript_application` tool and the previous frozen Rust worker. Four selected late-alias IPC controls originally differed; constructor and negative boundaries remain in the same denominator. Tests compare selected IPC fields and ASCII source spans plus window counts; they do not claim full graph, runtime Electron behavior, public schema, or REA Evidence equality. Original partial graph coverage remains preserved.

## Evidence at this source freeze

EOF focused run: 12 passed, 0 failed, 0 ignored, 2153 filtered out (development evidence only).

JS focused command and result:

```text
running 19 tests
test mcp::rea_javascript::rea_javascript_tests::actual_manifest_read_never_executes_script_and_rejects_stale_or_outside_input ... ok
test mcp::rea_javascript::rea_javascript_tests::dependency_and_script_collections_are_literal_and_paginated ... ok
test mcp::rea_javascript::rea_javascript_tests::electron_and_main_are_reported_as_declarations_without_runtime_claims ... ok
test mcp::rea_javascript::rea_javascript_tests::empty_exports_are_distinguished_from_an_absent_declaration ... ok
test mcp::rea_javascript::rea_javascript_tests::entries_retain_pointer_provenance_including_blocked_and_browser_false_values ... ok
test mcp::rea_javascript::rea_javascript_tests::malformed_duplicate_deep_and_oversized_declarations_fail_explicitly ... ok
test mcp::rea_javascript_graph::ast::alias_tests::original_alias_chains_shadowing_cycles_and_redeclarations_match ... ok
test mcp::rea_javascript_graph::ast::alias_tests::original_namespace_and_constructor_alias_boundaries_match ... ok
test mcp::rea_javascript_graph::ast::alias_tests::original_source_order_alias_and_mutation_controls_match ... ok
test mcp::rea_javascript_graph::tests::cancelled_request_is_rejected_before_runtime_or_source_admission ... ok
test mcp::rea_javascript_graph::tests::graph_continuation_rejects_identity_from_previous_analysis_semantics ... ok
test mcp::rea_javascript_graph::tests::imports_keep_multiple_selected_extension_candidates_without_loader_claim ... ok
test mcp::rea_javascript_graph::tests::invalid_ast_semantic_errors_utf16_surrogates_and_resource_excess_refuse ... ok
test mcp::rea_javascript_graph::tests::lexical_electron_calls_produce_only_role_compatible_candidate_edges ... ok
test mcp::rea_javascript_graph::tests::pagination_is_bound_to_every_selected_source_and_explicit_grammar ... ok
test mcp::rea_javascript_graph::tests::reassigned_bindings_fake_modules_and_shadowed_commonjs_exports_are_not_promoted ... ok
test mcp::rea_javascript_graph::tests::source_admission_rejects_outside_symlink_stale_hash_and_does_not_execute ... ok
test mcp::rea_javascript_graph::tests::type_only_dependencies_preserve_declaration_and_inline_specifier_scopes ... ok
test mcp::rea_javascript_graph::tests::typescript_jsx_type_only_imports_and_dynamic_expressions_are_ast_observations ... ok

test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 2149 filtered out; finished in 0.06s
```

The initial full-source wrapper failed before compilation because this new worktree inherited sparse checkout; 681 historical tracked files were absent. The worktree-specific sparse checkout was disabled and all 10,647 tracked files became present, with the same clean source commit. The first JS patch application also stopped before editing source because two new-file diff headers lacked `new file mode`; the corrected patch changes only packaging and preserves every implementation/fixture byte. Both original failures are retained in external task evidence. The subsequent focused compile failed with E0277 in the new test helper because the installed SHA-256 digest array does not implement LowerHex; a test-only std::fmt::Write conversion repaired that assumption without changing the production AST or original fixture. That compiler failure is also retained.

The original public MCP collector was independently checked with malformed/no-id and non-JSON numeric-tail controls. Older v3/v4 observations and failures remain available. Reviewed collector v5 is `a50826baf7d3fa6cc0634befff43fbb9faadff8574c2e99506068905fd2c6f99`; acceptance is limited to finite capture. No full cancellation, restart, cross-host or hostile-filesystem proof is inferred.

## Fixed format scope

Qualification follows the actual original contract. `inspect_model_artifact` inspects GGUF v2/v3 and Safetensors declarations, scoped/full hashes, metadata previews, tensor types/ranges and retained views. Unknown and historically ambiguous storage layouts remain unknown. The original contract does not inspect tensor payload or inference quality.

`inspect_apk_signature` observes declared v1/v2/v3/v3.1 signers, DER fingerprints, algorithm/digest declarations, SDK ranges, lineage and source stamp. The frozen original explicitly leaves authenticity, signature verification, lineage trust and v1 entry coverage unverified. These facts must not be silently upgraded by a separate native cryptographic facility. V4/full Android platform trust is not added as a required original-contract gate without independent original evidence.

`inspect_android_package` requires the original selected JADX/JDK profile for manifest, package/SDK/permission declarations, class/resource counts and static component projection; it does not execute the APK. `decode_android_resources` uses the selected apktool provider with no source recovery, owns and removes its temporary workspace, and retains the original locale/table/timeout boundaries.

## Remaining qualification

The complete source/build monitor, existing nine-stage matrix, independent build consumer, actual new-binary EOF and JS comparisons, and exploratory same-parsed-body cost probe are external evidence tied to the final frozen candidate. They are not marked passed in advance. Full schema/Evidence/float and representation closure, authentic persistence, concurrency negatives, all original formats/tools, real IDA/Hopper profiles, dynamic isolation, cross-host recovery and deployment remain open.

GitHub publication is separate: a retained same-repository publication attempt returned account-suspension HTTP 403. No alternate identity/transport is used; local source commits and evidence must not be described as already present in PR84.

## Superseding graph identity repair

The actual 3beb8a28 / 4bd93ab8 diagnostic worker repaired five selected alias/constructor projections, but retained the old graph profile v2. The old b80ff24a and repaired 4bd93ab8 workers returned the same graph SHA for changed rows. For after.js that captured identity is e1032f30477d34882a64d5d86f648c416742e663a1bad3853913667ab885888c. This violates the documented rule that analysis/collection semantics must advance the graph profile.

The production change advances only GRAPH_PROFILE to v3. Tests retain v1 refusal, add v2 refusal, and use that actual captured v2 identity at offsets 0 and 1 with a current-v3 positive control. Explicit external/type-erasure profile expectations and the capability scope are updated. The JSON EOF observer and lexical alias algorithm remain unchanged.

The owner deliberately cancelled its R2 full matrix before editing source: original job 1a1ac7d38f4-fc05-54b0, complete/durable cancelled terminal, exit -15; inner matrix exit 143, signal 15, build_bound false, no final binding. The before/after full tracked source snapshots agree and the worktree remained clean. This is a retained cancelled attempt, not a successful full matrix or a code-test failure.

The R2 finite captures remain historical, not promoted by a later binary: JSON/Evidence collected 116 cases with 89/89 EOF matches, 14 non-EOF diagnostic mismatches and one complete unpaired-surrogate representation mismatch (parsed 101/116; full unnormalized object 1/116; raw frame 0/116). The selected internal JS worker projection matched 13/13 with five repaired cases and zero observed regressions. Fresh captures and a new full matrix are required for this v3 candidate; no complete tool, full schema, external engine, isolation, performance or deployment qualification follows from these finite results.

Four source tests for actual npm Evidence, finite-number rendering, fractional Evidence and schema rejection require explicit ignored-test execution with pinned real inputs. An ordinary full matrix does not execute these acceptance gates. Their eventual results must be reported separately. Global HOLD/NO_GO and all 229 open tool rows remain unchanged.
