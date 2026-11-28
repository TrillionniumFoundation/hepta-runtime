# Runtime complete HIA migration: remaining source-bound behavior domains

Status: SOURCE INVENTORY AND INTEGRATION CANDIDATE. This is not execution qualification, deployment, or permission to delete the old implementation.

The full original target has 136 MCP handlers. The retained pure HIA runtime has a qualified 13-handler route scope. The other 123 handlers remain explicit pending business implementations. The imported current author contains 126 components; the earlier original 124-component qualification is retained at its exact original source and is not transferred to the added components.

## Exact inputs

- Current Rust behavior source: `ae1c7ea593da45f7299c692a2acd44605c35be09`.
- Imported native source: `c57a7fddfd9ed042b19e4d61f4f28603856340ea`.
- Source inventory physically captured 194 files (3713595 bytes), checked Git blob SHA-1 and mode, then reread every file unchanged.
- Original behavior methods listed in JSON are source indexes, not claimed executions.

## Independent implementation domains

| Domain | Unrouted handlers | Original test files | Prerequisites |
|---|---:|---:|---|
| agent_tools | 11 | 8 | final_Hepta_native_worker_store, public_native_process_owner, MCP_request_reply_protocol |
| file_bytes | 6 | 6 | immutable_host_configuration, descriptor_path_authority, typed_JSON, local_IO_owners |
| search | 4 | 5 | file_bytes, durable_requests, process_owner, regex_owners |
| process_owner | 9 | 31 | final_Hepta_native_job_bundle, immutable_host_configuration, descriptor_path_authority |
| durable_requests | 10 | 31 | request_context, caller_authority, record_crypto, atomic_storage, process_owner |
| stream_handoff | 6 | 6 | process_owner, durable_requests, host_transport |
| pty | 5 | 3 | host_transport, process_owner, platform_PTY_syscalls |
| host_control | 10 | 10 | immutable_host_configuration, host_transport, OS_inspection_syscalls, process_owner |
| documents | 9 | 6 | file_bytes, process_owner, format_engines |
| rea_evidence | 13 | 23 | file_bytes, durable_requests, rea_typed_wire |
| rea_formats | 10 | 20 | file_bytes, rea_evidence, bounded_parsers, explicit_signature_engines |
| rea_external_analysis | 10 | 21 | rea_evidence, process_owner, host_transport, explicit_external_engines |
| rea_model_sessions | 4 | 6 | rea_formats, durable_requests, process_owner, model_engine_boundary |
| weight_artifacts | 10 | 14 | file_bytes, durable_requests, exact_numeric_owners, admitted_custody |
| weight_workers | 6 | 12 | process_owner, durable_requests, model_engine_boundary, weight_artifacts |

The dependency labels record interface requirements, not permission to lower a gate. Process and durable requests can develop independently against exact typed contracts, then must pass the original joint lifecycle/recovery gates. File-byte/path authority is the smallest useful first product domain. Search, streaming, PTY, and host controls depend on the process/host boundary. REA and weights retain their original parser/numeric/source/engine contracts.

## agent_tools

Bind the same release, request, catalog, state and witness to the real HIA Worker; persist/reopen actual results without launching Python or Rust business handlers.

Handlers: `hia_describe`, `hia_artifact`, `hia_read`, `hia_context`, `hia_inspect`, `hia_candidate`, `hia_verify`, `hia_emit`, `hia_evaluate`, `hia_adopt`, `hia_rollback`.

Original complete module controls to retain:

- `src/mcp/hia_contract_tests.rs`.
- `src/mcp/hia_controller_native_jobs_tests.rs`.
- `src/mcp/hia_controller_release_tests.rs`.
- `src/mcp/hia_provider_tests.rs`.
- `src/mcp/hia_request_prepare_tests.rs`.
- `src/mcp/hia_wire_candidate_tests.rs`.
- `tests/hia_installed_public_jobs_integration.py`.
- `tests/hia_native_helper_mcp_integration.py`.

## file_bytes

Preserve complete parameter/error ordering, descriptor-relative no-follow custody, inode/version identity, limits, metadata and exact bytes; the local-only component profile does not substitute for configured-host routing.

Handlers: `read_multiple_files`, `file_info`, `binary_read`, `binary_write`, `binary_upload`, `binary_patch_inode`.

Original complete module controls to retain:

- `src/mcp/runtime/binary_observation_source_tests.rs`.
- `src/mcp/runtime/binary_tests.rs`.
- `src/mcp/runtime/multi_read_tests.rs`.
- `tests/binary_file_tests.py`.
- `tests/metadata_preservation_tests.py`.
- `tests/multi_read_tests.py`.

## search

Preserve actual asynchronous searches, cancellation, ordered result cursors, source effects and retained original-job identity.

Handlers: `search_start`, `search_results`, `search_list`, `search_stop`.

Original complete module controls to retain:

- `src/mcp/fs/search_tests.rs`.
- `src/mcp/runtime/search_jobs_tests.rs`.
- `tests/search_effects_native_acceptance.py`.
- `tests/search_six_host_acceptance.py`.
- `tests/search_worker_tests.py`.

## process_owner

Run original START/STATUS/read/wait/cancel/inventory and restart/unknown-outcome witnesses through the complete native owner; preserve terminal type and byte/offset exactness, no replay, original budgets and one-child provenance.

Handlers: `shell`, `shell_start`, `process_start`, `process_status`, `process_read`, `process_wait`, `process_cancel`, `process_list`, `process_list_page`.

Original complete module controls to retain:

- `src/mcp/fs/shell_tests.rs`.
- `src/mcp/runtime/jobs_cancel_io_tests.rs`.
- `src/mcp/runtime/jobs_inventory_cache_tests.rs`.
- `src/mcp/runtime/jobs_inventory_digest_tests.rs`.
- `src/mcp/runtime/jobs_inventory_pending_tests.rs`.
- `src/mcp/runtime/jobs_inventory_source_tests.rs`.
- `src/mcp/runtime/jobs_inventory_streaming_tests.rs`.
- `src/mcp/runtime/jobs_native_executable_tests.rs`.
- `src/mcp/runtime/jobs_native_profile_tests.rs`.
- `src/mcp/runtime/jobs_observe_request_tests.rs`.
- `src/mcp/runtime/jobs_output_durability_tests.rs`.
- `src/mcp/runtime/jobs_owner_metadata_tests.rs`.
- `src/mcp/runtime/jobs_owner_publication_tests.rs`.
- `src/mcp/runtime/jobs_pagination_tests.rs`.
- `src/mcp/runtime/jobs_pending_admission_tests.rs`.
- `src/mcp/runtime/jobs_record_comparison_tests.rs`.
- `src/mcp/runtime/jobs_registry_async_tests.rs`.
- `src/mcp/runtime/jobs_registry_coalescing_tests.rs`.
- `src/mcp/runtime/jobs_registry_content_tests.rs`.
- `src/mcp/runtime/jobs_registry_decode_tests.rs`.
- `src/mcp/runtime/jobs_registry_prefill_tests.rs`.
- `src/mcp/runtime/jobs_security_tests.rs`.
- `src/mcp/runtime/jobs_staging_durability_tests.rs`.
- `src/mcp/runtime/jobs_start_io_tests.rs`.
- `src/mcp/runtime/jobs_terminal_publication_tests.rs`.
- `src/mcp/runtime/jobs_tests.rs`.
- `src/mcp/runtime/native_jobs_tests.rs`.
- `tests/hia_installed_public_jobs_integration.py`.
- `tests/native_library_process_canary.py`.
- `tests/operator_job_identity_tests.py`.
- `tests/process_ops_tests.py`.

## durable_requests

Preserve encrypted/request records, original leases, indexes, retained history/archive, recovery, cancellation, incomplete states and exact request identity across restart.

Handlers: `request_archive`, `request_history`, `request_status`, `request_result`, `request_start`, `request_cancel`, `operation_start`, `operation_status`, `operation_result`, `operation_cancel`.

Original complete module controls to retain:

- `src/mcp/runtime/operation_async_tests.rs`.
- `src/mcp/runtime/operation_crypto_tests.rs`.
- `src/mcp/runtime/request_archive_batch_tests.rs`.
- `src/mcp/runtime/request_archive_codec_tests.rs`.
- `src/mcp/runtime/request_archive_cold_tests.rs`.
- `src/mcp/runtime/request_archive_content_parallel_tests.rs`.
- `src/mcp/runtime/request_archive_content_tests.rs`.
- `src/mcp/runtime/request_archive_directory_tests.rs`.
- `src/mcp/runtime/request_archive_index_tests.rs`.
- `src/mcp/runtime/request_archive_memory_tests.rs`.
- `src/mcp/runtime/request_archive_owned_tests.rs`.
- `src/mcp/runtime/request_archive_page_batch_tests.rs`.
- `src/mcp/runtime/request_archive_parallel_tests.rs`.
- `src/mcp/runtime/request_archive_runs_tests.rs`.
- `src/mcp/runtime/request_archive_seal_tests.rs`.
- `src/mcp/runtime/request_archive_store_tests.rs`.
- `src/mcp/runtime/request_async_tests.rs`.
- `src/mcp/runtime/request_audit_batch_tests.rs`.
- `src/mcp/runtime/request_audit_lookup_tests.rs`.
- `src/mcp/runtime/request_audit_query_tests.rs`.
- `src/mcp/runtime/request_audit_stage_tests.rs`.
- `src/mcp/runtime/request_audit_sync_tests.rs`.
- `src/mcp/runtime/request_audit_tests.rs`.
- `src/mcp/runtime/request_metadata_trace_tests.rs`.
- `src/mcp/runtime/request_results_growth_tests.rs`.
- `src/mcp/runtime/request_results_policy_tests.rs`.
- `src/mcp/runtime/request_results_read_workers_tests.rs`.
- `src/mcp/runtime/request_results_tests.rs`.
- `src/mcp/runtime/request_usage_batch_tests.rs`.
- `src/mcp/runtime/request_usage_projection_tests.rs`.
- `tests/dc_functional_v9_request_async_real_ssh_six_host_acceptance.py`.

## stream_handoff

Preserve actual broker ownership, exact stream cursors and EOF, authenticated handoff, restart and no-restart continuation, cancellation and one-owner publication.

Handlers: `stream_handoff_prepare`, `stream_handoff_status`, `stream_handoff_read`, `stream_handoff_write`, `stream_handoff_close`, `stream_handoff_list`.

Original complete module controls to retain:

- `src/mcp/runtime/stream_tests.rs`.
- `tests/stream_broker_tests.py`.
- `tests/stream_handoff_acceptance.py`.
- `tests/stream_handoff_tests.py`.
- `tests/stream_history_tests.py`.
- `tests/stream_native_acceptance.py`.

## pty

Preserve real controlling terminal, dimensions, binary writes, retained output archive, exact PID/boot identity, controller-loss reconnect and original process-group cleanup.

Handlers: `pty_start`, `pty_read`, `pty_write`, `pty_close`, `pty_list`.

Original complete module controls to retain:

- `src/mcp/runtime/pty_operator_tests.rs`.
- `src/mcp/runtime/pty_tests.rs`.
- `tests/terminal_host_tests.py`.

## host_control

Preserve configured aliases and real machine/platform facts, allowlists and privilege scope, exact process/boot identity, separate stopped checkpoint restore/resume and bounded accounting. Never report a configured flag as an executed fact.

Handlers: `host_processes`, `host_signal`, `sudo_start`, `host_health`, `process_checkpoint`, `service_status`, `privileged_action`, `hardware_snapshot`, `network_inspect`, `usage_stats`.

Original complete module controls to retain:

- `src/mcp/runtime/config_identity_tests.rs`.
- `src/mcp/runtime/config_tests.rs`.
- `src/mcp/runtime/inspect_security_tests.rs`.
- `src/mcp/runtime/inspect_tests.rs`.
- `src/mcp/runtime/inspection_result_tests.rs`.
- `src/mcp/runtime/request_usage_batch_tests.rs`.
- `src/mcp/runtime/request_usage_projection_tests.rs`.
- `tests/checkpoint_lifecycle_tests.py`.
- `tests/native_checkpoint_acceptance.py`.
- `tests/operator_acceptance.py`.

## documents

Preserve original document/PDF/image/worksheet behavior, security and metadata; each external engine is recorded explicitly and old Python business code remains a porting obligation.

Handlers: `document_read`, `image_read`, `document_write`, `document_edit`, `pdf_edit`, `worksheet_edit`, `document_render`, `worksheet_recalculate`, `pdf_security`.

Original complete module controls to retain:

- `src/mcp/runtime/documents_tests.rs`.
- `tests/complex_worksheet_tests.py`.
- `tests/document_extended_tests.py`.
- `tests/document_local_tests.py`.
- `tests/document_mcp_acceptance.py`.
- `tests/metadata_preservation_tests.py`.

## rea_evidence

Preserve full evidence bytes/modes, immutable source identities, descriptor-based snapshots, source-map bounds, same-session restore and all original 229 ledger scopes without elevating a source mapping to behavior parity.

Handlers: `rea_inspect_analysis_view`, `rea_import_evidence_bundle`, `rea_export_evidence_bundle`, `rea_get_evidence_bundle`, `rea_read_evidence_bundle`, `rea_close_evidence_snapshot`, `rea_inspect_source_map`, `rea_evidence_session_checkpoint`, `rea_evidence_session_resume`, `rea_evidence_session_list`, `rea_verify_evidence`, `rea_retain_preview`, `rea_read_preview`.

Original complete module controls to retain:

- `src/mcp/rea_analysis_view_mcp_input_tests.rs`.
- `src/mcp/rea_analysis_view_tests.rs`.
- `src/mcp/rea_evidence_checkpoint_order_tests.rs`.
- `src/mcp/rea_evidence_checkpoint_tests.rs`.
- `src/mcp/rea_evidence_creation_tests.rs`.
- `src/mcp/rea_evidence_export_tests.rs`.
- `src/mcp/rea_evidence_file_tests.rs`.
- `src/mcp/rea_evidence_import_tests.rs`.
- `src/mcp/rea_evidence_readback_tests.rs`.
- `src/mcp/rea_evidence_root_string_tests.rs`.
- `src/mcp/rea_evidence_session_tests.rs`.
- `src/mcp/rea_evidence_source_length_tests.rs`.
- `src/mcp/rea_evidence_source_process_tests.rs`.
- `src/mcp/rea_evidence_source_tests.rs`.
- `src/mcp/rea_evidence_tests.rs`.
- `src/mcp/rea_source_map_content_tests.rs`.
- `src/mcp/rea_source_map_tests.rs`.
- `src/mcp/rea_store_tests.rs`.
- `tests/rea_compatibility_ledger_tests.py`.
- `tests/rea_evidence_checkpoint_http.py`.
- `tests/rea_evidence_checkpoint_upgrade_tests.py`.
- `tests/rea_evidence_import_qualification_tests.py`.
- `tests/rea_multihost_recovery_tests.py`.

## rea_formats

Preserve complete format/parser controls, exact integer/extent checks, typed errors and signature evidence; keep external trust and parser authority boundaries explicit.

Handlers: `rea_inspect_artifact`, `rea_inspect_model`, `rea_read_model`, `rea_inspect_application`, `rea_inspect_archive`, `rea_inspect_asar`, `rea_read_asar_member`, `rea_inspect_elf_notes`, `rea_inspect_apk_signature_evidence`, `rea_inspect_apk_signature`.

Original complete module controls to retain:

- `src/mcp/rea_apk_evidence_tests.rs`.
- `src/mcp/rea_apk_mcp_input_tests.rs`.
- `src/mcp/rea_apk_signature_observation_tests.rs`.
- `src/mcp/rea_apk_signature_tests.rs`.
- `src/mcp/rea_apk_signature_view_tests.rs`.
- `src/mcp/rea_apk_static_worker_tests.rs`.
- `src/mcp/rea_application_tests.rs`.
- `src/mcp/rea_artifact_zip_parser_tests.rs`.
- `src/mcp/rea_artifact_zip_tests.rs`.
- `src/mcp/rea_asar_parser_tests.rs`.
- `src/mcp/rea_asar_tests.rs`.
- `src/mcp/rea_elf_notes_parser_tests.rs`.
- `src/mcp/rea_elf_notes_tests.rs`.
- `src/mcp/rea_elf_notes_worker_tests.rs`.
- `src/mcp/rea_model_parser_tests.rs`.
- `src/mcp/rea_model_session_tests.rs`.
- `src/mcp/rea_model_tests.rs`.
- `tests/rea_apk_signature_mcp.py`.
- `tests/rea_asar_qualification.py`.
- `tests/rea_compatibility_ledger_tests.py`.

## rea_external_analysis

Preserve original real engine invocations, cancellation, deadlines, retained raw outputs, profile pins and exact typed evidence; no Rust/Python orchestration fallback may masquerade as HIA.

Handlers: `rea_inspect_web_capture`, `rea_compare_web_captures`, `rea_replay_web_entry`, `rea_inspect_javascript_package`, `rea_inspect_javascript_graph`, `rea_static_profiles`, `rea_static_start`, `rea_static_status`, `rea_static_read`, `rea_static_cancel`.

Original complete module controls to retain:

- `src/mcp/rea_browser_process_tests.rs`.
- `src/mcp/rea_browser_tests.rs`.
- `src/mcp/rea_engine_ghidra_tests.rs`.
- `src/mcp/rea_engine_profile_tests.rs`.
- `src/mcp/rea_engine_scratch_tests.rs`.
- `src/mcp/rea_engine_tests.rs`.
- `src/mcp/rea_engine_usage_tests.rs`.
- `src/mcp/rea_ghidra_contract_tests.rs`.
- `src/mcp/rea_ghidra_contract_v4_tests.rs`.
- `src/mcp/rea_ghidra_instructions_tests.rs`.
- `src/mcp/rea_javascript_alias_tests.rs`.
- `src/mcp/rea_javascript_graph_tests.rs`.
- `src/mcp/rea_javascript_tests.rs`.
- `src/mcp/rea_static_summary_tests.rs`.
- `src/mcp/rea_static_tests.rs`.
- `src/mcp/rea_web_tests.rs`.
- `tests/rea_browser_external.py`.
- `tests/rea_browser_native_differential.py`.
- `tests/rea_compatibility_ledger_tests.py`.
- `tests/rea_ghidra_analysis_external.py`.
- `tests/rea_lifecycle_qualification_tests.py`.

## rea_model_sessions

Preserve resident-model session identity, exact query/read bounds, lifecycle, typed model outputs and actual restoration.

Handlers: `rea_model_session_list`, `rea_model_session_open`, `rea_model_session_query`, `rea_model_session_read`.

Original complete module controls to retain:

- `src/mcp/rea_model_session_tests.rs`.
- `src/mcp/rea_worker_tests.rs`.
- `src/mcp/rea_worker_transport_tests.rs`.
- `tests/rea_compatibility_ledger_tests.py`.
- `tests/rea_lifecycle_parallel_tests.py`.
- `tests/rea_model_session_http.py`.

## weight_artifacts

Preserve original full tensor/format arithmetic, exact patch and restore, cohort transactions, continuation/proof scopes and independent actual original comparisons; do not turn research-only WSP outputs into production eligibility.

Handlers: `weight_artifact_patch`, `weight_artifact_restore`, `weight_cohort_patch`, `weight_cohort_restore`, `weight_linear_forward`, `weight_linear_ridge_plan`, `weight_continuation_certificate`, `weight_semantic_replay`, `weight_semantic_certificate`, `weight_guarded_linear_patch`.

Original complete module controls to retain:

- `src/mcp/weight_artifact_cohort_tests.rs`.
- `src/mcp/weight_artifact_tests.rs`.
- `src/mcp/weight_certificate_tests.rs`.
- `src/mcp/weight_forward_tests.rs`.
- `src/mcp/weight_guard_journal_tests.rs`.
- `src/mcp/weight_guard_tests.rs`.
- `src/mcp/weight_ridge_tests.rs`.
- `src/mcp/weight_semantic/lib.rs`.
- `src/mcp/weight_semantic/lib_tests.rs`.
- `src/mcp/weight_semantic_certificate_tests.rs`.
- `src/mcp/weight_semantic_tests.rs`.
- `src/mcp/weight_tensor_tests.rs`.
- `src/mcp/weight_tests.rs`.
- `tests/weight_forward_external.rs`.

## weight_workers

Preserve actual model worker protocol, profile/source pins, resident state, bounded outputs and independent engine effects; replacing its Python coordinator remains required.

Handlers: `weight_profiles`, `weight_open`, `weight_call`, `weight_status`, `weight_read`, `weight_close`.

Original complete module controls to retain:

- `src/mcp/weight_tests.rs`.
- `tests/weight_mcp_external.rs`.
- `workers/weight/tests/test_analysis_workflow.py`.
- `workers/weight/tests/test_artifacts.py`.
- `workers/weight/tests/test_current100k_provider.py`.
- `workers/weight/tests/test_laya_adapter.py`.
- `workers/weight/tests/test_laya_encoding.py`.
- `workers/weight/tests/test_mechanism.py`.
- `workers/weight/tests/test_patches.py`.
- `workers/weight/tests/test_qualify_current100k.py`.
- `workers/weight/tests/test_session.py`.
- `workers/weight/tests/test_transport.py`.

## Shared acceptance

- Actual same-endpoint MCP negotiation/catalog/error order, complete typed request/reply and caller authority.
- Original reference binaries and input rows remain immutable; current native executions have their own full raw receipts.
- Full Runtime nextest in both feature configurations with one test thread and zero retries; full native original partition/caller gates.
- Final matching Hepta cold/release/install/identical installed rebuild; original public19 and default03 Worker gate are distinct.
- Real trace proves no Python/Rust business execution on admitted HIA routes; external system/engine ABI boundaries explicitly classified.
- Original configured-host and platform behavior must be qualified; Linux-only components do not replace macOS/Windows or cross-host behavior.
- Only after all routes, persistence/restart, active-job drain/reconcile and same-endpoint cutover pass may old runtime files/branches retire.

All original argument validation, error identity, output framing, deadlines, effect ordering, identity/lease/cancellation/witness rules, and persistent recovery behavior must remain. External engine ABI and host compatibility must be labeled explicitly. Standalone native proof requires the actual final process trace; a Rust controller with an HIA worker is not a full runtime rewrite.

Actual service state at the read-only inventory still uses the existing Mac Runtime controller and a Python Worker configuration. No active service has been switched. The exact same endpoints, real persistence, original task behavior, and recovery must be validated on the final native candidate before cutover or removal. All original branches and failed artifacts remain in Git history; only actually integrated ancestors are candidates for later branch cleanup.

