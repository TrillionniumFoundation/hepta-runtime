"""Build and test the declared HIA runtime profile from pinned source bytes.

NATIVE_COMPONENTS_PASS records the fresh full compiler cold gate, native tests
and their retained Python comparisons. Aggregate PASS also requires all declared
independent Rust comparisons. Neither phase qualifies the remaining 125
production tool owners, production adoption, or removal of the old runtime.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_hia_native_inventory import ORIGINAL_RUNTIME_BLOBS, inspect
from hia_native_build import NativeBuild, HEPTA_COMMIT, HEPTA_TREE, check_dependency, json_bytes
from hia_native_cold import validate_cold_evidence
from hia_native_entropy_qualification import (CORPUS_FILES as ENTROPY_CORPUS_FILES,
                                             FOLDER as ENTROPY_FOLDER,
                                             capture_entropy_corpus,
                                             entropy_evidence as checked_entropy_evidence)
from hia_native_scope_qualification import (CORPUS_FILES as SCOPE_CORPUS_FILES,
                                           FOLDER as SCOPE_FOLDER, scope_evidence as checked_scope_evidence)
from hia_native_editable_qualification import (CORPUS_FILES as EDITABLE_CORPUS_FILES,
                                              FOLDER as EDITABLE_FOLDER, editable_evidence as checked_editable_evidence)
from hia_native_line_verify_qualification import (CORPUS_FILES as LINE_VERIFY_CORPUS_FILES,
                                                 FOLDER as LINE_VERIFY_FOLDER,
                                                 line_verify_evidence as checked_line_verify_evidence)
from hia_native_view_qualification import (CORPUS_FILES as VIEW_CORPUS_FILES,
                                          FOLDER as VIEW_FOLDER, view_evidence as checked_view_evidence)
from hia_native_view_growth_qualification import (FOLDER as VIEW_GROWTH_FOLDER,
                                                 native_evidence as checked_view_growth_evidence)
from hia_native_view_resource_qualification import native_evidence as checked_view_resource_evidence
from hia_native_view_cache_qualification import (FOLDER as CACHE_FOLDER,
                                                qualification_evidence as checked_view_cache_evidence)
from hia_native_scope_os_qualification import (FOLDER as SCOPE_OS_FOLDER, SUITES as SCOPE_OS_SUITES,
                                              exact_profile as scope_os_profile,
                                              write_corpus as capture_scope_os_corpus,
                                              native_evidence as checked_scope_os_evidence)
from hia_native_authority_qualification import (FOLDER as AUTHORITY_FOLDER, SUITES as AUTHORITY_SUITES,
                                               evidence as checked_authority_evidence)
from hia_native_batch_plan_qualification import (FOLDER as BATCH_PLAN_FOLDER,
                                                batch_plan_evidence as checked_batch_plan_evidence)

import hia_native_batch_apply_qualification as batch_apply_qualification
import hia_native_batch_write_pipeline as batch_write_pipeline
import hia_native_atomic_write_qualification as atomic_write_qualification
import hia_native_filesystem_parity_qualification as filesystem_parity_qualification
from hia_native_history_qualification import (FOLDER as HISTORY_FOLDER,
                                              qualification_evidence as checked_history_evidence)

from hia_native_json_qualification import (COMPONENTS as JSON_COMPONENTS, TRANSPORT_REPORT as JSON_TRANSPORT_REPORT,
                                           qualification_evidence as checked_json_evidence)
from hia_native_request_context_qualification import qualification_evidence as checked_request_context_evidence
from hia_native_result_publication_qualification import qualification_evidence as checked_result_publication_evidence
from hia_native_request_scope_qualification import qualification_evidence as checked_request_scope_evidence
import hia_native_execution_qualification as execution_qualification
import hia_native_effect_fence_qualification as effect_fence_qualification
import hia_native_config_qualification as config_qualification
import hia_native_session_qualification as session_qualification
import hia_native_file_lock_pipeline as file_lock_pipeline
import hia_native_shell_qualification as shell_qualification
import hia_native_shell_capture_gate as capture_gate
import hia_native_bellman_qualification as bellman_qualification
import hia_native_bellman_commitment_qualification as bellman_commitment_qualification
import hia_native_local_create_pipeline as local_create_qualification
import hia_native_local_create_spec_qualification as local_create_spec_qualification
import hia_native_text_editor_params_qualification as text_editor_params_qualification
import hia_native_connection_qualification as connection_qualification
import hia_native_public_registry_qualification as public_registry_qualification
import hia_native_result_qualification as result_qualification
import hia_native_serde_error_pipeline as serde_error_pipeline
import hia_native_result_storage_pipeline as storage_pipeline
import hia_native_service_pipeline as service_pipeline
import hia_native_write_chain_pipeline as write_chain_pipeline

# Every native owner needs an executable qualification entry. Transport tests
# cover the two packers that NativeBuild compiles internally.
MODULES = (
    local_create_qualification.MODULE,
    local_create_spec_qualification.MODULE,
    text_editor_params_qualification.MODULE,
    *bellman_qualification.MODULES,
    bellman_commitment_qualification.MODULE,
    {"key": "request_storage_json", "name": "request-storage-json", "source": "native/request_storage_json.hepta",
     "builder": "result_storage", "manifest_env": "HIA_RESULT_STORAGE_BUILD", "test": "test_result_storage_json.py"},
    {"key": "request_record_validation", "name": "request-record-validation", "source": "native/request_record_validation.hepta",
     "builder": "result_storage", "manifest_env": "HIA_RESULT_STORAGE_BUILD", "test": "test_result_record_validation.py"},
    {"key": "request_safe_dto", "name": "request-safe-dto", "source": "native/request_safe_dto.hepta",
     "builder": "result_storage", "manifest_env": "HIA_RESULT_STORAGE_BUILD", "test": "test_result_safe_dto.py",
     "companion_sources": ("native/config_result_owner.hepta", "native/config_result_packer.hepta")},
    {"key": "request_retention", "name": "request-retention", "source": "native/request_retention.hepta",
     "builder": "result_storage", "manifest_env": "HIA_RESULT_STORAGE_BUILD", "test": "test_result_retention.py"},
    {"key": "request_record_io", "name": "request-record-io", "source": "native/request_record_io.hepta",
     "builder": "result_storage", "manifest_env": "HIA_RESULT_STORAGE_BUILD", "test": "result-storage-record-io",
     "additional_tests": ("result-storage-record-io-faults",),
     "companion_sources": ("native/request_record_io_packer.hepta",)},
    {"key": "request_store_directory", "name": "request-store-directory", "source": "native/request_store_directory.hepta",
     "builder": "result_storage", "manifest_env": "HIA_RESULT_STORAGE_BUILD", "test": "result-storage-directory",
     "companion_sources": ("native/request_store_directory_packer.hepta",)},
    {"key": "request_archive_metadata", "name": "request-archive-metadata", "source": "native/request_archive_metadata.hepta",
     "builder": "result_storage", "manifest_env": "HIA_RESULT_STORAGE_BUILD", "test": "result-storage-archive-metadata",
     "additional_tests": ("result-storage-archive-metadata-faults",),
     "companion_sources": ("native/request_archive_metadata_packer.hepta",)},
    {"key": "request_archive_publish", "name": "request-archive-publish", "source": "native/request_archive_publish.hepta",
     "builder": "result_storage", "manifest_env": "HIA_RESULT_STORAGE_BUILD", "test": "result-storage-archive-publish",
     "additional_tests": ("result-storage-archive-publish-faults",),
     "companion_sources": ("native/request_archive_publish_packer.hepta",)},
    {"key": "request_archive_store", "name": "request-archive-store", "source": "native/request_archive_store.hepta",
     "builder": "result_storage", "manifest_env": "HIA_RESULT_STORAGE_BUILD", "test": "result-storage-archive-store",
     "additional_tests": ("result-storage-archive-store-faults",),
     "companion_sources": ("native/request_archive_store_packer.hepta",)},
    {"key": "serde_error", "name": "serde-error", "source": "native/serde_error.hepta",
     "standalone": "filter", "buffer_profile": "serde-json.v1",
     "manifest_env": "HIA_SERDE_ERROR_MANIFEST", "test": "test_serde_error.py",
     "additional_tests": ("test_serde_error_resources.py", "test_serde_error_evidence.py")},
    {"key": "batch_write", "name": "batch-write", "source": "native/batch_write.hepta",
     "builder": "batch_write", "manifest_env": "HIA_BATCH_WRITE_BUNDLE",
     "test": "test_batch_write_controller.py",
     "additional_tests": ("test_batch_render.py", "test_utf8_probe.py", "test_batch_write_files.py",
                          "test_batch_write_kernel.py", "test_batch_write_concurrency.py",
                          "test_batch_write_wide.py", "test_batch_write_evidence.py"),
     "companion_sources": ("native/batch_render.hepta", "native/batch_write_packer.hepta")},
    {"key": "binary32_json", "name": "binary32-json", "source": "native/binary32_json.hepta",
     "builder": "result_values", "manifest_env": "HIA_RESULT_BUILD", "test": "test_binary32_json.py"},
    {"key": "typed_result_json", "name": "typed-result-json", "source": "native/typed_result_json.hepta",
     "builder": "result_values", "manifest_env": "HIA_RESULT_BUILD", "test": "test_typed_result_json.py"},
    {"key": "request_result", "name": "request-result", "source": "native/request_result.hepta",
     "builder": "result_values", "manifest_env": "HIA_RESULT_BUILD", "test": "test_request_result.py",
     "additional_tests": ("test_result_value_evidence.py",)},
    {"key": "runtime_bytes", "name": "runtime-bytes", "source": "native/runtime_bytes.hepta",
     "standalone": "filter", "manifest_env": "HIA_BYTES_MANIFEST", "test": "test_runtime_bytes.py"},
    {"key": "runtime_protocol", "name": "runtime-protocol", "source": "native/runtime_protocol.hepta",
     "standalone": "stdio", "manifest_env": "HIA_PROTOCOL_MANIFEST", "test": "test_runtime_protocol.py"},
    {"key": "text_budget", "name": "text-budget", "source": "native/text_budget.hepta",
     "standalone": "filter", "manifest_env": "HIA_TEXT_MANIFEST", "test": "test_text_budget.py"},
    {"key": "terminal_clean", "name": "terminal-clean", "source": "native/terminal_clean.hepta",
     "standalone": "filter", "manifest_env": "HIA_TERMINAL_MANIFEST", "test": "test_shell_native.py"},
    {"key": "shell_gate", "name": "shell-gate", "source": "native/shell_gate.hepta",
     "standalone": "filter", "manifest_env": "HIA_SHELL_GATE_MANIFEST", "test": "test_shell_gate_native.py",
     "additional_tests": ("test_shell_evidence.py",)},
    {"key": "shell_process", "name": "shell-process", "source": "native/shell_process.hepta",
     "builder": "shell_process", "manifest_env": "HIA_SHELL_PROCESS_MANIFEST",
     "test": "shell_process_state.py",
     "additional_tests": ("shell_process_transport.py", "hia_native_shell_process_qualification.py",
                          "shell_process_evidence_controls.py"),
     "companion_sources": ("native/shell_process_packer.hepta",)},
    {"key": "shell_background_text", "name": "shell-background-text",
     "source": "native/shell_background_text.hepta", "standalone": None,
     "manifest_env": "HIA_SHELL_BACKGROUND_TEXT_MANIFEST", "test": "shell_background_text.py"},
    {"key": "shell_outcome", "name": "shell-outcome", "source": "native/shell_outcome.hepta",
     "builder": "shell_outcome", "manifest_env": "HIA_SHELL_OUTCOME_MANIFEST",
     "test": "shell_outcome_state.py"},
    {"key": "shell_output_io", "name": "shell-output", "source": "native/shell_output_io.hepta",
     "builder": "shell_output", "manifest_env": "HIA_SHELL_OUTPUT_MANIFEST",
     "test": "shell_output_io.py", "companion_sources": ("native/shell_output_packer.hepta",)},
    {"key": "shell_foreground", "name": "shell-foreground", "source": "native/shell_foreground_controller.hepta",
     "builder": "shell_foreground", "manifest_env": "HIA_SHELL_FOREGROUND_MANIFEST",
     "test": "shell_foreground_controller.py", "additional_tests": ("shell_foreground_io.py",),
     "companion_sources": ("native/shell_foreground_packer.hepta",)},
    *capture_gate.MODULES,
    {"key": "request_context", "name": "request-context", "source": "native/request_context.hepta",
     "standalone": None, "manifest_env": "HIA_REQUEST_CONTEXT_MANIFEST", "test": "test_request_context.py"},
    {"key": "response_hints", "name": "response-hints", "source": "native/response_hints.hepta",
     "standalone": "filter", "manifest_env": "HIA_RESPONSE_HINTS_MANIFEST", "test": "test_response_hints.py",
     "additional_tests": ("test_request_context_transport.py", "test_request_context_evidence.py")},
    {"key": "result_publication", "name": "result-publication", "source": "native/result_publication.hepta",
     "builder": "result_publication", "manifest_env": "HIA_RESULT_PUBLICATION_FIXTURE_MANIFEST",
     "test": "test_result_publication.py", "additional_tests": ("test_result_publication_evidence.py",),
     "companion_sources": ("native/result_publication_packer.hepta",)},
    {"key": "request_scope_lifecycle", "name": "request-scope-lifecycle", "source": "native/request_scope_lifecycle.hepta",
     "builder": "request_scope", "manifest_env": "HIA_REQUEST_SCOPE_MANIFEST",
     "test": "test_request_scope_lifecycle.py",
     "additional_tests": ("test_request_scope_boundaries.py", "test_request_scope_evidence.py"),
     "companion_sources": ("native/request_cache_lease.hepta",)},
    {"key": "line_endpoint", "name": "line-endpoint", "source": "native/line_endpoint.hepta",
     "standalone": None, "manifest_env": "HIA_ENDPOINT_MANIFEST", "test": "test_line_endpoint.py"},
    {"key": "line_verify", "name": "line-verify", "source": "native/line_verify.hepta",
     "standalone": "filter", "manifest_env": "HIA_LINE_VERIFY_MANIFEST", "test": "test_line_verify.py"},
    {"key": "batch_edit_params", "name": "batch-edit-params", "source": "native/batch_edit_params.hepta",
     "builder": "batch_edit_params", "manifest_env": "HIA_BATCH_EDIT_PARAMS_BUNDLE",
     "test": "test_batch_edit_params.py", "companion_sources": ("native/serde_json_span.hepta",)},
    {"key": "batch_plan_input", "name": "batch-plan-input", "source": "native/batch_plan_input.hepta",
     "builder": "batch_plan_input", "manifest_env": "HIA_BATCH_PLAN_INPUT_MEMBERS",
     "test": "test_batch_plan_input.py",
     "companion_sources": ("native/serde_json_span.hepta", "native/batch_edit_params.hepta",
                           "native/editable_content.hepta", "native/batch_plan.hepta",
                           "native/line_endpoint.hepta", "native/line_verify.hepta")},
    {"key": "batch_plan", "name": "batch-plan", "source": "native/batch_plan.hepta",
     "builder": "batch_plan", "manifest_env": "HIA_BATCH_PLAN_BUNDLE", "test": "test_batch_plan.py",
     "additional_tests": ("test_batch_plan_evidence.py",)},
    {"key": "batch_apply", "name": "batch-apply", "source": "native/batch_apply.hepta",
     "builder": "batch_apply", "manifest_env": "HIA_APPLY_BUNDLE", "test": "test_batch_apply.py",
     "additional_tests": ("test_batch_apply_contract.py", "test_batch_apply_artifacts.py",
                          "test_batch_apply_evidence.py")},
    {"key": "batch_diff", "name": "batch-diff", "source": "native/batch_diff.hepta",
     "builder": "batch_diff", "manifest_env": "HIA_BATCH_DIFF_BUNDLE", "test": "test_batch_diff.py",
     "companion_sources": ("native/batch_apply.hepta", "native/editable_content.hepta",
                           "native/text_budget.hepta", "native/result_publication.hepta")},
    {"key": "atomic_write", "name": "atomic-write", "source": "native/atomic_write.hepta",
     "builder": "atomic_write", "manifest_env": "HIA_ATOMIC_MANIFEST", "test": "test_atomic_write_policy.py",
     "additional_tests": ("test_atomic_write_kernel.py", "test_atomic_write_boundary.py",
                          "test_atomic_write_evidence.py"),
     "companion_sources": ("native/atomic_write_packer.hepta",)},
    {"key": "filesystem_parity", "name": "filesystem-parity", "source": "native/filesystem_parity.hepta",
     "builder": "filesystem_parity", "manifest_env": "HIA_FILESYSTEM_PARITY_MANIFEST",
     "test": "test_filesystem_parity_state.py",
     "additional_tests": ("test_filesystem_parity_build.py", "test_filesystem_parity_kernel.py"),
     "companion_sources": ("native/filesystem_parity_packer.hepta",)},
    {"key": "delta", "name": "delta", "source": "native/delta.hepta",
     "standalone": "filter", "manifest_env": "HIA_DELTA_MANIFEST", "test": "test_delta.py"},
    {"key": "editable_content", "name": "editable-content", "source": "native/editable_content.hepta",
     "standalone": "filter", "manifest_env": "HIA_EDITABLE_MANIFEST", "test": "test_editable_content.py"},
    {"key": "view_render", "name": "view-render", "source": "native/view_render.hepta",
     "standalone": "filter", "buffer_profile": "view-render.v1",
     "companion_sources": ("native/view_filter_packer.hepta",),
     "manifest_env": "HIA_VIEW_MANIFEST", "test": "test_view_render.py",
     "additional_tests": ("test_view_transport.py",)},
    {"key": "view_render_growth", "name": "view-render-growth", "source": "native/view_render.hepta",
     "standalone": None, "buffer_profile": "history.v1",
     "manifest_env": "HIA_VIEW_GROWTH_MANIFEST", "test": "test_view_render_growth.py",
     "additional_tests": ("test_view_render_growth_evidence.py",)},
    {"key": "view_read", "name": "view-read", "source": "native/view_read.hepta",
     "builder": "view_read", "manifest_env": "HIA_VIEW_READ_FIXTURE_MANIFEST",
     "companion_sources": ("native/view_read_packer.hepta",), "test": "test_view_call_read.py"},
    {"key": "view_params", "name": "view-params", "source": "native/view_params.hepta",
     "standalone": None, "buffer_profile": "history.v1",
     "manifest_env": "HIA_VIEW_PARAMS_MANIFEST", "test": "test_view_call_params.py"},
    {"key": "view_call", "name": "view-call", "source": "native/view_call.hepta",
     "builder": "view_call", "manifest_env": "HIA_VIEW_CALL_FIXTURE_MANIFEST",
     "companion_sources": ("native/view_read.hepta", "native/line_endpoint.hepta",
                           "native/file_lock_key.hepta", "native/request_scope_lifecycle.hepta",
                           "native/request_cache_lease.hepta", "native/view_cache.hepta",
                           "native/view_render.hepta", "native/request_context.hepta",
                           "native/view_error.hepta", "native/view_call_packer.hepta",
                           "native/view_regex.hepta", "native/view_regex_diagnostic.hepta",
                           "native/regex_syntax.hepta", "native/regex_unicode_data.hepta",
                           "native/regex_hir.hepta", "native/regex_nfa.hepta", "native/regex_match.hepta"),
     "test": "test_view_call_sync.py",
     "additional_tests": ("test_view_call_wide.py", "test_view_call_resources.py", "test_view_call_evidence.py",
                          "test_view_search.py", "test_view_search_native_evidence.py",
                          "test_view_regex_search.py", "test_view_regex_search_native_evidence.py")},
    {"key": "runtime_mcp", "name": "runtime-mcp", "source": "native/runtime_mcp.hepta",
     "builder": "runtime_mcp", "manifest_env": "HIA_RUNTIME_MCP_MANIFEST",
     "companion_sources": (
         'native/config_directory_owner_span.hepta',
         'native/config_fs_span.hepta',
         'native/config_json_span.hepta',
         'native/config_validation_span.hepta',
         'native/config_identity.hepta',
         'native/config_mcp.hepta',
         'native/execution_controller.hepta',
         'native/execution_json.hepta',
         'native/execution_shadow.hepta',
         'native/serde_json.hepta',
         'native/result_publication.hepta',
         'native/regex_syntax.hepta',
         'native/regex_unicode_data.hepta',
         'native/regex_hir.hepta',
         'native/regex_nfa.hepta',
         'native/regex_match.hepta',
         'native/regex_controller.hepta',
         'native/runtime_mcp_catalog.hepta',
         'native/runtime_mcp_admission.hepta',
         'native/view_gateway.hepta',
         'native/client_context.hepta',
         'native/view_params.hepta',
         'native/session_context.hepta',
         'native/session_workdir.hepta',
         'native/local_path_policy.hepta',
         'native/canonical_path.hepta',
         'native/path_source.hepta',
         'native/serde_json_span.hepta',
         'native/workdir_gateway.hepta',
         'native/workdir_params.hepta',
         'native/workdir_io.hepta',
         'native/workdir_render.hepta',
         'native/view_error.hepta',
         'native/runtime_mcp_protocol.hepta',
         'native/view_call.hepta',
         'native/line_endpoint.hepta',
         'native/view_read.hepta',
         'native/file_lock_key.hepta',
         'native/request_scope_lifecycle.hepta',
         'native/request_cache_lease.hepta',
         'native/view_cache.hepta',
         'native/view_render.hepta',
         'native/request_context.hepta',
         'native/view_regex.hepta',
         'native/view_regex_diagnostic.hepta',
         'native/filesystem_gateway.hepta',
         'native/filesystem_params.hepta',
         'native/filesystem_call.hepta',
         'native/filesystem_parity.hepta',
         'native/filesystem_render.hepta',
         'native/directory_move_guard.hepta',
         'native/filesystem_fence.hepta',
         'native/effect_owner_fence.hepta',
         'native/effect_fence_fs.hepta',
         'native/fence_json.hepta',
         'native/binary_codec.hepta',
         'native/effect_fence_manager.hepta',
         'native/runtime_mcp_image_packer.hepta',
     ),
     "test": "test_runtime_mcp.py", "additional_tests": ("test_runtime_mcp_evidence.py",
                                                         "test_view_search_public.py",
                                                         "test_view_regex_search_public.py",
                                                         "test_view_regex_search_public_evidence.py",
                                                         "test_runtime_mcp_raw_value.py",
                                                         "test_runtime_mcp_raw_value_evidence.py")},
    {"key": "filesystem_public", "name": "filesystem-public", "source": "native/filesystem_gateway.hepta",
     "builder": "filesystem_public", "manifest_env": "HIA_FILESYSTEM_PUBLIC_MANIFEST",
     "test": "test_filesystem_public.py",
     "companion_sources": ("native/filesystem_params.hepta", "native/filesystem_call.hepta",
                           "native/filesystem_parity.hepta", "native/filesystem_render.hepta",
                           "native/filesystem_fence.hepta", "native/directory_move_guard.hepta",
                           "native/runtime_mcp_image_packer.hepta")},
    {"key": "view_cache", "name": "view-cache", "source": "native/view_cache.hepta",
     "standalone": None, "manifest_env": "HIA_CACHE_MANIFEST", "test": "test_view_cache.py",
     "additional_tests": ("test_view_cache_evidence.py",)},
    {"key": "history", "name": "history", "source": "native/history.hepta",
     "builder": "history", "manifest_env": "HIA_HISTORY_BUNDLE", "test": "test_history.py",
     "additional_tests": ("test_history_evidence.py",)},
    {"key": "session_workdir", "name": "session-workdir", "source": "native/session_workdir.hepta",
     "builder": "session_workdir", "manifest_env": "HIA_SESSION_BUNDLE", "test": "test_session_workdir.py",
     "additional_tests": ("test_session_evidence.py",)},
    {"key": "file_locks", "name": "file-locks", "source": "native/file_lock_state.hepta",
     "builder": "file_locks", "manifest_env": "HIA_FILE_LOCK_MANIFEST", "test": "test_file_lock_state.py",
     "additional_tests": ("test_file_lock_key.py", "test_file_lock_evidence.py"),
     "companion_sources": ("native/file_lock_key.hepta", "native/file_lock_state_packer.hepta",
                           "native/file_lock_key_packer.hepta")},
    {"key": "file_lock_service", "name": "file-lock-service", "source": "native/file_lock_service.hepta",
     "builder": "file_lock_service", "manifest_env": "HIA_FILE_LOCK_SERVICE_MANIFEST",
     "test": "test_file_lock_service.py",
     "additional_tests": ("test_file_lock_service_contract.py", "test_file_lock_service_evidence.py"),
     "companion_sources": ("native/file_lock_service_packer.hepta",)},
    {"key": "write_chain", "name": "write-chain", "source": "native/write_chain.hepta",
     "builder": "write_chain", "manifest_env": "HIA_WRITE_CHAIN_BUNDLE", "test": "test_shared_atomic.py",
     "additional_tests": ("test_write_chain_controller.py", "test_write_chain_files.py",
                          "test_write_chain_kernel.py", "test_write_chain_concurrency.py",
                          "test_write_chain_evidence.py"),
     "companion_sources": ("native/atomic_write_shared.hepta", "native/local_read.hepta",
                           "native/write_chain_packer.hepta")},
    {"key": "directory_service", "name": "directory-service", "source": "native/directory_caller.hepta",
     "builder": "directory_service", "manifest_env": "HIA_DIRECTORY_BUNDLE", "test": "test_directory_service.py",
     "additional_tests": ("directory_service_faults.py", "test_directory_service_transport.py",
                          "test_directory_service_build.py", "test_directory_service_regex.py"),
     "companion_sources": ("native/canonical_path.hepta", "native/client_context.hepta",
                           "native/config_directory_owner.hepta", "native/directory_create.hepta",
                           "native/directory_errno.hepta", "native/directory_fence_fs.hepta",
                           "native/directory_fence_packer.hepta", "native/directory_fence_queue_fixture_packer.hepta",
                           "native/directory_service_packer.hepta", "native/directory_service_prefix.hepta",
                           "native/effect_fence_caller_manager.hepta", "native/effect_fence_caller_owner.hepta",
                           "native/local_path_policy.hepta", "native/path_source.hepta",
                           "native/session_request_context.hepta")},
    {"key": "workdir_service", "name": "workdir-service", "source": "native/workdir_caller.hepta",
     "builder": "workdir_service", "manifest_env": "HIA_WORKDIR_BUNDLE", "test": "test_workdir_params.py",
     "additional_tests": ("test_workdir_caller_controls.py", "test_workdir_service_regex.py"),
     "companion_sources": ("native/local_canonical.hepta", "native/workdir_params.hepta",
                           "native/workdir_service_packer.hepta", "native/workdir_service_prefix.hepta")},
    {"key": "sdk_connection", "name": "sdk-connection", "source": "native/sdk_connection.hepta",
     "builder": "sdk_connection", "manifest_env": "HIA_CONNECTION_BUILD", "test": "test_sdk_message.py",
     "additional_tests": ("test_sdk_transport.py", "test_sdk_connection.py",
                          "test_sdk_connection_elf.py", "test_sdk_connection_controls.py"),
     "companion_sources": ("native/sdk_message.hepta", "native/sdk_default_fixture.hepta",
                           "native/sdk_connection_packer.hepta")},
    {"key": "public_registry", "name": "public-registry", "source": "native/public_tool_dispatch.hepta",
     "builder": "public_registry", "manifest_env": "HIA_PUBLIC_REGISTRY_BUILD",
     "test": "run_public_registry_cases.py",
     "additional_tests": ("test_public_registry_controls.py", "test_public_registry_elf.py"),
     "companion_sources": ("native/public_runtime_packer.hepta",)},
    {"key": "fence_json", "name": "fence-json", "source": "native/fence_json.hepta",
     "standalone": "filter", "manifest_env": "HIA_FENCE_JSON_MANIFEST", "test": "test_fence_json.py"},
    {"key": "serde_json", "name": "serde-json", "source": "native/serde_json.hepta",
     "standalone": "filter", "buffer_profile": "serde-json.v1",
     "companion_sources": ("native/serde_filter_packer.hepta",),
     "manifest_env": "HIA_SERDE_JSON_MANIFEST", "test": "test_serde_json.py",
     "additional_tests": ("test_serde_json_transport.py", "test_serde_json_raw_value.py",
                          "test_json_evidence.py", "test_serde_json_raw_value_evidence.py")},
    {"key": "runtime_config_span", "name": "runtime-config-span", "source": "native/config_directory_owner_span.hepta",
     "builder": "runtime_config_span", "manifest_env": "HIA_CONFIG_SPAN_BUILD", "test": "test_config_span.py",
     "additional_tests": ("test_config_span_evidence.py",),
     "companion_sources": ("native/config_fs_span.hepta", "native/config_json_span.hepta",
                           "native/config_validation_span.hepta", "native/directory_move_guard.hepta")},
    {"key": "runtime_config", "name": "runtime-config", "source": "native/config_owner.hepta",
     "builder": "runtime_config", "manifest_env": "HIA_CONFIG_BUILD", "test": "test_config_json.py",
     "additional_tests": ("test_config_semantics.py", "test_config_fs.py", "test_config_owner.py",
                          "test_config_mcp.py", "test_config_mcp_receipts.py",
                          "test_regex_unicode.py",
                          "test_regex_syntax.py",
                          "test_regex_hir.py",
                          "test_regex_nfa_0.py",
                          "test_regex_nfa_1.py",
                          "test_regex_match.py",
                          "test_regex_pipeline.py",
                          "test_regex_controls.py",
                          "test_config_regex.py"),
     "companion_sources": ("native/config_json.hepta", "native/config_validation.hepta",
                           "native/config_identity.hepta", "native/config_fs.hepta", "native/config_mcp.hepta",
                           "native/result_publication.hepta",
                           "native/config_fs_packer.hepta", "native/config_owner_packer.hepta",
                           "native/config_owner_fixture_packer.hepta", "native/config_mcp_packer.hepta",
                           "native/config_regex_packer.hepta",
                           "native/regex_controller.hepta",
                           "native/regex_hir.hepta",
                           "native/regex_hir_packer.hepta",
                           "native/regex_match.hepta",
                           "native/regex_nfa.hepta",
                           "native/regex_pipeline_packer.hepta",
                           "native/regex_syntax.hepta",
                           "native/regex_syntax_packer.hepta",
                           "native/regex_unicode.hepta",
                           "native/regex_unicode_data.hepta",
                           "native/regex_unicode_packer.hepta")},
    {"key": "execution_shadow", "name": "execution-shadow", "source": "native/execution_shadow.hepta",
     "builder": "execution_shadow", "manifest_env": "HIA_EXECUTION_BUNDLE",
     "companion_sources": ("native/execution_json.hepta", "native/execution_controller.hepta"),
     "test": "test_execution_shadow.py",
     "additional_tests": ("test_execution_json.py", "test_execution_json_errors.py",
                          "test_execution_controller.py", "test_execution_evidence.py")},
    {"key": "effect_fence", "name": "effect-fence", "source": "native/effect_owner_fence.hepta",
     "builder": "effect_fence", "manifest_env": "HIA_FENCE_BUNDLE",
     "companion_sources": ("native/effect_fence_fs.hepta", "native/effect_fence_manager.hepta",
                           "native/effect_fence_async_packer.hepta",
                           "native/effect_fence_async_queue_fixture_packer.hepta"),
     "test": "test_fence_async.py",
     "additional_tests": ("test_fence_worker.py", "test_fence_lifetime.py",
                          "effect_fence_async_serial_adapter.py", "test_fence_kernel.py",
                          "test_fence_packer.py", "test_fence_evidence.py")},
    {"key": "binary_codec", "name": "binary-codec", "source": "native/binary_codec.hepta",
     "standalone": "filter", "manifest_env": "HIA_CODEC_MANIFEST", "test": "test_binary_codec.py"},
    {"key": "operation_kdf", "name": "operation-kdf", "source": "native/operation_kdf.hepta",
     "standalone": "filter", "manifest_env": "HIA_KDF_MANIFEST", "test": "test_operation_kdf.py"},
    {"key": "operation_aead", "name": "operation-aead", "source": "native/operation_aead.hepta",
     "standalone": "filter", "manifest_env": "HIA_AEAD_MANIFEST", "test": "test_operation_aead.py"},
    {"key": "operation_nonce", "name": "operation-nonce", "source": "native/operation_nonce.hepta",
     "standalone": "filter", "manifest_env": "HIA_NONCE_MANIFEST", "test": "test_operation_nonce.py"},
    {"key": "operation_record", "name": "operation-record", "source": "native/operation_record.hepta",
     "builder": "record_composition", "manifest_env": "HIA_RECORD_MANIFEST", "test": "test_operation_record.py"},
    {"key": "system_entropy", "name": "system-entropy", "source": "native/entropy_policy.hepta",
     "companion_sources": ("native/entropy_packer.hepta",), "builder": "entropy",
     "manifest_env": "HIA_ENTROPY_MANIFEST", "test": "test_entropy_backend.py",
     "additional_tests": ("test_entropy_packer.py", "test_entropy_kernel_backend.py", "test_entropy_transport.py")},
    {"key": "operation_scope", "name": "operation-scope", "source": "native/operation_scope.hepta",
     "builder": "scope_composition", "manifest_env": "HIA_SCOPE_MANIFEST", "test": "test_operation_scope.py"},
    {"key": "operation_scope_os", "name": "operation-scope-os", "source": "native/operation_scope.hepta",
     "builder": "scope_os_composition", "manifest_env": "HIA_SCOPE_OS_MANIFEST", "test": "test_scope_os.py",
     "additional_tests": ("test_scope_os_packer.py", "test_scope_os_evidence.py")},
    {"key": "caller_authority", "name": "caller-authority", "source": "native/caller_authority.hepta",
     "companion_sources": ("native/authority_loader.hepta", "native/authority_packer.hepta"),
     "builder": "authority_composition", "manifest_env": "HIA_AUTHORITY_ELF_MANIFEST",
     "test": "test_caller_authority.py",
     "additional_tests": ("test_authority_loader_kernel.py", "test_authority_transport.py",
                          "test_authority_packer.py", "test_authority_evidence.py")},
    {"key": "policy", "name": "policy", "source": "native/policy.hepta",
     "standalone": "filter", "manifest_env": "HIA_POLICY_MANIFEST", "test": "test_policy.py"},
    {"key": "stat_version", "name": "stat-version", "source": "native/stat_version.hepta",
     "standalone": "filter", "manifest_env": "HIA_STAT_VERSION_MANIFEST", "test": "test_stat_version.py"},
    {"key": "native_io", "name": "native-io", "source": "native/io_policy.hepta",
     "companion_sources": ("native/io_packer.hepta",), "builder": "io",
     "manifest_env": "HIA_IO_MANIFEST", "test": "test_native_io.py",
     "additional_tests": ("test_native_full_io.py",)},
    {"key": "multi_read_service", "name": "multi-read-service", "source": "native/multi_read_service.hepta",
     "standalone": None, "manifest_env": "HIA_MULTI_READ_MANIFEST", "test": "test_multi_read_controller.py"},
    {"key": "file_info_service", "name": "file-info-service", "source": "native/file_info_service.hepta",
     "standalone": None, "manifest_env": "HIA_FILE_INFO_MANIFEST", "test": "test_file_info_controller.py"},
    {"key": "local_service", "name": "local-service", "source": "native/local_service.hepta",
     "companion_sources": ("native/composition_packer.hepta",), "builder": "composition",
     "manifest_env": "HIA_SERVICE_MANIFEST", "test": "test_local_service.py",
     "additional_tests": ("test_multi_service.py", "test_info_service.py", "test_file_info_io_state.py",
                          "test_file_info_deadline_state.py", "test_file_info_io_faults.py",
                          "test_file_info_guard.py", "test_native_deadline_probe.py")},
)
PACKERS = {"native/filter_packer.hepta", "native/stdio_packer.hepta"}
EXTRA_TESTS = ("test_transport.py", "test_native_composition.py", "test_qualification_reporting.py",
               "test_native_pipeline.py", "test_original_pipeline.py")
RUST_CORPUS_FILES = ("native-corpus.json", "input.bin.gz", "native-output.bin.gz")
FILE_INFO_SUITES = (
    ("test_info_service.py", "file-info-python-reference.json", "hepta.runtime.native-info-service-test.v1",
     {"info_requests": 64, "original_info_comparisons": 39, "original_failure_comparisons": 4,
      "parameter_refusals": 13, "domain_refusals": 12, "acl_comparisons": 1, "all_actual_elf_responses": 73}),
    ("test_file_info_controller.py", "file-info-controller.json", "hepta.runtime.file-info-controller-test.v1",
     {"requests": 23, "native_controller_calls": 152, "native_leaf_calls": 42, "fixture_io_calls": 35}),
    ("test_file_info_io_state.py", "file-info-io-state.json", "hepta.runtime.native-info-io-state-test.v1",
     {"native_io_calls": 3579, "native_sha_calls": 729, "original_metadata_controls": 6,
      "requests": 53, "synthetic_effects": 2711}),
    ("test_file_info_deadline_state.py", "file-info-deadline-state.json", "hepta.runtime.native-info-deadline-state-test.v1",
     {"native_io_calls": 327, "native_sha_calls": 44, "original_metadata_controls": 0,
      "requests": 16, "synthetic_effects": 243}),
    ("test_file_info_io_faults.py", "file-info-io-faults.json", "hepta.runtime.native-info-io-fault-test.v1",
     {"actual_info_requests": 10, "fixture_races": 6, "original_success_comparisons": 2, "syscall_faults": 6}),
    ("test_file_info_guard.py", "file-info-guard.json", "hepta.runtime.native-info-guard-test.v1",
     {"closed_stderr_controls": 1, "deadline_requests": 2, "kernel_notification_holds": 2,
      "original_info_comparisons": 9, "original_read_comparisons": 2, "parent_resource_controls": 12,
      "root_fd2_controls": 3, "root_rebind_controls": 2, "setup_failure_controls": 5,
      "setup_recovery_controls": 5, "worker_cancellations": 2, "worker_reap_controls": 2}),
    ("test_native_deadline_probe.py", "file-info-blocking-probe.json", "hepta.runtime.native-deadline-probe.v1", None),
)
FILE_INFO_RECEIPTS = tuple(row[1] for row in FILE_INFO_SUITES)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def qualification_env(inherited: dict | None = None) -> dict:
    """Keep ordinary host settings, then admit only qualifier-owned HIA inputs.

    Standalone suites intentionally support development overrides. The closed
    qualification must not inherit an external loader, source or probe path.
    """
    parent = os.environ if inherited is None else inherited
    return {key: value for key, value in parent.items() if not key.startswith("HIA_")}


def sources() -> dict:
    paths = set((ROOT / "native").rglob("*"))
    paths.update((ROOT / "tests/hia_native").rglob("*"))
    paths.update(ROOT / "scripts" / name for name in (
        "hia_native_build.py", "hia_native_loader.py", "generate_hia_transport.py",
        "hia_native_bellman_build.py", "hia_native_bellman_qualification.py",
        "hia_native_bellman_commitment_build.py", "hia_native_bellman_commitment_qualification.py",
        "hia_native_local_create_build.py", "hia_native_local_create_qualification.py",
        "hia_native_local_create_pipeline.py", "hia_native_local_create_segments_qualification.py",
        "hia_native_local_create_async_qualification.py",
        "hia_native_text_editor_params_qualification.py",
        "local_create_adapter.S", "local_create_spec_adapter.S",
        "hia_native_local_create_spec_build.py", "hia_native_local_create_spec_qualification.py",
        "hia_native_local_create_spec_state_qualification.py",
        "hia_native_io_build.py", "hia_native_composition_build.py", "hia_native_record_build.py", "hia_native_cold.py",
        "hia_native_entropy_build.py", "hia_native_entropy_qualification.py",
        "hia_native_scope_build.py", "hia_native_scope_qualification.py",
        "hia_native_editable_qualification.py", "hia_native_view_qualification.py",
        "hia_native_view_growth_qualification.py",
        "hia_native_view_resource_qualification.py",
        "hia_native_view_fixture_qualification.py",
        "hia_native_view_read_build.py", "hia_native_view_call_build.py",
        "hia_native_view_call_qualification.py", "hia_native_view_search_qualification.py",
        "hia_native_view_search_reference.py", "hia_native_view_search_public_qualification.py",
        "hia_native_view_regex_search_qualification.py", "hia_native_view_regex_search_reference.py",
        "hia_native_view_regex_search_public_qualification.py", "view_call_regex_bridge.S",
        "view_read_adapter.S",
        "view_call_adapter.S", "view_call_fixture_controls.S", "view_call_engine.S",
        "view_call_read_bridge.S", "view_call_key_bridge.S", "view_call_scope_bridge.S",
        "hia_native_runtime_mcp_build.py", "hia_native_runtime_mcp_evidence.py",
        "hia_native_span_raw_value_qualification.py",
        "hia_native_runtime_mcp_reference.py", "hia_native_runtime_mcp_original.py",
        "hia_native_runtime_mcp_adapter.py", "hia_native_runtime_mcp_pack.py",
        "hia_native_runtime_mcp_pipeline.py", "hia_native_runtime_mcp_fixtures.py",
        "hia_native_public_exchange_qualification.py",
        "hia_native_filesystem_public_build.py", "hia_native_filesystem_public_pipeline.py",
        "hia_native_filesystem_public_fixtures.py", "hia_native_filesystem_public_reference_source.py",
        "runtime_mcp_filesystem_fence_bridge.S", "runtime_mcp_filesystem_fence_native.S",
        "runtime_mcp_filesystem_fixture.S", "runtime_mcp_filesystem_front_fixture.S",
        "runtime_mcp_filesystem_io_bridge.S", "runtime_mcp_filesystem_observer.S",
        "runtime_mcp_filesystem_view_bridge.S",
        "hia_native_workdir_reference.py", "runtime_mcp_extra_engine.S", "runtime_mcp_canonical_bridge.S",
        "runtime_mcp_transport.S", "runtime_mcp_execution_bridge.S",
        "runtime_mcp_view_bridge.S", "runtime_mcp_workdir_io_bridge.S",
        "hia_native_view_cache_build.py", "hia_native_view_cache_qualification.py",
        "hia_native_history_build.py", "hia_native_history_qualification.py", "hia_native_json_qualification.py",
        "hia_native_raw_value_qualification.py",
        "hia_native_request_context_build.py", "hia_native_request_context_qualification.py", "hia_native_request_context_reference.py",
        "hia_native_result_publication_build.py", "hia_native_result_publication_qualification.py",
        "hia_native_result_publication_reference.py", "result_publication_adapter.S",
        "hia_native_request_scope_build.py", "hia_native_request_scope_qualification.py",
        "hia_native_request_scope_reference.py",
        'build_config_fs_probe.py',
        'build_config_mcp_service.py',
        'build_config_owner_probe.py',
        'build_hia_config_service.py',
        'config_fs_adapter.S',
        'config_mcp_adapter.S',
        'config_owner_adapter.S',
        'config_schema.py',
        'hia_native_config_reference.py',
        'hia_native_config_qualification.py',
        'hia_native_config_span_build.py',
        'hia_native_config_span_qualification.py',
        'hia_native_config_span_pipeline.py',
        'hia_native_config_span_fixtures.py',
        'config_mcp_grow_adapter.S',
        "build_regex_probe.py",
        "config_regex_adapter.S",
        "hia_native_regex_qualification.py",
        "hia_native_regex_reference.py",
        "regex_hir_adapter.S",
        "regex_pipeline_adapter.S",
        "regex_syntax_adapter.S",
        "regex_unicode_adapter.S",
        "hia_native_execution_build.py", "hia_native_execution_qualification.py",
        "hia_native_session_build.py", "hia_native_session_qualification.py",
        "hia_native_file_lock_build.py", "hia_native_file_lock_qualification.py",
        "hia_native_file_lock_service_build.py", "hia_native_file_lock_service_qualification.py",
        "hia_native_file_lock_pipeline.py",
        "hia_native_shell_qualification.py", "hia_native_shell_reference.py",
        "qualify_hia_shell_native.py",
        "hia_native_shell_process_build.py", "hia_native_shell_process_qualification.py",
        "hia_native_shell_process_reference.py", "hia_native_shell_process_evidence.py",
        "hia_native_shell_outcome_build.py", "hia_native_shell_outcome_qualification.py",
        "hia_native_shell_output_build.py", "hia_native_shell_output_qualification.py",
        "hia_native_shell_foreground_build.py", "hia_native_shell_foreground_qualification.py",
        "shell_foreground_adapter.S",
        "hia_native_failure_evidence.py", "shell_output_adapter.S",
        "shell_process_adapter.S", "qualify_hia_shell_process.py",
        "hia_native_effect_fence_build.py", "hia_native_effect_fence_qualification.py",
        "hia_native_line_verify_qualification.py",
        "hia_native_batch_plan_build.py", "hia_native_batch_plan_qualification.py",
        "hia_native_batch_edit_params_build.py", "hia_native_batch_edit_params_qualification.py",
        "hia_native_batch_edit_params_pipeline.py",
        "hia_native_batch_plan_input_build.py", "hia_native_batch_plan_input_qualification.py",
        "hia_native_batch_plan_input_pipeline.py",
        "hia_native_batch_apply_build.py", "hia_native_batch_apply_qualification.py",
        "hia_native_batch_diff_build.py", "hia_native_batch_diff_qualification.py",
        "hia_native_batch_diff_pipeline.py",
        "hia_native_atomic_write_build.py", "hia_native_atomic_write_qualification.py",
        "hia_native_filesystem_parity_build.py", "hia_native_filesystem_parity_reference.py",
        "hia_native_filesystem_parity_qualification.py",
        "hia_native_scope_os_build.py", "hia_native_scope_os_qualification.py",
        "hia_native_authority_build.py", "hia_native_authority_layout.py",
        "hia_native_authority_probe_build.py", "hia_native_authority_qualification.py",
        "check_hia_native_inventory.py", "check_hia_native_target.py", "qualify_hia_runtime_native.py", "hia_native_pipeline.py", "hia_native_rust_pipeline.py", "hia_native_failure.py", "hia_native_failure_evidence.py",
        "compare_hia_runtime_rust.py"))
    paths.update((ROOT / "src/mcp/server.rs", ROOT / "src/utils/line_hash.rs", ROOT / "src/utils/truncation.rs",
                  ROOT / ".github/workflows/hia-migration-target.yml", ROOT / ".github/workflows/hia-runtime-native.yml", ROOT / ".github/workflows/hia-runtime-shell.yml",
                  ROOT / ".github/workflows/hia-runtime-shell-process.yml",
                  ROOT / ".github/workflows/hia-runtime-bellman.yml",
                  ROOT / ".github/workflows/hia-runtime-original-shard.yml", ROOT / "rustfmt.toml"))
    paths.update(ROOT / name for name in ORIGINAL_RUNTIME_BLOBS)
    paths.update(ROOT / "scripts" / name for name in capture_gate.SCRIPTS)
    paths.update(ROOT / name for name in capture_gate.ORACLE_SOURCES)
    paths.update(ROOT / name for name in service_pipeline.sources(ROOT))
    paths.update(ROOT / name for name in public_registry_qualification.source_pins(ROOT))
    paths.update(ROOT / name for name in result_qualification.source_pins(ROOT))
    paths.update(ROOT / name for name in serde_error_pipeline.sources(ROOT))
    paths.update(ROOT / name for name in storage_pipeline.sources(ROOT))
    paths.update(ROOT / name for name in batch_write_pipeline.q.pins(ROOT))
    return {path.relative_to(ROOT).as_posix(): sha(path) for path in sorted(paths)
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}


def git_head() -> str | None:
    completed = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
                               capture_output=True, text=True, timeout=15)
    if completed.returncode or Path(completed.stdout.strip()).resolve() != ROOT:
        return None
    completed = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                               capture_output=True, text=True, timeout=15)
    return completed.stdout.strip() if completed.returncode == 0 else None


def save_report(path: Path, result: dict) -> None:
    temporary = path.with_suffix(".pending.json")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def process_summary(name: str, stdout: bytes) -> dict:
    if capture_gate.process_kind(name) is not None:
        return capture_gate.progress_records(name, stdout)[-1]
    if name in ("hia_native_shell_process_qualification.py", "shell-process-rust-compare"):
        return shell_process_progress_summary(stdout, original=name == "shell-process-rust-compare")
    if name in ("shell_output_io.py", "shell-output-native", "shell_foreground_io.py", "shell-foreground-native"):
        return shell_io_progress_records(name, stdout)[-1]
    if name != "test_batch_plan.py":
        return json.loads(stdout)
    # This suite retains two complete-domain progress records before its final
    # report. Admit exactly that framing; a trailing PASS cannot hide failures,
    # omitted large cases, duplicate reports or other output.
    rows = [json.loads(line) for line in stdout.splitlines()]
    expected = [
        {"phase": "maximum_plain", "status": "PASS", "output_bytes": 524298089,
         "workspace_bytes": 534831101},
        {"phase": "maximum_stale", "status": "PASS", "output_bytes": 524301763,
         "workspace_bytes": 534835575},
    ]
    if len(rows) != 3 or json_bytes(rows[:2]) != json_bytes(expected):
        raise ValueError("batch complete-domain progress evidence differs")
    return rows[2]


def record_check(output: Path, report: dict, *, name: str, command: list[str],
                 timeout: float, env: dict | None = None,
                 input_bytes: bytes | None = None,
                 report_path: Path | None = None,
                 record_identity: bool = False) -> subprocess.CompletedProcess:
    """Retain completed, refused and timed-out checks before propagating failure."""
    started = time.monotonic()
    stdout, stderr = b"", b""
    code, start_error, pid = None, None, None
    timed_out = False
    process = None
    storage_process = storage_pipeline.process_folder(output, name) is not None
    try:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        pid = process.pid
        try:
            stdout, stderr = process.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            # Kill only this new process group, including inherited output pipes.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if storage_process:
                try:
                    stdout, stderr = process.communicate(timeout=3)
                except subprocess.TimeoutExpired as cleanup:
                    stdout, stderr = cleanup.stdout or b"", cleanup.stderr or b""
            else:
                stdout, stderr = process.communicate()
            stdout = stdout if stdout is not None else exc.stdout or b""
            stderr = stderr if stderr is not None else exc.stderr or b""
        code = process.returncode
    except OSError as exc:
        start_error = {"type": type(exc).__name__, "message": str(exc)}
    (output / (name + ".stdout")).write_bytes(stdout)
    (output / (name + ".stderr")).write_bytes(stderr)
    check = {"name": name, "phase": report.get("phase"), "command": command,
             "exit_code": code, "timed_out": timed_out, "timeout_seconds": timeout,
             "elapsed_seconds": time.monotonic() - started,
             "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
             "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
             "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)}
    if record_identity:
        check.update(pid=pid, cwd=str(ROOT))
    if start_error:
        check["start_error"] = start_error
    try:
        check["summary"] = process_summary(name, stdout)
    except (ValueError, UnicodeDecodeError):
        pass
    completion_error = None
    if storage_process:
        try:
            storage_pipeline.finish_actual_process(ROOT, output, check, process, stdout, stderr)
        except Exception as error:
            completion_error = error
    report["checks"].append(check)
    save_report(output / "result.json" if report_path is None else report_path, report)
    if completion_error is not None:
        raise completion_error
    if start_error or timed_out or code != 0:
        reason = "timed out" if timed_out else "could not start" if start_error else "failed"
        raise RuntimeError(name + " " + reason + "; original stdout/stderr retained")
    return subprocess.CompletedProcess(command, code, stdout, stderr)


INDEPENDENT_WAIT_SUITES = (
    "test_scope_os.py", "test_authority_transport.py", "test_file_info_guard.py",
)


ORDERED_INDEPENDENT_SUITES = (("test_serde_json.py", "test_serde_json_transport.py",
                              "test_serde_json_raw_value.py"),)
PARALLEL_NATIVE_SUITES = INDEPENDENT_WAIT_SUITES + tuple(
    name for group in ORDERED_INDEPENDENT_SUITES for name in group)


def run_native_checks(output: Path, report: dict, tests: tuple[str, ...], env: dict,
                      *, parallel_tests: tuple[str, ...] = INDEPENDENT_WAIT_SUITES,
                      ordered_groups: tuple[tuple[str, ...], ...] = ORDERED_INDEPENDENT_SUITES,
                      commands: dict[str, list[str]] | None = None,
                      timeout: float = 180) -> None:
    """Overlap two OS waits and one ordered JSON worker with the main suite.

    The compiler cold gate has already completed. Large application/history/view
    suites stay on the main thread; JSON owns separate artifacts and one worker.
    Workers retain private execution receipts. Only the caller updates the full
    report, in declaration order, and every submitted process is drained even
    when another check fails. Each process keeps its original deadline.
    """
    if len(set(tests)) != len(tests) or any(Path(name).name != name for name in tests):
        raise ValueError("native executable suite names must be unique basenames")
    commands = commands or {}
    if set(commands) - set(tests):
        raise ValueError("native command override names an undeclared suite")
    config_commands = (config_qualification.test_commands(ROOT, output, report)
                       if set(tests) & set(config_qualification.TESTS) else {})
    service_commands = (service_pipeline.test_commands(ROOT, output, report)
                        if set(tests) & set(service_pipeline.DIRECTORY_TESTS) else {})
    config_commands.update({name: command for name, command in service_commands.items()
                            if name in service_pipeline.DIRECTORY_TESTS})
    if set(tests) & set(public_registry_qualification.TESTS):
        config_commands.update(public_registry_qualification.test_commands(ROOT, output, report))
    if set(tests) & set((*result_qualification.TESTS, result_qualification.CONTROL_TEST)):
        config_commands.update(result_qualification.test_commands(ROOT, output, report))
    if set(tests) & set(serde_error_pipeline.TESTS):
        config_commands.update(serde_error_pipeline.test_commands(ROOT, output, report))
    if set(tests) & set(storage_pipeline.TESTS):
        config_commands.update(storage_pipeline.test_commands(ROOT, output, report))
    if set(tests) & set(batch_write_pipeline.q.SUITES):
        config_commands.update(batch_write_pipeline.test_commands(ROOT, output, report))
    shell_commands = (shell_process_test_commands(output, report)
                      if set(tests) & {*SHELL_PROCESS_TESTS, SHELL_BACKGROUND_TEST} else {})
    outcome_commands = (shell_outcome_test_commands(output, report)
                        if SHELL_OUTCOME_TEST in tests else {})
    output_commands = (shell_output_test_commands(output, report)
                       if SHELL_OUTPUT_TEST in tests else {})
    foreground_commands = (shell_foreground_test_commands(output, report)
                           if set(tests) & set(SHELL_FOREGROUND_TESTS) else {})
    capture_commands = (capture_gate.test_commands(output, report)
                        if set(tests) & set(capture_gate.TESTS) else {})
    exact_commands = {**config_commands, **shell_commands, **outcome_commands,
                      **output_commands, **foreground_commands, **capture_commands}
    def command(name):
        prefix = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name)]
        argv = commands.get(name, prefix)
        if (type(argv) is not list or any(type(value) is not str for value in argv)
                or (argv != exact_commands[name] if name in exact_commands
                    else argv[:len(prefix)] != prefix)):
            raise ValueError("native command differs from its source-owned suite: " + name)
        return argv
    invocation = {name: command(name) for name in tests}
    selected = tuple(name for name in tests if name in parallel_tests)
    groups = tuple(group for group in ordered_groups if set(group) & set(tests))
    flattened = tuple(name for group in groups for name in group)
    if (any(not group or set(group) - set(tests) for group in groups)
            or len(set(flattened)) != len(flattened) or set(flattened) & set(selected)):
        raise ValueError("ordered independent suite group is partial or duplicated")
    receipts, futures, collected = {}, {}, set()
    report["native_parallel_receipts"] = {}
    for name in (*selected, *flattened):
        receipts[name] = ({"phase": report.get("phase"), "checks": []},
                          output / (name + ".execution.json"))
    def execute(group):
        failures = {}
        for name in group:
            private, path = receipts[name]
            try:
                record_check(output, private, name=name, command=invocation[name],
                             timeout=timeout, env=env, report_path=path,
                             record_identity=name == "test_bellman_commitment.py")
                failures[name] = None
            except Exception as error:
                failures[name] = error
        return failures
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="hia-native-waits") as waits, \
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="hia-native-json") as ordered:
        try:
            for name in selected:
                futures[name] = waits.submit(execute, (name,))
            for group in groups:
                future = ordered.submit(execute, group)
                for name in group:
                    futures[name] = future
            def collect(name):
                failure = futures[name].result()[name]
                private, path = receipts[name]
                if (len(private["checks"]) != 1 or private["checks"][0]["name"] != name
                        or json.loads(path.read_bytes()) != private):
                    raise ValueError("independent native invocation receipt is incomplete: " + name)
                if name in collected or any(row["name"] == name for row in report["checks"]):
                    raise ValueError("independent native invocation was recorded twice: " + name)
                report["checks"].append(private["checks"][0])
                report["native_parallel_receipts"][path.name] = sha(path)
                collected.add(name)
                save_report(output / "result.json", report)
                return failure
            for name in tests:
                if name in futures:
                    failure = collect(name)
                    if failure is not None:
                        raise failure
                else:
                    if name == "shell_process_evidence_controls.py":
                        retire_shell_process_native(output, report)
                    record_check(output, report, name=name, command=invocation[name], timeout=timeout, env=env,
                                 record_identity=name in ("test_batch_plan_input.py", "test_text_editor_params.py", "test_bellman_commitment.py"))
        finally:
            for name in futures:
                if name not in collected:
                    try:
                        failure = collect(name)
                        if failure is not None:
                            report.setdefault("native_parallel_drain_errors", []).append(
                                {"name": name, "type": type(failure).__name__, "message": str(failure)})
                    except Exception as error:
                        report.setdefault("native_parallel_drain_errors", []).append(
                            {"name": name, "type": type(error).__name__, "message": str(error)})
            save_report(output / "result.json", report)

    if "test_batch_edit_params.py" in tests:
        # Preserve a byte-identical component view of this actual main receipt.
        # Pure readers subsequently require it; they never recreate a missing file.
        from hia_native_batch_edit_params_pipeline import native_evidence
        native_evidence(ROOT, output, report, completed_test_summary, create=True)

    if "test_batch_plan_input.py" in tests:
        from hia_native_batch_plan_input_pipeline import native_evidence
        native_evidence(ROOT, output, report, completed_test_summary, create=True)

    if "test_batch_diff.py" in tests:
        from hia_native_batch_diff_pipeline import native_evidence
        native_evidence(ROOT, output, report, completed_test_summary, create=True)


def io_reference_evidence(output: Path, report: dict) -> dict:
    """Admit the direct retained-Python comparisons, never a dummy Rust recipe."""
    checks = [row for row in report["checks"] if row["name"] == "test_native_io.py"]
    if len(checks) != 1:
        raise ValueError("native IO requires exactly one completed executable suite")
    row = checks[0]
    raw = (output / "test_native_io.py.stdout").read_bytes()
    errors = (output / "test_native_io.py.stderr").read_bytes()
    if (row["exit_code"] != 0 or row["timed_out"] is not False
            or row.get("start_error") or hashlib.sha256(raw).hexdigest() != row["stdout_sha256"]
            or hashlib.sha256(errors).hexdigest() != row["stderr_sha256"]
            or json.loads(raw) != row.get("summary")):
        raise ValueError("native IO test execution evidence differs")
    counts = row["summary"].get("native_io")
    if counts != {"elf_requests": 119, "original_read_comparisons": 8}:
        raise ValueError("native IO retained-reference coverage differs")
    originals = report["inventory"]["original_sources"]
    return {"status": "PASS", "reference_kind": "retained original Python binary read",
            "original_read_comparisons": counts["original_read_comparisons"],
            "actual_elf_requests": counts["elf_requests"], "native_cases_added_by_replay": 0,
            "test_stdout_sha256": row["stdout_sha256"], "test_stderr_sha256": row["stderr_sha256"],
            "module_manifest_sha256": report["modules"]["native_io"]["sha256"],
            "original_sources": {name: originals[name] for name in (
                "src/mcp/runtime/binary_file.py", "src/mcp/runtime/file_metadata.py")},
            "scope": "bounded descriptor reads; persistent root custody is an explicit distinction",
            "complete_original_tool_parity": False}


def stat_version_reference_evidence(output: Path, report: dict) -> dict:
    """Bind direct original-Python execution and its separately named inverse."""
    checks = [row for row in report["checks"] if row["name"] == "test_stat_version.py"]
    if len(checks) != 1:
        raise ValueError("stat-version reference requires exactly one completed native suite")
    check = checks[0]
    stdout = (output / "test_stat_version.py.stdout").read_bytes()
    stderr = (output / "test_stat_version.py.stderr").read_bytes()
    summary = json.loads(stdout)
    if (check["exit_code"] != 0 or check["timed_out"] is not False or check.get("start_error")
            or hashlib.sha256(stdout).hexdigest() != check["stdout_sha256"]
            or hashlib.sha256(stderr).hexdigest() != check["stderr_sha256"]
            or summary != check.get("summary") or summary.get("status") != "PASS"):
        raise ValueError("stat-version test execution evidence differs")
    counts = {"native_calls": 10624, "original_version_calls": 5236, "canonical_inverse_cases": 5236,
              "domain_rejections": 66, "frame_rejections": 78, "capacity_controls": 5,
              "elf_cases": 3, "vm_cases": 8}
    folder = output / "stat-version-python-reference"
    metadata = json.loads((folder / "native-corpus.json").read_bytes())
    if (metadata.get("schema") != "hepta.runtime.stat-version-corpus.v1"
            or metadata.get("counts") != counts or summary.get("counts") != counts):
        raise ValueError("stat-version original/inverse coverage differs")
    packed = (folder / "stat-version-cases.jsonl.gz").read_bytes()
    wire = gzip.decompress(packed)
    if (hashlib.sha256(packed).hexdigest() != metadata["corpus_sha256"]
            or hashlib.sha256(wire).hexdigest() != metadata["raw_sha256"]):
        raise ValueError("stat-version captured corpus identity differs")
    rows = wire.splitlines()
    if not wire.endswith(b"\n") or len(rows) != metadata["cases"] or len(rows) != 10620:
        raise ValueError("stat-version captured call accounting differs")
    observed = {"format": 0, "inverse": 0, 0xFFFFFFFF: 0, 0xFFFFFFFE: 0, 0xFFFFFFFD: 0}
    for encoded in rows:
        row = json.loads(encoded)
        request, returned = bytes.fromhex(row["request"]), bytes.fromhex(row["output"])
        status = row["status"]
        if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
            raise ValueError("invalid stat-version captured status")
        if status in (0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD):
            if returned:
                raise ValueError("stat-version refusal corpus contains a result")
            observed[status] += 1
        else:
            if len(returned) != status or len(request) < 16 or request[:8] != b"HSTVER01":
                raise ValueError("invalid stat-version captured success")
            operation = int.from_bytes(request[8:16], "little")
            if operation not in (1, 2):
                raise ValueError("unknown stat-version successful operation")
            observed["format" if operation == 1 else "inverse"] += 1
    if observed != {"format": 5236, "inverse": 5236, 0xFFFFFFFF: 78, 0xFFFFFFFE: 4, 0xFFFFFFFD: 66}:
        raise ValueError("stat-version captured original/inverse/refusal domains differ")
    module = json.loads((output / report["modules"]["stat_version"]["manifest"]).read_bytes())
    original = report["inventory"]["original_sources"]["src/mcp/runtime/binary_file.py"]
    if (metadata["source_sha256"] != module["source_sha256"]
            or metadata["image_sha256"] != module["image_sha256"]
            or summary["source_sha256"] != module["source_sha256"]
            or metadata["original_source_sha256"] != original["sha256"]
            or summary["original_source_sha256"] != original["sha256"]):
        raise ValueError("stat-version original/native source identity differs")
    return {"status": "PASS", "reference_kind": "unchanged original Python version function",
            "original_version_calls": 5236, "canonical_inverse_cases": 5236,
            "inverse_reference": "new inverse validated by arbitrary-precision arithmetic and original-formatter roundtrip",
            "native_calls": 10624, "captured_native_cases": 10620,
            "separate_native_calls": "one exact-capacity success and three ELF comparison inputs",
            "native_cases_added_by_replay": 0, "counts": counts,
            "original_source": original, "source_sha256": module["source_sha256"],
            "image_sha256": module["image_sha256"],
            "module_manifest_sha256": report["modules"]["stat_version"]["sha256"],
            "corpus_metadata_sha256": sha(folder / "native-corpus.json"),
            "corpus_sha256": metadata["corpus_sha256"], "raw_sha256": metadata["raw_sha256"],
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "scope": "pure stat version codec; no filesystem or complete tool replacement"}


def completed_test_summary(output: Path, report: dict, name: str) -> tuple[dict, dict]:
    checks = [row for row in report["checks"] if row["name"] == name]
    if len(checks) != 1:
        raise ValueError(name + " requires exactly one completed executable suite")
    check = checks[0]
    stdout = (output / (name + ".stdout")).read_bytes()
    stderr = (output / (name + ".stderr")).read_bytes()
    summary = process_summary(name, stdout)
    if (check["exit_code"] != 0 or check["timed_out"] is not False or check.get("start_error")
            or hashlib.sha256(stdout).hexdigest() != check["stdout_sha256"]
            or hashlib.sha256(stderr).hexdigest() != check["stderr_sha256"]
            or summary != check.get("summary")):
        raise ValueError(name + " test execution evidence differs")
    return check, summary


def request_context_evidence(output: Path, report: dict) -> dict:
    return checked_request_context_evidence(ROOT, output, report, completed_test_summary)


def result_publication_evidence(output: Path, report: dict) -> dict:
    return checked_result_publication_evidence(ROOT, output, report, completed_test_summary)


def request_scope_evidence(output: Path, report: dict) -> dict:
    return checked_request_scope_evidence(ROOT, output, report, completed_test_summary)


def filesystem_parity_evidence(output: Path, report: dict) -> dict:
    value = filesystem_parity_qualification.native_evidence(ROOT, output, report, completed_test_summary)
    # Trace extents are tuples in memory; reports retain the owner's exact
    # canonical JSON value so a reloaded report compares without type drift.
    return filesystem_parity_qualification.decode(filesystem_parity_qualification.canonical(value))


def filesystem_parity_retirement(output: Path, report: dict, *, create: bool = False) -> dict:
    value = filesystem_parity_qualification.retire_fixtures(
        ROOT, output, report, completed_test_summary, create=create)
    return filesystem_parity_qualification.decode(filesystem_parity_qualification.canonical(value))


def filesystem_public_evidence(output: Path, report: dict) -> dict:
    from hia_native_filesystem_public_pipeline import native_evidence
    return native_evidence(ROOT, output, report, completed_test_summary)


def filesystem_public_retirement(output: Path, report: dict, *, create: bool = False,
                                 native: dict | None = None) -> dict:
    from hia_native_filesystem_public_pipeline import native_fixture_evidence
    return native_fixture_evidence(ROOT, output, report, completed_test_summary,
                                   create=create, native=native)


def shell_evidence(output: Path, report: dict) -> dict:
    return shell_qualification.qualification_evidence(ROOT, output, report, completed_test_summary)


SHELL_PROCESS_TESTS = (
    "shell_process_state.py", "shell_process_transport.py",
    "hia_native_shell_process_qualification.py", "shell_process_evidence_controls.py",
)
SHELL_BACKGROUND_TEST = "shell_background_text.py"
SHELL_OUTCOME_TEST = "shell_outcome_state.py"
SHELL_OUTPUT_TEST = "shell_output_io.py"
SHELL_FOREGROUND_TESTS = ("shell_foreground_controller.py", "shell_foreground_io.py")


def shell_io_progress_records(name: str, stdout: bytes) -> list[dict]:
    """Admit the complete serial progress protocol, including its final report."""
    output_io = name in (SHELL_OUTPUT_TEST, "shell-output-native")
    if not output_io and name not in (SHELL_FOREGROUND_TESTS[1], "shell-foreground-native"):
        raise ValueError("unknown shell IO progress suite")
    module = _shell_test_module(SHELL_OUTPUT_TEST if output_io else SHELL_FOREGROUND_TESTS[1])
    specifications = module.specs() if output_io else module.specifications()
    names = [row["name"] for row in specifications]
    count = 20 if output_io else 12
    if len(names) != count or len(set(names)) != count:
        raise ValueError("registered shell IO progress inventory differs")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate shell IO progress field")
            result[key] = value
        return result

    def nonfinite(_):
        raise ValueError("nonfinite shell IO progress value")

    rows = [json.loads(line, object_pairs_hook=unique_object, parse_constant=nonfinite)
            for line in stdout.splitlines()]
    if len(rows) != count + 1:
        raise ValueError("shell IO progress omitted or added a record")
    fields = {"case", "status", "effects", "outcome"} if output_io else {"case", "status"}
    expected_status = "NATIVE_IO_PASS" if output_io else "ACTUAL_NATIVE_PASS"
    for expected_name, row in zip(names, rows[:-1]):
        if (type(row) is not dict or set(row) != fields
                or row.get("case") != expected_name or row.get("status") != expected_status):
            raise ValueError("shell IO progress case/order/status differs")
        if output_io and (type(row["effects"]) is not int or row["effects"] < 1
                          or type(row["outcome"]) is not bool):
            raise ValueError("shell IO progress effect/outcome type differs")
    summary = rows[-1]
    schema = "hepta.runtime.shell-output-io-read.v1" if output_io else "hepta.runtime.shell-foreground-io-read.v1"
    if (type(summary) is not dict or summary.get("schema") != schema or summary.get("status") != "PASS"
            or type(summary.get("cases")) is not int or summary["cases"] != count
            or summary.get("complete_registered_corpus") is not True
            or type(summary.get("retired_fixtures")) is not int or summary["retired_fixtures"] != count
            or summary.get("actual_native_process_wait") is not (not output_io)
            or type(summary.get("native_phase_cases_added_by_reference")) is not int
            or summary["native_phase_cases_added_by_reference"] != 0):
        raise ValueError("shell IO aggregate progress differs")
    if output_io and (summary.get("io_only") is not False
                      or type(summary.get("effects")) is not int
                      or summary["effects"] != sum(row["effects"] for row in rows[:-1])):
        raise ValueError("shell IO aggregate effects/scope differs")
    return rows


def bind_shell_io_progress(output: Path, name: str, evidence: dict, cases: list[dict]) -> None:
    rows = shell_io_progress_records(name, (output / (name + ".stdout")).read_bytes())
    if json_bytes(rows[-1]) != json_bytes(evidence):
        raise ValueError("shell IO final stdout differs from complete retained evidence")
    if json_bytes(rows[:-1]) != json_bytes(cases):
        raise ValueError("shell IO case stdout differs from complete retained evidence")


def _shell_test_module(name: str):
    import importlib.util
    path = ROOT / "tests/hia_native" / name
    spec = importlib.util.spec_from_file_location("shell_gate_" + name.removesuffix(".py"), path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load source-owned shell qualification module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def shell_process_test_commands(output: Path, report: dict) -> dict[str, list[str]]:
    manifest = output / report["modules"]["shell_process"]["manifest"]
    background = output / report["modules"]["shell_background_text"]["manifest"]
    base = output / "shell-process"
    prefix = [sys.executable, "-I", "-B"]
    return {
        SHELL_PROCESS_TESTS[0]: prefix + [str(ROOT / "tests/hia_native/shell_process_state.py"),
            "--native-manifest", str(manifest), "--output", str(base / "state")],
        SHELL_PROCESS_TESTS[1]: prefix + [str(ROOT / "tests/hia_native/shell_process_transport.py"),
            "--native-manifest", str(manifest), "--output", str(base / "transport")],
        SHELL_PROCESS_TESTS[2]: prefix + [str(ROOT / "scripts/hia_native_shell_process_qualification.py"),
            "--native-executable", str(manifest.parent / "shell-process.elf"),
            "--native-manifest", str(manifest),
            "--cases-source", str(ROOT / "tests/hia_native/shell_process_cases.py"),
            "--output", str(base / "native-os"), "--jobs", "2"],
        SHELL_PROCESS_TESTS[3]: prefix + [str(ROOT / "tests/hia_native/shell_process_evidence_controls.py"),
            "--evidence", str(base / "native-os"), "--native-manifest", str(manifest),
            "--output", str(base / "evidence"), "--native-only"],
        SHELL_BACKGROUND_TEST: prefix + [str(ROOT / "tests/hia_native/shell_background_text.py"),
            "--native-manifest", str(background),
            "--output", str(output / "shell-background-text/native")],
    }


def shell_outcome_test_commands(output: Path, report: dict) -> dict[str, list[str]]:
    manifest = output / report["modules"]["shell_outcome"]["manifest"]
    return {SHELL_OUTCOME_TEST: [sys.executable, "-I", "-B",
        str(ROOT / "tests/hia_native/shell_outcome_state.py"),
        "--native-manifest", str(manifest), "--output", str(output / "shell-outcome/native")]}


def shell_output_test_commands(output: Path, report: dict) -> dict[str, list[str]]:
    manifest = output / report["modules"]["shell_output_io"]["manifest"]
    outcome = output / report["modules"]["shell_outcome"]["manifest"]
    return {SHELL_OUTPUT_TEST: [sys.executable, "-I", "-B",
        str(ROOT / "tests/hia_native/shell_output_io.py"),
        "--native-manifest", str(manifest), "--outcome-manifest", str(outcome),
        "--output", str(output / "shell-output/native")]}


def shell_foreground_test_commands(output: Path, report: dict) -> dict[str, list[str]]:
    manifest = output / report["modules"]["shell_foreground"]["manifest"]
    return {name: [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name),
                  "--native-manifest", str(manifest),
                  "--output", str(output / "shell-foreground" / folder)]
            for name, folder in zip(SHELL_FOREGROUND_TESTS, ("state", "native"))}


def shell_process_progress_summary(stdout: bytes, *, original: bool) -> dict:
    module = _shell_test_module("shell_process_cases.py")
    names = {row["name"] for row in module.specs()}
    if len(names) != 38:
        raise ValueError("required real-OS shell case inventory changed")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate real-OS shell progress field")
            result[key] = value
        return result
    rows = [json.loads(line, object_pairs_hook=unique_object) for line in stdout.splitlines()]
    if len(rows) != len(names) + 1:
        raise ValueError("real-OS shell progress omitted or added a record")
    seen = set()
    for row in rows[:-1]:
        if (type(row) is not dict or set(row) != {"name", "status", "duration_ns", "error"}
                or row.get("name") not in names or row["name"] in seen
                or row.get("status") != "PASS" or row.get("error") is not None
                or type(row.get("duration_ns")) is not int or row["duration_ns"] < 0):
            raise ValueError("real-OS shell progress contains an incomplete case")
        seen.add(row["name"])
    summary = rows[-1]
    expected = "ORIGINAL_COMPARISON_PASS" if original else "NATIVE_ONLY_PASS"
    if (seen != names or type(summary) is not dict or set(summary) != {"status", "case_count", "report"}
            or summary.get("status") != expected or type(summary.get("case_count")) is not int
            or summary["case_count"] != 38 or type(summary.get("report")) is not str
            or not Path(summary["report"]).is_absolute()):
        raise ValueError("real-OS shell aggregate progress differs")
    return summary


def shell_completed_process(output: Path, report: dict, name: str, command: list[str],
                            *, phase: str, timeout: int, status: str = "PASS") -> dict:
    import math
    row, summary = completed_test_summary(output, report, name)
    stdout = (output / (name + ".stdout")).read_bytes()
    stderr = (output / (name + ".stderr")).read_bytes()
    elapsed = row.get("elapsed_seconds")
    if (row.get("command") != command or row.get("phase") != phase
            or type(row.get("exit_code")) is not int or row["exit_code"] != 0
            or "start_error" in row or row.get("timed_out") is not False
            or type(row.get("timeout_seconds")) not in (int, float)
            or row["timeout_seconds"] != timeout
            or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0
            or type(row.get("stdout_bytes")) is not int or row["stdout_bytes"] != len(stdout)
            or type(row.get("stderr_bytes")) is not int or row["stderr_bytes"] != 0 or stderr
            or type(summary) is not dict or summary.get("status") != status):
        raise ValueError("shell qualification process invocation or completion differs: " + name)
    if name in (SHELL_PROCESS_TESTS[2], "shell-process-rust-compare"):
        expected_report = Path(command[command.index("--output") + 1]) / "report.json"
        if summary.get("report") != str(expected_report):
            raise ValueError("shell real-OS stdout reports a different output directory")
    return {key: row[key] for key in ("name", "phase", "command", "exit_code", "timed_out",
            "timeout_seconds", "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256")}


def retire_shell_process_native(output: Path, report: dict) -> None:
    import hia_native_shell_process_evidence as evidence
    command = shell_process_test_commands(output, report)[SHELL_PROCESS_TESTS[2]]
    shell_completed_process(output, report, SHELL_PROCESS_TESTS[2], command,
        phase="native_components", timeout=180, status="NATIVE_ONLY_PASS")
    manifest = output / report["modules"]["shell_process"]["manifest"]
    evidence.retire_fixtures(output / "shell-process/native-os", manifest)


def shell_retained_files(output: Path, folders: tuple[Path, ...]) -> dict[str, str]:
    """Only sealed ordinary evidence enters the aggregate; fixture targets retire first."""
    result = {}
    for folder in folders:
        if folder.is_symlink() or folder.resolve(strict=True) != folder.absolute():
            raise ValueError("shell evidence root crosses a symlink")
        for path in sorted(folder.rglob("*")):
            if path.is_symlink() or path.resolve() != path.absolute():
                raise ValueError("unretired shell fixture or evidence symlink")
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("shell evidence is not an owned ordinary file")
            result[path.relative_to(output).as_posix()] = sha(path)
    return result


def shell_process_evidence(output: Path, report: dict) -> dict:
    import hia_native_shell_process_evidence as evidence
    manifest = output / report["modules"]["shell_process"]["manifest"]
    base = output / "shell-process"
    commands = shell_process_test_commands(output, report)
    completed = {
        name: shell_completed_process(output, report, name, commands[name],
            phase="native_components", timeout=180,
            status="NATIVE_ONLY_PASS" if name == SHELL_PROCESS_TESTS[2] else "PASS")
        for name in SHELL_PROCESS_TESTS
    }
    state_module = _shell_test_module("shell_process_state.py")
    state = state_module.read_evidence(base / "state", manifest)
    if ((state.get("cases"), state.get("controls"), state.get("entries"),
         state.get("reader_control_count")) != (23, 14, 304, 5)):
        raise ValueError("shell state native coverage differs")
    state_report = json.loads((base / "state/report.json").read_bytes())
    if (state_report.get("recorded_directory") != str(base / "state")
            or state_report["native"]["supplied_manifest_path"] != str(manifest)):
        raise ValueError("shell state evidence was relocated without its strong path binding")
    transport_module = _shell_test_module("shell_process_transport.py")
    transport = transport_module.read_evidence(base / "transport", manifest)
    if transport.get("cases") != 6:
        raise ValueError("shell transport and descendant custody coverage differs")
    transport_report = json.loads((base / "transport/report.json").read_bytes())
    if (transport_report["native"]["manifest_path"] != str(manifest)
            or transport_report["native"]["executable_path"] != str(manifest.parent / "shell-process.elf")):
        raise ValueError("shell transport executable path differs")
    for case in transport_report["cases"]:
        directory = base / "transport" / case["name"]
        receipt = json.loads((directory / "process.json").read_bytes())
        if (receipt["cwd"] != str(directory)
                or receipt["argv"] != [str(manifest.parent / "shell-process.elf"),
                                       "--process-fixture", str(directory / "capture")]):
            raise ValueError("shell transport receipt path differs")
    native = evidence.read_native_evidence(base / "native-os", manifest, require_full=True)
    if native.get("fixtures_retired") is not True:
        raise ValueError("shell native fixtures must be strongly retired before admission")
    controls_module = _shell_test_module("shell_process_evidence_controls.py")
    controls = controls_module.read_evidence(base / "evidence", manifest)
    metadata = json.loads(manifest.read_bytes())
    build_root = manifest.parent.parent
    artifacts = shell_retained_files(output, (
        manifest.parent, (build_root / metadata["owner_manifest"]).parent,
        (build_root / metadata["packer_manifest"]).parent))
    corpus = shell_retained_files(output, (base,))
    return {
        "schema": "hepta.runtime.shell-process-required-native.v1", "status": "PASS",
        "state": state, "transport": transport, "real_os": native, "evidence_controls": controls,
        "completed_processes": completed, "artifact_sha256": artifacts, "corpus_sha256": corpus,
        "original_rust_compared": False, "production_shell_execution_qualified": False,
        "whole_runtime_replaced": False, "production_activated": False, "old_stack_removal_qualified": False,
    }


def shell_background_evidence(output: Path, report: dict) -> dict:
    manifest = output / report["modules"]["shell_background_text"]["manifest"]
    folder = output / "shell-background-text/native"
    command = shell_process_test_commands(output, report)[SHELL_BACKGROUND_TEST]
    completed = shell_completed_process(output, report, SHELL_BACKGROUND_TEST, command,
        phase="native_components", timeout=180)
    module = _shell_test_module("shell_background_text.py")
    result = module.read_evidence(folder, manifest)
    if result.get("counts") != {
            "capacity_refusals": 14, "controls": 51, "exact_capacity_successes": 6,
            "invalid_controls": 31, "native_entries": 3507, "semantic_cases": 3456}:
        raise ValueError("background native semantic/control coverage differs")
    captured = json.loads((folder / "report.json").read_bytes())
    if (captured.get("recorded_directory") != str(folder)
            or captured["native"]["manifest_path"] != str(manifest)):
        raise ValueError("background evidence was relocated without its strong path binding")
    return {
        "schema": "hepta.runtime.shell-background-required-native.v1", "status": "PASS",
        "native": result, "completed_process": completed,
        "artifact_sha256": shell_retained_files(output, (manifest.parent,)),
        "corpus_sha256": shell_retained_files(output, (folder,)),
        "original_rust_compared": False, "filesystem_reads_qualified": False,
        "whole_runtime_replaced": False, "production_activated": False, "old_stack_removal_qualified": False,
    }


def shell_outcome_evidence(output: Path, report: dict) -> dict:
    manifest = output / report["modules"]["shell_outcome"]["manifest"]
    folder = output / "shell-outcome/native"
    command = shell_outcome_test_commands(output, report)[SHELL_OUTCOME_TEST]
    completed = shell_completed_process(output, report, SHELL_OUTCOME_TEST, command,
        phase="native_components", timeout=180)
    result = _shell_test_module(SHELL_OUTCOME_TEST).read_evidence(folder, native_manifest=manifest)
    if result.get("status") != "PASS" or result.get("counts", {}).get("semantic_cases") != 78083:
        raise ValueError("complete shell outcome native semantic/control evidence differs")
    captured = json.loads((folder / "report.json").read_bytes())
    if (captured.get("recorded_directory") != str(folder)
            or captured.get("native", {}).get("manifest_path") != str(manifest)):
        raise ValueError("shell outcome evidence path or current build binding differs")
    return {
        "schema": "hepta.runtime.shell-outcome-required-native.v1", "status": "PASS",
        "native": result, "completed_process": completed,
        "artifact_sha256": shell_retained_files(output, (manifest.parent,)),
        "corpus_sha256": shell_retained_files(output, (folder,)),
        "original_rust_compared": False, "filesystem_reads_qualified": False,
        "whole_runtime_replaced": False, "production_activated": False,
        "production_shell_execution_qualified": False, "old_stack_removal_qualified": False,
    }


def shell_output_evidence(output: Path, report: dict) -> dict:
    manifest = output / report["modules"]["shell_output_io"]["manifest"]
    outcome = output / report["modules"]["shell_outcome"]["manifest"]
    folder = output / "shell-output/native"
    command = shell_output_test_commands(output, report)[SHELL_OUTPUT_TEST]
    completed = shell_completed_process(output, report, SHELL_OUTPUT_TEST, command,
        phase="native_components", timeout=180)
    result = _shell_test_module(SHELL_OUTPUT_TEST).read_evidence(
        folder, native_manifest=manifest, outcome_manifest=outcome, require_full=True)
    if (result.get("schema") != "hepta.runtime.shell-output-io-read.v1"
            or result.get("status") != "PASS" or result.get("cases") != 20
            or result.get("complete_registered_corpus") is not True
            or result.get("shared_original_io_cases") != 6
            or result.get("io_only") is not False or result.get("retired_fixtures") != 20
            or result.get("native_phase_cases_added_by_reference") != 0
            or result.get("actual_native_process_wait") is not False):
        raise ValueError("complete shell output IO and actual outcome evidence differs")
    captured = json.loads((folder / "report.json").read_bytes())
    if (captured.get("producer_folder") != str(folder)
            or captured.get("native_manifest") != str(manifest)
            or captured.get("outcome_manifest") != str(outcome)):
        raise ValueError("shell output evidence path or current builds differ")
    progress = []
    for case in captured["cases"]:
        retained = json.loads((folder / "cases" / case["name"] / "result.json").read_bytes())
        progress.append({"case": case["name"], "status": "NATIVE_IO_PASS",
                         "effects": retained["validation"]["effects"],
                         "outcome": retained["outcome"] is not None})
    bind_shell_io_progress(output, SHELL_OUTPUT_TEST, result, progress)
    metadata = json.loads(manifest.read_bytes())
    build_root = manifest.parent.parent
    artifacts = shell_retained_files(output, (
        manifest.parent, (build_root / metadata["owner_manifest"]).parent,
        (build_root / metadata["packer_manifest"]).parent, outcome.parent))
    return {
        "schema": "hepta.runtime.shell-output-required-native.v1", "status": "PASS",
        "native": result, "completed_process": completed,
        "artifact_sha256": artifacts, "corpus_sha256": shell_retained_files(output, (folder,)),
        "original_rust_compared": False, "actual_native_process_wait": False,
        "native_phase_cases_added_by_reference": 0,
        "whole_runtime_replaced": False, "production_activated": False,
        "production_shell_execution_qualified": False, "old_stack_removal_qualified": False,
    }


def shell_foreground_evidence(output: Path, report: dict) -> dict:
    manifest = output / report["modules"]["shell_foreground"]["manifest"]
    completed = {name: shell_completed_process(output, report, name, command,
        phase="native_components", timeout=180)
        for name, command in shell_foreground_test_commands(output, report).items()}
    state_folder = output / "shell-foreground/state"
    native_folder = output / "shell-foreground/native"
    state = _shell_test_module(SHELL_FOREGROUND_TESTS[0]).read_evidence(state_folder, native_manifest=manifest)
    native = _shell_test_module(SHELL_FOREGROUND_TESTS[1]).read_evidence(
        native_folder, native_manifest=manifest, require_full=True)
    captured = json.loads((state_folder / "report.json").read_bytes())
    counts = captured.get("counts", {})
    if (state.get("status") != "PASS"
            or captured.get("schema") != "hepta.runtime.shell-foreground-controller-corpus.v1"
            or captured.get("recorded_directory") != str(state_folder)
            or captured.get("native", {}).get("manifest_path") != str(manifest)
            or any(type(counts.get(key)) is not int for key in (
                "semantic_cases", "native_control_cases", "actual_native_entries",
                "complete_guarded_buffer_snapshots"))
            or counts != {"semantic_cases": 20, "native_control_cases": 84,
                          "actual_native_entries": 810,
                          "complete_guarded_buffer_snapshots": 4860}):
        raise ValueError("complete HIA foreground controller state evidence differs")
    if (native.get("schema") != "hepta.runtime.shell-foreground-io-read.v1"
            or native.get("status") != "PASS" or native.get("complete_registered_corpus") is not True
            or type(native.get("cases")) is not int or type(native.get("retired_fixtures")) is not int
            or native.get("cases") != 12 or native.get("retired_fixtures") != 12
            or native.get("shared_original_io_cases") != 6
            or native.get("actual_native_process_wait") is not True
            or native.get("native_phase_cases_added_by_reference") != 0):
        raise ValueError("complete real foreground wait/IO/outcome evidence differs")
    progress = [{"case": case["name"], "status": "ACTUAL_NATIVE_PASS"}
                for case in _shell_test_module(SHELL_FOREGROUND_TESTS[1]).specifications()]
    bind_shell_io_progress(output, SHELL_FOREGROUND_TESTS[1], native, progress)
    metadata = json.loads(manifest.read_bytes())
    build_root = manifest.parent.parent
    folders = [manifest.parent, (build_root / metadata["controller_manifest"]).parent,
               (build_root / metadata["packer_manifest"]).parent]
    for field, key in (("process_manifest", "shell_process"),
                       ("output_manifest", "shell_output_io"),
                       ("outcome_manifest", "shell_outcome")):
        dependency = output / report["modules"][key]["manifest"]
        if (metadata.get(field) != str(dependency)
                or metadata.get(field + "_sha256") != sha(dependency)):
            raise ValueError("foreground component dependency differs from this same gate: " + key)
        folders.append(dependency.parent)
        if key in ("shell_process", "shell_output_io"):
            component = json.loads(dependency.read_bytes())
            component_root = dependency.parent.parent
            folders.extend((component_root / component[name]).parent
                           for name in ("owner_manifest", "packer_manifest"))
    return {
        "schema": "hepta.runtime.shell-foreground-required-native.v1", "status": "PASS",
        "state": state, "native": native, "completed_processes": completed,
        "artifact_sha256": shell_retained_files(output, tuple(folders)),
        "corpus_sha256": shell_retained_files(output, (state_folder, native_folder)),
        "actual_native_process_wait": True, "original_rust_compared": False,
        "native_phase_cases_added_by_reference": 0,
        "capture_preparation_qualified": False, "background_registry_qualified": False,
        "whole_runtime_replaced": False, "production_activated": False,
        "production_shell_execution_qualified": False, "old_stack_removal_qualified": False,
    }


def entropy_evidence(output: Path, report: dict) -> dict:
    return checked_entropy_evidence(ROOT, output, report, completed_test_summary)


def caller_authority_evidence(output: Path, report: dict) -> dict:
    return checked_authority_evidence(ROOT, output, report, completed_test_summary)


def operation_scope_evidence(output: Path, report: dict) -> dict:
    return checked_scope_evidence(ROOT, output, report, completed_test_summary)


def editable_content_evidence(output: Path, report: dict) -> dict:
    return checked_editable_evidence(ROOT, output, report, completed_test_summary)


def line_verify_evidence(output: Path, report: dict) -> dict:
    return checked_line_verify_evidence(ROOT, output, report, completed_test_summary)


def batch_edit_params_evidence(output: Path, report: dict) -> dict:
    from hia_native_batch_edit_params_pipeline import native_evidence
    return native_evidence(ROOT, output, report, completed_test_summary)


def batch_plan_input_evidence(output: Path, report: dict) -> dict:
    from hia_native_batch_plan_input_pipeline import native_evidence
    return native_evidence(ROOT, output, report, completed_test_summary)


def batch_diff_evidence(output: Path, report: dict) -> dict:
    from hia_native_batch_diff_pipeline import native_evidence
    return native_evidence(ROOT, output, report, completed_test_summary)



def batch_plan_evidence(output: Path, report: dict) -> dict:
    hepta = Path(report["compiler_checkout"]).resolve(strict=True)
    bootstrap = json.loads((output / "build/bootstrap/bootstrap.json").read_bytes())
    if check_dependency(hepta) != bootstrap.get("dependency"):
        raise ValueError("batch source parser differs from the actual pinned compiler checkout")
    evidence = checked_batch_plan_evidence(ROOT, output, report, completed_test_summary, hepta=hepta)
    bundle = output / report["modules"]["batch_plan"]["manifest"]
    manifest = json.loads(bundle.read_bytes())
    build = output / "build"
    composition = build / manifest["composition"]["manifest"]
    packed = json.loads(composition.read_bytes())
    directories = {bundle.parent, composition.parent}
    directories.update((build / row["manifest"]).parent for row in manifest["wide_modules"])
    directories.update(build / "modules" / ("composition-" + row["source_sha256"][:24])
                       for row in (packed["packer"], *packed["members"]))
    artifacts = {}
    for directory in sorted(directories):
        for path in sorted(directory.iterdir()):
            if path.is_symlink() or not path.is_file() or path.resolve() != path:
                raise ValueError("batch retained artifact is not a regular owned file")
            artifacts[path.relative_to(output).as_posix()] = sha(path)
    corpus = {BATCH_PLAN_FOLDER + "/" + name: sha(output / BATCH_PLAN_FOLDER / name)
              for name in ("native-corpus.json", "requests.bin.gz", "native-output.bin.gz",
                           "history.jsonl.gz", "elf-observation.json")}
    return {**evidence, "artifact_sha256": artifacts, "corpus_sha256": corpus}


def batch_apply_test_commands(output: Path, bundle: Path) -> dict[str, list[str]]:
    folder = output / "batch-apply"
    prefix = lambda name: [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name)]
    return {
        "test_batch_apply.py": prefix("test_batch_apply.py") + ["--bundle", str(bundle),
            "--corpus", str(folder / "corpus")],
        "test_batch_apply_contract.py": prefix("test_batch_apply_contract.py") + ["--bundle", str(bundle),
            "--result", str(folder / "contract.json")],
        "test_batch_apply_artifacts.py": prefix("test_batch_apply_artifacts.py") + ["--bundle", str(bundle),
            "--output", str(folder / "artifacts")],
        "test_batch_apply_evidence.py": prefix("test_batch_apply_evidence.py") + ["--bundle", str(bundle),
            "--corpus", str(folder / "corpus"), "--contract", str(folder / "contract.json"),
            "--artifacts", str(folder / "artifacts"), "--result", str(folder / "evidence-controls.json")],
    }


def batch_apply_evidence(output: Path, report: dict) -> dict:
    q = batch_apply_qualification
    hepta = Path(report["compiler_checkout"]).resolve(strict=True)
    bootstrap = json.loads((output / "build/bootstrap/bootstrap.json").read_bytes())
    if check_dependency(hepta) != bootstrap.get("dependency"):
        raise ValueError("batch application source parser differs from the pinned compiler checkout")
    bundle = output / report["modules"]["batch_apply"]["manifest"]
    folder = output / "batch-apply"
    raw = q.evidence(folder / "corpus", folder / "contract.json", folder / "artifacts", bundle,
                     source_root=ROOT, hepta=hepta)
    receipts = (
        ("test_batch_apply.py", folder / "corpus/native-corpus.json", {"rows", "controls"}),
        ("test_batch_apply_contract.py", folder / "contract.json", {"rows", "wire_hex", "success_hex"}),
        ("test_batch_apply_artifacts.py", folder / "artifacts/result.json",
            {"joined_cases", "source_contract", "joined_loaded_artifacts"}),
        ("test_batch_apply_evidence.py", folder / "evidence-controls.json", {"execution_source_pins"}),
    )
    commands = batch_apply_test_commands(output, bundle)
    completed = {}
    for name, path, omitted in receipts:
        check, summary = completed_test_summary(output, report, name)
        retained = q.json_file(path)
        if (q.canonical(summary) != q.canonical({k: v for k, v in retained.items() if k not in omitted})
                or check.get("command") != commands[name] or check.get("timeout_seconds") != 180
                or type(check.get("elapsed_seconds")) not in (int, float)
                or not 0 < check["elapsed_seconds"] < 180
                or check.get("stdout_bytes") != (output / (name + ".stdout")).stat().st_size
                or check.get("stderr_bytes") != (output / (name + ".stderr")).stat().st_size):
            raise ValueError("batch application retained report differs from actual completed process: " + name)
        completed[name] = {k: check[k] for k in ("command", "exit_code", "timed_out", "timeout_seconds",
            "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256")}
    controls = q.json_file(folder / "evidence-controls.json")
    expected = {"schema": "hepta.runtime.batch-apply-evidence-controls.v1", "status": "PASS",
        "accepted_complete_receipts": 1, "rejected_corruptions": 17,
        "native_calls_added": 0, "rust_calls_added": 0, "execution_source_pins": raw["source_pins"],
        "native_evidence_sha256": q.sha(q.canonical(raw))}
    if any(q.canonical(controls.get(k)) != q.canonical(v) for k, v in expected.items()):
        raise ValueError("batch application corruption controls are incomplete or changed")
    manifest = q.json_file(bundle)
    build = output / "build"
    composition = build / manifest["composition"]["manifest"]
    packed = q.json_file(composition)
    directories = {bundle.parent, composition.parent, (build / manifest["debug_probe"]["manifest"]).parent}
    directories.update((build / row["manifest"]).parent for row in manifest["wide_modules"])
    directories.update(build / "modules" / ("composition-" + row["source_sha256"][:24])
                       for row in (packed["packer"], *packed["members"]))
    artifacts = {}
    for directory in sorted(directories):
        for path in sorted(directory.iterdir()):
            q.require(path.is_file() and not path.is_symlink() and path.resolve() == path,
                      "batch application artifact is not a regular owned file")
            artifacts[path.relative_to(output).as_posix()] = sha(path)
    corpus = {}
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            q.require(not path.is_symlink() and path.resolve() == path, "batch application corpus path differs")
            corpus[path.relative_to(output).as_posix()] = sha(path)
    return {"schema": "hepta.runtime.batch-apply-completed-evidence.v1", "status": "PASS",
            "native_evidence": raw, "completed_processes": completed,
            "artifact_sha256": artifacts, "corpus_sha256": corpus,
            "complete_original_tool_parity": False, "production_activated": False,
            "whole_runtime_replaced": False}


def atomic_write_test_commands(output: Path, bundle: Path, hepta: Path) -> dict[str, list[str]]:
    folder = output / "atomic-write"
    prefix = lambda name: [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name)]
    return {
        "test_atomic_write_policy.py": prefix("test_atomic_write_policy.py") + [
            "--manifest", str(bundle.parent / "policy.json"), "--output", str(folder / "policy")],
        "test_atomic_write_kernel.py": prefix("test_atomic_write_kernel.py") + [
            "--manifest", str(bundle), "--output", str(folder / "kernel")],
        "test_atomic_write_boundary.py": prefix("test_atomic_write_boundary.py") + [
            "--manifest", str(bundle), "--hepta", str(hepta), "--build-root", str(output / "build"),
            "--output", str(folder / "boundary")],
        "test_atomic_write_evidence.py": prefix("test_atomic_write_evidence.py") + [
            "--manifest", str(bundle), "--policy", str(folder / "policy"), "--kernel", str(folder / "kernel"),
            "--boundary", str(folder / "boundary"),
            "--policy-stdout", str(output / "test_atomic_write_policy.py.stdout"),
            "--kernel-stdout", str(output / "test_atomic_write_kernel.py.stdout"),
            "--boundary-stdout", str(output / "test_atomic_write_boundary.py.stdout"),
            "--hepta", str(hepta), "--runtime", str(ROOT), "--output", str(folder / "evidence-controls")],
    }


def atomic_write_fixture_directories() -> tuple[str, ...]:
    """Live effect targets are distinct from the complete retained snapshots.

    Their symlinks, inaccessible directories and large uncompressed contents
    stay in the execution sandbox. Only these exact fixture roots are omitted
    from artifact transport, after all four actual suites have been verified.
    """
    kernel = tuple(f"atomic-write/kernel/{index:04d}-{case['name']}/fixture"
                   for index, case in enumerate(atomic_write_qualification.case_module.cases()))
    boundary = tuple("atomic-write/boundary/" + name + "/fixture" for name in (
        *(f"contract-{index:02d}" for index in range(19)),
        *("transport-" + name for name in ("empty", "short-length", "short-frame", "over-capacity",
            "empty-frame", "bad-frame", "extra-argument", "invalid-recovery")), "parent-death"))
    return kernel + boundary


def atomic_write_retained_files(output: Path, directory: Path, *, fixtures: tuple[str, ...] = ()) -> dict:
    omitted = {output / name for name in fixtures}
    files = {}
    if directory.is_symlink() or directory.resolve(strict=True) != directory:
        raise ValueError("atomic retained root crosses a symlink")
    for base, dirs, names in os.walk(directory, followlinks=False):
        dirs.sort()
        for name in list(dirs):
            path = Path(base) / name
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or path.resolve() != path:
                raise ValueError("atomic retained directory is not owned or crosses a symlink")
            if path in omitted:
                dirs.remove(name)
        for name in sorted(names):
            path = Path(base) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or path.resolve() != path:
                raise ValueError("atomic retained evidence is not an owned regular file")
            files[path.relative_to(output).as_posix()] = sha(path)
    return files


def atomic_write_retire_fixtures(output: Path, fixtures: tuple[str, ...], receipt: Path,
                                 evidence: dict, *, create: bool = False) -> dict:
    """Share the same checked target retirement with the original replay driver."""
    return atomic_write_qualification.retire_fixtures(output, fixtures, receipt, evidence, create=create)


def atomic_write_completed_process(output: Path, report: dict, name: str, command: list[str],
                                   *, phase: str = "native_components") -> dict:
    check, _ = completed_test_summary(output, report, name)
    elapsed = check.get("elapsed_seconds")
    if (check.get("command") != command or check.get("phase") != phase
            or type(check.get("exit_code")) is not int or type(check.get("stdout_bytes")) is not int
            or type(check.get("stderr_bytes")) is not int or type(check.get("timeout_seconds")) is not int
            or check["timeout_seconds"] != 180 or type(elapsed) not in (int, float) or not 0 < elapsed < 180
            or check.get("stdout_bytes") != (output / (name + ".stdout")).stat().st_size
            or check.get("stderr_bytes") != (output / (name + ".stderr")).stat().st_size
            or (output / (name + ".stderr")).read_bytes() != b""):
        raise ValueError("atomic actual invocation, output or unchanged deadline differs: " + name)
    return {key: check[key] for key in ("command", "exit_code", "timed_out", "timeout_seconds",
        "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256")}


def atomic_write_evidence(output: Path, report: dict) -> dict:
    q = atomic_write_qualification
    hepta = Path(report["compiler_checkout"]).resolve(strict=True)
    bootstrap = json.loads((output / "build/bootstrap/bootstrap.json").read_bytes())
    if check_dependency(hepta) != bootstrap.get("dependency"):
        raise ValueError("atomic source parser differs from the pinned compiler checkout")
    bundle = output / report["modules"]["atomic_write"]["manifest"]
    folder = output / "atomic-write"
    commands = atomic_write_test_commands(output, bundle, hepta)
    completed = {name: atomic_write_completed_process(output, report, name, command)
                 for name, command in commands.items()}
    native = q.evidence(bundle, folder / "policy", folder / "kernel", folder / "boundary",
        source_root=ROOT, reference_root=ROOT, hepta=hepta,
        policy_stdout=output / "test_atomic_write_policy.py.stdout",
        kernel_stdout=output / "test_atomic_write_kernel.py.stdout",
        boundary_stdout=output / "test_atomic_write_boundary.py.stdout")
    controls = q.controls_evidence(folder / "evidence-controls", native, source_root=ROOT, reference_root=ROOT,
        stdout=output / "test_atomic_write_evidence.py.stdout")
    fixtures = atomic_write_fixture_directories()
    if (folder / "retired-fixtures.json").exists():
        atomic_write_retire_fixtures(output, fixtures, folder / "retired-fixtures.json", native)
    corpus = atomic_write_retained_files(output, folder, fixtures=fixtures)
    for name in commands:
        for channel in ("stdout", "stderr"):
            relative = name + "." + channel
            corpus[relative] = sha(output / relative)
    return {"schema": "hepta.runtime.atomic-write-completed-evidence.v1", "status": "PASS",
        "native_evidence": native, "control_evidence": controls, "completed_processes": completed,
        "artifact_sha256": atomic_write_retained_files(output, bundle.parent), "corpus_sha256": corpus,
        "transient_fixture_directories": list(fixtures), "complete_original_tool_parity": False,
        "remote_ssh_parity": False, "production_activated": False, "whole_runtime_replaced": False}


def view_render_evidence(output: Path, report: dict) -> dict:
    return checked_view_evidence(ROOT, output, report, completed_test_summary)


def view_render_growth_evidence(output: Path, report: dict) -> dict:
    return checked_view_growth_evidence(ROOT, output, report, completed_test_summary, include_evidence=True)


def view_call_evidence(output: Path, report: dict) -> dict:
    from hia_native_view_call_qualification import native_evidence, qualification_evidence
    native = native_evidence(ROOT, output, report)
    return qualification_evidence(ROOT, output, report, native)


def view_search_evidence(output: Path, report: dict) -> dict:
    from hia_native_view_search_qualification import qualification_evidence
    return qualification_evidence(ROOT, output, report, completed_test_summary)


def view_regex_search_evidence(output: Path, report: dict) -> dict:
    from hia_native_view_regex_search_qualification import qualification_evidence
    return qualification_evidence(ROOT, output, report, completed_test_summary)


def view_resource_evidence(output: Path, report: dict) -> dict:
    return checked_view_resource_evidence(ROOT, output, report, completed_test_summary)


def runtime_mcp_evidence(output: Path, report: dict) -> dict:
    from hia_native_runtime_mcp_evidence import qualification_evidence
    return qualification_evidence(ROOT, output, report, completed_test_summary)


def runtime_mcp_fixture_retirement(output: Path, report: dict, *, create=False,
                                   public=None, public_search=None, public_regex_search=None) -> dict:
    from hia_native_runtime_mcp_pipeline import native_fixture_evidence
    return native_fixture_evidence(ROOT, output, report, completed_test_summary, create=create,
        native=public, literal=public_search, regex=public_regex_search)


def view_search_public_evidence(output: Path, report: dict) -> dict:
    from hia_native_view_search_public_qualification import public_native_evidence
    return public_native_evidence(ROOT, output, report, completed_test_summary)


def view_regex_search_public_evidence(output: Path, report: dict) -> dict:
    from hia_native_view_regex_search_public_qualification import qualification_evidence
    return qualification_evidence(ROOT, output, report, completed_test_summary)


def view_fixture_retirement(output: Path, report: dict, *, create=False,
                            native: dict | None = None, public: dict | None = None,
                            search: dict | None = None, public_search: dict | None = None,
                            regex_search: dict | None = None, public_regex_search: dict | None = None) -> dict:
    from hia_native_view_fixture_qualification import retire_fixtures
    native = view_call_evidence(output, report) if native is None else native
    public = runtime_mcp_evidence(output, report) if public is None else public
    search = view_search_evidence(output, report) if search is None else search
    public_search = view_search_public_evidence(output, report) if public_search is None else public_search
    regex_search = view_regex_search_evidence(output, report) if regex_search is None else regex_search
    public_regex_search = (view_regex_search_public_evidence(output, report)
                           if public_regex_search is None else public_regex_search)
    fixtures = tuple(sorted([*native['transient_fixture_directories'],
                             *search['transient_fixture_directories'],
                             *regex_search['transient_fixture_directories']]))
    return retire_fixtures(output, fixtures,
        {'view_call': native, 'view_search': search, 'runtime_mcp': public,
         'view_search_public': public_search, 'view_regex_search': regex_search,
         'view_regex_search_public': public_regex_search}, create=create)


def json_evidence(output: Path, report: dict) -> dict:
    return checked_json_evidence(ROOT, output, report, completed_test_summary)


def history_evidence(output: Path, report: dict) -> dict:
    return checked_history_evidence(ROOT, output, report, completed_test_summary)


def config_evidence(output: Path, report: dict, *, create: bool = False) -> dict:
    return config_qualification.native_evidence(ROOT, output, report, completed_test_summary, create=create)


def config_span_evidence(output: Path, report: dict) -> dict:
    from hia_native_config_span_pipeline import qualification_evidence
    return qualification_evidence(ROOT, output, report, completed_test_summary)


def config_span_fixture_retirement(output: Path, report: dict, *, create=False, native=None) -> dict:
    from hia_native_config_span_pipeline import native_fixture_evidence
    return native_fixture_evidence(ROOT, output, report, completed_test_summary, create=create, native=native)


def file_locks_evidence(output: Path, report: dict) -> dict:
    return file_lock_pipeline.qualification_evidence(ROOT, output, report, completed_test_summary, "file_locks")


def file_lock_service_evidence(output: Path, report: dict) -> dict:
    return file_lock_pipeline.qualification_evidence(ROOT, output, report, completed_test_summary, "file_lock_service")


def write_chain_evidence(output: Path, report: dict) -> dict:
    return write_chain_pipeline.qualification_evidence(ROOT, output, report, completed_test_summary)


def directory_service_evidence(output: Path, report: dict) -> dict:
    return service_pipeline.native_evidence(ROOT, output, report, completed_test_summary, "directory_service")


def workdir_service_evidence(output: Path, report: dict) -> dict:
    return service_pipeline.native_evidence(ROOT, output, report, completed_test_summary, "workdir_service")


def sdk_connection_evidence(output: Path, report: dict, *, create=False) -> dict:
    return connection_qualification.native_evidence(ROOT, output, report, completed_test_summary, create=create)


def batch_write_evidence(output: Path, report: dict) -> dict:
    return batch_write_pipeline.qualification_evidence(ROOT, output, report, completed_test_summary)


def serde_error_evidence(output: Path, report: dict) -> dict:
    return serde_error_pipeline.native_evidence(ROOT, output, report, completed_test_summary)


def result_storage_evidence(output: Path, report: dict, *, create: bool = False) -> dict:
    return storage_pipeline.native_evidence(ROOT, output, report, completed_test_summary, create=create)


def result_values_evidence(output: Path, report: dict) -> dict:
    return result_qualification.native_evidence(ROOT, output, report, completed_test_summary)


def public_registry_evidence(output: Path, report: dict, *, create=False) -> dict:
    return public_registry_qualification.native_evidence(ROOT, output, report, completed_test_summary, create=create)


def session_evidence(output: Path, report: dict) -> dict:
    return session_qualification.qualification_evidence(ROOT, output, report, completed_test_summary)


def effect_fence_evidence(output: Path, report: dict) -> dict:
    return effect_fence_qualification.qualification_evidence(ROOT, output, report)


def execution_test_commands(output: Path, report: dict) -> dict[str, list[str]]:
    q = execution_qualification
    bundle = output / report["modules"]["execution_shadow"]["manifest"]
    metadata = q.object_at(bundle)
    members = {name: output / "build" / row["manifest"] for name, row in metadata["members"].items()}
    serde = output / report["modules"]["serde_json"]["manifest"]
    original = ROOT / "tests/hia_native/execution_json_original_rows.jsonl.gz"
    folder = output / q.FOLDER
    arguments = {
        q.TESTS[0]: ["--manifest", members["core"], "--output", folder / "core"],
        q.TESTS[1]: ["--manifest", members["json"], "--serde-manifest", serde,
                    "--core-manifest", members["core"], "--output", folder / "json"],
        q.TESTS[2]: ["--manifest", members["json"], "--serde-manifest", serde,
                    "--original", original, "--output", folder / "errors"],
        q.TESTS[3]: ["--manifest", members["controller"], "--typed-manifest", members["json_composed"],
                    "--core-manifest", members["core_composed"], "--serde-manifest", serde,
                    "--original", original, "--output", folder / "controller"],
        "test_execution_evidence.py": ["--runtime", ROOT, "--hepta", report["compiler_checkout"],
                    "--manifest", bundle, "--corpus", folder, "--output", folder / "evidence-controls"],
    }
    for label, name in zip(("core", "json", "errors", "controller"), q.TESTS):
        arguments["test_execution_evidence.py"] += ["--" + label + "-stdout", output / (name + ".stdout")]
    return {name: [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name), *map(str, args)]
            for name, args in arguments.items()}


def execution_evidence(output: Path, report: dict) -> dict:
    q = execution_qualification
    owner = report["modules"]["execution_shadow"]
    if owner.get("builder") != "execution_shadow" or owner.get("source") != "native/execution_shadow.hepta":
        raise ValueError("execution owner registry differs")
    bundle = output / owner["manifest"]
    if sha(bundle) != owner["sha256"]:
        raise ValueError("execution bundle identity changed")
    folder = output / q.FOLDER
    stdout = {name: output / (name + ".stdout") for name in q.TESTS}
    native = q.checked_native(bundle, folder, source_root=ROOT,
                              hepta=Path(report["compiler_checkout"]), stdout=stdout)
    controls = q.controls_evidence(folder / "evidence-controls", native, source_root=ROOT,
                                   stdout=output / "test_execution_evidence.py.stdout")
    completed = {}
    for name, command in execution_test_commands(output, report).items():
        check, _ = completed_test_summary(output, report, name)
        if (check.get("command") != command or check.get("timeout_seconds") != 180
                or type(check.get("elapsed_seconds")) not in (int, float)
                or not 0 < check["elapsed_seconds"] < 180
                or check["stdout_bytes"] != (output / (name + ".stdout")).stat().st_size
                or check["stderr_bytes"] != 0):
            raise ValueError("execution actual completed command differs: " + name)
        completed[name] = {key: check[key] for key in ("command", "exit_code", "timed_out", "timeout_seconds",
            "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256")}
    artifacts = dict(native["artifact_sha256"])
    for path in (folder / "evidence-controls/result.json", output / "test_execution_evidence.py.stdout"):
        artifacts[path.relative_to(output).as_posix()] = sha(path)
    return {"schema": "hepta.runtime.execution-completed-evidence.v1", "status": "PASS",
            "native": native, "controls": controls, "completed_processes": completed,
            "artifact_sha256": artifacts, "production_activated": False,
            "whole_runtime_replaced": False, "old_stack_removal_qualified": False}


def view_cache_evidence(output: Path, report: dict) -> dict:
    return checked_view_cache_evidence(ROOT, output, report, completed_test_summary)


def operation_scope_os_evidence(output: Path, report: dict) -> dict:
    checks = {}
    for name, _, receipt, _, _ in SCOPE_OS_SUITES:
        check, summary = completed_test_summary(output, report, name)
        retained = json.loads((output / SCOPE_OS_FOLDER / receipt).read_bytes())
        if {key: value for key, value in retained.items() if key != "cases"} != summary:
            raise ValueError("OS scope retained observations differ from completed suite stdout: " + name)
        checks[name] = {key: check[key] for key in ("stdout_sha256", "stderr_sha256")}
    return {**checked_scope_os_evidence(ROOT, output, report), "checks": checks}


def full_io_reference_evidence(output: Path, report: dict) -> dict:
    """Retain operation-two filesystem comparisons separately from chunk reads."""
    check, summary = completed_test_summary(output, report, "test_native_full_io.py")
    counts = {"elf_requests": 123, "original_read_comparisons": 0, "original_full_read_comparisons": 63}
    if summary.get("status") != "PASS" or summary.get("native_full_io") != counts:
        raise ValueError("native full IO retained-reference coverage differs")
    originals = report["inventory"]["original_sources"]
    return {"status": "PASS", "reference_kind": "live original Python complete single-link file read",
            "actual_elf_requests": 123, "original_full_read_comparisons": 63,
            "valid_full_read_comparisons": 41, "invalid_utf8_comparisons": 22,
            "chunk_read_comparisons_added": 0, "native_cases_added_by_replay": 0,
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "module_manifest_sha256": report["modules"]["native_io"]["sha256"],
            "original_sources": {name: originals[name] for name in (
                "src/mcp/runtime/multi_read_host.py", "src/mcp/runtime/binary_file.py",
                "src/mcp/runtime/file_metadata.py")},
            "scope": "operation-two complete UTF-8 reads, link/version checks and pathname confirmation",
            "complete_original_remote_tool_parity": False}


def local_service_reference_evidence(output: Path, report: dict) -> dict:
    """Account the live original helper comparisons at the actual MCP boundary."""
    check, summary = completed_test_summary(output, report, "test_local_service.py")
    counts = {"elf_requests": 234, "original_read_comparisons": 118,
              "protocol_errors": 20, "domain_errors": 21, "native_controller_calls": 9}
    if (summary.get("schema") != "hepta.runtime.native-local-service-test.v1"
            or summary.get("status") != "pass" or summary.get("counts") != counts):
        raise ValueError("local service retained-reference coverage differs")
    capture = output / "local-service-python-reference.json"
    if json.loads(capture.read_bytes()) != summary:
        raise ValueError("local service live reference receipt differs from actual stdout")
    module = report["modules"]["local_service"]
    manifest = output / module["manifest"]
    metadata = json.loads(manifest.read_bytes())
    originals = report["inventory"]["original_sources"]
    if (sha(manifest) != module["sha256"] or summary.get("manifest_sha256") != module["sha256"]
            or summary.get("executable_sha256") != metadata.get("executable_sha256")
            or summary.get("original_helper_sha256") != originals["src/mcp/runtime/binary_file.py"]["sha256"]):
        raise ValueError("local service executable or original helper identity differs")
    return {"status": "PASS", "reference_kind": "live retained original Python binary read through native MCP",
            "original_read_comparisons": counts["original_read_comparisons"],
            "actual_elf_requests": counts["elf_requests"], "native_cases_added_by_replay": 0,
            "protocol_refusals": counts["protocol_errors"], "domain_refusals": counts["domain_errors"],
            "isolated_controller_calls": counts["native_controller_calls"],
            "controller_startup_acknowledgement": "three explicit lifecycle fixture acknowledgements; no file operation",
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "live_reference_receipt_sha256": sha(capture),
            "module_manifest_sha256": module["sha256"], "executable_sha256": metadata["executable_sha256"],
            "original_sources": {name: originals[name] for name in (
                "src/mcp/runtime/binary_file.py", "src/mcp/runtime/file_metadata.py",
                "src/mcp/runtime/binary.rs", "src/mcp/runtime/config.rs",
                "src/mcp/runtime/inspect.rs", "src/mcp/runtime/ssh.rs", "src/mcp/server.rs")},
            "scope": "explicit administrator-owned native-local read-only profile; host_list and binary_read subset",
            "complete_original_remote_tool_parity": False, "production_activated": False}


def multi_service_reference_evidence(output: Path, report: dict) -> dict:
    """Bind real composed MCP batches to live original filesystem results."""
    check, summary = completed_test_summary(output, report, "test_multi_service.py")
    counts = {"elf_requests": 101, "all_actual_elf_responses": 108,
              "original_batch_comparisons": 57, "original_failure_comparisons": 13,
              "expected_domain_refusals": 33, "expected_parameter_refusals": 11,
              "original_budget_boundary_pairs": 4}
    if (summary.get("schema") != "hepta.runtime.native-multi-service-test.v1"
            or summary.get("status") != "pass" or summary.get("counts") != counts):
        raise ValueError("multi-file service retained-reference coverage differs")
    capture = output / "multi-service-python-reference.json"
    if json.loads(capture.read_bytes()) != summary:
        raise ValueError("multi-file service live receipt differs from actual stdout")
    module = report["modules"]["local_service"]
    manifest = output / module["manifest"]
    metadata = json.loads(manifest.read_bytes())
    originals = report["inventory"]["original_sources"]
    if (sha(manifest) != module["sha256"] or summary.get("manifest_sha256") != module["sha256"]
            or summary.get("executable_sha256") != metadata.get("executable_sha256")
            or summary.get("original_helper_sha256") != originals["src/mcp/runtime/multi_read_host.py"]["sha256"]):
        raise ValueError("multi-file service executable or original helper identity differs")
    return {"status": "PASS", "reference_kind": "live original Python multi-file results through actual native MCP",
            "actual_elf_responses": 108, "batch_tool_calls": 101,
            "original_batch_success_comparisons": 57, "original_batch_failure_comparisons": 13,
            "original_budget_boundary_pairs": 4, "parameter_refusals": 11, "domain_refusals": 33,
            "native_cases_added_by_replay": 0, "synthetic_io_comparisons": 0,
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "live_reference_receipt_sha256": sha(capture),
            "module_manifest_sha256": module["sha256"], "executable_sha256": metadata["executable_sha256"],
            "original_sources": {name: originals[name] for name in (
                "src/mcp/runtime/multi_read.rs", "src/mcp/runtime/multi_read_host.py",
                "src/mcp/runtime/binary_file.py", "src/mcp/runtime/file_metadata.py",
                "src/mcp/runtime/config.rs", "src/mcp/server.rs")},
            "scope": "native-local read_multiple_files; complete UTF-8 results and exact MCP result budget",
            "complete_original_remote_tool_parity": False, "production_activated": False}


def multi_read_controller_evidence(output: Path, report: dict) -> dict:
    """Synthetic IO is a controller control, never real filesystem coverage."""
    check, summary = completed_test_summary(output, report, "test_multi_read_controller.py")
    counts = {"requests": 1747, "native_controller_calls": 1946, "native_leaf_calls": 137,
              "fixture_io_calls": 53, "original_wire_size_calls": 1,
              "original_rust_validation_cases": 1689, "actual_elf_requests": 0}
    if (summary.get("status") != "PASS" or summary.get("counts") != counts
            or summary.get("scope") != "native controller with explicitly synthetic IO completions"):
        raise ValueError("multi-read controller fixture/reference accounting differs")
    owner = report["modules"]["multi_read_service"]
    manifest = output / owner["manifest"]
    metadata = json.loads(manifest.read_bytes())
    corpus_path = output / "multi-read-rust-oracle/native-corpus.json"
    corpus = json.loads(corpus_path.read_bytes())
    if (sha(manifest) != owner["sha256"] or corpus.get("cases") != 1689
            or corpus.get("source_sha256") != metadata.get("source_sha256")
            or corpus.get("image_sha256") != metadata.get("image_sha256")):
        raise ValueError("multi-read controller corpus/image identity differs")
    return {"status": "PASS", "reference_kind": "native controller with explicit synthetic IO fixtures",
            "counts": counts, "native_cases_added_by_replay": 0,
            "module_manifest_sha256": owner["sha256"], "corpus_metadata_sha256": sha(corpus_path),
            "composition_provenance_sha256": sha(ROOT / "native/multi_read_service_composition.json"),
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "original_wire_size_source": report["inventory"]["original_sources"]["src/mcp/runtime/multi_read_host.py"],
            "actual_filesystem_comparisons": 0, "complete_original_tool_parity": False}


def operation_kdf_evidence(output: Path, report: dict) -> dict:
    """Keep primitive, original-binding, capacity and ELF observations distinct."""
    check, summary = completed_test_summary(output, report, "test_operation_kdf.py")
    counts = {"native_calls": 1378, "standard_reference_cases": 867, "original_binding_cases": 388,
              "exact_capacity_reference_cases": 7, "capacity_refusal_cases": 14, "elf_requests": 5}
    if summary.get("status") != "PASS" or summary.get("counts") != counts:
        raise ValueError("operation KDF reference/capacity accounting differs")
    folder = output / "operation-kdf-rust-oracle"
    metadata_path = folder / "native-corpus.json"
    metadata = json.loads(metadata_path.read_bytes())
    if (metadata.get("schema") != "hepta.runtime.native-operation-kdf-corpus.v1"
            or metadata.get("counts") != counts):
        raise ValueError("operation KDF corpus schema or coverage differs")
    owner = report["modules"]["operation_kdf"]
    manifest = output / owner["manifest"]
    module = json.loads(manifest.read_bytes())
    original = report["inventory"]["original_sources"]["src/mcp/runtime/operation_crypto.rs"]
    reference_names = ("oracle_operation_kdf.rs", "kdf_oracle/Cargo.toml", "kdf_oracle/Cargo.lock",
                       "kdf_oracle/build.rs", "kdf_oracle/original_access.rs")
    reference_sources = {name: sha(ROOT / "tests/hia_native" / name) for name in reference_names}
    if (sha(manifest) != owner["sha256"]
            or metadata.get("source_sha256") != module.get("source_sha256")
            or metadata.get("source_sha256") != sha(ROOT / "native/operation_kdf.hepta")
            or metadata.get("image_sha256") != module.get("image_sha256")
            or metadata.get("original_source_sha256") != original["sha256"]
            or metadata.get("composition_sha256") != sha(ROOT / "native/operation_kdf_composition.json")
            or metadata.get("oracle_sources_sha256") != reference_sources):
        raise ValueError("operation KDF original/native/oracle source identity differs")
    entry = metadata["corpus"]
    if entry.get("file") != "kdf_cases.jsonl.gz" or entry.get("cases") != 1364:
        raise ValueError("operation KDF captured corpus identity differs")
    packed = (folder / entry["file"]).read_bytes()
    wire = gzip.decompress(packed)
    if (hashlib.sha256(packed).hexdigest() != entry.get("gzip_sha256")
            or hashlib.sha256(wire).hexdigest() != entry.get("raw_sha256")
            or len(wire) != entry.get("raw_bytes") or not wire.endswith(b"\n")):
        raise ValueError("operation KDF captured corpus bytes differ")
    rows = wire.splitlines()
    if len(rows) != entry["cases"] or len(rows) + counts["capacity_refusal_cases"] != counts["native_calls"]:
        raise ValueError("operation KDF captured/native call accounting differs")
    observed = {"standard_primitive_successes": 0, "original_binding_successes": 0, "refusals": 0}
    output_hash = hashlib.sha256()
    for encoded in rows:
        row = json.loads(encoded)
        request, returned = bytes.fromhex(row["input_hex"]), bytes.fromhex(row["output_hex"])
        code = row["code"]
        if (type(code) is not int or not 0 <= code <= 0xFFFFFFFF
                or request.hex() != row["input_hex"] or returned.hex() != row["output_hex"]):
            raise ValueError("operation KDF captured status or byte encoding differs")
        if code in (0xFFFFFFFF, 0xFFFFFFFD):
            if returned:
                raise ValueError("operation KDF refusal contains output bytes")
            observed["refusals"] += 1
        else:
            if code > 8160 or code != len(returned) or len(request) < 56 or request[:8] != b"HRKDF001":
                raise ValueError("operation KDF captured success differs")
            operation = int.from_bytes(request[8:16], "little")
            if not 1 <= operation <= 9:
                raise ValueError("operation KDF successful operation is unknown")
            observed["standard_primitive_successes" if operation <= 4 else "original_binding_successes"] += 1
        output_hash.update(f"{code}:{returned.hex()}\n".encode())
    if observed != {"standard_primitive_successes": 871, "original_binding_successes": 391, "refusals": 102}:
        raise ValueError("operation KDF captured reference domains differ")
    if output_hash.hexdigest() != metadata.get("native_output_sha256"):
        raise ValueError("operation KDF captured native output digest differs")
    return {"status": "PASS", "counts": counts, "captured_native_cases": len(rows),
            "captured_domains": observed, "native_cases_added_by_replay": 0,
            "module_manifest_sha256": owner["sha256"], "source_sha256": module["source_sha256"],
            "image_sha256": module["image_sha256"], "original_source": original,
            "composition_sha256": metadata["composition_sha256"], "oracle_sources_sha256": reference_sources,
            "corpus_metadata_sha256": sha(metadata_path), "corpus_sha256": entry["gzip_sha256"],
            "input_sha256": entry["raw_sha256"], "native_output_sha256": output_hash.hexdigest(),
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "scope": "internal primitive and binding bytes with synthetic keys; no authentication or AEAD owner qualification",
            "public_mcp_key_output": False, "complete_original_crypto_scope_parity": False}


def operation_aead_evidence(output: Path, report: dict) -> dict:
    """Bind native AEAD, non-disclosure refusals and original record fixtures."""
    check, summary = completed_test_summary(output, report, "test_operation_aead.py")
    counts = {"native_calls": 1856, "encryption_reference_cases": 671, "decryption_reference_cases": 671,
              "authentication_refusals": 354, "admission_refusals": 119, "capacity_refusals": 15,
              "exact_capacity_successes": 4, "original_record_projection_cases": 33, "elf_requests": 6}
    if summary.get("status") != "PASS" or summary.get("counts") != counts:
        raise ValueError("operation AEAD reference/authentication/capacity accounting differs")
    folder = output / "operation-aead-rust-oracle"
    metadata_path = folder / "native-corpus.json"
    metadata = json.loads(metadata_path.read_bytes())
    reference = {"distribution": "cryptography", "version": "50.0.0", "algorithm": "ChaCha20Poly1305"}
    if (metadata.get("schema") != "hepta.runtime.native-operation-aead-corpus.v1"
            or metadata.get("counts") != counts or metadata.get("python_reference") != reference):
        raise ValueError("operation AEAD corpus schema or independent reference differs")
    owner = report["modules"]["operation_aead"]
    manifest = output / owner["manifest"]
    module = json.loads(manifest.read_bytes())
    original = report["inventory"]["original_sources"]["src/mcp/runtime/operation_crypto.rs"]
    reference_names = ("oracle_operation_aead.rs", "aead_oracle/Cargo.toml", "aead_oracle/Cargo.lock",
                       "aead_oracle/build.rs", "aead_oracle/original_access.rs")
    reference_sources = {name: sha(ROOT / "tests/hia_native" / name) for name in reference_names}
    if (sha(manifest) != owner["sha256"]
            or metadata.get("source_sha256") != module.get("source_sha256")
            or metadata.get("source_sha256") != sha(ROOT / "native/operation_aead.hepta")
            or metadata.get("image_sha256") != module.get("image_sha256")
            or metadata.get("original_source_sha256") != original["sha256"]
            or metadata.get("composition_sha256") != sha(ROOT / "native/operation_aead_composition.json")
            or metadata.get("oracle_sources_sha256") != reference_sources):
        raise ValueError("operation AEAD original/native/oracle source identity differs")
    entry = metadata["corpus"]
    if entry.get("file") != "aead_cases.jsonl.gz" or entry.get("cases") != 1841:
        raise ValueError("operation AEAD captured corpus identity differs")
    packed = (folder / entry["file"]).read_bytes()
    wire = gzip.decompress(packed)
    if (hashlib.sha256(packed).hexdigest() != entry.get("gzip_sha256")
            or hashlib.sha256(wire).hexdigest() != entry.get("raw_sha256")
            or len(wire) != entry.get("raw_bytes") or not wire.endswith(b"\n")):
        raise ValueError("operation AEAD captured corpus bytes differ")
    rows = wire.splitlines()
    if len(rows) != entry["cases"] or len(rows) + counts["capacity_refusals"] != counts["native_calls"]:
        raise ValueError("operation AEAD captured/native call accounting differs")
    observed = {"encryption_successes": 0, "decryption_successes": 0, "authentication_refusals": 0,
                "admission_refusals": 0, "original_record_projections": 0}
    output_hash = hashlib.sha256()
    for encoded in rows:
        row = json.loads(encoded)
        request, returned = bytes.fromhex(row["input_hex"]), bytes.fromhex(row["output_hex"])
        code = row["code"]
        if (type(code) is not int or not 0 <= code <= 0xFFFFFFFF
                or request.hex() != row["input_hex"] or returned.hex() != row["output_hex"]):
            raise ValueError("operation AEAD captured status or byte encoding differs")
        if code in (0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFC):
            if returned:
                raise ValueError("operation AEAD refusal released bytes")
            observed["authentication_refusals" if code == 0xFFFFFFFC else "admission_refusals"] += 1
        else:
            if code > 1048640 or code != len(returned) or len(request) < 88 or request[:8] != b"HRAEAD01":
                raise ValueError("operation AEAD captured success differs")
            operation = int.from_bytes(request[8:16], "little")
            if operation not in (1, 2):
                raise ValueError("operation AEAD successful operation is unknown")
            observed["encryption_successes" if operation == 1 else "decryption_successes"] += 1
        if "original_record" in row:
            if not isinstance(row["original_record"], dict):
                raise ValueError("operation AEAD original record fixture differs")
            observed["original_record_projections"] += 1
        output_hash.update(f"{code}:{returned.hex()}\n".encode())
    if observed != {"encryption_successes": 684, "decryption_successes": 684, "authentication_refusals": 354,
                    "admission_refusals": 119, "original_record_projections": 33}:
        raise ValueError("operation AEAD captured reference domains differ")
    if output_hash.hexdigest() != metadata.get("native_output_sha256"):
        raise ValueError("operation AEAD captured native output digest differs")
    return {"status": "PASS", "counts": counts, "captured_native_cases": len(rows),
            "captured_domains": observed, "native_cases_added_by_replay": 0,
            "module_manifest_sha256": owner["sha256"], "source_sha256": module["source_sha256"],
            "image_sha256": module["image_sha256"], "original_source": original,
            "composition_sha256": metadata["composition_sha256"], "oracle_sources_sha256": reference_sources,
            "python_reference": reference, "corpus_metadata_sha256": sha(metadata_path),
            "corpus_sha256": entry["gzip_sha256"], "input_sha256": entry["raw_sha256"],
            "native_output_sha256": output_hash.hexdigest(),
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "scope": "internal AEAD byte primitive and synthetic original record fixtures; no nonce or scope lifecycle ownership",
            "public_mcp_key_output": False, "complete_original_crypto_scope_parity": False,
            "constant_time_qualified": False, "compiler_stack_erasure_qualified": False}


def nonce_composition_evidence(output: Path, report: dict, tested: dict) -> dict:
    """Bind the persistent nonce fixture to its tested leaf and closed image table."""
    owner = report["nonce_composition"]
    relative = Path(owner["manifest"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("nonce composition manifest is outside the retained result")
    manifest = output / relative

    def raw_file(path: Path) -> bytes:
        if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
            raise ValueError("nonce composition artifact is not a regular owned file")
        return path.read_bytes()

    def digest(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    raw_manifest = raw_file(manifest)
    metadata = json.loads(raw_manifest)
    if (owner.get("builder") != "composition_fixture" or digest(raw_manifest) != owner["sha256"]
            or metadata.get("schema") != "hepta.runtime.native-composition.v1"
            or metadata.get("target") != "linux-x86_64" or metadata.get("transport") != "newline-json"
            or metadata.get("compiler_commit") != HEPTA_COMMIT
            or metadata.get("compiler_sha256") != report["compiler_image_sha256"]
            or metadata.get("executable") != "native-local-read.elf"
            or metadata.get("runtime_python_required") is not False
            or metadata.get("runtime_libc_required") is not False
            or metadata.get("whole_runtime_replaced") is not False):
        raise ValueError("nonce composition manifest identity or ownership differs")
    specs = (("nonce-hex-fixture", "tests/hia_native/nonce_hex_transport.hepta", 1, 2,
              8 << 20, 8 << 20, 16 << 20),
             ("operation-nonce", "native/operation_nonce.hepta", 0, 0, 164, 64, 1576960))
    profile = [{"id": i, "name": name, "source_sha256": sha(ROOT / source), "flags": flags,
                "call_mask": mask, "input_capacity": inp, "output_capacity": out,
                "workspace_capacity": work}
               for i, (name, source, flags, mask, inp, out, work) in enumerate(specs)]
    if (json_bytes(metadata.get("profile")) != json_bytes(profile)
            or type(metadata.get("members")) is not list or len(metadata["members"]) != 2):
        raise ValueError("nonce composition fixed two-image authority table differs")
    rows = [("packer", "native/composition_packer.hepta", metadata["packer"])]
    rows.extend((f"module_{i:02d}", spec[1], metadata["members"][i]) for i, spec in enumerate(specs))
    frame = bytearray(b"HIABND01" + struct.pack("<3Q", 2, 0, 0))
    for index, (stem, source_name, row) in enumerate(rows):
        if row.get("manifest") != stem + ".json":
            raise ValueError("nonce composition child manifest path differs")
        raw = raw_file(manifest.parent / row["manifest"])
        child = json.loads(raw)
        if (digest(raw) != row.get("manifest_sha256")
                or child.get("schema") != "hepta.runtime.native-module.v1"
                or child.get("abi") != "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
                or child.get("target") != "linux-x86_64" or child.get("compiler_commit") != HEPTA_COMMIT
                or child.get("compiler_sha256") != report["compiler_image_sha256"]
                or child.get("source") != stem + ".hepta" or child.get("image") != stem + ".image.bin"
                or child.get("standalone") is not None):
            raise ValueError("nonce composition child manifest or compiler differs")
        source = raw_file(manifest.parent / child["source"])
        image = raw_file(manifest.parent / child["image"])
        if (source != raw_file(ROOT / source_name) or digest(source) != child.get("source_sha256")
                or digest(source) != row.get("source_sha256") or not 0 < len(image) <= 1 << 20
                or digest(image) != child.get("image_sha256") or digest(image) != row.get("image_sha256")
                or child.get("input_capacity") != 8 << 20 or child.get("output_capacity") != 8 << 20
                or child.get("workspace_capacity") != 32 << 20):
            raise ValueError("nonce composition source/image artifact or capacity differs")
        if index == 2 and any(child.get(key) != tested.get(key)
                              for key in ("source_sha256", "image_sha256", "compiler_sha256")):
            raise ValueError("packed nonce leaf differs from the directly tested native image")
        if index:
            p = profile[index - 1]
            frame.extend(struct.pack("<8Q", len(image), p["input_capacity"], p["output_capacity"],
                                     p["workspace_capacity"], p["flags"], p["call_mask"], 0, 0))
            frame.extend(bytes.fromhex(digest(source)) + bytes.fromhex(digest(image)) + image)
    key = digest(json_bytes({"compiler": report["compiler_image_sha256"], "members": profile,
                             "packer": sha(ROOT / "native/composition_packer.hepta")}))
    executable = raw_file(manifest.parent / "native-local-read.elf")
    inspection = metadata["inspection"]
    if (metadata.get("key") != key or metadata.get("frame_sha256") != digest(frame)
            or metadata.get("frame_bytes") != len(frame) or len(frame) > 8 << 20
            or digest(executable) != metadata.get("executable_sha256")
            or inspection.get("sha256") != digest(executable) or inspection.get("bytes") != len(executable)
            or inspection.get("dynamic_loader") is not False or inspection.get("libc") is not False
            or inspection.get("interpreter") is not None
            or metadata.get("packing") != {"owner": "HIA", "input_unchanged": True,
                 "buffer_canaries_unchanged": True, "packer_image_sha256": metadata["packer"]["image_sha256"]}):
        raise ValueError("nonce composition packed frame or executable identity differs")
    return {"status": "PASS", "manifest_sha256": digest(raw_manifest),
            "source_sha256": profile[0]["source_sha256"], "executable_sha256": digest(executable),
            "frame_sha256": digest(frame), "profile": profile, "modules": metadata["members"],
            "packer": metadata["packer"], "requests": 16399, "processes": 2,
            "scope": "test-only persistent nonce leaf; no public crypto service or OS effects"}


def operation_nonce_evidence(output: Path, report: dict) -> dict:
    """Keep native state controls, persistent ELF calls and original replay distinct."""
    check, summary = completed_test_summary(output, report, "test_operation_nonce.py")
    counts = {"native_calls": 17830, "initializations": 9, "destructions": 4,
              "accepted_reservations": 17183, "nonce_refusals": 287, "admission_refusals": 325,
              "state_refusals": 13, "capacity_refusals": 9, "elf_requests": 16401,
              "elf_processes": 4, "composed_elf_requests": 16399}
    if summary != {"status": "PASS", "counts": counts}:
        raise ValueError("operation nonce state/capacity/ELF accounting differs")
    stderr = (output / "test_operation_nonce.py.stderr").read_text()
    if stderr.count("\nRan 9 tests in ") != 1 or not stderr.endswith("\nOK\n"):
        raise ValueError("operation nonce requires all nine completed executable test groups")
    folder = output / "operation-nonce-rust-oracle"
    metadata_path = folder / "native-corpus.json"
    metadata = json.loads(metadata_path.read_bytes())
    if (metadata.get("schema") != "hepta.runtime.native-operation-nonce-corpus.v1"
            or metadata.get("counts") != counts):
        raise ValueError("operation nonce corpus schema or coverage differs")
    owner = report["modules"]["operation_nonce"]
    relative = Path(owner["manifest"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("operation nonce manifest is outside the retained result")
    manifest = output / relative
    module = json.loads(manifest.read_bytes())
    original = report["inventory"]["original_sources"]["src/mcp/runtime/operation_crypto.rs"]
    reference_names = ("oracle_operation_nonce.rs", "nonce_oracle/Cargo.toml", "nonce_oracle/Cargo.lock",
                       "nonce_oracle/build.rs", "nonce_oracle/original_access.rs")
    reference_sources = {name: sha(ROOT / "tests/hia_native" / name) for name in reference_names}
    if (sha(manifest) != owner["sha256"]
            or module.get("compiler_commit") != HEPTA_COMMIT
            or module.get("compiler_sha256") != report["compiler_image_sha256"]
            or metadata.get("source_sha256") != module.get("source_sha256")
            or metadata.get("source_sha256") != sha(ROOT / "native/operation_nonce.hepta")
            or metadata.get("image_sha256") != module.get("image_sha256")
            or metadata.get("original_source_sha256") != original["sha256"]
            or metadata.get("composition_sha256") != sha(ROOT / "native/operation_nonce_composition.json")
            or metadata.get("oracle_sources_sha256") != reference_sources):
        raise ValueError("operation nonce original/native/oracle source identity differs")
    for field in ("source", "image"):
        name = Path(module[field])
        artifact = manifest.parent / name
        if (name.is_absolute() or len(name.parts) != 1 or artifact.is_symlink()
                or artifact.resolve() != artifact.absolute()
                or sha(artifact) != module[field + "_sha256"]):
            raise ValueError("operation nonce direct module artifact identity differs")
    fixture = nonce_composition_evidence(output, report, module)
    if metadata.get("composition_fixture") != {key: fixture[key] for key in
            ("source_sha256", "manifest_sha256", "executable_sha256", "requests")}:
        raise ValueError("operation nonce retained ELF fixture identity differs")
    entry = metadata["corpus"]
    if (entry.get("file") != "nonce_cases.jsonl.gz" or entry.get("cases") != 17811
            or entry.get("raw_bytes") != 6935313
            or entry.get("raw_sha256") != "04818159bcc689f78298b91766cf6352016f1acdb7ff404db0f5764f482ec63f"):
        raise ValueError("operation nonce captured corpus identity differs")
    packed = (folder / entry["file"]).read_bytes()
    if hashlib.sha256(packed).hexdigest() != entry.get("gzip_sha256"):
        raise ValueError("operation nonce captured corpus bytes differ")
    wire = gzip.decompress(packed)
    if (hashlib.sha256(wire).hexdigest() != entry["raw_sha256"]
            or len(wire) != entry["raw_bytes"] or not wire.endswith(b"\n")):
        raise ValueError("operation nonce captured corpus bytes differ")
    rows = wire.splitlines()
    if len(rows) != entry["cases"] or len(rows) + counts["capacity_refusals"] + 10 != counts["native_calls"]:
        raise ValueError("operation nonce captured/native call accounting differs")
    observed = {"initializations": 0, "destructions": 0, "accepted_reservations": 0,
                "invalid_refusals": 0, "binding_refusals": 0, "nonce_refusals": 0, "state_refusals": 0}
    refusals = {0xFFFFFFFF: "invalid_refusals", 0xFFFFFFFD: "binding_refusals",
                0xFFFFFFFC: "nonce_refusals", 0xFFFFFFFB: "state_refusals"}
    sessions = {}
    output_hash = hashlib.sha256()
    for encoded in rows:
        row = json.loads(encoded)
        if set(row) != {"session", "input_hex", "code", "count"}:
            raise ValueError("operation nonce captured row fields differ")
        session, code, count = row["session"], row["code"], row["count"]
        request = bytes.fromhex(row["input_hex"])
        if (type(session) is not str or not session or not session.isascii()
                or any(c in session for c in ":\r\n") or type(code) is not int
                or type(count) is not int or not 0 <= count <= 16384
                or request.hex() != row["input_hex"]):
            raise ValueError("operation nonce captured status, state or encoding differs")
        previous = sessions.get(session, 0)
        if code == 0:
            if len(request) < 24 or request[:8] != b"HRNONC01" or request[16:24] != bytes(8):
                raise ValueError("operation nonce captured successful frame differs")
            op = int.from_bytes(request[8:16], "little")
            if op not in (1, 2, 3) or len(request) != (164 if op == 2 else 24):
                raise ValueError("operation nonce captured successful operation differs")
            observed[{1: "initializations", 2: "accepted_reservations", 3: "destructions"}[op]] += 1
            expected = previous + 1 if op == 2 else 0
        elif code in refusals:
            observed[refusals[code]] += 1
            expected = previous
        else:
            raise ValueError("operation nonce captured refusal domain differs")
        if count != expected:
            raise ValueError("operation nonce captured state transition differs")
        sessions[session] = count
        output_hash.update(f"{session}:{code}:{count}\n".encode())
    expected_domains = {"initializations": 9, "destructions": 4, "accepted_reservations": 17183,
                        "invalid_refusals": 186, "binding_refusals": 139,
                        "nonce_refusals": 287, "state_refusals": 3}
    if observed != expected_domains or len(sessions) != 8:
        raise ValueError("operation nonce captured reference domains differ")
    if (output_hash.hexdigest() != metadata.get("native_output_sha256")
            or output_hash.hexdigest() != "28f0e89d9488aa1fca4e877f822d2fe5e7b6ba7a253ab48c2b4aaca9c7b23967"):
        raise ValueError("operation nonce captured native output digest differs")
    return {"status": "PASS", "counts": counts, "test_groups": 9, "captured_native_cases": len(rows),
            "captured_domains": observed, "sessions": len(sessions), "native_cases_added_by_replay": 0,
            "private_state_fault_controls": 10, "module_manifest_sha256": owner["sha256"],
            "source_sha256": module["source_sha256"], "image_sha256": module["image_sha256"],
            "original_source": original, "composition_sha256": metadata["composition_sha256"],
            "oracle_sources_sha256": reference_sources, "composition_fixture": fixture,
            "corpus_metadata_sha256": sha(metadata_path), "corpus_sha256": entry["gzip_sha256"],
            "input_sha256": entry["raw_sha256"], "native_output_sha256": output_hash.hexdigest(),
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "scope": "serial nonce reservation over a trusted private workspace; no entropy or production scope lifetime",
            "concurrent_scope_qualified": False, "entropy_qualified": False,
            "complete_original_crypto_scope_parity": False, "production_activated": False}


def record_composition_evidence(output: Path, report: dict) -> dict:
    """Bind the record fixture and all crypto leaves to their tested native images."""
    owner = report["modules"]["operation_record"]
    relative = Path(owner["manifest"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("record composition manifest is outside the retained result")
    manifest = output / relative

    def raw_file(path: Path) -> bytes:
        if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
            raise ValueError("record composition artifact is not a regular owned file")
        return path.read_bytes()

    def digest(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    raw_manifest = raw_file(manifest)
    metadata = json.loads(raw_manifest)
    if (owner.get("builder") != "record_composition" or digest(raw_manifest) != owner["sha256"]
            or metadata.get("schema") != "hepta.runtime.native-composition.v1"
            or metadata.get("target") != "linux-x86_64" or metadata.get("transport") != "newline-json"
            or metadata.get("compiler_commit") != HEPTA_COMMIT
            or metadata.get("compiler_sha256") != report["compiler_image_sha256"]
            or metadata.get("executable") != "native-local-read.elf"
            or metadata.get("runtime_python_required") is not False
            or metadata.get("runtime_libc_required") is not False
            or metadata.get("whole_runtime_replaced") is not False):
        raise ValueError("record composition manifest identity or ownership differs")
    specs = (("record-hex-fixture", "tests/hia_native/record_hex_transport.hepta", 1, 2,
              8 << 20, 8 << 20, 16 << 20),
             ("operation-record", "native/operation_record.hepta", 1, 28,
              8 << 20, 2 << 20, 3 << 20),
             ("operation-kdf", "native/operation_kdf.hepta", 0, 0, 8 << 20, 32, 2048),
             ("binary-codec", "native/binary_codec.hepta", 0, 0, 8 << 20, 32, 1184),
             ("operation-aead", "native/operation_aead.hepta", 0, 0, 8 << 20, 1048640, 512))
    profile = [{"id": i, "name": name, "source_sha256": sha(ROOT / source), "flags": flags,
                "call_mask": mask, "input_capacity": inp, "output_capacity": out,
                "workspace_capacity": work}
               for i, (name, source, flags, mask, inp, out, work) in enumerate(specs)]
    if (json_bytes(metadata.get("profile")) != json_bytes(profile)
            or type(metadata.get("members")) is not list or len(metadata["members"]) != 5):
        raise ValueError("record composition fixed five-image authority table differs")
    provenance = json.loads((ROOT / "native/operation_record_composition.json").read_bytes())
    provenance_sources = ("native/operation_kdf_composition.json", "native/binary_codec_composition.json",
                          "native/operation_aead_composition.json")
    if (provenance.get("schema") != "hepta.runtime.operation-record-composition.v1"
            or provenance.get("source_sha256") != profile[1]["source_sha256"]
            or provenance.get("members") != [dict(p, source=spec[1]) for p, spec in zip(profile, specs)]
            or provenance.get("compiler_commit") != HEPTA_COMMIT
            or provenance.get("compiler_sha256") != report["compiler_image_sha256"]
            or provenance.get("packer_source_sha256") != sha(ROOT / "native/composition_packer.hepta")
            or provenance.get("crypto_source_provenance") != {name: sha(ROOT / name) for name in provenance_sources}):
        raise ValueError("record composition owner/dependency source provenance differs")
    rows = [("packer", "native/composition_packer.hepta", metadata["packer"])]
    rows.extend((f"module_{i:02d}", spec[1], metadata["members"][i]) for i, spec in enumerate(specs))
    frame = bytearray(b"HIABND01" + struct.pack("<3Q", 5, 0, 0))
    record = {}
    for index, (stem, source_name, row) in enumerate(rows):
        if row.get("manifest") != stem + ".json":
            raise ValueError("record composition child manifest path differs")
        raw = raw_file(manifest.parent / row["manifest"])
        child = json.loads(raw)
        if (digest(raw) != row.get("manifest_sha256")
                or child.get("schema") != "hepta.runtime.native-module.v1"
                or child.get("abi") != "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
                or child.get("target") != "linux-x86_64" or child.get("compiler_commit") != HEPTA_COMMIT
                or child.get("compiler_sha256") != report["compiler_image_sha256"]
                or child.get("source") != stem + ".hepta" or child.get("image") != stem + ".image.bin"
                or child.get("standalone") is not None):
            raise ValueError("record composition child manifest or compiler differs")
        source = raw_file(manifest.parent / child["source"])
        image = raw_file(manifest.parent / child["image"])
        if (source != raw_file(ROOT / source_name) or digest(source) != child.get("source_sha256")
                or digest(source) != row.get("source_sha256") or not 0 < len(image) <= 1 << 20
                or digest(image) != child.get("image_sha256") or digest(image) != row.get("image_sha256")
                or child.get("input_capacity") != 8 << 20 or child.get("output_capacity") != 8 << 20
                or child.get("workspace_capacity") != 32 << 20):
            raise ValueError("record composition source/image artifact or capacity differs")
        if index == 2:
            record = child
        if index in (3, 4, 5):
            tested_key = {3: "operation_kdf", 4: "binary_codec", 5: "operation_aead"}[index]
            tested_owner = report["modules"][tested_key]
            tested_relative = Path(tested_owner["manifest"])
            if tested_relative.is_absolute() or ".." in tested_relative.parts:
                raise ValueError("record primitive manifest is outside the retained result")
            tested_path = output / tested_relative
            tested_raw = raw_file(tested_path)
            tested = json.loads(tested_raw)
            if (digest(tested_raw) != tested_owner["sha256"]
                    or any(child.get(key) != tested.get(key)
                           for key in ("source_sha256", "image_sha256", "compiler_sha256"))):
                raise ValueError("packed record crypto leaf differs from its directly tested native image")
        if index:
            p = profile[index - 1]
            frame.extend(struct.pack("<8Q", len(image), p["input_capacity"], p["output_capacity"],
                                     p["workspace_capacity"], p["flags"], p["call_mask"], 0, 0))
            frame.extend(bytes.fromhex(digest(source)) + bytes.fromhex(digest(image)) + image)
    key = digest(json_bytes({"compiler": report["compiler_image_sha256"], "members": profile,
                             "packer": sha(ROOT / "native/composition_packer.hepta")}))
    executable = raw_file(manifest.parent / "native-local-read.elf")
    inspection = metadata["inspection"]
    if (metadata.get("key") != key or metadata.get("frame_sha256") != digest(frame)
            or metadata.get("frame_bytes") != len(frame) or len(frame) > 8 << 20
            or digest(executable) != metadata.get("executable_sha256")
            or inspection.get("sha256") != digest(executable) or inspection.get("bytes") != len(executable)
            or inspection.get("dynamic_loader") is not False or inspection.get("libc") is not False
            or inspection.get("interpreter") is not None
            or metadata.get("packing") != {"owner": "HIA", "input_unchanged": True,
                 "buffer_canaries_unchanged": True, "packer_image_sha256": metadata["packer"]["image_sha256"]}):
        raise ValueError("record composition packed frame or executable identity differs")
    return {"status": "PASS", "manifest_sha256": digest(raw_manifest),
            "fixture_source_sha256": profile[0]["source_sha256"],
            "source_sha256": record["source_sha256"], "image_sha256": record["image_sha256"],
            "executable_sha256": digest(executable), "frame_sha256": digest(frame),
            "profile": profile, "modules": metadata["members"], "packer": metadata["packer"],
            "requests": 9, "processes": 1,
            "scope": "test-only record/KDF/SHA/AEAD composition; trusted scope admission and entropy remain separate"}


def operation_record_evidence(output: Path, report: dict) -> dict:
    """Bind record refusal/cleanup controls, fixed images and original domains."""
    check, summary = completed_test_summary(output, report, "test_operation_record.py")
    counts = {"requests": 978, "native_controller_calls": 3071, "native_leaf_calls": 2093,
              "aad_reference_cases": 106, "preflight_reference_cases": 3, "seal_reference_cases": 174,
              "open_reference_cases": 175, "binding_refusals": 64, "integrity_refusals": 177,
              "admission_refusals": 125, "capacity_refusals": 9, "child_contract_refusals": 140,
              "exact_capacity_successes": 5, "codec_cleanup_reference_calls": 3, "actual_elf_requests": 9}
    if summary != {"native_record_counts": counts}:
        raise ValueError("operation record refusal/capacity/continuation/ELF accounting differs")
    stderr = (output / "test_operation_record.py.stderr").read_text()
    if stderr.count("\nRan 9 tests in ") != 1 or not stderr.endswith("\nOK\n"):
        raise ValueError("operation record requires all nine completed executable test groups")
    fixture = record_composition_evidence(output, report)
    folder = output / "operation-record-rust-oracle"
    metadata_path = folder / "native-corpus.json"
    metadata = json.loads(metadata_path.read_bytes())
    reference = {"distribution": "cryptography", "version": "50.0.0",
                 "algorithms": ["ChaCha20Poly1305", "stdlib hmac SHA256", "stdlib hashlib SHA256"]}
    if (metadata.get("schema") != "hepta.runtime.native-operation-record-corpus.v1"
            or metadata.get("counts") != counts or metadata.get("python_reference") != reference):
        raise ValueError("operation record corpus schema or independent reference differs")
    original = report["inventory"]["original_sources"]["src/mcp/runtime/operation_crypto.rs"]
    reference_names = ("oracle_operation_record.rs", "record_oracle/Cargo.toml", "record_oracle/Cargo.lock",
                       "record_oracle/build.rs", "record_oracle/original_access.rs")
    reference_sources = {name: sha(ROOT / "tests/hia_native" / name) for name in reference_names}
    if (metadata.get("source_sha256") != fixture["source_sha256"]
            or metadata.get("image_sha256") != fixture["image_sha256"]
            or metadata.get("manifest_sha256") != fixture["manifest_sha256"]
            or metadata.get("composition_sources") != [row["source_sha256"] for row in fixture["profile"]]
            or metadata.get("original_source_sha256") != original["sha256"]
            or metadata.get("composition_sha256") != sha(ROOT / "native/operation_record_composition.json")
            or metadata.get("builder_sha256") != sha(ROOT / "scripts/hia_native_record_build.py")
            or metadata.get("test_sha256") != sha(ROOT / "tests/hia_native/test_operation_record.py")
            or metadata.get("oracle_sources_sha256") != reference_sources):
        raise ValueError("operation record original/native/oracle source identity differs")
    entry = metadata["corpus"]
    if (entry.get("file") != "record_cases.jsonl.gz" or entry.get("cases") != 823
            or entry.get("raw_bytes") != 53410414
            or entry.get("raw_sha256") != "086e930fd70eb8e2a78dc1f1ff313fe3ca4e1eec7312cc97f33bc661018051ec"):
        raise ValueError("operation record captured corpus identity differs")
    packed = (folder / entry["file"]).read_bytes()
    if hashlib.sha256(packed).hexdigest() != entry.get("gzip_sha256"):
        raise ValueError("operation record captured corpus bytes differ")
    wire = gzip.decompress(packed)
    if (hashlib.sha256(wire).hexdigest() != entry["raw_sha256"]
            or len(wire) != entry["raw_bytes"] or not wire.endswith(b"\n")):
        raise ValueError("operation record captured corpus bytes differ")
    rows = wire.splitlines()
    if (len(rows) != entry["cases"]
            or len(rows) + counts["capacity_refusals"] + counts["exact_capacity_successes"]
               + counts["child_contract_refusals"] + 1 != counts["requests"]
            or counts["native_controller_calls"] != counts["requests"] + counts["native_leaf_calls"]):
        raise ValueError("operation record captured/native call accounting differs")
    observed = {"aad_successes": 0, "preflight_successes": 0, "seal_successes": 0, "open_successes": 0,
                "invalid_refusals": 0, "payload_refusals": 0, "binding_refusals": 0,
                "integrity_refusals": 0, "verified_scope_rows": 0}
    output_hash = hashlib.sha256()
    for encoded in rows:
        row = json.loads(encoded)
        if set(row) not in ({"input_hex", "output_hex", "code"},
                            {"input_hex", "output_hex", "code", "verified_token_hex"}):
            raise ValueError("operation record captured row fields differ")
        request, returned = bytes.fromhex(row["input_hex"]), bytes.fromhex(row["output_hex"])
        code = row["code"]
        if (type(code) is not int or not 0 <= code <= 0xFFFFFFFF
                or request.hex() != row["input_hex"] or returned.hex() != row["output_hex"]):
            raise ValueError("operation record captured status or byte encoding differs")
        if code == 0xFFFFFFFF:
            if returned:
                raise ValueError("operation record malformed-frame refusal released bytes")
            observed["invalid_refusals"] += 1
        else:
            if (len(request) < 96 or request[:8] != b"HRREC001" or request[16:24] != bytes(8)
                    or int.from_bytes(request[8:16], "little") not in (1, 2, 3, 4)
                    or int.from_bytes(request[24:32], "little") not in (1, 2)):
                raise ValueError("operation record original-domain frame differs")
            operation = int.from_bytes(request[8:16], "little")
            at = 96
            for index in range(6):
                size = int.from_bytes(request[48 + index * 8:56 + index * 8], "little")
                if size > len(request) - at:
                    raise ValueError("operation record original-domain field span differs")
                request[at:at + size].decode("utf-8", "strict")
                at += size
            if ((operation == 1 and at != len(request)) or (operation == 2 and len(request) - at < 44)
                    or (operation == 3 and len(request) - at < 32)):
                raise ValueError("operation record original-domain tail differs")
            refusals = {0xFFFFFFFD: "payload_refusals", 0xFFFFFFFC: "binding_refusals", 0xFFFFFFFB: "integrity_refusals"}
            if code in refusals:
                if returned:
                    raise ValueError("operation record semantic refusal released bytes")
                observed[refusals[code]] += 1
            else:
                if code > 1048660 or code != len(returned):
                    raise ValueError("operation record captured success length differs")
                observed[{1: "aad_successes", 2: "seal_successes", 3: "open_successes", 4: "preflight_successes"}[operation]] += 1
        if "verified_token_hex" in row:
            token = bytes.fromhex(row["verified_token_hex"])
            if (token.hex() != row["verified_token_hex"] or not 32 <= len(token) <= 4096
                    or any(value < 33 or value > 126 for value in token)
                    or len(request) < 96 or int.from_bytes(request[8:16], "little") not in (2, 3)):
                raise ValueError("operation record verified-token fixture differs")
            observed["verified_scope_rows"] += 1
        output_hash.update(f"{code}:{returned.hex()}\n".encode())
    expected = {"aad_successes": 106, "preflight_successes": 3, "seal_successes": 174, "open_successes": 175,
                "invalid_refusals": 121, "payload_refusals": 4, "binding_refusals": 63,
                "integrity_refusals": 177, "verified_scope_rows": 6}
    if observed != expected:
        raise ValueError("operation record captured original/adapter domains differ")
    if (output_hash.hexdigest() != metadata.get("native_output_sha256")
            or output_hash.hexdigest() != "38e6a6c2eae9e5748f9f7ddf3b0cc3519a78cb5642cecd00ae53cd050287621d"):
        raise ValueError("operation record captured native output digest differs")
    return {"status": "PASS", "counts": counts, "test_groups": 9, "captured_native_cases": len(rows),
            "original_domain_rows": 702, "adapter_only_rows": 121, "captured_domains": observed,
            "extra_non_utf8_byte_refusals": 1, "native_cases_added_by_replay": 0,
            "module_manifest_sha256": fixture["manifest_sha256"],
            "source_sha256": fixture["source_sha256"], "image_sha256": fixture["image_sha256"],
            "original_source": original, "composition_sha256": metadata["composition_sha256"],
            "oracle_sources_sha256": reference_sources, "composition_fixture": fixture,
            "python_reference": reference, "corpus_metadata_sha256": sha(metadata_path),
            "corpus_sha256": entry["gzip_sha256"], "input_sha256": entry["raw_sha256"],
            "native_output_sha256": output_hash.hexdigest(),
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "scope": "internal binding/AAD and pure seal/open composition; scope capability and nonce lifetime remain separate",
            "public_mcp_key_output": False, "complete_original_crypto_scope_parity": False,
            "production_activated": False}


def native_composition_evidence(output: Path, report: dict) -> dict:
    """Recheck every image, fixed authority table and actual generic bridge suite."""
    owner = report["modules"]["local_service"]
    relative = Path(owner["manifest"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("native composition manifest path is not retained under the result")
    manifest = output / relative

    def raw_file(path: Path) -> bytes:
        if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
            raise ValueError("native composition artifact is not a regular owned file: " + str(path))
        return path.read_bytes()

    def digest(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    raw_manifest = raw_file(manifest)
    metadata = json.loads(raw_manifest)
    if (owner.get("builder") != "composition" or digest(raw_manifest) != owner["sha256"]
            or metadata.get("schema") != "hepta.runtime.native-composition.v1"
            or metadata.get("target") != "linux-x86_64" or metadata.get("transport") != "newline-json"
            or metadata.get("compiler_commit") != HEPTA_COMMIT
            or metadata.get("compiler_sha256") != report["compiler_image_sha256"]
            or metadata.get("executable") != "native-local-read.elf"
            or metadata.get("runtime_python_required") is not False
            or metadata.get("runtime_libc_required") is not False
            or metadata.get("whole_runtime_replaced") is not False):
        raise ValueError("native composition manifest identity or runtime ownership differs")
    specs = (("local-service", "native/local_service.hepta", 1, 126, 32 << 20),
             ("policy", "native/policy.hepta", 0, 0, 32 << 20),
             ("codec", "native/binary_codec.hepta", 0, 0, 32 << 20),
             ("io", "native/io_policy.hepta", 3, 4, 8 << 20),
             ("stat-version", "native/stat_version.hepta", 0, 0, 32 << 20),
             ("multi-read-service", "native/multi_read_service.hepta", 1, 30, 32 << 20),
             ("file-info-service", "native/file_info_service.hepta", 1, 30, 32 << 20))
    profile = [{"id": index, "name": name, "source_sha256": sha(ROOT / source),
                "flags": flags, "call_mask": mask, "input_capacity": 8 << 20,
                "output_capacity": 8 << 20, "workspace_capacity": workspace}
               for index, (name, source, flags, mask, workspace) in enumerate(specs)]
    if (json_bytes(metadata.get("profile")) != json_bytes(profile) or type(metadata.get("members")) is not list
            or len(metadata["members"]) != len(specs)):
        raise ValueError("native composition fixed seven-image authority table differs")
    frame = bytearray(b"HIABND01" + struct.pack("<3Q", len(specs), 0, 0))
    rows = [("packer", "native/composition_packer.hepta", metadata["packer"])]
    rows.extend((f"module_{index:02d}", spec[1], metadata["members"][index]) for index, spec in enumerate(specs))
    for index, (stem, source_name, row) in enumerate(rows):
        if row.get("manifest") != stem + ".json":
            raise ValueError("native composition child manifest path differs")
        raw = raw_file(manifest.parent / row["manifest"])
        child = json.loads(raw)
        if (digest(raw) != row["manifest_sha256"] or child.get("schema") != "hepta.runtime.native-module.v1"
                or child.get("abi") != "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
                or child.get("target") != "linux-x86_64" or child.get("compiler_commit") != HEPTA_COMMIT
                or child.get("compiler_sha256") != report["compiler_image_sha256"]
                or child.get("source") != stem + ".hepta" or child.get("image") != stem + ".image.bin"
                or child.get("standalone") is not None):
            raise ValueError("native composition child manifest or compiler differs")
        source = raw_file(manifest.parent / child["source"])
        image = raw_file(manifest.parent / child["image"])
        if (source != raw_file(ROOT / source_name) or digest(source) != child.get("source_sha256")
                or digest(source) != row.get("source_sha256") or not 0 < len(image) <= 1 << 20
                or digest(image) != child.get("image_sha256") or digest(image) != row.get("image_sha256")
                or child.get("input_capacity") != 8 << 20 or child.get("output_capacity") != 8 << 20
                or child.get("workspace_capacity") != 32 << 20):
            raise ValueError("native composition source/image artifact or capacity differs")
        if index:
            tested_key = (None, "policy", "binary_codec", "native_io", "stat_version", "multi_read_service", "file_info_service")[index - 1]
            if tested_key is not None:
                tested_owner = report["modules"][tested_key]
                tested_relative = Path(tested_owner["manifest"])
                if tested_relative.is_absolute() or ".." in tested_relative.parts:
                    raise ValueError("tested composition child manifest is outside the retained result")
                tested_path = output / tested_relative
                tested_raw = raw_file(tested_path)
                if digest(tested_raw) != tested_owner["sha256"]:
                    raise ValueError("tested composition child manifest identity differs")
                tested = json.loads(tested_raw)
                if tested_key == "native_io":
                    if tested.get("policy_manifest") != "policy.json":
                        raise ValueError("tested IO policy manifest path differs")
                    tested_raw = raw_file(tested_path.parent / "policy.json")
                    if digest(tested_raw) != tested["policy_manifest_sha256"]:
                        raise ValueError("tested IO policy manifest identity differs")
                    tested = json.loads(tested_raw)
                if (tested.get("image_sha256") != child["image_sha256"]
                        or tested.get("source_sha256") != child["source_sha256"]
                        or tested.get("compiler_sha256") != child["compiler_sha256"]):
                    raise ValueError("packed child differs from its independently tested native image")
            p = profile[index - 1]
            frame.extend(struct.pack("<8Q", len(image), p["input_capacity"], p["output_capacity"],
                                     p["workspace_capacity"], p["flags"], p["call_mask"], 0, 0))
            frame.extend(bytes.fromhex(digest(source)) + bytes.fromhex(digest(image)) + image)
    key = digest(json_bytes({"compiler": report["compiler_image_sha256"], "members": profile,
                             "packer": sha(ROOT / "native/composition_packer.hepta")}))
    executable = raw_file(manifest.parent / "native-local-read.elf")
    inspection = metadata["inspection"]
    if (metadata.get("key") != key or metadata.get("frame_sha256") != digest(frame)
            or metadata.get("frame_bytes") != len(frame) or len(frame) > 8 << 20
            or digest(executable) != metadata.get("executable_sha256")
            or inspection.get("sha256") != digest(executable) or inspection.get("bytes") != len(executable)
            or inspection.get("dynamic_loader") is not False or inspection.get("libc") is not False
            or inspection.get("interpreter") is not None
            or metadata.get("packing") != {"owner": "HIA", "input_unchanged": True,
                 "buffer_canaries_unchanged": True, "packer_image_sha256": metadata["packer"]["image_sha256"]}):
        raise ValueError("native composition packed frame or executable identity differs")
    check, summary = completed_test_summary(output, report, "test_native_composition.py")
    if summary != {"status": "PASS", "native_executions": 26, "native_frames": 39,
                   "adapter": "closed-native-multi-image"}:
        raise ValueError("native composition executable control coverage differs")
    return {"status": "PASS", "kind": "new closed native composition adapter",
            "module_manifest_sha256": digest(raw_manifest), "executable_sha256": digest(executable),
            "frame_sha256": digest(frame), "profile": profile, "modules": metadata["members"],
            "packer": metadata["packer"], "native_executions": summary["native_executions"],
            "native_frames": summary["native_frames"], "native_cases_added_by_replay": 0,
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "original_reference_recipe": None, "whole_runtime_replaced": False}


def validate_file_info_guard_times(timings) -> None:
    """Both real production holds must retain their original fixed duration."""
    import math

    if (type(timings) is not list or len(timings) != 2
            or {row.get("mode") for row in timings} != {"read", "flistxattr"}):
        raise ValueError("file-info requires both actual production deadline controls")
    for row in timings:
        elapsed, held = row.get("elapsed_seconds"), row.get("hold_seconds_until_response")
        if (set(row) != {"mode", "fixed_deadline_seconds", "elapsed_seconds", "hold_seconds_until_response"}
                or row["fixed_deadline_seconds"] != 30 or type(elapsed) not in (int, float)
                or type(held) not in (int, float) or not math.isfinite(elapsed) or not math.isfinite(held)
                or not 29.5 <= elapsed < 33 or not 0 < held <= elapsed):
            raise ValueError("file-info production deadline timing differs")


def file_info_evidence(output: Path, report: dict) -> dict:
    """Bind real deadline/filesystem receipts separately from native fixtures."""
    def owned(relative: str, expected: str | None = None) -> tuple[Path, bytes]:
        part = Path(relative)
        path = output / part
        if (part.is_absolute() or ".." in part.parts or path.is_symlink()
                or not path.is_file() or path.resolve() != path.absolute()):
            raise ValueError("file-info artifact is outside the retained owned result")
        raw = path.read_bytes()
        if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("file-info retained artifact identity differs")
        return path, raw

    summaries, receipts, checks = {}, {}, {}
    for test, name, schema, counts in FILE_INFO_SUITES:
        check, summary = completed_test_summary(output, report, test)
        if (summary.get("schema") != schema or summary.get("status") != "pass"
                or (counts is not None and json_bytes(summary.get("counts")) != json_bytes(counts))):
            raise ValueError("file-info exact test/reference/effect accounting differs: " + test)
        capture, raw = owned(name)
        if json.loads(raw) != summary:
            raise ValueError("file-info receipt differs from completed executable stdout: " + test)
        summaries[test] = summary
        receipts[name] = sha(capture)
        checks[test] = {"stdout_sha256": check["stdout_sha256"], "stderr_sha256": check["stderr_sha256"],
                        "test_source_sha256": sha(ROOT / "tests/hia_native" / test)}

    owner = report["modules"]["local_service"]
    manifest, raw = owned(owner["manifest"], owner["sha256"])
    metadata = json.loads(raw)
    if (owner.get("builder") != "composition" or len(metadata.get("members", [])) != 7
            or metadata.get("compiler_sha256") != report["compiler_image_sha256"]):
        raise ValueError("file-info requires the qualified seven-image composition")
    executable, raw_executable = owned(str(manifest.parent.relative_to(output) / metadata["executable"]),
                                     metadata["executable_sha256"])
    if not raw_executable.startswith(b"\x7fELF"):
        raise ValueError("file-info service is not the retained native executable")
    packed = {}
    packed_manifest_sha = {}
    for index in (2, 3, 6):
        row = metadata["members"][index]
        path, raw = owned(str(manifest.parent.relative_to(output) / row["manifest"]), row["manifest_sha256"])
        packed[index] = json.loads(raw)
        packed_manifest_sha[index] = sha(path)
    controller_owner = report["modules"]["file_info_service"]
    controller_path, raw = owned(controller_owner["manifest"], controller_owner["sha256"])
    controller = json.loads(raw)
    for key in ("source_sha256", "image_sha256", "compiler_sha256"):
        if controller.get(key) != packed[6].get(key):
            raise ValueError("file-info packed controller differs from its independently tested image")
    if controller.get("source_sha256") != sha(ROOT / "native/file_info_service.hepta"):
        raise ValueError("file-info controller source identity differs")
    if (packed[3].get("source_sha256") != sha(ROOT / "native/io_policy.hepta")
            or packed[2].get("source_sha256") != sha(ROOT / "native/binary_codec.hepta")):
        raise ValueError("file-info IO/codec source identity differs")
    originals = report["inventory"]["original_sources"]
    binary_sha = originals["src/mcp/runtime/binary_file.py"]["sha256"]
    metadata_sha = originals["src/mcp/runtime/file_metadata.py"]["sha256"]
    for name in ("test_info_service.py", "test_file_info_io_faults.py", "test_file_info_guard.py"):
        summary = summaries[name]
        if (summary.get("manifest_sha256") != owner["sha256"]
                or summary.get("executable_sha256") != metadata["executable_sha256"]
                or summary.get("original_helper_sha256") != binary_sha):
            raise ValueError("file-info live executable or original source receipt differs: " + name)
    normal = summaries["test_info_service.py"]
    fixture = summaries["test_file_info_controller.py"]
    state = summaries["test_file_info_io_state.py"]
    deadline_state = summaries["test_file_info_deadline_state.py"]
    faults = summaries["test_file_info_io_faults.py"]
    guard = summaries["test_file_info_guard.py"]
    probe = summaries["test_native_deadline_probe.py"]
    if (normal.get("original_metadata_sha256") != metadata_sha
            or fixture.get("original_metadata_sha256") != metadata_sha
            or fixture.get("source_sha256") != controller["source_sha256"]
            or fixture.get("image_sha256") != controller["image_sha256"]
            or fixture.get("io_completions") != "explicit synthetic fixtures, not filesystem observations"):
        raise ValueError("file-info controller/reference fixture identity or scope differs")
    for item in (state, deadline_state, guard):
        if (item.get("io_manifest_sha256") != packed_manifest_sha[3]
                or item.get("io_source_sha256") != packed[3]["source_sha256"]):
            raise ValueError("file-info state/guard receipt belongs to a different IO image")
    if (state.get("manifest_sha256") != owner["sha256"]
            or state.get("codec_source_sha256") != packed[2]["source_sha256"]
            or state.get("original_metadata_source_sha256") != metadata_sha
            or state.get("os_effects") != "declared synthetic completions; actual ELF tests are separate"
            or deadline_state.get("guard") != "synthetic acknowledgements; no real wall-clock deadline claim"):
        raise ValueError("file-info native fixture source or synthetic-effect boundary differs")
    if (faults.get("actual_elf_responses") != 30 or faults.get("production_semantic_fallback") is not False
            or guard.get("actual_elf_responses") != 34 or guard.get("production_semantic_fallback") is not False
            or guard.get("original_metadata_source_sha256") != metadata_sha
            or guard.get("hold_kind") != "actual worker syscall held by kernel notification"
            or guard.get("synthetic_hia_acknowledgements") is not False
            or guard.get("empty_pipe_kernel_block_probe_included") is not False):
        raise ValueError("file-info real syscall/deadline accounting or scope differs")
    source_names = ("info_guard_supervisor.py", "io_fault_supervisor.py",
                    "test_file_info_guard.py", "test_local_service.py")
    if guard.get("test_sources_sha256") != {name: sha(ROOT / "tests/hia_native" / name) for name in source_names}:
        raise ValueError("file-info guard helper/source receipt differs")
    timings = guard.get("timings")
    validate_file_info_guard_times(timings)
    block = probe.get("observed_block", {})
    if (probe.get("explicit_test_timeout_ms") != 200 or type(probe.get("elapsed_nanoseconds")) is not int
            or not 190000000 <= probe["elapsed_nanoseconds"] < 2000000000
            or probe.get("native_exit") != 0 or probe.get("wait_signal") != 9
            or probe.get("worker_reaped") is not True or probe.get("runtime_python_required") is not False
            or probe.get("evidence_kind") != "actual empty-pipe blocking SYS_read"
            or probe.get("source_sha256") != sha(ROOT / "tests/hia_native/native_deadline_probe.S")
            or type(probe.get("executable_sha256")) is not str
            or block.get("state") != "S" or block.get("syscall") != "0" or block.get("read_bytes") != 1
            or "pipe_read" not in block.get("wait_channel", "")
            or probe.get("retained_executable") != "file-info-blocking-probe.elf"):
        raise ValueError("file-info actual kernel-block/reap probe evidence differs")
    path, raw = owned("file-info-blocking-probe.elf", probe.get("executable_sha256"))
    if not raw.startswith(b"\x7fELF"):
        raise ValueError("file-info blocking probe executable is not native ELF")
    receipts[path.name] = sha(path)
    return {"status": "PASS", "scope": "native-local Linux file_info; original helpers and owned-worker boundary",
            "complete_original_remote_tool_parity": False, "production_activated": False,
            "module_manifest_sha256": owner["sha256"], "executable_sha256": metadata["executable_sha256"],
            "controller_manifest_sha256": sha(controller_path), "controller_image_sha256": controller["image_sha256"],
            "io_manifest_sha256": packed_manifest_sha[3], "codec_manifest_sha256": packed_manifest_sha[2],
            "normal_original_comparisons": normal["counts"], "controller_fixture_controls": fixture["counts"],
            "io_fixture_controls": state["counts"], "deadline_fixture_controls": deadline_state["counts"],
            "actual_metadata_fault_controls": faults["counts"], "actual_deadline_controls": guard["counts"],
            "actual_service_responses": 137, "production_deadline_seconds": 30, "deadline_timings": timings,
            "actual_blocking_probe": probe, "native_cases_added_by_replay": 0,
            "receipts_sha256": receipts, "checks": checks,
            "original_sources": {name: originals[name] for name in (
                "src/mcp/runtime/binary_file.py", "src/mcp/runtime/file_metadata.py",
                "src/mcp/runtime/binary.rs", "src/mcp/runtime/config.rs", "src/mcp/server.rs")}}


def python_reference_evidence(output: Path, report: dict) -> dict:
    return {"native_io": io_reference_evidence(output, report),
            "native_full_io": full_io_reference_evidence(output, report),
            "stat_version": stat_version_reference_evidence(output, report),
            "local_service": local_service_reference_evidence(output, report),
            "multi_file_service": multi_service_reference_evidence(output, report)}


def initial_report(hepta: Path) -> dict:
    return {
        "schema": "hepta.runtime.hia-native-qualification.v1",
        "status": "RUNNING", "phase": "compiler_cold",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "checkout_head": None, "source_identity_authority": "source_sha256", "source_sha256": {},
        "compiler_commit": HEPTA_COMMIT, "compiler_tree": HEPTA_TREE,
        "compiler_checkout": str(hepta),
        "scope": "native HIA semantic owners, fixed local MCP read and ordinary-file view profiles, serial caller authority, and Linux x86-64 dependencies",
        "whole_runtime_replaced": False, "production_activated": False,
        "old_stack_removal_qualified": False, "matching_source_full_cold_qualified": False,
        "compiler_cold_status": "PENDING", "native_components_status": "RUNNING",
        "retained_python_comparison_status": "PENDING", "rust_comparison_status": "PENDING", "checks": [],
    }


def native_environment(output: Path, hepta: Path, report: dict) -> dict:
    env = qualification_env()
    env.update({
        "HIA_HEPTA_DIR": str(hepta), "HIA_BUILD_ROOT": str(output / "build"),
        "HIA_BELLMAN_QUALIFICATION_OUTPUT": str(output),
        "HIA_BELLMAN_COMMITMENT_QUALIFICATION_OUTPUT": str(output),
        "HIA_LOCAL_CREATE_OUTPUT": str(output / "local-create"),
        "HIA_LOCAL_CREATE_QUALIFICATION_OUTPUT": str(output),
        "HIA_LOCAL_CREATE_SPEC_OUTPUT": str(output / "local-create-spec"),
        "HIA_TEXT_EDITOR_PARAMS_QUALIFICATION_OUTPUT": str(output),
        "HIA_BYTES_CORPUS_DIR": str(output / "rust-oracle"), "PYTHONDONTWRITEBYTECODE": "1",
        "HIA_TEXT_CORPUS_DIR": str(output / "text-rust-oracle"),
        "HIA_TERMINAL_CORPUS_DIR": str(output / "terminal-clean"),
        "HIA_SHELL_GATE_CORPUS_DIR": str(output / "shell-gate"),
        "HIA_SHELL_QUALIFICATION_OUTPUT": str(output),
        "HIA_REQUEST_CONTEXT_CORPUS_DIR": str(output / "request-context-rust-oracle"),
        "HIA_RESPONSE_HINTS_CORPUS_DIR": str(output / "response-hints-rust-oracle"),
        "HIA_REQUEST_CONTEXT_TRANSPORT_DIR": str(output / "request-context-transport"),
        "HIA_REQUEST_CONTEXT_QUALIFICATION_OUTPUT": str(output),
        "HIA_RESULT_PUBLICATION_CORPUS_DIR": str(output / "result-publication"),
        "HIA_RESULT_PUBLICATION_QUALIFICATION_OUTPUT": str(output),
        "HIA_REQUEST_SCOPE_CORPUS_DIR": str(output / "request-scope"),
        "HIA_REQUEST_SCOPE_BOUNDARY_DIR": str(output / "request-scope-boundaries"),
        "HIA_REQUEST_SCOPE_QUALIFICATION_OUTPUT": str(output),
        "HIA_ENDPOINT_CORPUS_DIR": str(output / "endpoint-rust-oracle"),
        "HIA_DELTA_CORPUS_DIR": str(output / "delta-rust-oracle"),
        "HIA_EDITABLE_CORPUS_DIR": str(output / EDITABLE_FOLDER),
        "HIA_LINE_VERIFY_CORPUS_DIR": str(output / LINE_VERIFY_FOLDER),
        "HIA_BATCH_PLAN_CORPUS_DIR": str(output / BATCH_PLAN_FOLDER),
        "HIA_VIEW_CORPUS_DIR": str(output / VIEW_FOLDER),
        "HIA_VIEW_GROWTH_CORPUS_DIR": str(output / VIEW_GROWTH_FOLDER),
        "HIA_VIEW_GROWTH_QUALIFICATION_OUTPUT": str(output),
        "HIA_VIEW_READ_CAPTURE_DIR": str(output / "view-call/read"),
        "HIA_VIEW_CALL_CAPTURE_DIR": str(output / "view-call/caller"),
        "HIA_VIEW_PARAMS_CAPTURE_DIR": str(output / "view-call/params"),
        "HIA_VIEW_WIDE_CAPTURE_DIR": str(output / "view-call/wide"),
        "HIA_VIEW_CALL_QUALIFICATION_OUTPUT": str(output),
        "HIA_VIEW_SEARCH_CAPTURE_DIR": str(output / "view-search"),
        "HIA_VIEW_SEARCH_QUALIFICATION_OUTPUT": str(output),
        "HIA_VIEW_SEARCH_PUBLIC_CAPTURE_DIR": str(output / "view-search-public"),
        "HIA_VIEW_REGEX_SEARCH_CAPTURE_DIR": str(output / "view-regex-search"),
        "HIA_VIEW_REGEX_SEARCH_QUALIFICATION_OUTPUT": str(output),
        "HIA_VIEW_REGEX_SEARCH_PUBLIC_CAPTURE_DIR": str(output / "view-regex-search-public"),
        "HIA_VIEW_REGEX_SEARCH_PUBLIC_QUALIFICATION_OUTPUT": str(output),
        "HIA_VIEW_RESOURCE_CAPTURE_DIR": str(output / "view-call/resources"),
        "HIA_RUNTIME_MCP_CORPUS_DIR": str(output / "runtime-mcp"),
        "HIA_RUNTIME_MCP_QUALIFICATION_OUTPUT": str(output),
        "HIA_CACHE_CORPUS_DIR": str(output / CACHE_FOLDER),
        "HIA_CACHE_QUALIFICATION_OUTPUT": str(output),
        "HIA_FENCE_JSON_CORPUS_DIR": str(output / JSON_COMPONENTS["fence_json"]["folder"]),
        "HIA_SERDE_JSON_CORPUS_DIR": str(output / JSON_COMPONENTS["serde_json"]["folder"]),
        "HIA_RAW_VALUE_CORPUS_DIR": str(output / "serde-json-raw-value-rust-oracle"),
        "HIA_SERDE_JSON_TRANSPORT_REPORT": str(output / JSON_TRANSPORT_REPORT),
        "HIA_JSON_QUALIFICATION_OUTPUT": str(output),
        "HIA_HISTORY_CORPUS_DIR": str(output / HISTORY_FOLDER),
        "HIA_HISTORY_QUALIFICATION_OUTPUT": str(output),
        "HIA_CODEC_CORPUS_DIR": str(output / "codec-rust-oracle"),
        "HIA_KDF_CORPUS_DIR": str(output / "operation-kdf-rust-oracle"),
        "HIA_AEAD_CORPUS_DIR": str(output / "operation-aead-rust-oracle"),
        "HIA_NONCE_CORPUS_DIR": str(output / "operation-nonce-rust-oracle"),
        "HIA_RECORD_CORPUS_DIR": str(output / "operation-record-rust-oracle"),
        "HIA_ENTROPY_BACKEND_REPORT": str(output / ENTROPY_FOLDER / "backend.json"),
        "HIA_ENTROPY_PACKER_REPORT": str(output / ENTROPY_FOLDER / "packer.json"),
        "HIA_ENTROPY_KERNEL_REPORT": str(output / ENTROPY_FOLDER / "kernel-native.json"),
        "HIA_ENTROPY_TRANSPORT_REPORT": str(output / ENTROPY_FOLDER / "transport.json"),
        "HIA_SCOPE_CORPUS_DIR": str(output / SCOPE_FOLDER),
        "HIA_AUTHORITY_CORPUS_DIR": str(output / AUTHORITY_FOLDER / "controller"),
        "HIA_AUTHORITY_TEST_REPORT": str(output / AUTHORITY_FOLDER / "controller.json"),
        "HIA_AUTHORITY_KERNEL_CORPUS_DIR": str(output / AUTHORITY_FOLDER / "kernel"),
        "HIA_AUTHORITY_TRANSPORT_CORPUS_DIR": str(output / AUTHORITY_FOLDER / "transport"),
        "HIA_AUTHORITY_PACKER_REPORT": str(output / AUTHORITY_FOLDER / "packer.json"),
        "HIA_AUTHORITY_EVIDENCE_REPORT": str(output / AUTHORITY_FOLDER / "evidence.json"),
        "HIA_POLICY_CORPUS_DIR": str(output / "policy-rust-oracle"),
        "HIA_STAT_VERSION_CORPUS_DIR": str(output / "stat-version-python-reference"),
        "HIA_SERVICE_RESULT": str(output / "local-service-python-reference.json"),
        "HIA_MULTI_SERVICE_RESULT": str(output / "multi-service-python-reference.json"),
        "HIA_INFO_SERVICE_RESULT": str(output / "file-info-python-reference.json"),
        "HIA_FILE_INFO_RESULT": str(output / "file-info-controller.json"),
        "HIA_INFO_IO_STATE_RESULT": str(output / "file-info-io-state.json"),
        "HIA_INFO_DEADLINE_STATE_RESULT": str(output / "file-info-deadline-state.json"),
        "HIA_INFO_IO_FAULT_RESULT": str(output / "file-info-io-faults.json"),
        "HIA_INFO_GUARD_RESULT": str(output / "file-info-guard.json"),
        "HIA_DEADLINE_PROBE_RESULT": str(output / "file-info-blocking-probe.json"),
        "HIA_DEADLINE_PROBE_EXECUTABLE": str(output / "file-info-blocking-probe.elf"),
        "HIA_MULTI_READ_CORPUS_DIR": str(output / "multi-read-rust-oracle"),
        "HIA_REFERENCE_RUNTIME": str(ROOT),
        "HIA_FENCE_ASYNC_CORPUS_DIR": str(output / effect_fence_qualification.FOLDER / "async"),
        "HIA_FENCE_WORKER_CORPUS_DIR": str(output / effect_fence_qualification.FOLDER / "worker"),
        "HIA_FENCE_LIFETIME_CORPUS_DIR": str(output / effect_fence_qualification.FOLDER / "lifetime"),
        "HIA_FENCE_CORPUS_DIR": str(output / effect_fence_qualification.FOLDER / "owner"),
        "HIA_FENCE_KERNEL_CORPUS_DIR": str(output / effect_fence_qualification.FOLDER / "kernel"),
        "HIA_FENCE_KERNEL_BACKEND": "native",
        "HIA_FENCE_PACKER_REPORT": str(output / effect_fence_qualification.FOLDER / "packer.json"),
        "HIA_FENCE_EVIDENCE_REPORT": str(output / effect_fence_qualification.FOLDER / "evidence.json"),
        "HIA_FENCE_QUALIFICATION_OUTPUT": str(output),
        "HIA_CONFIG_JSON_CORPUS_DIR": str(output / "config-native/typed-corpus"),
        "HIA_CONFIG_SEMANTICS_CORPUS_DIR": str(output / "config-native/semantics-corpus"),
        "HIA_REGEX_OUTPUT_DIR": str(output / "regex-native"),
    })
    env.update({variable: str(output / SCOPE_OS_FOLDER / receipt)
                for _, variable, receipt, _, _ in SCOPE_OS_SUITES})
    for item in MODULES:
        built = output / report["modules"][item["key"]]["manifest"]
        env[item["manifest_env"]] = str(built)
        if item.get("builder") == "composition":
            env["HIA_COMPOSITION_MANIFEST"] = str(built)
        elif item.get("builder") == "batch_edit_params":
            from hia_native_batch_edit_params_pipeline import environment
            env.update(environment(ROOT, output, report))
        elif item.get("builder") == "batch_plan_input":
            from hia_native_batch_plan_input_pipeline import environment
            env.update(environment(ROOT, output, report))
        elif item.get("builder") == "batch_diff":
            from hia_native_batch_diff_pipeline import environment
            env.update(environment(ROOT, output, report))
        elif item.get("builder") == "effect_fence":
            bundle = json.loads(built.read_bytes())
            env["HIA_FENCE_ASYNC_MANIFEST"] = str(
                output / "build" / bundle["members"]["production"]["manifest"])
            env["HIA_FENCE_ASYNC_SINGLE_MANIFEST"] = str(
                output / "build" / bundle["members"]["queue_fixture"]["manifest"])
        elif item.get("builder") == "result_publication":
            bundle = json.loads(built.read_bytes())
            env["HIA_RESULT_PUBLICATION_MANIFEST"] = str(output / "build" / bundle["owner_manifest"])
        elif item.get("builder") == "view_read":
            bundle = json.loads(built.read_bytes())
            env["HIA_VIEW_READ_MANIFEST"] = str(built.parent.parent / bundle["owner_manifest"])
        elif item.get("builder") == "authority_composition":
            env["HIA_AUTHORITY_MANIFEST"] = str(built.parent / "module_00.json")
            env["HIA_AUTHORITY_LOADER_MANIFEST"] = str(built.parent / "module_08.json")
            env["HIA_AUTHORITY_PROBE_MANIFEST"] = str(output / report["modules"][item["key"]]["probe_manifest"])
    env["HIA_NONCE_COMPOSITION_MANIFEST"] = str(output / report["nonce_composition"]["manifest"])
    env["HIA_CACHE_ELF_MANIFEST"] = str(output / report["cache_composition"]["manifest"])
    env["HIA_REQUEST_CONTEXT_ELF_MANIFEST"] = str(output / report["request_context_composition"]["manifest"])
    env["HIA_VIEW_PARAMS_VALUE_MANIFEST"] = env["HIA_SERDE_JSON_MANIFEST"]
    env["HIA_VIEW_SEARCH_FIXTURE_MANIFEST"] = env["HIA_VIEW_CALL_FIXTURE_MANIFEST"]
    env["HIA_VIEW_REGEX_SEARCH_FIXTURE_MANIFEST"] = env["HIA_VIEW_CALL_FIXTURE_MANIFEST"]
    env.update(connection_qualification.test_environment(output))
    return env


def prepare_native(output: Path, hepta: Path, report: dict) -> NativeBuild:
    report["source_sha256"] = sources()
    report["checkout_head"] = git_head()
    report["inventory"] = inspect(ROOT)
    required = ({item["source"] for item in MODULES} | PACKERS
                | {name for item in MODULES for name in item.get("companion_sources", ())})
    if {item["path"] for item in report["inventory"]["native_sources"]} != required:
        raise ValueError("every declared native source requires an executable qualification entry")
    builder = NativeBuild(hepta, output / "build")
    compiler = builder.bootstrap()
    report["compiler_image_sha256"] = sha(compiler)
    report["compiler_bootstrap_sha256"] = sha(output / "build/bootstrap/bootstrap.json")
    report["compiler_cold_status"] = "RUNNING"
    # This outer allowance lets the unchanged upstream 180 s owner finish
    # its separate 3 s cleanup and write the original report on failures.
    record_check(output, report, name="compiler-full-cold",
                 command=[sys.executable, "-I", "-B", str(hepta / "tools/replay_hia_selfhost_cold.py"),
                          "--output", str(output / "compiler-cold.json")], timeout=240)
    report["compiler_cold_evidence"] = validate_cold_evidence(
        output / "compiler-cold.json", dependency=builder.identity,
        compiler_sha256=report["compiler_image_sha256"])
    builder._recheck()
    report["matching_source_full_cold_qualified"] = True
    report["compiler_cold_status"] = "PASS"
    report["phase"] = "native_components"
    report["modules"] = {}
    (output / ENTROPY_FOLDER).mkdir(mode=0o700)
    (output / SCOPE_OS_FOLDER).mkdir(mode=0o700)
    (output / AUTHORITY_FOLDER).mkdir(mode=0o700)
    (output / "filesystem-parity/native").mkdir(mode=0o700, parents=True)
    for item in MODULES:
        if item.get("builder") == "result_storage":
            built = storage_pipeline.build_storage(hepta, output / "build", ROOT)
        elif item.get("builder") == "result_values":
            built = result_qualification.build_result_values(hepta, output / "build", ROOT)
        elif item.get("builder") == "io":
            from hia_native_io_build import build_io
            built = build_io(hepta, output / "build")
        elif item.get("builder") == "composition":
            from hia_native_composition_build import build_local_read
            built = build_local_read(hepta, output / "build")
        elif item.get("builder") == "record_composition":
            from hia_native_record_build import build_record
            built = build_record(hepta, output / "build")
        elif item.get("builder") == "text_editor_params":
            built = text_editor_params_qualification.build(hepta, output, source_root=ROOT)
        elif item.get("builder") == "local_create":
            from hia_native_local_create_build import build_local_create
            built = build_local_create(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "local_create_spec":
            from hia_native_local_create_spec_build import build_local_create_spec
            built = build_local_create_spec(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "entropy":
            from hia_native_entropy_build import build_entropy
            built = build_entropy(hepta, output / "build")
        elif item.get("builder") == "scope_composition":
            from hia_native_scope_build import build_scope
            built = build_scope(hepta, output / "build")
        elif item.get("builder") == "scope_os_composition":
            from hia_native_scope_os_build import build_scope_os
            built = build_scope_os(hepta, output / "build")
        elif item.get("builder") == "authority_composition":
            from hia_native_authority_build import build_authority
            from hia_native_authority_probe_build import build_loader_probe
            built = build_authority(hepta, output / "build", source_root=ROOT)
            probe = build_loader_probe(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "history":
            from hia_native_history_build import build_history
            built = build_history(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "session_workdir":
            from hia_native_session_build import build_session
            built = build_session(hepta, output / "build", source_root=ROOT, reference_root=ROOT)
        elif item.get("builder") == "file_locks":
            from hia_native_file_lock_build import build_file_locks
            built = build_file_locks(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "file_lock_service":
            from hia_native_file_lock_service_build import build_file_lock_service
            built = build_file_lock_service(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "write_chain":
            from hia_native_write_chain_build import build_write_chain
            built = build_write_chain(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "directory_service":
            from hia_native_directory_service_build import build_directory_service
            built = build_directory_service(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "workdir_service":
            from hia_native_workdir_service_build import build_workdir_service
            built = build_workdir_service(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "sdk_connection":
            built = connection_qualification.build_connection(hepta, output / "build", ROOT)
        elif item.get("builder") == "public_registry":
            built = public_registry_qualification.build_public_registry(hepta, output / "build", ROOT)
        elif item.get("builder") == "runtime_config":
            built = config_qualification.build_config(hepta, output / "build", ROOT)
        elif item.get("builder") == "runtime_config_span":
            from hia_native_config_span_build import build_config_span
            nested = output / "build/config-span-bundle"
            shutil.copytree(output / "build/bootstrap", nested / "build/bootstrap")
            built = build_config_span(hepta, nested, source_root=ROOT)
        elif item.get("builder") == "result_publication":
            from hia_native_result_publication_build import build_result_publication
            built = build_result_publication(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "request_scope":
            from hia_native_request_scope_build import build_request_scope
            built = build_request_scope(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") in {"view_read", "view_call", "runtime_mcp"}:
            # These compositions deliberately compile shared owners in different
            # borrowed-buffer profiles. Keep their module namespaces separate,
            # while each builder rechecks the same admitted compiler bytes.
            nested = output / "build" / (item["key"] + "-bundle")
            shutil.copytree(output / "build/bootstrap", nested / "bootstrap")
            if item["builder"] == "view_read":
                from hia_native_view_read_build import build_view_read
                built = build_view_read(hepta, nested, source_root=ROOT)
            elif item["builder"] == "view_call":
                from hia_native_view_call_build import build_view_call
                built = build_view_call(hepta, nested, source_root=ROOT)
            else:
                from hia_native_runtime_mcp_build import build_runtime_mcp
                built = build_runtime_mcp(hepta, nested, source_root=ROOT)
        elif item.get("builder") == "filesystem_public":
            # The separately linked two-session observer consumes the exact
            # public graph's already fresh members. It compiles no new owner.
            from hia_native_runtime_mcp_build import build_runtime_mcp
            public_manifest = output / report["modules"]["runtime_mcp"]["manifest"]
            public = json.loads(public_manifest.read_bytes())
            nested = output / "build/filesystem-public-bundle"
            shutil.copytree(output / "build/bootstrap", nested / "bootstrap")
            reused = {row["name"]: Path(row["manifest"]) for row in public["members"]}
            built = build_runtime_mcp(hepta, nested, source_root=ROOT, manifests=reused,
                                      private_fixture=True)
        elif item.get("builder") == "execution_shadow":
            from hia_native_execution_build import build_execution
            built = build_execution(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "effect_fence":
            from hia_native_effect_fence_build import build_effect_fence_bundle
            built = build_effect_fence_bundle(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "batch_write":
            from hia_native_batch_write_build import build_batch_write
            built = build_batch_write(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "batch_apply":
            from hia_native_batch_apply_build import build_batch_apply
            built = build_batch_apply(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "shell_process":
            from hia_native_shell_process_build import build_shell_process
            built = build_shell_process(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "shell_outcome":
            from hia_native_shell_outcome_build import build_shell_outcome
            built = build_shell_outcome(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "shell_output":
            from hia_native_shell_output_build import build_shell_output
            built = build_shell_output(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "shell_foreground":
            from hia_native_shell_foreground_build import build_shell_foreground
            built = build_shell_foreground(hepta, output / "build", source_root=ROOT,
                process_manifest=output / report["modules"]["shell_process"]["manifest"],
                output_manifest=output / report["modules"]["shell_output_io"]["manifest"],
                outcome_manifest=output / report["modules"]["shell_outcome"]["manifest"])
        elif item.get("builder") in capture_gate.KEYS:
            built = capture_gate.build(item["key"], hepta, output / "build")
        elif item.get("builder") == "atomic_write":
            from hia_native_atomic_write_build import build_atomic_write
            built = build_atomic_write(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "filesystem_parity":
            from hia_native_filesystem_parity_build import build_filesystem_parity
            built = build_filesystem_parity(hepta, output / "build", source_root=ROOT)
        elif item.get("builder") == "batch_edit_params":
            from hia_native_batch_edit_params_build import build_batch_edit_params
            nested = output / "batch-edit-params/build"
            shutil.copytree(output / "build/bootstrap", nested / "bootstrap")
            built = build_batch_edit_params(hepta, nested, source_root=ROOT)
        elif item.get("builder") == "batch_plan_input":
            from hia_native_batch_plan_input_build import build_batch_plan_input
            nested = output / "batch-plan-input/build"
            shutil.copytree(output / "build/bootstrap", nested / "bootstrap")
            built = build_batch_plan_input(hepta, nested, source_root=ROOT)
        elif item.get("builder") == "batch_diff":
            from hia_native_batch_diff_pipeline import build as build_batch_diff
            built = build_batch_diff(hepta, output, source_root=ROOT)
        elif item.get("builder") == "batch_plan":
            from hia_native_batch_plan_build import build_batch_plan
            built = build_batch_plan(hepta, output / "build", source_root=ROOT)
        else:
            built = builder.compile(item["name"], ROOT / item["source"], standalone=item["standalone"],
                                    buffer_profile=item.get("buffer_profile", "standard"))
        report["modules"][item["key"]] = {
            "manifest": str(built.relative_to(output)), "sha256": sha(built), "source": item["source"],
            "builder": item.get("builder", "borrowed_bytes")}
        if item.get("builder") == "request_scope":
            report["request_scope_composition"] = dict(report["modules"][item["key"]])
        if item.get("builder") == "authority_composition":
            report["modules"][item["key"]].update(
                probe_manifest=str(probe.relative_to(output)), probe_sha256=sha(probe))
    report["view_call"] = {
        "manifest": report["modules"]["view_call"]["manifest"],
        "read_fixture_manifest": report["modules"]["view_read"]["manifest"],
        "params_manifest": report["modules"]["view_params"]["manifest"],
        "value_manifest": report["modules"]["serde_json"]["manifest"],
        "corpora": {name: "view-call/" + name for name in ("read", "params", "caller", "wide")},
    }
    # The literal domain uses the same admitted caller executable. It does not
    # add an alias builder or count the shared HIA owners a second time.
    report["view_search"] = {
        "manifest": report["modules"]["view_call"]["manifest"],
        "corpus": "view-search",
    }
    report["view_search_public"] = {
        "manifest": report["modules"]["runtime_mcp"]["manifest"],
        "corpus": "view-search-public",
    }
    report["view_regex_search"] = {
        "manifest": report["modules"]["view_call"]["manifest"],
        "corpus": "view-regex-search",
    }
    report["view_regex_search_public"] = {
        "manifest": report["modules"]["runtime_mcp"]["manifest"],
        "corpus": "view-regex-search-public",
    }
    from hia_native_composition_build import ModuleSpec, build_composition
    nonce_fixture = build_composition(hepta, output / "build", [
        ModuleSpec("nonce-hex-fixture", ROOT / "tests/hia_native/nonce_hex_transport.hepta",
                   flags=1, call_mask=2, workspace_capacity=16 << 20),
        ModuleSpec("operation-nonce", ROOT / "native/operation_nonce.hepta",
                   input_capacity=164, output_capacity=64, workspace_capacity=1576960),
    ])
    report["nonce_composition"] = {"manifest": str(nonce_fixture.relative_to(output)),
                                    "sha256": sha(nonce_fixture), "builder": "composition_fixture"}
    from hia_native_view_cache_build import build_cache
    cache_fixture = build_cache(hepta, output / "build")
    report["cache_composition"] = {"manifest": str(cache_fixture.relative_to(output)),
                                   "sha256": sha(cache_fixture), "builder": "composition_fixture"}
    from hia_native_request_context_build import build_request_context
    context_fixture = build_request_context(hepta, output / "build", source_root=ROOT)
    report["request_context_composition"] = {"manifest": str(context_fixture.relative_to(output)),
                                            "sha256": sha(context_fixture), "builder": "composition_fixture"}
    (output / "batch-apply").mkdir()
    (output / "atomic-write").mkdir()
    (output / "config-native").mkdir()
    (output / "config-span").mkdir()
    (output / "regex-native").mkdir()
    (output / "file-locks").mkdir()
    (output / "file-lock-service").mkdir()
    (output / "write-chain").mkdir()
    (output / "workdir-native").mkdir()
    return builder


def native_tests() -> tuple[str, ...]:
    tests = tuple(name for item in MODULES for name in (item["test"], *item.get("additional_tests", ()))) + EXTRA_TESTS
    if len(tests) != len(set(tests)):
        raise ValueError("native suite registry contains duplicate entries")
    return tests


def native_commands(output: Path, report: dict, tests: tuple[str, ...]) -> dict[str, list[str]]:
    commands = batch_apply_test_commands(output, output / report["modules"]["batch_apply"]["manifest"])
    commands.update(execution_test_commands(output, report))
    commands.update(config_qualification.test_commands(ROOT, output, report))
    from hia_native_config_span_pipeline import test_commands as config_span_commands
    commands.update(config_span_commands(ROOT, output, report))
    commands.update(session_qualification.test_commands(ROOT, output, report))
    commands.update(file_lock_pipeline.test_commands(ROOT, output, report))
    commands.update(filesystem_parity_qualification.test_commands(ROOT, output, report))
    commands.update(write_chain_pipeline.test_commands(ROOT, output, report))
    commands.update(service_pipeline.test_commands(ROOT, output, report))
    commands.update(connection_qualification.test_commands(ROOT, output, report))
    commands.update(public_registry_qualification.test_commands(ROOT, output, report))
    commands.update(result_qualification.test_commands(ROOT, output, report))
    commands.update(serde_error_pipeline.test_commands(ROOT, output, report))
    commands.update(storage_pipeline.test_commands(ROOT, output, report))
    commands.update(batch_write_pipeline.test_commands(ROOT, output, report))
    from hia_native_filesystem_public_pipeline import test_commands as filesystem_public_commands
    if "test_filesystem_public.py" in tests:
        commands.update(filesystem_public_commands(ROOT, output, report))
    commands.update(atomic_write_test_commands(output, output / report["modules"]["atomic_write"]["manifest"],
                                               Path(report["compiler_checkout"])))
    if set(tests) & {*SHELL_PROCESS_TESTS, SHELL_BACKGROUND_TEST}:
        commands.update(shell_process_test_commands(output, report))
    if SHELL_OUTCOME_TEST in tests:
        commands.update(shell_outcome_test_commands(output, report))
    if SHELL_OUTPUT_TEST in tests:
        commands.update(shell_output_test_commands(output, report))
    if set(tests) & set(SHELL_FOREGROUND_TESTS):
        commands.update(shell_foreground_test_commands(output, report))
    if set(tests) & set(capture_gate.TESTS):
        commands.update(capture_gate.test_commands(output, report))
    return {name: command for name, command in commands.items() if name in tests}


def collect_native_evidence(output: Path, report: dict) -> None:
    report["text_editor_params_evidence"] = text_editor_params_qualification.native_evidence(output, report)
    report["local_create_file_evidence"] = local_create_qualification.native_evidence(output, report)
    report["local_create_spec_evidence"] = local_create_spec_qualification.native_evidence(output, report)
    report["local_create_segments_evidence"] = local_create_qualification.segments.native_evidence(output, report)
    report["local_create_async_held_evidence"] = local_create_qualification.held.native_evidence(output, report)
    report["bellman_evidence"] = bellman_qualification.native_evidence(output, report)
    report["bellman_commitment_evidence"] = bellman_commitment_qualification.native_evidence(output, report)
    report["request_context_evidence"] = request_context_evidence(output, report)
    report["result_publication_evidence"] = result_publication_evidence(output, report)
    report["request_scope_evidence"] = request_scope_evidence(output, report)
    report["filesystem_parity_evidence"] = filesystem_parity_evidence(output, report)
    report["filesystem_parity_fixture_retirement"] = filesystem_parity_retirement(output, report, create=True)
    report["shell_evidence"] = shell_evidence(output, report)
    report["shell_process_evidence"] = shell_process_evidence(output, report)
    report["shell_background_evidence"] = shell_background_evidence(output, report)
    report["shell_outcome_evidence"] = shell_outcome_evidence(output, report)
    report["shell_output_evidence"] = shell_output_evidence(output, report)
    report["shell_foreground_evidence"] = shell_foreground_evidence(output, report)
    for key in capture_gate.KEYS:
        report[key + "_evidence"] = capture_gate.native_evidence(output, report, key)
    report["original_python_comparisons"] = python_reference_evidence(output, report)
    report["native_composition_evidence"] = native_composition_evidence(output, report)
    report["multi_read_controller_evidence"] = multi_read_controller_evidence(output, report)
    report["file_info_evidence"] = file_info_evidence(output, report)
    report["operation_kdf_evidence"] = operation_kdf_evidence(output, report)
    report["operation_aead_evidence"] = operation_aead_evidence(output, report)
    report["operation_nonce_evidence"] = operation_nonce_evidence(output, report)
    report["operation_record_evidence"] = operation_record_evidence(output, report)
    capture_entropy_corpus(ROOT, output, report, completed_test_summary)
    report["system_entropy_evidence"] = entropy_evidence(output, report)
    report["operation_scope_evidence"] = operation_scope_evidence(output, report)
    report["editable_content_evidence"] = editable_content_evidence(output, report)
    report["line_verify_evidence"] = line_verify_evidence(output, report)
    report["batch_edit_params_evidence"] = batch_edit_params_evidence(output, report)
    report["batch_plan_input_evidence"] = batch_plan_input_evidence(output, report)
    report["batch_diff_evidence"] = batch_diff_evidence(output, report)
    report["batch_plan_evidence"] = batch_plan_evidence(output, report)
    report["batch_apply_evidence"] = batch_apply_evidence(output, report)
    atomic = atomic_write_evidence(output, report)
    retirement = output / "atomic-write/retired-fixtures.json"
    atomic_write_retire_fixtures(output, atomic_write_fixture_directories(), retirement,
                                atomic["native_evidence"], create=True)
    atomic["corpus_sha256"][retirement.relative_to(output).as_posix()] = sha(retirement)
    report["atomic_write_evidence"] = atomic
    report["view_render_evidence"] = view_render_evidence(output, report)
    report["view_render_growth_evidence"] = view_render_growth_evidence(output, report)
    report["view_call_evidence"] = view_call_evidence(output, report)
    report["view_search_evidence"] = view_search_evidence(output, report)
    report["view_regex_search_evidence"] = view_regex_search_evidence(output, report)
    report["view_resource_evidence"] = view_resource_evidence(output, report)
    report["runtime_mcp_evidence"] = runtime_mcp_evidence(output, report)
    report["filesystem_public_evidence"] = filesystem_public_evidence(output, report)
    report["filesystem_public_fixture_retirement"] = filesystem_public_retirement(
        output, report, create=True, native=report["filesystem_public_evidence"])
    report["view_search_public_evidence"] = view_search_public_evidence(output, report)
    report["view_regex_search_public_evidence"] = view_regex_search_public_evidence(output, report)
    report["view_fixture_retirement"] = view_fixture_retirement(output, report, create=True,
        native=report["view_call_evidence"], public=report["runtime_mcp_evidence"],
        search=report["view_search_evidence"], public_search=report["view_search_public_evidence"],
        regex_search=report["view_regex_search_evidence"],
        public_regex_search=report["view_regex_search_public_evidence"])
    report["runtime_mcp_fixture_retirement"] = runtime_mcp_fixture_retirement(output, report, create=True,
        public=report["runtime_mcp_evidence"], public_search=report["view_search_public_evidence"],
        public_regex_search=report["view_regex_search_public_evidence"])
    report["view_cache_evidence"] = view_cache_evidence(output, report)
    report["history_evidence"] = history_evidence(output, report)
    report["session_evidence"] = session_evidence(output, report)
    report["file_locks_evidence"] = file_locks_evidence(output, report)
    report["file_lock_service_evidence"] = file_lock_service_evidence(output, report)
    report["write_chain_evidence"] = write_chain_evidence(output, report)
    report["directory_service_evidence"] = directory_service_evidence(output, report)
    report["workdir_service_evidence"] = workdir_service_evidence(output, report)
    report["sdk_connection_evidence"] = sdk_connection_evidence(output, report, create=True)
    report["public_registry_evidence"] = public_registry_evidence(output, report, create=True)
    report["result_values_evidence"] = result_values_evidence(output, report)
    report["serde_error_evidence"] = serde_error_evidence(output, report)
    report["result_storage_evidence"] = result_storage_evidence(output, report, create=True)
    report["batch_write_evidence"] = batch_write_evidence(output, report)
    service_pipeline.prepare_transport(ROOT, output, report, completed_test_summary)
    report["json_evidence"] = json_evidence(output, report)
    report["execution_evidence"] = execution_evidence(output, report)
    report["effect_fence_evidence"] = effect_fence_evidence(output, report)
    report["config_evidence"] = config_evidence(output, report, create=True)
    report["config_span_evidence"] = config_span_evidence(output, report)
    report["config_span_fixture_retirement"] = config_span_fixture_retirement(
        output, report, create=True, native=report["config_span_evidence"])
    scope_os_manifest = output / report["modules"]["operation_scope_os"]["manifest"]
    capture_scope_os_corpus(ROOT, output / SCOPE_OS_FOLDER, scope_os_profile(ROOT, scope_os_manifest))
    report["operation_scope_os_evidence"] = operation_scope_os_evidence(output, report)
    report["caller_authority_evidence"] = caller_authority_evidence(output, report)
    report["retained_python_comparison_status"] = "PASS"
    report["python_reference_inputs"] = {
        "stat-version-python-reference/" + name: sha(output / "stat-version-python-reference" / name)
        for name in ("native-corpus.json", "stat-version-cases.jsonl.gz")}
    report["python_reference_inputs"]["local-service-python-reference.json"] = sha(
        output / "local-service-python-reference.json")
    report["python_reference_inputs"]["multi-service-python-reference.json"] = sha(
        output / "multi-service-python-reference.json")
    for name in FILE_INFO_RECEIPTS:
        report["python_reference_inputs"][name] = sha(output / name)
    report["python_reference_inputs"]["file-info-blocking-probe.elf"] = sha(output / "file-info-blocking-probe.elf")
    report["rust_oracle_inputs"] = {
        "rust-oracle/" + name: sha(output / "rust-oracle" / name) for name in RUST_CORPUS_FILES}
    report["rust_oracle_inputs"].update(report["text_editor_params_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["local_create_file_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["local_create_spec_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["local_create_segments_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["local_create_async_held_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["request_context_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["result_publication_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["request_scope_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["filesystem_parity_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["filesystem_parity_fixture_retirement"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_render_growth_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_call_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_search_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_regex_search_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_resource_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["runtime_mcp_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["filesystem_public_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["filesystem_public_fixture_retirement"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_search_public_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_regex_search_public_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_fixture_retirement"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["runtime_mcp_fixture_retirement"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["shell_evidence"]["artifact_sha256"])
    for key in ("shell_process_evidence", "shell_background_evidence", "shell_outcome_evidence",
                "shell_output_evidence", "shell_foreground_evidence",
                *(key + "_evidence" for key in capture_gate.KEYS)):
        report["rust_oracle_inputs"].update(report[key]["artifact_sha256"])
        report["rust_oracle_inputs"].update(report[key]["corpus_sha256"])
    report["rust_oracle_inputs"].update({
        ENTROPY_FOLDER + "/" + name: sha(output / ENTROPY_FOLDER / name) for name in ENTROPY_CORPUS_FILES})
    report["rust_oracle_inputs"].update(report["system_entropy_evidence"]["artifacts"]["artifact_sha256"])
    report["rust_oracle_inputs"].update({
        SCOPE_FOLDER + "/" + name: sha(output / SCOPE_FOLDER / name) for name in SCOPE_CORPUS_FILES})
    for folder, names in ((EDITABLE_FOLDER, EDITABLE_CORPUS_FILES), (VIEW_FOLDER, VIEW_CORPUS_FILES),
                          (LINE_VERIFY_FOLDER, LINE_VERIFY_CORPUS_FILES)):
        report["rust_oracle_inputs"].update({folder + "/" + name: sha(output / folder / name) for name in names})
    report["rust_oracle_inputs"].update(report["operation_scope_evidence"]["composition"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["operation_scope_os_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["operation_scope_os_evidence"]["composition"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_cache_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["view_cache_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["history_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["history_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["result_values_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["result_values_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["serde_error_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["serde_error_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["result_storage_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["result_storage_evidence"]["corpus_sha256"])
    # The complete batch corpus is also inspected by batch_write_evidence on
    # every admission; preserve the actual completed process and bundle roots.
    batch_names = [report["modules"]["batch_write"]["manifest"]] + [
        name + suffix for name in batch_write_pipeline.q.SUITES for suffix in (".stdout", ".stderr")]
    report["rust_oracle_inputs"].update({name: sha(output / name) for name in batch_names})
    report["rust_oracle_inputs"].update(report["json_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["json_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["execution_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["effect_fence_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["effect_fence_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["config_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["config_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["config_span_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["config_span_fixture_retirement"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["batch_edit_params_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["batch_plan_input_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["batch_diff_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["batch_plan_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["batch_plan_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["batch_apply_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["batch_apply_evidence"]["corpus_sha256"])
    report["rust_oracle_inputs"].update(report["atomic_write_evidence"]["artifact_sha256"])
    report["rust_oracle_inputs"].update(report["atomic_write_evidence"]["corpus_sha256"])
    for key in ("directory_service", "workdir_service", "sdk_connection", "public_registry"):
        report["rust_oracle_inputs"].update(report[key + "_evidence"]["artifact_sha256"])
        report["rust_oracle_inputs"].update(report[key + "_evidence"]["corpus_sha256"])
    write_manifest = write_chain_pipeline.bundle(output, report)
    report["rust_oracle_inputs"].update(service_pipeline.retained_files(output, write_manifest.parent))
    report["rust_oracle_inputs"].update(service_pipeline.retained_files(output, output / "write-chain"))
    authority = report["caller_authority_evidence"]
    for label in ("artifact", "probe"):
        report["rust_oracle_inputs"].update({"build/" + name: expected
            for name, expected in authority[label]["artifact_sha256"].items()})
    report["rust_oracle_inputs"].update(authority["corpus_sha256"])
    report["rust_oracle_inputs"].update({
        "text-rust-oracle/" + name: sha(output / "text-rust-oracle" / name)
        for name in ("native-corpus.json", "requests.hex", "native-output.txt")})
    report["rust_oracle_inputs"].update({
        "endpoint-rust-oracle/" + name: sha(output / "endpoint-rust-oracle" / name)
        for name in ("native-corpus.json", "endpoint_cases.jsonl.gz")})
    report["rust_oracle_inputs"].update({
        "delta-rust-oracle/" + name: sha(output / "delta-rust-oracle" / name)
        for name in ("native-corpus.json", "requests.hex", "native-output.txt")})
    report["rust_oracle_inputs"].update({
        "codec-rust-oracle/" + name: sha(output / "codec-rust-oracle" / name)
        for name in ("native-corpus.json", "codec_cases.jsonl.gz")})
    report["rust_oracle_inputs"].update({
        "policy-rust-oracle/" + name: sha(output / "policy-rust-oracle" / name)
        for name in ("native-corpus.json", "requests.hex", "native-output.txt")})
    report["rust_oracle_inputs"].update({
        "multi-read-rust-oracle/" + name: sha(output / "multi-read-rust-oracle" / name)
        for name in ("native-corpus.json", "requests.hex.gz", "native-output.txt.gz")})
    report["rust_oracle_inputs"].update({
        "operation-kdf-rust-oracle/" + name: sha(output / "operation-kdf-rust-oracle" / name)
        for name in ("native-corpus.json", "kdf_cases.jsonl.gz")})
    report["rust_oracle_inputs"].update({
        "operation-aead-rust-oracle/" + name: sha(output / "operation-aead-rust-oracle" / name)
        for name in ("native-corpus.json", "aead_cases.jsonl.gz")})
    report["rust_oracle_inputs"].update({
        "operation-nonce-rust-oracle/" + name: sha(output / "operation-nonce-rust-oracle" / name)
        for name in ("native-corpus.json", "nonce_cases.jsonl.gz")})
    report["rust_oracle_inputs"].update({
        "operation-record-rust-oracle/" + name: sha(output / "operation-record-rust-oracle" / name)
        for name in ("native-corpus.json", "record_cases.jsonl.gz")})


def finish_native(output: Path, report: dict, builder: NativeBuild) -> None:
    builder.bootstrap()  # Revalidate the same compiler image after all tests.
    builder._recheck()
    if sources() != report["source_sha256"]:
        raise RuntimeError("native source/test/inventory inputs changed during qualification")
    report["native_components_status"] = "PASS"
    report["status"] = "NATIVE_COMPONENTS_PASS"
    report["phase"] = "awaiting_original_rust_comparison"


def run(output: Path, hepta: Path) -> dict:
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    report_path = output / "result.json"
    started = time.monotonic()
    report = initial_report(hepta)
    save_report(report_path, report)
    try:
        builder = prepare_native(output, hepta, report)
        tests = native_tests()
        run_native_checks(output, report, tests, native_environment(output, hepta, report),
                          timeout=180, commands=native_commands(output, report, tests))
        collect_native_evidence(output, report)
        finish_native(output, report, builder)
    except BaseException as exc:
        report["status"] = "FAIL"
        report["native_components_status"] = "FAIL"
        report["rust_comparison_status"] = "NOT_RUN"
        if report["compiler_cold_status"] in {"PENDING", "RUNNING"}:
            report["compiler_cold_status"] = "FAIL"
        if report["retained_python_comparison_status"] == "PENDING":
            report["retained_python_comparison_status"] = "NOT_RUN"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        (output / "failure.txt").write_text(traceback.format_exc())
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["native_components_elapsed_seconds"] = time.monotonic() - started
    report["native_components_finished_at"] = datetime.now(timezone.utc).isoformat()
    save_report(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path,
                        help="new output directory; existing results are never overwritten")
    args = parser.parse_args()
    result = run(args.output.resolve(), args.hepta.resolve(strict=True))
    print(json.dumps({"status": result["status"], "rust_comparison_status": result["rust_comparison_status"],
                      "compiler_cold_status": result["compiler_cold_status"],
                      "retained_python_comparison_status": result["retained_python_comparison_status"],
                      "report": str(args.output.resolve() / "result.json"),
                      "check_processes": len(result["checks"]), "whole_runtime_replaced": False}, sort_keys=True))
    return 0 if result["status"] == "NATIVE_COMPONENTS_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
