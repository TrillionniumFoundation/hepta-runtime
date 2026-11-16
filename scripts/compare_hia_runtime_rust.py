"""Finish native qualification with original owners and independent Rust references.

The aggregate result can become PASS only after all required recipes match the
retained native corpus. Replaying a corpus does not add new native test cases.
"""
from __future__ import annotations

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import struct
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_service_pipeline as service_pipeline
import hia_native_public_registry_qualification as public_registry_qualification
import hia_native_result_qualification as result_qualification
import hia_native_serde_error_pipeline as serde_error_pipeline
import hia_native_result_storage_pipeline as storage_pipeline
import hia_native_batch_write_pipeline as batch_write_pipeline
from qualify_hia_runtime_native import (MODULES, completed_test_summary, entropy_evidence,
                                       PARALLEL_NATIVE_SUITES,
                                       editable_content_evidence, view_render_evidence, view_cache_evidence,
                                       view_render_growth_evidence, view_call_evidence, view_search_evidence,
                                       view_search_public_evidence, view_regex_search_evidence,
                                       view_regex_search_public_evidence,
                                       view_resource_evidence, runtime_mcp_evidence, view_fixture_retirement,
                                       runtime_mcp_fixture_retirement,
                                       line_verify_evidence, batch_plan_evidence, batch_apply_evidence, caller_authority_evidence,
                                       history_evidence, json_evidence, request_context_evidence, result_publication_evidence,
                                       request_scope_evidence, shell_evidence, shell_process_evidence, shell_background_evidence,
                                       shell_outcome_evidence, shell_output_evidence, shell_foreground_evidence, shell_completed_process,
                                       shell_retained_files, execution_evidence, effect_fence_evidence, config_evidence,
                                       session_evidence, file_locks_evidence, file_lock_service_evidence, filesystem_parity_evidence,
                                       filesystem_parity_retirement, atomic_write_evidence, atomic_write_completed_process, atomic_write_retained_files,
                                       write_chain_evidence, directory_service_evidence, workdir_service_evidence, sdk_connection_evidence,
                                       public_registry_evidence, result_values_evidence, serde_error_evidence, result_storage_evidence, batch_write_evidence,
                                       filesystem_public_evidence, filesystem_public_retirement,
                                       atomic_write_retire_fixtures,
                                       file_info_evidence, multi_read_controller_evidence, native_composition_evidence,
                                       operation_aead_evidence, operation_kdf_evidence, operation_nonce_evidence,
                                       operation_record_evidence, operation_scope_evidence,
                                       operation_scope_os_evidence,
                                       python_reference_evidence, qualification_env,
                                       record_check, save_report, sha, sources)
from check_hia_native_inventory import RUNTIME_BASE_COMMIT, check_original_sources
from hia_native_build import HEPTA_COMMIT
from hia_native_cold import validate_cold_evidence
from hia_native_entropy_qualification import (FOLDER as ENTROPY_FOLDER, KERNEL_RECEIPT,
                                             ORIGINAL_SOURCE as ENTROPY_ORIGINAL_SOURCE,
                                             normalized_kernel_report, object_at as entropy_object,
                                             oracle_dependencies as entropy_dependencies)
from hia_native_scope_qualification import FOLDER as SCOPE_FOLDER, ORACLE_COUNTS as SCOPE_ORACLE_COUNTS
from hia_native_editable_qualification import FOLDER as EDITABLE_FOLDER, CASES as EDITABLE_CASES
from hia_native_view_qualification import FOLDER as VIEW_FOLDER, CASES as VIEW_CASES, stream_identity as view_stream_identity
from hia_native_view_growth_qualification import (FOLDER as VIEW_GROWTH_FOLDER, CASES as VIEW_GROWTH_CASES,
                                                 stream_identity as view_growth_stream_identity)
from hia_native_view_cache_qualification import compare_original as compare_cache_original
from hia_native_authority_qualification import compare_original as compare_authority_original
from hia_native_history_qualification import compare_original as compare_history_original
from hia_native_json_qualification import (compare_original as compare_json_original,
                                           check_original_receipts as check_json_original_receipts)
from hia_native_request_context_reference import (compare_original as compare_request_original,
                                                  check_original_receipts as check_request_original_receipts)
from hia_native_result_publication_reference import (compare_original as compare_publication_original,
                                                     check_original_receipts as check_publication_original_receipts)
from hia_native_request_scope_reference import (compare_original as compare_request_scope_original,
                                                check_original_receipts as check_request_scope_original_receipts)
import hia_native_shell_qualification as shell_qualification
import hia_native_shell_capture_gate as capture_gate
import hia_native_bellman_qualification as bellman_qualification
import hia_native_bellman_commitment_qualification as bellman_commitment_qualification
import hia_native_local_create_pipeline as local_create_qualification
import hia_native_local_create_spec_qualification as local_create_spec_qualification
import hia_native_text_editor_params_qualification as text_editor_params_qualification
from hia_native_batch_plan_qualification import (FOLDER as BATCH_PLAN_FOLDER,
                                                ORIGINALS as BATCH_PLAN_ORIGINALS,
                                                REFERENCE_ROWS as BATCH_PLAN_ROWS)
from hia_native_scope_os_qualification import (FOLDER as SCOPE_OS_FOLDER, PAIRED_RECEIPT as SCOPE_OS_PAIRED_RECEIPT,
                                              exact_profile as scope_os_profile, paired_evidence as scope_os_paired_evidence)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def packet_count(raw: bytes, *, output: bool) -> int:
    offset, count = 0, 0
    while offset < len(raw):
        if len(raw) - offset < 16:
            raise ValueError("truncated oracle corpus header")
        first, second = struct.unpack_from("<QQ", raw, offset)
        size = second if output else first
        offset += 16
        if size > len(raw) - offset:
            raise ValueError("truncated oracle corpus payload")
        offset += size
        count += 1
    return count


def executable(name: str) -> Path:
    selected = shutil.which(name)
    if selected is None:
        raise FileNotFoundError("required compiler executable unavailable: " + name)
    # Keep a rustup shim's argv[0] while reporting its resolved bytes separately.
    return Path(selected).absolute()


def check_input_pins(output: Path, report: dict) -> None:
    if sources() != report["source_sha256"]:
        raise ValueError("source inputs differ from the completed native phase")
    if "qualification_pipeline" in report:
        from hia_native_pipeline import verify_pipeline_receipts
        verify_pipeline_receipts(output, report)
    if "original_qualification_pipeline" in report:
        from hia_native_rust_pipeline import verify_collected_receipts
        verify_collected_receipts(output, report)
    originals = check_original_sources(ROOT)
    if report.get("inventory", {}).get("original_sources") != originals:
        raise ValueError("original Rust reference inventory differs from the native phase")
    bootstrap = output / "build/bootstrap/bootstrap.json"
    if sha(bootstrap) != report.get("compiler_bootstrap_sha256"):
        raise ValueError("compiler bootstrap receipt differs from the native phase")
    for label in ("B1", "B2", "B3"):
        if sha(bootstrap.with_name(label + ".image.bin")) != report["compiler_image_sha256"]:
            raise ValueError("native compiler fixed-point image changed")
    boot = json.loads(bootstrap.read_bytes())
    cold = validate_cold_evidence(output / "compiler-cold.json", dependency=boot["dependency"],
                                  compiler_sha256=report["compiler_image_sha256"])
    if (report.get("matching_source_full_cold_qualified") is not True
            or report.get("compiler_cold_status") != "PASS"
            or report.get("compiler_cold_evidence") != cold):
        raise ValueError("required matching-source full cold evidence differs")
    if report.get("text_editor_params_evidence") != text_editor_params_qualification.native_evidence(output, report):
        raise ValueError("required Text Editor parameter native evidence differs")
    if "text_editor_params" in report.get("original_rust_comparisons", {}):
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if report["original_rust_comparisons"]["text_editor_params"] != text_editor_params_qualification.original_evidence(output, report, rustc):
            raise ValueError("required target Text Editor type replay differs")
    if report.get("local_create_file_evidence") != local_create_qualification.native_evidence(output, report):
        raise ValueError("required local-create source/native evidence differs")
    if report.get("local_create_segments_evidence") != local_create_qualification.segments.native_evidence(output, report):
        raise ValueError("required segmented Create source/native evidence differs")
    if report.get("local_create_async_held_evidence") != local_create_qualification.held.native_evidence(output, report):
        raise ValueError("required held Create source/native evidence differs")
    if "local_create_file" in report.get("original_rust_comparisons", {}):
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if report["original_rust_comparisons"]["local_create_file"] != local_create_qualification.original_evidence(output, report, rustc):
            raise ValueError("required current-target local-create replay differs")
    if report.get("local_create_spec_evidence") != local_create_spec_qualification.native_evidence(output, report):
        raise ValueError("required complete Local Create native evidence differs")
    if "local_create_spec" in report.get("original_rust_comparisons", {}):
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if report["original_rust_comparisons"]["local_create_spec"] != local_create_spec_qualification.original_evidence(output, report, rustc):
            raise ValueError("required complete Local Create original replay differs")
    if report.get("bellman_evidence") != bellman_qualification.native_evidence(output, report):
        raise ValueError("required Bellman native hardware/corpus/static evidence differs")
    if report.get("bellman_commitment_evidence") != bellman_commitment_qualification.native_evidence(output, report):
        raise ValueError("required Bellman typed commitment native evidence differs")
    if "bellman_commitment" in report.get("original_rust_comparisons", {}):
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if report["original_rust_comparisons"]["bellman_commitment"] != bellman_commitment_qualification.original_evidence(output, report, rustc):
            raise ValueError("required actual current-target Bellman typed commitment replay differs")
    if "bellman_core" in report.get("original_rust_comparisons", {}):
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if report["original_rust_comparisons"]["bellman_core"] != bellman_qualification.original_evidence(output, report, rustc):
            raise ValueError("required actual current-target Bellman Rust replay differs")
    if (report.get("retained_python_comparison_status") != "PASS"
            or report.get("original_python_comparisons") != python_reference_evidence(output, report)):
        raise ValueError("required retained-Python IO/stat-version/local-service evidence differs")
    if report.get("native_composition_evidence") != native_composition_evidence(output, report):
        raise ValueError("required native composition evidence differs")
    if report.get("multi_read_controller_evidence") != multi_read_controller_evidence(output, report):
        raise ValueError("required multi-read controller evidence differs")
    if report.get("operation_kdf_evidence") != operation_kdf_evidence(output, report):
        raise ValueError("required operation KDF primitive/binding evidence differs")
    if report.get("operation_aead_evidence") != operation_aead_evidence(output, report):
        raise ValueError("required operation AEAD/authentication evidence differs")
    if report.get("operation_nonce_evidence") != operation_nonce_evidence(output, report):
        raise ValueError("required operation nonce state/ELF evidence differs")
    if report.get("operation_record_evidence") != operation_record_evidence(output, report):
        raise ValueError("required operation record composition/reference evidence differs")
    if report.get("file_info_evidence") != file_info_evidence(output, report):
        raise ValueError("required file-info controller/metadata/deadline evidence differs")
    if report.get("system_entropy_evidence") != entropy_evidence(output, report):
        raise ValueError("required entropy compiler/effect/transport/trace evidence differs")
    if report.get("operation_scope_evidence") != operation_scope_evidence(output, report):
        raise ValueError("required private scope lifetime/composition/reference-domain evidence differs")
    if report.get("editable_content_evidence") != editable_content_evidence(output, report):
        raise ValueError("required editable state/byte-preservation/static-image evidence differs")
    if report.get("line_verify_evidence") != line_verify_evidence(output, report):
        raise ValueError("required line-ID verification/diagnostic/index evidence differs")
    from hia_native_batch_edit_params_pipeline import native_evidence as batch_params_native
    from hia_native_batch_edit_params_pipeline import retained_original as batch_params_original
    if batch_params_native(ROOT, output, report, completed_test_summary) != report.get("batch_edit_params_evidence"):
        raise ValueError("registered batch parameter native evidence differs")
    if "batch_edit_params" in report.get("original_rust_comparisons", {}):
        if batch_params_original(ROOT, output, report, completed_test_summary) != report["original_rust_comparisons"]["batch_edit_params"]:
            raise ValueError("registered batch parameter original evidence differs")
    from hia_native_batch_plan_input_pipeline import native_evidence as batch_input_native
    from hia_native_batch_plan_input_pipeline import retained_original as batch_input_original
    if batch_input_native(ROOT, output, report, completed_test_summary) != report.get("batch_plan_input_evidence"):
        raise ValueError("registered batch Planner input native evidence differs")
    if "batch_plan_input" in report.get("original_rust_comparisons", {}):
        if batch_input_original(ROOT, output, report, completed_test_summary) != report["original_rust_comparisons"]["batch_plan_input"]:
            raise ValueError("registered batch Planner input original evidence differs")
    from hia_native_batch_diff_pipeline import native_evidence as batch_diff_native
    from hia_native_batch_diff_pipeline import retained_original as batch_diff_original
    if batch_diff_native(ROOT, output, report, completed_test_summary) != report.get("batch_diff_evidence"):
        raise ValueError("registered complete batch diff native evidence differs")
    if "batch_diff" in report.get("original_rust_comparisons", {}):
        if batch_diff_original(ROOT, output, report, completed_test_summary) != report["original_rust_comparisons"]["batch_diff"]:
            raise ValueError("registered complete batch diff original evidence differs")
    if report.get("batch_plan_evidence") != batch_plan_evidence(output, report):
        raise ValueError("required complete batch input/endpoint/large-result evidence differs")
    if report.get("batch_apply_evidence") != batch_apply_evidence(output, report):
        raise ValueError("required batch application complete native execution evidence differs")
    if report.get("atomic_write_evidence") != atomic_write_evidence(output, report):
        raise ValueError("required atomic policy, kernel, boundary or refusal evidence differs")
    if report.get("filesystem_parity_evidence") != filesystem_parity_evidence(output, report):
        raise ValueError("required complete native filesystem state, build and kernel evidence differs")
    if report.get("filesystem_parity_fixture_retirement") != filesystem_parity_retirement(output, report):
        raise ValueError("required private filesystem fixture retirement evidence differs")
    if "filesystem_parity" in report.get("original_rust_comparisons", {}):
        rustc = Path(report["rust_compiler"]["invocation_path"])
        retained = retained_filesystem_parity(output, report, rustc)
        if report["original_rust_comparisons"]["filesystem_parity"] != retained:
            raise ValueError("required complete original filesystem invocation or retained corpus differs")
    if "atomic_write" in report.get("original_rust_comparisons", {}):
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if report["original_rust_comparisons"]["atomic_write"] != atomic_write_original_evidence(output, report, rustc):
            raise ValueError("required actual atomic original invocation or retained corpus differs")
    if report.get("view_render_evidence") != view_render_evidence(output, report):
        raise ValueError("required complete view byte-domain/cache-plan/transport evidence differs")
    if report.get("view_render_growth_evidence") != view_render_growth_evidence(output, report):
        raise ValueError("required growing view snapshots and physical evidence differ")
    local_view = view_call_evidence(output, report)
    if report.get("view_call_evidence") != local_view:
        raise ValueError("required local view reader, typed parameters and complete caller evidence differ")
    local_search = view_search_evidence(output, report)
    if report.get("view_search_evidence") != local_search:
        raise ValueError("required literal search native producer and complete corpus evidence differ")
    local_regex_search = view_regex_search_evidence(output, report)
    if report.get("view_regex_search_evidence") != local_regex_search:
        raise ValueError("required regex search native producer and complete corpus evidence differ")
    if report.get("view_resource_evidence") != view_resource_evidence(output, report):
        raise ValueError("required view engine allocation/cleanup process evidence differs")
    public_mcp = runtime_mcp_evidence(output, report)
    if report.get("runtime_mcp_evidence") != public_mcp:
        raise ValueError("required complete public MCP execution and evidence controls differ")
    public_filesystem = filesystem_public_evidence(output, report)
    if report.get("filesystem_public_evidence") != public_filesystem:
        raise ValueError("required public filesystem native-only evidence differs")
    if report.get("filesystem_public_fixture_retirement") != filesystem_public_retirement(
            output, report, native=public_filesystem):
        raise ValueError("required public filesystem fixture archival differs")
    if "filesystem_public" in report.get("original_rust_comparisons", {}):
        from hia_native_filesystem_public_pipeline import retained_original as filesystem_public_original
        if filesystem_public_original(ROOT, output, report, completed_test_summary) != report["original_rust_comparisons"]["filesystem_public"]:
            raise ValueError("required fresh public filesystem original or physical refusal evidence differs")
    public_search = view_search_public_evidence(output, report)
    if report.get("view_search_public_evidence") != public_search:
        raise ValueError("required complete public literal search producer evidence differs")
    public_regex_search = view_regex_search_public_evidence(output, report)
    if report.get("view_regex_search_public_evidence") != public_regex_search:
        raise ValueError("required complete public regex search producer evidence differs")
    if report.get("view_fixture_retirement") != view_fixture_retirement(
            output, report, native=local_view, public=public_mcp, search=local_search,
            public_search=public_search, regex_search=local_regex_search,
            public_regex_search=public_regex_search):
        raise ValueError("complete owned view test fixture retention differs")
    if report.get("runtime_mcp_fixture_retirement") != runtime_mcp_fixture_retirement(
            output, report, public=public_mcp, public_search=public_search,
            public_regex_search=public_regex_search):
        raise ValueError("complete public FIFO/hardlink/attribute fixture retention differs")
    local_comparisons = report.get("original_rust_comparisons", {})
    if "runtime_mcp" in local_comparisons:
        if local_comparisons["runtime_mcp"] != compare_runtime_mcp(output, report, None):
            raise ValueError("required public MCP original comparison differs")
    if any(key in local_comparisons for key in ("view_read", "view_params", "view_call")):
        from hia_native_view_call_qualification import compare_original as checked_view_original
        original = checked_view_original(ROOT, output, report, local_view)
        for key in ("view_read", "view_params", "view_call"):
            if key in local_comparisons and local_comparisons[key] != original:
                raise ValueError("shared original view execution or retained complete bytes differ")
    if (any(key in local_comparisons for key in ("view_read", "view_params", "view_call", "runtime_mcp"))
            or "view_search_original_comparison" in report
            or "view_search_public_original_comparison" in report
            or any(row.get("name") in VIEW_SEARCH_ORIGINAL_CHECKS for row in report["checks"])):
        # These two wrappers are required even though search shares the view
        # component/recipe entry. A successful nine-process view comparison
        # cannot stand in for the additional three original search processes.
        search_original = compare_view_search(output, report, native=local_search)
        if "runtime_mcp" in local_comparisons or "view_search_public_original_comparison" in report:
            compare_view_search_public(output, report, search_original, native=public_search)
    if (any(key in local_comparisons for key in ("view_read", "view_params", "view_call", "runtime_mcp"))
            or "view_regex_search_original_comparison" in report
            or "view_regex_search_public_original_comparison" in report
            or any(row.get("name") in VIEW_REGEX_SEARCH_ORIGINAL_CHECKS for row in report["checks"])):
        regex_original = compare_view_regex_search(output, report, native=local_regex_search)
        if "runtime_mcp" in local_comparisons or "view_regex_search_public_original_comparison" in report:
            compare_view_regex_search_public(output, report, regex_original, native=public_regex_search)
    if report.get("json_evidence") != json_evidence(output, report):
        raise ValueError("required JSON actual native/ELF/corpus evidence differs")
    if report.get("request_context_evidence") != request_context_evidence(output, report):
        raise ValueError("required request context state/response/transport evidence differs")
    check_request_original_receipts(ROOT, output, report, completed_test_summary)
    if report.get("result_publication_evidence") != result_publication_evidence(output, report):
        raise ValueError("required result publication construction/ELF/write evidence differs")
    check_publication_original_receipts(ROOT, output, report, completed_test_summary)
    if report.get("request_scope_evidence") != request_scope_evidence(output, report):
        raise ValueError("required request continuation/cache lease/native refusal evidence differs")
    check_request_scope_original_receipts(ROOT, output, report, completed_test_summary)
    if report.get("shell_evidence") != shell_evidence(output, report):
        raise ValueError("required complete native shell evidence changed")
    if report.get("shell_process_evidence") != shell_process_evidence(output, report):
        raise ValueError("required native shell process evidence changed")
    if report.get("shell_background_evidence") != shell_background_evidence(output, report):
        raise ValueError("required native shell background evidence changed")
    if report.get("shell_outcome_evidence") != shell_outcome_evidence(output, report):
        raise ValueError("required native shell outcome evidence changed")
    if report.get("shell_output_evidence") != shell_output_evidence(output, report):
        raise ValueError("required native shell output IO/outcome evidence changed")
    if report.get("shell_foreground_evidence") != shell_foreground_evidence(output, report):
        raise ValueError("required native foreground process/IO/outcome evidence changed")
    for key in capture_gate.KEYS:
        capture_gate.exact(report.get(key + "_evidence"), capture_gate.native_evidence(output, report, key),
                           "required native capture evidence changed")
    comparisons = report.get("original_rust_comparisons", {})
    for key in capture_gate.KEYS:
        if key in comparisons:
            rustc = Path(report["rust_compiler"]["invocation_path"])
            capture_gate.exact(comparisons[key], capture_gate.original_evidence(output, report, key, rustc),
                               "required original capture evidence changed")
    if "shell_process" in comparisons:
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if comparisons["shell_process"] != shell_process_original_evidence(output, report, rustc):
            raise ValueError("required fresh original shell process evidence changed")
    if "shell_background_text" in comparisons:
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if comparisons["shell_background_text"] != shell_background_original_evidence(output, report, rustc):
            raise ValueError("required fresh original background byte evidence changed")
    if "shell_outcome" in comparisons:
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if comparisons["shell_outcome"] != shell_outcome_original_evidence(output, report, rustc):
            raise ValueError("required fresh original shell outcome evidence changed")
    if "shell_output_io" in comparisons:
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if comparisons["shell_output_io"] != shell_output_original_evidence(output, report, rustc):
            raise ValueError("required original/native real output IO evidence changed")
    if "shell_foreground" in comparisons:
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if comparisons["shell_foreground"] != shell_foreground_original_evidence(output, report, rustc):
            raise ValueError("required original/native complete foreground evidence changed")
    for key in shell_qualification.COMPONENTS:
        if key in report.get("original_rust_comparisons", {}):
            rustc = Path(report["rust_compiler"]["invocation_path"])
            expected = shell_qualification.original_evidence(ROOT, output, report, key, rustc,
                executable(str(rustc.with_name("cargo"))), completed_test_summary)
            if report["original_rust_comparisons"][key] != expected:
                raise ValueError("required fresh shell original evidence changed")
    if report.get("execution_evidence") != execution_evidence(output, report):
        raise ValueError("required execution typed/core/controller evidence differs")
    if report.get("effect_fence_evidence") != effect_fence_evidence(output, report):
        raise ValueError("required effect fence actual process/lifetime/kernel evidence differs")
    if report.get("config_evidence") != config_evidence(output, report):
        raise ValueError("required configuration native evidence differs")
    from hia_native_config_span_pipeline import qualification_evidence as span_native
    from hia_native_config_span_pipeline import native_fixture_evidence as span_retired
    from hia_native_config_span_pipeline import retained_original as span_original
    span = span_native(ROOT, output, report, completed_test_summary)
    if span != report.get("config_span_evidence"):
        raise ValueError("required native configuration span evidence differs")
    if span_retired(ROOT, output, report, completed_test_summary, native=span) != report.get("config_span_fixture_retirement"):
        raise ValueError("required configuration span fixture retirement differs")
    if "runtime_config_span" in report.get("original_rust_comparisons", {}):
        if report["original_rust_comparisons"]["runtime_config_span"] != span_original(ROOT, output, report, completed_test_summary):
            raise ValueError("required fresh configuration span original comparison differs")
    if "runtime_config" in report.get("original_rust_comparisons", {}):
        if report["original_rust_comparisons"]["runtime_config"] != retained_config_original(output, report):
            raise ValueError("required complete original configuration evidence differs")
    if "execution_shadow" in report.get("original_rust_comparisons", {}):
        if report["original_rust_comparisons"]["execution_shadow"] != retained_execution_original(output, report):
            raise ValueError("required complete original execution replay changed")
    check_json_original_receipts(ROOT, output, report, completed_test_summary)
    if report.get("history_evidence") != history_evidence(output, report):
        raise ValueError("required history state/original-domain/static-image evidence differs")
    import hia_native_file_lock_pipeline as file_lock_pipeline
    for key, evidence in (("file_locks", file_locks_evidence), ("file_lock_service", file_lock_service_evidence)):
        if report.get(key + "_evidence") != evidence(output, report):
            raise ValueError("required complete file-lock native process evidence differs: " + key)
        if key in report.get("original_rust_comparisons", {}):
            rustc = Path(report["rust_compiler"]["invocation_path"])
            actual = file_lock_pipeline.retained_original(ROOT, output, report, rustc, completed_test_summary, key)
            if report["original_rust_comparisons"][key] != actual:
                raise ValueError("required actual file-lock original invocation changed: " + key)
    if report.get("session_evidence") != session_evidence(output, report):
        raise ValueError("required session state, latch, full corpus and executable evidence differs")
    import hia_native_write_chain_pipeline as write_chain_pipeline
    for key, inspect in (("write_chain", write_chain_evidence), ("directory_service", directory_service_evidence),
                         ("workdir_service", workdir_service_evidence), ("sdk_connection", sdk_connection_evidence)):
        if report.get(key + "_evidence") != inspect(output, report):
            raise ValueError("required complete service native evidence differs: " + key)
        if key in report.get("original_rust_comparisons", {}):
            rustc = Path(report["rust_compiler"]["invocation_path"])
            actual = (write_chain_pipeline.retained_original(ROOT, output, report, rustc, completed_test_summary)
                      if key == "write_chain" else service_pipeline.retained_original(
                          ROOT, output, report, rustc, completed_test_summary, key))
            if report["original_rust_comparisons"][key] != actual:
                raise ValueError("required actual service original invocation changed: " + key)
    if report.get("batch_write_evidence") != batch_write_evidence(output, report):
        raise ValueError("complete batch-write native evidence changed")
    if "batch_write" in report.get("original_rust_comparisons", {}):
        rustc = Path(report["rust_compiler"]["invocation_path"])
        actual = batch_write_pipeline.retained_original(ROOT, output, report, rustc, completed_test_summary)
        if report["original_rust_comparisons"]["batch_write"] != actual:
            raise ValueError("complete original batch-write replay changed")
    if report.get("serde_error_evidence") != serde_error_evidence(output, report):
        raise ValueError("complete diagnostic native evidence changed")
    if report.get("result_storage_evidence") != result_storage_evidence(output, report):
        raise ValueError("complete storage native evidence changed")
    for key, domain in storage_pipeline.KEYS.items():
        if key in report.get("original_rust_comparisons", {}):
            actual = storage_pipeline.original_evidence(ROOT, output, report, completed_test_summary, domain)
            if report["original_rust_comparisons"][key] != actual:
                raise ValueError("complete original storage evidence changed: " + key)
    if "result_storage_evidence_controls" in report:
        if report["result_storage_evidence_controls"] != storage_pipeline.control_evidence(
                ROOT, output, report, completed_test_summary):
            raise ValueError("complete storage evidence controls changed")
    elif report.get("status") == "PASS":
        raise ValueError("completed aggregate omitted storage evidence controls")
    if "serde_error" in report.get("original_rust_comparisons", {}):
        actual = serde_error_pipeline.original_evidence(ROOT, output, report, completed_test_summary)
        if report["original_rust_comparisons"]["serde_error"] != actual:
            raise ValueError("complete diagnostic original replay changed")
    if report.get("result_values_evidence") != result_values_evidence(output, report):
        raise ValueError("complete typed result native evidence changed")
    for key, domain in result_qualification.KEYS.items():
        if key in report.get("original_rust_comparisons", {}):
            if report["original_rust_comparisons"][key] != result_qualification.original_evidence(ROOT, output, report, completed_test_summary, domain):
                raise ValueError("complete typed result original evidence changed: " + key)
    if "result_values_evidence_controls" in report:
        if report["result_values_evidence_controls"] != result_values_control_evidence(output, report):
            raise ValueError("typed result original controls changed")
    if report.get("public_registry_evidence") != public_registry_evidence(output, report):
        raise ValueError("required public registry native process evidence differs")
    if "public_registry" in report.get("original_rust_comparisons", {}):
        actual = public_registry_qualification.original_evidence(ROOT, output, report, completed_test_summary)
        if report["original_rust_comparisons"]["public_registry"] != actual:
            raise ValueError("required actual public registry original replay differs")
    if "public_registry_evidence_controls" in report:
        if report["public_registry_evidence_controls"] != public_registry_control_evidence(output, report):
            raise ValueError("actual public registry evidence controls differ")
    elif report.get("status") == "PASS":
        raise ValueError("completed aggregate omitted public registry evidence controls")
    if "service_original_fixture_retirement" in report:
        rustc = Path(report["rust_compiler"]["invocation_path"])
        actual = service_pipeline.original_fixture_transport(ROOT, output, report, rustc, completed_test_summary)
        if report["service_original_fixture_retirement"] != actual:
            raise ValueError("service original fixture retirement differs")
    if "session_workdir" in report.get("original_rust_comparisons", {}):
        import hia_native_session_qualification as session_qualification
        rustc = Path(report["rust_compiler"]["invocation_path"])
        actual = session_qualification.retained_original(ROOT, output, report, rustc, completed_test_summary)
        if report["original_rust_comparisons"]["session_workdir"] != actual:
            raise ValueError("required actual session original invocation changed")
    if report.get("view_cache_evidence") != view_cache_evidence(output, report):
        raise ValueError("required cache state/lifecycle/view-plan/transport evidence differs")
    if report.get("operation_scope_os_evidence") != operation_scope_os_evidence(output, report):
        raise ValueError("required actual OS entropy/scope/custody evidence differs")
    if report.get("caller_authority_evidence") != caller_authority_evidence(output, report):
        raise ValueError("required caller authority/source/image/OS/complete-corpus evidence differs")
    for collection in ("rust_oracle_inputs", "python_reference_inputs"):
        for relative, expected in report[collection].items():
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts or sha(output / path) != expected:
                raise ValueError("retained native reference corpus changed: " + relative)
    if set(report.get("native_parallel_receipts", {})) != {
            name + ".execution.json" for name in PARALLEL_NATIVE_SUITES}:
        raise ValueError("independent native process receipt inventory differs")
    for relative, expected in report["native_parallel_receipts"].items():
        if Path(relative).name != relative or sha(output / relative) != expected:
            raise ValueError("independent native process receipt changed")
        receipt = json.loads((output / relative).read_bytes())
        rows = receipt.get("checks", [])
        if (len(rows) != 1 or rows[0] not in report["checks"] or rows[0].get("exit_code") != 0
                or rows[0].get("timed_out") is not False or rows[0].get("start_error")):
            raise ValueError("independent native process did not finish successfully")
    if report.get("original_rust_comparisons"):
        receipts = report.get("rust_parallel_receipts", {})
        completed_parallel = {key: value for key, value in PARALLEL_RUST_RECIPES.items()
                              if key in report["original_rust_comparisons"]}
        expected_receipts = {value[0] for value in completed_parallel.values()}
        if set(receipts) != expected_receipts:
            raise ValueError("independent original reference receipt inventory differs")
        for key, (name, expected) in completed_parallel.items():
            path = output / name
            if sha(path) != receipts[name]:
                raise ValueError("independent original reference receipt changed")
            private = json.loads(path.read_bytes())
            rows = [row for row in private.get("checks", []) if row["name"] in expected]
            if ([row["name"] for row in rows] != list(expected)
                    or any(row not in report["checks"] or row["exit_code"] != 0
                           or row["timed_out"] is not False for row in rows)):
                raise ValueError("independent original reference completion differs: " + key)
    check_compiled_modules(output, report)


def check_compiled_modules(output: Path, report: dict) -> None:
    """Reopen each registered build according to its explicit manifest schema."""
    declared = {item["key"]: item for item in MODULES}
    for key, item in report["modules"].items():
        expected = declared[key]
        relative = Path(item["manifest"])
        if (item.get("source") != expected["source"]
                or item.get("builder") != expected.get("builder", "borrowed_bytes")
                or relative.is_absolute() or ".." in relative.parts):
            raise ValueError("compiled module registry or retained path differs: " + key)
        manifest = output / relative
        if sha(manifest) != item["sha256"]:
            raise ValueError("compiled module manifest changed")
        module = json.loads(manifest.read_bytes())
        if item.get("builder") in {"view_call", "batch_diff"}:
            # Its strict bundle reader above checked every child and packer
            # compiler identity, complete input/output and composed ELF.
            continue
        compiler_field = "compiler_image_sha256" if item.get("builder") in {"runtime_mcp", "filesystem_public"} else "compiler_sha256"
        compiler = capture_gate.compiler_identity(output, report, key) if key in capture_gate.KEYS else module
        if (compiler.get("compiler_commit") != HEPTA_COMMIT
                or compiler.get(compiler_field) != report["compiler_image_sha256"]):
            raise ValueError("compiled module compiler identity changed")
        if item.get("builder") in {'composition', 'record_composition', 'scope_composition', 'scope_os_composition', 'entropy', 'authority_composition', 'batch_plan', 'batch_edit_params', 'text_editor_params', 'batch_plan_input', 'filesystem_public', 'batch_apply', 'atomic_write', 'filesystem_parity', 'history', 'execution_shadow', 'effect_fence', 'runtime_config', 'runtime_config_span', 'result_publication', 'session_workdir', 'request_scope', 'file_locks', 'file_lock_service', 'view_read', 'runtime_mcp', 'shell_process', 'shell_outcome', 'shell_output', 'shell_foreground', *capture_gate.KEYS, 'write_chain', 'directory_service', 'workdir_service', 'sdk_connection', 'public_registry', 'result_values', 'batch_write', 'result_storage'}:
            # The appropriate fixed table, all child source/image pairs,
            # packer and executable were revalidated above, including its suite.
            continue
        if item.get("builder") == "io":
            if (module.get("schema") != "hepta.runtime.native-io.v1"
                    or module.get("executable") != "native-read.elf"
                    or module.get("policy_manifest") != "policy.json"
                    or sha(manifest.parent / "native-read.elf") != module["executable_sha256"]
                    or sha(manifest.parent / "policy.json") != module["policy_manifest_sha256"]):
                raise ValueError("native IO executable or policy manifest changed")
            for kind in ("policy", "packer"):
                if (sha(manifest.parent / (kind + ".hepta")) != module[kind + "_source_sha256"]
                        or sha(ROOT / "native" / ("io_" + kind + ".hepta")) != module[kind + "_source_sha256"]):
                    raise ValueError("native IO source changed: " + kind)
            policy = json.loads((manifest.parent / "policy.json").read_bytes())
            if (policy.get("source") != "policy.hepta" or policy.get("image") != "policy.image.bin"
                    or policy.get("compiler_commit") != HEPTA_COMMIT
                    or policy.get("compiler_sha256") != report["compiler_image_sha256"]
                    or policy.get("source_sha256") != module["policy_source_sha256"]
                    or sha(manifest.parent / "policy.image.bin") != policy.get("image_sha256")):
                raise ValueError("native IO policy image changed")
            continue
        if item.get("builder") == "local_create":
            # This is a packed composition. Reopen its complete fixed source,
            # child image, packer arrays and ELF through the existing owner.
            local_create_qualification.blocking.verify_build(manifest, source_root=ROOT)
            continue
        if item.get("builder") == "local_create_spec":
            local_create_spec_qualification.verify_build(manifest, source_root=ROOT)
            continue
        for label in ("source", "image"):
            if label not in module or label + "_sha256" not in module:
                raise ValueError("flat native module omitted its declared artifact: " + label)
            if sha(manifest.parent / module[label]) != module[label + "_sha256"]:
                raise ValueError("compiled module artifact changed: " + label)
        standalone = module.get("standalone")
        if standalone and sha(manifest.parent / standalone["path"]) != standalone["sha256"]:
            raise ValueError("compiled standalone executable changed")


def rust_compile(output: Path, report: dict, rustc: Path, *, key: str,
                 source: Path, binary: Path, extra: tuple[str, ...] = (), edition: str = "2021") -> None:
    if binary.exists():
        raise ValueError("oracle executable already exists: " + str(binary))
    record_check(output, report, name=key + "-compile",
                 command=[str(rustc), "-O", "--edition=" + edition, *extra, str(source), "-o", str(binary)],
                 timeout=120)


def compare_bytes(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    if corpus["schema"] != "hepta.runtime.bytes-native-tests.v1":
        raise ValueError("unknown byte corpus schema")
    values = {}
    for name in ("input.bin.gz", "native-output.bin.gz"):
        packed = (folder / name).read_bytes()
        raw = gzip.decompress(packed)
        entry = corpus["corpus"][name]
        if (digest(packed), len(packed), digest(raw), len(raw)) != (
                entry["sha256"], entry["compressed_bytes"], entry["raw_sha256"], entry["raw_bytes"]):
            raise ValueError("byte corpus metadata mismatch: " + name)
        values[name] = raw
    wire, expected = values["input.bin.gz"], values["native-output.bin.gz"]
    count = packet_count(wire, output=False)
    counts = corpus["counts"]
    if (count <= 0 or count != counts["rust_oracle_cases"]
            or packet_count(expected, output=True) != count
            or counts["native_calls"] != count + counts["byte_extension_cases"]):
        raise ValueError("byte corpus case accounting differs")
    module_path = output / report["modules"]["runtime_bytes"]["manifest"]
    if corpus["module"] != json.loads(module_path.read_bytes()):
        raise ValueError("byte corpus belongs to a different native module")
    binary = folder / "oracle"
    source = ROOT / "tests/hia_native/oracle_runtime_bytes.rs"
    rust_compile(output, report, rustc, key="runtime-bytes-rust", source=source, binary=binary)
    row = record_check(output, report, name="runtime-bytes-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": count, "native_cases_added_by_replay": 0,
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust byte oracle disagrees with the native corpus")
    return result


def compare_text(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "text-rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    wire = (folder / "requests.hex").read_bytes()
    expected = (folder / "native-output.txt").read_bytes()
    source = ROOT / "tests/hia_native/oracle_text_budget.rs"
    if corpus.get("schema") != "hepta.runtime.native-corpus.v1" or corpus.get("component") != "text_budget":
        raise ValueError("unknown text corpus schema")
    if (digest(wire), len(wire), digest(expected), len(expected)) != (
            corpus["requests_sha256"], corpus["requests_bytes"],
            corpus["native_output_sha256"], corpus["native_output_bytes"]):
        raise ValueError("text corpus metadata mismatch")
    count = len(wire.splitlines())
    if count <= 0 or count != corpus["cases"] or len(expected.splitlines()) != count:
        raise ValueError("text corpus case accounting differs")
    if corpus["source_sha256"] != sha(ROOT / "native/text_budget.hepta") or corpus["oracle_sha256"] != sha(source):
        raise ValueError("text corpus source identity differs")
    module = json.loads((output / report["modules"]["text_budget"]["manifest"]).read_bytes())
    if corpus["image_sha256"] != module["image_sha256"]:
        raise ValueError("text corpus belongs to a different native image")
    if (corpus["original_truncation_sha256"] != sha(ROOT / "src/utils/truncation.rs")
            or corpus["original_line_hash_sha256"] != sha(ROOT / "src/utils/line_hash.rs")):
        raise ValueError("original text reference source identity differs")
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="text-budget-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    row = record_check(output, report, name="text-budget-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": count, "native_cases_added_by_replay": 0,
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust text oracle disagrees with the native corpus")
    return result


def compare_endpoint(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "endpoint-rust-oracle"
    metadata = json.loads((folder / "native-corpus.json").read_bytes())
    packed = (folder / "endpoint_cases.jsonl.gz").read_bytes()
    wire = gzip.decompress(packed)
    if metadata.get("schema") != "hepta.runtime.native-corpus.v1":
        raise ValueError("unknown endpoint corpus schema")
    entry = metadata["corpus"]
    if (digest(packed), len(packed), digest(wire), len(wire)) != (
            entry["gzip_sha256"], entry["gzip_bytes"], entry["raw_sha256"], entry["raw_bytes"]):
        raise ValueError("endpoint corpus metadata mismatch")
    count = len(wire.splitlines())
    if count <= 0 or count != metadata["rust_oracle_cases"]:
        raise ValueError("endpoint corpus case accounting differs")
    if metadata["source_sha256"] != sha(ROOT / "native/line_endpoint.hepta"):
        raise ValueError("endpoint corpus source differs")
    cargo = executable("cargo")
    env = dict(os.environ)
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    manifest = ROOT / "tests/hia_native/endpoint_oracle/Cargo.toml"
    target = folder / "target"
    record_check(output, report, name="line-endpoint-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-line-endpoint-reference"
    row = record_check(output, report, name="line-endpoint-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=60)
    result = json.loads(row.stdout)
    if result.get("status") != "PASS" or result.get("rust_oracle_cases") != count or row.stderr:
        raise ValueError("original Rust endpoint oracle disagrees with the native corpus")
    result.update({"native_cases_added_by_replay": 0, "input_sha256": digest(wire),
                   "oracle_executable_sha256": sha(binary), "cargo_manifest_sha256": sha(manifest),
                   "cargo_lock_sha256": sha(manifest.with_name("Cargo.lock"))})
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def compare_delta(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "delta-rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    wire = (folder / "requests.hex").read_bytes()
    expected = (folder / "native-output.txt").read_bytes()
    source = ROOT / "tests/hia_native/oracle_delta.rs"
    if (corpus.get("schema") != "hepta.runtime.native-corpus.v1"
            or corpus.get("component") != "delta"
            or corpus.get("requests_file") != "requests.hex"
            or corpus.get("native_output_file") != "native-output.txt"):
        raise ValueError("unknown delta corpus schema")
    if (digest(wire), len(wire), digest(expected), len(expected)) != (
            corpus["requests_sha256"], corpus["requests_bytes"],
            corpus["native_output_sha256"], corpus["native_output_bytes"]):
        raise ValueError("delta corpus metadata mismatch")
    count = len(wire.splitlines())
    if count <= 0 or count != corpus["cases"] or len(expected.splitlines()) != count:
        raise ValueError("delta corpus case accounting differs")
    if corpus["source_sha256"] != sha(ROOT / "native/delta.hepta") or corpus["oracle_sha256"] != sha(source):
        raise ValueError("delta corpus source identity differs")
    module = json.loads((output / report["modules"]["delta"]["manifest"]).read_bytes())
    if corpus["image_sha256"] != module["image_sha256"]:
        raise ValueError("delta corpus belongs to a different native image")
    if (corpus["original_commit"] != RUNTIME_BASE_COMMIT
            or corpus["original_delta_sha256"] != sha(ROOT / "src/mcp/fs/delta.rs")
            or corpus["original_line_hash_sha256"] != sha(ROOT / "src/utils/line_hash.rs")):
        raise ValueError("original delta reference source identity differs")
    if corpus["rust_compile_flags"] != ["--edition=2021", "-O", "-C", "overflow-checks=off"]:
        raise ValueError("delta reference release semantics differ")
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="delta-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    row = record_check(output, report, name="delta-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": count, "native_cases_added_by_replay": 0,
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust delta oracle disagrees with the native corpus")
    return result


def compare_codec(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "codec-rust-oracle"
    metadata = json.loads((folder / "native-corpus.json").read_bytes())
    if metadata.get("schema") != "hepta.runtime.native-codec-corpus.v1":
        raise ValueError("unknown codec corpus schema")
    packed = (folder / "codec_cases.jsonl.gz").read_bytes()
    wire = gzip.decompress(packed)
    entry = metadata["corpus"]
    if (digest(packed), len(packed), digest(wire), len(wire)) != (
            entry["gzip_sha256"], entry["gzip_bytes"], entry["raw_sha256"], entry["raw_bytes"]):
        raise ValueError("codec corpus metadata mismatch")
    count = wire.count(b"\n")
    if count <= 0 or not wire.endswith(b"\n") or count != metadata["counts"]["rust_oracle_cases"]:
        raise ValueError("codec corpus case accounting differs")
    source = ROOT / "tests/hia_native/oracle_binary_codec.rs"
    manifest = ROOT / "tests/hia_native/codec_oracle/Cargo.toml"
    composition = ROOT / "native/binary_codec_composition.json"
    module = json.loads((output / report["modules"]["binary_codec"]["manifest"]).read_bytes())
    for key, expected in (("source_sha256", module["source_sha256"]),
                          ("image_sha256", module["image_sha256"]),
                          ("oracle_source_sha256", sha(source)),
                          ("cargo_manifest_sha256", sha(manifest)),
                          ("cargo_lock_sha256", sha(manifest.with_name("Cargo.lock"))),
                          ("composition_sha256", sha(composition))):
        if metadata[key] != expected:
            raise ValueError("codec corpus source identity differs: " + key)
    cargo = executable("cargo")
    env = dict(os.environ)
    env["RUSTC"] = str(rustc)
    target = folder / "target"
    record_check(output, report, name="binary-codec-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-binary-codec-reference"
    row = record_check(output, report, name="binary-codec-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=90)
    result = json.loads(row.stdout)
    if result.get("status") != "PASS" or result.get("rust_oracle_cases") != count or row.stderr:
        raise ValueError("independent Rust codec oracle disagrees with the native corpus")
    result.update({"native_cases_added_by_replay": 0, "input_sha256": digest(wire),
                   "oracle_source_sha256": sha(source), "oracle_executable_sha256": sha(binary),
                   "reference_kind": "independent locked Rust crates; original binary policy is Python",
                   "cargo_manifest_sha256": sha(manifest), "cargo_lock_sha256": sha(manifest.with_name("Cargo.lock")),
                   "python_native_test_observation": {"version": metadata["python_reference"],
                       "operation": metadata["running_python_policy"],
                       "cases": metadata["counts"]["running_python_cases"],
                       "scope": "only the observed CPython padding policy was compared directly"}})
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def compare_policy(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "policy-rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    wire = (folder / "requests.hex").read_bytes()
    expected = (folder / "native-output.txt").read_bytes()
    source = ROOT / "tests/hia_native/oracle_policy.rs"
    if (corpus.get("schema") != "hepta.runtime.native-corpus.v1" or corpus.get("component") != "policy"
            or corpus.get("requests_file") != "requests.hex"
            or corpus.get("native_output_file") != "native-output.txt"):
        raise ValueError("unknown policy corpus schema")
    if (digest(wire), len(wire), digest(expected), len(expected)) != (
            corpus["requests_sha256"], corpus["requests_bytes"],
            corpus["native_output_sha256"], corpus["native_output_bytes"]):
        raise ValueError("policy corpus metadata mismatch")
    count = len(wire.splitlines())
    if count <= 0 or count != corpus["cases"] or len(expected.splitlines()) != count:
        raise ValueError("policy corpus case accounting differs")
    module = json.loads((output / report["modules"]["policy"]["manifest"]).read_bytes())
    if (corpus["source_sha256"] != sha(ROOT / "native/policy.hepta")
            or corpus["oracle_sha256"] != sha(source) or corpus["image_sha256"] != module["image_sha256"]
            or corpus["original_commit"] != RUNTIME_BASE_COMMIT
            or corpus["original_config_sha256"] != sha(ROOT / "src/mcp/runtime/config.rs")
            or corpus["composition_sha256"] != sha(ROOT / "native/policy_provenance.json")):
        raise ValueError("policy corpus original/native source identity differs")
    if corpus["rust_compile_flags"] != ["--edition=2021", "-O", "-C", "overflow-checks=off"]:
        raise ValueError("policy reference release semantics differ")
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="policy-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    row = record_check(output, report, name="policy-rust-compare", command=[str(binary)],
                       input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": count, "native_cases_added_by_replay": 0,
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust policy oracle disagrees with the native corpus")
    return result


def compare_multi_read(output: Path, report: dict, rustc: Path) -> dict:
    """Compare unchanged original typed validation, never synthetic file reads."""
    folder = output / "multi-read-rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    if (corpus.get("schema") != "hepta.runtime.multi-read-validation-corpus.v1"
            or corpus.get("cases") != 1689
            or corpus.get("original_source") != "src/mcp/runtime/multi_read.rs"
            or corpus.get("original_source_sha256") != sha(ROOT / "src/mcp/runtime/multi_read.rs")
            or corpus.get("source_sha256") != sha(ROOT / "native/multi_read_service.hepta")):
        raise ValueError("multi-read validation corpus source or scope differs")
    module_path = output / report["modules"]["multi_read_service"]["manifest"]
    module = json.loads(module_path.read_bytes())
    if corpus.get("image_sha256") != module["image_sha256"]:
        raise ValueError("multi-read validation corpus belongs to a different image")
    values = {}
    for name in ("requests.hex.gz", "native-output.txt.gz"):
        packed = (folder / name).read_bytes()
        if digest(packed) != corpus["artifacts"].get(name):
            raise ValueError("multi-read validation compressed corpus differs: " + name)
        values[name] = gzip.decompress(packed)
    wire, expected = values["requests.hex.gz"], values["native-output.txt.gz"]
    if (digest(wire) != corpus.get("request_raw_sha256")
            or digest(expected) != corpus.get("native_output_raw_sha256")
            or len(expected) != corpus.get("native_output_bytes")
            or not wire.endswith(b"\n") or not expected.endswith(b"\n")
            or len(wire.splitlines()) != corpus["cases"] or len(expected.splitlines()) != corpus["cases"]):
        raise ValueError("multi-read validation native case accounting differs")
    source = ROOT / "tests/hia_native/oracle_multi_read.rs"
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="multi-read-rust", source=source, binary=binary, edition="2024")
    row = record_check(output, report, name="multi-read-rust-compare", command=[str(binary)],
                       input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": corpus["cases"], "native_cases_added_by_replay": 0,
              "actual_filesystem_cases": 0, "scope": "unchanged original validate after typed DTO admission",
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust multi-read validation disagrees with the native corpus")
    return result


def compare_operation_kdf(output: Path, report: dict, rustc: Path) -> dict:
    """Run locked ring plus the complete unchanged original crypto module."""
    evidence = operation_kdf_evidence(output, report)
    if evidence != report.get("operation_kdf_evidence"):
        raise ValueError("operation KDF native evidence changed before Rust replay")
    folder = output / "operation-kdf-rust-oracle"
    wire = gzip.decompress((folder / "kdf_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("operation KDF input corpus changed before Rust replay")
    manifest = ROOT / "tests/hia_native/kdf_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("operation KDF reference target directory already exists")
    cargo = executable("cargo")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-kdf-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-operation-kdf-reference"
    row = record_check(output, report, name="operation-kdf-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", "rust_oracle_cases": 1364, "original_owner_calls": 405,
                "original_record_key_cipher_comparisons": 28,
                "output_sha256": evidence["native_output_sha256"], "native_cases_added_by_replay": 0}
    result = {**observed, "status": "PASS" if observed == expected and not row.stderr else "FAIL",
              "input_sha256": evidence["input_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "oracle_executable_sha256": sha(binary),
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source": evidence["original_source"],
              "composition_sha256": evidence["composition_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "reference_kind": "locked ring primitives and complete unchanged original operation_crypto.rs",
              "scope": "internal derivation/binding bytes and opaque original record-key equivalence; no native AEAD or scope lifecycle qualification"}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust operation KDF owner or output accounting differs")
    return result


def compare_operation_aead(output: Path, report: dict, rustc: Path) -> dict:
    """Replay native bytes through ring and the unchanged original seal/open owners."""
    evidence = operation_aead_evidence(output, report)
    if evidence != report.get("operation_aead_evidence"):
        raise ValueError("operation AEAD native evidence changed before Rust replay")
    folder = output / "operation-aead-rust-oracle"
    wire = gzip.decompress((folder / "aead_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("operation AEAD input corpus changed before Rust replay")
    manifest = ROOT / "tests/hia_native/aead_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("operation AEAD reference target directory already exists")
    cargo = executable("cargo")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-aead-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-operation-aead-reference"
    row = record_check(output, report, name="operation-aead-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", "rust_oracle_cases": 1841, "encryption_cases": 684,
                "decryption_cases": 684, "refusal_cases": 473,
                "original_seal_calls": 33, "original_open_calls": 33,
                "original_authentication_refusals": 11,
                "output_sha256": evidence["native_output_sha256"], "native_cases_added_by_replay": 0}
    result = {**observed, "status": "PASS" if observed == expected and not row.stderr else "FAIL",
              "input_sha256": evidence["input_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "oracle_executable_sha256": sha(binary),
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source": evidence["original_source"],
              "composition_sha256": evidence["composition_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "reference_kind": "locked ring ChaCha20-Poly1305 and complete unchanged original seal/open owners",
              "scope": "byte primitive interoperability with synthetic entropy; no native nonce custody or scope lifecycle qualification"}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust operation AEAD owner or output accounting differs")
    return result


def compare_operation_nonce(output: Path, report: dict, rustc: Path) -> dict:
    """Execute the unchanged Rust binding and NonceLedger on each retained session."""
    evidence = operation_nonce_evidence(output, report)
    if evidence != report.get("operation_nonce_evidence"):
        raise ValueError("operation nonce native evidence changed before Rust replay")
    folder = output / "operation-nonce-rust-oracle"
    wire = gzip.decompress((folder / "nonce_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("operation nonce input corpus changed before Rust replay")
    manifest = ROOT / "tests/hia_native/nonce_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("operation nonce reference target directory already exists")
    cargo = executable("cargo")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-nonce-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-operation-nonce-reference"
    row = record_check(output, report, name="operation-nonce-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", "rust_oracle_cases": 17811, "original_binding_calls": 17611,
                "original_nonce_reservations": 17470, "accepted_reservations": 17183,
                "nonce_refusals": 287, "sessions": 8,
                "output_sha256": evidence["native_output_sha256"], "native_cases_added_by_replay": 0}
    result = {**observed, "status": "PASS" if observed == expected and not row.stderr else "FAIL",
              "input_sha256": evidence["input_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "oracle_executable_sha256": sha(binary),
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source": evidence["original_source"],
              "composition_sha256": evidence["composition_sha256"],
              "composition_fixture": evidence["composition_fixture"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "reference_kind": "complete unchanged original TrustedResultBinding and NonceLedger",
              "scope": "serial reservation and original scope budget; no entropy, production locking or key lifetime qualification"}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust nonce ledger or output accounting differs")
    return result


def compare_operation_record(output: Path, report: dict, rustc: Path) -> dict:
    """Replay the complete original binding/AAD and seal/open byte owners."""
    evidence = operation_record_evidence(output, report)
    if evidence != report.get("operation_record_evidence"):
        raise ValueError("operation record native evidence changed before Rust replay")
    folder = output / "operation-record-rust-oracle"
    wire = gzip.decompress((folder / "record_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("operation record input corpus changed before Rust replay")
    manifest = ROOT / "tests/hia_native/record_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("operation record reference target directory already exists")
    cargo = executable("cargo")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-record-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-operation-record-reference"
    row = record_check(output, report, name="operation-record-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", "rust_oracle_cases": 823, "refusal_cases": 365,
                "original_binding_constructor_calls": 164, "original_binding_aad_calls": 109,
                "original_seal_calls": 177, "original_open_calls": 353,
                "original_preflight_seal_calls": 8, "original_preflight_entropy_reached": 3,
                "original_verified_scope_constructor_calls": 6, "original_owner_calls": 817,
                "output_sha256": evidence["native_output_sha256"], "native_cases_added_by_replay": 0}
    result = {**observed, "status": "PASS" if observed == expected and not row.stderr else "FAIL",
              "input_sha256": evidence["input_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "oracle_executable_sha256": sha(binary), "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source": evidence["original_source"], "composition_sha256": evidence["composition_sha256"],
              "composition_fixture": evidence["composition_fixture"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "original_domain_rows": 702, "adapter_only_rows": 121,
              "reference_kind": "complete unchanged original TrustedResultBinding, AAD, seal_with_entropy and open",
              "scope": "internal byte owner with fresh synthetic scope per row; persistent capability/entropy/nonce lifetime remains separate"}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust record owner, domain or output accounting differs")
    return result


def compare_system_entropy(output: Path, report: dict, rustc: Path) -> dict:
    """Build unchanged SystemEntropy and replay all owned-child Linux backend cases."""
    evidence = entropy_evidence(output, report)
    if evidence != report.get("system_entropy_evidence"):
        raise ValueError("entropy native evidence changed before original replay")
    folder = output / ENTROPY_FOLDER
    manifest = ROOT / "tests/hia_native/entropy_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("entropy original reference target directory already exists")
    env = qualification_env()
    # Test the locked default Linux backend, without inherited custom cfg/target
    # selection. Its actual Cargo fingerprint and syscall trace are checked too.
    removed = sorted(key for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET") if key in env)
    for key in removed:
        env.pop(key)
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="system-entropy-rust-compile",
                 command=[str(executable("cargo")), "build", "--locked", "--release",
                          "--manifest-path", str(manifest), "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-system-entropy-reference"
    binary_hash = sha(binary)
    fingerprints = list((target / "release/.fingerprint").glob("getrandom-*/lib-getrandom.json"))
    if len(fingerprints) != 1:
        raise ValueError("entropy original requires exactly one default getrandom backend")
    fingerprint = entropy_object(fingerprints[0])
    if fingerprint.get("features") != "[]" or fingerprint.get("rustflags") != []:
        raise ValueError("entropy original getrandom feature/cfg backend differs")
    generated = list((target / "release/build").glob("hia-system-entropy-reference-*/out/original_operation_reference.rs"))
    expected_source = (b"#[allow(dead_code)]\nmod original {\n"
                       + (ROOT / ENTROPY_ORIGINAL_SOURCE).read_bytes() + b"\n"
                       + (ROOT / "tests/hia_native/entropy_oracle/original_access.rs").read_bytes() + b"\n}\n")
    if len(generated) != 1 or generated[0].read_bytes() != expected_source:
        raise ValueError("entropy oracle did not retain the complete unchanged original module")
    env.update({"HIA_ENTROPY_REFERENCE_BINARY": str(binary), "HIA_ENTROPY_REFERENCE_SHA256": binary_hash,
                "HIA_ENTROPY_KERNEL_REPORT": str(folder / "kernel-original.json")})
    record_check(output, report, name="system-entropy-rust-compare",
                 command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/test_entropy_kernel_backend.py")],
                 env=env, timeout=180)
    check, observed = completed_test_summary(output, report, "system-entropy-rust-compare")
    retained_original = entropy_object(folder / "kernel-original.json")
    if {key: value for key, value in retained_original.items() if key != "traces"} != observed:
        raise ValueError("entropy original full trace receipt differs from its completed process")
    original = normalized_kernel_report(ROOT, retained_original, original=True, binary_sha256=binary_hash)
    native = normalized_kernel_report(ROOT, entropy_object(folder / KERNEL_RECEIPT), original=False,
                                       binary_sha256=evidence["artifacts"]["binary_sha256"], artifacts=evidence["artifacts"])
    if original["traces"] != native["traces"] or original["sha256"] != native["sha256"]:
        raise ValueError("entropy original and native Linux backend traces differ")
    if sha(binary) != binary_hash or entropy_evidence(output, report) != evidence:
        raise ValueError("entropy source, observed native corpus or original binary changed during replay")
    result = {"schema": "hepta.runtime.system-entropy-rust-comparison.v1", "status": "PASS",
              "reference_kind": "complete unchanged original SystemEntropy with locked default Linux ring/getrandom backend",
              "tests_run": 8, "processes": 25, "request_frames": 56, "original_owner_calls": 56,
              "successful_outputs": 46, "entropy_refusals": 10, "native_cases_added_by_replay": 0,
              "normalized_trace_sha256": original["sha256"], "normalized_syscall_traces_match": True,
              "normal_random_bytes_equality_claimed": False, "normalization": original["normalization"],
              "native_counts": native["counts"], "original_counts": original["counts"],
              "corpus_metadata_sha256": evidence["corpus_sha256"],
              "native_report_sha256": sha(folder / KERNEL_RECEIPT),
              "original_report_sha256": sha(folder / "kernel-original.json"),
              "original_stdout_sha256": check["stdout_sha256"], "original_stderr_sha256": check["stderr_sha256"],
              "oracle_executable_sha256": binary_hash, "source_sha256": evidence["source_sha256"],
              "generated_original_module_sha256": sha(generated[0]),
              "getrandom_fingerprint_sha256": sha(fingerprints[0]),
              "getrandom_features": [], "getrandom_rustflags": [],
              "oracle_dependencies": entropy_dependencies(ROOT), "cleared_backend_overrides": removed,
              "original_runtime_lock_identical": False, "full_runtime_lock_build_claimed": False,
              "thread_safe_workspace_claimed": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_operation_scope(output: Path, report: dict, rustc: Path) -> dict:
    """Replay complete live original scopes, clones and nonces on the declared domain."""
    evidence = operation_scope_evidence(output, report)
    if evidence != report.get("operation_scope_evidence"):
        raise ValueError("scope native histories changed before original Rust replay")
    folder = output / SCOPE_FOLDER
    wire = gzip.decompress((folder / "scope_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("scope reference history changed before original Rust replay")
    manifest = ROOT / "tests/hia_native/scope_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("scope original reference target directory already exists")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-scope-rust-compile",
                 command=[str(executable("cargo")), "build", "--locked", "--release",
                          "--manifest-path", str(manifest), "--target-dir", str(target)], env=env, timeout=180)
    generated = list((target / "release/build").glob("hia-operation-scope-reference-*/out/original_operation_reference.rs"))
    expected_source = (b"#[allow(dead_code)]\nmod original {\n"
                       + (ROOT / "src/mcp/runtime/operation_crypto.rs").read_bytes() + b"\n"
                       + (ROOT / "tests/hia_native/scope_oracle/original_access.rs").read_bytes() + b"\n}\n")
    if len(generated) != 1 or generated[0].read_bytes() != expected_source:
        raise ValueError("scope oracle did not retain the complete unchanged original module")
    binary = target / "release/hia-operation-scope-reference"
    binary_hash = sha(binary)
    row = record_check(output, report, name="operation-scope-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", **SCOPE_ORACLE_COUNTS, "output_sha256": evidence["native_output_sha256"]}
    if (row.stderr or observed != expected
            or any(type(observed.get(key)) is not int for key in SCOPE_ORACLE_COUNTS)
            or sha(binary) != binary_hash or operation_scope_evidence(output, report) != evidence):
        raise ValueError("scope original owner, exact result, lifetime or exclusion-domain accounting differs")
    result = {**observed, "schema": "hepta.runtime.operation-scope-rust-comparison.v1",
              "input_sha256": evidence["input_sha256"], "oracle_executable_sha256": binary_hash,
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "generated_original_module_sha256": sha(generated[0]),
              "original_source_sha256": evidence["original_source_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "native_domains": evidence["domains"],
              "reference_kind": "complete unchanged original private scope, real live clones and nonce sets with deterministic entropy",
              "real_os_entropy_connected": False, "concurrent_shared_capability_qualified": False,
              "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_operation_scope_os(output: Path, report: dict, rustc: Path, *, report_path: Path | None = None) -> dict:
    evidence = operation_scope_os_evidence(output, report)
    if evidence != report.get("operation_scope_os_evidence"):
        raise ValueError("OS scope native source or complete traces changed before original Rust comparison")
    folder = output / SCOPE_OS_FOLDER
    manifest = ROOT / "tests/hia_native/scope_os_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("OS scope original reference target directory already exists")
    env = qualification_env()
    removed = sorted(key for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET") if key in env)
    for key in removed:
        env.pop(key)
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-scope-os-rust-compile",
                 command=[str(executable("cargo")), "build", "--locked", "--release",
                          "--manifest-path", str(manifest), "--target-dir", str(target)], env=env, timeout=180, report_path=report_path)
    generated = list((target / "release/build").glob("hia-operation-scope-os-reference-*/out/original_operation_reference.rs"))
    expected_source = (b"#[allow(dead_code)]\nmod original {\n"
                       + (ROOT / "src/mcp/runtime/operation_crypto.rs").read_bytes() + b"\n"
                       + (ROOT / "tests/hia_native/scope_os_oracle/original_access.rs").read_bytes() + b"\n}\n")
    if len(generated) != 1 or generated[0].read_bytes() != expected_source:
        raise ValueError("OS scope oracle did not retain the complete unchanged original module")
    fingerprints = list((target / "release/.fingerprint").glob("getrandom-*/lib-getrandom.json"))
    if len(fingerprints) != 1:
        raise ValueError("OS scope original requires exactly one default getrandom backend")
    fingerprint = json.loads(fingerprints[0].read_bytes())
    if fingerprint.get("features") != "[]" or fingerprint.get("rustflags") != []:
        raise ValueError("OS scope original getrandom feature/cfg backend differs")
    binary = target / "release/hia-operation-scope-os-reference"
    binary_hash = sha(binary)
    native_manifest = output / report["modules"]["operation_scope_os"]["manifest"]
    artifact = scope_os_profile(ROOT, native_manifest)
    env.update({"HIA_SCOPE_OS_MANIFEST": str(native_manifest), "HIA_SCOPE_OS_REFERENCE_BINARY": str(binary),
                "HIA_SCOPE_OS_REFERENCE_SHA256": binary_hash,
                "HIA_SCOPE_OS_RESULT": str(folder / SCOPE_OS_PAIRED_RECEIPT)})
    record_check(output, report, name="operation-scope-os-rust-compare",
                 command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/test_scope_os.py")],
                 env=env, timeout=180, report_path=report_path)
    check, summary = completed_test_summary(output, report, "operation-scope-os-rust-compare")
    retained = json.loads((folder / SCOPE_OS_PAIRED_RECEIPT).read_bytes())
    if {key: value for key, value in retained.items() if key != "cases"} != summary:
        raise ValueError("OS scope paired raw observations differ from completed process stdout")
    paired = scope_os_paired_evidence(ROOT, folder, artifact, binary_hash)
    if sha(binary) != binary_hash or operation_scope_os_evidence(output, report) != evidence:
        raise ValueError("OS scope source, observed native corpus or original binary changed during comparison")
    result = {**paired, "schema": "hepta.runtime.operation-scope-os-rust-comparison.v1",
              "reference_kind": "complete unchanged original ResultCryptoScope with default Linux SystemEntropy and live original clones",
              "native_corpus_sha256": evidence["corpus_sha256"],
              "generated_original_module_sha256": sha(generated[0]),
              "getrandom_fingerprint_sha256": sha(fingerprints[0]),
              "getrandom_features": [], "getrandom_rustflags": [], "cleared_backend_overrides": removed,
              "original_stdout_sha256": check["stdout_sha256"], "original_stderr_sha256": check["stderr_sha256"],
              "real_os_entropy_connected": True, "original_runtime_lock_identical": False,
              "concurrent_shared_capability_qualified": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_history(output: Path, report: dict, rustc: Path) -> dict:
    return compare_history_original(ROOT, output, report, rustc, completed_test_summary,
                                    record_check, qualification_env())


def compare_view_cache(output: Path, report: dict, rustc: Path) -> dict:
    return compare_cache_original(ROOT, output, report, rustc, completed_test_summary,
                                  record_check, qualification_env())


def batch_replay_stream_identity(path: Path, maximum: int) -> tuple[int, str]:
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError("batch original output must be a regular unsymlinked stream")
    size, identity = 0, hashlib.sha256()
    with gzip.open(path, "rb") as stream:
        while raw := stream.read(1 << 20):
            size += len(raw)
            if size > maximum:
                raise ValueError("batch original output exceeds the complete native byte domain")
            identity.update(raw)
    return size, identity.hexdigest()


def compare_batch_plan(output: Path, report: dict, rustc: Path) -> dict:
    evidence = batch_plan_evidence(output, report)
    if evidence != report.get("batch_plan_evidence"):
        raise ValueError("batch native source, complete streams or actual artifacts changed before original replay")
    folder = output / BATCH_PLAN_FOLDER
    cargo = executable(str(rustc.with_name("cargo")))
    cargo_hash = sha(cargo)
    build_dir = folder / "original-build"
    # The component's build routine creates the source-bound receipt from the
    # actual locked Cargo invocation. It has its own retained stdout/stderr.
    # This outer check records that completed process separately from replay.
    build_program = "\n".join((
        "import json, sys",
        "from pathlib import Path",
        "root, destination = Path(sys.argv[1]), Path(sys.argv[2])",
        "sys.path.insert(0, str(root / 'tests/hia_native'))",
        "from compare_batch_plan_original import build_original",
        "destination.mkdir(parents=True, exist_ok=False)",
        "binary, receipt = build_original(root, root, destination, cargo=sys.argv[3], rustc=sys.argv[4])",
        "print(json.dumps(receipt, sort_keys=True))",
    ))
    env = qualification_env()
    compiled = record_check(output, report, name="batch-plan-rust-compile",
        command=[sys.executable, "-I", "-B", "-c", build_program,
                 str(ROOT), str(build_dir), str(cargo), str(rustc)], env=env, timeout=180)
    build = json.loads(compiled.stdout)
    source_map = {name: row["sha256"] for name, row in BATCH_PLAN_ORIGINALS.items()}
    source_map.update({name: sha(ROOT / name) for name in (
        "tests/hia_native/oracle_batch_plan.rs", "tests/hia_native/batch_plan_oracle/Cargo.toml",
        "tests/hia_native/batch_plan_oracle/Cargo.lock")})
    binary = build_dir / "target/release/hia-batch-plan-reference"
    expected_command = [str(cargo), "build", "--release", "--locked", "--manifest-path",
                        str(ROOT / "tests/hia_native/batch_plan_oracle/Cargo.toml")]
    if (compiled.stderr or build.get("schema") != "hepta.runtime.batch-plan.original-build.v1"
            or build.get("status") != "PASS" or build.get("exit_code") != 0
            or build.get("timed_out") is not False or build.get("command") != expected_command
            or build.get("source_map") != source_map
            or build.get("oracle_sha256") != source_map["tests/hia_native/oracle_batch_plan.rs"]
            or build.get("binary_sha256") != sha(binary)
            or build.get("stdout_sha256") != sha(build_dir / "build.stdout")
            or build.get("stderr_sha256") != sha(build_dir / "build.stderr")
            or json.loads((build_dir / "build.json").read_bytes()) != build):
        raise ValueError("batch actual locked Cargo compilation receipt differs")
    replay = folder / "original-replay"
    row = record_check(output, report, name="batch-plan-rust-compare",
        command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_batch_plan_original.py"),
                 "--source-root", str(ROOT), "--runtime", str(ROOT), "--corpus", str(folder),
                 "--output", str(replay), "--binary", str(binary),
                 "--build-receipt", str(build_dir / "build.json")], env=env, timeout=180)
    observed = json.loads(row.stdout)
    if (row.stderr or observed.get("schema") != "hepta.runtime.batch-plan.original-comparison.v1"
            or observed.get("status") != "PASS" or type(observed.get("original_rows")) is not int
            or observed["original_rows"] != BATCH_PLAN_ROWS or observed.get("rows_expected") != BATCH_PLAN_ROWS
            or observed.get("output_complete") is not True or observed.get("exit_code") != 0
            or observed.get("stream_errors") != [] or observed.get("timeout_seconds") != 180
            or observed.get("stdout_bytes") != evidence["native_output_bytes"]
            or observed.get("stdout_sha256") != evidence["native_output_sha256"]
            or observed.get("native_corpus_sha256") != evidence["corpus_metadata_sha256"]
            or observed.get("binary_sha256") != build["binary_sha256"]
            or observed.get("compilation") != "reused actual source-matched compiled binary; no fresh compilation claim"
            or json.loads((replay / "comparison.json").read_bytes()) != observed
            or json.loads((replay / "build.json").read_bytes()) != build
            or batch_replay_stream_identity(replay / "original-output.bin.gz", evidence["native_output_bytes"]) != (
                evidence["native_output_bytes"], evidence["native_output_sha256"])
            or sha(binary) != build["binary_sha256"] or sha(cargo) != cargo_hash
            or batch_plan_evidence(output, report) != evidence):
        raise ValueError("original batch complete ordered responses or source custody differ")
    result = {"schema": "hepta.runtime.batch-plan-rust-comparison.v1", "status": "PASS",
              "cases": BATCH_PLAN_ROWS, "native_cases_added_by_replay": 0,
              "reference_kind": "unchanged original batch preflight, operation parsing and endpoint planning blocks",
              "compiled_by_qualification_recipe": True,
              "replay_uses_this_recipe_binary": True,
              "original_output_sha256": observed["stdout_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "output_bytes": evidence["native_output_bytes"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "oracle_executable_sha256": build["binary_sha256"], "cargo_executable_sha256": cargo_hash,
              "original_build_receipt_sha256": sha(build_dir / "build.json"),
              "original_replay_receipt_sha256": sha(replay / "comparison.json"),
              "source_bindings": observed["source_bindings"],
              "complete_original_tool_parity": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_batch_apply(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_batch_apply_qualification as q
    evidence = batch_apply_evidence(output, report)
    if evidence != report.get("batch_apply_evidence"):
        raise ValueError("batch application native evidence changed before original replay")
    project = output / "batch-apply-rust-reference"
    folder = output / "batch-apply"
    q.prepare_original_reference(project, evidence["native_evidence"], folder / "corpus", folder / "artifacts",
                                 source_root=ROOT)
    command = [sys.executable, "-I", "-B", str(project / "driver.py"), "--manifest", str(project / "input.json"),
               "--rustc", str(rustc), "--output", str(project / "replay")]
    record_check(output, report, name="batch-apply-rust-compare", command=command, timeout=180,
                 env=qualification_env())
    check, summary = completed_test_summary(output, report, "batch-apply-rust-compare")
    if (q.canonical(summary) != q.canonical(q.json_file(project / "replay/result.json"))
            or (output / "batch-apply-rust-compare.stderr").read_bytes() != b""
            or check["command"] != command or check["timeout_seconds"] != 180):
        raise ValueError("batch application original driver differs from its actual process")
    result = q.original_comparison_evidence(project, source_root=ROOT)
    if batch_apply_evidence(output, report) != evidence:
        raise ValueError("batch application native evidence changed during original replay")
    return {**result, "original_stdout_sha256": check["stdout_sha256"],
            "original_stderr_sha256": check["stderr_sha256"]}


def atomic_write_original_command(output: Path, report: dict, rustc: Path) -> list[str]:
    cargo = executable(str(rustc.with_name("cargo")))
    return [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_atomic_write_original.py"),
            "--runtime", str(ROOT), "--native-manifest", str(output / report["modules"]["atomic_write"]["manifest"]),
            "--policy-corpus", str(output / "atomic-write/policy"), "--output", str(output / "atomic-write-original"),
            "--rustc", str(rustc), "--cargo", str(cargo)]


def atomic_write_original_evidence(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_atomic_write_qualification as q
    folder = output / "atomic-write-original"
    command = atomic_write_original_command(output, report, rustc)
    completed = atomic_write_completed_process(output, report, "atomic-write-rust-compare", command,
                                               phase="original_rust_comparison")
    evidence = q.original_comparison_evidence(folder, output / report["modules"]["atomic_write"]["manifest"],
        output / "atomic-write/policy", source_root=ROOT, reference_root=ROOT,
        stdout=output / "atomic-write-rust-compare.stdout")
    retained = q.obj(folder / "result.json")
    for name, path in (("rustc", rustc), ("cargo", Path(command[-1]))):
        if any(retained[name].get(key) != value for key, value in q.file_record(path).items()):
            raise ValueError("atomic original compiler or Cargo executable changed")
    fixtures = tuple(f"atomic-write-original/{kind}-kernel/{index:04d}-{case['name']}/fixture"
                     for kind in ("native", "original") for index, case in enumerate(q.case_module.cases()))
    # The original driver retires these only after complete native and Rust
    # kernel evidence is admitted, including when their semantic comparison fails.
    # original_comparison_evidence above verifies that exact retained receipt.
    return {"schema": "hepta.runtime.atomic-write-required-original.v1", "status": "PASS",
        "reference_kind": "complete unchanged Linux Local atomic_write, actual std::Path and std::io properties",
        "compiled_by_qualification_recipe": True, "completed_process": completed, "reference_evidence": evidence,
        "retained_files_sha256": atomic_write_retained_files(output, folder, fixtures=fixtures),
        "rust_path_cases": 88807, "original_atomic_write_requests": 171, "kernel_state_and_trace_comparisons": 151,
        "paired_native_atomic_write_requests": 171, "native_phase_cases_added_by_reference": 0,
        "original_error_display_property_rows": 4095, "original_nul_and_writezero_properties": 2,
        "complete_original_tool_parity": False, "remote_ssh_parity": False,
        "production_activated": False, "whole_runtime_replaced": False}


def compare_atomic_write(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_atomic_write_qualification as q
    native = atomic_write_evidence(output, report)
    if native != report.get("atomic_write_evidence"):
        raise ValueError("atomic native execution evidence changed before original replay")
    record_check(output, report, name="atomic-write-rust-compare",
        command=atomic_write_original_command(output, report, rustc), timeout=180, env=qualification_env())
    folder = output / "atomic-write-original"
    completed = q.original_comparison_evidence(folder, output / report["modules"]["atomic_write"]["manifest"],
        output / "atomic-write/policy", source_root=ROOT, reference_root=ROOT,
        stdout=output / "atomic-write-rust-compare.stdout")
    result = atomic_write_original_evidence(output, report, rustc)
    if atomic_write_evidence(output, report) != native:
        raise ValueError("atomic native execution evidence changed during original replay")
    return result


def compare_line_verify(output: Path, report: dict, rustc: Path) -> dict:
    evidence = line_verify_evidence(output, report)
    if evidence != report.get("line_verify_evidence"):
        raise ValueError("line verification native evidence changed before original replay")
    folder = output / "line-verify-rust-oracle"
    source = ROOT / "tests/hia_native/oracle_line_verify.rs"
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="line-verify-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    binary_hash = sha(binary)
    with gzip.open(folder / "requests.hex.gz", "rb") as handle:
        wire = handle.read(evidence["input_bytes"] + 1)
    with gzip.open(folder / "native-output.txt.gz", "rb") as handle:
        expected = handle.read(evidence["native_output_bytes"] + 1)
    if ((len(wire), digest(wire)) != (evidence["input_bytes"], evidence["input_sha256"])
            or (len(expected), digest(expected)) != (evidence["native_output_bytes"], evidence["native_output_sha256"])):
        raise ValueError("line verification original-domain corpus changed before replay")
    row = record_check(output, report, name="line-verify-rust-compare", command=[str(binary)],
                       input_bytes=wire, timeout=60)
    if (row.stdout != expected or row.stderr or sha(binary) != binary_hash
            or line_verify_evidence(output, report) != evidence):
        raise ValueError("complete original line verification/diagnostic/index bytes differ")
    result = {"status": "PASS", "rust_oracle_cases": evidence["captured_native_cases"],
              "native_cases_added_by_replay": 0, "input_sha256": digest(wire),
              "native_output_sha256": digest(expected), "rust_output_sha256": digest(row.stdout),
              "oracle_source_sha256": sha(source), "oracle_executable_sha256": binary_hash,
              "original_source_sha256": evidence["original_source_sha256"],
              "scope": evidence["scope"], "complete_original_tool_parity": False,
              "production_activated": False}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_editable_content(output: Path, report: dict, rustc: Path) -> dict:
    evidence = editable_content_evidence(output, report)
    if evidence != report.get("editable_content_evidence"):
        raise ValueError("editable native state history changed before original Rust replay")
    folder = output / EDITABLE_FOLDER
    target = folder / "target"
    if target.exists():
        raise ValueError("editable original reference target already exists")
    manifest = ROOT / "tests/hia_native/editable_oracle/Cargo.toml"
    env = qualification_env()
    env.update({"RUSTC": str(rustc), "RUSTFLAGS": "-C overflow-checks=off"})
    record_check(output, report, name="editable-content-rust-compile",
                 command=[str(executable("cargo")), "build", "--locked", "--release",
                          "--manifest-path", str(manifest), "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-editable-original-reference"
    binary_hash = sha(binary)
    row = record_check(output, report, name="editable-content-rust-compare",
                       command=[str(binary)], input_bytes=(folder / "requests.hex").read_bytes(), env=env, timeout=60)
    if (row.stderr or row.stdout != (folder / "native-output.txt").read_bytes()
            or row.stdout.count(b"\n") != EDITABLE_CASES or sha(binary) != binary_hash
            or editable_content_evidence(output, report) != evidence):
        raise ValueError("original EditableContent complete ordered responses differ")
    result = {"schema": "hepta.runtime.editable-rust-comparison.v1", "status": "PASS",
              "cases": EDITABLE_CASES, "native_cases_added_by_replay": 0,
              "reference_kind": "unchanged original EditableContent and incoming-line methods with typed test transport",
              "input_sha256": evidence["input_sha256"], "native_output_sha256": evidence["native_output_sha256"],
              "original_output_sha256": digest(row.stdout), "oracle_executable_sha256": binary_hash,
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source_sha256": evidence["original_source_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "complete_original_tool_parity": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_view_render(output: Path, report: dict, rustc: Path) -> dict:
    return compare_render_corpus(output, report, rustc, growth=False)


def compare_view_render_growth(output: Path, report: dict, rustc: Path) -> dict:
    return compare_render_corpus(output, report, rustc, growth=True)


VIEW_SEARCH_ORIGINAL_CHECKS = ("view_search_original", "test_view_search_original_evidence.py")
VIEW_REGEX_SEARCH_ORIGINAL_CHECKS = ("view_regex_search_original", "test_view_regex_search_original_evidence.py")
VIEW_SEARCH_CONTROLS_FOLDER = "view-search-original-evidence"
VIEW_SEARCH_CONTROL_NAMES = {
    "test_01_typed_json": ("duplicate-key", "nan-token", "infinity-token", "overflow-float",
        "boolean-is-not-uint", "nested-boolean-is-not-count"),
    "test_02_actual_process_receipts": ("missing-timed_out", "missing-timeout_seconds", "spawn-error",
        "boolean-exit", "float-deadline", "zero-elapsed", "different-command", "malformed-stream-pin"),
    "test_03_artifact_paths": ("parent-traversal", "absolute-path", "inward-file-symlink",
        "inward-parent-symlink", "directory-artifact", "fifo-artifact"),
    "test_04_actual_io_and_complete_records": ("boolean-case-id", "io-occurrence-gap",
        "raw-snapshot-length", "boolean-read-count", "complete-visible-body-byte",
        "unreferenced-output-blob", "missing-actual-read-event", "mutation-at-wrong-io"),
    "test_05_cancel_and_cache": ("boolean-publication-count", "missing-cancel-base",
        "unexpected-cancel-hint", "cancel-base-byte-differs", "search-mutated-existing-cache",
        "error-status-below-result-limit"),
    "test_06_complete_byte_comparison": ("full-byte-input.gz", "full-byte-body.gz",
        "full-byte-base.gz", "full-byte-snapshot.gz", "native-io-order",
        "native-success-not-boolean", "search-used-text-read", "whole-prime-used-raw-read"),
}


def _view_search_domain(regex: bool = False):
    if type(regex) is not bool:
        raise ValueError("search domain selection is not boolean")
    if regex:
        import hia_native_view_regex_search_reference as reference
        return (reference, "view_regex_search", "view-regex-search",
                VIEW_REGEX_SEARCH_ORIGINAL_CHECKS, "view-regex-search-original-controls")
    import hia_native_view_search_reference as reference
    return reference, "view_search", "view-search", VIEW_SEARCH_ORIGINAL_CHECKS, VIEW_SEARCH_CONTROLS_FOLDER


def _view_search_check(output: Path, report: dict, name: str, command: list[str], summary: dict,
                       *, regex: bool = False) -> dict:
    """Admit one required aggregate wrapper and both complete actual streams."""
    reference, stem, slug, checks, capture_name = _view_search_domain(regex)
    label = "regex" if regex else "literal"
    rows = [row for row in report["checks"] if row.get("name") == name]
    reference.need(len(rows) == 1, f"exactly one completed {label} search wrapper is required: " + name)
    row = rows[0]
    reference.keys(row, ("name", "phase", "command", "exit_code", "timed_out", "timeout_seconds",
        "elapsed_seconds", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes", "summary"),
        f"{label} search wrapper receipt")
    for key, expected in dict(name=name, phase="original_rust_comparison", command=command,
                               exit_code=0, timed_out=False, timeout_seconds=180, summary=summary).items():
        reference.exact(row[key], expected, f"{label} search wrapper " + key)
    elapsed = row["elapsed_seconds"]
    reference.need(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed <= 180,
                   f"{label} search wrapper elapsed time differs")
    artifacts = {}
    for stream in ("stdout", "stderr"):
        relative = name + "." + stream
        raw = reference.inside(output, relative).read_bytes()
        reference.exact(len(raw), row[stream + "_bytes"], f"{label} search wrapper complete stream length")
        reference.exact(digest(raw), row[stream + "_sha256"], f"{label} search wrapper complete stream hash")
        artifacts[relative] = digest(raw)
        if stream == "stdout":
            reference.exact(reference.decode(raw), summary, f"{label} search wrapper complete JSON stdout")
        elif name == checks[0]:
            reference.exact(raw, b"", f"{label} search original wrapper stderr")
    return artifacts


def _view_search_original_origin(report: dict, *, regex: bool = False) -> tuple[str, Path]:
    """Bind the original wrapper to its own recorded checkout, including after relocation."""
    reference, stem, slug, checks, capture_name = _view_search_domain(regex)
    rows = [row for row in report["checks"] if row.get("name") == checks[0]]
    reference.need(len(rows) == 1, "exactly one completed search original wrapper is required")
    command = rows[0].get("command")
    reference.need(type(command) is list and len(command) == 14
        and all(type(item) is str for item in command)
        and Path(command[0]).is_absolute() and command[1:3] == ["-I", "-B"],
        "search original wrapper command shape differs")
    reference.exact(command[4::2], ["--runtime-root", "--output", "--cargo", "--rustc", "--native-corpus"],
        "search original wrapper argument order")
    recorded_root = Path(command[5])
    reference.need(recorded_root.is_absolute() and ".." not in recorded_root.parts
        and str(recorded_root) == command[5], "search original checkout is not canonical")
    reference.exact(command[3], str(recorded_root / f"tests/hia_native/{stem}_oracle/run.py"),
        "search original wrapper source path")
    return command[0], recorded_root


def _view_search_original_evidence(output: Path, report: dict, native: dict, *, regex: bool = False) -> dict:
    """Re-read actual native provenance, fresh original bytes and post-replay controls."""
    reference, stem, slug, checks, capture_name = _view_search_domain(regex)
    label = "regex" if regex else "literal"
    original = output / reference.ORACLE_OUTPUT_FOLDER
    corpus = reference.inside(output, native["corpus"] + "/native-cases.jsonl").parent
    baseline = reference.reference_evidence(ROOT, original, native_corpus=corpus)
    reference.exact(baseline["status"], "COMPLETE_BYTE_PARITY_REQUIRES_NATIVE_ADMISSION",
                    "complete original search comparison")
    result = reference.decode(reference.inside(original, "result.json").read_bytes())
    reference.exact(result["status"], "BYTES_EQUAL_REQUIRES_NATIVE_ADMISSION", "fresh search replay status")
    reference.exact(result["explicit_offline"], False, "aggregate search build offline selection")
    producer = [row for row in report["checks"] if row.get("name") == f"test_{stem}.py"]
    reference.need(len(producer) == 1, "exactly one actual native search producer is required")
    command = producer[0].get("command")
    reference.need(type(command) is list and len(command) == 4 and all(type(item) is str for item in command)
        and Path(command[0]).is_absolute() and command[1:3] == ["-I", "-B"]
        and Path(command[3]).is_absolute(), "native search producer command shape differs")
    producer_root = Path(command[3]).parents[2]
    reference.exact(command[3], str(producer_root / f"tests/hia_native/test_{stem}.py"),
                    "native search producer source path")
    # The native shard and original aggregate may have different checkouts.
    # Their complete source bytes were independently admitted above; do not
    # rewrite either actual command or equate their historical absolute roots.
    original_python, recorded_root = _view_search_original_origin(report, regex=regex)
    recorded_output = Path(result["build_environment"]["CARGO_TARGET_DIR"]).parent
    reference.exact(recorded_output.name, reference.ORACLE_OUTPUT_FOLDER, "fresh search output folder")
    cargo = result["processes"][1]["command"][0]
    rustc = result["build_environment"]["RUSTC"]
    reference.exact(rustc, report["rust_compiler"]["invocation_path"], "aggregate search Rust invocation")
    reference.exact(cargo, str(Path(rustc).with_name("cargo")), "aggregate search Cargo invocation")
    original_command = [original_python, "-I", "-B",
        str(recorded_root / f"tests/hia_native/{stem}_oracle/run.py"),
        "--runtime-root", str(recorded_root), "--output", str(recorded_output),
        "--cargo", cargo, "--rustc", rustc,
        "--native-corpus", str(recorded_output.parent / native["corpus"])]
    artifacts = dict(native["artifact_sha256"])
    source_pins = dict(native["source_sha256"])

    def merge(destination, additions):
        for name, pin in additions.items():
            if name in destination:
                reference.exact(pin, destination[name], "shared search evidence pin " + name)
            destination[name] = pin

    merge(artifacts, {reference.ORACLE_OUTPUT_FOLDER + "/" + name: pin
                      for name, pin in baseline["artifact_sha256"].items()})
    merge(source_pins, baseline["source_sha256"])
    merge(artifacts, _view_search_check(output, report, checks[0], original_command, result, regex=regex))
    capture = capture_name
    captured = {}
    for filename in ("baseline.json", "result.json"):
        relative = capture + "/" + filename
        raw = reference.inside(output, relative).read_bytes()
        artifacts[relative] = digest(raw)
        captured[filename] = raw
    reference.exact(captured["baseline.json"], reference.canonical(baseline), "post-original complete baseline")
    controls = reference.decode(captured["result.json"])
    test_relative = "tests/hia_native/" + checks[1]
    reader_relative = f"scripts/hia_native_{stem}_reference.py"
    for relative in (test_relative, reader_relative, "scripts/compare_hia_runtime_rust.py"):
        merge(source_pins, {relative: sha(reference.inside(ROOT, relative))})
    expected = dict(schema=f"hepta.runtime.{slug}-original-controls.v1", status="PASS",
        groups=6, controls=42, rejected=42, expected_groups=6, expected_controls=42,
        actual_hia_calls=0, actual_rust_processes=0, control_records_are_execution_claims=False,
        reader_sha256=source_pins[reader_relative], test_sha256=source_pins[test_relative],
        baseline_sha256=digest(reference.canonical(baseline)),
        whole_view_migrated=False, whole_runtime_replaced=False)
    reference.keys(controls, (*expected, "controls_detail"), "post-original control summary")
    for key, value in expected.items():
        reference.exact(controls[key], value, "post-original control " + key)
    details = controls["controls_detail"]
    wanted = [(group, name) for group, names in VIEW_SEARCH_CONTROL_NAMES.items() for name in names]
    reference.need(type(details) is list and len(details) == len(wanted) == 42,
                   "post-original complete control inventory differs")
    for row, (group, name) in zip(details, wanted):
        reference.keys(row, ("group", "name", "rejected", "error_type", "message"), "post-original control")
        for key, value in dict(group=group, name=name, rejected=True, error_type="AssertionError").items():
            reference.exact(row[key], value, "post-original control " + key)
        reference.need(type(row["message"]) is str and bool(row["message"]), "post-original refusal lacks its error")
    controls_command = [original_python, "-I", "-B", str(recorded_root / test_relative)]
    merge(artifacts, _view_search_check(output, report, checks[1], controls_command, controls, regex=regex))
    positions = [next(index for index, row in enumerate(report["checks"]) if row["name"] == name)
                 for name in (f"test_{stem}.py", *checks)]
    reference.need(positions == sorted(positions), "search original or rejection controls ran before their producer")
    return dict(schema=f"hepta.runtime.{slug}-original-comparison.v1", status="PASS",
        original_output=reference.ORACLE_OUTPUT_FOLDER, corpus=native["corpus"],
        fresh_original_processes=3, shared_original_recipe=True,
        required_original_checks=list(checks),
        native_producer_evidence_sha256=digest(reference.canonical(native)),
        reference=baseline, evidence_controls=controls, native_cases_added_by_replay=0,
        artifact_sha256=dict(sorted(artifacts.items())), source_sha256=dict(sorted(source_pins.items())),
        original_mcp_router_executed=False, whole_view_migrated=False, whole_runtime_replaced=False)


def compare_view_search(output: Path, report: dict, rustc: Path | None = None,
                        *, execute: bool = False, native: dict | None = None, regex: bool = False) -> dict:
    """Share three original processes and one later rejection suite across view entries."""
    reference, stem, slug, checks, capture_name = _view_search_domain(regex)
    label = "regex" if regex else "literal"
    reader = view_regex_search_evidence if regex else view_search_evidence
    native = reader(output, report) if native is None else native
    reference.exact(native, report.get(stem + "_evidence"), "admitted native search evidence")
    rows = {name: [row for row in report["checks"] if row.get("name") == name]
            for name in checks}
    reference.need(all(len(value) <= 1 for value in rows.values()), "duplicate shared search original wrapper")
    original = output / reference.ORACLE_OUTPUT_FOLDER
    if not rows[checks[0]]:
        if not execute or rustc is None:
            raise ValueError(f"fresh {label} search original recipe has not executed")
        reference.need(not rows[checks[1]], "search rejection suite precedes original execution")
        reference.need(not original.exists() and not original.is_symlink(), "unrecorded search original output exists")
        corpus = reference.inside(output, native["corpus"] + "/native-cases.jsonl").parent
        command = [sys.executable, "-I", "-B", str(ROOT / f"tests/hia_native/{stem}_oracle/run.py"),
            "--runtime-root", str(ROOT), "--output", str(original),
            "--cargo", str(executable(str(rustc.with_name("cargo")))), "--rustc", str(rustc),
            "--native-corpus", str(corpus)]
        record_check(output, report, name=checks[0], command=command,
                     timeout=180, env=qualification_env())
    if not rows[checks[1]]:
        if not execute:
            raise ValueError(f"{label} search original evidence controls have not executed")
        capture = output / capture_name
        reference.need(not capture.exists() and not capture.is_symlink(), "unrecorded search original controls exist")
        corpus = reference.inside(output, native["corpus"] + "/native-cases.jsonl").parent
        env = qualification_env()
        env.update({"HIA_" + stem.upper() + "_ORIGINAL_OUTPUT": str(original),
                    "HIA_" + stem.upper() + "_NATIVE_CORPUS": str(corpus),
                    "HIA_" + stem.upper() + "_ORIGINAL_EVIDENCE_CAPTURE_DIR": str(capture)})
        record_check(output, report, name=checks[1],
            command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / checks[1])],
            timeout=180, env=env)
    result = _view_search_original_evidence(output, report, native, regex=regex)
    if stem + "_original_comparison" in report:
        reference.exact(result, report[stem + "_original_comparison"], "retained search original comparison")
    elif not execute:
        raise ValueError(f"required {label} search original comparison was not recorded")
    else:
        report[stem + "_original_comparison"] = result
        save_report(output / "result.json", report)
    return result


def compare_view_call_group(output: Path, report: dict, rustc: Path) -> dict:
    from hia_native_view_call_qualification import compare_original
    native = view_call_evidence(output, report)
    if native != report.get("view_call_evidence"):
        raise ValueError("local view native inputs changed before original replay")
    # All three component entries share this one fresh locked build and its
    # nine recorded processes. Later entries strictly re-read the same result.
    original = compare_original(ROOT, output, report, native, record_check=record_check,
                                cargo=executable(str(rustc.with_name("cargo"))), rustc=rustc)
    compare_view_search(output, report, rustc, execute=True)
    compare_view_regex_search(output, report, rustc, execute=True)
    return original


def compare_view_search_public(output: Path, report: dict, original: dict,
                               *, execute: bool = False, native: dict | None = None, regex: bool = False) -> dict:
    """Read public search bytes against the already admitted shared original."""
    reference, stem, slug, checks, capture_name = _view_search_domain(regex)
    label = "regex" if regex else "literal"
    if regex:
        from hia_native_view_regex_search_public_qualification import compare_public_reference
    else:
        from hia_native_view_search_public_qualification import compare_public_reference
    reader = view_regex_search_public_evidence if regex else view_search_public_evidence
    native = reader(output, report) if native is None else native
    reference.exact(native, report.get(stem + "_public_evidence"), "admitted public search native evidence")
    reference.exact(original, report.get(stem + "_original_comparison"), "prior shared search original evidence")
    relative = native["corpus"]
    reference.need(type(relative) is str and relative != "" and not Path(relative).is_absolute()
        and ".." not in Path(relative).parts and str(Path(relative)) == relative,
        "public search corpus is not a canonical relative path")
    reference.exact(original["original_output"], reference.ORACLE_OUTPUT_FOLDER, "shared search original folder")
    result = compare_public_reference(ROOT, output / relative, output / original["original_output"])
    if stem + "_public_original_comparison" in report:
        reference.exact(result, report[stem + "_public_original_comparison"], "retained public search original comparison")
    elif not execute:
        raise ValueError(f"required public {label} search original comparison was not recorded")
    else:
        report[stem + "_public_original_comparison"] = result
        save_report(output / "result.json", report)
    return result


def compare_view_regex_search(output: Path, report: dict, rustc: Path | None = None,
                              *, execute: bool = False, native: dict | None = None) -> dict:
    return compare_view_search(output, report, rustc, execute=execute, native=native, regex=True)


def compare_view_regex_search_public(output: Path, report: dict, original: dict,
                                     *, execute: bool = False, native: dict | None = None) -> dict:
    return compare_view_search_public(output, report, original, execute=execute, native=native, regex=True)


def compare_runtime_mcp(output: Path, report: dict, rustc: Path | None) -> dict:
    from hia_native_view_call_qualification import compare_original
    import hia_native_runtime_mcp_pipeline as public_pipeline
    native = view_call_evidence(output, report)
    if native != report.get("view_call_evidence"):
        raise ValueError("local view native inputs changed before public MCP comparison")
    if runtime_mcp_evidence(output, report) != report.get("runtime_mcp_evidence"):
        raise ValueError("public MCP native inputs changed before original comparison")
    original = compare_original(ROOT, output, report, native)
    search_original = compare_view_search(output, report)
    regex_original = compare_view_regex_search(output, report)
    if rustc is None:
        public = public_pipeline.retained_original(ROOT, output, report, completed_test_summary)
    else:
        public = public_pipeline.execute_original(ROOT, output, report, rustc,
            record_check, completed_test_summary, qualification_env())
    compare_view_search_public(output, report, search_original, execute=rustc is not None)
    compare_view_regex_search_public(output, report, regex_original, execute=rustc is not None)
    from hia_native_span_raw_value_qualification import compare_original as compare_span_original
    extension = compare_span_original(ROOT, output, report, rustc,
        record_check, completed_test_summary, qualification_env())
    return dict(public, span_raw_value=extension)


def compare_render_corpus(output: Path, report: dict, rustc: Path, *, growth: bool) -> dict:
    evidence_reader = view_render_growth_evidence if growth else view_render_evidence
    evidence_key = "view_render_growth_evidence" if growth else "view_render_evidence"
    cases = VIEW_GROWTH_CASES if growth else VIEW_CASES
    stream_identity = view_growth_stream_identity if growth else view_stream_identity
    stem = "view-render-growth" if growth else "view-render"
    evidence = evidence_reader(output, report)
    if evidence != report.get(evidence_key):
        raise ValueError("view native read snapshots or rendered bytes changed before original Rust replay")
    folder = output / (VIEW_GROWTH_FOLDER if growth else VIEW_FOLDER)
    source = ROOT / "tests/hia_native/oracle_view_render.rs"
    binary = folder / "original-view.elf"
    rust_compile(output, report, rustc, key=stem + "-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    binary_hash = sha(binary)
    replay = folder / "original-replay"
    row = record_check(output, report, name=stem + "-rust-compare",
        command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_view_original.py"),
                 "--source", str(source), "--binary", str(binary),
                 "--requests", str(folder / "requests.hex.gz"),
                 "--expected", str(folder / "native-output.txt.gz"),
                 "--metadata", str(folder / "native-corpus.json"), "--output", str(replay)],
        env=qualification_env(), timeout=60)
    observed = json.loads(row.stdout)
    if (row.stderr or observed.get("status") != "PASS" or type(observed.get("cases")) is not int
            or observed["cases"] != cases or observed.get("run_exit_code") != 0
            or observed.get("compiled_by_qualification_recipe") is not True
            or observed.get("native_and_rust_output_sha256") != evidence["native_output_sha256"]
            or observed.get("raw_output_bytes") != evidence["native_output_bytes"]
            or observed.get("executable", {}).get("sha256") != binary_hash
            or observed.get("inputs_before") != observed.get("inputs_after")
            or json.loads((replay / "result.json").read_bytes()) != observed
            or stream_identity(replay / "rust-output.txt.gz", evidence["native_output_bytes"]) != (
                evidence["native_output_bytes"], evidence["native_output_sha256"])
            or sha(binary) != binary_hash or evidence_reader(output, report) != evidence):
        raise ValueError("original view complete ordered responses or source custody differ")
    result = {"schema": "hepta.runtime." + stem + "-rust-comparison.v1", "status": "PASS",
              "cases": cases, "native_cases_added_by_replay": 0,
              "reference_kind": "unchanged original range, file render, cache, delta and result gate methods with independent read fixtures",
              "input_sha256": evidence["input_sha256"], "native_output_sha256": evidence["native_output_sha256"],
              "original_output_sha256": observed["native_and_rust_output_sha256"],
              "oracle_executable_sha256": binary_hash, "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_sources_sha256": evidence["original_sources_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "original_replay_receipt_sha256": sha(replay / "result.json"),
              "complete_original_tool_parity": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_caller_authority(output: Path, report: dict, rustc: Path, *, report_path: Path | None = None) -> dict:
    cargo = executable(str(rustc.with_name("cargo")))
    executable(str(rustc.with_name("cargo-fmt")))
    rustfmt = executable(str(rustc.with_name("rustfmt")))

    def environment():
        # Cargo can prefer its home-directory proxy over PATH. RUSTFMT pins
        # the actual formatter even when that proxy dispatches cargo-fmt.
        env = qualification_env()
        env["PATH"] = str(cargo.parent) + os.pathsep + env.get("PATH", os.defpath)
        env["RUSTFMT"] = str(rustfmt)
        return env

    def capture(*args, **kwargs):
        return record_check(*args, **kwargs, report_path=report_path)

    return compare_authority_original(ROOT, output, report, rustc, record_check=capture,
        completed_test_summary=completed_test_summary, qualification_env=environment, cargo=cargo)


def compare_fence_json(output: Path, report: dict, rustc: Path) -> dict:
    return compare_json_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        "fence_json", completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_serde_json(output: Path, report: dict, rustc: Path) -> dict:
    return compare_json_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        "serde_json", completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_request_context(output: Path, report: dict, rustc: Path) -> dict:
    return compare_request_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        "request_context", completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_response_hints(output: Path, report: dict, rustc: Path) -> dict:
    return compare_request_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        "response_hints", completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_result_publication(output: Path, report: dict, rustc: Path) -> dict:
    return compare_publication_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_request_scope(output: Path, report: dict, rustc: Path) -> dict:
    return compare_request_scope_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_terminal_clean(output: Path, report: dict, rustc: Path) -> dict:
    return shell_qualification.compare_original(ROOT, output, report, "terminal_clean", rustc,
        executable(str(rustc.with_name("cargo"))), completed_test_summary, record_check, qualification_env)


def compare_shell_gate(output: Path, report: dict, rustc: Path) -> dict:
    return shell_qualification.compare_original(ROOT, output, report, "shell_gate", rustc,
        executable(str(rustc.with_name("cargo"))), completed_test_summary, record_check, qualification_env)


def retained_execution_original(output: Path, report: dict) -> dict:
    import hia_native_execution_qualification as q
    name = "execution-shadow-rust-compare"
    check, summary = completed_test_summary(output, report, name)
    folder = output / "execution-shadow-rust-reference"
    result = q.original_evidence(ROOT, output / q.FOLDER, folder, stdout=output / (name + ".stdout"))
    q.exact(summary, result["report"], "actual original aggregate stdout differs")
    if (check.get("timeout_seconds") != 180 or not 0 < check.get("elapsed_seconds", 0) < 180
            or check.get("stderr_bytes") != 0 or check["stdout_bytes"] != (output / (name + ".stdout")).stat().st_size):
        raise ValueError("execution original aggregate process differs")
    command = check["command"]
    expected = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_execution_original.py"),
                "--runtime", str(ROOT), "--corpus", str(output / q.FOLDER), "--output", str(folder),
                "--rustc", report["rust_compiler"]["invocation_path"]]
    if len(command) != len(expected) + 2 or command[:len(expected)] != expected or command[-2] != "--cargo":
        raise ValueError("execution original aggregate invocation differs")
    return {**result, "completed_process": {key: check[key] for key in
            ("command", "exit_code", "timed_out", "timeout_seconds", "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256")}}


def compare_execution(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_execution_qualification as q
    before = execution_evidence(output, report)
    if before != report.get("execution_evidence"):
        raise ValueError("execution native evidence changed before original replay")
    cargo = executable(str(rustc.with_name("cargo")))
    command = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_execution_original.py"),
               "--runtime", str(ROOT), "--corpus", str(output / q.FOLDER),
               "--output", str(output / "execution-shadow-rust-reference"), "--rustc", str(rustc), "--cargo", str(cargo)]
    record_check(output, report, name="execution-shadow-rust-compare", command=command, timeout=180,
                 env=qualification_env())
    result = retained_execution_original(output, report)
    if execution_evidence(output, report) != before:
        raise ValueError("execution native evidence changed during original replay")
    return result


def retained_config_original(output: Path, report: dict) -> dict:
    import hia_native_config_qualification as q
    return {"configuration": q.original_evidence(ROOT, output, report, completed_test_summary),
            "regex": q.regex_original_evidence(ROOT, output, report, completed_test_summary)}


def compare_config(output: Path, report: dict, rustc: Path) -> dict:
    before = config_evidence(output, report)
    if before != report.get("config_evidence"):
        raise ValueError("configuration native evidence changed before original replay")
    cargo = executable(str(rustc.with_name("cargo")))
    command = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_config_original.py"),
               "--repo", str(ROOT), "--native-results", str(output / "config-native/result.json"),
               "--output", str(output / "config-original"), "--cargo", str(cargo), "--rustc", str(rustc)]
    record_check(output, report, name="config-rust-compare", command=command, timeout=180,
                 env=qualification_env())
    regex_command = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_regex_original.py"),
                     "--repo", str(ROOT), "--native-results", str(output / "regex-native/result.json"),
                     "--output", str(output / "regex-original"), "--cargo", str(cargo), "--rustc", str(rustc)]
    record_check(output, report, name="regex-rust-compare", command=regex_command, timeout=180,
                 env=qualification_env())
    result = retained_config_original(output, report)
    if config_evidence(output, report) != before:
        raise ValueError("configuration native evidence changed during original replay")
    return result


def compare_effect_fence(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_effect_fence_qualification as q
    return q.compare_original(ROOT, output, report, rustc,
                              q.completed_process, record_check, qualification_env())


def compare_file_locks(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_file_lock_pipeline as q
    return q.compare_original(ROOT, output, report, rustc, completed_test_summary,
                              record_check, qualification_env(), "file_locks")


def compare_file_lock_service(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_file_lock_pipeline as q
    return q.compare_original(ROOT, output, report, rustc, completed_test_summary,
                              record_check, qualification_env(), "file_lock_service")


def compare_session_workdir(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_session_qualification as q
    return q.compare_original(ROOT, output, report, rustc, completed_test_summary,
                              record_check, qualification_env())


def compare_filesystem_parity(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_filesystem_parity_qualification as q
    value = q.compare_original(ROOT, output, report, rustc, record_check, completed_test_summary)
    return q.decode(q.canonical(value))


def retained_filesystem_parity(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_filesystem_parity_qualification as q
    value = q.retained_original(ROOT, output, report, rustc, completed_test_summary)
    return q.decode(q.canonical(value))


def shell_process_original_commands(output: Path, report: dict, rustc: Path) -> dict[str, list[str]]:
    """One fresh original build owns both required process and text comparisons."""
    cargo = executable(str(rustc.with_name("cargo")))
    manifest = output / report["modules"]["shell_process"]["manifest"]
    base = output / "shell-process-original"
    build = base / "build"
    prefix = [sys.executable, "-I", "-B"]
    reference = prefix + [str(ROOT / "scripts/hia_native_shell_process_reference.py"),
        "--runtime", str(ROOT), "--rustc", str(rustc), "--cargo", str(cargo)]
    return {
        "shell-process-rust-build": reference + ["--output", str(build)],
        "shell-process-rust-compare": prefix + [str(ROOT / "scripts/hia_native_shell_process_qualification.py"),
            "--native-executable", str(manifest.parent / "shell-process.elf"),
            "--native-manifest", str(manifest),
            "--oracle-executable", str(build / "target/release/hepta-shell-process-original-oracle"),
            "--oracle-build-manifest", str(build / "result.json"),
            "--cases-source", str(ROOT / "tests/hia_native/shell_process_cases.py"),
            "--output", str(base / "cases"), "--jobs", "2"],
        "shell-background-rust-compare": reference + [
            "--output", str(base / "background"), "--reference-build", str(build),
            "--background-corpus", str(output / "shell-background-text/native")],
    }


def shell_process_original_evidence(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_shell_process_reference as reference
    import hia_native_shell_process_evidence as process
    base = output / "shell-process-original"
    manifest = output / report["modules"]["shell_process"]["manifest"]
    cargo = executable(str(rustc.with_name("cargo")))
    commands = shell_process_original_commands(output, report, rustc)
    completed = {}
    for name, timeout, status in (
            ("shell-process-rust-build", 900, "PASS"),
            ("shell-process-rust-compare", 180, "ORIGINAL_COMPARISON_PASS")):
        completed[name] = shell_completed_process(output, report, name, commands[name],
            phase="original_rust_comparison", timeout=timeout, status=status)
    original = reference.read_evidence(ROOT, base / "build", rustc, cargo)
    if (original.get("fresh_original_rust_build_qualified") is not True
            or original.get("original_tests") != 21):
        raise ValueError("complete fresh original shell source/tests are not qualified")
    comparison = process.read_evidence(base / "cases", manifest, base / "build/result.json",
                                      require_full=True)
    if comparison.get("fixtures_retired") is not True:
        raise ValueError("original/native shell fixtures must be strongly retired before admission")
    # The strong readers bind actual original compiler/dependency sources, both
    # executable identities, all 38 inputs/logs/traces and exact original paths.
    # Retain every recipe-owned byte as a separate aggregate mutation barrier.
    return {
        "schema": "hepta.runtime.shell-process-required-original.v1", "status": "PASS",
        "compiled_by_qualification_recipe": True,
        "reference_kind": "complete unchanged shell/background owners and all 21 original tests",
        "completed_processes": completed, "reference_build": original,
        "real_os_comparison": comparison, "original_tests": 21, "paired_real_os_cases": 38,
        "retained_files_sha256": shell_retained_files(output, (base / "build", base / "cases")),
        "native_phase_cases_added_by_reference": 0, "original_rust_compared": True,
        "production_shell_execution_qualified": False, "production_activated": False,
        "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
    }


def compare_shell_process(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_shell_process_reference as reference
    import hia_native_shell_process_evidence as process
    before = shell_process_evidence(output, report)
    if before != report.get("shell_process_evidence"):
        raise ValueError("required native shell process evidence changed before original replay")
    commands = shell_process_original_commands(output, report, rustc)
    record_check(output, report, name="shell-process-rust-build",
        command=commands["shell-process-rust-build"], timeout=900, env=qualification_env())
    base = output / "shell-process-original"
    cargo = executable(str(rustc.with_name("cargo")))
    reference.read_evidence(ROOT, base / "build", rustc, cargo)
    record_check(output, report, name="shell-process-rust-compare",
        command=commands["shell-process-rust-compare"], timeout=180, env=qualification_env())
    manifest = output / report["modules"]["shell_process"]["manifest"]
    process.read_evidence(base / "cases", manifest, base / "build/result.json", require_full=True)
    process.retire_fixtures(base / "cases", manifest, base / "build/result.json")
    result = shell_process_original_evidence(output, report, rustc)
    if shell_process_evidence(output, report) != before:
        raise ValueError("required native shell process evidence changed during original replay")
    return result


def shell_background_original_evidence(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_shell_process_reference as reference
    base = output / "shell-process-original"
    original_process = shell_process_original_evidence(output, report, rustc)
    if report.get("original_rust_comparisons", {}).get("shell_process") != original_process:
        raise ValueError("background replay does not reuse this gate's complete fresh shell reference")
    command = shell_process_original_commands(output, report, rustc)["shell-background-rust-compare"]
    completed = shell_completed_process(output, report, "shell-background-rust-compare", command,
        phase="original_rust_comparison", timeout=300)
    result = reference.read_background_evidence(ROOT, base / "build",
        output / "shell-background-text/native", base / "background",
        rustc, executable(str(rustc.with_name("cargo"))))
    if (result.get("semantic_cases") != 3456 or result.get("native_transport_controls") != 51
            or result.get("original_rust_compared") is not True
            or result.get("fresh_original_rust_build_qualified") is not True
            or result.get("reference_report_sha256") != original_process["reference_build"]["report_sha256"]):
        raise ValueError("complete original background byte projection or fresh build binding differs")
    return {
        "schema": "hepta.runtime.shell-background-required-original.v1", "status": "PASS",
        "compiled_by_qualification_recipe": True, "reused_same_gate_shell_reference": True,
        "completed_process": completed, "comparison": result,
        "retained_files_sha256": shell_retained_files(output, (base / "background",)),
        "semantic_cases": 3456, "native_controls": 51, "native_phase_cases_added_by_reference": 0,
        "original_rust_compared": True, "native_filesystem_reads_qualified": False,
        "production_shell_execution_qualified": False, "production_activated": False,
        "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
    }


def compare_shell_background(output: Path, report: dict, rustc: Path) -> dict:
    before = shell_background_evidence(output, report)
    if before != report.get("shell_background_evidence"):
        raise ValueError("required native background evidence changed before original replay")
    expected = shell_process_original_evidence(output, report, rustc)
    if report.get("original_rust_comparisons", {}).get("shell_process") != expected:
        raise ValueError("fresh process reference must complete before background replay")
    command = shell_process_original_commands(output, report, rustc)["shell-background-rust-compare"]
    record_check(output, report, name="shell-background-rust-compare",
        command=command, timeout=300, env=qualification_env())
    result = shell_background_original_evidence(output, report, rustc)
    if shell_background_evidence(output, report) != before:
        raise ValueError("required native background evidence changed during original replay")
    return result


def shell_outcome_original_command(output: Path, report: dict, rustc: Path) -> list[str]:
    manifest = output / report["modules"]["shell_outcome"]["manifest"]
    base = output / "shell-process-original"
    return [sys.executable, "-I", "-B", str(ROOT / "scripts/hia_native_shell_outcome_qualification.py"),
        "--runtime", str(ROOT), "--reference-build", str(base / "build"),
        "--native-corpus", str(output / "shell-outcome/native"),
        "--native-manifest", str(manifest), "--output", str(base / "outcome"),
        "--rustc", str(rustc), "--cargo", str(executable(str(rustc.with_name("cargo"))))]


def shell_outcome_original_evidence(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_shell_outcome_qualification as outcome
    base = output / "shell-process-original"
    original_process = shell_process_original_evidence(output, report, rustc)
    if report.get("original_rust_comparisons", {}).get("shell_process") != original_process:
        raise ValueError("outcome replay does not reuse this gate's complete fresh shell reference")
    command = shell_outcome_original_command(output, report, rustc)
    completed = shell_completed_process(output, report, "shell-outcome-rust-compare", command,
        phase="original_rust_comparison", timeout=300)
    manifest = output / report["modules"]["shell_outcome"]["manifest"]
    result = outcome.read_evidence(ROOT, base / "build", output / "shell-outcome/native",
        manifest, base / "outcome", rustc, executable(str(rustc.with_name("cargo"))))
    # Checkpoints reload JSON object keys as strings, including operation numbers.
    # Preserve every strongly checked field in the same representation on both paths.
    result = json.loads(json.dumps(result, sort_keys=True, allow_nan=False))
    if (result.get("comparison", {}).get("counts", {}).get("semantic_cases") != 78083
            or result.get("original_rust_compared") is not True
            or result.get("fresh_original_rust_build_qualified") is not True
            or result.get("reference_report_sha256") != original_process["reference_build"]["report_sha256"]):
        raise ValueError("complete original outcome byte projection or fresh build binding differs")
    return {
        "schema": "hepta.runtime.shell-outcome-required-original.v1", "status": "PASS",
        "compiled_by_qualification_recipe": True, "reused_same_gate_shell_reference": True,
        "completed_process": completed, "comparison": result,
        "retained_files_sha256": shell_retained_files(output, (base / "outcome",)),
        "semantic_cases": 78083, "native_phase_cases_added_by_reference": 0,
        "original_rust_compared": True, "native_filesystem_reads_qualified": False,
        "production_shell_execution_qualified": False, "production_activated": False,
        "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
    }


def compare_shell_outcome(output: Path, report: dict, rustc: Path) -> dict:
    before = shell_outcome_evidence(output, report)
    if before != report.get("shell_outcome_evidence"):
        raise ValueError("required native outcome evidence changed before original replay")
    original_process = shell_process_original_evidence(output, report, rustc)
    if report.get("original_rust_comparisons", {}).get("shell_process") != original_process:
        raise ValueError("fresh process reference must complete before outcome replay")
    command = shell_outcome_original_command(output, report, rustc)
    record_check(output, report, name="shell-outcome-rust-compare", command=command,
        timeout=300, env=qualification_env())
    result = shell_outcome_original_evidence(output, report, rustc)
    if shell_outcome_evidence(output, report) != before:
        raise ValueError("required native outcome evidence changed during original replay")
    return result


def shell_output_original_command(output: Path, report: dict, rustc: Path) -> list[str]:
    manifest = output / report["modules"]["shell_output_io"]["manifest"]
    outcome = output / report["modules"]["shell_outcome"]["manifest"]
    base = output / "shell-process-original"
    return [sys.executable, "-I", "-B", str(ROOT / "scripts/hia_native_shell_output_qualification.py"),
        "--runtime", str(ROOT), "--reference-build", str(base / "build"),
        "--native-corpus", str(output / "shell-output/native"),
        "--native-manifest", str(manifest), "--outcome-manifest", str(outcome),
        "--output", str(base / "output-io"),
        "--rustc", str(rustc), "--cargo", str(executable(str(rustc.with_name("cargo"))))]


def shell_output_original_evidence(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_shell_output_qualification as output_io
    base = output / "shell-process-original"
    process = shell_process_original_evidence(output, report, rustc)
    outcome = shell_outcome_original_evidence(output, report, rustc)
    comparisons = report.get("original_rust_comparisons", {})
    if comparisons.get("shell_process") != process or comparisons.get("shell_outcome") != outcome:
        raise ValueError("output IO replay requires this gate's fresh process and complete outcome evidence")
    command = shell_output_original_command(output, report, rustc)
    completed = shell_completed_process(output, report, "shell-output-rust-compare", command,
        phase="original_rust_comparison", timeout=300)
    manifest = output / report["modules"]["shell_output_io"]["manifest"]
    outcome_manifest = output / report["modules"]["shell_outcome"]["manifest"]
    result = output_io.read_evidence(ROOT, base / "build", output / "shell-output/native",
        manifest, outcome_manifest, base / "output-io", rustc, executable(str(rustc.with_name("cargo"))))
    if (result.get("paired_real_io_cases") != 6 or result.get("original_rust_compared") is not True
            or result.get("fresh_original_rust_build_qualified") is not True
            or result.get("native_phase_cases_added_by_reference") != 0
            or result.get("actual_native_process_wait") is not False
            or result.get("reference_report_sha256") != process["reference_build"]["report_sha256"]):
        raise ValueError("original/native complete real IO comparison or fresh build binding differs")
    return {
        "schema": "hepta.runtime.shell-output-required-original.v1", "status": "PASS",
        "compiled_by_qualification_recipe": True, "reused_same_gate_shell_reference": True,
        "completed_process": completed, "comparison": result,
        "retained_files_sha256": shell_retained_files(output, (base / "output-io",)),
        "paired_real_io_cases": 6, "native_phase_cases_added_by_reference": 0,
        "original_rust_compared": True, "actual_native_process_wait": False,
        "production_shell_execution_qualified": False, "production_activated": False,
        "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
    }


def compare_shell_output(output: Path, report: dict, rustc: Path) -> dict:
    before = shell_output_evidence(output, report)
    if before != report.get("shell_output_evidence"):
        raise ValueError("required native IO/outcome evidence changed before original replay")
    process = shell_process_original_evidence(output, report, rustc)
    outcome = shell_outcome_original_evidence(output, report, rustc)
    comparisons = report.get("original_rust_comparisons", {})
    if comparisons.get("shell_process") != process or comparisons.get("shell_outcome") != outcome:
        raise ValueError("fresh process and complete outcome comparison must precede output IO replay")
    command = shell_output_original_command(output, report, rustc)
    record_check(output, report, name="shell-output-rust-compare", command=command,
        timeout=300, env=qualification_env())
    result = shell_output_original_evidence(output, report, rustc)
    if shell_output_evidence(output, report) != before:
        raise ValueError("required native IO/outcome evidence changed during original replay")
    return result


def shell_foreground_original_command(output: Path, report: dict, rustc: Path) -> list[str]:
    manifest = output / report["modules"]["shell_foreground"]["manifest"]
    base = output / "shell-process-original"
    return [sys.executable, "-I", "-B", str(ROOT / "scripts/hia_native_shell_foreground_qualification.py"),
        "--runtime", str(ROOT), "--reference-build", str(base / "build"),
        "--original-io-corpus", str(base / "output-io/original-io"),
        "--native-corpus", str(output / "shell-foreground/native"),
        "--native-manifest", str(manifest), "--output", str(base / "foreground"),
        "--rustc", str(rustc), "--cargo", str(executable(str(rustc.with_name("cargo"))))]


def shell_foreground_original_evidence(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_shell_foreground_qualification as foreground
    base = output / "shell-process-original"
    paired = shell_output_original_evidence(output, report, rustc)
    if report.get("original_rust_comparisons", {}).get("shell_output_io") != paired:
        raise ValueError("foreground replay must reuse this gate's completed original real IO corpus")
    command = shell_foreground_original_command(output, report, rustc)
    completed = shell_completed_process(output, report, "shell-foreground-rust-compare", command,
        phase="original_rust_comparison", timeout=300)
    manifest = output / report["modules"]["shell_foreground"]["manifest"]
    result = foreground.read_evidence(ROOT, base / "build", base / "output-io/original-io",
        output / "shell-foreground/native", manifest, base / "foreground", rustc,
        executable(str(rustc.with_name("cargo"))))
    if (result.get("paired_real_foreground_cases") != 6
            or result.get("original_rust_compared") is not True
            or result.get("fresh_original_rust_build_qualified") is not True
            or result.get("actual_native_process_wait") is not True
            or result.get("native_phase_cases_added_by_reference") != 0
            or result.get("original_processes_added_by_comparison") != 0
            or result.get("reference_report_sha256") != paired["comparison"]["reference_report_sha256"]
            or result.get("original_io_report_sha256") != paired["comparison"]["original_io"]["report"]["sha256"]):
        raise ValueError("complete original/native foreground bytes or same-gate evidence differ")
    return {
        "schema": "hepta.runtime.shell-foreground-required-original.v1", "status": "PASS",
        "compiled_by_qualification_recipe": True, "reused_same_gate_shell_reference": True,
        "reused_same_gate_real_original_io": True,
        "completed_process": completed, "comparison": result,
        "retained_files_sha256": shell_retained_files(output, (base / "foreground",)),
        "paired_real_foreground_cases": 6, "native_phase_cases_added_by_reference": 0,
        "original_processes_added_by_comparison": 0,
        "original_rust_compared": True, "actual_native_process_wait": True,
        "production_shell_execution_qualified": False, "production_activated": False,
        "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
    }


def compare_shell_foreground(output: Path, report: dict, rustc: Path) -> dict:
    before = shell_foreground_evidence(output, report)
    if before != report.get("shell_foreground_evidence"):
        raise ValueError("required native foreground evidence changed before original comparison")
    paired = shell_output_original_evidence(output, report, rustc)
    if report.get("original_rust_comparisons", {}).get("shell_output_io") != paired:
        raise ValueError("fresh original real IO comparison must precede foreground composition")
    record_check(output, report, name="shell-foreground-rust-compare",
        command=shell_foreground_original_command(output, report, rustc),
        timeout=300, env=qualification_env())
    result = shell_foreground_original_evidence(output, report, rustc)
    if shell_foreground_evidence(output, report) != before:
        raise ValueError("required native foreground evidence changed during original comparison")
    return result


def compare_shell_capture_path(output: Path, report: dict, rustc: Path) -> dict:
    return capture_gate.compare(output, report, "shell_capture_path", rustc)


def compare_shell_capture_mkdir(output: Path, report: dict, rustc: Path) -> dict:
    return capture_gate.compare(output, report, "shell_capture_mkdir", rustc)


def compare_shell_capture_file(output: Path, report: dict, rustc: Path) -> dict:
    return capture_gate.compare(output, report, "shell_capture_file", rustc)


def compare_shell_capture_prepare(output: Path, report: dict, rustc: Path) -> dict:
    return capture_gate.compare(output, report, "shell_capture_prepare", rustc)


def compare_write_chain(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_write_chain_pipeline as q
    return q.compare_original(ROOT, output, report, rustc, completed_test_summary, record_check, qualification_env())


def compare_directory_service(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_service_pipeline as q
    return q.compare_original(ROOT, output, report, rustc, completed_test_summary,
                              record_check, qualification_env(), "directory_service")


def compare_workdir_service(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_service_pipeline as q
    return q.compare_original(ROOT, output, report, rustc, completed_test_summary,
                              record_check, qualification_env(), "workdir_service")


def compare_sdk_connection(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_service_pipeline as q
    return q.compare_original(ROOT, output, report, rustc, completed_test_summary,
                              record_check, qualification_env(), "sdk_connection")


def compare_serde_error(output: Path, report: dict, rustc: Path) -> dict:
    before = serde_error_evidence(output, report)
    if before != report.get("serde_error_evidence"):
        raise ValueError("diagnostic native evidence changed before original replay")
    for name, command in serde_error_pipeline.original_commands(ROOT, output, report, rustc).items():
        record_check(output, report, name=name, command=command, timeout=180, env=qualification_env())
    actual = serde_error_pipeline.original_evidence(ROOT, output, report, completed_test_summary)
    if serde_error_evidence(output, report) != before:
        raise ValueError("diagnostic native corpus changed during original replay")
    return actual


def compare_result_storage(output: Path, report: dict, rustc: Path, domain: str) -> dict:
    before = result_storage_evidence(output, report)
    if before != report.get("result_storage_evidence"):
        raise ValueError("storage native corpus changed before original execution")
    command = storage_pipeline.original_command(ROOT, output, report, rustc,
        executable(str(rustc.with_name("cargo"))), domain)
    record_check(output, report, name=storage_pipeline.RUST_NAMES[domain],
        command=command, timeout=180, env=qualification_env())
    actual = storage_pipeline.original_evidence(ROOT, output, report, completed_test_summary, domain)
    if result_storage_evidence(output, report) != before:
        raise ValueError("storage native corpus changed during complete original replay")
    return actual


def run_result_storage_controls(output: Path, report: dict) -> None:
    storage_pipeline.run_controls(ROOT, output, report, completed_test_summary, record_check, qualification_env())


def compare_result_values(output: Path, report: dict, rustc: Path, domain: str) -> dict:
    before = result_values_evidence(output, report)
    if before != report.get("result_values_evidence"):
        raise ValueError("native result evidence changed before original execution")
    cargo = executable(str(rustc.with_name("cargo")))
    command = result_qualification.original_command(ROOT, output, report, rustc, cargo, domain)
    record_check(output, report, name="result-" + domain + "-rust-compare", command=command,
                 timeout=180, env=qualification_env())
    actual = result_qualification.original_evidence(ROOT, output, report, completed_test_summary, domain)
    if result_values_evidence(output, report) != before:
        raise ValueError("native result corpus changed during complete original replay")
    return actual


def compare_binary32_json(output: Path, report: dict, rustc: Path) -> dict:
    return compare_result_values(output, report, rustc, "binary32")


def compare_typed_result_json(output: Path, report: dict, rustc: Path) -> dict:
    return compare_result_values(output, report, rustc, "typed")


def compare_request_result(output: Path, report: dict, rustc: Path) -> dict:
    return compare_result_values(output, report, rustc, "request")


RESULT_VALUE_CONTROL_LABELS = (
    "actual-original-nonzero", "actual-original-timeout", "actual-original-limit", "actual-original-command",
    "original-environment", "missing-actual-compile", "compiled-original-image", "original-function-custody",
    "incomplete-original-domain", "fresh-replay-timeout", "complete-original-output", "large-original-output-truncated",
    "locked-registry-archive",
)


def result_values_control_command(output: Path) -> list[str]:
    return [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/check_result_value_evidence.py"),
            "--repo", str(ROOT), "--output", str(output),
            "--report", str(output / "result-values-controls-input.json"),
            "--result", str(output / "result-values-evidence-controls.json")]


def result_values_control_evidence(output: Path, report: dict) -> dict:
    helper, name = result_qualification, "result-values-evidence-controls"
    snapshot = helper.object_at(output / "result-values-controls-input.json")
    indices = [i for i, row in enumerate(report["checks"]) if row.get("name") == name]
    if len(indices) != 1 or snapshot.get("checks") != report["checks"][:indices[0]]:
        raise ValueError("result controls did not observe the complete prior process set")
    for key in ("source_sha256", "modules", "result_values_evidence", "original_rust_comparisons",
                "compiler_checkout", "compiler_commit", "compiler_image_sha256"):
        if snapshot.get(key) != report.get(key):
            raise ValueError("result control input changed: " + key)
    row, summary = completed_test_summary(output, report, name)
    out, err = helper.completed(output, name, row, result_values_control_command(output), ROOT, 180, aggregate=True)
    value = helper.object_at(output / "result-values-evidence-controls.json")
    baseline = {domain: helper.original_evidence(ROOT, output, snapshot, completed_test_summary, domain)
                for domain in helper.DOMAINS}
    expected = helper.sha(helper.encoded(baseline))
    if (err or json.loads(out) != summary or summary != value or row.get("phase") != "original_rust_comparison"
            or value.get("schema") != "hepta.result-values.original-controls.v1" or value.get("status") != "PASS"
            or value.get("rejections") != 13 or value.get("restorations") != 14
            or value.get("complete_original_admissions") != 6
            or value.get("actual_native_calls_added") != 0 or value.get("actual_rust_calls_added") != 0
            or value.get("restored_file_bytes_and_modes") is not True
            or value.get("report_sha256") != sha(output / "result-values-controls-input.json")
            or value.get("baseline_evidence_sha256") != expected or value.get("final_evidence_sha256") != expected
            or tuple(item.get("label") for item in value.get("controls", ())) != RESULT_VALUE_CONTROL_LABELS
            or any(item.get("rejected") is not True or not item.get("exception") for item in value["controls"])):
        raise ValueError("result complete evidence corruption/restoration domain differs")
    helper.duration(value.get("elapsed_seconds"), 180)
    names = ("result-values-controls-input.json", "result-values-evidence-controls.json", name + ".stdout", name + ".stderr")
    return {"schema": "hepta.result-values.aggregate-controls.v1", "status": "PASS",
            "artifact_sha256": {item: sha(output / item) for item in names}, "rejections": 13,
            "actual_native_calls_added": 0, "actual_rust_calls_added": 0}


def run_result_values_controls(output: Path, report: dict) -> None:
    # All original workers are drained before temporarily damaging evidence.
    with (output / "result-values-controls-input.json").open("xb") as stream:
        stream.write(result_qualification.encoded(report))
    record_check(output, report, name="result-values-evidence-controls",
                 command=result_values_control_command(output), timeout=180, env=qualification_env())
    report["result_values_evidence_controls"] = result_values_control_evidence(output, report)


def compare_public_registry(output: Path, report: dict, rustc: Path) -> dict:
    before = public_registry_evidence(output, report)
    if before != report.get("public_registry_evidence"):
        raise ValueError("public registry native evidence changed before original replay")
    command = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_public_registry_original.py"),
               "--repo", str(ROOT), "--build", str(output / "build/public-registry-build.json"),
               "--output", str(output / "public-registry-original"),
               "--cargo", str(executable(str(rustc.with_name("cargo")))),
               "--rustc", str(rustc), "--rustfmt", str(executable(str(rustc.with_name("rustfmt"))))]
    record_check(output, report, name="public-registry-rust-compare", command=command,
                 timeout=180, env=qualification_env())
    result = public_registry_qualification.original_evidence(ROOT, output, report, completed_test_summary)
    if public_registry_evidence(output, report) != before:
        raise ValueError("public registry native evidence changed during original replay")
    return result


PUBLIC_REGISTRY_CONTROL_LABELS = (
    "missing-actual-native-completion", "nonzero-native-exit", "native-timeout",
    "changed-actual-native-command", "nonzero-original-exit", "changed-original-deadline",
    "incomplete-native-session-report", "omitted-native-response-session",
    "changed-actual-native-request-custody", "changed-actual-embedded-router-image",
    "changed-compiled-router-image", "rehashed-empty-native-compiler-observer",
    "changed-native-packer-input", "changed-executed-HIA-source", "missing-private-receipt-control",
    "omitted-original-response-session", "missing-actual-original-build", "changed-original-executable",
    "changed-whole-original-wrapper", "changed-locked-SDK-source",
)


def public_registry_control_command(output: Path) -> list[str]:
    return [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/check_public_registry_evidence.py"),
            "--repo", str(ROOT), "--output", str(output),
            "--report", str(output / "public-registry-controls-input.json"),
            "--result", str(output / "public-registry-evidence-controls.json")]


def public_registry_control_evidence(output: Path, report: dict) -> dict:
    """Admit the real quiescent corruption process and its unchanged evidence."""
    helper = public_registry_qualification
    name = "public-registry-evidence-controls"
    snapshot = helper.object_at(output / "public-registry-controls-input.json")
    prior = [row for row in report["checks"] if row.get("name") != name]
    if snapshot.get("checks") != prior:
        raise ValueError("public evidence controls did not observe the complete prior process set")
    for key in ("source_sha256", "modules", "public_registry_evidence", "original_rust_comparisons",
                "compiler_checkout", "compiler_commit", "compiler_image_sha256"):
        if snapshot.get(key) != report.get(key):
            raise ValueError("public evidence control input changed: " + key)
    row, summary = completed_test_summary(output, report, name)
    out, err = helper.completed(output, name, row, public_registry_control_command(output), ROOT, 180, aggregate=True)
    value = helper.object_at(output / "public-registry-evidence-controls.json")
    baseline = helper.original_evidence(ROOT, output, snapshot, completed_test_summary)
    expected = helper.sha(helper.encoded(baseline))
    if (err or json.loads(out) != summary or summary != value
            or row.get("phase") != "original_rust_comparison"
            or value.get("schema") != "hepta.public-registry.evidence-controls.v1"
            or value.get("status") != "PASS" or value.get("rejections") != 20
            or value.get("full_baseline_admissions") != 22
            or value.get("actual_native_calls_added") != 0 or value.get("actual_rust_calls_added") != 0
            or value.get("restored_file_bytes_and_modes") is not True
            or value.get("report_sha256") != sha(output / "public-registry-controls-input.json")
            or value.get("baseline_evidence_sha256") != expected or value.get("final_evidence_sha256") != expected
            or tuple(item.get("label") for item in value.get("controls", ())) != PUBLIC_REGISTRY_CONTROL_LABELS
            or any(item.get("rejected") is not True or not item.get("exception") for item in value["controls"])):
        raise ValueError("public evidence corruption/restoration domain is incomplete")
    helper.duration(value.get("elapsed_seconds"), 180)
    names = ("public-registry-controls-input.json", "public-registry-evidence-controls.json",
             name + ".stdout", name + ".stderr")
    return {"schema": "hepta.public-registry.aggregate-controls.v1", "status": "PASS",
            "artifact_sha256": {item: sha(output / item) for item in names},
            "rejections": 20, "full_baseline_admissions": 22,
            "actual_native_calls_added": 0, "actual_rust_calls_added": 0}


def run_public_registry_controls(output: Path, report: dict) -> None:
    # Every original recipe, including the two parallel OS workers, is already
    # drained. The separate immutable input avoids a self-referential report SHA.
    with (output / "public-registry-controls-input.json").open("xb") as stream:
        stream.write(public_registry_qualification.encoded(report))
    record_check(output, report, name="public-registry-evidence-controls",
                 command=public_registry_control_command(output), timeout=180, env=qualification_env())
    report["public_registry_evidence_controls"] = public_registry_control_evidence(output, report)


def compare_batch_write(output: Path, report: dict, rustc: Path) -> dict:
    return batch_write_pipeline.compare_original(ROOT, output, report, rustc, completed_test_summary,
                                                  record_check, qualification_env())


def compare_batch_edit_params(output: Path, report: dict, rustc: Path) -> dict:
    from hia_native_batch_edit_params_pipeline import execute_original
    return execute_original(ROOT, output, report, rustc, record_check=record_check,
                            completed=completed_test_summary, qualification_env=qualification_env)


def compare_batch_plan_input(output: Path, report: dict, rustc: Path) -> dict:
    from hia_native_batch_plan_input_pipeline import execute_original
    return execute_original(ROOT, output, report, rustc, record_check=record_check,
                            completed=completed_test_summary, qualification_env=qualification_env)


def compare_batch_diff(output: Path, report: dict, rustc: Path) -> dict:
    from hia_native_batch_diff_pipeline import execute_original
    return execute_original(ROOT, output, report, rustc, record_check=record_check,
                            completed=completed_test_summary, qualification_env=qualification_env)



def compare_config_span(output: Path, report: dict, rustc: Path) -> dict:
    from hia_native_config_span_pipeline import execute_original
    return execute_original(ROOT, output, report, rustc, record_check, completed_test_summary)


def compare_filesystem_public(output: Path, report: dict, rustc: Path) -> dict:
    from hia_native_filesystem_public_pipeline import execute_original
    return execute_original(ROOT, output, report, rustc, record_check, completed_test_summary)


RECIPES = {"serde_error": compare_serde_error, "batch_write": compare_batch_write, "runtime_bytes": compare_bytes, "text_budget": compare_text,
           "terminal_clean": compare_terminal_clean, "shell_gate": compare_shell_gate,
           "shell_process": compare_shell_process, "shell_background_text": compare_shell_background,
           "shell_outcome": compare_shell_outcome,
           "shell_output_io": compare_shell_output,
           "shell_foreground": compare_shell_foreground,
           "shell_capture_path": compare_shell_capture_path,
           "shell_capture_mkdir": compare_shell_capture_mkdir,
           "shell_capture_file": compare_shell_capture_file,
           "shell_capture_prepare": compare_shell_capture_prepare,
           "request_context": compare_request_context, "response_hints": compare_response_hints,
           "result_publication": compare_result_publication,
           "request_scope_lifecycle": compare_request_scope,
           "line_verify": compare_line_verify, "batch_plan": compare_batch_plan, "batch_apply": compare_batch_apply,
           "batch_edit_params": compare_batch_edit_params,
           "batch_plan_input": compare_batch_plan_input,
           "batch_diff": compare_batch_diff,
           "atomic_write": compare_atomic_write,
           "editable_content": compare_editable_content, "view_render": compare_view_render,
           "view_render_growth": compare_view_render_growth,
           "view_read": compare_view_call_group, "view_params": compare_view_call_group,
           "view_call": compare_view_call_group, "runtime_mcp": compare_runtime_mcp,
           "view_cache": compare_view_cache, "history": compare_history, "session_workdir": compare_session_workdir,
           "file_locks": compare_file_locks, "file_lock_service": compare_file_lock_service,
           "write_chain": compare_write_chain, "directory_service": compare_directory_service,
           "workdir_service": compare_workdir_service, "sdk_connection": compare_sdk_connection,
           "public_registry": compare_public_registry,
           "binary32_json": compare_binary32_json, "typed_result_json": compare_typed_result_json,
           "request_result": compare_request_result,
           "fence_json": compare_fence_json, "serde_json": compare_serde_json, "execution_shadow": compare_execution,
           "effect_fence": compare_effect_fence, "runtime_config": compare_config,
           "runtime_config_span": compare_config_span,
           "operation_scope_os": compare_operation_scope_os,
           "line_endpoint": compare_endpoint, "delta": compare_delta, "binary_codec": compare_codec,
           "policy": compare_policy, "multi_read_service": compare_multi_read,
           "operation_kdf": compare_operation_kdf, "operation_aead": compare_operation_aead,
           "operation_nonce": compare_operation_nonce, "operation_record": compare_operation_record,
           "system_entropy": compare_system_entropy, "operation_scope": compare_operation_scope,
           "caller_authority": compare_caller_authority,
           "filesystem_parity": compare_filesystem_parity,
           "bellman_core": bellman_qualification.compare_original,
           "bellman_commitment": bellman_commitment_qualification.compare_original,
           "local_create_file": local_create_qualification.compare_original,
           "local_create_spec": local_create_spec_qualification.compare_original,
           "filesystem_public": compare_filesystem_public,
           "text_editor_params": text_editor_params_qualification.compare_original}
# Protocol is a new, explicitly limited service. Its original line-hash owner
# is covered by the bytes oracle; parser/lifecycle behavior has direct tests.
NEW_COMPONENTS = {"runtime_protocol"}
# All arithmetic inputs/output bits and native process receipts are checked by
# bellman_qualification.native_evidence in check_input_pins. This independent
# hardware domain is explicit and is not counted as an original Rust recipe.
HARDWARE_REFERENCE_COMPONENTS = {"finite_binary64"}
# These are checked in check_input_pins against the native process evidence and
# original Python source identities. They are not counted as Rust comparisons.
PYTHON_REFERENCE_COMPONENTS = {"native_io", "stat_version", "local_service", "file_info_service"}

RECIPES.update({key: (lambda output, report, rustc, domain=domain:
    compare_result_storage(output, report, rustc, domain)) for key, domain in storage_pipeline.KEYS.items()})


PARALLEL_RUST_RECIPES = {
    "operation_scope_os": ("operation-scope-os-rust.execution.json",
        ("operation-scope-os-rust-compile", "operation-scope-os-rust-compare")),
    "caller_authority": ("caller-authority-rust.execution.json",
        ("caller-authority-rust-format", "caller-authority-rust-compile",
         "caller-authority-rust-compare", "caller-authority-rust-kernel")),
}


SHARED_RUST_PROCESS_RECIPES = {
    "response_hints": "request_context",
    "view_params": "view_read",
    "view_call": "view_read",
}

# These are the existing owners' complete fresh-build/replay wrapper limits.
# Every other original process remains subject to the 180-second ceiling.
RUST_PROCESS_DEADLINES = {
    "shell-process-rust-build": ("shell_process", 900),
    "shell-background-rust-compare": ("shell_background_text", 300),
    "shell-outcome-rust-compare": ("shell_outcome", 300),
    "shell-output-rust-compare": ("shell_output_io", 300),
    "shell-foreground-rust-compare": ("shell_foreground", 300),
    "shell-capture-path-rust-build": ("shell_capture_path", 300),
    "shell-capture-path-rust-compare": ("shell_capture_path", 300),
    "shell-capture-mkdir-rust-build": ("shell_capture_mkdir", 300),
    "shell-capture-mkdir-rust-compare": ("shell_capture_mkdir", 300),
    "shell-capture-file-rust-build": ("shell_capture_file", 300),
    "shell-capture-file-rust-compare": ("shell_capture_file", 300),
    "shell-capture-prepare-rust-build": ("shell_capture_prepare", 300),
    "shell-capture-prepare-rust-compare": ("shell_capture_prepare", 300),
}


RUST_RECIPE_DEPENDENCIES = {"runtime_mcp": ("view_call",),
                            **{key: (owner,) for key, owner in SHARED_RUST_PROCESS_RECIPES.items()},
                            "shell_background_text": ("shell_process",),
                            "shell_outcome": ("shell_process",),
                            "shell_output_io": ("shell_process", "shell_outcome"),
                            "shell_foreground": ("shell_process", "shell_outcome", "shell_output_io")}


def original_process_attribution(report: dict, keys: tuple[str, ...]) -> dict[str, str]:
    """Return each physical process once; declared consumers retain its owner."""
    mapping = report.get("rust_recipe_processes")
    wanted = {key: owner for key, owner in SHARED_RUST_PROCESS_RECIPES.items() if key in keys}
    positions = {key: index for index, key in enumerate(keys)}
    if (type(mapping) is not dict or set(mapping) != set(keys)
            or report.get("rust_recipe_shared_processes") != wanted
            or any(owner not in positions or positions[owner] >= positions[key]
                   for key, owner in wanted.items())):
        raise ValueError("original shared process attribution differs from its declared producer")
    owners = {}
    for key in keys:
        names = mapping[key]
        if (type(names) is not list or not names or any(type(name) is not str or not name for name in names)
                or len(names) != len(set(names))):
            raise ValueError("original recipe omitted its unique actual process records")
        if key == "local_create_file" and names != list(local_create_qualification.PROCESS_NAMES):
            raise ValueError("local-create requires its exact twelve ordered original processes")
        if key == "local_create_spec" and names != list(local_create_spec_qualification.PROCESS_NAMES):
            raise ValueError("complete Local Create requires its exact six ordered original processes")
        if key in wanted:
            if names != mapping[wanted[key]]:
                raise ValueError("shared original recipe does not retain its producer's complete process set")
        else:
            if set(names) & set(owners):
                raise ValueError("original processes are omitted, duplicated or attributed to another recipe")
            owners.update((name, key) for name in names)
    return owners


def rust_recipe_order(report: dict) -> tuple[str, ...]:
    """Use recipe declaration order after a sorted JSON report is reloaded."""
    registered = tuple(item["key"] for item in MODULES)
    selected = report.get("modules")
    if (len(set(registered)) != len(registered) or type(selected) is not dict
            or set(selected) - set(registered) or set(RECIPES) - set(registered)):
        raise ValueError("original recipe module inventory differs from its registered owners")
    if set(selected) - RECIPES.keys() - NEW_COMPONENTS - PYTHON_REFERENCE_COMPONENTS - HARDWARE_REFERENCE_COMPONENTS:
        raise ValueError("selected original module has no registered reference recipe")
    ordered = tuple(key for key in RECIPES if key in selected)
    positions = {key: index for index, key in enumerate(ordered)}
    for consumer, dependencies in RUST_RECIPE_DEPENDENCIES.items():
        if consumer in positions and any(
                producer not in positions or positions[producer] >= positions[consumer]
                for producer in dependencies):
            raise ValueError("original recipe producer must precede its dependent consumer: " + consumer)
    return ordered


def run_rust_recipes(output: Path, report: dict, rustc: Path, *, recipe_keys: tuple[str, ...] | None = None) -> None:
    """Overlap the two independent OS references with private report writers.

    Their Cargo targets, native corpus and raw process files are distinct. JSON
    stays in the main ordered stream and shares its one fresh build. Workers
    receive immutable native evidence snapshots. The caller collects every
    completed check in declaration order, including failures during draining.
    """
    ordered = rust_recipe_order(report)
    keys = ordered if recipe_keys is None else recipe_keys
    if (not keys or len(keys) != len(set(keys)) or set(keys) - set(ordered)
            or keys != tuple(key for key in ordered if key in keys)):
        raise ValueError("original recipe selection is empty, duplicated, undeclared or out of source order")
    positions = {key: index for index, key in enumerate(keys)}
    for consumer, dependencies in RUST_RECIPE_DEPENDENCIES.items():
        if consumer in positions and any(producer not in positions or positions[producer] >= positions[consumer]
                                         for producer in dependencies):
            raise ValueError("original recipe selection omits or reorders its producer: " + consumer)
    selected = {key: value for key, value in PARALLEL_RUST_RECIPES.items() if key in keys}
    if recipe_keys is None and not selected:
        raise ValueError("independent OS reference recipes are missing")
    receipts, futures, collected = {}, {}, set()
    report["rust_parallel_receipts"] = {}
    report["rust_recipe_processes"] = {}
    report["rust_recipe_shared_processes"] = {}
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="hia-original-os") as pool:
        for key, (name, expected) in selected.items():
            private = copy.deepcopy(report)
            original_checks = copy.deepcopy(private["checks"])
            path = output / name
            receipts[key] = (private, original_checks, path, expected)
            futures[key] = pool.submit(RECIPES[key], output, private, rustc, report_path=path)
        def collect(key):
            private, original_checks, path, expected = receipts[key]
            result, failure = None, None
            try:
                result = futures[key].result()
            except Exception as error:
                failure = error
            if private["checks"][:len(original_checks)] != original_checks:
                raise ValueError("independent original reference modified native process evidence")
            checks = private["checks"][len(original_checks):]
            names = [row["name"] for row in checks]
            if (not checks or names != list(expected[:len(checks)]) or len(checks) > len(expected)
                    or any(name in {row["name"] for row in report["checks"]} for name in names)
                    or json.loads(path.read_bytes()) != private):
                raise ValueError("independent original reference process receipts differ: " + key)
            report["checks"].extend(checks)
            report["rust_recipe_processes"][key] = names
            if failure is None:
                if (len(checks) != len(expected)
                        or any(row["exit_code"] != 0 or row["timed_out"] is not False for row in checks)):
                    raise ValueError("independent original reference did not complete: " + key)
                report["original_rust_comparisons"][key] = result
            report["rust_parallel_receipts"][path.name] = sha(path)
            collected.add(key)
            save_report(output / "result.json", report)
            return failure
        try:
            for key in keys:
                if key in futures:
                    failure = collect(key)
                    if failure is not None:
                        raise failure
                else:
                    before = copy.deepcopy(report["checks"])
                    first = len(report["checks"])
                    owner = SHARED_RUST_PROCESS_RECIPES.get(key)
                    if owner is not None and (owner not in report["original_rust_comparisons"]
                                              or owner not in report["rust_recipe_processes"]):
                        raise ValueError("shared original recipe has no completed producer: " + key)
                    try:
                        report["original_rust_comparisons"][key] = RECIPES[key](output, report, rustc)
                    finally:
                        if report["checks"][:first] != before:
                            raise ValueError("original recipe changed a completed process record: " + key)
                        rows = report["checks"][first:]
                        names = [row["name"] for row in rows]
                        if owner is not None:
                            if names:
                                raise ValueError("shared original recipe invented a second execution: " + key)
                            names = list(report["rust_recipe_processes"][owner])
                            report["rust_recipe_shared_processes"][key] = owner
                        elif (not names or len(names) != len(set(names))
                              or set(names) & {row["name"] for row in before}):
                            raise ValueError("original recipe did not retain unique actual process records: " + key)
                        report["rust_recipe_processes"][key] = names
                        save_report(output / "result.json", report)
            original_process_attribution(report, keys)
        finally:
            for key in futures:
                if key not in collected:
                    try:
                        failure = collect(key)
                        if failure is not None:
                            report.setdefault("rust_parallel_drain_errors", []).append(
                                {"name": key, "type": type(failure).__name__, "message": str(failure)})
                    except Exception as error:
                        report.setdefault("rust_parallel_drain_errors", []).append(
                            {"name": key, "type": type(error).__name__, "message": str(error)})
            save_report(output / "result.json", report)


def run(output: Path, rustc_name: str) -> dict:
    report_path = output / "result.json"
    report = json.loads(report_path.read_bytes())
    if (report.get("schema") != "hepta.runtime.hia-native-qualification.v1"
            or report.get("status") != "NATIVE_COMPONENTS_PASS"
            or report.get("native_components_status") != "PASS"
            or report.get("rust_comparison_status") != "PENDING"):
        raise ValueError("only a completed native phase with a pending Rust comparison can advance")
    started = time.monotonic()
    report.update({"status": "RUNNING", "phase": "original_rust_comparison",
                   "rust_comparison_status": "RUNNING", "original_rust_comparisons": {}})
    save_report(report_path, report)
    try:
        if set(report["modules"]) != {item["key"] for item in MODULES}:
            raise ValueError("completed native phase module inventory differs")
        check_input_pins(output, report)
        unknown = set(report["modules"]) - RECIPES.keys() - NEW_COMPONENTS - PYTHON_REFERENCE_COMPONENTS - HARDWARE_REFERENCE_COMPONENTS
        if unknown:
            raise ValueError("missing original reference recipe: " + ", ".join(sorted(unknown)))
        rustc = executable(rustc_name)
        compiler_sha = sha(rustc)
        version = record_check(output, report, name="original-rust-compiler-version",
                               command=[str(rustc), "--version", "--verbose"], timeout=15)
        report["rust_compiler"] = {"invocation_path": str(rustc), "resolved_path": str(rustc.resolve()),
                                   "invocation_executable_sha256": compiler_sha,
                                   "version": version.stdout.decode("utf-8")}
        run_rust_recipes(output, report, rustc)
        if set(report["original_rust_comparisons"]) != RECIPES.keys():
            raise ValueError("not all required Rust reference recipes completed")
        report["service_original_fixture_retirement"] = service_pipeline.original_fixture_transport(
            ROOT, output, report, rustc, completed_test_summary, create=True)
        check_input_pins(output, report)
        run_result_values_controls(output, report)
        run_public_registry_controls(output, report)
        run_result_storage_controls(output, report)
        check_input_pins(output, report)
        if sha(rustc) != compiler_sha:
            raise ValueError("original Rust compiler executable changed during comparison")
        report["rust_comparison_status"] = "PASS"
        report["status"] = "PASS"
        report["phase"] = "complete"
    except BaseException as exc:
        report["status"] = "FAIL"
        report["rust_comparison_status"] = "FAIL"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        (output / "rust-comparison-failure.txt").write_text(traceback.format_exc())
    report["rust_comparison_elapsed_seconds"] = time.monotonic() - started
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    save_report(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="completed native-phase directory")
    parser.add_argument("--rustc", default="rustc", help="Rust compiler executable; CI supplies its pinned path")
    args = parser.parse_args()
    result = run(args.output.resolve(strict=True), args.rustc)
    summary = {"status": result["status"], "rust_comparison_status": result["rust_comparison_status"],
               "compiler_cold_status": result.get("compiler_cold_status"),
               "retained_python_comparison_status": result.get("retained_python_comparison_status"),
               "report": str(args.output.resolve() / "result.json"),
               "check_processes": len(result["checks"]), "whole_runtime_replaced": False}
    if result["status"] != "PASS":
        summary["error"] = result.get("error")
        summary["failed_processes"] = [
            {key: row.get(key) for key in ("name", "exit_code", "timed_out", "start_error",
                                          "elapsed_seconds", "timeout_seconds")}
            for row in result["checks"]
            if row.get("exit_code") != 0 or row.get("timed_out") is not False or row.get("start_error")]
    print(json.dumps(summary, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
