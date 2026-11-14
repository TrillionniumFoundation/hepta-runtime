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
import signal
import struct
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_hia_native_inventory import ORIGINAL_RUNTIME_BLOBS, inspect
from hia_native_build import NativeBuild, HEPTA_COMMIT, HEPTA_TREE, json_bytes
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
from hia_native_view_cache_qualification import (FOLDER as CACHE_FOLDER,
                                                qualification_evidence as checked_view_cache_evidence)
from hia_native_scope_os_qualification import (FOLDER as SCOPE_OS_FOLDER, SUITES as SCOPE_OS_SUITES,
                                              exact_profile as scope_os_profile,
                                              write_corpus as capture_scope_os_corpus,
                                              native_evidence as checked_scope_os_evidence)

# Every native owner needs an executable qualification entry. Transport tests
# cover the two packers that NativeBuild compiles internally.
MODULES = (
    {"key": "runtime_bytes", "name": "runtime-bytes", "source": "native/runtime_bytes.hepta",
     "standalone": "filter", "manifest_env": "HIA_BYTES_MANIFEST", "test": "test_runtime_bytes.py"},
    {"key": "runtime_protocol", "name": "runtime-protocol", "source": "native/runtime_protocol.hepta",
     "standalone": "stdio", "manifest_env": "HIA_PROTOCOL_MANIFEST", "test": "test_runtime_protocol.py"},
    {"key": "text_budget", "name": "text-budget", "source": "native/text_budget.hepta",
     "standalone": "filter", "manifest_env": "HIA_TEXT_MANIFEST", "test": "test_text_budget.py"},
    {"key": "line_endpoint", "name": "line-endpoint", "source": "native/line_endpoint.hepta",
     "standalone": None, "manifest_env": "HIA_ENDPOINT_MANIFEST", "test": "test_line_endpoint.py"},
    {"key": "line_verify", "name": "line-verify", "source": "native/line_verify.hepta",
     "standalone": "filter", "manifest_env": "HIA_LINE_VERIFY_MANIFEST", "test": "test_line_verify.py"},
    {"key": "delta", "name": "delta", "source": "native/delta.hepta",
     "standalone": "filter", "manifest_env": "HIA_DELTA_MANIFEST", "test": "test_delta.py"},
    {"key": "editable_content", "name": "editable-content", "source": "native/editable_content.hepta",
     "standalone": "filter", "manifest_env": "HIA_EDITABLE_MANIFEST", "test": "test_editable_content.py"},
    {"key": "view_render", "name": "view-render", "source": "native/view_render.hepta",
     "standalone": "filter", "buffer_profile": "view-render.v1",
     "companion_sources": ("native/view_filter_packer.hepta",),
     "manifest_env": "HIA_VIEW_MANIFEST", "test": "test_view_render.py",
     "additional_tests": ("test_view_transport.py",)},
    {"key": "view_cache", "name": "view-cache", "source": "native/view_cache.hepta",
     "standalone": None, "manifest_env": "HIA_CACHE_MANIFEST", "test": "test_view_cache.py",
     "additional_tests": ("test_view_cache_evidence.py",)},
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
EXTRA_TESTS = ("test_transport.py", "test_native_composition.py", "test_qualification_reporting.py")
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
        "hia_native_io_build.py", "hia_native_composition_build.py", "hia_native_record_build.py", "hia_native_cold.py",
        "hia_native_entropy_build.py", "hia_native_entropy_qualification.py",
        "hia_native_scope_build.py", "hia_native_scope_qualification.py",
        "hia_native_editable_qualification.py", "hia_native_view_qualification.py",
        "hia_native_view_cache_build.py", "hia_native_view_cache_qualification.py",
        "hia_native_line_verify_qualification.py",
        "hia_native_scope_os_build.py", "hia_native_scope_os_qualification.py",
        "check_hia_native_inventory.py", "qualify_hia_runtime_native.py", "compare_hia_runtime_rust.py"))
    paths.update((ROOT / "src/mcp/server.rs", ROOT / "src/utils/line_hash.rs", ROOT / "src/utils/truncation.rs",
                  ROOT / ".github/workflows/hia-runtime-native.yml"))
    paths.update(ROOT / name for name in ORIGINAL_RUNTIME_BLOBS)
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


def record_check(output: Path, report: dict, *, name: str, command: list[str],
                 timeout: float, env: dict | None = None,
                 input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    """Retain completed, refused and timed-out checks before propagating failure."""
    started = time.monotonic()
    stdout, stderr = b"", b""
    code, start_error = None, None
    timed_out = False
    try:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            stdout, stderr = process.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            # Kill only this new process group, including inherited output pipes.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
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
    if start_error:
        check["start_error"] = start_error
    try:
        check["summary"] = json.loads(stdout)
    except (ValueError, UnicodeDecodeError):
        pass
    report["checks"].append(check)
    save_report(output / "result.json", report)
    if start_error or timed_out or code != 0:
        reason = "timed out" if timed_out else "could not start" if start_error else "failed"
        raise RuntimeError(name + " " + reason + "; original stdout/stderr retained")
    return subprocess.CompletedProcess(command, code, stdout, stderr)


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
    summary = json.loads(stdout)
    if (check["exit_code"] != 0 or check["timed_out"] is not False or check.get("start_error")
            or hashlib.sha256(stdout).hexdigest() != check["stdout_sha256"]
            or hashlib.sha256(stderr).hexdigest() != check["stderr_sha256"]
            or summary != check.get("summary")):
        raise ValueError(name + " test execution evidence differs")
    return check, summary


def entropy_evidence(output: Path, report: dict) -> dict:
    return checked_entropy_evidence(ROOT, output, report, completed_test_summary)


def operation_scope_evidence(output: Path, report: dict) -> dict:
    return checked_scope_evidence(ROOT, output, report, completed_test_summary)


def editable_content_evidence(output: Path, report: dict) -> dict:
    return checked_editable_evidence(ROOT, output, report, completed_test_summary)


def line_verify_evidence(output: Path, report: dict) -> dict:
    return checked_line_verify_evidence(ROOT, output, report, completed_test_summary)


def view_render_evidence(output: Path, report: dict) -> dict:
    return checked_view_evidence(ROOT, output, report, completed_test_summary)


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


def run(output: Path, hepta: Path) -> dict:
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    report_path = output / "result.json"
    started = time.monotonic()
    report = {
        "schema": "hepta.runtime.hia-native-qualification.v1",
        "status": "RUNNING", "phase": "compiler_cold",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "checkout_head": None, "source_identity_authority": "source_sha256", "source_sha256": {},
        "compiler_commit": HEPTA_COMMIT, "compiler_tree": HEPTA_TREE,
        "scope": "native kernels, closed seven-image local MCP read profile, and Linux x86-64 stdio/read-only dependencies",
        "whole_runtime_replaced": False, "production_activated": False,
        "old_stack_removal_qualified": False, "matching_source_full_cold_qualified": False,
        "compiler_cold_status": "PENDING", "native_components_status": "RUNNING",
        "retained_python_comparison_status": "PENDING", "rust_comparison_status": "PENDING", "checks": [],
    }
    save_report(report_path, report)
    try:
        manifest = sources()
        report["source_sha256"] = manifest
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
        env = qualification_env()
        env.update({
            "HIA_HEPTA_DIR": str(hepta), "HIA_BUILD_ROOT": str(output / "build"),
            "HIA_BYTES_CORPUS_DIR": str(output / "rust-oracle"), "PYTHONDONTWRITEBYTECODE": "1",
            "HIA_TEXT_CORPUS_DIR": str(output / "text-rust-oracle"),
            "HIA_ENDPOINT_CORPUS_DIR": str(output / "endpoint-rust-oracle"),
            "HIA_DELTA_CORPUS_DIR": str(output / "delta-rust-oracle"),
            "HIA_EDITABLE_CORPUS_DIR": str(output / EDITABLE_FOLDER),
            "HIA_LINE_VERIFY_CORPUS_DIR": str(output / LINE_VERIFY_FOLDER),
            "HIA_VIEW_CORPUS_DIR": str(output / VIEW_FOLDER),
            "HIA_CACHE_CORPUS_DIR": str(output / CACHE_FOLDER),
            "HIA_CACHE_QUALIFICATION_OUTPUT": str(output),
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
        })
        env.update({variable: str(output / SCOPE_OS_FOLDER / receipt)
                    for _, variable, receipt, _, _ in SCOPE_OS_SUITES})
        for item in MODULES:
            if item.get("builder") == "io":
                from hia_native_io_build import build_io
                built = build_io(hepta, output / "build")
            elif item.get("builder") == "composition":
                from hia_native_composition_build import build_local_read
                built = build_local_read(hepta, output / "build")
                env["HIA_COMPOSITION_MANIFEST"] = str(built)
            elif item.get("builder") == "record_composition":
                from hia_native_record_build import build_record
                built = build_record(hepta, output / "build")
            elif item.get("builder") == "entropy":
                from hia_native_entropy_build import build_entropy
                built = build_entropy(hepta, output / "build")
            elif item.get("builder") == "scope_composition":
                from hia_native_scope_build import build_scope
                built = build_scope(hepta, output / "build")
            elif item.get("builder") == "scope_os_composition":
                from hia_native_scope_os_build import build_scope_os
                built = build_scope_os(hepta, output / "build")
            else:
                built = builder.compile(item["name"], ROOT / item["source"], standalone=item["standalone"],
                                        buffer_profile=item.get("buffer_profile", "standard"))
            report["modules"][item["key"]] = {
                "manifest": str(built.relative_to(output)), "sha256": sha(built), "source": item["source"],
                "builder": item.get("builder", "borrowed_bytes")}
            env[item["manifest_env"]] = str(built)
        from hia_native_composition_build import ModuleSpec, build_composition
        nonce_fixture = build_composition(hepta, output / "build", [
            ModuleSpec("nonce-hex-fixture", ROOT / "tests/hia_native/nonce_hex_transport.hepta",
                       flags=1, call_mask=2, workspace_capacity=16 << 20),
            ModuleSpec("operation-nonce", ROOT / "native/operation_nonce.hepta",
                       input_capacity=164, output_capacity=64, workspace_capacity=1576960),
        ])
        report["nonce_composition"] = {"manifest": str(nonce_fixture.relative_to(output)),
                                        "sha256": sha(nonce_fixture), "builder": "composition_fixture"}
        env["HIA_NONCE_COMPOSITION_MANIFEST"] = str(nonce_fixture)
        from hia_native_view_cache_build import build_cache
        cache_fixture = build_cache(hepta, output / "build")
        report["cache_composition"] = {"manifest": str(cache_fixture.relative_to(output)),
                                       "sha256": sha(cache_fixture), "builder": "composition_fixture"}
        env["HIA_CACHE_ELF_MANIFEST"] = str(cache_fixture)
        tests = tuple(dict.fromkeys(name for item in MODULES
                                    for name in (item["test"], *item.get("additional_tests", ())))) + EXTRA_TESTS
        for name in tests:
            record_check(output, report, name=name,
                         command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name)],
                         env=env, timeout=180)
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
        report["view_render_evidence"] = view_render_evidence(output, report)
        report["view_cache_evidence"] = view_cache_evidence(output, report)
        scope_os_manifest = output / report["modules"]["operation_scope_os"]["manifest"]
        capture_scope_os_corpus(ROOT, output / SCOPE_OS_FOLDER, scope_os_profile(ROOT, scope_os_manifest))
        report["operation_scope_os_evidence"] = operation_scope_os_evidence(output, report)
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
        builder.bootstrap()  # Revalidate the same compiler image after all tests.
        builder._recheck()
        if sources() != manifest:
            raise RuntimeError("native source/test/inventory inputs changed during qualification")
        report["native_components_status"] = "PASS"
        report["status"] = "NATIVE_COMPONENTS_PASS"
        report["phase"] = "awaiting_original_rust_comparison"
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
