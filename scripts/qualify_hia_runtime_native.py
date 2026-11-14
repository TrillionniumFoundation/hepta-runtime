"""Build and test the declared HIA runtime profile from pinned source bytes.

NATIVE_COMPONENTS_PASS records the fresh full compiler cold gate, native tests
and their retained Python comparisons. Aggregate PASS also requires all eight
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
    {"key": "delta", "name": "delta", "source": "native/delta.hepta",
     "standalone": "filter", "manifest_env": "HIA_DELTA_MANIFEST", "test": "test_delta.py"},
    {"key": "binary_codec", "name": "binary-codec", "source": "native/binary_codec.hepta",
     "standalone": "filter", "manifest_env": "HIA_CODEC_MANIFEST", "test": "test_binary_codec.py"},
    {"key": "operation_kdf", "name": "operation-kdf", "source": "native/operation_kdf.hepta",
     "standalone": "filter", "manifest_env": "HIA_KDF_MANIFEST", "test": "test_operation_kdf.py"},
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
    {"key": "local_service", "name": "local-service", "source": "native/local_service.hepta",
     "companion_sources": ("native/composition_packer.hepta",), "builder": "composition",
     "manifest_env": "HIA_SERVICE_MANIFEST", "test": "test_local_service.py",
     "additional_tests": ("test_multi_service.py",)},
)
PACKERS = {"native/filter_packer.hepta", "native/stdio_packer.hepta"}
EXTRA_TESTS = ("test_transport.py", "test_native_composition.py", "test_qualification_reporting.py")
RUST_CORPUS_FILES = ("native-corpus.json", "input.bin.gz", "native-output.bin.gz")


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
        "hia_native_io_build.py", "hia_native_composition_build.py", "hia_native_cold.py",
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
              "protocol_errors": 20, "domain_errors": 21, "native_controller_calls": 8}
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
            "controller_startup_acknowledgement": "two explicit lifecycle fixture acknowledgements; no file operation",
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
    specs = (("local-service", "native/local_service.hepta", 1, 62, 32 << 20),
             ("policy", "native/policy.hepta", 0, 0, 32 << 20),
             ("codec", "native/binary_codec.hepta", 0, 0, 32 << 20),
             ("io", "native/io_policy.hepta", 2, 0, 86016),
             ("stat-version", "native/stat_version.hepta", 0, 0, 32 << 20),
             ("multi-read-service", "native/multi_read_service.hepta", 1, 30, 32 << 20))
    profile = [{"id": index, "name": name, "source_sha256": sha(ROOT / source),
                "flags": flags, "call_mask": mask, "input_capacity": 8 << 20,
                "output_capacity": 8 << 20, "workspace_capacity": workspace}
               for index, (name, source, flags, mask, workspace) in enumerate(specs)]
    if (json_bytes(metadata.get("profile")) != json_bytes(profile) or type(metadata.get("members")) is not list
            or len(metadata["members"]) != len(specs)):
        raise ValueError("native composition fixed six-image authority table differs")
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
            tested_key = (None, "policy", "binary_codec", "native_io", "stat_version", "multi_read_service")[index - 1]
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
        "scope": "native kernels, closed six-image local MCP read profile, and Linux x86-64 stdio/read-only dependencies",
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
        env = qualification_env()
        env.update({
            "HIA_HEPTA_DIR": str(hepta), "HIA_BUILD_ROOT": str(output / "build"),
            "HIA_BYTES_CORPUS_DIR": str(output / "rust-oracle"), "PYTHONDONTWRITEBYTECODE": "1",
            "HIA_TEXT_CORPUS_DIR": str(output / "text-rust-oracle"),
            "HIA_ENDPOINT_CORPUS_DIR": str(output / "endpoint-rust-oracle"),
            "HIA_DELTA_CORPUS_DIR": str(output / "delta-rust-oracle"),
            "HIA_CODEC_CORPUS_DIR": str(output / "codec-rust-oracle"),
            "HIA_KDF_CORPUS_DIR": str(output / "operation-kdf-rust-oracle"),
            "HIA_POLICY_CORPUS_DIR": str(output / "policy-rust-oracle"),
            "HIA_STAT_VERSION_CORPUS_DIR": str(output / "stat-version-python-reference"),
            "HIA_SERVICE_RESULT": str(output / "local-service-python-reference.json"),
            "HIA_MULTI_SERVICE_RESULT": str(output / "multi-service-python-reference.json"),
            "HIA_MULTI_READ_CORPUS_DIR": str(output / "multi-read-rust-oracle"),
            "HIA_REFERENCE_RUNTIME": str(ROOT),
        })
        for item in MODULES:
            if item.get("builder") == "io":
                from hia_native_io_build import build_io
                built = build_io(hepta, output / "build")
            elif item.get("builder") == "composition":
                from hia_native_composition_build import build_local_read
                built = build_local_read(hepta, output / "build")
                env["HIA_COMPOSITION_MANIFEST"] = str(built)
            else:
                built = builder.compile(item["name"], ROOT / item["source"], standalone=item["standalone"])
            report["modules"][item["key"]] = {
                "manifest": str(built.relative_to(output)), "sha256": sha(built), "source": item["source"],
                "builder": item.get("builder", "borrowed_bytes")}
            env[item["manifest_env"]] = str(built)
        tests = tuple(dict.fromkeys(name for item in MODULES
                                    for name in (item["test"], *item.get("additional_tests", ())))) + EXTRA_TESTS
        for name in tests:
            record_check(output, report, name=name,
                         command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name)],
                         env=env, timeout=180)
        report["original_python_comparisons"] = python_reference_evidence(output, report)
        report["native_composition_evidence"] = native_composition_evidence(output, report)
        report["multi_read_controller_evidence"] = multi_read_controller_evidence(output, report)
        report["operation_kdf_evidence"] = operation_kdf_evidence(output, report)
        report["retained_python_comparison_status"] = "PASS"
        report["python_reference_inputs"] = {
            "stat-version-python-reference/" + name: sha(output / "stat-version-python-reference" / name)
            for name in ("native-corpus.json", "stat-version-cases.jsonl.gz")}
        report["python_reference_inputs"]["local-service-python-reference.json"] = sha(
            output / "local-service-python-reference.json")
        report["python_reference_inputs"]["multi-service-python-reference.json"] = sha(
            output / "multi-service-python-reference.json")
        report["rust_oracle_inputs"] = {
            "rust-oracle/" + name: sha(output / "rust-oracle" / name) for name in RUST_CORPUS_FILES}
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
