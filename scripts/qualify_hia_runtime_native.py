"""Build and test the declared HIA runtime profile from pinned source bytes.

NATIVE_COMPONENTS_PASS records the fresh full compiler cold gate, native tests
and their retained Python comparisons. Aggregate PASS also requires all six
independent Rust comparisons. Neither phase qualifies the remaining 125
production tool owners, production adoption, or removal of the old runtime.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_hia_native_inventory import ORIGINAL_RUNTIME_BLOBS, inspect
from hia_native_build import NativeBuild, HEPTA_COMMIT, HEPTA_TREE
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
    {"key": "policy", "name": "policy", "source": "native/policy.hepta",
     "standalone": "filter", "manifest_env": "HIA_POLICY_MANIFEST", "test": "test_policy.py"},
    {"key": "native_io", "name": "native-io", "source": "native/io_policy.hepta",
     "companion_sources": ("native/io_packer.hepta",), "builder": "io",
     "manifest_env": "HIA_IO_MANIFEST", "test": "test_native_io.py"},
)
PACKERS = {"native/filter_packer.hepta", "native/stdio_packer.hepta"}
EXTRA_TESTS = ("test_transport.py", "test_qualification_reporting.py")
RUST_CORPUS_FILES = ("native-corpus.json", "input.bin.gz", "native-output.bin.gz")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources() -> dict:
    paths = set((ROOT / "native").rglob("*"))
    paths.update((ROOT / "tests/hia_native").rglob("*"))
    paths.update(ROOT / "scripts" / name for name in (
        "hia_native_build.py", "hia_native_loader.py", "generate_hia_transport.py",
        "hia_native_io_build.py", "hia_native_cold.py",
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
    if counts != {"elf_requests": 113, "original_read_comparisons": 8}:
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
        "scope": "native pure kernels, MCP protocol subset, and Linux x86-64 stdio/read-only descriptor dependencies",
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
        env = dict(os.environ)
        env.update({
            "HIA_HEPTA_DIR": str(hepta), "HIA_BUILD_ROOT": str(output / "build"),
            "HIA_BYTES_CORPUS_DIR": str(output / "rust-oracle"), "PYTHONDONTWRITEBYTECODE": "1",
            "HIA_TEXT_CORPUS_DIR": str(output / "text-rust-oracle"),
            "HIA_ENDPOINT_CORPUS_DIR": str(output / "endpoint-rust-oracle"),
            "HIA_DELTA_CORPUS_DIR": str(output / "delta-rust-oracle"),
            "HIA_CODEC_CORPUS_DIR": str(output / "codec-rust-oracle"),
            "HIA_POLICY_CORPUS_DIR": str(output / "policy-rust-oracle"),
            "HIA_REFERENCE_RUNTIME": str(ROOT),
        })
        for item in MODULES:
            if item.get("builder") == "io":
                from hia_native_io_build import build_io
                built = build_io(hepta, output / "build")
            else:
                built = builder.compile(item["name"], ROOT / item["source"], standalone=item["standalone"])
            report["modules"][item["key"]] = {
                "manifest": str(built.relative_to(output)), "sha256": sha(built), "source": item["source"],
                "builder": item.get("builder", "borrowed_bytes")}
            env[item["manifest_env"]] = str(built)
        tests = tuple(dict.fromkeys(item["test"] for item in MODULES)) + EXTRA_TESTS
        for name in tests:
            record_check(output, report, name=name,
                         command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name)],
                         env=env, timeout=180)
        report["original_python_comparisons"] = {"native_io": io_reference_evidence(output, report)}
        report["retained_python_comparison_status"] = "PASS"
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
