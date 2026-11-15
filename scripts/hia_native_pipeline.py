"""Run the complete native gate across source-bound, independently retained jobs.

One fresh cold/build artifact is admitted by its workflow-produced SHA256. Six
explicit partitions execute every registered suite once. Collection rechecks all
raw process bytes, immutable build inputs and complete shard inventories before
the unchanged evidence owners can advance to the original Rust comparisons.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qualify_hia_runtime_native as q

PARTITIONS = {
    "batch": ("batch_plan", "batch_apply", "atomic_write"),
    "text": ("runtime_bytes", "runtime_protocol", "text_budget", "terminal_clean", "shell_gate", "request_context", "response_hints", "result_publication", "request_scope_lifecycle",
             "line_endpoint", "line_verify",
             "delta", "editable_content", "file_locks", "file_lock_service"),
    "view": ("view_render", "view_render_growth", "view_read", "view_params", "view_call",
             "runtime_mcp", "view_cache", "history", "session_workdir"),
    "json": ("fence_json", "serde_json", "execution_shadow", "effect_fence"),
    "config": ("runtime_config", "runtime_config_span"),
    "system": ("filesystem_parity", "binary_codec", "operation_kdf", "operation_aead", "operation_nonce", "operation_record",
               "system_entropy", "operation_scope", "operation_scope_os", "caller_authority", "policy",
               "stat_version", "native_io", "multi_read_service", "file_info_service", "local_service"),
}
BUILD_SEAL = "native-build.json"
BUILD_REPORT = "prepared-report.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path: Path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON field: " + key)
            value[key] = item
        return value
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def relative_path(name: str) -> Path:
    if (type(name) is not str or not name or "\\" in name or "\x00" in name
            or PurePosixPath(name).is_absolute() or any(p in {"", ".", ".."} for p in name.split("/"))):
        raise ValueError("artifact path is not an owned relative path")
    return Path(name)


def owned(root: Path, name: str) -> Path:
    path = root / relative_path(name)
    if root.is_symlink() or path.resolve() != path.absolute():
        raise ValueError("artifact path crosses a symlink")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("artifact is not an owned regular file")
    return path


def file_identity(path: Path) -> dict:
    info = path.stat()
    return {"sha256": digest(path), "bytes": info.st_size, "mode": stat.S_IMODE(info.st_mode)}


def inventory(root: Path, exclude=()) -> tuple[dict, list[str]]:
    if root.is_symlink() or root.resolve(strict=True) != root.absolute():
        raise ValueError("artifact root must be an owned real directory")
    files, directories = {}, []
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        for name in dirs:
            path = Path(base) / name
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("artifact directory is not owned or crosses a symlink")
            directories.append(path.relative_to(root).as_posix())
        for name in sorted(names):
            path = Path(base) / name
            relative = path.relative_to(root).as_posix()
            owned(root, relative)
            if relative not in exclude:
                files[relative] = file_identity(path)
    return files, directories


def verify_directories(root: Path, names: list[str], *, restore: bool = False) -> None:
    """Keep actual empty evidence directories through ZIP artifact transport."""
    if type(names) is not list or any(type(name) is not str for name in names) or len(names) != len(set(names)):
        raise ValueError("native shard directory inventory differs")
    if root.is_symlink() or root.resolve(strict=True) != root.absolute():
        raise ValueError("native shard directory root crosses a symlink")
    for name in sorted(names, key=lambda value: (value.count("/"), value)):
        path = root / relative_path(name)
        if path.is_symlink() or path.resolve() != path.absolute():
            raise ValueError("native shard directory crosses a symlink")
        if restore:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("native shard directory is not owned")


def verify_files(root: Path, files: dict, *, restore_modes: bool = False) -> None:
    if type(files) is not dict or not files:
        raise ValueError("artifact file inventory is empty")
    for name, expected in files.items():
        if (type(expected) is not dict or set(expected) != {"sha256", "bytes", "mode"}
                or type(expected["sha256"]) is not str or not SHA256.fullmatch(expected["sha256"])
                or type(expected["bytes"]) is not int or expected["bytes"] < 0
                or type(expected["mode"]) is not int or not 0 <= expected["mode"] <= 0o777):
            raise ValueError("artifact identity or ordinary permission bits differ")
        path = owned(root, name)
        if path.stat().st_size != expected["bytes"] or digest(path) != expected["sha256"]:
            raise ValueError("retained artifact bytes differ: " + name)
    # Artifact ZIP transport drops executable bits. Restore only verified owned
    # regular files, after every byte identity passed, and never special bits.
    for name, expected in files.items():
        path = owned(root, name)
        if restore_modes:
            path.chmod(expected["mode"])
        elif stat.S_IMODE(path.stat().st_mode) != expected["mode"]:
            raise ValueError("retained artifact permissions differ: " + name)


def partition_tests(partitions=None) -> dict[str, tuple[str, ...]]:
    partitions = PARTITIONS if partitions is None else partitions
    modules = {item["key"]: item for item in q.MODULES}
    flat = [key for keys in partitions.values() for key in keys]
    if set(partitions) != {"batch", "text", "view", "json", "config", "system"} or len(flat) != len(set(flat)) or set(flat) != set(modules):
        raise ValueError("every native module must belong to exactly one explicit partition")
    result = {group: tuple(name for key in keys for name in
                         (modules[key]["test"], *modules[key].get("additional_tests", ())))
              for group, keys in partitions.items()}
    result["text"] += q.EXTRA_TESTS
    tests = [name for names in result.values() for name in names]
    if len(tests) != len(set(tests)) or set(tests) != set(q.native_tests()):
        raise ValueError("every native executable suite must execute exactly once")
    for ordered in q.ORDERED_INDEPENDENT_SUITES:
        if not any(all(name in names for name in ordered) for names in result.values()):
            raise ValueError("an ordered native evidence dependency crosses partitions")
    ordered_locks = q.file_lock_pipeline.ORDERED_SUITES
    if not any(all(name in names for name in ordered_locks)
               and [names.index(name) for name in ordered_locks] == sorted(names.index(name) for name in ordered_locks)
               for names in result.values()):
        raise ValueError("file-lock state, service and evidence dependencies must stay ordered in one partition")
    return result


def context(output: Path, hepta: Path, invocation: str) -> dict:
    if type(invocation) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", invocation):
        raise ValueError("workflow invocation identity is missing or malformed")
    return {"invocation": invocation, "source": str(q.ROOT), "output": str(output),
            "compiler": str(hepta), "python": sys.executable, "checkout_head": q.git_head()}


def validate_check(root: Path, row: dict, name: str, command: list[str], timeout: int, phase: str) -> None:
    elapsed = row.get("elapsed_seconds")
    if (row.get("name") != name or row.get("command") != command or row.get("phase") != phase
            or type(row.get("exit_code")) is not int or row["exit_code"] != 0
            or row.get("timed_out") is not False or row.get("start_error")
            or type(row.get("timeout_seconds")) is not int or row["timeout_seconds"] != timeout
            or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0):
        raise ValueError("native process is incomplete or its exact invocation/deadline differs: " + name)
    for suffix in ("stdout", "stderr"):
        path = owned(root, name + "." + suffix)
        if (type(row.get(suffix + "_bytes")) is not int or path.stat().st_size != row[suffix + "_bytes"]
                or digest(path) != row.get(suffix + "_sha256")):
            raise ValueError("actual native process output bytes differ: " + name)
    try:
        summary = q.process_summary(name, (root / (name + ".stdout")).read_bytes())
    except (ValueError, UnicodeDecodeError):
        if "summary" in row:
            raise ValueError("native process has an invented parsed summary")
    else:
        if q.json_bytes(summary) != q.json_bytes(row.get("summary")):
            raise ValueError("native process summary differs from actual stdout")


def validate_cold_process(output: Path, report: dict, hepta: Path) -> None:
    rows = report.get("checks", [])
    if len(rows) != 1:
        raise ValueError("prepared build must retain exactly one fresh full cold process")
    validate_check(output, rows[0], "compiler-full-cold",
                   [sys.executable, "-I", "-B", str(hepta / "tools/replay_hia_selfhost_cold.py"),
                    "--output", str(output / "compiler-cold.json")], 240, "compiler_cold")


def admit_prepared(output: Path, hepta: Path, expected: str, invocation: str, *, exact: bool = True):
    if type(expected) is not str or not SHA256.fullmatch(expected) or digest(owned(output, BUILD_SEAL)) != expected:
        raise ValueError("prepared artifact differs from the fresh workflow build SHA256")
    seal = read_json(output / BUILD_SEAL)
    if (set(seal) != {"schema", "context", "files", "directories", "partitions"}
            or seal["schema"] != "hepta.runtime.native-build.v1"
            or seal["context"] != context(output, hepta, invocation)
            or seal["partitions"] != {k: list(v) for k, v in partition_tests().items()}):
        raise ValueError("prepared artifact source, invocation, location or partition registry differs")
    verify_files(output, seal["files"], restore_modes=exact)
    if type(seal["directories"]) is not list or len(set(seal["directories"])) != len(seal["directories"]):
        raise ValueError("prepared artifact directory inventory differs")
    for name in seal["directories"]:
        path = output / relative_path(name)
        if path.resolve() != path.absolute() or path.is_symlink():
            raise ValueError("prepared directory crosses a symlink")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if exact:
        files, directories = inventory(output, {BUILD_SEAL, "result.json"})
        if files != seal["files"] or set(directories) != set(seal["directories"]):
            raise ValueError("prepared artifact has omitted or undeclared files")
    report = read_json(owned(output, BUILD_REPORT))
    if (report.get("status") != "NATIVE_BUILD_READY" or report.get("phase") != "native_build_complete"
            or report.get("native_components_status") != "PENDING"
            or report.get("rust_comparison_status") != "PENDING"
            or report.get("retained_python_comparison_status") != "PENDING"
            or report.get("source_sha256") != q.sources() or report.get("checkout_head") != q.git_head()
            or report.get("compiler_checkout") != str(hepta)
            or any(report.get(k) is not False for k in
                   ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified"))):
        raise ValueError("prepared report is not an exact-source unqualified native build")
    if report.get("inventory") != q.inspect(q.ROOT) or set(report.get("modules", {})) != {m["key"] for m in q.MODULES}:
        raise ValueError("prepared source/module inventory differs")
    builder = q.NativeBuild(hepta, output / "build")
    if (digest(builder.bootstrap()) != report.get("compiler_image_sha256")
            or digest(output / "build/bootstrap/bootstrap.json") != report.get("compiler_bootstrap_sha256")):
        raise ValueError("prepared compiler fixed-point receipt differs")
    cold = q.validate_cold_evidence(output / "compiler-cold.json", dependency=builder.identity,
                                    compiler_sha256=report["compiler_image_sha256"])
    if (report.get("compiler_cold_evidence") != cold or report.get("compiler_cold_status") != "PASS"
            or report.get("matching_source_full_cold_qualified") is not True):
        raise ValueError("prepared build lacks complete matching-source cold evidence")
    validate_cold_process(output, report, hepta)
    return seal, report, builder


def fail(output: Path, report: dict, error: BaseException, phase: str) -> None:
    report.update(status="FAIL", phase=phase, native_components_status="FAIL",
                  rust_comparison_status="NOT_RUN", error={"type": type(error).__name__, "message": str(error)},
                  finished_at=datetime.now(timezone.utc).isoformat())
    (output / (phase + "-failure.txt")).write_text(traceback.format_exc())
    q.save_report(output / "result.json", report)


def prepare(output: Path, hepta: Path, invocation: str) -> dict:
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    report, started = q.initial_report(hepta), time.monotonic()
    q.save_report(output / "result.json", report)
    try:
        partitions = partition_tests()
        binding = context(output, hepta, invocation)
        builder = q.prepare_native(output, hepta, report)
        builder.bootstrap()
        builder._recheck()
        if report["source_sha256"] != q.sources() or context(output, hepta, invocation) != binding:
            raise ValueError("source changed while preparing the native build")
        report.update(status="NATIVE_BUILD_READY", phase="native_build_complete", native_components_status="PENDING",
                      prepared_elapsed_seconds=time.monotonic() - started,
                      prepared_finished_at=datetime.now(timezone.utc).isoformat())
        q.save_report(output / "result.json", report)
        q.save_report(output / BUILD_REPORT, report)
        files, directories = inventory(output, {"result.json", BUILD_SEAL})
        q.save_report(output / BUILD_SEAL, {"schema": "hepta.runtime.native-build.v1", "context": binding,
            "files": files, "directories": directories, "partitions": {k: list(v) for k, v in partitions.items()}})
        return {"status": report["status"], "prepared_sha256": digest(output / BUILD_SEAL)}
    except BaseException as error:
        fail(output, report, error, "native_build")
        raise


def export_shard(output: Path, destination: Path, seal: dict, report: dict) -> None:
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    data = destination / "data"
    data.mkdir(mode=0o700)
    if any(row.get("name") == "test_atomic_write_policy.py" for row in report.get("checks", ())):
        # Actual filesystem snapshots and full content gzips are mandatory.
        # Their live effect targets may be symlinks or inaccessible directories;
        # they are not evidence files and never enter a transported artifact.
        evidence = q.atomic_write_evidence(output, report)
        q.atomic_write_retire_fixtures(output, tuple(evidence["transient_fixture_directories"]),
            output / "atomic-write/retired-fixtures.json", evidence["native_evidence"], create=True)
    if any(row.get("name") == "test_view_call_sync.py" for row in report.get("checks", ())):
        # The ordinary-file and public MCP cases intentionally create real
        # links. Retain their complete file bytes and link metadata after all
        # native receipts pass, then retire only those private test targets.
        public = q.runtime_mcp_evidence(output, report)
        literal = q.view_search_public_evidence(output, report)
        regex = q.view_regex_search_public_evidence(output, report)
        q.view_fixture_retirement(output, report, create=True, public=public,
                                 public_search=literal, public_regex_search=regex)
        # The public Workdir domain also has FIFO/hardlink/xattr state. Its
        # richer source-bound archive is read-only in collection; normal
        # original comparison alone may reconstruct it at the exact origin.
        q.runtime_mcp_fixture_retirement(output, report, create=True, public=public,
                                        public_search=literal, public_regex_search=regex)
    if any(row.get("name") == "test_filesystem_parity_kernel.py" for row in report.get("checks", ())):
        # Retain every complete native result, syscall trace and state snapshot
        # before removing the private effect targets from artifact transport.
        # This native phase cannot depend on the later Rust comparison recipe.
        q.filesystem_parity_retirement(output, report, create=True)
    if any(row.get("name") == "test_config_span.py" for row in report.get("checks", ())):
        q.config_span_fixture_retirement(output, report, create=True)
    files, directories = inventory(output, {BUILD_SEAL, "result.json", *seal["files"]})
    for name in directories:
        if name not in seal.get("directories", ()):
            (data / relative_path(name)).mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, identity in files.items():
        target = data / relative_path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(owned(output, name), target)
        target.chmod(identity["mode"])
    q.save_report(destination / "shard-report.json", report)
    q.save_report(destination / "shard.json", {"schema": "hepta.runtime.native-shard.v2",
        "binding": report["qualification_shard"], "files": files, "directories": inventory(data)[1],
        "report_sha256": digest(destination / "shard-report.json")})


def shard(output: Path, hepta: Path, expected: str, invocation: str, group: str, destination: Path) -> dict:
    seal, prepared, builder = admit_prepared(output, hepta, expected, invocation)
    tests = partition_tests()[group]
    report, started = copy.deepcopy(prepared), time.monotonic()
    report.update(status="RUNNING", phase="native_components", native_components_status="RUNNING",
                  qualification_shard={"group": group, "invocation": invocation,
                                       "prepared_sha256": expected, "tests": list(tests)})
    q.save_report(output / "result.json", report)
    try:
        q.run_native_checks(output, report, tests, q.native_environment(output, hepta, report), timeout=180,
                            commands=q.native_commands(output, report, tests))
        # Re-admit the original bytes without accepting any newly created file
        # as a replacement for a prepared compiler, module or cold receipt.
        admit_prepared(output, hepta, expected, invocation, exact=False)
        report.update(status="NATIVE_SHARD_PASS", phase="native_shard_complete", native_components_status="PARTIAL",
                      shard_elapsed_seconds=time.monotonic() - started,
                      shard_finished_at=datetime.now(timezone.utc).isoformat())
        q.save_report(output / "result.json", report)
        export_shard(output, destination, seal, report)
        return {"status": report["status"], "group": group, "checks": len(tests),
                "shard_sha256": digest(destination / "shard.json")}
    except BaseException as error:
        fail(output, report, error, "native_shard")
        raise


def admit_shard(data: Path, receipt_path: Path, report_path: Path, prepared: dict, expected: str,
                invocation: str, group: str, *, exact_files: bool) -> tuple[dict, dict]:
    receipt = read_json(receipt_path)
    tests = partition_tests()[group]
    binding = {"group": group, "invocation": invocation, "prepared_sha256": expected, "tests": list(tests)}
    if (set(receipt) != {"schema", "binding", "files", "directories", "report_sha256"}
            or receipt["schema"] != "hepta.runtime.native-shard.v2" or receipt["binding"] != binding
            or digest(report_path) != receipt["report_sha256"]):
        raise ValueError("native shard binding or actual report identity differs")
    verify_files(data, receipt["files"], restore_modes=exact_files)
    verify_directories(data, receipt["directories"], restore=exact_files)
    if exact_files:
        files, directories = inventory(data)
        if files != receipt["files"] or set(directories) != set(receipt["directories"]):
            raise ValueError("native shard artifact file or directory inventory differs")
    report = read_json(report_path)
    changed = {"status", "phase", "native_components_status", "checks"}
    additions = {"qualification_shard", "native_parallel_receipts", "shard_elapsed_seconds", "shard_finished_at"}
    if (set(report) != set(prepared) | additions
            or any(q.json_bytes(report.get(key)) != q.json_bytes(value)
                   for key, value in prepared.items() if key not in changed)
            or report.get("status") != "NATIVE_SHARD_PASS" or report.get("phase") != "native_shard_complete"
            or report.get("native_components_status") != "PARTIAL" or report.get("qualification_shard") != binding
            or q.json_bytes(report.get("checks", [])[:1]) != q.json_bytes(prepared["checks"])
            or [row.get("name") for row in report["checks"][1:]] != list(tests)):
        raise ValueError("native shard is incomplete, duplicated or differs from its prepared source")
    # Build manifests contain relative paths; the source-owned command prefix
    # and output location come from the prepared cold invocation, not a shard.
    output = Path(prepared["checks"][0]["command"][-1]).parent
    commands = q.native_commands(output, prepared, tests)
    by_name = {}
    for row in report["checks"][1:]:
        name = row["name"]
        command = commands.get(name, [sys.executable, "-I", "-B", str(q.ROOT / "tests/hia_native" / name)])
        validate_check(data, row, name, command, 180, "native_components")
        by_name[name] = row
    parallel = {name + ".execution.json" for name in tests if name in q.PARALLEL_NATIVE_SUITES}
    if set(report["native_parallel_receipts"]) != parallel:
        raise ValueError("native shard omitted a private execution receipt")
    for name, expected_hash in report["native_parallel_receipts"].items():
        path = owned(data, name)
        private = read_json(path)
        if (digest(path) != expected_hash or q.json_bytes(private) != q.json_bytes({"phase": "native_components",
                "checks": [by_name[name.removesuffix(".execution.json")]]})):
            raise ValueError("private shard execution receipt differs from the actual completed process")
    return receipt, report


def verify_pipeline_receipts(output: Path, report: dict) -> None:
    pipeline = report["qualification_pipeline"]
    if (set(pipeline) != {"schema", "invocation", "prepared_sha256", "shards", "tests"}
            or pipeline["schema"] != "hepta.runtime.native-pipeline.v1"
            or set(pipeline["shards"]) != set(PARTITIONS) or pipeline["tests"] != list(q.native_tests())):
        raise ValueError("complete native pipeline inventory differs")
    seal, prepared, _ = admit_prepared(output, Path(report["compiler_checkout"]), pipeline["prepared_sha256"],
                                      pipeline["invocation"], exact=False)
    native_rows, parallel = {}, {}
    for group, identities in pipeline["shards"].items():
        prefix = "qualification-shards/" + group + "/"
        if set(identities) != {"shard.json", "shard-report.json"}:
            raise ValueError("retained shard receipt inventory differs")
        for name, expected in identities.items():
            if digest(owned(output, prefix + name)) != expected:
                raise ValueError("retained shard receipt changed")
        _, part = admit_shard(output, output / prefix / "shard.json", output / prefix / "shard-report.json",
                             prepared, pipeline["prepared_sha256"], pipeline["invocation"], group, exact_files=False)
        native_rows.update({row["name"]: row for row in part["checks"][1:]})
        parallel.update(part["native_parallel_receipts"])
    expected_rows = prepared["checks"] + [native_rows[name] for name in q.native_tests()]
    native_names = {row["name"] for row in expected_rows}
    if (q.json_bytes(report["checks"][:len(expected_rows)]) != q.json_bytes(expected_rows)
            or any(row.get("name") in native_names for row in report["checks"][len(expected_rows):])
            or report["native_parallel_receipts"] != parallel):
        raise ValueError("aggregate process records differ from the complete actual shards")


def collect(output: Path, hepta: Path, expected: str, invocation: str, shards: Path) -> dict:
    seal, prepared, builder = admit_prepared(output, hepta, expected, invocation)
    report = copy.deepcopy(prepared)
    report.update(status="RUNNING", phase="native_components", native_components_status="RUNNING")
    q.save_report(output / "result.json", report)
    try:
        folders = sorted(shards.iterdir())
        if len(folders) != len(PARTITIONS) or any(p.is_symlink() or not p.is_dir() for p in folders):
            raise ValueError(f"collector requires exactly {len(PARTITIONS)} complete shard artifacts")
        parts, copies, all_files, all_directories = {}, {}, {}, set()
        for folder in folders:
            receipt_path, report_path = owned(folder, "shard.json"), owned(folder, "shard-report.json")
            group = read_json(receipt_path).get("binding", {}).get("group")
            if group not in PARTITIONS or group in parts:
                raise ValueError("collector received a duplicate or unknown native shard")
            if set(p.name for p in folder.iterdir()) != {"data", "shard.json", "shard-report.json"}:
                raise ValueError("shard artifact has undeclared top-level members")
            receipt, part = admit_shard(folder / "data", receipt_path, report_path, prepared, expected,
                                        invocation, group, exact_files=True)
            parts[group] = (folder, receipt, part)
            all_directories.update(receipt["directories"])
            for name, identity in receipt["files"].items():
                if name in seal["files"] or name in {BUILD_SEAL, "result.json"} or name.startswith("qualification-shards/"):
                    raise ValueError("native shard attempts to replace an immutable prepared artifact")
                if name in all_files and all_files[name] != identity:
                    raise ValueError("native shard artifacts have conflicting bytes: " + name)
                all_files[name], copies[name] = identity, folder / "data" / name
        if set(parts) != set(PARTITIONS):
            raise ValueError("collector is missing a complete native shard")
        verify_directories(output, sorted(all_directories), restore=True)
        for name, source in copies.items():
            target = output / relative_path(name)
            if target.exists() or target.is_symlink():
                raise ValueError("collector would overwrite an existing artifact")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(all_files[name]["mode"])
        receipts, native_rows, parallel = {}, {}, {}
        for group in PARTITIONS:
            folder, _, part = parts[group]
            dest = output / "qualification-shards" / group
            dest.mkdir(parents=True, mode=0o700)
            receipts[group] = {}
            for name in ("shard.json", "shard-report.json"):
                shutil.copyfile(folder / name, dest / name)
                receipts[group][name] = digest(dest / name)
            native_rows.update({row["name"]: row for row in part["checks"][1:]})
            parallel.update(part["native_parallel_receipts"])
        report["checks"] = prepared["checks"] + [native_rows[name] for name in q.native_tests()]
        report["native_parallel_receipts"] = parallel
        report["qualification_pipeline"] = {"schema": "hepta.runtime.native-pipeline.v1", "invocation": invocation,
            "prepared_sha256": expected, "shards": receipts, "tests": list(q.native_tests())}
        verify_pipeline_receipts(output, report)
        q.collect_native_evidence(output, report)
        q.finish_native(output, report, builder)
        report["native_components_elapsed_seconds"] = (datetime.now(timezone.utc) -
            datetime.fromisoformat(report["started_at"])).total_seconds()
        report["native_components_finished_at"] = datetime.now(timezone.utc).isoformat()
        q.save_report(output / "result.json", report)
        return {"status": report["status"], "checks": len(report["checks"]), "whole_runtime_replaced": False}
    except BaseException as error:
        fail(output, report, error, "native_collect")
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "shard", "collect"))
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--invocation", required=True)
    parser.add_argument("--prepared-sha256")
    parser.add_argument("--group", choices=tuple(PARTITIONS))
    parser.add_argument("--export", type=Path)
    parser.add_argument("--shards", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    hepta, output = args.hepta.resolve(strict=True), args.output.absolute()
    if args.phase == "prepare":
        result = prepare(output, hepta, args.invocation)
        if args.github_output:
            with args.github_output.open("a") as stream:
                stream.write("prepared_sha256=" + result["prepared_sha256"] + "\n")
    elif args.phase == "shard":
        if args.group is None or args.export is None:
            parser.error("shard requires --group and --export")
        result = shard(output, hepta, args.prepared_sha256, args.invocation, args.group, args.export.absolute())
    else:
        if args.shards is None:
            parser.error("collect requires --shards")
        result = collect(output, hepta, args.prepared_sha256, args.invocation, args.shards.resolve(strict=True))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
