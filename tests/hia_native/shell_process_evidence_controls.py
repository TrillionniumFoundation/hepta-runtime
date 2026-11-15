"""Physical refusal controls for the read-only shell-process evidence reader.

Each case is an independent ordinary-file copy of retired evidence. Mutations
and any deliberate hash rebinding are retained. Actual audited reader processes
keep complete stdout/stderr and receipts. The verifier never reruns a process.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve()
READER = ROOT / "scripts/hia_native_shell_process_evidence.py"
NATIVE = (
    "missing_case", "duplicate_case", "partial_as_full", "native_input",
    "control_input", "native_stdout", "trace_pid", "trace_action", "trace_return",
    "trace_child_return", "missing_reap", "missing_footer", "source_identity",
    "elf_identity", "manifest_identity", "cancel_as_background",
    "retired_payload", "retired_mode", "retired_raw_path",
)
ORIGINAL = (
    "original_capture", "original_stdout", "events_mismatch",
    "original_sequence", "original_cancel_callback", "original_event_order",
)
SCOPE = {
    "production_activated": False, "production_shell_execution_qualified": False,
    "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
}


_READER_MODULE = None


def reader_module():
    global _READER_MODULE
    if _READER_MODULE is not None:
        return _READER_MODULE
    spec = importlib.util.spec_from_file_location("shell_process_evidence_control_reader", READER)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load current evidence reader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _READER_MODULE = module
    return module


def raw(path: Path) -> bytes:
    if (path.is_symlink() or path.resolve(strict=True) != path.absolute()
            or not stat.S_ISREG(path.lstat().st_mode) or path.lstat().st_nlink != 1):
        raise ValueError("control evidence must be an independent ordinary file")
    return path.read_bytes()


def pin(path: Path) -> dict:
    data = raw(path)
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def json_read(path: Path):
    return reader_module().strict_json(raw(path))


def json_write(path: Path, value, *, new=False) -> None:
    data = (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()
    with path.open("xb" if new else "wb") as stream:
        stream.write(data)


def inventory(directory: Path) -> dict:
    def scan_error(error):
        raise error
    result = {}
    for parent, dirs, files in os.walk(directory, followlinks=False, onerror=scan_error):
        for name in dirs:
            item = Path(parent) / name
            if item.is_symlink() or not stat.S_ISDIR(item.lstat().st_mode):
                raise ValueError("control inventory contains a non-directory")
        for name in files:
            path = Path(parent) / name
            result[str(path.relative_to(directory))] = pin(path)
    return dict(sorted(result.items()))


def load_files(directory: Path) -> dict[str, bytes]:
    names = inventory(directory)
    return {name: raw(directory / name) for name in names}


def mutation_recipe(baseline: dict[str, bytes], kind: str, module) -> dict[str, bytes]:
    """Pure deterministic transform: no evidence code, process or filesystem IO."""
    files = dict(baseline)
    def get(path):
        return module.strict_json(files[path])
    def put(path, value):
        files[path] = (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()
    def byte_pin(path):
        data = files[path]
        return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    def bind(value, path):
        value.update(byte_pin(path))
    def bind_case(name):
        report = get("report.json")
        row = next(x for x in report["cases"] if x["name"] == name)
        native = row.get("native", row)
        for key in ("process", "validation"):
            bind(native[key], name + "/native/" + key + ".json")
        if "original" in row:
            for key in ("process", "validation"):
                bind(row["original"][key], name + "/original/" + key + ".json")
            bind(row["comparison"], name + "/comparison.json")
        put("report.json", report)
    def bind_stream(name, side, stream):
        mapping = {"native": {"stdin": "stdin.bin", "stdout": "fixture.stdout", "stderr": "fixture.stderr"},
                   "original": {"stdin": "stdin.jsonl", "stdout": "stdout.jsonl", "stderr": "stderr"}}
        prefix = name + "/" + side + "/"
        receipt = get(prefix + "process.json")
        bind(receipt["streams"][stream], prefix + mapping[side][stream])
        put(prefix + "process.json", receipt)
        bind_case(name)
    def bind_trace(name):
        prefix = name + "/native/"
        validation = get(prefix + "validation.json")
        bind(validation["trace_file"], prefix + "capture/effects.bin")
        data = files[prefix + "capture/effects.bin"]
        if data[-128:-120] == b"HSHPAUD1":
            validation["audit_footer"] = {
                "offset": len(data) - 128,
                "words": list(struct.unpack("<16Q", data[-128:]))[1:],
                "raw_hex": data[-128:].hex(),
            }
        put(prefix + "validation.json", validation)
        bind_case(name)
    def bind_retirement():
        prefix = "fixture-retirement/"
        receipt, prepared = get(prefix + "receipt.json"), get(prefix + "prepared.json")
        digest = byte_pin("report.json")["sha256"]
        receipt["report_sha256"] = digest
        receipt["validated_evidence"]["report_sha256"] = digest
        prepared["validated_evidence"]["report_sha256"] = digest
        for name, case in receipt["cases"].items():
            path = prefix + "cases/" + name + ".json"
            bind(case["snapshot"], path)
            bind(prepared["cases"][name]["snapshot"], path)
        put(prefix + "prepared.json", prepared)
        bind(receipt["prepared_receipt"], prefix + "prepared.json")
        put(prefix + "receipt.json", receipt)
    report = get("report.json")
    name = "stdout_and_stderr"
    if kind == "missing_case":
        report["cases"].pop()
        report["case_count"] -= 1
        put("report.json", report)
    elif kind == "duplicate_case":
        report["cases"][-1] = copy.deepcopy(report["cases"][0])
        put("report.json", report)
    elif kind == "partial_as_full":
        report["selected_cases"] = [report["cases"][0]["name"]]
        report["full_case_set"] = False
        report["cases"] = report["cases"][:1]
        report["case_count"] = 1
        put("report.json", report)
    elif kind == "native_input":
        path = name + "/native/stdin.bin"
        data = bytearray(files[path])
        data[48] ^= 1
        files[path] = bytes(data)
        bind_stream(name, "native", "stdin")
    elif kind == "control_input":
        name = "foreground_cancel"
        path = name + "/native/stdin.bin"
        data = bytearray(files[path])
        struct.pack_into("<Q", data, len(data) - 48 + 16, 4)
        files[path] = bytes(data)
        receipt = get(name + "/native/process.json")
        receipt["controls"][0]["operation"] = 4
        receipt["controls"][0]["frame_hex"] = bytes(data[-48:]).hex()
        put(name + "/native/process.json", receipt)
        bind_stream(name, "native", "stdin")
    elif kind == "native_stdout":
        path = name + "/native/fixture.stdout"
        data = bytearray(files[path])
        data[56] ^= 1
        files[path] = bytes(data)
        bind_stream(name, "native", "stdout")
    elif kind in ("trace_pid", "trace_action", "trace_return", "trace_child_return", "missing_reap", "missing_footer"):
        path = name + "/native/capture/effects.bin"
        data = files[path]
        rows = [list(struct.unpack("<16Q", data[i:i+128])) for i in range(0, len(data), 128)]
        if kind == "trace_pid":
            index = next(i for i, row in enumerate(rows[:-1]) if row[1] == 2)
            rows[index][2] += 100000
        elif kind == "trace_action":
            rows[0][5] = 15
        elif kind == "trace_return":
            index = next(i for i, row in enumerate(rows[:-1]) if row[1] == 1 and row[5] == 16 and row[14] == 1 and row[9] == 1)
            rows[index][9] = 0
        elif kind == "trace_child_return":
            index = next(i for i, row in enumerate(rows[:-1]) if row[1] == 2 and row[5] == 7 and row[6] == 1 and row[14] == 1)
            rows[index][15] = 2
        elif kind == "missing_reap":
            index = next(i for i, row in enumerate(rows[:-1]) if row[1] == 1 and row[5] == 16 and row[14] == 1 and row[9] == 1)
            del rows[index]
            rows[-1][1] -= 1
        else:
            rows.pop()
        files[path] = b"".join(struct.pack("<16Q", *row) for row in rows)
        bind_trace(name)
    elif kind in ("source_identity", "elf_identity", "manifest_identity"):
        key = {"source_identity": "cases_source", "elf_identity": "native_executable",
               "manifest_identity": "native_build_manifest"}[kind]
        path = "input-snapshots/" + key
        if kind == "manifest_identity":
            value = get(path)
            value["production_activated"] = True
            put(path, value)
        else:
            data = bytearray(files[path])
            data[-1] ^= 1
            files[path] = bytes(data)
        inputs = get("inputs.json")
        bind(inputs[key], path)
        report["inputs"] = inputs
        put("inputs.json", inputs)
        put("report.json", report)
    elif kind == "cancel_as_background":
        name = "foreground_cancel"
        prefix = name + "/native/"
        data = bytearray(files[prefix + "fixture.stdout"])
        struct.pack_into("<Q", data, 24, 4)
        files[prefix + "fixture.stdout"] = bytes(data)
        frames = get(prefix + "frames.json")
        first = frames[0]
        body = bytes(data[16:112])
        first["body_hex"] = body.hex()
        first["event"]["kind"] = 4
        first["event"]["raw_hex"] = body.hex()
        put(prefix + "frames.json", frames)
        bind_stream(name, "native", "stdout")
    elif kind in ("retired_payload", "retired_mode", "retired_raw_path"):
        name = "raw_unix_cwd" if kind == "retired_raw_path" else "empty_path_current_directory"
        path = "fixture-retirement/cases/" + name + ".json"
        snapshot = get(path)
        target = (b"work/raw-\xff-\xfe" if kind == "retired_raw_path" else b"work/sh").hex()
        row = next(x for x in snapshot["entries"] if x["path_hex"] == target)
        if kind == "retired_payload":
            payload = "fixture-retirement/" + row["payload"]
            data = bytearray(files[payload])
            data[-2] ^= 1
            files[payload] = bytes(data)
            row["content"] = byte_pin(payload)
        elif kind == "retired_mode":
            row["permissions"] = 0o777
            row["identity"]["mode"] = stat.S_IFREG | 0o777
        else:
            row["path_hex"] = b"work/raw-\xfe-\xff".hex()
        put(path, snapshot)
    elif kind == "original_capture":
        path = name + "/original/retained/stdout.bin"
        data = bytearray(files[path])
        data[0] ^= 1
        files[path] = bytes(data)
        comparison = get(name + "/comparison.json")
        bind(comparison["capture_comparison"]["streams"]["stdout"]["original"], path)
        put(name + "/comparison.json", comparison)
        bind_case(name)
    elif kind in ("original_stdout", "events_mismatch", "original_sequence",
                  "original_cancel_callback", "original_event_order"):
        if kind == "original_cancel_callback":
            name = "foreground_cancel"
        prefix = name + "/original/"
        events = get(prefix + "events.json")
        if kind == "events_mismatch":
            events[-1]["callback_count"] = 19
            put(prefix + "events.json", events)
        else:
            if kind == "original_stdout":
                events[0]["command_hex"] = "00" + events[0]["command_hex"][2:]
            elif kind == "original_sequence":
                events[1]["seq"] = 1
            elif kind == "original_event_order":
                slots = [(row["elapsed_ns"], row["unix_ns"]) for row in events]
                if [row["event"] for row in events] != ["started", "capture_ready", "foreground", "final"]:
                    raise ValueError("original order control baseline changed")
                events[1], events[2] = events[2], events[1]
                for i, row in enumerate(events):
                    row["seq"] = i + 1
                    row["elapsed_ns"], row["unix_ns"] = slots[i]
            else:
                final = events[-1]
                events.insert(-1, {
                    "schema": final["schema"], "event": "completion", "oracle_pid": final["oracle_pid"],
                    "elapsed_ns": final["elapsed_ns"], "unix_ns": final["unix_ns"], "pid": final["pid"],
                    "exit_code": -1, "callback_count": 1, "job_id": str(final["oracle_pid"]) + "-1",
                    "resource_uri": "octofs://jobs/" + str(final["oracle_pid"]) + "-1",
                    "raw_wait_status": None, "raw_wait_status_observable": False,
                })
                events[-1]["callback_count"] = 1
                for i, row in enumerate(events, 1):
                    row["seq"] = i
            files[prefix + "stdout.jsonl"] = b"".join(
                (json.dumps(x, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
                for x in events
            )
            if kind != "original_stdout":
                put(prefix + "events.json", events)
            if kind in ("original_cancel_callback", "original_event_order"):
                validation = get(prefix + "validation.json")
                validation["event_names"] = [row["event"] for row in events]
                put(prefix + "validation.json", validation)
            bind_stream(name, "original", "stdout")
    elif kind == "_generic_rejection_counterfeit":
        # This intentionally wrong physical recipe must never count as coverage
        # for a registered trace/sequence test, even though the reader rejects it.
        report["status"] = "FAIL"
        put("report.json", report)
    else:
        raise ValueError("unregistered physical mutation: " + kind)
    bind_retirement()
    return files


def verify_recipe(baseline: dict[str, bytes], observed: dict[str, bytes],
                  name: str, module) -> None:
    if name not in NATIVE + ORIGINAL:
        raise ValueError("unregistered named mutation")
    expected = mutation_recipe(baseline, name, module)
    if set(observed) != set(expected):
        raise ValueError("named mutation file inventory differs: " + name)
    different = [path for path in expected if observed[path] != expected[path]]
    if different:
        raise ValueError("physical mutation is not its named deterministic recipe: " + name + ": " + different[0])


def materialize_mutation(directory: Path, baseline: dict[str, bytes], name: str, module) -> None:
    expected = mutation_recipe(baseline, name, module)
    for relative, data in expected.items():
        if data != baseline[relative]:
            (directory / relative).write_bytes(data)
    if name in NATIVE + ORIGINAL:
        verify_recipe(baseline, load_files(directory), name, module)


def process_run(folder: Path, evidence: Path, native: Path, original: Path | None,
                native_only: bool, relocated: bool, expected: str, *,
                recipe_name: str | None = None, recipe_baseline: Path | None = None) -> dict:
    folder.mkdir(parents=True, exist_ok=False)
    python = Path(sys.executable).resolve(strict=True)
    argv = [str(python), "-B", str(READER), "--evidence", str(evidence),
            "--native-manifest", str(native), "--audit-read-only"]
    if original is not None:
        argv += ["--original-manifest", str(original)]
    if native_only:
        argv.append("--native-only")
    if relocated:
        argv.append("--relocated-evidence")
    entrypoint = READER
    if recipe_name is not None:
        if recipe_baseline is None:
            raise ValueError("recipe verifier requires the original baseline")
        entrypoint = SOURCE
        argv = [str(python), "-B", str(SOURCE), "--verify-recipe", str(evidence),
                "--baseline", str(recipe_baseline), "--recipe", recipe_name, "--audit-read-only"]
    environment = {"PATH": os.defpath, "LC_ALL": "C", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"}
    started = time.monotonic_ns()
    process = None
    stdout = stderr = b""
    timed_out, error = False, None
    try:
        process = subprocess.Popen(argv, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
    except Exception as exc:
        error = {"type": type(exc).__name__, "message": str(exc)}
        if process is not None and process.poll() is None:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
    finished = time.monotonic_ns()
    (folder / "stdout.bin").write_bytes(stdout)
    (folder / "stderr.bin").write_bytes(stderr)
    receipt = {
        "schema": "hepta.runtime.shell-process-evidence-control-process.v1",
        "argv": argv, "cwd": str(ROOT), "environment": environment,
        "python": {"path": str(python), **pin(python)}, "reader": {"path": str(READER), **pin(READER)},
        "entrypoint": {"path": str(entrypoint), **pin(entrypoint)},
        "recipe": ({"name": recipe_name, "baseline": str(recipe_baseline)}
                   if recipe_name is not None else None),
        "pid": process.pid if process is not None else None,
        "started_ns": started, "finished_ns": finished, "duration_ns": finished - started,
        "deadline_ms": 120000, "exit_code": process.returncode if process is not None else None,
        "timed_out": timed_out, "exception": error,
        "expected": expected, "relocated_evidence": relocated,
        "stdout": pin(folder / "stdout.bin"), "stderr": pin(folder / "stderr.bin"),
    }
    json_write(folder / "process.json", receipt, new=True)
    module = reader_module()
    try:
        result = module.strict_json(stdout)
    except Exception as exc:
        result = {"status": "MALFORMED_READER_STDOUT", "message": str(exc)}
    passed = (
        error is None and not timed_out and not stderr and result.get("status") == expected
        and receipt["exit_code"] == (0 if expected == "PASS" else 1)
        and result.get("read_only_audit_enforced") is True
    )
    validation = {"status": "PASS" if passed else "FAIL", "reader_result": result}
    json_write(folder / "validation.json", validation, new=True)
    return validation


def source_files() -> dict:
    paths = (SOURCE, READER, ROOT / "scripts/hia_native_shell_process_qualification.py",
             ROOT / "tests/hia_native/shell_process_cases.py")
    return {str(p.relative_to(ROOT)): pin(p) for p in paths}


def run(evidence: Path, native_manifest: Path, output: Path,
        original_manifest: Path | None = None, native_only: bool = False) -> dict:
    evidence, native_manifest, output = evidence.absolute(), native_manifest.absolute(), output.absolute()
    original_manifest = original_manifest.absolute() if original_manifest is not None else None
    module = reader_module()
    baseline = (module.read_native_evidence(evidence, native_manifest) if native_only
                else module.read_evidence(evidence, native_manifest, original_manifest))
    if not baseline["fixtures_retired"]:
        raise ValueError("retire the validated fixture roots before making physical tamper copies")
    has_original = baseline["original_comparison_cases"] > 0
    names = NATIVE + (ORIGINAL if has_original else ())
    before = inventory(evidence)
    baseline_bytes = load_files(evidence)
    sources = source_files()
    output.mkdir(parents=True, exist_ok=False)
    for relative in sources:
        path = output / "source-snapshots" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw(ROOT / relative))
    json_write(output / "baseline-inventory.json", before, new=True)
    json_write(output / "baseline-validation.json", baseline, new=True)
    status = []
    status.append(("positive_strong", process_run(output / "positive-strong", evidence, native_manifest,
                                                original_manifest, native_only, False, "PASS")["status"]))
    copies = output / "copies"
    copies.mkdir()
    baseline_copy = copies / "positive"
    shutil.copytree(evidence, baseline_copy, copy_function=shutil.copyfile)
    if inventory(baseline_copy) != before:
        raise ValueError("physical positive copy differs from admitted baseline")
    status.append(("positive_relocated", process_run(output / "positive-relocated", baseline_copy, native_manifest,
                                                   original_manifest, native_only, True, "PASS")["status"]))
    mutations = []
    for name in names:
        destination = copies / name
        shutil.copytree(evidence, destination, copy_function=shutil.copyfile)
        if inventory(destination) != before:
            raise ValueError("physical refusal copy differs before mutation")
        materialize_mutation(destination, baseline_bytes, name, module)
        after = inventory(destination)
        changes = {path: {"before": before.get(path), "after": after.get(path)}
                   for path in sorted(set(before) | set(after)) if before.get(path) != after.get(path)}
        if not changes:
            raise ValueError("registered physical mutation made no actual change")
        validation = process_run(output / "runs" / name, destination, native_manifest,
                                 original_manifest, native_only, True, "REJECTED")
        mutation = {
            "name": name, "changes": changes, "status": validation["status"],
            "full_hash_rebinding_is_explicit": True,
        }
        mutations.append(mutation)
        status.append((name, validation["status"]))
    # A generic rejected report must not masquerade as unrelated named coverage.
    # Run the same pure recipe comparator used by read_evidence in real audited
    # processes, retaining independently copied bytes and complete receipts.
    substitutions = []
    substitution_names = ("trace_pid",) + (("original_sequence",) if has_original else ())
    for name in substitution_names:
        destination = copies / ("coverage-substitution-" + name)
        shutil.copytree(evidence, destination, copy_function=shutil.copyfile)
        materialize_mutation(destination, baseline_bytes, "_generic_rejection_counterfeit", module)
        after = inventory(destination)
        changes = {path: {"before": before.get(path), "after": after.get(path)}
                   for path in sorted(set(before) | set(after)) if before.get(path) != after.get(path)}
        validation = process_run(
            output / "recipe-runs" / name, destination, native_manifest, original_manifest,
            native_only, True, "REJECTED", recipe_name=name, recipe_baseline=evidence,
        )
        substitutions.append({
            "name": name, "actual_recipe": "_generic_rejection_counterfeit",
            "changes": changes, "status": validation["status"],
        })
        status.append(("coverage_substitution_" + name, validation["status"]))
    changed = source_files() != sources or inventory(evidence) != before
    report = {
        "schema": "hepta.runtime.shell-process-evidence-controls.v1",
        "status": "PASS" if not changed and all(s == "PASS" for _, s in status) else "FAIL",
        "source_or_baseline_changed": changed, "sources": sources,
        "baseline": str(evidence), "baseline_report": pin(evidence / "report.json"),
        "native_manifest": {"path": str(native_manifest), **pin(native_manifest)},
        "original_manifest": ({"path": str(original_manifest), **pin(original_manifest)}
                              if original_manifest is not None else None),
        "native_only": native_only, "positive_processes": 2, "refusal_processes": len(names),
        "coverage_substitution_refusals": len(substitution_names),
        "coverage_substitutions": substitutions,
        "mutations": mutations, "process_results": [{"name": n, "status": s} for n, s in status],
        "files": inventory(output), **SCOPE,
    }
    json_write(output / "report.json", report, new=True)
    return report


def read_evidence(output: Path, native_manifest: Path | None = None,
                  original_manifest: Path | None = None) -> dict:
    output = output.absolute()
    module = reader_module()
    report = module.strict_json(raw(output / "report.json"))
    if (type(report) is not dict or report.get("schema") != "hepta.runtime.shell-process-evidence-controls.v1"
            or report.get("status") != "PASS" or report.get("source_or_baseline_changed") is not False
            or report.get("sources") != source_files()
            or any(report.get(k) is not v for k, v in SCOPE.items())):
        raise ValueError("physical controls report/source/scope differs")
    actual_files = inventory(output)
    actual_files.pop("report.json")
    if actual_files != report["files"]:
        raise ValueError("physical control evidence file inventory changed")
    for relative, expected in report["sources"].items():
        if pin(output / "source-snapshots" / relative) != expected:
            raise ValueError("sealed control producer source changed")
    recorded_native = Path(report["native_manifest"]["path"])
    if native_manifest is None:
        native_manifest = recorded_native
    if native_manifest.absolute() != recorded_native or {"path": str(recorded_native), **pin(recorded_native)} != report["native_manifest"]:
        raise ValueError("current native manifest binding differs")
    recorded_original = report["original_manifest"]
    if recorded_original is not None:
        if original_manifest is None:
            original_manifest = Path(recorded_original["path"])
        if {"path": str(original_manifest.absolute()), **pin(original_manifest.absolute())} != recorded_original:
            raise ValueError("current original manifest binding differs")
    elif original_manifest is not None:
        raise ValueError("controls did not use the requested original manifest")
    native_only = report["native_only"]
    if type(native_only) is not bool:
        raise ValueError("invalid native-only controls flag")
    baseline_path = Path(report["baseline"])
    baseline = (module.read_native_evidence(baseline_path, recorded_native) if native_only
                else module.read_evidence(baseline_path, recorded_native, original_manifest))
    if baseline != json_read(output / "baseline-validation.json") or not baseline["fixtures_retired"]:
        raise ValueError("actual retired control baseline changed")
    baseline_inventory = json_read(output / "baseline-inventory.json")
    baseline_bytes = load_files(baseline_path)
    if inventory(baseline_path) != baseline_inventory or pin(baseline_path / "report.json") != report["baseline_report"]:
        raise ValueError("physical controls modified their source baseline")
    names = NATIVE + (ORIGINAL if baseline["original_comparison_cases"] else ())
    if (report["positive_processes"] != 2 or report["refusal_processes"] != len(names)
            or [x["name"] for x in report["mutations"]] != list(names)):
        raise ValueError("registered refusal inventory differs")
    expected_results = [{"name": "positive_strong", "status": "PASS"},
                        {"name": "positive_relocated", "status": "PASS"}]
    expected_results += [{"name": name, "status": "PASS"} for name in names]
    substitution_names = ("trace_pid",) + (("original_sequence",) if baseline["original_comparison_cases"] else ())
    if (report.get("coverage_substitution_refusals") != len(substitution_names)
            or type(report.get("coverage_substitutions")) is not list
            or [x["name"] for x in report["coverage_substitutions"]] != list(substitution_names)):
        raise ValueError("named-coverage substitution control inventory differs")
    expected_results += [{"name": "coverage_substitution_" + name, "status": "PASS"}
                         for name in substitution_names]
    if report["process_results"] != expected_results:
        raise ValueError("reader execution result inventory differs")

    def execution(run_folder: Path, case_path: Path, relocated: bool, expected: str,
                  recipe_name: str | None = None):
        receipt = json_read(run_folder / "process.json")
        python = Path(receipt["python"]["path"])
        argv = [str(python), "-B", str(READER), "--evidence", str(case_path),
                "--native-manifest", str(recorded_native), "--audit-read-only"]
        if original_manifest is not None:
            argv += ["--original-manifest", str(original_manifest)]
        if native_only:
            argv.append("--native-only")
        if relocated:
            argv.append("--relocated-evidence")
        entrypoint = READER
        recipe = None
        if recipe_name is not None:
            entrypoint = SOURCE
            recipe = {"name": recipe_name, "baseline": str(baseline_path)}
            argv = [str(python), "-B", str(SOURCE), "--verify-recipe", str(case_path),
                    "--baseline", str(baseline_path), "--recipe", recipe_name, "--audit-read-only"]
        expected_environment = {"PATH": os.defpath, "LC_ALL": "C", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"}
        if (receipt.get("schema") != "hepta.runtime.shell-process-evidence-control-process.v1"
                or receipt.get("argv") != argv or receipt.get("cwd") != str(ROOT)
                or receipt.get("environment") != expected_environment
                or receipt.get("python") != {"path": str(python), **pin(python)}
                or receipt.get("reader") != {"path": str(READER), **pin(READER)}
                or receipt.get("entrypoint") != {"path": str(entrypoint), **pin(entrypoint)}
                or receipt.get("recipe") != recipe
                or not module.integer(receipt.get("pid"), 1)
                or receipt.get("exit_code") != (0 if expected == "PASS" else 1)
                or receipt.get("timed_out") is not False or receipt.get("exception") is not None
                or receipt.get("deadline_ms") != 120000
                or receipt.get("expected") != expected or receipt.get("relocated_evidence") is not relocated
                or not module.integer(receipt.get("started_ns"), 0)
                or not module.integer(receipt.get("finished_ns"), receipt["started_ns"])
                or receipt.get("duration_ns") != receipt["finished_ns"] - receipt["started_ns"]
                or receipt.get("stdout") != pin(run_folder / "stdout.bin")
                or receipt.get("stderr") != pin(run_folder / "stderr.bin")
                or raw(run_folder / "stderr.bin") != b""):
            raise ValueError("actual audited reader process receipt differs")
        observed = module.strict_json(raw(run_folder / "stdout.bin"))
        if (observed.get("status") != expected or observed.get("read_only_audit_enforced") is not True
                or json_read(run_folder / "validation.json") != {"status": "PASS", "reader_result": observed}):
            raise ValueError("actual audited reader output differs")
        try:
            if recipe_name is not None:
                verify_recipe(baseline_bytes, load_files(case_path), recipe_name, module)
                reconstructed = {"status": "PASS", "recipe": recipe_name, **module.SCOPE}
            else:
                reconstructed = module._read_evidence(
                    case_path, recorded_native, original_manifest, True,
                    relocated=relocated, native_only=native_only,
                )
            reconstructed["read_only_audit_enforced"] = True
        except (module.EvidenceError, ValueError, AssertionError, TypeError, KeyError, OSError) as error:
            reconstructed = {
                "status": "REJECTED", "error_type": type(error).__name__, "message": str(error),
                "read_only_audit_enforced": True, **module.SCOPE,
            }
        if reconstructed != observed:
            raise ValueError("recorded refusal was not reconstructed from the actual physical mutation")

    execution(output / "positive-strong", baseline_path, False, "PASS")
    if inventory(output / "copies/positive") != baseline_inventory:
        raise ValueError("unchanged physical positive copy differs")
    execution(output / "positive-relocated", output / "copies/positive", True, "PASS")
    for mutation in report["mutations"]:
        name = mutation["name"]
        destination = output / "copies" / name
        verify_recipe(baseline_bytes, load_files(destination), name, module)
        after = inventory(destination)
        changes = {path: {"before": baseline_inventory.get(path), "after": after.get(path)}
                   for path in sorted(set(baseline_inventory) | set(after))
                   if baseline_inventory.get(path) != after.get(path)}
        if (mutation.get("changes") != changes or not changes or mutation.get("status") != "PASS"
                or mutation.get("full_hash_rebinding_is_explicit") is not True):
            raise ValueError("retained physical mutation differs")
        execution(output / "runs" / name, destination, True, "REJECTED")
    for substitution in report["coverage_substitutions"]:
        name = substitution["name"]
        destination = output / "copies" / ("coverage-substitution-" + name)
        if load_files(destination) != mutation_recipe(baseline_bytes, "_generic_rejection_counterfeit", module):
            raise ValueError("retained generic-rejection counterfeit differs from its exact recipe")
        after = inventory(destination)
        changes = {path: {"before": baseline_inventory.get(path), "after": after.get(path)}
                   for path in sorted(set(baseline_inventory) | set(after))
                   if baseline_inventory.get(path) != after.get(path)}
        if (substitution.get("actual_recipe") != "_generic_rejection_counterfeit"
                or substitution.get("changes") != changes or not changes
                or substitution.get("status") != "PASS"):
            raise ValueError("wrong-name recipe substitution evidence differs")
        execution(output / "recipe-runs" / name, destination, True, "REJECTED", name)
    return {
        "schema": "hepta.runtime.shell-process-evidence-control-review.v1", "status": "PASS",
        "positive_processes": 2, "refusal_processes": len(names),
        "actual_reader_processes": len(names) + 2, "read_only_audit_enforced": True,
        "coverage_substitution_refusals": len(substitution_names),
        "actual_recipe_verifier_processes": len(substitution_names),
        "physical_mutations_reconstructed": True, "fresh_original_rust_build_qualified": baseline["fresh_original_rust_build_qualified"],
        "whole_registered_case_count": baseline["case_count"], **SCOPE,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--native-manifest", type=Path)
    parser.add_argument("--original-manifest", type=Path)
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--verify-recipe", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--recipe")
    parser.add_argument("--audit-read-only", action="store_true")
    args = parser.parse_args()
    if args.verify_recipe is not None:
        if args.baseline is None or args.recipe not in NATIVE + ORIGINAL:
            parser.error("--verify-recipe requires --baseline and a registered --recipe")
        module = reader_module()
        if args.audit_read_only:
            sys.addaudithook(module.readonly_audit)
        try:
            verify_recipe(load_files(args.baseline), load_files(args.verify_recipe), args.recipe, module)
            result = {"status": "PASS", "recipe": args.recipe,
                      "read_only_audit_enforced": args.audit_read_only, **module.SCOPE}
        except module.ReadOnlyViolation as error:
            print(json.dumps({"status": "READ_ONLY_VIOLATION", "message": str(error), **module.SCOPE},
                             sort_keys=True))
            return 2
        except (module.EvidenceError, ValueError, AssertionError, TypeError, KeyError, OSError) as error:
            result = {"status": "REJECTED", "error_type": type(error).__name__, "message": str(error),
                      "read_only_audit_enforced": args.audit_read_only, **module.SCOPE}
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "PASS" else 1
    if args.audit_read_only:
        if args.verify is None:
            parser.error("--audit-read-only requires --verify or --verify-recipe")
        sys.addaudithook(reader_module().readonly_audit)
    if args.verify is not None:
        result = read_evidence(args.verify, args.native_manifest, args.original_manifest)
    else:
        if args.evidence is None or args.native_manifest is None or args.output is None:
            parser.error("--evidence, --native-manifest and --output are required")
        result = run(args.evidence, args.native_manifest, args.output, args.original_manifest, args.native_only)
        if result["status"] == "PASS":
            result = read_evidence(args.output, args.native_manifest, args.original_manifest)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
