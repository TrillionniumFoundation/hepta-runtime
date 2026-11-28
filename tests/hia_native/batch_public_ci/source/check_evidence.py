#!/usr/bin/env python3
"""Independent copies and rehashed-data refusals; never execute a native owner."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import math
import signal
import os
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import receipt_support as support
import read_builds
import read_files
import read_typed
import source_check
import run_recipe
from receipt_support import ROOT, PIN, SHA, require, regular, read_json, put

LABELS = (
    "source-comment", "rehashed-source", "compiler-stdout", "compiler-receipt",
    "rehashed-compiler-tail", "compiled-image", "fixture-pack-output", "typed-call-count",
    "rehashed-typed-semantic", "rehashed-typed-controls", "rehashed-filesystem-event",
    "rehashed-native-state-tail", "rehashed-original-binary", "body-comparison-summary",
    "process-deadline", "body-process-cwd", "rehashed-original-typed-output", "retired-final-archive",
)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def expected_changes(label, original):
    changes = {}
    def raw(name):
        return changes[name] if name in changes else original(name)
    def document(name):
        return json.loads(raw(name))
    def change(name, value):
        changes[name] = value
    def modify(name, edit):
        value = document(name)
        edit(value)
        change(name, encoded(value))
    module = "build/body/modules/batch_write/"
    if label in ("source-comment", "rehashed-source"):
        name = "source/body_native/batch_write.hepta"
        change(name, raw(name) + b"\n")
        if label == "rehashed-source":
            modify("source/source-profile.json", lambda d: d["files"].update({"body_native/batch_write.hepta": PIN(changes[name])}))
            modify("result.json", lambda d: d.update(source_profile=PIN(changes["source/source-profile.json"])))
    elif label == "compiler-stdout":
        modify(module + "module.stdout.log", lambda d: d.update(core_u32=d["core_u32"] + 1))
    elif label == "compiler-receipt":
        modify(module + "module.receipt.json", lambda d: d.update(core_u32=d["core_u32"] + 1))
        modify(module + "build.json", lambda d: d.update(compile_receipt=document(module + "module.receipt.json")))
    elif label == "rehashed-compiler-tail":
        name = module + "module.output.bin"
        value = bytearray(raw(name)); value[-1] ^= 1; change(name, bytes(value))
        for name in (module + "module.receipt.json", module + "module.stdout.log"):
            modify(name, lambda d: d.update(output_sha256=SHA(changes[module + "module.output.bin"])))
        modify(module + "build.json", lambda d: d.update(compile_receipt=document(module + "module.receipt.json")))
    elif label == "compiled-image":
        name = module + "module.image.bin"
        value = bytearray(raw(name)); value[-1] ^= 1; change(name, bytes(value))
    elif label == "fixture-pack-output":
        name = "build/fixture/pack.output.bin"
        value = bytearray(raw(name)); value[-1] ^= 1; change(name, bytes(value))
        modify("build/fixture/BUILD.json", lambda d: d["artifacts"].update({"pack.output.bin": PIN(changes[name])}))
    elif label == "typed-call-count":
        modify("typed/result.json", lambda d: d.update(actual_native_calls=3142))
    elif label in ("rehashed-typed-semantic", "rehashed-typed-controls"):
        name = "semantic.jsonl" if label.endswith("semantic") else "controls.jsonl"
        items = [json.loads(line) for line in raw("typed/" + name).splitlines()]
        if name == "semantic.jsonl": items[0]["carrier_sha256"] = "0" * 64
        else: items[0]["kind"] = "short-output"
        data = b"".join((json.dumps(x, sort_keys=True, separators=(",", ":")) + "\n").encode() for x in items)
        change("typed/" + name, data)
        modify("typed/result.json", lambda d: d["artifacts"].update({name: PIN(data)}))
    elif label == "rehashed-filesystem-event":
        name = "body/original/events.jsonl.gz"
        items = [json.loads(line) for line in gzip.decompress(raw(name)).splitlines()]
        node = next(x for x in items[-1]["filesystem"] if "sha256" in x)
        node["sha256"] = "0" * 64
        data = gzip.compress(b"".join((json.dumps(x, sort_keys=True, separators=(",", ":")) + "\n").encode() for x in items), mtime=0)
        change(name, data)
        modify("body/original/result.json", lambda d: d.update({"events.jsonl.gz": PIN(data)}))
    elif label == "rehashed-native-state-tail":
        name = "body/native/stderr.bin"
        data = bytearray(raw(name)); data[64 + 4095] ^= 1; data = bytes(data)
        change(name, data)
        modify("body/native/result.json", lambda d: d.update({"stderr.bin": PIN(data)}))
    elif label == "rehashed-original-binary":
        name = "hepta-batch-body-original-oracle"
        data = bytearray(raw("original/bin/" + name)); data[-1] ^= 1; data = bytes(data)
        change("original/bin/" + name, data)
        change("original/target/release/" + name, data)
        modify("original/BUILD.json", lambda d: d["binaries"].update({name: dict(path="bin/" + name, **PIN(data))}))
    elif label == "body-comparison-summary":
        modify("body/complete-comparison.json", lambda d: d.update(body_requests_per_side=925))
        modify("body/result.json", lambda d: d.update(comparison=document("body/complete-comparison.json"),
            comparison_pin=PIN(changes["body/complete-comparison.json"])))
    elif label == "process-deadline":
        modify("processes/typed-native.json", lambda d: d.update(timeout_seconds=181))
    elif label == "body-process-cwd":
        modify("body/processes/native.json", lambda d: d.update(cwd=d["cwd"] + "/different"))
    elif label == "rehashed-original-typed-output":
        name = "processes/typed-original.stdout"
        items = [json.loads(line) for line in raw(name).splitlines()]
        first = next(x for x in items if x["domain"] == "typed-object")
        first["result"]["canonical"] += " "
        data = b"".join((json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for x in items)
        change(name, data)
        modify("processes/typed-original.json", lambda d: d.update(stdout=dict(path="typed-original.stdout", **PIN(data))))
    else:
        require(label == "retired-final-archive", "unknown negative control")
        name = "body/original/final-filesystem.bin.gz"
        data = bytearray(gzip.decompress(raw(name))); data[-17] ^= 1
        changed = gzip.compress(bytes(data), mtime=0)
        change(name, changed)
        modify("body/original/retirement.json", lambda d: d.update(archive=dict(path="final-filesystem.bin.gz", **PIN(changed))))
    return changes


def core_inputs(output):
    accessed = set()
    original_regular = support.regular
    modules = (support, read_builds, read_files, read_typed, source_check, run_recipe)
    previous = {module: module.regular for module in modules}
    def tracked(path):
        path = Path(path).absolute()
        raw = original_regular(path)
        if path.is_relative_to(output):
            accessed.add(str(path.relative_to(output)))
        return raw
    try:
        for module in modules:
            module.regular = tracked
        baseline = run_recipe.core(output, require_final=False)
    finally:
        for module, function in previous.items():
            module.regular = function
    return baseline, sorted(accessed)


def run(output):
    output = Path(output).resolve(strict=True)
    require(ROOT == output / "source", "controls must run from the retained exact source snapshot")
    folder = output / "evidence-controls"
    folder.mkdir(parents=True, exist_ok=False)
    baseline, accessed = core_inputs(output)
    (folder / "baseline-report.json").write_bytes(regular(output / "result.json"))
    snapshot = folder / "replica"
    snapshot.mkdir()
    admitted = {}
    for name in sorted(accessed):
        raw = regular(output / name)
        p = snapshot / name
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("xb") as stream:
            stream.write(raw)
        admitted[name] = PIN(raw)
        require(p.stat().st_ino != (output / name).stat().st_ino and p.stat().st_nlink == 1,
                "control copy aliases original evidence")
    put(folder / "snapshot-inputs.json", {"files": admitted, "source_profile": PIN(regular(ROOT / "source-profile.json"))})
    rows = []
    def reader(label, accepted):
        directory = folder / label
        directory.mkdir(exist_ok=False)
        argv = [sys.executable, "-B", str(snapshot / "source/run_recipe.py"), "--phase", "core", "--output", str(snapshot)]
        before = time.monotonic()
        child = None
        out = err = b""
        row = {"name": label, "argv": argv, "cwd": str(folder), "timeout_seconds": 180,
            "accepted": accepted, "actual_owner_processes": 0, "timed_out": False, "reaped": False,
            "controlled_env": {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "", "LC_ALL": "C"}}
        try:
            child = subprocess.Popen(argv, cwd=folder, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                env=dict(os.environ, **row["controlled_env"]))
            row.update(pid=child.pid, process_group=os.getpgid(child.pid))
            require(row["pid"] == row["process_group"], "control reader process custody")
            try:
                out, err = child.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                out, err = child.communicate()
        finally:
            try:
                if child is not None and child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    finally:
                        out, err = child.communicate()
            finally:
                if child is not None:
                    row.update(returncode=child.returncode, reaped=child.poll() is not None)
                row.update(elapsed_seconds=time.monotonic() - before, stdout=PIN(out), stderr=PIN(err))
                (directory / "stdout").write_bytes(out)
                (directory / "stderr").write_bytes(err)
                put(directory / "process.json", row)
        require(row["timed_out"] is False and row["reaped"] is True, "control reader did not complete")
        if accepted:
            require(child.returncode == 0 and err == b"" and json.loads(out)["reader_process_launches"] == 0,
                    "independent relocated reader failed")
        else:
            require(child.returncode == 1 and (b"ValueError:" in err or b"AssertionError:" in err)
                    and b"ModuleNotFoundError" not in err and b"FileNotFoundError" not in err,
                    "data mutation did not produce a semantic reader refusal: " + label)
        rows.append(row)
    reader("relocated-admission", True)
    mutations = []
    for label in LABELS:
        changes = expected_changes(label, lambda name: regular(snapshot / name))
        saved = {}
        delta = []
        for index, (name, data) in enumerate(sorted(changes.items())):
            p = snapshot / name
            saved[name] = regular(p)
            p.write_bytes(data)
            delta_path = folder / "mutations" / label / (str(index) + ".bin")
            delta_path.parent.mkdir(parents=True, exist_ok=True)
            delta_path.write_bytes(data)
            delta.append({"path": name, "before": PIN(saved[name]), "after": PIN(data),
                "retained": str(delta_path.relative_to(folder))})
        try:
            reader(label, False)
            mutations.append({"name": label, "files": delta})
        finally:
            for name, data in saved.items():
                (snapshot / name).write_bytes(data)
    reader("restored-admission", True)
    require(admitted == {name: PIN(regular(snapshot / name)) for name in admitted}, "control snapshot was not restored exactly")
    # The exact copied fixture is no longer needed after every mutated byte and
    # complete validator process stream was retained independently above.
    shutil.rmtree(snapshot)
    result = {"schema": "hepta.runtime.rebuilt-batch-private-evidence-controls.v1", "status": "PASS",
        "admissions": 2, "refusals": 18, "control_labels": list(LABELS), "processes": rows,
        "mutations": mutations, "snapshot_files": len(admitted), "snapshot_retired_after_exact_restore": True,
        "actual_owner_processes": 0, "native_or_rust_cases_added": 0,
        "full_source_and_evidence_regular_copy": True, "public_batch_qualified": False}
    put(folder / "result.json", result)
    return result


def verify(output):
    """Re-read every control, complete mutation, and actual reader process."""
    output = Path(output).absolute()
    folder = output / "evidence-controls"
    result = read_json(folder / "result.json")
    require(result["schema"] == "hepta.runtime.rebuilt-batch-private-evidence-controls.v1"
            and result["status"] == "PASS" and result["admissions"] == 2
            and result["refusals"] == 18 and result["control_labels"] == list(LABELS),
            "fixed complete evidence-control domain")
    require(result["actual_owner_processes"] == result["native_or_rust_cases_added"] == 0
            and result["snapshot_retired_after_exact_restore"] is True
            and result["full_source_and_evidence_regular_copy"] is True
            and result["public_batch_qualified"] is False,
            "evidence-control execution/scope boundary")
    current_report = read_json(output / "result.json")
    baseline = read_json(folder / "baseline-report.json")
    expected_baseline = dict(current_report, status="VERIFYING")
    require(baseline == expected_baseline, "control baseline changed beyond final completion")
    _, accessed = core_inputs(output)
    snapshot = read_json(folder / "snapshot-inputs.json")
    admitted = {}
    def original(name):
        return regular(folder / "baseline-report.json") if name == "result.json" else regular(output / name)
    for name in accessed:
        admitted[name] = PIN(original(name))
    require(snapshot == {"files": admitted, "source_profile": PIN(regular(ROOT / "source-profile.json"))}
            and result["snapshot_files"] == len(admitted), "exact admitted copy closure")
    require(not (folder / "replica").exists(), "owned control copy was not retired")
    labels = ["relocated-admission", *LABELS, "restored-admission"]
    require(len(result["processes"]) == len(labels) and len(result["mutations"]) == len(LABELS),
            "complete control process/mutation inventory")
    producer = Path(current_report["producer_root"])
    original_folder = producer / "evidence-controls"
    expected_command = [current_report["python"], "-B", str(original_folder / "replica/source/run_recipe.py"),
                        "--phase", "core", "--output", str(original_folder / "replica")]
    for label, retained in zip(labels, result["processes"]):
        row = read_json(folder / label / "process.json")
        accepted = label in (labels[0], labels[-1])
        require(row == retained and row["name"] == label and row["accepted"] is accepted
                and row["argv"] == expected_command and row["cwd"] == str(original_folder)
                and row["timeout_seconds"] == 180 and row["actual_owner_processes"] == 0
                and row["timed_out"] is False and row["reaped"] is True,
                "actual evidence-control process identity")
        require(type(row["pid"]) is int and row["pid"] > 0 and row["pid"] == row["process_group"]
                and row["controlled_env"] == {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "", "LC_ALL": "C"},
                "owned evidence-control process/environment")
        elapsed = row["elapsed_seconds"]
        require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed < 180,
                "evidence-control deadline")
        stdout, stderr = regular(folder / label / "stdout"), regular(folder / label / "stderr")
        require(row["stdout"] == PIN(stdout) and row["stderr"] == PIN(stderr), "complete control process streams")
        if accepted:
            expected = {"status": "REBUILT_BATCH_PRIVATE_CORE_PASS", "fresh_original_build": True,
                "body_requests_per_side": 926, "typed_cases": 417, "typed_controls": 115,
                "actual_current_sdk_cases": 22, "reader_process_launches": 0,
                "public_batch_qualified": False, "gateway_caller_qualified": False, "whole_runtime_replaced": False}
            require(row["returncode"] == 0 and stderr == b"" and json.loads(stdout) == expected,
                    "actual relocated/restored admission")
        else:
            require(row["returncode"] == 1 and stdout == b""
                    and (b"ValueError:" in stderr or b"AssertionError:" in stderr)
                    and b"ModuleNotFoundError" not in stderr and b"FileNotFoundError" not in stderr,
                    "actual data-only refusal")
    for label, mutation in zip(LABELS, result["mutations"]):
        changes = expected_changes(label, original)
        expected = []
        for index, (name, data) in enumerate(sorted(changes.items())):
            relative = "mutations/" + label + "/" + str(index) + ".bin"
            require(name in admitted and regular(folder / relative) == data,
                    "complete exact data mutation: " + label)
            expected.append({"path": name, "before": PIN(original(name)), "after": PIN(data), "retained": relative})
        require(mutation == {"name": label, "files": expected}, "mutation provenance or full bytes differ")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output), sort_keys=True))
