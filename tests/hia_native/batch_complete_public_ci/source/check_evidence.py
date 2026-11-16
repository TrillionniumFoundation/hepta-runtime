#!/usr/bin/env python3
"""Relocation and rehashed-data refusals in exact independent file copies."""
from pathlib import Path
import argparse
import contextlib
import gzip
import json
import math
import shutil
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import receipt_support as support
import read_builds
import read_public
import read_stdio
import source_check
import retire_fixture
import run_recipe
from receipt_support import ROOT, PIN, SHA, regular, read_json, put, require

LABELS = ("source-comment", "rehashed-source", "compiler-stdout", "compiler-stdout-fields", "compiler-stdout-types", "compiler-receipt",
    "rehashed-compiler-tail", "rehashed-pack-workspace", "private-case-count", "rehashed-event-input",
    "rehashed-accepted-input", "private-exchange-deadline", "lane-deadline", "retired-object-omission",
    "rehashed-original-binary", "stdio-case-name")
READERS = {"source-comment": "source", "rehashed-source": "core", "compiler-stdout": "compiler",
    "compiler-stdout-fields": "compiler", "compiler-stdout-types": "compiler",
    "compiler-receipt": "compiler", "rehashed-compiler-tail": "compiler", "rehashed-pack-workspace": "native",
    "private-case-count": "private", "rehashed-event-input": "private", "rehashed-accepted-input": "private",
    "private-exchange-deadline": "private", "lane-deadline": "lane", "retired-object-omission": "retirement",
    "rehashed-original-binary": "original", "stdio-case-name": "stdio"}
ACTIVE = False


def audit(event, args):
    if ACTIVE and (event.startswith("subprocess.") or event in
            ("os.system", "os.exec", "os.posix_spawn", "os.fork", "os.forkpty")):
        raise RuntimeError("read-only qualification tried to start a process: " + event)


sys.addaudithook(audit)


@contextlib.contextmanager
def readonly():
    global ACTIVE
    prior, ACTIVE = ACTIVE, True
    try:
        yield
    finally:
        ACTIVE = prior


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def module_location(original):
    recipe = json.loads(original("result.json"))
    manifest = json.loads(original("native/public-build/public94/manifest.json"))
    member = next(row for row in manifest["members"] if row["name"] == "protocol")
    producer = Path(recipe["producer_root"])
    path = Path(member["manifest"])
    require(path.is_relative_to(producer), "control module outside declared producer")
    return path.parent.relative_to(producer).as_posix() + "/", member["source"]


def expected_changes(label, original):
    changes = {}
    def raw(name):
        return changes.get(name, original(name))
    def document(name):
        return json.loads(raw(name))
    def edit(name, action):
        row = document(name)
        action(row)
        changes[name] = encoded(row)
    module, _ = module_location(original)
    private = "public/session/native/"
    if label in ("source-comment", "rehashed-source"):
        name = "source/native-source/native/sdk_public_protocol.hepta"
        changes[name] = raw(name) + b"\n"
        if label == "rehashed-source":
            edit("source/source-profile.json", lambda r: r["files"].update({name[7:]: PIN(changes[name])}))
            edit("result.json", lambda r: r.update(source_profile=PIN(changes["source/source-profile.json"])))
    elif label == "compiler-stdout":
        edit(module + "module.stdout.log", lambda r: r.update(core_u32=r["core_u32"] + 1))
    elif label == "compiler-stdout-fields":
        edit(module + "module.stdout.log", lambda r: (r.pop("abi_status"), r.update(undeclared=None)))
    elif label == "compiler-stdout-types":
        edit(module + "module.stdout.log", lambda r: r.update(abi_status=False))
    elif label == "compiler-receipt":
        edit(module + "module.receipt.json", lambda r: r.update(core_u32=r["core_u32"] + 1))
        edit(module + "build.json", lambda r: r.update(compile_receipt=document(module + "module.receipt.json")))
    elif label == "rehashed-compiler-tail":
        name = module + "module.output.bin"
        changed = bytearray(raw(name)); changed[-1] ^= 1
        changes[name] = bytes(changed)
        for receipt in ("module.receipt.json", "module.stdout.log"):
            edit(module + receipt, lambda r: r.update(output_sha256=SHA(changes[name])))
        edit(module + "build.json", lambda r: r.update(compile_receipt=document(module + "module.receipt.json")))
    elif label == "rehashed-pack-workspace":
        name = "native/public-build/public94/pack.workspace.bin"
        changed = bytearray(raw(name)); changed[-1] ^= 1
        changes[name] = bytes(changed)
        receipt_name = "native/public-build/public94/pack.receipt.json"
        edit(receipt_name, lambda r: r.update(workspace_sha256=SHA(changes[name])))
        manifest_name = "native/public-build/public94/manifest.json"
        edit(manifest_name, lambda r: r.update(pack=document(receipt_name)))
        edit("native/BUILD.json", lambda r: r["graphs"]["public"].update(manifest_pin=PIN(changes[manifest_name])))
    elif label == "private-case-count":
        edit(private + "result.json", lambda r: r.update(completed_cases=16))
    elif label == "rehashed-event-input":
        name = private + "events.jsonl.gz"
        rows = [json.loads(line) for line in gzip.decompress(raw(name)).splitlines()]
        rows[0]["input"]["sha256"] = "0" * 64
        data = b"".join(read_public.common.canonical(row) for row in rows)
        changes[name] = gzip.compress(data, mtime=0)
        edit(private + "result.json", lambda r: r["events"].update(compressed=PIN(changes[name]), uncompressed=PIN(data)))
    elif label == "rehashed-accepted-input":
        name = private + "process/stdin.bin.gz"
        data = bytearray(gzip.decompress(raw(name))); data[-1] ^= 1
        data = bytes(data); changes[name] = gzip.compress(data, mtime=0)
        edit(private + "process/process.json", lambda r: r["streams"]["stdin"].update(
            compressed=PIN(changes[name]), uncompressed=PIN(data)))
        edit(private + "result.json", lambda r: r.update(process=document(private + "process/process.json")))
    elif label == "private-exchange-deadline":
        edit(private + "process/exchanges.json", lambda r: r[0].update(deadline_seconds=61))
    elif label == "lane-deadline":
        edit("public/session/native.lane.json", lambda r: r.update(outer_lane_deadline_seconds=181))
    elif label == "retired-object-omission":
        edit(private + "retirement.json", lambda r: r["removed"].pop())
    elif label == "rehashed-original-binary":
        name = "hepta-batch-sdk-current-original-oracle"
        data = bytearray(raw("original/bin/" + name)); data[-1] ^= 1; data = bytes(data)
        changes["original/bin/" + name] = changes["original/target/release/" + name] = data
        edit("original/BUILD.json", lambda r: r["binaries"].update({name: {"path": "bin/" + name, **PIN(data)}}))
    else:
        require(label == "stdio-case-name", "unknown fixed evidence refusal")
        edit("stdio/legacy/native/result.json", lambda r: r["events"][2].update(name="another-case"))
    return changes


def dispatch(kind, output):
    output = Path(output)
    source = output / "source"
    if kind == "source":
        return source_check.check(source)
    if kind == "core":
        return run_recipe.core(output, require_final=False)
    if kind == "compiler":
        relative, name = module_location(lambda p: regular(output / p))
        return read_builds.compiler(output / relative, regular(source / "native-source" / name))
    if kind == "native":
        return read_builds.native(output / "native", source)
    if kind == "original":
        return read_builds.original(output / "original", source / "original-reference")
    graphs = read_json(output / "native/BUILD.json")["graphs"]
    folder = output / "public/session/native"
    if kind == "private":
        return read_public.inspect(folder, source, expected_binary=graphs["private"]["elf_pin"])
    if kind == "retirement":
        return retire_fixture.verify(folder, read_json(folder / "result.json"))
    if kind == "stdio":
        return read_stdio.inspect(output / "stdio/legacy/native", source, graphs["public"]["elf_pin"])
    require(kind == "lane", "unknown strict reader selection")
    producer = Path(read_json(output / "result.json")["producer_root"])
    return run_recipe.check_lane(folder, "private", "native", "session",
        producer / "native" / graphs["private"]["elf"], producer, source)


def core_inputs(output):
    output = Path(output).absolute()
    accessed = set()
    previous_regular = support.regular
    modules = (support, read_builds, read_public, read_stdio, source_check, retire_fixture, run_recipe)
    previous = {module: module.regular for module in modules}
    def tracked(path):
        path = Path(path).absolute()
        raw = previous_regular(path)
        if path.is_relative_to(output):
            accessed.add(path.relative_to(output).as_posix())
        return raw
    try:
        for module in modules:
            module.regular = tracked
        with readonly():
            result = run_recipe.core(output, require_final=False)
    finally:
        for module, function in previous.items():
            module.regular = function
    # Every source is admitted explicitly; pure authoring reads may bypass the
    # regular-file helper, but may never widen this frozen source declaration.
    profile = source_check.check(output / "source")
    accessed.update("source/" + name for name in ["source-profile.json", *profile["files"]])
    return result, sorted(accessed)


def run(output):
    output = Path(output).resolve(strict=True)
    require(ROOT == output / "source", "controls must run from the copied frozen source")
    folder = output / "evidence-controls"
    folder.mkdir(exist_ok=False)
    _, accessed = core_inputs(output)
    (folder / "baseline-report.json").write_bytes(regular(output / "result.json"))
    replica = folder / "replica"
    replica.mkdir()
    admitted = {}
    for name in accessed:
        raw = regular(output / name)
        destination = replica / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(raw)
        require(destination.stat().st_nlink == 1 and destination.stat().st_ino != (output / name).stat().st_ino,
            "control copy aliases retained evidence")
        admitted[name] = PIN(raw)
    put(folder / "snapshot-inputs.json", {"files": admitted, "source_profile": PIN(regular(ROOT / "source-profile.json"))})
    rows, mutations = [], []
    def observe(label, kind, accepted):
        started = time.monotonic()
        error = None
        try:
            with readonly():
                dispatch(kind, replica)
        except (ValueError, AssertionError) as caught:
            error = {"type": type(caught).__name__, "message": str(caught)}
        require((error is None) == accepted, "strict data-only control result: " + label)
        row = {"name": label, "reader": kind, "accepted": accepted, "error": error,
            "elapsed_seconds": time.monotonic() - started, "execution_kind": "in_process_readonly_reader",
            "process_launches": 0, "process_audit_guard_enabled": True}
        put(folder / (label + ".json"), row)
        rows.append(row)
    observe("relocated-admission", "core", True)
    for label in LABELS:
        changes = expected_changes(label, lambda name: regular(replica / name))
        saved, delta = {}, []
        for index, (name, data) in enumerate(sorted(changes.items())):
            require(name in admitted, "mutation escaped complete admitted evidence")
            saved[name] = regular(replica / name)
            (replica / name).write_bytes(data)
            retained = "mutations/" + label + "/" + str(index) + ".bin"
            (folder / retained).parent.mkdir(parents=True, exist_ok=True)
            (folder / retained).write_bytes(data)
            delta.append({"path": name, "before": PIN(saved[name]), "after": PIN(data), "retained": retained})
        try:
            observe(label, READERS[label], False)
            mutations.append({"name": label, "files": delta})
        finally:
            for name, raw in saved.items():
                (replica / name).write_bytes(raw)
    observe("restored-admission", "core", True)
    require(admitted == {name: PIN(regular(replica / name)) for name in admitted}, "independent copy was not restored")
    shutil.rmtree(replica)
    result = {"schema": "hepta.runtime.batch-public-evidence-controls.v1", "status": "PASS",
        "admissions": 2, "refusals": len(LABELS), "control_labels": list(LABELS), "observations": rows,
        "mutations": mutations, "snapshot_files": len(admitted), "snapshot_retired_after_exact_restore": True,
        "independent_regular_copies": True, "actual_owner_processes": 0, "native_or_rust_cases_added": 0,
        "public_batch_qualified": False, "whole_runtime_replaced": False}
    put(folder / "result.json", result)
    return result


def verify(output):
    """Read controls and every complete mutation without writing or launching."""
    output = Path(output).absolute()
    folder = output / "evidence-controls"
    result = read_json(folder / "result.json")
    require(result["schema"] == "hepta.runtime.batch-public-evidence-controls.v1" and result["status"] == "PASS"
        and result["admissions"] == 2 and result["refusals"] == len(LABELS)
        and result["control_labels"] == list(LABELS) and result["actual_owner_processes"] == 0
        and result["native_or_rust_cases_added"] == 0 and result["snapshot_retired_after_exact_restore"] is True
        and result["independent_regular_copies"] is True and result["public_batch_qualified"] is False
        and result["whole_runtime_replaced"] is False, "complete evidence-control scope")
    require(read_json(folder / "baseline-report.json") == dict(read_json(output / "result.json"), status="VERIFYING"),
        "control baseline changed beyond recipe completion")
    _, accessed = core_inputs(output)
    def original(name):
        return regular(folder / "baseline-report.json") if name == "result.json" else regular(output / name)
    admitted = {name: PIN(original(name)) for name in accessed}
    require(read_json(folder / "snapshot-inputs.json") == {"files": admitted,
        "source_profile": PIN(regular(ROOT / "source-profile.json"))}
        and result["snapshot_files"] == len(admitted) and not (folder / "replica").exists(), "exact independent snapshot closure")
    labels = ["relocated-admission", *LABELS, "restored-admission"]
    require(len(result["observations"]) == len(labels) and len(result["mutations"]) == len(LABELS), "complete fixed control set")
    for label, actual in zip(labels, result["observations"], strict=True):
        accepted = label in (labels[0], labels[-1])
        row = read_json(folder / (label + ".json"))
        require(row == actual and row["name"] == label and row["reader"] == ("core" if accepted else READERS[label])
            and row["accepted"] is accepted and row["execution_kind"] == "in_process_readonly_reader"
            and row["process_launches"] == 0 and row["process_audit_guard_enabled"] is True
            and read_public.number(row["elapsed_seconds"], 180), "actual strict reader observation")
        require(row["error"] is None if accepted else type(row["error"]) is dict
            and set(row["error"]) == {"type", "message"} and row["error"]["type"] in ("ValueError", "AssertionError")
            and type(row["error"]["message"]) is str and bool(row["error"]["message"]), "semantic data refusal")
    for label, mutation in zip(LABELS, result["mutations"], strict=True):
        changes = expected_changes(label, original)
        expected = []
        for index, (name, data) in enumerate(sorted(changes.items())):
            retained = "mutations/" + label + "/" + str(index) + ".bin"
            require(name in admitted and regular(folder / retained) == data, "exact complete retained mutation")
            expected.append({"path": name, "before": PIN(original(name)), "after": PIN(data), "retained": retained})
        require(mutation == {"name": label, "files": expected}, "complete mutation provenance")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output), sort_keys=True))
