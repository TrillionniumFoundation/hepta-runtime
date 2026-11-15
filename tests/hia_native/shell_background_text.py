"""Native background resource rendering and complete byte evidence.

The development expectations use Python's UTF-8 replacement operation. The
original Rust comparison is a separate qualification; this module never marks
that comparison or production routing complete.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import re
import shutil
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve()
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
Q = lambda value: struct.pack("<Q", value)
MASK = (1 << 64) - 1
INVALID, CAPACITY = 0xffffffff, 0xfffffffe
PREFIX = b"octofs://jobs/"
LABEL = b"\n\nstderr:\n"
MARKER = "\n[earlier output dropped — showing the last 30000 bytes]".encode()
SCOPE = {
    "original_rust_compared": False, "filesystem_reads_qualified": False,
    "production_activated": False, "whole_runtime_replaced": False,
    "old_stack_removal_qualified": False,
}

def need(value, message):
    if not value:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, "duplicate JSON field")
        result[key] = value
    return result

def obj(raw):
    return json.loads(raw, object_pairs_hook=pairs)

def raw_file(path):
    path = Path(path)
    need(stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink(),
         "evidence is not an ordinary file")
    return path.read_bytes()

def pin(path):
    raw = raw_file(path)
    return {"size": len(raw), "sha256": digest(raw)}

def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")

def hx(value):
    need(type(value) is str, "hex field type")
    raw = bytes.fromhex(value)
    need(raw.hex() == value, "noncanonical hex")
    return raw

def source_files():
    return {name: pin(ROOT / name) for name in (
        "native/shell_background_text.hepta", "native/shell_background_text_abi.md",
        "tests/hia_native/shell_background_text.py", "scripts/hia_native_loader.py",
    )}

def frame(*, op=1, known=1, status=0, code=0, out_truncated=0, err_truncated=0,
          ident=b"id", command=b"command", out=b"", err=b""):
    return (b"HSHBGT01" + struct.pack("<10Q", op, known, status, code & MASK,
            out_truncated, err_truncated, len(ident), len(command), len(out), len(err))
            + ident + command + out + err)

def definition(name, **fields):
    return {"name": name, "fields": fields}

def expected(fields):
    op, known = fields.get("op", 1), fields.get("known", 1)
    ident, command = fields.get("ident", b"id"), fields.get("command", b"command")
    output, text, uri = b"", b"", b""
    present, truncated, workspace = 1, 0, 0
    if op == 3:
        uri = PREFIX + ident
    elif op == 4:
        present = int(ident.startswith(PREFIX))
        uri = ident[len(PREFIX):] if present else b""
    elif not known:
        present = 0
    else:
        out, err = fields.get("out", b""), fields.get("err", b"")
        a, b = fields.get("out_truncated", 0), fields.get("err_truncated", 0)
        if op == 1:
            a, b = int(len(out) > 30000), int(len(err) > 30000)
            out, err = out[-30000:], err[-30000:]
        out = out.decode("utf-8", "replace").encode("utf-8")
        err = err.decode("utf-8", "replace").encode("utf-8")
        combined = out if not err else err if not out else out + LABEL + err
        workspace = len(combined)
        c = int(len(combined) > 30000)
        output = combined[-30000:].decode("utf-8", "replace").encode("utf-8") if c else combined
        truncated = int(bool(a or b or c))
        status = (b"running" if fields.get("status", 0) == 0
                  else b"exited with code " + str(fields.get("code", 0)).encode())
        text = (b"job " + ident + b"\ncommand: " + command + b"\nstatus: " + status
                + (MARKER if truncated else b"") + b"\n\n" + output)
        uri = PREFIX + ident
    body = (b"HSHBGR01" + struct.pack("<5Q", present, truncated, len(output), len(text), len(uri))
            + output + text + uri)
    return body, workspace

def specifications():
    rows = []
    for op in (1, 2):
        rows.append(definition("unknown-" + str(op), op=op, known=0, ident=b"", command=b""))
        rows.append(definition("empty-" + str(op), op=op))
    codes = (-2147483648, -2147483647, -1000000000, -100, -10, -1, 0, 1, 9, 10, 99, 100,
             999999999, 1000000000, 2147483646, 2147483647)
    for code in codes:
        rows.append(definition("exit-code-" + str(code), status=1, code=code))
    ids = (b"", b"1-2", b"../x", b"a?x#frag%20", b"a\0b\n", "作业/🌍".encode(), PREFIX)
    for i, ident in enumerate(ids):
        rows.append(definition("uri-" + str(i), op=3, known=0, ident=ident, command=b""))
        rows.append(definition("parse-" + str(i), op=4, known=0, ident=PREFIX + ident, command=b""))
    for i, uri in enumerate((b"", b"octofs://job/", b"OCTOFS://jobs/id", b" octofs://jobs/id",
                              b"octofs://jobs", b"octofs:/jobs/id", b"x" + PREFIX)):
        rows.append(definition("parse-mismatch-" + str(i), op=4, known=0, ident=uri, command=b""))
    samples = (b"", b"a", b"\n\n", b"\r\n", b"\x1b[31mred\x1b[0m\r\n",
               b"\xff", b"\xe2\x82", b"\xe2\x82A", "🌍".encode())
    for i, out in enumerate(samples):
        for j, err in enumerate(samples):
            rows.append(definition("stream-combination-%d-%d" % (i, j), out=out, err=err))
    for value in range(256):
        rows.append(definition("byte-%d" % value, op=2, out=bytes([value])))
    for lead in (0xc0, 0xc2, 0xdf, 0xe0, 0xed, 0xef, 0xf0, 0xf4, 0xf5):
        for second in range(256):
            rows.append(definition("pair-%d-%d" % (lead, second), op=2, out=bytes([lead, second])))
    for lead, second in ((0xe0, 0x9f), (0xe0, 0xa0), (0xed, 0x9f), (0xed, 0xa0),
                         (0xf0, 0x8f), (0xf0, 0x90), (0xf4, 0x8f), (0xf4, 0x90)):
        for third in (0, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xff):
            rows.append(definition("triple-%d-%d-%d" % (lead, second, third),
                                   op=2, out=bytes([lead, second, third])))
            rows.append(definition("quad-%d-%d-%d" % (lead, second, third),
                                   op=2, out=bytes([lead, second, third, 0x80])))
    for n in (29989, 29990, 29999, 30000, 30001, 30002, 59999, 60000, 60001):
        for op in (1, 2):
            rows.append(definition("ascii-tail-%d-%d" % (op, n), op=op, out=b"a" * n))
            rows.append(definition("labeled-tail-%d-%d" % (op, n), op=op, out=b"x", err=b"e" * n))
            rows.append(definition("lossy-tail-%d-%d" % (op, n), op=op, out=b"\xff" * n))
    for unit in ("é".encode(), "€".encode(), "🌍".encode(), b"\xe2\x82"):
        for shift in range(5):
            data = b"x" * shift + unit * 15001
            for op in (1, 2):
                rows.append(definition("multibyte-tail-%d-%s-%d" % (op, unit.hex(), shift),
                                       op=op, out=data))
    rows.append(definition("second-lossy-expands-to-30006", op=2,
                           out=b"x" + "🌍".encode() + b"a" * 29997))
    rows.append(definition("lossy-label-combined-boundary", op=2, out=b"a" * 29988, err=b"\xff"))
    rows.append(definition("observed-seek-failure-large-result", op=2, out=b"x" * 100123,
                           err=b"\xff" * 10101, out_truncated=1))
    for a in (0, 1):
        for b in (0, 1):
            rows.append(definition("observed-flags-%d-%d" % (a, b), op=2,
                                   out_truncated=a, err_truncated=b))
    rows.append(definition("unbounded-metadata", ident=("作业\0\n" * 5001).encode(),
                           command=(b"\r\n\x1b[31mcommand\0" * 3001), out=b"last\n"))
    rng = random.Random(0x4853484247543031)
    for i in range(512):
        op = rng.choice((1, 2))
        fields = dict(op=op, ident=rng.choice(ids), command=rng.choice(samples[:5]),
                      out=rng.randbytes(rng.randrange(129)), err=rng.randbytes(rng.randrange(129)),
                      status=1, code=rng.randrange(-(1 << 31), 1 << 31))
        if op == 2:
            fields.update(out_truncated=rng.randrange(2), err_truncated=rng.randrange(2))
        rows.append(definition("random-%03d" % i, **fields))
    need(len({row["name"] for row in rows}) == len(rows), "duplicate semantic case")
    return rows

def control_specifications():
    base = frame()
    rows = []
    def invalid(name, wire):
        rows.append({"name": name, "wire": wire, "output": 256, "workspace": 256, "return": INVALID})
    invalid("empty-frame", b"")
    invalid("short-header", base[:87])
    invalid("wrong-magic", b"X" + base[1:])
    invalid("trailing-byte", base + b"x")
    for at, values in (
        (8, (0, 5, MASK)), (16, (2, MASK)), (24, (2, MASK)), (32, (1, MASK)),
        (40, (2, MASK)), (48, (2, MASK)),
        (56, (MASK, MASK - 80)), (64, (MASK,)), (72, (MASK,)), (80, (MASK,)),
    ):
        for value in values:
            invalid("header-%d-%d" % (at, value), base[:at] + Q(value) + base[at + 8:])
    invalid("invalid-id-utf8", frame(ident=b"\xff"))
    invalid("invalid-command-utf8", frame(command=b"\xf0\x80"))
    invalid("invalid-i32-positive", frame(status=1, code=2147483648))
    invalid("invalid-i32-zero-extended-negative", frame(status=1, code=0xffffffff))
    invalid("snapshot-supplied-truncated", frame(out_truncated=1))
    invalid("unknown-with-command", frame(known=0))
    invalid("unknown-with-status", frame(known=0, command=b"", status=1))
    invalid("uri-with-known", frame(op=3, command=b""))
    invalid("parse-with-logs", frame(op=4, known=0, command=b"", out=b"x"))
    selected = (
        definition("empty-known"),
        definition("both-streams", out=b"hello", err=b"\xff\xe2\x82"),
        definition("second-expansion", op=2, out=b"x" + "🌍".encode() + b"a" * 29997),
        definition("uri-empty", op=3, known=0, ident=b"", command=b""),
        definition("parse-empty", op=4, known=0, ident=PREFIX, command=b""),
        definition("unknown", known=0, command=b""),
    )
    for item in selected:
        body, workspace = expected(item["fields"])
        wire = frame(**item["fields"])
        rows.append({"name": item["name"] + "-output-zero", "wire": wire,
                     "output": 0, "workspace": workspace, "return": CAPACITY})
        rows.append({"name": item["name"] + "-output-minus-one", "wire": wire,
                     "output": len(body) - 1, "workspace": workspace, "return": CAPACITY})
        if workspace:
            rows.append({"name": item["name"] + "-workspace-minus-one", "wire": wire,
                         "output": len(body) + 13, "workspace": workspace - 1, "return": CAPACITY})
        rows.append({"name": item["name"] + "-exact-capacities", "wire": wire,
                     "output": len(body), "workspace": workspace, "return": len(body), "body": body})
    return rows

def check_corpus(case_rows, control_rows, requests, responses):
    expected_requests, at = bytearray(), 0
    cases = specifications()
    need(type(case_rows) is list and len(case_rows) == len(cases), "semantic inventory")
    for index, (row, case) in enumerate(zip(case_rows, cases)):
        wire = frame(**case["fields"])
        body, workspace = expected(case["fields"])
        expected_requests.extend(Q(len(wire)) + wire)
        need(row["index"] == index and row["name"] == case["name"], "semantic order")
        need(row["source_and_buffer_guards_checked_by_loader"] is True, "native guards not observed")
        need(row["output_capacity"] == len(body) + 17
             and row["workspace_capacity"] == workspace + 13, "semantic capacities")
        need(hx(row["output_tail_hex"]) == b"\xa7" * 17, "output tail changed")
        need(len(responses) - at >= 16, "missing actual response header")
        returned, count = struct.unpack_from("<2Q", responses, at)
        at += 16
        need(returned == count == len(body) == row["return_u64"], "full native return differs")
        need(responses[at:at + count] == body, "complete native body differs")
        at += count
    need(at == len(responses), "extra actual response bytes")
    need(bytes(expected_requests) == requests, "complete actual requests differ")
    controls = control_specifications()
    need(type(control_rows) is list and len(control_rows) == len(controls), "control inventory")
    for row, control in zip(control_rows, controls):
        need(row["name"] == control["name"] and hx(row["input_hex"]) == control["wire"],
             "control input differs")
        need(row["output_capacity"] == control["output"] and row["workspace_capacity"] == control["workspace"],
             "control capacity differs")
        need(row["source_and_buffer_guards_checked_by_loader"] is True, "control guards not observed")
        need(type(row["return_u64"]) is int and row["return_u64"] == control["return"],
             "control full return differs")
        before, after = hx(row["output_before_hex"]), hx(row["output_after_hex"])
        need(before == b"\xa7" * control["output"] and len(after) == len(before), "control extent")
        if control["return"] in (INVALID, CAPACITY):
            need(after == before, "refusal published output")
        else:
            need(after == control["body"], "exact capacity body differs")
    return {
        "semantic_cases": len(cases), "controls": len(controls),
        "invalid_controls": sum(row["return"] == INVALID for row in controls),
        "capacity_refusals": sum(row["return"] == CAPACITY for row in controls),
        "exact_capacity_successes": sum(row["return"] < 0xfffffff0 for row in controls),
        "native_entries": len(cases) + len(controls),
    }

def composition_check():
    paths = {
        "native/shell_gate.hepta": "52682cdf9e13a3eaf3ad8f168112531b2f918ed6139f06b769665a2ddaec05d1",
        "native/policy.hepta": "57d64450b81a46b92687a3efec056e2491e4c4a4ffde57a0999124d6bb0736d0",
    }
    def function(raw, name):
        text = raw.decode("utf-8")
        start = text.index("\nfn " + name + "(") + 1
        return text[start:text.index("\nend\n", start) + 5]
    target = raw_file(ROOT / "native/shell_background_text.hepta")
    rows = []
    for path, old, new, mutable in (
        ("native/shell_gate.hepta", "f62", "f19", False),
        ("native/shell_gate.hepta", "f63", "f20", False),
        ("native/shell_gate.hepta", "f65", "f21", False),
        ("native/policy.hepta", "f18", "f22", False),
        ("native/policy.hepta", "f18", "f23", True),
    ):
        raw = raw_file(ROOT / path)
        need(digest(raw) == paths[path], "imported helper source changed")
        expected_function = function(raw, old).replace("fn " + old + "(", "fn " + new + "(", 1)
        if mutable:
            expected_function = expected_function.replace(":readbuf", ":mutbuf")
        actual = function(target, new)
        need(actual == expected_function, "imported helper instruction/control flow differs")
        rows.append({"source": path, "source_sha256": paths[path], "original": old,
                     "destination": new, "private_buffer_type_change": mutable,
                     "actual_function_sha256": digest(actual.encode())})
    return rows

def native_binding(path):
    path = Path(path).resolve(strict=True)
    metadata = obj(raw_file(path))
    need(metadata.get("schema") == "hepta.runtime.native-module.v1"
         and metadata.get("abi") == "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
         and metadata.get("compiler_commit") == COMPILER
         and metadata.get("target") == "linux-x86_64", "native renderer ABI/compiler")
    for key in ("source", "image"):
        name = metadata.get(key)
        need(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name),
             "native member is not a plain basename")
        need(pin(path.parent / name)["sha256"] == metadata.get(key + "_sha256"),
             "native renderer member changed")
    need(pin(path.parent / metadata["source"]) == pin(ROOT / "native/shell_background_text.hepta"),
         "native renderer does not match current source")
    return {"manifest": pin(path), "source": pin(path.parent / metadata["source"]),
            "image": pin(path.parent / metadata["image"]), "manifest_path": str(path)}, metadata

def execute_child(folder):
    folder = Path(folder).resolve(strict=True)
    spec = importlib.util.spec_from_file_location("background_native_loader", folder / "hia_native_loader.py")
    need(spec is not None and spec.loader is not None, "cannot load recorded native loader")
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    manifest = folder / "native/manifest.json"
    cases, controls = [], []
    requests, responses = bytearray(), bytearray()
    with loader.NativeModule(manifest, manifest_sha256=digest(raw_file(manifest))) as module:
        for index, case in enumerate(specifications()):
            wire = frame(**case["fields"])
            body, workspace = expected(case["fields"])
            returned, output, work = module.invoke_raw(
                wire, output_capacity=len(body) + 17, workspace_capacity=workspace + 13,
                output_fill=0xa7, workspace_fill=0xd3,
            )
            need(returned == len(body) and output[:returned] == body,
                 "actual native semantic mismatch: " + case["name"])
            need(output[returned:] == b"\xa7" * 17, "actual native output tail changed")
            requests.extend(Q(len(wire)) + wire)
            responses.extend(Q(returned) + Q(returned) + output[:returned])
            cases.append({
                "index": index, "name": case["name"], "return_u64": returned,
                "output_capacity": len(output), "workspace_capacity": len(work),
                "output_tail_hex": output[returned:].hex(),
                "source_and_buffer_guards_checked_by_loader": True,
            })
        for control in control_specifications():
            returned, output, work = module.invoke_raw(
                control["wire"], output_capacity=control["output"], workspace_capacity=control["workspace"],
                output_fill=0xa7, workspace_fill=0xd3,
            )
            controls.append({
                "name": control["name"], "input_hex": control["wire"].hex(),
                "return_u64": returned, "output_capacity": len(output), "workspace_capacity": len(work),
                "output_before_hex": (b"\xa7" * control["output"]).hex(),
                "output_after_hex": output.hex(),
                "source_and_buffer_guards_checked_by_loader": True,
            })
    facts = check_corpus(cases, controls, bytes(requests), bytes(responses))
    (folder / "requests.bin").write_bytes(requests)
    (folder / "responses.bin").write_bytes(responses)
    result = {
        "schema": "hepta.runtime.shell-background-text-native.v1", "status": "PASS",
        "comparison": "python-development-model", "cases": cases, "controls": controls, "counts": facts,
        "driver": pin(SOURCE), "loader": pin(folder / "hia_native_loader.py"),
        "manifest": pin(manifest), "requests": pin(folder / "requests.bin"),
        "responses": pin(folder / "responses.bin"), **SCOPE,
    }
    write_json(folder / "native-results.json", result)
    return {"status": "PASS", "result": pin(folder / "native-results.json"),
            "result_file": "native-results.json", "counts": facts}

def reader_controls(result, requests, responses):
    rows = []
    for name in ("missing_case", "output_tail_write", "false_guard_flag",
                 "refusal_output_write", "response_body_write"):
        changed = copy.deepcopy(result)
        changed_responses = responses
        if name == "missing_case":
            changed["cases"].pop()
        elif name == "output_tail_write":
            changed["cases"][0]["output_tail_hex"] = (b"\0" + b"\xa7" * 16).hex()
        elif name == "false_guard_flag":
            changed["cases"][0]["source_and_buffer_guards_checked_by_loader"] = False
        elif name == "refusal_output_write":
            row = changed["controls"][0]
            raw = bytearray(hx(row["output_after_hex"]))
            raw[0] ^= 1
            row["output_after_hex"] = raw.hex()
        else:
            raw = bytearray(responses)
            raw[16] ^= 1
            changed_responses = bytes(raw)
        try:
            check_corpus(changed["cases"], changed["controls"], requests, changed_responses)
        except ValueError as error:
            rows.append({"name": name, "rejected": True, "reason": str(error)})
        else:
            raise ValueError("reader accepted changed evidence: " + name)
    return rows

def run(native_manifest, output):
    binding, metadata = native_binding(native_manifest)
    source_pins, composition = source_files(), composition_check()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "native").mkdir()
    manifest = Path(native_manifest).resolve()
    copies = {
        "renderer_driver.py": SOURCE, "hia_native_loader.py": ROOT / "scripts/hia_native_loader.py",
        "native/manifest.json": manifest,
        "native/" + metadata["source"]: manifest.parent / metadata["source"],
        "native/" + metadata["image"]: manifest.parent / metadata["image"],
    }
    for name, source in copies.items():
        shutil.copyfile(source, output / name)
    command = [sys.executable, str(output / "renderer_driver.py"), "--_execute", str(output)]
    environment = os.environ.copy()
    environment.pop("PYTHONOPTIMIZE", None)
    started = time.monotonic_ns()
    process = subprocess.Popen(command, cwd=output, env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    finished = time.monotonic_ns()
    (output / "stdout.bin").write_bytes(stdout)
    (output / "stderr.bin").write_bytes(stderr)
    receipt = {
        "schema": "hepta.runtime.shell-background-text-execution.v1",
        "command": command, "cwd": str(output), "pid": process.pid,
        "started_ns": started, "finished_ns": finished, "elapsed_ns": finished - started,
        "returncode": process.returncode, "completed": True, "timed_out": timed_out,
        "stdout": pin(output / "stdout.bin"), "stderr": pin(output / "stderr.bin"), **SCOPE,
    }
    write_json(output / "process.json", receipt)
    need(process.returncode == 0 and not timed_out and not stderr,
         "actual native renderer child did not finish successfully")
    need(source_files() == source_pins and native_binding(native_manifest)[0] == binding
         and composition_check() == composition, "source/image changed during execution")
    files = tuple(copies) + ("stdout.bin", "stderr.bin", "process.json", "native-results.json",
                            "requests.bin", "responses.bin")
    write_json(output / "report.json", {
        "schema": "hepta.runtime.shell-background-text-evidence.v1", "status": "PASS",
        "source_files": source_pins, "composition": composition, "native": binding,
        "recorded_directory": str(output), "files": {name: pin(output / name) for name in files},
        **SCOPE,
    })
    return read_evidence(output, native_manifest)

def read_evidence(folder, native_manifest=None):
    """Rebuild complete expectations and inspect recorded bytes; no native execution."""
    folder = Path(folder).resolve(strict=True)
    report = obj(raw_file(folder / "report.json"))
    need(report.get("schema") == "hepta.runtime.shell-background-text-evidence.v1"
         and report.get("status") == "PASS", "evidence schema/status")
    need(all(report.get(key) is value for key, value in SCOPE.items()), "overstated scope")
    need(report.get("source_files") == source_files()
         and report.get("composition") == composition_check(), "current renderer source differs")
    metadata = obj(raw_file(folder / "native/manifest.json"))
    need(metadata.get("schema") == "hepta.runtime.native-module.v1"
         and metadata.get("abi") == "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
         and metadata.get("compiler_commit") == COMPILER
         and metadata.get("target") == "linux-x86_64", "copied native ABI/compiler")
    for key in ("source", "image"):
        need(type(metadata.get(key)) is str
             and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", metadata[key]), "native member path")
    expected_files = {
        "renderer_driver.py", "hia_native_loader.py", "native/manifest.json",
        "native/" + metadata["source"], "native/" + metadata["image"],
        "stdout.bin", "stderr.bin", "process.json", "native-results.json", "requests.bin", "responses.bin",
    }
    need(type(report.get("files")) is dict and set(report["files"]) == expected_files,
         "evidence file inventory")
    for name in expected_files:
        need(pin(folder / name) == report["files"][name], "evidence member changed: " + name)
    need(pin(folder / "renderer_driver.py") == pin(SOURCE), "executed driver differs")
    need(pin(folder / "hia_native_loader.py") == pin(ROOT / "scripts/hia_native_loader.py"),
         "executed loader differs")
    need(pin(folder / "native" / metadata["source"]) == pin(ROOT / "native/shell_background_text.hepta"),
         "executed HIA source differs")
    for key in ("source", "image"):
        actual = pin(folder / "native" / metadata[key])
        need(actual["sha256"] == metadata.get(key + "_sha256")
             and actual == report["native"][key], "copied native source/image differs")
    need(pin(folder / "native/manifest.json") == report["native"]["manifest"], "copied manifest differs")
    if native_manifest is not None:
        current, _ = native_binding(native_manifest)
        for key in ("manifest", "source", "image"):
            need(current[key] == report["native"][key], "current native artifact differs")
    receipt = obj(raw_file(folder / "process.json"))
    need(receipt.get("schema") == "hepta.runtime.shell-background-text-execution.v1"
         and receipt.get("completed") is True and receipt.get("timed_out") is False
         and type(receipt.get("returncode")) is int and receipt["returncode"] == 0,
         "actual native process not completed")
    need(all(receipt.get(key) is value for key, value in SCOPE.items()), "process scope differs")
    directory = report["recorded_directory"]
    need(type(directory) is str and Path(directory).is_absolute(), "recorded directory")
    command = receipt["command"]
    need(type(command) is list and len(command) == 4 and Path(command[0]).is_absolute()
         and command[1:] == [str(Path(directory) / "renderer_driver.py"), "--_execute", directory]
         and receipt["cwd"] == directory, "actual invocation differs")
    need(type(receipt.get("pid")) is int and receipt["pid"] > 0, "actual process PID")
    need(type(receipt["started_ns"]) is int and type(receipt["finished_ns"]) is int
         and receipt["finished_ns"] >= receipt["started_ns"]
         and receipt["elapsed_ns"] == receipt["finished_ns"] - receipt["started_ns"],
         "actual process timing differs")
    need(receipt["stdout"] == pin(folder / "stdout.bin")
         and receipt["stderr"] == pin(folder / "stderr.bin")
         and raw_file(folder / "stderr.bin") == b"", "actual process streams differ")
    summary = obj(raw_file(folder / "stdout.bin"))
    need(summary.get("status") == "PASS" and summary.get("result_file") == "native-results.json"
         and summary.get("result") == pin(folder / "native-results.json"), "child stdout differs")
    actual = obj(raw_file(folder / "native-results.json"))
    need(actual.get("schema") == "hepta.runtime.shell-background-text-native.v1"
         and actual.get("status") == "PASS" and actual.get("comparison") == "python-development-model",
         "actual corpus schema/status")
    need(all(actual.get(key) is value for key, value in SCOPE.items()), "actual corpus scope")
    for key, file in (("driver", "renderer_driver.py"), ("loader", "hia_native_loader.py"),
                      ("manifest", "native/manifest.json"), ("requests", "requests.bin"),
                      ("responses", "responses.bin")):
        need(actual.get(key) == pin(folder / file), "actual corpus source/stream binding")
    requests, responses = raw_file(folder / "requests.bin"), raw_file(folder / "responses.bin")
    counts = check_corpus(actual["cases"], actual["controls"], requests, responses)
    need(actual["counts"] == counts == summary["counts"], "actual corpus counts differ")
    controls = reader_controls(actual, requests, responses)
    return {
        "status": "PASS", "schema": "hepta.runtime.shell-background-text-readback.v1",
        "verification": "portable-complete-byte-evidence", "counts": counts,
        "reader_control_count": len(controls), "reader_controls": controls,
        "source_sha256": metadata["source_sha256"],
        "request_bytes": len(requests), "response_bytes": len(responses),
        "report_sha256": digest(raw_file(folder / "report.json")), **SCOPE,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--_execute", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args._execute is not None:
        result = execute_child(args._execute)
    elif args.verify is not None:
        result = read_evidence(args.verify, args.native_manifest)
    else:
        if args.native_manifest is None or args.output is None:
            parser.error("--native-manifest and --output are required for actual execution")
        result = run(args.native_manifest, args.output)
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
