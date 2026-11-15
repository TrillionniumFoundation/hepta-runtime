#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bind existing R34 observation originals into a fresh collector source file.

This sealer reads files and Python syntax only. It does not import or execute
the collector, archived tools, original auditors, tests, benchmarks or SSH.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pprint
import re
import stat

HERE = Path(__file__).resolve().parent
ROOT = PurePosixPath("/home/qian/hepta-runtime-optimization-20261106-r34")
R16 = PurePosixPath("/home/qian/hepta-runtime-optimization-20261104-r16")
TEMPLATE_SHA = "3e717ec2bcb434daabcce3caeb106afbf588ad5b1b2328207f8ff443a50db65f"
FILES = {"parent-report.json": "campaign-01/report.json", "summary.json": "campaign-01/summary.json",
         "observation-holder-native-01.json": "observation-holder-native-01.json",
         "observation-holder-read-01.json": "observation-holder-read-01.json",
         "observation-holder-report-01.json": "observation-holder-report-01.json",
         "observation-postflight-01.json": "observation-postflight-01.json"}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def stamp(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def regular(path):
    need(path.is_absolute() and path.resolve(strict=True) == path, "indirect local original")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 8 * 1024 * 1024,
         "unsafe or oversized local original")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        need(stamp(os.fstat(stream.fileno())) == stamp(before), "local original changed before open")
        raw = stream.read(8 * 1024 * 1024 + 1)
        need(len(raw) == before.st_size and stamp(os.fstat(stream.fileno())) == stamp(before) == stamp(path.lstat()),
             "local original changed while read")
    return raw


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def archive_name(path):
    path = PurePosixPath(path)
    need(path.is_absolute() and ".." not in path.parts, "nonabsolute original remote identity")
    if path.is_relative_to(ROOT):
        return path.relative_to(ROOT).as_posix()
    if path.is_relative_to(R16):
        return "external/r16/" + path.relative_to(R16).as_posix()
    return None


def native_streams(native, page):
    need(page.get("job_id") == native.get("job_id"), "original holder read belongs to another job")
    streams = {}
    for name in ("stdout", "stderr"):
        row = page[name]
        raw = bytes.fromhex(row["bytes_hex"])
        need(row["offset"] == 0 and row["next_offset"] == row["size"] == len(raw)
             and row["eof"] is True and row["text"].encode() == raw
             and native["log_bytes"][name] == {"seen": len(raw), "stored": len(raw)},
             "holder original raw stream is not complete")
        streams[name] = {"bytes": len(raw), "sha256": sha(raw)}
    return streams


def seal(originals, output):
    template_path = HERE / "archive_r34_observation.unsealed-02.py"
    template = regular(template_path)
    need(sha(template) == TEMPLATE_SHA, "reviewed unsealed collector changed")
    source = template.decode()
    tree = ast.parse(source)
    assignments = {node.targets[0].id: node for node in tree.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
    need(ast.literal_eval(assignments["ACTUAL"].value) is None, "template was already sealed")
    static = ast.literal_eval(assignments["STATIC_PINS"].value)
    dynamic = set(ast.literal_eval(assignments["DYNAMIC_REQUIRED"].value))
    needed = set(static) | dynamic
    raw_files, documents, local_pins = {}, {}, {}
    for local_name, member in FILES.items():
        path = originals / local_name
        raw = regular(path)
        raw_files[member], documents[member] = raw, json.loads(raw)
        local_pins[member] = {"local_path": str(path), "bytes": len(raw), "sha256": sha(raw)}
    parent = documents["campaign-01/report.json"]
    gates = documents["campaign-01/summary.json"]
    postflight = documents["observation-postflight-01.json"]
    native = documents["observation-holder-native-01.json"]
    page = documents["observation-holder-read-01.json"]
    holder = documents["observation-holder-report-01.json"]
    job = native.get("job_id")
    need(isinstance(job, str) and re.fullmatch(r"[0-9a-f]+(?:-[0-9a-f]+)+", job) is not None,
         "actual original holder job identity missing")
    need(native.get("state") in {"succeeded", "failed", "cancelled", "timed_out"}
         and native.get("terminal_publication_confirmed") is True
         and native.get("output_complete") is True and native.get("output_durable") is True
         and native.get("automatic_retry") is False
         and native.get("log_synced") == {"stdout": True, "stderr": True}
         and native.get("log_truncated") == {"stdout": False, "stderr": False}
         and native.get("log_errors") == {"stdout": None, "stderr": None}, "actual durable original holder terminal required")
    stream_pins = native_streams(native, page)
    completion_lines = [json.loads(line) for line in page["stdout"]["text"].splitlines() if line]
    completion = completion_lines[-1] if completion_lines else {}
    need(holder.get("schema") == "hepta-x230-r21-held-agent-campaign/v1"
         and holder.get("holder_script_sha256") == "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"
         and holder.get("remote_script_sha256") == static["tools-01/r34_campaign.py"]
         and all(completion.get(key) == holder.get(key) for key in ("passed", "remote_returncode", "owned_agent_reaped")),
         "original holder report/stream/current parent source differs")
    need(parent.get("schema") == "hepta-r25-observation-campaign-control/v1"
         and parent.get("attempt") == "01" and parent.get("finished_utc")
         and type(parent.get("passed")) is bool
         and gates.get("schema") == "hepta-r25-observation-gates/v1"
         and gates.get("observation_gate_passed") is False
         and gates.get("performance_gates_passed") is False
         and parent.get("observation_gate_passed") is False,
         "actual completed original rejected R34 campaign/gate required")
    need(postflight.get("schema") == "hepta-r34-rejected-observation-owner-postflight/v1"
         and postflight.get("original_observation_job_id") == job
         and postflight.get("candidate_adopted") is False
         and postflight.get("normal_lifecycle_started") is False
         and postflight.get("lifecycle_materialization_started") is False
         and set(postflight.get("normal_lifecycle_paths_absent", []))
             == {"lifecycle-inputs-01.json", "lifecycle-campaign-01", "lifecycle-abba-01"},
         "postflight must state actual unrun lifecycle, without a fabricated failed job")
    need(postflight.get("original_lifecycle_materializer_job_id") is None,
         "this R34 closure must not contain an invented lifecycle materializer job")
    pins, sizes, origins = {}, {}, {}

    def add(name, count, digest, origin):
        if name not in needed:
            return
        need(type(count) is int and 0 <= count <= 8 * 1024 * 1024
             and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
             "malformed actual original identity")
        need(name not in pins or pins[name] == digest and sizes[name] == count,
             "contradictory original identities: " + name)
        if name in static:
            need(digest == static[name], "actual identity differs from frozen protocol/qualification input: " + name)
        pins[name], sizes[name] = digest, count
        origins.setdefault(name, []).append(origin)

    def walk(value, origin):
        if isinstance(value, dict):
            if {"path", "bytes", "sha256"} <= set(value) and isinstance(value["path"], str):
                name = archive_name(value["path"])
                if name is not None:
                    add(name, value["bytes"], value["sha256"], origin)
            for key, child in value.items():
                walk(child, origin + "/" + str(key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, origin + "/" + str(index))

    for member, raw in raw_files.items():
        add(member, len(raw), sha(raw), "local-original/" + member)
    for name, document in documents.items():
        walk(document, name)
    need(dynamic <= set(pins), "actual dynamic identities still missing: " + ", ".join(sorted(dynamic - set(pins))))
    actual = {"schema": "hepta-r34-original-observation-archive-bindings/v1", "holder_job_id": job,
        "sha256": {name: pins[name] for name in sorted(dynamic)},
        "bytes": {name: sizes[name] for name in sorted(dynamic)},
        "identity_origins": {name: origins[name] for name in sorted(pins)}, "local_originals": local_pins,
        "holder_native_state": native["state"], "holder_native_exit_code": native.get("exit_code"),
        "holder_original_streams": stream_pins, "workflow_reported_passed": parent["passed"],
        "holder_reported_owned_agent_reaped": holder.get("owned_agent_reaped"),
        "capacity_build_or_campaign_started_by_coordinator": postflight.get("capacity_build_or_campaign_started_by_coordinator"),
        "observation_gate_passed": False, "performance_gates_passed": False,
        "rejection_reasons": gates.get("rejection_reasons"), "candidate_adopted": False,
        "lifecycle_materialization_started": False, "normal_lifecycle_started": False,
        "lifecycle_materializer_job_id": None,
        "collector_auditors_or_measurements_executed_by_sealer": False}
    lines = source.splitlines(keepends=True)
    node = assignments["ACTUAL"]
    lines[node.lineno - 1:node.end_lineno] = ["ACTUAL = " + pprint.pformat(actual, sort_dicts=True, width=120) + "\n"]
    sealed_source = "".join(lines)
    sealed_tree = ast.parse(sealed_source)
    actual_nodes = [node for node in sealed_tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "ACTUAL" for target in node.targets)]
    need(len(actual_nodes) == 1, "sealed ACTUAL assignment count differs")
    actual_nodes[0].value = ast.Constant(value=None)
    need(ast.dump(tree, include_attributes=False) == ast.dump(sealed_tree, include_attributes=False),
         "sealing changed code outside the actual binding assignment")
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
         and not os.path.lexists(output), "create-only sealed output directory required")
    package = {"archive_r34_observation.py": sealed_source.encode(), "actual-bindings-01.json": encoded(actual)}
    manifest = {"schema": "hepta-r34-observation-archive-seal/v1", "sealed": True,
        "template": {"path": str(template_path), "bytes": len(template), "sha256": sha(template)},
        "files": {name: {"bytes": len(raw), "sha256": sha(raw)} for name, raw in package.items()},
        "source_change": "only ACTUAL assignment filled from original bytes/identity-bearing reports",
        "collector_executed": False, "original_auditors_reexecuted": False,
        "normal_lifecycle_or_materializer_executed": False,
        "archive_receipt_or_hash": None}
    package["seal-manifest.json"] = encoded(manifest)
    output.mkdir(mode=0o700)
    for name, raw in package.items():
        create(output / name, raw)
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--originals", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(seal(args.originals, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
