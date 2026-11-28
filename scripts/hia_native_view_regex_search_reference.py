"""Read-only admission of the complete regex-search Rust reference.

The reader reconstructs all original source composition, the exact generated
input, every output record, and all three actual process receipts. Native ELF
producer admission remains the native component's separate responsibility.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import stat
import struct

ORACLE_RELATIVE = "tests/hia_native/view_regex_search_oracle"
ORACLE_OUTPUT_FOLDER = "view-regex-search-original"
HARNESS_FILES = ("Cargo.toml", "Cargo.lock", "README.md", "source_manifest.json",
                 "cases.py", "verify_sources.py", "replay_compare.py", "run.py")
PROCESS_NAMES = ("rust-version", "build", "original")
ORIGINAL_RESULT_LIMIT = 8 << 20


def need(condition, message):
    if not condition:
        raise AssertionError(message)


def uint(value, name, maximum=(1 << 64) - 1):
    need(type(value) is int and 0 <= value <= maximum, name + " must be an unsigned integer")
    return value


def exact(value, expected, name):
    need(type(value) is type(expected), name + " type differs")
    if type(expected) is dict:
        need(set(value) == set(expected), name + " fields differ")
        for key in expected:
            exact(value[key], expected[key], name + "." + str(key))
    elif type(expected) in (list, tuple):
        need(len(value) == len(expected), name + " length differs")
        for index, (actual, reference) in enumerate(zip(value, expected)):
            exact(actual, reference, name + "[" + str(index) + "]")
    else:
        need(value == expected, name + " differs")


def keys(value, expected, name):
    need(type(value) is dict and set(value) == set(expected), name + " fields differ")


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "duplicate JSON field")
        value[key] = item
    return value


def _finite(value):
    if type(value) is float:
        need(math.isfinite(value), "nonfinite JSON number")
    elif type(value) is dict:
        for item in value.values():
            _finite(item)
    elif type(value) is list:
        for item in value:
            _finite(item)


def decode(raw):
    result = json.loads(raw, object_pairs_hook=_pairs,
        parse_constant=lambda token: (_ for _ in ()).throw(AssertionError("nonfinite JSON token")))
    _finite(result)
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode() + b"\n"


def inside(root, relative):
    need(type(relative) is str and relative != "", "artifact path must be nonempty text")
    rel = Path(relative)
    need(not rel.is_absolute() and ".." not in rel.parts and str(rel) == relative,
         "artifact path must be canonical and relative")
    root = Path(root)
    need(not root.is_symlink(), "artifact root is a symlink")
    current = root.absolute()
    for part in rel.parts:
        current /= part
        need(not current.is_symlink(), "artifact traverses a symlink")
    metadata = current.stat()
    need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid(),
         "artifact is not an owned regular file")
    need(current.resolve().is_relative_to(root.resolve()), "artifact escaped root")
    return current


def identity(path):
    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
            length += len(block)
    return dict(bytes=length, sha256=digest.hexdigest())


def pin(value, name):
    keys(value, ("bytes", "sha256"), name)
    uint(value["bytes"], name + ".bytes")
    digest = value["sha256"]
    need(type(digest) is str and len(digest) == 64 and
         all(char in "0123456789abcdef" for char in digest), name + ".sha256 differs")
    return value


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _process(row, name, command, cwd, expected_stdin):
    keys(row, ("name", "command", "cwd", "timeout_seconds", "elapsed_seconds",
               "exit_code", "timed_out", "spawn_error", "stdin", "stdout", "stderr"),
         "process receipt")
    exact(row["name"], name, "process name")
    exact(row["command"], command, "actual command")
    exact(row["cwd"], cwd, "actual cwd")
    exact(row["timeout_seconds"], 180, "actual process deadline")
    exact(row["exit_code"], 0, "process exit")
    exact(row["timed_out"], False, "process timeout")
    exact(row["spawn_error"], None, "process spawn error")
    elapsed = row["elapsed_seconds"]
    need(type(elapsed) in (float, int) and math.isfinite(elapsed) and 0 < elapsed < 180,
         "actual process elapsed time differs")
    exact(row["stdin"], expected_stdin, "actual stdin")
    for name in ("stdout", "stderr"):
        pin(row[name], name)


def _blob(blobs, value, size, used, name):
    index = uint(value, name + " index", len(blobs) - 1)
    uint(size, name + " size")
    raw = blobs[index]
    exact(len(raw), size, name + " complete length")
    used.add(index)
    return raw


def _render(row, blobs, used, *, hints=False):
    need(type(row) is dict and type(row.get("ok")) is bool, "render success type differs")
    fields = ("ok", "blob", "bytes") if row["ok"] else ("ok", "error")
    keys(row, (*fields, "hints") if hints else fields, "render observation")
    if hints:
        exact(row["hints"], [], "render hints")
    if row["ok"]:
        return _blob(blobs, row["blob"], row["bytes"], used, "rendered bytes")
    need(type(row["error"]) is str, "render error type differs")
    return row["error"].encode()


def _record(request, original):
    meta, blobs = original["metadata"], original["blobs"]
    _finite(meta)
    keys(meta, ("case_id", "name", "session", "outcome", "rendered", "before_cancel",
                "cache_before", "cache_after", "io_counts", "events", "fired_hooks",
                "outside_scope_hints_empty"), "original result")
    for field in ("case_id", "name", "session"):
        exact(meta[field], request[field], "case " + field)
    exact(meta["outside_scope_hints_empty"], True, "outside context hints")
    used = set()
    count = dict(cases=1, regex_search_cases=int(request["domain"] == "regex-search"),
                 whole_preparation_cases=int(request["domain"] == "whole-prime"),
                 successful=0, errors=0, cancelled=0, body_bytes=0, rendered_bytes=0,
                 raw_read_bytes=0, logical_io=0, read_calls=0, metadata_calls=0,
                 cache_probe_bytes=0)
    rendered = _render(meta["rendered"], blobs, used)
    gate_ok = meta["rendered"]["ok"] and len(rendered) <= ORIGINAL_RESULT_LIMIT
    if meta["rendered"]["ok"]:
        count["rendered_bytes"] = len(rendered)
    outcome = meta["outcome"]
    if request["cancel_after_render"]:
        exact(outcome, {"cancelled": True, "publication_bytes": 0}, "cancel outcome")
        base = _render(meta["before_cancel"], blobs, used, hints=True)
        exact(meta["before_cancel"]["ok"], gate_ok, "cancelled result gate status")
        if gate_ok or not meta["rendered"]["ok"]:
            exact(base, rendered, "cancelled original base")
        count["cancelled"] = 1
    else:
        exact(meta["before_cancel"], None, "unexpected cancellation observation")
        keys(outcome, ("ok", "blob", "bytes", "hints", "hints_remaining"), "visible outcome")
        need(type(outcome["ok"]) is bool, "visible success type differs")
        exact(outcome["ok"], gate_ok, "original result gate status")
        exact(outcome["hints"], [], "visible hints")
        exact(outcome["hints_remaining"], [], "remaining hints")
        body = _blob(blobs, outcome["blob"], outcome["bytes"], used, "visible body")
        if outcome["ok"]:
            exact(meta["rendered"]["ok"], True, "successful rendered state")
            exact(body, rendered, "successful result body")
        elif not meta["rendered"]["ok"]:
            exact(body, rendered, "error result body")
        count["successful" if outcome["ok"] else "errors"] = 1
        count["body_bytes"] = len(body)
    observed, expected_events = {}, []
    fired = []
    need(type(meta["events"]) is list, "event list type differs")
    for event in meta["events"]:
        if event.get("kind") == "mutation":
            keys(event, ("kind", "hook", "event", "occurrence", "when"), "mutation event")
            index = uint(event["hook"], "mutation hook", len(request["hooks"]) - 1)
            need(index not in fired, "hook fired twice")
            hook = request["hooks"][index]
            for field in ("event", "occurrence", "when"):
                exact(event[field], hook[field], "mutation " + field)
            need(expected_events and expected_events[-1] == (event["event"], event["occurrence"])
                 and event["when"] == "after", "mutation was not immediately after its I/O")
            fired.append(index)
            continue
        keys(event, ("kind", "event", "occurrence", "result"), "logical I/O event")
        exact(event["kind"], "io", "I/O kind")
        name = event["event"]
        need(name in ("exists", "is_dir", "is_file", "metadata", "read"), "unexpected I/O event")
        occurrence = observed.get(name, 0) + 1
        exact(event["occurrence"], occurrence, "I/O occurrence")
        observed[name] = occurrence
        expected_events.append((name, occurrence))
        result = event["result"]
        need(type(result) is dict and type(result.get("ok")) is bool, "I/O result success type differs")
        if not result["ok"]:
            keys(result, ("ok", "error"), "I/O error")
            need(type(result["error"]) is str, "I/O error is not text")
        elif name == "read":
            keys(result, ("ok", "bytes", "snapshot_blob"), "raw read result")
            raw = _blob(blobs, result["snapshot_blob"], result["bytes"], used, "raw read snapshot")
            count["raw_read_bytes"] += len(raw)
        elif name == "metadata":
            keys(result, ("ok", "size", "is_file", "is_dir"), "metadata result")
            uint(result["size"], "metadata size")
            need(type(result["is_file"]) is bool and type(result["is_dir"]) is bool,
                 "metadata file types differ")
        else:
            keys(result, ("ok", "value"), "path predicate")
            need(type(result["value"]) is bool, "path predicate is not boolean")
        count["logical_io"] += 1
    need(type(meta["io_counts"]) is dict, "I/O count map type differs")
    for value in meta["io_counts"].values():
        uint(value, "I/O count")
    exact(meta["io_counts"], observed, "I/O count reconstruction")
    exact(fired, list(range(len(request["hooks"]))), "all scheduled actual mutations")
    need(type(meta["fired_hooks"]) is list, "fired hook list type differs")
    for value in meta["fired_hooks"]:
        uint(value, "fired hook index")
    exact(meta["fired_hooks"], fired, "reported fired hooks")
    count["read_calls"] = observed.get("read", 0)
    count["metadata_calls"] = observed.get("metadata", 0)
    cache = []
    for side in ("cache_before", "cache_after"):
        need(type(meta[side]) is list and len(meta[side]) == len(request["cache_probes"]),
             "cache probe count differs")
        values = []
        for probe, path in zip(meta[side], request["cache_probes"]):
            keys(probe, ("path_hex", "present", "blob", "bytes"), "cache probe")
            exact(probe["path_hex"], path, "cache probe path")
            need(type(probe["present"]) is bool, "cache presence is not boolean")
            if probe["present"]:
                raw = _blob(blobs, probe["blob"], probe["bytes"], used, "cache bytes")
                count["cache_probe_bytes"] += len(raw)
                values.append(raw)
            else:
                exact(probe["blob"], None, "absent cache blob")
                exact(probe["bytes"], 0, "absent cache bytes")
                values.append(None)
        cache.append(values)
    if request["domain"] == "regex-search":
        exact(cache[0], cache[1], "search left session cache unchanged")
    exact(used, set(range(len(blobs))), "every original output blob must be referenced")
    summary = dict(case_id=meta["case_id"], name=meta["name"], domain=request["domain"],
                   rendered_bytes=meta["rendered"].get("bytes"), result_bytes=outcome.get("bytes"),
                   ok=outcome.get("ok"), cancelled=request["cancel_after_render"], io_counts=observed)
    return count, summary


def _equal_stream(stream, expected):
    view = memoryview(expected)
    for offset in range(0, len(view), 1 << 20):
        block = view[offset:offset + (1 << 20)]
        need(stream.read(len(block)) == block, "complete regenerated original input differs")


def _native_operation(domain, event):
    need(domain in ("regex-search", "whole-prime"), "native operation domain differs")
    need(event.get("event") in ("exists", "is_dir", "is_file", "metadata", "read"),
         "native operation event differs")
    expected = (5 if domain == "regex-search" else 2) if event["event"] == "read" else 1
    exact(event.get("operation"), expected, "actual HIA reader operation")


def _native_operations(cases, replay, corpus):
    rows = replay.rows(inside(corpus, "native-cases.jsonl"))
    admitted = 0
    for request in cases.iter_cases():
        meta = request["metadata"]
        row = rows[meta["case_id"]]
        for event in row["io"]:
            _native_operation(meta["domain"], event)
            admitted += 1
    return admitted


def reference_evidence(root, output, *, native_corpus=None):
    root, output = Path(root), Path(output)
    artifacts, sources = {}, {}

    def artifact(name, expected=None):
        path = inside(output, name)
        actual = identity(path)
        if expected is not None:
            exact(actual, pin(expected, name), name + " bytes/hash")
        artifacts[name] = actual["sha256"]
        return path

    def source_file(name, expected=None):
        path = inside(root, name)
        actual = identity(path)
        if expected is not None:
            exact(actual, pin(expected, name), name + " source bytes/hash")
        sources[name] = actual["sha256"]
        return path

    source_file("scripts/hia_native_view_regex_search_reference.py")
    report = decode(artifact("result.json").read_bytes())
    keys(report, ("schema", "status", "materialization", "reference", "native_comparison",
                  "processes", "harness_inputs", "harness_unchanged", "companion_inputs",
                  "build_environment", "explicit_offline", "independent_input", "original_output",
                  "case_summary", "binary", "whole_view_migrated", "whole_runtime_replaced"),
         "original report")
    exact(report["schema"], "hepta.runtime.view-regex-search-original-reference.v1", "original schema")
    exact(report["harness_unchanged"], True, "unchanged harness")
    for name in ("whole_view_migrated", "whole_runtime_replaced"):
        exact(report[name], False, name)
    keys(report["harness_inputs"], HARNESS_FILES, "harness inputs")
    for name in HARNESS_FILES:
        source_file(ORACLE_RELATIVE + "/" + name, report["harness_inputs"][name])
    manifest = decode(inside(root, ORACLE_RELATIVE + "/source_manifest.json").read_bytes())
    exact(report["companion_inputs"], manifest["companion_inputs"], "companion source identities")
    for name, expected in manifest["companion_inputs"].items():
        source_file("tests/hia_native/view_call_oracle/" + name, expected)
    for name, expected in manifest["files"].items():
        source_file(name, expected)
    verify = load_module(inside(root, ORACLE_RELATIVE + "/verify_sources.py"), "_search_admit_source")
    cases = load_module(inside(root, ORACLE_RELATIVE + "/cases.py"), "_search_admit_cases")
    assembled, checked_manifest = verify.check_sources(root.resolve())
    expected_materialization = dict(source_commit=checked_manifest["commit"],
        original_source_files_match=True, extracted_original_bodies_unchanged=True,
        actual_tokio_filesystem_io=True, source=verify.pin(assembled.encode()),
        registry_dependencies=verify.check_dependency_subset(
            inside(root, ORACLE_RELATIVE + "/Cargo.lock").read_bytes(), inside(root, "Cargo.lock").read_bytes()),
        unsupported_branches_abort=True, original_mcp_router_executed=False,
        whole_view_migrated=False, whole_runtime_replaced=False)
    exact(canonical(report["materialization"]), canonical(expected_materialization), "original materialization")
    exact(artifact("crate/src/main.rs").read_bytes(), assembled.encode(), "actual compiled original Rust")
    for name in ("Cargo.toml", "Cargo.lock"):
        exact(artifact("crate/" + name).read_bytes(),
              inside(root, ORACLE_RELATIVE + "/" + name).read_bytes(), "actual crate " + name)
    actual_crate = {str(path.relative_to(output / "crate")) for path in (output / "crate").rglob("*") if path.is_file()}
    exact(actual_crate, {"Cargo.toml", "Cargo.lock", "src/main.rs"}, "complete crate file set")
    env = report["build_environment"]
    need(type(env) is dict and {"RUSTC", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS"} <= set(env)
         and set(env) <= {"RUSTC", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE", "RUSTUP_TOOLCHAIN"},
         "build environment fields differ")
    need(all(type(value) is str for value in env.values()), "build environment values must be text")
    exact(env["CARGO_BUILD_JOBS"], "2", "Cargo job count")
    recorded = Path(env["CARGO_TARGET_DIR"]).parent
    need(recorded.is_absolute() and env["CARGO_TARGET_DIR"] == str(recorded / "target"),
         "recorded build output differs")
    rustc = env["RUSTC"]
    need(Path(rustc).is_absolute() and Path(rustc).name == "rustc", "Rust invocation path differs")
    process_rows = decode(artifact("process-receipts.json").read_bytes())
    exact(canonical(report["processes"]), canonical(process_rows), "report versus raw process receipts")
    need(type(process_rows) is list and len(process_rows) == 3, "exactly three fresh original processes required")
    build = process_rows[1].get("command")
    need(type(build) is list and build and type(build[0]) is str and
         Path(build[0]).is_absolute() and Path(build[0]).name == "cargo", "Cargo invocation path differs")
    need(type(report["explicit_offline"]) is bool, "offline selection must be boolean")
    build_command = [build[0], "build", "--locked"]
    if report["explicit_offline"]:
        build_command.append("--offline")
    build_command += ["--manifest-path", str(recorded / "crate/Cargo.toml"), "--release"]
    commands = ([rustc, "--version"], build_command,
                [str(recorded / "target/release/hepta-view-regex-search-original-oracle"), str(recorded / "fixtures")])
    for index, (name, command) in enumerate(zip(PROCESS_NAMES, commands)):
        row = process_rows[index]
        _process(row, name, command, str(recorded / "crate"), report["independent_input"] if index == 2 else None)
        artifact(name + ".stdout", row["stdout"])
        artifact(name + ".stderr", row["stderr"])
        if name != "build":
            exact(row["stderr"]["bytes"], 0, name + " stderr")
    binary = artifact("target/release/hepta-view-regex-search-original-oracle", report["binary"])
    with binary.open("rb") as stream:
        header = stream.read(64)
    need(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b">\x00",
         "original binary is not an x86-64 ELF")
    exact(process_rows[2]["stdout"], report["original_output"], "full original stream identity")
    artifact("original.stdout", report["original_output"])
    input_path = artifact("input.bin", report["independent_input"])
    total = sum(1 for _ in cases.iter_cases())
    exact(total, 271, "independent case count")
    names, summary = [], None
    with input_path.open("rb") as inputs, inside(output, "original.stdout").open("rb") as original_stream:
        _equal_stream(inputs, cases.INPUT_MAGIC + struct.pack("<Q", total))
        originals = cases.read_records(original_stream, cases.OUTPUT_MAGIC)
        for request in cases.iter_cases():
            _equal_stream(inputs, cases.blob_record(request["metadata"], request["blobs"]))
            counts, row = _record(request["metadata"], next(originals))
            if summary is None:
                summary = {name: 0 for name in counts}
            for name, value in counts.items():
                summary[name] += value
            names.append(row)
        exact(inputs.read(1), b"", "no extra independent input")
        exact(next(originals, None), None, "no extra original record")
    summary.update(actual_tokio_io=True, actual_unchanged_search=True,
        actual_original_mcp_router=False, alternative_path_search=False,
        directory_search=False, regex_search=True, whole_view_migrated=False,
        whole_runtime_replaced=False)
    exact(canonical(report["reference"]), canonical(summary), "complete reference summary reconstruction")
    exact(artifact("case-summary.json", report["case_summary"]).read_bytes(), canonical(names),
          "complete case summary reconstruction")
    if report["native_comparison"] is None:
        exact(report["status"], "REFERENCE_READY", "reference-only status")
    else:
        need(native_corpus is not None, "native comparison was reported without an admitted comparison input")
        exact(report["status"], "BYTES_EQUAL_REQUIRES_NATIVE_ADMISSION", "byte-comparison status")
    comparison = None
    if native_corpus is not None:
        replay = load_module(inside(root, ORACLE_RELATIVE + "/replay_compare.py"), "_search_admit_compare")
        comparison = replay.compare_native(Path(native_corpus), output)
        exact(_native_operations(cases, replay, Path(native_corpus)), summary["logical_io"],
              "HIA operation observation count")
        if report["native_comparison"] is not None:
            exact(canonical(report["native_comparison"]), canonical(comparison), "recorded native comparison")
    return dict(status="REFERENCE_READY" if comparison is None else "COMPLETE_BYTE_PARITY_REQUIRES_NATIVE_ADMISSION",
        schema="hepta.runtime.view-regex-search-original-evidence.v1", reference=summary,
        fresh_original_processes=3, native_comparison=comparison,
        artifact_sha256=dict(sorted(artifacts.items())), source_sha256=dict(sorted(sources.items())),
        original_mcp_router_executed=False, whole_view_migrated=False, whole_runtime_replaced=False)
