"""Read the actual locked original and pair complete worker results without replay."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile
import tomllib

from worker_cases import duration_cases, graph_cases, lines, original_graphs
from worker_evidence import decode_body, packets, sha, words

BASE = "tests/hia_native/blocking_worker_ci"
ORIGINAL = "tests/hia_native/blocking_worker/reference/weight_bellman.rs"
ORIGINAL_SHA = "254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7"
MODES = ("ordinary", "duration", "lifecycle", "retained", "queue-hold", "core-deadline", "writer-deadline", "writer-trace")
TIME = re.compile(rb'("native_operation_wall_seconds":)(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?=[,}])')


def read_json(path):
    return json.loads(path.read_bytes())


def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def original_evidence(path, source_root):
    """Every retained source, crate, generated module and owned process is read."""
    raw_pins = (path / "worker-reference-pins.json").read_bytes()
    assert raw_pins == (source_root / BASE / "worker-reference-pins.json").read_bytes()
    pins = json.loads(raw_pins)["files"]
    assert len(pins) == 12
    actual_source = {p.relative_to(path / "source").as_posix() for p in (path / "source").rglob("*") if p.is_file()}
    assert actual_source == set(pins)
    for name, identity in pins.items():
        raw = (path / "source" / name).read_bytes()
        assert len(raw) == identity["bytes"] and sha(raw) == identity["sha256"], name
        assert raw == (source_root / name).read_bytes(), name
        if "git_blob" in identity:
            assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == identity["git_blob"]
    original = (path / "source" / ORIGINAL).read_bytes()
    assert sha(original) == ORIGINAL_SHA
    fixture = path / "source" / BASE / "worker-reference"
    observer = (fixture / "trace_access.rs").read_bytes()
    old = (path / "source" / BASE / "tracer/trace_access.rs").read_bytes()
    old = old[old.index(b"pub fn trace_canonical_writer"):]
    assert observer.count(old) == 1
    assert (path / "generated/weight_bellman.rs").read_bytes() == original
    assert (path / "generated/original_bellman_with_observer.rs").read_bytes() == original + b"\n" + observer

    specs = {"rustc-version": (30, ["rustc", "--version", "--verbose"]),
             "cargo-version": (30, ["cargo", "--version"]),
             "cargo-build": (300, ["cargo", "build", "--locked", "--manifest-path"]),
             "cargo-metadata": (120, ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path"])}
    assert {p.stem for p in (path / "processes").glob("*.json")} == set(specs) | set(MODES)
    receipts = {}; processes = {}; parent = origin = environment = None; pids = set()
    for label in [*specs, *MODES]:
        receipt = read_json(path / "processes" / (label + ".json"))
        assert receipt["label"] == label and receipt["started"] is True and receipt["timed_out"] is False
        assert receipt["returncode"] == 0 and "failure" not in receipt
        limit = specs[label][0] if label in specs else 60
        assert receipt["timeout_seconds"] == limit and 0 <= receipt["elapsed_ns"] <= limit * 1000000000
        assert type(receipt["pid"]) is int and receipt["pid"] == receipt["pgid"] and receipt["pid"] > 0
        assert receipt["pid"] not in pids; pids.add(receipt["pid"])
        assert type(receipt["parent_pid"]) is int and receipt["parent_pid"] > 0
        if parent is None:
            parent, origin, environment = receipt["parent_pid"], receipt["cwd"], receipt["environment"]
            assert environment == {"RUSTUP_TOOLCHAIN": "1.95.0", "CARGO_ENCODED_RUSTFLAGS": "",
                                   "CARGO_HOME": origin + "-build-work/cargo-home", "CARGO_TARGET_DIR": origin + "-build-work/target"}
        assert (receipt["parent_pid"], receipt["cwd"], receipt["environment"]) == (parent, origin, environment)
        command = specs[label][1] if label in specs else [origin + "/original-worker", label]
        if label in ("cargo-build", "cargo-metadata"):
            command = command + [origin + "/source/" + BASE + "/worker-reference/Cargo.toml"]
        assert receipt["command"] == command
        content = {}
        for channel in ("stdout", "stderr"):
            rel = "processes/" + label + "." + channel
            raw = (path / rel).read_bytes()
            assert receipt[channel] == dict(path=rel, **pin(raw))
            content[channel] = raw
        if label in MODES:
            raw = (path / (label + ".inputs")).read_bytes()
            assert receipt["stdin_sha256"] == sha(raw)
            assert json.loads(content["stderr"]) == {"pid": receipt["pid"], "parent_pid": parent, "pgid": receipt["pid"]}
            processes[label] = [json.loads(line) for line in content["stdout"].splitlines()]
        else:
            assert receipt["stdin_sha256"] is None
        receipts[label] = receipt
    assert (path / "processes/rustc-version.stdout").read_bytes().startswith(b"rustc 1.95.0 ")
    assert (path / "processes/cargo-version.stdout").read_bytes().startswith(b"cargo 1.95.0 ")
    generated_module = (path / "generated/module.rs").read_text()
    assert generated_module.startswith('#[allow(dead_code)]\n#[path = "' + origin + '-build-work/target/debug/build/hia-bellman-worker-reference-')
    assert generated_module.endswith('/out/original_bellman_with_observer.rs"]\nmod original;\n')

    locked = {(p["name"], p["version"]): p for p in tomllib.loads((fixture / "Cargo.lock").read_text())["package"] if "source" in p}
    registry = read_json(path / "registry.json")
    assert len(registry) == len(locked) == 132
    assert set(registry) == {name + "-" + version for name, version in locked}
    metadata = read_json(path / "processes/cargo-metadata.stdout")
    packages = {(p["name"], p["version"]): p for p in metadata["packages"] if p["source"] is not None}
    assert set(packages) == set(locked)
    declared_package = tomllib.loads((fixture / "Cargo.toml").read_text())["package"]
    assert declared_package["name"] == "hia-bellman-worker-reference"
    assert [(p["name"], p["version"]) for p in metadata["packages"] if p["source"] is None] == [(declared_package["name"], declared_package["version"])]
    assert {p.name for p in (path / "registry").iterdir()} == {name + suffix for name in registry for suffix in (".crate", ".source.json")}
    source_files = archive_bytes = 0
    for key, locked_package in locked.items():
        name = key[0] + "-" + key[1]; package = packages[key]
        assert package["source"] == locked_package["source"]
        assert package["manifest_path"].startswith(environment["CARGO_HOME"] + "/registry/src/")
        assert package["manifest_path"].endswith("/" + name + "/Cargo.toml")
        archive = (path / "registry" / (name + ".crate")).read_bytes()
        assert sha(archive) == locked_package["checksum"]
        expected = read_json(path / "registry" / (name + ".source.json")); observed = {}
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar:
                if member.isdir(): continue
                assert member.isfile() and not member.linkname and member.name.startswith(name + "/")
                relative = member.name[len(name) + 1:]
                assert not PurePosixPath(relative).is_absolute() and ".." not in PurePosixPath(relative).parts and relative not in observed
                raw = tar.extractfile(member).read(); assert len(raw) == member.size
                observed[relative] = pin(raw)
        assert observed == expected
        assert registry[name] == {"archive_bytes": len(archive), "sha256": sha(archive), "actual_source_files": len(observed)}
        source_files += len(observed); archive_bytes += len(archive)

    graphs = original_graphs(); from qualify_bellman import ERRORS
    assert (path / "ordinary.inputs").read_bytes() == lines(graphs)
    actual = processes["ordinary"]; assert len(actual) == len(graphs) == 363
    successes = refusals = 0
    for index, (declared, result) in enumerate(zip(graphs, actual)):
        assert set(result) == {"index", "name", "kind", "text", "before_ns", "after_ns", "available_before", "available_after"}
        assert result["index"] == index and result["name"] == declared["name"] and result["available_before"] == result["available_after"] == 2
        assert result["after_ns"] >= result["before_ns"]
        if declared["expected_error_code"] is None:
            assert result["kind"] == 0
            value = json.loads(result["text"]); assert len(value) == 36
            assert 0 <= value["native_operation_wall_seconds"] <= (result["after_ns"] - result["before_ns"]) / 1e9
            successes += 1
        else:
            assert result["kind"] == 1 and result["text"] == ERRORS[declared["expected_error_code"]]
            refusals += 1
    assert (successes, refusals) == (338, 25)
    durations = duration_cases(); assert (path / "duration.inputs").read_bytes() == lines(durations)
    assert len(processes["duration"]) == len(durations) == 1292
    for ns, row in zip(durations, processes["duration"]):
        assert set(row) == {"nanoseconds", "bits"} and row["nanoseconds"] == ns and 0 <= row["bits"] < 1 << 64
    for mode in MODES[2:-1]:
        assert (path / (mode + ".inputs")).read_bytes() == b"" and len(processes[mode]) == 1
    life = processes["lifecycle"][0]
    assert life["queued_permits"] == life["after_cancel_permits"] == 0 and life["drained_permits"] == 2 and life["cancelled"] is True
    assert life["third_before"] == life["third_after"] == "native Bellman planning capacity exhausted; no work admitted"
    assert len(life["blocking_thread_ids"]) == len(set(life["blocking_thread_ids"])) == 2 and all(type(v) is int and v > 0 for v in life["blocking_thread_ids"])
    retained = processes["retained"][0]
    assert retained["ready_count"] == 40 and retained["final_permits"] == 2
    assert [x["index"] for x in retained["results"]] == list(reversed(range(40)))
    queue = processes["queue-hold"][0]
    assert queue["after_ns"] - queue["before_ns"] >= 30000000000 and queue["held_permits"] == 1 and queue["final_permits"] == 2
    assert json.loads(queue["result"])["native_operation_wall_seconds"] < 30
    for mode, writer, message in [("core-deadline", False, "Bellman planning exceeded its 30-second compute deadline"),
                                   ("writer-deadline", True, "Bellman canonical serialization exceeded its deadline")]:
        row = processes[mode][0]
        assert row["writer"] is writer and row["message"] == message and row["accepted_bytes"] == 0
        assert row["accepted_sha256"] == sha(b"") and row["original_source_sha256"] == ORIGINAL_SHA
        assert struct.unpack("<d", struct.pack("<Q", row["elapsed_bits"]))[0] >= 30
    writer_inputs = (path / "source" / BASE / "writer-cases.jsonl").read_bytes()
    assert (path / "writer-trace.inputs").read_bytes() == writer_inputs
    assert len(processes["writer-trace"]) == 6; counts = []
    for index, row in enumerate(processes["writer-trace"]):
        assert row["index"] == index; trace = row["trace"]
        fragments = [bytes.fromhex(v) for v in trace["write_calls"]]; canonical = bytes.fromhex(trace["canonical_hex"])
        assert b"".join(fragments) == canonical and len(canonical) == trace["canonical_bytes"] and sha(canonical) == trace["request_sha256"]
        assert trace["original_source_sha256"] == ORIGINAL_SHA and trace["observer_changes_original_write_body"] is False and trace["public_handler_qualified"] is False
        counts.append(len(fragments))
    assert counts == [8, 27, 111, 153, 42, 111]
    result = read_json(path / "RESULT.json")
    assert result["status"] == "ACTUAL_REFERENCE_CAPTURED" and result["source_pins_sha256"] == sha(raw_pins)
    assert result["binary_sha256"] == sha((path / "original-worker").read_bytes())
    assert result["graph_cases"] == 363 and result["graph_successes"] == 338 and result["graph_refusals"] == 25
    assert result["duration_cases"] == 1292 and result["registry_packages"] == 132 and result["writer_calls"] == 452
    assert all(result[key] is False for key in ["source_functions_modified", "native_executed", "full_worker_qualified", "public_handler_qualified"])
    return {"status": "ORIGINAL_READ_ONLY_PASS", "registry_packages": 132, "registry_source_files": source_files,
            "registry_archive_bytes": archive_bytes, "actual_processes": len(receipts), "graph_cases": 363,
            "duration_cases": 1292, "writer_calls": 452, "source_pins_sha256": sha(raw_pins),
            "binary_sha256": result["binary_sha256"], "source_commit": result["source_commit"]}, processes


def without_elapsed(raw):
    """Preserve every other byte, including signed zero and number formatting."""
    value = json.loads(raw); assert len(value) == 36
    assert math.isfinite(value["native_operation_wall_seconds"]) and value["native_operation_wall_seconds"] >= 0
    matches = list(TIME.finditer(raw)); assert len(matches) == 1
    match = matches[0]
    return raw[:match.start(2)] + b"0" + raw[match.end(2):]


def taken(path):
    requests = {}; jobs = {}; bodies = {}
    for raw in packets((path / "stdin.bin").read_bytes()):
        h = words(raw[:64]); requests[h[2]] = (h, raw[64:])
    for raw in packets((path / "stdout.bin").read_bytes()):
        h = words(raw[:64])
        if h[2] != 1: continue
        request, payload = requests[h[3]]
        if request[1] == 1 and h[4]: jobs[h[4]] = payload
        if h[6]:
            assert request[1] == 4 and h[4] not in bodies
            body, parts, value = decode_body(raw[192:]); assert body[9] == h[5]
            bodies[h[4]] = (body, parts, value)
    return jobs, bodies


def complete_buffers(path):
    """For small scalar/control captures; every physical gzip byte is consumed."""
    index = read_json(path / "buffers.json"); order = sorted(index, key=lambda key: index[key]["index"])
    assert [index[key]["index"] for key in order] == list(range(len(order)))
    result = {}
    with gzip.open(path / "buffers.bin.gz", "rb") as stream:
        for key in order:
            header = stream.read(8); assert len(header) == 8
            size = struct.unpack("<Q", header)[0]; assert size == index[key]["bytes"]
            raw = stream.read(size); assert len(raw) == size and sha(raw) == key
            result[key] = raw
        assert stream.read(1) == b""
    return result


def pair_reference(native, reference, source_root, groups=None):
    evidence, rows = original_evidence(reference, source_root)
    if groups is None:
        groups = {name: native / ("diagnostic-worker-" + name + ("-v1" if name.startswith("ordinary") else "-v2"))
                  for name in ("lifetime", "retained", "eof", "held1", "held2", "held3", "held4", "ordinary0", "ordinary1", "ordinary2", "ordinary3")}
    from qualify_bellman import pack_graph, ERRORS
    cases = graph_cases(); compared = 0; bytes_compared = 0
    bounds = [0, 91, 182, 273, 363]
    for cohort in range(4):
        path = groups["ordinary" + str(cohort)]; jobs, bodies = taken(path)
        progress = read_json(path / "ordinary.progress.json")
        assert set(jobs) == set(bodies) == set(range(1, bounds[cohort + 1] - bounds[cohort] + 1))
        assert len(progress) == len(jobs)
        for job, index in enumerate(range(bounds[cohort], bounds[cohort + 1]), 1):
            name, description, error = cases[index]; body, parts, value = bodies[job]
            assert jobs[job] == pack_graph(description)
            assert progress[job - 1] == {"case": index, "name": name, "job": job, "code": error or 0}
            original = rows["ordinary"][index]
            if error is None:
                left, right = parts[2][64:], original["text"].encode()
                assert without_elapsed(left) == without_elapsed(right), (index, name, "complete wire")
                bytes_compared += len(left) + len(right)
            else:
                assert body[9] == error and parts[2] == b"" and original["text"] == ERRORS[error]
            compared += 1
    assert compared == 363
    jobs, bodies = taken(groups["lifetime"])
    assert without_elapsed(bodies[2][1][2][64:]) == without_elapsed(rows["lifecycle"][0]["surviving_result"].encode())
    jobs, bodies = taken(groups["retained"])
    assert set(jobs) == set(bodies) == set(range(1, 41))
    for result in rows["retained"][0]["results"]:
        assert without_elapsed(bodies[result["index"] + 1][1][2][64:]) == without_elapsed(result["text"].encode())
    jobs, bodies = taken(groups["held1"])
    assert set(jobs) == set(bodies) == {1}
    assert without_elapsed(bodies[1][1][2][64:]) == without_elapsed(rows["queue-hold"][0]["result"].encode())
    for name, code in [("held2", 0xfffffdf0), ("held3", 0xfffffde1)]:
        jobs, bodies = taken(groups[name]); assert set(jobs) == set(bodies) == {1} and bodies[1][0][9] == code

    path = native / "diagnostic-elapsed-v2"
    if not path.exists(): path = native / "elapsed"
    blobs = complete_buffers(path); calls = read_json(path / "calls.json"); claimed = set(); previous = None
    assert len(calls) == 2617
    for index, result in enumerate(rows["duration"]):
        for offset, start in enumerate([0, (1 << 64) - 1 - result["nanoseconds"]]):
            call = calls[2 * index + offset]
            assert call["case"] == index and call["phase"] == "ordinary" and call["code"] == 24
            assert blobs[call["input"]] == b"HBELRQ01" + struct.pack("<3Q", start, start + result["nanoseconds"], 0)
            assert blobs[call["after_output"]] == b"HBELRS01" + struct.pack("<2Q", result["bits"], result["nanoseconds"]) + bytes([0xa5]) * 16
            assert blobs[call["before_workspace"]] == blobs[call["after_workspace"]] == bytes([0x5a]) * 32
            assert blobs[call["before_output"]] == (bytes([0xa5]) * 40 if previous is None else previous)
            previous = blobs[call["after_output"]]
            claimed.add(2 * index + offset)
    for call in calls:
        for key in ("input", "before_output", "after_output", "before_workspace", "after_workspace"): assert call[key] in blobs
    assert len(claimed) == 2584
    # The remaining 33 calls belong to the independent exact atomicity/recovery
    # controls reader; they are not claimed as additional Duration observations.
    return {"status": "NATIVE_ORIGINAL_COMPLETE_PAIR_PASS", "original": evidence, "ordinary_cases": compared,
            "ordinary_successes": 338, "ordinary_error_codes_and_messages": 25, "complete_wire_bytes_compared": bytes_compared,
            "retained_results": 40, "actual_duration_values": 1292, "native_duration_calls": len(claimed),
            "elapsed_only_normalized": True, "normalized_field": "native_operation_wall_seconds",
            "actual_native_or_rust_executed_by_reader": False, "public_handler_qualified": False}
