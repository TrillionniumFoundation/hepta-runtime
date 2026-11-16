"""Read-only admission of complete unchanged-workdir Rust/SDK/kernel evidence.

This reader never executes Rust, recomputes a workdir response, opens live
fixtures, or treats the reference-only status as native parity.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
from pathlib import Path, PurePosixPath
import re
import stat
import struct

SCHEMA = "hepta.runtime.workdir-original-reference.v1"
MARKER = re.compile(rb"\s*(\d+)\s+getpgid\((\d+)\)\s+= -1 ESRCH \(No such process\)\n")
EVENTS = {"scenario_setup_begin", "scenario_setup_complete", "scenario_end", "step_begin", "step_end",
          "outer_call_tool_enter", "handler_enter", "handler_exit", "policy_lookup", "local_policy_enter",
          "local_policy_exit", "remote_policy_enter", "remote_policy_exit", "helper_enter", "helper_exit"}


def require(condition, message):
    if not condition:
        raise ValueError("workdir original evidence: " + message)


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("workdir original evidence: nonfinite JSON constant " + value)
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    def finite(item):
        if type(item) is float: require(math.isfinite(item), "overflowing JSON number")
        elif type(item) is dict:
            for child in item.values(): finite(child)
        elif type(item) is list:
            for child in item: finite(child)
    finite(value)
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode() + b"\n"


def same(actual, expected, label):
    require(type(actual) is type(expected), label + " type")
    if type(expected) is dict:
        require(set(actual) == set(expected), label + " fields")
        for name in expected: same(actual[name], expected[name], label + "." + name)
    elif type(expected) is list:
        require(len(actual) == len(expected), label + " length")
        for index, (a, b) in enumerate(zip(actual, expected)): same(a, b, label + "[%d]" % index)
    else:
        require(actual == expected, label + " value")


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def identity(path):
    digest, size = hashlib.sha256(), 0
    with Path(path).open("rb") as stream:
        while data := stream.read(1 << 20): digest.update(data); size += len(data)
    return {"bytes": size, "sha256": digest.hexdigest()}


def inside(root, name):
    require(type(name) is str, "artifact path type")
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and str(relative) == name and name not in ("", ".")
            and ".." not in relative.parts, "artifact path escapes output")
    root = Path(root).absolute()
    path = Path(root.anchor)
    for part in root.parts[1:]:
        path /= part
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), "output root crosses a symlink/non-directory")
    for index, part in enumerate(relative.parts):
        path /= part
        mode = path.lstat().st_mode
        require(not stat.S_ISLNK(mode), "artifact path crosses a symlink")
        require(stat.S_ISREG(mode) if index == len(relative.parts) - 1 else stat.S_ISDIR(mode),
                "artifact path is not a regular file")
    return path


def _hash_fields(value):
    require(type(value) is dict and set(value) == {"bytes", "sha256"}, "file pin fields")
    require(type(value["bytes"]) is int and value["bytes"] >= 0, "file pin byte extent")
    require(type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None,
            "file pin SHA256")


def _receipt(row, expected, output):
    require(type(row) is dict and set(row) == {"name", "command", "cwd", "timeout_seconds", "elapsed_seconds",
        "exit_code", "timed_out", "start_error", "stdout", "stderr", "stdin"}, "process receipt fields")
    for name in ("name", "command", "cwd", "stdin"): same(row[name], expected[name], "process " + name)
    require(type(row["timeout_seconds"]) is int and row["timeout_seconds"] == 180, "actual process deadline")
    require(type(row["exit_code"]) is int and row["exit_code"] == 0, "actual process exit")
    require(row["timed_out"] is False and row["start_error"] is None, "actual process completion")
    elapsed = row["elapsed_seconds"]
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed < 180, "actual process elapsed")
    for stream in ("stdout", "stderr"):
        _hash_fields(row[stream])
        same(identity(inside(output, row["name"] + "." + stream)), row[stream], "complete process " + stream)


def _snapshot(value, root_hex=None):
    require(type(value) is dict and set(value) == {"root_hex", "current_hex", "effective_hex", "poisoned", "session_applied"}, "state fields")
    require(type(value["poisoned"]) is bool and type(value["session_applied"]) is bool, "state bool type")
    for name in ("root_hex", "current_hex", "effective_hex"):
        text = value[name]
        if text is None:
            require(name == "current_hex", "null effective/root path")
        else:
            require(type(text) is str and len(text) % 2 == 0 and re.fullmatch("[0-9a-f]*", text) is not None, "raw state path")
    if root_hex is not None: same(value["root_hex"], root_hex, "unchanged session root")
    same(value["effective_hex"], value["root_hex"] if value["poisoned"] or value["current_hex"] is None else value["current_hex"], "effective original state")


def _read_records(path):
    size = path.stat().st_size
    with path.open("rb") as stream:
        require(stream.read(8) == b"HWDRO001", "original output magic")
        while stream.tell() < size:
            header = stream.read(16)
            require(len(header) == 16, "truncated output header")
            length, count = struct.unpack("<QQ", header)
            require(length <= size - stream.tell(), "metadata beyond complete output")
            metadata = strict_json(stream.read(length))
            require(count <= (size - stream.tell()) // 8, "blob count beyond complete output")
            blobs = []
            for _ in range(count):
                raw_size = stream.read(8)
                require(len(raw_size) == 8, "truncated blob header")
                extent, = struct.unpack("<Q", raw_size)
                require(extent <= size - stream.tell(), "blob beyond complete output")
                blobs.append(stream.read(extent))
            yield metadata, blobs
        require(stream.tell() == size, "output suffix")


def _blob(blobs, index, used, label):
    require(type(index) is int and 0 <= index < len(blobs), label + " blob index")
    used.add(index)
    return blobs[index]


def _exchange(row, message, blobs, used):
    require(type(row) is dict and set(row) == ({"request_blob", "response_blob"} if "id" not in message else
            {"request_blob", "response_blob", "response_bytes"}), "SDK exchange fields")
    request = _blob(blobs, row["request_blob"], used, "SDK request")
    require(request.endswith(b"\n"), "complete SDK request line")
    same(strict_json(request), message, "actual SDK request input")
    if "id" not in message:
        require(row["response_blob"] is None, "notification response")
        return None
    response = _blob(blobs, row["response_blob"], used, "SDK response")
    require(type(row["response_bytes"]) is int and row["response_bytes"] == len(response), "complete SDK response extent")
    require(response.endswith(b"\n"), "complete SDK response line")
    value = strict_json(response)
    same(value["id"], message["id"], "actual SDK response id")
    require(value.get("jsonrpc") == "2.0" and ("result" in value) != ("error" in value), "SDK response envelope")
    return value


def _body(row, blobs, used, label):
    require(type(row["ok"]) is bool, label + " status")
    raw = _blob(blobs, row["body_blob"], used, label)
    require(type(row["body_bytes"]) is int and row["body_bytes"] == len(raw), label + " complete extent")
    raw.decode("utf-8")
    return raw


def _kernel(raw, markers, name):
    require(not raw or raw.endswith(b"\n"), "complete kernel trace")
    parsed, offset, nonmarkers = [], 0, 0
    for line in raw.splitlines(keepends=True):
        match = MARKER.fullmatch(line)
        if match:
            parsed.append((int(match[2]), offset, offset + len(line), int(match[1])))
        else:
            require(b"getpgid(" not in line, "malformed actual marker syscall")
            require(re.match(rb"\s*\d+\s+", line) is not None, "kernel line lacks actual process identity")
            require(re.search(rb"\s(?:connect|socket|socketpair|bind|listen|accept|sendto|recvfrom)\(", line) is None,
                    "remote/network I/O outside reference domain")
            nonmarkers += 1
        offset += len(line)
    same([value[0] for value in parsed], [value[0] for value in markers], "kernel marker order")
    same([value[0] for value in parsed], list(range(1_000_000_001, 1_000_000_001 + len(parsed))), "kernel marker sequence")
    require(len({value[3] for value in parsed}) == 1, "one actual current-thread marker producer")
    index = []
    for position, ((marker, begin, end, pid), (_, kind, case_id, event)) in enumerate(zip(parsed, markers)):
        until = parsed[position + 1][1] if position + 1 < len(parsed) else len(raw)
        index.append({"process": name, "marker": marker, "pid": pid, "record_kind": kind, "case_id": case_id,
                      "event": event, "marker_offset": begin, "effects_offset": end, "effects_end": until,
                      "effects": pin(raw[end:until])})
    return index, nonmarkers


def _input_stream(raw, expected_rows):
    same(raw, b"".join(canonical(row) for row in expected_rows), "complete regenerated original input")


class _Export:
    def __init__(self, path, magic):
        self.stream = path.open("rb")
        header = self.stream.read(16)
        require(len(header) == 16 and header[:8] == magic, "actual observation export header")
        self.expected, = struct.unpack("<Q", header[8:])
        self.count = 0

    def take(self, identifier, variant, values):
        header = struct.pack("<" + "Q" * (2 + len(values)), identifier, variant, *(len(value) for value in values))
        same(self.stream.read(len(header)), header, "actual observation export record")
        for value in values: same(self.stream.read(len(value)), value, "complete actual observation export bytes")
        self.count += 1
        require(self.count <= self.expected, "observation export count overflow")

    def finish(self):
        require(self.count == self.expected and self.stream.read(1) == b"", "complete observation export count/suffix")
        self.stream.close()


def _streams(output, grouped):
    counts = {"scenarios": 0, "case_steps": 0, "public_calls": 0, "helper_calls": 0,
              "private_controls": 0, "outer_call_tool_entries": 0, "handler_entries": 0,
              "kernel_markers": 0, "kernel_file_and_network_records": 0,
              "body_bytes": 0, "largest_body_bytes": 0, "poison_steps": 0,
              "render_cases": 0, "render_body_bytes": 0}
    kernel_rows = []
    diagnostics = []
    typed_export = _Export(inside(output, "typed-observations.bin"), b"HWDPT001")
    render_export = _Export(inside(output, "render-observations.bin"), b"HWDJR001")
    error_export = _Export(inside(output, "error-observations.bin"), b"HWDJE001")
    observation_index = []
    typed_rejections = 0
    omitted_lossy_errors = 0
    for policy, scenarios in grouped.items():
        name = "replay-" + policy
        markers = []
        records = _read_records(inside(output, name + ".stdout"))
        for scenario in scenarios:
            roots = {session["id"]: session["root_hex"] for session in scenario["sessions"]}
            sequence = [("scenario_start", None), *(("case", step) for step in scenario["steps"]), ("scenario_end", None)]
            previous_states = {}
            for kind, step in sequence:
                item = next(records, None)
                require(item is not None, "missing original record")
                metadata, blobs = item
                require(type(metadata) is dict and metadata.get("kind") == kind, "original record order")
                same(metadata["scenario_id"], scenario["scenario_id"], "original scenario id")
                used = set()
                if kind == "scenario_start":
                    same(metadata["name"], scenario["name"], "scenario name")
                    same(metadata["policy_id"], policy, "scenario policy")
                    require(len(metadata["sessions"]) == len(scenario["sessions"]), "session creation count")
                    for observed, requested in zip(metadata["sessions"], scenario["sessions"]):
                        same(observed["session"], requested["id"], "session creation id")
                        _snapshot(observed["state"], requested["root_hex"])
                        same(observed["state"], {"root_hex": requested["root_hex"], "current_hex": None,
                             "effective_hex": requested["root_hex"], "poisoned": False, "session_applied": False}, "new original session")
                        require(len(observed["exchanges"]) == len(requested["initial_messages"]), "initialization exchange count")
                        for exchange, message in zip(observed["exchanges"], requested["initial_messages"]): _exchange(exchange, message, blobs, used)
                        previous_states[requested["id"]] = observed["state"]
                    counts["scenarios"] += 1
                elif kind == "case":
                    for key in ("case_id", "name", "domain", "session"): same(metadata[key], step[key], "case " + key)
                    sid = step["session"]
                    _snapshot(metadata["state_before"], roots[sid]); _snapshot(metadata["state_after"], roots[sid])
                    same(metadata["state_before"], previous_states[sid], "same-session state continuity")
                    previous_states[sid] = metadata["state_after"]
                    require(not metadata["state_before"]["session_applied"] or metadata["state_after"]["session_applied"], "latch reset by later operation")
                    for key in ("outer_call_tool_entries", "handler_entries"):
                        require(type(metadata[key]) is int and metadata[key] in (0, 1), "actual SDK entry count")
                        counts[key] += metadata[key]
                    counts["case_steps"] += 1
                    counts[{"public-sdk": "public_calls", "helper": "helper_calls", "private-control": "private_controls", "private-render": "render_cases"}[step["domain"]]] += 1
                    action = step["action"]
                    if action["kind"] == "public":
                        response = _exchange(metadata["result"], action["message"], blobs, used)
                        if metadata["handler_entries"] == 0:
                            same(metadata["state_after"], metadata["state_before"], "SDK refusal before original handler")
                        else:
                            require(metadata["outer_call_tool_entries"] == 1 and metadata["state_after"]["session_applied"] is True,
                                    "original handler context/latch ordering")
                        diagnostics.append({"case_id": step["case_id"], "name": step["name"],
                            "source_output": name + ".stdout", "request_blob": metadata["result"]["request_blob"],
                            "outer_entries": metadata["outer_call_tool_entries"], "handler_entries": metadata["handler_entries"],
                            "response": response})
                    elif action["kind"] == "helper":
                        _body(metadata["result"], blobs, used, "direct helper result")
                        same(metadata["state_after"], metadata["state_before"], "helper has no state application")
                    elif action["kind"] == "render":
                        rendered = _body(metadata["result"], blobs, used, "private original result rendering")
                        require(metadata["result"]["ok"] is True, "original result-only rendering success")
                        same(metadata["state_after"], metadata["state_before"], "result-only rendering has no state effects")
                        counts["render_body_bytes"] += len(rendered)
                        counts["body_bytes"] += len(rendered)
                        counts["largest_body_bytes"] = max(counts["largest_body_bytes"], len(rendered))
                    elif action["kind"] == "poison":
                        require(metadata["result"] == {"actual_poisoned_lock": True} and metadata["state_after"]["poisoned"] is True,
                                "actual RwLock poison control")
                        counts["poison_steps"] += 1
                    if action["kind"] != "public":
                        require(metadata["outer_call_tool_entries"] == metadata["handler_entries"] == 0, "private action counted as SDK execution")
                else:
                    same(sorted(metadata["sessions"]), sorted(roots), "terminal session ids")
                    for sid, value in metadata["sessions"].items():
                        same(value["state"], previous_states[sid], "terminal original session")
                        require(type(value["service"]["initialized"]) is bool, "actual SDK service state")
                event_counts = {}
                handler_body = helper_body = None
                handler_ok = None
                canonical_arguments = typed_raw = None
                render_records = []
                error_records = []
                if kind == "case" and step["domain"] == "private-render":
                    render_records.append((metadata["result"], "private-render"))
                for event in metadata["events"]:
                    require(type(event) is dict and set(event) == {"kind", "marker", "data", "state"}, "event fields")
                    require(event["kind"] in EVENTS and type(event["marker"]) is int, "event kind/marker")
                    event_counts[event["kind"]] = event_counts.get(event["kind"], 0) + 1
                    if event["state"] is not None:
                        _snapshot(event["state"], roots[step["session"]] if kind == "case" else None)
                    markers.append((event["marker"], kind, metadata.get("case_id"), event["kind"]))
                    data = event["data"]
                    if event["kind"] in ("helper_exit", "handler_exit"):
                        body = _body(data, blobs, used, "observed original body")
                        counts["body_bytes"] += len(body); counts["largest_body_bytes"] = max(counts["largest_body_bytes"], len(body))
                        if event["kind"] == "helper_exit":
                            helper_body = body
                            if data["ok"]: render_records.append((data, "helper"))
                            else: error_records.append(body)
                        else: handler_body, handler_ok = body, data["ok"]
                    elif event["kind"] == "outer_call_tool_enter":
                        canonical_arguments = _blob(blobs, data["canonical_arguments_blob"], used, "actual canonical SDK arguments")
                        require(type(data["canonical_arguments_bytes"]) is int and len(canonical_arguments) == data["canonical_arguments_bytes"], "actual canonical SDK extent")
                        parsed = strict_json(canonical_arguments)
                        require(type(parsed) is dict, "actual SDK arguments Map")
                        requested = step["action"]["message"]["params"].get("arguments")
                        same(parsed, {} if requested is None else requested, "actual SDK canonical argument values")
                    elif event["kind"] == "helper_enter":
                        parameters = strict_json(_blob(blobs, data["parameters_blob"], used, "actual helper parameters"))
                        if kind == "case" and step["action"]["kind"] == "helper": same(parameters, step["action"]["parameters"], "direct original helper input")
                    elif event["kind"] == "handler_enter":
                        typed_raw = _blob(blobs, data["typed_parameters_blob"], used, "actual typed parameters")
                        typed = strict_json(typed_raw)
                        require(type(typed) is dict and set(typed) == {"path", "reset"}, "actual typed serialization fields")
                        require(typed["path"] is None or type(typed["path"]) is str, "actual typed path")
                        require(typed["reset"] is None or type(typed["reset"]) is bool, "actual typed reset")
                require(used == set(range(len(blobs))), "unreferenced complete output blob")
                if kind == "case":
                    if canonical_arguments is not None:
                        identifier = step["case_id"]
                        response_raw = blobs[metadata["result"]["response_blob"]]
                        typed_bytes = b"" if typed_raw is None else typed_raw
                        diagnostic = response["error"]["message"].encode() if typed_raw is None else b""
                        typed_kind = int(typed_raw is None)
                        typed_rejections += typed_kind
                        typed_export.take(identifier, typed_kind, (canonical_arguments, typed_bytes, diagnostic, response_raw))
                        observation_index.append({"kind": "typed", "case_id": identifier, "name": step["name"], "process": name,
                            "handler_entries": metadata["handler_entries"], "canonical_arguments": pin(canonical_arguments),
                            "typed_serialization": pin(typed_bytes), "diagnostic": pin(diagnostic), "sdk_response": pin(response_raw)})
                    for record, domain in render_records:
                        detail = record["detail"]
                        variant = {"get": 0, "set": 1, "reset": 2}[detail["kind"]]
                        previous = bytes.fromhex(detail.get("previous_hex", "")); current = bytes.fromhex(detail.get("current_hex", ""))
                        body = blobs[record["body_blob"]]
                        render_export.take(step["case_id"], variant, (previous, current, body))
                        observation_index.append({"kind": "render", "case_id": step["case_id"], "name": step["name"], "process": name,
                            "domain": domain, "variant": variant, "previous": pin(previous), "current": pin(current), "body": pin(body)})
                    for body in error_records:
                        if body == b"Parameter 'path' must be a non-empty string":
                            variant, path, detail = 4, b"", b""
                        elif body.startswith(b"Path does not exist or is not accessible: "):
                            require(body.endswith(b")"), "complete original canonical failure framing")
                            path, separator, detail = body[len(b"Path does not exist or is not accessible: "):-1].rpartition(b" (error: ")
                            require(separator and detail, "original canonical error separator")
                            variant = 5
                        else:
                            require(body.startswith(b"Path is not a directory: "), "original helper error variant")
                            variant, path, detail = 6, body[len(b"Path is not a directory: "):], b""
                        if b"\xef\xbf\xbd" in path:
                            omitted_lossy_errors += 1
                            continue
                        path.decode("utf-8")
                        error_export.take(step["case_id"], variant, (path, detail, body))
                        observation_index.append({"kind": "helper-error", "case_id": step["case_id"], "name": step["name"], "process": name,
                            "variant": variant, "raw_path_inferred_only_from_lossless_display": True,
                            "path": pin(path), "os_error_text": pin(detail), "body": pin(body)})
                    require(event_counts.get("step_begin") == event_counts.get("step_end") == 1, "case event boundaries")
                    require(metadata["events"][0]["kind"] == "step_begin" and metadata["events"][-1]["kind"] == "step_end", "ordered case event boundaries")
                    same(metadata["events"][0]["state"], metadata["state_before"], "actual state before first event")
                    same(metadata["events"][-1]["state"], metadata["state_after"], "actual state after last event")
                    require(event_counts.get("outer_call_tool_enter", 0) == metadata["outer_call_tool_entries"], "outer SDK count/event binding")
                    require(event_counts.get("handler_enter", 0) == event_counts.get("handler_exit", 0) == metadata["handler_entries"], "handler count/event binding")
                    require(event_counts.get("helper_enter", 0) == event_counts.get("helper_exit", 0), "complete helper event pair")
                    if handler_body is not None and helper_body is not None: same(handler_body, helper_body, "unchanged helper/handler body")
                    if handler_body is not None:
                        content = response["result"]["content"]
                        require(type(content) is list and len(content) == 1 and content[0]["type"] == "text", "actual SDK string adaptation")
                        same(content[0]["text"].encode(), handler_body, "complete adapted original body")
                        require(response["result"].get("isError", False) is (not handler_ok), "actual SDK string-result error flag")
        require(next(records, None) is None, "extra original record")
        index, nonmarkers = _kernel(inside(output, name + ".strace").read_bytes(), markers, name)
        kernel_rows.extend(index); counts["kernel_markers"] += len(markers); counts["kernel_file_and_network_records"] += nonmarkers
    expected_index = b"".join(canonical(row) for row in kernel_rows)
    same(inside(output, "kernel-index.jsonl").read_bytes(), expected_index, "complete kernel interval index")
    typed_export.finish(); render_export.finish(); error_export.finish()
    same(inside(output, "observation-index.jsonl").read_bytes(), b"".join(canonical(row) for row in observation_index), "complete actual observation index")
    observations = {"typed_records": typed_export.count, "render_records": render_export.count,
                    "typed_rejections": typed_rejections, "renderer_private_cases": counts["render_cases"],
                    "error_records": error_export.count, "error_omitted_lossy_paths": omitted_lossy_errors}
    return counts, diagnostics, observations


def _module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def reference_evidence(root, output, *, oracle_root=None):
    root, output = Path(root).absolute(), Path(output).absolute()
    oracle = root / "tests/hia_native/workdir_oracle" if oracle_root is None else Path(oracle_root).absolute()
    source = _module(oracle / "verify_sources.py", "_workdir_qualification_source")
    cases = _module(oracle / "cases.py", "_workdir_qualification_cases")
    result = strict_json(inside(output, "result.json").read_bytes())
    require(type(result) is dict and set(result) == {"schema", "status", "execution_output_root", "execution_runtime_root",
        "source_commit", "materialized", "summary", "observations", "recorded_processes", "actual_original_rust_replays", "fresh_cargo_builds",
        "rustc_version_processes", "strace_version_processes", "native_comparison_executed", "full_original_router_executed",
        "original_workdir_body_executed", "actual_sdk_transport_and_extractor", "actual_local_filesystem", "actual_kernel_trace",
        "remote_io_executed", "configuration_loader_executed", "whole_runtime_replaced", "artifacts"}, "complete reference report fields")
    require(result["schema"] == SCHEMA and result["status"] == "REFERENCE_READY", "reference-only status")
    for field, expected in {"native_comparison_executed": False, "full_original_router_executed": False,
        "original_workdir_body_executed": True, "actual_sdk_transport_and_extractor": True,
        "actual_local_filesystem": True, "actual_kernel_trace": True, "remote_io_executed": False,
        "configuration_loader_executed": False, "whole_runtime_replaced": False}.items():
        require(result[field] is expected, field + " scope")
    execution = result["execution_output_root"]
    require(type(execution) is str and Path(execution).is_absolute() and "\0" not in execution, "execution output provenance")
    execution = Path(execution)
    inputs = cases.materialized(execution / "fixtures")
    grouped = {key: [row for row in inputs["scenarios"] if row["policy_id"] == key] for key in inputs["policies"]}
    artifact_names = {"source-pins.json", "process-receipts.json", "input-index.json", "kernel-index.jsonl",
                      "typed-observations.bin", "render-observations.bin", "error-observations.bin", "observation-index.jsonl"}
    for name in ("rust-version", "strace-version", "build"):
        artifact_names.update({name + ".stdout", name + ".stderr"})
    for name, rows in grouped.items():
        artifact_names.update({"replay-" + name + suffix for suffix in (".input.jsonl", ".stdout", ".stderr", ".strace")})
        artifact_names.add("policy-" + name + ".json")
        _input_stream(inside(output, "replay-" + name + ".input.jsonl").read_bytes(), rows)
        same(inside(output, "policy-" + name + ".json").read_bytes(), canonical(inputs["policies"][name]), "original policy input")
    same(set(result["artifacts"]), artifact_names, "complete artifact inventory")
    artifact_sha256 = {}
    for name, expected in result["artifacts"].items():
        _hash_fields(expected); same(identity(inside(output, name)), expected, "actual artifact " + name)
        artifact_sha256[name] = expected["sha256"]
    pins = strict_json(inside(output, "source-pins.json").read_bytes())
    same(pins["harness"], {name: identity(oracle / name) for name in source.HARNESS_FILES}, "complete harness inputs")
    same(pins["original"], {name: identity(root / name) for name in source.SOURCE_FILES}, "complete original inputs")
    same(pins["canonical_policy_target"], source.target_source_pins(), "complete current-target policy inputs")
    assembled, manifest = source.check_sources(root)
    same(result["source_commit"], manifest["commit"], "original commit identity")
    for name, raw in (("Cargo.toml", (oracle / "Cargo.toml").read_bytes()), ("Cargo.lock", (oracle / "Cargo.lock").read_bytes()), ("src/main.rs", assembled)):
        actual = inside(output, "crate/" + name)
        same(actual.read_bytes(), raw, "materialized unchanged original " + name)
        same(pins["materialized"][name], pin(raw), "materialized source pin")
        artifact_sha256["crate/" + name] = pin(raw)["sha256"]
    same(result["materialized"]["source"], pin(assembled), "assembled original source")
    same(result["materialized"], {"source_commit": manifest["commit"], "source": pin(assembled),
        "canonical_policy_target": manifest["canonical_policy_target"],
        "original_file_count": len(source.SOURCE_FILES), "original_body_count": len(manifest["extractions"]),
        "registry_dependencies": source.dependency_subset(root), "original_bodies_unchanged": True,
        "actual_sdk_parameters_extractor": True, "actual_sdk_method_adapter": True,
        "original_workdir_body_executed": True, "original_full_router_executed": False,
        "configuration_installation_fixture": True, "original_config_loader_executed": False,
        "remote_io_executed": False, "unsupported_remote_branch_aborts": True}, "complete materialized source scope")
    binary = inside(output, "target/release/hepta-workdir-original-oracle")
    require(binary.read_bytes()[:4] == b"\x7fELF", "actual original ELF")
    same(identity(binary), {key: pins["executables"]["original"][key] for key in ("bytes", "sha256")}, "actual original ELF pin")
    artifact_sha256["target/release/hepta-workdir-original-oracle"] = identity(binary)["sha256"]
    invocations = {key: value["invocation"] for key, value in pins["executables"].items()}
    same(invocations["original"], str(execution / "target/release/hepta-workdir-original-oracle"), "actual original executable command")
    commands = [("rust-version", [invocations["rustc"], "--version"], None),
                ("strace-version", [invocations["strace"], "--version"], None),
                ("build", [invocations["cargo"], "build", "--locked", "--manifest-path", str(execution / "crate/Cargo.toml"), "--release"], None)]
    receipts = strict_json(inside(output, "process-receipts.json").read_bytes())
    # An explicit cached-host request may append --offline; it is not required
    # for a production fresh build and never changes dependency/source checks.
    if len(receipts) > 2 and receipts[2].get("command") == commands[2][1] + ["--offline"]:
        commands[2][1].append("--offline")
    for name in grouped:
        commands.append(("replay-" + name, [invocations["strace"], "-f", "-qq", "-s", "0", "-xx", "-e", "trace=%file,%network,getpgid",
            "-o", str(execution / ("replay-" + name + ".strace")), invocations["original"], str(execution / "fixtures"), str(execution / ("policy-" + name + ".json"))],
            identity(inside(output, "replay-" + name + ".input.jsonl"))))
    require(len(receipts) == len(commands), "complete actual process count")
    for receipt, (name, command, input_pin) in zip(receipts, commands):
        _receipt(receipt, {"name": name, "command": command, "cwd": str(execution / "crate"), "stdin": input_pin}, output)
    for field, value in (("recorded_processes", len(commands)), ("actual_original_rust_replays", len(grouped)),
                         ("fresh_cargo_builds", 1), ("rustc_version_processes", 1), ("strace_version_processes", 1)):
        same(result[field], value, "original process accounting " + field)
    counts, diagnostics, observations = _streams(output, grouped)
    same(result["summary"], counts, "recounted original streams")
    same(result["observations"], observations, "recounted actual observation exports")
    artifact_sha256["result.json"] = identity(inside(output, "result.json"))["sha256"]
    return {"schema": "hepta.runtime.workdir-original-evidence.v1", "status": "REFERENCE_READY",
            "original_workdir_body_executed": True, "actual_sdk_parameters_extractor": True,
            "actual_local_filesystem": True, "actual_kernel_trace": True,
            "original_full_router_executed": False, "remote_io_executed": False,
            "native_comparison_executed": False, "whole_runtime_replaced": False,
            "summary": counts, "observations": observations, "recorded_processes": len(commands), "actual_original_rust_replays": len(grouped),
            "source_sha256": {"original": {name: value["sha256"] for name, value in pins["original"].items()},
                              "harness": {name: value["sha256"] for name, value in pins["harness"].items()}},
            "artifact_sha256": artifact_sha256, "diagnostics": diagnostics}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--oracle-root", type=Path)
    parser.add_argument("--evidence-output", type=Path, required=True)
    args = parser.parse_args()
    admitted = reference_evidence(args.runtime_root, args.output, oracle_root=args.oracle_root)
    raw = canonical(admitted)
    with args.evidence_output.open("xb") as stream: stream.write(raw)
    print(json.dumps({"status": admitted["status"], "summary": admitted["summary"],
                      "observations": admitted["observations"], "evidence": pin(raw)}, sort_keys=True))
