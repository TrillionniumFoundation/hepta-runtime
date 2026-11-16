"""Fresh locked workdir reference with complete SDK, state and kernel streams."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parent


def sibling(name):
    spec = importlib.util.spec_from_file_location("_workdir_original_" + name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cases, sources = sibling("cases"), sibling("verify_sources")
canonical = sources.canonical


def identity(path):
    size = 0
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1 << 20):
            size += len(block)
            digest.update(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


def process(name, command, output, cwd, env, receipts, stdin=None):
    started = time.monotonic()
    status, timed_out, start_error = None, False, None
    with contextlib.ExitStack() as stack:
        input_stream = stack.enter_context(Path(stdin).open("rb")) if stdin else subprocess.DEVNULL
        stdout = stack.enter_context((output / (name + ".stdout")).open("xb"))
        stderr = stack.enter_context((output / (name + ".stderr")).open("xb"))
        try:
            child = subprocess.run(command, cwd=cwd, env=env, stdin=input_stream,
                                   stdout=stdout, stderr=stderr, timeout=180)
            status = child.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        except OSError as error:
            start_error = str(error)
    receipt = {"name": name, "command": command, "cwd": str(cwd), "timeout_seconds": 180,
               "elapsed_seconds": time.monotonic() - started, "exit_code": status,
               "timed_out": timed_out, "start_error": start_error,
               "stdout": identity(output / (name + ".stdout")),
               "stderr": identity(output / (name + ".stderr")),
               "stdin": None if stdin is None else identity(stdin)}
    receipts.append(receipt)
    (output / "process-receipts.json").write_bytes(canonical(receipts))
    if status != 0 or timed_out or start_error is not None:
        raise AssertionError("actual reference process failed; full streams retained: " + name)
    return receipt


def observed_summary(output, grouped):
    counts = {"scenarios": 0, "case_steps": 0, "public_calls": 0, "helper_calls": 0,
              "private_controls": 0, "outer_call_tool_entries": 0, "handler_entries": 0,
              "kernel_markers": 0, "kernel_file_and_network_records": 0,
              "body_bytes": 0, "largest_body_bytes": 0, "poison_steps": 0,
              "render_cases": 0, "render_body_bytes": 0}
    index = []
    for policy_id, scenarios in grouped.items():
        name = "replay-" + policy_id
        expected = []
        for row in scenarios:
            expected.append(("scenario_start", row, None))
            expected.extend(("case", row, step) for step in row["steps"])
            expected.append(("scenario_end", row, None))
        markers = []
        with (output / (name + ".stdout")).open("rb") as stream:
            records = cases.read_records(stream)
            for kind, row, step in expected:
                metadata, blobs = next(records)
                assert metadata["kind"] == kind and metadata["scenario_id"] == row["scenario_id"]
                if kind == "scenario_start":
                    counts["scenarios"] += 1
                if kind == "case":
                    assert (metadata["case_id"], metadata["name"], metadata["domain"]) == (step["case_id"], step["name"], step["domain"])
                    counts["case_steps"] += 1
                    counts[{"public-sdk": "public_calls", "helper": "helper_calls", "private-control": "private_controls", "private-render": "render_cases"}[step["domain"]]] += 1
                    counts["outer_call_tool_entries"] += metadata["outer_call_tool_entries"]
                    counts["handler_entries"] += metadata["handler_entries"]
                    counts["poison_steps"] += step["action"]["kind"] == "poison"
                    if step["domain"] == "private-render":
                        body = blobs[metadata["result"]["body_blob"]]
                        assert len(body) == metadata["result"]["body_bytes"]
                        counts["render_body_bytes"] += len(body)
                        counts["body_bytes"] += len(body)
                        counts["largest_body_bytes"] = max(counts["largest_body_bytes"], len(body))
                for event in metadata["events"]:
                    markers.append((event["marker"], kind, metadata.get("case_id"), event["kind"]))
                    if event["kind"] in ("helper_exit", "handler_exit"):
                        body = blobs[event["data"]["body_blob"]]
                        assert len(body) == event["data"]["body_bytes"]
                        counts["body_bytes"] += len(body)
                        counts["largest_body_bytes"] = max(counts["largest_body_bytes"], len(body))
            assert next(records, None) is None
        raw_trace = (output / (name + ".strace")).read_bytes()
        parsed = []
        offset = 0
        for line in raw_trace.splitlines(keepends=True):
            match = re.fullmatch(rb"\s*(\d+)\s+getpgid\((\d+)\)\s+= -1 ESRCH \(No such process\)\n", line)
            if match:
                parsed.append((int(match[2]), offset, offset + len(line), int(match[1])))
            else:
                counts["kernel_file_and_network_records"] += 1
            offset += len(line)
        assert [row[0] for row in parsed] == [row[0] for row in markers]
        counts["kernel_markers"] += len(markers)
        for position, ((marker, begin, end, pid), (_, kind, case_id, event)) in enumerate(zip(parsed, markers)):
            until = parsed[position + 1][1] if position + 1 < len(parsed) else len(raw_trace)
            index.append({"process": name, "marker": marker, "pid": pid, "record_kind": kind,
                          "case_id": case_id, "event": event, "marker_offset": begin,
                          "effects_offset": end, "effects_end": until,
                          "effects": sources.pin(raw_trace[end:until])})
    (output / "kernel-index.jsonl").write_bytes(b"".join(canonical(row) for row in index))
    return counts


def export_observations(output, grouped):
    """Export actual Rust bytes; do not synthesize a typed or render result."""
    typed_rows, rendered_rows, error_rows, index = [], [], [], []
    lossy_error_paths = 0
    for policy in grouped:
        name = "replay-" + policy
        with (output / (name + ".stdout")).open("rb") as stream:
            for metadata, blobs in cases.read_records(stream):
                if metadata["kind"] != "case": continue
                identifier = metadata["case_id"]
                outer = [event for event in metadata["events"] if event["kind"] == "outer_call_tool_enter"]
                entered = [event for event in metadata["events"] if event["kind"] == "handler_enter"]
                if metadata["domain"] == "public-sdk" and outer:
                    assert len(outer) == 1 and len(entered) == metadata["handler_entries"]
                    arguments = blobs[outer[0]["data"]["canonical_arguments_blob"]]
                    response = blobs[metadata["result"]["response_blob"]]
                    actual_response = json.loads(response)
                    typed = blobs[entered[0]["data"]["typed_parameters_blob"]] if entered else b""
                    diagnostic = b"" if entered else actual_response["error"]["message"].encode()
                    kind = 0 if entered else 1
                    typed_rows.append((identifier, kind, arguments, typed, diagnostic, response))
                    index.append({"kind": "typed", "case_id": identifier, "name": metadata["name"], "process": name,
                        "handler_entries": len(entered), "canonical_arguments": sources.pin(arguments),
                        "typed_serialization": sources.pin(typed), "diagnostic": sources.pin(diagnostic), "sdk_response": sources.pin(response)})
                observed = [(event["data"], "helper") for event in metadata["events"] if metadata["domain"] != "private-render" and event["kind"] == "helper_exit" and event["data"]["ok"]]
                if metadata["domain"] == "private-render": observed.append((metadata["result"], "private-render"))
                for record, domain in observed:
                    detail = record["detail"]; variant = {"get": 0, "set": 1, "reset": 2}[detail["kind"]]
                    previous = bytes.fromhex(detail.get("previous_hex", "")); current = bytes.fromhex(detail.get("current_hex", ""))
                    body = blobs[record["body_blob"]]
                    rendered_rows.append((identifier, variant, previous, current, body))
                    index.append({"kind": "render", "case_id": identifier, "name": metadata["name"], "process": name,
                        "domain": domain, "variant": variant, "previous": sources.pin(previous), "current": sources.pin(current), "body": sources.pin(body)})
                for event in metadata["events"]:
                    if event["kind"] != "helper_exit" or event["data"]["ok"]: continue
                    body = blobs[event["data"]["body_blob"]]
                    if body == b"Parameter 'path' must be a non-empty string":
                        variant, path, detail = 4, b"", b""
                    elif body.startswith(b"Path does not exist or is not accessible: "):
                        assert body.endswith(b")")
                        path, separator, detail = body[len(b"Path does not exist or is not accessible: "):-1].rpartition(b" (error: ")
                        assert separator and detail
                        variant = 5
                    else:
                        assert body.startswith(b"Path is not a directory: ")
                        variant, path, detail = 6, body[len(b"Path is not a directory: "):], b""
                    if b"\xef\xbf\xbd" in path:
                        lossy_error_paths += 1
                        continue
                    path.decode("utf-8")
                    error_rows.append((identifier, variant, path, detail, body))
                    index.append({"kind": "helper-error", "case_id": identifier, "name": metadata["name"], "process": name,
                        "variant": variant, "raw_path_inferred_only_from_lossless_display": True,
                        "path": sources.pin(path), "os_error_text": sources.pin(detail), "body": sources.pin(body)})
    import struct
    with (output / "typed-observations.bin").open("xb") as stream:
        stream.write(b"HWDPT001" + struct.pack("<Q", len(typed_rows)))
        for identifier, kind, arguments, typed, diagnostic, response in typed_rows:
            stream.write(struct.pack("<6Q", identifier, kind, len(arguments), len(typed), len(diagnostic), len(response)))
            stream.write(arguments + typed + diagnostic + response)
    with (output / "render-observations.bin").open("xb") as stream:
        stream.write(b"HWDJR001" + struct.pack("<Q", len(rendered_rows)))
        for identifier, variant, previous, current, body in rendered_rows:
            stream.write(struct.pack("<5Q", identifier, variant, len(previous), len(current), len(body)))
            stream.write(previous + current + body)
    with (output / "error-observations.bin").open("xb") as stream:
        stream.write(b"HWDJE001" + struct.pack("<Q", len(error_rows)))
        for identifier, variant, path, detail, body in error_rows:
            stream.write(struct.pack("<5Q", identifier, variant, len(path), len(detail), len(body)))
            stream.write(path + detail + body)
    (output / "observation-index.jsonl").write_bytes(b"".join(canonical(row) for row in index))
    return {"typed_records": len(typed_rows), "render_records": len(rendered_rows),
            "typed_rejections": sum(row[1] for row in typed_rows), "renderer_private_cases": sum(row["domain"] == "private-render" for row in index if row["kind"] == "render"),
            "error_records": len(error_rows), "error_omitted_lossy_paths": lossy_error_paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--strace", type=Path, default=Path("/usr/bin/strace"))
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    source_before = {name: identity(ROOT / name) for name in sources.HARNESS_FILES}
    policy_before = sources.target_source_pins()
    runtime_before = {name: identity(args.runtime_root / name) for name in sources.SOURCE_FILES}
    crate = output / "crate"
    materialized = sources.materialize(args.runtime_root, crate)
    fixture_root = output / "fixtures"
    fixture_root.mkdir()
    inputs = cases.materialized(fixture_root)
    grouped = {name: [row for row in inputs["scenarios"] if row["policy_id"] == name]
               for name in inputs["policies"]}
    assert all(grouped.values())
    for name, rows in grouped.items():
        (output / ("replay-" + name + ".input.jsonl")).write_bytes(b"".join(canonical(row) for row in rows))
        (output / ("policy-" + name + ".json")).write_bytes(canonical(inputs["policies"][name]))
    (output / "input-index.json").write_bytes(canonical({"fixture_root": str(fixture_root),
        "groups": {name: [{"scenario_id": row["scenario_id"], "name": row["name"],
            "case_ids": [step["case_id"] for step in row["steps"]]} for row in rows] for name, rows in grouped.items()}}))
    environment = dict(os.environ)
    environment.update(RUSTC=str(args.rustc.absolute()), CARGO_TARGET_DIR=str(output / "target"),
                       CARGO_BUILD_JOBS="2", LC_ALL="C", TZ="UTC")
    environment["PATH"] = str(args.cargo.absolute().parent) + os.pathsep + environment.get("PATH", "")
    receipts = []
    process("rust-version", [str(args.rustc.absolute()), "--version"], output, crate, environment, receipts)
    process("strace-version", [str(args.strace.absolute()), "--version"], output, crate, environment, receipts)
    command = [str(args.cargo.absolute()), "build", "--locked", "--manifest-path", str(crate / "Cargo.toml"), "--release"]
    if args.offline: command.append("--offline")
    process("build", command, output, crate, environment, receipts)
    binary = output / "target/release/hepta-workdir-original-oracle"
    for name in grouped:
        process("replay-" + name, [str(args.strace.absolute()), "-f", "-qq", "-s", "0", "-xx",
            "-e", "trace=%file,%network,getpgid", "-o", str(output / ("replay-" + name + ".strace")),
            str(binary), str(fixture_root), str(output / ("policy-" + name + ".json"))],
            output, crate, environment, receipts, output / ("replay-" + name + ".input.jsonl"))
    summary = observed_summary(output, grouped)
    observations = export_observations(output, grouped)
    source_after = {name: identity(ROOT / name) for name in sources.HARNESS_FILES}
    runtime_after = {name: identity(args.runtime_root / name) for name in sources.SOURCE_FILES}
    assert source_before == source_after and runtime_before == runtime_after
    assert sources.target_source_pins() == policy_before
    (output / "source-pins.json").write_bytes(canonical({"harness": source_before, "original": runtime_before,
        "canonical_policy_target": policy_before,
        "materialized": {name: identity(crate / name) for name in ("Cargo.toml", "Cargo.lock", "src/main.rs")},
        "executables": {name: {"invocation": str(path.absolute()), "resolved": str(path.resolve()),
            **identity(path)} for name, path in (("cargo", args.cargo), ("rustc", args.rustc), ("strace", args.strace), ("original", binary))}}))
    artifact_names = [path.name for path in output.iterdir() if path.is_file() and path.name != "result.json"]
    artifacts = {name: identity(output / name) for name in sorted(artifact_names)}
    result = {"schema": "hepta.runtime.workdir-original-reference.v1", "status": "REFERENCE_READY",
        "execution_output_root": str(output), "execution_runtime_root": str(args.runtime_root.absolute()),
        "source_commit": materialized["source_commit"], "materialized": materialized,
        "summary": summary, "observations": observations, "recorded_processes": len(receipts), "actual_original_rust_replays": len(grouped),
        "fresh_cargo_builds": 1, "rustc_version_processes": 1, "strace_version_processes": 1,
        "native_comparison_executed": False, "full_original_router_executed": False,
        "original_workdir_body_executed": True, "actual_sdk_transport_and_extractor": True,
        "actual_local_filesystem": True, "actual_kernel_trace": True, "remote_io_executed": False,
        "configuration_loader_executed": False, "whole_runtime_replaced": False,
        "artifacts": artifacts}
    (output / "result.json").write_bytes(canonical(result))
    print(json.dumps({"status": "REFERENCE_READY", "summary": summary,
                      "recorded_processes": len(receipts), "actual_original_rust_replays": len(grouped)}, sort_keys=True))


if __name__ == "__main__":
    main()
