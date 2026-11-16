#!/usr/bin/env python3
"""Compare actual native G2 state and ordinary responses to the target oracle.

This is a bounded normal-function qualification. It does not qualify the full
message codec, asynchronous EOF behavior, cached default handlers, production
handlers, or compiler cold bootstrap.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sha = lambda raw: hashlib.sha256(raw).hexdigest()
U = lambda raw, offset: struct.unpack_from("<Q", raw, offset)[0]


def pair(raw, offset):
    at, size = struct.unpack_from("<QQ", raw, offset)
    if at == 0:
        assert size == 0
        return None
    assert at + size <= len(raw)
    return raw[at:at + size]


def frame(magic, body, operation=1):
    return magic + struct.pack("<QQ", operation, len(body)) + body


def read_state(state):
    head = ctypes.string_at(ctypes.addressof(state._workspace), 64)
    mode, peer_exists = U(head, 8), bool(U(head, 16))
    sizes = [U(head, offset) for offset in (24, 32, 40)]
    assert sum(sizes) < (1 << 20) - 16384
    raw = ctypes.string_at(ctypes.addressof(state._workspace) + 16384, sum(sizes))
    version, caps, info = raw[:sizes[0]], raw[sizes[0]:sizes[0] + sizes[1]], raw[sizes[0] + sizes[1]:]
    peer = {"protocolVersion": version.decode(), "capabilities": json.loads(caps),
            "clientInfo": json.loads(info)} if peer_exists else None
    return {"header_hex": head.hex(), "mode": mode, "peer_info": peer}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-name", default="normal-v1")
    args = parser.parse_args()
    assert args.run_name.replace("-", "").isalnum()
    evidence = ROOT / "evidence"
    output = evidence / args.run_name
    output.mkdir()
    counts = {"sessions": 0, "message_calls": 0, "connection_calls": 0, "fixture_calls": 0,
              "context_joins": 0, "response_lines": 0, "bootstrap_discover_calls": 0,
              "eof_owner_calls": 0, "elf_sessions": 0, "elf_response_lines": 0}
    summary = {"schema": "hepta.g1g2g3.normal-context-regression.v1", "status": "RUNNING", "counts": counts,
               "target_sdk": "rmcp 3.9.0", "normal_domain_only": True,
               "actual_target_oracle": True, "historical_pass_reused": False,
               "production_activated": False, "old_path_removed": False,
               "full_target_qualified": False, "G1_full_codec_qualified": False,
               "G3_async_transport_qualified": False, "G4_cache_handlers_qualified": False,
               "fresh_cold_qualified": False,
               "qualifier_source_sha256": sha(Path(__file__).read_bytes()),
               "source_overlay_sha256": sha((ROOT / "source_overlay.json").read_bytes())}
    begin = time.monotonic()
    def save():
        (output / "summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    save()
    try:
        case_raw = (ROOT / "cases/normal.jsonl").read_bytes()
        reference_raw = (evidence / "oracle-normal.jsonl").read_bytes()
        cases = [json.loads(line) for line in case_raw.splitlines()]
        references = [json.loads(line) for line in reference_raw.splitlines()]
        case_manifest = json.loads((ROOT / "cases/manifest.json").read_bytes())
        assert sha(case_raw) == case_manifest["sha256"]
        oracle_build = json.loads((evidence / "oracle-build.json").read_bytes())
        observation = json.loads((evidence / "oracle-observation.json").read_bytes())
        assert observation["oracle_build_sha256"] == sha((evidence / "oracle-build.json").read_bytes())
        assert observation["binary_sha256"] == oracle_build["binary_sha256"]
        assert observation["cases_sha256"] == sha(case_raw)
        assert observation["observations_sha256"] == sha(reference_raw)
        assert json.loads((evidence / "target-lock-subset.json").read_bytes())["all_retained_exactly_match_target"]
        records = json.loads((evidence / "hia-modules.json").read_bytes())["members"]
        sys.path.insert(0, str(ROOT / "scripts"))
        from hia_native_loader import NativeModule
        def module(name):
            path = ROOT / records[name]["path"]
            assert sha(path.read_bytes()) == records[name]["sha256"]
            return NativeModule(path, manifest_sha256=records[name]["sha256"])
        observations = (output / "native-events.jsonl").open("w")
        with observations, module("message") as message, module("connection") as connection, module("fixture") as fixture:
            with message.session(output_capacity=1 << 20, workspace_capacity=2 << 20) as decoder, fixture.session(output_capacity=1 << 20, workspace_capacity=65536) as handler:
                for case, reference in zip(cases, references, strict=True):
                    assert case["label"] == reference["label"]
                    assert reference["terminal"] == {"phase": "running", "quit": "Closed"}, (case["label"], reference["terminal"])
                    actual_lines = []
                    with connection.session(output_capacity=2 << 20, workspace_capacity=1 << 20) as state:
                        for number, (event, observed) in enumerate(zip(case["events"], reference["events"], strict=True)):
                            raw = event["wire"].encode()
                            assert observed["wire"] == event["wire"]
                            request = json.loads(raw)
                            projection = decoder(frame(b"HRCJQ001", raw))
                            counts["message_calls"] += 1
                            action = state(frame(b"HRCNQ001", projection))
                            counts["connection_calls"] += 1
                            assert action[:8] == b"HRCNS001"
                            kind = U(action, 8)
                            reply = pair(action, 64) if kind == 1 else b""
                            if 2 <= kind <= 5:
                                reply = handler(action)
                                counts["fixture_calls"] += 1
                            assert kind in [1, 2, 3]
                            assert U(action, 16) == 0
                            after = read_state(state)
                            row = {"label": case["label"], "event": number, "method": request["method"],
                                   "projection_hex": projection.hex(), "admission_hex": action.hex(),
                                   "reply_hex": reply.hex(), "state_after": after}
                            observations.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                            observations.flush()
                            expected_mode = {"bootstrap": 0, "legacy": 1, "inline": 2}[event["expected_lifecycle"]]
                            assert after["mode"] == expected_mode, (case["label"], number, "persistent lifecycle", after)
                            assert U(action, 24) == int(expected_mode == 2)
                            if request["method"] == "server/discover" and expected_mode == 0:
                                assert after["peer_info"] is None
                                counts["bootstrap_discover_calls"] += 1
                            if kind == 2:
                                identifier = json.loads(pair(projection, 80))
                                method = pair(projection, 64).decode()
                                matches = [item["before"] for item in reference["trace"] if "before" in item
                                           and item["before"]["request_id"] == identifier
                                           and item["before"]["request"]["method"] == method]
                                assert len(matches) == 1, (case["label"], number, "target context match")
                                before = matches[0]
                                version = pair(action, 144)
                                assert (version.decode() if version is not None else None) == before["protocol_version"], (case["label"], number, "context version")
                                assert json.loads(pair(projection, 96)) == before["metadata"], (case["label"], number, "metadata")
                                peer = before["peer_info"]
                                assert U(action, 48) == int(peer is not None)
                                if peer is not None:
                                    assert pair(action, 112).decode() == peer["protocolVersion"]
                                    assert json.loads(pair(action, 96)) == peer["capabilities"]
                                    assert json.loads(pair(action, 128)) == peer["clientInfo"]
                                assert after["peer_info"] == peer
                                counts["context_joins"] += 1
                            if event["response"]:
                                assert "result" in observed["response"], (case["label"], number, observed["response"])
                                assert reply + b"\n" == observed["response_raw"].encode(), (case["label"], number, reply, observed["response_raw"])
                                actual_lines.append(reply + b"\n")
                                counts["response_lines"] += 1
                                if request["method"] == "initialize":
                                    assert observed["response"]["result"]["serverInfo"] == {"name": "rmcp", "version": "3.9.0"}
                                elif request["method"] == "server/discover":
                                    assert observed["response"]["result"]["_meta"]["io.modelcontextprotocol/serverInfo"] == {"name": "rmcp", "version": "3.9.0"}
                            else:
                                assert not reply
                        end = state(frame(b"HRCNQ001", b"", 2))
                        counts["connection_calls"] += 1
                        counts["eof_owner_calls"] += 1
                        assert U(end, 8) == 6 and U(end, 16) == 1 and read_state(state)["mode"] == 3
                        observations.write(json.dumps({"label": case["label"], "owner_eof_hex": end.hex()}, sort_keys=True) + "\n")
                    counts["sessions"] += 1
        fixture_dir = ROOT.parent / "hia-build-g4/g4-transport-elf"
        packed = json.loads((fixture_dir / "manifest.json").read_bytes())
        executable = fixture_dir / packed["executable"]
        assert sha(executable.read_bytes()) == packed["elf_sha256"]
        elf_dir = output / "elf"
        elf_dir.mkdir()
        processes = []
        for index, (case, reference) in enumerate(zip(cases, references, strict=True)):
            stdin = b"".join(event["wire"].encode() + b"\n" for event in case["events"])
            expected = b"".join(event["response_raw"].encode() for event in reference["events"] if "response_raw" in event)
            started = time.monotonic()
            process = subprocess.run([str(executable)], input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            stem = f"{index:03d}"
            for suffix, raw in [("stdin", stdin), ("stdout", process.stdout), ("stderr", process.stderr)]:
                (elf_dir / (stem + "." + suffix)).write_bytes(raw)
            processes.append({"label": case["label"], "stem": stem, "exit_code": process.returncode,
                "elapsed_seconds": time.monotonic() - started, "stdin_sha256": sha(stdin),
                "stdout_sha256": sha(process.stdout), "stderr_sha256": sha(process.stderr),
                "expected_stdout_sha256": sha(expected), "stdout_bytes": len(process.stdout)})
            (output / "elf-processes.json").write_text(json.dumps(processes, indent=2, sort_keys=True) + "\n")
            assert process.returncode == 0 and process.stderr == b"" and process.stdout == expected, (case["label"], "normal packed ELF")
            counts["elf_sessions"] += 1
            counts["elf_response_lines"] += len(process.stdout.splitlines())
        assert counts["sessions"] == case_manifest["sessions"] == counts["elf_sessions"]
        assert counts["message_calls"] == case_manifest["events"]
        assert counts["response_lines"] == case_manifest["expected_response_lines"] == counts["elf_response_lines"]
        summary.update(status="PASS", cases_sha256=sha(case_raw), oracle_sha256=sha(reference_raw),
            native_events_sha256=sha((output / "native-events.jsonl").read_bytes()),
            packed_elf_sha256=packed["elf_sha256"], modules=records,
            matched_boundaries=["normal bootstrap discover", "normal five-version negotiation",
                "rmcp 3.9.0 identity bytes", "metadata and protocol context",
                "peer state", "normal LF-framed packed native responses"])
    except BaseException:
        summary.update(status="FAIL", failure=traceback.format_exc())
        raise
    finally:
        summary["elapsed_seconds"] = time.monotonic() - begin
        save()
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
