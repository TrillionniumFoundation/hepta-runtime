#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify native ASAR against @electron/asar 4.2.0 and real MCP child ownership.

The fixture producer and consumer are independent upstream JavaScript. This
harness alone runs Node; the shipped ASAR and selected-source paths are Rust.
Only this harness's MCP parent and its verified direct child may be signalled.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time


HELPER = Path(__file__).with_name("rea_javascript_cancellation_external.py")
spec = importlib.util.spec_from_file_location("hepta_owned_cancellation", HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def digest(bytes_):
    return hashlib.sha256(bytes_).hexdigest()


def write_json(path, value):
    with Path(path).open("x") as output:
        json.dump(value, output, indent=2, ensure_ascii=False)
        output.write("\n")


def encode(header, data=b""):
    raw = header if isinstance(header, bytes) else json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode()
    padded = (len(raw) + 3) // 4 * 4
    return struct.pack("<IIII", 4, 8 + padded, 4 + padded, len(raw)) + raw + b"\0" * (padded - len(raw)) + data


def report(result):
    if result.get("isError"):
        raise AssertionError(f"unexpected tool refusal: {result}")
    content = result.get("content", [])
    assert len(content) == 1 and content[0].get("type") == "text"
    return json.loads(content[0]["text"])


def inventory(repository):
    paths = sorted([*repository.joinpath("src").rglob("*.rs"), repository / "Cargo.toml", repository / "Cargo.lock"])
    values = [{"path": str(path.relative_to(repository)), "bytes": path.stat().st_size,
               "sha256": helper.sha256(path)} for path in paths]
    return {"files": values, "sha256": digest(json.dumps(values, separators=(",", ":")).encode())}


class Calls:
    def __init__(self, mcp):
        self.mcp = mcp
        self.id = 10
        self.observations = []

    def call(self, name, arguments, denied=False):
        self.id += 1
        started = time.monotonic()
        result = self.mcp.request(self.id, "tools/call", {"name": name, "arguments": arguments})
        self.observations.append({"id": self.id, "name": name, "denial_expected": denied,
                                  "seconds": time.monotonic() - started, "is_error": bool(result.get("isError"))})
        if denied:
            assert result.get("isError") is True, f"expected refusal for {arguments}: {result}"
            return result
        return report(result)


def initialize(runtime, config, work):
    work.mkdir(mode=0o700)
    mcp = helper.Mcp(runtime, config, work)
    mcp.request(1, "initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
                                 "clientInfo": {"name": "hepta-asar-qualification", "version": "1"}})
    mcp.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    return mcp


def selection(first):
    return {"expected_version": first["source"]["observed_version"],
            "expected_header_sha256": first["source"]["header_sha256"]}


def stop_owned_worker(mcp, runtime, request_id, expected_request):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert mcp.alive(), "original MCP owner exited"
        assert request_id not in mcp.take_ready(), "request completed before a live child could be stopped"
        for pid in helper.direct_children(mcp.child.pid):
            first = helper.identity(pid)
            if first is None or first["ppid"] != mcp.child.pid:
                continue
            argv = helper.command_line(pid)
            if len(argv) != 4 or argv[:3] != [os.fsencode(runtime), b"rea-asar-worker", b"--request"]:
                continue
            try:
                parsed = json.loads(argv[3])
            except (ValueError, UnicodeError):
                continue
            if parsed != expected_request:
                continue
            try:
                pidfd = os.pidfd_open(pid, 0)
            except ProcessLookupError:
                continue
            second = helper.identity(pid)
            if not helper.same_identity(second, first) or second["ppid"] != mcp.child.pid or helper.command_line(pid) != argv:
                os.close(pidfd)
                continue
            signal.pidfd_send_signal(pidfd, signal.SIGSTOP, None, 0)
            until = time.monotonic() + 1
            while time.monotonic() < until:
                stopped = helper.identity(pid)
                if not helper.same_identity(stopped, first):
                    os.close(pidfd)
                    raise AssertionError("owned child exited before stop observation")
                if stopped["state"] == "T":
                    return pidfd, {"before_stop": first, "stopped": stopped,
                                   "argv": [os.fsdecode(x) for x in argv], "confirmed_at": helper.now()}
                time.sleep(0.002)
            signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
            os.close(pidfd)
            raise AssertionError("owned child did not enter stopped state")
        time.sleep(0.002)
    raise AssertionError("no original owned ASAR worker observed within ten seconds")


def lifecycle(runtime, config, large, small, work, cancel):
    mcp = initialize(runtime, config, work)
    pidfd = None
    worker = None
    value = {"qualified": False, "cancel": cancel, "worker_deadline_seconds": 20,
             "cancellation_window_seconds": 5, "manual_worker_sigkill_sent": False}
    try:
        baseline = report(mcp.request(2, "tools/call", {"name": "rea_inspect_asar", "arguments": {"path": str(small)}}))
        value["baseline_entry_count"] = baseline["entry_count"]
        mcp.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "rea_inspect_asar", "arguments": {"path": str(large), "limit": 1}}})
        pidfd, worker = stop_owned_worker(mcp, runtime, 3, {"operation": "index", "offset": 0, "limit": 1})
        value["owner"] = mcp.owner
        value["worker"] = worker
        sent = time.monotonic_ns()
        if cancel:
            mcp.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {
                "requestId": 3, "reason": "qualify original owned stopped ASAR worker cancellation"}})
            observed = helper.observe_cancel(mcp, pidfd, worker, work, sent)
            value["cancellation"] = observed
            assert observed["passed"], observed
        else:
            refused = mcp.response(3, timeout=30)
            elapsed = (time.monotonic_ns() - sent) / 1e9
            value["deadline_response"] = refused
            value["deadline_seconds_from_confirmed_stop"] = elapsed
            assert refused.get("isError") is True and "20 second wall-clock deadline" in json.dumps(refused)
            assert 17 <= elapsed <= 26, "fixed production deadline must own the termination"
            assert helper.identity(worker["before_stop"]["pid"]) is None
            assert worker["before_stop"]["pid"] not in helper.direct_children(mcp.child.pid)
            assert mcp.alive()
        recovered = report(mcp.request(4, "tools/call", {"name": "rea_inspect_asar", "arguments": {"path": str(small)}}))
        value["same_owner_recovery"] = mcp.alive() and recovered["source"] == baseline["source"]
        assert value["same_owner_recovery"]
        value["qualified"] = True
    except BaseException as error:
        value["failure"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if pidfd is not None:
            if helper.same_identity(helper.identity(worker["before_stop"]["pid"]), worker["before_stop"]):
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                    value["manual_worker_sigkill_sent"] = True
                except ProcessLookupError:
                    pass
            os.close(pidfd)
        value["cleanup"] = mcp.close()
        if value["manual_worker_sigkill_sent"] or mcp.reader_errors or not value["cleanup"]["owner_reaped"] or not value["cleanup"]["reader_threads_joined"]:
            value["qualified"] = False
        write_json(work / "qualification.json", value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--expected-runtime-sha256", required=True)
    parser.add_argument("--asar-package", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--node", default="/usr/bin/node")
    parser.add_argument("--allow-owned-child-signals", action="store_true")
    args = parser.parse_args()
    assert args.allow_owned_child_signals and sys.platform == "linux" and hasattr(os, "pidfd_open")
    repository, work, source_runtime, package = map(Path, [args.repository, args.workspace, args.runtime, args.asar_package])
    assert all(p.is_absolute() for p in [repository, work, source_runtime, package])
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = {"schema": "hepta.asar-native-qualification.v1", "qualified": False,
              "gates": {}, "started": helper.now(), "harness_sha256": helper.sha256(__file__),
              "ownership_helper_sha256": helper.sha256(HELPER), "observations": []}
    runtime = work / "hepta-runtime-qualified"
    mcp = None
    before = inventory(repository)
    write_json(work / "source-before.json", before)
    try:
        result["runtime"] = helper.copy_runtime(source_runtime, runtime, args.expected_runtime_sha256)
        inputs = work / "inputs"
        inputs.mkdir(mode=0o700)
        reference_root = inputs / "upstream"
        command = [args.node, str(repository / "scripts/rea-asar-reference.mjs"), str(package), str(reference_root)]
        with (work / "upstream-producer.log").open("xb") as log:
            produced = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=60, check=False)
        assert produced.returncode == 0, (work / "upstream-producer.log").read_text()
        reference = json.loads((reference_root / "reference.json").read_text())
        result["reference"] = {"path": str(reference_root / "reference.json"), "sha256": helper.sha256(reference_root / "reference.json"),
                               "producer_consumer": reference["producer_consumer"], "package_sources": reference["package_sources"]}
        archive = Path(reference["archive"]["path"])
        config = work / "runtime-config.json"
        write_json(config, {"state_dir": str(work / "state"), "controller_workspace_roots": [str(inputs)],
                            "hosts": {"never-connect": {"ssh_target": "never-connect-invalid", "remote_state_dir": str(work / "never-used"),
                            "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}})
        mcp = initialize(runtime, config, work / "mcp")
        calls = Calls(mcp)
        first = calls.call("rea_inspect_asar", {"path": str(archive), "limit": 3})
        pinned = selection(first)
        assert first["source"]["header_sha256"] == reference["archive"]["header_sha256"]
        assert first["source"]["header_bytes"] == reference["archive"]["header_bytes"]
        assert first["source"]["header_sha256_scope"] == reference["archive"]["header_sha256_scope"] == "complete_pickle_header"
        assert first["source"]["header_sha256"] != reference["archive"]["electron_json_header_sha256"]
        assert first["source"]["header_pinned"] is False and first["source"]["header_pin_authenticated"] is False
        rows = list(first["result"]["rows"])
        next_offset = first["result"]["next_offset"]
        while next_offset is not None:
            page = calls.call("rea_inspect_asar", {"path": str(archive), "limit": 3, "offset": next_offset, **pinned})
            assert page["source"] == {**first["source"], "header_pinned": True}
            rows.extend(page["result"]["rows"])
            next_offset = page["result"]["next_offset"]
        fields = ["path", "kind", "size_bytes", "relative_data_offset", "unpacked", "executable_declaration", "link_target"]
        assert [{k:r[k] for k in fields} for r in rows] == [{k:r[k] for k in fields} for r in reference["entries"]]
        result["gates"]["complete_inventory_matches_upstream_and_authored_names"] = True
        read_checks = 0
        for entry in reference["entries"]:
            if entry["kind"] != "packed_file":
                calls.call("rea_read_asar_member", {"path": str(archive), "member": entry["path"], **pinned}, denied=True)
                continue
            for expected in entry["ranges"]:
                acquired = calls.call("rea_read_asar_member", {"path": str(archive), "member": entry["path"],
                                      "offset": expected["offset"], "length": expected["length"], **pinned})["result"]
                assert acquired["bytes_hex"] == expected["bytes_hex"]
                assert acquired["member_sha256"] == entry["sha256"]
                assert acquired["declared_integrity_verified"] is True
                assert acquired["entry"]["integrity"]["content_verified"] is True
                assert acquired["publisher_authenticated"] is False
                read_checks += 1
        result["gates"]["packed_member_ranges_and_whole_sha256_match_upstream_authored_bytes"] = True
        result["member_range_checks"] = read_checks
        known = {e["path"]:e for e in reference["entries"]}
        plain_sources, packed_sources = [], []
        for source in reference["graph_sources"]:
            base = {"id": source["id"], "syntax": source["syntax"], "module_kind": source["module_kind"],
                    "expected_sha256": known[source["member"]]["sha256"]}
            plain_sources.append({**base, "path": str(Path(reference["authored_root"]) / source["member"])})
            packed_sources.append({**base, "path": str(archive), "asar": {"member": source["member"], **pinned}})
        plain = calls.call("rea_inspect_javascript_graph", {"sources": plain_sources, "collection": "ipc_edges"})
        packed = calls.call("rea_inspect_javascript_graph", {"sources": packed_sources, "collection": "ipc_edges"})
        for key in ["graph_sha256", "sources", "rows", "counts"]:
            assert plain[key] == packed[key], key
        assert "archive_sources" not in plain and len(packed["archive_sources"]) == 3
        assert plain["counts"]["ipc_candidate_edges"] == 1
        assert not Path(reference["execution_marker"]).exists()
        result["gates"]["explicit_asar_graph_preserves_plain_source_identity_and_observations"] = True
        write_json(work / "plain-graph.json", plain)
        write_json(work / "asar-graph.json", packed)
        negatives = inputs / "negative"
        negatives.mkdir(mode=0o700)
        header = json.loads((reference_root / "upstream-header.json").read_text())
        original = archive.read_bytes()
        data = original[reference["archive"]["header_bytes"]:]
        denied_cases = {
            "short": b"\x04\0\0\0",
            "duplicate": encode(b'{"files":{},"files":{}}'),
            "escaped_duplicate": encode(b'{"files":{"a":{"size":0,"offset":"0"},"\\u0061":{"size":0,"offset":"0"}}}'),
            "non_utf8": encode(b'{"files":{"\xff":{"size":0,"offset":"0"}}}'),
            "unsafe_path": encode({"files": {"../escape": {"size":0,"offset":"0"}}}),
            "float_size": encode({"files": {"a": {"size":1.0,"offset":"0"}}}, b"x"),
            "float_string_offset": encode({"files": {"a": {"size":0,"offset":"0.0"}}}),
            "overlap": encode({"files": {"a": {"size":2,"offset":"0"}, "z": {"size":2,"offset":"1"}}}, b"abc"),
            "out_of_bounds": encode({"files": {"a": {"size":4,"offset":"0"}}}, b"abc"),
            "unpacked_offset": encode({"files": {"a": {"size":0,"offset":"0","unpacked":True}}}),
        }
        for label, content in denied_cases.items():
            path = negatives / f"{label}.asar"
            path.write_bytes(content)
            calls.call("rea_inspect_asar", {"path": str(path)}, denied=True)
        corrupt_header = json.loads(json.dumps(header))
        corrupt_header["files"]["src"]["files"]["main.js"]["integrity"]["blocks"][0] = "0" * 64
        corruption = negatives / "corrupt-integrity.asar"
        corruption.write_bytes(encode(corrupt_header, data))
        corrupt_index = calls.call("rea_inspect_asar", {"path": str(corruption)})
        calls.call("rea_read_asar_member", {"path": str(corruption), "member": "src/main.js", "length": 1, **selection(corrupt_index)}, denied=True)
        outside = work / "outside.asar"
        outside.write_bytes(encode({"files":{}}))
        link = inputs / "outside-link.asar"
        link.symlink_to(outside)
        for path in [outside, link]:
            calls.call("rea_inspect_asar", {"path": str(path)}, denied=True)
        calls.call("rea_inspect_asar", {"path": str(archive), "offset": 1}, denied=True)
        calls.call("rea_read_asar_member", {"path": str(archive), "member": "src/main.js", **pinned,
                    "expected_header_sha256":"0"*64}, denied=True)
        stale_source = json.loads(json.dumps(packed_sources))
        stale_source[0]["asar"]["expected_header_sha256"] = "0"*64
        calls.call("rea_inspect_javascript_graph", {"sources": stale_source}, denied=True)
        binary_source = {"id":"binary.js", "path":str(archive), "asar":{"member":"assets/binary.bin", **pinned}}
        calls.call("rea_inspect_javascript_graph", {"sources":[binary_source]}, denied=True)
        duplicate_source = json.loads(json.dumps(packed_sources))
        duplicate_source[1]["asar"]["member"] = duplicate_source[0]["asar"]["member"]
        calls.call("rea_inspect_javascript_graph", {"sources":duplicate_source}, denied=True)
        result["gates"]["malformed_conflicting_unsafe_stale_and_non_utf8_inputs_refuse"] = True
        result["observations"] = calls.observations
        result["ordinary_mcp_cleanup"] = mcp.close()
        assert result["ordinary_mcp_cleanup"]["owner_reaped"] and result["ordinary_mcp_cleanup"]["reader_threads_joined"]
        mcp = initialize(runtime, config, work / "mcp-restart")
        rebound = report(mcp.request(2,"tools/call", {"name":"rea_read_asar_member", "arguments":{
            "path":str(archive),"member":"src/main.js","length":1,**pinned}}))
        assert rebound["result"]["member_sha256"] == known["src/main.js"]["sha256"]
        result["gates"]["reconnect_can_reobserve_same_pinned_archive"] = True
        result["restart_cleanup"] = mcp.close()
        assert result["restart_cleanup"]["owner_reaped"] and result["restart_cleanup"]["reader_threads_joined"]
        mcp = None
        large = inputs / "owned-cancellation.asar"
        large.write_bytes(encode({"files":{f"entry-{i:05}":{"size":0,"offset":"0"} for i in range(50_000)}}))
        small = inputs / "owned-recovery.asar"
        small.write_bytes(encode({"files":{"empty":{"size":0,"offset":"0"}}}))
        for cancel, name in [(True,"cancel"),(False,"deadline")]:
            outcome = lifecycle(runtime, config, large, small, work / name, cancel)
            result[name] = outcome
            assert outcome["qualified"], outcome
            result["gates"][f"owned_stopped_worker_{name}_reaped_and_same_owner_recovers"] = True
        assert helper.sha256(archive) == reference["archive"]["sha256"]
        assert not Path(reference["execution_marker"]).exists()
        result["gates"]["fixture_unchanged_and_target_never_executed"] = True
        result["qualified"] = True
    except BaseException as error:
        result["failure"] = {"type":type(error).__name__, "message":str(error)}
    finally:
        if mcp is not None:
            result["failure_cleanup"] = mcp.close()
        after = inventory(repository)
        write_json(work / "source-after.json", after)
        result["source_inventory_sha256"] = before["sha256"]
        result["source_unchanged"] = before == after
        if not result["source_unchanged"]:
            result["qualified"] = False
        result["runtime_sha256_after"] = helper.sha256(runtime) if runtime.exists() else None
        if result["runtime_sha256_after"] != args.expected_runtime_sha256:
            result["qualified"] = False
        result["finished"] = helper.now()
        result["artifacts"] = {str(p.relative_to(work)):{"sha256":helper.sha256(p),"bytes":p.stat().st_size}
                               for p in sorted(work.rglob("*")) if p.is_file() and not p.is_symlink() and
                               p != runtime and "state" not in p.relative_to(work).parts}
        write_json(work / "qualification.json", result)
        print(json.dumps({"qualified":result["qualified"],"gates":result["gates"],
                          "failure":result.get("failure"),"qualification":str(work / "qualification.json")}),flush=True)
    return 0 if result["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
