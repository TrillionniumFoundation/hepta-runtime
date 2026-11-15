#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Six private jobs: controller crash, same-key reuse, concurrent cancel, restart.

Reuses the qualified fixture descriptor checks, child workload and native MCP
client. Only freshly created fixture jobs and this invocation's own controller /
optional private SSH master can receive signals. Never retries an uncertain write.
Cancellation acknowledgement is distinct from durable terminal output proof.
"""
import argparse
import base64
import concurrent.futures
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import signal
import subprocess
import sys
import threading
import time

import allocator_environment as allocator

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_native_observation as measurements
bench = measurements.bench
import x230_six_running_recovery_canary as original
import owned_ssh_interruption as interruption

DEV_ROOT = Path("/home/qian/hepta-runtime-optimization-20261104-r16")
HOSTS = original.HOSTS
REMOTE = original.REMOTE.replace(
    '("exit.json", 1048576), ("exit.witness.json", 4096)]',
    '("exit.json", 1048576), ("exit.witness.json", 4096), ("cancel-request.json", 4096)]')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "profile-template", "topology", "frozen-jobs", "socket-parent", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--candidate-arena-max", type=int, choices=allocator.ALLOWED_ARENA_MAX, required=True)
    parser.add_argument("--interrupt-host", choices=("rog",))
    args = parser.parse_args()
    out = args.out.absolute()
    bench.need(sys.platform == "linux" and out.parent == DEV_ROOT and out.resolve() == out
               and not os.path.lexists(out) and 1 <= args.workers <= 8,
               "fresh direct R16 development output required")
    bench.need(REMOTE != original.REMOTE, "independent cancel-request observation hook missing")
    out.mkdir(mode=0o700)
    report_path = out / "report.json"
    report = {"schema": "hepta-six-host-cancel-recovery/v2", "passed": False,
              "started_unix": time.time(), "phase": "initial", "hosts": {},
              "native_calls": [], "ssh_calls": [], "phases": [],
              "automatic_rpc_retries": 0, "production_service_mutations": 0,
              "remote_cleanup_operations": 0,
              "not_covered": ["host reboot", "physical power loss", "WAN partition",
                              "production owner transfer", "transactional exactly-once external effects"],
              "macos_signal_identity": "best effort account/PID-start binding; no pidfd",
              "transport_interruption": {"requested_host": args.interrupt_host, "attempted": False}}
    lock = threading.RLock()
    active = None
    jobs = []
    saved_records = {}
    requests = {}
    binary_before = agent_before = None
    topology_raw = None
    serial = 0

    def checkpoint(phase=None):
        with lock:
            if phase is not None:
                report["phase"] = phase
                report["phases"].append({"phase": phase, "unix": time.time()})
            bench.save_report(report_path, report)

    def next_serial():
        nonlocal serial
        with lock:
            serial += 1
            return serial

    def reference(host):
        return {"host": host, "job_id": report["hosts"][host]["job_id"]}

    def read_arguments(host):
        return {**reference(host), "stdout_offset": 0, "stderr_offset": 0, "limit": 16384}

    def native(host, tool, arguments):
        bench.need(host in HOSTS and tool in {"process_start", "process_status", "process_read", "process_cancel"}
                   and arguments["host"] == host, "unexpected native route")
        number = next_serial()
        row = {"sequence": number, "host": host, "tool": tool, "phase": report["phase"],
               "arguments_sha256": bench.digest(bench.canonical(arguments)),
               "okay": False, "automatic_retry": False, "started_unix": time.time(), "rpc": {},
               "controller_directory": str(active.directory.relative_to(out))}
        started = time.monotonic_ns()
        row["start_monotonic_ns"] = started
        try:
            reply = active.rpc("tools/call", {"name": tool, "arguments": arguments}, timeout=50, evidence=row["rpc"])
            raw = bench.canonical(reply)
            path = out / f"native-{number:04d}-{host}-{tool}.json"
            bench.create_file(path, raw)
            row.update(reply_path=str(path), response_sha256=bench.digest(raw), reply_bytes=len(raw))
            bench.need("error" not in reply and not reply.get("result", {}).get("isError", False),
                       "native call refused: " + host + "/" + tool)
            text = [v["text"] for v in reply["result"].get("content", []) if v.get("type") == "text"]
            bench.need(text, "native response missing JSON")
            result = json.loads(text[0])
            bench.need(result.get("audit_recorded") is True and "audit_warning" not in result,
                       "native result lacks durable audit acknowledgement")
            if tool != "process_start":
                bench.need(result.get("job_id") == arguments["job_id"], "native job identity differs")
            row["okay"] = True
            return result
        except BaseException as error:
            row["error"] = type(error).__name__ + ": " + str(error)[:1500]
            row["effect_unknown"] = tool in {"process_start", "process_cancel"}
            raise
        finally:
            row["end_monotonic_ns"] = time.monotonic_ns()
            row["elapsed_ms"] = (row["end_monotonic_ns"] - started) / 1e6
            with lock:
                report["native_calls"].append(row)

    def remote(host, mode, terminal=False):
        bench.need(mode in {"prepare", "inspect"}, "no release or cleanup effects in cancel canary")
        item = report["hosts"][host]
        payload = {key: item[key] for key in ("base", "name", "source_job_id", "source_record_sha256")}
        payload.update(host=host, nonce=report["nonce"], mode=mode,
                       expected_platform="darwin" if topology["hosts"][host]["platform"] == "macos" else "linux")
        if mode == "inspect":
            payload.update(fixture_identity=item["prepare"]["fixture_identity"],
                           job_id=item["job_id"], terminal=terminal)
        number = next_serial()
        command = "/usr/bin/python3 -I -S - " + shlex.quote(base64.b64encode(bench.canonical(payload)).decode())
        row = {"sequence": number, "host": host, "mode": mode, "terminal": terminal,
               "okay": False, "automatic_retry": False, "mutation_attempted": mode == "prepare"}
        started = time.monotonic()
        try:
            completed = subprocess.run([str(wrapper), "-T", item["ssh_target"], command],
                input=REMOTE.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False, env={"PATH": "/usr/bin:/bin", "LANG": "C", "SSH_AUTH_SOCK": agent})
            for stream, raw in (("stdout", completed.stdout), ("stderr", completed.stderr)):
                path = out / f"ssh-{number:04d}-{host}-{mode}.{stream}"
                bench.create_file(path, raw)
                row[stream] = {"path": str(path), "bytes": len(raw), "sha256": bench.digest(raw)}
            row["returncode"] = completed.returncode
            bench.need(completed.returncode == 0 and len(completed.stdout) <= original.REMOTE_LIMIT
                       and len(completed.stderr) <= 65536, "independent SSH helper failed: " + host)
            value = json.loads(completed.stdout)
            bench.need(value["host"] == host and value["nonce"] == report["nonce"]
                       and value["mode"] == mode, "independent helper identity differs")
            if mode == "inspect":
                bench.need(value["fixture_identity"] == item["prepare"]["fixture_identity"],
                           "private fixture changed")
            row["okay"] = True
            return value
        except BaseException as error:
            row["error"] = type(error).__name__ + ": " + str(error)[:1500]
            row["effect_unknown"] = mode == "prepare"
            raise
        finally:
            row["elapsed_ms"] = 1000 * (time.monotonic() - started)
            with lock:
                report["ssh_calls"].append(row)

    def parallel(phase, operation):
        checkpoint(phase)
        failed = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(operation, host): host for host in HOSTS}
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    report["hosts"][host][phase] = future.result()
                except BaseException as error:
                    report["hosts"][host][phase] = {"error": type(error).__name__ + ": " + str(error)[:1500]}
                    failed.append(host)
                checkpoint()
        bench.need(not failed, phase + " failed on " + ",".join(failed))

    def controller(directory):
        directory.mkdir(mode=0o700)
        return bench.Controller(args.candidate, config, profile, directory, args.workers,
                                path_prefix=wrapper.parent,
                                allocator_values=allocator.configured(args.candidate_arena_max))

    def confirm_running(host):
        deadline = time.monotonic() + 20
        while True:
            status = native(host, "process_status", reference(host))
            output = native(host, "process_read", read_arguments(host))
            prefix = bytes.fromhex(output["stdout"]["bytes_hex"])
            expected = ("BEGIN " + host + "\n").encode()
            bench.need(status.get("state") in {"running", "activating"}
                       and prefix in (b"", expected), "private job became terminal or output differs")
            if status.get("state") == "running" and prefix == expected:
                proof = remote(host, "inspect")
                files = proof["files"]
                bench.need(original.decoded(files, "execution-marker") == original.MARKER
                           and original.decoded(files, "stdin.bin") == original.INPUT
                           and original.decoded(files, "release-marker", False) is None
                           and original.decoded(files, "cancel-request.json", False) is None
                           and original.decoded(files, "exit.json", False) is None
                           and original.decoded(files, "exit.witness.json", False) is None,
                           "running input/marker/terminal evidence differs")
                request = json.loads(original.decoded(files, "request.json"))
                bench.need(request["job_id"] == reference(host)["job_id"]
                           and re.fullmatch("[0-9a-f]{32}", request["launch_nonce"])
                           and request["terminal_publication_protocol"] == 1,
                           "running request identity differs")
                return {"status": status, "proof": proof, "launch_nonce": request["launch_nonce"]}
            bench.need(time.monotonic() < deadline, "running confirmation deadline")
            time.sleep(.2)

    def same_key(host, expected_state):
        reused = native(host, "process_start", requests[host])
        bench.need(reused.get("reused") is True and reused.get("retried_launch") is False
                   and reused["job"]["id"] == reference(host)["job_id"] and reused.get("launch") is None
                   and reused.get("status", {}).get("job_id") == reference(host)["job_id"]
                   and reused["status"].get("state") == expected_state,
                   "same-key replay changed original execution")
        bench.need(bench.read_file(state / "jobs" / (reference(host)["job_id"] + ".json"), 65536)
                   == saved_records[host], "same-key replay changed controller receipt")
        return reused

    def terminal(host):
        deadline = time.monotonic() + 45
        while True:
            status = native(host, "process_status", reference(host))
            if status.get("state") == "cancelled":
                break
            bench.need(status.get("state") in {"running", "activating", "finalizing"}
                       and time.monotonic() < deadline, "private cancellation not terminal")
            time.sleep(.2)
        bench.need(status.get("cancelled") is True and not status.get("timed_out")
                   and status.get("output_complete") is True and status.get("output_durable") is True
                   and status.get("terminal_publication_confirmed") is True
                   and status.get("log_synced") == {"stdout": True, "stderr": True}
                   and status.get("log_truncated") == {"stdout": False, "stderr": False}
                   and status.get("log_errors") == {"stdout": None, "stderr": None},
                   "cancel terminal output durability differs")
        output = native(host, "process_read", read_arguments(host))
        proof = remote(host, "inspect", terminal=True)
        files = proof["files"]
        bench.need(original.decoded(files, "execution-marker") == original.MARKER
                   and original.decoded(files, "stdin.bin") == original.INPUT
                   and original.decoded(files, "release-marker", False) is None,
                   "cancelled job input, one-execution marker or unreleased gate differs")
        outputs = {}
        expected = {"stdout": ("BEGIN " + host + "\n").encode(),
                    "stderr": ("HEPTA-CANARY-STDERR " + host + "\n").encode()}
        for stream, data in expected.items():
            part = output[stream]
            bench.need(bytes.fromhex(part["bytes_hex"]) == data
                       and part["offset"] == 0 and part["next_offset"] == part["size"] == len(data)
                       and part["eof"] is True and original.decoded(files, stream + ".log") == data,
                       "cancelled job complete output differs: " + stream)
            outputs[stream] = {"bytes": len(data), "sha256": bench.digest(data)}
        bench.need(status["log_bytes"] == {stream: {"seen": len(data), "stored": len(data)}
                                          for stream, data in expected.items()}, "cancel log counters differ")
        records = {name: json.loads(original.decoded(files, name)) for name in
                   ("request.json", "cancel-request.json", "exit.json", "exit.witness.json")}
        nonce = report["hosts"][host]["before_crash_running"]["launch_nonce"]
        for name, record in records.items():
            bench.need(record["job_id"] == reference(host)["job_id"] and record["launch_nonce"] == nonce,
                       "cancel terminal identity differs: " + name)
        bench.need(records["exit.witness.json"]["exit_sha256"] == files["exit.json"]["sha256"]
                   and all(status.get(k) == v for k, v in records["exit.json"].items()),
                   "cancel terminal witness or native status differs")
        bench.need(files["request.json"] == report["hosts"][host]["before_crash_running"]["proof"]["files"]["request.json"],
                   "original remote request changed")
        return {"status": status, "outputs": outputs, "proof": proof, "execution_count": 1}

    def shutdown():
        nonlocal active
        result = active.close()
        active = None
        bench.need(result["exit_code"] == 0 and result["shutdown_method"] == "stdin_eof"
                   and not result["observed_descendant_survivors"] and result["reader_error"] is None
                   and result["resources"]["sampler_error"] is None
                   and result["transport_capture"]["reader_eof"] is True
                   and result["unmatched_responses"] == 0, "normal controller cleanup differs")
        return result

    try:
        checkpoint("preflight")
        jobs = bench.load_jobs(args.frozen_jobs)
        topology_raw, topology = bench.load_topology(args.topology, args.profile_template)
        bench.create_file(out / "topology.json", topology_raw)
        report["topology"] = topology
        agent = os.environ.get("SSH_AUTH_SOCK", "")
        bench.need(agent.startswith("/"), "held SSH agent required")
        agent_before = bench.agent_identity(agent)
        binary_before = bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024))
        report["allocator_configuration"] = allocator.run_metadata(
            {"candidate": allocator.configured(args.candidate_arena_max)}, {"candidate": binary_before})
        report.update(candidate_sha256=binary_before, nonce=secrets.token_hex(12),
                      helper_hashes={name: bench.digest(bench.read_file(Path(module.__file__), 262144))
                                     for name, module in (("original", original), ("measurement", measurements),
                                                          ("benchmark", bench), ("interruption", interruption))},
                      script_sha256=bench.digest(bench.read_file(Path(__file__), 262144)),
                      remote_helper_sha256=bench.digest(REMOTE.encode()),
                      workload_sha256=bench.digest(original.CHILD.encode()))
        profile, report["profile"] = bench.fresh_profile(args.profile_template, out / "profile", args.socket_parent, agent)
        profile_data = json.loads(bench.read_file(profile))
        wrapper, report["ssh_wrapper_sha256"] = original.private_wrapper(profile_data, agent, out / "bin")
        for job in jobs:
            record = job["record"]
            old_job = PurePosixPath(record["remote_job_dir"])
            bench.need(record["executable"] == "/usr/bin/python3" and record["args"][:2] == ["-I", "-S"]
                       and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", record["ssh_target"])
                       and old_job.is_absolute() and old_job.name == record["id"]
                       and old_job.parent.name == "jobs" and ".." not in old_job.parts,
                       "frozen fixture provenance differs")
            base = old_job.parent.parent
            name = "running-recovery-" + report["nonce"] + "-" + job["host"]
            report["hosts"][job["host"]] = {"base": str(base), "name": name, "fixture": str(base / name),
                "source_job_id": record["id"], "source_record_sha256": job["record_sha256"],
                "ssh_target": record["ssh_target"]}
        parallel("prepare", lambda host: remote(host, "prepare"))
        report["observed_topology"] = bench.check_prepared_topology(report["hosts"], topology)
        state = out / "state"
        state.mkdir(mode=0o700)
        (state / "jobs").mkdir(mode=0o700)
        hosts = {}
        for host in HOSTS:
            item = report["hosts"][host]
            hosts[host] = {"execution_mode": "operator", "ssh_target": item["ssh_target"],
                "platform": topology["hosts"][host]["platform"], "remote_state_dir": item["fixture"],
                "allow_execute": True, "allow_pty": False, "allow_write": False,
                "allow_job_network": True, "allow_detached_fallback": topology["hosts"][host]["platform"] == "macos", "privileged_actions": {}}
            child = {"host": host, "fixture": item["fixture"],
                     "fixture_identity": item["prepare"]["fixture_identity"], "stdin_sha256": bench.digest(original.INPUT)}
            requests[host] = {"host": host, "executable": "/usr/bin/python3", "args":
                ["-I", "-S", "-u", "-c", original.CHILD, bench.canonical(child).decode().strip()],
                "cwd": item["fixture"], "env": {}, "stdin": original.INPUT.decode(),
                "timeout_seconds": original.TARGET_SECONDS, "idempotency_key": "six-cancel-" + report["nonce"] + "-" + host}
            bench.create_file(out / (host + "-request.json"), bench.canonical(requests[host]))
        config = out / "runtime.json"
        bench.create_file(config, bench.canonical({"state_dir": str(state), "controller_workspace_roots": [], "hosts": hosts}))
        active = controller(out / "first-controller")
        report["first_startup"] = active.startup
        def launch(host):
            result = native(host, "process_start", requests[host])
            record = result["job"]
            bench.need(result.get("reused") is False and result["launch"]["ok"] is True
                       and record["host"] == host and record["launch_state"] == "launched"
                       and re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", record["id"])
                       and PurePosixPath(record["remote_job_dir"]) == PurePosixPath(report["hosts"][host]["fixture"]) / "jobs" / record["id"],
                       "new launch escaped the private fixture")
            raw = bench.read_file(state / "jobs" / (record["id"] + ".json"), 65536)
            with lock:
                report["hosts"][host]["job_id"] = record["id"]
                saved_records[host] = raw
            return result
        parallel("launch", launch)
        parallel("before_crash_running", confirm_running)
        if args.interrupt_host is not None:
            item = report["transport_interruption"]
            master = interruption.find_master(active, report["hosts"][args.interrupt_host]["ssh_target"], profile_data)
            item.update(attempted=True, original_master=master)
            checkpoint("private_transport_interruption_intent")
            item["signal_receipt"] = interruption.interrupt_master(active, report["hosts"][args.interrupt_host]["ssh_target"], profile_data, master)
            bench.need(item["signal_receipt"]["pidfd_terminal_observed"], "own SSH master exit not observed")
            parallel("after_transport_running", confirm_running)
            replacement = interruption.find_master(active, report["hosts"][args.interrupt_host]["ssh_target"], profile_data)
            bench.need((replacement["pid"], replacement["birth_ticks"]) != (master["pid"], master["birth_ticks"]),
                       "SSH replacement generation not observed")
            item.update(replacement_master=replacement, passed=True)
        checkpoint("kill_only_owned_controller")
        bench.need(active.child.poll() is None and bench.process_stat(active.child.pid)[0] == active.birth,
                   "owned controller identity changed")
        pidfd = os.pidfd_open(active.child.pid)
        try:
            bench.need(bench.process_stat(active.child.pid)[0] == active.birth, "owned controller changed after pidfd")
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        finally:
            os.close(pidfd)
        active.child.wait(timeout=10)
        time.sleep(.3)
        report["intentional_crash"] = active.close()
        active = None
        crash = report["intentional_crash"]
        bench.need(crash["exit_code"] == -signal.SIGKILL and not crash["observed_descendant_survivors"]
                   and crash["reader_error"] is None and crash["unmatched_responses"] == 0,
                   "owned controller crash cleanup differs")
        active = controller(out / "after-crash-controller")
        report["after_crash_startup"] = active.startup
        parallel("after_crash_running", confirm_running)
        parallel("same_key_after_crash", lambda host: same_key(host, "running"))
        def cancel(host):
            result = native(host, "process_cancel", {**reference(host), "grace_seconds": 3})
            bench.need(result.get("result") in {"stop_requested", "term_sent"}
                       and result.get("automatic_retry") is False and result.get("termination_confirmed") is False
                       and result.get("atomic_identity") is (topology["hosts"][host]["platform"] == "linux"),
                       "cancellation signal acknowledgement differs")
            return result
        parallel("concurrent_cancel", cancel)
        parallel("terminal", terminal)
        report["after_cancel_shutdown"] = shutdown()
        active = controller(out / "after-cancel-controller")
        report["after_cancel_startup"] = active.startup
        parallel("terminal_after_restart", terminal)
        parallel("same_key_after_cancel", lambda host: same_key(host, "cancelled"))
        def already_cancelled(host):
            result = native(host, "process_cancel", {**reference(host), "grace_seconds": 0})
            bench.need(result.get("result") == "already_exited" and result.get("termination_confirmed") is False
                       and result.get("automatic_retry") is False, "terminal recancel differs")
            return result
        parallel("cancel_after_terminal", already_cancelled)
        report["shutdown"] = shutdown()
        bench.need(allocator.source_sha256() == report["allocator_configuration"]["helper_sha256"],
                   "allocator helper changed during experiment")
        report["passed"] = True
        checkpoint("completed")
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:2000]}
        report["passed"] = False
    finally:
        if active is not None:
            try:
                report["interrupted_shutdown"] = active.close()
            except BaseException as error:
                report["cleanup_error"] = type(error).__name__ + ": " + str(error)[:1500]
            report["passed"] = False
        try:
            report["source_originals_unchanged"] = bool(jobs) and all(bench.read_file(j["path"], 65536) == j["record_bytes"] for j in jobs)
            report["binary_unchanged"] = binary_before is not None and bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024)) == binary_before
            report["current_agent_unchanged"] = agent_before is not None and bench.agent_identity(os.environ["SSH_AUTH_SOCK"]) == agent_before
            report["topology_manifest_unchanged"] = topology_raw is not None and bench.read_file(args.topology, 65536) == topology_raw
            ids = {host: row["job_id"] for host, row in report["hosts"].items() if "job_id" in row}
            report["controller_records"] = original.collect_controller_records(out / "state/jobs", ids, saved_records)
            report["new_start_call_count"] = sum(r["tool"] == "process_start" and r["phase"] == "launch" for r in report["native_calls"])
            report["same_key_lookup_call_count"] = sum(r["tool"] == "process_start" and r["phase"] != "launch" for r in report["native_calls"])
            report["cancel_call_count"] = sum(r["tool"] == "process_cancel" for r in report["native_calls"])
            report["passed"] = (report["passed"] and report["source_originals_unchanged"] and report["binary_unchanged"]
                and report["current_agent_unchanged"] and report["controller_records"]["exact_original_set"]
                and report["topology_manifest_unchanged"]
                and report["new_start_call_count"] == 6 and report["same_key_lookup_call_count"] == 12
                and report["cancel_call_count"] == 12)
        except BaseException as error:
            report["final_check_error"] = type(error).__name__ + ": " + str(error)[:1500]
            report["passed"] = False
        report["finished_unix"] = time.time()
        checkpoint()
    print(json.dumps({"report": str(report_path), "passed": report["passed"], "error": report.get("error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

