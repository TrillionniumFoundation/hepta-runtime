#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One private x230 A20 job: controller SIGKILL, recovery, witnessed terminal output.

Run on x230 under a held current forwarded agent. This creates one new operator
job in --out/target-state and never loads or changes production runtime state.
It tests controller death, not target reboot or physical power loss.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import sys
import time

sys.dont_write_bytecode = True
import x230_observation_benchmark as bench

DEV_ROOT = Path.home() / "hepta-runtime-optimization-20261023"
INPUT = ("0123456789abcdef" * 256).encode()
STDERR = b"HEPTA-CANARY-STDERR\n"
MARKER = b"EXECUTED\n"
RELEASE = b"RELEASE\n"
CHILD = r'''import hashlib, os, sys, time
data = sys.stdin.buffer.read()
assert len(data) == 4096 and hashlib.sha256(data).hexdigest() == sys.argv[2]
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
try:
    assert os.write(fd, b"EXECUTED\n") == 9
    os.fsync(fd)
finally:
    os.close(fd)
directory = os.open(os.path.dirname(sys.argv[1]), os.O_RDONLY | os.O_DIRECTORY)
try: os.fsync(directory)
finally: os.close(directory)
print("BEGIN", flush=True)
print("HEPTA-CANARY-STDERR", file=sys.stderr, flush=True)
deadline = time.monotonic() + 45
while True:
    if time.monotonic() >= deadline:
        raise SystemExit("private release gate timed out")
    try:
        release_fd = os.open(sys.argv[3], os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        time.sleep(0.05)
        continue
    with os.fdopen(release_fd, "rb") as release:
        assert release.read(9) == b"RELEASE\n"
    break
print("END " + hashlib.sha256(data).hexdigest(), flush=True)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--profile-template", type=Path, required=True)
    parser.add_argument("--x230-record", type=Path, required=True)
    parser.add_argument("--socket-parent", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    out = args.out.absolute()
    bench.need(sys.platform == "linux" and out.parent == DEV_ROOT and out.resolve() == out
               and not out.exists() and 1 <= args.workers <= 8,
               "run only on x230 with a fresh direct child of the current dev directory")
    out.mkdir(mode=0o700)
    report = {"schema": "hepta-x230-native-lifecycle-canary/v2", "passed": False,
              "started_unix": time.time(), "controller_hostname": socket.gethostname(),
              "scope": "one new x230 operator job; own controller SIGKILL and same-key recovery",
              "not_covered": ["production owner transfer", "target reboot", "physical power loss"],
              "automatic_rpc_retries": 0, "job_start_requests": 0, "calls": []}
    report_path = out / "report.json"
    active = None
    binary_before = source_record = agent_before = None

    def checkpoint(phase):
        report["phase"] = phase
        bench.save_report(report_path, report)

    def call(tool, arguments):
        bench.need(tool in {"process_start", "process_status", "process_read"}, "unexpected canary tool")
        if tool == "process_start":
            report["job_start_requests"] += 1
        row = {"tool": tool, "phase": report.get("phase"), "started_unix": time.time(), "okay": False}
        started = time.monotonic()
        report["calls"].append(row)
        try:
            reply = active.rpc("tools/call", {"name": tool, "arguments": arguments}, timeout=50)
            row["response_sha256"] = bench.digest(bench.canonical(reply))
            if "error" in reply or reply.get("result", {}).get("isError", False):
                row["refusal"] = reply
                raise RuntimeError("native canary call refused: " + tool)
            texts = [item["text"] for item in reply["result"].get("content", []) if item.get("type") == "text"]
            bench.need(texts, "native response has no JSON text")
            result = json.loads(texts[0])
            bench.need(result.get("audit_recorded") is True and "audit_warning" not in result,
                       "canary result lacks durable audit acknowledgement")
            if tool != "process_start":
                bench.need(result.get("job_id") == arguments["job_id"], "observation job ID changed")
            row["okay"] = True
            return result
        except Exception as error:
            row["error"] = type(error).__name__ + ": " + str(error)[:1000]
            raise
        finally:
            row["elapsed_ms"] = (time.monotonic() - started) * 1000

    try:
        checkpoint("preflight")
        source_record = bench.read_file(args.x230_record, 65536)
        original = json.loads(source_record)
        bench.need(original["host"] == "x230" and original["execution_mode"] == "operator"
                   and original["ssh_target"] == "hepta-native-test-v7-x230", "unexpected x230 alias provenance")
        report["alias_provenance_record_sha256"] = bench.digest(source_record)
        agent = os.environ.get("SSH_AUTH_SOCK", "")
        bench.need(agent.startswith("/"), "a held current SSH_AUTH_SOCK is required")
        agent_before = bench.agent_identity(agent)
        candidate = args.candidate.absolute()
        binary_before = bench.digest(bench.read_file(candidate, 128 * 1024 * 1024))
        report["candidate_sha256"] = binary_before
        profile, report["profile"] = bench.fresh_profile(args.profile_template, out / "profile", args.socket_parent, agent)
        profile_data = json.loads(bench.read_file(profile))
        wrapper_dir = out / "bin"
        wrapper_dir.mkdir(mode=0o700)
        options = {"IdentityAgent": agent, "UserKnownHostsFile": profile_data["known_hosts"],
                   "GlobalKnownHostsFile": "/dev/null", "BatchMode": "yes", "ConnectTimeout": "8",
                   "ConnectionAttempts": "1", "StrictHostKeyChecking": "yes", "ForwardAgent": "no",
                   "ForwardX11": "no", "ClearAllForwardings": "yes", "ControlMaster": "no",
                   "ControlPath": "none", "ControlPersist": "no", "ProxyCommand": "none", "ProxyJump": "none",
                   "IdentityFile": "none", "CertificateFile": "none", "PreferredAuthentications": "publickey",
                   "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no", "IdentitiesOnly": "no",
                   "AddKeysToAgent": "no", "UpdateHostKeys": "no", "KnownHostsCommand": "none",
                   "LocalCommand": "none", "PermitLocalCommand": "no", "RequestTTY": "no"}
        command = ["/usr/bin/ssh", "-F", profile_data["ssh_config"]]
        for key, value in options.items():
            command.extend(["-o", key + "=" + value])
        wrapper = ("#!/bin/sh\nexec " + " ".join(map(shlex.quote, command)) + ' "$@"\n').encode()
        bench.create_file(wrapper_dir / "ssh", wrapper, 0o700)
        report["ssh_wrapper_sha256"] = bench.digest(wrapper)
        state, target, marker = out / "state", out / "target-state", out / "execution-marker"
        release = out / "release-marker"
        state.mkdir(mode=0o700)
        (state / "jobs").mkdir(mode=0o700)
        target.mkdir(mode=0o700)
        config = out / "runtime.json"
        bench.create_file(config, bench.canonical({"state_dir": str(state), "controller_workspace_roots": [],
            "hosts": {"x230": {"execution_mode": "operator", "ssh_target": original["ssh_target"],
            "platform": "linux", "remote_state_dir": str(target), "allow_execute": True,
            "allow_pty": False, "allow_write": False, "allow_job_network": True,
            "allow_detached_fallback": False, "privileged_actions": {}}}}))
        input_sha = bench.digest(INPUT)
        expected_stdout = ("BEGIN\nEND " + input_sha + "\n").encode()
        request = {"host": "x230", "executable": "/usr/bin/python3",
                   "args": ["-I", "-S", "-u", "-c", CHILD, str(marker), input_sha, str(release)],
                   "cwd": str(out), "env": {}, "stdin": INPUT.decode(), "timeout_seconds": 60,
                   "idempotency_key": "x230-lifecycle-" + bench.digest(str(out).encode())[:24]}
        bench.create_file(out / "request.json", bench.canonical(request))
        report.update(stdin_bytes=len(INPUT), stdin_sha256=input_sha,
                      release_gate_timeout_seconds=45, target_timeout_seconds=60, release_published=False,
                      request_sha256=bench.digest(bench.canonical(request)), idempotency_key=request["idempotency_key"])
        first = out / "first-controller"
        first.mkdir(mode=0o700)
        active = bench.Controller(candidate, config, profile, first, args.workers, path_prefix=wrapper_dir)
        report["first_startup"] = active.startup
        checkpoint("launch_one_private_job")
        started = call("process_start", request)
        record = started["job"]
        bench.need(started.get("reused") is False and record["host"] == "x230"
                   and record["launch_state"] == "launched" and started["launch"]["ok"] is True,
                   "first private launch was not newly acknowledged")
        job_id = record["id"]
        report["job_id"] = job_id
        bench.need(Path(record["remote_job_dir"]) == target / "jobs" / job_id,
                   "new job escaped the private target-state directory")
        saved_record = bench.read_file(state / "jobs" / (job_id + ".json"), 65536)
        report["job_record_sha256"] = bench.digest(saved_record)
        ref = {"host": "x230", "job_id": job_id}
        read_args = {**ref, "stdout_offset": 0, "stderr_offset": 0, "limit": 16384}
        checkpoint("confirm_running_begin")
        deadline = time.monotonic() + 12
        while True:
            status, output = call("process_status", ref), call("process_read", read_args)
            prefix = bytes.fromhex(output["stdout"]["bytes_hex"])
            if status.get("state") == "running" and prefix == b"BEGIN\n":
                break
            bench.need(time.monotonic() < deadline and prefix in (b"", b"BEGIN\n"),
                       "did not observe running plus BEGIN before the kill window")
            time.sleep(.2)
        report["before_crash_status"] = status
        bench.need(bench.read_file(marker, 128) == MARKER, "initial execution marker is not exactly one")
        bench.need(not os.path.lexists(release), "release gate existed before the intentional crash")
        checkpoint("kill_only_owned_controller")
        bench.need(active.child.poll() is None and bench.process_stat(active.child.pid)[0] == active.birth,
                   "controller PID identity changed before intentional SIGKILL")
        # pidfd binds the signal to this exact live process, never a process group.
        pidfd = os.pidfd_open(active.child.pid, 0)
        try:
            bench.need(bench.process_stat(active.child.pid)[0] == active.birth, "controller PID changed after pidfd open")
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        finally:
            os.close(pidfd)
        active.child.wait(timeout=10)
        time.sleep(.3)
        report["intentional_crash"] = active.close()
        active = None
        bench.need(report["intentional_crash"]["exit_code"] == -signal.SIGKILL
                   and not report["intentional_crash"]["observed_descendant_survivors"]
                   and report["intentional_crash"]["reader_error"] is None
                   and report["intentional_crash"]["unmatched_responses"] == 0, "owned-controller crash cleanup differs")
        restart = out / "restarted-controller"
        restart.mkdir(mode=0o700)
        bench.need(bench.agent_identity(agent) == agent_before, "held agent changed during controller restart")
        active = bench.Controller(candidate, config, profile, restart, args.workers, path_prefix=wrapper_dir)
        report["restart_startup"] = active.startup
        checkpoint("recover_same_job_and_key")
        report["first_recovered_status"] = call("process_status", ref)
        bench.need(report["first_recovered_status"].get("state") == "running",
                   "original job was not still running after controller SIGKILL and restart")
        reused = call("process_start", request)
        bench.need(reused.get("reused") is True and reused.get("retried_launch") is False
                   and reused["job"]["id"] == job_id and reused.get("launch") is None,
                   "same idempotency key did not reuse the original without relaunch")
        bench.need(reused.get("status", {}).get("job_id") == job_id
                   and reused["status"].get("state") == "running", "original job stopped before same-key reuse completed")
        report["same_key_reuse"] = {"reused": True, "retried_launch": False, "job_id": job_id,
                                    "status": reused["status"]}
        bench.need(bench.read_file(marker, 128) == MARKER and not os.path.lexists(release),
                   "execution count or unreleased gate changed during recovery")
        checkpoint("release_confirmed_running_original")
        pending_release = out / "release-marker.pending"
        bench.create_file(pending_release, RELEASE)
        os.rename(pending_release, release)
        directory_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        report.update(release_published=True, release_published_unix=time.time(),
                      release_sha256=bench.digest(RELEASE))
        checkpoint("wait_for_durable_completion")
        deadline = time.monotonic() + 65
        while True:
            status = call("process_status", ref)
            if status.get("state") == "succeeded" and status.get("output_durable") is True:
                break
            bench.need(status.get("state") in {"running", "activating", "finalizing", "succeeded"}
                       and time.monotonic() < deadline, "private job did not complete durably")
            time.sleep(.5)
        report["terminal_status"] = status
        checkpoint("verify_terminal_publication")
        bench.need(status.get("terminal_publication_confirmed") is True,
                   "terminal status lacks the A20 publication witness confirmation")
        job_directory = target / "jobs" / job_id
        publication_files = {name: bench.read_file(job_directory / name, limit) for name, limit in (
            ("request.json", 65536), ("exit.json", 1024 * 1024), ("exit.witness.json", 4096))}
        publication = {name: json.loads(data) for name, data in publication_files.items()}
        for name, value in publication.items():
            bench.need(isinstance(value, dict) and type(value.get("terminal_publication_protocol")) is int
                       and value["terminal_publication_protocol"] == 1 and value.get("job_id") == job_id,
                       "persisted publication protocol or original job ID differs: " + name)
        launch_nonce = publication["request.json"].get("launch_nonce")
        bench.need(isinstance(launch_nonce, str) and len(launch_nonce) == 32
                   and all(character in "0123456789abcdef" for character in launch_nonce),
                   "persisted request launch nonce is invalid")
        bench.need(all(value.get("launch_nonce") == launch_nonce for value in publication.values()),
                   "persisted request, exit and witness launch identities differ")
        raw_exit_sha = bench.digest(publication_files["exit.json"])
        bench.need(publication["exit.witness.json"].get("exit_sha256") == raw_exit_sha,
                   "witness does not bind the exact persisted exit bytes")
        bench.need(all(status.get(key) == value for key, value in publication["exit.json"].items()),
                   "native terminal observation differs from the persisted exit receipt")
        report["terminal_publication_receipt"] = {
            "protocol": 1, "job_id": job_id, "launch_nonce": launch_nonce,
            "strict_integer_protocol_verified": True, "request_exit_witness_identity_matches": True,
            "status_matches_persisted_exit": True, "terminal_publication_confirmed": True,
            "witness_exit_sha256": raw_exit_sha,
            "files": {name: {"bytes": len(data), "sha256": bench.digest(data)}
                      for name, data in publication_files.items()},
            "meaning": "The visible witness binds the exit bytes whose file and directory synchronization completed before witness publication."}
        bench.need(status.get("exit_code") == 0 and status.get("output_complete") is True
                   and status.get("log_synced") == {"stdout": True, "stderr": True}
                   and status.get("log_bytes") == {"stdout": {"seen": len(expected_stdout), "stored": len(expected_stdout)},
                                                   "stderr": {"seen": len(STDERR), "stored": len(STDERR)}}
                   and status.get("log_truncated") == {"stdout": False, "stderr": False}
                   and status.get("log_errors") == {"stdout": None, "stderr": None}
                   and not status.get("timed_out") and not status.get("cancelled"),
                   "terminal durable capture receipt differs")
        output = call("process_read", read_args)
        report["complete_outputs"] = {}
        for stream, expected in (("stdout", expected_stdout), ("stderr", STDERR)):
            part = output[stream]
            data = bytes.fromhex(part["bytes_hex"])
            bench.need(data == expected and part["offset"] == 0 and part["next_offset"] == part["size"] == len(data)
                       and part["eof"] is True, "complete native output or cursor differs: " + stream)
            bench.need(bench.read_file(target / "jobs" / job_id / (stream + ".log"), 16384) == expected,
                       "native output differs from this x230 fixture's persisted log")
            report["complete_outputs"][stream] = {"bytes": len(data), "sha256": bench.digest(data), "persisted_log_matches": True}
        bench.need(bench.read_file(target / "jobs" / job_id / "stdin.bin", 4096) == INPUT,
                   "durable job stdin differs from the full 4 KiB request")
        bench.need(bench.read_file(marker, 128) == MARKER, "execution was missing or duplicated")
        bench.need(bench.read_file(release, 128) == RELEASE, "private release marker changed")
        report["execution_count"] = 1
        bench.need(bench.read_file(state / "jobs" / (job_id + ".json"), 65536) == saved_record,
                   "controller restart or reuse changed the original job identity record")
        report["shutdown"] = active.close()
        active = None
        closed = report["shutdown"]
        bench.need(closed["exit_code"] == 0 and closed["shutdown_method"] == "stdin_eof"
                   and not closed["observed_descendant_survivors"] and closed["reader_error"] is None
                   and closed["unmatched_responses"] == 0, "restarted controller normal cleanup failed")
        report["passed"] = True
        checkpoint("completed")
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1500]}
        report["passed"] = False
    finally:
        if active is not None:
            try:
                report["interrupted_shutdown"] = active.close()
            except BaseException as error:
                report["cleanup_error"] = type(error).__name__ + ": " + str(error)[:500]
            report["passed"] = False
        try:
            report["binary_unchanged"] = binary_before is not None and bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024)) == binary_before
            report["source_record_unchanged"] = source_record is not None and bench.read_file(args.x230_record, 65536) == source_record
            report["current_agent_unchanged"] = agent_before is not None and bench.agent_identity(agent) == agent_before
        except BaseException as error:
            report["final_check_error"] = type(error).__name__ + ": " + str(error)[:500]
        report["passed"] = report["passed"] and all(report.get(key) is True for key in (
            "binary_unchanged", "source_record_unchanged", "current_agent_unchanged"))
        report["finished_unix"] = time.time()
        try:
            bench.save_report(report_path, report)
        except BaseException as error:
            report["passed"] = False
            report["report_save_error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
            # Preserve failed staging files and the original error. A distinct
            # create-only receipt avoids colliding with a retained report.next.
            fallback = out / f"report-final-{os.getpid()}-{time.time_ns()}.json"
            try:
                bench.create_file(fallback, bench.canonical(report))
                report_path = fallback
                descriptor = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except BaseException as fallback_error:
                report["fallback_save_error"] = {
                    "type": type(fallback_error).__name__, "reason": str(fallback_error)[:1000]}
                try:
                    print(json.dumps({"unsaved_canary_report": report}), file=sys.stderr, flush=True)
                except BaseException:
                    # Even a broken error stream must not replace the original
                    # failure with a misleading cleanup exception.
                    pass
    print(json.dumps({"report": str(report_path), "job_id": report.get("job_id"), "passed": report["passed"],
                      "error": report.get("error"), "execution_count": report.get("execution_count")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
