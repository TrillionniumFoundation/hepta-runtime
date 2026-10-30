#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""ABBA local stdio MCP reuse throughput, with every SSH status attempt denied.

Six real launched identities/requests are copied from an immutable recovery
report. No new key is submitted. This measures lookup, native MCP and audit plus
denied status probes; it does not measure remote execution or normal status TPS.
"""
import argparse
import concurrent.futures
import gzip
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time

HERE = Path(__file__).absolute().parent
HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
BENCH_SHA = "0c4a06ed1613039d703bb575a8440c9030eac2dc51fcc2c96e96fc90a609da3e"
SAMPLER_SHA = "a9554e63416504428439a6cf3fe1f5b8ede090c2ef856bda3f1add413d06d40a"
OLD_REPORT = Path("/home/qian/hepta-runtime-optimization-20261023/a62-native-cf8e1d8fae61ab15e23c011c-six-running/report.json")
OLD_REPORT_SHA = "7b583ee5f48eb30616e420a4471c1c69247efd48a01d117bed26a5334b106c99"
REQUEST_FIELDS = ("args", "cpu_quota_percent", "cwd", "env", "executable", "host",
                  "memory_max_bytes", "nice", "stdin", "timeout_seconds")
DENY_SSH = '''#!/usr/bin/python3 -I
import hashlib, json, os, sys, time
row = {"pid":os.getpid(), "monotonic_ns":time.monotonic_ns(), "denied_before_exec":True,
       "argv_sha256":hashlib.sha256(json.dumps(sys.argv[1:], separators=(",", ":")).encode()).hexdigest()}
fd = os.open(os.environ["HEPTA_REUSE_DENIAL_LOG"], os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    raw = (json.dumps(row, sort_keys=True) + "\\n").encode()
    if os.write(fd, raw) != len(raw): raise OSError("incomplete denial receipt")
finally:
    os.close(fd)
os.write(2, b"SSH status probe denied by local reuse benchmark\\n")
os._exit(125)
'''


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_module(path, expected, name):
    need(sha(path) == expected, name + " reviewed SHA differs")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(sha(path) == expected, name + " changed during import")
    return module


def request_digest(params):
    binding = {key: params.get(key) for key in REQUEST_FIELDS}
    binding.update(args=params.get("args", []), env=params.get("env", {}))
    return hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def load_originals(p, bench, report_path, expected_sha, output):
    info, raw = p.receipt(p.direct(report_path), contents=True)
    need(info["sha256"] == expected_sha, "recovery report SHA differs")
    report = json.loads(raw)
    need(report.get("schema") == "hepta-six-running-controller-recovery/v1"
         and report.get("passed") is True and report.get("controller_records_unchanged_after_shutdown") is True
         and set(report["hosts"]) == set(HOSTS), "recovery report is not successful original six-host evidence")
    p.create(output / "recovery-report.original.json", raw)
    config_path = p.direct(Path(report["runtime_config"]))
    config_info, config_raw = p.receipt(config_path, contents=True)
    config = json.loads(config_raw)
    registry = p.direct(Path(config["state_dir"]) / "jobs")
    need(set(config["hosts"]) == set(HOSTS), "original configured host set differs")
    retained = {row["host"]: row for row in report["retained_controller_records"]}
    need(len(report["retained_controller_records"]) == len(retained) == 6, "ambiguous retained originals")
    need({path.name for path in registry.glob("*.json")} == {
        report["hosts"][host]["job_id"] + ".json" for host in HOSTS}, "original registry contains another job")
    pinned = {str(report_path): info, str(config_path): config_info}
    jobs = []
    for host in HOSTS:
        owner = report["hosts"][host]
        request_path = p.direct(report_path.parent / (host + "-request.json"))
        request_info, request_raw = p.receipt(request_path, contents=True)
        params = json.loads(request_raw)
        calls = [row for row in report["native_calls"] if row.get("host") == host
                 and row.get("tool") == "process_start" and row.get("phase") == "launch"]
        need(len(calls) == 1 and request_info["sha256"] == owner["request_sha256"]
             == calls[0]["arguments_sha256"] == bench.digest(bench.canonical(params)),
             "original request bytes/digest differ: " + host)
        path = p.direct(registry / (owner["job_id"] + ".json"))
        record_info, record_raw = p.receipt(path, contents=True)
        record = json.loads(record_raw)
        need(record_info["sha256"] == retained[host]["sha256"] == owner["launch"]["record_sha256"]
             and retained[host].get("original_bytes_unchanged") is True,
             "retained controller receipt differs: " + host)
        full_digest = request_digest(params)
        need(record["host"] == params["host"] == host and record["id"] == owner["job_id"]
             and record["idempotency_key"] == params["idempotency_key"] == owner["idempotency_key"]
             and record["launch_state"] == "launched" and record["execution_mode"] == "operator"
             and record["system_jobctl"] is False and record.get("request_digest") == full_digest
             and record["request_fingerprint"] == int(full_digest[:16], 16), "unverified original binding: " + host)
        target = config["hosts"][host]
        need(record["ssh_target"] == target["ssh_target"]
             and record["remote_job_dir"] == target["remote_state_dir"].rstrip("/") + "/jobs/" + record["id"]
             and record["executable"] == params["executable"] and record["args"] == params.get("args", [])
             and record["cwd"] == params.get("cwd") and record["env_keys"] == sorted(params.get("env", {})),
             "physical/request fields differ: " + host)
        need(stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1,
             "original receipt is not private single-link metadata")
        pinned.update({str(path): record_info, str(request_path): request_info})
        p.create(output / (host + "-request.original.json"), request_raw)
        p.create(output / (host + "-job.original.json"), record_raw)
        jobs.append({"host": host, "id": record["id"], "params": params, "record": record,
                     "raw": record_raw, "sha256": record_info["sha256"]})
    return config, jobs, pinned


def make_controller(bench, sampler):
    class Controller(bench.Controller):
        def __init__(self, binary, config, directory, wrapper, denial_log):
            self.binary, self.directory = Path(binary), directory
            self.rows, self.pending = [], {}
            self.lock, self.write_lock = threading.Lock(), threading.Lock()
            self.serial = self.unmatched = 0
            self.reader_error = None
            self.stderr = (directory / "stderr.log").open("xb")
            argv = [str(binary), "mcp", "--runtime-config", str(config), "--runtime-prewarm",
                    "--runtime-audit-group-commit"]
            env = {"PATH": str(wrapper.parent), "LANG": "C", "SHELL": "/bin/sh", "RUST_LOG": "warn",
                   "TOKIO_WORKER_THREADS": "2", "HEPTA_REUSE_DENIAL_LOG": str(denial_log)}
            started = time.monotonic()
            self.pidfd = self.resources = self.reader = None
            try:
                self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                              stderr=self.stderr, cwd=directory, env=env, start_new_session=True)
            except BaseException:
                self.stderr.close()
                raise
            try:
                self.pidfd = os.pidfd_open(self.child.pid)
                self.birth = bench.process_stat(self.child.pid)[0]
                self.resources = sampler.Resources(self.child.pid, directory / "resource-errors.jsonl")
                self.reader = threading.Thread(target=self.read_loop, daemon=True)
                self.reader.start()
                reply = self.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                 "clientInfo": {"name": "hepta-local-reuse-abba", "version": "1"}}, 60)
                need("result" in reply and "error" not in reply, "MCP initialization failed")
                self.notify("notifications/initialized", {})
                self.startup = {"pid": self.child.pid, "birth_ticks": self.birth, "argv": argv,
                                "ready_ms": (time.monotonic() - started) * 1000, "reply": reply,
                                "path_contains_only_deny_wrapper_directory": True, "ssh_agent_forwarded": False}
            except BaseException:
                self.close()
                raise

        def close(self):
            if hasattr(self, "closed_receipt"):
                return self.closed_receipt
            try:
                self.child.stdin.close()
            except BrokenPipeError:
                pass
            signals = []
            deadline = time.monotonic() + 30
            while True:
                pid, status, usage = os.wait4(self.child.pid, os.WNOHANG)
                if pid == self.child.pid:
                    break
                if time.monotonic() >= deadline:
                    sig = signal.SIGTERM if not signals else signal.SIGKILL
                    need(len(signals) < 2, "original controller did not reap after bounded shutdown")
                    if self.pidfd is not None:
                        signal.pidfd_send_signal(self.pidfd, sig)
                    else:
                        # wait4 just proved this is still our original unreaped child.
                        os.kill(self.child.pid, sig)
                    signals.append(sig.name)
                    deadline = time.monotonic() + 10
                time.sleep(.02)
            self.child.returncode = os.waitstatus_to_exitcode(status)
            if self.pidfd is not None:
                os.close(self.pidfd)
            if self.reader is not None:
                self.reader.join(2)
            self.stderr.close()
            resources = self.resources.stop() if self.resources is not None else {"sampler_unavailable": True}
            survivors = []
            for pid, birth in list(self.resources.seen) if self.resources is not None else []:
                if pid == self.child.pid:
                    continue
                try:
                    if bench.process_stat(pid)[0] == birth:
                        survivors.append({"pid": pid, "birth_ticks": birth})
                except (FileNotFoundError, ProcessLookupError):
                    pass
            self.closed_receipt = {"exit_code": self.child.returncode, "raw_wait_status": status,
                "actual_wait4_pid": self.child.pid, "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
                "maxrss_kib": usage.ru_maxrss, "shutdown_signals": signals, "resources": resources,
                "reader_error": self.reader_error, "reader_stopped": self.reader is None or not self.reader.is_alive(),
                "unmatched_responses": self.unmatched, "observed_descendant_survivors": survivors}
            return self.closed_receipt
    return Controller


def metrics(rows, seconds):
    values = sorted(row["elapsed_ms"] for row in rows if row.get("executed"))
    good = sum(row.get("okay") is True for row in rows)
    return {"calls": len(rows), "executed": len(values), "successes": good, "seconds": seconds,
            "successful_calls_per_second": good / seconds, "all_attempt_completion_rate": len(values) / seconds,
            **{f"p{q}_ms": values[math.ceil(len(values) * q / 100) - 1] if values else None for q in (50, 95, 99)},
            "max_ms": max(values) if values else None}


def phase(controller, bench, jobs, concurrency, count, phase_name, events, log_lock):
    stop = threading.Event()
    rows, pings, heartbeat_errors = [], [], []
    def write(row):
        with log_lock:
            events.write(json.dumps(row, ensure_ascii=False) + "\n")
            events.flush()
    def request(index):
        job = jobs[index % 6]
        row = {"phase": phase_name, "index": index, "host": job["host"], "job_id": job["id"],
               "executed": False, "okay": False, "start_monotonic": time.monotonic(), "automatic_retry": False}
        try:
            need(not stop.is_set(), "unexecuted after earlier failure")
            row["executed"] = True
            reply = controller.rpc("tools/call", {"name": "process_start", "arguments": job["params"]}, 30)
            row["reply"] = reply
            need("error" not in reply and reply.get("result", {}).get("isError") is not True, "native reuse refused")
            texts = [part["text"] for part in reply["result"]["content"] if part.get("type") == "text"]
            need(len(texts) == 1, "ambiguous native result")
            value = json.loads(texts[0])
            need(value.get("reused") is True and value.get("retried_launch") is False and value.get("launch") is None
                 and value.get("job") == job["record"] and value.get("audit_recorded") is True
                 and "audit_warning" not in value and value.get("status", {}).get("job_id") == job["id"]
                 and value["status"].get("state") == "status_unavailable"
                 and value["status"].get("status_authoritative") is False, "reuse identity/audit/denied-status contract differs")
            row["okay"] = True
        except Exception as error:
            row["error"] = type(error).__name__ + ": " + str(error)
            stop.set()
        row["elapsed_ms"] = (time.monotonic() - row["start_monotonic"]) * 1000
        write(row)
        return row
    def heartbeat():
        try:
            while not stop.is_set():
                row = {"kind": "ping", "phase": phase_name, "executed": True, "start_monotonic": time.monotonic()}
                try:
                    row["reply"] = controller.rpc("ping", {}, 30)
                    row["okay"] = "result" in row["reply"] and "error" not in row["reply"]
                except Exception as error:
                    row.update(okay=False, error=type(error).__name__ + ": " + str(error))
                row["elapsed_ms"] = (time.monotonic() - row["start_monotonic"]) * 1000
                pings.append(row)
                write(row)
                if not row["okay"]:
                    stop.set()
                stop.wait(.02)
        except BaseException as error:
            heartbeat_errors.append(type(error).__name__ + ": " + str(error))
            stop.set()
    birth, before = bench.process_stat(controller.child.pid)
    need(birth == controller.birth, "controller birth differs before phase")
    started = time.monotonic()
    ping_thread = threading.Thread(target=heartbeat, daemon=True)
    ping_thread.start()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            rows = list(pool.map(request, range(count)))
        seconds = time.monotonic() - started
        after_birth, after = bench.process_stat(controller.child.pid)
        need(after_birth == birth and after >= before, "controller CPU/birth changed")
    finally:
        stop.set()
        ping_thread.join(35)
    need(not ping_thread.is_alive(), "ping did not finish within its RPC timeout")
    need(not heartbeat_errors, "heartbeat/logging failed: " + repr(heartbeat_errors))
    return {"phase": phase_name, "concurrency": concurrency, **metrics(rows, seconds),
            "unique_originals": 6, "cold_wave_maximum_simultaneous_unique_keys": min(concurrency, 6),
            "controller_cpu_seconds": after - before,
            "controller_cpu_ms_per_success": 1000 * (after - before) / sum(row["okay"] for row in rows)
                if any(row["okay"] for row in rows) else None,
            "ping": metrics(pings, seconds), "resources_after": controller.resources.snapshot(),
            "passed": all(row["okay"] for row in rows) and bool(pings) and all(row["okay"] for row in pings)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qualification", "test-audit", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("qualification-sha256", "test-audit-sha256", "candidate-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--baseline-qualification", type=Path)
    parser.add_argument("--protocol-library", type=Path, default=HERE / "pinned_native_protocol.py")
    parser.add_argument("--resource-library", type=Path, default=HERE.parent / "a27/resources/resource_sampler.py")
    parser.add_argument("--recovery-report", type=Path, default=OLD_REPORT)
    parser.add_argument("--recovery-report-sha256", default=OLD_REPORT_SHA)
    parser.add_argument("--calls", type=int, choices=(48, 96), default=48)
    parser.add_argument("--synthetic-records", type=int, choices=(0, 6000), default=6000)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    os.umask(0o077)
    need(args.qualification.is_absolute() and args.qualification.resolve(strict=True) == args.qualification
         and sha(args.qualification) == args.qualification_sha256, "candidate qualification path/SHA differs")
    attested = json.loads(args.qualification.read_bytes())
    need(sha(args.qualification) == args.qualification_sha256 and attested.get("qualified") is True,
         "candidate qualification changed or did not pass")
    helper_sha = attested["harness_before"]["run_native_validation.py"]
    need(helper_sha == attested["harness_after"]["run_native_validation.py"], "qualification helper changed during gates")
    v = load_module(HERE / "run_native_validation.py", helper_sha, "reuse_qualification")
    bench = load_module(HERE / "x230_observation_benchmark.py", BENCH_SHA, "reuse_stdio")
    sampler = load_module(args.resource_library, SAMPLER_SHA, "reuse_resources")
    p = v.load_protocol(args.protocol_library)
    args.out = p.direct(args.out, exists=False)
    args.out.mkdir(mode=0o700)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    report = {"schema": "hepta-local-reuse-throughput-abba/v1", "passed": False, "order": "ABBA",
              "scope": "real stdio MCP + original-key lookup + audit + denied local SSH status probes",
              "not_covered": ["remote launch throughput", "normal remote status", "multi-host network throughput"],
              "calls_per_cell": args.calls, "synthetic_records": args.synthetic_records, "tokio_workers": 2,
              "rpc_retries": 0, "new_keys_submitted": 0, "real_ssh_execs": None, "remote_effects": None,
              "cold_definition": "six original keys after explicit directory membership invalidation; OS cache uncontrolled",
              "observer_cost": "20ms ping loop, 100ms resource sampler and gzip event logging included in local workload",
              "rounds": [], "helpers": {}, "runner_sha256": sha(__file__)}
    active = None
    pinned = {}
    try:
        need(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux with pidfd/wait4 required")
        baseline = p.load_qualification(args.baseline_qualification or v.A62 / "qualification/report.json", "baseline", args.out)
        need(baseline["report"]["sha256"] == v.BASELINE_REPORT_SHA
             and baseline["binary"]["sha256"] == v.BASELINE_ELF_SHA, "A62 qualification/ELF differs")
        candidate = v.load_candidate(p, args, args.out)
        need(candidate["binary"]["sha256"] == args.candidate_sha256 != v.BASELINE_ELF_SHA, "candidate ELF differs")
        bundles = {"A": baseline, "B": candidate}
        for bundle in bundles.values():
            need(not args.out.is_relative_to(Path(bundle["source"])), "output cannot mutate qualified source")
        config, jobs, pinned = load_originals(p, bench, args.recovery_report, args.recovery_report_sha256, args.out)
        report.update(qualifications=bundles, original_inputs=pinned,
                      originals=[{key: job[key] for key in ("host", "id", "sha256")} for job in jobs])
        helpers = [Path(__file__).absolute(), HERE / "run_native_validation.py", HERE / "x230_observation_benchmark.py",
                   args.protocol_library, args.resource_library]
        report["helpers"] = {str(path): p.receipt(p.direct(path)) for path in helpers}
        Controller = make_controller(bench, sampler)
        for number, arm in enumerate("ABBA"):
            load, gate = v.load_gate(p)
            need(gate["clear"], "busy build/service or incomplete load sample; no automatic retry")
            p.check_manifest(pinned)
            p.check_manifest(report["helpers"])
            need(sha(bundles[arm]["binary"]["path"]) == bundles[arm]["binary"]["sha256"], "ELF changed")
            directory = args.out / f"round-{number}-{arm}"
            directory.mkdir(mode=0o700)
            state = directory / "state"
            registry = state / "jobs"
            registry.mkdir(mode=0o700, parents=True)
            os.chmod(state, 0o700)
            expected = {}
            for job in jobs:
                path = registry / (job["id"] + ".json")
                p.create(path, job["raw"])
                expected[path.name] = job["sha256"]
            for index in range(args.synthetic_records):
                identity = f"benchmark-unqueried-history-{index:05d}"
                synthetic = dict(jobs[0]["record"], id=identity, host="main", ssh_target="never-connect.invalid",
                    unit="hepta-runtime-job-" + identity, remote_job_dir="/__hepta_never_execute__/jobs/" + identity,
                    executable="/__hepta_never_execute__", args=[], cwd=None, env_keys=[], request_digest="0" * 64,
                    request_fingerprint=0, idempotency_key="local-unqueried-history-" + str(index), created_unix_ms=index)
                raw = bench.canonical(synthetic)
                path = registry / (identity + ".json")
                with path.open("xb") as stream:
                    stream.write(raw)
                expected[path.name] = bench.digest(raw)
            p.create(directory / "jobs-input-sha256.json", p.canonical(expected))
            config_path = directory / "runtime.json"
            p.create(config_path, p.canonical(dict(config, state_dir=str(state), controller_workspace_roots=[])))
            wrapper_dir = directory / "bin"
            wrapper_dir.mkdir(mode=0o700)
            wrapper = wrapper_dir / "ssh"
            p.create(wrapper, DENY_SSH.encode())
            wrapper.chmod(0o700)
            denial = directory / "denied-ssh.jsonl"
            p.create(denial, b"")
            row = {"round": number, "arm": arm, "directory": str(directory), "cells": [], "load_before": load, "passed": False,
                   "wrapper_sha256": sha(wrapper), "synthetic_history_is_not_original_job_evidence": True}
            report["rounds"].append(row)
            active = Controller(bundles[arm]["binary"]["path"], config_path, directory, wrapper, denial)
            row["startup"] = active.startup
            with gzip.open(directory / "events.jsonl.gz", "wt", encoding="utf-8", compresslevel=1) as events:
                for concurrency in (1, 4, 8):
                    p.create(registry / f"cache-invalidation-C{concurrency}.marker", b"not a job record\n")
                    cell = {"concurrency": concurrency, "phases": []}
                    row["cells"].append(cell)
                    for label, count in (("cold-six-originals", 6), ("warm", args.calls - 6)):
                        result = phase(active, bench, jobs, concurrency, count, f"C{concurrency}-{label}", events, threading.Lock())
                        cell["phases"].append(result)
                        p.save(args.out / "report.json", report)
                        print(json.dumps({"round": number, "arm": arm, "phase": result["phase"],
                                          "calls": count, "successes": result["successes"], "seconds": result["seconds"]}), flush=True)
                        need(result["passed"], "native reuse/ping contract failed; remaining calls are not retried")
            row["shutdown"] = active.close()
            active = None
            attempts = [json.loads(line) for line in denial.read_text().splitlines()]
            row["blocked_status_attempts"] = len(attempts)
            need(len(attempts) >= args.calls * 3 and all(item.get("denied_before_exec") is True for item in attempts),
                 "missing or malformed denied status attempt receipts")
            need(sha(wrapper) == row["wrapper_sha256"], "deny wrapper changed")
            current = {path.name: sha(path) for path in registry.glob("*.json")}
            need(current == expected, "original/synthetic registry changed or a new job was allocated")
            close = row["shutdown"]
            need(close["exit_code"] == 0 and not close["shutdown_signals"] and close["reader_stopped"]
                 and close["reader_error"] is None and close["unmatched_responses"] == 0
                 and not close["observed_descendant_survivors"], "controller cleanup differs")
            row["passed"] = True
            row.update(real_ssh_execs=0, remote_effects=0, all_job_receipts_unchanged=True)
            p.save(args.out / "report.json", report)
        p.check_manifest(pinned)
        p.check_manifest(report["helpers"])
        p.assert_bundle_unchanged(baseline)
        p.check_manifest(candidate["pinned"])
        need(v.candidate_sources(p, Path(candidate["source"])) == candidate["source_map"], "candidate source changed")
        report["passed"] = len(report["rounds"]) == 4 and all(row["passed"] for row in report["rounds"])
        if report["passed"]:
            report.update(real_ssh_execs=0, remote_effects=0)
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)}
    finally:
        if active is not None:
            try:
                report["interrupted_shutdown"] = active.close()
            except BaseException as error:
                report["cleanup_error"] = type(error).__name__ + ": " + str(error)
        report["finished_utc"] = p.utc()
        p.save(args.out / "report.json", report)
    print(json.dumps({"report": str(args.out / "report.json"), "passed": report["passed"], "error": report.get("error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
