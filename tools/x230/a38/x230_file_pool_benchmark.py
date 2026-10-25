#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Compare direct and pooled file reads through the same qualified native binary.

Only file_info/binary_read are sent to remote hosts. Synthetic prior job outputs
are checked byte-for-byte. Every request is sent once; failed cells are retained.
The ABBA order, per-host mix and concurrency are fixed before measurement.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import statistics
import threading
import time

import x230_observation_benchmark as bench
from x230_six_running_recovery_canary import private_wrapper


class Resources:
    """Independent sampled fields; retain every non-exit observation error."""

    def __init__(self, pid):
        self.pid = pid
        self.birth = bench.process_stat(pid)[0]
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.seen = {}
        self.samples = 0
        self.errors = []
        self.peaks = {}
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            pending, visited, values = [(self.pid, None)], set(), {}
            while pending:
                pid, parent = pending.pop()
                if pid in visited:
                    continue
                visited.add(pid)
                try:
                    born, cpu = bench.process_stat(pid)
                    self.check_lineage(pid, born, parent)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except Exception as error:
                    self.error(pid, "stat", error)
                    continue
                row = {}
                for field in ("status", "fd", "children"):
                    try:
                        if field == "status":
                            status = dict(line.split(":", 1) for line in
                                          Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
                            for key in ("VmRSS", "VmHWM"):
                                if key in status:
                                    row[key] = int(status[key].split()[0])
                        elif field == "fd":
                            row["fd"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
                        else:
                            for task in Path(f"/proc/{pid}/task").iterdir():
                                try:
                                    pending.extend((child, (pid, born)) for child in
                                                   map(int, (task / "children").read_text().split()))
                                except (FileNotFoundError, ProcessLookupError):
                                    pass
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                    except Exception as error:
                        self.error(pid, field, error)
                try:
                    if bench.process_stat(pid)[0] != born:
                        raise RuntimeError("process generation changed during sample")
                    self.check_lineage(pid, born, parent)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except Exception as error:
                    self.error(pid, "final_identity", error)
                    continue
                values[pid] = row
                with self.lock:
                    self.seen[(pid, born)] = max(cpu, self.seen.get((pid, born), 0))
            with self.lock:
                self.samples += 1
                for field, suffix in (("VmRSS", "rss_kib"), ("VmHWM", "hwm_kib"), ("fd", "fd")):
                    observed = [row[field] for row in values.values() if field in row]
                    if observed:
                        key = "tree_" + suffix
                        self.peaks[key] = max(sum(observed), self.peaks.get(key, 0))
                    if field in values.get(self.pid, {}):
                        key = "controller_" + suffix
                        self.peaks[key] = max(values[self.pid][field], self.peaks.get(key, 0))
            self.stop_event.wait(0.1)

    def check_lineage(self, pid, born, parent):
        if parent is None:
            bench.need(pid == self.pid and born == self.birth, "controller generation changed")
            return
        parent_pid, parent_birth = parent
        raw = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        bench.need(int(raw[1]) == parent_pid and int(raw[19]) == born,
                   "sampled child parent/generation changed")
        bench.need(bench.process_stat(parent_pid)[0] == parent_birth,
                   "sampled parent generation changed")

    def error(self, pid, field, error):
        with self.lock:
            self.errors.append({"pid": pid, "field": field, "error": type(error).__name__ + ": " + str(error)})

    def snapshot(self):
        with self.lock:
            return {"samples": self.samples, "peaks": dict(self.peaks), "errors": list(self.errors),
                    "sampled_tree_cpu_seconds": sum(self.seen.values()),
                    "sample_interval_seconds": 0.1, "sampled_peaks_are_not_exhaustive_limits": True}

    def stop(self):
        self.stop_event.set()
        self.thread.join(5)
        return self.snapshot()


bench.Resources = Resources


def quantile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]


def call(controller, job, tool, phase, version=None, expected_error=None):
    path = str(Path(job["record"]["remote_job_dir"]) / "stdout.log")
    args = {"host": job["host"], "path": path}
    if tool == "binary_read":
        args.update(offset=0, limit=65536, expected_version=version)
    if expected_error == "outside_root":
        args["path"] = str(Path(path).parent.parent / "outside-unselected-file")
    started = time.monotonic()
    row = {"host": job["host"], "tool": tool, "phase": phase, "automatic_retry": False}
    dto = None
    try:
        reply = controller.rpc("tools/call", {"name": tool, "arguments": args})
        row["response_sha256"] = bench.digest(bench.canonical(reply))
        refused = "error" in reply or reply.get("result", {}).get("isError") is True
        if expected_error:
            bench.need(refused, "negative read unexpectedly succeeded")
            text = json.dumps(reply, sort_keys=True)
            bench.need("source version changed" in text if expected_error == "stale_version" else
                       "outside configured read roots" in text, "unexpected negative error")
            row.update(okay=True, expected_error=expected_error)
            return row, dto
        bench.need(not refused, "native file read refused: " + json.dumps(reply)[:1500])
        content = [x["text"] for x in reply["result"].get("content", []) if x.get("type") == "text"]
        bench.need(len(content) == 1, "native file read JSON envelope differs")
        dto = json.loads(content[0])
        expected = job["expected"]
        bench.need(dto["path"] == path and dto["size"] == len(expected), "original file identity/size differs")
        if tool == "file_info":
            bench.need(dto["sha256"] == bench.digest(expected), "complete file digest differs")
        else:
            data = base64.b64decode(dto["data_base64"], validate=True)
            bench.need(data == expected and dto["chunk_sha256"] == bench.digest(expected)
                       and dto["offset"] == 0 and dto["next_offset"] == len(expected)
                       and dto["eof"] is True, "original output/cursor/hash differs")
            if version:
                bench.need(dto["version"] == version, "version changed")
        row.update(okay=True, bytes=len(expected), data_sha256=bench.digest(expected), version=dto["version"])
    except Exception as error:
        row.update(okay=False, error=type(error).__name__ + ": " + str(error))
    finally:
        row["elapsed_ms"] = (time.monotonic() - started) * 1000
    return row, dto


def fixture(directory, jobs):
    config = bench.fixture(directory, jobs)
    value = json.loads(config.read_text())
    for job in jobs:
        value["hosts"][job["host"]]["allowed_read_path_prefixes"] = [job["record"]["remote_job_dir"]]
    config.write_bytes(bench.canonical(value))
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--profile-template", type=Path, required=True)
    parser.add_argument("--frozen-jobs", type=Path, required=True)
    parser.add_argument("--socket-parent", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--calls", type=int, default=96)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 4, 8])
    parser.add_argument("--soak-seconds", type=int, default=0)
    args = parser.parse_args()
    bench.need(args.calls >= 12 and args.calls % 12 == 0, "balanced call count must be a multiple of 12")
    bench.need(all(1 <= x <= 16 for x in args.concurrency), "concurrency exceeds native capacity")
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    jobs = bench.load_jobs(args.frozen_jobs)
    original_hash = bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024))
    agent = os.environ["SSH_AUTH_SOCK"]
    agent_before = bench.agent_identity(agent)
    profile, profile_receipt = bench.fresh_profile(args.profile_template, args.out / "profile", args.socket_parent, agent)
    profile_data = json.loads(bench.read_file(profile))
    wrapper, wrapper_sha = private_wrapper(profile_data, agent, args.out / "bin")
    report = {"schema": "hepta-x230-file-pool-abba/v1", "binary_sha256": original_hash,
              "profile_receipt": profile_receipt, "ssh_wrapper_sha256": wrapper_sha,
              "order": ["off", "on", "on", "off"] if not args.soak_seconds else ["on"],
              "concurrency": args.concurrency, "calls_per_cell": args.calls, "rounds": [],
              "script_sha256": bench.digest(Path(__file__).read_bytes()), "complete": False,
              "remote_operations": ["file_info", "binary_read"], "remote_writes": False,
              "scope": "same-binary transport comparison; synthetic completed-job outputs"}
    raw = (args.out / "calls.jsonl").open("x")
    raw_lock = threading.Lock()
    current = None

    def save():
        bench.save_report(args.out / "report.json", report)

    def record(row):
        row.update(round=round_index, mode=mode)
        with raw_lock:
            raw.write(json.dumps(row, sort_keys=True) + "\n")
            raw.flush()

    try:
        for round_index, mode in enumerate(report["order"]):
            directory = args.out / f"round-{round_index}-{mode}"
            config = fixture(directory, jobs)
            controller_dir = directory / "controller"
            controller_dir.mkdir(mode=0o700)
            usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
            current = bench.Controller(args.candidate, config, profile, controller_dir, 2,
                                       path_prefix=wrapper.parent, file_pool=mode == "on")
            item = {"index": round_index, "mode": mode, "startup": current.startup,
                    "cells": [], "warmup": [], "negative": []}
            report["rounds"].append(item)
            versions = {}
            for job in jobs:
                row, dto = call(current, job, "file_info", "warmup")
                record(row); item["warmup"].append(row)
                bench.need(row["okay"], "file warmup failed")
                versions[job["host"]] = dto["version"]
                row, _ = call(current, job, "binary_read", "warmup", dto["version"])
                record(row); item["warmup"].append(row)
                bench.need(row["okay"], "binary warmup failed")
            stop_at = time.monotonic() + args.soak_seconds
            iteration = 0
            while True:
                for concurrency in args.concurrency:
                    before = bench.process_stat(current.child.pid)
                    start = time.monotonic()
                    def operation(index):
                        job = jobs[(index // 2) % 6]
                        tool = "file_info" if index % 2 == 0 else "binary_read"
                        row = call(current, job, tool, "measured", versions[job["host"]])[0]
                        row.update(index=index, concurrency=concurrency, iteration=iteration)
                        record(row)
                        return row
                    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                        rows = list(pool.map(operation, range(args.calls)))
                    elapsed = time.monotonic() - start
                    after = bench.process_stat(current.child.pid)
                    bench.need(before[0] == after[0], "controller generation changed")
                    latency = [row["elapsed_ms"] for row in rows]
                    cell = {"concurrency": concurrency, "iteration": iteration, "calls": len(rows),
                            "success": sum(row["okay"] for row in rows), "seconds": elapsed,
                            "successful_calls_per_second": sum(row["okay"] for row in rows) / elapsed,
                            "cpu_ms_per_call": 1000 * (after[1] - before[1]) / len(rows),
                            "p50_ms": statistics.median(latency), "p95_ms": quantile(latency, .95),
                            "p99_ms": quantile(latency, .99), "resources": current.resources.snapshot()}
                    item["cells"].append(cell)
                    save()
                    print(json.dumps({"mode": mode, "round": round_index, **{k: v for k, v in cell.items() if k != "resources"}}), flush=True)
                    bench.need(cell["success"] == cell["calls"], "measured cell contains failures; comparison invalid")
                iteration += 1
                if not args.soak_seconds or time.monotonic() >= stop_at:
                    break
            for job in jobs:
                for reason in ("stale_version", "outside_root"):
                    row, _ = call(current, job, "binary_read", "negative",
                                  versions[job["host"]] + "-invalid" if reason == "stale_version" else None, reason)
                    record(row); item["negative"].append(row)
                    bench.need(row["okay"], "negative case failed")
            item["shutdown"] = current.close()
            current = None
            usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            item["waited_process_tree_cpu_seconds"] = (
                usage_after.ru_utime + usage_after.ru_stime
                - usage_before.ru_utime - usage_before.ru_stime)
            item["waited_cpu_scope"] = "controller and reaped local descendants for complete round, including warmup, rejection cases and shutdown; remote CPU excluded"
            bench.need(item["shutdown"]["exit_code"] == 0, "controller shutdown failed")
            bench.need(not item["shutdown"]["observed_descendant_survivors"], "observed controller descendants remain")
            bench.need(item["shutdown"]["reader_error"] is None, "controller reply reader failed")
            bench.need(item["shutdown"]["unmatched_responses"] == 0, "controller returned unmatched responses")
            save()
        report["binary_unchanged"] = bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024)) == original_hash
        report["agent_unchanged"] = bench.agent_identity(agent) == agent_before
        bench.need(report["binary_unchanged"] and report["agent_unchanged"], "inputs changed")
        report["complete"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        if current is not None:
            report["failure_shutdown"] = current.close()
        raw.close()
        report["calls_sha256"] = bench.digest((args.out / "calls.jsonl").read_bytes())
        save()
    raise SystemExit(0 if report["complete"] else 1)


if __name__ == "__main__":
    main()
