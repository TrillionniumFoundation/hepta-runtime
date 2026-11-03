#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""R14 fresh-child thread/allocator causal probe; not a performance benchmark."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import types

ROOT = Path("/home/qian/hepta-runtime-optimization-20261103-r14")
OUT = ROOT / "thread-arena-diagnostic-02"
HARNESS = Path("/home/qian/hepta-runtime-optimization-20261103-r12/source/tools/x230/20261103/r12/run_cancel_responsiveness.py")
READY_SHA = "efdc0a817aa4a9b80106a31b899678a4b7863523dd47e145f99b5d6ee2aa6442"
TICKS = os.sysconf("SC_CLK_TCK")
ORDER = [("arena1", "1"), ("arena4", "4"), ("arena4", "4"), ("arena1", "1")]
REPORT = {}
HEADER = re.compile(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+(?:\s+(.*))?$")


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save():
    temporary = OUT / "report.next"
    with temporary.open("w") as stream:
        json.dump(REPORT, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, OUT / "report.json")


def task_stat(path):
    text = path.read_text()
    end = text.rfind(")")
    fields = text[end + 2:].split()
    return {"name": text[text.find("(") + 1:end], "state": fields[0],
            "start_ticks": int(fields[19]), "user_ticks": int(fields[11]),
            "system_ticks": int(fields[12]),
            "cpu_ticks": int(fields[11]) + int(fields[12])}


def identity(controller):
    row = task_stat(Path(f"/proc/{controller.child.pid}/stat"))
    need(row["start_ticks"] == controller.birth and row["state"] != "Z",
         "owned child PID generation changed or exited")
    return row


def snapshot(controller, phase, wave=None):
    process = identity(controller)
    pid = controller.child.pid
    fields = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                  if ":" in line)
    names = ("VmRSS", "VmHWM", "VmSize", "VmPeak", "VmData", "VmStk",
             "RssAnon", "RssFile", "RssShmem")
    tasks, disappeared = [], []
    for path in sorted(Path(f"/proc/{pid}/task").iterdir(), key=lambda p: int(p.name)):
        try:
            item = task_stat(path / "stat")
            item["tid"] = int(path.name)
            tasks.append(item)
        except FileNotFoundError:
            disappeared.append(int(path.name))
    identity(controller)
    return {"phase": phase, "wave": wave, "monotonic": time.monotonic(),
            "utc": now(), "threads": int(fields["Threads"].split()[0]),
            "listed_tasks": len(tasks), "disappeared_during_sample": disappeared,
            "memory_kib": {key: int(fields[key].split()[0]) for key in names if key in fields},
            "process_cpu_ticks": process["cpu_ticks"], "tasks": tasks,
            "atomic_snapshot": False}


def detailed_memory(controller, directory, phase):
    identity(controller)
    raw = Path(f"/proc/{controller.child.pid}/smaps").read_text()
    identity(controller)
    path = directory / (phase + ".smaps.txt")
    with path.open("x") as stream:
        stream.write(raw)
    maps, current = [], None
    for line in raw.splitlines():
        matched = HEADER.match(line)
        if matched:
            current = {"start": int(matched[1], 16), "end": int(matched[2], 16),
                       "permissions": matched[3], "pathname": matched[4] or ""}
            maps.append(current)
        elif current is not None and ":" in line:
            key, value = line.split(":", 1)
            if key in {"Size", "Rss", "Pss", "Private_Clean", "Private_Dirty",
                       "Anonymous", "AnonHugePages", "Swap"}:
                current[key + "_kib"] = int(value.split()[0])
    anonymous = [row for row in maps if not row["pathname"] and row["permissions"].startswith("rw")]
    pairs = []
    for first, second in zip(maps, maps[1:]):
        if (not first["pathname"] and not second["pathname"]
                and first["permissions"].startswith("rw")
                and second["permissions"].startswith("---")
                and first["end"] == second["start"]
                and first["start"] % (64 * 1024 * 1024) == 0
                and second["end"] - first["start"] == 64 * 1024 * 1024):
            pairs.append({"start": hex(first["start"]), "reserved_kib": 65536,
                          "writable_kib": first.get("Size_kib"),
                          "rss_kib": first.get("Rss_kib")})
    return {"phase": phase, "raw": str(path), "sha256": sha(path),
            "anonymous_writable_regions": len(anonymous),
            "anonymous_writable_rss_kib": sum(r.get("Rss_kib", 0) for r in anonymous),
            "anonymous_writable_top": sorted(anonymous, key=lambda r: r.get("Rss_kib", 0), reverse=True)[:20],
            "heap_rss_kib": sum(r.get("Rss_kib", 0) for r in maps if r["pathname"] == "[heap]"),
            "reservation_like_64m_pairs": pairs,
            "reservation_interpretation": "mapping-shape heuristic, not direct malloc arena enumeration"}


def summarize(row):
    samples = row["snapshots"]
    ready, loaded, idle = samples[0], next(s for s in samples if s["phase"] == "after_load"), samples[-1]
    ready_cpu = {(t["tid"], t["start_ticks"]): t["cpu_ticks"] for t in ready["tasks"]}
    generations = {}
    for sample in samples:
        for task in sample["tasks"]:
            key = (task["tid"], task["start_ticks"])
            previous = generations.setdefault(key, {
                "tid": task["tid"], "start_ticks": task["start_ticks"], "name": task["name"],
                "first_phase": sample["phase"], "last_phase": sample["phase"],
                "observations": 0, "max_cpu_ticks": task["cpu_ticks"],
                "cpu_ticks_at_ready": ready_cpu.get(key, 0),
                "existed_at_ready": key in ready_cpu})
            previous["last_phase"] = sample["phase"]
            previous["observations"] += 1
            previous["max_cpu_ticks"] = max(previous["max_cpu_ticks"], task["cpu_ticks"])
    for generation in generations.values():
        generation["observed_cpu_since_ready_seconds"] = (
            generation["max_cpu_ticks"] - generation["cpu_ticks_at_ready"]) / TICKS
    return {"ready_threads": ready["threads"],
            "peak_observed_threads": max(s["threads"] for s in samples),
            "thread_generations_observed": len(generations),
            "after_load_threads": loaded["threads"], "after_idle_threads": idle["threads"],
            "ready_memory_kib": ready["memory_kib"], "after_load_memory_kib": loaded["memory_kib"],
            "after_idle_memory_kib": idle["memory_kib"],
            "process_cpu_ready_to_load_seconds":
                (loaded["process_cpu_ticks"] - ready["process_cpu_ticks"]) / TICKS,
            "thread_cpu": sorted(generations.values(),
                                 key=lambda r: r["observed_cpu_since_ready_seconds"], reverse=True),
            "thread_cpu_scope": "observed per-TID cumulative ticks; transient unobserved tails may be absent",
            "throughput_claimed": False}


def main():
    sys.dont_write_bytecode = True
    started = time.monotonic()
    deadline = started + 180
    q = json.loads((ROOT / "qualification-01/report.json").read_text())
    local = json.loads((ROOT / "local-campaigns-01/report.json").read_text())
    remote = json.loads((ROOT / "remote-campaigns-01/report.json").read_text())
    ready = json.loads((ROOT / "implementation-ready.json").read_text())
    need(q.get("qualified") is True and q.get("finished_utc"), "qualification is incomplete")
    need(local.get("success") is True and local.get("finished_utc")
         and remote.get("success") is True and remote.get("finished_utc"),
         "original measurements must be complete before this separate diagnostic")
    need(sha(ROOT / "implementation-ready.json") == READY_SHA
         and q["source_tested"] == q["source_after"] == ready["source_after"],
         "frozen candidate source binding differs")
    binary = Path(q["binaries"]["hepta-runtime"]["path"])
    need(binary == ROOT / "qualification-01/hepta-runtime"
         and sha(binary) == q["binaries"]["hepta-runtime"]["sha256"],
         "qualified runtime binding differs")
    harness_binding = [item for item in local["bound_inputs"] if item["path"] == str(HARNESS)]
    need(len(harness_binding) == 1 and sha(HARNESS) == harness_binding[0]["sha256"],
         "original harness changed after completed campaigns")
    harness_sha = sha(HARNESS)
    spec = importlib.util.spec_from_file_location("existing_cancel_harness", HARNESS)
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    OUT.mkdir(mode=0o700, exist_ok=False)
    REPORT.update({
        "schema": "hepta-r14-thread-arena-causal-probe/v1", "success": False,
        "started_utc": now(), "automatic_retries": 0, "compile_or_source_changes": False,
        "scope": "fresh owned local wrong-host refusal children; not a formal performance benchmark",
        "background_activity": "R13 archive upload and independent audit I/O may overlap; rates are not reported as benchmark results",
        "old_harness": {"path": str(HARNESS), "sha256": harness_sha},
        "diagnostic_script_sha256": sha(__file__),
        "qualified_runtime": {"path": str(binary), "sha256": q["binaries"]["hepta-runtime"]["sha256"]},
        "qualification_report_sha256": sha(ROOT / "qualification-01/report.json"),
        "local_report_sha256": sha(ROOT / "local-campaigns-01/report.json"),
        "remote_report_sha256": sha(ROOT / "remote-campaigns-01/report.json"),
        "glibc_confstr": os.confstr("CS_GNU_LIBC_VERSION"),
        "clock_ticks_per_second": TICKS, "workers": 2, "concurrency": 8,
        "receipt_bytes": 4194272, "payload": "escaped",
        "warmup_waves": 2, "load_waves": 24, "idle_seconds": 12,
        "order": [label for label, unused in ORDER],
        "intervention": "MALLOC_ARENA_MAX=1 or 4 only in four fresh child environments; original harness file and production environment untouched",
        "predecessor_diagnostic_report_sha256": "1395c0e75c4c53e10386d7865e3e2f45c7f44bab184d7dffeb9e461dfb600937",
        "predecessor_diagnostic_script_sha256": "67e26e38b16ae9c829fe66b75e766217ea83951529e4e1462ecd451154c82e1c",
        "thread_sampling": "after ready, each warmup/load wave, and every idle second; peak_observed is not an asserted instantaneous maximum",
        "cases": [],
    })
    save()
    data = bench.receipt(4194272, "escaped")
    expected_receipt_sha = hashlib.sha256(data).hexdigest()
    try:
        for position, (label, arena) in enumerate(ORDER):
            need(time.monotonic() < deadline, "diagnostic overall bound reached")
            directory = OUT / f"{position:02d}-{label}"
            config, receipt, guard, trap = bench.fixture(directory, data)
            row = {"position": position, "arm": label, "arena_max": arena,
                   "snapshots": [], "memory_details": [], "warmup_replies": [],
                   "load_replies": [], "success": False}
            REPORT["cases"].append(row)
            spawned = []
            def owned_spawn(argv, **kwargs):
                need(not spawned and argv[0] == str(binary) and argv[1] == "mcp"
                     and kwargs.get("cwd") == directory
                     and kwargs.get("start_new_session") is True,
                     "diagnostic launch exceeded its owned child boundary")
                env = dict(kwargs["env"])
                need(set(env) == {"PATH", "LANG", "SHELL", "TOKIO_WORKER_THREADS", "RUST_LOG"}
                     and env["TOKIO_WORKER_THREADS"] == "2",
                     "original harness child environment differs")
                if arena is not None:
                    env["MALLOC_ARENA_MAX"] = arena
                kwargs["env"] = env
                row["child_env"] = env
                process = subprocess.Popen(argv, **kwargs)
                spawned.append(process)
                return process
            bench.subprocess = types.SimpleNamespace(
                Popen=owned_spawn, PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired)
            controller = None
            print(json.dumps({"state": "case_started", "position": position, "arm": label}), flush=True)
            try:
                controller = bench.Controller(binary, config, guard, directory, 2)
                need(len(spawned) == 1, "unexpected owned child count")
                row["startup"] = controller.startup
                row["snapshots"].append(snapshot(controller, "ready"))
                row["memory_details"].append(detailed_memory(controller, directory, "ready"))
                for wave in range(2):
                    need(time.monotonic() < deadline, "diagnostic overall bound reached")
                    replies = controller.batch(bench.calls(8), timeout=min(20, deadline - time.monotonic()))
                    bench.validate(replies)
                    row["warmup_replies"].extend(replies)
                    row["snapshots"].append(snapshot(controller, "warmup", wave))
                row["snapshots"].append(snapshot(controller, "before_load"))
                for wave in range(24):
                    need(time.monotonic() < deadline, "diagnostic overall bound reached")
                    replies = controller.batch(bench.calls(8), timeout=min(20, deadline - time.monotonic()))
                    bench.validate(replies)
                    for reply in replies:
                        reply["diagnostic_wave"] = wave
                    row["load_replies"].extend(replies)
                    row["snapshots"].append(snapshot(controller, "load", wave))
                row["snapshots"].append(snapshot(controller, "after_load"))
                row["memory_details"].append(detailed_memory(controller, directory, "after_load"))
                idle_start = time.monotonic()
                for second in range(1, 13):
                    target = idle_start + second
                    while time.monotonic() < target:
                        need(time.monotonic() < deadline, "diagnostic overall bound reached")
                        time.sleep(max(0.0, min(.2, target - time.monotonic())))
                    row["snapshots"].append(snapshot(controller, f"idle_{second}s"))
                row["observed_idle_seconds"] = time.monotonic() - idle_start
                row["memory_details"].append(detailed_memory(controller, directory, "after_idle"))
                row["receipt_unchanged"] = sha(receipt) == expected_receipt_sha
                row["no_operation_cancel_intent"] = not (directory / "state/audit/events.jsonl").exists()
                row["no_ssh_dispatch"] = not trap.exists()
                need(row["receipt_unchanged"] and row["no_operation_cancel_intent"] and row["no_ssh_dispatch"],
                     "refusal fixture changed or advanced to an effect")
                row["summary"] = summarize(row)
            finally:
                if controller is not None:
                    row["shutdown"] = controller.close()
                elif spawned:
                    process = spawned[0]
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(10)
                    row["failed_initialization_cleanup_exit"] = process.returncode
                save()
            need(row["shutdown"]["exit_code"] == 0
                 and row["shutdown"]["method"] == "stdin_eof"
                 and row["shutdown"]["unmatched"] == 0
                 and row["shutdown"]["reader_error"] is None, "owned child shutdown failed")
            row["success"] = True
            save()
            summary = row["summary"]
            print(json.dumps({"state": "case_finished", "position": position, "arm": label,
                              "threads": [summary["ready_threads"], summary["peak_observed_threads"],
                                          summary["after_load_threads"], summary["after_idle_threads"]],
                              "rss_kib": [summary["ready_memory_kib"]["VmRSS"],
                                          summary["after_load_memory_kib"]["VmRSS"],
                                          summary["after_idle_memory_kib"]["VmRSS"]],
                              "hwm_kib": summary["after_idle_memory_kib"]["VmHWM"]}), flush=True)
        need(sha(binary) == REPORT["qualified_runtime"]["sha256"]
             and sha(HARNESS) == harness_sha, "qualified input changed during diagnostic")
        REPORT["success"] = True
    except BaseException as error:
        REPORT["error"] = {"type": type(error).__name__, "reason": str(error)[:1200]}
        raise
    finally:
        REPORT["finished_utc"] = now()
        REPORT["wall_seconds_diagnostic_only"] = time.monotonic() - started
        save()
        print(json.dumps({"success": REPORT["success"], "report": str(OUT / "report.json")}), flush=True)


if __name__ == "__main__":
    import signal
    def interrupted(signum, unused_frame):
        raise InterruptedError("diagnostic received signal " + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    main()
