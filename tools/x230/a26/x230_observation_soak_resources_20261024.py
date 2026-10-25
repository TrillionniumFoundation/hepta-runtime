#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Run the frozen soak with a bounded per-second process/resource timeline."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import time

BASE_DRIVER_SHA256 = "9aed77048e91757034877c9d117781e6f36873db5c9e8d70fe0dfca76eb098ff"
HERE = Path(__file__).resolve().parent
path = HERE / "x230_observation_soak.py"
if hashlib.sha256(path.read_bytes()).hexdigest() != BASE_DRIVER_SHA256:
    raise RuntimeError("frozen soak driver changed")
spec = importlib.util.spec_from_file_location("x230_frozen_soak", path)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

class TimelineResources(base.Resources):
    def __init__(self, pid):
        self.timeline = []
        self.master_generations = {}
        self.timeline_capped = False
        self.error_count = 0
        self.origin = time.monotonic()
        super().__init__(pid)

    def run(self):
        next_record = self.origin
        while not self.stop_event.is_set():
            try:
                pending, visited = [self.pid], set()
                totals = {"rss": 0, "fd": 0, "threads": 0, "masters": 0}
                controller = {"rss_kib": 0, "fd": 0, "threads": 0}
                controller_sampled = False
                sample_errors = 0
                while pending:
                    pid = pending.pop()
                    if pid in visited:
                        continue
                    visited.add(pid)
                    try:
                        born, cpu = base.process_stat(pid)
                        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
                        rss = int(status.get("VmRSS", "0 kB").split()[0])
                        hwm = int(status.get("VmHWM", "0 kB").split()[0])
                        fds = len(list(Path(f"/proc/{pid}/fd").iterdir()))
                        threads = int(status.get("Threads", "0").strip())
                        args = (Path(f"/proc/{pid}") / "cmdline").read_bytes().split(b"\0")
                        comm = (Path(f"/proc/{pid}") / "comm").read_text().strip()
                        is_master = comm == "ssh" and b"-N" in args and b"-n" in args and b"-G" not in args and b"ControlMaster=yes" in args
                        base.need(base.process_stat(pid)[0] == born, "sample process identity changed")
                        for task in Path(f"/proc/{pid}/task").iterdir():
                            try:
                                pending.extend(map(int, (task / "children").read_text().split()))
                            except (FileNotFoundError, ProcessLookupError):
                                pass
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                    except Exception as error:
                        sample_errors += 1
                        with self.lock:
                            self.error_count += 1
                            if len(self.errors) < 32:
                                self.errors.append(type(error).__name__ + ": " + str(error)[:200])
                        continue
                    with self.lock:
                        self.seen[(pid, born)] = max(cpu, self.seen.get((pid, born), 0))
                        if pid == self.pid:
                            controller_sampled = True
                            controller = {"rss_kib": rss, "fd": fds, "threads": threads}
                            for key, value in [("controller_rss_kib", rss), ("controller_hwm_kib", hwm), ("controller_fd", fds)]:
                                self.peaks[key] = max(self.peaks[key], value)
                        if is_master:
                            key = (pid, born)
                            if key not in self.master_generations:
                                self.master_generations[key] = {"generation": len(self.master_generations),
                                    "first_seen_seconds": time.monotonic() - self.origin,
                                    "last_seen_seconds": time.monotonic() - self.origin,
                                    "samples": 0}
                            record = self.master_generations[key]
                            record["last_seen_seconds"] = time.monotonic() - self.origin
                            record["samples"] += 1
                    totals["rss"] += rss
                    totals["fd"] += fds
                    totals["threads"] += threads
                    totals["masters"] += int(is_master)
                now = time.monotonic()
                with self.lock:
                    self.samples += 1
                    for key, value in [("tree_rss_kib", totals["rss"]), ("tree_fd", totals["fd"]), ("descendants", max(0, len(visited) - 1))]:
                        self.peaks[key] = max(self.peaks[key], value)
                    if now >= next_record:
                        if len(self.timeline) < 1800:
                            self.timeline.append({"seconds": now - self.origin, "controller": controller,
                                "controller_identity_sampled": controller_sampled,
                                "tree_rss_kib": totals["rss"], "tree_fd": totals["fd"],
                                "tree_threads": totals["threads"],
                                "observed_descendants": max(0, len(visited) - 1),
                                "observed_master_count": totals["masters"],
                                "observed_master_generations": len(self.master_generations),
                                "sample_errors": sample_errors})
                            if len(self.timeline) % 60 == 0:
                                print(json.dumps({"resource_progress": self.timeline[-1]}), flush=True)
                        else:
                            self.timeline_capped = True
                        next_record = now + 1.0
            except Exception as error:
                with self.lock:
                    self.error_count += 1
                    if len(self.errors) < 32:
                        self.errors.append(type(error).__name__ + ": " + str(error)[:200])
            self.stop_event.wait(.1)

    def snapshot(self):
        result = super().snapshot()
        with self.lock:
            result.update({"timeline": list(self.timeline),
                "timeline_capped": self.timeline_capped,
                "error_count": self.error_count,
                "observed_master_generations": [dict(value) for value in self.master_generations.values()],
                "master_classifier": "owned controller descendant comm=ssh with -N, -n, ControlMaster=yes and no -G; sampled generations only",
                "timeline_interval_seconds": 1.0,
                "base_driver_sha256": BASE_DRIVER_SHA256,
                "timeline_driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "timeline_is_sampled_lower_bound": True})
        return result

base.Resources = TimelineResources
if __name__ == "__main__":
    raise SystemExit(base.main())
