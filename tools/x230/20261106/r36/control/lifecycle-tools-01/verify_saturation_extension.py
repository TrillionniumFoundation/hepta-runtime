#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent arithmetic and identity audit for the finite cancellation gate."""
from collections import Counter
import json
from pathlib import Path

import audit_native_evidence as evidence

need = evidence.need
HOST_COUNTS = {"ai395":6, "mac":6, "main":5, "pocket4":5, "rog":5, "x230":5}


def identity(value):
    raw = value["raw_stat"]
    tail = raw[raw.rfind(") ") + 2:].split()
    actual = {"pid":int(raw.split("(", 1)[0]), "birth_ticks":int(tail[19]),
              "parent_pid":int(tail[1]), "state":tail[0]}
    need(all(value[key] == data for key, data in actual.items()), "raw held-Child identity differs")
    need(actual["state"] != "Z", "held ordinary transport was terminal")
    return actual


def verify(report, directory):
    directory = Path(directory)
    gate = directory / "saturation-gate"
    value = report["saturation"]
    need(value["schema"] == "hepta-r25-cancel-saturation/v1" and value["passed"] is True
         and value["pressure_count"] == 32 and value["normal_admitted"] == 16
         and value["normal_children"] == 8 and value["drain_errors"] == []
         and value["automatic_retries"] == 0 and value["only_confirmed_original_keys"] is True,
         "not a closed fixed saturation proof")
    need(not (gate / "config.json").exists() and not (gate / "config.json").is_symlink(), "status gate was not retired after drain")
    config_raw = evidence.bound_file(gate, {"file":"config.closed.json", **{k:value["config"][k] for k in ("bytes", "sha256")}})
    config = json.loads(config_raw)
    need(config == value["config"]["value"] and config["nonce"] == report["nonce"], "gate config binding differs")
    need(config["expires_monotonic_ns"] - config["created_monotonic_ns"] == 8_000_000_000,
         "gate lifetime is not the frozen eight seconds")
    controller = {"pid":report["after_crash_startup"]["pid"], "birth_ticks":report["after_crash_startup"]["birth_ticks"]}
    need(config["controller"] == controller and set(config["bindings"]) == set(HOST_COUNTS), "gate controller/host set differs")
    wrapper = report["saturation_wrapper"]
    need(wrapper["gates_effect_commands"] is False and wrapper["only_exact_original_status_predicate"] is True
         and wrapper["maximum_gate_seconds"] == 8
         and config["status_command_sha256"] == wrapper["predicate"]["remote_command_sha256"], "gate predicate differs")
    evidence.bound_file(directory / "bin", {"file":"ssh", "bytes":wrapper["script_bytes"], "sha256":wrapper["script_sha256"]})
    evidence.bound_file(directory / "bin", {"file":"ssh-original", "bytes":wrapper["original_wrapper_bytes"], "sha256":wrapper["original_wrapper_sha256"]})
    for host, binding in config["bindings"].items():
        record = report["hosts"][host]["launch"]["job"]
        expected = {"job_id":record["id"], "job_dir":record["remote_job_dir"], "request_digest":record["request_digest"],
                    "unit":record["unit"], "wait_seconds":0}
        need(record["launch_state"] == "launched" and record["system_jobctl"] is False
             and binding == {"ssh_target":record["ssh_target"], "request":expected}, "gate selected something other than original status")
    snapshots = value["snapshots"]
    need(len(snapshots) == 2 and [s["label"] for s in snapshots] == ["before_cancel", "after_all_six_cancel_acks"],
         "wrong gate snapshot set")
    held_sets = []
    for snapshot in snapshots:
        own = identity(snapshot["controller"])
        need((own["pid"], own["birth_ticks"]) == (controller["pid"], controller["birth_ticks"]), "controller generation changed")
        rows = snapshot["held_children"]
        need(len(rows) == 8 and len({(r["ready"]["pid"], r["ready"]["birth_ticks"]) for r in rows}) == 8,
             "ordinary active transport count differs")
        need(max(Counter(r["ready"]["host"] for r in rows).values()) <= 2, "ordinary per-host cap exceeded")
        held = []
        for row in rows:
            raw = evidence.bound_file(gate, {"file":row["ready_file"], "bytes":row["ready_bytes"], "sha256":row["ready_sha256"]})
            ready = json.loads(raw)
            observed = identity(row["observed"])
            need(ready == row["ready"] and ready["controller"] == controller
                 and ready["config_sha256"] == value["config"]["sha256"] and ready["nonce"] == report["nonce"]
                 and ready["status_command_sha256"] == config["status_command_sha256"]
                 and ready["request"] == config["bindings"][ready["host"]]["request"]
                 and observed["pid"] == ready["pid"] and observed["birth_ticks"] == ready["birth_ticks"]
                 and observed["parent_pid"] == ready["parent_pid"] == controller["pid"], "held original transport lost binding")
            need(config["created_monotonic_ns"] <= ready["ready_monotonic_ns"] <= snapshot["start_monotonic_ns"],
                 "held-Child readiness escaped gate clock")
            held.append((ready["pid"], ready["birth_ticks"], row["ready_sha256"]))
        held_sets.append(sorted(held))
    need(held_sets[0] == held_sets[1], "ordinary Child custody changed while cancel used reserve")
    calls = value["calls"]
    need(len(calls) == 32 and {r["index"] for r in calls} == set(range(32))
         and len({r["sequence"] for r in calls}) == 32 and Counter(r["host"] for r in calls) == HOST_COUNTS,
         "pressure request set differs")
    raw_calls = {r["sequence"]:r for r in report["native_calls"] if r["phase"] == "saturation_pressure"}
    need(set(raw_calls) == {r["sequence"] for r in calls}, "pressure response set differs from native capture")
    for row in calls:
        native, dto, host = raw_calls[row["sequence"]], row["result"], row["host"]
        need(native["host"] == host and native["tool"] == "process_start" and native["controller_directory"] == "after-crash-controller"
             and dto["reused"] is True and dto["retried_launch"] is False and dto["launch"] is None
             and dto["job"] == report["hosts"][host]["launch"]["job"]
             and dto["status"]["state"] in {"status_unavailable", "running", "cancelled"}, "pressure result is not original observation-only reuse")
        need(native["rpc"]["send_end_monotonic_ns"] <= snapshots[0]["start_monotonic_ns"],
             "a pressure request was not submitted before cancel proof")
    refused = [r for r in calls if r["result"]["status"]["state"] == "status_unavailable"]
    need(len(refused) == value["status_unavailable_count"] == 16
         and value["pending_before_cancel"] == 16
         and sorted(value["refused_before_cancel"], key=lambda r:r["index"]) == sorted(refused, key=lambda r:r["index"]),
         "normal admission refusal/pending split differs")
    for row in refused:
        need(raw_calls[row["sequence"]]["end_monotonic_ns"] <= snapshots[0]["start_monotonic_ns"],
             "claimed pre-cancel refusal completed later")
    cancels = [r for r in report["native_calls"] if r["phase"] == "concurrent_cancel"]
    need(len(cancels) == 6 and {r["host"] for r in cancels} == set(HOST_COUNTS)
         and all(r["tool"] == "process_cancel" and snapshots[0]["end_monotonic_ns"] <= r["start_monotonic_ns"]
                 <= r["end_monotonic_ns"] <= snapshots[1]["start_monotonic_ns"] for r in cancels),
         "six cancel acknowledgements were not wholly inside the saturation proof")
    release_raw = (gate / "release.json").read_bytes()
    release = json.loads(release_raw)
    need(release == value["release"] and release["controller"] == controller and release["nonce"] == report["nonce"],
         "gate release receipt differs")
    need(snapshots[1]["end_monotonic_ns"] <= release["released_monotonic_ns"] < config["expires_monotonic_ns"]
         and value["cancel_acks_before_release"] is True
         and release["released_monotonic_ns"] < value["drained_monotonic_ns"], "gate opened before cancellation proof completed")
    retirement = value["retirement"]
    need(retirement["config_file"] == "config.closed.json"
         and retirement["config_sha256"] == value["config"]["sha256"]
         and retirement["release_sha256"] == evidence.sha(release_raw)
         and retirement["directory_synced"] is True
         and value["drained_monotonic_ns"] <= retirement["start_monotonic_ns"]
         <= retirement["end_monotonic_ns"] <= report["after_cancel_startup"]["start_monotonic_ns"],
         "gate retirement is not bound to complete drain before controller restart")
    for row in calls:
        if row not in refused:
            need(raw_calls[row["sequence"]]["rpc"]["rpc_end_monotonic_ns"] >= release["released_monotonic_ns"],
                 "held ordinary request returned before explicit release")
    return {"verified":True, "normal_pressure_calls":32, "admitted_and_drained":16,
            "capacity_status_unavailable":16, "unchanged_held_original_children":8,
            "cancel_acks_before_release":6, "new_remote_jobs":6, "effect_retries":0,
            "gate_elapsed_ms":(release["released_monotonic_ns"] - config["created_monotonic_ns"]) / 1e6,
            "gate_release_sha256":evidence.sha(release_raw),
            "retired_after_drain_before_restart":True,
            "scope":"Artificial local status-only gate; proves cancellation control availability, not maximum throughput."}
