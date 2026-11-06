#!/usr/bin/env python3
"""Recompute R36 rejected lifecycle gates from downloaded cells and receipts.

This script performs no network, process control, workload, or benchmark replay.
Original per-round files are not supplied: cell arithmetic is independently
recomputed, while bindings and original auditor assertions remain distinct.
"""
import ast
import datetime as dt
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECEIPTS = ROOT / "r36-perf-receipts"
OUTPUT = Path(__file__).resolve().parent
LIFECYCLE = ROOT / "r36-control" / "lifecycle-tools-01"
CONTROL = ROOT / "r36-control" / "tools-01"
EXPECTED = {
    "lifecycle-gates.json": (17202, "243dd43cda85f1ad7700c9eba7f3cf4583edc6641cf4259447cbca71c648924e"),
    "lifecycle-summary.json": (60616, "6dd4723959fde86bcc41f2d466d74a800a32a7658f7f3f30d35a76737e9d5fca"),
    "lifecycle-report.json": (32373, "1ee73f9556b2ce0e139394e5add300fcf49c2ad985ed00eb16064e9f6842cebb"),
    "lifecycle-round-index.json": (15137, "bff451b8bff33fbaff9198f2e8525bd845b1a593985d2b40c6cc26ae2caba71f"),
    "lifecycle-parent.json": (79577, "f5da48f7569240789a9c30d9661dd74ea797297fa6e12e715bc420316b00f020"),
}
BINARIES = {"A": "bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13",
            "B": "c43db0ef333ce7862080157a1a7fa892ae401a065bdfa96d97d4fd29f2a4eccb"}
checks = []


def check(name, condition, scope="receipt or extracted-cell arithmetic"):
    checks.append({"name": name, "passed": bool(condition), "scope": scope})
    if not condition:
        raise ValueError("Review inconsistency: " + name)


def close(name, actual, expected):
    check(name, math.isfinite(actual) and math.isfinite(expected)
          and math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-9))


def identity(path):
    raw = path.read_bytes()
    return {"file": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def bound(left, right):
    return all(left[key] == right[key] for key in ("bytes", "sha256"))


def literal(path, name):
    nodes = [node for node in ast.parse(path.read_text()).body if isinstance(node, ast.Assign)
             and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    check("one literal " + path.name + ":" + name, len(nodes) == 1)
    return ast.literal_eval(nodes[0].value)


ids = {name: identity(RECEIPTS / name) for name in EXPECTED}
for name, (size, digest) in EXPECTED.items():
    check("received identity " + name, ids[name]["bytes"] == size and ids[name]["sha256"] == digest)
g, s, r, i, p = [json.loads((RECEIPTS / name).read_bytes()) for name in EXPECTED]
for data, schema in [(g, "hepta-r25-lifecycle-gates/v1"), (s, "hepta-r25-lifecycle-abba-summary/v1"),
                     (r, "hepta-r25-lifecycle-abba-control/v1"), (i, "hepta-r25-lifecycle-round-index/v1"),
                     (p, "hepta-r36-normal-lifecycle-campaign-control/v1")]:
    check("schema " + schema, data["schema"] == schema)
policy_path = LIFECYCLE / "lifecycle-gate-policy.json"
policy = json.loads(policy_path.read_bytes())
analyzer = LIFECYCLE / "analyze_lifecycle_gates.py"
summarizer = LIFECYCLE / "summarize_lifecycle_abba_01.py"
phases = literal(analyzer, "PHASES")
required = literal(analyzer, "GATED")
all_phases = literal(summarizer, "PHASES")
generations = literal(summarizer, "GENERATIONS")
check("original operation phases", list(phases) == policy["measured_operation_phases"])
check("original required groups", list(required) == policy["gated_groups"])
check("frozen gate policy identity", bound(g["gate_policy"], identity(policy_path)))
check("original threshold and resolution contract", policy["throughput_minimum_b_over_a"] == .95
      and policy["rpc_p95_maximum_b_over_a"] == 1.10 and policy["cpu_counter_tolerance_ticks_per_phase_per_round"] == 1
      and policy["rss_maximum_extra_kib"] == 512 and policy["rss_maximum_ratio"] == 1.05)
manifest_path = LIFECYCLE / "lifecycle-tools-manifest-01.json"
manifest = json.loads(manifest_path.read_bytes())
check("local frozen manifest matches round index", bound(identity(manifest_path), i["tools_manifest"]))
for name, pin in manifest["files"].items():
    check("lifecycle source pin " + name, Path(name).name == name and bound(pin, identity(LIFECYCLE / name)))
check("closed four-round ABBA", i["closed"] is True and all(v["order"] == "ABBA" and v["round_count"] == 4 for v in (i, r, s, g)))
check("index bound by gate and controller", bound(g["round_index"], ids["lifecycle-round-index.json"])
      and bound(r["round_index"], ids["lifecycle-round-index.json"]) and s["round_index_sha256"] == ids["lifecycle-round-index.json"]["sha256"])
check("summary bound by controller", bound(r["summary"], ids["lifecycle-summary.json"]))
check("round index/controller equality", i["rounds"] == r["rounds"] and i["plan"] == r["plan"]
      and i["tools_manifest"] == r["tools_manifest"])
check("summary manifest hash", s["tools_manifest_sha256"] == i["tools_manifest"]["sha256"])
for arm, key in [("A", "baseline"), ("B", "candidate")]:
    check("runtime pin " + arm, i[key] == r[key] and i[key]["sha256"] == BINARIES[arm]
          and p["binaries"][arm]["hepta-runtime"]["sha256"] == BINARIES[arm])

round_reviews = []
for number, arm in enumerate("ABBA"):
    index_row, summary_row = i["rounds"][number], s["rounds"][number]
    directory = f"round-{number}-{arm}"
    check(directory + " identities/order", all(v["index"] == number and v["arm"] == arm and v["directory"] == directory
          for v in (index_row, summary_row)) and summary_row["candidate_sha256"] == BINARIES[arm])
    check(directory + " raw report/audit binding", summary_row["report_sha256"] == index_row["report"]["sha256"]
          and summary_row["independent_analysis_sha256"] == index_row["independent_analysis"]["sha256"])
    check(directory + " exact phase file set", len(index_row["phase_files"]) == 11
          and {Path(x["path"]).name for x in index_row["phase_files"]} == {"phase-" + phase + ".json" for phase in all_phases})
    check(directory + " exact summary phase order", [x["phase"] for x in summary_row["phase_rows"]] == list(all_phases))
    check(directory + " effect/call counts", (summary_row["new_starts"], summary_row["same_key_lookups"], summary_row["cancellations"],
          summary_row["native_calls"], summary_row["independent_ssh_calls"], summary_row["phase_count"], summary_row["measured_controller_phase_count"])
          == (6, 12, 12, 90, 36, 11, 10))
    last = 0
    controller_generations = {}
    for phase in summary_row["phase_rows"]:
        prefix = directory + ":" + phase["phase"]
        check(prefix + " sequence continuity", phase["operation_sequence_before"] == last
              and phase["operation_sequence_after"] - last == phase["native_calls"] + phase["independent_ssh_calls"])
        last = phase["operation_sequence_after"]
        check(prefix + " six hosts", phase["completed_hosts"] == 6)
        close(prefix + " hosts/whole-phase second", phase["hosts_per_second"], 6 / phase["wall_seconds"])
        close(prefix + " native/whole-phase second", phase["native_calls_per_second"], phase["native_calls"] / phase["wall_seconds"])
        check(prefix + " tool counts", sum(phase["native_calls_by_tool"].values()) == phase["native_calls"])
        if phase["phase"] == "prepare":
            check(prefix + " no active controller", phase["controller_identity"] is None and phase["controller_cpu_seconds"] is None
                  and phase["native_calls"] == 0 and phase["independent_ssh_calls"] == 6
                  and phase["raw_counter_interval_brackets_complete_phase"] is False)
        else:
            cpu = phase["controller_cpu_seconds"]
            check(prefix + " complete controller bracket reported", phase["raw_counter_interval_brackets_complete_phase"] is True
                  and phase["controller_identity"]["directory"] == generations[phase["phase"]][0])
            close(prefix + " CPU per host", phase["controller_cpu_ms_per_host"], 1000 * cpu / 6)
            close(prefix + " CPU per native call", phase["controller_cpu_ms_per_native_call"], 1000 * cpu / phase["native_calls"])
            generation = phase["controller_identity"]["directory"]
            if generation in controller_generations:
                check(prefix + " stable generation identity", controller_generations[generation] == phase["controller_identity"])
            controller_generations[generation] = phase["controller_identity"]
    check(directory + " final sequence and three generations", last == 126 and len(controller_generations) == 3)
    check(directory + " unique controller identities", len({(x["pid"], x["birth_ticks"]) for x in controller_generations.values()}) == 3)
    round_reviews.append({"round": number, "arm": arm, "report": index_row["report"], "audit": index_row["independent_analysis"],
                          "phase_files": index_row["phase_files"], "reported_native_calls": 90, "reported_ssh_calls": 36,
                          "sequence_end": last, "generations": controller_generations})
check("total effects", (s["total_new_starts"], s["total_same_key_lookups"], s["total_cancellations"]) == (24, 48, 48))

# Recompute descriptive whole-phase means too; these are never gate denominators.
for entry in s["phase_comparisons"]:
    phase_name = entry["phase"]
    check("descriptive pair indices " + phase_name, entry["arm_a_rounds"] == [0, 3] and entry["arm_b_rounds"] == [1, 2])
    rows = [next(x for x in rd["phase_rows"] if x["phase"] == phase_name) for rd in s["rounds"]]
    for metric, values in entry["metrics"].items():
        a = [rows[v][metric] for v in (0, 3)]
        b = [rows[v][metric] for v in (1, 2)]
        check("descriptive rows " + phase_name + ":" + metric, values["A"] == a and values["B"] == b)
        if any(value is None for value in a + b):
            check("descriptive absent CPU " + phase_name + ":" + metric, values["B_over_A_mean"] is None)
            continue
        av, bv = sum(a) / 2, sum(b) / 2
        close("descriptive A mean " + phase_name + ":" + metric, av, values["A_mean"])
        close("descriptive B mean " + phase_name + ":" + metric, bv, values["B_mean"])
        close("descriptive ratio " + phase_name + ":" + metric, bv / av, values["B_over_A_mean"])
        for ix in range(2):
            close("descriptive pair " + phase_name + ":" + metric + str(ix), b[ix] / a[ix], values["adjacent_B_over_A"][ix])

cells = g["arms"]
for arm, round_numbers in [("A", [0, 3]), ("B", [1, 2])]:
    check(arm + " exact ten-cell set/order", [(c["round"], c["phase"]) for c in cells[arm]["cells"]]
          == [(number, phase) for number in round_numbers for phase in phases])
    for c in cells[arm]["cells"]:
        prefix = f"cell {arm}{c['round']}:{c['phase']}"
        check(prefix + " six finite latencies", c["calls"] == len(c["latencies_ms"]) == 6
              and all(math.isfinite(v) and v > 0 for v in c["latencies_ms"]))
        check(prefix + " valid span", math.isfinite(c["rpc_span_seconds"]) and c["rpc_span_seconds"] > 0
              and max(c["latencies_ms"]) <= 1000 * c["rpc_span_seconds"])
        check(prefix + " raw clock frequency reported", c["clock_ticks_per_second"] == 100)
        for key in ("controller_cpu_seconds", "controller_and_waited_child_cpu_seconds"):
            check(prefix + " nonnegative " + key, math.isfinite(c[key]) and c[key] >= 0)
            ticks = c[key] * c["clock_ticks_per_second"]
            close(prefix + " integer-tick derived " + key, ticks, round(ticks))
        check(prefix + " waited-child CPU nonnegative", c["controller_and_waited_child_cpu_seconds"] >= c["controller_cpu_seconds"])
        phase_row = next(row for row in s["rounds"][c["round"]]["phase_rows"] if row["phase"] == c["phase"])
        close(prefix + " same controller CPU as phase summary", c["controller_cpu_seconds"], phase_row["controller_cpu_seconds"])
        check(prefix + " RPC span within whole phase", c["rpc_span_seconds"] <= phase_row["wall_seconds"])
        tool = "process_cancel" if c["phase"] in ("concurrent_cancel", "cancel_after_terminal") else "process_start"
        check(prefix + " expected tool/count", phase_row["native_calls_by_tool"] == {tool: 6}
              and phase_row["native_calls"] == 6 and phase_row["independent_ssh_calls"] == 0)


def aggregate(arm, selected_phases):
    selected = [cell for cell in cells[arm]["cells"] if cell["phase"] in selected_phases]
    latencies = [value for cell in selected for value in cell["latencies_ms"]]
    span = sum(cell["rpc_span_seconds"] for cell in selected)
    return {"calls": len(latencies), "phase_windows": len(selected), "rpc_span_seconds": span,
            "rpc_per_second": len(latencies) / span, "rpc_p95_ms": sorted(latencies)[math.ceil(len(latencies) * .95) - 1],
            "controller_cpu_seconds": sum(cell["controller_cpu_seconds"] for cell in selected),
            "controller_and_waited_child_cpu_seconds": sum(cell["controller_and_waited_child_cpu_seconds"] for cell in selected),
            "quantization_tolerance_seconds": sum(1 / cell["clock_ticks_per_second"] for cell in selected)}


comparisons = {}
failures = []
for name in ("all_operations", *phases):
    selected_phases = phases if name == "all_operations" else (name,)
    a, b = [aggregate(arm, selected_phases) for arm in "AB"]
    reported = g["comparisons"][name]
    for arm, result in [("A", a), ("B", b)]:
        for key, value in result.items():
            close(name + " " + arm + " " + key, value, reported[arm][key])
    check(name + " expected calls/windows", a["calls"] == b["calls"] == (60 if name == "all_operations" else 12)
          and a["phase_windows"] == b["phase_windows"] == (10 if name == "all_operations" else 2))
    rps_ratio, p95_ratio = b["rpc_per_second"] / a["rpc_per_second"], b["rpc_p95_ms"] / a["rpc_p95_ms"]
    cpu_limit = a["controller_cpu_seconds"] + b["quantization_tolerance_seconds"]
    results = {"throughput": rps_ratio >= policy["throughput_minimum_b_over_a"],
               "rpc_p95": p95_ratio <= policy["rpc_p95_maximum_b_over_a"],
               "controller_cpu_with_declared_tick_tolerance": b["controller_cpu_seconds"] <= cpu_limit + 1e-12}
    close(name + " RPS ratio", rps_ratio, reported["B_over_A_rpc_per_second"])
    close(name + " p95 ratio", p95_ratio, reported["B_over_A_rpc_p95"])
    close(name + " CPU ceiling", cpu_limit, reported["controller_cpu_limit_seconds"])
    check(name + " exact gate vector", results == reported["gates"])
    check(name + " required status", reported["adoption_required"] == (name in required))
    for key, passed in results.items():
        if name in required and not passed:
            failures.append({"group": name, "gate": key})
    comparisons[name] = {"A": a, "B": b, "adoption_required": name in required, "gates_recomputed": results,
                         "B_over_A_rpc_per_second": rps_ratio, "B_over_A_rpc_p95": p95_ratio,
                         "rpc_rate_change_percent": (rps_ratio - 1) * 100, "rpc_p95_change_percent": (p95_ratio - 1) * 100,
                         "p95_order_statistic_one_based": math.ceil(a["calls"] * .95),
                         "controller_cpu_limit_seconds": cpu_limit,
                         "throughput_ratio_headroom": rps_ratio - policy["throughput_minimum_b_over_a"],
                         "p95_ratio_headroom": policy["rpc_p95_maximum_b_over_a"] - p95_ratio,
                         "controller_cpu_headroom_seconds": cpu_limit - b["controller_cpu_seconds"]}

for arm in "AB":
    check(arm + " six RSS generation peaks", len(cells[arm]["rss_kib"]) == 6
          and all(type(v) is int and v > 0 for v in cells[arm]["rss_kib"]))
rss_a, rss_b = [max(cells[arm]["rss_kib"]) for arm in "AB"]
rss_limit = min(rss_a + policy["rss_maximum_extra_kib"], rss_a * policy["rss_maximum_ratio"])
rss_pass = rss_b <= rss_limit
check("RSS dual-gate recomputation", g["rss"] == {"A_sampled_peak_kib": rss_a, "B_sampled_peak_kib": rss_b,
                                                "limit_kib": rss_limit, "passed": rss_pass})
adoption = not failures and rss_pass
check("exact four required failures", failures == [{"group": "all_operations", "gate": "throughput"},
      {"group": "launch", "gate": "throughput"}, {"group": "launch", "gate": "rpc_p95"},
      {"group": "launch", "gate": "controller_cpu_with_declared_tick_tolerance"}])
check("verified is distinct from passed", g["verified"] is True and s["verified"] is True
      and g["normal_lifecycle_descriptive_verified"] is True and g["passed"] is adoption and adoption is False)

inner_names = [v for number, arm in enumerate("ABBA") for v in (f"canary-{number}-{arm}", f"audit-{number}-{arm}")] + ["summary", "normal-lifecycle-gates"]
check("exact ten inner stages", [v["name"] for v in r["stages"]] == inner_names)
previous_end = 0
for stage in r["stages"]:
    expected_rc = 1 if stage["name"] == "normal-lifecycle-gates" else 0
    check("inner terminal " + stage["name"], stage["returncode"] == expected_rc and stage["automatic_retry"] is False
          and stage["waited_and_reaped"] is True and stage["proc_absent"] is True
          and stage["owned_process_group_absent"] is True and stage["cleanup_signals"] == [])
    check("inner ordered clocks " + stage["name"], previous_end <= stage["start_monotonic_ns"] < stage["end_monotonic_ns"])
    check("inner deadline " + stage["name"], (stage["end_monotonic_ns"] - stage["start_monotonic_ns"]) / 1e9 < stage["timeout_seconds"])
    previous_end = stage["end_monotonic_ns"]
check("inner rejected because gate returned one", r["passed"] is False
      and r["error"] == {"reason": "normal-lifecycle-gates returned nonzero", "type": "ValueError"})
check("no automatic retry", all(value["automatic_retries"] == 0 for value in (g, i, r, p))
      and r["uncertain_effects_are_not_retried"] is True and p["uncertain_effects_are_not_retried"] is True)
check("outer exact stages", [v["name"] for v in p["stages"]] == ["lifecycle-tool-tests", "normal-lifecycle-abba"])
outer = p["stages"][1]
for name, ref in zip(["lifecycle-report.json", "lifecycle-round-index.json", "lifecycle-summary.json", "lifecycle-gates.json"], outer["output_bindings"]):
    check("outer binds local " + name, bound(ref, ids[name]))
check("four outer output bindings", len(outer["output_bindings"]) == 4)
check("outer rejection preserves original output", p["passed"] is False and p["adoption_passed"] is False
      and outer["returncode"] == 1 and outer["passed"] is False and outer["timed_out"] is False)
for stage in p["stages"]:
    check("outer owned stage/group closure " + stage["name"], stage["waited_and_reaped"] is True
          and stage["owned_process_absent"] is True and stage["owned_process_group_absent"] is True
          and stage["cleanup_signals"] == [])
    close("outer elapsed " + stage["name"], stage["elapsed_seconds"], (stage["end_monotonic_ns"] - stage["start_monotonic_ns"]) / 1e9)
check("independent-controller cleanup remains unknown in parent", outer["independent_controller_cleanup"]
      == "unknown; stage-group absence is insufficient and no workload is retried")
for key in ("inputs_unchanged", "source_inputs_unchanged", "baseline_source_inputs_unchanged", "measurement_attribution_valid"):
    check("outer reported " + key, p[key] is True, "parent assertion; no fresh remote observation")
check("candidate/scope pins", p["candidate_release"] == "R36" and p["candidate_binary_sha256"] == BINARIES["B"]
      and p["saturated_cancellation_verified"] is False and p["production_services_modified"] is False)
monitor = p["compiler_monitor"]
check("compiler monitor receipts passed", monitor["passed"] is True and monitor["monitor_sources_unchanged"] is True)
check("compiler monitor covers stages", monitor["guarded_body_start_monotonic_ns"] <= p["stages"][0]["start_monotonic_ns"]
      and monitor["guarded_body_end_monotonic_ns"] >= outer["end_monotonic_ns"])
check("compiler policy unchanged", monitor["limits"] == json.loads((CONTROL / "compiler-monitor-policy-01.json").read_bytes())["limits"])
for name, pin in monitor["sources"].items():
    check("compiler monitor source " + name, bound(pin, identity(CONTROL / Path(pin["path"]).name)))
check("outer launcher identity", p["launcher_sha256"] == identity(CONTROL / "r36_lifecycle_campaign.py")["sha256"])

rss = dict(g["rss"], extra_kib=rss_b-rss_a, B_over_A=rss_b/rss_a,
           change_percent=(rss_b/rss_a-1)*100, headroom_kib=rss_limit-rss_b,
           A_generation_peaks_kib=cells["A"]["rss_kib"], B_generation_peaks_kib=cells["B"]["rss_kib"])
review = {
    "schema": "hepta-r36-lifecycle-independent-arithmetic-review/v1", "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    "review_consistency_passed": True, "original_required_lifecycle_gates_passed": False,
    "candidate_accepted": False, "decision": "reject R36 under the original mandatory normal-lifecycle gates",
    "raw_evidence_reaudit_performed": False, "extracted_cell_latency_count_recomputed": 120,
    "new_gate_added": False, "benchmark_replay_performed": False, "saturated_cancellation_verified": False,
    "input_identities": ids, "review_script": identity(Path(__file__)),
    "original_analyzer": identity(analyzer), "original_summarizer": identity(summarizer), "gate_policy": policy,
    "frozen_policy_identity": identity(policy_path), "frozen_manifest_identity": identity(manifest_path),
    "runtime_sha256": BINARIES, "required_gate_failures": failures, "comparisons": comparisons, "rss": rss,
    "extracted_cells_reviewed": cells, "round_binding_review": round_reviews,
    "inner_failure": r["error"], "outer_failure": p["error"],
    "owned_stage_groups_reported_absent": True,
    "independent_controller_cleanup": outer["independent_controller_cleanup"],
    "compiler_monitor": monitor,
    "method": {"rpc_rate": "successful native RPC count / sum complete per-phase RPC spans",
               "rpc_span": "Already-extracted cell span; original per-call clock endpoints not supplied",
               "p95": "Nearest rank ceil(0.95*N); all_operations N=60 rank=57, each phase N=12 rank=12, recomputed from the 120 cell latencies",
               "controller_cpu": "Sum extracted complete-phase utime+stime deltas; cross-check phase summary; raw /proc strings not supplied",
               "cpu_gate": "B <= A + sum(1/HZ for each B cell) + 1e-12; 100 Hz, 0.10 s aggregate or 0.02 s per phase",
               "cpu_gate_is_relative_10_percent": False,
               "waited_child_cpu": "Retained separately and excluded from CPU gate",
               "rss": "Maximum of all six controller-generation peaks per arm; B <= min(A+512 KiB, A*1.05)",
               "whole_phase_means": "Recomputed as descriptive values; never substituted for gate RPC-span denominators",
               "numeric_consistency_tolerance": "math.isclose(rel_tol=1e-12,abs_tol=1e-9); original strict gate comparisons retained"},
    "interpretation": [
        "The failed required gate set has four members: aggregate throughput, plus launch throughput, p95 and controller CPU.",
        "At 100 Hz, launch controller CPU implies A=4+5=9 ticks, B=7+5=12 ticks. The original two-tick tolerance yields an 11-tick ceiling, exceeded by one tick. This is not a floating-point near-boundary ambiguity.",
        "Live cancellation and RSS gates pass; they do not override failure of other mandatory gates.",
        "Descriptive summary verified=true means completed coherent evidence, not candidate performance acceptance. Both inner and outer control reports preserve the failed result.",
        "One finite ABBA supports this predeclared acceptance decision, not statistical significance or a proven causal explanation for the regression.",
        "Per parent decision, no async supplement or saturation workload follows this rejected normal-lifecycle result; no replay is used to seek a passing outcome.",
    ],
    "limitations": [
        "This review uses five downloaded JSON receipts plus frozen local policy/source. It independently recomputes extracted-cell arithmetic and all required gate decisions, but not the original raw RPC timestamps, /proc counters or wire/result data.",
        "The 44 original phase files, four per-round raw reports, four original independent audits and resource traces are referenced by hash but not locally supplied for this review. The later evidence archive can support their raw re-verification.",
        "Controller generation identities, no-retry and source immutability are checked for report consistency, not observed anew on the hosts.",
        "Outer independent-controller cleanup remains unknown in the retained failure report; stage-group absence does not independently prove those controller sessions absent.",
        "Compiler ledger and compiler audit bodies were not rerun locally. Their reported verdict, identity, source pins, policy and guard interval were checked.",
        "Counts describe C6 native lifecycle RPCs, not job-compute throughput, maximum capacity, saturated cancellation or cluster CPU/RSS.",
    ],
    "checks": checks, "check_count": len(checks),
    "secondary_reviewer": {"agent": "/root/audit_perf_history/control_review", "reported_checks_passed": 519,
                           "scope": "Independent extracted-cell/summary arithmetic, unchanged required failure outcome; no raw trace re-audit"},
}
(OUTPUT / "lifecycle-review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
lines = ["# R36 Normal lifecycle 独立复核：拒绝采纳", "",
         "**R36 没有通过原 mandatory normal-lifecycle 门限，维持拒绝结果。** 所有数值与原 gates.json 一致；没有改门限、丢弃样本、追加重测或用通过的子项抵消失败项。", "",
         "| 必选分组 | RPC/s A → B | 吞吐 B/A／变化 | p95 A → B，ms | p95 B/A／变化 | Controller CPU B／原上限 | 结果 |",
         "|---|---:|---:|---:|---:|---:|---|"]
for name in required:
    c = comparisons[name]
    a, b = c["A"], c["B"]
    status = "通过" if all(c["gates_recomputed"].values()) else "失败"
    lines.append(f"| {name} | {a['rpc_per_second']:.6f} → {b['rpc_per_second']:.6f} | {c['B_over_A_rpc_per_second']:.9f} / {c['rpc_rate_change_percent']:+.4f}% | {a['rpc_p95_ms']:.6f} → {b['rpc_p95_ms']:.6f} | {c['B_over_A_rpc_p95']:.9f} / {c['rpc_p95_change_percent']:+.4f}% | {b['controller_cpu_seconds']:.2f}s / {c['controller_cpu_limit_seconds']:.2f}s | {status} |")
lines += ["", "原门限：throughput B/A ≥0.95；p95 B/A ≤1.10；Controller CPU为 A 总量加每个 B phase/round 一个 raw clock tick，并保留原代码1e−12比较容差。CPU门限不是10%相对变化。", "",
          "明确失败四项：all_operations吞吐；launch吞吐、p95和Controller CPU。Launch的100 Hz计数对应A=4+5=9 ticks、B=7+5=12 ticks；两轮容差2 ticks后上限11 ticks，仍超1 tick（0.01秒），不是浮点取整误判。", "",
          f"RSS通过：A {rss_a:,} KiB，B {rss_b:,} KiB，增加{rss_b-rss_a} KiB（{rss['change_percent']:+.4f}%）；上限min(A+512,A×1.05)={rss_limit:,} KiB，余量{rss['headroom_kib']} KiB。该结果为Controller采样峰值。Concurrent cancellation三项通过，但不能抵消其他mandatory项失败。", "",
          "## 复算内容和拒绝链", "",
          f"本次{len(checks)}项一致性检查通过；另一个只读reviewer独立完成519项检查。从gates内20个C6 cell、120条latency值重算全部分组：每臂all_operations为60次调用／10个RPC时间窗；每个独立phase为12次／2窗。吞吐使用calls/sum(RPC spans)；p95为nearest rank，60条取第57条，12条取第12条。11阶段×4轮的顺序、44个原phase文件身份、phase汇总、generation对应、完整计数及四份原audit绑定均一致。", "",
          "四轮正常canary及原audit各自返回0，summary返回0；normal-lifecycle-gates返回1，inner report passed=false；outer normal-lifecycle-abba返回1，外层passed=false、adoption_passed=false。输入未变、编译监测有效，失败不是timeout。summary verified=true表示证据完整，不能解释为性能采纳通过。", "",
          "**边界：原四轮report、44个phase原件、wire、/proc原始字符串及resource trace尚未下载，本次没有宣称原始证据重审。** RPC span与CPU来自原analyzer导出的cell，已与phase summary交叉验证；分位数则确实从cell内120个latency数值独立重算。以后归档原件到位可验证其来源链。", "",
          "外层报告明确保留independent_controller_cleanup=unknown；owned stage process/group absent已报告，不能据此声称所有独立Controller session均已清除。原逐轮审计是否充分证明独立Controller闭合，须读取归档中的原件。", "",
          "## 处理结论", "",
          "维持R36拒绝采纳，保留失败原件。主线程已决定停止后续async与saturation实验；不重测来寻求通过。这是一次有限ABBA在预设门限下的决定，不宣称统计显著性，也不推测回归必然由某个代码机制导致。吞吐指标为native lifecycle RPC，不是job compute吞吐或最大并发容量。", "",
          "完整数据、失败项、文件SHA和范围声明见同目录`lifecycle-review.json`，本地复算程序为`review_lifecycle.py`。", "",
          "## 复核原件身份", "", "| 文件 | 字节 | SHA256 |", "|---|---:|---|"]
for name, ident in ids.items():
    lines.append(f"| {name} | {ident['bytes']} | `{ident['sha256']}` |")
lines += ["", f"生成时间：{review['created_utc']}。只写新review文件；未改冻结控制、源代码或远端状态。", ""]
(OUTPUT / "lifecycle-review.md").write_text("\n".join(lines))
print(json.dumps({"review_consistency_passed": True, "candidate_accepted": False, "required_failures": failures,
                  "checks": len(checks), "outputs": [identity(OUTPUT / "lifecycle-review.json"), identity(OUTPUT / "lifecycle-review.md"), identity(Path(__file__))]}))
