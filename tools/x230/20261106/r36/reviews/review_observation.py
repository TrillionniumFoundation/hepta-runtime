#!/usr/bin/env python3
"""Local, non-executing review of the three downloaded R36 OBS receipts.

This is a descriptive arithmetic/provenance review, not a replacement gate or
a raw-evidence auditor. It does not invoke frozen measurement code or any host.
"""
import ast
import datetime as dt
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "r36-perf-receipts"
OUTPUT = Path(__file__).resolve().parent
CONTROL = ROOT / "r36-control" / "tools-01"
EXPECTED = {
    "observation-summary.json": (13844, "a5a17eadb4d6a934fe464ccb1cb8dee5b32911355e294f25e3d93ad97024a246"),
    "observation-native-analysis.json": (62873, "b2695e1c9992b0b0a9b547ea2d64e4da6fa83e7b5616ebb294215849b470bda0"),
    "observation-parent.json": (118815, "d86577f327efb970588070c9c64f05942bd82ddff5613a11026d4448820c9299"),
}
BINARIES = {
    "A": "bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13",
    "B": "c43db0ef333ce7862080157a1a7fa892ae401a065bdfa96d97d4fd29f2a4eccb",
}
checks = []


def check(name, condition, scope="local arithmetic or receipt consistency"):
    checks.append({"name": name, "passed": bool(condition), "scope": scope})
    if not condition:
        raise ValueError("Review check failed: " + name)


def close(name, actual, expected):
    check(name, math.isfinite(actual) and math.isfinite(expected)
          and math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-9))


def identity(path):
    raw = path.read_bytes()
    return {"file": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def same_identity(left, right):
    return all(left[k] == right[k] for k in ("bytes", "sha256"))


identities = {name: identity(INPUT / name) for name in EXPECTED}
for name, (size, digest) in EXPECTED.items():
    check("received bytes and SHA256: " + name,
          identities[name]["bytes"] == size and identities[name]["sha256"] == digest)
s = json.loads((INPUT / "observation-summary.json").read_bytes())
n = json.loads((INPUT / "observation-native-analysis.json").read_bytes())
p = json.loads((INPUT / "observation-parent.json").read_bytes())
check("summary schema", s["schema"] == "hepta-r25-observation-gates/v1")
check("native analysis schema", n["schema"] == "hepta-native-observation-independent-analysis/v3")
check("parent schema", p["schema"] == "hepta-r25-observation-campaign-control/v1")
check("candidate release", p["candidate_release"] == "R36")

# Read literal policy only. Do not import or execute the frozen summary module.
summary_source = CONTROL / "summarize_r25_campaign.py"
tree = ast.parse(summary_source.read_text())
gate_nodes = [x for x in tree.body if isinstance(x, ast.Assign)
              and isinstance(x.targets[0], ast.Name) and x.targets[0].id == "GATES"]
check("one literal frozen GATES definition", len(gate_nodes) == 1)
gates = ast.literal_eval(gate_nodes[0].value)
check("thresholds match unchanged original summary source", gates == s["thresholds"] == p["thresholds"])
check("summary and native runtime identities", s["binary_sha256"] == n["binary_sha256"] == BINARIES)
for arm in BINARIES:
    check("parent runtime " + arm, p["binaries"][arm]["hepta-runtime"]["sha256"] == BINARIES[arm])
check("summary binds received native analysis", same_identity(s["evidence"]["native_analysis"], identities["observation-native-analysis.json"]))
check("parent binds received summary", same_identity(p["summary"], identities["observation-summary.json"]))
check("native report identity linkage", n["original_bytes"] == s["evidence"]["native_report"]["bytes"]
      and n["original_sha256"] == s["evidence"]["native_report"]["sha256"])

stages = p["stages"]
stage_names = ["native-observation", "native-audit", "native-boundary", "boundary-audit",
               "cancel-recovery", "recovery-audit", "observation-summary"]
check("exact seven stages in order", [x["name"] for x in stages] == stage_names)
references = [s["evidence"][key] for key in ["native_report", "native_analysis", "boundary_report",
              "boundary_analysis", "lifecycle_report", "lifecycle_analysis"]] + [p["summary"]]
stage_review = []
previous_end = 0
for stage, reference in zip(stages, references):
    name = stage["name"]
    check(name + " output binding", stage["output_bindings"] == [reference])
    check(name + " output path", stage["outputs"] == [reference["path"]])
    check(name + " terminal and owned cleanup receipt", stage["returncode"] == 0 and stage["passed"] is True
          and stage["waited_and_reaped"] is True and stage["owned_process_absent"] is True
          and stage["owned_process_group_absent"] is True and stage["cleanup_signals"] == [],
          "reported stage terminal/cleanup; no fresh process inspection")
    check(name + " chronological order", previous_end <= stage["start_monotonic_ns"] < stage["end_monotonic_ns"])
    elapsed = (stage["end_monotonic_ns"] - stage["start_monotonic_ns"]) / 1e9
    close(name + " elapsed arithmetic", elapsed, stage["elapsed_seconds"])
    check(name + " within effective timeout", elapsed <= stage["effective_timeout_seconds"])
    previous_end = stage["end_monotonic_ns"]
    stage_review.append({"name": name, "elapsed_seconds": elapsed, "returncode": stage["returncode"],
                         "owned_process_and_group_absent_reported": True, "output": reference})
for key in ["passed", "observation_gate_passed", "correctness_stages_completed", "inputs_unchanged",
            "source_inputs_unchanged", "baseline_source_inputs_unchanged", "baseline_enablement_verified",
            "measurement_attribution_valid"]:
    check("parent reported " + key, p[key] is True, "parent report assertion; no raw rerun")
check("no retry, mutation, or blockers", p["automatic_retries"] == 0 and p["production_services_modified"] is False
      and p["rejection_reasons"] == [] and p["open_blockers"] == [])
check("qualified source maps match current inputs reported", p["qualified_source_maps_match_current_inputs"] == {"A": True, "B": True})
prep = p["candidate_preparation_gate"]
check("qualification receipt passed", prep["passed"] is True and prep["qualified_source_files"] == 220)
check("qualification test totals", prep["tests"] == {"failed": 0, "ignored": 34, "passed": 1645, "retries": 0, "selected": 1679})
check("qualification source digest linkage", prep["full_source_inputs_sha256"] == p["source_inputs_sha256"]
      and prep["baseline_full_source_inputs_sha256"] == p["baseline_source_inputs_sha256"])
check("qualified R36 patch identity", prep["candidate_patch"]["sha256"] == "c693664d88e1bbed7e1257ad292d9d7b54eb3521db039cc1b8468f1e7b13caf1")
check("normal-only scope retained", p["saturated_cancellation_verified"] is False and prep["saturated_cancellation_verified"] is False)
check("original canary does not claim ABBA lifecycle performance", s["lifecycle"]["ABBA_performance_claim"] is False)

monitor = p["compiler_monitor"]
check("monitor receipts passed", monitor["passed"] is True and monitor["monitor_sources_unchanged"] is True)
check("monitor encompasses all seven stages", monitor["guarded_body_start_monotonic_ns"] <= stages[0]["start_monotonic_ns"]
      and monitor["guarded_body_end_monotonic_ns"] >= stages[-1]["end_monotonic_ns"])
policy = json.loads((CONTROL / "compiler-monitor-policy-01.json").read_bytes())
check("original monitor limits unchanged", monitor["limits"] == policy["limits"])
for label, record in monitor["sources"].items():
    check("local frozen monitor source identity " + label, same_identity(record, identity(CONTROL / Path(record["path"]).name)))
check("launcher transmitted-byte identity", p["launcher_sha256"] == identity(CONTROL / "r36_campaign.py")["sha256"])
check("quiescence recorded compiler-free", p["quiescence"]["passed"] is True
      and all(x["compiler_processes"] == [] for x in p["quiescence"]["checks"]))

check("analysis verification flag", n["verified"] is True, "existing analyzer assertion; raw report not downloaded")
check("six physical host topology reported", n["topology_verification"]["verified"] is True
      and n["topology_verification"]["alias_count"] == n["topology_verification"]["physical_machine_groups"] == 6)
allocator = n["allocator_environment_verification"]
check("same allocator environment reported", allocator["verified"] is True and allocator["controllers_with_live_environment"] == 8
      and allocator["configuration"]["same_allocator_environment"] is True)
check("arena one on both arms", all(allocator["configuration"]["variants"][a]["environment"] == {"MALLOC_ARENA_MAX": "1"} for a in BINARIES))
check("measured, warmup and restart counts", (n["measured_calls"], n["warmup_calls"], n["preflight_restart_calls"], n["total_calls"], n["failed_calls"])
      == (2304, 288, 72, 2664, 0))
check("call totals sum", n["measured_calls"] + n["warmup_calls"] + n["preflight_restart_calls"] == n["total_calls"])
check("warmup excluded", n["r16_measurement"]["warmup_included_in_performance_denominator"] is False)
check("same-controller synchronous CPU", n["r16_measurement"]["sampled_tree_cpu_used_for_performance"] is False)

check("concurrency matrix exactly C1 C8 C16", [x["concurrency"] for x in s["cases"]] == [1, 8, 16]
      and [x["concurrency"] for x in n["cases"]] == [1, 8, 16])
case_review = []
for reported, analyzed in zip(s["cases"], n["cases"]):
    c = reported["concurrency"]
    for arm in BINARIES:
        data = analyzed["arms"][arm]
        prefix = f"C{c} {arm} "
        check(prefix + "two equal measured rounds", data["calls"] == 384 and len(data["round_calls_per_second"]) == len(data["round_controller_cpu_ms_per_call"]) == 2)
        close(prefix + "pooled RPS", data["calls"] / data["seconds"], data["calls_per_second"])
        close(prefix + "CPU per call", 1000 * data["controller_cpu_seconds"] / data["calls"], data["controller_cpu_ms_per_call"])
        close(prefix + "sum round seconds", sum(192 / v for v in data["round_calls_per_second"]), data["seconds"])
        close(prefix + "sum round CPU", sum(192 * v / 1000 for v in data["round_controller_cpu_ms_per_call"]), data["controller_cpu_seconds"])
        close(prefix + "round spread", (max(data["round_calls_per_second"]) / min(data["round_calls_per_second"]) - 1) * 100,
              data["round_rate_max_min_spread_percent"])
        for metric, value in reported[arm].items():
            close(prefix + metric + " cross-report", value, data[metric])
    ratios = {key: reported["B"][key] / reported["A"][key] for key in reported["A"]}
    changes = {key: (value - 1) * 100 for key, value in ratios.items()}
    for metric in ratios:
        close(f"C{c} ratio {metric}", ratios[metric], reported["B_over_A"][metric])
        close(f"C{c} change {metric}", changes[metric], reported["change_percent"][metric])
        close(f"C{c} native change {metric}", changes[metric], analyzed["change_percent"][metric])
    result = {"throughput": ratios["calls_per_second"] >= gates["throughput_b_over_a_min"],
              "p95": ratios["p95_ms"] <= gates["p95_b_over_a_max"],
              "controller_cpu": ratios["controller_cpu_ms_per_call"] <= gates["controller_cpu_b_over_a_max"]}
    for key, passed in result.items():
        check(f"C{c} {key} gate consistency", passed == reported[key + "_regression_gate_passed"])
    check(f"C{c} combined gate", all(result.values()) == reported["regression_gate_passed"])
    paired = []
    for i, (ar, br) in enumerate([(0, 1), (3, 2)]):
        a, b = analyzed["arms"]["A"], analyzed["arms"]["B"]
        pair = {"baseline_round": ar, "candidate_round": br, "diagnostic_only": True,
                "rps_B_over_A": b["round_calls_per_second"][i] / a["round_calls_per_second"][i],
                "cpu_B_over_A": b["round_controller_cpu_ms_per_call"][i] / a["round_controller_cpu_ms_per_call"][i]}
        if c == 8:
            rp = s["C8_adjacent_pairs_diagnostic_only"][i]
            close("C8 paired RPS " + str(i), pair["rps_B_over_A"], rp["B_over_A"]["successful_rps"])
            close("C8 paired CPU " + str(i), pair["cpu_B_over_A"], rp["B_over_A"]["controller_cpu_ms_per_call"])
            pair["p95_B_over_A_reported_not_independently_recomputed"] = rp["B_over_A"]["p95_ms"]
        paired.append(pair)
    case_review.append({"concurrency": c, "arms": analyzed["arms"], "B_over_A": ratios, "change_percent": changes,
                        "gates_recomputed": result, "gate_headroom_ratio": {
                            "throughput_above_floor": ratios["calls_per_second"] - gates["throughput_b_over_a_min"],
                            "p95_below_ceiling": gates["p95_b_over_a_max"] - ratios["p95_ms"],
                            "cpu_below_ceiling": gates["controller_cpu_b_over_a_max"] - ratios["controller_cpu_ms_per_call"]},
                        "adjacent_pairs_diagnostic_only": paired})

rss_rows = []
for item in n["resources"]:
    obs = item["observations"]
    rss_rows.append({"arm": item["version"], "round": item["round"], "phase": item["phase"],
                     "available": obs["metric_samples"]["controller_rss_kib"] > 0,
                     "controller_fd_peak": obs["peaks"]["controller_fd"], "controller_hwm_kib": obs["peaks"]["controller_hwm_kib"],
                     "error_counts": obs["error_counts"], "rss_samples": obs["metric_samples"]["controller_rss_kib"],
                     "sampled_controller_rss_peak_kib": obs["peaks"]["controller_rss_kib"],
                     "sampled_tree_rss_peak_kib": obs["peaks"]["tree_rss_kib"], "sampler_error": obs["sampler_error"]})
check("all eight RSS records reproduced", rss_rows == s["controller_rss"]["rows"] and len(rss_rows) == 8)
check("RSS round/generation set", {(r["round"], r["arm"], r["phase"]) for r in rss_rows}
      == {(i, arm, phase) for i, arm in enumerate("ABBA") for phase in ("shutdown", "restart_shutdown")})
check("RSS availability", all(r["available"] and r["sampler_error"] is None for r in rss_rows))
peaks = {arm: max(r["sampled_controller_rss_peak_kib"] for r in rss_rows if r["arm"] == arm) for arm in BINARIES}
absolute = peaks["A"] + gates["controller_rss_extra_kib_max"]
proportional = peaks["A"] * gates["controller_rss_b_over_a_max"]
ceiling = min(absolute, proportional)
rss_passed = peaks["B"] <= ceiling
rss = {"A_peak_kib": peaks["A"], "B_peak_kib": peaks["B"], "B_over_A": peaks["B"] / peaks["A"],
       "extra_kib": peaks["B"] - peaks["A"], "candidate_ceiling_kib": ceiling}
for key, value in rss.items():
    close("RSS " + key, value, s["controller_rss"][key])
check("RSS gate recomputed", s["controller_rss"]["passed"] == rss_passed and s["controller_rss"]["available"] is True)
rss.update({"absolute_ceiling_kib": absolute, "proportional_ceiling_kib": proportional,
            "headroom_kib": ceiling - peaks["B"], "change_percent": (rss["B_over_A"] - 1) * 100,
            "rss_sample_count": sum(r["rss_samples"] for r in rss_rows), "rows": rss_rows,
            "passed": rss_passed, "measurement_scope": "sampled controller RSS peak, not cluster memory or allocation bound"})
all_perf_pass = all(all(c["gates_recomputed"].values()) for c in case_review) and rss_passed
check("combined performance gate", all_perf_pass == s["performance_gates_passed"])
check("original correctness and evidence flags", s["correctness_verified"] is True and s["evidence_verified"] is True,
      "original summary assertions; boundary/canary originals not downloaded")
check("observation combined gate", s["observation_gate_passed"] == (all_perf_pass and s["correctness_verified"] and s["evidence_verified"]))
check("boundary receipt totals", s["boundary"]["counts"] == {"capacity_rejection": 32, "other_error": 0, "success": 32})
check("canary receipt totals", all(s["lifecycle"][k] == v for k, v in {"new_starts": 6, "same_key_lookups": 12, "cancellations": 12}.items()))

review = {
    "schema": "hepta-r36-observation-independent-arithmetic-review/v1",
    "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    "review_passed": True, "formal_observation_performance_gates_recomputed_passed": all_perf_pass,
    "raw_evidence_reaudit_performed": False, "final_r36_adoption_decided": False,
    "method": {"pooled_rps": "sum measured calls / sum measured wall seconds",
               "cpu_per_call_ms": "1000 * sum same-controller CPU seconds / sum measured calls",
               "percentiles": "Cross-report values and ratios checked; raw latency order statistics not recomputed",
               "round_reconstruction": "192 measured calls per round; derive seconds and CPU from per-round rates",
               "numerical_consistency_tolerance": "math.isclose(rel_tol=1e-12, abs_tol=1e-9); strict original thresholds for gates",
               "new_gate_or_benchmark_rerun": False},
    "input_identities": identities, "review_script": identity(Path(__file__)),
    "frozen_summary_source": identity(summary_source), "frozen_thresholds": gates,
    "runtime_sha256": BINARIES, "cases": case_review, "controller_rss": rss,
    "calls": {k: n[k] for k in ("measured_calls", "warmup_calls", "preflight_restart_calls", "total_calls", "failed_calls")},
    "control_receipt_review": {"stages": stage_review, "source_inputs_sha256_reported": p["source_inputs_sha256"],
                               "baseline_source_inputs_sha256_reported": p["baseline_source_inputs_sha256"],
                               "qualification_tests_reported": prep["tests"], "qualified_source_files_reported": 220,
                               "monitor": monitor, "no_raw_monitor_reaudit": True,
                               "original_correctness_reported": {"boundary": s["boundary"], "canary": s["lifecycle"]}},
    "raw_evidence_references_not_locally_reviewed": {k: v for k, v in s["evidence"].items() if k != "native_analysis"},
    "decision": {
        "observation_nonregression": "passed all pre-existing gates",
        "observation_improvement": "No stable throughput or tail-latency improvement established by this finite ABBA",
        "c8": "Throughput -2.2104%, p95 +6.2838%, controller CPU/call -0.9358%; all within frozen gates",
        "resource_effect": "Pooled sampled peak RSS -168 KiB; small controller CPU reductions; descriptive only",
        "pair_warning": "C8 and C16 paired throughput directions disagree; C8 first-pair p95 >1.10 is diagnostic, not a gate",
        "c1_p99": "Observed +12.8746%; original protocol has no p99 gate",
        "remaining": "Normal lifecycle gate and any required final evidence/CI closure remain separate; async read supplement descriptive only",
        "saturated_cancellation_verified": False,
    },
    "limitations": [
        "Only three downloaded JSON receipts and unchanged local policy sources were reviewed. The 3,541,846-byte native report and its transport/resource trace files were not available in this review.",
        "No independent rehash/replay of wire frames, raw latency samples, synchronous CPU ticks, frozen job results, boundary/canary reports or compiler ledger was performed here; their original auditor verdicts and identities were checked for receipt consistency only.",
        "Source and binary immutability, native terminal, process absence, topology, and allocator settings are linked original report assertions, not fresh remote observations by this reviewer.",
        "Two rounds per arm do not establish statistical significance; no confidence interval or historic pooling is claimed.",
        "RSS is sampled controller memory, not total cluster memory. Resource traces retain missing/process-exit/permission observations; sampler_error=null does not mean every process metric was available.",
        "Percentile ratios are checked from reported percentiles. C8 paired p95 values are retained as reported because per-round percentile samples/denominators are not present in the downloaded analysis.",
    ],
    "checks": checks, "check_count": len(checks),
    "secondary_reviewer": {"agent": "/root/audit_perf_history/control_review", "reported_checks_passed": 167,
                           "scope": "Independent read-only aggregate/ratio/gate/RSS review of the same three receipts; no raw re-audit"},
}
(OUTPUT / "observation-review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
lines = ["# R36 Observation 独立算术复核", "",
         "**原冻结 observation 非退化门限全部通过；这组结果没有证明稳定的吞吐或尾延迟提升。**",
         "", "每臂每档 384 次 measured calls；ABBA 四轮，C1/C8/C16，六台物理主机。变化按 B/A−1 计算。", "",
         "| 并发 | calls/s A → B | 吞吐变化 | p95 A → B，ms | p95 变化 | CPU/call A → B，ms | CPU 变化 |", "|---|---:|---:|---:|---:|---:|---:|"]
for c in case_review:
    a, b, d = c["arms"]["A"], c["arms"]["B"], c["change_percent"]
    lines.append(f"| C{c['concurrency']} | {a['calls_per_second']:.6f} → {b['calls_per_second']:.6f} | {d['calls_per_second']:+.4f}% | {a['p95_ms']:.6f} → {b['p95_ms']:.6f} | {d['p95_ms']:+.4f}% | {a['controller_cpu_ms_per_call']:.6f} → {b['controller_cpu_ms_per_call']:.6f} | {d['controller_cpu_ms_per_call']:+.4f}% |")
lines += ["", "原门限分别为 throughput B/A ≥0.95、p95 B/A ≤1.10、CPU/call B/A ≤1.10。三个并发档分别判断，九项全部通过。C8 最接近门限：吞吐 ratio 0.977895625393，p95 ratio 1.062837705212；没有新增、放宽或替换门限。", "",
          "Controller RSS 的八条记录与 native analysis 一致：A 峰值 19,032 KiB，B 18,864 KiB，下降 168 KiB（0.8827%）；双门限为 min(19,032+512, 19,032×1.05)=19,544 KiB，余量 680 KiB。1,564 个有效 Controller RSS 样本支持这个采样峰值，原资源采样缺失／进程退出／权限记录仍保留；它不是集群内存或精确分配上限。", "",
          "## 效果解释", "",
          "C1 吞吐下降约0.88%，C8下降约2.21%，C16增加约0.44%；CPU/call三个档分别下降约0.41%、0.94%、1.53%。这些都是有限样本的描述性结果。C8相邻两对吞吐变化为−4.867%和+0.536%，C16为−1.453%和+2.351%，方向不一致。RSS第一对增加96 KiB，第二对下降168 KiB，也不能称每轮内存都下降。", "",
          "C1 p99增加12.8746%（206.755035→233.373984 ms），原协议没有p99门限。C8第一对报告p95 ratio为1.107028371042、第二对1.019801729919；配对值只作诊断，第一对超过1.10不能替代预先冻结的pooled p95 gate。本次没有各轮p95原始分母，未独立复算这两个配对p95值。", "",
          "## 复核边界", "",
          f"本次 {len(checks)} 项检查全部通过，另一个只读 reviewer 完成167项独立汇总检查。已按 calls/seconds 和 CPU seconds/calls 重算吞吐、CPU/call，重建每轮总量，核对全部比值、门限、RSS记录、七阶段输出SHA绑定及退出／所有权闭合回执。候选 runtime SHA 为 `{BINARIES['B']}`。220文件资格映射、1645 passed / 34 ignored / 0 failed / 0 retry、编译监测和输入未变均与原父报告的绑定／标记一致。", "",
          "**没有下载并重审3,541,846字节的 native 原报告，也未复算逐条 wire frame、原始 latency 分位数或 CPU ticks。** 原边界／canary报告、compiler ledger及原trace也未在本次重审；其hash和原审计通过状态只作回执一致性核对。所有文件SHA及完整检查列表见同目录 `observation-review.json`，复算方法见 `review_observation.py`。", "",
          "本结论只完成原 observation 关卡。R36整体采纳仍须独立normal lifecycle关卡及最终证据／CI闭合；异步read追加实验为描述性证据，不改变原采纳门限，也不代表job compute吞吐或最大并发容量。饱和取消能力未验证。", "",
          "## 本次三个原件", "", "| 文件 | 字节 | SHA256 |", "|---|---:|---|"]
for name, ident in identities.items():
    lines.append(f"| {name} | {ident['bytes']} | `{ident['sha256']}` |")
lines += ["", f"生成时间：{review['created_utc']}。本复核仅写入新的独立review目录，没有修改冻结runner、gate、source或远端状态。", ""]
(OUTPUT / "observation-review.md").write_text("\n".join(lines))
print(json.dumps({"review_passed": True, "checks": len(checks), "outputs": [identity(OUTPUT / "observation-review.json"), identity(OUTPUT / "observation-review.md")]}))
