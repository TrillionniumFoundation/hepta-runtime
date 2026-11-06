#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Recompute frozen normal-operation nonregression gates from a closed ABBA."""
import argparse
import json
import math
from pathlib import Path

import summarize_lifecycle_abba_01 as original

need = original.need
PHASES = ("launch", "same_key_after_crash", "concurrent_cancel", "same_key_after_cancel", "cancel_after_terminal")
GATED = ("all_operations", "launch", "concurrent_cancel")


def p95(values):
    need(values and all(math.isfinite(value) and value >= 0 for value in values), "invalid native latencies")
    return sorted(values)[math.ceil(len(values) * .95) - 1]


def group(cells, phases):
    selected = [cell for cell in cells if cell["phase"] in phases]
    latencies = [value for cell in selected for value in cell["latencies_ms"]]
    seconds = sum(cell["rpc_span_seconds"] for cell in selected)
    need(seconds > 0 and len(latencies) == 6 * len(selected), "incomplete C6 native operation group")
    return {"calls":len(latencies), "phase_windows":len(selected), "rpc_span_seconds":seconds,
            "rpc_per_second":len(latencies) / seconds, "rpc_p95_ms":p95(latencies),
            "controller_cpu_seconds":sum(cell["controller_cpu_seconds"] for cell in selected),
            "controller_and_waited_child_cpu_seconds":sum(cell["controller_and_waited_child_cpu_seconds"] for cell in selected),
            "quantization_tolerance_seconds":sum(1 / cell["clock_ticks_per_second"] for cell in selected)}


def analyze(index_path):
    index_path = Path(index_path).absolute()
    policy_path = Path(__file__).with_name("lifecycle-gate-policy.json")
    policy_raw = original.read(policy_path)
    policy = json.loads(policy_raw)
    need(policy["schema"] == "hepta-r25-lifecycle-gate-policy/v1"
         and policy["measured_operation_phases"] == list(PHASES) and policy["gated_groups"] == list(GATED)
         and policy["cpu_counter_tolerance_ticks_per_phase_per_round"] == 1,
         "frozen lifecycle gate policy differs")
    descriptive = original.summarize(index_path)
    index = json.loads(original.read(index_path))
    arms = {"A":{"cells":[],"rss_kib":[]}, "B":{"cells":[],"rss_kib":[]}}
    for number, arm in enumerate("ABBA"):
        row = index["rounds"][number]
        directory = index_path.parent / row["directory"]
        raw = original.bound(directory / "report.json", row["report"])
        report = json.loads(raw)
        phase_bindings = {Path(item["path"]).name:item for item in row["phase_files"]}
        for phase in PHASES:
            calls = [call for call in report["native_calls"] if call["phase"] == phase]
            need(len(calls) == 6 and {call["host"] for call in calls} == original.HOSTS
                 and all(call["okay"] is True and call["automatic_retry"] is False for call in calls),
                 "operation phase did not complete exactly once per host")
            expected = "process_cancel" if phase in {"concurrent_cancel", "cancel_after_terminal"} else "process_start"
            need(all(call["tool"] == expected for call in calls), "unexpected tool in operation phase")
            spans = [(call["rpc"]["rpc_start_monotonic_ns"],call["rpc"]["rpc_end_monotonic_ns"]) for call in calls]
            need(all(0 < begin < end for begin,end in spans), "invalid RPC clock interval")
            filename = "phase-" + phase + ".json"
            measured = json.loads(original.bound(directory / filename, phase_bindings[filename]))
            metrics = original.phase_metrics(measured, report, phase)
            before, after = measured["counter_before"], measured["counter_after"]
            def full_cpu(counter):
                raw = counter["raw_stat"]
                fields = raw[raw.rfind(") ") + 2:].split()
                return sum(int(fields[index]) for index in (11,12,13,14))
            total_delta = full_cpu(after) - full_cpu(before)
            hertz = before["clock_ticks_per_second"]
            need(total_delta >= 0 and hertz == after["clock_ticks_per_second"] and hertz > 0,
                 "invalid complete-phase controller/reaped-child CPU delta")
            arms[arm]["cells"].append({"round":number,"phase":phase,"calls":6,
                "rpc_span_seconds":(max(end for _,end in spans)-min(begin for begin,_ in spans))/1e9,
                "latencies_ms":[(end-begin)/1e6 for begin,end in spans],
                "controller_cpu_seconds":metrics["controller_cpu_seconds"],
                "controller_and_waited_child_cpu_seconds":total_delta/hertz,
                "clock_ticks_per_second":hertz})
        for stage in ("intentional_crash", "after_cancel_shutdown", "shutdown"):
            resources = report[stage]["resources"]
            need(resources["sampler_error"] is None and resources["metric_samples"].get("controller_rss_kib", 0) > 0,
                 "controller RSS sample unavailable")
            arms[arm]["rss_kib"].append(resources["peaks"]["controller_rss_kib"])
    comparisons, accepted = {}, True
    for name in ("all_operations", *PHASES):
        phases = PHASES if name == "all_operations" else (name,)
        a, b = (group(arms[arm]["cells"], phases) for arm in "AB")
        need(a["calls"] == b["calls"], "operation group call count differs")
        ratio_rps, ratio_p95 = b["rpc_per_second"]/a["rpc_per_second"], b["rpc_p95_ms"]/a["rpc_p95_ms"]
        cpu_limit = a["controller_cpu_seconds"] + b["quantization_tolerance_seconds"]
        gates = {"throughput":ratio_rps >= policy["throughput_minimum_b_over_a"],
                 "rpc_p95":ratio_p95 <= policy["rpc_p95_maximum_b_over_a"],
                 "controller_cpu_with_declared_tick_tolerance":b["controller_cpu_seconds"] <= cpu_limit + 1e-12}
        required = name in GATED
        if required:
            accepted = accepted and all(gates.values())
        comparisons[name] = {"A":a,"B":b,"B_over_A_rpc_per_second":ratio_rps,
                             "B_over_A_rpc_p95":ratio_p95,"controller_cpu_limit_seconds":cpu_limit,
                             "gates":gates,"adoption_required":required}
    rss_a, rss_b = (max(arms[arm]["rss_kib"]) for arm in "AB")
    rss_limit = min(rss_a + policy["rss_maximum_extra_kib"], rss_a * policy["rss_maximum_ratio"])
    rss = {"A_sampled_peak_kib":rss_a,"B_sampled_peak_kib":rss_b,"limit_kib":rss_limit,"passed":rss_b <= rss_limit}
    accepted = accepted and rss["passed"]
    return {"schema":"hepta-r25-lifecycle-gates/v1","verified":True,"passed":accepted,
            "order":"ABBA","round_count":4,"total_new_jobs":24,"automatic_retries":0,
            "round_index":original.fingerprint(index_path),"gate_policy":original.fingerprint(policy_path),
            "normal_lifecycle_descriptive_verified":descriptive["verified"],
            "comparisons":comparisons,"rss":rss,"arms":arms,
            "scope":policy["sample_scope"],
            "cpu_scope":"Controller CPU plus separately reported raw cutime+cstime for reaped local children; no remote-host or cluster CPU claim."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    result = analyze(args.index)
    original.create(args.output.absolute(), original.canonical(result))
    print(json.dumps({"verified":result["verified"],"passed":result["passed"],"output":str(args.output)}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
