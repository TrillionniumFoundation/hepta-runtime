#!/usr/bin/env python3
"""Local arithmetic over the already returned DERIVED D2 cost projection only."""
import hashlib
import json
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path

SOURCE = Path("/tmp/hepta-d2-cost-projection-02/cost-projection.json")
OUT = Path("/tmp/hepta-runtime-recovery-20261106/d2-c1-cost-analysis-02")
EXPECTED_BYTES = 296868
EXPECTED_SHA256 = "d1243423b5fe119653b3185627d8a6a638c6a0f2c946880a7ded05db178ed479"
EXPECTED_GIT = "e633612cc65afcd24907382676776938dc10a985"
CHILDREN = ("file_checked", "file_read_reference", "file_read_hash",
            "file_final_check", "file_identity", "shell_resolution", "profile_policy")
PARENTS = ("validation_worker", "validation_owner")


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def decimal(numerator, denominator=1):
    with localcontext() as context:
        context.prec = 50
        return format(Decimal(numerator) / Decimal(denominator), ".12f")


def sum_ns(summary, phase, kind):
    distribution = summary["phases"][phase][kind + "_cpu_per_request_ns"]
    assert distribution["count"] == summary["requests"]
    value = distribution["sum_ns"]
    assert type(value) is int
    return value


def metric(ns, requests, controller_ns):
    assert type(ns) is int and type(controller_ns) is int
    return {"cpu_sum_ns": ns, "requests": requests,
            "mean_ms_per_request": decimal(ns, requests * 1000000),
            "percent_of_controller_cpu": decimal(ns * 100, controller_ns)}


def derive(summary, controller_ns):
    n = summary["requests"]
    parents = {p: {"inclusive": metric(sum_ns(summary,p,"inclusive"), n, controller_ns),
                   "exclusive": metric(sum_ns(summary,p,"exclusive"), n, controller_ns),
                   "cpu_event_count": summary["phases"][p]["cpu_event_count"]} for p in PARENTS}
    children = {p: {**metric(sum_ns(summary,p,"exclusive"), n, controller_ns),
                    "cpu_event_count": summary["phases"][p]["cpu_event_count"],
                    "cpu_events_per_request": decimal(summary["phases"][p]["cpu_event_count"], n)}
                for p in CHILDREN}
    whole = sum(sum_ns(summary,p,"inclusive") for p in PARENTS)
    remainder = sum(sum_ns(summary,p,"exclusive") for p in PARENTS)
    child = sum(sum_ns(summary,p,"exclusive") for p in CHILDREN)
    recorded = summary["recorded_synchronous_cpu_exclusive_ns"]
    all_exclusive = sum(p["exclusive_cpu_per_request_ns"]["sum_ns"] for p in summary["phases"].values())
    assert all_exclusive == recorded
    assert whole == child + remainder
    residual = controller_ns - recorded
    return {
        "requests": n, "controller_cpu": metric(controller_ns,n,controller_ns),
        "recorded_sync_exclusive": metric(recorded,n,controller_ns),
        "whole_validation_inclusive": metric(whole,n,controller_ns),
        "parents": parents, "children_exclusive": children,
        "seven_children_exclusive_total": metric(child,n,controller_ns),
        "parent_exclusive_remainder": metric(remainder,n,controller_ns),
        "other_recorded_synchronous_exclusive": metric(recorded-whole,n,controller_ns),
        "signed_controller_minus_recorded_sync": metric(residual,n,controller_ns),
        "decomposition_integer_identity": {
            "validation_whole_ns": whole, "children_exclusive_ns": child,
            "parent_exclusive_ns": remainder, "difference_ns": whole-child-remainder},
        "r36_direct_cpu_budget_counterfactual": {
            "budget": "entire measured worker+owner exclusive remainder; actual R36 addresses only a subset",
            "entire_parent_remainder_ms_per_request": decimal(remainder,n*1000000),
            "entire_parent_remainder_percent_of_controller_cpu": decimal(remainder*100,controller_ns),
            "entire_parent_remainder_percent_of_whole_validation": decimal(remainder*100,whole),
            "cpu_only_service_rate_factor_if_entire_remainder_vanished_and_all_else_unchanged":
                decimal(controller_ns,controller_ns-remainder),
            "measured_r36_gain": None, "production_throughput_prediction": None,
            "scope_limitation": "Includes other original work and diagnostic bookkeeping. It is an optimistic direct-cost allocation, not an unconditional physical limit or a measured R36 saving."
        }
    }


raw = SOURCE.read_bytes()
pin = identity(raw)
assert pin == {"bytes":EXPECTED_BYTES,"sha256":EXPECTED_SHA256,"git_blob_sha1":EXPECTED_GIT}
projection = json.loads(raw)
assert projection["schema"] == "hepta-d2-c1-cost-projection/v1"
a = projection["adapter"]
selected = [(i,t) for i,t in enumerate(a["traces"])
            if t["binding"]["mode"]=="on" and t["binding"]["phase"]=="first"]
rounds = []
for index,t in selected:
    s=t["category_phase_summaries"]["measured"]
    counter=t["measured_controller_cpu_comparison"]
    assert s["requests"] == counter["calls"]
    ns=Fraction(counter["controller_cpu_ticks_delta"]*1000000000,counter["clock_ticks_per_second"])
    assert ns.denominator==1 and ns==counter["controller_cpu_ns"]
    assert s["recorded_synchronous_cpu_exclusive_ns"] == counter["recorded_synchronous_cpu_exclusive_ns"]
    assert ns-s["recorded_synchronous_cpu_exclusive_ns"] == counter["signed_controller_minus_recorded_sync_ns"]
    rounds.append({"round":t["binding"]["round"],"source_trace_index":index,
        "source_measured_summary_path":f"$.adapter.traces[{index}].category_phase_summaries.measured",
        "source_counter_path":f"$.adapter.traces[{index}].measured_controller_cpu_comparison",
        "controller_cpu_ticks_delta":counter["controller_cpu_ticks_delta"],
        "clock_ticks_per_second":counter["clock_ticks_per_second"],
        "counter_tick_resolution_ns":counter["cpu_clock_tick_resolution_ns"],
        "costs":derive(s,int(ns))})
combined_summary=a["measured_phase_summary"]
assert sum(r["costs"]["requests"] for r in rounds)==combined_summary["requests"]
for p in combined_summary["phases"]:
    for kind in ("inclusive","exclusive"):
        assert sum(sum_ns(t["category_phase_summaries"]["measured"],p,kind)
                   for _,t in selected)==sum_ns(combined_summary,p,kind)
controller_total=sum(r["costs"]["controller_cpu"]["cpu_sum_ns"] for r in rounds)
combined=derive(combined_summary,controller_total)
result={
 "schema":"hepta-d2-c1-derived-cost-calculation/v1",
 "classification":"DERIVED local arithmetic from an exact, returned projection; not a new audit or acceptance gate",
 "projection_source":pin,
 "projection_source_local_path":str(SOURCE),
 "original_adapter_source":projection["source"],
 "calculation_source":identity(Path(__file__).read_bytes()),
 "scope":{
   "selected_original_categories":["ON first controller: measured"],
   "warmup_preflight_restart_excluded_from_cost_denominator":True,
   "whole_validation":"validation_worker inclusive + validation_owner inclusive",
   "seven_children":"exclusive only",
   "means":"integer nanosecond sums / actual request count / 1000000",
   "controller_percent":"integer CPU sum / controller utime+stime tick delta *100",
   "combined":"sum original per-round numerators and denominators; not an unweighted percentage average",
   "decimal_rendering":"12 decimal places; exact integer sums and denominators retained",
   "wall_spans_added":False,"phase_quantiles_added":False,
   "signed_residual_clamped":False,"off_trace_zero_cpu_claim":False,
   "raw_trace_reparsed":False,"original_parser_executed":False,"original_auditor_executed":False,
   "host_calls":0,"workload_rerun":False,"r36_executed_here":False,
   "on_off_is_production_optimization_claim":False},
 "copied_original_adapter_flags":{k:a[k] for k in
   ("analysis_complete","errors","original_returncode","controller_close_evidence_complete",
    "strict_on_request_bijection_count","measured_on_request_count","validation_whole_cost_field")},
 "observed_trace_counts":[{"index":i,"round":t["binding"]["round"],"mode":t["binding"]["mode"],
     "phase":t["binding"]["phase"],"counts":t["trace_summary"]["counts"],
     "selected_on_counts":t["selected_on_counts"]} for i,t in enumerate(a["traces"])],
 "rounds":rounds,"combined":combined,
 "r36_frozen_sources":{
   "profile":{"git_blob":"a68cdc86cd3eed479d21028cdb4a13157376b4f7","bytes":25779,
              "sha256":"eb7d677f2ca713d4719668202d7808925785f259aa15d6494ae8ec30fed17a3a"},
   "candidate_patch":{"git_blob":"273f9f72dd2e8da9d26cad55403cc09694bc96c3","bytes":6384,
              "sha256":"fc0d76fda9d8fb921443f6031a80a1bff3dd765284fc54bd08055c613abb04d0"},
   "interpretation":"Per-synchronous-sweep lazy16KiB scratch reuse and unused SHA Context avoidance lie inside parent exclusive. Original read loops, file checks, identity, shell resolution and policy remain."},
 "performance_acceptance_claim":False
}
OUT.mkdir(parents=True,exist_ok=True,mode=0o700)
encoded=(json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
with (OUT/"cost-calculation.json").open("xb") as f:f.write(encoded)
print(json.dumps({"result_identity":identity(encoded),"rounds":rounds,"combined":combined},sort_keys=True))
