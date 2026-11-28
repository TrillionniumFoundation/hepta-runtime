#!/usr/bin/env python3
"""Zero-forward container projection of the explicitly composite qualification.

The original failed main receipt remains failed. Its three complete native
cases must be identical in the composite. All native phase values are copied
unchanged for the original byte-pinned CLI parity checker.
"""
import argparse
from pathlib import Path
import transport_reference as t

CONTINUATION_SHA = "a2212ee79bff7f4ea611ac9984f700dd3afc1868b51d73eff6690272b9fdb9bc"
MAIN_SHA = "9763f0c078a46c7367703bb7d072003fe2136cf6e5f59656f7733e6f90ac40e9"
FAILURE_SHA = "4cbf5fc0c624f944c53caf2cf12ffd0398d20f6df4e046f210d1b81404ca7713"
PLAN_SHA = "3e145469d1da17d9f92a2d95183d8a1119a12719de2eb1d5a22ee9d38fb65fc8"
RESPONSE_SHA = "b6549b634395e5c5bdf085d8b4cb7f9b464920665268081ff36d4914a87c0bc0"
SOURCE_SHA = "16dbc208a21e4aca99dd576fb731a877598219dd"
COUNTS = {"server_starts":4,"rpc_wire_calls":35,"tool_calls":27,
          "roundtrip_wire_calls":10,"roundtrip_new_intents":4,"recover_wire_calls":6,"crash_attempts":1}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--actual", type=Path, required=True)
    p.add_argument("--original-failure", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    raw = t.read(a.actual, 4*1024**2, private=True)
    v = t.parse(raw)
    original = t.read(a.original_failure, 4*1024**2, private=True)
    old = t.parse(original)
    t.require(t.digest(original) == FAILURE_SHA and old["status"] == "FAIL_OR_INCOMPLETE",
              "original failure receipt changed or was relabeled")
    t.require(v["schema"] == "hepta.late-quote.http-continuation-qualification.v1.result"
              and v["status"] == "PASS" and v["counts"] == COUNTS, "composite actual qualification incomplete")
    t.require(t.digest(t.read(Path(__file__).with_name("late_quote_mcp_continuation.py").resolve()))
              == CONTINUATION_SHA == v["continuation_driver_sha256"]
              and v["original_main_driver_sha256"] == MAIN_SHA
              and v["original_failed_main_result_sha256"] == FAILURE_SHA
              and v["original_main_plan_sha256"] == PLAN_SHA
              and v["original_refusal_response_sha256"] == RESPONSE_SHA,
              "composite execution or historical identity differs")
    t.require(v["identity"] == old["identity"] and v["identity"]["source_commit"] == SOURCE_SHA,
              "native executable identity differs")
    t.require(v["training_steps"] == v["optimizer_steps"] == 0
              and v["forward_source_control_flow_upper_bound"] == 29
              and v["pure_compiler_source_control_flow_upper_bound"] == 8
              and v["original_failure_preserved"] is True
              and v["original_negative_effect_snapshot_available"] is False
              and v["new_schema_refusal_verified"] is True, "composite scope differs")
    t.require(set(v["receipts"]) == {"47","83","137","crash137"}, "all four actual cases required")
    for seed in ("47","83","137"):
        t.require(v["receipts"][seed] == old["receipts"][seed], "an original native case was altered")
    x = {"schema":"hepta.late-quote.composite-parity-format-projection.v1", "status":"PASS",
         "qualification_is_composite_continuation":True,"original_main_attempt_passed":False,
         "engineering_replay_of_already_observed_batches":True,
         "cases":[{"initial":v["receipts"][seed]["roundtrip"]} for seed in ("47","83","137")],
         "crash_recovery":v["receipts"]["crash137"]["first_recovery"],
         "complete_forward_results_observed":v["complete_forward_results_observed"],
         "ci_identity":v["identity"],
         "format_only_adapter":{"raw_composite_result":str(a.actual.resolve(strict=True)),
             "raw_composite_result_sha256":t.digest(raw),"original_failed_result_sha256":FAILURE_SHA,
             "source_continuation_driver_sha256":CONTINUATION_SHA,
             "adapter_sha256":t.digest(t.read(Path(__file__).resolve())),
             "native_phase_observations_modified":False,"model_forward_calls":0,"optimizer_steps":0}}
    sha = t.write_once(a.output, x)
    print(t.json.dumps({"projection":str(a.output),"sha256":sha,"raw_result_sha256":t.digest(raw),"model_forwards":0}))


if __name__ == "__main__":
    main()
