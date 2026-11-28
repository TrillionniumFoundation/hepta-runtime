#!/usr/bin/env python3
"""Create a zero-model format projection for the unchanged original parity checker.

Only container keys are renamed. Every native phase observation is copied
unchanged. The complete raw MCP receipt SHA is retained in the projection.
"""
import argparse
from pathlib import Path
import transport_reference as t
MAIN_SHA="9763f0c078a46c7367703bb7d072003fe2136cf6e5f59656f7733e6f90ac40e9"
SOURCE_SHA="16dbc208a21e4aca99dd576fb731a877598219dd"
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--actual",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    raw=t.read(a.actual,4*1024**2,private=True);v=t.parse(raw)
    t.require(v["schema"]=="hepta.late-quote.http-relocated-qualification.v1.result" and v["status"]=="PASS","actual relocated result must PASS")
    t.require(v["reconstructed_driver_sha256"]==MAIN_SHA and v["identity"]["source_commit"]==SOURCE_SHA,"actual MCP identity differs")
    t.require(v["training_steps"]==0 and v["optimizer_steps"]==0 and v["forward_source_control_flow_upper_bound"]==29,"actual model-work scope differs")
    t.require(set(v["receipts"])=={"47","83","137","crash137"},"exact actual cases required")
    x={"schema":"hepta.late-quote.parity-format-projection.v1","status":v["status"],
      "engineering_replay_of_already_observed_batches":True,
      "cases":[{"initial":v["receipts"][seed]["roundtrip"]} for seed in ("47","83","137")],
      "crash_recovery":v["receipts"]["crash137"]["first_recovery"],
      "complete_forward_results_observed":v["complete_forward_results_observed"],
      "ci_identity":v["identity"],
      "format_only_adapter":{"raw_mcp_result":str(a.actual.resolve(strict=True)),"raw_mcp_result_sha256":t.digest(raw),
        "source_driver_sha256":MAIN_SHA,"adapter_sha256":t.digest(t.read(Path(__file__).resolve())),
        "native_phase_observations_modified":False,"model_forward_calls":0,"optimizer_steps":0}}
    pin=t.write_once(a.output,x)
    print(t.json.dumps({"projection":str(a.output),"sha256":pin,"raw_result_sha256":t.digest(raw),"model_forward_calls":0}))
if __name__=="__main__":main()

