"""Run the actual registered commitment suite and original recipe in isolation.

This focused gate retains component scope. The complete runtime aggregate also
requires the separate matching-source Hepta cold qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import traceback

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import hia_native_bellman_commitment_qualification as commitment
import qualify_hia_runtime_native as aggregate
from hia_native_build import NativeBuild

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta",type=Path,required=True)
    parser.add_argument("--original",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--rustup",default="rustup")
    parser.add_argument("--bootstrap-from",type=Path)
    a=parser.parse_args();output=a.output.resolve();output.mkdir()
    report={"schema":"hepta.runtime.bellman-commitment-focused-gate.v1","status":"RUNNING",
            "phase":"native_components","modules":{},"checks":[],
            "full_runtime_aggregate_completed":False,"compiler_full_cold_replayed":False,**commitment.SCOPE}
    try:
        source=commitment.source_evidence()
        for name in commitment.TARGET_PINS:
            if (a.original/name).read_bytes()!=(ROOT/commitment.REFERENCE/Path(name).name).read_bytes():
                raise ValueError("independent original source differs: "+name)
        report["independent_original_checked"]=True
        report["source_evidence"]=source
        build=output/"build"
        if a.bootstrap_from:
            (build/"bootstrap").mkdir(parents=True)
            for name in ("B1.image.bin","B2.image.bin","B3.image.bin","bootstrap.json"):
                shutil.copyfile(a.bootstrap_from/name,build/"bootstrap"/name)
        builder=NativeBuild(a.hepta.resolve(),build)
        item=commitment.MODULE
        manifest=builder.compile(item["name"],ROOT/item["source"],standalone=item["standalone"],
                                 buffer_profile=item["buffer_profile"])
        report["modules"][item["key"]]={"manifest":str(manifest.relative_to(output)),
            "sha256":commitment.digest(manifest.read_bytes()),"source":item["source"],"builder":"borrowed_bytes"}
        env=aggregate.qualification_env()
        env.update(HIA_HEPTA_DIR=str(a.hepta.resolve()),HIA_BELLMAN_COMMITMENT_QUALIFICATION_OUTPUT=str(output))
        env[item["manifest_env"]]=str(manifest)
        aggregate.record_check(output,report,name=commitment.TEST,
            command=[sys.executable,"-I","-B",str(ROOT/"tests/hia_native"/commitment.TEST)],timeout=180,env=env)
        report["bellman_commitment_evidence"]=commitment.native_evidence(output,report)
        report["phase"]="original_rust_comparison"
        selected=aggregate.record_check(output,report,name="bellman-commitment-selected-rustc",
            command=[a.rustup,"which","--toolchain","1.95.0","rustc"],timeout=15)
        rustc=Path(selected.stdout.decode().strip())
        if not rustc.is_absolute() or not rustc.is_file(): raise ValueError("selected original compiler is missing")
        result=commitment.compare_original(output,report,rustc)
        report["original_rust_comparisons"]={item["key"]:result}
        commitment.exact(result,commitment.original_evidence(output,report,rustc),"completed commitment reference differs")
        commitment.exact(source,commitment.source_evidence(),"commitment source changed during qualification")
        builder._recheck()
        report.update(status="PRIVATE_TYPED_COMMITMENT_PASS",phase="complete")
    except BaseException as error:
        report.update(status="FAIL",failure={"type":type(error).__name__,"message":str(error)})
        (output/"failure.txt").write_text(traceback.format_exc())
    finally:
        aggregate.save_report(output/"result.json",report)
    print(json.dumps({"status":report["status"],"phase":report["phase"],"report":str(output/"result.json"),
                      "report_sha256":hashlib.sha256((output/"result.json").read_bytes()).hexdigest(),
                      "actual_recorded_processes":len(report["checks"]),"failure":report.get("failure")}))
    return 0 if report["status"]=="PRIVATE_TYPED_COMMITMENT_PASS" else 1

if __name__=="__main__":
    raise SystemExit(main())
