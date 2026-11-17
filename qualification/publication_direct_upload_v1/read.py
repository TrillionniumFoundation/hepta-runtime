#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Independently reread the uploaded eight-case proof and every retained input."""
from pathlib import Path
import argparse,json,shutil,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser()
    for name in ("source","prepared","build-recipe","direct-recipe","public-reader","retained","output","proof"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.source))
    from common import canonical,decode,pin,require,source_evidence
    import read_all,readonly
    own=source_evidence(HERE);source=source_evidence(a.source)
    inputs=decode((HERE/"INPUTS.json").read_bytes())
    require(pin(a.source/"SOURCE_MANIFEST.json")==inputs["reader_manifest"],"whole exact Direct8 reader")
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    uploaded,archive=restore(a.proof,inputs["uploaded_proof"])
    def files(root):
        return {path.relative_to(root).as_posix():pin(path) for path in root.rglob("*") if path.is_file()}
    require(files(uploaded/"recipe-source")==files(a.source),"complete uploaded reader source unchanged")
    before=decode((uploaded/"capture/SUMMARY.json").read_bytes())
    require(before["status"]=="COMPLETE_EIGHT_DIRECT_FUTURES_JOIN_PASS"
        and [row["case"] for row in before["cases"]]==list(range(22,30))
        and before["production"]==inputs["production"]
        and before["source_binding"]==inputs["production_binding"]
        and before["native_replayed"] is before["original_replayed"] is False
        and before["physical_controls_pending"] is True,"original whole uploaded scope")
    sys.argv=[read_all.__file__,"--prepared",str(a.prepared),"--build-recipe",str(a.build_recipe),
        "--direct-recipe",str(a.direct_recipe),"--public-reader",str(a.public_reader),
        "--retained",str(a.retained),"--output",str(a.output)]
    read_all.main()
    def compare():
        after=decode((a.output/"SUMMARY.json").read_bytes())
        for key in ("status","source","production","source_binding","original_replayed","native_replayed",
                    "physical_controls_pending","full_sdk"):
            require(before[key]==after[key],"complete immutable result field "+key)
        require([r["role"] for r in before["roles"]]==[r["role"] for r in after["roles"]]==inputs["roles"],
            "all six unchanged retained archive roles")
        cases=[]
        for old_role,new_role in zip(before["roles"],after["roles"],strict=True):
            role=old_role["role"]
            require(old_role["exit_code"]==new_role["exit_code"]==0
                and old_role["applications_executed"]==new_role["applications_executed"]==0
                and old_role["per_case_limit_seconds"]==new_role["per_case_limit_seconds"]==180
                and old_role["no_outer_repeated_timeout"] is new_role["no_outer_repeated_timeout"] is True,
                "actual complete pure reader role")
            require(old_role["summary"]==pin(uploaded/"capture"/role/"SUMMARY.json")
                and new_role["summary"]==pin(a.output/role/"SUMMARY.json"),"whole role summary pins")
            for old,new in zip(old_role["cases"],new_role["cases"],strict=True):
                for key in ("case","name","status","guards","worker_jobs","worker_frames","worker_bytes","host_bytes","semantic_replay"):
                    require(old[key]==new[key],"unchanged complete case field "+key)
                require(old["guards"]==11 and old["semantic_replay"] is False,"original complete reader guards")
                name="READ-%03d.json"%old["case"];left=uploaded/"capture"/role/name;right=a.output/role/name
                require(pin(left)==old["proof"] and pin(right)==new["proof"],"complete old/new proof pins")
                first=decode(left.read_bytes());second=decode(right.read_bytes())
                for value in (first,second):
                    require(value["status"]=="READONLY_PASS" and value["before"]==value["after"]
                        and value["entries"]==len(value["before"]) and len(value["probes"])==11
                        and all(r["rejected"] is True for r in value["probes"])
                        and value["native_executed"] is value["rust_executed"] is value["evidence_written"] is False,
                        "complete original guard byte and metadata custody")
                require(first["evidence"]==second["evidence"],
                    "full independent direct command/files/state/host/worker/Drop evidence equality")
                cases.append({"case":old["case"],"name":old["name"],"old_proof":pin(left),
                    "new_proof":pin(right),"complete_evidence_equal":True})
        require(sorted(row["case"] for row in cases)==list(range(22,30)),"all eight exactly once")
        return {"status":"COMPLETE_UPLOADED_DIRECT_EIGHT_INDEPENDENT_JOIN_PASS","cases":cases,
            "uploaded_archive":archive,"application_executions":0,"original_replayed":False,
            "native_replayed":False,"physical_controls_pending":True,"full_sdk":False}
    proof=readonly.guarded(compare,roots=[HERE,a.source,uploaded,a.output])
    (a.output/"UPLOADED_READ.json").write_bytes(canonical(proof))
    saved=a.output/"uploaded-archive";saved.mkdir()
    for name in ("READ.json","ARCHIVE.json","FILES.json"):
        shutil.copyfile(a.proof/name,saved/name)
    summary={"status":proof["evidence"]["status"],"cases":len(proof["evidence"]["cases"]),
        "guards":len(proof["probes"]),"entries":proof["entries"],"proof":pin(a.output/"UPLOADED_READ.json"),
        "source":own,"reader":source,"application_executions":0,"physical_controls_pending":True,"full_sdk":False}
    (a.output/"INDEPENDENT_SUMMARY.json").write_bytes(canonical(summary))
    print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
