#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Full uploaded proofs, original native archives, and independent semantic reads."""
from pathlib import Path
import argparse,hashlib,json,shutil,sys
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser()
    for n in ("source","build-recipe","prepared","retained","output","proof"):p.add_argument("--"+n,type=Path,required=True)
    p.add_argument("--role",choices=("legacy-a","legacy-b","modern-a","modern-b"),required=True)
    a=p.parse_args();sys.path.insert(0,str(a.source))
    from common import require,pin,canonical,decode,source_evidence
    import recover_read,readonly
    own=source_evidence(HERE);source=source_evidence(a.source)
    inputs=decode((HERE/"INPUTS.json").read_bytes())
    require(pin(a.source/"SOURCE_MANIFEST.json")=={k:inputs["reader_manifest"][k] for k in ("bytes","sha256")},"exact complete qualified reader")
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    uploaded,archive=restore(a.proof,inputs["proofs"][a.role])
    def files(root):return {x.relative_to(root).as_posix():pin(x) for x in root.rglob("*") if x.is_file()}
    require(files(uploaded/"recipe-source")==files(a.source),"complete uploaded unchanged reader source")
    sys.argv=[recover_read.__file__,"--prepared",str(a.prepared),"--build-recipe",str(a.build_recipe),
        "--retained",str(a.retained),"--output",str(a.output),"--role",a.role]
    recover_read.main()
    def compare():
        old=decode((uploaded/"capture/SUMMARY.json").read_bytes())
        new=decode((a.output/"SUMMARY.json").read_bytes())
        require(old["role"]==new["role"]==a.role and old["first"]==new["first"] and old["count"]==new["count"]
            and old["production"]==new["production"] and old["source_binding"]==new["source_binding"]
            and old["native_artifact"]==new["native_artifact"] and old["source"]==new["source"],
            "complete producer/read scope unchanged")
        rows=[]
        for before,after in zip(old["cases"],new["cases"],strict=True):
            require(before["case"]==after["case"] and before["status"]==after["status"] and before["guards"]==after["guards"]==11,
                "every original success re-read")
            name="READ-%03d.json"%before["case"];left=uploaded/"capture"/name;right=a.output/name
            require(pin(left)==before["proof"] and pin(right)==after["proof"],"whole actual proof byte identities")
            a0=decode(left.read_bytes());a1=decode(right.read_bytes())
            for q in (a0,a1):
                require(q["status"]=="READONLY_PASS" and q["before"]==q["after"] and q["entries"]==len(q["before"])
                    and len(q["probes"])==11 and all(x["rejected"] is True for x in q["probes"])
                    and q["native_executed"] is q["rust_executed"] is q["evidence_written"] is False,"all original immutable guard evidence")
            require(a0["evidence"]==a1["evidence"],"complete independent wire/state/files/host/worker result equality")
            rows.append(dict(case=before["case"],old=pin(left),new=pin(right),complete_evidence_equal=True))
        return dict(status="COMPLETE_UPLOADED_PUBLIC_CASES_INDEPENDENT_JOIN_PASS",role=a.role,cases=rows,
            uploaded_archive=archive,application_executions=0,full_sdk=False,direct_eight_pending=True)
    proof=readonly.guarded(compare,roots=[HERE,a.source,uploaded,a.output])
    (a.output/"UPLOADED_READ.json").write_bytes(canonical(proof))
    saved=a.output/"uploaded-archive";saved.mkdir()
    for n in ("READ.json","ARCHIVE.json","FILES.json"):shutil.copyfile(a.proof/n,saved/n)
    (a.output/"INDEPENDENT_SUMMARY.json").write_bytes(canonical(dict(status=proof["evidence"]["status"],
        role=a.role,cases=len(proof["evidence"]["cases"]),guards=len(proof["probes"]),entries=proof["entries"],
        source=own,application_executions=0,direct_eight_pending=True)))
    print(json.dumps(proof["evidence"],sort_keys=True),flush=True)
if __name__=="__main__":main()
