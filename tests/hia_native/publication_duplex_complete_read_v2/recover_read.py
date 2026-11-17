#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Recover whole existing public artifacts; join complete wire/state/worker evidence."""
from pathlib import Path
import argparse,json,shutil,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require,source_evidence
import read_native,public_worker,readonly,provenance
PARTITIONS={"legacy-a":(0,6),"legacy-b":(6,5),"modern-a":(11,6),"modern-b":(17,5)}
def tree(root):
    return {p.relative_to(root).as_posix():dict(pin(p),mode=p.stat().st_mode&0o777,
        mtime_ns=p.stat().st_mtime_ns) for p in sorted(root.rglob("*")) if p.is_file()}
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--prepared",type=Path,required=True)
    parser.add_argument("--build-recipe",type=Path,required=True)
    parser.add_argument("--retained",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--role",choices=PARTITIONS,required=True)
    a=parser.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    source=source_evidence(HERE)
    for p in HERE.rglob("*.py"):compile(p.read_bytes(),str(p),"exec")
    (a.output/"SOURCE_CHECK.json").write_bytes(canonical(source))
    prep=decode((a.prepared/"PREPARED.json").read_bytes())
    info=decode((HERE/"RETAINED_INPUTS.json").read_bytes())
    require(prep["inputs"]==info,"prepared full graph/original exact input pins")
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    retained,archive=restore(a.retained,info["retained_public"][a.role])
    for label,folder in (("native",a.retained),("build",a.prepared/"build"),("original",a.prepared/"original")):
        target=a.output/(label+"-archive");target.mkdir()
        for name in ("READ.json","FILES.json","ARCHIVE.json"):shutil.copyfile(folder/name,target/name)
    for name in ("PREPARED.json","build-read.json","build-read.stdout","build-read.stderr",
        "original-read.json","original-read.stdout","original-read.stderr","ORIGINAL_READ.json"):
        shutil.copyfile(a.prepared/name,a.output/name)
    original=Path(prep["original"])
    graph=a.prepared/"build/extracted/capture/source"
    sdk=a.prepared/"original/extracted"/info["sdk_service"]["path"]
    closure=provenance.verify(HERE,retained/"recipe-source",graph,sdk)
    (a.output/"PROVENANCE.json").write_bytes(canonical(closure))
    plan=decode((original/"PLAN.json").read_bytes())
    native=retained/"capture/native"
    current=decode((native/"PLAN.json").read_bytes())
    results=decode((native/"RESULTS.json").read_bytes())
    first,count=PARTITIONS[a.role];selected=plan["cases"][first:first+count]
    expected={k:info["build"]["binary"][k] for k in ("bytes","sha256")}
    require((current["first"],current["count"])==(first,count)
        and current["cases"]==selected and current["original_plan"]==pin(original/"PLAN.json")
        and current["declaration"]==plan["declaration"] and len(results)==count,
        "all frozen public input rows retained")
    require(current["binary"]==pin(Path(prep["binary"]))==expected,"exact built actual 124-image binary")
    require({p.name for p in (native/"cases").iterdir()}=={"%03d"%case["case"] for case in selected},
        "complete selected actual case set")
    copied=decode((retained/"capture/CAPTURE_COPY.json").read_bytes())
    require(copied["complete_bytes"] is copied["mode_mtime"] is copied["original_retained"] is True
        and copied["files"]==tree(native),"entire retained capture copy bytes/modes/mtime")
    process=decode((retained/"capture/CAPTURE_PROCESS.json").read_bytes())
    require(process["exit_code"]==0 and process["outer_timeout_seconds"] is None
        and process["child_process_limit_seconds"]==180 and process["child_exchange_limit_seconds"]==60,
        "actual producers succeeded with exact original deadlines")
    (a.output/"PRODUCER.json").write_bytes(canonical(dict(artifact=archive,process=process,
        old_summary=decode((retained/"capture/SUMMARY.json").read_bytes()),
        original_capture_source=info["native_capture_source"],failures_preserved=True)))
    rows=[]
    for case,record in zip(selected,results,strict=True):
        number=case["case"];n=native/"cases"/("%03d"%number);o=original/"cases"/("%03d"%number)
        require(record==decode((n/"RESULT.json").read_bytes())
            and record["production_source"]==info["build"]["production"],"actual complete result/source association")
        start=time.monotonic()
        def operation():
            wire=read_native.compare(n,o,case,expected)
            worker=public_worker.verify(n,o,case)
            return dict(status="COMPLETE_PUBLIC_WIRE_STATE_WORKER_AND_LIFECYCLE_JOIN_PASS",
                case=number,name=case["name"],era=case["era"],wire_state=wire,worker=worker,
                full_sdk=False,direct_eight_qualified=False,semantic_replay=False)
        proof=readonly.guarded(operation,roots=[HERE,n,o])
        elapsed=time.monotonic()-start
        require(elapsed<180,"whole independent case reader original180s")
        target=a.output/("READ-%03d.json"%number);target.write_bytes(canonical(proof))
        evidence=proof["evidence"]
        row=dict(case=number,name=case["name"],era=case["era"],status=evidence["status"],
            elapsed_seconds=elapsed,guards=len(proof["probes"]),entries=proof["entries"],
            worker_jobs=evidence["worker"]["publisher_jobs"],
            worker_frames=evidence["worker"]["actual_worker"]["frames"],
            worker_bytes=evidence["worker"]["actual_worker"]["bytes"],
            host_bytes=evidence["worker"]["host_bytes"],proof=pin(target),semantic_replay=False)
        rows.append(row)
        (a.output/"READ_RESULTS.json").write_bytes(canonical(rows))
        print("PUBLIC_COMPLETE_READ "+json.dumps(row,sort_keys=True),flush=True)
    summary=dict(status="COMPLETE_RETAINED_PUBLIC_PARTITION_JOIN_PASS",role=a.role,
        first=first,count=count,cases=rows,native_artifact=archive,
        production=info["build"]["production"],source_binding=info["source_binding"],
        source=source,original_replayed=False,native_replayed=False,direct_eight_pending=True,
        physical_reader_controls_pending=True,full_sdk=False)
    (a.output/"SUMMARY.json").write_bytes(canonical(summary))
    print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
