#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every completed direct case, retaining the partially failed producer."""
from pathlib import Path
import argparse,json,shutil,sys,time
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require,source_evidence
import read_direct,direct_worker,direct_provenance,readonly
def tree(root):
    return {p.relative_to(root).as_posix():dict(pin(p),mode=p.stat().st_mode&0o777,
        mtime_ns=p.stat().st_mtime_ns) for p in sorted(root.rglob("*")) if p.is_file()}
def main():
    p=argparse.ArgumentParser()
    for name in ("prepared","build-recipe","direct-recipe","public-reader","retained","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--role",required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    source=source_evidence(HERE);info=decode((HERE/"INPUTS.json").read_bytes());role=info["roles"][a.role]
    prep=decode((a.prepared/"domain/PREPARED.json").read_bytes())
    require(prep["inputs"]["build"]==info["direct_build"],"actual direct build dependency unchanged")
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    retained,archive=restore(a.retained,role["artifact"])
    failure_root=a.retained.parent/(a.retained.name+"-reader-failure")
    failed,failed_archive=restore(failure_root,role["reader_failure"])
    require(pin(failed/"recipe-source/SOURCE_MANIFEST.json")==
        info["reader_predecessor_failure"]["source_manifest"],"whole unchanged predecessor reader source")
    source_evidence(failed/"recipe-source")
    stderr=(failed/"driver.stderr").read_bytes()
    require(b"ValueError: only a settled direct future can end its Scope68 loan" in stderr,
        "exact retained predecessor reader failure")
    failed_saved=a.output/"predecessor-reader-failure";failed_saved.mkdir()
    for name in ("READ.json","FILES.json","ARCHIVE.json"):shutil.copyfile(failure_root/name,failed_saved/name)
    for name in ("driver.stdout","driver.stderr"):shutil.copyfile(failed/name,failed_saved/name)
    (failed_saved/"SUMMARY.json").write_bytes(canonical(dict(archive=failed_archive,
        source=info["reader_predecessor_failure"],original_conclusion="failure",native_or_original_replayed=False)))
    prior=info["reader_v2_terminals"][a.role]
    prior_root=a.retained.parent/(a.retained.name+"-reader-v2")
    prior_files,prior_archive=restore(prior_root,prior)
    require(pin(prior_files/"recipe-source/SOURCE_MANIFEST.json")==info["reader_v2_manifest"],
        "whole second reader source identity")
    source_evidence(prior_files/"recipe-source")
    if prior["error"] is not None:
        error_path=(prior_files/"capture/prepare-records/driver.prepare.stderr"
            if a.role=="old22" else prior_files/"driver.stderr")
        require(prior["error"].encode() in error_path.read_bytes(),"exact preserved second reader refusal")
        require(prior["conclusion"]=="failure","no relabelling a failed reader")
    else:
        previous=decode((prior_files/"capture/SUMMARY.json").read_bytes())
        require(prior["conclusion"]=="success" and a.role=="old24"
            and [x["case"] for x in previous["cases"]]==[24]
            and previous["status"]=="COMPLETE_RETAINED_DIRECT_CASE_JOIN_PASS","retained successful complete case24")
    saved=a.output/"reader-v2-terminal";saved.mkdir()
    for name in ("READ.json","FILES.json","ARCHIVE.json"):shutil.copyfile(prior_root/name,saved/name)
    for name in ("driver.stdout","driver.stderr"):
        path=prior_files/name
        if path.exists():shutil.copyfile(path,saved/name)
    for name in ("SUMMARY.json","READ_RESULTS.json","READ-024.json"):
        path=prior_files/"capture"/name
        if path.exists():shutil.copyfile(path,saved/name)
    if a.role=="old22":
        shutil.copyfile(prior_files/"capture/prepare-records/driver.prepare.stderr",saved/"prepare.stderr")
    (saved/"TERMINAL.json").write_bytes(canonical(dict(identity=prior,archive=prior_archive,
        original_conclusion=prior["conclusion"],source_unchanged=True,application_replayed=False)))
    original=Path(prep["original"]);graph=a.prepared/"domain/public-prepared/build/extracted/capture/source"
    closure=direct_provenance.verify(HERE,retained/"recipe-source",graph,a.direct_recipe,a.public_reader,role["producer_manifest"])
    (a.output/"PROVENANCE.json").write_bytes(canonical(closure))
    for label,folder in (("native",a.retained),("direct-build",a.prepared/"domain/direct-build"),
        ("build",a.prepared/"domain/public-prepared/build"),("original",a.prepared/"domain/public-prepared/original")):
        target=a.output/(label+"-archive");target.mkdir()
        for name in ("READ.json","FILES.json","ARCHIVE.json"):shutil.copyfile(folder/name,target/name)
    for folder,names in ((a.prepared,("SOURCE_CHECK.json","PREPARE_PROCESS.json","prepare.stdout","prepare.stderr")),
        (a.prepared/"domain",("PREPARED.json","DIRECT_BUILD_READ.json","PRIOR_PROCESS.json","prior.stdout","prior.stderr"))):
        for name in names:shutil.copyfile(folder/name,a.output/name)
    native=retained/"capture/native";plan=decode((original/"PLAN.json").read_bytes())
    current=decode((native/"PLAN.json").read_bytes());results=decode((native/"RESULTS.json").read_bytes())
    first,count=role["partition"];selected=[plan["cases"][i] for i in role["completed"]]
    require((current["first"],current["count"])==(first,count)
        and current["cases"]==plan["cases"][first:first+count]
        and current["original_plan"]==pin(original/"PLAN.json") and current["declaration"]==plan["declaration"],
        "entire unchanged actual native attempted domain")
    require([r["case"] for r in results]==role["completed"],"every completed case is included exactly once")
    require({p.name for p in (native/"cases").iterdir()}=={"%03d"%i for i in role["captured"]},
        "whole success and failure case set")
    expected={k:info["direct_build"]["binary"][k] for k in ("bytes","sha256")}
    require(current["binary"]==pin(Path(prep["binary"]))==expected,"whole qualified actual fixed direct ELF")
    copied=decode((retained/"capture/CAPTURE_COPY.json").read_bytes())
    require(copied["complete_bytes"] is copied["mode_mtime"] is copied["original_retained"] is True
        and copied["files"]==tree(native),"all retained native copy bytes/modes/mtime")
    process=decode((retained/"capture/CAPTURE_PROCESS.json").read_bytes())
    require(process["exit_code"]==role["producer_exit"] and process["outer_timeout_seconds"] is None
        and process["child_process_limit_seconds"]==180 and process["child_exchange_limit_seconds"]==60,
        "actual known producer terminal and original per-process budgets")
    excluded=[]
    for number in role["failed"]:
        path=native/"cases"/("%03d"%number);failure=decode((path/"FAILURE.json").read_bytes())
        failed_process=decode((path/"process/PROCESS.json").read_bytes())
        require(not (path/"RESULT.json").exists() and failure["type"]=="UnboundLocalError"
            and failure["message"]=="cannot access local variable 'blocklocked' where it is not associated with a value"
            and failed_process["cleanup_errors"]==[] and failed_process["process_group_absent"] is True,
            "only the fully retained known observer failure is outside this complete-case role")
        excluded.append(dict(case=number,failure=failure,process=failed_process,qualified=False))
    require(role["producer_exit"]==(1 if excluded else 0),"producer FAIL must never be relabelled PASS")
    (a.output/"PRODUCER.json").write_bytes(canonical(dict(archive=archive,process=process,
        original_summary=decode((retained/"capture/SUMMARY.json").read_bytes()) if (retained/"capture/SUMMARY.json").exists() else None,
        failures_retained=excluded,producer_conclusion_changed=False)))
    rows=[]
    for case,record in zip(selected,results,strict=True):
        number=case["case"];n=native/"cases"/("%03d"%number);o=original/"cases"/("%03d"%number)
        require(record==decode((n/"RESULT.json").read_bytes())
            and record["production_source"]==info["production"],"whole actual result/source association")
        start=time.monotonic()
        def operation():
            semantic=read_direct.compare(n,o,case,expected);worker=direct_worker.verify(n,o,case)
            return dict(status="COMPLETE_DIRECT_STATE_FILES_WORKER_DROP_AND_LIFECYCLE_JOIN_PASS",
                case=number,name=case["name"],semantics=semantic,worker=worker,
                semantic_replay=False,full_sdk=False)
        proof=readonly.guarded(operation,roots=[HERE,n,o,original/"cases/000"])
        elapsed=time.monotonic()-start;require(elapsed<180,"whole direct independent case reader180s")
        target=a.output/("READ-%03d.json"%number);target.write_bytes(canonical(proof));e=proof["evidence"]
        row=dict(case=number,name=case["name"],status=e["status"],elapsed_seconds=elapsed,
            guards=len(proof["probes"]),entries=proof["entries"],proof=pin(target),
            worker_jobs=e["worker"]["publisher_jobs"],worker_frames=e["worker"]["actual_worker"].get("frames",0),
            worker_bytes=e["worker"]["actual_worker"]["bytes"],host_bytes=e["worker"]["host_bytes"],
            semantic_replay=False)
        rows.append(row);(a.output/"READ_RESULTS.json").write_bytes(canonical(rows))
        print("DIRECT_COMPLETE_READ "+json.dumps(row,sort_keys=True),flush=True)
    summary=dict(status="COMPLETE_RETAINED_DIRECT_CASE_JOIN_PASS",role=a.role,cases=rows,archive=archive,
        failed_cases_retained=excluded,production=info["production"],source_binding=info["source_binding"],
        source=source,original_replayed=False,native_replayed=False,physical_controls_pending=True,full_sdk=False)
    (a.output/"SUMMARY.json").write_bytes(canonical(summary));print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
