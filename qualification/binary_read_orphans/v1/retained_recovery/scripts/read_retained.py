#!/usr/bin/env python3
"""Complete recovery admission of unchanged captured applications; never execute one."""
from pathlib import Path
import argparse,ast,encodings.cp437,gzip,hashlib,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from readonly import guarded
import read_capture,read_build_evidence,build_reuse,restore_original
from read_build_evidence import tree,saved_guard
import read_evidence as original_evidence

def reader_contract(root):
    root=Path(root);change=decode((root/"READER_CHANGE.json").read_bytes())
    before=(root/"trusted-qualification/scripts/read_capture.py").read_text()
    after=(root/"scripts/read_capture.py").read_text();current=before
    for row in change["changes"]:
        require(current.count(row["before"])==1,"one exact frozen reader preimage")
        current=current.replace(row["before"],row["after"])
    require(current==after and pin(root/"trusted-qualification/scripts/read_capture.py")==change["before"]
        and pin(root/"scripts/read_capture.py")==change["after"],"exact whole reader derivation")
    require(len(change["changes"])==2 and change["applications_replayed"]==0
        and change["native_images_unchanged"]is True,"narrow pure comparison scope")
    derivation=decode((root/"RETAINED_READER_DERIVATION.json").read_bytes())
    old=(root/derivation["before"]).read_text();new=old
    for row in derivation["changes"]:
        require(new.count(row["before"])==1,"retained producer reader preimage")
        new=new.replace(row["before"],row["after"])
    require(new==(root/derivation["after"]).read_text(),"all saved producer/guard/physical evidence checks retained")
    for name in("cases","protocol","read_journal","build_reuse","read_build_evidence"):
        require((root/"scripts"/(name+".py")).read_bytes()==(root/"trusted-qualification/scripts"/(name+".py")).read_bytes(),
            "full input, ABI, journal and native build readers unchanged")
    return dict(status="EXACT_LIVE_PARENT_PATH_READER_DERIVATION_PASS",before=change["before"],after=change["after"],
        production_changed=False,applications_replayed=0,diagnostic_commit=change["diagnostic_commit"],
        diagnostic_run=change["diagnostic_run"])

def failed_producer(source,capture,name,build_work):
    source,capture,build_work=Path(source),Path(capture),Path(build_work)
    binding=source_evidence(source);gate=decode((capture/"GATE.json").read_bytes())
    require(gate["status"]=="FAIL"and gate["source"]==binding and gate["group"]==name
        and gate["compiler_or_rust_executions"]==0 and gate["whole_runtime_replaced"]is False
        and gate["error_type"]=="RuntimeError"and gate["message"]=="recorded command failed: full-read",
        "exact preserved diagnostic-reader failure")
    processes=decode((capture/"processes/processes.json").read_bytes())
    expected=[("source-check",60),("build-fetch",60),("build-unpack",180),("build-admission",180),
        ("capture-original",180),("capture-native",180),("full-read",180)]
    require(processes==gate["processes"]and[(p["name"],p["timeout_seconds"])for p in processes]==expected,
        "exact completed producer process set")
    returns={}
    for p in processes:
        failed=p["name"]=="full-read"
        require(p["pid"]==p["pgid"]and p["exit_code"]==(1 if failed else 0)and p["completed"]is True
            and p["timed_out"]is False and 0<=p["elapsed_seconds"]<p["timeout_seconds"]and p["stdin"]is None,
            "natural bounded producer process custody")
        for suffix in("stdout","stderr"):
            item=p[suffix];require(item["file"]==p["name"]+"."+suffix
                and pin(capture/"processes"/item["file"])=={k:item[k]for k in("bytes","sha256")},"whole original process streams")
        if failed:
            error=(capture/"processes"/p["stderr"]["file"]).read_bytes()
            first={"ordinary":1,"first-path":6,"second-path":11,"last-path":16,"refusals":35,"unicode":40}[name]
            require(p["stdout"]["bytes"]==0 and error.endswith(
                b"ValueError: actual complete original/native effect sequence differs: "+str(first).encode()+b"\n")
                and b"na.apply(comparison_effects(oe))==nb.apply(comparison_effects(ne))"in error,
                "precise original relative-path comparison failure retained")
        else:
            require(p["stderr"]["bytes"]==0,"unread producer diagnostic")
            returns[p["name"]]=decode((capture/"processes"/p["stdout"]["file"]).read_bytes())
    require(returns["source-check"]==decode((capture/"INPUT_DOMAIN.json").read_bytes())
        and returns["source-check"]["status"]=="READ_ORPHANS_SOURCE_AND_INPUT_ONLY_PASS","exact source/input-only gate")
    completed=decode((capture/"COMPLETED.json").read_bytes())
    require(gate["completed"]==completed==[dict(role=r,report=returns["capture-"+r])for r in("original","native")],
        "both original and native completed before original reader failure")
    for p in processes:
        if not p["name"].startswith("capture-"):continue
        role=p["name"][8:];report=decode((capture/"application"/role/"CAPTURE.json").read_bytes())
        require(report["status"]=="PASS"and report["role"]==role and returns[p["name"]]["full_buffers"]==report["buffers"]
            and returns[p["name"]]["processes"]==report["processes"],"complete real application return")
        for process in report["processes"]:
            path=capture/"application"/role/process["path"]/"carrier-process.json";record=decode(path.read_bytes())
            require(pin(path)==process["receipt"]and record["parent_pgid"]==p["pgid"],"every actual producer in bounded group")
    original_source=processes[0]["cwd"]
    reuse_origin=processes[1]["argv"][processes[1]["argv"].index("--work")+1]
    admission=decode((capture/"BUILD_ADMISSION.json").read_bytes())
    require(admission==returns["build-admission"],"whole original build admission")
    upstream=read_build_evidence.verify(source,build_work)
    require(admission["evidence"]==upstream,"complete retained upstream qualification")
    files=saved_guard(admission,{original_source:tree(source),reuse_origin+"/original":tree(build_work/"original"),
        reuse_origin+"/download":tree(build_work/"download")})
    actual=read_capture.verify(source,capture/"application",name)
    require(not(capture/"READONLY.json").exists()and not(capture/"controls").exists(),"no invented old successful gate")
    return dict(status="PRESERVED_FAILED_READER_WITH_COMPLETE_ACTUAL_CAPTURES_PASS",group=name,actual=actual,upstream_build=upstream,
        producer_processes=len(processes),retained_guard_invocations=1,retained_guard_probes=11,
        retained_guard_full_file_references=files,new_application_executions=0,original_failure_retained=True)

def verify(root,semantic,name,upstream):
    root,semantic,upstream=Path(root),Path(semantic),Path(upstream)
    contract=reader_contract(root);bound=restore_original.selection(root,name)
    archive=restore_original.verify(root,semantic,bound)
    source=semantic/"original/restored/source";capture=semantic/"original/restored/run"
    if bound["gate_status"]=="PASS":
        retained=original_evidence.verify(source,capture,name,upstream)
    else:
        require(bound["gate_status"]=="FAIL","frozen original terminal status")
        retained=failed_producer(source,capture,name,upstream)
    return dict(status="COMPLETE_RETAINED_READ_ORPHANS_PASS",group=name,original_status=bound["gate_status"],
        actual=retained["actual"],archive=archive,retained=retained,reader_contract=contract,
        applications_replayed=0,whole_runtime_replaced=False)

def main():
    p=argparse.ArgumentParser();p.add_argument("--semantic",type=Path,required=True)
    p.add_argument("--upstream",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    before=source_evidence(ROOT);build_reuse.prepare_imports(a.upstream)
    value=guarded(lambda:verify(ROOT,a.semantic,a.group,a.upstream),roots=[ROOT,a.semantic,a.upstream])
    require(source_evidence(ROOT)==before,"pure source changed")
    print(encoded(value).decode(),end="")
if __name__=="__main__":main()
