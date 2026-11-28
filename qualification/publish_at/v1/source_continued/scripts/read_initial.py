#!/usr/bin/env python3
"""Read the complete retained initial captures and recover only the pure reader."""
from pathlib import Path
import argparse,ast,gzip,hashlib,importlib.util,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from readonly import guarded
import capture_reuse,build_reuse,read_build_evidence,read_capture
from read_build_evidence import saved_guard,tree
def prepare_old_failure(old,data):
    # Load the exact old reader and exact old source-relative case function before
    # entering the guard. No target helper, native image or original function runs.
    def module(name,path):
        spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    reader=module("retained_old_publication_reader",old/"scripts/read_capture.py")
    cases=module("retained_old_publication_cases",old/"scripts/cases.py")
    reader.group=cases.group
    return reader
def old_rejection(reader,source,data,name):
    try:reader.verify(source,data,name)
    except (ValueError,OSError,EOFError,KeyError)as e:return dict(status="REJECTED",error_type=type(e).__name__,message=str(e))
    raise ValueError("unchanged original copied-source reader unexpectedly admitted")
def verify(source,retained,build_work,name,diagnosis):
    archive=capture_reuse.verify(source,retained,name);base=Path(retained)/"original/restored"
    old=base/"source";run=base/"run";data=run/"application";old_identity=source_evidence(old)
    require(old_identity["manifest"]["sha256"]==archive["binding"]["manifest_sha256"],"complete archived source identity")
    require((old/"scripts/read_capture.py").read_bytes()==(source/"reference/read_capture_before.py").read_bytes()
        and (old/"DOMAIN.json").read_bytes()==(source/"DOMAIN.json").read_bytes(),"exact retained reader and frozen domain")
    gate=decode((run/"GATE.json").read_bytes());require(gate["status"]=="FAIL"and gate["group"]==name
        and gate["source"]==old_identity and gate["message"]=="recorded command failed: physical-controls","retained original pure failure")
    processes=decode((run/"processes/processes.json").read_bytes())
    expected=[("source-check",60),("build-fetch",60),("build-unpack",180),("build-admission",180),
        ("capture-original",180),("capture-native",180),("full-read",180),("physical-controls",180)]
    require(processes==gate["processes"]and[(p["name"],p["timeout_seconds"])for p in processes]==expected,"complete original bounded process set")
    returns={}
    for i,p in enumerate(processes):
        require(p["pid"]==p["pgid"]and p["completed"]is True and p["timed_out"]is False
            and p["exit_code"]==(1 if i==7 else 0)and 0<=p["elapsed_seconds"]<p["timeout_seconds"]and p["stdin"]is None,
            "original terminal process distinct from timeout/unknown")
        for suffix in("stdout","stderr"):
            v=p[suffix];require(v["file"]==p["name"]+"."+suffix and pin(run/"processes"/v["file"])=={k:v[k]for k in("bytes","sha256")},
                "all original full process streams")
        raw=(run/"processes"/p["stdout"]["file"]).read_bytes()
        if i<7:
            require(p["stderr"]["bytes"]==0,"unexpected original diagnostics");returns[p["name"]]=decode(raw)
        else:
            require(raw==b""and"wrong physical rejection reason: source-manifest"in(run/"processes"/p["stderr"]["file"]).read_text(),
                "exact original physical-reader failure")
    require(returns["source-check"]==decode((run/"INPUT_DOMAIN.json").read_bytes()),"whole source/input output")
    for role in("original","native"):
        capture=decode((data/role/"CAPTURE.json").read_bytes());record=returns["capture-"+role]
        require(record["full_buffers"]==capture["buffers"]and record["processes"]==capture["processes"],"complete original application process return")
        producer=processes[4 if role=="original"else 5]
        for item in capture["processes"]:
            receipt=decode((data/role/item["path"]/"carrier-process.json").read_bytes())
            require(receipt["parent_pgid"]==producer["pgid"],"actual saved child stays in original bounded group")
    admission=decode((run/"BUILD_ADMISSION.json").read_bytes());proof=read_build_evidence.verify(old,build_work)
    require(admission==returns["build-admission"]and admission["evidence"]==proof,"complete original build admission")
    old_source=processes[0]["cwd"];old_reuse=processes[1]["argv"][processes[1]["argv"].index("--work")+1]
    saved_guard(admission,{old_source:tree(old),old_reuse+"/original":tree(Path(build_work)/"original"),old_reuse+"/download":tree(Path(build_work)/"download")})
    actual=read_capture.verify(old,data,name);baseline=decode((run/"READONLY.json").read_bytes())
    require(baseline==returns["full-read"]and baseline["evidence"]==actual,"all original/native semantic bytes remain equal")
    original_data=processes[6]["argv"][processes[6]["argv"].index("--data")+1]
    saved_guard(baseline,{old_source:tree(old),original_data:tree(data)})
    require(diagnosis["evidence"]["status"]=="REJECTED"and diagnosis["evidence"]["error_type"]=="PermissionError",
        "original implicit-source lookup rejected by actual read-only guard")
    names=["native-buffer","original-stdout","native-journal","original-case","native-image"]
    controls_origin=processes[7]["argv"][processes[7]["argv"].index("--output")+1]
    for item in names:
        root=run/"controls"/item;value=decode((root/"READONLY.json").read_bytes())
        require(value["evidence"]["status"]=="REJECTED","prior completed physical refusal")
        saved_guard(value,{old_source:tree(old),controls_origin+"/"+item+"/data":tree(root/"data")})
    root=run/"controls/source-manifest";mutation=decode((root/"MUTATION.json").read_bytes())
    require((root/"changed-before.bin").read_bytes()==(old/"SOURCE_MANIFEST.json").read_bytes()
        and(root/"changed-after.bin").read_bytes()==(root/"source/SOURCE_MANIFEST.json").read_bytes()
        ==(root/"changed-before.bin").read_bytes()+b"\nACTUAL_BAD_SOURCE\n","exact previously executed source mutation")
    require(mutation["before_bytes"]==pin(root/"changed-before.bin")and mutation["after_bytes"]==pin(root/"changed-after.bin"),
        "complete preserved source mutation evidence")
    return actual
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--retained",type=Path,required=True)
    p.add_argument("--build-work",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);retained=a.retained.resolve(strict=True);build_work=a.build_work.resolve(strict=True)
    build_reuse.prepare_imports(build_work)
    base=retained/"original/restored";old=base/"source";bad=base/"run/controls/source-manifest"
    original=prepare_old_failure(old,bad/"data")
    diagnosis=guarded(lambda:old_rejection(original,bad/"source",bad/"data",a.group),roots=[bad/"source",bad/"data"])
    result=guarded(lambda:verify(source,retained,build_work,a.group,diagnosis),
        roots=[source,retained,build_work/"original",build_work/"download"])
    result["preserved_initial_failure_diagnosis"]=diagnosis;result["application_executions"]=0
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
