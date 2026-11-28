#!/usr/bin/env python3
"""Independent full uploaded qualification read; zero applications and controls replayed."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/"reader"));sys.path.insert(0,str(ROOT/"qualified/scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from readonly import guarded
import capture_archive_input as archive_input
import build_reuse,read_build_evidence,read_evidence,read_recovered_evidence,read_initial
def frozen(digest):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==digest,"frozen independent reader manifest")
    identity=source_evidence(ROOT);binding=decode((ROOT/"BINDING.json").read_bytes())
    return identity,binding
def preserved_failure(work,name,bound):
    root=Path(work)/"previous-reader"
    archive=archive_input.verify(ROOT,root,name,bound)
    base=root/"original/restored";source=base/"source";run=base/"run"
    require((source/"archive_reader.py").read_bytes()==(ROOT/"reference/archive_reader_before.py").read_bytes()
        and(source/"archive_input.py").read_bytes()==(ROOT/"reference/capture_archive_before.py").read_bytes()
        and(source/"BINDING.json").read_bytes()==(ROOT/"reference/BINDING_before.json").read_bytes(),"whole original failed independent reader source")
    gate=decode((run/"GATE.json").read_bytes());processes=decode((run/"processes/processes.json").read_bytes())
    require(gate["status"]=="FAIL"and gate["stage"]=="independent-read"and gate["group"]==name
        and gate["message"]=="recorded command failed: independent-read"
        and gate["application_hia_executions"]==gate["rust_executions"]==gate["physical_controls_replayed"]==0
        and gate["processes"]==processes,"exact previous non-application failure")
    expected=[("fetch",60),("restore",180),("build-fetch",60),("build-unpack",180),("independent-read",180)]
    require([(p["name"],p["timeout_seconds"])for p in processes]==expected,"all prior independent stages")
    for i,p in enumerate(processes):
        require(p["pid"]==p["pgid"]and p["completed"]is True and p["timed_out"]is False
            and p["exit_code"]==(1 if i==4 else 0)and 0<=p["elapsed_seconds"]<p["timeout_seconds"]
            and p["stdin"]is None,"natural prior terminal stage")
        for suffix in("stdout","stderr"):
            r=p[suffix];require(r["file"]==p["name"]+"."+suffix and pin(run/"processes"/r["file"])=={k:r[k]for k in("bytes","sha256")},
                "complete preserved prior stage streams")
        if i<4:require(p["stderr"]["bytes"]==0,"prior unexpected diagnostic")
        else:
            require(p["stdout"]["bytes"]==0 and"ImportError: cannot import name 'Hashing' from 'archive_input'"in(run/"processes"/p["stderr"]["file"]).read_text(),
                "exact retained import namespace collision")
    return archive
def verify(work,name):
    work=Path(work);retained=work/"capture";archive=archive_input.verify(ROOT,retained,name)
    base=retained/"original/restored";source=base/"source";capture=base/"run";qualified=ROOT/"qualified"
    actual={p.relative_to(source).as_posix():p for p in source.rglob("*")if p.is_file()}
    expected={p.relative_to(qualified).as_posix():p for p in qualified.rglob("*")if p.is_file()}
    require(set(actual)==set(expected),"all exact frozen qualification source files")
    for path,physical in actual.items():
        require(physical.read_bytes()==expected[path].read_bytes()
            and physical.stat().st_mode&0o777==expected[path].stat().st_mode&0o777,"all frozen qualification source bytes and modes")
    bound=archive_input.binding(ROOT,name);previous=preserved_failure(work,name,bound["preserved_reader_failure"]);gate=decode((capture/"GATE.json").read_bytes())
    require(gate["status"]=="PASS"and gate["group"]==name,"retained full qualification gate")
    if bound["read_kind"]=="recovery":
        result=read_recovered_evidence.verify(source,capture,name,work/"build-reuse")
        require(result["status"]=="COMPLETE_UPLOADED_PUBLISH_RECOVERY_PASS","full recovered original evidence")
    else:
        require(bound["read_kind"]=="actual","fixed qualification role")
        result=read_evidence.verify(source,capture,name,work/"build-reuse")
        require(result["status"]=="COMPLETE_UPLOADED_PUBLISH_QUALIFICATION_PASS","full fresh original evidence")
    return dict(status="COMPLETE_INDEPENDENT_PUBLISH_UPLOAD_PASS",group=name,archive=archive,qualification=result,preserved_reader_failure=previous,
        new_application_executions=0,physical_controls_replayed=0,whole_runtime_replaced=False)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","restore","read"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();before,bindings=frozen(a.source_manifest_sha256);bound=bindings["groups"][a.group];work=a.work.absolute()
    if a.stage=="fetch":
        result=archive_input.fetch(work/"capture",bound)
        result["previous_reader"]=archive_input.fetch(work/"previous-reader",bound["preserved_reader_failure"])
    elif a.stage=="restore":
        result=archive_input.unpack(work/"capture",bound)
        result["previous_reader"]=archive_input.unpack(work/"previous-reader",bound["preserved_reader_failure"])
    else:
        build_reuse.prepare_imports(work/"build-reuse")
        result=guarded(lambda:verify(work,a.group),roots=[ROOT,work/"capture/original",work/"capture/download",
            work/"build-reuse/original",work/"build-reuse/download",work/"previous-reader/original",work/"previous-reader/download"])
    require(source_evidence(ROOT)==before,"independent source changed")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
