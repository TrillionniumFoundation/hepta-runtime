#!/usr/bin/env python3
"""Independent full uploaded qualification read; zero applications and controls replayed."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/"reader"));sys.path.insert(0,str(ROOT/"qualified/scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from readonly import guarded
import archive_input,build_reuse,read_build_evidence,read_evidence,read_recovered_evidence,read_initial
def frozen(digest):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==digest,"frozen independent reader manifest")
    identity=source_evidence(ROOT);binding=decode((ROOT/"BINDING.json").read_bytes())
    return identity,binding
def verify(work,name):
    work=Path(work);retained=work/"capture";archive=archive_input.verify(ROOT,retained,name)
    base=retained/"original/restored";source=base/"source";capture=base/"run";qualified=ROOT/"qualified"
    actual={p.relative_to(source).as_posix():p for p in source.rglob("*")if p.is_file()}
    expected={p.relative_to(qualified).as_posix():p for p in qualified.rglob("*")if p.is_file()}
    require(set(actual)==set(expected),"all exact frozen qualification source files")
    for path,physical in actual.items():
        require(physical.read_bytes()==expected[path].read_bytes()
            and physical.stat().st_mode&0o777==expected[path].stat().st_mode&0o777,"all frozen qualification source bytes and modes")
    bound=archive_input.binding(ROOT,name);gate=decode((capture/"GATE.json").read_bytes())
    require(gate["status"]=="PASS"and gate["group"]==name,"retained full qualification gate")
    if bound["read_kind"]=="recovery":
        result=read_recovered_evidence.verify(source,capture,name,work/"build-reuse")
        require(result["status"]=="COMPLETE_UPLOADED_PUBLISH_RECOVERY_PASS","full recovered original evidence")
    else:
        require(bound["read_kind"]=="actual","fixed qualification role")
        result=read_evidence.verify(source,capture,name,work/"build-reuse")
        require(result["status"]=="COMPLETE_UPLOADED_PUBLISH_QUALIFICATION_PASS","full fresh original evidence")
    return dict(status="COMPLETE_INDEPENDENT_PUBLISH_UPLOAD_PASS",group=name,archive=archive,qualification=result,
        new_application_executions=0,physical_controls_replayed=0,whole_runtime_replaced=False)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","restore","read"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();before,bindings=frozen(a.source_manifest_sha256);bound=bindings["groups"][a.group];work=a.work.absolute()
    if a.stage=="fetch":result=archive_input.fetch(work/"capture",bound)
    elif a.stage=="restore":result=archive_input.unpack(work/"capture",bound)
    else:
        build_reuse.prepare_imports(work/"build-reuse")
        result=guarded(lambda:verify(work,a.group),roots=[ROOT,work/"capture/original",work/"capture/download",
            work/"build-reuse/original",work/"build-reuse/download"])
    require(source_evidence(ROOT)==before,"independent source changed")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
