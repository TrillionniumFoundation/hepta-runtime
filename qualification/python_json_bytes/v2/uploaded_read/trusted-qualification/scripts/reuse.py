#!/usr/bin/env python3
"""Whole archive recovery and pure build admission; application calls remain zero."""
from pathlib import Path
import argparse,importlib.util,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,source_evidence,owned
import archive_restore
from guard_refs import tree,saved_guard
def same(left,right):
    a={p.relative_to(left).as_posix():p for p in left.rglob("*")if p.is_file()}
    b={p.relative_to(right).as_posix():p for p in right.rglob("*")if p.is_file()}
    require(set(a)==set(b),"complete restored source set differs")
    for key in a:
        require(a[key].read_bytes()==b[key].read_bytes()and a[key].stat().st_mode&0o777==b[key].stat().st_mode&0o777,
            "complete restored source bytes/modes differ")
def prepare_build(source,work):
    base=work/"original/restored";same(source/"trusted-build",base/"source")
    sys.path.insert(0,str(source/"trusted-build/scripts"))
    spec=importlib.util.spec_from_file_location("qualified_python_json_bytes_build_reader",source/"trusted-build/scripts/read_build.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return base,module
def processes(folder,rows,expected):
    require(decode(owned(folder,"processes.json").read_bytes())==rows
        and[(r["name"],r["timeout_seconds"])for r in rows]==expected,"complete fixed bounded process table")
    results={}
    for r in rows:
        require(r["pid"]==r["pgid"]and r["parent_pid"]>0 and r["completed"]is True and r["timed_out"]is False
            and r["exit_code"]==0 and r["stdin"]is None and 0<=r["elapsed_seconds"]<r["timeout_seconds"],
            "natural completed bounded process")
        for name in("stdout","stderr"):
            v=r[name];require(v["file"]==r["name"]+"."+name
                and pin(owned(folder,v["file"]))=={k:v[k]for k in("bytes","sha256")},"whole retained process streams")
        require(r["stderr"]["bytes"]==0,"hidden retained process error")
        results[r["name"]]=decode(owned(folder,r["stdout"]["file"]).read_bytes())
    return results
def verify_build(source,work,module):
    base=work/"original/restored";old=base/"source";run=base/"run";artifact=run/"artifact"
    same(source/"trusted-build",old);identity=source_evidence(old)
    bound=decode(owned(source,"BUILD_INPUT.json").read_bytes())
    require(pin(old/"SOURCE_MANIFEST.json")["sha256"]==bound["manifest_sha256"],"exact frozen qualified build")
    gate=decode(owned(run,"GATE.json").read_bytes())
    require(gate["status"]=="PASS"and gate["schema"]=="hepta.runtime.python-json-bytes.build-gate.v1"
        and gate["source"]==identity and gate["hia_compiles"]==1 and gate["application_hia_executions"]==0
        and gate["original_applications"]==gate["new_seed_executions"]==gate["new_bootstrap_generations"]==0,
        "complete build-only producer scope")
    values=processes(run/"processes",gate["processes"],[("source-check",60),("native-build",900),("read-build",180)])
    require(values["source-check"]==gate["source_check"]==decode(owned(run,"SOURCE_CHECK.json").read_bytes())
        and values["source-check"]["status"]=="PYTHON_JSON_BYTES_SOURCE_PASS"
        and values["native-build"]==gate["build"]==decode(owned(artifact,"build/module.json").read_bytes()),
        "complete author/source/build producer records")
    result=module.verify(old,artifact);guard=decode(owned(run,"READONLY.json").read_bytes())
    require(guard==values["read-build"]and guard["evidence"]==gate["read"]==result
        and result["image"]==bound["image"],"complete fixed build pure result and image")
    rows=gate["processes"];origin=rows[0]["cwd"];args=rows[2]["argv"];old_artifact=args[args.index("--build")+1]
    references=saved_guard(guard,{origin:tree(old),old_artifact:tree(artifact)})
    return dict(status="FULL_RETAINED_PYTHON_JSON_BYTES_BUILD_PASS",binding=bound,build=result,
        saved_guard_full_file_references=references,new_application_calls=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","unpack","read-build","check-legacy"])
    p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True)
    p.add_argument("--kind",choices=["build","legacy"],required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);work=a.work.resolve(strict=True);before=source_evidence(source)
    binding=decode(owned(source,"BUILD_INPUT.json"if a.kind=="build"else"LEGACY_INPUT.json").read_bytes())
    if a.stage in("fetch","unpack"):
        function=archive_restore.fetch if a.stage=="fetch"else archive_restore.unpack
        result=function(work,binding)
    elif a.stage=="check-legacy":
        require(a.kind=="legacy","legacy source admission kind")
        same(source/"trusted-legacy",work/"original/restored/source")
        result=dict(status="COMPLETE_FROZEN_LEGACY_SOURCE_PASS",source_manifest=binding["manifest_sha256"],
            source_files=34,new_application_calls=0)
    else:
        require(a.kind=="build","build reader kind");base,module=prepare_build(source,work)
        from readonly import guarded
        result=guarded(lambda:verify_build(source,work,module),roots=[source,work/"download",work/"original"])
    require(source_evidence(source)==before,"archive reuse changed frozen source")
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
