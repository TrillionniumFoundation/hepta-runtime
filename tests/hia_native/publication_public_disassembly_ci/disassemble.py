#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read existing exact graph bytes and disassemble the mechanical object only."""
from pathlib import Path
import argparse,json,os,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/"build-reference"))
from async_build_common import require,pin,put,doc,files
import restore_full,read_graph,read_build,dynamic_builder,read_only_guard as guard
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),"fresh complete disassembly output");a.output.mkdir(parents=True)
    proof=a.output/"proof";proof.mkdir()
    target,archive=restore_full.restore(a.output/"retained",doc(HERE/"INPUT.json"))
    capture=target/"capture";retained=capture/"retained"
    require(files(target/"recipe-source")==files(HERE/"build-reference"),"exact retained build recipe")
    read_graph.prepare(retained);dynamic_builder.load(capture/"source")
    result=guard.guarded(lambda:dict(retained=read_graph.verify(retained),current=read_build.verify(retained,capture)),
        roots=[target,HERE],foreign_path=Path("/dev/null"))
    put(proof/"READ_ONLY.json",result);put(proof/"ARCHIVE.json",archive)
    report=dict(status="COMPLETE_EXISTING_OBJECT_DISASSEMBLY",application_executed=False,native_or_rust_replayed=False,
        artifact=archive,source_commit="1c5c6d5632d54c2eb30abeb47568d63b4cb743c3",entries={})
    for role in ("public","publisher","filesystem"):
        folder=capture/("build-"+role)/("async-"+role)
        obj=folder/"bridge.o";assembly=folder/"combined.S"
        dst=proof/role;dst.mkdir()
        for name in ("bridge.o","combined.S","manifest.json"):shutil.copyfile(folder/name,dst/name)
        argv=["/usr/bin/objdump","-drw","-Mintel",str(obj)]
        before=pin(obj);started=time.monotonic()
        completed=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
        require(completed.returncode==0 and not completed.stderr,"actual read-only objdump status")
        require(pin(obj)==before,"object unchanged by inspection")
        (dst/"objdump.stdout").write_bytes(completed.stdout);(dst/"objdump.stderr").write_bytes(completed.stderr)
        text=completed.stdout.decode();lines=text.splitlines()
        index=next((i for i,l in enumerate(lines) if "<pump_trace_publication>:" in l),None)
        excerpt=lines[max(0,index-2):index+210] if index is not None else []
        selected=[l for l in excerpt if "r9d" in l or "<ppt_" in l or "<pump_trace_" in l]
        row=dict(object=before,assembly=pin(assembly),argv=argv,exit_code=completed.returncode,
            elapsed_seconds=time.monotonic()-started,stdout=pin(dst/"objdump.stdout"),stderr=pin(dst/"objdump.stderr"),
            excerpt="\n".join(excerpt)+"\n",selected=selected)
        put(dst/"PROCESS.json",row);report["entries"][role]=row
    report["guards"]=len(result["probes"]);report["snapshot_entries"]=len(result["before"])
    put(proof/"REPORT.json",report);print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
