#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Separate actual session retirement from actual process-runtime retirement."""
from pathlib import Path
import argparse,hashlib,json,stat,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ENC=lambda x:(json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
def require(ok,message):
    if not ok:raise ValueError(message)
def pin(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def blob(data):return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
def row(path,data):return dict(path=path,mode="100644",**pin(data),git_blob=blob(data))
def write(root,name,data):
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o644)
def inventory(root):return {p.relative_to(root).as_posix():row(p.relative_to(root).as_posix(),p.read_bytes()) for p in sorted(root.rglob("*")) if p.is_file()}
def main():
    p=argparse.ArgumentParser();p.add_argument("--baseline",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),"fresh source author");a.output.mkdir(parents=True)
    rows=json.loads((HERE/"BASE_SOURCE_ROWS.json").read_bytes());change=json.loads((HERE/"CHANGES.json").read_bytes())
    package=json.loads((HERE/"SOURCE_MANIFEST.json").read_bytes())
    require({p.name for p in HERE.iterdir()}=={r["path"] for r in package["files"]}|{"SOURCE_MANIFEST.json"},"complete author source")
    for r in package["files"]:
        v=(HERE/r["path"]).read_bytes()
        require(pin(v)=={k:r[k] for k in ("bytes","sha256")} and blob(v)==r["git_blob"],"author input")
    require(len(rows["rows"])==525 and rows["commit"]==change["proof"]["baseline"],"exact baseline")
    graph=a.output/"source";graph.mkdir()
    for r in rows["rows"]:
        q=a.baseline/r["path"];v=q.read_bytes()
        require(not q.is_symlink() and stat.S_IMODE(q.stat().st_mode)==0o644 and row(r["path"],v)==r,"complete source before: "+r["path"])
        write(graph,r["path"],v)
    before=inventory(graph);original={}
    for edit in change["edits"]:
        path=edit["path"];old=(graph/path).read_bytes();original.setdefault(path,old)
        a0=edit["old"].encode();a1=edit["new"].encode()
        require(old.count(a0)==1,"exact unique source boundary")
        write(graph,path,old.replace(a0,a1))
    for path,old in original.items():
        candidate=(graph/path).read_bytes();inverse=candidate
        for edit in reversed(change["edits"]):
            if edit["path"]!=path:continue
            a0=edit["old"].encode();a1=edit["new"].encode()
            require(inverse.count(a1)==1,"exact inverse boundary")
            inverse=inverse.replace(a1,a0)
        require(inverse==old,"whole original assembly restored")
        declared=next(r for r in change["proof"]["changes"] if r["path"]==path)
        require(dict(**pin(candidate),git_blob=blob(candidate))==declared["after"],"exact candidate output")
    for q in sorted(HERE.iterdir()):write(graph,"authoring/publication_runtime_v1/"+q.name,q.read_bytes())
    binding=json.loads((graph/"native/runtime_mcp_sources.json").read_bytes())
    require(binding["sources"]=={p:{k:r[k] for k in ("bytes","sha256")} for p,r in before.items() if p!="native/runtime_mcp_sources.json"},"full baseline closure")
    current=inventory(graph);binding["sources"]={p:{k:r[k] for k in ("bytes","sha256")} for p,r in current.items() if p!="native/runtime_mcp_sources.json"}
    binding["publication_session_runtime_extension"]=change["proof"]
    write(graph,"native/runtime_mcp_sources.json",ENC(binding))
    final=inventory(graph);require(len(final)==530,"exact successor source closure")
    require(all(final[p]==r for p,r in before.items() if p not in set(original)|{"native/runtime_mcp_sources.json"}),"all other original source bytes")
    require(all(final[p]==r for p,r in before.items() if p.endswith(".hepta")),"all HIA bytes unchanged")
    sys.path.insert(0,str(graph/"scripts"));import public_nine_build as build
    require(Path(build.__file__).resolve()==graph/"scripts/public_nine_build.py","exact builder");build.source_check(graph)
    modes=[("production",{}),("journal",dict(private_pump_fixture=True)),("trace",dict(private_pump_fixture=True,private_pump_trace=True)),("publisher",dict(private_pump_fixture=True,private_pump_trace=True,private_publication_trace=True)),("carrier",dict(private_fixture=True))]
    actual=[];asm=a.output/"assembly";asm.mkdir()
    for name,kwargs in modes:
        source=build.adapter_source(graph,**kwargs).encode();write(asm,name+".S",source)
        for i,argv in enumerate((["as","--64","-o",str(asm/(name+".o")),str(asm/(name+".S"))],["nm","-u",str(asm/(name+".o"))],["readelf","-r",str(asm/(name+".o"))],["objdump","-drw","-Mintel",str(asm/(name+".o"))])):
            start=time.monotonic();proc=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
            write(asm,name+"-"+str(i)+".stdout",proc.stdout);write(asm,name+"-"+str(i)+".stderr",proc.stderr)
            receipt=dict(argv=argv,exit_code=proc.returncode,elapsed_seconds=time.monotonic()-start,timeout_seconds=30,stdout=pin(proc.stdout),stderr=pin(proc.stderr))
            write(asm,name+"-"+str(i)+".json",ENC(receipt));actual.append(receipt)
            require(proc.returncode==0 and not proc.stderr,"actual assembler inspection")
            if i==1:require(not proc.stdout,"no undefined symbol")
            if i==2:require(b"There are no relocations" in proc.stdout,"no relocation")
            if i==3 and name!="carrier":
                text=proc.stdout.decode()
                for symbol in ("pump_initialize_shared","pump_begin_finish","pump_finish_service","pump_finish_runtime","pump_finish_storage"):
                    require("<"+symbol+">:" in text,"actual private native boundary: "+symbol)
                part=text[text.index("<pump_trace_publication>:"):text.index("<pump_trace_emit>:",text.index("<pump_trace_publication>:"))]
                matches=[line for line in part.splitlines() if "r9d" in line and "0x4000" in line]
                require(len(matches)==1 and "41 b9 00 40 00 00" in matches[0] and "PTR" not in matches[0],"retained explicit immediate")
    report=dict(status="SESSION_RUNTIME_SOURCE_AND_FIVE_BOUNDARIES_PASS",source_files=len(final),rows=list(final.values()),delta={p:dict(before=before.get(p),after=r) for p,r in final.items() if before.get(p)!=r},application_executed=False,hia_executed=False,rust_executed=False,public_async_qualified=False,actual_processes=actual)
    write(a.output,"AUTHOR.json",ENC(report))
    b=(graph/"native/runtime_mcp_sources.json").read_bytes()
    print("SESSION_RUNTIME_BINDING_EXPORT "+json.dumps(dict(path="native/runtime_mcp_sources.json",utf8=b.decode(),**pin(b),git_blob=blob(b)),sort_keys=True))
    print("SESSION_RUNTIME_AUTHOR_EXPORT "+json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
