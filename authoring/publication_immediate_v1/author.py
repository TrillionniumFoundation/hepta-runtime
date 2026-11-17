#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""One explicit assembler immediate; copy every unchanged source byte exactly."""
from pathlib import Path
import argparse,hashlib,json,shutil,stat,subprocess,sys,time
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
    rows=json.loads((HERE/"BASE_SOURCE_ROWS.json").read_bytes());change=json.loads((HERE/"CHANGE.json").read_bytes())
    package=json.loads((HERE/"SOURCE_MANIFEST.json").read_bytes())
    require({p.name for p in HERE.iterdir()}=={r["path"] for r in package["files"]}|{"SOURCE_MANIFEST.json"},"complete author source")
    for r in package["files"]:
        v=(HERE/r["path"]).read_bytes();require(pin(v)=={k:r[k] for k in ("bytes","sha256")} and blob(v)==r["git_blob"],"exact author input")
    require(len(rows["rows"])==521 and rows["commit"]==change["baseline"],"exact 521 input closure")
    graph=a.output/"source";graph.mkdir()
    for r in rows["rows"]:
        q=a.baseline/r["path"];v=q.read_bytes()
        require(not q.is_symlink() and stat.S_IMODE(q.stat().st_mode)==0o644 and row(r["path"],v)==r,"complete exact source before: "+r["path"])
        write(graph,r["path"],v)
    before=inventory(graph);path=change["path"];old=(graph/path).read_bytes()
    require(pin(old)=={k:change["before"][k] for k in ("bytes","sha256")} and blob(old)==change["before"]["git_blob"],"actual old boundary")
    require(old.count(change["old"].encode())==1,"unique old operand")
    new=old.replace(change["old"].encode(),change["new"].encode())
    require(pin(new)=={k:change["after"][k] for k in ("bytes","sha256")} and blob(new)==change["after"]["git_blob"],"exact new boundary")
    require(new.count(change["new"].encode())==1 and new.replace(change["new"].encode(),change["old"].encode())==old,"whole instruction inverse")
    write(graph,path,new)
    for q in sorted(HERE.iterdir()):write(graph,"authoring/publication_immediate_v1/"+q.name,q.read_bytes())
    binding=json.loads((graph/"native/runtime_mcp_sources.json").read_bytes())
    require(binding["sources"]=={p:{k:r[k] for k in ("bytes","sha256")} for p,r in before.items() if p!="native/runtime_mcp_sources.json"},"whole original closure")
    current=inventory(graph);binding["sources"]={p:{k:r[k] for k in ("bytes","sha256")} for p,r in current.items() if p!="native/runtime_mcp_sources.json"}
    binding["publication_trace_immediate_extension"]=dict(baseline=rows["commit"],path=path,before=change["before"],after=change["after"],all_hia_bytes_unchanged=True,public_async_qualified=False)
    write(graph,"native/runtime_mcp_sources.json",ENC(binding))
    final=inventory(graph);require(len(final)==525,"exact successor source closure")
    require(all(final[p]==r for p,r in before.items() if p not in (path,"native/runtime_mcp_sources.json")),"all other old sources unchanged")
    sys.path.insert(0,str(graph/"scripts"));import public_nine_build as build
    require(Path(build.__file__).resolve()==graph/"scripts/public_nine_build.py","exact build author")
    build.source_check(graph)
    modes=[("production",{}),("journal",dict(private_pump_fixture=True)),("trace",dict(private_pump_fixture=True,private_pump_trace=True)),("publisher",dict(private_pump_fixture=True,private_pump_trace=True,private_publication_trace=True)),("carrier",dict(private_fixture=True))]
    actual=[]
    asm=a.output/"assembly";asm.mkdir()
    for name,kwargs in modes:
        source=build.adapter_source(graph,**kwargs).encode();write(asm,name+".S",source)
        for i,argv in enumerate((["as","--64","-o",str(asm/(name+".o")),str(asm/(name+".S"))],["nm","-u",str(asm/(name+".o"))],["readelf","-r",str(asm/(name+".o"))],["objdump","-drw","-Mintel",str(asm/(name+".o"))])):
            start=time.monotonic();proc=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
            write(asm,name+"-"+str(i)+".stdout",proc.stdout);write(asm,name+"-"+str(i)+".stderr",proc.stderr)
            receipt=dict(argv=argv,exit_code=proc.returncode,elapsed_seconds=time.monotonic()-start,timeout_seconds=30,stdout=pin(proc.stdout),stderr=pin(proc.stderr))
            write(asm,name+"-"+str(i)+".json",ENC(receipt));actual.append(receipt)
            require(proc.returncode==0 and not proc.stderr,"exact assembler inspection")
            if i==1:require(not proc.stdout,"no undefined symbol")
            if i==2:require(b"There are no relocations" in proc.stdout,"no mechanical relocation")
            if i==3 and name!="carrier":
                text=proc.stdout.decode();start=text.index("<pump_trace_publication>:");end=text.index("<pump_trace_emit>:",start);part=text[start:end]
                matches=[line for line in part.splitlines() if "r9d" in line and "0x4000" in line]
                require(len(matches)==1 and "41 b9 00 40 00 00" in matches[0] and "PTR" not in matches[0],"actual immediate machine code")
                write(asm,name+"-checked-instructions.txt",part.encode())
    report=dict(status="EXACT_IMMEDIATE_SOURCE_AND_FIVE_BOUNDARIES_PASS",source_files=len(final),rows=list(final.values()),
        delta={p:dict(before=before.get(p),after=r) for p,r in final.items() if before.get(p)!=r},application_executed=False,hia_executed=False,rust_executed=False,public_async_qualified=False,actual_processes=actual)
    write(a.output,"AUTHOR.json",ENC(report))
    print("IMMEDIATE_BINDING_EXPORT "+json.dumps(dict(path="native/runtime_mcp_sources.json",utf8=(graph/"native/runtime_mcp_sources.json").read_text(),**pin((graph/"native/runtime_mcp_sources.json").read_bytes()),git_blob=blob((graph/"native/runtime_mcp_sources.json").read_bytes())),sort_keys=True))
    print("IMMEDIATE_AUTHOR_EXPORT "+json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
