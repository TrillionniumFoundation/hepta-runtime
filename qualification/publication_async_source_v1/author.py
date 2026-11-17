#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact source composition only; never execute HIA or original application code."""
from pathlib import Path,PurePosixPath
import argparse,copy,hashlib,importlib.util,json,re,stat,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
BASE="320862f03902153b5c804d1b68142126a9c7a606"
HEPTA="d3e2c90173cf733e42b299d0c4274df4b593a12f"
PIN=lambda raw:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
BLOB=lambda raw:hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2)+"\n").encode()
CAN=lambda v:json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def require(ok,message):
    if not ok:raise ValueError(message)
def decode(raw):
    def pairs(items):
        d={}
        for key,value in items:
            require(key not in d,"duplicate JSON key");d[key]=value
        return d
    return json.loads(raw,object_pairs_hook=pairs)
def owned(root,name):
    p=PurePosixPath(name)
    require(not p.is_absolute() and ".." not in p.parts and p.as_posix()==name,"source path")
    here=root
    for part in p.parts:
        here=here/part;require(not here.is_symlink(),"source symlink")
    require(stat.S_ISREG(here.stat().st_mode),"source regular file")
    return here
def package():
    m=decode((HERE/"SOURCE_MANIFEST.json").read_bytes())
    actual={p.relative_to(HERE).as_posix() for p in HERE.rglob("*") if p.is_file()}
    require(actual=={r["path"] for r in m["files"]}|{"SOURCE_MANIFEST.json"},"author package set")
    for r in m["files"]:
        p=owned(HERE,r["path"]);raw=p.read_bytes()
        require(PIN(raw)=={k:r[k] for k in ("bytes","sha256")} and BLOB(raw)==r["git_blob"]
            and stat.S_IMODE(p.stat().st_mode)==0o644,"author package identity: "+r["path"])
        if p.suffix==".py":compile(raw,str(p),"exec")
    return PIN((HERE/"SOURCE_MANIFEST.json").read_bytes())
def inventory(root):
    out={}
    for p in sorted(root.rglob("*")):
        require(not p.is_symlink(),"generated source symlink")
        if p.is_file():
            require(stat.S_ISREG(p.stat().st_mode),"generated ordinary source")
            raw=p.read_bytes();out[p.relative_to(root).as_posix()]=dict(**PIN(raw),git_blob=BLOB(raw),mode=format(p.stat().st_mode,"o"))
    return out
def fn(raw,index):
    found=re.findall(rb"^fn f"+str(index).encode()+rb"\(.*?^end\n",raw,re.M|re.S)
    require(len(found)==1,"exact HIA function text")
    return found[0]
def write(root,path,raw):
    p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
def apply(baseline,hepta,output):
    identity=package();require(not output.exists(),"fresh generated source")
    output.mkdir(parents=True)
    rows=decode((HERE/"BASE_SOURCE_ROWS.json").read_bytes())
    require(rows["commit"]==BASE and len(rows["rows"])==486,"unique shared production baseline")
    for row in rows["rows"]:
        raw=owned(baseline,row["path"]).read_bytes()
        require(PIN(raw)=={k:row[k] for k in ("bytes","sha256")} and BLOB(raw)==row["git_blob"],"baseline exact byte: "+row["path"])
        require(format((baseline/row["path"]).stat().st_mode,"o")==row["mode"],"baseline mode")
        write(output,row["path"],raw)
    old=inventory(output)
    original_binding=decode((output/"native/runtime_mcp_sources.json").read_bytes())
    require(original_binding["sources"]=={p:{k:r[k] for k in ("bytes","sha256")} for p,r in old.items() if p!="native/runtime_mcp_sources.json"},"entire baseline binding")
    overlay=HERE/"overlay"
    for path in sorted(overlay.rglob("*")):
        if path.is_file():write(output,path.relative_to(overlay).as_posix(),path.read_bytes())
    changes=decode((HERE/"MECHANICAL.json").read_bytes())
    for path,change in changes["files"].items():
        before=(baseline/path).read_text();current=before
        require(PIN(before.encode())==change["before"],"mechanical source identity")
        for splice in change["steps"]:
            count=splice.get("count",1)
            require(current.count(splice["old"])==count,"exact mechanical anchor: "+path)
            current=current.replace(splice["old"],splice["new"])
        require(current.encode()==(output/path).read_bytes(),"exact mechanical result: "+path)
        inverse=current
        for splice in reversed(change["steps"]):
            count=splice.get("count",1)
            require(inverse.count(splice["new"])==count,"unique reverse anchor: "+path)
            inverse=inverse.replace(splice["new"],splice["old"])
        require(inverse==before,"whole mechanical inverse")
    sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    def asts(raw):return {f["name"]:f for f in assemble_program(raw).as_dict()["functions"]}
    caller0=(baseline/"native/text_publication_call.hepta").read_bytes()
    caller1=(output/"native/text_publication_call.hepta").read_bytes()
    caller_wrapper=(HERE/"caller_cancel_wrapper.hia").read_bytes()
    require(caller1==caller0.replace(fn(caller0,4),caller_wrapper)+fn(caller0,4).replace(b"fn f4(",b"fn f43(",1),
        "caller exact wrapper/relocated body")
    ca,cb=asts(caller0),asts(caller1)
    require(len(ca)==43 and len(cb)==44 and set(cb)==set(ca)|{"f43"},"caller exact function set")
    for name in ca:
        if name!="f4":require(ca[name]==cb[name],"unchanged caller AST: "+name)
    copied=copy.deepcopy(ca["f4"]);copied["name"]="f43"
    require(copied==cb["f43"],"relocated whole caller AST")
    require(cb["f4"]==asts(b"hia-asm.v1 hepta.hia.program.v8 wrapper\n"+caller_wrapper)["f4"],"new caller wrapper")
    front0=(baseline/"native/runtime_mcp.hepta").read_bytes()
    front1=(output/"native/runtime_mcp.hepta").read_bytes()
    patch=decode((HERE/"FRONTEND_PATCH.json").read_bytes())
    oldf=fn(front0,6)
    require(oldf.count(patch["old"].encode())==1,"frontend exact child15 guard")
    newf=oldf.replace(patch["old"].encode(),patch["new"].encode())
    require(front1==front0.replace(oldf,newf),"frontend only exact child16 admission")
    fa,fb=asts(front0),asts(front1)
    require(len(fa)==len(fb)==97 and set(fa)==set(fb),"frontend function set")
    for name in fa:
        if name!="f6":require(fa[name]==fb[name],"unchanged frontend AST: "+name)
    worker=(output/"native/publication_worker.hepta").read_bytes()
    require(PIN(worker)==dict(bytes=82810,sha256="a81ec08a77b61bd100b5bd4a6737d2c41296d6d266019a1ec9e8e867d27af0ed"),"qualified worker HIA")
    require(PIN((output/"scripts/publication_worker.S").read_bytes())==dict(bytes=23720,sha256="2a2e31907c05ca837a8fc13dd7c6b3334b12dc6503bfd26b3cb32a06996859f9"),"qualified actual worker boundary")
    asts(worker)
    # Python's unbounded integers preserve every u64 constant in old metadata.
    # No JavaScript JSON model participates in any composition transformation.
    common=dict(schema="hepta.runtime.publication-async-source.v1",baseline=BASE,
        baseline_binding=rows["binding"],worker_qualification="840522dd42ff3332158f0cccad802425f3708a26",
        native_worker_only_qualified=True,public_async_qualified=False,full_sdk=False,
        descriptors=[64,65,66,67,68],await_edges=[[18,64],[64,66],[66,67]],
        process_pool_hub_offset=216,pool_limit=512,pending_node_span=[1184,1896],
        preserved_fence_span=[3584,3744],preserved_scope_context_span=[3744,3888],
        shared_lease7_cache8=True,notification_cancel_drops_future=False,
        caller_drop_skips_post_await_forget=True,blocking_body_survives_caller_drop=True)
    cpath="native/text_publication_call_composition.json"
    comp=decode((baseline/cpath).read_bytes());before_comp=copy.deepcopy(comp)
    comp.update(source=PIN(caller1),functions=len(cb),
        blocks=sum(len(f["blocks"]) for f in cb.values()),
        operations=sum(len(b["ops"]) for f in cb.values() for b in f["blocks"]),
        function_sha256={name:hashlib.sha256(CAN(f)).hexdigest() for name,f in cb.items()})
    comp["aliases"]["retained_after_body"]="f43"
    comp["publication_async_extension"]=dict(common,retained_ast_functions=sorted(set(ca)-{"f4"}),
        relocation={"f4":"f43"},cancel_code=4294967287,
        cancel_order=["actual_worker_Drop","actual_Scope_op8","actual_fence_release","frontend_silent"])
    write(output,cpath,ENC(comp))
    fpath="native/runtime_mcp_composition.json"
    comp=decode((baseline/fpath).read_bytes())
    comp.update(source_bytes=len(front1),source_sha256=PIN(front1)["sha256"],
        function_sha256={name:hashlib.sha256(CAN(f)).hexdigest() for name,f in fb.items()})
    comp["publication_async_extension"]=dict(common,changed_functions=["f6"],retained_ast_functions=sorted(set(fa)-{"f6"}),
        added_cancel_child=16,existing_extract_cancel_child=15,complete_cancelled_only=True)
    write(output,fpath,ENC(comp))
    # Keep the complete source-only author and its exact inputs portable.
    for path in sorted(HERE.rglob("*")):
        if path.is_file():write(output,"authoring/public_publication_async_v1/"+path.relative_to(HERE).as_posix(),path.read_bytes())
    write(output,"native/publication_worker_component.json",ENC(dict(common,
        worker_source=PIN(worker),worker_boundary=PIN((output/"scripts/publication_worker.S").read_bytes()),
        runtime_hia_images=124,direct_hia_images=116,packed_hia_images=8,physical_images=117,
        descriptor_count=69,descriptor_base=8192,engine_bytes=16384,
        production_observer=False,private_observer_fd=6)))
    fresh=inventory(output);new_sources={p:{k:r[k] for k in ("bytes","sha256")} for p,r in fresh.items() if p!="native/runtime_mcp_sources.json"}
    binding=copy.deepcopy(original_binding);binding["sources"]=new_sources
    binding["publication_async_extension"]=common
    write(output,"native/runtime_mcp_sources.json",ENC(binding))
    final=inventory(output)
    require(set(old)<=set(final),"no existing source removed")
    changed={p:dict(before=old.get(p),after=r) for p,r in final.items() if old.get(p)!=r}
    return dict(status="PUBLICATION_ASYNC_SOURCE_ONLY_PASS",baseline=BASE,baseline_binding=rows["binding"],
        author_package=identity,files=len(final),rows=[dict(path=p,**r) for p,r in final.items()],
        delta=changed,caller_functions=44,frontend_functions=97,
        old_caller_ast_retained=42,old_frontend_ast_retained=96,caller_relocated_ast_retained=1,
        assembly_checked=False,hia_executed=False,original_executed=False,public_async_qualified=False,full_sdk=False)
def boundary(source,output):
    require(not output.exists(),"fresh assembler capture");output.mkdir()
    sys.path.insert(0,str(source/"scripts"))
    import public_nine_build as build
    require(Path(build.__file__).resolve()==source/"scripts/public_nine_build.py","exact generated builder import")
    checked=build.source_check(source)
    modes=[("production",{}),("journal",dict(private_pump_fixture=True)),
        ("trace",dict(private_pump_fixture=True,private_pump_trace=True)),
        ("publisher",dict(private_pump_fixture=True,private_pump_trace=True,private_publication_trace=True)),
        ("carrier",dict(private_fixture=True))]
    records=[]
    for name,kwargs in modes:
        raw=build.adapter_source(source,**kwargs).encode();(output/(name+".S")).write_bytes(raw)
        commands=[["as","--64","-o",str(output/(name+".o")),str(output/(name+".S"))],
                  ["nm","-u",str(output/(name+".o"))],["readelf","-r",str(output/(name+".o"))]]
        for index,argv in enumerate(commands):
            prefix=output/(name+"-"+str(index));begin=__import__("time").monotonic_ns()
            with Path(str(prefix)+".stdout").open("xb") as stdout,Path(str(prefix)+".stderr").open("xb") as stderr:
                proc=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=30,check=False)
            receipt=dict(argv=argv,returncode=proc.returncode,limit_seconds=30,elapsed_ns=__import__("time").monotonic_ns()-begin,
                stdout=PIN(Path(str(prefix)+".stdout").read_bytes()),stderr=PIN(Path(str(prefix)+".stderr").read_bytes()))
            Path(str(prefix)+".json").write_bytes(ENC(receipt));records.append(receipt)
            require(proc.returncode==0 and Path(str(prefix)+".stderr").read_bytes()==b"","actual assembler or symbol preflight failed: "+name)
            if index==1:require(Path(str(prefix)+".stdout").read_bytes()==b"","undefined boundary symbol")
            if index==2:require(b"There are no relocations" in Path(str(prefix)+".stdout").read_bytes(),"unexpected mechanical relocation")
    return dict(status="ALL_FIVE_FIXED_BOUNDARIES_ASSEMBLED",source=checked,processes=records,application_executed=False)
def main():
    p=argparse.ArgumentParser();p.add_argument("--baseline",type=Path,required=True);p.add_argument("--hepta",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();base=a.baseline.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.resolve()
    require(not out.exists(),"fresh author result");out.mkdir(parents=True)
    first=apply(base,hepta,out/"source")
    second=apply(base,hepta,out/"repeated")
    require(first==second and inventory(out/"source")==inventory(out/"repeated"),"whole portable source reproduction")
    (out/"SOURCE_ROWS.json").write_bytes(ENC(first))
    (out/"ASSEMBLY.json").write_bytes(ENC(boundary(out/"source",out/"assembly")))
    first["assembly_checked"]=True
    (out/"AUTHOR.json").write_bytes(ENC(first))
    for name in ("native/text_publication_call_composition.json","native/runtime_mcp_composition.json","native/publication_worker_component.json","native/runtime_mcp_sources.json"):
        raw=(out/"source"/name).read_bytes()
        print("PUBLICATION_SOURCE_EXPORT "+json.dumps(dict(path=name,**PIN(raw),git_blob=BLOB(raw),utf8=raw.decode()),sort_keys=True))
    print("PUBLICATION_AUTHOR_EXPORT "+json.dumps(first,sort_keys=True))
    print(json.dumps(dict(status=first["status"],files=first["files"],delta_files=len(first["delta"]),five_assembled_boundaries=True,hia_executed=False,original_executed=False),sort_keys=True))
if __name__=="__main__":main()
