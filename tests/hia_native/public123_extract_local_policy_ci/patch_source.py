"""Exact source repair and complete source/AST inverses; never execute HIA or Rust."""
from pathlib import Path
import ast,copy,json,shutil,sys
from read_primitives import *
import source_support as support,read_graph
HERE=Path(__file__).resolve().parent
def source(root):
    root=Path(root);index=doc(HERE/"PRODUCTION_ROWS.json")
    wanted={r["path"]:{k:r[k] for k in ("bytes","sha256")} for r in index["rows"]}
    require(len(wanted)==486 and set(wanted)=={p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()},"complete successor source inventory")
    for name,identity in wanted.items():require(pin(root/name)==identity,"successor source bytes: "+name)
    require(pin(root/"native/runtime_mcp_sources.json")==index["binding"],"successor binding")
    return wanted
def apply(retained,output):
    before=Path(retained)/"capture/composition/source";read_graph.source(retained)
    require(not output.exists(),"fresh successor source")
    shutil.copytree(before,output)
    for p in sorted((HERE/"overlay").rglob("*")):
        if p.is_file():shutil.copyfile(p,output/p.relative_to(HERE/"overlay"))
    source(output)
def prove(retained,root,hepta):
    before=Path(retained)/"capture/composition/source";root=Path(root)
    old_index=read_graph.source(retained);now=source(root)
    changed=sorted(k for k in now if now[k]!=old_index[k])
    require(changed==sorted(["native/extract_gateway.hepta","authoring/public_extract/gateway.pseudo","native/extract_gateway_composition.json","native/runtime_mcp_sources.json","scripts/hia_native_runtime_mcp_build.py"]),"exact five changes from retained e5, four from latest10ed")
    proof=doc(HERE/"SOURCE_REPAIR.json")
    for row in proof["source_patches"]:
        a,b=raw(before/row["path"]),raw(root/row["path"])
        old,new=row["before_text"].encode(),row["after_text"].encode()
        require(a.count(old)==1 and a.replace(old,new)==b and b.count(new)==1 and b.replace(new,old)==a,"exact bidirectional source patch")
    api=support.tools(Path(hepta));assemble,render=api[3:]
    a=assemble(raw(before/"native/extract_gateway.hepta")).as_dict()
    b=assemble(raw(root/"native/extract_gateway.hepta")).as_dict()
    require(render(b).encode()==raw(root/"native/extract_gateway.hepta"),"complete HIA roundtrip")
    old={f["name"]:f for f in a["functions"]};new={f["name"]:f for f in b["functions"]}
    require(len(old)==37 and set(old)==set(new),"exact owner function inventory")
    require({k:v for k,v in a.items() if k!="functions"}=={k:v for k,v in b.items() if k!="functions"},"owner header")
    retained_functions={k:sha(support.CANON(v)) for k,v in old.items() if k!="f14"}
    require(all(old[k]==new[k] for k in retained_functions),"all36 other owner functions exact")
    before_blocks={x["id"]:x for x in old["f14"]["blocks"]};after_blocks={x["id"]:x for x in new["f14"]["blocks"]}
    require(list(before_blocks)==list(after_blocks),"f14 block inventory")
    require({k:v for k,v in old["f14"].items() if k!="blocks"}=={k:v for k,v in new["f14"].items() if k!="blocks"},"f14 signature/effects")
    require(all(before_blocks[k]==after_blocks[k] for k in before_blocks if k!="b5"),"all other f14 blocks exact including Remote")
    restored=copy.deepcopy(after_blocks["b5"]);ops=restored["ops"]
    injected={"op":"const","args":[],"attrs":{"value":1},"out":[{"name":"v166","type":"u64"}]}
    at=next(i for i,x in enumerate(ops) if x["out"]==[{"name":"v166","type":"u64"}])
    require(ops[at]==injected and ops[at+1]=={"op":"call","args":["v82","v108","v166"],"attrs":{"function":"f35"},"out":[{"name":"v109","type":"u64"}]},"Local fixed opcode1 instruction")
    del ops[at];ops[at]["args"][2]="v92"
    require(restored==before_blocks["b5"],"complete inverse f14/b5")
    previous=doc(before/"native/extract_gateway_composition.json");current=doc(root/"native/extract_gateway_composition.json")
    recovered=copy.deepcopy(current);repair=recovered.pop("fixed_local_policy_operation")
    require(repair["local_policy_operation"]==1 and repair["remote_write_flag_unchanged"] is True,"composition fixed Local operation")
    recovered["operations"]-=1;recovered["source"]=previous["source"]
    require(recovered==previous,"all other composition fields and u64 integers exact")
    require(current["source"]==pin(root/"native/extract_gateway.hepta"),"composition source identity")
    stats={"functions":len(new),"blocks":sum(len(f["blocks"]) for f in new.values()),"operations":sum(len(k["ops"]) for f in new.values() for k in f["blocks"])}
    require(stats=={"functions":37,"blocks":560,"operations":2313},"exact owner budget")
    target=raw(HERE/"target_server.rs")
    require(sha(target)=="0957f7d7d56ad76540a42ba82b33fc29a625bb186cece2a207a764ea8c5beb6f","original Rust target identity")
    start=target.index(b"fn enforce_runtime_path_spec(");end=target.index(b"\n#[tool_router]",start)
    target=target[start:end]
    require(b"fs::PathSource::Local(path) => {\n\t\t\t\truntime::config::check_local_path(&path).map_err(|error| error.to_string())?;\n\t\t\t}" in target,"actual Local branch checks both source and append")
    require(b"\t\t\t\t\twrite,\n" in target,"actual Remote flag retained")
    return {"status":"EXACT_LOCAL_POLICY_OPCODE_SOURCE_AST_PASS","source_commit":doc(HERE/"PRODUCTION_ROWS.json")["commit"],"changed_from_retained_e5":changed,"changed_from_latest10ed":[x["path"] for x in proof["changed"]],"retained_functions":retained_functions,"retained_other_f14_blocks":len(before_blocks)-1,"source":current["source"],"stats":stats,"local_policy_operation":1,"remote_flag_and_engine_unchanged":True,"complete_inverse_bytes_and_ast":True,"native_or_rust_executions":0}
