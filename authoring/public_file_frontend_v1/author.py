"""Add explicit foreground file routes over the complete retained public graph.

All predecessor functions are either unchanged or retained at a new exact
function index. The old physical sources are never overwritten.
"""
from __future__ import annotations
import argparse, copy, importlib.util, json, pathlib, stat, subprocess, sys
sys.dont_write_bytecode = True

INPUTS = (
 "native/runtime_mcp.hepta", "native/runtime_mcp_composition.json",
 "native/runtime_mcp_catalog_ninth.hepta", "native/runtime_mcp_catalog_ninth_composition.json",
 "authoring/public_publication_v1/source_support.py",
 "authoring/public_publication_v1/inherited_catalog.py",
 "authoring/public_publication_v1/catalog_author.py",
 "authoring/public_extract/catalog_assets/actual/ordinary.typed.json",
 "authoring/public_extract/catalog_assets/actual/modern.typed.json",
 "authoring/public_mixed_opener/catalog_assets/actual/ordinary.typed.json",
 "authoring/public_file_frontend_v1/author.py",
 "authoring/public_file_frontend_v1/frontend.pseudo",
)
INSTALLED = {"host_list", "effective_config", "execution_shadow_admit", "view", "workdir",
 "directory_create", "file_move", "directory_move", "text_editor", "extract_lines", "text_file_write"}
ADDED = {"file_info", "binary_read"}

def capture(root, name):
    p=root/name
    if p.resolve(strict=True)!=p or not stat.S_ISREG(p.lstat().st_mode):
        raise ValueError("nonphysical input: "+name)
    return p.read_bytes(), stat.S_IMODE(p.stat().st_mode)

def frontend(api, source, z):
    original=source["native/runtime_mcp.hepta"]
    comp=json.loads(source["native/runtime_mcp_composition.json"])
    before=api[-2](original).as_dict()
    old={f["name"]:f for f in before["functions"]}
    z.require(comp["source_sha256"]==z.SHA(original) and comp["source_bytes"]==len(original),
              "complete frontend source differs")
    z.require(comp["function_sha256"]=={n:z.SHA(z.CANON(f)) for n,f in old.items()},
              "complete frontend AST index differs")
    names=dict(comp["functions"]); seed=copy.deepcopy(before)
    relocated={}
    for alias in ("tool_kind","prepare","after_tool"):
        retained="retained_file_"+alias
        z.require(retained not in names, "duplicate file predecessor")
        dest="f"+str(len(seed["functions"]))
        names[retained]=dest; relocated[names[alias]]=dest
        f=copy.deepcopy(old[names[alias]]);f["name"]=dest;seed["functions"].append(f)
    constants={"INVALID":0xffffffff,"CANCELLED":0xfffffff7,"MAXIMUM":(1<<64)-1,
               "FILE_WORD":z.WORD("file_inf"),"BINARY_WORD":z.WORD("binary_r"),
               "CATALOG_QUERY":z.WORD("HRMCD002"),"FILE_REQUEST":z.WORD("HFBGWQ01")}
    raw,aliases,proof=z.compile_delta(api,api[-1](seed).encode(),names,
        source["authoring/public_file_frontend_v1/frontend.pseudo"].decode(),
        constants,before["module"])
    after={f["name"]:f for f in api[-2](raw).as_dict()["functions"]}
    retained={}
    for n,f in old.items():
        actual=copy.deepcopy(after[relocated.get(n,n)]);actual["name"]=n
        z.require(actual==f, "complete original frontend inverse differs: "+n)
        retained[n]={"current":relocated.get(n,n),"ast_sha256":z.SHA(z.CANON(f))}
    proof.update(schema="hepta.runtime.file-frontend.v1",baseline=z.identity(original),
        complete_original_functions=retained,tools={"file_info":14,"binary_read":15},
        fixed_child=17,global_slot=71,catalog_profile=13,
        foreground_only=True,requested_observation_pool_qualified=False,
        native_executed=False,public_qualified=False)
    comp.update(source_sha256=z.SHA(raw),source_bytes=len(raw),functions=aliases,
        function_sha256={n:z.SHA(z.CANON(f)) for n,f in after.items()},
        file_extension=proof)
    return {"native/runtime_mcp_filebytes.hepta":raw,
        "native/runtime_mcp_filebytes_composition.json":z.ENCODE(comp)},proof

def catalog(api, source, z, assets, literal):
    chosen={};prefixes={};provenance={}
    for label in ("ordinary","modern"):
        name="authoring/public_extract/catalog_assets/actual/"+label+".typed.json"
        raw=source[name]; text,top,items=assets.exact_tools(raw)
        z.require(len(items)==113 and top["resultType"][3]=="complete","actual native catalog differs")
        chosen[label]=[(n,v) for n,v in items if n in INSTALLED|ADDED]
        z.require(len(chosen[label])==13 and {n for n,_ in chosen[label]}==INSTALLED|ADDED,
                  "actual native Tool set differs")
        if label=="ordinary":
            z.require(list(top)==["resultType","tools"],"ordinary prefix differs")
            prefixes[label]=b',"result":{'
        else:
            z.require(list(top)==["resultType","ttlMs","cacheScope","tools"]
                and top["ttlMs"][3]==0 and top["cacheScope"][3]=="public","modern prefix differs")
            prefixes[label]=b',"result":'+text[:top["tools"][0]].encode()
        provenance[label]={"whole_source":z.identity(raw),
            "selected":[{"name":n,**z.identity(v)} for n,v in chosen[label]]}
    z.require(chosen["ordinary"]==chosen["modern"],"Tools differ across SDK policy")
    present=chosen["ordinary"];old_items=[(n,v) for n,v in present if n in INSTALLED]
    common=b'"tools":['+b",".join(v for _,v in old_items)+b"]}}"
    _,_,absent_all=assets.exact_tools(source["authoring/public_mixed_opener/catalog_assets/actual/ordinary.typed.json"])
    absent=[(n,v) for n,v in absent_all if n in INSTALLED|ADDED]
    z.require({n for n,_ in absent}==INSTALLED-{"host_list","effective_config","execution_shadow_admit"}
              and len(absent)==8,"no-config file catalog unexpectedly differs")
    z.require(all(dict(present)[n]==v for n,v in absent),"no-config Tool bytes differ")
    offsets={};pos=9
    for n,v in old_items: offsets[n]=(pos,len(v));pos+=len(v)+1
    whole=b'"tools":['+b",".join(v for _,v in present)+b"]}}"
    filtered=b'"tools":['+b",".join(v for _,v in absent)+b"]}}"
    original=source["native/runtime_mcp_catalog_ninth.hepta"]
    comp=json.loads(source["native/runtime_mcp_catalog_ninth_composition.json"])
    z.require(comp["source_sha256"]==z.SHA(original) and comp["source_bytes"]==len(original),
              "complete catalog source differs")
    doc=api[-2](original).as_dict(); old={f["name"]:f for f in doc["functions"]}
    names=dict(comp["aliases"]);seed=copy.deepcopy(doc)
    retained_entry="f"+str(len(seed["functions"]))
    names["retained_file_catalog_entry"]=retained_entry
    f=copy.deepcopy(old[names["entry"]]);f["name"]=retained_entry;seed["functions"].append(f)
    nodes=[]
    for n,v in present:
        if n in ADDED: nodes.append(literal("file_literal_"+n,v))
    prefix0=len(prefixes["ordinary"]);prefix1=len(prefixes["modern"])
    z.require(prefix0==11 and prefix1==67, "retained prefix extent differs")
    lines=[
      "def configured_file_list(s: readbuf, o: mutbuf, w: mutbuf) -> u32:",
      "    if length(o) < 32:","        return RESOURCE",
      "    if length(s) != 40:","        return INVALID",
      "    modern = load(s, 16)","    present = load(s, 24)",
      "    if modern > 1 or present > 1 or load(s, 32) != 13:","        return INVALID",
      "    if length(w) < "+str(4096+len(common))+":",
      "        return grow(o, 1, "+str(4096+len(common))+")",
      "    prefix = choose(modern == 0, "+str(prefix0)+", "+str(prefix1)+")",
      "    size = prefix + choose(present == 1, "+str(len(whole))+", "+str(len(filtered))+")",
      "    if length(o) - 32 < size:","        return grow(o, 2, size + 32)",
      "    common_literal(w, 4096)",
      "    if modern == 0:","        prefix_0(o, 32)","    else:","        prefix_1(o, 32)",
      "    at = 32 + prefix","    copy_range(o, w, at, 4096, 9)",
      "    if present == 1:"]
    for selection,indent in ((present,"        "),(absent,"        ")):
        if selection is absent: lines.append("    else:")
        used=9; pieces=[common[:9]]
        for ix,(n,v) in enumerate(selection):
            if ix: lines.append(indent+"store(o, at + "+str(used)+", 44)");used+=1;pieces.append(b",")
            if n in offsets:
                off,size=offsets[n]
                lines.append(indent+"copy_range(o, w, at + "+str(used)+", "+str(4096+off)+", "+str(size)+")")
                pieces.append(common[off:off+size])
            else:
                lines.append(indent+"file_literal_"+n+"(o, at + "+str(used)+")");pieces.append(v)
            used+=len(v)
        lines.append(indent+"copy_range(o, w, at + "+str(used)+", "+str(4096+len(common)-3)+", 3)")
        pieces.append(common[-3:])
        z.require(b"".join(pieces)==(whole if selection is present else filtered),
                  "full native catalog copy inverse differs")
    lines+=["    return finish(o, size)",""]
    nodes.append("\n".join(lines))
    nodes.append("""def entry(s: readbuf, o: mutbuf, w: mutbuf) -> u32:
    if length(s) == 40:
        if load(s, 0) == CATALOG_QUERY and load(s, 8) == 7 and load(s, 32) == 13:
            return configured_file_list(s, o, w)
    return retained_file_catalog_entry(s, o, w)
""")
    raw,aliases,proof=z.compile_delta(api,api[-1](seed).encode(),names,"\n".join(nodes),
        {"INVALID":0xffffffff,"RESOURCE":0xfffffffe,"CATALOG_QUERY":z.WORD("HRMCD002")},doc["module"])
    after={f["name"]:f for f in api[-2](raw).as_dict()["functions"]}
    prior_entry=comp["aliases"]["entry"];retained={}
    for n,f in old.items():
        dest=retained_entry if n==prior_entry else n
        actual=copy.deepcopy(after[dest]);actual["name"]=n
        z.require(actual==f,"complete original catalog inverse differs: "+n)
        retained[n]={"current":dest,"ast_sha256":z.SHA(z.CANON(f))}
    proof.update(schema="hepta.runtime.file-catalog.v1",baseline=z.identity(original),
        complete_original_functions=retained,tools_present=[n for n,_ in present],
        tools_absent=[n for n,_ in absent],selected_present=z.identity(whole),
        selected_absent=z.identity(filtered),provenance=provenance,
        native_executed=False,public_qualified=False)
    comp.update(source_sha256=z.SHA(raw),source_bytes=len(raw),aliases=aliases,
        functions=proof["functions"],blocks=proof["blocks"],operations=proof["operations"],
        file_extension=proof)
    return {"native/runtime_mcp_catalog_filebytes.hepta":raw,
        "native/runtime_mcp_catalog_filebytes_composition.json":z.ENCODE(comp)},proof

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=pathlib.Path,required=True)
    p.add_argument("--hepta",type=pathlib.Path,required=True)
    p.add_argument("--receipt",type=pathlib.Path,required=True);a=p.parse_args()
    root=a.root.resolve(strict=True);snap={n:capture(root,n) for n in INPUTS}
    source={n:v[0] for n,v in snap.items()}
    imports=root/"authoring/public_publication_v1";sys.path.insert(0,str(imports))
    import source_support as z, inherited_catalog as assets, catalog_author
    z.require(subprocess.check_output(["git","-C",str(a.hepta),"rev-parse","HEAD"]).strip()
        ==b"d3e2c90173cf733e42b299d0c4274df4b593a12f","compiler source commit differs")
    api=z.tools(a.hepta)
    generated,front=frontend(api,source,z);more,cat=catalog(api,source,z,assets,catalog_author.literal)
    generated.update(more)
    for n,v in snap.items(): z.require(capture(root,n)==v,"author input changed: "+n)
    for n,raw in generated.items():
        target=root/n
        if target.exists(): z.require(target.read_bytes()==raw,"output already exists with different bytes: "+n)
        else: target.write_bytes(raw)
    for n,v in snap.items(): z.require(capture(root,n)==v,"terminal author input changed: "+n)
    report={"schema":"hepta.runtime.file-default-author.v1",
        "inputs":{n:{**z.identity(v[0]),"mode":v[1]} for n,v in snap.items()},
        "outputs":{n:z.identity(v) for n,v in generated.items()},
        "frontend":front,"catalog":cat,"public_qualified":False}
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    with a.receipt.open("xb") as f:f.write(z.ENCODE(report))
    print(json.dumps({"outputs":report["outputs"],"frontend":{k:front[k] for k in ("functions","blocks","operations")},
         "catalog":{k:cat[k] for k in ("functions","blocks","operations")}}))

if __name__=="__main__": main()
