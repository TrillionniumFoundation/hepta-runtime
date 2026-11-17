"""Exact request-owned fence source patch and full 486-file byte closure; no HIA execution."""
from pathlib import Path
import copy,json,shutil
from read_primitives import *
HERE=Path(__file__).resolve().parent
def source(root,*,baseline=False):
    root=Path(root);index=doc(HERE/("BASE_ROWS.json" if baseline else "PRODUCTION_ROWS.json"))
    wanted={r["path"]:{k:r[k] for k in ("bytes","sha256")} for r in index["rows"]}
    require(len(wanted)==486 and set(wanted)=={p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()},"complete successor source inventory")
    for name,identity in wanted.items():require(pin(root/name)==identity,"successor source bytes: "+name)
    require(pin(root/"native/runtime_mcp_sources.json")==index["binding"],"successor binding")
    return wanted
def apply(previous,output):
    before=Path(previous)/"source";source(before,baseline=True)
    require(not output.exists(),"fresh successor source")
    shutil.copytree(before,output)
    for p in sorted((HERE/"overlay").rglob("*")):
        if p.is_file():shutil.copyfile(p,output/p.relative_to(HERE/"overlay"))
    source(output)
def prove(previous,root):
    before=Path(previous)/"source";root=Path(root)
    old=source(before,baseline=True);now=source(root)
    reader_before=raw(HERE/"read_successor_before.py");reader_current=reader_before
    for row in doc(HERE/"READER_PATCHES.json")["edits"]:
        old_part,new_part=row["before"].encode(),row["after"].encode()
        require(reader_current.count(old_part)==1,"unique full graph reader adaptation")
        reader_current=reader_current.replace(old_part,new_part)
    require(reader_current==raw(HERE/"read_successor.py"),"complete graph reader exact source adaptation")
    changed=sorted(k for k in now if now[k]!=old[k])
    expected=["native/runtime_mcp_sources.json","scripts/runtime_mcp_filesystem_fence_bridge.S","scripts/runtime_mcp_task_storage.S"]
    require(changed==expected,"exact two mechanical owner changes and binding")
    proof=doc(HERE/"SOURCE_REPAIR.json")
    patches=proof["patches"];require(len(patches)==7,"exact seven mechanical splices")
    for name in expected[1:]:
        a=raw(before/name);b=raw(root/name);current=a
        selected=[p for p in patches if p["path"]==name]
        for row in selected:
            previous_bytes,current_bytes=row["before"].encode(),row["after"].encode()
            require(current.count(previous_bytes)==1,"unique mechanical source before")
            current=current.replace(previous_bytes,current_bytes)
        require(current==b,"complete mechanical forward transform")
        for row in reversed(selected):
            previous_bytes,current_bytes=row["before"].encode(),row["after"].encode()
            require(current.count(current_bytes)==1,"unique mechanical source inverse")
            current=current.replace(current_bytes,previous_bytes)
        require(current==a,"complete mechanical inverse bytes")
    old_binding=doc(before/"native/runtime_mcp_sources.json");new_binding=doc(root/"native/runtime_mcp_sources.json")
    restored=copy.deepcopy(new_binding);extension=restored.pop("request_owned_fence_extension")
    for name in expected[1:]:
        require(restored["sources"][name]==pin(root/name),"mechanical owner bound bytes")
        restored["sources"][name]=old_binding["sources"][name]
    require(restored==old_binding,"all other complete root binding fields unchanged")
    require(extension["pending_fields"]=={"descriptor":3584,"continuation":3648,"installed":3712,"ownership":3720,"native":3728,"hub":3736,"range_end_exclusive":3744},"fixed private node field ownership")
    hia=[k for k in old if k.endswith(".hepta")]
    require(len(hia)==138 and all(raw(before/name)==raw(root/name) for name in hia),"all138 HIA source files exact retained bytes")
    require(all(raw(before/name)==raw(root/name) for name in old if name not in expected),"all483 other production files unchanged")
    return {"status":"EXACT_REQUEST_OWNED_FENCE_SOURCE_PASS","source_commit":doc(HERE/"PRODUCTION_ROWS.json")["commit"],"changed":changed,"mechanical_splices":7,"retained_hia_source_files":138,"retained_other_source_files":483,"complete_inverse_mechanical_bytes":True,"pending_node_range":[3584,3744],"native_or_rust_executions":0,"actual_wait_or_multi_permit_qualified":False}
