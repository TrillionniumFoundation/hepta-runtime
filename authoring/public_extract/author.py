"""Compose the frozen 118-HIA source graph; no native semantic execution."""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
import stat
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_support import SHA, CANON, ENCODE, identity, require, tools
from author_modules import controllers, frontend

BASELINE_PIN = "d836d1d46c37aeaaf4ab1f5c388186f77b3b1469a396fbdd8dfb28933bf6ddd4"
SHARED = {
 "native/local_read.hepta":"a4eacfcdae04233097a2d37ae15447b2e6e99dd5325e98b409b4404896786df0",
 "native/file_lock_key.hepta":"99174dd26e97882b65489e9f913a2a22663546dcc783a678c9f571458841ddce",
 "native/file_lock_state.hepta":"dd6d1e9938767ae6333af5267efbc684e23fd87d3def4e095ac914c80bbbcaa8",
 "native/editable_content.hepta":"3ca1dd3fe69191dae3eb4a6df0cc103cf8cb7e6000148bfa95f31c957be0cedd",
 "native/history.hepta":"e00f11f708239c1c8b4ee06da7833433ef86427ebd77544fc9b46ce2b6eb44eb",
 "native/atomic_write.hepta":"bedb27429d970833db4800436511788eaae2bfaa5487b4c751a94f8e7cbe410b",
 "native/view_cache.hepta":"d363c2d3b06bf6d3de0ab20ad40ea3a090baf5d02fef9d280e54e6ef78c6cb01",
 "native/shell_capture_path.hepta":"ce3f9ab277ad16cdcfb27c860fc97203de5dc0790072da5ff5f186632f7c69c2",
 "native/shell_capture_mkdir.hepta":"251b0c83afea0a050c2a71644b2c8e3246c6039888366408c3b98beb17ccaff6",
 "native/view_error.hepta":"22254938e43feaebc8d24147f76c0aefdfc46b8574fad66d247ddafb2c209c5a",
 "native/line_endpoint.hepta":"10fc5fab68d2a59b74627743123c3f42ee828d6585c390ae73d13dda1a243423"}
COPIED = {
 "native/extract_body.hepta":"c68ecd06b8ce4a4fef46a65880e78112560c84bf7cd0ca39f9219fa8ca10eb42",
 "native/extract_data.hepta":"f669c391474a8443440a39893d9aed4a597e1f33339a3a811e31f53bee0f4263",
 "native/extract_line_verify.hepta":"9b944c8526c496d308181c6c9a5ffbd0369acbf702fc9980ed5cba6764275a0b"}

def physical(root, name):
    relative = Path(name)
    require(not relative.is_absolute() and ".." not in relative.parts and relative.as_posix() == name, "source path escaped")
    path = root / relative
    require(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), "source is not a physical regular file")
    return path.read_bytes()

def admitted_author(author, profile_sha256):
    raw = physical(author, "AUTHOR_SOURCE.json")
    require(SHA(raw) == profile_sha256, "source author profile differs")
    profile = json.loads(raw)
    require(profile["schema"] == "hepta.runtime.public-extract-author-source.v1", "author profile schema differs")
    for name,pin in profile["files"].items():
        require(identity(physical(author,name)) == pin, "author source changed: " + name)
    return profile

def admitted_base(base, author):
    raw = physical(base,"native/runtime_mcp_sources.json")
    require(SHA(raw) == BASELINE_PIN, "default111 baseline binding differs")
    md = json.loads(raw)
    data = {"native/runtime_mcp_sources.json":raw}
    for name,pin in md["sources"].items():
        data[name] = physical(base,name)
        require(identity(data[name]) == pin, "baseline source bytes differ: " + name)
    rows = json.loads(physical(author,"BASELINE.json"))["files"]
    require(len(rows) == len(data) == 390, "baseline source inventory differs")
    require({r["path"]:{k:r[k] for k in ("bytes","sha256")} for r in rows} ==
            {name:identity(value) for name,value in data.items()}, "baseline source index differs")
    for name,pin in SHARED.items():
        require(SHA(data[name]) == pin, "shared extract owner changed: " + name)
    return md,data

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("baseline","hepta","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--author-profile-sha256",required=True)
    a=p.parse_args()
    author=Path(__file__).resolve().parent
    profile=admitted_author(author,a.author_profile_sha256)
    baseline,source=admitted_base(a.baseline.resolve(strict=True),author)
    require(not a.output.exists(), "source author output already exists")
    api=tools(a.hepta)
    generated,owners=controllers(api,source,author)
    front,front_proof=frontend(api,source,author)
    generated.update(front)
    grouped={}
    for row in json.loads(physical(author,"source_edits.json")):
        grouped.setdefault(row["path"],[]).append(row)
    patch_proof={}
    for path,rows in grouped.items():
        current=source[path].decode()
        for row in rows:
            require(current.count(row["before"]) == 1 and row["before"] != row["after"], "nonunique source anchor: "+path)
            current=current.replace(row["before"],row["after"],1)
        expected=physical(author,"overlay/"+path)
        require(current.encode() == expected, "reviewed overlay differs from anchored source edits: "+path)
        patch_proof[path]={"before":identity(source[path]),"after":identity(expected),"edits":len(rows)}
    for path in (author/"overlay").rglob("*"):
        if path.is_file():
            name=path.relative_to(author/"overlay").as_posix()
            raw=physical(author,"overlay/"+name)
            require(name not in generated, "mechanical overlay overwrites generated HIA")
            if name in source:
                require(name in grouped, "baseline changed without an anchored edit")
            generated[name]=raw
    for name,pin in COPIED.items():
        require(SHA(generated[name]) == pin, "qualified extract body source changed")
    source.update(generated)
    author_names=["author.py","source_support.py","author_modules.py","params.pseudo","gateway.pseudo",
                  "caller.pseudo","adapter.pseudo","frontend.pseudo","source_edits.json","BASELINE.json","README.md"]
    for name in author_names:
        source["authoring/public_extract/"+name]=physical(author,name)
    report={"schema":"hepta.runtime.public-extract-source-assembly.v1","status":"SOURCE_ASSEMBLED",
        "baseline_commit":"05044de882e3c72f1f9bd243c85d15f203d62125","baseline_binding_sha256":BASELINE_PIN,
        "author_profile_sha256":a.author_profile_sha256,"owners":owners,"frontend":front_proof,
        "source_edits":patch_proof,"shared_original_owner_sources":SHARED,"copied_qualified_body_sources":COPIED,
        "direct_hia_members":110,"packed_hia_members":8,"physical_containers":111,"runtime_hia_images":118,
        "extract_slots":[59,60,61,62,63],"same_process_hub":400,"callable_context":456,"caller_installation":464,
        "catalog_integration_pending":True,"native_semantics_executed":False,"rust_executed":False,
        "public_handler_qualified":False,"full_async_cancellation_qualified":False,
        "remote_qualified":False,"whole_runtime_replaced":False,"main_advanced":False}
    source["native/runtime_mcp_extract_source.json"]=ENCODE(report)
    binding=copy.deepcopy(baseline)
    binding["current_layout"].update(direct_hia_members=110,descriptor_slots=64,expected_physical_containers=111,
        expected_runtime_hia_images=118,extract_slots=[59,60,61,62,63],reserved_successor_slots=[],
        extract_context_offset=456,extract_install_offset=464,extract_local_body_only=True,
        extract_catalog_integration_pending=True)
    binding["qualification"].update({"extract_public":"NOT_RUN","full_sdk":False,"async":False})
    binding["extract_public_extension"]={"source_proof":"native/runtime_mcp_extract_source.json",
        "baseline_binding_sha256":BASELINE_PIN,"source_profile_sha256":a.author_profile_sha256,
        "native_semantics_executed":False,"rust_executed":False,"public_handler_qualified":False}
    del source["native/runtime_mcp_sources.json"]
    binding["sources"]={name:identity(raw) for name,raw in sorted(source.items())}
    source["native/runtime_mcp_sources.json"]=ENCODE(binding)
    a.output.mkdir(parents=True)
    for name,raw in source.items():
        path=a.output/"source"/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
    report.update(source_binding=identity(source["native/runtime_mcp_sources.json"]),
        complete_source_files=len(source),source_files={name:identity(raw) for name,raw in sorted(source.items())})
    (a.output/"AUTHOR.json").write_bytes(ENCODE(report))
    require(admitted_author(author,a.author_profile_sha256)==profile,"author source mutated")
    admitted_base(a.baseline.resolve(strict=True),author)
    print(json.dumps({k:v for k,v in report.items() if k not in ("owners","frontend","source_files")},sort_keys=True))

if __name__=="__main__":
    main()
