"""Independently invert the complete SDK reader/layout adaptation and admit all new source bytes."""
from pathlib import Path
import hashlib,json
def require(ok,text):
    if not ok:raise ValueError(text)
def identity(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),"mode":"100644"}
def verify(package):
    package=Path(package).resolve(strict=True)
    proof=json.loads((package/"ci/EXTRACT_ADAPTERS.json").read_bytes())
    for name,row in proof["files"].items():
        before=(package/row["original"]).read_bytes();after=(package/name).read_bytes()
        require(identity(before)==row["before"] and identity(after)==row["after"],"adapter full source identity: "+name)
        restored=after.decode()
        for change in reversed(row["changes"]):
            require(restored.count(change["after"])==change["count"],"adapter inverse multiplicity: "+name)
            restored=restored.replace(change["after"],change["before"])
        require(restored.encode()==before,"complete source inverse: "+name)
    author=json.loads((package/"source_origin/AUTHOR.json").read_bytes())
    rows=json.loads((package/"INPUTS.json").read_bytes())["installed_graph_rows"]
    actual={r["path"]:{k:r[k] for k in ("bytes","sha256")} for r in rows}
    require(len(actual)==452 and actual==author["source_files"],"complete authored graph identity")
    require(author["baseline_source"]=="27342064731d701925bfd202cd97d33bdd27bcee"
        and author["source_binding_sha256"]=="348e86674cb61cb4fa2f88466df70a010bfbbdb654f7289778e1f6e223e6f80d"
        and author["native_or_rust_executions"]==0,"mixed-opener catalog source provenance")
    author=json.loads((package/"source_origin/RETAINED_CUSTOM_AUTHOR.json").read_bytes())
    require(len(author["source_files"])==436,"retained complete typed-custom source")
    require(author["baseline_source"]=="9250e574640dc4a9050f6b7b42275ef9809317bd"
        and author["source_binding_sha256"]=="22c8c5a0fa49b852d9144356b335cccedc5b0b2b37e43bf027336ff5f8762b5f"
        and author["native_or_rust_executed"] is False,"typed CustomRequest source provenance")
    author=json.loads((package/"source_origin/RETAINED_OWNER_CLEAR_AUTHOR.json").read_bytes())
    require(len(author["source_files"])==432 and author["source_binding_sha256"]=="dd5af0b52523e7652ca4a763fef0f8c1865b773b07f2cf6dd05b42e9e5c66438","exact retained caller-clear source inventory")
    require(author["baseline_source"]=="36a061b94f4cb607912fe6f7c14b3c1a0014c466"
        and author["baseline_binding"]=="8016acfef110430ce56aaac1b956fc56a27463fd3362d29280620f185013573d"
        and author["native_or_rust_executed"] is False,"exact caller-clear source provenance")
    author=json.loads((package/"source_origin/RETAINED_REPAIR_AUTHOR.json").read_bytes())
    require(author["baseline_commit"]=="a521066dfa07db38e6a22bd2f03d1dae3c203cc2"
        and author["sdk_baseline_commit"]=="fa2aed97cf22b720d85bd8d08b720aeadba3c4d6"
        and author["baseline_binding_sha256"]=="2c423747b2827c3a6d0993b89583c47691640ea44fcf5f77e6c0ed2aaaf0dc70"
        and author["runtime_hia_images"]==118 and author["direct_hia_members"]==110
        and author["extract_slots"]==[59,60,61,62,63]
        and author["native_semantics_executed"] is False,"exact source-only extension provenance")
    return {"status":"EXTRACT_BUILD_SOURCE_ADAPTERS_PASS","files":len(proof["files"]),"graph_files":452,"native_or_rust_executed":False}
