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
    require(len(actual)==425 and actual==author["source_files"],"complete authored graph identity")
    require(author["baseline_commit"]=="fa2aed97cf22b720d85bd8d08b720aeadba3c4d6"
        and author["baseline_binding_sha256"]=="92456e41c9614005b96f3404b1a6dfbc65cc77f798ffd5b0024018ffad156e54"
        and author["runtime_hia_images"]==118 and author["direct_hia_members"]==110
        and author["extract_slots"]==[59,60,61,62,63]
        and author["native_semantics_executed"] is False,"exact source-only extension provenance")
    return {"status":"EXTRACT_BUILD_SOURCE_ADAPTERS_PASS","files":len(proof["files"]),"graph_files":425,"native_or_rust_executed":False}
