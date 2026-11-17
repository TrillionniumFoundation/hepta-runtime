"""Read the complete public118-extract package and the exact installed source closure."""
from pathlib import Path
import argparse,hashlib,json,stat,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import pin,require,verify
import author_shape_admission
import verify_adapters
import extract_adapters
BINDING="2c423747b2827c3a6d0993b89583c47691640ea44fcf5f77e6c0ed2aaaf0dc70"
GRAPH_COMMIT="a521066dfa07db38e6a22bd2f03d1dae3c203cc2"
def git_blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def installed_source(package,root):
    package,root=Path(package).resolve(strict=True),Path(root).resolve(strict=True)
    inputs=json.loads((package/"INPUTS.json").read_bytes())
    result={}
    require(len(inputs["installed_graph_rows"])==425,"complete installed source inventory")
    for row in inputs["installed_graph_rows"]:
        name=row["path"]
        require(not Path(name).is_absolute() and ".." not in Path(name).parts,"source path")
        path=root/name
        require(path.resolve(strict=True)==path and stat.S_ISREG(path.lstat().st_mode),"aliased installed source: "+name)
        raw=path.read_bytes()
        actual={"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"git_blob":git_blob(raw),
                "mode":"100755" if path.stat().st_mode&0o111 else "100644"}
        require(actual=={k:row[k] for k in actual},"installed source differs: "+name)
        result[name]=actual
    require(pin(root/"native/runtime_mcp_sources.json")["sha256"]==BINDING,"actual default source binding")
    return result
def source(package,manifest_sha256,*,syntax=False):
    package=Path(package).resolve(strict=True);manifest=package/"PACKAGE.json"
    require(pin(manifest)["sha256"]==manifest_sha256,"package manifest identity differs")
    data=json.loads(manifest.read_bytes())
    expected=dict(data["files"]);expected["PACKAGE.json"]=pin(manifest)
    actual=verify(package,expected)
    for name,row in data["files"].items():
        mode=row.get("mode","100644")
        require(mode in ("100644","100755") and bool((package/name).stat().st_mode&0o111)==(mode=="100755"),
                "source executable mode differs: "+name)
        require(git_blob((package/name).read_bytes())==row["git_blob"],"complete Git identity: "+name)
    inputs=json.loads((package/"INPUTS.json").read_bytes())
    require(inputs["schema"]=="hepta.runtime.public118-extract.inputs.v1"
        and inputs["graph"]["files"]==425 and inputs["graph"]["source_commit"]==GRAPH_COMMIT
        and inputs["graph"]["source_binding_sha256"]==BINDING
        and inputs["port"]["files"]==143 and inputs["original"]["files"]==31,"fixed source closures differ")
    graph=installed_source(package,package/"graph/source")
    require(set(graph)=={p.removeprefix("graph/source/") for p in data["files"] if p.startswith("graph/source/")},
            "graph snapshot inventory differs")
    require(pin(package/"port/PACKAGE.json")["sha256"]==inputs["port"]["package_sha256"],"port package identity")
    port={p.removeprefix("port/") for p in data["files"] if p.startswith("port/")}
    require(len(port)==143,"complete port source inventory")
    for name in port:
        require((package/"port"/name).read_bytes()==(package/"graph/source/runtime_support/bellman_port"/name).read_bytes(),
                "default dependency source differs: "+name)
    original={p.removeprefix("wire/reference/") for p in data["files"] if p.startswith("wire/reference/")}
    require(len(original)==31 and pin(package/"wire/reference/package-manifest.json")==inputs["original"]["package_manifest"],
            "original complete source identity")
    require(inputs["joint"]["commit"]=="f5b021fbfdc2e02d0df0bb4089001da4bae2ac3a"
            and len(inputs["joint_source_rows"])==1490,"immutable Authority/Batch source closure")
    for row in inputs["joint_source_rows"]:
        name="joint/"+row["path"]
        require(actual[name]=={k:row[k] for k in ("bytes","sha256")}
            and git_blob((package/name).read_bytes())==row["git_blob"],"immutable joint source: "+name)
    for row in inputs["existing_source_rows"]:
        require(actual[row["path"]]=={k:row[k] for k in ("bytes","sha256")}
            and git_blob((package/row["path"]).read_bytes())==row["git_blob"],"retained source differs: "+row["path"])
    shape=author_shape_admission.verify(package)
    verify_adapters.verify(package)
    extract_adapters.verify(package)
    if syntax:
        require(set(data["new_python_sources"])<=set(data["files"]),"new Python inventory")
        for name in sorted(data["files"]):
            if name.endswith(".py"):compile((package/name).read_bytes(),str(package/name),"exec",dont_inherit=True)
    return {"manifest":pin(manifest),"files":len(actual),"inputs":pin(package/"INPUTS.json"),
            "graph_source_binding":BINDING,
            "shape_admission_source":shape["changed_files"]["source/native/sdk_request_task_registry.hepta"]}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--package",type=Path,required=True);p.add_argument("--manifest-sha256",required=True)
    p.add_argument("--installed-source",type=Path);a=p.parse_args()
    result=source(a.package,a.manifest_sha256,syntax=True)
    if a.installed_source:result["actual_installed_source"]=installed_source(a.package,a.installed_source)
    print(json.dumps({"status":"EXACT_SOURCE_CLOSURE_PASS",**result,"native_executed":False,"rust_executed":False},sort_keys=True))
if __name__=="__main__":main()
