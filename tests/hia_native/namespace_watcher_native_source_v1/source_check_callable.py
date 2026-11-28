"""Pure exact source admission and syntax; does not execute native or Rust."""
import ast,hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,read,require,pin,source
def run():
    identity=source()
    from source_check import check
    require(check()["source_manifest_sha256"]==identity,"original source-only checks preserved")
    for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
    fixed=loads(read(ROOT/"SOURCE_QUALIFIED.json"))
    for name,key in (("native/namespace_watcher.hepta","owner"),("native/namespace_watcher.composition.json","composition")):
        raw=read(ROOT/name);expected=fixed[key]
        require(pin(raw)=={k:expected[k] for k in ("bytes","sha256")},"actual source-build fixed owner")
        require(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==expected["git_blob"],"owner Git pin")
    spans=loads(read(ROOT/"reference/ORIGINAL_SPANS.json"))
    for name,row in spans["sources"].items():
        require(pin(read(ROOT/name))=={k:row[k] for k in ("bytes","sha256")},"whole target source")
    for row in spans["spans"]:
        raw=read(ROOT/row["source"])[row["start_byte"]:row["end_byte"]]
        require(raw==read(ROOT/row["extraction"]) and pin(raw)=={k:row[k] for k in ("bytes","sha256")},"original span unchanged")
    asm=read(ROOT/"authoring/namespace_watcher_callable.S.in").decode()
    require(asm.count("@OWNER_BYTES@")==1 and ".zero @OWNER_BYTES@" in asm,"one exact owner reservation")
    labels=re.findall(r"^([a-zA-Z_][a-zA-Z_0-9]*):",asm,re.M)
    require(len(labels)==len(set(labels)),"unique actual assembly labels")
    for target in re.findall(r"^\s+(?:j[a-z]+|call)\s+([a-zA-Z_][a-zA-Z_0-9]*)\s*(?:/\*.*)?$",asm,re.M):
        if target not in ("r15",):require(target in labels,"resolved source branch: "+target)
    require("syscall" in asm and "lock cmpxchg" in asm and "namespace_watcher_owner:" in asm,"actual native mechanisms")
    result=dict(status="CALLABLE_SOURCE_ONLY_PASS",source_manifest_sha256=identity,
        owner=fixed["owner"],template=pin(asm.encode()),original_spans=len(spans["spans"]),
        native_or_rust_executions=0,watcher_qualified=False,namespace_version_qualified=False,
        public_handler_qualified=False)
    print(encoded(result).decode(),end="")
if __name__=="__main__":run()
