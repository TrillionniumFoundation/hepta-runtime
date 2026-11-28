"""Complete source and exact original span admission; no owner semantic execution."""
import ast,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,pin,require,encoded
def check():
    identity=source()
    for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
    old=read(ROOT/"previous/namespace_watcher.pseudo")
    current=read(ROOT/"authoring/namespace_watcher.pseudo")
    before=b"and not (get(w,16)==4 and get(w,40)==21):"
    after=b"and (get(w,16)!=4 or get(w,40)!=21):"
    require(old.count(before)==1 and current==old.replace(before,after),"sole compiler-compatible Boolean rewrite")
    for x in (0,3,4,5,0xffffffffffffffff):
        for y in (0,20,21,22,0xffffffffffffffff):
            require((not(x==4 and y==21))==(x!=4 or y!=21),"complete equality-partition De Morgan proof")
    nodes=ast.parse(current).body
    require(len(nodes)==26 and all(isinstance(n,ast.FunctionDef)for n in nodes),"complete authored Watcher functions")
    spans=json.loads(read(ROOT/"reference/ORIGINAL_SPANS.json"))
    for name,row in spans["sources"].items():
        require(pin(read(ROOT/name))=={k:row[k]for k in("bytes","sha256")},"whole original source")
    for row in spans["spans"]:
        raw=read(ROOT/row["source"])[row["start_byte"]:row["end_byte"]]
        require(raw==read(ROOT/row["extraction"])and pin(raw)=={k:row[k]for k in("bytes","sha256")},"exact original Watcher")
    require(pin(read(ROOT/"imports/namespace_fingerprint.hepta"))["sha256"]=="273c0b8c8305140a1b83a89a6686a0567afb8e4dd7b7a0d82c0b1de15267e842","whole qualified scalar source")
    return dict(status="SOURCE_ONLY_PASS",source_manifest_sha256=identity,source_files=len(json.loads(read(ROOT/"SOURCE.json"))["files"]),
        original_spans=len(spans["spans"]),native_or_rust_semantic_executions=0)
if __name__=="__main__":print(encoded(check()).decode(),end="")
