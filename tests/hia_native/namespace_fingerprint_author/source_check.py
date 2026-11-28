"""Complete source and original-span admission. No HIA/Rust semantic execution."""
import ast,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,pin,require,encoded
def check():
    digest=source()
    for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
    nodes=ast.parse(read(ROOT/"authoring/namespace_fingerprint.pseudo")).body
    require(all(isinstance(n,ast.FunctionDef) for n in nodes),"whole owner pseudo")
    spans=json.loads(read(ROOT/"reference/ORIGINAL_SPANS.json"))
    for name,expected in spans["sources"].items():
        body=read(ROOT/name);require(pin(body)=={k:expected[k] for k in ("bytes","sha256")},"complete target reference")
    for row in spans["spans"]:
        body=read(ROOT/row["source"])[row["start_byte"]:row["end_byte"]]
        require(body==read(ROOT/row["extraction"]),"unchanged original fingerprint")
        require(pin(body)=={k:row[k] for k in ("bytes","sha256")},"exact original span")
    asm=read(ROOT/"authoring/namespace_fingerprint_callable.S.in")
    require(asm.count(b"@OWNER_BYTES@")==1,"fixed embedded owner extent")
    require(b"589824" in asm and b".asciz \".\"" in asm,"actual original openat flags and component")
    require(pin(read(ROOT/"imports/bellman_commitment.hepta"))["sha256"]=="18a810c251fa1c73764bb0968d8db969ac5fc6a922e4a692cd5ce5e3f960ae36","qualified whole SHA preimage")
    require(pin(read(ROOT/"imports/binary_codec.hepta"))["sha256"]=="f58ab824ecb47545f19cd1d0daded9e41fca5457110693677d84e393e3098f23","qualified read64 preimage")
    return dict(status="SOURCE_ONLY_PASS",source_sha256=digest,source_files=len(json.loads(read(ROOT/"SOURCE.json"))["files"]),
        original_spans=len(spans["spans"]),native_or_rust_semantic_executions=0)
if __name__=="__main__":print(encoded(check()).decode(),end="")
