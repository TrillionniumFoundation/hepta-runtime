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

    from protocol import domain
    d=domain()
    original=read(ROOT/"reference/namespace_version.rs.txt")
    target=read(ROOT/"reference/target.rs")
    suffix=b"\n// Test-owned visibility only. The complete target module above is unchanged.\npub(super) fn fixture_fingerprint(directory: &File) -> Result<Version> {\n    fingerprint(directory)\n}\n"
    require(target==original+suffix,"whole unchanged target module and sole private visibility wrapper")
    for name in("main.rs","owned_environment.rs"):
        raw=read(ROOT/"reference"/name)
        require(raw.startswith(b"// Copyright 2026 Muvon Un Limited\n") and b"Apache License, Version 2.0"in raw,
                "new reference source copyright")
    import tomllib
    packages=tomllib.loads(read(ROOT/"reference/Cargo.lock").decode())["package"]
    target_packages=tomllib.loads(read(ROOT/"reference/target-Cargo.lock").decode())["package"]
    target_index={(p["name"],p["version"]):p for p in target_packages}
    def dep(text,rows):
        parts=text.split()
        found=[(p["name"],p["version"])for p in rows if p["name"]==parts[0]and(len(parts)==1 or p["version"]==parts[1])]
        require(len(parts)in(1,2)and len(found)==1,"one exact locked dependency identity")
        return found[0]
    plan=json.loads(read(ROOT/"reference/REGISTRY_PLAN.json"))
    require(pin(read(ROOT/"reference/Cargo.lock"))==plan["reference_lock"]and
            len([p for p in packages if"source"in p])==plan["packages"]==22,"actual frozen Cargo feature lock")
    for p in packages:
        if"source"in p:
            q=target_index[(p["name"],p["version"])]
            require({k:v for k,v in p.items()if k!="dependencies"}=={k:v for k,v in q.items()if k!="dependencies"},
                    "whole target registry package identity and checksum")
            require({dep(x,packages)for x in p.get("dependencies",[])}<={dep(x,target_packages)for x in q.get("dependencies",[])},
                    "only actual feature-selected target edges")
    require({p["version"]for p in packages if p["name"]=="sha2"}=={"0.11.0"},"actual target SHA-256 dependency")
    return dict(status="SOURCE_ONLY_PASS",source_sha256=digest,source_files=len(json.loads(read(ROOT/"SOURCE.json"))["files"]),
        original_spans=len(spans["spans"]),native_or_rust_semantic_executions=0)
if __name__=="__main__":print(encoded(check()).decode(),end="")
