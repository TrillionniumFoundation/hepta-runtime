"""Frozen full original source, exact target lock and unchanged diagnostic profile."""
import hashlib,sys,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import read,loads,pin,require,source,encoded
def verify():
    identity=source();original=read(ROOT/"reference/namespace_version.rs.txt")
    require(pin(original)==dict(bytes=12833,sha256="7dd63c53bc1a85995a353bedc9643e7e4eb864cc7a5603dc331f0b4dd12576db")
        and hashlib.sha1(b"blob "+str(len(original)).encode()+b"\0"+original).hexdigest()=="4672d33a9ede7470a469f619da4dae91f89fcecd",
        "entire exact original target module")
    require(read(ROOT/"reference/target.rs")==original+read(ROOT/"reference/fixture_footer.rs"),"all original bytes unchanged; fixture appended only")
    lock=tomllib.loads(read(ROOT/"reference/Cargo.lock").decode())
    target=tomllib.loads(read(ROOT/"reference/target-Cargo.lock").decode())
    plan=loads(read(ROOT/"reference/REGISTRY_PLAN.json"))
    packages={p["name"]+"-"+p["version"]:p for p in lock["package"]if"source"in p}
    wanted={p["name"]+"-"+p["version"]:p for p in plan["crates"]}
    require(set(packages)==set(wanted)and len(packages)==22,"every unchanged locked implementation package")
    for name,p in packages.items():
        require(p["checksum"]==wanted[name]["checksum"]==wanted[name]["archive"]["sha256"]
            and any(all(row.get(k)==p.get(k)for k in("name","version","source","checksum"))for row in target["package"]),
            "all original implementation lock bytes")
    manifest=tomllib.loads(read(ROOT/"reference/Cargo.toml").decode())
    require(manifest["profile"]["dev"]=={"opt-level":1,"debug":2,"debug-assertions":True,"overflow-checks":True,
        "codegen-units":256,"lto":False,"panic":"unwind"},"unchanged complete original profile")
    own=[p for p in lock["package"]if"source"not in p]
    require(len(own)==1 and own[0]["name"]==manifest["package"]["name"]=="hia-namespace-versions-reference","one exact current fixture binary")
    for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
    return dict(status="COMPLETE_ORIGINAL_NAMESPACE_SOURCE_PASS",source_manifest_sha256=identity,
        original=pin(original),locked_crates=22,native_application_calls=0,original_application_calls=0)
if __name__=="__main__":print(encoded(verify()).decode(),end="")
