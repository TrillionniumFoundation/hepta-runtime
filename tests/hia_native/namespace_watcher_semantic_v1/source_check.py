"""Exact unchanged original Rust prefix, locked implementation closure, and source-only checks."""
from pathlib import Path
import ast,hashlib,json,sys,tomllib
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,pin,read,require,source
from protocol import domain
def verify():
    identity=source();d=domain()
    target=read(ROOT/"reference/namespace_version.rs.txt")
    require(pin(target)==dict(bytes=12833,sha256="7dd63c53bc1a85995a353bedc9643e7e4eb864cc7a5603dc331f0b4dd12576db"),"exact current target original namespace module")
    require(hashlib.sha1(b"blob "+str(len(target)).encode()+b"\0"+target).hexdigest()=="4672d33a9ede7470a469f619da4dae91f89fcecd","exact original target Git blob")
    footer=read(ROOT/"reference/watcher_fixture_footer.rs")
    require(read(ROOT/"reference/target.rs")==target+footer,"entire original module unchanged, accessors appended only")
    require(b"self.inner"not in target and b"pub(super) fn fixture_"in footer,"observer accessors separate from source")
    plan=loads(read(ROOT/"reference/REGISTRY_PLAN.json"))
    packages=tomllib.loads(read(ROOT/"reference/Cargo.lock").decode())["package"]
    actual={p["name"]+"-"+p["version"]:p for p in packages if"source"in p}
    wanted={p["name"]+"-"+p["version"]:p for p in plan["crates"]}
    require(len(actual)==len(wanted)==22 and set(actual)==set(wanted),"full exact locked implementation packages")
    target_lock=tomllib.loads(read(ROOT/"reference/target-Cargo.lock").decode())
    for name,p in actual.items():
        require(p["checksum"]==wanted[name]["checksum"]==wanted[name]["archive"]["sha256"]and
            any(all(row.get(k)==p.get(k)for k in("name","version","source","checksum"))for row in target_lock["package"]),
            "every locked crate derives from full target lock")
    root=next(p for p in packages if"source"not in p)
    manifest=tomllib.loads(read(ROOT/"reference/Cargo.toml").decode())
    profile=manifest["profile"]["dev"]
    require(profile=={"opt-level":1,"debug":2,"debug-assertions":True,"overflow-checks":True,
        "codegen-units":256,"lto":False,"panic":"unwind"},"same qualified original diagnostic build profile")
    require(root["name"]==manifest["package"]["name"]=="hia-namespace-watcher-reference","exact sole original binary")
    for path in ROOT.rglob("*.py"):
        compile(read(path),str(path),"exec")
    for path in("reference/main.rs","reference/owned_environment.rs","reference/watcher_fixture_footer.rs"):
        raw=read(ROOT/path);require(b"Copyright 2026 Muvon Un Limited"in raw and b"Licensed under the Apache License, Version 2.0"in raw,"new Rust source standard license")
    require(d["limits"]==dict(process_seconds=60,reader_seconds=180,rust_build_seconds=900,job_minutes=15),"all original fixed budgets")
    return dict(status="SOURCE_ONLY_PASS",source_manifest_sha256=identity,cases=58,operations=984,
        groups=d["groups"],locked_crates=22,original_module=pin(target),native_or_rust_executions=0,
        private_watcher_qualified=False,namespace_version_qualified=False,public_handler_qualified=False)
if __name__=="__main__":print(encoded(verify()).decode(),end="")
