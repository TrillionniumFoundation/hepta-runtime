"""Exact unchanged original Rust prefix, locked implementation closure, and source-only checks."""
from pathlib import Path
import ast,hashlib,json,sys,tomllib
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,pin,read,require,source
from protocol import domain
def verify():
    identity=source();d=domain()
    require(read(ROOT/"BUILD-PINS.json")==read(ROOT/"NEW-BUILD-PINS.json"),"single exact new build binding")
    build=loads(read(ROOT/"BUILD-PINS.json"))
    require(build["head"]=="fe3a437e9b69474bfa3242a55767b7c22344a339" and build["artifact"]==14365816793
        and build["expected_owner_source"]==dict(bytes=103757,sha256="b7947d6c8922b28a25499fd8bf20f84879f5fe32e8a33f546d0fdb16ec38a06f")
        and build["expected_owner"]==dict(bytes=138252,sha256="ef9ff8fe126bbb9f3db97ce5bc2ed73721d212da2d281a557dd7236eb81b24b9")
        and build["expected_flat"]==dict(bytes=144700,sha256="47c86139bcbc735c4b465a7c698fe73b656ed018e944a02c02dcf049f7e0fae9"),
        "exact new fixed-eight owner and actual same-CI packed image")
    baseline=ast.parse(read(ROOT/"baseline/run_pairs.py.txt"))
    candidate=ast.parse(read(ROOT/"run_pairs.py"))
    old_run=next(x for x in baseline.body if isinstance(x,ast.FunctionDef)and x.name=="run")
    new_run=next(x for x in candidate.body if isinstance(x,ast.FunctionDef)and x.name=="run")
    def case_body(function):
        outer=next(x for x in function.body if isinstance(x,ast.Try))
        return next(x for x in outer.body if isinstance(x,ast.For)and isinstance(x.target,ast.Name)and x.target.id=="case")
    require(ast.dump(case_body(old_run),include_attributes=False)==ast.dump(case_body(new_run),include_attributes=False),
        "entire original per-case setup/mutation/full snapshots/three actual observations/comparison/retirement AST unchanged")
    old_child=next(x for x in baseline.body if isinstance(x,ast.ClassDef)and x.name=="Child")
    new_child=next(x for x in candidate.body if isinstance(x,ast.ClassDef)and x.name=="Child")
    for name in("chunk","receive","exchange","end_input","finish","kill","wait"):
        a=next(x for x in old_child.body if isinstance(x,ast.FunctionDef)and x.name==name)
        b=next(x for x in new_child.body if isinstance(x,ast.FunctionDef)and x.name==name)
        require(ast.dump(a,include_attributes=False)==ast.dump(b,include_attributes=False),"unchanged complete stream/custody method "+name)
    require(pin(read(ROOT/"fixture.py"))==dict(bytes=4262,sha256="9b87b425286039af326e89993a45dcadb836fc0c01d95eb0f4a1515ae0ea9c15"),
        "all unchanged complete filesystem observation source")
    require(pin(read(ROOT/"native_child.py"))==dict(bytes=16479,sha256="08fbae195740c909bbf6849e3715793cfba4887e0b366276b827d4b95adc7857"),
        "unchanged actual native observer/off/callback/capacity semantics")
    old_capture=read(ROOT/"baseline/capture_native.py.txt")
    require(pin(old_capture)==dict(bytes=2790,sha256="ff5fee8d97e870a534335dc1d088fd0cf63897fc5f5df8c1c2a95be5c86f10f8"),
        "complete original native capture source retained")
    capture=read(ROOT/"capture_native.py").decode()
    replacements=[
        ("from common import pin,require\nfrom evidence_codec import encoded","from common import encoded,pin,require"),
        ('        complete=b"".join((wire,*raws))\n        self.stream.write(complete);self.offset+=len(complete)',
         '        self.stream.write(wire);self.offset+=len(wire)\n        for raw in raws:self.stream.write(raw);self.offset+=len(raw)')]
    for new,old in replacements:
        require(capture.count(new)==1,"unique complete evidence-only transformation")
        capture=capture.replace(new,old)
    require(capture.encode()==old_capture,"inverse preserves all native observation and buffer capture code")
    v2=read(ROOT/"baseline/run_pairs_v2.py.txt").decode()
    candidate_pair=read(ROOT/"run_pairs.py").decode()
    replacements=[
        ("from common import encoded,loads,pin,read,require,source\nfrom evidence_codec import encoded as evidence_encoded",
         "from common import encoded,loads,pin,read,require,source"),
        ('(self.folder/"EXCHANGES.json").write_bytes(evidence_encoded(self.rows))',
         '(self.folder/"EXCHANGES.json").write_bytes(encoded(self.rows))'),
        ('try:(output/name).write_bytes(evidence_encoded(value))','try:(output/name).write_bytes(encoded(value))')]
    for new,old in replacements:
        require(candidate_pair.count(new)==1,"unique parent evidence-only transformation")
        candidate_pair=candidate_pair.replace(new,old)
    require(candidate_pair==v2,"entire V2 process/tracer/tree/control semantic body preserved by exact inverse")
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
