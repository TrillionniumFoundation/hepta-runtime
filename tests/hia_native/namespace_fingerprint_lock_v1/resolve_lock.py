"""Resolve only the reference feature lock against exact target package identities."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,sys,tomllib
def require(v,m):
    if not v:raise ValueError(m)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def resolve_dependency(text,packages):
    pieces=text.split();require(1<=len(pieces)<=2,"registry dependency notation")
    matches=[(p["name"],p["version"])for p in packages if p["name"]==pieces[0]and(len(pieces)==1 or p["version"]==pieces[1])]
    require(len(matches)==1,"one fully resolved locked dependency");return matches[0]
def run(root,rust,output,cargo_home):
    sys.path.insert(0,str(root))
    from common import source,read
    from process import Recorder,environment
    identity=source();require(identity=="ecdbde292efdaa65f7800d37a0152396ad68671c61df27934f76da9a4b61566c","unchanged failed producer source")
    output.mkdir(parents=True,exist_ok=False);shutil.copytree(root/"reference",output/"reference")
    before=read(output/"reference/Cargo.lock");require(pin(before)["sha256"]=="b85174e16de4a129c6aa90c85f2e7c86f3e3de4ef12c7599dc17fa469ff46cb0","exact rejected seed")
    (output/"SEED-Cargo.lock").write_bytes(before)
    env,binding=environment(os.environ,rust);env["CARGO_HOME"]=str(cargo_home)
    rec=Recorder(root,output/"processes",env)
    try:
        rec.run("rustc-version",[rust/"rustc","--version","--verbose"],timeout=60)
        rec.run("cargo-version",[rust/"cargo","--version","--verbose"],timeout=60)
        rec.run("resolve-feature-lock",[rust/"cargo","fetch","--manifest-path",output/"reference/Cargo.toml"],cwd=output/"reference",timeout=180)
    finally:
        for name in("rustc-version","cargo-version","resolve-feature-lock"):
            for suffix in("stdout","stderr"):
                path=output/"processes"/(name+"."+suffix)
                if path.is_file():
                    print("RETAINED_PROCESS_BEGIN "+name+"."+suffix)
                    raw=read(path);print(raw.decode(),end=""if raw.endswith(b"\n")else"\n")
                    print("RETAINED_PROCESS_END "+name+"."+suffix)
    lock=read(output/"reference/Cargo.lock")
    actual=tomllib.loads(lock.decode())["package"];target=tomllib.loads(read(root/"reference/target-Cargo.lock").decode())["package"]
    old={(p["name"],p["version"]):p for p in target}
    crates=[]
    for p in actual:
        if"source"not in p:
            require(p["name"]=="hia-namespace-fingerprint-reference"and p["version"]=="0.1.0","exact sole new reference root")
            continue
        q=old[(p["name"],p["version"])]
        require({k:v for k,v in p.items()if k!="dependencies"}=={k:v for k,v in q.items()if k!="dependencies"},
                "whole target package identity; no registry upgrade")
        current={resolve_dependency(d,actual)for d in p.get("dependencies",[])}
        previous={resolve_dependency(d,target)for d in q.get("dependencies",[])}
        require(current<=previous,"only exact Cargo feature-selected target dependency edges")
        name=p["name"]+"-"+p["version"]+".crate"
        found=list((cargo_home/"registry/cache").glob("*/"+name));require(len(found)==1,"one actual fetched package")
        raw=read(found[0]);require(pin(raw)["sha256"]==p["checksum"],"whole fetched archive equals immutable target checksum")
        crates.append(dict(name=p["name"],version=p["version"],checksum=p["checksum"],archive=pin(raw),
            dependencies=[list(x)for x in sorted(current)],target_dependencies=[list(x)for x in sorted(previous)]))
    require(sum("source"not in p for p in actual)==1,"single exact reference root")
    require(source()==identity,"original source is not rewritten")
    report=dict(schema="hepta.namespace-fingerprint.reference-lock-preparation.v1",status="FEATURE_LOCK_PREPARATION_PASS",
        original_failed_source=identity,original_failed_head="21d4a9e886ca632a859e8447b17bdb2f4f279379",
        original_failed_run=44111096554,seed_lock=pin(before),lock=pin(lock),
        target_lock=pin(read(root/"reference/target-Cargo.lock")),crates=crates,packages=len(crates),
        actual_processes=rec.records,environment=binding,original_reference_replays=0,native_owner_executions=0,
        no_registry_version_upgrade=True,production_locked_requirement_unchanged=True)
    (output/"LOCK-PREPARATION.json").write_bytes(encoded(report))
    print("GENERATED_FILE_BEGIN reference/Cargo.lock");print(lock.decode(),end="");print("GENERATED_FILE_END reference/Cargo.lock")
    print("GENERATED_FILE_BEGIN reference/LOCK-PREPARATION.json");print(encoded(report).decode(),end="");print("GENERATED_FILE_END reference/LOCK-PREPARATION.json")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for key in("source","rust-bin","output","cargo-home"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();run(a.source.resolve(strict=True),a.rust_bin.resolve(strict=True),a.output.absolute(),a.cargo_home.absolute())
