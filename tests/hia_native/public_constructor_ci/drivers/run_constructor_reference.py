"""CI-only fresh exact Rust constructor build and complete-byte comparison."""
from pathlib import Path
import argparse, gzip, hashlib, json, os, shutil, subprocess, sys, time
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def save_bytes(path,raw):
    with path.open("xb") as handle:
        with gzip.GzipFile(fileobj=handle,mode="wb",filename="",mtime=0) as compressed:
            compressed.write(raw)
    packed=path.read_bytes()
    return dict(path=path.name,bytes=len(raw),sha256=SHA(raw),
                compressed_bytes=len(packed),compressed_sha256=SHA(packed))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("source","output","rust-bin","native-evidence"):
        p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    if os.environ.get("CI")!="true":
        raise SystemExit("This exact Rust builder executes only in CI.")
    source,output,rust,native=(getattr(a,n.replace("-","_")).resolve()
        for n in ("source","output","rust-bin","native-evidence"))
    output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(source/"drivers"))
    from exact_rust_build import Recorder,build_exact_oracle
    sys.path.insert(0,str(source/"source/tests"))
    from constructor_cases import cases
    selected=cases("wide")
    summary=dict(schema="hepta.text-constructor-actual-target.v1",status="RUNNING",
        expected_cases=len(selected),completed_cases=0,actual_target_rust_compared=False,
        target_application_commit="d3d75c30719db966b004756f610007a7c723729e",
        full_sdk_qualified=False,public_target_handler_comparison=False,rows=[])
    def save():
        put(output/"SUMMARY.json",summary)
    save()
    started=time.monotonic()
    try:
        provenance=json.loads((source/"reference/SOURCES.json").read_bytes())
        for rel,pin in provenance["files"].items():
            assert SHA((source/rel).read_bytes())==pin["sha256"]
        for name in ("oracle","cache-seed","target"):
            shutil.copytree(source/"reference"/name,output/name)
        env=dict(PATH=str(rust)+os.pathsep+os.environ.get("PATH",""),
                 RUSTC=str(rust/"rustc"),CARGO_TARGET_DIR=str(output/"rust-build"))
        prefetch=Recorder(output,"evidence/cache-prefetch",env)
        version=prefetch.run("rustc-version",[rust/"rustc","--version","--verbose"],timeout=180)
        assert version.decode().splitlines()[0].startswith("rustc 1.95.0 ")
        seed_lock=(output/"cache-seed/Cargo.lock").read_bytes()
        prefetch.run("cargo-fetch-locked",[rust/"cargo","fetch","--locked",
            "--manifest-path",output/"cache-seed/Cargo.toml"],timeout=180)
        assert (output/"cache-seed/Cargo.lock").read_bytes()==seed_lock
        binary,receipt,_=build_exact_oracle(output,"oracle","target-text-result-constructor",rust)
        subset=json.loads((output/"evidence/target-lock-subset.json").read_bytes())
        actual=next(row for row in subset["registry_source_verification"] if row["name"]=="rmcp")
        assert actual["version"]=="3.9.0"
        assert actual["checksum"]=="d24a7e92f4bcaa36b97fa93c4fa7ca8f3e669eced949345b3462dba333c7f909"
        for rel in ("src/model.rs","src/model/content.rs"):
            assert actual["source_files"][rel]==provenance["files"]["reference/sdk/"+rel]["sha256"]
        # Preserve the archives actually checked by the fresh builder. A later
        # reader can recompute every recorded source-file hash without Cargo.
        metadata=json.loads((output/"evidence/rust-build-processes/metadata-offline.stdout").read_bytes())
        verified={(r["name"],r["version"],r["source"]):r for r in subset["registry_source_verification"]}
        archives=output/"registry-archives";archives.mkdir()
        custody=[]
        for package in metadata["packages"]:
            if not package.get("source"):
                continue
            pin=verified[(package["name"],package["version"],package["source"])]
            crate=Path(package["manifest_path"]).parent
            original=crate.parent.parent.parent/"cache"/crate.parent.name/(crate.name+".crate")
            raw=original.read_bytes();assert SHA(raw)==pin["checksum"]
            target=archives/(crate.name+".crate")
            with target.open("xb") as handle:handle.write(raw)
            custody.append(dict(name=package["name"],version=package["version"],
                source=package["source"],path=str(target.relative_to(output)),
                bytes=len(raw),sha256=SHA(raw)))
        receipt["registry_archive_custody"]=custody
        retained=output/"reference-bin"/binary.name
        retained.parent.mkdir()
        shutil.copyfile(binary,retained);retained.chmod(0o500)
        assert SHA(retained.read_bytes())==receipt["binary_sha256"]
        receipt["retained_binary_relative_path"]=str(retained.relative_to(output))
        receipt["actual_target_sdk_executed"]=False
        put(output/"BUILD.json",receipt)
        for index,case in enumerate(selected):
            folder=output/f"case-{index:03d}";folder.mkdir()
            raw=case.frame()
            inp=save_bytes(folder/"stdin.bin.gz",raw)
            begin=time.monotonic();timed=False
            try:
                process=subprocess.run([str(retained)],input=raw,stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,timeout=60,env={"PATH":"","LC_ALL":"C"})
                out,err,code=process.stdout,process.stderr,process.returncode
            except subprocess.TimeoutExpired as exc:
                out,err,code,timed=exc.stdout or b"",exc.stderr or b"",None,True
            record=dict(case=case.name,index=index,exit_code=code,timed_out=timed,
                deadline_seconds=60,elapsed_seconds=time.monotonic()-begin,
                stdin=inp,stdout=save_bytes(folder/"stdout.bin.gz",out),
                stderr=save_bytes(folder/"stderr.bin.gz",err),native_full_output_equal=False)
            put(folder/"CASE.json",record)
            expected=gzip.decompress((native/f"case-{index:03d}/constructor-2/output.gz").read_bytes())
            if code!=0 or timed or err or out!=expected:
                raise ValueError(("actual target constructor differs",case.name,code,timed))
            record["native_full_output_equal"]=True;put(folder/"CASE.json",record)
            summary["rows"].append(dict(case=case.name,folder=folder.name,
                receipt_sha256=SHA((folder/"CASE.json").read_bytes()),stdout_sha256=SHA(out),stdout_bytes=len(out)))
            summary["completed_cases"]+=1;save()
        receipt["actual_target_sdk_executed"]=True;put(output/"BUILD.json",receipt)
        summary.update(status="ACTUAL_TARGET_CONSTRUCTOR_PASS",actual_target_rust_compared=True,
                       fresh_exact_rust_built=True,complete_output_compared=True)
    except BaseException as exc:
        summary.update(status="FAIL",error=repr(exc))
        raise
    finally:
        summary["elapsed_seconds"]=time.monotonic()-started;save()
    print(json.dumps({k:v for k,v in summary.items() if k!="rows"},sort_keys=True))

if __name__=="__main__":
    main()


