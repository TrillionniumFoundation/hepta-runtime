"""CI-only fresh exact SDK transport observations; all inputs are owned ping data."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def packed(path,raw):
    data=gzip.compress(raw,mtime=0);path.write_bytes(data)
    return dict(path=path.name,bytes=len(raw),sha256=SHA(raw),compressed_bytes=len(data),compressed_sha256=SHA(data))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","cases","native","rust-bin","output"):p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args()
    if os.environ.get("CI")!="true":raise SystemExit("Fresh Rust transport execution is restricted to CI.")
    source=a.source.resolve(strict=True);cases=a.cases.resolve(strict=True);native=a.native.resolve(strict=True)
    rust=a.rust_bin.resolve(strict=True);output=a.output.absolute();output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(source/"drivers"))
    from exact_rust_build import Recorder,build_exact_oracle
    provenance=json.loads((source/"reference/SOURCES.json").read_bytes())
    assert provenance["selected_modes"]==["async","codec-eof"] and provenance["shutdown_handler_execution_selected"] is False
    for row in provenance["files"]:
        raw=(source/row["path"]).read_bytes();assert SHA(raw)==row["sha256"] and len(raw)==row["bytes"]
    for name in ("oracle","cache-seed","target"):shutil.copytree(source/"reference"/name,output/name,copy_function=shutil.copyfile)
    shutil.copytree(cases/"cases",output/"cases",copy_function=shutil.copyfile)
    corpus=json.loads((output/"cases/manifest.json").read_bytes())
    result=dict(schema="hepta.public-serial-transport.actual-target-reference.v1",status="RUNNING",
        expected_cases=28,completed_cases=0,rows=[],actual_target_transport_compared=False,
        fresh_exact_sdk_built=False,rust_executed=False,full_sdk_qualified=False,
        full_async_runtime_qualified=False,public_codec_implemented=False,
        cancellation_future_or_task_execution_qualified=False,production_activated=False,old_path_removed=False)
    started=time.monotonic()
    def checkpoint():result["elapsed_seconds"]=time.monotonic()-started;put(output/"SUMMARY.json",result)
    checkpoint()
    try:
        env=dict(PATH=str(rust)+os.pathsep+os.environ.get("PATH",""),RUSTC=str(rust/"rustc"),
                 CARGO_TARGET_DIR=str(output/"rust-build"))
        prefetch=Recorder(output,"evidence/cache-prefetch",env)
        version=prefetch.run("rustc-version",[rust/"rustc","--version","--verbose"],timeout=180)
        assert version.decode().splitlines()[0].startswith("rustc 1.95.0 ")
        seed=(output/"cache-seed/Cargo.lock").read_bytes()
        prefetch.run("cargo-fetch-locked",[rust/"cargo","fetch","--locked","--manifest-path",output/"cache-seed/Cargo.toml"],timeout=180)
        assert (output/"cache-seed/Cargo.lock").read_bytes()==seed
        binary,receipt,_=build_exact_oracle(output,"oracle","g3-target-transport-oracle",rust)
        subset=json.loads((output/"evidence/target-lock-subset.json").read_bytes())
        sdk=next(row for row in subset["registry_source_verification"] if row["name"]=="rmcp")
        assert sdk["version"]=="3.9.0" and sdk["checksum"]=="d24a7e92f4bcaa36b97fa93c4fa7ca8f3e669eced949345b3462dba333c7f909"
        assert sdk["source_files"]["src/transport/async_rw.rs"]==SHA((source/"reference/sdk/async_rw.rs").read_bytes())
        metadata=json.loads((output/"evidence/rust-build-processes/metadata-offline.stdout").read_bytes())
        verified={(r["name"],r["version"],r["source"]):r for r in subset["registry_source_verification"]}
        archives=output/"registry-archives";archives.mkdir();custody=[]
        for package in metadata["packages"]:
            if not package.get("source"):continue
            info=verified[(package["name"],package["version"],package["source"])]
            crate=Path(package["manifest_path"]).parent
            original=crate.parent.parent.parent/"cache"/crate.parent.name/(crate.name+".crate")
            raw=original.read_bytes();assert SHA(raw)==info["checksum"]
            target=archives/(crate.name+".crate");target.write_bytes(raw)
            custody.append(dict(name=package["name"],version=package["version"],source=package["source"],
                path=str(target.relative_to(output)),bytes=len(raw),sha256=SHA(raw)))
        retained=output/"reference-bin"/binary.name;retained.parent.mkdir()
        shutil.copyfile(binary,retained);retained.chmod(0o500)
        assert SHA(retained.read_bytes())==receipt["binary_sha256"]
        receipt.update(registry_archive_custody=custody,retained_binary_relative_path=str(retained.relative_to(output)),
                       actual_target_sdk_executed=False)
        put(output/"BUILD.json",receipt)
        result["fresh_exact_sdk_built"]=True;checkpoint()
        for index,case in enumerate(corpus["cases"]):
            assert case["mode"] in ("async","codec-eof")
            request={k:v for k,v in case.items() if k not in ("input_bytes","input_sha256")}
            assert set(request)<= {"label","mode","input_file","chunk_size"}
            wire=json.dumps(request,ensure_ascii=False,separators=(",",":")).encode()+b"\n"
            folder=output/("case-"+str(index).zfill(3));folder.mkdir()
            begin=time.monotonic();timed=False
            try:
                process=subprocess.run([str(retained)],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    cwd=output,env={"PATH":"","LC_ALL":"C"},timeout=60)
                stdout,stderr,code=process.stdout,process.stderr,process.returncode
            except subprocess.TimeoutExpired as exc:
                stdout,stderr,code,timed=exc.stdout or b"",exc.stderr or b"",None,True
            row=dict(index=index,label=case["label"],mode=case["mode"],exit_code=code,timed_out=timed,
                deadline_seconds=60,elapsed_seconds=time.monotonic()-begin,environment={"PATH":"","LC_ALL":"C"},
                stdin=packed(folder/"stdin.bin.gz",wire),stdout=packed(folder/"stdout.bin.gz",stdout),
                stderr=packed(folder/"stderr.bin.gz",stderr),native_wire_compared=False)
            put(folder/"PROCESS.json",row)
            assert code==0 and not timed and not stderr,case["label"]
            observed=json.loads(stdout)
            assert observed["label"]==case["label"] and observed["mode"]==case["mode"]
            if case["mode"]=="async":
                actual=gzip.decompress((native/case["label"]/"stdout.bin.gz").read_bytes())
                assert actual==observed["writer_bytes"].encode(),case["label"]
                row["native_wire_compared"]=True;put(folder/"PROCESS.json",row)
            result["rows"].append(dict(index=index,label=case["label"],mode=case["mode"],folder=folder.name,
                process_sha256=SHA((folder/"PROCESS.json").read_bytes()),stdout_sha256=SHA(stdout),stdout_bytes=len(stdout)))
            result["completed_cases"]+=1;checkpoint()
        assert result["completed_cases"]==28
        receipt["actual_target_sdk_executed"]=True;put(output/"BUILD.json",receipt)
        result.update(status="ACTUAL_TARGET_TRANSPORT_REFERENCE_PASS",rust_executed=True,
                      actual_target_transport_compared=True,serial_public_wire_cases=24,codec_eof_reference_only_cases=4)
    except BaseException as exc:result.update(status="FAIL",error=repr(exc));raise
    finally:checkpoint()
    print(json.dumps({k:v for k,v in result.items() if k!="rows"},sort_keys=True))
if __name__=="__main__":main()
