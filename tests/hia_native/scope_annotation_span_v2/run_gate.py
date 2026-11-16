"""Fresh source-bound original and HIA qualification; all failures remain."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from build import verify_source
from cases import cases,domain,frame,packet
from rust_reference import Recorder,build_reference,environment,put

SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def original(target,output,rust_bin):
    assert os.environ.get("GITHUB_ACTIONS")=="true" or os.environ.get("HIA_AUTHORIZED_REFERENCE_HOST")=="ai395"
    source_sha=verify_source()
    fetch=output/"fetch-project"
    fetch.mkdir()
    for name in ("main.rs","Cargo.toml"):
        (fetch/name).write_bytes((ROOT/"reference"/name).read_bytes())
    lock=(target/"Cargo.lock").read_bytes()
    (fetch/"Cargo.lock").write_bytes(lock)
    env,binding=environment(os.environ,rust_bin,output/"fetch-target-unused")
    rec=Recorder(ROOT,output/"fetch-processes",env)
    rec.run("fetch-exact-original-dependencies",[rust_bin/"cargo","fetch","--target","x86_64-unknown-linux-gnu"],cwd=fetch,timeout=180)
    known={(p["name"],p["version"],p.get("source")):p.get("checksum") for p in tomllib.loads(lock.decode())["package"] if p.get("source")}
    for row in tomllib.loads((fetch/"Cargo.lock").read_text())["package"]:
        if row.get("source"):
            assert known[(row["name"],row["version"],row["source"])]==row["checksum"]
        else:
            assert row["name"]=="scope-annotation-original"
    put(output/"fetch-environment.json",binding)
    binary,built,rec=build_reference(ROOT,target,output/"original",rust_bin)
    assert verify_source()==source_sha
    data=b"".join(packet(frame(row)) for row in cases())
    frozen=json.loads((ROOT/"DOMAIN.json").read_bytes())
    assert len(data)==frozen["input_bytes"] and SHA(data)==frozen["input_sha256"] and domain()==frozen
    observed,process=rec.run("original-replay",[binary],stdin=data,timeout=180)
    put(output/"original/REPLAY.json",dict(status="ACTUAL_UNCHANGED_ORIGINAL_METHODS_EXECUTED",cases=len(frozen["cases"]),
        source_manifest_sha256=source_sha,domain_sha256=SHA((ROOT/"DOMAIN.json").read_bytes()),
        binary_sha256=built["binary_sha256"],input_bytes=len(data),input_sha256=SHA(data),
        output_bytes=len(observed),output_sha256=SHA(observed),pid=process["pid"],
        actual_target_sdk_executed=True,actual_tracing_warning_observed=True,full_native_comparison=False))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--hepta",type=Path,required=True)
    parser.add_argument("--target",type=Path)
    parser.add_argument("--rust-bin",type=Path)
    parser.add_argument("--bootstrap",type=Path)
    parser.add_argument("--native-only",action="store_true")
    args=parser.parse_args()
    source_sha=verify_source()
    output=args.output.absolute()
    output.mkdir(parents=True,exist_ok=False)
    env,_=environment(os.environ)
    rec=Recorder(ROOT,output/"gate-processes",env)
    gate=dict(schema="hepta.scope-annotation-span.gate.v2",status="RUNNING",source_manifest_sha256=source_sha,
              domain_sha256=SHA((ROOT/"DOMAIN.json").read_bytes()),native_only=args.native_only,
              execution_source_root=str(ROOT),execution_output_root=str(output),whole_runtime_replaced=False)
    started=time.monotonic()
    put(output/"GATE.json",gate)
    try:
        if not args.native_only:
            assert args.target is not None and args.rust_bin is not None and args.bootstrap is None
            original(args.target.resolve(strict=True),output,args.rust_bin.resolve(strict=True))
        command=[sys.executable,"-I","-B",ROOT/"build.py","--hepta",args.hepta.resolve(strict=True),"--output",output/"build"]
        if args.bootstrap is not None:
            command += ["--bootstrap",args.bootstrap.resolve(strict=True)]
        rec.run("native-build",command,timeout=180)
        for name,script in (("native-domain","run_native.py"),("native-controls","controls.py")):
            folder=output/("native" if name=="native-domain" else "controls")
            rec.run(name,[sys.executable,"-I","-B",ROOT/script,"--build",output/"build/BUILD.json","--output",folder],timeout=180)
        command=[sys.executable,"-I","-B",ROOT/"verify_readonly.py","--output",output,"--source-manifest-sha256",source_sha]
        if args.native_only:
            command.append("--native-only")
        complete,_=rec.run("complete-readonly",command,timeout=180)
        report=json.loads(complete)
        assert len(report["probes"])==12 and report["before"]==report["after"]
        rec.run("native-evidence-controls",[sys.executable,"-I","-B",ROOT/"evidence_controls.py",
            "--capture",output,"--output",output/"reader-controls"],timeout=180)
        if not args.native_only:
            rec.run("original-evidence-controls",[sys.executable,"-I","-B",ROOT/"original_evidence_controls.py",
                "--runtime",ROOT,"--capture",output,"--output",output/"original-reader-controls"],timeout=180)
        complete,_=rec.run("complete-readonly-after-controls",command+["--require-evidence-controls"],timeout=180)
        report=json.loads(complete)
        assert len(report["probes"])==12 and report["before"]==report["after"]
        gate.update(status=report["evidence"]["status"],evidence=report["evidence"],readonly_guard_refusals=12)
    except BaseException as error:
        gate.update(status="FAIL",error=dict(type=type(error).__name__,message=str(error)))
        raise
    finally:
        gate.update(elapsed_seconds=time.monotonic()-started,source_unchanged=verify_source()==source_sha)
        put(output/"GATE.json",gate)
    print(json.dumps(gate,sort_keys=True))


if __name__=="__main__":main()
