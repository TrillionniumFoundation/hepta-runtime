"""Fresh real private publisher capture. No unknown process is resumed or replaced."""
from pathlib import Path
import argparse,os,shutil,sys,tomllib
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from common import encoded,loads,pin,read,require,source,files
from commands import commands
from process import Recorder,environment
def capture(hepta,output,rust_bin,temporary):
    identity=source();output.mkdir(parents=True,exist_ok=False);temporary.mkdir(parents=True,exist_ok=False)
    shutil.copytree(ROOT,output/"source");shutil.copytree(ROOT/"reference",output/"reference")
    env,environment_record=environment(os.environ,rust_bin,temporary/"target")
    env["CARGO_HOME"]=str(temporary/"cargo");env.pop("HEPTA_REQUEST_AUDIT_TRACE",None)
    metadata=dict(schema="hepta.audit-anchor-publish.capture.v1",status="RUNNING",
        source_root=str(ROOT),producer_root=str(output),rust_bin=str(rust_bin),python=sys.executable,
        compiler_root=str(hepta),build_temporary=str(temporary),cargo_home=env["CARGO_HOME"],
        owned_fixture=str(temporary/"owned-fixture"),environment=environment_record,
        root_pid=os.getpid(),root_pgid=os.getpgrp(),audit_trace_environment_absent=True,
        source_manifest_sha256=identity,uid=os.geteuid(),gid=os.getegid(),
        public_handler_qualified=False,whole_runtime_replaced=False,whole_audit_caller_qualified=False)
    rows=commands(metadata);metadata["commands"]=rows;(output/"CAPTURE.json").write_bytes(encoded(metadata))
    recorder=Recorder(ROOT,output/"processes",env)
    try:
        for row in rows:
            _,process=recorder.run(row["name"],row["argv"],cwd=row["cwd"],timeout=row["timeout"])
            print(row["name"]+" PASS "+str(process["elapsed_seconds"]),flush=True)
            if row["name"]=="rust-vendor":
                (output/"crates").mkdir()
                packages=tomllib.loads(read(ROOT/"reference/Cargo.lock").decode())["package"]
                for package in packages:
                    if "source" not in package:continue
                    name=package["name"]+"-"+package["version"]+".crate"
                    found=list((temporary/"cargo/registry/cache").glob("*/"+name))
                    require(len(found)==1 and pin(read(found[0]))["sha256"]==package["checksum"],"whole locked archive")
                    shutil.copyfile(found[0],output/"crates"/name)
            if row["name"]=="rust-build":
                binary=temporary/"target/x86_64-unknown-linux-gnu/debug/hia-audit-anchor-publish-reference"
                shutil.copyfile(binary,output/"original.elf");(output/"original.elf").chmod(0o500)
                metadata["original_binary"]=pin(read(output/"original.elf"))
            if row["name"].startswith(("native-observed-","native-off-","original-")):
                folder=output/row["name"];receipt=loads(read(folder/"RETIREMENT.json"))
                from fixture import retire
                retired=retire(Path(metadata["owned_fixture"]),receipt)
                (folder/"RETIRED.json").write_bytes(encoded(retired))
        require(source()==identity,"full frozen source unchanged through real processes")
        metadata.update(status="PRODUCERS_PASS_READBACK_PENDING",files=files(output,("CAPTURE.json",)))
        (output/"CAPTURE.json").write_bytes(encoded(metadata))
    except BaseException as error:
        metadata.update(status="FAIL",exception=repr(error),completed_processes=len(recorder.records))
        (output/"CAPTURE.json").write_bytes(encoded(metadata))
        if recorder.records:
            sys.stderr.write((output/"processes"/(recorder.records[-1]["name"]+".stderr")).read_text())
        raise
    finally:
        owned=Path(metadata['owned_fixture'])
        if owned.exists():
            from fixture import snapshot
            try:
                (output/'FAILED_OWNED_FILESYSTEM.json').write_bytes(encoded(snapshot(owned)))
            except BaseException as error:
                (output/'FAILED_OWNED_FILESYSTEM_ERROR.json').write_bytes(encoded(dict(error=repr(error))))
    return metadata
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("hepta","output","rust-bin","temporary"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();capture(a.hepta.resolve(strict=True),a.output.absolute(),a.rust_bin.resolve(strict=True),a.temporary.absolute())
