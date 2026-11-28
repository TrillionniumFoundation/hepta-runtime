"""Fresh native and exact Rust on the same owned directory; no unknown process replay."""
from pathlib import Path
import argparse,os,shutil,sys,tomllib
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,pin,read,require,source,files
from commands import commands
from process import Recorder,environment
def capture(retained,output,rust_bin,temporary):
    identity=source();output.mkdir(parents=True,exist_ok=False);temporary.mkdir(parents=True,exist_ok=False)
    shutil.copytree(ROOT,output/"source");shutil.copytree(ROOT/"reference",output/"reference")
    env,binding=environment(os.environ,rust_bin,temporary/"target");env["CARGO_HOME"]=str(temporary/"cargo")
    env.pop("HEPTA_REQUEST_AUDIT_TRACE",None)
    metadata=dict(schema="hepta.namespace-watcher.semantic-capture.v1",status="RUNNING",
        source_root=str(ROOT),producer_root=str(output),rust_bin=str(rust_bin),python=sys.executable,
        retained_root=str(retained),build_temporary=str(temporary),cargo_home=env["CARGO_HOME"],
        owned_fixture=str(temporary/"owned-fixture"),environment=binding,root_pid=os.getpid(),root_pgid=os.getpgrp(),
        source_manifest_sha256=identity,uid=os.geteuid(),gid=os.getegid(),
        private_watcher_qualified=False,namespace_version_qualified=False,public_handler_qualified=False,
        whole_runtime_replaced=False)
    rows=commands(metadata);metadata["commands"]=rows;(output/"CAPTURE.json").write_bytes(encoded(metadata))
    recorder=Recorder(ROOT,output/"processes",env)
    try:
        for row in rows:
            _,result=recorder.run(row["name"],row["argv"],cwd=row["cwd"],timeout=row["timeout"])
            print(row["name"]+" PASS "+str(result["elapsed_seconds"]),flush=True)
            if row["name"]=="toolchain":
                require(b"rustc 1.95.0" in read(output/"processes/toolchain.stdout"),"actual fixed Rust 1.95.0")
            if row["name"]=="rust-vendor":
                (output/"crates").mkdir()
                packages=tomllib.loads(read(ROOT/"reference/Cargo.lock").decode())["package"]
                for package in packages:
                    if"source"not in package:continue
                    name=package["name"]+"-"+package["version"]+".crate"
                    matches=list((temporary/"cargo/registry/cache").glob("*/"+name))
                    require(len(matches)==1 and pin(read(matches[0]))["sha256"]==package["checksum"],"entire exact locked archive")
                    shutil.copyfile(matches[0],output/"crates"/name)
            if row["name"]=="rust-build":
                binary=temporary/"target/x86_64-unknown-linux-gnu/debug/hia-namespace-watcher-reference"
                shutil.copyfile(binary,output/"original.elf");(output/"original.elf").chmod(0o500)
                metadata["original_binary"]=pin(read(output/"original.elf"))
        require(source()==identity and not any(Path(metadata["owned_fixture"]).iterdir()),"complete frozen source and retired owned trees")
        metadata.update(status="PRODUCERS_PASS_READBACK_PENDING",files=files(output,("CAPTURE.json",)))
        (output/"CAPTURE.json").write_bytes(encoded(metadata))
    except BaseException as error:
        metadata.update(status="FAIL",exception=repr(error),completed_processes=len(recorder.records))
        (output/"CAPTURE.json").write_bytes(encoded(metadata))
        if recorder.records:
            sys.stderr.write((output/"processes"/(recorder.records[-1]["name"]+".stderr")).read_text(errors="backslashreplace"))
        raise
    return metadata
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in("retained","output","rust-bin","temporary"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();capture(a.retained.resolve(strict=True),a.output.absolute(),a.rust_bin.resolve(strict=True),a.temporary.absolute())
