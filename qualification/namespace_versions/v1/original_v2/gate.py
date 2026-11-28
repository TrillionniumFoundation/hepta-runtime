"""Build the actual unchanged original and bind its real local statics; zero applications."""
import argparse,os,shutil,sys,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,require,pin
from process import Recorder,environment
from elf_read import symbols
def run(rust_bin,output):
    identity=source();output.mkdir(parents=True,exist_ok=False)
    shutil.copytree(ROOT/"reference",output/"reference")
    env,binding=environment(os.environ,rust_bin,output/"target")
    env["CARGO_HOME"]=str(output/"cargo-home");env.pop("HEPTA_REQUEST_AUDIT_TRACE",None)
    recorder=Recorder(ROOT,output/"processes",env);python=Path(sys.executable).resolve(strict=True);ref=output/"reference"
    config=["--config",'source.crates-io.replace-with="fixed-vendor"',"--config","source.fixed-vendor.directory="+__import__("json").dumps(str(output/"vendor"))]
    commands=[
        ("source-check",[python,"-I","-B",ROOT/"source_check.py"],ROOT,60),
        ("toolchain",[rust_bin/"rustc","--version","--verbose"],ROOT,60),
        ("cargo-version",[rust_bin/"cargo","--version","--verbose"],ROOT,60),
        ("rust-fetch",[rust_bin/"cargo","fetch","--locked","--manifest-path",ref/"Cargo.toml"],ref,180),
        ("rust-vendor",[rust_bin/"cargo","vendor","--locked","--offline","--versioned-dirs","--manifest-path",ref/"Cargo.toml",output/"vendor"],ref,180),
        ("rust-build",[rust_bin/"cargo","build","--frozen","--verbose","--target","x86_64-unknown-linux-gnu","--manifest-path",ref/"Cargo.toml",*config],ref,900),
        ("actual-symbols",["/usr/bin/readelf","--wide","--symbols","--relocs",output/"original.elf"],ROOT,60)]
    metadata=dict(schema="hepta.namespace-versions.original-build.v1",status="RUNNING",source_manifest_sha256=identity,
        source_root=str(ROOT),build_root=str(output),rust_bin=str(rust_bin),environment=binding,
        commands=[dict(name=n,argv=list(map(str,args)),cwd=str(cwd),timeout_seconds=timeout)for n,args,cwd,timeout in commands],
        native_application_calls=0,original_application_calls=0,namespace_version_qualified=False,public_handler_qualified=False)
    (output/"BUILD.json").write_bytes(encoded(metadata))
    try:
        for name,args,cwd,timeout in commands:
            recorder.run(name,args,cwd=cwd,timeout=timeout)
            if name=="toolchain":require(read(output/"processes/toolchain.stdout").startswith(b"rustc 1.95.0 "),"actual original Rust 1.95.0")
            if name=="rust-vendor":
                (output/"crates").mkdir()
                for p in tomllib.loads(read(ROOT/"reference/Cargo.lock").decode())["package"]:
                    if"source"not in p:continue
                    archive_name=p["name"]+"-"+p["version"]+".crate"
                    matches=list((output/"cargo-home/registry/cache").glob("*/"+archive_name))
                    require(len(matches)==1 and pin(read(matches[0]))["sha256"]==p["checksum"],"complete exact locked crate archive")
                    shutil.copyfile(matches[0],output/"crates"/archive_name)
            if name=="rust-build":
                binary=output/"target/x86_64-unknown-linux-gnu/debug/hia-namespace-versions-reference"
                shutil.copyfile(binary,output/"original.elf");(output/"original.elf").chmod(0o500)
                binding_elf=symbols(read(output/"original.elf"))
                (output/"ELF-BINDINGS.json").write_bytes(encoded(binding_elf))
                metadata["original_binary"]=pin(read(output/"original.elf"));metadata["elf_bindings"]=binding_elf
            print("ORIGINAL_BUILD_PROCESS "+name+" PASS",flush=True)
        metadata.update(status="ORIGINAL_NAMESPACE_BUILD_PASS",processes=recorder.records)
        (output/"BUILD.json").write_bytes(encoded(metadata))
        raw,_=recorder.run("read",[python,"-I","-B",ROOT/"read_build.py","--build",output,"--output",output/"GUARDED.json"],timeout=180)
        result=loads(raw);require(source()==identity,"complete source unchanged")
        result.update(status="NAMESPACE_VERSIONS_ORIGINAL_BUILD_PASS",processes=recorder.records,environment=binding)
        (output/"GATE.json").write_bytes(encoded(result));print("NAMESPACE_ORIGINAL_GATE_BEGIN");print(encoded(result).decode(),end="");print("NAMESPACE_ORIGINAL_GATE_END")
    except BaseException as error:
        metadata.update(status="FAIL",exception=repr(error),processes=recorder.records)
        (output/"BUILD.json").write_bytes(encoded(metadata));raise
    finally:
        for row in recorder.records:
            path=output/"processes"/row["stderr"]["file"]
            if path.exists()and path.stat().st_size:sys.stderr.buffer.write(read(path))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--rust-bin",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.rust_bin.resolve(strict=True),a.output.absolute())
