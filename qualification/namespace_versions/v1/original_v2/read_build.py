"""Pure complete original source/crate/build/ELF reader; no original process launch."""
import argparse,hashlib,io,shlex,sys,tarfile,time,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,require,pin,files
from read_only_guard import guarded
from source_check import verify as source_check
from elf_read import symbols
def verify(build):
    identity=source();checked=source_check();metadata=loads(read(build/"BUILD.json"))
    require(metadata["schema"]=="hepta.namespace-versions.original-build.v1"and metadata["status"]=="ORIGINAL_NAMESPACE_BUILD_PASS"
        and metadata["source_manifest_sha256"]==identity and metadata["native_application_calls"]==metadata["original_application_calls"]==0
        and metadata["namespace_version_qualified"]is False and metadata["public_handler_qualified"]is False,"precise build-only result")
    require(files(ROOT/"reference")==files(build/"reference"),"complete unchanged original/reference source tree")
    records=loads(read(build/"processes/processes.json"))
    require(records==metadata["processes"]and len(records)==len(metadata["commands"])==7,"all actual original build processes")
    for row,expected in zip(records,metadata["commands"]):
        require(all(row[k]==expected[k]for k in("name","argv","cwd","timeout_seconds"))and row["completed"]
            and not row["timed_out"]and row["exit_code"]==0 and row["elapsed_seconds"]<=row["timeout_seconds"]
            and row["pid"]==row["pgid"]and row["parent_pid"]>0 and row["stdin"]is None,"entire actual process custody and command")
        for stream in("stdout","stderr"):
            raw=read(build/"processes"/row[stream]["file"])
            require(row[stream]==dict(file=row["name"]+"."+stream,**pin(raw)),"whole original build process streams")
    rustbin=Path(metadata["rust_bin"]);origin=Path(metadata["build_root"]);ref=origin/"reference"
    config=["--config",'source.crates-io.replace-with="fixed-vendor"',"--config","source.fixed-vendor.directory="+__import__("json").dumps(str(origin/"vendor"))]
    require(records[5]["argv"]==list(map(str,[rustbin/"cargo","build","--frozen","--verbose","--target","x86_64-unknown-linux-gnu",
        "--manifest-path",ref/"Cargo.toml",*config])),"exact complete original cargo invocation")
    require(read(build/"processes/toolchain.stdout").startswith(b"rustc 1.95.0 "),"whole fixed Rust toolchain version")
    environment=metadata["environment"]["explicit_reference_environment"]
    require(environment["RUSTC"]==str(rustbin/"rustc")and environment["RUSTDOC"]==str(rustbin/"rustdoc")
        and all(environment[k]==""for k in("RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS","CARGO_BUILD_RUSTFLAGS"))
        and environment["CARGO_BUILD_TARGET"]=="x86_64-unknown-linux-gnu"
        and environment["CARGO_TARGET_DIR"]==str(origin/"target")and metadata["environment"]["cargo_encoded_rustflags_override"]=="",
        "all actual original build environment overrides fixed")
    stderr=read(build/"processes/rust-build.stderr").decode()
    invocations=[]
    for line in stderr.splitlines():
        stripped=line.strip()
        if stripped.startswith("Running ")and chr(96)in stripped:
            raw=stripped.split(chr(96),1)[1].rsplit(chr(96),1)[0]
            args=shlex.split(raw);invocations.append(args)
    actual=[a for a in invocations if"--crate-name"in a and a[a.index("--crate-name")+1]=="hia_namespace_versions_reference"]
    require(len(actual)==1,"one actual original target Rust compiler")
    args=actual[0]
    require(str(rustbin/"rustc")in args and any(x in args for x in("main.rs",str(ref/"main.rs")))and"--edition=2021"in args
        and"--crate-type"in args and args[args.index("--crate-type")+1]=="bin"and"--emit=dep-info,link"in args,
        "whole original source edition and executable compilation")
    settings=[args[i+1]for i,x in enumerate(args[:-1])if x=="-C"]
    require(all(x in settings for x in("opt-level=1","codegen-units=256","debuginfo=2","debug-assertions=on"))
        and not any(x in settings for x in("debug-assertions=off","overflow-checks=off","panic=abort","lto","lto=yes")),
        "actual original diagnostic arithmetic/panic profile")
    packages=[p for p in tomllib.loads(read(ROOT/"reference/Cargo.lock").decode())["package"]if"source"in p]
    crate_files=0;crate_bytes=0;omitted={};vendor_count=0
    for p in packages:
        name=p["name"]+"-"+p["version"];raw=read(build/"crates"/(name+".crate"))
        require(pin(raw)["sha256"]==p["checksum"],"entire actual locked crate archive")
        archive={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz")as tar:
            for entry in tar:
                path=Path(entry.name);require(not path.is_absolute()and".."not in path.parts and path.parts[0]==name,"bounded crate member")
                if entry.isdir():continue
                require(entry.isfile(),"ordinary complete crate source")
                body=tar.extractfile(entry).read();require(len(body)==entry.size,"whole exact crate member")
                relative=Path(*path.parts[1:]).as_posix();require(relative not in archive,"unique full crate source member")
                archive[relative]=body;crate_files+=1;crate_bytes+=len(body)
        directory=build/"vendor"/name;actualfiles=files(directory)
        checksum=loads(read(directory/".cargo-checksum.json"));require(checksum["package"]==p["checksum"],"whole vendor crate checksum identity")
        require(set(actualfiles)==set(checksum["files"])|{".cargo-checksum.json"},"all actual vendor members")
        absent={}
        for relative,body in archive.items():
            if relative not in actualfiles:
                require(Path(relative).name in(".gitignore",".gitattributes"),"only documented Cargo nonimplementation metadata omission")
                absent[relative]=pin(body);continue
            require(read(directory/relative)==body and checksum["files"][relative]==pin(body)["sha256"],"every complete implementation source byte")
        require(set(actualfiles)-{".cargo-checksum.json"}<=set(archive),"no implementation member outside locked archives")
        omitted[name]=absent;vendor_count+=len(actualfiles)
    actual_elf=read(build/"original.elf");binding=symbols(actual_elf)
    require(binding==metadata["elf_bindings"]==loads(read(build/"ELF-BINDINGS.json"))
        and metadata["original_binary"]==pin(actual_elf)
        and read(build/"target/x86_64-unknown-linux-gnu/debug/hia-namespace-versions-reference")==actual_elf,
        "entire actual retained executable, local statics and compiled type layouts")
    readelf=read(build/"processes/actual-symbols.stdout").decode()
    for row in binding["symbols"].values():require(row["name"]in readelf,"actual source-defined readelf symbol present")
    return dict(status="COMPLETE_ORIGINAL_NAMESPACE_BUILD_READ_PASS",source_manifest_sha256=identity,original_module=checked["original"],
        original_binary=pin(actual_elf),elf_bindings=binding,locked_crates=len(packages),archive_source_files=crate_files,
        archive_source_bytes=crate_bytes,vendor_files=vendor_count,retained_nonimplementation_metadata=omitted,
        actual_rustc_invocations=len(invocations),native_application_calls=0,original_application_calls=0,
        reader_native_executions=0,reader_rust_executions=0,namespace_version_qualified=False,public_handler_qualified=False)
def run(build,output):
    started=time.monotonic();result=guarded(lambda:verify(build),roots=[ROOT,build],foreign_path="/tmp/namespace-original-forbidden/CAPTURE.json")
    require(time.monotonic()-started<=180,"whole pure reader deadline")
    output.write_bytes(encoded(result));print(encoded(dict(result["evidence"],guard_probes=len(result["probes"]),files=len(result["before"]),
        elapsed_seconds=time.monotonic()-started)).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--build",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    run(a.build.resolve(strict=True),a.output.absolute())
