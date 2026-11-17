"""Whole frozen source, actual Rust toolchain/registry and owned process receipts."""
import sys,types,shlex
from pathlib import Path
from reader_common import ROOT,read,loads,pin,require,files,source,integer,pair_path
from read_pairs import exact,elapsed
from read_dependencies import verify as dependencies
from read_trace_controls import verify as trace_controls
def prepare_source(root):
    names=("common","protocol","source_check");saved={n:sys.modules.get(n)for n in names};modules={};old_path=list(sys.path)
    try:
        for name in names:
            path=root/(name+".py");m=types.ModuleType(name);m.__file__=str(path);m.__package__=""
            sys.modules[name]=m;exec(compile(read(path),str(path),"exec"),m.__dict__);modules[name]=m
        result=modules["source_check"].verify()
    finally:
        sys.path[:]=old_path
        for name,old in saved.items():
            if old is None:sys.modules.pop(name,None)
            else:sys.modules[name]=old
    return dict(root=root,result=result)
def commands(m,groups):
    root=Path(m["source_root"]);out=Path(m["producer_root"]);rust=Path(m["rust_bin"]);python=m["python"]
    ref=out/"reference";config=["--config",'source.crates-io.replace-with="fixed-vendor"',
        "--config",'source.fixed-vendor.directory="'+str(out/"vendor")+'"']
    rows=[
        ("source-check",[python,"-I","-B",root/"source_check.py"],root,60),
        ("toolchain",[rust/"rustc","--version","--verbose"],root,60),
        ("cargo-version",[rust/"cargo","--version","--verbose"],root,60),
        ("strace-version",["/usr/bin/strace","--kill-on-exit","--version"],root,60),
        ("trace-process-controls",[python,"-I","-B",root/"trace_controls.py","--output",out/"trace-controls"],root,60),
        ("native-build-readback",[python,"-I","-B",root/"read_build_cli.py","--retained",m["retained_root"]],root,180),
        ("rust-fetch",[rust/"cargo","fetch","--locked","--manifest-path",ref/"Cargo.toml"],ref,180),
        ("rust-vendor",[rust/"cargo","vendor","--locked","--offline","--versioned-dirs","--manifest-path",ref/"Cargo.toml",out/"vendor"],ref,180),
        ("rust-build",[rust/"cargo","build","--frozen","--verbose","--target","x86_64-unknown-linux-gnu","--manifest-path",ref/"Cargo.toml",*config],ref,900)]
    for group in groups:
        name="paired-"+group
        argv=[python,"-I","-B",root/"run_pairs.py","--retained",m["retained_root"],
            "--binary",out/"original.elf","--output",out/name,"--fixture",Path(m["owned_fixture"])/group,"--group",group]
        rows.append((name,argv,root,60))
    return[dict(name=n,argv=[str(x)for x in argv],cwd=str(cwd),timeout=budget)for n,argv,cwd,budget in rows]
def process(row,expected,folder,parent):
    require(set(row)=={"name","argv","cwd","pid","parent_pid","pgid","exit_code","timed_out","completed",
        "timeout_seconds","elapsed_seconds","stdin","stdout","stderr"}and row["name"]==expected["name"]
        and row["argv"]==expected["argv"]and row["cwd"]==expected["cwd"]and row["stdin"]is None
        and type(row["pid"])is int and row["pid"]>0 and row["pid"]==row["pgid"]and row["parent_pid"]==parent
        and row["pid"]!=parent and row["exit_code"]==0 and type(row["exit_code"])is int
        and row["timed_out"]is False and row["completed"]is True and type(row["timeout_seconds"])is int
        and row["timeout_seconds"]==expected["timeout"],"whole actual owned process identity/command/terminal")
    elapsed(row["elapsed_seconds"],expected["timeout"]);result={}
    for key in("stdout","stderr"):
        p=row[key];require(set(p)=={"file","bytes","sha256"}and p["file"]==row["name"]+"."+key,"complete process stream names")
        raw=read(folder/p["file"]);require(pin(raw)=={k:p[k]for k in("bytes","sha256")},"complete actual process "+key);result[key]=raw
    return result
def verify(bundle,prepared,admission):
    root=bundle/"run";src=bundle/"source"
    require(read(ROOT/"PRODUCER-SOURCE.json")==read(src/"SOURCE.json")==read(root/"source/SOURCE.json"),
        "whole exact frozen V4 producer source manifest and captured copy")
    source_sha=source(src,read(ROOT/"PRODUCER-SOURCE.json"),"hepta.namespace-watcher.semantic-source.v1")
    require(source(root/"source",read(ROOT/"PRODUCER-SOURCE.json"),"hepta.namespace-watcher.semantic-source.v1")==source_sha,
        "all actual copied producer source bytes")
    require(prepared["root"]==src and prepared["result"]["source_manifest_sha256"]==source_sha,"same preloaded whole original source check")
    expected_ref={n[10:]:r for n,r in loads(read(src/"SOURCE.json"))["files"].items()if n.startswith("reference/")}
    require(files(root/"reference")=={n:dict(bytes=r["bytes"],sha256=r["sha256"],mode=0o644)for n,r in expected_ref.items()},
        "every complete actual original source and lock before Cargo")
    domain=loads(read(src/"DOMAIN.json"));require(domain==loads(read(ROOT/"DOMAIN.json"))and domain["total_cases"]==58
        and domain["total_operations"]==984 and domain["max_roots"]==260 and
        domain["limits"]==dict(process_seconds=60,reader_seconds=180,rust_build_seconds=900,job_minutes=15),
        "entire unchanged original semantic domain and all budgets")
    m=loads(read(root/"CAPTURE.json"));require(m["schema"]=="hepta.namespace-watcher.semantic-capture.v1"
        and m["status"]=="PRODUCERS_PASS_READBACK_PENDING"and m["source_manifest_sha256"]==source_sha
        and m["uid"]==m["gid"]==1001 and integer(m["root_pid"],1)and integer(m["root_pgid"],1)
        and all(m[k]is False for k in("private_watcher_qualified","namespace_version_qualified","public_handler_qualified","whole_runtime_replaced")),
        "original completed producer attribution remains unchanged")
    for key in("source_root","producer_root","retained_root","build_temporary","cargo_home","owned_fixture","rust_bin","python"):pair_path(m[key])
    require(m["cargo_home"]==str(Path(m["build_temporary"])/"cargo")and
        m["owned_fixture"]==str(Path(m["build_temporary"])/"owned-fixture")and m["python"]=="/usr/bin/python3"
        and Path(m["rust_bin"]).parts[-2:]==("1.95.0-x86_64-unknown-linux-gnu","bin"),"exact original build/runtime paths")
    require(files(root,("CAPTURE.json",))==m["files"],"all complete actual captured files, modes and no additions")
    expected=commands(m,domain["groups"]);exact(m["commands"],expected,"all source-defined actual commands")
    rows=loads(read(root/"processes/processes.json"));require(len(rows)==len(expected)==22 and len({r["pid"]for r in rows})==22,
        "all independently owned completed producer processes")
    streams={r["name"]:process(r,e,root/"processes",m["root_pid"])for r,e in zip(rows,expected)}
    for name,stream in streams.items():
        if name not in("rust-fetch","rust-vendor","rust-build"):require(stream["stderr"]==b"","complete successful producer stderr")
    exact(loads(streams["source-check"]["stdout"]),prepared["result"],"complete actual source-check process result")
    exact(loads(streams["native-build-readback"]["stdout"]),admission,"complete actual fixed8 native build readback")
    tool=streams["toolchain"]["stdout"].decode()
    require(tool.startswith("rustc 1.95.0 ")and "\nrelease: 1.95.0\n"in tool and "\nhost: x86_64-unknown-linux-gnu\n"in tool,
        "actual exact target Rust toolchain")
    require(streams["cargo-version"]["stdout"].startswith(b"cargo 1.95.0 ")and
        b"strace -- version 6.8"in streams["strace-version"]["stdout"],"actual recorded Cargo and ptrace implementation")
    env=m["environment"];rust=Path(m["rust_bin"])
    wanted=dict(RUSTC=str(rust/"rustc"),RUSTDOC=str(rust/"rustdoc"),RUSTC_WRAPPER="",RUSTC_WORKSPACE_WRAPPER="",
        CARGO_BUILD_RUSTC=str(rust/"rustc"),CARGO_BUILD_RUSTC_WRAPPER="",CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER="",
        CARGO_ENCODED_RUSTFLAGS="",CARGO_ENCODED_RUSTDOCFLAGS="",CARGO_BUILD_RUSTFLAGS="",
        CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu",CARGO_TARGET_DIR=str(Path(m["build_temporary"])/"target"))
    require(env["explicit_reference_environment"]==wanted and env["cargo_encoded_rustflags_override"]==""
        and env["inherited_environment_values_not_logged"]is True and
        type(env["removed_keys"])is list and env["removed_keys"]==sorted(set(env["removed_keys"])),
        "all actual controlled Rust/Cargo environment, no inferred build flags")
    binary=read(root/"original.elf");require(pin(binary)==m["original_binary"]and binary[:7]==b"\x7fELF\x02\x01\x01",
        "complete actual unchanged original executable")
    build=streams["rust-build"]["stderr"].decode();invocations=[]
    for line in build.splitlines():
        if line.lstrip().startswith("Running "):
            text=line.strip()[8:];require(text.startswith(chr(96))and text.endswith(chr(96)),"whole Cargo verbose invocation")
            invocations.append(shlex.split(text[1:-1]))
    roots=[a for a in invocations if"--crate-name"in a and a[a.index("--crate-name")+1]=="hia_namespace_watcher_reference"]
    require(len(roots)==1,"one complete actual target source compiler invocation")
    argv=roots[0];require(argv[0]==str(rust/"rustc")and argv[argv.index("--crate-type")+1]=="bin"
        and argv[argv.index("--edition")+1]=="2021"and argv[argv.index("--target")+1]=="x86_64-unknown-linux-gnu"
        and "main.rs"in argv,"actual exact original main source/target")
    codegen=[argv[i+1]for i,x in enumerate(argv)if x=="-C"]
    require("opt-level=1"in codegen and "debuginfo=2"in codegen and "debug-assertions=on"in codegen
        and "codegen-units=256"in codegen and not any(x in codegen for x in("overflow-checks=off","panic=abort","lto=yes")),
        "actual unchanged original profile and full validation")
    deps=dependencies(root,src)
    controls=trace_controls(root/"trace-controls",rows[4],streams["trace-process-controls"]["stdout"],source_sha)
    return dict(metadata=m,domain=domain,processes={r["name"]:r for r in rows},
        producer=dict(python_resolved="/usr/bin/python3.12"),source_sha256=source_sha,
        summary=dict(status="COMPLETE_WATCHER_PRODUCER_CUSTODY_PASS",processes=22,toolchain=pin(streams["toolchain"]["stdout"]),
            dependencies=deps,trace_controls=controls,original_binary=m["original_binary"]))
