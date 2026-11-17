"""Whole same-source producer capture; physical reads only after explicit preload."""
from pathlib import Path
import math
from common import ROOT,encoded,loads,pin,read,require,files,source
from commands import commands
from protocol import domain
from read_frames import equal
import source_check,read_callable_build,read_dependencies,read_pair
PREPARED_SOURCE_CHECK=None
def prepare():
    global PREPARED_SOURCE_CHECK
    PREPARED_SOURCE_CHECK=source_check.check()
def exact_commands(metadata):
    old=metadata["source_root"];rows=commands(dict(metadata,source_root=str(ROOT)))
    for row in rows:
        row["argv"]=[old+x[len(str(ROOT)):]if x==str(ROOT)or x.startswith(str(ROOT)+"/")else x for x in row["argv"]]
        if row["cwd"]==str(ROOT):row["cwd"]=old
    return rows
def custody(root,m):
    rows=loads(read(root/"processes/processes.json"));wanted=exact_commands(m);outputs={};expected_files={"processes.json"}
    equal(m["commands"],wanted,"all exact recorded producer command arguments")
    require(len(rows)==len(wanted)==19 and all(type(m[k])is int and m[k]>1 for k in("root_pid","root_pgid")),
            "complete actual capture custody and commands")
    for row,command in zip(rows,wanted,strict=True):
        name=command["name"]
        require(row["name"]==name and row["argv"]==command["argv"]and row["cwd"]==command["cwd"]and
                type(row["timeout_seconds"])is int and row["timeout_seconds"]==command["timeout"]and
                type(row["exit_code"])is int and row["exit_code"]==0 and row["timed_out"]is False and
                row["completed"]is True and row["stdin"]is None and
                type(row["elapsed_seconds"])in(int,float)and math.isfinite(row["elapsed_seconds"])and
                0<row["elapsed_seconds"]<=command["timeout"],"actual bounded successful owned process: "+name)
        require(all(type(row[k])is int and row[k]>1 for k in("pid","pgid","parent_pid"))and
                row["pgid"]==row["pid"]!=row["parent_pid"]==m["root_pid"],"every actual parent and owned process group")
        streams={}
        for kind in("stdout","stderr"):
            filename=name+"."+kind;raw=read(root/"processes"/filename)
            equal(row[kind],dict(file=filename,**pin(raw)),"entire actual process stream "+filename)
            streams[kind]=raw;expected_files.add(filename)
        outputs[name]=dict(row=row,**streams)
    require(set(files(root/"processes"))==expected_files,"complete owned process file set")
    require(b"\nrelease: 1.95.0\n"in outputs["toolchain"]["stdout"]and
            b"\nhost: x86_64-unknown-linux-gnu\n"in outputs["toolchain"]["stdout"]and
            outputs["cargo-version"]["stdout"].startswith(b"cargo 1.95.0 ")and
            outputs["strace-version"]["stdout"].startswith(b"strace -- version "),"actual fixed original compiler and syscall observer")
    require(PREPARED_SOURCE_CHECK is not None and outputs["source-check"]["stdout"]==encoded(PREPARED_SOURCE_CHECK),
            "complete source check, preloaded before guard without compiling under guard")
    require(pin(read(root/"original.elf"))==m["original_binary"]and read(root/"original.elf")[:4]==b"\x7fELF",
            "whole fresh original executable")
    env=m["environment"]["explicit_reference_environment"];rust=Path(m["rust_bin"])
    require(env["RUSTC"]==str(rust/"rustc")and env["RUSTDOC"]==str(rust/"rustdoc")and
            env["CARGO_BUILD_RUSTC"]==str(rust/"rustc")and env["CARGO_TARGET_DIR"]==str(Path(m["build_temporary"])/"target")and
            env["CARGO_BUILD_TARGET"]=="x86_64-unknown-linux-gnu"and
            all(env[k]==""for k in("RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC_WRAPPER",
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS","CARGO_BUILD_RUSTFLAGS"))and
            m["cargo_home"]==str(Path(m["build_temporary"])/"cargo"),"nonambient locked actual Rust invocation")
    build=loads(read(root/"build/BUILD.json"))
    require(outputs["native-build"]["stdout"]==encoded(build)and outputs["native-build"]["stderr"]==b"",
            "entire actual native build stdout/stderr")
    require(build["assembler"][0]["argv"]==["/usr/bin/as","--64","--fatal-warnings","-o",
        m["producer_root"]+"/build/assembler/adapter.o",m["source_root"]+"/authoring/namespace_fingerprint_callable.S"],
        "exact original assembler source and destination")
    rustlog=outputs["rust-build"]["stderr"].decode("utf-8")
    main=[s for s in rustlog.splitlines()if"Running "in s and"--crate-name hia_namespace_fingerprint_reference "in s]
    require(len(main)==1 and "main.rs"in main[0]and"--crate-type bin"in main[0]and"--edition=2021"in main[0]and
            "test"in main[0]and"--extern sha2="in main[0]and"--extern libc="in main[0]and"--extern serde_json="in main[0]and
            outputs["rust-build"]["stdout"]==b"","actual fresh original full-module rustc invocation and diagnostics")
    for name in("source-check","toolchain","cargo-version","strace-version","native-build-readback"):
        require(outputs[name]["stderr"]==b"","complete successful tool diagnostics "+name)
    return outputs
def verify(root):
    m=loads(read(root/"CAPTURE.json"));source_sha=source()
    require(m["schema"]=="hepta.namespace-fingerprint.capture.v1"and m["status"]=="PRODUCERS_PASS_READBACK_PENDING"and
            m["source_manifest_sha256"]==source_sha and all(m[k]is False for k in
            ("namespace_watch_qualified","namespace_version_qualified","public_handler_qualified","whole_runtime_replaced")),
            "original complete producer remains pending reader without enlarged qualification")
    equal(files(root,("CAPTURE.json",)),m["files"],"entire source/build/process/buffer/FS capture and modes")
    equal(files(root/"source"),files(ROOT),"whole copied native/reference source")
    equal(files(root/"reference"),files(ROOT/"reference"),"whole actual compiled original source")
    processes=custody(root,m);compiled=read_callable_build.verify(root/"build")
    require(processes["native-build-readback"]["stdout"]==encoded(compiled),"complete actual pre-replay build reader")
    dependencies=read_dependencies.verify(root);cohorts=[]
    for group in domain(ROOT)["groups"]:
        process=processes["paired-"+group];report=loads(read(root/("paired-"+group)/"PAIRED.json"))
        require(process["stdout"]==encoded(report)and process["stderr"]==b"","whole actual same-tree cohort process streams")
        cohorts.append(read_pair.verify(root,m,group,process["row"],compiled,source_sha))
    require(sum(c["cases"]for c in cohorts)==72 and sum(c["operations"]for c in cohorts)==156,
            "entire unchanged frozen corpus")
    return dict(schema="hepta.namespace-fingerprint.readback.v1",status="PASS",source_manifest_sha256=source_sha,
        actual_producer_processes=len(processes),fresh_build=compiled,dependencies=dependencies,cohorts=cohorts,
        cases=72,operations=156,actual_role_processes=30,actual_role_operations=468,
        owner_calls=sum(c["actual_owner_calls"]for c in cohorts),
        boundary_calls=sum(c["actual_boundary_calls"]for c in cohorts),
        complete_observed_buffer_bytes=sum(c["observed_buffer_bytes"]for c in cohorts),
        complete_observer_free_buffer_bytes=sum(c["observer_free_buffer_bytes"]for c in cohorts),
        native_or_rust_executions=0,reader_writes=0,
        qualified_scope="private original fingerprint fallback and same-tree actual libc pump; whole buffers, kernel effects and native observer-free equality",
        exact_public_error_rendering_qualified=False,namespace_watch_qualified=False,namespace_version_qualified=False,
        archive_store_qualified=False,hot_cache_qualified=False,begin_finish_caller_qualified=False,
        public_handler_qualified=False,whole_runtime_replaced=False)
