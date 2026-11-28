"""Whole same-source producer capture; only physical retained reads are permitted."""
from pathlib import Path
import math
from common import ROOT,encoded,loads,pin,read,require,files,source
from commands import commands
from protocol import cases,domain
import source_check,read_callable_build,read_callable,read_original,read_dependencies
def exact_commands(metadata):
    # Recompute the same source-owned argv using the current admitted source only.
    # Old producer locations are compared as inert strings, never opened.
    old=metadata["source_root"];m=dict(metadata,source_root=str(ROOT))
    rows=commands(m)
    for row in rows:
        row["argv"]=[old+x[len(str(ROOT)):] if x==str(ROOT) or x.startswith(str(ROOT)+"/") else x for x in row["argv"]]
        if row["cwd"]==str(ROOT):row["cwd"]=old
    return rows
def custody(root,m):
    rows=loads(read(root/"processes/processes.json"));wanted=exact_commands(m);outputs={};expected_files={"processes.json"}
    require(m["commands"]==wanted and len(rows)==len(wanted)==35,"all exact recorded producer commands")
    require(all(type(m[k]) is int and m[k]>1 for k in ("root_pid","root_pgid")),"actual capture custody")
    for row,command in zip(rows,wanted,strict=True):
        name=command["name"]
        require(row["name"]==name and row["argv"]==command["argv"] and row["cwd"]==command["cwd"] and
            type(row["timeout_seconds"]) is int and row["timeout_seconds"]==command["timeout"] and
            type(row["exit_code"]) is int and row["exit_code"]==0 and row["timed_out"] is False and row["completed"] is True and row["stdin"] is None and
            type(row["elapsed_seconds"]) in (int,float) and math.isfinite(row["elapsed_seconds"]) and 0<row["elapsed_seconds"]<=command["timeout"],
            "actual bounded successful owned process: "+name)
        require(all(type(row[k]) is int and row[k]>1 for k in ("pid","pgid","parent_pid")) and
            row["pgid"]==row["pid"]!=row["parent_pid"]==m["root_pid"],"every actual PID/PGID and parent")
        streams={}
        for kind in ("stdout","stderr"):
            filename=name+"."+kind;raw=read(root/"processes"/filename)
            require(row[kind]==dict(file=filename,**pin(raw)),"entire actual process stream: "+filename)
            streams[kind]=raw;expected_files.add(filename)
        outputs[name]=dict(row=row,**streams)
    require(set(files(root/"processes"))==expected_files,"exact whole process file set")
    require(b"\nrelease: 1.95.0\n" in outputs["toolchain"]["stdout"] and b"\nhost: x86_64-unknown-linux-gnu\n" in outputs["toolchain"]["stdout"] and
            outputs["cargo-version"]["stdout"].startswith(b"cargo 1.95.0 ") and outputs["strace-version"]["stdout"].startswith(b"strace -- version "),
            "actual fixed original compiler and syscall observer")
    require(outputs["source-check"]["stdout"]==encoded(source_check.check()),"entire actual source-check report")
    require(pin(read(root/"original.elf"))==m["original_binary"] and read(root/"original.elf")[:4]==b"\x7fELF","entire original executable")
    env=m["environment"]["explicit_reference_environment"];rust=Path(m["rust_bin"])
    require(env["RUSTC"]==str(rust/"rustc") and env["RUSTDOC"]==str(rust/"rustdoc") and
        env["CARGO_TARGET_DIR"]==str(Path(m["build_temporary"])/"target") and env["CARGO_BUILD_TARGET"]=="x86_64-unknown-linux-gnu" and
        all(env[k]=="" for k in ("RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC_WRAPPER","CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS","CARGO_BUILD_RUSTFLAGS")) and
        m["cargo_home"]==str(Path(m["build_temporary"])/"cargo"),"nonambient locked Rust invocation")
    build=loads(read(root/"build/BUILD.json"))
    require(outputs["native-build"]["stdout"]==encoded(build) and outputs["native-build"]["stderr"]==b"","whole actual build stdout/stderr")
    require(build["assembler"][0]["argv"]==["/usr/bin/as","--64","--fatal-warnings","-o",m["producer_root"]+"/build/assembler/adapter.o",m["source_root"]+"/authoring/audit_anchor_publish_callable.S"],
            "exact actual assembler source and output")
    for group in domain(ROOT)["groups"]:
        rows=cases(ROOT,group)
        markers=b"".join(("PUBLISH_PUMP_%s %d %d\n"%(phase,ci,1+ci*100+si)).encode()
                        for ci,c in rows for si in range(len(c["steps"])) for phase in ("BEGIN","END"))
        for mode in ("observed","off"):
            name="native-"+mode+"-"+group;report=loads(read(root/name/"NATIVE.json"));process=outputs[name]["row"]
            require(outputs[name]["stdout"]==encoded(report) and outputs[name]["stderr"]==markers,"whole native stdout/stderr")
            require(report["source_root"]==m["source_root"] and report["build_root"]==m["producer_root"]+"/build" and
                    report["output_root"]==m["producer_root"]+"/"+name and report["pgid"]==process["pid"] and
                    report["root"]==m["owned_fixture"] and report["uid"]==m["uid"] and report["gid"]==m["gid"],
                    "actual complete native path and process identity")
            if mode=="off":require(report["parent_pid"]==process["pid"] and report["pid"]!=process["pid"],"actual traced native child")
            else:require(report["pid"]==process["pid"] and report["parent_pid"]==m["root_pid"],"actual direct native child")
        name="original-"+group;report=loads(read(root/name/"ORIGINAL.json"))
        require(outputs[name]["stdout"]==encoded(report) and outputs[name]["stderr"]==b"","whole original driver stdout/stderr")
    for name in ("source-check","toolchain","cargo-version","strace-version"):require(outputs[name]["stderr"]==b"","complete tool diagnostics")
    return outputs
def verify(root):
    m=loads(read(root/"CAPTURE.json"))
    require(m["schema"]=="hepta.audit-anchor-publish.capture.v1" and m["status"]=="PRODUCERS_PASS_READBACK_PENDING" and
            m["source_manifest_sha256"]==source() and m["audit_trace_environment_absent"] is True and
            m["whole_audit_caller_qualified"] is False and m["public_handler_qualified"] is False and m["whole_runtime_replaced"] is False,
            "original successful producers retain pending-reader status")
    require(files(root,("CAPTURE.json",))==m["files"],"all captured source/build/process/buffer/filesystem files and modes")
    require(files(root/"source")==files(ROOT) and files(root/"reference")==files(ROOT/"reference"),"entire exact original/native source tree")
    processes=custody(root,m);compiled=read_callable_build.verify(root/"build");dependencies=read_dependencies.dependencies(root)
    cohorts=[];kinds=set();counts=dict(owner_calls=0,json_calls=0,filesystem_calls=0);full_bytes=0;outer_bytes=0;boundary_bytes=0
    concise=lambda d:{k:v for k,v in d.items() if k not in ("observations","events","per_case_counts","signatures","temporaries")}
    for group in domain(ROOT)["groups"]:
        observed=read_callable.verify(root/("native-observed-"+group),compiled["image"],observed=True,group=group)
        off=read_callable.verify(root/("native-off-"+group),compiled["image"],observed=False,group=group,peer=observed,
                                trace=root/("native-off-"+group+".strace"),stderr=root/"processes"/("native-off-"+group+".stderr"))
        original=read_original.verify(root,m,observed,group,processes["original-"+group]["row"])
        for key,value in observed["counts"].items():counts[key]+=value
        kinds.update(map(tuple,observed["effect_kinds"]))
        cohorts.append(dict(group=group,observed=concise(observed),observer_off=concise(off),original=original))
    require(kinds=={(2,i) for i in (1,4,5,6,7,8,9,17,18,19)}|{(3,4)},"all publication/entropy/JSON effect domains actually represented")
    return dict(schema="hepta.audit-anchor-publish.readback.v1",status="PASS",source_manifest_sha256=source(),
                actual_producer_processes=len(processes),fresh_build=compiled,dependencies=dependencies,cohorts=cohorts,
                cases=99,operations=137,actual_counts=counts,native_or_rust_executions=0,reader_writes=0,
                qualified_scope="private publish_archive_anchor and actual SystemRandom entropy within each owned service lifetime",
                process_wide_entropy_cache_concurrency_qualified=False,exact_serde_error_text_compared=False,
                namespace_version_qualified=False,archive_store_qualified=False,hot_cache_qualified=False,
                begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
