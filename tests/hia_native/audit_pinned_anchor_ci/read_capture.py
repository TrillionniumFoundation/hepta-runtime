"""Complete new same-source anchor capture readback, without executing any code."""
from pathlib import Path
import math
from common import ROOT,encoded,loads,pin,read,require,files,source
from commands import commands
from protocol import cases
import source_check,read_callable_build,read_callable,read_original,read_transport_controls,read_dependencies,read_trace,hia_controls

def custody(root,m):
    rows=loads(read(root/"processes/processes.json"));wanted=commands(m);outputs={};expected_files={"processes.json"}
    require(m["commands"]==wanted and len(rows)==len(wanted)==13,"all exact new producer commands")
    require(all(type(m[k]) is int and m[k]>1 for k in ("root_pid","root_pgid")),"actual capture custody")
    for row,command in zip(rows,wanted,strict=True):
        name=command["name"]
        require(row["name"]==name and row["argv"]==command["argv"] and row["cwd"]==command["cwd"] and
            type(row["timeout_seconds"]) is int and row["timeout_seconds"]==command["timeout"] and
            type(row["exit_code"]) is int and row["exit_code"]==0 and row["timed_out"] is False and row["completed"] is True and row["stdin"] is None and
            type(row["elapsed_seconds"]) in (int,float) and math.isfinite(row["elapsed_seconds"]) and 0<row["elapsed_seconds"]<=command["timeout"],"actual bounded successful owned process")
        require(all(type(row[k]) is int and row[k]>1 for k in ("pid","pgid","parent_pid")) and
            row["pgid"]==row["pid"]!=row["parent_pid"]==m["root_pid"],"every actual PID/PGID and parent")
        streams={}
        for kind in ("stdout","stderr"):
            filename=name+"."+kind;raw=read(root/"processes"/filename)
            require(row[kind]==dict(file=filename,**pin(raw)),"all complete actual process streams")
            streams[kind]=raw;expected_files.add(filename)
        outputs[name]=dict(row=row,**streams)
    require(set(files(root/"processes"))==expected_files,"exact complete process file set")
    require(b"\nrelease: 1.95.0\n" in outputs["toolchain"]["stdout"] and b"\nhost: x86_64-unknown-linux-gnu\n" in outputs["toolchain"]["stdout"] and
            outputs["cargo-version"]["stdout"].startswith(b"cargo 1.95.0 ") and outputs["strace-version"]["stdout"].startswith(b"strace -- version "),"actual fixed tools")
    require(outputs["source-check"]["stdout"]==encoded(source_check.check()),"complete actual source-check report")
    require(pin(read(root/"original.elf"))==m["original_binary"] and read(root/"original.elf")[:4]==b"\x7fELF","actual complete original binary")
    env=m["environment"]["explicit_reference_environment"];rust=Path(m["rust_bin"])
    require(env["RUSTC"]==str(rust/"rustc") and env["RUSTDOC"]==str(rust/"rustdoc") and
        env["CARGO_TARGET_DIR"]==str(Path(m["build_temporary"])/"target") and env["CARGO_BUILD_TARGET"]=="x86_64-unknown-linux-gnu" and
        all(env[k]=="" for k in ("RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC_WRAPPER","CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS","CARGO_BUILD_RUSTFLAGS")) and
        m["cargo_home"]==str(Path(m["build_temporary"])/"cargo"),"nonambient original compiler/dependency paths")
    reports={"native-build":"build/BUILD.json","native-observed":"native-observed/NATIVE.json","native-observer-off":"native-observer-off/NATIVE.json",
             "original":"original/ORIGINAL.json","native-controls":"transport-controls/CONTROLS.json","owner-controls":"owner-controls/CONTROLS.json"}
    domain=cases(ROOT);markers=b"".join(("ANCHOR_PUMP_%s %d %d\n"%(phase,ci,1+ci*100+si)).encode() for ci,c in enumerate(domain) for si in range(len(c["steps"])) for phase in ("BEGIN","END"))
    for name,path in reports.items():
        report=loads(read(root/path));process=outputs[name]["row"]
        require(outputs[name]["stdout"]==encoded(report),"entire actual stdout equals producer report")
        require(outputs[name]["stderr"]==(markers if name in ("native-observed","native-observer-off") else b""),"complete expected producer stderr")
        if name=="native-build":
            require(report["assembler"][0]["argv"]==["/usr/bin/as","--64","--fatal-warnings","-o",m["producer_root"]+"/build/assembler/adapter.o",m["source_root"]+"/authoring/audit_pinned_anchor_callable.S"],"actual source-bound assembler")
        elif name=="original":
            actual=loads(read(root/"original/process.json"))
            require(actual["parent_pid"]>1 and actual["pgid"]==process["pid"] and actual["parent_pid"]!=process["pid"] and
                    actual["source_root"]==m["source_root"],"actual original Rust child under traced fixture process")
        else:
            folder=path.rsplit("/",1)[0]
            require(report["source_root"]==m["source_root"] and report["build_root"]==m["producer_root"]+"/build" and
                    report["output_root"]==m["producer_root"]+"/"+folder and report["pgid"]==process["pid"],"exact actual native source/build/output roots")
            if name=="native-observer-off":require(report["parent_pid"]==process["pid"] and report["pid"]!=process["pid"],"actual traced native child")
            else:require(report["pid"]==process["pid"] and report["parent_pid"]==m["root_pid"],"actual direct native child")
            if name in ("native-observed","native-observer-off"):
                require(report["root"]==m["owned_fixture"] and report["uid"]==m["uid"] and report["gid"]==m["gid"],"exact ordinary fixture identity")
            elif name=="native-controls":require(report["fixture"]==m["control_fixture"] and report["uid"]==m["uid"] and report["gid"]==m["gid"],"exact admission fixture identity")
            else:require(report["observed_root"]==m["producer_root"]+"/native-observed","exact actual checkpoint source")
    for name in ("source-check","toolchain","cargo-version","strace-version"):
        require(outputs[name]["stderr"]==b"","complete tool diagnostics")
    return outputs

def verify(root):
    m=loads(read(root/"CAPTURE.json"))
    require(m["schema"]=="hepta.audit-pinned-anchor.capture.v1" and m["status"]=="PASS" and m["source_manifest_sha256"]==source() and
        m["audit_trace_environment_absent"] is True and m["whole_audit_caller_qualified"] is False and m["public_handler_qualified"] is False and m["whole_runtime_replaced"] is False,"exact scoped same-source successful capture")
    require(files(root,("CAPTURE.json",))==m["files"],"every captured file and mode")
    require(files(root/"source")==files(ROOT) and files(root/"reference")==files(ROOT/"reference"),"entire exact original/native source tree")
    processes=custody(root,m);compiled=read_callable_build.verify(root/"build");dependencies=read_dependencies.dependencies(root)
    observed=read_callable.verify(root/"native-observed",compiled["image"],observed=True)
    off=read_callable.verify(root/"native-observer-off",compiled["image"],observed=False,peer=observed,trace=root/"native-observer-off.strace",stderr=root/"processes/native-observer-off.stderr")
    original=read_original.verify(root,m,observed)
    original_process=loads(read(root/"original/process.json"));original_rows=loads(read(root/"original/OBSERVATIONS.json"))
    traced,stderr=read_trace.original(read(root/"original.strace"),original_process["pid"],cases(ROOT),original_rows)
    require(stderr==read(root/"original/original.stderr"),"all actual original stderr observed independently")
    transport=read_transport_controls.verify(root/"transport-controls",compiled["image"],observed)
    owner=hia_controls.verify(root/"owner-controls",root/"native-observed",root/"build/modules/audit-pinned-anchor/manifest.json")
    concise=lambda d:{k:v for k,v in d.items() if k not in ("observations","events","per_case_counts")}
    return dict(schema="hepta.audit-pinned-anchor.readback.v1",status="PASS",source_manifest_sha256=source(),actual_producer_processes=len(processes),
        fresh_build=compiled,dependencies=dependencies,observed=concise(observed),observer_off=concise(off),original=original,original_syscalls=traced,
        transport_controls=transport,owner_controls=owner,native_or_rust_executions=0,reader_writes=0,
        qualified_scope="private persistent PinnedAnchor open/fence/drop with actual ordinary retained-descriptor filesystem transport",
        exact_serde_error_text_compared=False,archive_store_qualified=False,hot_cache_qualified=False,begin_finish_caller_qualified=False,
        public_handler_qualified=False,whole_runtime_replaced=False)
