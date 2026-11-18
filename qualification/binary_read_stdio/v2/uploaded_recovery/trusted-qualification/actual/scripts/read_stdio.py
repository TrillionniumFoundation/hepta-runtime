#!/usr/bin/env python3
"""Complete pure stdio, kernel, HIA and process-pool evidence admission; no execution."""
from pathlib import Path
import gzip,hashlib,struct
from common import canonical,decode,owned,pin,require,sha,source_evidence
from cases import domain,group,validate,wire
from buffer_store import Reader
from read_fixtures import fixture_rows,setup
from read_journal import Journal,invocation,result,U
from read_kernel import verify as read_kernel,bind_effects
from read_lifecycle import lifecycle

def load(root,name):return decode(owned(root,name).read_bytes())
def stream(path,receipt):
    with gzip.open(path,"rb")as file:raw=file.read()
    require(dict(bytes=len(raw),sha256=sha(raw))==receipt["raw"]and pin(path)==receipt["compressed"]
        and receipt["complete_raw_bytes_in_gzip"]is True and receipt["no_expanded_ordinary_copy_created"]is True,
        "complete compressed process stream differs")
    return raw
def process(source,folder,row,case,raw,role,origin):
    native=role!="original";observed=role=="observed";p=row["process"]
    require(p==load(folder,"PROCESS.json"),"complete process publication")
    names=("stdin","stdout","stderr","body","formatter","ack")
    require({x.name for x in folder.iterdir()}=={n+".gz"for n in names}|{"PROCESS.json","kernel.jsonl.gz","kernel-process.json"}
        and all(x.is_file()and not x.is_symlink()for x in folder.iterdir()),"complete ordinary process file set")
    build=load(source,"BUILD_REUSE.json");base=Path(origin["capture"]);variant="observed"if observed else"production"
    if native:argv=[str(base/"build-reuse/original/restored/run/build"/variant/"binary-read-stdio.elf")]
    else:
        argv=[origin["python"],"-I","-S","-B"]
        if case["fault"]:argv.append(str(base/"source/scripts/fault_original.py"))
        argv.append(str(base/"source/target/binary_file.py"))
    launcher=[origin["python"],"-I","-S","-B",str(base/"source/scripts/trace_launch.py"),
        "native-first-fstat"if native and case["fault"]else"normal",*argv]
    python=dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
    require(p["argv"]==argv and p["launcher_argv"]==launcher and p["launcher"]==pin(source/"scripts/trace_launch.py")
        and p["launcher_python"]==python and p["binary"]==(build["executables"][variant]if native else python)
        and p["native"]is native and p["observed"]is observed and p["fault"]is case["fault"]
        and p["fixed_journal_fds"]==([3,4,5]if observed else[]),"exact executed images, launch and observer")
    require(p["completed"]is True and p["timed_out"]is False and p["timeout_seconds"]==60
        and 0<p["elapsed_ns"]<61_000_000_000 and p["same_outer_process_group"]is True
        and p["parent_pgid"]==p["child_pgid"]and p["parent_pid"]!=p["pid"]
        and p["reaped"]is True and p["after_reap_proc_absent"]is True
        and p["stdin_closed"]is True and p["stdin_broken_pipe"]is False and "failure"not in p,
        "complete bounded natural process custody")
    require(p["input_chunk_bytes"]==case["input_chunk_bytes"]and p["output_chunk_bytes"]==case["output_chunk_bytes"]
        and p["expected_input_bytes"]==len(raw)and set(p["streams"])==set(names),"all fixed process inputs and stream set")
    actual={name:stream(folder/(name+".gz"),p["streams"][name])for name in("stdin","stdout","stderr","ack")}
    require(actual["stdin"]==raw,"exact complete stdin")
    offset=0
    for value in p["writes"]:
        require(value["offset"]==offset and 0<value["count"]<=case["input_chunk_bytes"],"actual fragmented input coverage")
        offset+=value["count"]
    require(offset==len(raw),"all frozen input bytes sent once")
    require(p["returncode"]in(0,1)and p["wait_status"]==p["returncode"]<<8,"ordinary helper exit status")
    if observed:
        require(actual["ack"]==bytes(8)and p["body_framing"]["final_ack_offset"]==p["body_framing"]["bytes"]
            and p["lifecycle_ack"]["bytes"]==8,"complete observed lifecycle ACK")
    else:
        require(actual["ack"]==b""and "lifecycle_ack"not in p and "body_framing"not in p,
            "production/reference has no observer ACK")
        for n in("body","formatter"):require(stream(folder/(n+".gz"),p["streams"][n])==b"","observer-free process journal")
    return p,actual
def formatter(source,folder,process,terminal,expected):
    meta=load(source,"trusted-build/native/platform_data.json")
    require(meta["data_bytes"]==10152 and meta["workspace_required"]==12288
        and meta["unicode_version"]=="15.0.0"and len(meta["classes"])==16,"qualified formatter data identity")
    path=folder/"formatter.gz";receipt=process["streams"]["formatter"]
    if U(terminal,8)==0:
        require(stream(path,receipt)==b"","success invoked error formatter");return dict(calls=0,capacity_retries=0,full_buffer_bytes=0)
    require(U(terminal,8)==3,"formatter borrowed non-error response")
    digest=hashlib.sha256();total=0;ordinal=0;previous_work=None;previous_output=None;cap=4096
    def take(file,event,code=None):
        nonlocal total
        header=file.read(64);require(len(header)==64 and header[:8]==b"HBRFJR01","complete formatter journal header")
        h=struct.unpack("<8Q",header);raw=file.read(h[4])
        require(len(raw)==h[4]and h[1]==event and h[2]==ordinal and h[5]==len(terminal)
            and h[6]==cap and h[7]==12288 and(code is None or h[3]==code),"formatter event/borrow/capacity/return")
        for value in(header,raw):digest.update(value);total+=len(value)
        return h,raw
    with gzip.open(path,"rb")as file:
        while True:
            ordinal+=1
            _,inp=take(file,1,0);_,wb=take(file,2,0);_,ob=take(file,3,0)
            ha,oa=take(file,4);_,wa=take(file,5,ha[3]);code=ha[3]
            require(inp==terminal and len(wb)==len(wa)==12288 and len(ob)==len(oa)==cap,
                "complete formatter arenas")
            require(wb==(bytes(12288)if previous_work is None else previous_work)
                and ob==(bytes(cap)if previous_output is None else previous_output+bytes(cap-len(previous_output))),
                "formatter owned-buffer continuation/growth")
            require(sha(wa[:10152])==meta["data_sha256"]and wa[10152:]==wb[10152:]==bytes(12288-10152),
                "formatter immutable pool and complete unused workspace")
            if code==0xfffffffe:
                require(oa==ob and len(expected)>cap and cap<128<<20,"formatter capacity refusal changed output")
                previous_output=oa;previous_work=wa;cap*=2;continue
            require(code==len(expected)and 0<code<=cap and oa[:code]==expected and oa[code:]==ob[code:],
                "formatter exact diagnostic and full output tail")
            require(not file.read(1),"unread formatter journal suffix");break
    require(dict(bytes=total,sha256=digest.hexdigest())==receipt["raw"]and pin(path)==receipt["compressed"]
        and receipt["complete_raw_bytes_in_gzip"]is True and receipt["no_expanded_ordinary_copy_created"]is True,
        "complete formatter journal custody")
    return dict(calls=ordinal,capacity_retries=ordinal-1,full_buffer_bytes=total-ordinal*5*64,journal_bytes=total)
def capture(source,capture_root,role,name,queries,fixtures,expected,origin):
    root=capture_root/role/name;summary=load(root,"CAPTURE.json");rows=load(root,"cases.json")
    selected=group(name);native=role!="original";observed=role=="observed";ids=[c["id"]for c in selected]
    require(summary["status"]=="ACTUAL_STDIO_READ67_CAPTURE_COMPLETE"and summary["source"]==source_evidence(source)
        and summary["role"]==role and summary["group"]==name and summary["cases"]==summary["process_count"]==len(ids)
        and summary["observer_enabled"]is observed and summary["original_outputs_read"]is False
        and summary["passive_kernel_trace"]is True and summary["runtime_python_required"]is(not native)
        and summary["runtime_libc_required"]is(not native)and [r["id"]for r in rows]==ids,
        "complete new input-only actual role domain")
    env=summary["environment"]
    require(env["unicode_version"]=="15.0.0"and env["lc_messages"]=="C"and env["platform"]=="linux"
        and env["machine"]=="x86_64"and env["python"].startswith("3.12.3 "),"qualified actual Python diagnostic environment")
    store=Reader(root/"buffers");values={};stats=dict(body_calls=0,child_calls=0,raw_os_effects=0,
        body_journal_bytes=0,body_full_buffer_bytes=0,formatter_calls=0,formatter_capacity_retries=0,
        formatter_full_buffer_bytes=0,kernel_calls=0,kernel_bytes=0,orphan_records=0,lifecycle_full_bytes=0,
        actual_bound_file_syscalls=0)
    sums={n:0 for n in("stdin","stdout","stderr","body","formatter","ack")}
    for case,row in zip(selected,rows):
        require(row["name"]==case["name"],"frozen input scenario name")
        q=queries[row["id"]];folder=root/("case-"+str(case["id"]).zfill(3))
        require(row["input"]==q and row["before"]==row["after"]==q["snapshot"],"unchanged shared complete filesystem")
        fixture_rows(row["before"],store,case);fixture_rows(row["after"],store,case)
        raw=wire(q)if native else canonical(q["request"])
        p,out=process(source,folder,row,case,raw,role,origin)
        require(p["parent_pid"]==summary["pid"]and p["binary"]==summary["executed_binary"],"actual role parent and image")
        for key in sums:sums[key]+=p["streams"][key]["raw"]["bytes"]
        kernel=read_kernel(folder,p,out["stdin"],out["stdout"],out["stderr"],q,case)
        stats["kernel_calls"]+=kernel["calls"];stats["kernel_bytes"]+=kernel["trace_bytes"]
        stats["orphan_records"]+=len(kernel["orphans"])
        if p["returncode"]==0:
            require(not out["stderr"]and out["stdout"].endswith(b"\n"),"complete successful actual wire")
            value=decode(out["stdout"]);current=dict(exit=0,value=value,stdout=out["stdout"],stderr=b"")
        else:
            require(not out["stdout"]and out["stderr"].endswith(b"\n"),"complete original failure wire")
            current=dict(exit=1,stdout=b"",stderr=out["stderr"])
        require(not case["fault"]or current["exit"]==1,"real EIO remains an actual failure")
        if native:
            original=expected[row["id"]]
            require(current["exit"]==original["exit"]and current["stderr"]==original["stderr"],"exact original exit and diagnostic")
            if current["exit"]==0:
                require(current["value"]==original["value"]and out["stdout"]==canonical(current["value"]),
                    "complete original JSON Value and native canonical output")
            if observed:require(current==original["native_production"],"production and observed full process outputs")
        if observed:
            journal=Journal(folder/"body.gz")
            invoked=invocation(journal,raw,None,1,fixture=fixtures[row["id"]]);terminal=invoked["frame"]
            stats["actual_bound_file_syscalls"]+=bind_effects(invoked["effects"],kernel)
            life=lifecycle(journal,p,invoked,kernel,case)
            done=journal.finish(p["streams"]["body"])
            require(p["body_framing"]==dict(records=done["events"]+4+life["pages"],bytes=done["journal_bytes"],
                final_ack_offset=done["journal_bytes"]),"complete mixed body and lifecycle framing")
            for k in("body_calls","child_calls","raw_os_effects"):stats[k]+=done[k]
            stats["body_journal_bytes"]+=done["journal_bytes"];stats["body_full_buffer_bytes"]+=done["full_buffer_bytes"]
            stats["lifecycle_full_bytes"]+=life["full_context_bytes"]+life["full_pool_bytes"]
            parsed=result(terminal);require(parsed["ok"]is(current["exit"]==0),"complete body terminal and helper exit")
            if parsed["ok"]:
                require(parsed["value"]==current["value"]and terminal[64:]+b"\n"==out["stdout"],"full body output loan publication")
            rendered=formatter(source,folder,p,terminal,current["stderr"][:-1]if current["exit"]else b"")
            stats["formatter_calls"]+=rendered["calls"];stats["formatter_capacity_retries"]+=rendered["capacity_retries"]
            stats["formatter_full_buffer_bytes"]+=rendered["full_buffer_bytes"]
        values[row["id"]]=current
    buffers=store.finish()
    require(buffers["complete_images"]==summary["buffer_images"]and buffers["logical_buffer_bytes"]==summary["logical_buffer_bytes"]
        and sums==summary["streams"]and stats["kernel_calls"]==summary["kernel_calls"]and stats["kernel_bytes"]==summary["kernel_bytes"],
        "complete retained buffer, process stream and passive syscall inventory")
    require(stats["orphan_records"]==sum(c["fault"]for c in selected),"complete actual role orphan domain")
    return values,dict(cases=len(ids),role=role,group=name,streams=sums,buffers=buffers,**stats)

def verify(source,capture_root,name):
    source,capture_root=Path(source),Path(capture_root);validate()
    queries,fixtures,setup_stats=setup(source,capture_root/"setup",name);qs={q["id"]:q for q in queries}
    origin=load(capture_root,"ORIGIN.json");require(origin["group"]==name,"actual group origin")
    reference,a=capture(source,capture_root,"original",name,qs,fixtures,{},origin)
    production,b=capture(source,capture_root,"production",name,qs,fixtures,reference,origin)
    for key,value in reference.items():value["native_production"]=production[key]
    observed,c=capture(source,capture_root,"observed",name,qs,fixtures,reference,origin)
    success=sum(r["exit"]==0 for r in reference.values());failure=sum(r["exit"]==1 for r in reference.values())
    stats=[a,b,c];require(success+failure==2 and len(reference)==len(production)==len(observed)==2,"complete two-input role group")
    if name=="diagnostics":require(c["formatter_capacity_retries"]>=2,"actual final formatter capacity growth")
    result=dict(status="COMPLETE_STDIO_READ67_SEMANTICS_PASS",group=name,inputs=2,
        original_processes=2,production_processes=2,observed_processes=2,actual_helper_processes=6,
        success_pairs=success,error_pairs=failure,setup=setup_stats,roles=stats,
        real_fault_inputs=sum(v["fault"]for v in group(name)),actual_target_replays=0,
        public_or_ssh_calls=0,raw_python_success_json_whitespace_parity=False,
        all_cpython_internal_failure_semantics_qualified=False,application_executed_by_reader=False)
    for key in("body_calls","child_calls","raw_os_effects","body_journal_bytes","body_full_buffer_bytes",
        "formatter_calls","formatter_capacity_retries","formatter_full_buffer_bytes","kernel_calls","kernel_bytes",
        "orphan_records","lifecycle_full_bytes","actual_bound_file_syscalls"):
        result[key]=sum(v[key]for v in stats)
    return result
