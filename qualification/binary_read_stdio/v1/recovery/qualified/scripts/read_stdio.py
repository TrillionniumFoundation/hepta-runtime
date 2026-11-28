#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pure full process, filesystem, body and formatter admission; no application replay."""
from pathlib import Path
import gzip,hashlib,struct
from common import canonical,decode,owned,pin,require,sha,source_evidence
from cases import domain,group,validate,wire,control
from buffer_store import Reader
from read_fixtures import fixture_rows,setup
from read_journal import Journal,invocation,result,U

def load(root,name):return decode(owned(root,name).read_bytes())
def stream(path,receipt):
    with gzip.open(path,"rb")as file:raw=file.read()
    require(dict(bytes=len(raw),sha256=sha(raw))==receipt["raw"]and pin(path)==receipt["compressed"]
        and receipt["complete_raw_bytes_in_gzip"]is True and receipt["no_expanded_ordinary_copy_created"]is True,
        "complete compressed process stream differs")
    return raw
def process(source,capture,folder,row,case,raw,role,origin):
    native=role!="original";observed=role=="observed";is_control=role=="controls"
    p=row["process"];require(p==load(folder,"PROCESS.json"),"process record publication")
    build=load(source,"BUILD_REUSE.json");base=Path(origin["capture"])
    variant="observed"if observed else"production"
    argv=[str(base/"build-reuse/original/restored/run/build"/variant/"binary-read-stdio.elf")]if native else[
        origin["python"],"-I","-S","-B",str(base/"source/target/binary_file.py")]
    require(p["argv"]==argv and p["native"]is native and p["observed"]is observed and p["control"]is is_control
        and p["fixed_journal_fds"]==([3,4]if observed else[]),"fixed executable arguments and observer binding")
    if native:require(p["binary"]==build["executables"][variant],"executed complete native ELF binding")
    require(p["completed"]is True and p["timed_out"]is False and p["timeout_seconds"]==30
        and 0<p["elapsed_ns"]<31_000_000_000 and p["same_outer_process_group"]is True
        and p["parent_pgid"]==p["child_pgid"]and p["parent_pid"]!=p["pid"]
        and p["reaped"]is True and p["after_reap_proc_absent"]is True
        and p["stdin_closed"]is True and p["stdin_broken_pipe"]is False and "failure"not in p,
        "complete bounded helper process custody")
    require(p["input_chunk_bytes"]==case["input_chunk_bytes"]
        and p["output_chunk_bytes"]==(65536 if is_control else case["output_chunk_bytes"])
        and p["expected_input_bytes"]==len(raw),"frozen fragmented I/O input")
    require(set(p["streams"])=={"stdin","stdout","stderr","body","formatter"},"complete process stream set")
    actual={name:stream(folder/(name+".gz"),p["streams"][name])for name in("stdin","stdout","stderr")}
    require(actual["stdin"]==raw,"complete actual stdin differs from frozen input")
    count=0
    for w in p["writes"]:
        require(w["offset"]==count and 0<w["count"]<=case["input_chunk_bytes"],"actual input fragments")
        count+=w["count"]
    require(count==len(raw),"complete fragmented input coverage")
    before=p["before_eof"]
    if not is_control:
        require(before is not None and before["alive"]is True and before["sent_bytes"]==len(raw)
            and before["hold_milliseconds"]==5 and before["output_bytes"]==dict(stdout=0,stderr=0,body=0,formatter=0),
            "helper executed or published before owned stdin EOF")
        maps=owned(folder,"before-eof.maps").read_bytes()
        require(before["maps"]==pin(folder/"before-eof.maps")and maps,"complete pre-EOF process mappings")
        if native:
            require(set(before["fd"])==({"0","1","2","3","4"}if observed else{"0","1","2"}),
                "native helper inherited a non-fixed descriptor")
            entries=[]
            for line in maps.decode().splitlines():
                fields=line.split();require(len(fields)>=5,"actual proc mapping shape")
                entries.append(fields)
            require(not any(".so"in" ".join(v[5:])or"python"in" ".join(v[5:]).lower()for v in entries)
                and not any(v[1][1]=="w"and v[1][2]=="x"for v in entries),"native mapped host runtime or writable executable")
    if not observed:
        for name in("body","formatter"):
            require(stream(folder/(name+".gz"),p["streams"][name])==b"","observer-free helper emitted a journal")
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
    is_control=role=="controls";observed=role=="observed";native=role!="original"
    selected=domain()["controls"]if is_control else group(name);ids=[c["id"]for c in selected]
    require(summary["status"]=="ACTUAL_STDIO_HELPER_CAPTURE_COMPLETE"and summary["source"]==source_evidence(source)
        and summary["role"]==role and summary["group"]==name and summary["cases"]==summary["process_count"]==len(ids)
        and summary["observer_enabled"]is observed and summary["original_outputs_read"]is False
        and summary["runtime_python_required"]is (not native)and summary["runtime_libc_required"]is (not native)
        and [r["id"]for r in rows]==ids,"complete frozen helper process domain")
    env=summary["environment"]
    require(env["unicode_version"]=="15.0.0"and env["lc_messages"]=="C"and env["platform"]=="linux"
        and env["machine"]=="x86_64"and env["python"].startswith("3.12.3 "),"fixed diagnostic reference environment")
    store=Reader(root/"buffers");values={};stats=dict(body_calls=0,child_calls=0,raw_os_effects=0,
        body_journal_bytes=0,body_full_buffer_bytes=0,formatter_calls=0,formatter_capacity_retries=0,formatter_full_buffer_bytes=0)
    sums={n:0 for n in("stdin","stdout","stderr","body","formatter")}
    for case,row in zip(selected,rows):
        require(row["name"]==case["name"],"input scenario name")
        folder=root/("case-"+str(case["id"]).zfill(3))
        if is_control:raw=control(case)
        else:
            q=queries[row["id"]]
            require(row["input"]==q and row["before"]==row["after"]==q["snapshot"],"shared actual filesystem changed")
            fixture_rows(row["before"],store,case);fixture_rows(row["after"],store,case)
            raw=wire(q)if native else canonical(q["request"])
        p,out=process(source,capture_root,folder,row,case,raw,role,origin)
        require(p["parent_pid"]==summary["pid"]and p["binary"]==summary["executed_binary"],"actual helper parent/binary")
        for key in sums:sums[key]+=p["streams"][key]["raw"]["bytes"]
        if is_control:
            require(p["returncode"]==111 and p["wait_status"]==111<<8
                and out["stdout"]==out["stderr"]==b"","private bounded-wire refusal")
            continue
        require(p["returncode"]in(0,1)and p["wait_status"]==p["returncode"]<<8,"ordinary helper result exit")
        if p["returncode"]==0:
            require(out["stderr"]==b""and out["stdout"].endswith(b"\n"),"successful helper streams")
            value=decode(out["stdout"]);current=dict(exit=0,value=value,stdout=out["stdout"],stderr=b"")
        else:
            require(out["stdout"]==b""and out["stderr"].endswith(b"\n"),"failed helper streams")
            current=dict(exit=1,stderr=out["stderr"],stdout=b"")
        if role!="original":
            original=expected[row["id"]]
            require(current["exit"]==original["exit"]and current["stderr"]==original["stderr"],"complete original diagnostic/exit mismatch")
            if current["exit"]==0:
                require(current["value"]==original["value"]and out["stdout"]==canonical(current["value"]),
                    "complete original JSON Value and native serialization differ")
            if role=="observed":
                require(current==original["native_production"],"production/observed complete stdout/stderr/exit differ")
        if observed:
            journal=Journal(folder/"body.gz")
            terminal=invocation(journal,raw,None,1,fixture=fixtures[row["id"]])["terminal"]
            done=journal.finish(p["streams"]["body"])
            for k in("body_calls","child_calls","raw_os_effects"):stats[k]+=done[k]
            stats["body_journal_bytes"]+=done["journal_bytes"];stats["body_full_buffer_bytes"]+=done["full_buffer_bytes"]
            parsed=result(terminal)
            require(parsed["ok"]is (current["exit"]==0),"body terminal status/stdio exit")
            if parsed["ok"]:
                require(parsed["value"]==current["value"]and terminal[64:]+b"\n"==out["stdout"],
                    "complete borrowed JSON publication")
            formatted=formatter(source,folder,p,terminal,current["stderr"][:-1]if current["exit"] else b"")
            stats["formatter_calls"]+=formatted["calls"];stats["formatter_capacity_retries"]+=formatted["capacity_retries"]
            stats["formatter_full_buffer_bytes"]+=formatted["full_buffer_bytes"]
        values[row["id"]]=current
    buffers=store.finish()
    require(buffers["complete_images"]==summary["buffer_images"]and buffers["logical_buffer_bytes"]==summary["logical_buffer_bytes"]
        and sums==summary["streams"],"complete process buffer/stream inventory")
    return values,dict(cases=len(ids),role=role,group=name,streams=sums,buffers=buffers,**stats)
def verify(source,capture_root):
    source,capture_root=Path(source),Path(capture_root);validate()
    queries,fixtures,setup_stats=setup(source,capture_root/"setup");qs={q["id"]:q for q in queries}
    origin=load(capture_root,"ORIGIN.json");all_stats=[];success=0;failure=0
    for g in domain()["groups"]:
        name=g["name"]
        reference,a=capture(source,capture_root,"original",name,qs,fixtures,{},origin)
        production,b=capture(source,capture_root,"production",name,qs,fixtures,reference,origin)
        for key,value in reference.items():value["native_production"]=production[key]
        observed,c=capture(source,capture_root,"observed",name,qs,fixtures,reference,origin)
        success+=sum(r["exit"]==0 for r in reference.values());failure+=sum(r["exit"]==1 for r in reference.values())
        all_stats.extend((a,b,c))
    _,controls=capture(source,capture_root,"controls","controls",qs,fixtures,{},origin)
    require(success+failure==48 and sum(v["formatter_capacity_retries"]for v in all_stats)>=3,
        "complete process comparison or actual formatter growth domain")
    return dict(status="COMPLETE_BINARY_READ_STDIO_SEMANTICS_PASS",native_cases=96,original_cases=48,
        production_cases=48,observed_cases=48,actual_helper_processes=155,private_controls=11,
        success_pairs=success,error_pairs=failure,setup=setup_stats,groups=all_stats,controls=controls,
        body_calls=sum(v["body_calls"]for v in all_stats),child_calls=sum(v["child_calls"]for v in all_stats),
        raw_os_effects=sum(v["raw_os_effects"]for v in all_stats),
        body_full_buffer_bytes=sum(v["body_full_buffer_bytes"]for v in all_stats),
        formatter_calls=sum(v["formatter_calls"]for v in all_stats),
        formatter_capacity_retries=sum(v["formatter_capacity_retries"]for v in all_stats),
        formatter_full_buffer_bytes=sum(v["formatter_full_buffer_bytes"]for v in all_stats),
        actual_ssh_or_public_calls=0,raw_python_success_json_whitespace_parity=False,application_executed_by_reader=False)
