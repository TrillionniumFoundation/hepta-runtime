"""Full unchanged original/native comparison, including live descriptor observations."""
from pathlib import Path
import os,stat
from evidence_common import decode,encoded,pin,require,sha,source_evidence
from protocol import events,exception,project,u
from entropy_model import Model
import read_journal
def expected_filter(numbers,number,conditions=()):
    rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000)]
    for call in numbers:
        rows.extend([(0x20,0,0,0),(0x15,0,2*len(conditions)+1,call)])
        for j,(arg,value)in enumerate(conditions):
            rows.extend([(0x20,0,0,16+8*arg),(0x15,0,2*(len(conditions)-j-1)+1,value)])
        rows.append((0x06,0,0,0x00050000|number))
    rows.append((0x06,0,0,0x7fff0000))
    return dict(numbers=list(numbers),errno=number,conditions=[list(x)for x in conditions],bpf=[list(x)for x in rows])
def initial_filters(case,fd):
    result=[];kind=case["kind"]
    if kind=="getrandom-error":result.append(expected_filter([318],case["errno"]))
    elif kind!="normal":result.append(expected_filter([318],case["errno"]if kind in("fallback","sticky")else 38))
    if kind=="open-error":result.append(expected_filter([257],case["errno"],[(2,524288)]))
    if kind in("initial-stat","initial-stat-close"):result.append(expected_filter([5,262],case["errno"],[(0,fd)]))
    if kind=="initial-stat-close":result.append(expected_filter([3],case["close_errno"],[(0,fd)]))
    if kind=="read-error":result.append(expected_filter([0],case["errno"],[(0,fd)]))
    return result
def semantic(error):
    return {k:error[k]for k in("type","errno","filename")}|dict(
        literal=error["message"]if error["type"]in("NotImplementedError","RuntimeError")else None)
def expected_outcome(case,index):
    kind=case["kind"];number=None;filename=None;literal=None
    if kind=="getrandom-error":number=case["errno"]
    elif kind=="open-error":
        number=case["errno"]
        if number in(2,6,19,13):
            number=None;literal=NotImplementedError("/dev/urandom (or equivalent) not found")
        else:filename="/dev/urandom"
    elif kind=="initial-stat"or(kind=="initial-stat-close"and index==0):number=case["errno"]
    elif kind=="read-error":
        if case["errno"]:number=case["errno"]
        else:literal=RuntimeError("Failed to read 16 bytes from /dev/urandom")
    elif kind=="no-free":number=24;filename="/dev/urandom"
    if literal is not None:return dict(ok=False,error=exception(literal))
    if number is not None:
        error=OSError(number,os.strerror(number),filename)if filename is not None else OSError(number,os.strerror(number))
        return dict(ok=False,error=exception(error))
    return dict(ok=True)
def descriptor_projection(start,fds):
    initial=start["initial_fds"];foreign=initial[str(start["foreign_fd"])]
    for fd,old in initial.items():
        require(fd in fds,"a preexisting descriptor was closed")
        now=fds[fd]
        require(all(now[k]==old[k]for k in("target","dev","inode","mode","cloexec")),"a preexisting descriptor changed identity")
    result=[]
    for fd,row in sorted(fds.items(),key=lambda r:int(r[0])):
        if fd in initial:continue
        if row["target"]=="/dev/urandom":
            require(stat.S_ISCHR(row["mode"])and row["cloexec"],"actual cache device and CLOEXEC")
            resource="urandom"
        elif(row["dev"],row["inode"])==(foreign["dev"],foreign["inode"]):resource="foreign"
        else:raise ValueError("unaccounted actual descriptor")
        result.append(dict(fd_offset=int(fd)-start["next_fd"],resource=resource,cloexec=row["cloexec"]))
    return result
def actions(case,index,row,start,filters):
    wanted=index==1 and case["kind"]in("sticky","cache-stat","cache-replaced","cache-closed")
    require(len(row["actions"])==int(wanted),"exact real fixture action count")
    if not wanted:return
    a=row["actions"][0];kind=case["kind"]
    if kind=="sticky":
        value=expected_filter([318],case["after_errno"])
        require(a==dict(kind="stronger-getrandom-fault",filter=value,
            probe=dict(ok=False,error=exception(OSError(case["after_errno"],os.strerror(case["after_errno"]))))),
            "real stronger getrandom filter and direct kernel probe")
        filters.append(value)
    elif kind=="cache-stat":
        value=expected_filter([5,262],case["errno"],[(0,a["fd"])])
        require(a==dict(kind="cached-fstat-fault",fd=start["next_fd"],filter=value),"actual cached descriptor fault")
        filters.append(value)
    elif kind=="cache-replaced":
        require(a["kind"]=="actual-dup2-foreign"and a["source"]==start["foreign_fd"]and a["fd"]==start["next_fd"]
            and a["before"]["target"]=="/dev/urandom"and a["after"]==row["before_fds"][str(a["fd"])]
            and a["after"]["cloexec"],"actual foreign descriptor replacement")
    else:
        require(a==dict(kind="actual-close-cache",fd=start["next_fd"],before=a["before"])
            and a["before"]["target"]=="/dev/urandom"and str(a["fd"])not in row["before_fds"],
            "actual cached descriptor close without replacement")
def faults(case,caps,filters,index,next_fd):
    for position,cap in enumerate(caps):
        op,a,b=cap["operation"],cap["a"],cap["b"];value=cap["return_value"];matched=[]
        numbers={1:318,2:257,3:5,4:3,5:0};number=numbers.get(op)
        args={0:a,2:524288 if op==2 else 0}
        for rule in filters:
            if number in rule["numbers"]and all(args.get(i,0)==v for i,v in rule["conditions"]):matched.append(rule["errno"])
        if case["kind"]=="cache-closed"and index==1 and position==0:
            require(op==3 and a==next_fd and value==-9 and cap["payload_hex"]=="",
                "actual deliberately closed cached descriptor returns EBADF")
        elif matched:require(value==-matched[-1],"actual kernel response matches installed seccomp fault")
        elif op==2:
            require(value==-24 if case["kind"]=="no-free"else 0<=value<128,"real descriptor allocation/limit response")
        elif op in(3,4,6):require(value==0,"real successful stat/close/transfer response")
        else:require(0<value<=16,"real nonempty kernel entropy response")
def load_role(source,application,role,domain,runtime,build):
    folder=application/role;capture=decode((folder/"CAPTURE.json").read_bytes())
    require(capture["status"]=="PASS"and capture["role"]==role and capture["application_calls"]==97
        and capture["application_deadline_seconds"]==60 and capture["source"]==source_evidence(source),
        "actual complete role capture")
    processes=decode((folder/"processes/processes.json").read_bytes())
    require(processes==capture["processes"]and len(processes)==len(domain["cases"])==len(capture["completed"]),
        "all frozen actual processes ran exactly once")
    result={}
    for case,completed,process in zip(domain["cases"],capture["completed"],processes):
        name=case["name"];path=folder/name
        require(completed["case"]==name and completed["process"]==process,"complete per-case process binding")
        expected=[capture["python_executable"],"-I","-S","-B",capture["source_origin"]+"/scripts/worker.py",
            "--source",capture["source_origin"],"--build",capture["build_origin"],"--runtime",capture["runtime_origin"],
            "--output",capture["output_origin"]+"/"+name,"--role",role,"--case",name]
        require(process["argv"]==expected and process["cwd"]==capture["source_origin"]
            and process["name"]==role+"-"+name and process["pid"]==process["pgid"]
            and process["exit_code"]==0 and process["timed_out"]is False and process["completed"]is True
            and process["timeout_seconds"]==60 and 0<=process["elapsed_seconds"]<60 and process["stdin"]is None,
            "natural bounded actual process and exact original input")
        for stream in("stdout","stderr"):
            record=process[stream];file=folder/"processes"/record["file"]
            require(record["file"]==process["name"]+"."+stream and record["bytes"]==0
                and pin(file)=={k:record[k]for k in("bytes","sha256")},"full empty actual process streams")
        names={p.name for p in path.iterdir()}
        require(names==set(completed["files"])=={"events.bin","results.jsonl","foreign-file"},"complete actual file set")
        for filename,record in completed["files"].items():
            require(dict(**pin(path/filename),mode=(path/filename).stat().st_mode&0o777)==record,"every actual file byte and mode")
        require((path/"foreign-file").read_bytes()==b"foreign descriptor must survive cache replacement\n","foreign descriptor content survived")
        rows=[decode(line)for line in(path/"results.jsonl").read_bytes().splitlines()]
        require([r["record"]for r in rows]==["START"]+["CALL"]*len(case["modes"])+["DONE"],"every actual result record")
        start,*calls,done=rows;raw=(path/"events.bin").read_bytes();ev=events(raw)
        require(start["case"]==case and start["role"]==role and start["pid"]==process["pid"]
            and start["runtime"]==runtime and start["original_unchanged"]is True,"original runtime and frozen case binding")
        require(start["filters"]==initial_filters(case,start["next_fd"]),"all actual initial fault filters")
        require(start["actions"]==([dict(kind="close-stdin",fd=0)]if case["kind"]=="fd-zero"else[]),
            "fixed setup descriptor action")
        require(done["calls"]==len(calls)and done["callback_errors"]==[]and done["events"]==
            dict(bytes=len(raw),sha256=sha(raw),events=len(ev))and done["process_lifetime_cache_not_explicitly_closed"]is True,
            "complete actual terminal event stream and process lifetime")
        if role=="original":require(not raw and start["build_elf"]is None and start["image_mapping"]is None,"original ran no native image")
        else:
            bound=decode((source/"BUILD_REUSE.json").read_bytes())
            mapping=start["image_mapping"]
            require(start["build_elf"]==bound["elf"]and mapping["bytes"]==bound["elf"]["bytes"]
                and mapping["seals"]==15 and mapping["read"]and mapping["execute"]and mapping["write"]is False
                and bool(mapping["callback"])==case["observer"]and mapping["exports"]==build["exports"],"one complete immutable actual code image")
        filters=list(start["filters"]);selected=[];previous_end=0;previous_events=0
        for index,(row,mode)in enumerate(zip(calls,case["modes"])):
            require(row["index"]==index and row["mode"]==mode,"actual input ordering")
            a,b=row["event_start"],row["event_end"]
            require(a==dict(bytes=previous_end,sha256=sha(raw[:previous_end]),events=previous_events)
                and a["bytes"]<=b["bytes"]<=len(raw),"complete per-call event prefix")
            part=[e for e in ev if a["bytes"]<=e["start"]<b["bytes"]]
            require((not part or part[0]["start"]==a["bytes"]and part[-1]["end"]==b["bytes"])
                and b==dict(bytes=b["bytes"],sha256=sha(raw[:b["bytes"]]),events=previous_events+len(part)),
                "complete per-call event boundaries and prefix bytes")
            previous_end=b["bytes"];previous_events=b["events"]
            actions(case,index,row,start,filters)
            before=descriptor_projection(start,row["before_fds"]);after=descriptor_projection(start,row["after_fds"])
            selected.append(dict(row=row,events=part,before=before,after=after,filters=list(filters)))
        require(previous_end==len(raw)and previous_events==len(ev)and done["filters"]==filters,"no unread actual events or fault")
        require(descriptor_projection(start,done["final_fds"])==selected[-1]["after"],"cache and forgotten FDs survive final result")
        limits=start["limits"]
        if case["kind"]in("one-free","no-free"):
            free=1 if case["kind"]=="one-free"else 0
            require(limits["free"]==free and limits["during"][0]==max(map(int,start["initial_fds"]))+1+free
                and limits["during"][1]==limits["before"][1]and done["limits"]==dict(**limits,after=limits["before"]),
                "actual exact FD limit and restoration")
        else:require(limits is None and done["limits"]is None,"no unrequested resource limit")
        result[name]=dict(start=start,calls=selected,events=len(ev),bytes=len(raw))
    return result
def verify(source,application,runtime_folder):
    identity=source_evidence(source);domain=decode((source/"DOMAIN.json").read_bytes())
    runtime=decode((runtime_folder/"BINDING.json").read_bytes())
    require(pin(runtime_folder/"python.bin")==runtime["python"]and pin(runtime_folder/"uuid.py")==runtime["uuid"],
        "complete actual original runtime bytes")
    build=decode((runtime_folder/"BUILD.json").read_bytes())
    require(build["executable"]==decode((source/"BUILD_REUSE.json").read_bytes())["elf"],"fixed runtime build image")
    original=load_role(source,application,"original",domain,runtime,build)
    native=load_role(source,application,"native",domain,runtime,build)
    totals=dict(cases=0,actual_pairs=0,observed_native_hia_calls=0,native_hia_calls=0,actual_capability_calls=0,observed_capability_calls=0,
        full_event_records=0,full_event_bytes=0,original_successes=0,original_errors=0,observer_off_pairs=0,orphan_transfers=0)
    details=[]
    for case in domain["cases"]:
        left=original[case["name"]];right=native[case["name"]];state=Model();case_caps=0
        for index,(a,b)in enumerate(zip(left["calls"],right["calls"])):
            x,y=a["row"],b["row"];value=x["result"];expected=expected_outcome(case,index)
            require(value["ok"]==expected["ok"]and(value["ok"]or value==expected),"unchanged CPython actual result agrees with fixed fault input")
            observations=x["original_observations"]
            if case["observer"]:
                require(len(observations)==1 and observations[0]["size"]==16 and observations[0]["ok"]==value["ok"],
                    "one delegating actual original entropy observation")
                if value["ok"]:
                    raw=bytes.fromhex(observations[0]["raw_hex"])
                    require(bytes.fromhex(value["payload_hex"])==project(raw,x["mode"]),"actual original UUID projection")
                else:require(observations[0]["error"]==value["error"],"unchanged original exception propagated")
            else:require(not observations,"observer-off original had no wrapper observation")
            actual=(read_journal.observed if case["observer"]else read_journal.unobserved)(y,b["events"],state,right["start"])
            require(actual["result"]["ok"]==value["ok"],"original/native success and error parity")
            if value["ok"]:
                for result in(value,actual["result"]):
                    payload=bytes.fromhex(result["payload_hex"])
                    if x["mode"]==1:require(len(payload)==16,"complete raw entropy output")
                    else:
                        require(len(payload)==32 and all(c in b"0123456789abcdef"for c in payload)
                            and payload[12]==ord("4")and payload[16]in b"89ab","actual UUID4 hex and variant")
                totals["original_successes"]+=1
            else:
                require(actual["result"]["error"]==semantic(value["error"]),"exact exception class errno filename or literal")
                totals["original_errors"]+=1
            require(a["before"]==b["before"]and a["after"]==b["after"],"all actual new/cache/forgotten descriptor transitions")
            faults(case,actual["capabilities"],b["filters"],index,right["start"]["next_fd"])
            if case["kind"]=="fd-zero":require(any(v["fd_offset"]==0 and v["resource"]=="urandom"for v in b["after"])
                and right["start"]["next_fd"]==0,"actual cached descriptor zero")
            totals["actual_pairs"]+=1;totals["observed_native_hia_calls"]+=actual["hia_calls"]
            totals["native_hia_calls"]+=actual["actual_hia_calls"]
            totals["actual_capability_calls"]+=actual["total_capabilities"]
            totals["observed_capability_calls"]+=len(actual["capabilities"]);case_caps+=len(actual["capabilities"])
            totals["observer_off_pairs"]+=int(not case["observer"])
        totals["cases"]+=1;totals["full_event_records"]+=right["events"];totals["full_event_bytes"]+=right["bytes"]
        totals["orphan_transfers"]+=len(state.orphans)
        details.append(dict(case=case["name"],pairs=len(case["modes"]),capabilities=case_caps,
            orphan_transfers=len(state.orphans),exact_error_and_fd_parity=True))
    require(totals["cases"]==42 and totals["actual_pairs"]==97,"whole frozen actual domain completed")
    return dict(status="ENTROPY_ACTUAL_ORIGINAL_NATIVE_COMPLETE_PASS",source=identity,totals=totals,cases=details,
        random_bytes_compared_only_to_their_own_actual_origin=True,application_replays=0,
        scope=dict(private_process_lifetime_entropy=True,serialized_context=True,public_route=False,
            write_upload_integrated=False,whole_runtime_replaced=False))
