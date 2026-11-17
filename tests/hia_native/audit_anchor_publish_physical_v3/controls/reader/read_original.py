"""Fresh original process custody, all full streams and independently traced effects."""
from pathlib import Path
import math,struct
from common import ROOT,encoded,files,loads,pin,read,require,source
from protocol import cases,initial,word,validate_semantic
from read_filesystem import complete,before_step,after_step,retired
from read_trace import records,from_syscalls
def original_errors(raw,ci,case,observations):
    lines=raw.splitlines();cursor=0;errors=[]
    for si,_ in enumerate(case["steps"]):
        gen=1+ci*100+si
        require(cursor<len(lines) and lines[cursor]==("PUBLISH_ORIGINAL_BEGIN %d %d"%(ci,gen)).encode(),"complete original begin")
        cursor+=1
        if word(bytes.fromhex(observations[si]["semantic_hex"]),8):
            prefix=b"OBSERVED_ORIGINAL_ERROR "
            require(cursor<len(lines) and lines[cursor].startswith(prefix),"entire actual target error retained")
            error=loads(lines[cursor][len(prefix):]);cursor+=1
            require(set(error)=={"generation","display","debug","chain"} and error["generation"]==gen and
                    all(type(error[k]) is str for k in ("display","debug")) and type(error["chain"]) is list and
                    error["chain"] and all(type(x) is str for x in error["chain"]) and error["chain"][0]==error["display"],
                    "complete original error display/debug/chain")
            errors.append(error)
        require(cursor<len(lines) and lines[cursor]==("PUBLISH_ORIGINAL_END %d %d"%(ci,gen)).encode(),"complete original end")
        cursor+=1
    require(cursor==len(lines),"no extra or omitted original stderr")
    return errors
def verify(root,metadata,native,group,producer):
    domain=cases(ROOT,group);folder=root/("original-"+group)
    expected={"ORIGINAL.json","OBSERVATIONS.json","RETIREMENT.json","RETIRED.json","processes.json"}
    for ci,_ in domain:
        for name in ("process.json","stdin","stdout","stderr"):expected.add("case-%04d/"%ci+name)
    require(set(files(folder))==expected,"exact complete original process files")
    report=loads(read(folder/"ORIGINAL.json"));processes=loads(read(folder/"processes.json"));observations=loads(read(folder/"OBSERVATIONS.json"))
    require(report["schema"]=="hepta.audit-anchor-publish.original.v1" and report["status"]=="PASS" and
            report["source_manifest_sha256"]==source() and report["group"]==group and report["cases"]==len(domain) and
            report["operations"]==len(observations)==sum(len(c["steps"]) for _,c in domain) and len(processes)==len(domain),
            "entire actual original source-owned group")
    require(report["source_root"]==metadata["source_root"] and report["output_root"]==metadata["producer_root"]+"/original-"+group and
            report["owned_root"]==metadata["owned_fixture"] and report["timeout_seconds"]==60 and
            type(report["elapsed_seconds"]) in (int,float) and math.isfinite(report["elapsed_seconds"]) and 0<report["elapsed_seconds"]<=60 and
            report["parent_pid"]==producer["pid"]==report["pgid"] and type(report["pid"]) is int and report["pid"]>1 and
            report["pid"]!=producer["pid"] and report["binary"]==metadata["original_binary"] and
            report["uid"]==metadata["uid"]==native["uid"] and report["gid"]==metadata["gid"]==native["gid"],
            "exact traced original cohort parent and unchanged deadline")
    trace=read(root/("original-"+group+".strace"));index=0;all_errors=[];by_case={};case_traces=[]
    for (ci,case),process in zip(domain,processes,strict=True):
        part=folder/("case-%04d"%ci);owned=str(Path(metadata["owned_fixture"])/("case-%04d"%ci))
        require(process==loads(read(part/"process.json")) and set(process)==
                {"case","argv","pid","parent_pid","pgid","exit_code","success","elapsed_seconds","source_root","owned_root","group","timeout_seconds","streams","binary"},
                "same complete original process row")
        require(process["case"]==ci and process["argv"]==[metadata["producer_root"]+"/original.elf",owned,group,str(ci)] and
                process["success"] is True and type(process["exit_code"]) is int and process["exit_code"]==0 and
                type(process["pid"]) is int and process["pid"]>1 and process["pid"]!=report["pid"] and
                process["parent_pid"]==report["pid"] and process["pgid"]==producer["pid"] and
                process["source_root"]==metadata["source_root"] and process["owned_root"]==owned and process["group"]==group and
                type(process["timeout_seconds"]) is int and process["timeout_seconds"]==60 and
                type(process["elapsed_seconds"]) in (int,float) and math.isfinite(process["elapsed_seconds"]) and
                0<process["elapsed_seconds"]<=report["elapsed_seconds"] and process["binary"]==metadata["original_binary"],
                "all fresh original real PID/parent/PGID/argv/deadline")
        for name in ("stdin","stdout","stderr"):require(pin(read(part/name))==process["streams"][name],"entire original stream "+name)
        require(set(process["streams"])=={"stdin","stdout","stderr"},"whole stream set")
        stdin=b"".join(struct.pack("<Q",128)+initial(ci,si,case) for si in range(len(case["steps"])))
        require(read(part/"stdin")==stdin,"all exact original source-owned requests")
        subset=observations[index:index+len(case["steps"])];index+=len(case["steps"])
        groups,stderr,syscalls=records(trace,process["pid"],[(ci,case)],b"PUBLISH_ORIGINAL")
        require(stderr==read(part/"stderr"),"every original stderr byte independently traced")
        first=min(r["index"] for values in groups.values() for r in values)
        opens=[r for r in syscalls if r["index"]<first and r["operation"]=="openat" and r["strings"]==[owned.encode()]]
        require(len(opens)==1 and opens[0]["returned"]>=0 and opens[0]["arguments"].startswith("AT_FDCWD, ") and
                "O_RDONLY" in opens[0]["arguments"] and "O_CLOEXEC" in opens[0]["arguments"],"actual unchanged State::new root open")
        actual=from_syscalls(groups,[(ci,case)],opens[0]["returned"],syscalls,original=True)
        require(actual["signatures"]==native["signatures"][ci],"every actual original syscall effect equals native, excluding independent random bytes/FD numbers")
        by_case[ci]=actual["temporaries"];previous=None;stdout=bytearray()
        for si,(step,row) in enumerate(zip(case["steps"],subset,strict=True)):
            wire=initial(ci,si,case);other=next(r for r in native["observations"] if (r["case"],r["step"])==(ci,si))
            require(set(row)=={"case","step","initial_hex","semantic_hex","before","after"} and row["case"]==ci and row["step"]==si and
                    row["initial_hex"]==wire.hex() and row["semantic_hex"]==other["semantic_hex"],"all source/native/original result bytes")
            raw=validate_semantic(bytes.fromhex(row["semantic_hex"]));stdout+=struct.pack("<Q",64)+raw
            before_step(case,step,row["before"],previous,by_case[ci],report["uid"],report["gid"])
            after_step(row["before"],row["after"],actual["signatures"][si],by_case[ci],report["uid"],report["gid"])
            require(all(complete(row[k],by_case[ci])==complete(other[k],native["temporaries"][ci]) for k in ("before","after")),
                    "complete original/native filesystem and hardlink equality")
            previous=row["after"]
        require(read(part/"stdout")==bytes(stdout),"every framed original stdout byte")
        all_errors.extend(original_errors(stderr,ci,case,subset))
        case_traces.append(dict(case=ci,pid=process["pid"],root_fd=opens[0]["returned"],
                                syscalls=sum(len(x) for x in actual["signatures"]),temporaries=actual["temporaries"],
                                outside_closes=actual["outside_closes"],
                                remaining_process_owned_roles=actual["remaining_process_owned_roles"]))
    require(index==len(observations),"no omitted original row")
    retirement=retired(folder,dict(root=report["owned_root"]),observations,by_case)
    for key,name in (("observations","OBSERVATIONS.json"),("processes","processes.json"),("retirement","RETIREMENT.json")):
        require(report[key]==pin(read(folder/name)),"exact complete original report binding")
    return dict(status="COMPLETE_PUBLISHER_ORIGINAL_READBACK_PASS",cases=len(domain),operations=index,
                original_processes=len(processes),original_errors=len(all_errors),complete_original_error_diagnostics=all_errors,
                trace=pin(trace),case_traces=case_traces,retired=retirement,filesystem_equal=True,
                exact_serde_error_text_compared=False,native_or_rust_executions=0,reader_writes=0)
