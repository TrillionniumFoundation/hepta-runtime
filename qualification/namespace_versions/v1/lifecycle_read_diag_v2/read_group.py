"""Whole independent same-tree, source, process, memory and kernel comparison for one actual group."""
import copy,json,os,stat,struct
from pathlib import Path
from common import ROOT,source,loads,read,pin,require,files
from protocol import cases,line,require_semantic
from comparison import Comparison
from read_buffers import verify as read_buffers
from read_trace import verify as read_trace,number
from trace_scope import traced
ERRORS=("namespace epoch exhausted","namespace event stream closed","invalid namespace event read length",
    "namespace event drain budget exhausted","truncated namespace event","namespace event size overflow",
    "truncated namespace event name","namespace descriptor is not a directory","namespace watcher unavailable",
    "archive content watcher unavailable","archive content watch set unavailable")
def error(value,record):
    s=require_semantic(value)
    if s["kind"]!=3:require(record is None,"no fabricated successful original error");return
    require(type(record)is dict and set(record)=={"display","debug","chain","raw_os_error"}and type(record["display"])is str
        and record["display"]and type(record["debug"])is str and record["debug"]and type(record["chain"])is list
        and record["chain"]and record["chain"][0]==record["display"],"all original anyhow/io error text and chain retained")
    if s["family"]==1:require(record["raw_os_error"]==s["code"],"exact actual original OS error, including zero")
    else:require(record["raw_os_error"]is None and record["display"]==ERRORS[s["code"]-1],"exact original literal error")
def source_process(row,report,case,folder):
    role=row["role"];require(role in("original","native-observed","native-off")and row["success"]is True
        and row["failure"]is None and row["exit_code"]==0 and row["timeout_seconds"]==60 and 0<row["elapsed_seconds"]<=60,
        "every actual process completed once inside unchanged deadline")
    require(row["owner_pid"]==report["pid"]and row["pgid"]==report["pgid"]==report["pid"]
        and row["pid"]!=row["tracer_pid"]!=row["owner_pid"]and row["parent_pid"]==row["tracer_pid"],"complete actual child/tracer/driver custody")
    ready=row["ready"];require(ready["pid"]==row["pid"]and ready["parent_pid"]==row["tracer_pid"]and ready["pgid"]==row["pgid"]
        and ready["group"]==case["group"]and ready["role"]==role and ready["uid"]==report["uid"]>0
        and ready["gid"]==report["gid"],"actual unprivileged process identity")
    for name,pid,parent in(("application_identity",row["pid"],row["tracer_pid"]),("tracer_identity",row["tracer_pid"],row["owner_pid"])):
        i=row[name];raw=bytes.fromhex(i["raw_hex"]);tail=raw[raw.rfind(b")")+2:].split()
        require(int(raw[:raw.find(b" ")])==pid==i["pid"]and int(tail[1])==parent==i["parent_pid"]
            and int(tail[2])==report["pgid"]==i["pgid"]and int(tail[3])==report["pgid"]==i["session"]
            and int(tail[19])==i["start_ticks"]>0,"complete actual proc stat receipt")
    source_root=Path(report["source_root"]);retained=Path(report["retained_root"])
    if role=="original":require(row["argv"]==[str(retained/"original/run/original.elf"),case["group"]],"exact compiled original application command")
    else:
        require(len(row["argv"])==12 and row["argv"][1:3]==["-I","-B"]and row["argv"][3]==str(source_root/"native_child.py")
            and row["argv"][4:6]==["--retained",str(retained)]and row["argv"][6:8]==["--output",str(Path(report["output_root"])/"roles"/role/"capture")]
            and row["argv"][8:]==["--group",case["group"],"--observer","on"if role=="native-observed"else"off"],
            "exact native application source and observer choice")
    require(row["tracer_argv"]==traced(row["argv"],Path(report["output_root"])/"roles"/role/"syscalls.strace")
        and row["cwd"]==report["source_root"],"whole actual traced application command")
    for name,expected in row["streams"].items():require(pin(read(folder/name))==expected,"entire real process stream")
    require(set(row["streams"])=={"stdin","stdout","stderr","syscalls.strace"},"all real process streams retained")
    incoming=read(folder/"stdin").splitlines(keepends=True);outgoing=read(folder/"stdout").splitlines(keepends=True)
    exchanges=loads(read(folder/"EXCHANGES.json"));require(len(incoming)==len(exchanges)==len(case["steps"])+2 and
        len(outgoing)==len(exchanges)+1 and loads(outgoing[0])==ready,"entire exact real line transport")
    requests=[];responses=[]
    for i,(req,res,entry)in enumerate(zip(incoming,outgoing[1:],exchanges)):
        require(req.endswith(b"\n")and res.endswith(b"\n")and entry==dict(index=i,request=pin(req),response=pin(res),request_hex=req.hex(),response_hex=res.hex()),
            "every complete request/response byte joins its custody record")
        requests.append(loads(req));responses.append(loads(res))
    roots=[dict(path_hex=os.fsencode(Path(report["fixture_root"])/("case-%04d"%case["case"])/r["name"]).hex(),late=r["late"])for r in case["roots"]]
    expected=[dict(cmd="prepare",case=case["case"],roots=roots)]
    expected.extend(dict(cmd="run",case=case["case"],step=i,operation=s["operation"])for i,s in enumerate(case["steps"]))
    expected.append(dict(cmd="finish",case=case["case"]))
    require(requests==expected and row["exchanges"]==len(expected),"every source-frozen original/native control appears exactly once")
    return ready,responses
def final_tree(folder,record):
    entries=record["complete_final"]["entries"];require(record["complete_final"]["exists"]is True and record["retired"]is False,"owned full final physical tree retained")
    expected_files={};expected_dirs={}
    for row in entries:
        name=os.fsdecode(bytes.fromhex(row["path_hex"]));require(not Path(name).is_absolute()and".."not in Path(name).parts,"ordinary recorded fixture member")
        if row["type"]==stat.S_IFREG:
            body=bytes.fromhex(row["content_hex"]);require(pin(body)==row["content"],"whole recorded fixture file bytes")
            expected_files[name]=dict(**pin(body),mode=row["mode"])
        elif row["type"]==stat.S_IFDIR:expected_dirs[name or "."]=row["mode"]
        else:raise ValueError("unexpected actual fixture object")
    require(files(folder)==expected_files,"every retained physical fixture byte and file mode")
    current={".":stat.S_IMODE(folder.lstat().st_mode)}
    for path in folder.rglob("*"):
        if path.is_dir():current[path.relative_to(folder).as_posix()]=stat.S_IMODE(path.lstat().st_mode)
    require(current==expected_dirs,"every full physical fixture directory and mode")
def trace_compare(case,traces,observations,processes,comparison):
    histories=[];witnesses=[]
    for role,trace in enumerate(traces):
        rows=[]
        fmap=comparison.events.get(role,{})
        def fd(v):
            n=number(v)if isinstance(v,str)else v
            return "event-scope-"+str(fmap[n])if n in fmap else n
        for si,step in enumerate(trace["business"]):
            require(step["step"]==si,"complete kernel step order");operation=case["steps"][si]["operation"]
            output=observations[si]["answers"][role];tids={r["tid"]:r["worker"]for r in output["parallel"]}
            buckets={}
            for r in step["operations"]:
                tid=r["tid"];worker="owner"if tid==processes[role]["pid"]else str(tids.get(tid,"unlisted"))
                require(worker!="unlisted","every business kernel action belongs to actual joined worker")
                name=r["name"];args=copy.deepcopy(r["args"]);returned=r["returned"]
                if name in("read","close"):args[0]=fd(args[0])
                elif name in("inotify_add_watch","inotify_rm_watch","getdents64"):args[0]=fd(args[0])
                elif name in("fcntl","openat"):args[0]=fd(args[0])
                if name=="inotify_init1"and returned is not None and returned>=0:returned=fd(returned)
                buckets.setdefault(worker,[]).append(dict(name=name,args=args,returned=returned,errno=r["errno"],payload=r["payload"]))
            if case["group"]in("fd3-concurrent-ordinary","fd3-concurrent-content"):
                # Initialization ownership is chosen by the real mutex scheduler. Every raw worker and per-thread order stays in the trace.
                complete=[v for values in buckets.values()for v in values]
                complete.sort(key=lambda x:json.dumps(x,sort_keys=True,separators=(",",":")))
                rows.append(dict(step=si,source_calls=complete))
            else:rows.append(dict(step=si,workers=buckets))
        histories.append(rows)
    require(histories[0]==histories[1]==histories[2],"all actual source-owned kernel calls and payload bytes, with witnessed worker/FD bijection: "+json.dumps(
        [dict(step=i,roles=[h[i]for h in histories])for i in range(len(histories[0]))if not(histories[0][i]==histories[1][i]==histories[2][i])],
        sort_keys=True,separators=(",",":")))
    return dict(complete_source_kernel_operations=sum(len(row["source_calls"])if"source_calls"in row else sum(len(v)for v in row["workers"].values())for row in histories[0]),
        all_roles_complete_equal=True,raw_thread_ids_and_fds_retained=True)
def verify(folder,group,source_identity=None):
    identity=source()if source_identity is None else source_identity;case=cases(group)[0];report=loads(read(folder/"PAIRED.json"));deps=loads(read(ROOT/"DEPENDENCIES.json"))
    require(report["schema"]=="hepta.namespace-versions.same-tree-pair.v1"and report["status"]=="PASS"
        and report["source_manifest_sha256"]==identity and report["group"]==group and report["cases"]==1
        and report["operations"]==len(case["steps"])and report["processes"]==report["application_processes"]==report["tracer_processes"]==3
        and report["timeout_seconds"]==60 and 0<report["elapsed_seconds"]<=60 and report["uid"]>0 and report["fixture_bytes_deleted"]==0
        and report["globals_reset"]is False and report["original_binary"]==deps["original_binary"],
        "precise complete actual process-group result")
    for name,row in report["files"].items():require(pin(read(folder/name))==row,"all complete group evidence files")
    require(set(report["files"])=={"INITIALS.json","OBSERVATIONS.json","RETIREMENT.json","PROCESSES.json","TRACE-CUSTODY.json"},"whole group evidence inventory")
    processes=loads(read(folder/"PROCESSES.json"));require([p["role"]for p in processes]==["native-observed","native-off","original"]
        and len({p["pid"]for p in processes})==3 and len({p["tracer_pid"]for p in processes})==3,"all independent actual applications")
    ready=[];responses=[]
    for p in processes:
        a,b=source_process(p,report,case,folder/"roles"/p["role"]);ready.append(a);responses.append(b)
    bindings=ready[2]["static_bindings"];expected=deps["original_elf_bindings"]
    elf=read(folder.parent.parent/"retained/original/run/original.elf")
    require(pin(elf)==deps["original_binary"],"whole independently retained actual original executable")
    phoff=int.from_bytes(elf[32:40],"little");phsize=int.from_bytes(elf[54:56],"little");phcount=int.from_bytes(elf[56:58],"little")
    segments=[struct.unpack_from("<II6Q",elf,phoff+i*phsize)for i in range(phcount)]
    header_segments=[s for s in segments if s[0]==1 and s[2]==0]
    require(len(header_segments)==1,"actual complete ELF header load segment")
    require(dict(bytes=bindings["bytes"],sha256=bindings["sha256"])==deps["original_binary"]
        and Path(bindings["executable"])==Path(processes[2]["argv"][0])and bindings["load_bias"]>=0
        and bindings["elf_header_address"]==bindings["load_bias"]+header_segments[0][3]>0,
        "runtime original reads the whole same compiled ELF and its actual load bias")
    require([s["kind"]for s in bindings["symbols"]]==["content","next","ordinary"],"every original real function-local static")
    for row in bindings["symbols"]:
        actual=expected["symbols"][row["kind"]]
        require(all(row[k]==actual[k]for k in("bytes","name","elf_value"))and row["address"]==bindings["load_bias"]+row["elf_value"]
            and row["address"]%8==0,"actual typed original static address equals complete ELF definition")
    require(ready[2]["rust_types"]==dict(all_actual_type_words=expected["type_words"],global_bytes=expected["type_words"][0],
        global_alignment=expected["type_words"][1],atomic_bytes=expected["type_words"][2],atomic_alignment=expected["type_words"][3]),
        "complete actual compiled Rust private type layouts")
    initials=loads(read(folder/"INITIALS.json"));observations=loads(read(folder/"OBSERVATIONS.json"));finals=loads(read(folder/"RETIREMENT.json"))
    require(len(initials)==len(finals)==1 and len(observations)==len(case["steps"]),"all complete actual physical observations")
    initial=initials[0];require(initial["case"]==case["case"]and initial["replies"]==[r[0]for r in responses]
        and initial["replies"][0]==initial["replies"][1]==initial["replies"][2]
        and initial["after"]==[initial["snapshot"]]*3,"all actual initial roots and unchanged prepare tree")
    state=initial["replies"][0]["state"];require(state["sets"]==[]and state["next"]==1 and
        state["globals"]==[dict(kind=k,initialized=False,poison=False,watcher=None)for k in("ordinary","content")],
        "actual typed original OnceLocks begin uninitialized; raw static storage need not be all zero")
    comparison=Comparison(case);previous=initial["snapshot"]
    for si,(observation,step)in enumerate(zip(observations,case["steps"])):
        require(observation["case"]==case["case"]and observation["step"]==si and observation["operation"]==step["operation"]["op"]
            and observation["answers"]==[r[si+1]for r in responses]and observation["after"]==[observation["before"]]*3,
            "every operation sees the same full physical tree and leaves it unchanged")
        if not step["actions"]:require(observation["before"]==previous,"no unexplained physical mutation between actual observations")
        previous=observation["before"]
        require(comparison.compare(observation["answers"],step["operation"])==observation["comparison"],"independently repeated whole semantic/state comparison")
        original=observation["answers"][2];error(original["semantic"],original["original_error"])
        for r in original["parallel"]:
            if"semantic"in r:error(r["semantic"],r["original_error"])
    relations=comparison.relations(observations)
    final=finals[0];require(final["case"]==case["case"]and final["replies"]==[r[-1]for r in responses]
        and final["complete_final"]==previous and final["constructor_bijections"]==comparison.witness and final["relations"]==relations,
        "complete final physical and constructor witnesses")
    states=[comparison.normalize_state(i,r[-1]["state"])for i,r in enumerate(responses)]
    require(states[0]==states[1]==states[2]and all(r[-1]["all_sets_and_caller_roots_dropped"]is True and
        r[-1]["globals_live_until_process_exit"]is True and r[-1]["state"]["sets"]==r[-1]["state"]["roots"]==[]for r in responses),
        "whole original/native process lifetime; no global reset or premature global drop")
    final_tree(folder/"fixture"/("case-%04d"%case["case"]),final)
    custody=loads(read(folder/"TRACE-CUSTODY.json"));require(custody["owner_pid"]==report["pid"]and custody["owner_pgid"]==report["pgid"]
        and custody["restored"]is True and custody["adopted_reaps"]==[]and custody["kill_on_tracer_exit"]is True
        and custody["trace_scope"]=="all-three-applications-entire-lifetimes"and custody["complete_driver_snapshots_retained"]is True,
        "whole actual tracer termination, reaping and no unowned process")
    native=[];traces=[]
    for i,p in enumerate(processes):
        captured=read_buffers(folder/"roles"/p["role"]/"capture",case,p)if i<2 else None
        if captured is not None:
            require(captured["image"]==deps["native_image"]and[c["state"]for c in captured["checkpoints"]]==[r["state"]for r in responses[i]],
                "all original/native states join independently decoded complete native physical buffers")
            for si,step in enumerate(case["steps"]):
                op=step["operation"];rows=[e for e in captured["entries"]if e["step"]==si];before=captured["checkpoints"][si]
                if op["op"]in("parallel-read","parallel-new"):
                    packets=responses[i][si+1]["parallel"];require(len(rows)==len(packets),"every real native concurrent HIA invocation")
                    for packet in packets:
                        matches=[e for e in rows if e["worker"]==packet["worker"]and e["raw"]==packet["native_frame_hex"]]
                        require(matches,"each raw worker terminal has its actual physical entry")
                elif op["op"]in("version","watched","content","set-new","set-version","set-drop"):
                    require(len(rows)==1 and rows[0]["raw"]==responses[i][si+1]["native_frame_hex"],"actual exact direct entry terminal")
                    r=rows[0]["request"];wanted={"version":1,"content":2,"set-new":3,"set-version":4,"set-drop":5,"watched":6}[op["op"]]
                    require(r["cmd"]==wanted,"same actual source native command")
                    if wanted in(1,2,6):require(r["fd"]==before["roots"][str(op["root"])]["fd"],"actual source borrowed directory FD")
                    if wanted==3:
                        require(r["count"]==len(op["roots"]),"all source constructor members")
                        if r["count"]<=258:require(r["members"]==[before["roots"][str(x)]for x in op["roots"]],"every complete borrowed actual member pointer and FD")
                else:require(rows==[],"private fixture never invents a namespace application call")
            native.append(captured)
        traces.append(read_trace(folder/"roles"/p["role"],case,p,responses[i][1:-1],captured))
    kernel=trace_compare(case,traces,observations,processes,comparison)
    return dict(schema="hepta.namespace-versions.actual-group-read.v1",status="COMPLETE_NAMESPACE_VERSIONS_ACTUAL_GROUP_READ_PASS",
        source_manifest_sha256=identity,group=group,case=case["case"],source_operations=len(case["steps"]),parallel_calls=sum(
            s["operation"]["workers"]*s["operation"].get("count",1)for s in case["steps"]if s["operation"]["op"].startswith("parallel-")),
        original_processes=1,native_processes=2,reader_native_executions=0,reader_original_executions=0,application_replays=0,
        native=native,traces=traces,kernel_comparison=kernel,constructor_bijections=comparison.witness,relations=relations,
        original_binary=deps["original_binary"],native_image=deps["native_image"],globals_reset=False,fixture_bytes_deleted=0,
        public_handler_qualified=False,whole_runtime_replaced=False)
