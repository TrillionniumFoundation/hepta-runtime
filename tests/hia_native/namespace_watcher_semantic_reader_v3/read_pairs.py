"""Pure full-domain request, wire, process, original callback and physical tree join."""
from pathlib import Path
import json,math,struct
from reader_common import read,loads,pin,require,integer,pair_path,word,read_lines
from read_tree import Tree
ROLES=("native-observed","native-off","original")
TRACE="inotify_init1,inotify_add_watch,inotify_rm_watch,read,openat,fcntl,dup2,dup3,close,write,writev,exit_group,newfstatat,fstat,statx,prlimit64,setrlimit"
ERRORS=("namespace epoch exhausted","namespace event stream closed","invalid namespace event read length",
    "namespace event drain budget exhausted","truncated namespace event","namespace event size overflow",
    "truncated namespace event name","namespace descriptor is not a directory")
def wire(value):return(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
def exact(a,b,message):require(wire(a)==wire(b),message)
def elapsed(value,maximum):
    require(type(value)in(int,float)and math.isfinite(value)and 0<=value<=maximum,"whole unchanged actual deadline")
def semantic(v):
    require(type(v)is dict and set(v)=={"kind","family","code","version"}and
        all(type(v[k])is int for k in("kind","family","code"))and v["kind"]in(0,1),"complete typed semantic result")
    if v["kind"]==0:
        require(v["family"]==v["code"]==0 and(v["version"]is None or type(v["version"])is list and
            len(v["version"])==2 and all(integer(x,1,(1<<63)-1)for x in v["version"])),"whole successful version")
    else:
        require(v["version"]is None and(v["family"]==1 and integer(v["code"],1,4095)or
            v["family"]==2 and integer(v["code"],1,8)),"whole original OS/literal error")
def state(value):
    require(type(value)is dict and set(value)=={"roots","watchers"}and
        type(value["roots"])is list and type(value["watchers"])is list,"complete state projection")
    require([x["root"]for x in value["roots"]]==sorted(set(x["root"]for x in value["roots"]))and
        [x["wid"]for x in value["watchers"]]==sorted(set(x["wid"]for x in value["watchers"])),"exact ordered original maps")
    for r in value["roots"]:
        require(set(r)=={"root","fd","strong_count","device","inode","mode"}and
            all(integer(v)for v in r.values())and r["fd"]==512+r["root"]and r["root"]<260 and
            r["strong_count"]>0 and r["inode"]>0,"complete held original File identity")
    for w in value["watchers"]:
        require(set(w)=={"wid","state"}and integer(w["wid"]),"exact original watcher identity")
        s=w["state"];require(set(s)=={"content","event_fd","limit","next","watches"}and type(s["content"])is bool
            and integer(s["event_fd"],32,319)and integer(s["limit"],0,258)and integer(s["next"],0,(1<<63)-1)
            and type(s["watches"])is list and len(s["watches"])<=max(1,s["limit"]),"full actual Watcher fields")
        for a in s["watches"]:
            require(set(a)=={"device","inode","wd","id","generation","dead","pin_fd","strong_count"}and
                type(a["dead"])is bool and all(integer(a[k])for k in set(a)-{"dead"})and
                integer(a["wd"],0,0x7fffffff)and a["id"]>0 and a["generation"]>0 and a["strong_count"]>0
                and a["pin_fd"]>=32,"whole original watch/pin row")
def process_identity(row,pid,parent,group):
    require(type(row)is dict and set(row)=={"pid","parent_pid","pgid","session","start_ticks","raw_hex"},"full actual proc identity")
    raw=bytes.fromhex(row["raw_hex"]);require(raw and len(raw)<=65536 and raw.endswith(b"\n"),"entire original proc stat")
    at=raw.rfind(b")");fields=raw[at+2:].split()
    require(at>0 and len(fields)>=20 and int(raw[:raw.find(b" ")])==pid and
        (int(fields[1]),int(fields[2]),int(fields[3]),int(fields[19]))==(parent,group,group,row["start_ticks"])
        and row["pid"]==pid and row["parent_pid"]==parent and row["pgid"]==row["session"]==group
        and all(integer(row[k],1)for k in("pid","parent_pid","pgid","session","start_ticks")),"exact actual PID/parent/PGID/session chain")
def role(folder,role_name,group,commands,parent,m,producer):
    r=loads(read(folder/"PROCESS.json"));rows=loads(read(folder/"EXCHANGES.json"))
    require(r["role"]==role_name and r["group"]==group and r["cwd"]==m["source_root"] and
        r["owner_pid"]==parent["pid"]and r["pgid"]==parent["pgid"]and r["parent_pid"]==r["tracer_pid"]and
        r["success"]is True and r["failure"]is None and type(r["exit_code"])is int and r["exit_code"]==0
        and type(r["timeout_seconds"])is int and r["timeout_seconds"]==60,"owned actual whole application result")
    elapsed(r["elapsed_seconds"],parent["elapsed_seconds"])
    for k in("pid","tracer_pid"):require(integer(r[k],1),"actual positive child PID")
    require(r["pid"]!=r["tracer_pid"]!=parent["pid"],"distinct owned process identities")
    process_identity(r["application_identity"],r["pid"],r["tracer_pid"],parent["pgid"])
    process_identity(r["tracer_identity"],r["tracer_pid"],parent["pid"],parent["pgid"])
    old_folder=Path(parent["output_root"])/"roles"/role_name
    if role_name=="original":argv=[str(Path(m["producer_root"])/"original.elf"),group]
    else:
        # Child.start resolves its interpreter before invoking the application.
        argv=[producer["python_resolved"],"-I","-B",str(Path(m["source_root"])/"native_child.py"),"--retained",m["retained_root"],
            "--output",str(old_folder/"capture"),"--group",group,"--observer","on"if role_name=="native-observed"else"off"]
    require(r["argv"]==argv,"exact original/native application command")
    trace_argv=["/usr/bin/strace","-qq","-f","--kill-on-exit","-s","65536","-xx","-v","-o",
        str(old_folder/"syscalls.strace"),"-e","trace="+TRACE,"-e","raw=read,write,writev","-e",
        "read="+",".join(str(x)for x in range(32,320)),*argv]
    require(r["tracer_argv"]==trace_argv,"complete actual unchanged kernel trace scope")
    require(set(r["streams"])=={"stdin","stdout","stderr","syscalls.strace"},"all full application streams")
    stream_bytes={}
    for name,p in r["streams"].items():
        raw=read(folder/name);require(pin(raw)==p,"entire actual application stream: "+name);stream_bytes[name]=raw
    raw_outputs,output_lines=read_lines(folder/"stdout");values=[v for _,v in output_lines]
    ready=dict(command="ready",role=role_name,group=group,pid=r["pid"],parent_pid=r["tracer_pid"],pgid=parent["pgid"],
        uid=m["uid"],gid=m["gid"],layout=dict(pool_first=32,pool_end=320,root_first=512,root_end=772))
    exact(r["ready"],ready,"whole actual ready identity");exact(values[0],ready,"actual first physical ready wire")
    require(len(rows)==len(commands)==r["exchanges"]==len(values)-1,"all complete exchanges and no response suffix")
    stdin=b"".join(wire(x)for x in commands);require(stream_bytes["stdin"]==stdin,"full source-derived actual stdin")
    for i,(request,record,(raw,value))in enumerate(zip(commands,rows,output_lines[1:])):
        require(set(record)=={"index","request","response","request_hex","response_hex"}and type(record["index"])is int
            and record["index"]==i and record["request"]==pin(wire(request))and record["response"]==pin(raw)
            and bytes.fromhex(record["request_hex"])==wire(request)and bytes.fromhex(record["response_hex"])==raw,
            "every complete indexed exchange byte")
        require(raw==wire(value),"actual complete canonical typed response line")
    marks=b""
    for command in commands:
        if command["cmd"]=="run":
            prefix=b"HNWORG"if role_name=="original"else b"HNWNAT"
            marks+=prefix+b"B1"+struct.pack("<2Q",command["case"],command["step"])
            marks+=prefix+b"E1"+struct.pack("<2Q",command["case"],command["step"])
    require(stream_bytes["stderr"]==marks,"every actual application begin/end marker and no unclaimed stderr")
    return dict(report=r,answers=values[1:],wire_bytes=len(stdin)+len(raw_outputs)+len(marks))
def callback(op,answer):
    rows=answer["callback"];original=answer.get("original_callback")
    require(type(rows)is list and(original is None or type(original)is list and len(original)==len(rows)),"whole callback streams")
    if op["op"]!="callback":
        require(rows==[]and(original is None or original==[]),"no callback outside explicit private read domain");return
    buffer=bytes(16384);script=op["script"]["reads"]
    for i,row in enumerate(rows):
        j=i if i<len(script)else len(script)-1
        require(j>=0 and(i<len(script)or op["script"]["repeat_last"]is True),"complete source callback script")
        item=script[j];before=buffer
        if "errno"in item:result=dict(errno=item["errno"])
        elif "kind"in item:result=dict(errno={"Interrupted":4,"WouldBlock":11}[item["kind"]])
        else:
            raw=bytes.fromhex(item["bytes"]);require(len(raw)<=16384,"full admitted callback payload")
            buffer=raw+buffer[len(raw):];result=dict(count=item["count"])
        wanted=dict(index=i,script_row=j,before_hex=before.hex(),after_hex=buffer.hex(),result=result)
        exact(row,wanted,"complete original/native callback buffer and source result")
        if original is not None:
            full=original[i];require(set(full)==set(wanted),"complete original callback fields")
            for name in set(wanted)-{"result"}:require(full[name]==wanted[name],"same complete original callback observation")
            if "count"in result:exact(full["result"],result,"actual original complete callback count")
            else:
                out=full["result"];require(set(out)=={"raw_os_error","kind","display","debug"}and
                    all(type(out[n])is str and out[n]for n in("kind","display","debug")),"entire original error observation")
                require(out["raw_os_error"]==item.get("errno")and
                    ("kind"not in item or out["kind"]==item["kind"]),"actual original errno or ErrorKind source")
def run_answer(answer,case,step,op,original=False):
    expected={"command","case","step","operation","semantic","state","callback"}|({"original_callback","original_error"}if original else{"native_frame_hex"})
    require(set(answer)==expected and answer["command"]=="run"and type(answer["case"])is int and answer["case"]==case
        and type(answer["step"])is int and answer["step"]==step and answer["operation"]==op["op"],"exact operation response domain")
    semantic(answer["semantic"]);state(answer["state"]);callback(op,answer)
    if original:
        err=answer["original_error"]
        if answer["semantic"]["kind"]==0:require(err is None,"successful original has no error")
        else:
            require(type(err)is dict and set(err)=={"display","debug","chain","raw_os_error"}and
                type(err["display"])is str and err["display"]and type(err["debug"])is str and err["debug"]
                and type(err["chain"])is list and err["chain"]and err["chain"][0]==err["display"]
                and all(type(x)is str and x for x in err["chain"]),"complete original display/debug/error chain")
            s=answer["semantic"]
            if s["family"]==1:require(type(err["raw_os_error"])is int and err["raw_os_error"]==s["code"],"actual original OS error")
            else:require(err["raw_os_error"]is None and err["display"]==ERRORS[s["code"]-1],"actual complete original literal error")
    else:
        raw=answer["native_frame_hex"];has_frame=op["op"]in("new","version","drain","changed","callback","drop")
        require((raw is not None)==has_frame,"every actual native terminal retained")
        if has_frame:
            frame=bytes.fromhex(raw);require(len(frame)==128 and frame[:8]==b"HNWR0001"and
                word(frame,16)==step+1 and word(frame,120)==0,"whole actual native terminal")
            command={"new":1,"version":2,"drain":3,"changed":5,"drop":4}.get(op["op"],3 if op.get("root")is None else 2)
            require(word(frame,32)==command and frame[40:72]==bytes(32),"actual source command and no terminal effect")
            projected=dict(kind=word(frame,8),family=word(frame,72),code=word(frame,80),
                version=[word(frame,88),word(frame,96)]if word(frame,8)==0 and command==2 else None)
            exact(projected,answer["semantic"],"whole actual HIA terminal projects to compared original result")
def verify(folder,m,command_record,cases,producer):
    report=loads(read(folder/"PAIRED.json"));group=cases[0]["group"]
    require(report["schema"]=="hepta.namespace-watcher.same-tree-pair.v1"and report["status"]=="PASS"
        and report["source_manifest_sha256"]==m["source_manifest_sha256"]and report["group"]==group
        and report["cases"]==len(cases)and report["operations"]==sum(len(c["steps"])for c in cases)
        and report["processes"]==report["application_processes"]==report["tracer_processes"]==3,
        "entire completed frozen paired domain")
    for k in("source_root","retained_root","uid","gid","original_binary"):
        exact(report[k],m[k],"same source/binary/ownership binding: "+k)
    require(report["parent_pid"]==m["root_pid"]==command_record["parent_pid"]and
        report["pid"]==report["pgid"]==command_record["pid"]==command_record["pgid"]
        and report["output_root"]==str(Path(m["producer_root"])/("paired-"+group))
        and report["fixture_root"]==str(Path(m["owned_fixture"])/group)
        and report["timeout_seconds"]==60,"actual paired parent and exact original path roots")
    elapsed(report["elapsed_seconds"],min(60,command_record["elapsed_seconds"]))
    require(report["namespace_version_qualified"]is False and report["public_handler_qualified"]is False
        and report["compared_complete_terminal_bytes"]is True and report["compared_complete_watcher_and_arc_state"]is True
        and report["driver_snapshots"]=="unchanged-complete-before-and-after-each-application","accurate private scope")
    required=("INITIALS.json","OBSERVATIONS.json","RETIREMENT.json","PROCESSES.json","TRACE-CUSTODY.json")
    require(set(report["files"])==set(required),"all complete physical reports")
    decoded={}
    for name in required:
        raw=read(folder/name);require(pin(raw)==report["files"][name],"entire captured report: "+name);decoded[name]=loads(raw)
    initials=decoded["INITIALS.json"];observations=decoded["OBSERVATIONS.json"];retirements=decoded["RETIREMENT.json"]
    require([r["case"]for r in initials]==[c["case"]for c in cases]==[r["case"]for r in retirements]and
        len(observations)==report["operations"],"all original cases and operations")
    custody=decoded["TRACE-CUSTODY.json"]
    exact(custody,dict(owner_pid=report["pid"],owner_pgid=report["pgid"],prior_subreaper=custody.get("prior_subreaper"),
        restored=True,adopted_reaps=[],kill_on_tracer_exit=True,trace_scope="all-three-applications-entire-lifetimes",
        complete_driver_snapshots_retained=True),"complete normal application/tracer cleanup")
    require(type(custody["prior_subreaper"])is int and custody["prior_subreaper"]in(0,1),"actual previous subreaper state")
    commands=[]
    for case in cases:
        root=Path(report["fixture_root"])/("case-%04d"%case["case"])
        commands.append(dict(cmd="prepare",case=case["case"],roots=[dict(
            path_hex=(str(root).encode()+b"/"+r["name"].encode()).hex(),late=r["late"])for r in case["roots"]]))
        commands.extend(dict(cmd="run",case=case["case"],step=i,operation=s["operation"])for i,s in enumerate(case["steps"]))
        commands.append(dict(cmd="finish",case=case["case"]))
    roles=[role(folder/"roles"/name,name,group,commands,report,m,producer)for name in ROLES]
    exact(decoded["PROCESSES.json"],[r["report"]for r in roles],"aggregate includes each full physical child process")
    require(len({r["report"][k]for r in roles for k in("pid","tracer_pid")})==6,"all six independently owned child PIDs")
    answer_at=operation_at=0
    for ci,case in enumerate(cases):
        initial=initials[ci];root=str(Path(report["fixture_root"])/("case-%04d"%case["case"]))
        require(set(initial)=={"case","owned_root","snapshot","after","replies"}and initial["owned_root"]==root,"same exact owned fixture")
        model=Tree(case,m["uid"],m["gid"]);physical=model.check(initial["snapshot"])
        require(initial["after"]==[initial["snapshot"]]*3,"every complete tree unchanged by prepare")
        expected_roots=[]
        for i,r in enumerate(case["roots"]):
            if not r["late"]:
                p=physical[r["name"].encode()]
                expected_roots.append(dict(root=i,fd=512+i,strong_count=1,device=p["device"],inode=p["inode"],mode=p["mode"]|p["type"]))
        prepared=dict(command="prepare",case=case["case"],state=dict(roots=expected_roots,watchers=[]))
        for ri,r in enumerate(roles):
            exact(r["answers"][answer_at],prepared,"actual same-tree prepared File metadata")
            exact(initial["replies"][ri],prepared,"all full initial replies retained")
        answer_at+=1
        for si,step in enumerate(case["steps"]):
            obs=observations[operation_at];operation_at+=1
            require(set(obs)=={"case","step","operation","before","after","answers"}and
                obs["case"]==case["case"]and obs["step"]==si and obs["operation"]==step["operation"]["op"],
                "every whole source-ordered observation")
            model.mutate(step["actions"]);model.check(obs["before"])
            require(obs["after"]==[obs["before"]]*3,"every actual application preserves all physical bytes and metadata")
            answers=[r["answers"][answer_at]for r in roles];answer_at+=1
            exact(obs["answers"],answers,"physical process replies equal all captured comparison rows")
            for ri,answer in enumerate(answers):run_answer(answer,case["case"],si,step["operation"],ri==2)
            for key in("semantic","state","callback"):
                exact(answers[0][key],answers[1][key],"observer-off exact complete result: "+key)
                exact(answers[0][key],answers[2][key],"unchanged original exact complete result: "+key)
            require(answers[0]["native_frame_hex"]==answers[1]["native_frame_hex"],"all full native terminal bytes unchanged without observer")
        finish=dict(command="finish",case=case["case"],all_owned_descriptors_closed=True)
        for r in roles:exact(r["answers"][answer_at],finish,"actual complete scope close before next case")
        answer_at+=1
        retired=retirements[ci];require(set(retired)=={"case","root","retired","complete_before"}and
            retired["root"]==root and retired["retired"]is True,"exact owned fixture retirement only")
        model.check(retired["complete_before"])
    require(answer_at==len(commands)and operation_at==len(observations),"no missing cases, calls or output suffix")
    return dict(report=report,commands=commands,roles=roles,cases=cases,observations=observations,
        summary=dict(group=group,cases=len(cases),operations=operation_at,application_processes=3,tracers=3,
            complete_wire_bytes=sum(r["wire_bytes"]for r in roles),original_binary=m["original_binary"]))
