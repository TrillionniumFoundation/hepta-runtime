#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read complete public/control bytes and both real session state projections."""
from pathlib import Path
import gzip,hashlib,json,stat,struct
from common import canonical,decode,pin,require,sha
from buffer_store import Reader
import read_state,wire_versions
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
class Hash:
    def __init__(self):self.h=hashlib.sha256();self.n=0
    def add(self,b):self.h.update(b);self.n+=len(b)
    def value(self):return dict(bytes=self.n,sha256=self.h.hexdigest())
def compressed(path,row):
    require(set(row)=={"raw","gzip","closed_before_compression","full_byte_reread"}
        and row["closed_before_compression"] is row["full_byte_reread"] is True,"complete closed-stream custody")
    require(pin(path)==row["gzip"],"whole compressed stream pin")
    result=Hash()
    with gzip.open(path,"rb") as stream:
        while b:=stream.read(1<<20):result.add(b)
    require(result.value()==row["raw"],"every decompressed stream byte")
    return result.value()
def normalize_files(rows,reader,identities,initial):
    result=[]
    for row in rows:
        require(set(row)==({"path","stat","kind","xattrs","entries"} if row["kind"]=="dir" else
            {"path","stat","kind","xattrs","data"}),"full observed filesystem row")
        s=row["stat"];require(set(s)=={"mode","dev","ino","nlink","uid","gid","size","atime_ns","mtime_ns","ctime_ns"},"whole stat fields")
        key=s["dev"],s["ino"]
        if key not in identities:identities[key]=len(identities)
        item=dict(path=row["path"],kind=row["kind"],identity=identities[key],
            mode=s["mode"],nlink=s["nlink"],owner_is_initial=s["uid"]==initial["uid"],
            group_is_initial=s["gid"]==initial["gid"],xattrs=row["xattrs"])
        if row["kind"]=="file":
            raw=reader.get(row["data"]);require(len(raw)==s["size"] and stat.S_ISREG(s["mode"]),"all observed file bytes")
            item.update(bytes=len(raw),sha256=sha(raw))
        else:
            require(stat.S_ISDIR(s["mode"]) and row["entries"]==sorted(set(row["entries"])),"whole directory set")
            item["entries"]=row["entries"]
        require(s["atime_ns"]>0 and s["mtime_ns"]>0 and s["ctime_ns"]>0,"actual timestamp values retained")
        result.append(item)
    return result
def compare(native_root,original_root,case,expected_binary):
    n=Path(native_root);o=Path(original_root)
    result=decode((n/"RESULT.json").read_bytes());process=decode((n/"process/PROCESS.json").read_bytes())
    require(result["case"]==case["case"] and result["name"]==case["name"] and result["era"]==case["era"]
        and result["status"]=="ACTUAL_NATIVE_TWO_SESSION_CAPTURED" and result["process"]==process,"actual native case identity")
    require(process["exit_code"]==0 and process["expected_success"] is True and process["timed_out"] is False
        and process["completion_error"] is None and process["cleanup_errors"]==[] and process["process_group_absent"] is True,
        "complete naturally ended process")
    require(process["cwd"]==case["root"] and process["timeout_seconds"]==180
        and process["exchange_limit_seconds"]==60 and 0<=process["elapsed_seconds"]<180,"actual original path and unchanged budgets")
    command=process["command"]
    require(command[1:4]==["-I","-S","-B"] and Path(command[4]).name=="fd_entry.py"
        and len(command)==15 and Path(command[6]).name=="config.json","fixed native capability entry")
    declared=Path(command[6]).parent
    config=dict(state_dir=str(declared/"controller-state"),controller_workspace_roots=[case["root"]],
        hosts={"fixture":dict(ssh_target="uncontacted-async-reference",remote_state_dir="/unused-runtime-state",
            allow_write=True,allowed_read_path_prefixes=["/allowed"],allowed_write_path_prefixes=["/allowed"],
            protected_path_prefixes=["/allowed/protected"])})
    require((n/"config.json").read_bytes()==canonical(config),"entire configured input")
    streams={name:compressed(n/"process"/(name+".gz"),row) for name,row in process["files"].items()}
    require(set(streams)=={"process.stdout","process.stderr","stdin-0","stdin-1","stdout-0","stdout-1",
        "control.stdin","control.stdout","bellman-journal","host-trace","publication-journal"},"entire closed stream set")
    require(streams["process.stdout"]["bytes"]==streams["process.stderr"]["bytes"]==0,"unmixed control and standard streams")
    require(set(p.name for p in (n/"process").iterdir())=={name+".gz" for name in streams}|
        {"PROCESS.json","CONTROLS.json","OBSERVATIONS.json"},"whole process evidence set")
    identities=process["stream_identity"]
    require(len(identities["inputs"])==len(identities["outputs"])==2,"two actual independent pipe pairs")
    ends=[*identities["inputs"],*identities["outputs"]]
    require(all(stat.S_ISFIFO(r["mode"]) for r in ends) and len({(r["dev"],r["ino"]) for r in ends})==4,
        "four actual separate pipes")
    host=decode((n/"HOST.json").read_bytes());commands=decode((n/"COMMANDS.json").read_bytes())
    require([e["event"] for e in host]==["holder_locked","process_started","holder_unlocked","holder_fd_closed"],"actual owned holder lifecycle")
    holder=host[0]["identity"]
    require(host[0]["directory"]==str(Path(case["root"])/"held") and host[0]["flags"]==6
        and stat.S_ISDIR(holder["mode"]) and host[2]["identity"]==holder and host[3]["fd"]==holder["fd"],"one real held directory descriptor")
    require(host[1]["pid"]==process["pid"] and host[1]["binary"]==expected_binary,"same graph process and binary")
    require([e["monotonic_ns"] for e in host]==sorted(e["monotonic_ns"] for e in host),"holder temporal order")
    controls=decode((n/"process/CONTROLS.json").read_bytes())
    store=Reader(n/"buffers");requests=Hash();responses=Hash();observations=[];captured_n=0;captured_b=0
    def get(row):
        nonlocal captured_n,captured_b
        raw=store.get(row);captured_n+=1;captured_b+=len(raw);return raw
    pointers=None;event_prefix={};last_read=[0,0];last_phase=[0,0]
    for number,row in enumerate(controls):
        require(row["number"]==number and row["sequence"]==number+1 and 0<=row["elapsed_ns"]<60_000_000_000,"every actual private exchange")
        q=get(row["request"]);h=get(row["header"]);body=get(row["result"]);co=get(row["coordinator"])
        pms=[get(r) for r in row["pms"]]
        require(len(q)>=64 and q[:8]==b"HAPFQ001" and (U(q,8),U(q,16),U(q,24),U(q,32),U(q,56))==
            (number+1,row["operation"],row["session"],len(q)-64,0),"exact fixed private request")
        require(len(h)==128 and h[:8]==b"HAPFR001" and (U(h,8),U(h,16),U(h,24),U(h,32),U(h,40),U(h,120))==
            (number+1,row["operation"],row["session"],0,len(body),12288),"exact actual private reply")
        require(len(co)==4096 and co[:8]==b"HAPFC001" and U(co,8)==4096 and U(co,64)==number+1
            and len(pms)==2 and all(len(pm)==4096 for pm in pms),"entire coordinator/PM pages")
        require((U(co,72),U(co,80),U(co,88),U(co,96),U(co,104))==
            (row["operation"],row["session"],len(q)-64,U(q,40),U(q,48)),"private input admitted into coordinator")
        current=(U(co,16),U(co,24),U(co,32),U(co,40),U(co,48),U(pms[0],240),U(pms[1],240))
        require(all(current) and current[3]!=current[4] and current[5]!=current[6],"actual two distinct sessions")
        if pointers is None:pointers=current
        require(current==pointers,"shared/per-session capabilities changed")
        for sid,pm in enumerate(pms):
            require(U(pm,1224)==sid and U(pm,248)==U(co,16) and U(pm,232)==U(co,24) and U(pm,224)==U(co,32),
                "actual session-to-process ownership")
            require(U(pm,1232)>=last_read[sid] and U(pm,328)>=last_phase[sid]
                and U(pm,328) in (0,1,2,3,4),"actual read/phase monotonicity")
            last_read[sid]=U(pm,1232);last_phase[sid]=U(pm,328)
            require((U(h,64+8*sid),U(h,80+8*sid),U(h,96+8*sid))==
                (U(pm,328),U(pm,816),U(pm,1232)),"full reply projects actual PM")
        require(U(co,448)==U(h,56)<=32 and U(co,136)==U(h,112) in (0,1),"actual append-only events/finalization")
        events=[]
        for i in range(U(co,448)):
            at=512+i*64;pool,job,engine,tag,stage,entered,returned,dropped=struct.unpack_from("<8Q",co,at)
            require(pool and job and tag and engine in current[5:] and stage in (1,2,3)
                and entered>0 and (stage==1 and returned==dropped==0 or stage==2 and returned>=entered and dropped==0
                or stage==3 and dropped>=entered and returned==0),"actual await context event")
            key=pool,job
            require(key not in {(e["pool"],e["job"]) for e in events},"unique real pool/job")
            ev=dict(pool=pool,job=job,engine=engine,tag=tag,stage=stage,entered=entered,returned=returned,dropped=dropped)
            if key in event_prefix:
                old=event_prefix[key];require(all(ev[k]==old[k] for k in ("pool","job","engine","tag","entered"))
                    and (ev==old or old["stage"]==1),"actual future transition cannot be rewritten")
            event_prefix[key]=ev;events.append(ev)
        require(len(events)==len(event_prefix),"actual event table was truncated")
        require(len({e["pool"] for e in events})<=1,"both sessions use the same actual publication pool")
        pieces=[h,body,co,*pms];states=[]
        require(len(row["snapshots"])==(2 if row["operation"] in (3,5) else 0),"complete snapshot operation inventory")
        for sid,item in enumerate(row["snapshots"]):
            sh=get(item["header"]);sb=get(item["body"]);pieces.extend((sh,sb))
            states.append(read_state.native(sh,sb,co,pms[sid],sid,number+1,row["operation"]))
        require(sum(len(x) for x in pieces[5:])==U(h,48),"whole suffix extent")
        requests.add(q)
        for raw in pieces:responses.add(raw)
        observations.append(dict(operation=row["operation"],session=row["session"],request=q,result=body,
            states=states,events=events,phases=tuple(U(pm,328) for pm in pms),final=U(co,136)))
    require(requests.value()==streams["control.stdin"] and responses.value()==streams["control.stdout"],
        "every actual control input/output byte accounted in order")
    require(observations and observations[-1]["operation"]==5 and observations[-1]["final"]==1
        and observations[-1]["phases"]==(4,4),"one process-runtime finalization after both closed services")
    require(sum(o["operation"]==5 for o in observations)==1,"runtime finalized exactly once")

    old_commands=decode((o/"COMMANDS.json").read_bytes());old_store=Reader(o/"buffers")
    require(len(commands)==len(old_commands)==result["commands"],"complete input command sequence")
    native_fs=decode((n/"FILESYSTEM.json").read_bytes());original_fs=decode((o/"FILESYSTEM.json").read_bytes())
    require(native_fs[-1]["name"]==original_fs[-1]["name"]=="after-runtime-drop","actual final filesystem barriers")
    version_proofs=[]
    public_in=[Hash(),Hash()];public_out=[Hash(),Hash()]
    stable=[];state_differences=[];at=0;previous_control=0
    for number,(row,old) in enumerate(zip(commands,old_commands,strict=True)):
        request=get(row["request"]);q=decode(request)
        oq=decode(old_store.get(old["request"]));ov=decode(old_store.get(old["response"]))
        require(request==canonical(oq) and row["number"]==number and row["source_step"]==old["source_step"]
            and q==dict(oq),"full unchanged actual original request")
        require(row["control_first"]==previous_control and row["control_count"]>0
            and row["state_control"]==row["control_first"]+row["control_count"]-1
            and 0<=row["elapsed_ns"]<60_000_000_000,"every actual private command range")
        previous_control+=row["control_count"];view=observations[row["state_control"]]
        require(view["operation"]==(5 if q["kind"]=="finalize" else 3) and view["session"]==q["session"],"full post-command snapshot")
        actual=row["result"];expected=ov["result"];kind=q["kind"];sid=q["session"]
        if kind in ("send","cache","eof","close_transport","drive"):
            require(actual==expected,"whole ordinary command result: "+kind)
        if kind=="send":public_in[sid].add(bytes.fromhex(q["wire_hex"]))
        if kind in ("read","drain"):
            actual_raw=bytes.fromhex(actual["wire_hex"]);expected_raw=bytes.fromhex(expected["wire_hex"])
            actual_wire,actual_versions=wire_versions.lines(actual_raw,case,native_fs[-1]["files"],store)
            expected_wire,expected_versions=wire_versions.lines(expected_raw,case,original_fs[-1]["files"],old_store)
            require(actual_wire==expected_wire,"complete current SDK wire outside individually stat-bound version differs at command "+str(number)+": "+repr((actual_raw,expected_raw)))
            require([r["path"] for r in actual_versions]==[r["path"] for r in expected_versions],"same publication version paths")
            version_proofs.append(dict(command=number,native=actual_versions,original=expected_versions))
            public_out[sid].add(bytes.fromhex(actual["wire_hex"]))
        if kind=="drain":
            require(expected["terminal"]=={"joined":True,"service_ok":True} and
                actual["terminal"]==dict(actual_phase=4,actual_eof_result=0,actual_pipe_closed=1),"actual service terminal semantics")
        if kind=="wait_events":
            require(actual["event"]==expected["event"] and actual["count"]==expected["count"],"actual original/native future transition count")
        if kind=="finalize":require(actual=={"actual_runtime_finalized":True} and expected=={"runtime_dropped":True},"actual runtime ownership end")
        if kind=="wait_blocked":
            require(actual["parent_pid"]==process["pid"] and actual["path"]==q["path"]
                and (actual["dev"],actual["ino"])==(holder["dev"],holder["ino"]),"real blocked children match real held directory")
            matching=[]
            for child in actual["children"]:
                if "fd" in child and (child["dev"],child["ino"])==(holder["dev"],holder["ino"]):
                    words=child["syscall"].split()
                    require(int(words[0],0)==73 and int(words[1],0)==child["fd"] and int(words[2],0)==2,"real owned flock syscall")
                    matching.append(child["pid"])
            require(matching==actual["matching_pids"] and len(set(matching))==len(matching)>=q["count"],"all observed blocked worker children")
        wanted=read_state.original(ov["state"]);got=[s["state"] for s in view["states"]]
        require(len(got)==2,"both post-command states are retained")
        # The process observation drives two independent schedulers; a plain
        # send is not a completion barrier. Every byte is structurally checked.
        # Compare complete states at actual blocked/read barriers before unlock,
        # completed-future barriers, and the final runtime boundary.
        settled=(number<host[2]["after_commands"] and kind not in ("send","eof","close_transport","drive","observe")) or kind=="finalize" or (kind=="wait_events" and q["event"]=="returned")
        if settled:
            require(got==wanted,"complete stable session/cache/history/lock state differs at command "+str(number)+": "+repr((got,wanted)))
            stable.append(number)
        elif got!=wanted:state_differences.append(number)
    require(previous_control==len(controls),"no unclaimed fixture controls")
    for sid in (0,1):
        require(public_in[sid].value()==streams["stdin-"+str(sid)] and
            public_out[sid].value()==streams["stdout-"+str(sid)],"all actual public pipe bytes accounted")
    ns=decode((n/"FILESYSTEM.json").read_bytes());orig=decode((o/"FILESYSTEM.json").read_bytes())
    require([(s["name"],s["after_commands"]) for s in ns]==[(s["name"],s["after_commands"]) for s in orig],
        "all original stable filesystem observations")
    ni={};oi={};ninitial=ns[0]["files"][0]["stat"];oinitial=orig[0]["files"][0]["stat"]
    file_rows=[]
    for left,right in zip(ns,orig,strict=True):
        nl=normalize_files(left["files"],store,ni,ninitial);ol=normalize_files(right["files"],old_store,oi,oinitial)
        require(nl==ol,"full publication filesystem effects differ: "+left["name"]);file_rows.append(nl)
        for r in left["files"]:
            if r["kind"]=="file":captured_n+=1;captured_b+=r["data"]["bytes"]
    complete=store.finish()
    require(result["complete_buffer_images"]==captured_n and result["logical_buffer_bytes"]==captured_b,
        "complete native buffer capture accounting")
    for key,file in (("commands","COMMANDS.json"),("host","HOST.json"),("filesystem","FILESYSTEM.json")):
        require(result["files"][key]==pin(n/file),"complete native result evidence custody")
    # These exact startup artifacts are produced by the admitted native
    # configuration owner, not by a publication request. No extra path or
    # nonempty lock/audit content is admitted.
    startup=n/"controller-state"
    require(startup.is_dir() and not startup.is_symlink()
        and stat.S_IMODE(startup.stat().st_mode)==0o700,"actual startup root")
    startup_expected={"audit":("directory",0o700),"jobs":("directory",0o700),
        "controller.lock":("file",0o600),"controller.owner.lock":("file",0o600)}
    require({p.relative_to(startup).as_posix() for p in startup.rglob("*")}==set(startup_expected),
        "complete actual startup configuration artifacts")
    startup_rows=[]
    for name,(kind,mode) in sorted(startup_expected.items()):
        p=startup/name;x=p.lstat()
        require(not p.is_symlink() and stat.S_IMODE(x.st_mode)==mode
            and (stat.S_ISDIR(x.st_mode) if kind=="directory" else stat.S_ISREG(x.st_mode)),
            "startup artifact kind/mode")
        if kind=="file":require(x.st_nlink==1 and p.read_bytes()==b"","empty private startup lock")
        else:require(not list(p.iterdir()),"empty startup directory")
        startup_rows.append(dict(path=name,kind=kind,mode=mode))
    require(set(p.name for p in n.iterdir())=={"RESULT.json","COMMANDS.json","HOST.json","FILESYSTEM.json",
        "config.json","buffers","process","controller-state"},"complete native case set")
    return dict(status="COMPLETE_TWO_SESSION_WIRE_AND_STABLE_STATE_COMPARISON_PASS",case=case["case"],name=case["name"],
        era=case["era"],commands=len(commands),private_exchanges=len(controls),
        stable_full_state_comparisons=stable,nonbarrier_observation_differences=state_differences,
        public_input=[h.value() for h in public_in],public_output=[h.value() for h in public_out],
        final_files=file_rows[-1],final_state=observations[-1]["states"],version_bindings=version_proofs,
        actual_configuration_startup=startup_rows,
        full_buffer_read=complete,all_native_streams=streams,actual_shared_pool_jobs=len(event_prefix),
        original_rerun=False,native_rerun=False,worker_journal_semantic_read_pending=True,
        full_30_domain=False,full_sdk=False)
