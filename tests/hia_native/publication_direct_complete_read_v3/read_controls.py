#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read complete public/control bytes and both real session state projections."""
from pathlib import Path
import gzip,hashlib,json,stat,struct
from common import canonical,decode,pin,require,sha
from buffer_store import Reader
import read_state
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
def read(native_root,case,expected_binary):
    n=Path(native_root)
    result=decode((n/"RESULT.json").read_bytes());process=decode((n/"process/PROCESS.json").read_bytes())
    require(result["case"]==case["case"] and result["name"]==case["name"] and result["era"]==case["era"]
        and result["status"]=="ACTUAL_NATIVE_DIRECT_FUTURE_CAPTURED" and result["process"]==process,"actual native case identity")
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

    return dict(root=n,result=result,process=process,streams=streams,host=host,holder=holder,
        commands=commands,controls=controls,store=store,get=get,observations=observations,
        pointers=pointers,event_prefix=event_prefix,counters=lambda:(captured_n,captured_b))
