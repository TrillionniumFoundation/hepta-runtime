#!/usr/bin/env python3
"""Complete immutable capture boundary, including actual native calls without the intended fault."""
from pathlib import Path
import encodings.cp437,gzip,hashlib,struct
from evidence_common import require,decode,pin,source_evidence
from buffer_store import Reader
import restore_original
from cases import group
U=lambda b,o:struct.unpack_from("<Q",b,o)[0]
I=lambda n:n-(1<<64)if n>>63 else n
def walk(v,reader):
    if isinstance(v,dict):
        if set(v)=={"bytes","sha256","blocks"}:reader.get(v)
        else:
            for x in v.values():walk(x,reader)
    elif isinstance(v,list):
        for x in v:walk(x,reader)
def journal(path,receipt,role):
    digest=hashlib.sha256();size=events=0;pending={};effects=[];phase={}
    with gzip.open(path,"rb")as f:
        if role=="original":
            while part:=f.read(1<<20):digest.update(part);size+=len(part)
        else:
            while magic:=f.read(8):
                require(len(magic)==8 and magic in(b"HINFJR01",b"HBRDJR01",b"HMDTJR01",b"HIFER001"),"complete native owner journal")
                hs=64 if magic==b"HIFER001"else 128
                h=magic+f.read(hs-8);require(len(h)==hs,"complete native journal header")
                count=U(h,16 if hs==64 else 32);require(count<=256<<20,"bounded whole journal span")
                raw=f.read(count);require(len(raw)==count,"complete retained native journal span")
                digest.update(h);digest.update(raw);size+=hs+count;events+=1
                event=U(h,8)
                if hs==128:
                    if event in(2,5)and len(raw)>=16:phase[magic]=U(raw,8)
                    if event==8:
                        require(magic not in pending and len(raw)>=64,"one pending actual native effect")
                        pending[magic]=(raw,phase.get(magic))
                    if event==9:
                        require(magic in pending and len(raw)>=96,"complete actual native effect reply")
                        req,ph=pending.pop(magic);effects.append(dict(owner=magic.decode(),phase=ph,operation=U(req,24),
                            fd=U(req,32),raw_return=I(U(raw,24)),request_hex=req.hex(),reply_hex=raw.hex()))
    require(not pending,"no unreturned effect at captured process end")
    require(pin(path)==receipt["compressed"]and dict(bytes=size,sha256=digest.hexdigest())==receipt["raw"],"complete retained process journal")
    return dict(events=events,bytes=size,sha256=digest.hexdigest(),effects=effects)
def verify(source,work,name):
    source,work=Path(source),Path(work);binding=restore_original.selection(source,name)
    archive=restore_original.verify(source,work,binding);root=work/"original/restored";old=root/"source";run=root/"run"
    processes=decode((run/"processes/processes.json").read_bytes());gate=decode((run/"GATE.json").read_bytes())
    require(processes==gate["processes"]and gate["status"]=="FAIL","whole failed continuation process sequence")
    expected=[("source-check",60),("partial-fetch",60),("partial-unpack",180),("partial-admission",180),
        ("build-fetch",60),("build-unpack",180),("build-admission",180),("capture-original",180),("capture-native",180)]
    if name=="shm":expected.append(("full-read",180))
    require([(p["name"],p["timeout_seconds"])for p in processes]==expected,"exact continuation terminal boundary")
    for at,p in enumerate(processes):
        require(p["completed"]and not p["timed_out"]and p["pid"]==p["pgid"]and p["exit_code"]==(1 if at==len(processes)-1 else 0),
            "natural bounded failed continuation process")
        for suffix in("stdout","stderr"):
            v=p[suffix];require(pin(run/"processes"/v["file"])=={k:v[k]for k in("bytes","sha256")},"whole producer streams")
    data=run/"application";queries=group(name);roles={}
    for role in("original","native"):
        folder=data/role;reader=Reader(folder/"buffers")
        with gzip.open(folder/"cases.jsonl.gz","rb")as f:lines=list(f)
        values=[decode(x)for x in lines];complete_ids=[v["input"]["id"]for v in values]
        expected_ids=[q["id"]for q in queries]if role=="original"or name=="shm"else[9]
        require(complete_ids==expected_ids,"whole completed input prefix")
        for raw,v in zip(lines,values):
            require(raw.endswith(b"\n")and v["input"]==next(q for q in queries if q["id"]==v["input"]["id"])
                and v["whole_process_exited"],"complete unchanged actual input row");walk(v,reader)
        reports=[];actual_calls=0;faulted=0;whole=[]
        carrier_ids=sorted((int(p.name)for p in(folder/"carriers").iterdir()))
        require(carrier_ids==expected_ids+([10]if role=="native"and name=="child-orphans"else[]),"only declared executed prefix/partial process")
        for cid in carrier_ids:
            c=folder/"carriers"/str(cid);partial=not(c/"carrier-process.json").exists()
            receipt=decode((c/("carrier-failure-process.json"if partial else"carrier-process.json")).read_bytes())
            exchanges=[decode(x)for x in(c/"exchanges.jsonl").read_bytes().splitlines()]
            sent=(c/"carrier.stdin").read_bytes()
            with gzip.open(c/"carrier.stdout.gz","rb")as f:received=f.read()
            s=r=0;commands=[];applications=[];arms=[]
            for ordinal,x in enumerate(exchanges,1):
                require(x["exchange"]==ordinal,"complete ordered exchange");walk(x,reader)
                a=reader.get(x["input"]);b=reader.get(x["output"])
                require(sent[s:s+len(a)]==a and received[r:r+len(b)]==b,"all actual streams equal saved complete exchange buffers")
                s+=len(a);r+=len(b)
                require(len(a)>=72 and U(a,0)==len(a)-8 and a[8:16]==b"HIFXFQ01"and U(a,16)==x["command"]
                    and U(a,32)==len(a)-72 and b[:8]==b"HIFXFR01"and U(b,16)==len(b)-64,"whole fixed actual frames")
                command=x["command"];commands.append(command)
                if command in(18,21):arms.append(dict(exchange=ordinal,command=command,result=U(b,8)))
                if command==1:
                    actual_calls+=1;require(U(b,8)==(0 if role=="original"else 64),"complete actual application return")
                    frame=b[64:]
                    if role=="original":
                        value=decode(frame);fault=int(not value["ok"]and value["error"].get("errno")==5)
                        applications.append(dict(exchange=ordinal,result=value,complete_frame=reader.get(x["output"]).hex(),
                            actual_seccomp_filters=value["actual_seccomp_filters"]))
                        faulted+=fault
                    else:
                        require(frame[:8]==b"HINFR001"and U(frame,8)==0,"retained old native invocation had no intended EIO")
                        applications.append(dict(exchange=ordinal,result_kind=U(frame,8),frame_hex=frame.hex()))
            require(s==len(sent)and r==len(received),"no unread command or output suffix")
            require(pin(c/"carrier.stdin")==receipt["streams"]["stdin"]and pin(c/"carrier.stderr")==receipt["streams"]["stderr"]
                and not(c/"carrier.stderr").read_bytes()and pin(c/"carrier.stdout.gz")==receipt["stdout"]["compressed"]
                and dict(bytes=len(received),sha256=hashlib.sha256(received).hexdigest())==receipt["stdout"]["raw"],"whole complete custody")
            j=journal(c/"carrier.journal.gz",receipt["journal"],role)
            if role=="native":
                require(not any(x["owner"]=="HBRDJR01"and x["operation"]==6 and x["raw_return"]==-5 for x in j["effects"]),
                    "unintended first-stat EIO was not actually present")
            if partial:
                require(cid==10 and role=="native"and name=="child-orphans"and len(applications)==1
                    and len(arms)==2 and arms[0]["result"]==0 and arms[1]["result"]==0xffffffff,
                    "first native call completed, second call never sent after stale armed selector")
            else:require(receipt["returncode"]==0 and not receipt.get("failed",False),"natural retained full carrier exit")
            reports.append(dict(id=cid,partial=partial,commands=commands,arms=arms,applications=applications,journal=j,
                process=pin(c/("carrier-failure-process.json"if partial else"carrier-process.json"))))
        for raw,v in zip(lines,values):
            c=folder/v["process_path"];whole.append(dict(id=v["input"]["id"],line=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),
                process=pin(c/"carrier-process.json"),invocations=len(v["actual"]["chain"]["invocations"])))
        blocks=blockbytes=0
        for p in sorted((folder/"buffers").iterdir()):
            require(p.is_file()and not p.is_symlink()and p.suffix==".gz","ordinary whole retained block")
            with gzip.open(p,"rb")as f:raw=f.read(65537);require(not f.read(1),"whole block suffix")
            require(0<len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==p.stem,"complete referenced and partial buffers")
            blocks+=1;blockbytes+=len(raw)
        roles[role]=dict(completed_rows=whole,actual_calls=actual_calls,actual_eio_results=faulted,carriers=reports,
            full_blocks=blocks,full_block_bytes=blockbytes)
    require(roles["original"]["actual_calls"]==(7 if name=="child-orphans"else 2)
        and roles["original"]["actual_eio_results"]==(7 if name=="child-orphans"else 1)
        and roles["native"]["actual_calls"]==2,"exact retained application counts")
    return dict(status="COMPLETE_INFO_PARTIAL_BOUNDARY_PASS",group=name,archive=archive,source=source_evidence(old),roles=roles,
        original_application_replay_allowed=False,previous_native_fault_injection_success=False,new_application_calls=0,
        old_failed_fixture_opcode=2,actual_read_fstat_opcode=6,production_owner_changes_required=False)
