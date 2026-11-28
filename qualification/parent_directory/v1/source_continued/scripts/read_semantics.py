# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Only read complete retained parent results, resources, journals and mutations."""
from pathlib import Path,PurePosixPath
import ast,gzip,hashlib,struct
from common import canonical,decode,owned,pin,require,source_evidence,sha,SCOPE
from buffer_store import Reader
from cases import domain,group,wire
from filesystem import metadata
from read_journal import Journal,U,I,result,stat_value,invocation
def load(root,name):return decode(owned(root,name).read_bytes())
def buffers(root,summary):
    reader=Reader(root/"buffers");rows=[decode(r)for r in owned(root,"buffer-index.jsonl").read_bytes().splitlines()]
    require(len(rows)==summary["buffer_images"]and sum(r["bytes"]for r in rows)==summary["logical_buffer_bytes"],"complete buffer acquisition index")
    allowed={canonical(r)for r in rows};get=reader.get
    for r in rows:get(r)
    def checked(r):
        require(canonical(r)in allowed,"descriptor absent from actual complete acquisition index");return get(r)
    reader.get=checked
    return reader,dict(complete_images=len(rows),logical_buffer_bytes=sum(r["bytes"]for r in rows))
def snapshots(rows,reader):
    require("."in rows and rows["."]["kind"]=="directory","root snapshot")
    for name,row in rows.items():
        require(row["kind"]in("file","directory","symlink","fifo")and row["mode"]>=0,"fixture entry kind")
        if row["kind"]=="file":require(len(reader.get(row["content"]))==row["size"],"complete fixture content")
        elif row["kind"]=="symlink":require(type(row["target"])is str,"symlink target")
def normalized(value,q):
    if type(value)is str:return value.replace(q["fixture"],"{F}")
    if type(value)is list:return [normalized(v,q)for v in value]
    if type(value)is dict:return {k:normalized(v,q)for k,v in value.items()if k!="fd"}
    return value
def projection(rows,reader):
    out={}
    for name,row in rows.items():
        value={k:row[k]for k in("kind","mode","uid","gid","links")}
        if row["kind"]=="file":value.update(size=row["size"],content=reader.get(row["content"]))
        elif row["kind"]=="symlink":value["target"]=row["target"]
        out[name]=value
    return out
def process(root,receipt,native):
    stem="carrier"if native else"original"
    require(receipt["returncode"]==0 and receipt["parent_pgid"]==receipt["child_pgid"]
        and receipt["fixed_notify_fd"]==4 and receipt["fixed_ack_fd"]==5
        and 0<receipt["elapsed_ns"]<61_000_000_000,"actual process custody")
    for key in("stdin","stderr")if native else("stdin","stdout","stderr"):
        require(pin(owned(root,stem+"."+key))==receipt["streams"][key],"complete process stream")
    require(not owned(root,stem+".stderr").read_bytes(),"actual stderr")
def bindings(source):
    p=source/"trusted-build/target/binary_file.py";raw=p.read_bytes()
    fn=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=="parent")
    return dict(original=pin(p),parent_ast_sha256=sha(ast.dump(fn,include_attributes=False).encode()),original_parent_unmodified=True)
def hook_rows(root,reader,receipt):
    doc=load(root,"hooks.json");events=[]
    for row in doc["events"]:
        raw=reader.get(row["raw"]);ack=reader.get(row["ack"])
        require(len(raw)==64 and raw[:8]==b"HPRDHK01"and U(raw,32)==row["operation"]
            and row["operation"]in(1,2,5)and ack==bytes(8),"full hook/ack")
        if row["operation"]in(2,5):
            require(row["fd"]==U(raw,40)and row["stat"]["mode"]&61440==16384 and type(row["target"])is str,"actual directory hook")
        events.append(dict(row,raw_bytes=raw,ack_bytes=ack))
    for row in doc["mutations"]:
        require(row["separate_process"]is True and row["target_pid"]==receipt["pid"]and row["actor_pid"]!=row["target_pid"],"separate actual mutation owner")
        snapshots(row["before"],reader);snapshots(row["after"],reader)
    return doc,events
def exchange_rows(root,reader,native,receipt):
    records=[decode(r)for r in owned(root,"exchanges.jsonl").read_bytes().splitlines()]
    parsed={};digest=hashlib.sha256();total=0
    outgoing=gzip.open(owned(root,"carrier.stdout.gz"),"rb")if native else owned(root,"original.stdout").open("rb")
    with owned(root,"carrier.stdin"if native else"original.stdin").open("rb")as incoming,outgoing:
        for n,e in enumerate(records,1):
            b=reader.get(e["input"]);r=reader.get(e["output"])
            require(e["exchange"]==n and 0<=e["elapsed_ns"]<61_000_000_000 and incoming.read(len(b))==b and outgoing.read(len(r))==r,"actual full exchange bytes")
            digest.update(r);total+=len(r)
            if native:
                require(len(b)>=72 and U(b,0)==len(b)-8 and b[8:16]==b"HPRDFQ01"
                    and U(b,16)==e["command"]and U(b,24)==e["session"]and U(b,32)==len(b)-72
                    and all(U(b,p)==0 for p in(40,48,56,64)),"complete fixture request")
                require(len(r)>=64 and r[:8]==b"HPRDFR01"and U(r,16)==len(r)-64,"complete fixture response")
                parsed[n]=(e,b[72:],r)
            else:
                require(canonical(decode(b))==b and canonical(decode(r))==r,"canonical original exchange")
                parsed[n]=(e,decode(b),decode(r))
        require(not incoming.read(1)and not outgoing.read(1),"unread process stream suffix")
    if native:require(receipt["stdout"]==dict(raw=dict(bytes=total,sha256=digest.hexdigest()),compressed=pin(root/"carrier.stdout.gz")),"native full stdout custody")
    return parsed
def process_view(v,reader,owned_fds,native):
    require(set(v["fd"])==set(map(str,range(6)))|set(map(str,owned_fds)),"actual process leaked/lost a descriptor")
    raw=reader.get(v["maps"])
    entries=[]
    for line in raw.decode().splitlines():
        cols=line.split();lo,hi=(int(x,16)for x in cols[0].split("-"));require(lo<hi,"maps range")
        entries.append((lo,hi,cols[1]," ".join(cols[5:])))
    if native:require(not any(".so"in p or"python"in p.lower()for _,_,_,p in entries),"native mapped a host runtime")
    return entries
def mapping(ctx,entries):
    for at,cap in((64,72),(88,96),(104,112),(120,128)):
        addr,n=U(ctx,at),U(ctx,cap)
        require(addr%4096==n%4096==0 and n>=4096
            and any(lo<=addr and addr+n<=hi and flags[:3]=="rw-"for lo,hi,flags,_ in entries)
            and any(lo<=addr+n and addr+n+4096<=hi and flags[:3]=="---"for lo,hi,flags,_ in entries),"owned arena guard mapping")
    require(all(U(ctx,p)==0 for p in(24,32,136,144)),"parent callable acquired undeclared child images")
def verify_group(source,root,name,queries,native,observer=True):
    summary=load(root,"CAPTURE.json");rows=load(root,"cases.json");tail=load(root,"tail.json");controls=load(root,"controls.json")
    receipt=load(root,"carrier-process.json"if native else"original-process.json")
    require(summary["status"]=="ACTUAL_PARENT_DOMAIN_COMPLETE"and summary["role"]==("native"if native else"original")
        and summary["source"]==source_evidence(source)and summary["process"]==receipt and summary["group"]==name
        and summary["observer_enabled"]==observer and summary["original_result_consulted_by_native"]is False
        and [r["id"]for r in rows]==[c["id"]for c in group(name)]and summary["cases"]==len(rows),"actual complete domain")
    process(root,receipt,native);reader,indexed=buffers(root,summary);parsed=exchange_rows(root,reader,native,receipt)
    expected_controls=(18 if name=="g00"else 6)if native and observer else 0
    require(len(parsed)==summary["exchanges"]and len(controls)==summary["private_controls"]==expected_controls,"complete exchange/control domain")
    hooks,events=hook_rows(root,reader,receipt)
    require(len(events)==summary["total_hooks"]and len(hooks["mutations"])==summary["mutations"],"complete hook inventory")
    used=set();states=[dict(work=None,call=0,fds={}),dict(work=None,call=0,fds={})];generations=[0,0]
    state_at={0:{}};held={};observations={};native_invocations={};hook_at=0
    journal=Journal(root/"carrier.journal.gz")if native and observer else None
    initial_payload={};context_current=[None,None];current_fd=[None,None]
    # Every exchange is admitted in actual order; each context has its own HIA
    # work continuation, descriptor set, generation and pending close sequence.
    for n,(e,b,r)in parsed.items():
        if native:
            s=e["session"];cmd=e["command"];code=U(r,8);used.add(n)
            if cmd in(1,10)and code==64:
                start=b if cmd==1 else b"HPRDQ001"+struct.pack("<11Q",3,U(states[s]["work"],16)if journal else 0,0,0,0,0,0,0,0,0,0)
                if cmd==1:
                    require(U(r,32)==generations[s]+1,"new context generation");generations[s]+=1;initial_payload[s]=b
                else:require(U(r,32)==generations[s],"close changed generation")
                if journal:
                    require(e["journal_begin"]==journal.position,"journal exchange start")
                    state=invocation(journal,start,r[64:],generations[s],states[s],events[hook_at:])
                    hook_at+=state["hooks"];states[s]=state;native_invocations[n]=state
                    require(e["journal_end"]==journal.position,"journal exchange end")
                value=result(r[64:]);phase=4 if U(r[64:],8)==6 else 2
                require(U(r,24)==phase and U(r,40)==int(phase==4),"native terminal context")
                if phase==4:held[s]=value["fd"];current_fd[s]=value["fd"]
                else:held.pop(s,None)
            else:
                if observer:require(e["journal_begin"]==e["journal_end"]==(journal.position if journal else 0),"nonapplication emitted HIA")
                if cmd==2 and code==0:require(U(r,24)==0 and U(r,40)==0,"release state")
                elif cmd in(8,9)and code==0:require(U(r,24)==0 and U(r,32)==0 and U(r,40)==0,"create state")
                elif cmd==3 and code==0:require(all(U(r,p)==0 for p in(16,24,32,40,48,56)),"destroy response")
                elif cmd in(4,5,6,7)and code==0:
                    observations[n]=(cmd,s,r[64:])
                    if cmd==4:context_current[s]=r[64:]
                elif cmd in(11,12):
                    if code==0:require(len(r[64:])==144,"actual fstat extent")
                    else:require(I(code)==-9 and not r[64:],"actual closed descriptor result")
                else:require(code in(0xffffffff,0xfffffffd)and not r[64:],"private refusal code")
        else:
            s=b["session"];cmd=b["command"];used.add(n)
            if cmd=="acquire":
                require(r["binding"]==bindings(source)and r["generation"]==generations[s]+1,"exact original body/generation")
                generations[s]+=1
                if r["result"]["ok"]:held[s]=r["result"]["fd"];current_fd[s]=r["result"]["fd"]
            elif cmd=="close":require(r==dict(ok=True),"actual original close");held.pop(s,None)
            elif cmd=="stat":require(set(r)==({"ok","metadata"}if r["ok"]else{"ok","errno"}),"original fstat observation")
            else:raise ValueError("unread original command")
        require(len(set(held.values()))==len(held),"two contexts alias one owned descriptor")
        state_at[n]=dict(held)
    def obs(saved,phase=None,gen=None):
        values={}
        for label,cmd in(("context",4),("workspace",5),("output",6),("input",7)):
            item=saved[label];require(item["exchange"]in observations,"missing full arena exchange")
            actual_cmd,s,raw=observations[item["exchange"]];require(actual_cmd==cmd and reader.get(item["bytes"])==raw,"complete arena binding")
            values[label]=raw
        ctx=values["context"]
        require(len(ctx)==4096 and ctx[:8]==b"HPDRCI01"and U(ctx,8)==4096,"context header")
        if phase is not None:require(U(ctx,56)==phase and U(ctx,184)==int(phase==4),"context ownership state")
        if gen is not None:require(U(ctx,192)==gen,"context generation")
        if phase in(2,4):
            require(U(ctx,176)==64 and U(ctx,96)==len(values["workspace"])and U(ctx,112)==len(values["output"])
                and U(ctx,72)==len(values["input"]),"full capacity binding")
            ledger=[U(ctx,256+i*8)for i in range(8)];actual={fd for fd in ledger if fd!=(1<<64)-1}
            require(len(actual)==U(ctx,184)and len([fd for fd in ledger if fd!=(1<<64)-1])==len(actual),"complete owned FD ledger")
            if phase==4:require(actual=={U(ctx,344)}and U(ctx,352)==1 and U(ctx,344)==U(values["workspace"],88),"held capability binding")
            else:require(not actual and U(ctx,344)==U(ctx,352)==U(ctx,360)==0,"closed capability retained")
        return values
    results={}
    for row in rows:
        q=queries[row["id"]].get("shared",queries[row["id"]].get("native"if native else"original"));require(q is not None and row["input"]==q,"frozen query")
        snapshots(row["before"],reader);snapshots(row["after"],reader)
        require(row["before"]==q["snapshot"]and 0<=row["elapsed_ns"]<60_000_000_000,"initial actual fixture or deadline")
        n=row["acquire_exchange"];e,b,r=parsed[n]
        if native:
            require(e["command"]==1 and e["session"]==q["session"]and b==wire(q)and U(r,8)==64 and result(r[64:])==row["result"],"actual native acquire")
            vals=obs(row["initial_observation"],4 if row["result"]["ok"]else 2,row["generation"])
            require(vals["input"][:len(b)]==b,"owned full initial input")
            if journal:require(vals["workspace"]==native_invocations[n]["work"]and vals["output"]==native_invocations[n]["output"],"journal/retained complete arenas")
        else:
            require(b==dict(command="acquire",session=q["session"],query=q)and r["result"]==row["result"]
                and r["binding"]==row["binding"]and r["generation"]==row["generation"],"actual original acquire")
        v=row["result"]
        if v["ok"]:
            for key in("before_mutation_stat","held_stat"):
                j=row[key+"_exchange"];ee,bb,rr=parsed[j]
                actual=dict(ok=True,metadata=stat_value(rr[64:]))if native else rr
                require(actual==row[key]and actual["ok"],"actual held directory observation")
            initial=row["before_mutation_stat"]["metadata"];current=row["held_stat"]["metadata"]
            require(initial["dev"]==current["dev"]and initial["inode"]==current["inode"]and initial["mode"]&61440==16384,"held directory identity changed")
            require(any(st["kind"]=="directory"and st["dev"]==initial["dev"]and st["inode"]==initial["inode"]
                for st in list(row["before"].values())+list(row["after"].values())),"granted directory lies outside actual fixture")
            entries=process_view(row["held_process"],reader,state_at[row["held_process"]["at_exchange"]].values(),native)
            require(str(v["fd"])in row["held_process"]["fd"],"granted parent absent from actual process")
            if native:mapping(vals["context"],entries)
            if q["close"]!="eof":
                j=row["close_exchange"];ee,bb,rr=parsed[j]
                require((result(rr[64:])if native else rr)==row["close_result"]==dict(ok=True),"actual close result")
                retired=row["retired"];dd=parsed[retired["stat_exchange"]][2]
                require((I(U(dd,8))==-9 and not dd[64:])if native else dd==dict(ok=False,errno=9),"actual last FD was not retired")
                if native:
                    done=obs(row["close_observation"],2,row["generation"])
                    if journal:require(done["workspace"]==native_invocations[j]["work"]and done["output"]==native_invocations[j]["output"],"close journal arenas")
                    rel=parsed[retired["release_exchange"]];require(rel[0]["command"]==2 and U(rel[2],8)==0,"result release")
                process_view(row["after_close_process"],reader,state_at[row["after_close_process"]["at_exchange"]].values(),native)
        else:
            require(set(v)=={"ok","error"},"exception object")
            if native:
                rel=parsed[row["error_release_exchange"]];require(rel[0]["command"]==2 and U(rel[2],8)==0,"error result release")
        process_view(row["after_process"],reader,state_at[row["after_process"]["at_exchange"]].values(),native)
        if native and "other_before"in row:
            require(set(row["other_before"])==set(row["other_after"]),"cross-context domain")
            for sid in row["other_before"]:
                before=obs(row["other_before"][sid],4);after=obs(row["other_after"][sid],4)
                require(before==after,"acquiring another context mutated a live parent")
        mutations=[m for m in hooks["mutations"]if m["id"]==q["id"]]
        require(len(mutations)==int(q["mutation"]is not None),"actual mutation set")
        if mutations:
            m=mutations[0];require(m["name"]==q["mutation"]and m["before"]==row["before"]and m["after"]==row["after"],"complete actual mutation projection")
            if q["mutation"].startswith("held_"):
                require(m["phase"]=="held"and m["operation"]is None and m["occurrence"]is None,"held mutation barrier")
            else:
                require(m["phase"]=="walk"and m["operation"]==2 and m["occurrence"]==len(PurePosixPath(q["request"]["path"]).parts[1:-1]),"actual openat mutation barrier")
        else:require(row["before"]==row["after"],"parent operation changed filesystem")
        limit=row["descriptor_limit"]
        if q["free_fds"]is not None:
            require(limit["free"]==q["free_fds"]and limit["during"][0]==6+q["free_fds"]and limit["after"]==limit["before"]
                and set(limit["fds"])==set(map(str,range(6))),"real descriptor bound differs")
        else:require(limit is None,"unexpected descriptor restriction")
        results[q["id"]]=dict(row=row,projection=projection(row["after"],reader))
    for c in controls:
        require(native,"original has native controls")
        before=obs(c["before"]);after=obs(c["after"]);require(before==after,"refusal changed full owned arenas")
        e,b,r=parsed[c["exchange"]]
        require(e["command"]==c["command"]and e["session"]==c["session"]and U(r,8)==c["code"],"actual refusal exchange")
    eof=summary["eof_case_ids"]
    require(eof==[r["id"]for r in rows if r["input"]["close"]=="eof"],"EOF domain")
    if journal:
        require(hook_at==summary["eof_hook_begin"],"pre-EOF complete effect set")
        for s in sorted(held):
            prior=states[s];start=b"HPRDQ001"+struct.pack("<11Q",3,U(prior["work"],16),0,0,0,0,0,0,0,0,0)
            state=invocation(journal,start,None,generations[s],prior,events[hook_at:]);hook_at+=state["hooks"]
            require(result(state["terminal"])==dict(ok=True)and not state["fds"],"EOF did not close actual parent")
        require(hook_at==len(events),"unread actual native hooks")
        journal_result=journal.finish(receipt["journal"])
    elif native:
        require(not events and receipt["journal"]["raw"]["bytes"]==0,"disabled observer ran")
        with gzip.open(root/"carrier.journal.gz","rb")as stream:require(not stream.read(1),"observer-off journal data")
        require(pin(root/"carrier.journal.gz")==receipt["journal"]["compressed"],"observer-off archive")
        journal_result=dict(events=0,body_calls=0,raw_os_effects=0,full_buffer_bytes=0)
    else:
        if eof:
            last=events[summary["eof_hook_begin"]:]
            require(len(last)==len(eof)and all(e["operation"]==5 and e["id"]is None for e in last),"actual original EOF closes")
        journal_result=None
    require(used==set(parsed),"unread exchanges")
    reader.finish()
    return results,dict(cases=len(rows),exchanges=len(parsed),private_controls=len(controls),buffers=indexed,
        journal=journal_result,actual_mutations=len(hooks["mutations"]),eof_parents=len(eof))
def setup_inputs(source,root):
    source,root=Path(source),Path(root);setup=load(root,"SETUP.json")
    require(setup["status"]=="FROZEN_PARENT_INPUTS_CREATED"and setup["source"]==source_evidence(source),"setup source")
    sr,sc=buffers(root,dict(buffer_images=setup["images"],logical_buffer_bytes=setup["logical_bytes"]))
    input_rows=load(root,"inputs.json");require([r["id"]for r in input_rows]==list(range(1,49)),"complete setup IDs")
    queries={r["id"]:r["roles"]for r in input_rows}
    for c in domain()["cases"]:
        roles=queries[c["id"]];require(set(roles)==({"original","native"}if c["mutation"]else{"shared"}),"independent mutable fixture roles")
        for q in roles.values():
            snapshots(q["snapshot"],sr)
            require(q["id"]==c["id"]and q["session"]==c["session"]and q["mutation"]==c["mutation"]
                and q["free_fds"]==c["free_fds"]and q["close"]==c["close"]
                and q["request"]=={k:c[k].replace("{F}",q["fixture"])for k in("root","path")},"frozen concrete fixture input")
    sr.finish();return queries,sc

def verify(source,capture):
    import read_prior
    source,capture=Path(source),Path(capture);base,oldsource,old=read_prior.paths(capture)
    oldqueries,oldsc=setup_inputs(oldsource,old/"setup");queries,sc=setup_inputs(source,capture/"setup")
    original={};reports=[]
    for index,g in enumerate(domain()["groups"]):
        name=g["name"]
        selected_source,selected_capture,selected_queries=(oldsource,old,oldqueries)if index<6 else(source,capture,queries)
        ov,oc=verify_group(selected_source,selected_capture/"original"/name,name,selected_queries,False)
        nv,nc=verify_group(selected_source,selected_capture/"native"/name,name,selected_queries,True)
        require(set(ov)==set(nv),"original/native case set")
        for cid in ov:
            o,n=ov[cid]["row"],nv[cid]["row"];oq,nq=o["input"],n["input"]
            require(normalized(o["result"],oq)==normalized(n["result"],nq),"actual parent result differs: "+str(cid))
            require(ov[cid]["projection"]==nv[cid]["projection"],"actual filesystem projection differs: "+str(cid))
            if o["result"]["ok"]:
                for key in("before_mutation_stat","held_stat"):
                    a,b=o[key]["metadata"],n[key]["metadata"]
                    require(all(a[k]==b[k]for k in(("mode","uid","gid","links")if oq["mutation"]else a.keys())),"actual held FD identity/metadata differs: "+str(cid))
            original[cid]=ov[cid]
        reports.append(dict(group=name,original=oc,native=nc))
    off,offstats=verify_group(source,capture/"native/unobserved","unobserved",queries,True,False)
    for cid,v in off.items():
        o,n=original[cid]["row"],v["row"]
        require(normalized(o["result"],o["input"])==normalized(n["result"],n["input"])and original[cid]["projection"]==v["projection"],"observer-off actual result differs")
    return dict(status="COMPLETE_PARENT_COMPARISON_PASS",source=source_evidence(source),original_cases=48,native_cases=48,
        observer_off_cases=10,groups=reports,unobserved=offstats,setup_buffers=dict(previous=oldsc,current=sc),scope=SCOPE,
        retained_completed_pairs=42,new_original_pairs=6,new_native_observed_pairs=6,semantic_replay=False)
