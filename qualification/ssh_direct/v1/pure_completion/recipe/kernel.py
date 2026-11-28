# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read actual strace bytes and bind HIA effects to original OS objects."""
import errno,re,signal,struct
from pathlib import Path
from capture_util import need,pin,decode
from model import q,word,MASK,command,M
ERRNO={v:k for k,v in errno.errorcode.items()}
def split_args(text):
    out=[];start=0;quote=False;escape=False;stack=[]
    for i,ch in enumerate(text):
        if quote:
            if escape:escape=False
            elif ch=="\\":escape=True
            elif ch=='"':quote=False
        elif ch=='"':quote=True
        elif ch in "([{<":stack.append(ch)
        elif ch in ")]}":
            need(stack and stack[-1]=={")":"(","]":"[","}":"{"}[ch],"kernel argument brackets "+text);stack.pop()
        elif ch==">"and stack and stack[-1]=="<":stack.pop()
        elif ch==","and not stack:out.append(text[start:i].strip());start=i+1
    need(not quote and not stack,"complete kernel argument bytes");out.append(text[start:].strip())
    return out
def unquote(text):
    need(re.fullmatch(r'"(?:\\x[0-9a-fA-F]{2})*"',text)is not None,"full non-abbreviated kernel string")
    return bytes.fromhex(text[1:-1].replace("\\x",""))
def visible(text):
    return re.sub(r"\\x([0-9a-fA-F]{2})",lambda m:chr(int(m[1],16)),text)
def pipe_id(text):
    m=re.search(r"<pipe:\[(\d+)\]>",visible(text));need(m is not None,"actual pipe object identity");return int(m[1])
def number(text):
    m=re.match(r"(-?[0-9]+)",text);need(m is not None,"actual integer syscall argument");return int(m[1])
def returned(text):
    if text.startswith("-1 "):
        name=text.split()[1];need(name in ERRNO,"known actual errno "+name);return -ERRNO[name]
    m=re.match(r"-?[0-9]+",text)
    return int(m[0])if m else None
def timestamp(raw):
    a,b=raw.split(".");return int(a)*1000000000+int((b+"000000000")[:9])
def traces(root):
    all_events=[];by_tid={};rows=[]
    for path in sorted(Path(root).glob("kernel.*")):
        tid=int(path.name.split(".")[-1]);need(tid not in by_tid,"unique kernel original TID file");events=[];pending=None
        raw=path.read_bytes();need(raw.endswith(b"\n"),"complete kernel trace line");rows.append(dict(file=path.name,**pin(path)))
        for index,line in enumerate(raw.decode("ascii").splitlines()):
            m=re.match(r"([0-9]+\.[0-9]+)\s+(.*)",line);need(m is not None,"kernel timestamped complete line")
            at=timestamp(m[1]);body=m[2];end=at
            if body.endswith("<unfinished ...>"):
                need(pending is None,"one outstanding actual syscall per thread");pending=(at,body[:-len("<unfinished ...>")],index);continue
            resumed=re.match(r"<\.\.\. ([a-zA-Z0-9_]+) resumed>(.*)",body)
            if resumed:
                need(pending is not None and pending[1].startswith(resumed[1]+"("),"matching original resumed syscall")
                at,prefix,first=pending;pending=None;body=prefix+resumed[2];index=first
            event=dict(tid=tid,at=at,end=end,line=index,body=body,index=len(events))
            syscall=re.match(r"([a-zA-Z0-9_]+)\((.*)\)\s+=\s+(.*?)(?:\s+<[0-9.]+>)?$",body)
            if syscall:
                event.update(name=syscall[1],args=split_args(syscall[2]),result=syscall[3],ret=returned(syscall[3]))
            elif body.startswith("+++"):event.update(name="process_end",args=[],result=body,ret=None)
            elif body.startswith("---"):event.update(name="signal",args=[],result=body,ret=None)
            else:need(False,"unparsed actual kernel trace "+body[:160])
            events.append(event);all_events.append(event)
        need(pending is None,"unfinished original syscall without final status")
        by_tid[tid]=events
    need(rows,"actual kernel trace files missing")
    all_events.sort(key=lambda e:(e["at"],e["tid"],e["index"]))
    return all_events,by_tid,rows
def between(by_tid,left,right,names):
    need(left["tid"]==right["tid"]and left["index"]<right["index"],"one original thread effect order")
    return [e for e in by_tid[left["tid"]][left["index"]+1:right["index"]]if e["name"]in names]
def raw_status(event):
    text=event["args"][1]
    m=re.search(r"WEXITSTATUS\(s\)\s*==\s*([0-9]+)",text)
    if m:return int(m[1])<<8
    m=re.search(r"WTERMSIG\(s\)\s*==\s*(SIG[A-Z0-9]+)",text)
    if m:return int(getattr(signal,m[1]))|(128 if "WCOREDUMP" in text else 0)
    need(False,"complete original wait status "+text)
def pointer(text,key):
    m=re.search(r"(?:^|,\s*|\{)"+re.escape(key)+r"=(0x[0-9a-f]+)",text)
    if m is None and key=="child_tidptr":m=re.search(r"(?:^|,\s*|\{)child_tid=(0x[0-9a-f]+)",text)
    return int(m[1],16)if m else None
def executed_children(events,binary):
    wanted=str(binary).encode();found={}
    for e in events:
        if e["name"]=="execve"and e["ret"]==0 and unquote(e["args"][0])==wanted:
            need(e["tid"]not in found,"child exec retried");found[e["tid"]]=e
    return found
def verify_native(root,records,c,report,binaries):
    events,tids,rows=traces(root);ctxs={r["header"][2]for r in records};pids={r["header"][3]for r in records}
    need(len(ctxs)==len(pids)==1,"single immutable actor context/controller process");ctx=next(iter(ctxs));pid=next(iter(pids))
    original_cwd=decode((root/"PROCESS.json").read_bytes())["cwd"]
    journal=(root/"actual/HIA-JOURNAL.bin").read_bytes();writes=[]
    for e in events:
        if e["name"]=="write"and "HIA-JOURNAL.bin"in visible(e["args"][0])and e["ret"]is not None and e["ret"]>0:
            b=unquote(e["args"][1]);need(e["ret"]==len(b)==number(e["args"][2]),"complete immutable journal write");writes.append((e,b))
    need(b"".join(b for e,b in writes)==journal,"every actual journal file byte bound to kernel writes")
    need(len(writes)==len(records),"one frozen observer full-frame write per HIA call")
    byseq={r["header"][5]:r for r in records}
    for e,b in writes:
        need(b[:8]==b"HSSJRN01","actual kernel journal magic");r=byseq[q(b,40)]
        need(b==r["raw"]and e["tid"]==r["header"][4],"exact original TID journal write");r["event"]=e
    owner=report[12];need(owner in tids and owner!=report[13],"independent entry/owner original thread")
    spawned_threads=[e for e in events if e["name"]in("clone","clone3")and e["ret"]and e["ret"]>0 and "CLONE_THREAD"in e["body"]]
    owner_spawn=[e for e in spawned_threads if e["ret"]==owner and pointer(e["body"],"child_tidptr")==ctx+48]
    join_spawn=[e for e in spawned_threads if pointer(e["body"],"child_tidptr")==ctx+120]
    need(len(owner_spawn)==len(join_spawn)==1,"one original clear-tid owner and one persistent join worker")
    join_tid=join_spawn[0]["ret"];need(join_tid!=owner,"independent unique join worker")
    need(all("CLONE_SETTLS"not in e["body"] for e in owner_spawn+join_spawn),"production threads do not borrow libc TLS")
    core=[r for r in records if r["module"]==3]
    join_ack=[r for r in core if r["op"]==12];need(len(join_ack)==1 and join_ack[0]["event"]["tid"]==join_tid,"one actual persistent join completion")
    owner_exit=[e for e in tids[owner]if e["name"]=="exit"and number(e["args"][0])==0]
    need(len(owner_exit)==1 and owner_exit[0]["at"]<=join_ack[0]["event"]["at"],"join acknowledges after original owner kernel exit")
    init=[r for r in core if r["op"]==2];need(len(init)==1 and q(init[0]["input"],64)==ctx+48,"HIA original thread capability is actual clear-tid slot")
    expected_child_count=c["count"]if c["mode"]not in(4,5)else 0
    actual_children=executed_children(events,binaries["child"])
    need(len(actual_children)==expected_child_count,"actual fixed child executions")
    requests={};effects=[];clocks=0
    for r in sorted(records,key=lambda x:x["header"][5]):
        mod,op=r["module"],r["op"];inp=r["input"];ev=r["event"]
        if mod==5 and op==0:requests.setdefault(r["request"],dict(calls=[],commands=[]))
        if r.get("request")is not None:requests.setdefault(r["request"],dict(calls=[],commands=[]))["calls"].append(r)
        if mod==4 and inp[:8]==b"HSDCMD01":
            raw,args=command(inp,M(r["before_work"]));need(args[0]==str(binaries["child"]).encode()and len(args)==10,"frozen exact executable and arguments")
            need(args[1]==(original_cwd+"/actual").encode(),"owned original output root")
            slot=int(args[2]);expected=[slot,c["behavior"],c["stdout_bytes"],c["stderr_bytes"],c["exit"],c["delay_us"],int(c["mode"]==1),c["close_input"]]
            need(args[2:]==[str(v).encode()for v in expected],"all frozen child arguments")
            requests[r["request"]]["slot"]=slot;requests[r["request"]]["commands"].append(r)
        if(mod==1 and op in(1,4))or(mod in(4,5)and inp[:8]in(b"HSDIOQ01",b"HSSFQ001")and op==1)or(mod==2 and op in(6,8)and(q(inp,64)or q(inp,72))):
            offset=64 if mod==2 else 56;clock=[e for e in tids[ev["tid"]][:ev["index"]]if e["name"]=="clock_gettime"and e["args"][0]=="CLOCK_MONOTONIC"and e["ret"]==0]
            need(clock,"actual kernel monotonic clock");m=re.search(r"tv_sec=([0-9]+),\s*tv_nsec=([0-9]+)",clock[-1]["args"][1]);need(m is not None,"complete actual timespec")
            n=int(m[1])*1000000000+int(m[2]);need(q(inp,offset)==n&MASK and q(inp,offset+8)==n>>64,"actual kernel clock supplied to HIA");clocks+=1
    need(len(requests)==c["count"],"one owned request per frozen input")
    for key,req in requests.items():
        calls=sorted(req["calls"],key=lambda r:r["header"][5]);need(len(req["commands"])==1,"one immutable command per request")
        admission=[r for r in calls if r["module"]==1]
        spawnack=[r for r in admission if r["op"]==7 and q(r["input"],32)==0]
        if not spawnack:continue
        need(len(spawnack)==1,"one original spawn acknowledgement");ack=spawnack[0]
        starts=[r for r in admission if r["header"][5]<ack["header"][5]and q(r["after_work"],112)==2]
        start=starts[-1];physical=between(tids,start["event"],ack["event"],{"fork","clone","clone3","vfork"})
        physical=[e for e in physical if e["ret"]and e["ret"]>0 and"CLONE_THREAD"not in e["body"]]
        need(len(physical)==1,"one physical original child spawn");childpid=physical[0]["ret"];req["pid"]=childpid
        need(childpid in actual_children,"original spawn identity reached trusted exec")
        child_events=tids[childpid];exec_event=actual_children[childpid]
        prior=child_events[:exec_event["index"]]
        pipe_objects={number(e["args"][1]):pipe_id(e["args"][0])for e in prior if e["name"]in("dup2","dup3")and e["ret"]is not None and e["ret"]>=0 and number(e["args"][1])in(0,1,2)}
        need(set(pipe_objects)=={0,1,2},"each actual original child pipe endpoint")
        actual_argv=[unquote(x)for x in split_args(exec_event["args"][1][1:-1])]
        _,offered_argv=command(req["commands"][0]["input"],M(req["commands"][0]["before_work"]))
        need(actual_argv==offered_argv and exec_event["args"][2]=="[]","every actual exec argument and empty environment matches HIA-owned bytes")
        need(any(e["name"]=="prctl"and e["args"][:2]==["PR_SET_PDEATHSIG","SIGKILL"]and e["ret"]==0 for e in prior),"actual child death custody before exec")
        need(any(e["name"]=="getppid"and e["ret"]==pid for e in prior),"actual original controller parent before exec")
        need(q(ack["input"],40)==key[0]+4352,"HIA spawned child capability remains original workspace")
        child_calls=[r for r in calls if r["module"]==2]
        need(all(r["event"]["tid"]==owner for r in child_calls),"all original child custody on independent owner")
        io_issues={q(r["after_work"],176):r for r in calls if r["module"]==4 and r["input"][:8]==b"HSDIOQ01"and q(r["output"],24)==1}
        output=[bytearray(),bytearray()]
        for r in calls:
            if r["module"]!=4 or r["input"][:8]!=b"HSDIOQ01"or r["op"]!=2:continue
            seq=q(r["input"],72);issue=io_issues[seq];action=q(issue["after_work"],168)
            names={1:{"write"},2:{"read"},3:{"read"},4:{"wait4"},5:{"close"},6:{"close"},7:{"close"}}[action]
            physical=between(tids,issue["event"],r["event"],names)
            if action in(1,2,3,5,6,7):physical=[e for e in physical if "<pipe:["in visible(e["args"][0])]
            else:physical=[e for e in physical if number(e["args"][0])==childpid]
            need(len(physical)==1,"one actual OS effect per IO offer");e=physical[0]
            if action!=4:need(pipe_id(e["args"][0])==pipe_objects[{1:0,2:1,3:2,5:0,6:1,7:2}[action]],"actual offered pipe belongs to the same original child")
            need(e["ret"]is not None and(q(r["input"],32)==e["ret"]&MASK),"actual syscall return supplied to IO policy")
            if action in(1,2,3):
                need(number(e["args"][2])==q(issue["after_work"],184),"actual bounded kernel buffer count")
                if action==1:
                    data=unquote(e["args"][1]);offset=q(issue["after_work"],192);count=q(issue["after_work"],184)
                    expected=bytes(((i*73)^(c["id"]*19)^(i>>3))&255 for i in range(c["input_bytes"]))
                    need(data==expected[offset:offset+count],"whole actual stdin write buffer")
                elif e["ret"]>0:
                    data=unquote(e["args"][1]);need(len(data)==e["ret"],"whole actual output read bytes")
                    if q(r["after_work"],200):
                        stream=action-2;need(q(r["after_work"],208)==len(output[stream]),"actual output append offset");output[stream].extend(data)
            elif action==4:
                need(q(r["input"],48)==childpid,"IO wait actual same original PID")
                if e["ret"]>0:need(q(r["input"],40)==raw_status(e),"actual original wait status supplied to HIA")
            effects.append(dict(request=key,kind="io",sequence=seq,action=action,tid=e["tid"],line=e["line"],return_value=e["ret"]))
        for r in child_calls:
            op=r["op"]
            if op not in(6,7,8,9):continue
            prior_calls=[x for x in child_calls if x["header"][5]<r["header"][5]]
            if op==9:
                matches=[x for x in calls if x["module"]==4 and x["header"][5]<r["header"][5]and x["input"][:8]==b"HSDIOQ01"and q(x["after_work"],168)==4]
                left=matches[-1]
            else:left=prior_calls[-1]
            names={"kill"}if op==7 else{"wait4"}
            physical=between(tids,left["event"],r["event"],names)
            physical=[e for e in physical if number(e["args"][0])==childpid]
            need(physical,"actual original child custody effect");e=physical[-1]
            a,b=q(r["input"],48),q(r["input"],56)
            if op==7:
                need(len(physical)==1 and e["args"][1]=="SIGKILL"and a==max(0,-e["ret"])and b==0,"single actual original-PID signal")
            elif(op==6 and a==0)or(op==8 and a==2):need(e["ret"]==0 and b==0,"actual child remains alive before clock decision")
            elif(op==6 and a==1)or(op in(8,9)and a==0):need(e["ret"]==childpid and b==raw_status(e),"same original child actually reaped")
            else:need(e["ret"]<0 and b==-e["ret"],"actual failed original wait errno")
            effects.append(dict(request=key,kind="custody",operation=op,tid=e["tid"],line=e["line"],return_value=e["ret"]))
        reap=[e for e in tids[owner]if e["name"]=="wait4"and e["ret"]==childpid]
        need(len(reap)==1,"exactly one kernel reap of original child")
        dropped=[r for r in child_calls if r["op"]==13];need(len(dropped)==1 and reap[0]["end"]<=dropped[0]["event"]["at"],"original guard released after actual reap")
        ended=[r for r in child_calls if r["op"]==2];need(len(ended)==1,"original pipes borrow ended exactly once")
        io_before=[r for r in calls if r["module"]==4 and r["header"][5]<ended[0]["header"][5]and r["input"][:8]==b"HSDIOQ01"]
        need(io_before and all(q(io_before[-1]["after_work"],at)==0 for at in(48,56,64)),"all actual pipes closed before ending original borrow")
        if c["mode"]not in(2,3,4,5,6,7,8):
            slot=req["slot"];need(bytes(output[0])==(root/f"actual/stdout-{slot}").read_bytes()and bytes(output[1])==(root/f"actual/stderr-{slot}").read_bytes(),"all actual accepted pipe bytes are returned")
        for marker in("ready","ended"):
            f=root/f"actual/{marker}-{req['slot']}"
            if f.exists():need(f.read_bytes()==struct.pack("<Q",childpid),"actual fixture original PID marker")
    if c["mode"]==3:
        caller=report[13];exits=[e for e in tids[caller]if e["name"]in("exit","exit_group")]
        reap=[e for e in tids[owner]if e["name"]=="wait4"and e["ret"]in actual_children]
        need(exits and reap and exits[-1]["at"]<reap[-1]["at"],"caller OS thread gone before independent owner finishes reap")
        waits=[e for e in tids[join_tid]if e["name"]=="futex"and e["args"][0]==hex(ctx+48)]
        need(waits and any("FUTEX_WAIT"in e["args"][1]for e in waits),"persistent join actually waits original owner clear-tid")
    return dict(status="ACTUAL_NATIVE_KERNEL_EFFECTS_PASS",controller=pid,owner_tid=owner,join_tid=join_tid,
        original_children=sorted(actual_children),hia_kernel_writes=len(writes),actual_clock_bindings=clocks,effects=effects,kernel_files=rows)
def verify_original(root,c,run,binaries):
    events,tids,rows=traces(root);children=executed_children(events,binaries["child"])
    original_cwd=decode((root/"PROCESS.json").read_bytes())["cwd"]
    expected=c["count"]if c["mode"]not in(4,5)else 0;need(len(children)==expected,"original trusted child execution count")
    owner=run["entry_tid"];need(owner in tids and owner!=run["caller_tid"],"original Entry independent owner thread")
    reaps=[]
    for pid,execution in children.items():
        waits=[e for e in events if e["name"]=="wait4"and e["ret"]==pid]
        need(len(waits)==1,"original exactly one successful kernel reap per child");reaps.extend(waits)
        need(waits[0]["tid"]==owner,"unchanged original independent owner reaps original process")
        args=split_args(execution["args"][1][1:-1]);decoded=[unquote(x)for x in args]
        need(len(decoded)==10 and decoded[0]==str(binaries["child"]).encode()and decoded[1]==(original_cwd+"/actual").encode(),"unchanged original fixed command")
        slot=int(decoded[2]);expected_args=[slot,c["behavior"],c["stdout_bytes"],c["stderr_bytes"],c["exit"],c["delay_us"],int(c["mode"]==1),c["close_input"]]
        need(decoded[2:]==[str(v).encode()for v in expected_args],"original full command argument bytes")
        for marker in("ready","ended"):
            f=root/f"actual/{marker}-{slot}"
            if f.exists():need(f.read_bytes()==struct.pack("<Q",pid),"original child marker exact process")
    if c["mode"]==3:
        caller=run["caller_tid"];ends=[e for e in tids[caller]if e["name"]in("exit","exit_group")]
        need(ends and reaps and ends[-1]["at"]<reaps[-1]["at"],"original caller runtime thread gone while cleanup retained")
        owner_clones=[e for e in events if e["name"]in("clone","clone3")and e["ret"]==owner]
        need(owner_clones,"original owner kernel thread");slot=pointer(owner_clones[-1]["body"],"child_tidptr")
        need(slot is not None,"original clear-tid pointer observed")
        waits=[e for e in events if e["name"]=="futex"and e["args"][0]==hex(slot)and"FUTEX_WAIT"in e["args"][1]]
        need(waits and any(e["tid"]not in(owner,caller)for e in waits),"cancelled waiter leaves independent original join worker")
    return dict(status="ACTUAL_ORIGINAL_KERNEL_LIFECYCLE_PASS",owner_tid=owner,original_children=sorted(children),
        actual_reaps=len(reaps),kernel_files=rows)
