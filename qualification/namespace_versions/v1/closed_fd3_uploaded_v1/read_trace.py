"""Read the complete actual syscall transcript, stderr markers, kernel read bytes and thread custody."""
import errno,re,struct
from common import read,pin,require
PREFIX=re.compile(r"^(?:\[pid\s+(\d+)\]|(\d+))\s+(.*)$")
CALL=re.compile(r"^([a-zA-Z0-9_]+)\((.*)\)\s+=\s+(.+)$")
def number(v):
    require(re.fullmatch(r"-?(?:0x[0-9a-f]+|[0-9]+)",v)is not None,"actual numeric syscall scalar")
    return int(v,0)if v.startswith(("0x","-0x"))else int(v)
def arguments(value):
    result=[];start=0;depth=0;quoted=False;escape=False
    for i,ch in enumerate(value):
        if quoted:
            if escape:escape=False
            elif ch=="\\":escape=True
            elif ch=='"':quoted=False
        elif ch=='"':quoted=True
        elif ch in"([{":depth+=1
        elif ch in")]}":depth-=1
        elif ch==","and depth==0:result.append(value[start:i].strip());start=i+1
    require(not quoted and depth==0,"whole actual syscall argument framing")
    result.append(value[start:].strip());return result
def parse(raw):
    pending={};rows=[];last=None;signals=[];physical=raw.decode().splitlines()
    for index,line in enumerate(physical):
        match=PREFIX.match(line);tid=int(match.group(1)or match.group(2))if match else None;body=match.group(3)if match else line.lstrip()
        if body.startswith("|"):
            require(last is not None and last["name"]=="read","all kernel byte dumps belong to actual reads")
            # strace prints a padded hex column, followed by its complete printable ASCII column.
            dump=re.fullmatch(r"\|\s+([0-9a-f]+)  ((?:[0-9a-f ]+))  (.{1,16}) \|",body)
            require(dump is not None,"whole actual read hexdump including ASCII: "+repr(body))
            offset=int(dump.group(1),16);octets=dump.group(2).split()
            require(0<len(octets)<=16 and all(re.fullmatch("[0-9a-f]{2}",x)for x in octets),"every actual kernel read byte retained")
            payload=bytes.fromhex("".join(octets));ascii_bytes="".join(chr(x)if 32<=x<127 else "."for x in payload)
            require(dump.group(3).rstrip()==ascii_bytes.rstrip(),"complete actual hexdump ASCII agrees with all raw bytes")
            require(offset==len(last["payload"]),"no gap or repeated actual kernel read bytes")
            last["payload"]+=payload;continue
        if not body:continue
        require(tid is not None,"all actual syscall lines carry traced thread identity")
        if body.startswith(("--- ","+++ ")):signals.append(dict(tid=tid,line=body,index=index));continue
        if body.endswith(" <unfinished ...>"):
            require(tid not in pending,"one unfinished actual syscall per thread")
            pending[tid]=(body[:-len(" <unfinished ...>")],index);continue
        if body.startswith("<... "):
            m=re.match(r"^<\.\.\. ([a-zA-Z0-9_]+) resumed>(.*)$",body)
            require(m is not None and tid in pending,"resumed actual owned syscall")
            prefix,first=pending.pop(tid);require(prefix.startswith(m.group(1)+"("),"same syscall resumes")
            body=prefix+m.group(2);begin=first
        else:begin=index
        m=CALL.match(body);require(m is not None,"complete actual syscall line")
        name,argtext,result=m.groups();args=arguments(argtext);head=result.split()[0]
        if head=="?":returned=None;error=None
        else:
            returned=number(head);error=None
            if returned<0:
                pieces=result.split();require(len(pieces)>=2 and pieces[1]in errno.errorcode.values(),"actual named kernel errno")
                error=getattr(errno,pieces[1]);require(returned==-1,"actual kernel failure return")
        row=dict(index=len(rows),first_line=begin,last_line=index,tid=tid,name=name,args=args,returned=returned,
            errno=error,raw=body,payload=b"")
        rows.append(row);last=row
    require(not pending,"every retained syscall finished before exact process exit")
    for row in rows:
        if row["name"]=="read":
            fd=number(row["args"][0])
            if (fd in(0,1,2)or 32<=fd<320)and row["returned"]is not None and row["returned"]>0:
                require(len(row["payload"])==row["returned"],"whole actual pooled read payload")
            else:require(not row["payload"],"no fabricated kernel payload on failed or unselected descriptor")
        else:require(not row["payload"],"only actual reads have captured kernel bytes")
    return rows,signals,len(physical)
def closed_standard(operation,rows,answer):
    mask=operation["mask"];control=answer["control"]
    require(control["mask"]==mask and control["content"]==operation["content"]and control["restored"]is True,
        "actual closed-descriptor operation and complete reported restoration")
    duplicates=[r for r in rows if r["name"]=="fcntl"and len(r["args"])==3 and r["args"][1]=="F_DUPFD_CLOEXEC"]
    require(len(duplicates)==5,"all three saved standards and two actual File duplicates")
    require([[number(r["args"][0]),number(r["args"][2]),r["returned"],r["errno"]]for r in duplicates]==
        [[0,900,900,None],[1,901,901,None],[2,902,902,None],[512,3,32,None],[513,3,33,None]],
        "every exact actual fcntl descriptor, lower bound, result and errno")
    created=[r for r in rows if r["name"]=="inotify_init1"];event=min(fd for fd in range(3)if mask&(1<<fd))
    require(len(created)==1 and created[0]["args"]==["IN_NONBLOCK|IN_CLOEXEC"]and created[0]["returned"]==event
        and created[0]["errno"]is None and control["event_fd"]==event and control["duplicate_fds"]==[32,33]
        and control["closed_owned_fds"]==[event,32,33]and control["all_duplicates_at_least_three"]is True,
        "actual watcher allocated the lowest closed standard descriptor and both File copies start at three")
    restores=[r for r in rows if r["name"]=="dup2"]
    require(len(restores)==3 and [[number(r["args"][0]),number(r["args"][1]),r["returned"],r["errno"]]for r in restores]==
        [[900,0,0,None],[901,1,1,None],[902,2,2,None]],"all three actual original standard descriptor restorations")
    flags=[]
    for fd in range(3):
        queries=[r for r in rows if r["name"]=="fcntl"and len(r["args"])>=2 and number(r["args"][0])==fd and r["args"][1]=="F_GETFD"]
        require(len(queries)>=2 and queries[0]["returned"]in(0,1)and queries[-1]["returned"]==queries[0]["returned"]
            and queries[0]["index"]<duplicates[fd]["index"]and queries[-1]["index"]>restores[fd]["index"],
            "whole actual initial and restored standard descriptor flags")
        value=queries[0]["returned"];flags.append(value)
        setters=[r for r in rows if r["name"]=="fcntl"and len(r["args"])==3 and number(r["args"][0])==fd and r["args"][1]=="F_SETFD"]
        require(len(setters)==1 and setters[0]["args"][2]==("FD_CLOEXEC"if value else"0")and setters[0]["returned"]==0
            and setters[0]["errno"]is None and setters[0]["index"]>restores[fd]["index"],"real exact F_SETFD restoration")
        early_closes=[r for r in rows if r["name"]=="close"and number(r["args"][0])==fd and r["index"]<created[0]["index"]]
        require(len(early_closes)==int(bool(mask&(1<<fd)))and all(r["returned"]==0 and r["errno"]is None for r in early_closes),
            "only selected standard descriptors close before original Watcher allocation")
        if mask&(1<<fd):
            require(any(r["returned"]==-1 and r["errno"]==9 and early_closes[0]["index"]<r["index"]<created[0]["index"]for r in queries),
                "closed standard descriptor absence is witnessed before actual Watcher allocation")
        copies=[r for r in rows if r["name"]=="close"and number(r["args"][0])==900+fd]
        require(len(copies)==1 and copies[0]["returned"]==0 and copies[0]["errno"]is None
            and copies[0]["index"]>setters[0]["index"],"every actual saved standard copy is released")
    owned_closes=[r for r in rows if r["name"]=="close"and number(r["args"][0])in(event,32,33)
        and created[0]["index"]<r["index"]<restores[0]["index"]]
    require([number(r["args"][0])for r in owned_closes]==[event,32,33]and all(r["returned"]==0 and r["errno"]is None for r in owned_closes),
        "original and native Watcher release actual event then both File descriptors in exact order")
    for fd in(event,32,33):
        require(any(r["name"]=="fcntl"and number(r["args"][0])==fd and r["args"][1]=="F_GETFD"
            and r["returned"]==-1 and r["errno"]==9 and owned_closes[-1]["index"]<r["index"]<restores[0]["index"]for r in rows),
            "every actual Watcher-owned descriptor is proven absent after complete drop")
    require(control["restored_flags"]==flags,"all reported restored flags equal actual kernel results")
    return dict(mask=mask,content=operation["content"],event_fd=event,duplicate_fds=[32,33],saved_fds=[900,901,902],
        restored_flags=flags,fcntl_clone_lower_bound=3,all_actual_arguments_results_errors_and_close_order_read=True)

def verify(folder,case,process,answers,native=None):
    raw=read(folder/"syscalls.strace");rows,signals,line_count=parse(raw);stderr=read(folder/"stderr");stdout=read(folder/"stdout")
    errpos=outpos=0;active=None;steps={i:[]for i in range(len(case["steps"]))};markers=[]
    begin_tag=b"HNVORGB1"if process["role"]=="original"else b"HNVNATB1"
    end_tag=b"HNVORGE1"if process["role"]=="original"else b"HNVNATE1"
    for r in rows:
        write=r["name"]in("write","writev")and r["returned"]is not None and r["returned"]>=0
        if write and number(r["args"][0])in(1,2):
            n=r["returned"];fd=number(r["args"][0])
            if fd==1:body=stdout[outpos:outpos+n];outpos+=n
            else:body=stderr[errpos:errpos+n];errpos+=n
            require(len(body)==n,"all actual stdio write counts join complete retained streams")
            if fd==2 and len(body)==24 and body[:8]in(begin_tag,end_tag):
                ci,step=struct.unpack("<2Q",body[8:]);require(ci==case["case"]and step in steps and r["tid"]==process["pid"],"actual ordered owner markers")
                if body[:8]==begin_tag:
                    require(active is None and len(markers)==2*step,"one exact next original operation");active=step
                else:
                    require(active==step and len(markers)==2*step+1,"actual operation end after all workers join");active=None
                markers.append(dict(step=step,begin=body[:8]==begin_tag,trace_index=r["index"],stderr_end=errpos));continue
        if active is not None:steps[active].append(r)
    require(active is None and len(markers)==2*len(case["steps"])and errpos==len(stderr)and outpos==len(stdout),
        "all actual markers, stdout and stderr bytes read completely")
    require(any(r["name"]=="exit_group"and r["args"]==["0"]for r in rows),"actual complete application success exit")
    threads={r["tid"]for r in rows}
    for step,op in enumerate(case["steps"]):
        operation=op["operation"]
        if operation["op"].startswith("parallel-"):
            actual=answers[step]["parallel"];tids={r["tid"]for r in actual}
            require(len(tids)==operation["workers"]and tids<=threads and process["pid"]not in tids,"all reported concurrent workers have actual traced syscalls")
            successful=[r["returned"]for r in steps[step]if r["name"]in("clone","clone3")and r["returned"]is not None and r["returned"]>0]
            require(set(successful)==tids,"all actual native/Rust worker creation results")
    matched=[]
    if native is not None and(native["typed_records"].get("observation",0)or native["typed_records"].get("fd-watcher-observation",0)):
        by_step_tid={}
        for step,srows in steps.items():
            for r in srows:
                if r["name"]=="read"and(number(r["args"][0])in(0,1,2)or 32<=number(r["args"][0])<320):
                    by_step_tid.setdefault((step,r["tid"]),[]).append(r)
        used={}
        for witness in native["kernel_witnesses"]:
            if witness["op"]!=2:continue
            key=(witness["step"],witness["tid"]);position=used.get(key,0)
            require(key in by_step_tid and position<len(by_step_tid[key]),"every actual native inotify read has one kernel syscall")
            r=by_step_tid[key][position];used[key]=position+1
            require(number(r["args"][0])==witness["event_fd"]and number(r["args"][1])==witness["child"]+98336
                and number(r["args"][2])==16384 and r["returned"]==witness["returned"]
                and(r["errno"]==witness["errno"]if r["returned"]<0 else r["payload"].hex()==witness["read_hex"]),
                "all actual native read arguments, real errno, count and kernel bytes match the complete live buffer")
            matched.append(dict(step=key[0],tid=key[1],syscall_index=r["index"],observation_index=witness["index"],bytes=len(r["payload"])))
        require(all(used.get(k,0)==len(v)for k,v in by_step_tid.items()),"no extra unobserved actual inotify read")
    business=[]
    owned={512+i for i,r in enumerate(case["roots"])if not r["late"]};event_fds=set()
    for step,srows in steps.items():
        relevant=[]
        for r in srows:
            name=r["name"];args=r["args"]
            if name=="inotify_init1"and r["returned"]is not None and r["returned"]>=0:
                owned.add(r["returned"]);event_fds.add(r["returned"])
            if name=="fcntl"and len(args)>=2 and args[1]=="F_DUPFD_CLOEXEC"and r["returned"]is not None and r["returned"]>=0:owned.add(r["returned"])
            if name=="openat"and re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)",args[0])and number(args[0])in owned and r["returned"]is not None and r["returned"]>=0:owned.add(r["returned"])
            if name in("inotify_init1","inotify_add_watch","inotify_rm_watch"):
                relevant.append(dict(name=name,args=args,returned=r["returned"],errno=r["errno"],payload=r["payload"].hex(),tid=r["tid"]))
            elif name=="read"and number(args[0])in event_fds:
                relevant.append(dict(name=name,args=[number(args[0]),number(args[2])],returned=r["returned"],errno=r["errno"],payload=r["payload"].hex(),tid=r["tid"]))
            elif name=="fcntl"and len(args)>=2 and args[1]=="F_DUPFD_CLOEXEC":
                relevant.append(dict(name=name,args=args,returned=r["returned"],errno=r["errno"],payload="",tid=r["tid"]))
            elif name=="close"and number(args[0])in owned:
                relevant.append(dict(name=name,args=[number(args[0])],returned=r["returned"],errno=r["errno"],payload="",tid=r["tid"]))
            elif name=="openat"and re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)",args[0])and number(args[0])>=32:
                relevant.append(dict(name=name,args=args,returned=r["returned"],errno=r["errno"],payload="",tid=r["tid"]))
            elif name=="getdents64"and number(args[0])in owned:
                relevant.append(dict(name=name,args=args if r["returned"]is not None and r["returned"]>=0 else [args[0],args[2]],
                    returned=r["returned"],errno=r["errno"],payload="",tid=r["tid"]))
            if name=="close"and r["returned"]==0:
                owned.discard(number(args[0]));event_fds.discard(number(args[0]))
        business.append(dict(step=step,operations=relevant))
        state=answers[step]["state"];owned={r["fd"]for r in state["roots"]};event_fds=set()
        watchers=[g["watcher"]for g in state["globals"]if g["watcher"]is not None]+[s["watcher"]for s in state["sets"]]
        for w in watchers:
            owned.add(w["event_fd"]);event_fds.add(w["event_fd"]);owned.update(r["pin_fd"]for r in w["watches"])
    floor=[closed_standard(s["operation"],steps[i],answers[i])for i,s in enumerate(case["steps"])if s["operation"]["op"]=="closed-standard-watcher"]
    return dict(closed_standard_descriptor_proofs=floor,trace=pin(raw),physical_lines=line_count,syscalls=len(rows),threads=sorted(threads),signals=signals,markers=markers,
        native_read_joins=matched,business=business,mappings=[{k:r[k]for k in("index","tid","name","args","returned","errno")}for r in rows if r["name"]in("mmap","munmap","mprotect")],stdio_bytes=dict(stdout=outpos,stderr=errpos),whole_kernel_payload_bytes=sum(len(r["payload"])for r in rows))
