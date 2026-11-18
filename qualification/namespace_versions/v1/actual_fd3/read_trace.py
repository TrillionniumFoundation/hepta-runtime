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
            if 32<=fd<320 and row["returned"]is not None and row["returned"]>0:
                require(len(row["payload"])==row["returned"],"whole actual pooled read payload")
            else:require(not row["payload"],"no fabricated kernel payload on failed or unselected descriptor")
        else:require(not row["payload"],"only actual reads have captured kernel bytes")
    return rows,signals,len(physical)
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
    if native is not None and native["typed_records"].get("observation",0):
        by_step_tid={}
        for step,srows in steps.items():
            for r in srows:
                if r["name"]=="read"and 32<=number(r["args"][0])<320:
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
    return dict(trace=pin(raw),physical_lines=line_count,syscalls=len(rows),threads=sorted(threads),signals=signals,markers=markers,
        native_read_joins=matched,business=business,mappings=[{k:r[k]for k in("index","tid","name","args","returned","errno")}for r in rows if r["name"]in("mmap","munmap","mprotect")],stdio_bytes=dict(stdout=outpos,stderr=errpos),whole_kernel_payload_bytes=sum(len(r["payload"])for r in rows))
