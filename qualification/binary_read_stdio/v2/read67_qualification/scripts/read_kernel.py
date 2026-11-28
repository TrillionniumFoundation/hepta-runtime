#!/usr/bin/env python3
"""Pure complete passive-kernel trace and descriptor-lifetime admission."""
from pathlib import Path,PurePosixPath
import gzip,hashlib,os,stat,struct
from common import decode,pin,require
MASK=(1<<64)-1
def s(v):return v-(1<<64)if v>>63 else v
def buf(rows,label):
    matches=[r for r in rows if r["label"]==label]
    require(len(matches)==1 and "hex"in matches[0],"one complete observed memory span: "+label)
    r=matches[0];raw=bytes.fromhex(r["hex"])
    require(len(raw)==r["bytes"],"complete observed memory extent");return raw
def snapshot(value,pid):
    require(value["pid"]==pid and value["readonly"]is True and value["stopped_at_syscall_entry"]is True
        and value["maps_hex"]==value["maps_after_hex"],"stable read-only actual stopped process")
    maps=bytes.fromhex(value["maps_hex"]);require(maps,"whole actual maps")
    fds=value["fds"];require(list(fds)==sorted(fds,key=int),"ordered complete FD inventory")
    for k,r in fds.items():
        require(k==str(int(k))and 0<=int(k)<=2147483647 and set(r)=={"target","stat","fdinfo_hex"},
            "actual descriptor record")
        info=bytes.fromhex(r["fdinfo_hex"]).decode();fields=dict(l.split(":\t",1)for l in info.splitlines()if":\t"in l)
        require("pos"in fields and "flags"in fields and "mnt_id"in fields and "ino"in fields
            and int(fields["ino"])==r["stat"]["inode"],"complete kernel fdinfo identity")
    return maps
def mapping_rows(raw):
    out=[]
    for line in raw.decode().splitlines():
        f=line.split();lo,hi=(int(x,16)for x in f[0].split("-"))
        require(lo<hi and len(f)>=5,"actual maps line");out.append((lo,hi,f[1],f[5:]))
    return out
def covered(rows,a,n,permission=None):
    return any(lo<=a and a+n<=hi and(permission is None or mode==permission)for lo,hi,mode,_ in rows)
def verify(folder,p,stdin,stdout,stderr,query,case):
    path=Path(folder)/"kernel.jsonl.gz";receipt=p["kernel"]
    require(pin(path)==receipt["compressed"] and decode((Path(folder)/"kernel-process.json").read_bytes())==receipt,
        "complete kernel receipt publication")
    rows=[];digest=hashlib.sha256();count=0
    with gzip.open(path,"rb")as stream:
        for raw in stream:
            require(raw.endswith(b"\n"),"whole kernel row");row=decode(raw)
            require(row["trace_row"]==len(rows),"kernel contiguous row index")
            digest.update(raw);count+=len(raw);rows.append(row)
    require(dict(bytes=count,sha256=digest.hexdigest())==receipt["raw"]and len(rows)==receipt["rows"],
        "every kernel trace byte")
    first,last=rows[0],rows[-1]
    require(first["record"]=="START"and first["pid"]==p["pid"]and first["options"]==1048593
        and first["ptrace_requests"]==[24,16896,16910]and first["memory_reader"]=="process_vm_readv"
        and first["register_or_memory_writes"]==first["syscall_result_replacements"]==0 and first["follow_forks"]is False,
        "passive direct-child tracing profile")
    require(last["record"]=="DONE"and last["capture_errors"]==receipt["capture_errors"]==[]
        and last["register_or_memory_writes"]==last["syscall_result_replacements"]==0
        and last["application_calls"]==receipt["application_calls"]==1,"zero observer injection/capture errors")
    calls=[];current=None;execs=signals=marks=0;ordinal=0;entry_exit=None;exit_row=None;mark_ordinal=None
    stdin_bytes=bytearray();writes={1:bytearray(),2:bytearray()};pre_eof=None
    for row in rows[1:-1]:
        kind=row["record"]
        if kind=="ENTER":
            require(current is None and row["ordinal"]==ordinal+1,"complete syscall entry sequence");ordinal+=1
            raw=bytes.fromhex(row["syscall_info_hex"])
            require(len(raw)>=80 and raw[0]==1 and struct.unpack_from("<I",raw,4)[0]==0xc000003e
                and list(struct.unpack_from("<7Q",raw,24))==[row["number"],*row["args"]]
                and struct.unpack_from("<Q",raw,8)[0]==row["instruction_pointer"],"raw actual syscall entry fields")
            for value in row["input"]:
                require("error"not in value,"unread syscall input")
                if "hex"in value:require(len(bytes.fromhex(value["hex"]))==value["bytes"],"whole entry memory")
                elif value["label"]=="pre-eof-inventory":
                    require(pre_eof is None and row["number"]==0 and row["args"][0]==0,"one actual pre-EOF stop")
                    pre_eof=value["value"];require(pre_eof==p["before_eof"]and pre_eof["syscall_ordinal"]==ordinal,
                        "pre-EOF actual trace and process inventory")
                elif value["label"]=="process-exit-inventory":
                    require(entry_exit is None and row["number"]in(60,231),"one actual OS-exit entry")
                    entry_exit=value["value"];require(entry_exit==p["pre_exit"]and entry_exit["syscall_ordinal"]==ordinal,
                        "actual final inventory publication")
                else:raise ValueError("unbound observer structured span")
            current=row
        elif kind=="LEAVE":
            require(current is not None and row["ordinal"]==current["ordinal"]and row["number"]==current["number"],
                "complete syscall return ownership")
            raw=bytes.fromhex(row["syscall_info_hex"]);result=row["result"]
            require(len(raw)>=33 and raw[0]==2 and struct.unpack_from("<I",raw,4)[0]==0xc000003e
                and struct.unpack_from("<q",raw,24)[0]==result and raw[32]==row["is_error"]
                and row["is_error"]in(0,1),"raw actual syscall return fields")
            for value in row["output"]:
                require("error"not in value and len(bytes.fromhex(value["hex"]))==value["bytes"],"whole returned memory")
            n=current["number"];a=current["args"]
            if n in(0,17)and result>=0:
                data=buf(row["output"],"read");require(len(data)==result and result<=a[2],"whole actual read")
                if n==0 and a[0]==0:stdin_bytes.extend(data)
            if n==1 and a[0]in(1,2)and result>=0:
                data=buf(current["input"],"write");require(len(data)==a[2]and result<=len(data),"whole stdio write")
                writes[a[0]].extend(data[:result])
            if n==20 and a[0]in(1,2)and result>=0:
                iov=buf(current["input"],"iovec");require(len(iov)==16*a[2],"complete stdout iov")
                data=b"".join(buf(current["input"],"writev-"+str(i))for i in range(a[2]))
                require(result<=len(data),"actual partial writev");writes[a[0]].extend(data[:result])
            calls.append(dict(entry=current,leave=row));current=None
        elif kind=="EXEC":
            require(row["pending_call"]==(current["ordinal"]if current else None),"actual exec sequence");execs+=1
        elif kind=="SIGNAL":
            require(row["forwarded_without_change"]is True and row["signal"]>0,"unchanged actual signal");signals+=1
        elif kind=="MARK":
            require(row["scope"]=="owned-stdin-eof"and row["application"]is True and marks==0
                and row["open_call"]==(current["ordinal"]if current else None),"one stdin-EOF application boundary")
            marks+=1;mark_ordinal=row["calls"]
        elif kind=="EXIT":
            require(exit_row is None and row["wait_status"]==p["wait_status"]and row["returncode"]==p["returncode"]
                and current is not None and row["open_exit"]=={k:v for k,v in current.items()if k not in("record","trace_row")}
                and current["number"]in(60,231),
                "whole process exits at observed syscall")
            exit_row=row;current=None
        else:raise ValueError("unrecognized complete kernel trace record")
    require(execs==receipt["execs"]==last["execs"]==1 and signals==receipt["signals"]==last["signals"]
        and marks==1 and ordinal==receipt["calls"]==last["calls"] and exit_row is not None and current is None,
        "complete direct-process trace custody")
    require(bytes(stdin_bytes)==stdin and bytes(writes[1])==stdout and bytes(writes[2])==stderr,
        "actual complete kernel stdin/stdout/stderr bytes")
    require(pre_eof is not None and entry_exit is not None and pre_eof["stdin_returned"]==len(stdin)
        and pre_eof["hold_milliseconds"]==5 and pre_eof["output_bytes"]==dict(stdout=0,stderr=0,body=0,formatter=0),
        "no application output before owned input EOF")
    before_maps=snapshot(pre_eof["snapshot"],p["pid"]);exit_maps=snapshot(entry_exit["snapshot"],p["pid"])
    require(entry_exit["requested_exit_code"]==p["returncode"]and entry_exit["number"]in(60,231),"real OS exit code")
    require(all(c["leave"]["result"]>=0 or c["leave"]["result"]>=-4095 for c in calls),"Linux errno extent")
    filters=[c for c in calls if c["entry"]["number"]==317]
    expected_bpf=b"".join(struct.pack("<HBBI",*x)for x in[(0x20,0,0,0),(0x15,0,1,5),(6,0,0,0x50005),
        (0x15,0,1,262),(6,0,0,0x50005),(6,0,0,0x7fff0000)])
    require(len(filters)==int(case["fault"]),"one actual kernel fault filter or none")
    if filters:
        c=filters[0];a=c["entry"]["args"];program=buf(c["entry"]["input"],"sock-fprog")
        require(a[:2]==[1,0]and c["leave"]["result"]==0 and len(program)==16
            and struct.unpack_from("<H",program,0)[0]==6
            and buf(c["entry"]["input"],"seccomp-bpf")==expected_bpf,"exact installed real EIO BPF")
        require(any(x["entry"]["number"]==157 and x["entry"]["args"][:2]==[38,1]
            and x["leave"]["result"]==0 and x["entry"]["ordinal"]<c["entry"]["ordinal"]for x in calls),
            "actual no-new-privileges admission")
    post=[c for c in calls if c["entry"]["ordinal"]>mark_ordinal]
    denied=[c for c in post if c["entry"]["number"]in(5,262)and c["leave"]["result"]==-5]
    require(len(denied)==int(case["fault"]),"actual first regular fstat EIO")
    initial=pre_eof["snapshot"]["fds"];final=entry_exit["snapshot"]["fds"];fds={int(k):v["target"]for k,v in initial.items()}
    if p["native"]:
        require(not any(c["entry"]["number"]in(2,257,3,5,262,8,107)
            and c["entry"]["ordinal"]>next(r["pending_call"]for r in rows if r["record"]=="EXEC")
            and c["entry"]["ordinal"]<=mark_ordinal for c in calls),"native filesystem effects precede stdin EOF")
        expected={str(i)for i in range(6 if p["observed"]else 3)}
        require(set(initial)==expected,"no foreign native inherited descriptor")
        entries=mapping_rows(before_maps)
        require(not any(".so"in" ".join(x[3])or"python"in" ".join(x[3]).lower()for x in entries)
            and not any(x[2][1:3]=="wx"for x in entries),"native maps no host runtime or WX")
    files=[];opened=[];closed=[];file_syscalls=[]
    for c in post:
        e,l=c["entry"],c["leave"];n,a,res=e["number"],e["args"],l["result"]
        if n in(2,257):
            raw=buf(e["input"],"path");require(raw.endswith(b"\0")and b"\0"not in raw[:-1],"actual open path")
            name=raw[:-1].decode()
            if name.startswith("/"):path=str(PurePosixPath(name))
            else:
                require(n==257 and a[0]in fds,"actual openat parent custody");path=str(PurePosixPath(fds[a[0]])/name)
            file_syscalls.append(c)
            if res>=0:
                require(res not in fds,"actual open reused a live FD");fds[res]=path;opened.append(dict(fd=res,path=path,ordinal=e["ordinal"]))
        elif n==3:
            require(a[0]in fds,"actual close had no live token");closed.append(dict(fd=a[0],ordinal=e["ordinal"]))
            fds.pop(a[0]);file_syscalls.append(c)
        elif n in(5,262,107,8)or n==0 and a[0]not in({0,5}if p["observed"]else{0}):
            file_syscalls.append(c)
    require(set(map(str,fds))==set(final)and all(final[str(fd)]["target"]==path for fd,path in fds.items()),
        "complete live FD set and targets at real process exit")
    extras=set(final)-set(initial);require(len(extras)==int(case["fault"]),"original/native process-lifetime orphan count")
    orphan=[]
    for fd in sorted(extras,key=int):
        r=final[fd];target=str(PurePosixPath(query["request"]["path"]))
        require(fds[int(fd)]==target and r["target"]==target and stat.S_ISREG(r["stat"]["mode"]),
            "actual leaked descriptor refers to requested regular file")
        selected=query["input_selected_stat"]
        require(all(r["stat"][a]==selected[b]for a,b in(("dev","st_dev"),("inode","st_ino"),("size","st_size"),
            ("mtime_ns","st_mtime_ns"),("ctime_ns","st_ctime_ns"))),"orphan actual inode identity")
        fstats=[c for c in denied if c["entry"]["args"][0]==int(fd)]
        require(len(fstats)==1 and any(x["fd"]==int(fd)and x["ordinal"]<fstats[0]["entry"]["ordinal"]for x in opened),
            "kernel fstat failed on previously opened exact orphan")
        require(not any(x["fd"]==int(fd)and x["ordinal"]>fstats[0]["entry"]["ordinal"]for x in closed),
            "orphan closed before whole process exit")
        orphan.append(dict(fd=int(fd),path=target,stat=r["stat"]))
    live_maps={}
    if p["native"]:
        for c in calls:
            if c["entry"]["ordinal"]<=next(r["pending_call"]for r in rows if r["record"]=="EXEC"):continue
            e,l=c["entry"],c["leave"];n,a,res=e["number"],e["args"],l["result"]
            if n==9 and res>=0:
                require(res not in live_maps and a[0]==0 and a[3]==0x22,"owned ordinary anonymous mmap")
                live_maps[res]=a[1]
            elif n==11 and res==0:
                require(a[0]in live_maps and live_maps[a[0]]==a[1],"complete owned mapping retirement")
                del live_maps[a[0]]
        pool_alloc=[c for c in post if c["entry"]["number"]==9 and c["leave"]["result"]>=0]
        require(pool_alloc,"actual shared process pool allocation")
        pool_address=pool_alloc[0]["leave"]["result"]
        require(pool_address in live_maps and len(live_maps)==1+int(case["fault"])
            and set(live_maps.values())=={8192},"only process pool and orphan pages survive ordinary EOF")
        maps=mapping_rows(exit_maps)
        require(all(covered(maps,a,4096,"rw-p")and covered(maps,a+4096,4096,"---p")for a in live_maps),
            "actual surviving pool pages and guard pages")
    else:pool_address=None
    return dict(calls=ordinal,trace_bytes=count,signals=signals,execs=execs,orphans=orphan,
        native_file_syscalls=file_syscalls if p["native"]else[],native_live_mappings=live_maps,
        native_pool_address=pool_address,pre_exit_maps=exit_maps,
        observer_acks=[buf(c["leave"]["output"],"read").hex()for c in post
            if p["observed"]and c["entry"]["number"]==0 and c["entry"]["args"][0]==5 and c["leave"]["result"]>=0],
        all_actual_syscalls_retained=True,
        all_cpython_internal_failure_semantics_qualified=False)
def bind_effects(effects,kernel):
    calls=kernel["native_file_syscalls"];ordinary=[r for r in effects if r["operation"]!=4]
    require(len(calls)==len(ordinary),"complete actual native file syscalls and HIA capability sequence")
    for r,c in zip(ordinary,calls):
        e,l=c["entry"],c["leave"];n,a=e["number"],e["args"];op=r["operation"]
        require(l["result"]==r["raw_return"],"actual kernel result equals complete HIA resume")
        if op==1:require(n==2 and buf(e["input"],"path")==b"/\0"and a[1:3]==[0xb0000,0],"native root open")
        elif op in(2,3):
            require(n==257 and a[0]==r["fd"]and a[2]==(0xb0000 if op==2 else 0xa0800)and a[3]==0
                and buf(e["input"],"path").hex()==r["request"],"native openat exact borrowed bytes")
        elif op==5:require(n==3 and a[0]==r["fd"],"native close actual token")
        elif op==6:
            require(n==5 and a[0]==r["fd"],"native fstat actual token")
            if l["result"]==0:require(buf(l["output"],"stat").hex()==r["payload"],"all native stat bytes")
        elif op==9:require(n==107,"actual native geteuid")
        elif op==11:
            require(n==0 and a[0]==r["fd"]and a[2]==r["a"],"native read extent")
            if l["result"]>=0:require(buf(l["output"],"read").hex()==r["payload"],"all actual native read bytes")
        elif op==19:require(n==8 and a[:3]==[r["fd"],r["a"],0],"native seek exact offset")
        else:raise ValueError("unknown native fixed capability")
    return len(ordinary)
