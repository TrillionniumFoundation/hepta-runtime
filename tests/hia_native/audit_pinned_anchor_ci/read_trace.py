"""Inert reading of actual strace records; never issue a filesystem operation."""
import errno,re
from common import require,pin
from protocol import word
from fixture import NAME

HEX=re.compile(r'"((?:\\x[0-9a-f]{2})*)"')
LINE=re.compile(r'^([0-9]+)\s+(.*)$')
CALL=re.compile(r'^([a-z0-9_]+)\((.*)\)\s+=\s+(-?[0-9]+)(?:\s+([A-Z][A-Z0-9_]+))?')
ERRORS={name:number for number,name in errno.errorcode.items()}
def strings(value):return [bytes.fromhex(x.replace("\\x","")) for x in HEX.findall(value)]
def records(raw,pid,domain,prefix):
    current=None;buffer=b"";stderr=bytearray();groups={};order=[];all_calls=[];sequence=0
    for line in raw.decode("utf-8").splitlines():
        m=LINE.match(line);require(m is not None,"complete actual PID trace line")
        if int(m[1])!=pid:continue
        text=m[2];call=CALL.match(text)
        if call is None:
            require("<unfinished ...>" in text or text.startswith("<... ") or text.startswith("--- ") or text.startswith("+++ "),"known complete strace record")
            continue
        op,args,ret,error=call.groups();ret=int(ret);code=0 if ret>=0 else ERRORS.get(error)
        require(code is not None,"complete actual trace errno")
        payloads=strings(args)
        row=dict(index=sequence,operation=op,arguments=args,returned=ret,errno=code,strings=payloads,command=current);sequence+=1
        all_calls.append(row)
        if op in ("write","writev") and args.startswith("2, "):
            part=b"".join(payloads);require(payloads and ret==len(part),"whole actual stderr write")
            stderr+=part;buffer+=part
            while b"\n" in buffer:
                value,buffer=buffer.split(b"\n",1)
                if value.startswith(prefix+b"_BEGIN "):
                    ci,gen=map(int,value.split()[1:]);require(current is None and (ci,gen) not in groups,"unique actual start")
                    current=(ci,gen);groups[current]=[];order.append(current)
                elif value.startswith(prefix+b"_END "):
                    ci,gen=map(int,value.split()[1:]);require(current==(ci,gen),"same actual terminal marker");current=None
                else:require(prefix==b"ANCHOR_ORIGINAL" and current is not None and value.startswith(b"OBSERVED_ORIGINAL_ERROR "),"complete actual diagnostic line")
            continue
        if current is not None:groups[current].append(row)
    expected=[(ci,1+ci*100+si) for ci,c in enumerate(domain) for si in range(len(c["steps"]))]
    require(current is None and not buffer and order==expected,"all complete original/native marked turns")
    return groups,bytes(stderr),all_calls

def native(raw,pid,domain,bindings,events,observations):
    groups,stderr,all_calls=records(raw,pid,domain,b"ANCHOR_PUMP")
    expected={key:[] for key in groups}
    for e in events:
        if e.get("kind")==3:continue
        expected[e["case"],e["generation"]].append(e)
    opened={};held=None;active_case=None;actual_count=0;disposed=0
    observed_by_key={(r["case"],1+r["case"]*100+r["step"]):r for r in observations}
    # Every actual descriptor close is visible, including destructor calls outside a turn.
    grouped_rows={r["index"]:r["command"] for rows in groups.values() for r in rows}
    for trace in all_calls:
        key=grouped_rows.get(trace["index"])
        if key is None:
            if trace["operation"]=="close" and held is not None and trace["arguments"]==str(held):
                require(trace["returned"]==0,"actual retained-descriptor destructor close")
                held=None;disposed+=1
            continue
        ci,gen=key
        if active_case!=ci:
            require(held is None,"previous retained anchor closed before next case");active_case=ci
        op,args,ret,code=trace["operation"],trace["arguments"],trace["returned"],trace["errno"]
        rows=expected[key]
        require(rows,"no extra native syscall inside owned turn")
        e=rows.pop(0);kind=e["operation"];a,b,c=e["arguments"];want=e["observed"]
        require(code==(want["actual_errno"] if want["actual_return"]<0 else 0),"actual native syscall errno")
        root=bindings[ci]["root_fd"]
        if kind==1:
            require(op=="openat" and args.startswith(str(root)+", ") and trace["strings"]==[NAME.encode()] and
                    all(x in args for x in ("O_RDONLY","O_NONBLOCK","O_NOFOLLOW","O_CLOEXEC")) and held is None,"actual fixed no-follow anchor open")
            require((ret<0)==(want["actual_return"]<0),"actual open success/error")
            if ret>=0:held=ret
        elif kind in (2,15):
            if kind==15:
                require(op in ("newfstatat","fstatat64") and args.startswith(str(root)+", ") and trace["strings"]==[NAME.encode()] and "AT_SYMLINK_NOFOLLOW" in args,"actual named no-follow metadata")
            else:
                require(held is not None and ((op in ("fstat","fstat64") and args.startswith(str(held)+", ")) or
                    (op in ("newfstatat","fstatat64") and args.startswith(str(held)+', "", ') and "AT_EMPTY_PATH" in args) or
                    (op=="statx" and args.startswith(str(held)+', "", ') and "AT_EMPTY_PATH" in args)),"actual held descriptor metadata")
            require(ret==want["actual_return"],"metadata returned status")
        elif kind==3:require(op=="geteuid" and args=="" and ret==want["actual_return"],"actual current uid")
        elif kind in (4,16):
            require(op==("read" if kind==4 else "pread64") and held is not None and args.startswith(str(held)+", "),"actual held descriptor read")
            tail=(", %d"%b) if kind==4 else (", %d, %d"%(b,c))
            require(args.endswith(tail) and ret==want["actual_return"],"actual full read bound and positional offset")
            data=bytes.fromhex(e["acknowledgement_hex"])[128:]
            require((ret<0 and not trace["strings"] and not data) or ret>=0 and trace["strings"]==[data] and ret==len(data),"all actual read bytes")
        elif kind==7:
            require(op=="close" and held is not None and args==str(held) and ret==want["actual_return"],"actual consumed anchor close")
            held=None
        else:raise ValueError("unsupported source-owned anchor syscall")
        actual_count+=1
    require(held is None and all(not rows for rows in expected.values()),"all HIA effects and final owned descriptors consumed")
    return dict(filesystem_calls=actual_count,dispose_closes=disposed,complete_trace=pin(raw)),stderr

def original(raw,pid,domain,observations):
    groups,stderr,all_calls=records(raw,pid,domain,b"ANCHOR_ORIGINAL")
    rows={(r["case"],1+r["case"]*100+r["step"]):r for r in observations}
    descriptor=None;case_id=None;reads=0;bytes_read=0;opens=0;closes=0;outside_closes=0
    grouped={r["index"]:r["command"] for group in groups.values() for r in group}
    for t in all_calls:
        key=grouped.get(t["index"]);op,args,ret=t["operation"],t["arguments"],t["returned"]
        if key is None:
            if op=="close" and descriptor is not None and args==str(descriptor):
                require(ret==0,"actual original File destructor");descriptor=None;outside_closes+=1
            continue
        ci,gen=key
        if case_id!=ci:require(descriptor is None,"original previous File dropped");case_id=ci
        if op=="openat":
            require(t["strings"]==[NAME.encode()] and descriptor is None and all(x in args for x in ("O_RDONLY","O_NONBLOCK","O_NOFOLLOW","O_CLOEXEC")),"actual unchanged original open")
            if ret>=0:descriptor=ret
            opens+=1
        elif op in ("read","pread64"):
            require(descriptor is not None and args.startswith(str(descriptor)+", "),"actual original held File read")
            if ret>=0:
                require(len(t["strings"])==1 and len(t["strings"][0])==ret,"complete original file read bytes")
                bytes_read+=ret
            reads+=1
        elif op=="close":
            require(descriptor is not None and args==str(descriptor),"only owned original anchor close inside turn")
            descriptor=None;closes+=1
        else:
            require(op in ("newfstatat","fstatat64","fstat","fstat64","statx","geteuid"),"all original inode validation syscalls retained")
    require(descriptor is None,"no original descriptor survives process exit")
    return dict(opens=opens,inside_closes=closes,outside_closes=outside_closes,read_calls=reads,read_bytes=bytes_read,complete_trace=pin(raw)),stderr
