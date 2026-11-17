"""Complete captured syscall/effect equivalence; no syscall or executable is invoked."""
import errno,re
from common import require,pin
from protocol import word
HEX=re.compile(r'"((?:\\x[0-9a-f]{2})*)"')
LINE=re.compile(r'^([0-9]+)\s+(.*)$')
CALL=re.compile(r'^([a-z0-9_]+)\((.*)\)\s+=\s+(-?[0-9]+)(?:\s+([A-Z][A-Z0-9_]+))?')
ERRORS={name:number for number,name in errno.errorcode.items()}
TEMP=re.compile(rb"\.archive-anchor-([0-9a-f]{64})\.tmp")
ANCHOR=b".request-archive-v11-anchor.json"
def strings(value):return [bytes.fromhex(x.replace("\\x","")) for x in HEX.findall(value)]
def records(raw,pid,rows,prefix):
    current=None;buffer=b"";stderr=bytearray();groups={};order=[];all_calls=[];sequence=0
    for line in raw.decode("utf-8").splitlines():
        m=LINE.match(line);require(m is not None,"complete actual PID trace line")
        if int(m[1])!=pid:continue
        text=m[2];call=CALL.match(text)
        if call is None:
            require("<unfinished ...>" in text or text.startswith("<... ") or text.startswith("--- ") or text.startswith("+++ "),
                    "known complete strace record")
            continue
        op,args,ret,error=call.groups();ret=int(ret);code=0 if ret>=0 else ERRORS.get(error)
        require(code is not None,"complete actual trace errno")
        payloads=strings(args)
        row=dict(index=sequence,operation=op,arguments=args,returned=ret,errno=code,strings=payloads,command=current)
        sequence+=1;all_calls.append(row)
        if op in ("write","writev") and args.startswith("2, "):
            part=b"".join(payloads);require(payloads and ret==len(part),"whole actual stderr")
            stderr+=part;buffer+=part
            while b"\n" in buffer:
                value,buffer=buffer.split(b"\n",1)
                if value.startswith(prefix+b"_BEGIN "):
                    ci,gen=map(int,value.split()[1:]);require(current is None and (ci,gen) not in groups,"unique marked turn")
                    current=(ci,gen);groups[current]=[];order.append(current)
                elif value.startswith(prefix+b"_END "):
                    ci,gen=map(int,value.split()[1:]);require(current==(ci,gen),"same complete marked turn");current=None
                else:require(prefix==b"PUBLISH_ORIGINAL" and current is not None and value.startswith(b"OBSERVED_ORIGINAL_ERROR "),
                             "complete original target error observation")
            continue
        if current is not None:groups[current].append(row)
    expected=[(ci,1+ci*100+si) for ci,c in rows for si in range(len(c["steps"]))]
    require(current is None and not buffer and order==expected,"all complete source-owned turns")
    return groups,bytes(stderr),all_calls
def signature_from_effects(events,case):
    caps={"1":"root"};all_sigs=[];temporaries=[];last_generation=None;entropy=b"";turn=[]
    for e in events:
        if e.get("kind")==3:continue
        if e["generation"]!=last_generation:
            if last_generation is not None:all_sigs.append(turn)
            last_generation=e["generation"];turn=[];entropy=b""
        op=e["operation"];a,b,c=e["arguments"];payloads=[bytes.fromhex(s) for s in e["payloads"]]
        result=e["observed"]["actual_return"];err=e["observed"]["actual_errno"] if result<0 else 0
        ack=bytes.fromhex(e["acknowledgement_hex"]);value=word(ack,56);data=ack[128:]
        role=caps.get(str(a));item=None
        if op==17:
            require(0<=a<=32 and b==c==0 and not any(payloads),"actual getrandom request")
            require(result<0 and not data or result>=0 and len(data)==result,"complete random result")
            if result>0:entropy+=data
            item=["getrandom",a,result,err]
        elif op==18:
            require(a==524288 and b==c==0 and not payloads[1] and payloads[0] in (b"/dev/random",b"/dev/urandom"),"fixed entropy device")
            newrole="random" if payloads[0]==b"/dev/random" else "urandom"
            if result>=0:caps[str(value)]=newrole
            item=["open-device",newrole,0 if result>=0 else -1,err]
        elif op==19:
            require(role=="random" and b==1 and c==(1<<64)-1 and not any(payloads),"actual readiness poll")
            item=["poll",role,result,err]
        elif op==4:
            require(role=="urandom" and c==0 and not any(payloads),"actual fallback read")
            if result>0:entropy+=data
            item=["read-entropy",b,result,err]
        elif op==1:
            require(role=="root" and b==193 and c==384 and not payloads[1] and len(entropy)==32,
                    "real entropy completed before exclusive publication")
            name=b".archive-anchor-"+entropy.hex().encode()+b".tmp"
            require(payloads[0]==name and TEMP.fullmatch(name),"temporary is complete actual entropy hex")
            temporaries.append(name.decode());index=len(temporaries)-1
            if result>=0:caps[str(value)]="temporary-"+str(index)
            item=["open-temporary",index,0 if result>=0 else -1,err]
        elif op==5:
            require(role and role.startswith("temporary-") and len(payloads[0])==b and not payloads[1] and c==0,"actual full remaining write")
            item=["write",role,payloads[0].hex(),result,err]
        elif op==6:
            require(role=="root" or role and role.startswith("temporary-"),"actual sync role")
            item=["fsync",role,result,err]
        elif op==7:
            require(role and role!="root","actual owned close");del caps[str(a)]
            item=["close",role,result,err]
        elif op==8:
            require(role=="root" and payloads[0].decode()==temporaries[-1] and payloads[1]==ANCHOR,"actual hardlink names")
            item=["link",len(temporaries)-1,result,err]
        elif op==9:
            require(role=="root" and payloads[0].decode()==temporaries[-1] and not payloads[1],"actual temporary cleanup name")
            item=["unlink",len(temporaries)-1,result,err]
        else:raise ValueError("unknown publisher effect")
        turn.append(item)
    if last_generation is not None:all_sigs.append(turn)
    return dict(signatures=all_sigs,temporaries=temporaries,retained_roles=sorted(caps.values()))
def from_syscalls(groups,rows,root_fd,all_calls,*,original):
    # File descriptors are actual observed kernel returns, not policy inputs.
    caps={root_fd:"root"};signatures=[];temporaries=[];outside_closes=[]
    relevant={r["index"] for group in groups.values() for r in group}
    next_index=0
    for ci,case in rows:
        for si,_ in enumerate(case["steps"]):
            group=groups[ci,1+ci*100+si];turn=[];entropy=b""
            if group:
                for t in all_calls:
                    if next_index<=t["index"]<group[0]["index"] and t["index"] not in relevant and t["operation"]=="close":
                        fd=int(t["arguments"])
                        if fd in caps and caps[fd]!="root":
                            require(t["returned"]==0,"actual out-of-turn entropy disposal")
                            outside_closes.append(caps.pop(fd))
                next_index=group[-1]["index"]+1
            for t in group:
                op,args,ret,err,data=t["operation"],t["arguments"],t["returned"],t["errno"],t["strings"]
                item=None
                if op=="getrandom":
                    match=re.search(r", ([0-9]+), 0$",args);require(match is not None,"exact getrandom flags and extent")
                    amount=int(match[1]);require(0<=amount<=32,"exact owned random request")
                    require(ret<0 and not data or ret>=0 and len(data)==1 and len(data[0])==ret,"all syscall random bytes")
                    if ret>0:entropy+=data[0]
                    item=["getrandom",amount,ret,err]
                elif op=="openat":
                    require(len(data)==1,"full observed pathname")
                    name=data[0]
                    if name in (b"/dev/random",b"/dev/urandom"):
                        require(args.startswith("AT_FDCWD, ") and "O_RDONLY" in args and "O_CLOEXEC" in args,"real entropy open")
                        role="random" if name==b"/dev/random" else "urandom"
                        if ret>=0:
                            require(ret not in caps,"unique actual descriptor");caps[ret]=role
                        item=["open-device",role,0 if ret>=0 else -1,err]
                    else:
                        require(args.startswith(str(root_fd)+", ") and all(s in args for s in ("O_WRONLY","O_CREAT","O_EXCL","O_NOFOLLOW","O_CLOEXEC")) and args.endswith(", 0600"),
                                "same exclusive no-follow private component open")
                        require(len(entropy)==32 and name==b".archive-anchor-"+entropy.hex().encode()+b".tmp","exact actual entropy-derived temp name")
                        temporaries.append(name.decode());index=len(temporaries)-1
                        if ret>=0:
                            require(ret not in caps,"unique actual temporary FD");caps[ret]="temporary-"+str(index)
                        item=["open-temporary",index,0 if ret>=0 else -1,err]
                elif op=="poll":
                    match=re.fullmatch(r"\[\{fd=([0-9]+), events=POLLIN\}\], 1, -1",args)
                    require(match is not None and caps.get(int(match[1]))=="random","same one real entropy poll")
                    item=["poll","random",ret,err]
                elif op=="read":
                    match=re.match(r"^([0-9]+), ",args);tail=re.search(r", ([0-9]+)$",args)
                    require(match is not None and tail is not None and caps.get(int(match[1]))=="urandom","same retained actual entropy read")
                    amount=int(tail[1]);require(0<amount<=32,"bounded remaining actual entropy")
                    require(ret<0 and not data or ret>=0 and len(data)==1 and len(data[0])==ret,"whole actual entropy read data")
                    if ret>0:entropy+=data[0]
                    item=["read-entropy",amount,ret,err]
                elif op=="write":
                    match=re.match(r"^([0-9]+), ",args);tail=re.search(r", ([0-9]+)$",args)
                    require(match is not None and tail is not None and len(data)==1 and len(data[0])==int(tail[1]),"full actual write data")
                    role=caps.get(int(match[1]));require(role and role.startswith("temporary-"),"same temporary write capability")
                    item=["write",role,data[0].hex(),ret,err]
                elif op in ("fsync","close"):
                    fd=int(args);role=caps.get(fd);require(role is not None,"same real capability")
                    if op=="close":require(role!="root","root kept borrowed inside turn");del caps[fd]
                    item=[op,role,ret,err]
                elif op=="linkat":
                    require(len(data)==2 and data==[temporaries[-1].encode(),ANCHOR] and
                            args.startswith(str(root_fd)+", ") and (", "+str(root_fd)+", ") in args and args.endswith(", 0"),
                            "whole same-root link names")
                    item=["link",len(temporaries)-1,ret,err]
                elif op=="unlinkat":
                    require(data==[temporaries[-1].encode()] and args.startswith(str(root_fd)+", ") and args.endswith(", 0"),
                            "whole same-root unlink name")
                    item=["unlink",len(temporaries)-1,ret,err]
                else:raise ValueError("unexpected syscall inside actual publisher: "+op)
                turn.append(item)
            signatures.append(turn)
    for t in all_calls:
        if t["index"]>=next_index and t["index"] not in relevant and t["operation"]=="close":
            fd=int(t["arguments"])
            if fd in caps:
                require(t["returned"]==0,"final actual capability close")
                outside_closes.append(caps.pop(fd))
    # Original SystemRandom caches its urandom descriptor until process exit. The
    # private native service disposes that descriptor at its explicit end.
    if original:
        require("root" not in caps.values() and set(caps.values())<= {"urandom"},"original explicit root drop and process-owned RNG")
    else:require(not caps,"native closes its private entropy and borrowed fixture root after service")
    return dict(signatures=signatures,temporaries=temporaries,outside_closes=outside_closes,
                remaining_process_owned_roles=sorted(caps.values()))
