"""Read every real traced syscall and bind all three complete same-tree turns."""
import errno,re,struct
from common import require
from callable_contract import word
PID=re.compile(r"^([0-9]+)\s+(.*)$")
CALL=re.compile(r"^([a-zA-Z0-9_]+)\((.*)\)\s+=\s+(-?0x[0-9a-f]+|-?[0-9]+|\?)(?:\s+([A-Z][A-Z0-9_]+))?")
HEX=re.compile(r'"((?:\\x[0-9a-f]{2})*)"')
DIRENT=re.compile(r'\{d_ino=([0-9]+), d_off=(-?[0-9]+), d_reclen=([0-9]+), d_type=(DT_[A-Z0-9]+), d_name="((?:\\x[0-9a-f]{2})*)"\}')
DT={"DT_UNKNOWN":0,"DT_FIFO":1,"DT_CHR":2,"DT_DIR":4,"DT_BLK":6,"DT_REG":8,"DT_LNK":10,"DT_SOCK":12,"DT_WHT":14}
ERR={name:code for code,name in errno.errorcode.items()}
def strings(s):return[bytes.fromhex(v.replace("\\x",""))for v in HEX.findall(s)]
def parse(raw):
    rows={};pending={};signals=[]
    for line in raw.decode("utf-8").splitlines():
        match=PID.fullmatch(line);require(match is not None,"complete actual PID trace")
        pid=int(match[1]);text=match[2];rows.setdefault(pid,[])
        if text.endswith("<unfinished ...>"):
            require(pid not in pending,"single real unfinished syscall")
            pending[pid]=text[:-len("<unfinished ...>")];continue
        if text.startswith("<... "):
            require(pid in pending,"actual resumed syscall has its original prefix")
            end=text.find(" resumed>");require(end>=5,"complete actual resumed marker")
            op=text[5:end];prefix=pending.pop(pid);require(prefix.startswith(op+"("),"same actual syscall resumed")
            text=prefix+text[end+9:]
        call=CALL.match(text)
        if call is None:
            require(text.startswith("--- ")or text.startswith("+++ "),"known full non-syscall trace record")
            signals.append((pid,text));continue
        op,args,ret,error=call.groups();ret=None if ret=="?"else(int(ret,0)if ret.startswith(("0x","-0x"))else int(ret))
        require((ret is None and op=="exit_group")or(ret is not None and(ret>=0 or error in ERR)),"real kernel errno or terminal exit")
        rows[pid].append(dict(op=op,args=args,ret=ret,errno=0 if ret is None or ret>=0 else ERR[error],strings=strings(args)))
    require(not pending,"no incomplete final kernel syscall")
    return rows,signals
def split_turns(rows,role,expected,stderr,stdout):
    begin=b"NFORGB01"if role=="original"else b"NFNATB01"
    end=b"NFORGE01"if role=="original"else b"NFNATE01"
    groups={};order=[];current=None;actual_error=bytearray();actual_output=bytearray();outside=[]
    for row in rows:
        op,args,ret,parts=row["op"],row["args"],row["ret"],row["strings"]
        if op in("write","writev")and(args.startswith("2, ")or args.startswith("1, ")):
            payload=b"".join(parts);require(ret==len(payload),"whole actual stdout/stderr kernel write")
            if args.startswith("1, "):actual_output.extend(payload);require(current is None,"output only after terminal boundary");continue
            actual_error.extend(payload)
            require(len(payload)==24 and payload[:8]in(begin,end),"exact binary boundary marker")
            ci,gen=struct.unpack("<2Q",payload[8:])
            if payload[:8]==begin:
                require(current is None and(ci,gen)not in groups,"one actual BEGIN per immutable turn")
                current=(ci,gen);groups[current]=[];order.append(current)
            else:require(current==(ci,gen),"actual END belongs to current call");current=None
            continue
        if current is None:outside.append(row)
        else:groups[current].append(row)
    require(current is None and order==expected and bytes(actual_error)==stderr and bytes(actual_output)==stdout,
            "all actual turns, complete process stdout/stderr and no missing prefix/suffix")
    return groups,outside
def entries(row):
    args=row["args"];require(args.startswith("80, ")and args.endswith(", 32768"),"actual libc directory buffer and FD")
    if row["ret"]<=0:
        if row["ret"]==0:require(args=="80, [], 32768","complete real EOF")
        return []
    out=[];matches=list(DIRENT.finditer(args))
    for m in matches:
        ino,off,size,kind,name=m.groups();require(kind in DT,"actual dtype")
        name=bytes.fromhex(name.replace("\\x",""))
        out.append(dict(name=name,inode=int(ino),offset=int(off),reclen=int(size),dtype=DT[kind]))
    middle=args[len("80, ["):-len("], 32768")]
    require(args.startswith("80, [")and args.endswith("], 32768")and
            middle==", ".join(m[0]for m in matches)and sum(e["reclen"]for e in out)==row["ret"],
            "every complete kernel dirent, no abbreviated array/name or missing bytes")
    return out
def summarize(group,turn,before):
    events=turn["effects"];actual=[];calls=[];opened=False;closed=False
    for row in group:
        op,args,ret,err=row["op"],row["args"],row["ret"],row["errno"]
        if op in("write","writev"):
            fd=int(args.split(",",1)[0]);require(fd not in(1,2,80,96),"observer journal writes stay outside owned namespace descriptors")
            continue
        if op=="openat":
            require(args=='96, "\\x2e", O_RDONLY|O_CLOEXEC|O_DIRECTORY'and not opened,"exact original openat component/flags once")
            require(ret in(-1,80),"actual private stream descriptor")
            calls.append(("open",ret,err));opened=True
        elif op=="fcntl":
            require(args.startswith("80, ")and opened and not closed,"actual owned stream fcntl")
            require(args in("80, F_GETFL","80, F_SETFD, FD_CLOEXEC"),"exact fdopendir setup syscall")
            calls.append(("fcntl",args,ret,err))
        elif op in("fstat","newfstatat"):
            require(args.startswith("80, ")and opened and not closed,"actual owned stream metadata")
            require(ret==0,"actual borrowed directory metadata succeeds")
            root=before["entries"][0]if before["exists"]else turn["binding"]["root_identity"]
            require("st_ino="+str(root["inode"])+","in args,"actual metadata binds the same physical root")
            if before["exists"]:require("st_uid="+str(root["uid"])+","in args and "st_gid="+str(root["gid"])+","in args,"actual metadata ownership")
            calls.append(("stat",ret,err))
        elif op=="getdents64":
            require(opened and not closed,"read actual live DIR")
            chunk=entries(row);actual.extend(chunk);calls.append(("getdents",ret,err,chunk))
        elif op=="close":
            require(args=="80"and opened and not closed,"one close of the owned stream")
            require(ret in(-1,0),"actual close return");closed=True;calls.append(("close",ret,err))
        else:raise ValueError("unlisted syscall inside real fingerprint: "+op)
    require(opened and calls and calls[0][0]=="open","actual original directory open")
    first=events[0];require(first["operation"]==1 and calls[0][1:]==(first["actual_return"],
            first["actual_errno"]if first["actual_return"]<0 else 0),"real open return matches libc borrow")
    closes=[r for r in calls if r[0]=="close"];cleanup=[e for e in events if e["operation"]in(4,5)]
    require(len(closes)==len(cleanup),"all actual owned cleanup effects")
    for syscall,effect in zip(closes,cleanup):
        require(syscall[1:]==(effect["actual_return"],effect["actual_errno"]if effect["actual_return"]<0 else 0),
                "actual close and immediate native errno")
    expected=[]
    for entry in turn["entries"]:
        raw=entry["raw"];expected.append(dict(name=entry["name"],inode=entry["inode"],
            offset=int.from_bytes(raw[8:16],"little",signed=True),reclen=len(raw),dtype=entry["dtype"]))
    require(actual==expected,"every actual kernel dirent equals complete native libc result in returned order")
    readdir_errors=[r[2]for r in calls if r[0]=="getdents"and r[1]<0]
    require(readdir_errors==[e["actual_errno"]for e in events if e["operation"]==3 and e["actual_return"]==0 and e["actual_errno"]],
            "exact real readdir error without invented retries")
    if any(e["operation"]==2 and e["actual_return"]==0 for e in events):
        setup=[r for r in calls if r[0]in("fcntl","stat")]
        require(setup and any(r[0]=="fcntl"and r[-2]==-1 for r in setup),"actual fdopendir failure occurred in owned kernel setup")
    visible=[x for x in actual if x["name"]not in(b".",b"..")]
    if actual:
        root=before["entries"][0];known={bytes.fromhex(r["path_hex"]):r for r in before["entries"][1:]}
        require({x["name"]for x in visible}==set(known) and len(visible)==len(known),"complete actual readable namespace, no missing or duplicated child")
        for entry in visible:
            row=known[entry["name"]]
            require(entry["inode"]==row["inode"]and entry["dtype"]==row["type"]>>12,"actual raw namespace identity/type")
        dots=[x for x in actual if x["name"]==b"."]
        require(len(dots)==1 and dots[0]["inode"]==root["inode"],"actual dot identity")
    return calls
def verify(raw,group_name,cases,processes,turns,paired,streams):
    allrows,signals=parse(raw);pids=[p["pid"]for p in processes]
    require(set(pids)|{processes[0]["parent_pid"]}==set(allrows)and len(set(pids))==3,"only the actual coordinator and three traced implementation processes")
    expected=[(c["case"],si+1)for c in cases for si,_ in enumerate(c["steps"])]
    signatures=[]
    for role,process in zip(("native-observed","native-off","original"),processes):
        groups,outside=split_turns(allrows[process["pid"]],role,expected,streams[role]["stderr"],streams[role]["stdout"])
        sig=[]
        for at,key in enumerate(expected):sig.append(summarize(groups[key],turns[at],paired[at]["before"]))
        closes=[r for r in outside if r["op"]=="close"and r["args"]=="96"]
        require(len(closes)==len(cases)and all(r["ret"]==0 for r in closes),"every borrowed root finally closed by its actual fixture")
        exits=[r for r in outside if r["op"]=="exit_group"];require(exits and exits[-1]["args"]=="0","real successful process exit")
        prctl=[r for r in outside if r["op"]=="prctl"]
        if group_name not in("ordinary","names","wide"):
            require(len(prctl)==2 and all(r["ret"]==0 for r in prctl)and
                    prctl[0]["args"].startswith("PR_SET_NO_NEW_PRIVS, 1,")and
                    prctl[1]["args"].startswith("PR_SET_SECCOMP, SECCOMP_MODE_FILTER,"),
                    "actual kernel NO_NEW_PRIVS and seccomp installation, no synthetic error reply")
        else:require(not prctl,"ordinary process has no injected kernel filter")
        signatures.append(sig)
    require(signatures[0]==signatures[1]==signatures[2],"complete original/native/off syscall effects on the same physical trees")
    return dict(traced_processes=len(allrows),actual_turns=3*len(expected),kernel_effects=sum(map(len,signatures[0])),
                three_actual_signatures_identical=True)
