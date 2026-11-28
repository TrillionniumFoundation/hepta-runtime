"""Pure complete strace decoder and same-operation real-kernel comparison."""
import errno,re,struct
from reader_common import read,require,pin
from read_pairs import exact
CALL=re.compile(r"^(\d+)\s+([A-Za-z0-9_]+)\((.*)\)\s+=\s+(.*)$")
FLAG={"IN_NONBLOCK":2048,"IN_CLOEXEC":524288,"IN_MODIFY":2,"IN_ATTRIB":4,"IN_CLOSE_WRITE":8,
    "IN_MOVED_FROM":64,"IN_MOVED_TO":128,"IN_CREATE":256,"IN_DELETE":512,"IN_DELETE_SELF":1024,
    "IN_MOVE_SELF":2048,"IN_ONLYDIR":16777216}
def number(value):
    value=value.strip();return int(value,16)if value.startswith(("0x","-0x"))else int(value,10)
def arguments(raw):
    rows=[];start=0;depth=0;quoted=False;escape=False
    for i,c in enumerate(raw):
        if quoted:
            if escape:escape=False
            elif c=="\\":escape=True
            elif c=='"':quoted=False
        elif c=='"':quoted=True
        elif c in"([{":depth+=1
        elif c in")]}":depth-=1
        elif c==","and depth==0:rows.append(raw[start:i].strip());start=i+1
        require(depth>=0,"whole syscall argument nesting")
    require(not quoted and depth==0,"complete original syscall arguments")
    if raw.strip():rows.append(raw[start:].strip())
    return rows
def unquote(value):
    require(value.startswith('"')and value.endswith('"'),"whole syscall string")
    value=value[1:-1]
    require(value==""or re.fullmatch(r"(?:\\x[0-9a-f]{2})+",value),"complete unabridged raw pathname")
    return bytes.fromhex(value.replace("\\x",""))
def mask(value):
    parts=value.split("|");require(parts and all(p in FLAG for p in parts),"exact supported original kernel flags")
    return sum(FLAG[p]for p in parts)
def returned(raw):
    if raw=="?":return None,None
    fields=raw.split(None,2);value=number(fields[0]);error=0
    if value==-1:
        require(len(fields)>=2 and fields[1]in errno.__dict__,"complete actual kernel errno")
        error=errno.__dict__[fields[1]];require(type(error)is int and 1<=error<=4095,"actual Linux errno code")
    return value,error
def stat_identity(text,extended=False):
    prefix="stx_"if extended else"st_"
    def field(n):
        m=re.search(r"\b"+prefix+n+r"=([^,}]+)",text);require(m is not None,"complete actual stat field "+n);return m[1]
    ino=number(field("ino"));mode=field("mode");parts=mode.split("|")
    require(len(parts)==2 and parts[0]in("S_IFDIR","S_IFREG"),"whole actual admitted directory/file mode")
    mode_value={"S_IFDIR":0o040000,"S_IFREG":0o100000}[parts[0]]|int(parts[1],8)
    if extended:
        major=number(field("dev_major"));minor=number(field("dev_minor"))
    else:
        match=re.search(r"\bst_dev=makedev\((0x[0-9a-f]+|\d+), (0x[0-9a-f]+|\d+)\)",text)
        require(match is not None,"complete actual native dev_t");major,minor=map(number,match.groups())
    device=(minor&255)|((major&4095)<<8)|((minor&~255)<<12)|((major&~4095)<<32)
    return[device,ino,mode_value]
def rows(path,pid):
    raw=read(path);require(raw.endswith(b"\n"),"all complete physical syscall lines")
    previous=None;count=0
    for line in raw.decode("utf-8").splitlines():
        if line.startswith(" | "):
            require(previous is not None and previous["name"]=="read"and previous["result"]>0 and
                len(line)>=60 and line[0:3]==" | "and line[8:10]=="  ","only full actual read payload rows")
            offset=int(line[3:8],16);field=line[10:59]
            require(re.fullmatch(r"(?:[0-9a-f]{2} | )+",field)is not None,"whole read payload hexdump columns")
            data=bytes.fromhex(field);require(offset==len(previous["data"])and 0<len(data)<=16,"contiguous whole read payload")
            previous["data"]+=data;continue
        m=CALL.fullmatch(line);require(m is not None and int(m[1])==pid,"every syscall belongs to the actual one application PID")
        if previous is not None:
            if previous["name"]=="read"and 32<=number(previous["args"][0])<320 and previous["result"]>0:
                require(len(previous["data"])==previous["result"],"every kernel read byte retained")
            else:require(previous["data"]==b"","no unrelated payload bytes")
            yield previous
        result,error=returned(m[4]);previous=dict(index=count,name=m[2],args=arguments(m[3]),
            result=result,errno=error,data=b"",line=line);count+=1
    require(previous is not None and previous["name"]=="exit_group"and previous["args"]==["0"]and
        previous["result"]is None and previous["data"]==b"","actual complete successful kernel process exit")
    yield previous
def selected(row):
    name=row["name"];a=row["args"];result=row["result"];error=row["errno"]
    base=dict(result=result,errno=error)
    if name=="inotify_init1":
        return dict(op="init",flags=mask(a[0]),**base)
    if name=="inotify_add_watch":
        return dict(op="add",fd=number(a[0]),path=unquote(a[1]).hex(),mask=mask(a[2]),**base)
    if name=="inotify_rm_watch":
        return dict(op="remove",fd=number(a[0]),wd=number(a[1]),**base)
    if name=="read"and 32<=number(a[0])<320:
        return dict(op="read",fd=number(a[0]),capacity=number(a[2]),data=row["data"].hex(),**base)
    if name in("fstat","statx","newfstatat")and a[0]!="AT_FDCWD"and number(a[0])>=32:
        if name=="newfstatat":require(a[1]=='""'and a[-1]=="AT_EMPTY_PATH","actual fd-relative native stat")
        if name=="statx":require(a[1]=='""'and "AT_EMPTY_PATH"in a[2],"actual original File metadata")
        data=a[1]if name=="fstat"else a[-1]if name=="statx"else a[2]
        return dict(op="stat",fd=number(a[0]),identity=stat_identity(data,name=="statx")if result==0 else None,**base)
    if name=="fcntl"and a[1]=="F_DUPFD_CLOEXEC"and number(a[0])>=32:
        require(0<=number(a[2])<=32,"native/original admitted low-descriptor duplication floor")
        return dict(op="clone",fd=number(a[0]),**base)
    if name=="close"and number(a[0])>=32:return dict(op="close",fd=number(a[0]),**base)
    if name=="openat"and result is not None and 32<=result<320:
        return dict(op="open-root",directory=a[0],path=unquote(a[1]).hex(),flags=a[2],**base)
    if name in("dup2","dup3")and number(a[1])>=512:
        require(name=="dup2"or a[2]=="O_CLOEXEC","actual owned root CLOEXEC")
        return dict(op="root-slot",source=number(a[0]),target=number(a[1]),**base)
    if name=="prlimit64"and a[1]=="RLIMIT_NOFILE"and a[2]!="NULL":
        return dict(op="limit",request=a[2],**base)
    return None
def verify(folder,role,commands):
    process=role["report"];pid=process["pid"];all_rows=list(rows(folder/"syscalls.strace",pid))
    markers=[c for c in commands if c["cmd"]=="run"];active=None;turn=0;mark=0;groups={};outside=[]
    output_total=0;input_total=0;seen_exit=0;all_inotify=0
    for row in all_rows:
        n=row["name"];args=row["args"]
        if n=="write"and number(args[0])==2:
            require(number(args[2])==24 and row["result"]==24 and row["errno"]==0 and mark<2*len(markers),
                "one exact syscall per complete operation marker")
            if mark%2==0:
                require(active is None,"no nested actual application operation")
                c=markers[mark//2];active=(c["case"],c["step"]);groups[active]=[]
            else:require(active is not None,"actual paired operation end");active=None
            mark+=1;continue
        if n in("write","writev")and number(args[0])==1:
            require(row["result"]is not None and row["result"]>0 and row["errno"]==0,"complete actual stdout writes")
            output_total+=row["result"]
        if n=="read"and number(args[0])==0:
            require(row["result"]is not None and row["result"]>=0 and row["errno"]==0,"successful complete control input")
            input_total+=row["result"]
        if n=="exit_group":seen_exit+=1
        item=selected(row)
        if item is not None:
            if active is not None:groups[active].append(item)
            else:outside.append(item)
        if n.startswith("inotify_"):
            require(active is not None,"all Watcher kernel calls remain inside the original method turn");all_inotify+=1
    require(active is None and mark==2*len(markers)and list(groups)==[(c["case"],c["step"])for c in markers]
        and seen_exit==1,"all actual source operation intervals and exact EOF")
    require(input_total==process["streams"]["stdin"]["bytes"]and output_total==process["streams"]["stdout"]["bytes"],
        "all complete raw syscall stdin/stdout byte counts")
    return dict(groups=groups,outside=outside,summary=dict(syscalls=len(all_rows),inotify=all_inotify,
        input_bytes=input_total,output_bytes=output_total,trace=process["streams"]["syscalls.strace"]))
def compare(traces,cases):
    for case in cases:
        for step,s in enumerate(case["steps"]):
            key=(case["case"],step);a,b,c=[trace["groups"][key]for trace in traces]
            exact(a,b,"all real native kernel effects unchanged with observer absent")
            # The original Rust implementation uses statx rather than libc fstat;
            # the pure decoder retains and compares its full dev/ino/mode result.
            # Rust's fallback path opens O_LARGEFILE explicitly on x86-64.
            def normalized(rows):
                out=[]
                for row in rows:
                    row=dict(row)
                    if row["op"]=="open-root":row["flags"]=row["flags"].replace("|O_LARGEFILE","")
                    out.append(row)
                return out
            exact(normalized(a),normalized(c),"all source method kernel effects match unchanged original: "+str(key))
    return dict(roles=[t["summary"]for t in traces],operation_intervals=sum(len(c["steps"])for c in cases))
