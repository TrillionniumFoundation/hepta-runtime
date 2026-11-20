"""Bind every actual native capability to complete unchanged kernel return and memory bytes."""
import struct
from evidence_common import require
SYSCALLS={
 "write":{1:257,6:257,7:257,2:5,3:3,4:None,5:107,8:8,9:16,10:73,11:1,12:74,13:263},
 "publish":{1:257,6:257,2:5,3:3,4:None,5:107,7:74,8:265,9:263,10:264},
 "read":{1:257,2:257,3:257,4:None,5:3,6:5,9:107,11:0,19:8},
 "metadata":{1:5,2:196,3:193,4:93,5:91,6:199,7:190,8:74},
 "entropy":{1:318,2:257,3:5,4:3,5:0,6:None}}
MAGIC={"write":b"HBWTHK01","publish":b"HPUBHK01","read":b"HBRDHK01","metadata":b"HMDTHK01","entropy":b"HENTHK01"}
def duplicates_fd(number,args):
    """Linux x86-64 descriptor duplication, excluding other fcntl commands."""
    return number in(32,33,292)or(number==72 and args[1]in(0,1030))
def matches_phase(call,e):
    phase=call["phase"]
    return phase==dict(magic_hex=MAGIC[e["owner"]].hex(),words=[e["generation"],e["call"],e["sequence"],
        e["operation"],e["fd"],e["a"],e["b"]])
def bind(effects,trace,application_scopes,control_fd):
    calls=[r for r in trace["calls"]if r["scope"]in application_scopes and"exit"in r];used=set();orphans=[];rows=[]
    for e in effects:
        owner=e["owner"];op=e["operation"];number=SYSCALLS[owner][op];fd,a,b=e["fd"],e["a"],e["b"]
        selected=[r for r in calls if r["scope"]==e["application_scope"]and matches_phase(r,e)]
        if number is None:
            require(e["raw_return"]==0 and not e["data"]and not e["request"],"actual orphan append envelope")
            require(not any((r["number"]==3 or duplicates_fd(r["number"],r["args"]))and r["args"][0]==fd for r in selected),"orphan append closed or duplicated its FD")
            require(any(r["number"]==39 and r["exit"]["result"]==trace["start"]["pid"]for r in selected),
                "orphan append actual creator-PID check")
            orphans.append(dict(fd=fd,context=e["context"],generation=e["generation"]));continue
        exact=[r for r in selected if r["number"]==number
            and(number in(107,318)or(owner=="entropy"and op==2)or r["args"][0]==fd)]
        require(len(exact)==1,"one actual native kernel syscall per fixed capability: "+owner+"/"+str(op))
        r=exact[0];require(r["ordinal"]not in used,"one syscall consumed twice");used.add(r["ordinal"])
        require(r["exit"]["result"]==e["raw_return"],"native resume differs from actual kernel return")
        args=r["args"];before=r["input_spans"];after=r["output_spans"];data=b""
        if number==5:data=after["stat"]["raw"]if e["raw_return"]==0 else b""
        elif number==0:
            require(args[2]==a,"actual read request size");data=after["read"]["raw"]if e["raw_return"]>=0 else b""
        elif number==318:
            require(args[1]==fd and args[2]==0,"actual getrandom count/flags")
            data=after["random"]["raw"]if e["raw_return"]>=0 else b""
        elif number==1:
            require(args[2]==a==len(e["request"])and before["write"]["raw"]==e["request"],"complete actual write input")
        elif number==257:
            path=before["path"]["raw"]
            if owner=="entropy":
                require(args[0]&0xffffffff==(-100)&0xffffffff and args[2]==524288 and path==b"/dev/urandom\0",
                    "fixed actual entropy source path/flags")
            else:
                require(path==e["request"],"full actual openat pathname")
                flags=657408
                if owner=="write":flags={1:657408,6:657474,7:657601}[op]
                if owner=="publish":flags=657410 if op==6 else 657408
                if owner=="read":flags=657408
                require(args[2]==flags and args[3]==(0 if owner=="read"else 384),"fixed actual regular open flags/mode")
        elif number==8:
            if owner=="write":require(args[1]==0 and args[2]==a,"actual FileIO append/current seek")
            else:require(args[1]==a and args[2]==0,"actual fingerprint seek")
        elif number==16:
            require(args[1]==0x5401,"actual FileIO isatty ioctl")
            data=after["termios"]["raw"]if e["raw_return"]==0 else b""
        elif number==73:require(args[1]==2,"actual exclusive flock")
        elif number==196:
            require(args[2]==a,"actual flistxattr capacity")
            data=after["attribute-list"]["raw"]if e["raw_return"]>=0 else b""
        elif number==193:
            require(args[3]==a and before["attribute"]["raw"]==e["request"],"actual fgetxattr name/capacity")
            data=after["attribute-value"]["raw"]if e["raw_return"]>=0 else b""
        elif number==93:require(args[1]==a and args[2]==b,"actual metadata owner IDs")
        elif number==91:require(args[1]==a,"actual metadata mode")
        elif number==199:require(before["attribute"]["raw"]==e["request"],"actual attribute removal name")
        elif number==190:
            require(args[3]==b and args[4]==0 and before["attribute"]["raw"]==e["request"][:a+1]
                and before["value"]["raw"]==e["request"][a+1:],"complete actual metadata value/name")
        elif number==263:require(args[2]==0 and before["path"]["raw"]==e["request"],"actual unlink name/flags")
        elif number in(264,265):
            require(args[2]==fd and before["destination"]["raw"]==e["request"][:a]
                and before["source"]["raw"]==e["request"][a:],"actual source/destination publication names")
            if number==265:require(args[4]==0,"actual link no-symlink-follow flags")
        require(data==e["data"],"every native effect reply byte derives from actual stopped-kernel output")
        rows.append(dict(owner=owner,operation=op,syscall=number,kernel_ordinal=r["ordinal"],raw_return=e["raw_return"]))
    semantic=set(v for table in SYSCALLS.values()for v in table.values()if v is not None)
    unowned=[]
    for r in calls:
        if r["ordinal"]in used or r["number"]not in semantic:continue
        fd=r["args"][0]
        if r["number"]==0 and fd in(control_fd,5):continue
        if r["number"]==1 and fd in(1,2,3,4):continue
        unowned.append(dict(ordinal=r["ordinal"],number=r["number"],fd=fd))
    require(not unowned,"unclaimed actual native semantic syscall")
    return dict(bound_effects=rows,orphans=orphans,all_kernel_returns_and_reply_bytes_bound=True,
        unclaimed_semantic_syscalls=unowned)
def fd_history(trace,through=None):
    """Actual opens/closes from the kernel, independent of any HIA or Python ownership ledger."""
    live={};closed=[];failed_close=[]
    for r in trace["calls"]:
        if through is not None and r["ordinal"]>=through:break
        if "exit"not in r:continue
        n=r["number"];a=r["args"];ret=r["exit"]["result"]
        if n in(2,257)and ret>=0:
            name=r["input_spans"]["path"]["raw"][:-1].decode("utf-8","surrogateescape")
            live[ret]=dict(path=name,open_ordinal=r["ordinal"],flags=a[1]if n==2 else a[2])
        elif duplicates_fd(n,a)and ret>=0:
            live[ret]=dict(path="<duplicated-fd-"+str(a[0])+">",open_ordinal=r["ordinal"],flags=None)
        elif n==3:
            if ret==0:
                if a[0]in live:closed.append(dict(fd=a[0],value=live.pop(a[0]),ordinal=r["ordinal"]))
            else:failed_close.append(dict(fd=a[0],result=ret,ordinal=r["ordinal"],live_at_attempt=a[0]in live))
    return dict(live=live,closed=closed,failed_close=failed_close)
