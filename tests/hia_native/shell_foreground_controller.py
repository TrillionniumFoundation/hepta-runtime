"""Native HIA foreground controller state cases; capabilities are synthetic.

Complete byte replay never loads code. OS execution, original Rust equivalence
and production routing are separately qualified.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,re,stat,struct,sys,time,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
COMPILER="d3e2c90173cf733e42b299d0c4274df4b593a12f"
PENDING=0xfffffff0
CONTRACT=0xfffffff9
CAPACITY=0xfffffffe
INVALID=0xffffffff
INFRA=0xfffffff8
SCOPE={"original_rust_compared":False,"real_shell_process_executed":False,
       "real_log_io_executed":False,"outcome_native_entry_executed":False,
       "production_activated":False,"whole_runtime_replaced":False,
       "production_shell_execution_qualified":False,"old_stack_removal_qualified":False}
Q=lambda n:struct.pack("<Q",n)
U=lambda b,at=0:struct.unpack_from("<Q",b,at)[0]
MASK=(1<<64)-1
GUARDS=((b"i"*16,b"I"*16),(b"o"*16,b"O"*16),(b"w"*16,b"W"*16))
ARRAYS=("input_before","output_before","workspace_before","input_after","output_after","workspace_after")
def need(value,reason):
    if not value:raise ValueError(reason)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def pinned(raw):return {"size":len(raw),"sha256":digest(raw)}
def pairs(items):
    result={}
    for key,value in items:
        need(key not in result,"duplicate JSON field");result[key]=value
    return result
def obj(raw):return json.loads(raw,object_pairs_hook=pairs)
def raw_file(path):
    path=Path(path);before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and not path.is_symlink(),"ordinary evidence file required")
    raw=path.read_bytes();after=path.stat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after) and len(raw)==before.st_size,"evidence changed while reading")
    return raw
def pin(path):return pinned(raw_file(path))
def put(b,at,value):struct.pack_into("<Q",b,at,value&MASK)
def wire(op=1,command=b":",cwd=b"/tmp",token=1):
    if op!=1:command=cwd=b""
    return b"HSHFGQ01"+struct.pack("<4Q",op,token,len(command),len(cwd))+command+cwd
def process_event(kind=2,seq=1,raw=0,error_kind=0,errno=0,code=0):
    return b"HSHPRR01"+struct.pack("<11Q",kind,1,1,4321,code&MASK,raw,error_kind,errno,seq,int(kind==3),int(kind in (2,4))*2+int(kind in (3,4)))
def outcome(text=b"projected result",kind=0):
    return b"HSHOUR01"+struct.pack("<4Q",kind,len(text),0,0)+text
def loan(wait=(0,0),stdout=b"raw stdout",stderr=b"raw stderr"):
    return b"HSHOUT01"+struct.pack("<13Q",1,wait[0],wait[1],0,0,0,0,0,0,len(stdout),len(stderr),0,0)+stdout+stderr
def io_descriptor(kind=1,body=None):
    n=len(body) if body is not None else 0
    return b"HSHOID01"+struct.pack("<7Q",kind,1,4096 if kind==1 else 0,n if kind==1 else 0,0,0,0)

class Boundary:
    def __init__(self,native=None,replay=None,arrays=None):
        self.native=native;self.replay=replay;self.raw_arrays=arrays
        self.records=[];self.array_records=[];self.session_count=0;self.case="";self.category=""
    def session(self,output_capacity=96,workspace_capacity=8192,output_fill=0xa7,workspace_fill=0):
        self.session_count+=1
        return Session(self,self.session_count,output_capacity,workspace_capacity,output_fill,workspace_fill)

class Session:
    def __init__(self,boundary,number,outcap,workcap,outfill,workfill):
        self.boundary=boundary;self.number=number
        self.out=bytearray([outfill])*outcap;self.work=bytearray([workfill])*workcap
    def invoke(self,request):
        b=self.boundary;caps=(len(request),len(self.out),len(self.work))
        before=[g[0]+v+g[1] for g,v in zip(GUARDS,(request,bytes(self.out),bytes(self.work)))]
        number=len(b.records)+1
        identity={"entry":number,"session":self.number,"case":b.case,"category":b.category,"capacities":list(caps)}
        if b.native is not None:
            import ctypes
            arrays=[ctypes.create_string_buffer(v,len(v)) for v in before]
            started=time.time_ns();clock=time.monotonic_ns();arguments=[]
            for array,n in zip(arrays,caps):arguments.extend((ctypes.addressof(array)+16,n))
            with b.native._lock:returned=b.native._entry(*arguments)
            after=[array.raw for array in arrays];full=before+after
            row={**identity,"return_u64":returned,"started_unix_ns":started,
                 "elapsed_ns":time.monotonic_ns()-clock,"pid":os.getpid(),
                 "arrays":{name:pinned(raw) for name,raw in zip(ARRAYS,full)}}
        else:
            need(number<=len(b.replay),"unrecorded controller entry")
            row=b.replay[number-1];full=b.raw_arrays[number-1]
            for key,value in identity.items():need(row.get(key)==value,"registered entry identity: "+key)
            need(full[:3]==before,"registered input/completion/prior buffer differs")
            need(row.get("arrays")=={name:pinned(raw) for name,raw in zip(ARRAYS,full)},"complete array binding")
            returned=row["return_u64"];after=full[3:]
        need(type(returned) is int and 0<=returned<=0xffffffff,"dirty controller return")
        for n,g,v in zip(caps,GUARDS,after):
            need(len(v)==n+32 and v[:16]==g[0] and v[-16:]==g[1],"bilateral controller guard")
        need(after[0]==before[0],"controller changed input")
        if returned==64:
            need(caps[1]>=64 and after[1][80:-16]==before[1][80:-16],"publication tail")
            d=after[1][16:80]
            need(d[:8]==b"HSHFGD01" and U(d,8)>0 and U(d,16)==1 and U(d,24) in (1,2) and U(d,48) in (1,2,3) and U(d,56)==0,"descriptor shape")
        else:
            need(returned in (0,PENDING,CONTRACT,CAPACITY,INVALID,INFRA),"unknown return")
            need(after[1]==before[1],"pending/refusal/retire changed output")
        need(type(row.get("pid")) is int and row["pid"]>0 and type(row.get("started_unix_ns")) is int and row["started_unix_ns"]>0 and type(row.get("elapsed_ns")) is int and row["elapsed_ns"]>=0,"actual entry timing")
        self.out[:]=after[1][16:-16];self.work[:]=after[2][16:-16]
        if returned==PENDING:
            words=struct.unpack_from("<12Q",self.work,256)
            need(self.work[256:264]==b"HSHFGFX1" and words[1]>0 and 1<=words[2]<=13 and words[6:]==(0,0,0,0,0,0),"issued capability")
        b.records.append(row);b.array_records.append(full)
        return returned

class Scenario:
    def __init__(self,boundary,name,*,process=None,io=None,wait=(0,0),command=b":",cwd=b"/tmp",
                 process_delays=None,io_delays=None,hooks=(),after_promotion_cancel=False,
                 cache=1,outcomes=None,category="semantic"):
        boundary.case=name;boundary.category=category
        self.boundary=boundary;self.name=name;self.session=boundary.session()
        self.command=command;self.cwd=cwd;self.wait=wait
        self.loan=loan(wait);self.body=outcome()
        self.process=list([(1,PENDING,None),(2,96,process_event()),(2,0,None)] if process is None else process)
        self.io=list([(1,PENDING,None),(2,PENDING,None),(2,64,io_descriptor(1,self.loan)),(2,0,None)] if io is None else io)
        self.outcomes=list([(40,self.body)] if outcomes is None else outcomes)
        self.process_at=self.io_at=self.outcome_at=0
        self.jobs={};self.next_job=1;self.dispatch_count={"p":0,"i":0}
        self.delay_lists={"p":process_delays or [],"i":io_delays or []}
        self.hooks=list(hooks);self.seen={};self.done_hooks=set();self.current_sequence=0
        self.after_promotion_cancel=after_promotion_cancel;self.promotion_cancel_sent=False
        self.cache=cache;self.events=[];self.calls=[];self.actions=[];self.growth=[]
        self.start=len(boundary.records)+1
        self.returned=self.session.invoke(wire(command=command,cwd=cwd))
    def capability(self):
        need(self.returned==PENDING,"expected pending controller capability")
        return struct.unpack_from("<6Q",self.session.work,256)
    def drive_one(self):
        if self.returned==64:
            data=bytes(self.session.out[:64]);source,offset,n,kind=struct.unpack_from("<4Q",data,24)
            if source==1:
                need(offset<=len(self.session.work) and n<=len(self.session.work)-offset,"workspace loan")
                body=bytes(self.session.work[offset:offset+n])
            else:
                body=self.body;need(offset==0 and n==len(body),"complete outcome extent")
            if kind==1:need(body==self.body,"forwarded outcome bytes")
            elif kind==2:need(len(body)==96 and body[:8]==b"HSHPRR01","process observation bytes")
            else:need(body==b"HSHFGC01"+struct.pack("<3Q",1,1,0),"cancel acknowledgement bytes")
            self.events.append({"kind":kind,"body_hex":body.hex(),"entry":len(self.boundary.records)})
            op=2
            if self.after_promotion_cancel and kind==2 and U(body,8)==3 and not self.promotion_cancel_sent:
                op=3;self.promotion_cancel_sent=True
            self.returned=self.session.invoke(wire(op));return
        magic,seq,action,a,b,c=self.capability()
        if seq!=self.current_sequence:
            self.current_sequence=seq;self.seen[action]=self.seen.get(action,0)+1
            self.actions.append((action,len(self.boundary.records),a,b,c))
        for i,(wanted,occurrence,op) in enumerate(self.hooks):
            if i not in self.done_hooks and action==wanted and self.seen[action]==occurrence:
                self.done_hooks.add(i)
                need(self.session.invoke(wire(op))==PENDING,"control during pending capability")
        work=self.session.work;r=0
        if action==13:r=96
        elif action==1:
            need(a==1 and b==65536+4*(len(self.command)+len(self.cwd))+16*96 and c==8192,"HIA checked capacities")
            struct.pack_into("<4Q",work,640,b,c,4096,128)
        elif action==2:
            need(not any(job["channel"]=="p" for job in self.jobs.values()),"process f0 needs a completed effect")
            request=bytes(work[a:a+b])
            need(c==1024 and request[:8]==b"HSHPRQ01" and U(request,16)==1,"process borrowed request")
            op=U(request,8)
            if op==1:need(request[40:]==self.command+self.cwd and U(request,24)==len(self.command) and U(request,32)==len(self.cwd),"unchanged process start bytes")
            else:need(len(request)==40 and request[24:]==bytes(16),"canonical process control")
            need(self.process_at<len(self.process),"unexpected process call")
            expected,r,message=self.process[self.process_at];self.process_at+=1
            need(op==expected,"process operation order")
            if message is not None:work[c:c+96]=message
            self.calls.append(("p",op,r,len(self.boundary.records),message.hex() if message else None))
        elif action==5:
            request=bytes(work[a:a+b])
            need(a==512 and b==40 and c==1152 and request[:8]==b"HSHOIQ01" and U(request,16)==1 and (U(request,24),U(request,32))==self.wait,"wait result loaned to IO")
            need(self.io_at<len(self.io),"unexpected IO call")
            expected,r,message=self.io[self.io_at];self.io_at+=1
            need(U(request,8)==expected,"IO operation order")
            if message is not None:work[c:c+64]=message
            put(work,648,max(8192,4096+len(self.loan)))
            self.calls.append(("i",expected,r,len(self.boundary.records),message.hex() if message else None))
        elif action in (3,7):
            channel="p" if action==3 else "i"
            need((a,b,c)==(0,0,0),"dispatch arguments")
            index=self.dispatch_count[channel];self.dispatch_count[channel]+=1
            delays=self.delay_lists[channel][index] if index<len(self.delay_lists[channel]) else [1]
            r=self.next_job;self.next_job+=1;self.jobs[r]={"channel":channel,"ready":list(delays)}
        elif action in (4,8):
            channel="p" if action==4 else "i"
            need(a in self.jobs and self.jobs[a]["channel"]==channel and b==c==0,"owned job polling")
            ready=self.jobs[a]["ready"];r=ready.pop(0) if len(ready)>1 else ready[0]
            if r==1:del self.jobs[a]
        elif action==6:need((a,b,c)==(0,0,0),"Unknown statx seed")
        elif action==9:need((a,b,c)==(0,0,0),"cache snapshot");r=self.cache
        elif action==10:
            need((a,b,c)==(4096,len(self.loan),704),"complete IO-to-outcome span")
            need(self.outcome_at<len(self.outcomes),"unexpected outcome call")
            r,message=self.outcomes[self.outcome_at];self.outcome_at+=1
            if message is not None:self.body=message;work[c:c+40]=message[:40]
            self.calls.append(("o",1,r,len(self.boundary.records),None))
        elif action==11:
            need(b==c==0 and a>=8192 and a&(a-1)==0,"HIA capacity growth")
            r=a;self.growth.append(a)
        elif action==12:
            need((a==0 or a in self.jobs) and (b==0 or b in self.jobs) and c==0,"activity owned jobs")
        else:raise ValueError("unknown synthetic capability")
        put(work,312,r);put(work,320,0);put(work,328,0);put(work,336,1)
        self.returned=self.session.invoke(wire(2))
    def until(self,action,occurrence=1):
        for _ in range(500):
            if self.returned==PENDING:
                _,seq,current,a,b,c=self.capability()
                seen=self.seen.get(current,0)+(seq!=self.current_sequence)
                if current==action and seen==occurrence:return self
            need(self.returned in (64,PENDING),"stopped before selected capability")
            self.drive_one()
        raise ValueError("controller prefix did not terminate")
    def finish(self):
        for _ in range(500):
            if self.returned==0:break
            need(self.returned in (64,PENDING),"controller scenario refusal "+self.name+": "+hex(self.returned))
            self.drive_one()
        else:raise ValueError("controller did not retire")
        need(self.process_at==len(self.process) and self.io_at==len(self.io) and self.outcome_at==len(self.outcomes),"incomplete capability plan: "+self.name)
        need(len(self.done_hooks)==len(self.hooks) and not self.jobs,"unconsumed controls/jobs")
        fg=[i for i,row in enumerate(self.calls) if row[0]=="p" and row[2]==96 and row[4] and U(bytes.fromhex(row[4]),8)==2]
        if fg:
            index=fg[0]
            need(index+1<len(self.calls) and self.calls[index+1][:2]==("i",1),"kind2 immediately calls IO")
            call_entry=self.calls[index][3]
            later_process=[x[3] for x in self.calls[index+1:] if x[0]=="p"]
            io_dispatch=[entry for action,entry,*_ in self.actions if action==7 and entry>call_entry]
            need(len(io_dispatch)>=2 and (not later_process or io_dispatch[1]<later_process[0]),"stdout task starts before quiet process work")
        return {"name":self.name,"first_entry":self.start,"last_entry":len(self.boundary.records),
                "events":self.events,"calls":self.calls,"growth":self.growth,
                "final_statx_cache":U(self.session.work,152)}

def exercise(boundary):
    semantic=[];controls=[]
    def case(name,**kwargs):
        s=Scenario(boundary,name,**kwargs);result=s.finish();semantic.append(result);return result
    def basic_io(wait=(0,0),cancel=False):
        if cancel:return [(1,PENDING,None),(2,PENDING,None),(3,PENDING,None),(2,64,io_descriptor(2)),(2,0,None)]
        return [(1,PENDING,None),(2,PENDING,None),(2,64,io_descriptor(1,loan(wait))),(2,0,None)]
    case("foreground-success")
    for name,raw in (("foreground-signal",9),("foreground-u32-high",0xffffffff)):
        case(name,process=[(1,PENDING,None),(2,96,process_event(raw=raw,code=-1)),(2,0,None)],wait=(0,raw),io=basic_io((0,raw)))
    for name,errno in (("wait-errno-zero",0),("wait-errno-eintr",4),("wait-errno-echild",10)):
        case(name,process=[(1,PENDING,None),(2,96,process_event(error_kind=1,errno=errno,code=-1)),(2,0,None)],wait=(2,errno),io=basic_io((2,errno)))
    case("raw-unix-cwd",cwd=b"/tmp/\xff.")
    case("unicode-command",command="printf '\u03bb\U0001f642'".encode())
    case("cache-unavailable",cache=2)
    case("cache-unknown",cache=0)
    r=case("outcome-capacity-retry",outcomes=[(CAPACITY,None),(CAPACITY,None),(40,outcome())])
    need(r["growth"]==[8192,16384],"registered outcome growth")
    for name,hook in (("cancel-io-blocked",(12,1,3)),("cancel-before-first-open",(6,1,3))):
        r=case(name,io=basic_io(cancel=True),io_delays=[[1],[0,1]],hooks=[hook],outcomes=[])
        ack=[e for e in r["events"] if e["kind"]==3]
        need(len(ack)==1 and not any(e["kind"]==1 for e in r["events"]),"cancel publishes no outcome")
        final=[c[3] for c in r["calls"] if c[0]=="i" and c[2]==64]
        need(ack[0]["entry"]<final[0],"cancel ACK precedes detached IO completion")
    r=case("cancel-before-process",process=[(1,PENDING,None),(3,PENDING,None),(2,96,process_event(kind=5,code=-1)),(2,0,None)],io=[],outcomes=[],process_delays=[[0,1]],hooks=[(12,1,3)])
    need(len(r["events"])==1 and U(bytes.fromhex(r["events"][0]["body_hex"]),8)==5,"process cancel observation")
    r=case("cancel-after-final-io",hooks=[(9,1,3)])
    need([e["kind"] for e in r["events"]]==[1],"synchronous outcome tail committed")
    case("shutdown-foreground",process=[(1,PENDING,None),(4,PENDING,None),(2,96,process_event(kind=6,seq=1,code=-1)),(2,96,process_event(seq=2,raw=9,code=-1)),(2,0,None)],wait=(0,9),io=basic_io((0,9)),process_delays=[[0,1]],hooks=[(12,1,4)])
    case("promotion-cancel-retains-child",process=[(1,PENDING,None),(2,96,process_event(kind=3,seq=1,code=-1)),(2,PENDING,None),(2,96,process_event(kind=4,seq=2,raw=1792,code=7)),(2,0,None)],io=[],outcomes=[],after_promotion_cancel=True)
    case("spawn-error-observation",process=[(1,PENDING,None),(2,96,process_event(kind=1,error_kind=1,errno=2,code=-1)),(2,0,None)],io=[],outcomes=[])
    case("nul-spawn-observation",command=b"printf\x00x",process=[(1,PENDING,None),(2,96,process_event(kind=1,error_kind=2,code=-1)),(2,0,None)],io=[],outcomes=[])
    r=case("outcome-before-quiet-reap",process=[(1,PENDING,None),(2,96,process_event(error_kind=1,errno=4,code=-1)),(2,PENDING,None),(2,0,None)],wait=(2,4),io=basic_io((2,4)),process_delays=[[1],[0]*20+[1]])
    ready=[e["entry"] for e in r["events"] if e["kind"]==1][0]
    retired=[c[3] for c in r["calls"] if c[0]=="p" and c[2]==0][0]
    need(ready<retired,"outcome cannot wait for quiet retirement")
    def control(name,request=None,expected=INVALID,outcap=96,workcap=8192,workfill=0):
        boundary.case=name;boundary.category="control";start=len(boundary.records)+1
        session=boundary.session(outcap,workcap,0xa7,workfill)
        returned=session.invoke(wire() if request is None else request)
        need(returned==expected,"registered refusal "+name+": "+hex(returned))
        controls.append({"name":name,"expected":expected,"first_entry":start,"last_entry":len(boundary.records)})
    original=wire()
    for n in (0,1,7,8,16,24,32,39):control("short-frame-"+str(n),original[:n])
    control("magic",b"BADFGQ01"+original[8:])
    for value in (0,5,MASK):
        raw=bytearray(original);put(raw,8,value);control("operation-"+str(value),bytes(raw))
    raw=bytearray(original);put(raw,16,0);control("token-zero",bytes(raw))
    for at in (24,32):
        raw=bytearray(original);put(raw,at,MASK);control("length-overflow-"+str(at),bytes(raw))
    control("trailing-byte",original+b"x")
    for raw in (b"\xff",b"\xc0\x80",b"\xed\xa0\x80",b"\xf4\x90\x80\x80",b"\xe2\x82"):
        control("invalid-command-utf8-"+raw.hex(),wire(command=raw))
    for op in (2,3,4):
        control("fresh-operation-"+str(op),wire(op),expected=INVALID)
        raw=bytearray(original);put(raw,8,op);control("control-with-payload-"+str(op),bytes(raw))
    for cap in (0,1,63):control("output-capacity-"+str(cap),expected=CAPACITY,outcap=cap)
    for cap in (0,1,8191):control("workspace-capacity-"+str(cap),expected=CAPACITY,workcap=cap)
    control("invalid-before-capacity",b"",outcap=0,workcap=0)
    control("dirty-state",expected=CONTRACT,workfill=1)
    control("start-frame-capacity",wire(command=b"x"*5000),expected=CAPACITY)
    for name,request,expected in (
        ("repeat-admitted-start",wire(),PENDING),
        ("repeat-pending-advance",wire(2),PENDING),
        ("changed-admitted-start",wire(command=b"printf x"),CONTRACT),
        ("changed-capture-token",wire(2,token=2),CONTRACT),
        ("invalid-repeated-command",wire(command=b"\xff"),INVALID),
    ):
        boundary.case=name;boundary.category="control";start=len(boundary.records)+1
        session=boundary.session()
        need(session.invoke(wire())==PENDING,"initial pending binding control")
        before=bytes(session.work)
        returned=session.invoke(request)
        need(returned==expected,"registered repeated-entry control: "+name)
        if expected==PENDING:need(bytes(session.work)==before,"repeat reissued/changed pending effect")
        controls.append({"name":name,"expected":expected,"first_entry":start,"last_entry":len(boundary.records)})
    def prefix_control(name,action,mutate,expected=CONTRACT,occurrence=1):
        start=len(boundary.records)+1
        s=Scenario(boundary,name,category="control");s.until(action,occurrence)
        mutate(s);returned=s.session.invoke(wire(2))
        need(returned==expected,"registered prefix refusal "+name+": "+hex(returned))
        controls.append({"name":name,"expected":expected,"first_entry":start,"last_entry":len(boundary.records)})
    for offset,value in ((256,0),(264,0),(272,0),(280,1),(288,1),(296,1),(304,1),(312,1),(320,1),(328,1),(336,2),(344,1)):
        prefix_control("pending-slot-"+str(offset),13,lambda s,a=offset,v=value:put(s.session.work,a,v))
    def completed(s,result=0,errno=0):
        put(s.session.work,312,result);put(s.session.work,320,errno);put(s.session.work,336,1)
    prefix_control("completion-errno-range",13,lambda s:completed(s,0,4096))
    prefix_control("completion-result-with-errno",13,lambda s:completed(s,1,1))
    prefix_control("context-too-small",13,lambda s:completed(s,0))
    prefix_control("context-overflow",13,lambda s:completed(s,MASK),INFRA)
    prefix_control("bridge-allocation-error",13,lambda s:completed(s,0,12),INFRA)
    prefix_control("process-retired-before-event",2,lambda s:completed(s,0))
    prefix_control("unknown-process-return",2,lambda s:completed(s,1234))
    prefix_control("dispatch-job-zero",3,lambda s:completed(s,0))
    prefix_control("poll-readiness-invalid",4,lambda s:completed(s,2))
    for label,offset,value in (("magic",1024,0),("token",1040,2),("sequence",1096,2),("kind",1032,7),("wait-kind",1080,2),("raw-status",1072,1<<32),("ok-errno",1088,1),("errno-carrier",1088,1<<31)):
        def change(s,a=offset,v=value,label=label):
            s.session.work[1024:1120]=process_event(error_kind=1 if label=="errno-carrier" else 0)
            put(s.session.work,a,v);completed(s,96)
        prefix_control("process-event-"+label,2,change,occurrence=2)
    for label,offset,value in (("magic",1152,0),("token",1168,2),("kind",1160,3),("offset",1176,4097),("short",1184,111),("oversized",1184,8192),("reserved",1192,1)):
        def change(s,a=offset,v=value):
            s.session.work[1152:1216]=io_descriptor(1,s.loan);put(s.session.work,a,v);completed(s,64)
        prefix_control("io-descriptor-"+label,5,change,occurrence=3)
    prefix_control("io-retired-before-descriptor",5,lambda s:completed(s,0))
    prefix_control("statx-cache-invalid",9,lambda s:completed(s,3))
    for label,offset,value in (("magic",704,0),("kind",712,2),("extent",720,4096),("uri-present",728,1),("uri-length",736,1)):
        def change(s,a=offset,v=value):
            s.session.work[704:744]=outcome()[:40];put(s.session.work,a,v);completed(s,40)
        prefix_control("outcome-header-"+label,10,change)
    return {"semantic":semantic,"controls":controls,
            "counts":{"semantic_cases":len(semantic),"native_control_cases":len(controls),
                      "actual_native_entries":len(boundary.records),
                      "complete_guarded_buffer_snapshots":len(boundary.records)*6}}

SOURCE=Path(__file__).resolve()
SOURCE_FILES=("tests/hia_native/shell_foreground_controller.py",
              "native/shell_foreground_controller.hepta",
              "native/shell_foreground_controller_abi.md",
              "native/shell_gate.hepta","scripts/hia_native_loader.py",
              "scripts/hia_native_shell_foreground_build.py")
EXPECTED_COUNTS={"semantic_cases":20,"native_control_cases":84,
                 "actual_native_entries":810,"complete_guarded_buffer_snapshots":4860}
def normalized(value):return obj(json.dumps(value,sort_keys=True))
def source_pins():return {name:pin(ROOT/name) for name in SOURCE_FILES}
def write_json(path,value):
    with Path(path).open("x",encoding="utf-8") as stream:
        json.dump(value,stream,sort_keys=True,indent=2);stream.write("\n")
def copy_file(source,destination):
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open("xb") as stream:stream.write(raw_file(source))
def load_py(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    previous=sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode=True;spec.loader.exec_module(module)
    finally:sys.dont_write_bytecode=previous
    return module
def basename(directory,name):
    need(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",name),"artifact basename")
    return Path(directory)/name

def admitted(top):
    top=Path(top).resolve(strict=True);raw=raw_file(top);outer=obj(raw)
    need(outer.get("schema")=="hepta.runtime.shell-foreground.v1","combined foreground manifest required")
    build=load_py(ROOT/"scripts/hia_native_shell_foreground_build.py","hia_foreground_state_build")
    reviewed=build.read_evidence(top,source_root=ROOT)
    need(reviewed.get("status")=="PASS","combined native build admission")
    relative=outer.get("controller_manifest")
    need(type(relative) is str and relative and not Path(relative).is_absolute() and ".." not in Path(relative).parts,"controller manifest relative path")
    selected=top.parent.parent/relative;metadata=obj(raw_file(selected))
    need(pin(selected)["sha256"]==outer.get("controller_manifest_sha256"),"controller manifest pin")
    need(metadata.get("schema")=="hepta.runtime.native-module.v1" and metadata.get("abi")=="hepta.runtime.borrowed-bytes.linux-x86_64.v1" and metadata.get("target")=="linux-x86_64" and metadata.get("compiler_commit")==COMPILER,"controller native ABI/compiler")
    members={}
    for key in ("source","image"):
        path=basename(selected.parent,metadata.get(key));members[key]=pin(path)
        need(members[key]["sha256"]==metadata.get(key+"_sha256")==outer.get("controller_"+key+"_sha256"),"combined controller "+key+" binding")
    need(members["source"]==pin(ROOT/"native/shell_foreground_controller.hepta"),"current controller source")
    return {"manifest_path":str(top),"manifest":pinned(raw),"controller_manifest":pin(selected),
            "source":members["source"],"image":members["image"],"compiler_commit":COMPILER,
            "build_evidence":reviewed},selected,metadata

def encode_arrays(path,records):
    with Path(path).open("xb") as stream:
        for arrays in records:
            for raw in arrays:
                compressed=zlib.compress(raw,1)
                stream.write(struct.pack("<QQ",len(raw),len(compressed))+compressed)

def decode_arrays(path,entries):
    result=[]
    with Path(path).open("rb") as stream:
        for entry in entries:
            caps=entry.get("capacities")
            need(type(caps) is list and len(caps)==3 and all(type(n) is int and 0<=n<=8192 for n in caps),"registered array capacity")
            arrays=[]
            for n in caps+caps:
                header=stream.read(16);need(len(header)==16,"array record header")
                size,encoded=struct.unpack("<QQ",header)
                need(size==n+32 and 0<encoded<=size+64,"complete guarded array extent")
                raw=stream.read(encoded);need(len(raw)==encoded,"array bytes truncated")
                decoder=zlib.decompressobj();decoded=decoder.decompress(raw,size+1)
                need(len(decoded)==size and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,"bounded complete array decoding")
                arrays.append(decoded)
            result.append(arrays)
        need(stream.read(1)==b"","extra complete array record")
    return result

def worker(folder):
    folder=Path(folder).resolve(strict=True)
    loader=load_py(folder/"hia_native_loader.py","hia_foreground_worker_loader")
    manifest=folder/"native/manifest.json"
    with loader.NativeModule(manifest,manifest_sha256=pin(manifest)["sha256"]) as native:
        boundary=Boundary(native=native)
        results=normalized(exercise(boundary))
    need(results["counts"]==EXPECTED_COUNTS,"registered actual state counts")
    with (folder/"entries.jsonl").open("x",encoding="utf-8") as stream:
        for row in boundary.records:stream.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n")
    encode_arrays(folder/"buffers.bin",boundary.array_records)
    result={"schema":"hepta.runtime.shell-foreground-controller-actual.v1",
            "driver":pin(SOURCE),"loader":pin(folder/"hia_native_loader.py"),
            "manifest":pin(manifest),"results":results,
            "entries":pin(folder/"entries.jsonl"),"buffers":pin(folder/"buffers.bin"),**SCOPE}
    write_json(folder/"native-result.json",result)
    print(json.dumps({"status":"PASS","counts":results["counts"],"result":pin(folder/"native-result.json")},sort_keys=True))

def run(top,folder):
    import subprocess
    top=Path(top).resolve(strict=True);folder=Path(folder).resolve()
    native,selected,metadata=admitted(top)
    before=source_pins();folder.mkdir(parents=True,exist_ok=False)
    for name in SOURCE_FILES:copy_file(ROOT/name,folder/"sources"/name)
    copy_file(SOURCE,folder/"state_driver.py")
    copy_file(ROOT/"scripts/hia_native_loader.py",folder/"hia_native_loader.py")
    copy_file(top,folder/"supplied-manifest.json")
    copy_file(selected,folder/"native/manifest.json")
    for key in ("source","image"):copy_file(basename(selected.parent,metadata[key]),folder/"native"/metadata[key])
    python=Path(sys.executable).resolve(strict=True)
    python_before=pin(python);copy_file(python,folder/"python.bin")
    command=[str(python),"-I","-B",str(folder/"state_driver.py"),"--_execute",str(folder)]
    environment={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"}
    start=time.time_ns();clock=time.monotonic_ns();timed_out=False
    with (folder/"stdout.bin").open("xb") as stdout,(folder/"stderr.bin").open("xb") as stderr:
        child=subprocess.Popen(command,cwd=folder,env=environment,stdout=stdout,stderr=stderr)
        try:child.wait(timeout=60)
        except subprocess.TimeoutExpired:
            timed_out=True;child.kill();child.wait()
    process={"schema":"hepta.runtime.shell-foreground-state-process.v1","command":command,"cwd":str(folder),
             "environment":environment,"pid":child.pid,"exit_code":child.returncode,"timed_out":timed_out,
             "timeout_seconds":60,"started_unix_ns":start,"finished_unix_ns":time.time_ns(),
             "elapsed_ns":time.monotonic_ns()-clock,"stdout":pin(folder/"stdout.bin"),"stderr":pin(folder/"stderr.bin"),
             "python":{"path":str(python),"before":python_before,"after":pin(python)}}
    write_json(folder/"process.json",process)
    need(not timed_out and child.returncode==0 and raw_file(folder/"stderr.bin")==b"","actual native state worker failed")
    need(source_pins()==before,"state source changed during execution")
    current,_,_=admitted(top);need(current==native,"native build changed during execution")
    actual=obj(raw_file(folder/"native-result.json"))
    files=["state_driver.py","hia_native_loader.py","python.bin","supplied-manifest.json",
           "native/manifest.json","native/"+metadata["source"],"native/"+metadata["image"],
           "entries.jsonl","buffers.bin","native-result.json","process.json","stdout.bin","stderr.bin"]
    files+=["sources/"+name for name in SOURCE_FILES]
    report={"schema":"hepta.runtime.shell-foreground-controller-corpus.v1","status":"PASS",
            "recorded_directory":str(folder),"recorded_source_root":str(ROOT),
            "sources":before,"native":native,"counts":actual["results"]["counts"],
            "files":{name:pin(folder/name) for name in files},**SCOPE}
    write_json(folder/"report.json",report)
    return read_evidence(folder,native_manifest=top)

def read_evidence(folder,native_manifest=None):
    folder=Path(folder).resolve(strict=True);report=obj(raw_file(folder/"report.json"))
    need(report.get("schema")=="hepta.runtime.shell-foreground-controller-corpus.v1" and report.get("status")=="PASS","controller corpus schema/status")
    need(all(report.get(k) is v for k,v in SCOPE.items()),"controller scope overstated")
    need(report.get("sources")==source_pins(),"controller qualification source changed")
    native,selected,metadata=admitted(native_manifest or report["native"]["manifest_path"])
    for key in ("manifest","controller_manifest","source","image","compiler_commit","build_evidence"):
        need(report["native"].get(key)==native[key],"current combined native binding: "+key)
    needed={"state_driver.py","hia_native_loader.py","python.bin","supplied-manifest.json",
            "native/manifest.json","native/"+metadata["source"],"native/"+metadata["image"],
            "entries.jsonl","buffers.bin","native-result.json","process.json","stdout.bin","stderr.bin"}
    needed.update("sources/"+name for name in SOURCE_FILES)
    need(type(report.get("files")) is dict and set(report["files"])==needed,"exact state evidence inventory")
    for name in needed:need(pin(folder/name)==report["files"][name],"evidence bytes changed: "+name)
    for name in SOURCE_FILES:need(pin(folder/"sources"/name)==report["sources"][name],"retained qualification source")
    need(pin(folder/"state_driver.py")==pin(SOURCE) and pin(folder/"hia_native_loader.py")==pin(ROOT/"scripts/hia_native_loader.py"),"actual worker source/loader")
    need(pin(folder/"supplied-manifest.json")==native["manifest"] and pin(folder/"native/manifest.json")==native["controller_manifest"],"retained native manifests")
    for key in ("source","image"):need(pin(folder/"native"/metadata[key])==native[key],"retained native member")
    process=obj(raw_file(folder/"process.json"));directory=report.get("recorded_directory")
    need(type(directory) is str and Path(directory).is_absolute(),"recorded corpus directory")
    python=process.get("python",{});path=python.get("path")
    need(type(path) is str and Path(path).is_absolute() and python.get("before")==python.get("after")==pin(folder/"python.bin"),"actual Python identity")
    command=[path,"-I","-B",str(Path(directory)/"state_driver.py"),"--_execute",directory]
    need(process.get("schema")=="hepta.runtime.shell-foreground-state-process.v1" and process.get("command")==command and process.get("cwd")==directory and process.get("environment")=={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"},"actual worker command/context")
    need(type(process.get("exit_code")) is int and process["exit_code"]==0 and process.get("timed_out") is False and process.get("timeout_seconds")==60,"actual worker completion")
    need(type(process.get("pid")) is int and process["pid"]>0 and type(process.get("elapsed_ns")) is int and process["elapsed_ns"]>0 and type(process.get("started_unix_ns")) is int and type(process.get("finished_unix_ns")) is int and process["finished_unix_ns"]>=process["started_unix_ns"],"actual worker timing")
    need(process.get("stdout")==pin(folder/"stdout.bin") and process.get("stderr")==pin(folder/"stderr.bin") and raw_file(folder/"stderr.bin")==b"","actual worker complete streams")
    actual=obj(raw_file(folder/"native-result.json"))
    need(actual.get("schema")=="hepta.runtime.shell-foreground-controller-actual.v1" and all(actual.get(k) is v for k,v in SCOPE.items()),"actual native result scope")
    for key,name in (("driver","state_driver.py"),("loader","hia_native_loader.py"),("manifest","native/manifest.json"),("entries","entries.jsonl"),("buffers","buffers.bin")):
        need(actual.get(key)==pin(folder/name),"actual native input/output binding: "+key)
    summary=obj(raw_file(folder/"stdout.bin"))
    need(summary=={"status":"PASS","counts":EXPECTED_COUNTS,"result":pin(folder/"native-result.json")},"actual worker summary")
    entries=[]
    for line in raw_file(folder/"entries.jsonl").splitlines(keepends=True):
        row=obj(line)
        need((json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode()==line,"canonical entry row")
        need(row.get("pid")==process["pid"] and row.get("elapsed_ns",0)<=process["elapsed_ns"],"entry actual process binding")
        entries.append(row)
    need(len(entries)==EXPECTED_COUNTS["actual_native_entries"],"complete registered entry inventory")
    arrays=decode_arrays(folder/"buffers.bin",entries)
    boundary=Boundary(replay=entries,arrays=arrays);replayed=normalized(exercise(boundary))
    need(len(boundary.records)==len(entries),"unconsumed native entries")
    need(replayed==actual.get("results"),"complete registered controller state cases")
    need(report.get("counts")==replayed["counts"]==EXPECTED_COUNTS,"controller state counts")
    positive=sum(c["expected"]==PENDING for c in replayed["controls"])
    return {"status":"PASS","schema":"hepta.runtime.shell-foreground-controller-review.v1",
            "verification":"complete-byte-state-replay-with-current-combined-native-build",
            "recorded_directory":directory,"report_sha256":pin(folder/"report.json")["sha256"],
            "counts":EXPECTED_COUNTS,"positive_transport_controls":positive,
            "refusal_controls":len(replayed["controls"])-positive,
            "control_names":[c["name"] for c in replayed["controls"]],
            "native":native,"current_source_bytes_verified":True,
            "native_entry_executed":True,"synthetic_capability_completions":True,
            "guards":{"complete_guarded_buffer_snapshots":len(entries)*6,
                      "input_unchanged":len(entries),"bilateral_boundaries_checked":len(entries),
                      "pending_refusal_retire_outputs_unchanged":sum(e["return_u64"]!=64 for e in entries),
                      "success_tails_unchanged":sum(e["return_u64"]==64 for e in entries)},
            "sources":report["sources"],**SCOPE}

def install_read_only_audit():
    # Existing frozen component readers import standard ctypes. Bootstrap that
    # library before the gate; no project module or qualification call is run.
    import ctypes
    import subprocess
    audit={"standard_library_bootstrap":["ctypes","subprocess"],"forbidden_calls":0}
    def deny(event,args):
        forbidden=event.startswith(("ctypes.","subprocess.","socket.")) or event in {
            "os.system","os.fork","os.forkpty","os.posix_spawn","os.spawn","os.exec",
            "os.remove","os.rmdir","os.rename","os.mkdir","os.chmod","os.truncate","os.link","os.symlink","shutil.copyfile"}
        if event=="open":
            path=args[0];flags=args[2] if len(args)>2 and type(args[2]) is int else 0
            mode=args[1] if len(args)>1 else None
            forbidden=forbidden or (isinstance(path,(str,bytes)) and os.fsdecode(path).startswith("/proc"))
            forbidden=forbidden or bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            forbidden=forbidden or (isinstance(mode,str) and any(c in mode for c in "wax+"))
        if forbidden:
            audit["forbidden_calls"]+=1
            raise RuntimeError("read-only audit blocked: "+event)
    sys.addaudithook(deny)
    return audit

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-manifest",type=Path)
    parser.add_argument("--output",type=Path)
    parser.add_argument("--verify",type=Path)
    parser.add_argument("--audit-read-only",action="store_true")
    parser.add_argument("--audit-negative",choices=("ffi","process","write","proc"))
    parser.add_argument("--_execute",type=Path)
    args=parser.parse_args()
    if args._execute:
        worker(args._execute);return
    audit=install_read_only_audit() if args.audit_read_only or args.audit_negative else None
    if args.audit_negative:
        try:
            if args.audit_negative=="ffi":
                import ctypes
                ctypes.CDLL(None)
            elif args.audit_negative=="process":
                import subprocess
                subprocess.run([sys.executable,"-c","pass"],check=True)
            elif args.audit_negative=="write":
                open("controller-audit-must-not-exist","wb")
            else:open("/proc/self/status","rb")
        except RuntimeError as error:
            need(str(error).startswith("read-only audit blocked: "),"wrong audit refusal")
            print(json.dumps({"status":"AUDIT_REFUSAL","control":args.audit_negative,
                              "error":str(error),"audit":audit},sort_keys=True));return
        raise ValueError("audit negative was not refused")
    if args.verify:result=read_evidence(args.verify,args.native_manifest)
    else:
        if not args.native_manifest or not args.output:parser.error("--native-manifest and --output required")
        if audit:parser.error("read-only audit requires --verify")
        result=run(args.native_manifest,args.output)
    if audit:
        need(audit["forbidden_calls"]==0,"reader attempted forbidden call")
        result["audit"]=audit
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":main()
