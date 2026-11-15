"""Actual guarded capture-prepare HIA state corpus and pure complete-byte reader.

Typed completion plans test the HIA state machine without claiming filesystem
execution. The independent OS fixture executes the fixed kernel effects.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,re,stat,struct,sys,time,zlib,gzip
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SOURCE=Path(__file__).resolve()
COMPILER="d3e2c90173cf733e42b299d0c4274df4b593a12f"
INVALID=0xffffffff
CAPACITY=0xfffffffe
PENDING=0xfffffffd
HEADER=128
SCOPE={"original_rust_compared":False,"filesystem_operations_executed":False,
       "async_cancellation_qualified":False,"glibc_thread_cancellation_qualified":False,
       "complete_capture_prepare_qualified":False,"registry_concurrency_qualified":False,
       "production_sequence_identity_qualified":False,"ambient_observations_qualified":False,
       "error_display_qualified":False,"job_construction_qualified":False,
       "production_activated":False,"whole_runtime_replaced":False,"old_stack_removal_qualified":False}
SOURCE_FILES=("native/shell_capture_prepare.hepta","native/shell_capture_prepare_abi.md",
              "native/shell_capture_prepare_reuse.json","native/shell_capture_path.hepta",
              "native/shell_capture_mkdir.hepta","native/shell_capture_file.hepta",
              "scripts/hia_native_shell_capture_prepare_build.py","scripts/hia_native_loader.py",
              "tests/hia_native/shell_capture_prepare_state.py")
ARRAY_NAMES=("input_before","output_before","workspace_before",
             "input_after","output_after","workspace_after")
GUARDS=((b"i"*16,b"I"*16),(b"o"*16,b"O"*16),(b"w"*16,b"W"*16))
MASK=(1<<64)-1
Q=lambda n:struct.pack("<Q",n&MASK)
U=lambda raw,offset=0:struct.unpack_from("<Q",raw,offset)[0]
def need(ok,why):
    if not ok:raise ValueError(why)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def pinned(raw):return {"size":len(raw),"sha256":digest(raw)}
def pairs(rows):
    result={}
    for k,v in rows:
        need(k not in result,"duplicate JSON field");result[k]=v
    return result
def obj(raw):return json.loads(raw,object_pairs_hook=pairs)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def normalized(value):return obj(encoded(value))
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def raw_file(path):
    path=Path(path);before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and not path.is_symlink(),"ordinary evidence file required")
    raw=path.read_bytes();after=path.stat()
    identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mode,x.st_mtime_ns,x.st_ctime_ns)
    need(identity(before)==identity(after) and len(raw)==before.st_size,"evidence changed during read")
    return raw
def pin(path):return pinned(raw_file(path))
def source_pins():return {n:pin(ROOT/n) for n in SOURCE_FILES}
def write_new(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as stream:stream.write(raw)
def load_py(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    previous=sys.dont_write_bytecode
    try:sys.dont_write_bytecode=True;spec.loader.exec_module(module)
    finally:sys.dont_write_bytecode=previous
    return module
def basename(folder,name):
    need(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",name),"native artifact basename")
    return Path(folder)/name


def required(n):return 1792+4*n
def output_required(n):return 384+3*n
def mutate_word(raw,offset,value):return raw[:offset]+Q(value)+raw[offset+8:]
def frame(tmp=b"",present=0,pid=7,cache=0,op=1):
    return b"HSHPPQ01"+b"".join(Q(v) for v in (op,present,pid,len(tmp),cache,0,0))+tmp
def request(spec,op=1):
    return frame(bytes.fromhex(spec["tmp_hex"]),spec["present"],spec["pid"],spec["cache"],op)
def paths(spec):
    tmp=bytes.fromhex(spec["tmp_hex"]) if spec["present"] else b"/tmp"
    directory=tmp+(b"/" if tmp and not tmp.endswith(b"/") else b"")+b"octofs-jobs-"+str(spec["pid"]).encode()
    identifier=str(spec["pid"]).encode()+b"-"+str(spec["sequence"]).encode()
    return directory,identifier,directory+b"/"+identifier+b".stdout.log",directory+b"/"+identifier+b".stderr.log"
def path_response(spec):
    values=paths(spec);body=b"".join(values)
    return b"HSHCPR01"+b"".join(Q(v) for v in (3,80+len(body),0,(spec["sequence"]+1)&MASK,*map(len,values),0))+body
def mk_response(kind,error,cache):
    return b"HSHMKR01"+Q(kind)+Q(error)+Q(cache)
def file_response(operation,kind=0,error=0,token=0):
    return b"HSHCFR01"+Q(48)+Q(operation)+Q(kind)+Q(error)+Q(token)
def spec(name,group="composition",tmp=b"",present=0,pid=7,sequence=9,cache=0,
         mkdir=None,stdout=None,stderr=None,close=0,unlink=0,infra=0):
    if mkdir is None:
        mkdir={"effects":[],"result":[2,0,cache]} if b"\0" in tmp else {"effects":[[1,0,0]],"result":[0,0,cache]}
    return {"name":name,"group":group,"tmp_hex":tmp.hex(),"present":present,"pid":pid,
            "sequence":sequence,"cache":cache,"init_error":infra,"mkdir":mkdir,
            "stdout":stdout if stdout is not None else [[0,9,1]],
            "stderr":stderr if stderr is not None else [[0,10,2]],
            "close_errno":close,"unlink_errno":unlink}
def specifications():
    rows=[]
    def add(group,**fields):
        rows.append(spec(f"{group}-{len(rows)+1:05d}",group,**fields))
    raw_paths=(b"",b"/",b"//",b"///",b".",b"./",b"..",b"a/../b",b"a//b///",
               b"./a/./b/.",b"/tmp/",b"/tmp//",b" white \t\r\n",b"back\\slash",
               b"\xff/\xfe",bytes(range(1,256)),b"/\xff//",b"\0",b"a\0b",b"\xff/\0\xfe")
    pids=(0,1,9,10,2147483648,4294967295)
    sequences=(0,1,9,10,1<<63,MASK)
    for index,tmp in enumerate(raw_paths):
        for pi,pid in enumerate(pids):
            for si,sequence in enumerate(sequences):
                add("raw-path-pid-sequence",tmp=tmp,present=1,pid=pid,sequence=sequence,cache=(index+pi+si)%3)
    for pid in pids:
        for sequence in sequences:
            for cache in range(3):add("absent-tempdir",pid=pid,sequence=sequence,cache=cache)
    errors=tuple(range(1,134))+(255,256,511,512,1023,1024,2047,2048,4094,4095)
    for error in errors:
        effects=[[1,error,0]];final_cache=0
        if error==2:effects*=3
        if error==17:effects=[[1,17,0],[2,2,0],[3,14,0]];final_cache=1
        add("mkdir-failure-no-sequence",mkdir={"effects":effects,"result":[1,error,final_cache]})
        if error!=4:
            add("stdout-failure-no-stderr",stdout=[[error,0,0]])
            add("stderr-failure-preserved",stderr=[[error,0,0]],close=(error+3)%4096,unlink=(error*31)%4096)
        add("close-error-ignored",stderr=[[28,0,0]],close=error,unlink=13)
        add("unlink-error-ignored",stderr=[[28,0,0]],close=4,unlink=error)
    for count in (1,2,3,8,31,64):
        for final_error in (0,1,13,28,4095):
            final=[final_error,9,1] if not final_error else [final_error,0,0]
            out=[[4,0,0]]*count+[final]
            add("stdout-EINTR",stdout=out)
            final=[final_error,10,2] if not final_error else [final_error,0,0]
            add("stderr-EINTR",stderr=[[4,0,0]]*count+[final],close=4,unlink=4)
    for cache in (0,1,2):
        stat_action=4 if cache==2 else 2
        for mode in (0o40755,0o40000,0o100644,0o120777,0,0o177777):
            final_cache=cache or 1
            ok=mode&0o170000==0o40000
            add("existing-kind",cache=cache,mkdir={"effects":[[1,17,0],[stat_action,0,mode]],
                                                "result":[0,0,final_cache] if ok else [1,17,final_cache]})
    add("statx-error-probe",mkdir={"effects":[[1,17,0],[2,2,0],[3,14,0]],"result":[1,17,1]})
    add("statx-unavailable-fallback",mkdir={"effects":[[1,17,0],[2,38,0],[3,38,0],[4,0,0o40755]],"result":[0,0,2]})
    add("statx-probe-unavailable",mkdir={"effects":[[1,17,0],[2,2,0],[3,38,0],[4,0,0o40755]],"result":[0,0,2]})
    add("ancestor-rebuild",tmp=b"new/deep",present=1,mkdir={"effects":[[1,2,0],[1,2,0],[1,0,0],[1,0,0],[1,0,0]],"result":[0,0,0]})
    for fd in (0,1,2,3,7,1024,2147483647):
        for token in (1,2,1<<32,1<<63,MASK):
            second=token-1 if token>1 else MASK
            add("capability-domain",stdout=[[0,fd,token]],stderr=[[0,fd+1 if fd<2147483647 else 0,second]])
    for error in (1,4,11,12,13,28,75,105,4095):
        for cache in range(3):add("allocation-infrastructure",infra=error,cache=cache)
    for size in (383,384,4095,4096,65537):
        add("large-raw-tempdir",tmp=b"x"*size,present=1,mkdir={"effects":[[1,36,0]],"result":[1,36,0]})
    return rows

def steps_for(specification):
    s=specification;steps=[{"phase":1,"error":s["init_error"]}]
    if s["init_error"]:return steps
    mk=s["mkdir"]
    for index in range(len(mk["effects"])+1):
        steps.append({"phase":2,"operation":1 if index==0 else 2,
                      "return":PENDING if index<len(mk["effects"]) else 32,"body":None if index<len(mk["effects"]) else mk_response(*mk["result"])})
        if index<len(mk["effects"]):steps.append({"phase":3,"kernel":mk["effects"][index]})
    if mk["result"][0]:return steps
    steps.extend(({"phase":4},{"phase":5,"return":80,"body":path_response(s)}))
    for role,start in ((3,6),(4,10)):
        attempts=s["stdout"] if role==3 else s["stderr"]
        for index in range(len(attempts)+1):
            final=attempts[-1]
            body=file_response(1,1,final[0],0) if final[0] else file_response(1,0,0,final[2])
            steps.append({"phase":start,"role":role,"operation":1 if index==0 else 2,
                          "return":PENDING if index<len(attempts) else 48,"body":None if index<len(attempts) else body})
            if index<len(attempts):steps.append({"phase":start+1,"role":role,"kernel":[1,*attempts[index]]})
        error,fd,token=attempts[-1]
        if error:
            if role==3:return steps
            steps.extend(({"phase":14,"error":s["close_errno"]},
                          {"phase":15,"role":5,"operation":1,"return":PENDING,"body":None},
                          {"phase":16,"role":5,"kernel":[2,s["unlink_errno"],0,0]},
                          {"phase":15,"role":5,"operation":2,"return":48,
                           "body":file_response(2,1,s["unlink_errno"],0) if s["unlink_errno"] else file_response(2)}))
            return steps
        steps.extend(({"phase":start+2,"role":role,"operation":1,"return":48,"body":file_response(4,0,0,token)},
                      {"phase":start+3,"role":role,"token":token}))
    return steps


class Model:
    """Independent assertion model; never supplies a runtime child request."""
    def __init__(self,s):
        self.spec=s;self.n=len(bytes.fromhex(s["tmp_hex"]));self.phase=1;self.sequence=1
        self.cache=s["cache"];self.observed=False;self.full=False;self.tokens=[0,0]
        self.error=[0,0,0,0];self.values=paths(s)
    def child_frame(self,step):
        p=self.phase;operation=step.get("operation",2 if p in (3,7,11,16) else 1)
        if p in (2,3):
            return b"HSHMKQ01"+Q(operation)+Q(self.spec["cache"] if operation==1 else 0)+Q(len(self.values[0]))+bytes(32)+self.values[0]
        if p==5:
            return b"HSHCPQ01"+Q(3)+Q(self.spec["present"])+Q(self.spec["pid"])+Q(self.spec["sequence"])+Q(self.n)+bytes(16)+bytes.fromhex(self.spec["tmp_hex"])
        if p in (6,7,8,10,11,12,15,16):
            kind=4 if p in (8,12) else 2 if p in (15,16) else 1
            path=b"" if kind==4 else self.values[3 if p in (10,11) else 2]
            return b"HSHCFQ01"+Q(operation)+Q(kind)+Q(len(path))+bytes(32)+path
        return b""
    def action(self):
        return {1:1,2:2,3:3,4:4,5:9,6:5,7:6,8:5,9:7,10:5,11:6,12:5,13:7,14:8,15:5,16:6}.get(self.phase,0)
    def args(self,step):
        action=self.action();n=self.n;wire=self.child_frame(step)
        role=3 if 6<=self.phase<=9 else 4 if 10<=self.phase<=13 else 5
        if action==1:return 512+3*n,1152+10*n,640+n,256+n
        if action==2:return 1024,len(wire),512,0
        if action==5:return role,1024,len(wire),512
        if action==6:return role,0,0,0
        if action==7:return role,self.tokens[role-3],0,0
        if action==8:return self.tokens[0],0,0,0
        if action==9:return 1024,len(wire),1280+n,512+3*n
        return 0,0,0,0
    def work(self,step,*,completion=None,loan=None):
        n=self.n;size=required(n);w=bytearray(size+32);w[size:]=b"\xd3"*32
        wire=self.child_frame(step);lengths=list(map(len,self.values)) if self.full else [len(self.values[0]),0,0,0]
        def put(p,v):struct.pack_into("<Q",w,p,v&MASK)
        w[:8]=b"HSHPPW01"
        vals={8:self.phase,16:self.sequence,24:n,32:size,40:output_required(n),48:self.spec["present"],
              56:self.spec["pid"],64:self.cache,72:int(self.observed),
              80:self.spec["sequence"] if self.observed else 0,
              88:(self.spec["sequence"]+1)&MASK if self.observed else 0,
              96:self.tokens[0],104:self.tokens[1],112:U(wire,8) if wire else 0,
              120:self.error[0],224:self.error[1],232:self.error[2],240:self.error[3],
              248:1280+n,256:lengths[0],264:lengths[1],272:lengths[2],280:lengths[3],
              288:len(wire),296:1152+10*n,304:640+n,312:self.spec["cache"]}
        for p,v in vals.items():put(p,v)
        if self.phase!=17:
            slot=b"HSHPPFX1"+Q(self.sequence)+Q(self.action())+b"".join(Q(v) for v in self.args(step))+bytes(40)
            w[128:224]=slot
        w[1024:1024+len(wire)]=wire
        p=1280+n
        if self.full:
            raw=path_response(self.spec);w[p:p+len(raw)]=raw
        else:w[p+80:p+80+len(self.values[0])]=self.values[0]
        if loan is not None:
            offset,raw=loan;w[offset:offset+len(raw)]=raw
        if completion is not None:
            result,error=completion
            w[184:216]=Q(1)+Q(result)+Q(error)+Q(0)
        return bytes(w)
    def advance(self,step,next_step):
        p=self.phase
        if p==1 and step["error"]:self.error=[2,4,1,step["error"]]
        if p==2 and step["return"]==32:
            kind,error,cache=self.spec["mkdir"]["result"];self.cache=cache
            if kind:self.error=[1,1,kind,error]
        if p==4:self.observed=True
        if p==5:self.full=True
        if p in (6,10) and step["return"]==48:
            error,fd,token=(self.spec["stdout"] if p==6 else self.spec["stderr"])[-1]
            if error:self.error=[1,2 if p==6 else 3,1,error]
            else:self.tokens[0 if p==6 else 1]=token
        if p==14:self.tokens[0]=0
        if next_step is None:
            self.phase=17
            if self.error[0]:self.tokens=[0,0]
        else:self.phase=next_step["phase"];self.sequence=(self.sequence+1)&MASK
    def response(self):
        values=self.values if self.full else (self.values[0],b"",b"",b"")
        payload=b"".join(values)
        return b"HSHPPR01"+b"".join(Q(v) for v in (128+len(payload),*self.error,int(self.observed),
              self.spec["sequence"] if self.observed else 0,(self.spec["sequence"]+1)&MASK if self.observed else 0,
              self.cache,*self.tokens,*map(len,values)))+payload

STREAM_FILES=("entries.jsonl.gz","buffers.bin.gz","requests.bin","responses.bin","case_records.jsonl.gz")
class Entries:
    def __init__(self,folder,modules=None,process=None):
        self.folder=Path(folder);self.modules=modules;self.process=process;self.number=0;self.semantic=0
        self.guards={"input_unchanged":0,"bilateral_boundaries_checked":0,"workspace_tails_unchanged":0,
                     "nonresult_outputs_unchanged":0,"success_tails_unchanged":0,"unchanged_workspace_checks":0,
                     "complete_parent_state_checks":0}
        self.files={};self.underlying=[];self.module_counts={k:0 for k in ("prepare","path","mkdir","file")}
        for name in STREAM_FILES:
            if modules is not None:
                raw=(self.folder/name).open("xb")
                if name.endswith(".gz"):
                    self.underlying.append(raw);self.files[name]=gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=raw,mtime=0)
                else:self.files[name]=raw
            else:self.files[name]=gzip.open(self.folder/name,"rb") if name.endswith(".gz") else (self.folder/name).open("rb")
    def close(self):
        for stream in self.files.values():stream.close()
        for stream in self.underlying:stream.close()
    def read_array(self,size):
        stream=self.files["buffers.bin.gz"];header=stream.read(8)
        need(len(header)==8 and U(header)==size,"complete bounded array record header")
        raw=stream.read(size);need(len(raw)==size,"complete bounded array decoding")
        return raw
    def invoke(self,key,name,category,label,wire,out,work,expected,*,state=None,body=None,unchanged=False,work_extent=None):
        self.number+=1;self.module_counts[key]+=1;caps=(len(wire),len(out),len(work))
        before=[a+v+b for (a,b),v in zip(GUARDS,(wire,out,work))]
        identity={"entry":self.number,"module":key,"case":name,"category":category,"label":label,
                  "capacities":list(caps),"expected_return":expected,"workspace_unchanged":unchanged,
                  "workspace_extent":work_extent,"complete_parent_state":state is not None}
        if self.modules is not None:
            import ctypes
            arrays=[ctypes.create_string_buffer(raw,len(raw)) for raw in before];args=[]
            for buffer,n in zip(arrays,caps):args.extend((ctypes.addressof(buffer)+16,n))
            started=time.time_ns();clock=time.monotonic_ns()
            with self.modules[key]._lock:returned=self.modules[key]._entry(*args)
            elapsed=time.monotonic_ns()-clock;full=before+[a.raw for a in arrays]
            row={**identity,"return_u64":returned,"started_unix_ns":started,"elapsed_ns":elapsed,"pid":os.getpid(),
                 "arrays":{k:pinned(v) for k,v in zip(ARRAY_NAMES,full)}}
            self.files["entries.jsonl.gz"].write(canonical(row))
            for raw in full:self.files["buffers.bin.gz"].write(Q(len(raw))+raw)
        else:
            line=self.files["entries.jsonl.gz"].readline(8193)
            need(bool(line) and len(line)<=8192 and line.endswith(b"\n"),"missing or oversized registered native entry")
            row=obj(line);need(canonical(row)==line,"canonical native entry row")
            need(set(row)==set(identity)|{"return_u64","started_unix_ns","elapsed_ns","pid","arrays"},"exact native entry fields")
            for k,v in identity.items():need(type(row.get(k)) is type(v) and row[k]==v,"registered native entry: "+k)
            full=[self.read_array(n+32) for n in caps+caps]
            need(full[:3]==before,"registered input and initialized arrays")
            need(row["arrays"]=={k:pinned(v) for k,v in zip(ARRAY_NAMES,full)},"complete array pins")
            returned=row["return_u64"]
            if self.process is not None:
                need(row["pid"]==self.process["pid"] and row["elapsed_ns"]<=self.process["elapsed_ns"]
                     and self.process["started_unix_ns"]<=row["started_unix_ns"]<=self.process["finished_unix_ns"],
                     "entry/actual worker process binding")
        need(type(returned) is int and returned==expected,"registered native return: "+name+"/"+label)
        need(type(row.get("pid")) is int and row["pid"]>0 and type(row.get("started_unix_ns")) is int
             and row["started_unix_ns"]>0 and type(row.get("elapsed_ns")) is int and row["elapsed_ns"]>=0,"actual entry timing")
        for n,(a,b),raw in zip(caps,GUARDS,full[3:]):
            need(len(raw)==n+32 and raw[:16]==a and raw[-16:]==b,"bilateral native guard")
        need(full[0]==full[3],"native changed input")
        self.guards["input_unchanged"]+=1;self.guards["bilateral_boundaries_checked"]+=1
        after_out=full[4][16:-16];after_work=full[5][16:-16]
        if work_extent is not None:
            need(work[work_extent:]==after_work[work_extent:],"workspace tail changed")
            self.guards["workspace_tails_unchanged"]+=1
        if returned in (INVALID,CAPACITY,PENDING):
            need(after_out==out,"nonresult changed complete output")
            self.guards["nonresult_outputs_unchanged"]+=1
        else:
            need(body is not None and after_out[:len(body)]==body,"complete registered response bytes")
            need(after_out[len(body):]==out[len(body):],"success output tail changed")
            self.guards["success_tails_unchanged"]+=1
        if unchanged or returned in (INVALID,CAPACITY):
            need(after_work==work,"refusal or ready-zero changed workspace")
            self.guards["unchanged_workspace_checks"]+=1
        if state is not None:
            need(after_work==state,"complete registered parent state")
            self.guards["complete_parent_state_checks"]+=1
        return after_out,after_work
    def record(self,s,first,body,effects):
        self.semantic+=1;wire=request(s)
        req=self.files["requests.bin"];resp=self.files["responses.bin"]
        row={"case_index":self.semantic,"name":s["name"],"group":s["group"],"spec_sha256":digest(canonical(s)),
             "first_entry":first,"last_entry":self.number,"request_offset":req.tell(),"request_bytes":len(wire),
             "request_sha256":digest(wire),"response_offset":resp.tell(),"response_bytes":len(body),
             "response_sha256":digest(body),"effects":effects}
        packet=Q(len(wire))+wire;answer=Q(128)+Q(len(body))+body
        if self.modules is not None:
            req.write(packet);resp.write(answer);self.files["case_records.jsonl.gz"].write(canonical(row))
        else:
            need(req.read(len(packet))==packet,"complete registered semantic request stream")
            need(resp.read(len(answer))==answer,"result stream differs from actual output arrays")
            need(self.files["case_records.jsonl.gz"].read(len(canonical(row)))==canonical(row),"complete registered case record")
    def finish(self):
        if self.modules is None:
            for name,stream in self.files.items():need(stream.read(1)==b"","extra evidence stream bytes: "+name)
        else:
            for stream in self.files.values():stream.flush()


def execute_scenario(entries,s,category="semantic",capture=None):
    n=len(bytes.fromhex(s["tmp_hex"]));wire=request(s);resume=request(s,2)
    model=Model(s);steps=steps_for(s);first=entries.number+1
    output=b"\xa7"*(output_required(n)+32);work=b"\xd3"*(required(n)+32)
    roles={};owned={};effects=[];sequence_calls=0;close_calls=0
    def checkpoint(label,before_wire,before_out,before_work,expected,after_out=None,after_work=None):
        if capture is not None:
            key=s["name"]+"/"+label
            if key not in capture:capture[key]={"wire":before_wire,"output":before_out,"work":before_work,
                "expected":expected,"after_output":after_out,"after_work":after_work,"extent":required(n)}
    initial_work=model.work(steps[0])
    checkpoint("fresh",wire,output,work,PENDING,output,initial_work)
    output,work=entries.invoke("prepare",s["name"],category,"start",wire,output,work,PENDING,
                              state=initial_work,work_extent=required(n))
    for index,step in enumerate(steps):
        phase=step["phase"];need(model.phase==phase and work==model.work(step),"registered phase order")
        label=f"step-{index+1:03d}-phase-{phase:02d}"
        checkpoint(f"p{phase}-pending",resume,output,work,PENDING,output,work)
        output,work=entries.invoke("prepare",s["name"],category,label+"-ready-zero",resume,output,work,
                                  PENDING,state=work,unchanged=True,work_extent=required(n))
        slot=work[128:224];action=U(slot,16);args=struct.unpack_from("<4Q",slot,24)
        need(action==model.action() and args==model.args(step),"registered capability")
        updated=bytearray(work);ret=0;error=0;loan=None;trace={"phase":phase,"action":action,"args":list(args)}
        if action==1:
            if s["init_error"]:error=s["init_error"];ret=(-error)&MASK
            else:roles={1:bytes(128),2:bytes(args[1]),3:bytes(args[2]),4:bytes(args[2]),5:bytes(args[2])}
        elif action in (2,5,9):
            if action==2:role,key,offset,size,dest,cap=2,"mkdir",args[0],args[1],args[2],32
            elif action==5:role,key,offset,size,dest,cap=args[0],"file",args[1],args[2],args[3],48
            else:role,key,offset,size,dest,cap=1,"path",*args
            child_wire=bytes(updated[offset:offset+size]);child_out=bytes(updated[dest:dest+cap])
            need(child_wire==model.child_frame(step),"actual HIA child frame differs from registered call")
            child_extent=128 if key=="path" else 512+10*(len(child_wire)-64+1) if key=="mkdir" else (
                U(roles[role],40) if roles[role][:8]==b"HSHCFW01" else 513+len(child_wire)-64)
            child_body,roles[role]=entries.invoke(key,s["name"],category,label+"-child",
                child_wire,child_out,roles[role],step["return"],body=step["body"],work_extent=child_extent)
            ret=step["return"];copied=child_body+bytes(16) if action==2 else child_body
            updated[dest:dest+len(copied)]=copied;loan=(dest,copied)
            trace.update(role=role,child_return=ret,child_request=pinned(child_wire),
                         child_complete_output=pinned(child_body))
        elif action==3:
            child=bytearray(roles[2]);leaf=child[96:192]
            leaf_action,errno,mode=step["kernel"]
            original_size=len(model.values[0]);borrow=0 if leaf_action==3 else 513+original_size
            need(leaf[:8]==b"HSHMKFX1" and U(leaf,16)==leaf_action and U(leaf,24)==borrow
                 and leaf[48:]==bytes(48),"actual mkdir issued effect domain")
            size=U(leaf,32);path=bytes(child[borrow:borrow+size])
            if leaf_action==3:need(size==0,"NULL statx probe must not borrow a path")
            else:need(size<=original_size and child[borrow+size]==0,"mkdir complete borrowed C string")
            need(U(leaf,40)==(511 if leaf_action==1 else 4095 if leaf_action in (2,3) else 0),"mkdir primitive flags/mode")
            raw=(-errno)&MASK if errno else 0
            child[144:176]=Q(1)+Q(raw)+Q(errno)+Q(mode);roles[2]=bytes(child)
            trace.update(role=2,leaf_action=leaf_action,errno=errno,mode=mode,path=pinned(path))
        elif action==4:
            need(sequence_calls==0,"multiple sequence observations")
            sequence_calls+=1;ret=s["sequence"]
        elif action==6:
            role=args[0];child=bytearray(roles[role]);leaf=child[128:224]
            leaf_action,errno,fd,token=step["kernel"]
            path=model.values[3 if role==4 else 2]
            expected_args=(512,len(path),524865,438) if leaf_action==1 else (512,len(path),0,0)
            need(leaf[:8]==b"HSHCFFX1" and U(leaf,16)==leaf_action
                 and struct.unpack_from("<4Q",leaf,24)==expected_args and leaf[56:]==bytes(40),
                 "actual file issued effect domain")
            need(child[512:513+len(path)]==path+b"\0","complete file borrowed C string")
            raw=(-errno)&MASK if errno else fd
            if leaf_action==1 and not errno:
                need(token!=0 and token not in owned,"new owned token")
                owned[token]={"owner":role,"fd":fd}
            child[184:216]=Q(1)+Q(raw)+Q(errno)+Q(token);roles[role]=bytes(child)
            trace.update(role=role,leaf_action=leaf_action,errno=errno,fd=fd,token=token,path=pinned(path))
        elif action==7:
            role,token,z0,z1=args;child=roles[role]
            need(U(child,8)==4 and U(child,16)==3 and U(child,48)==0 and U(child,56)==0
                 and U(child,80)==token and owned[token]["owner"]==role,"completed TAKE precedes receiver adoption")
            owned[token]["owner"]="prepare"
        elif action==8:
            token=args[0];need(owned[token]["owner"]=="prepare","receiver close lacks custody")
            error=s["close_errno"];ret=(-error)&MASK if error else 0
            del owned[token];close_calls+=1;need(close_calls==1,"duplicate receiver close")
        else:raise ValueError("unknown fixed capability")
        effects.append(trace)
        updated[184:216]=Q(1)+Q(ret)+Q(error)+Q(0);completed=bytes(updated)
        need(completed==model.work(step,completion=(ret,error),loan=loan),"undeclared capability write")
        next_step=steps[index+1] if index+1<len(steps) else None
        model.advance(step,next_step)
        wanted=model.work(next_step or {})
        expected=PENDING if next_step is not None else HEADER
        body=model.response() if expected==HEADER else None
        expected_out=(body+output[len(body):]) if body is not None else output
        checkpoint(f"p{phase}-ready",resume,output,completed,expected,expected_out,wanted)
        if action in (2,5) and ret in (32,48):
            checkpoint(f"p{phase}-final",resume,output,completed,expected,expected_out,wanted)
        output,work=entries.invoke("prepare",s["name"],category,label+"-complete",resume,output,completed,
                                  expected,state=wanted,body=body,work_extent=required(n))
    body=model.response();need(output[:len(body)]==body,"terminal body")
    checkpoint("terminal",resume,output,work,HEADER,output,work)
    output,work=entries.invoke("prepare",s["name"],category,"terminal-repeat",resume,output,work,HEADER,
                              body=body,state=work,unchanged=True,work_extent=required(n))
    if model.error[0]:
        need(not owned and model.tokens==[0,0],"failed continuation retained owned capture")
    else:
        need(set(owned)==set(model.tokens) and len(owned)==2
             and all(v["owner"]=="prepare" for v in owned.values()),"successful capture custody")
    need(sequence_calls==int(model.observed),"late sequence observation count")
    need(close_calls==int(model.error[1]==3),"stderr failure close count")
    if category=="semantic":entries.record(s,first,body,effects)
    return {"capability_calls":len(effects),"typed_kernel_completions":sum(x["action"] in (3,6,8) for x in effects),
            "sequence_observations":sequence_calls,"receiver_closes":close_calls}

def setup_specifications():
    return [
        spec("setup-success"),
        spec("setup-existing",mkdir={"effects":[[1,17,0],[2,0,0o40755]],"result":[0,0,1]}),
        spec("setup-unavailable",mkdir={"effects":[[1,17,0],[2,38,0],[3,38,0],[4,0,0o40755]],"result":[0,0,2]}),
        spec("setup-stderr",stderr=[[28,0,0]],close=4,unlink=13),
        spec("setup-raw",tmp=b"/tmp/raw\xff/",present=1),
        spec("setup-nul",tmp=b"n\0ul",present=1),
        spec("setup-infra",infra=12),
        spec("setup-mkdir",mkdir={"effects":[[1,13,0]],"result":[1,13,0]})]


def controls():
    rows=[]
    def add(name,base="setup-success/p1-pending",changes=(),expected=INVALID,post=None):
        rows.append({"name":name,"base":base,"changes":[list(v) for v in changes],"expected":expected,"post":post})
    fresh="setup-success/fresh"
    for length in range(64):add(f"truncated-request-{length:02d}",fresh,[("trim","wire",length)])
    for offset,values in ((0,(0,)),(8,(0,3,MASK)),(16,(2,MASK)),(24,(1<<32,MASK)),
                          (32,(1,MASK)),(40,(3,MASK)),(48,(1,)),(56,(1,))):
        for value in values:add(f"request-word-{offset}-{value}",fresh,[("word","wire",offset,value)])
    add("absent-with-raw-path","setup-raw/fresh",[("word","wire",16,0)])
    for base in (fresh,"setup-success/p1-pending","setup-success/terminal"):
        label=base.rsplit("/",1)[-1]
        add("output-too-small-"+label,base,[("trim","output",383)],CAPACITY)
        add("workspace-too-small-"+label,base,[("trim","work",1791)],CAPACITY)
    add("resume-uninitialized",fresh,[("word","wire",8,2)])
    add("start-live",changes=[("word","wire",8,1)])
    add("start-terminal","setup-success/terminal",[("word","wire",8,1)])
    for offset,value in ((0,0),(8,0),(8,18),(16,0),(24,1),(32,0),(40,0),(48,1),(56,8),(64,3),
                         (72,1),(80,1),(88,1),(96,1),(104,1),(112,1),(120,1),(224,1),(232,1),
                         (240,1),(248,0),(256,0),(264,1),(272,1),(280,1),(288,1),(296,0),
                         (304,0),(312,1),(320,1),(504,1),(512,1),(552,1),(560,1),(1016,1),
                         (1024,1),(1272,1),(1280,1)):
        add(f"pending-state-word-{offset}-{value}",changes=[("word","work",offset,value)])
    for offset,value in ((128,0),(136,0),(144,2),(152,0),(160,0),(168,0),(176,0),
                         (184,2),(192,1),(200,1),(208,1),(216,1)):
        add(f"issued-slot-{offset}-{value}",changes=[("word","work",offset,value)])
    add("seed-change-after-cache-present","setup-existing/p4-pending",[("word","wire",40,1)])
    add("seed-change-after-cache-unavailable","setup-unavailable/p4-pending",[("word","wire",40,2)])
    add("initial-seed-control-word","setup-existing/p4-pending",[("word","work",312,1)])
    add("terminal-original-seed","setup-existing/terminal",[("word","wire",40,1)])
    add("raw-request-rebind","setup-raw/p1-pending",[("flip","wire",64)])
    add("stored-raw-path","setup-raw/p1-pending",[("flip","work",1370)])
    for offset,value in ((184,2),(192,1),(200,12),(208,1),(216,1)):
        add(f"INIT-completion-{offset}","setup-success/p1-ready",[("word","work",offset,value)])
    for phase in (2,3,4,5,6,7,8,9,10,11,12,13):
        base=f"setup-success/p{phase}-pending"
        for offset in (136,144,152,160,168,176):
            add(f"phase-{phase}-argument-{offset}",base,[("flip","work",offset)])
        add(f"phase-{phase}-auxiliary",base,[("word","work",208,1)])
    for offset,value in ((512,0),(520,3),(528,1),(536,3),(544,1),(552,1),(192,31),(200,5)):
        add(f"mkdir-completion-{offset}","setup-success/p2-final",[("word","work",offset,value)])
    add("NUL-result-falsely-raw","setup-nul/p2-final",[("word","work",520,1),("word","work",528,22)])
    for phase in (6,10):
        for offset,value in ((512,0),(520,47),(528,2),(536,2),(544,1),(552,0),(192,47),(200,5)):
            add(f"create-result-{phase}-{offset}",f"setup-success/p{phase}-final",[("word","work",offset,value)])
    add("stderr-duplicates-stdout-token","setup-success/p10-final",[("word","work",552,1)])
    for phase in (8,12):
        for offset,value in ((528,1),(536,1),(544,4),(552,99),(192,PENDING)):
            add(f"TAKE-completion-{phase}-{offset}",f"setup-success/p{phase}-ready",[("word","work",offset,value)])
    for phase in (9,13):
        for offset,value in ((192,1),(200,5)):
            add(f"adoption-{phase}-{offset}",f"setup-success/p{phase}-ready",[("word","work",offset,value)])
    for offset,value in ((1280,0),(1288,2),(1296,0),(1304,1),(1312,0),(1320,1),(1328,1),(1336,1),(1344,1),(1352,1),
                         (192,79),(200,5)):
        add(f"path-completion-{offset}","setup-success/p5-ready",[("word","work",offset,value)])
    for offset in (1360,1370,1380,1390,1400):
        add(f"path-complete-body-{offset}","setup-success/p5-ready",[("flip","work",offset)])
    for offset,value in ((192,0),(200,4096),(208,1)):
        add(f"close-completion-{offset}","setup-stderr/p14-ready",[("word","work",offset,value)])
    for phase in (14,15,16):
        for offset in (144,152,160,168,176):
            add(f"cleanup-argument-{phase}-{offset}",f"setup-stderr/p{phase}-pending",[("flip","work",offset)])
    for offset,value in ((224,2),(232,0),(240,0)):
        add(f"saved-stderr-{offset}","setup-stderr/p15-pending",[("word","work",offset,value)])
    for offset,value in ((512,0),(520,0),(528,1),(536,2),(544,4096),(552,1)):
        add(f"unlink-completion-{offset}","setup-stderr/p15-final",[("word","work",offset,value)])
    for offset,value in ((8,16),(64,3),(72,0),(80,0),(88,0),(96,0),(104,0),(128,1),(512,1),(1024,1)):
        add(f"terminal-state-{offset}","setup-success/terminal",[("word","work",offset,value)])
    add("exact-private-capacity-start",fresh,[("trim","output",384),("trim","work",1792)],PENDING,"trim")
    add("exact-private-capacity-pending",changes=[("trim","output",384),("trim","work",1792)],expected=PENDING,post="trim")
    add("exact-private-capacity-terminal","setup-success/terminal",[("trim","output",384),("trim","work",1792)],HEADER,"trim")
    add("effect-sequence-wrap","setup-success/p1-ready",
        [("word","work",16,MASK),("word","work",136,MASK)],PENDING,"wrap")
    return rows

def execute_control(entries,item,templates):
    base=templates[item["base"]];buffers={k:base[k] for k in ("wire","output","work")}
    for change in item["changes"]:
        kind,which,*args=change
        if kind=="word":
            offset,value=args;need(offset+8<=len(buffers[which]),"control word out of bounds")
            buffers[which]=mutate_word(buffers[which],offset,value)
        elif kind=="flip":
            offset=args[0];old=buffers[which];need(offset<len(old),"control byte out of bounds")
            buffers[which]=old[:offset]+bytes([old[offset]^1])+old[offset+1:]
        elif kind=="trim":buffers[which]=buffers[which][:args[0]]
        else:raise ValueError("unknown registered control mutation")
    wire,out,work=(buffers[k] for k in ("wire","output","work"))
    expected=item["expected"];body=None;state=work
    if expected not in (INVALID,CAPACITY):
        state=base["after_work"][:len(work)]
        if item["post"]=="wrap":
            state=mutate_word(mutate_word(state,16,0),136,0)
        if expected==HEADER:
            complete=base["after_output"];body=complete[:U(complete,8)]
    entries.invoke("prepare",item["name"],"control",item["base"],wire,out,work,expected,
                   body=body,state=state,unchanged=expected in (INVALID,CAPACITY),
                   work_extent=min(len(work),base["extent"]))
    return {"name":item["name"],"return_u64":expected,"recipe_sha256":digest(canonical(item))}

def scenario_entries(s):
    steps=steps_for(s)
    return 2+2*len(steps)+sum(step["phase"] in (2,5,6,8,10,12,15) for step in steps)
def expected_counts():
    specs=specifications();setup=setup_specifications();checks=controls()
    actual=sum(map(scenario_entries,specs))+sum(map(scenario_entries,setup))+len(checks)
    return {"semantic_cases":len(specs),"control_cases":len(checks),"setup_cases":len(setup),
            "actual_hia_entries":actual,"actual_full_arrays":6*actual}
def exercise(entries):
    groups={};totals={"capability_calls":0,"typed_kernel_completions":0,"sequence_observations":0,"receiver_closes":0}
    for s in specifications():
        got=execute_scenario(entries,s);groups[s["group"]]=groups.get(s["group"],0)+1
        for key in totals:totals[key]+=got[key]
    templates={}
    for s in setup_specifications():execute_scenario(entries,s,"setup",templates)
    checked=[execute_control(entries,c,templates) for c in controls()]
    entries.finish();counts=expected_counts()
    need(entries.semantic==counts["semantic_cases"] and entries.number==counts["actual_hia_entries"],"complete registered coverage")
    return {"counts":counts,"groups":groups,"controls":checked,"guards":entries.guards,
            "module_entries":entries.module_counts,**totals,
            "invalid_refusals":sum(c["return_u64"]==INVALID for c in checked),
            "capacity_refusals":sum(c["return_u64"]==CAPACITY for c in checked),
            "positive_controls":sum(c["return_u64"] not in (INVALID,CAPACITY) for c in checked)}


def admitted(top):
    top=Path(top).resolve(strict=True);raw=raw_file(top);outer=obj(raw)
    need(outer.get("schema")=="hepta.runtime.shell-capture-prepare.v1","prepare TOP schema")
    builder=load_py(ROOT/"scripts/hia_native_shell_capture_prepare_build.py","capture_prepare_state_builder")
    reviewed=builder.read_evidence(top,source_root=ROOT)
    need(reviewed.get("status")=="PASS","prepare strong build evidence")
    tops={"prepare":top}
    for key in ("path","mkdir","file"):
        value=outer.get(key+"_manifest")
        need(type(value) is str and Path(value).is_absolute(),"explicit child TOP path: "+key)
        parent=Path(value).resolve(strict=True)
        need(pin(parent)["sha256"]==outer.get(key+"_manifest_sha256"),"child TOP pin: "+key)
        tops[key]=parent
    selected={};metadata={};members={}
    for key,parent in tops.items():
        meta=obj(raw_file(parent));relative=meta.get("owner_manifest")
        need(type(relative) is str and not Path(relative).is_absolute() and ".." not in Path(relative).parts,"owner manifest relative path")
        owner=parent.parent.parent/relative;module=obj(raw_file(owner))
        need(pin(owner)["sha256"]==meta.get("owner_manifest_sha256"),"owner manifest pin: "+key)
        need(module.get("schema")=="hepta.runtime.native-module.v1"
             and module.get("abi")=="hepta.runtime.borrowed-bytes.linux-x86_64.v1"
             and module.get("target")=="linux-x86_64" and module.get("compiler_commit")==COMPILER,"child ABI/target/compiler")
        files={k:pin(basename(owner.parent,module.get(k))) for k in ("source","image")}
        for kind in files:
            need(files[kind]["sha256"]==module.get(kind+"_sha256")==meta.get(kind+"_sha256"),"current module bytes: "+key+"/"+kind)
        need(files["source"]==pin(ROOT/("native/shell_capture_"+key+".hepta")),"current HIA source differs: "+key)
        selected[key]=owner;metadata[key]=module
        members[key]={"top":pin(parent),"owner_manifest":pin(owner),**files}
    return {"manifest_path":str(top),"manifest":pinned(raw),"modules":members,
            "compiler_commit":COMPILER,"build_evidence":reviewed},selected,metadata,tops

def worker(folder):
    folder=Path(folder).resolve(strict=True)
    loader=load_py(folder/"hia_native_loader.py","hia_capture_prepare_worker_loader")
    modules={}
    try:
        for key in ("prepare","path","mkdir","file"):
            manifest=folder/"modules"/key/"manifest.json"
            modules[key]=loader.NativeModule(manifest,manifest_sha256=pin(manifest)["sha256"])
        boundary=Entries(folder,modules=modules)
        try:result=exercise(boundary)
        finally:boundary.close()
    finally:
        for module in modules.values():module.close()
    observed={"schema":"hepta.runtime.shell-capture-prepare-actual.v1","driver":pin(SOURCE),
              "loader":pin(folder/"hia_native_loader.py"),
              "manifests":{k:pin(folder/"modules"/k/"manifest.json") for k in modules},
              "streams":{n:pin(folder/n) for n in STREAM_FILES},"results":result,**SCOPE}
    write_new(folder/"native-result.json",encoded(observed))
    print(json.dumps({"status":"PASS","counts":result["counts"],"result":pin(folder/"native-result.json")},sort_keys=True))

def artifact_names(metas):
    names={"state_driver.py","hia_native_loader.py","python.bin","supplied-manifest.json",
           "native-result.json","process.json","stdout.bin","stderr.bin",*STREAM_FILES}
    for key,meta in metas.items():
        names.update("modules/"+key+"/"+leaf for leaf in ("manifest.json",meta["source"],meta["image"]))
        if key!="prepare":names.add("parent-"+key+"-manifest.json")
    names.update("sources/"+n for n in SOURCE_FILES)
    return names

def run(top,folder):
    import subprocess
    top=Path(top).resolve(strict=True);folder=Path(folder).resolve()
    native,selected,metas,tops=admitted(top);before=source_pins()
    folder.mkdir(parents=True,exist_ok=False)
    for name in SOURCE_FILES:write_new(folder/"sources"/name,raw_file(ROOT/name))
    write_new(folder/"state_driver.py",raw_file(SOURCE))
    write_new(folder/"hia_native_loader.py",raw_file(ROOT/"scripts/hia_native_loader.py"))
    write_new(folder/"supplied-manifest.json",raw_file(top))
    for key,manifest in selected.items():
        meta=metas[key];where=folder/"modules"/key
        write_new(where/"manifest.json",raw_file(manifest))
        for kind in ("source","image"):write_new(where/meta[kind],raw_file(basename(manifest.parent,meta[kind])))
        if key!="prepare":write_new(folder/("parent-"+key+"-manifest.json"),raw_file(tops[key]))
    python=Path(sys.executable).resolve(strict=True);python_before=pin(python)
    write_new(folder/"python.bin",raw_file(python))
    command=[str(python),"-I","-B",str(folder/"state_driver.py"),"--_execute",str(folder)]
    environment={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"}
    start=time.time_ns();clock=time.monotonic_ns();timed_out=False
    with (folder/"stdout.bin").open("xb") as stdout,(folder/"stderr.bin").open("xb") as stderr:
        child=subprocess.Popen(command,cwd=folder,env=environment,stdout=stdout,stderr=stderr)
        try:child.wait(timeout=180)
        except subprocess.TimeoutExpired:timed_out=True;child.kill();child.wait()
    process={"schema":"hepta.runtime.shell-capture-prepare-process.v1","command":command,"cwd":str(folder),
             "environment":environment,"pid":child.pid,"exit_code":child.returncode,"timed_out":timed_out,
             "timeout_seconds":180,"started_unix_ns":start,"finished_unix_ns":time.time_ns(),
             "elapsed_ns":time.monotonic_ns()-clock,"stdout":pin(folder/"stdout.bin"),"stderr":pin(folder/"stderr.bin"),
             "python":{"path":str(python),"before":python_before,"after":pin(python)}}
    write_new(folder/"process.json",encoded(process))
    need(not timed_out and child.returncode==0 and raw_file(folder/"stderr.bin")==b"","actual capture prepare worker failed")
    need(source_pins()==before,"qualification source changed during execution")
    current,_,_,_=admitted(top);need(current==native,"native build changed during execution")
    actual=obj(raw_file(folder/"native-result.json"))
    report={"schema":"hepta.runtime.shell-capture-prepare-corpus.v1","status":"PASS",
            "recorded_directory":str(folder),"recorded_source_root":str(ROOT),"sources":before,
            "native":native,"counts":actual["results"]["counts"],
            "files":{n:pin(folder/n) for n in sorted(artifact_names(metas))},**SCOPE}
    write_new(folder/"report.json",encoded(report))
    return read_evidence(folder,native_manifest=top)

def read_evidence(folder,native_manifest=None):
    folder=Path(folder).resolve(strict=True);report=obj(raw_file(folder/"report.json"))
    need(report.get("schema")=="hepta.runtime.shell-capture-prepare-corpus.v1" and report.get("status")=="PASS","capture prepare corpus schema/status")
    need(all(report.get(k) is v for k,v in SCOPE.items()),"capture prepare scope overstated")
    need(report.get("sources")==source_pins(),"qualification source changed")
    native,selected,metas,tops=admitted(native_manifest or report["native"]["manifest_path"])
    for key in ("manifest","modules","compiler_commit","build_evidence"):
        need(report["native"].get(key)==native[key],"current native binding: "+key)
    required_files=artifact_names(metas)
    need(type(report.get("files")) is dict and set(report["files"])==required_files,"exact evidence file inventory")
    for name in required_files:need(pin(folder/name)==report["files"][name],"evidence bytes changed: "+name)
    for name in SOURCE_FILES:need(pin(folder/"sources"/name)==report["sources"][name],"retained qualification source: "+name)
    for local,current in (("state_driver.py",SOURCE),("hia_native_loader.py",ROOT/"scripts/hia_native_loader.py")):
        need(pin(folder/local)==pin(current),"actual worker source/cases/loader")
    need(pin(folder/"supplied-manifest.json")==native["manifest"],"retained native TOP")
    for key,meta in metas.items():
        files=native["modules"][key];where=folder/"modules"/key
        need(pin(where/"manifest.json")==files["owner_manifest"],"retained native module manifest")
        for kind in ("source","image"):need(pin(where/meta[kind])==files[kind],"retained native member")
        if key!="prepare":need(pin(folder/("parent-"+key+"-manifest.json"))==files["top"],"retained child TOP")
    process=obj(raw_file(folder/"process.json"));directory=report.get("recorded_directory")
    need(type(directory) is str and Path(directory).is_absolute(),"recorded corpus directory")
    python=process.get("python",{});path=python.get("path")
    need(type(path) is str and Path(path).is_absolute()
         and python.get("before")==python.get("after")==pin(folder/"python.bin"),"actual Python identity")
    command=[path,"-I","-B",str(Path(directory)/"state_driver.py"),"--_execute",directory]
    need(process.get("schema")=="hepta.runtime.shell-capture-prepare-process.v1"
         and process.get("command")==command and process.get("cwd")==directory
         and process.get("environment")=={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"},"actual worker command/context")
    need(type(process.get("exit_code")) is int and process["exit_code"]==0 and process.get("timed_out") is False
         and process.get("timeout_seconds")==180,"actual worker completion")
    need(type(process.get("pid")) is int and process["pid"]>0
         and type(process.get("elapsed_ns")) is int and process["elapsed_ns"]>0
         and type(process.get("started_unix_ns")) is int and type(process.get("finished_unix_ns")) is int
         and process["finished_unix_ns"]>=process["started_unix_ns"],"actual worker timing")
    need(process.get("stdout")==pin(folder/"stdout.bin") and process.get("stderr")==pin(folder/"stderr.bin")
         and raw_file(folder/"stderr.bin")==b"","actual worker complete streams")
    actual=obj(raw_file(folder/"native-result.json"))
    need(actual.get("schema")=="hepta.runtime.shell-capture-prepare-actual.v1"
         and all(actual.get(k) is v for k,v in SCOPE.items()),"actual native result scope")
    for key,name in (("driver","state_driver.py"),("loader","hia_native_loader.py")):
        need(actual.get(key)==pin(folder/name),"native invocation source binding: "+key)
    need(actual.get("manifests")=={k:pin(folder/"modules"/k/"manifest.json") for k in metas},"actual four module binding")
    need(actual.get("streams")=={n:pin(folder/n) for n in STREAM_FILES},"complete native stream binding")
    need(obj(raw_file(folder/"stdout.bin"))=={"status":"PASS","counts":expected_counts(),
                                             "result":pin(folder/"native-result.json")},"actual worker summary")
    boundary=Entries(folder,process=process)
    try:replayed=exercise(boundary)
    finally:boundary.close()
    need(replayed==actual.get("results"),"complete actual corpus results")
    need(report.get("counts")==replayed["counts"]==expected_counts(),"registered actual counts")
    return {"status":"PASS","schema":"hepta.runtime.shell-capture-prepare-review.v1",
            "verification":"complete-byte-replay-with-current-four-native-builds",
            "report_sha256":pin(folder/"report.json")["sha256"],"recorded_directory":directory,
            "counts":expected_counts(),"groups":replayed["groups"],"controls":replayed["controls"],
            "guards":replayed["guards"],"module_entries":replayed["module_entries"],
            "capability_calls":replayed["capability_calls"],"typed_kernel_completions":replayed["typed_kernel_completions"],
            "sequence_observations":replayed["sequence_observations"],"receiver_closes":replayed["receiver_closes"],
            "invalid_refusals":replayed["invalid_refusals"],"capacity_refusals":replayed["capacity_refusals"],
            "positive_controls":replayed["positive_controls"],"native":native,"sources":report["sources"],
            "native_entry_executed":True,"complete_semantic_request_stream":pin(folder/"requests.bin"),
            "complete_semantic_response_stream":pin(folder/"responses.bin"),"current_source_bytes_verified":True,**SCOPE}

def install_read_only_audit():
    # Standard ctypes initialization is disclosed. All project imports and the
    # complete reader run after the hook; native code is never loaded by a reader.
    import ctypes
    import subprocess
    audit={"standard_library_bootstrap":["ctypes","subprocess"],"forbidden_calls":0}
    def deny(event,args):
        forbidden=event.startswith(("ctypes.","subprocess.","socket.")) or event in {
            "os.system","os.fork","os.forkpty","os.posix_spawn","os.spawn","os.exec",
            "os.remove","os.rmdir","os.rename","os.mkdir","os.chmod","os.truncate",
            "os.link","os.symlink","shutil.copyfile"}
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
    if args._execute:worker(args._execute);return
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
                open("capture-prepare-audit-must-not-exist","wb")
            else:open("/proc/self/status","rb")
        except RuntimeError as error:
            need(str(error).startswith("read-only audit blocked: "),"wrong audit refusal")
            print(json.dumps({"status":"AUDIT_REFUSAL","control":args.audit_negative,
                              "error":str(error),"audit":audit},sort_keys=True));return
        raise ValueError("audit negative was not refused")
    if args.verify:result=read_evidence(args.verify,native_manifest=args.native_manifest)
    else:
        if not args.native_manifest or not args.output:parser.error("--native-manifest and --output required")
        if audit:parser.error("read-only audit requires --verify")
        result=run(args.native_manifest,args.output)
    if audit:
        need(audit["forbidden_calls"]==0,"reader attempted forbidden call")
        result["audit"]=audit
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":main()
