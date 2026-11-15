"""Actual guarded capture-file HIA state corpus and pure complete-byte reader.

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
HEADER=48
SCOPE={"original_rust_compared":False,"filesystem_operations_executed":False,
       "async_cancellation_qualified":False,"glibc_thread_cancellation_qualified":False,
       "capture_prepare_qualified":False,"registry_concurrency_qualified":False,
       "production_activated":False,"whole_runtime_replaced":False,"old_stack_removal_qualified":False}
SOURCE_FILES=("native/shell_capture_file.hepta","native/shell_capture_file_abi.md",
              "native/shell_capture_file_reuse.json","native/shell_capture_path.hepta",
              "scripts/hia_native_shell_capture_file_build.py","scripts/hia_native_loader.py",
              "tests/hia_native/shell_capture_file_state.py")
ARRAY_NAMES=("input_before","output_before","workspace_before",
             "input_after","output_after","workspace_after")
GUARDS=((b"i"*16,b"I"*16),(b"o"*16,b"O"*16),(b"w"*16,b"W"*16))
Q=lambda n:struct.pack("<Q",n)
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
def required(path):return 513+len(path)
def mutate_word(raw,offset,value):return raw[:offset]+Q(value)+raw[offset+8:]


def frame(kind=1,path=b"",op=1):
    return b"HSHCFQ01"+Q(op)+Q(kind)+Q(len(path))+bytes(32)+path
def result(operation,kind=0,error=0,token=0):
    return b"HSHCFR01"+Q(48)+Q(operation)+Q(kind)+Q(error)+Q(token)
def completion(work,error=0,fd=0,token=0):
    raw=fd if error==0 else (-error & ((1<<64)-1))
    return work[:184]+Q(1)+Q(raw)+Q(error)+Q(token)+work[216:]
def operation(kind,path=b"",calls=(),expected=(0,0,0)):
    return {"kind":kind,"path_hex":path.hex(),"completions":[list(c) for c in calls],"result":list(expected)}
def create(path=b"a/b",fd=7,token=23):
    return operation(1,path,[(0,fd,token)],(0,0,token))
def unlink(path=b"a/b",error=0):
    return operation(2,path,[(error,0,0)],(0,0,0) if error==0 else (1,error,0))
def drop(error=0):
    return operation(3,b"",[(error,0,0)],(0,0,0))
def take(token=23):
    return operation(4,b"",(),(0,0,token))
def specifications():
    rows=[]
    def add(group,ops):
        rows.append({"name":f"{group}-{len(rows)+1:05d}","group":group,"operations":ops})
    for error in range(1,4096):
        if error!=4:add("create-non-EINTR-errors",[operation(1,b"a/b",[(error,0,0)],(1,error,0))])
        add("unlink-single-attempt-errors",[unlink(error=error)])
    for error in range(4096):add("drop-ignores-close-result",[create(),drop(error)])
    nul_paths=(b"\0",b"a\0b",b"/\0",b"\0/..",b"prefix/\0/suffix",b"x"*383+b"\0",
               b"x"*384+b"\0",b"\xff/\0\xfe",b"\0"*4097,b"x"*1048577+b"\0")
    for path in nul_paths:
        for kind in (1,2):add("local-NUL-no-syscall",[operation(kind,path,(),(2,0,0))])
    paths=(b"",b"/",b"//",b".",b"./",b"..",b"new/./",b"a/../b",b"a//b///",
           b"./a/./b/.",b"white/ \t\r\n",b"back\\slash",b"\xff/\xfe",b"relative:"+bytes(range(1,256)))
    for path in paths:
        add("raw-path-create-take",[create(path),take()])
        add("raw-path-unlink",[unlink(path)])
    for value in range(1,256):
        path=b"raw/"+bytes([value])+b"X"
        add("all-nonzero-path-bytes-create-drop",[create(path),drop()])
        add("all-nonzero-path-bytes-unlink",[unlink(path,20)])
    for size in (383,384,4095,4096,65537,1048577):
        path=b"x"*size
        add("private-large-path-create-take",[create(path,fd=0,token=(1<<64)-1),take((1<<64)-1)])
        add("private-large-path-unlink",[unlink(path,36)])
    for count in (1,2,3,8,64,257):
        for error in (0,1,2,13,4095):
            calls=[(4,0,0)]*count+[(error,0,23 if error==0 else 0)]
            ops=[operation(1,b"retry/path",calls,(0,0,23) if error==0 else (1,error,0))]
            if error==0:ops.append(drop(4))
            add("create-retries-only-EINTR",ops)
    for fd in (0,1,2,3,7,1024,2147483647):
        for token in (1,2,1<<32,1<<63,(1<<64)-1):
            add("owned-handle-entire-typed-domain",[create(fd=fd,token=token),take(token)])
    return rows

STREAM_FILES=("entries.jsonl.gz","buffers.bin.gz","requests.bin","responses.bin","case_records.jsonl.gz")

class Entries:
    def __init__(self,folder,native=None,process=None):
        self.folder=Path(folder);self.native=native;self.process=process;self.number=0;self.semantic=0
        self.guards={"input_unchanged":0,"bilateral_boundaries_checked":0,"workspace_tails_unchanged":0,
                     "nonresult_outputs_unchanged":0,"success_tails_unchanged":0,"unchanged_workspace_checks":0}
        self.files={};self.underlying=[]
        for name in STREAM_FILES:
            if native is not None:
                raw=(self.folder/name).open("xb")
                if name.endswith(".gz"):
                    self.underlying.append(raw)
                    self.files[name]=gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=raw,mtime=0)
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
    def write_array(self,raw):
        self.files["buffers.bin.gz"].write(Q(len(raw))+raw)
    def invoke(self,name,group,category,step,wire,work,expected,*,outcap=64,unchanged=False,extent=None):
        self.number+=1;caps=(len(wire),outcap,len(work))
        if extent is None:extent=required(wire[64:])
        before=[a+body+b for (a,b),body in zip(GUARDS,(wire,b"\xa7"*outcap,work))]
        identity={"entry":self.number,"case":name,"group":group,"category":category,"step":step,
                  "capacities":list(caps),"expected_return":expected,"workspace_unchanged":unchanged,"workspace_extent":extent}
        if self.native is not None:
            import ctypes
            arrays=[ctypes.create_string_buffer(raw,len(raw)) for raw in before]
            arguments=[]
            for buffer,size in zip(arrays,caps):arguments.extend((ctypes.addressof(buffer)+16,size))
            started=time.time_ns();clock=time.monotonic_ns()
            with self.native._lock:returned=self.native._entry(*arguments)
            elapsed=time.monotonic_ns()-clock;full=before+[buffer.raw for buffer in arrays]
            row={**identity,"return_u64":returned,"started_unix_ns":started,"elapsed_ns":elapsed,"pid":os.getpid(),
                 "arrays":{key:pinned(raw) for key,raw in zip(ARRAY_NAMES,full)}}
            self.files["entries.jsonl.gz"].write(canonical(row))
            for raw in full:self.write_array(raw)
        else:
            line=self.files["entries.jsonl.gz"].readline(8193);need(bool(line) and len(line)<=8192 and line.endswith(b"\n"),"missing or oversized registered native entry")
            row=obj(line);need(canonical(row)==line,"canonical native entry row")
            need(set(row)==set(identity)|{"return_u64","started_unix_ns","elapsed_ns","pid","arrays"},
                 "exact native entry fields")
            for key,value in identity.items():
                need(type(row.get(key)) is type(value) and row[key]==value,"registered native entry: "+key)
            need(all(type(n) is int for n in row["capacities"]),"native capacity scalar types")
            full=[self.read_array(n+32) for n in caps+caps]
            need(full[:3]==before,"registered input and initialized arrays")
            need(row.get("arrays")=={key:pinned(raw) for key,raw in zip(ARRAY_NAMES,full)},"complete array pins")
            returned=row.get("return_u64")
            if self.process is not None:
                need(row.get("pid")==self.process["pid"] and row.get("elapsed_ns",0)<=self.process["elapsed_ns"]
                     and self.process["started_unix_ns"]<=row.get("started_unix_ns",0)<=self.process["finished_unix_ns"],
                     "entry/actual worker process binding")
        need(type(returned) is int and returned in (48,PENDING,INVALID,CAPACITY),"native returned unknown status")
        need(type(row.get("pid")) is int and row["pid"]>0 and type(row.get("started_unix_ns")) is int
             and row["started_unix_ns"]>0 and type(row.get("elapsed_ns")) is int and row["elapsed_ns"]>=0,
             "actual entry timing")
        for n,(a,b),raw in zip(caps,GUARDS,full[3:]):
            need(len(raw)==n+32 and raw[:16]==a and raw[-16:]==b,"bilateral native guard")
        need(full[0]==full[3],"native changed input")
        self.guards["input_unchanged"]+=1;self.guards["bilateral_boundaries_checked"]+=1
        if len(wire)>=64:
            tail=min(len(work),extent)
            need(full[2][16+tail:-16]==full[5][16+tail:-16],"workspace tail changed")
            self.guards["workspace_tails_unchanged"]+=1
        if returned==48:
            output=full[4][16:-16]
            need(len(output)>=HEADER and output[:8]==b"HSHCFR01" and U(output,8)==HEADER,"native result header")
            need(1<=U(output,16)<=4 and U(output,24)<=2,"native result operation/kind")
            if U(output,24)==1:need(1<=U(output,32)<=4095 and U(output,40)==0,"native raw OS error domain")
            else:need(U(output,32)==0,"native non-OS result has raw errno")
            need(full[4][16+HEADER:-16]==full[1][16+HEADER:-16],"success output tail changed")
            body=output[:HEADER];self.guards["success_tails_unchanged"]+=1
        else:
            need(full[4]==full[1],"nonresult changed complete output")
            body=None;self.guards["nonresult_outputs_unchanged"]+=1
        if unchanged or returned in (INVALID,CAPACITY):
            need(full[2]==full[5],"refusal or ready-zero changed workspace")
            self.guards["unchanged_workspace_checks"]+=1
        need(returned==expected,"registered native return: "+name+"/"+step)
        return body,full[5][16:-16]
    def record(self,spec,first,bodies):
        self.semantic+=1
        req=self.files["requests.bin"];resp=self.files["responses.bin"];records=self.files["case_records.jsonl.gz"]
        operations=[]
        for index,(op,body) in enumerate(zip(spec["operations"],bodies)):
            wire=frame(op["kind"],bytes.fromhex(op["path_hex"]))
            operations.append({"operation_index":index+1,"operation":op["kind"],
                "request_offset":req.tell(),"request_bytes":len(wire),"request_sha256":digest(wire),
                "response_offset":resp.tell(),"response_bytes":HEADER,"response_sha256":digest(body)})
            packet=Q(len(wire))+wire;answer=Q(HEADER)+Q(HEADER)+body
            if self.native is not None:req.write(packet);resp.write(answer)
            else:
                need(req.read(len(packet))==packet,"complete registered semantic request stream")
                need(resp.read(len(answer))==answer,"result stream differs from actual output arrays")
        row={"case_index":self.semantic,"name":spec["name"],"group":spec["group"],
             "spec_sha256":digest(canonical(spec)),"first_entry":first,"last_entry":self.number,
             "operations":operations,"typed_effects":sum(len(o["completions"]) for o in spec["operations"])}
        if self.native is not None:records.write(canonical(row))
        else:need(records.readline(8193)==canonical(row),"complete registered case record")
    def finish(self):
        if self.native is None:
            for name,stream in self.files.items():need(stream.read(1)==b"","extra evidence stream bytes: "+name)
        else:
            for stream in self.files.values():stream.flush()

def expected_slot(sequence,kind,path,token=0):
    args=(512,len(path),524865,438) if kind==1 else (512,len(path),0,0) if kind==2 else (token,0,0,0)
    return b"HSHCFFX1"+Q(sequence)+Q(kind)+b"".join(Q(n) for n in args)+bytes(40)
def check_effect(work,sequence,kind,original,token):
    need(work[:8]==b"HSHCFW01" and U(work,8)==kind and U(work,16)==1 and U(work,24)==sequence,
         "registered HIA pending state")
    need(work[128:224]==expected_slot(sequence,kind,original,token),"registered HIA effect arguments")
    need(work[512:513+len(original)]==original+b"\0","complete retained C string")
    need(U(work,48)==0 and U(work,56)==(token if kind==3 else 0),"HIA capability custody at effect issue")
def execute_scenario(entries,spec):
    original=bytes.fromhex(spec["operations"][0]["path_hex"]);extent=required(original)
    work=b"\xd3"*(extent+32);first=entries.number+1;sequence=0;bodies=[];held=0
    for operation_index,op in enumerate(spec["operations"]):
        kind=op["kind"];path=bytes.fromhex(op["path_hex"]);name=spec["name"];group=spec["group"]
        prefix=f"operation-{operation_index+1}"
        body,work=entries.invoke(name,group,"semantic",prefix+"-start",frame(kind,path),work,
                                PENDING if op["completions"] else HEADER,extent=extent)
        for index,(error,fd,token) in enumerate(op["completions"]):
            sequence=(sequence+1)&((1<<64)-1)
            check_effect(work,sequence,kind,original,held)
            _,polled=entries.invoke(name,group,"semantic",prefix+f"-pending-{index}",frame(kind,path,2),
                                    work,PENDING,unchanged=True,extent=extent)
            need(polled==work,"ready-zero poll changed state")
            body,work=entries.invoke(name,group,"semantic",prefix+f"-complete-{index}",frame(kind,path,2),
                                    completion(work,error,fd,token),
                                    PENDING if index+1<len(op["completions"]) else HEADER,extent=extent)
        need(body==result(kind,*op["result"]),"registered semantic result: "+name+"/"+prefix)
        need(work[128:224]==bytes(96),"completed operation retained an effect")
        if kind==1 and op["result"][0]==0:
            held=op["result"][2]
            need(U(work,16)==2 and U(work,48)==held and U(work,56)==0,"CREATE did not retain its capability")
        else:
            need(U(work,16)==3 and U(work,48)==0 and U(work,56)==0,"completed operation retained held custody")
            if kind in (3,4):held=0
        repeated,again=entries.invoke(name,group,"semantic",prefix+"-completed-repeat",frame(kind,path,2),
                                     work,HEADER,unchanged=True,extent=extent)
        need(repeated==body and again==work,"completed operation is not idempotent")
        bodies.append(body)
    entries.record(spec,first,bodies)
def templates(entries):
    path=b"a/b";extent=required(path);fresh=b"\xd3"*(extent+32)
    def invoke(label,wire,work,expected):
        return entries.invoke("setup-"+label,"setup","setup",label,wire,work,expected,extent=extent)
    _,pending=invoke("create-pending",frame(1,path),fresh,PENDING)
    check_effect(pending,1,1,path,0)
    body,held=invoke("create-held",frame(1,path,2),completion(pending,0,7,23),HEADER)
    need(body==result(1,0,0,23),"setup CREATE result")
    _,closing=invoke("drop-pending",frame(3),held,PENDING)
    check_effect(closing,2,3,path,23)
    body,closed=invoke("drop-done",frame(3,b"",2),completion(closing,4),HEADER)
    need(body==result(3),"setup DROP result")
    body,taken=invoke("take-done",frame(4),held,HEADER)
    need(body==result(4,0,0,23),"setup TAKE result")
    _,unlink_pending=invoke("unlink-pending",frame(2,path),fresh,PENDING)
    check_effect(unlink_pending,1,2,path,0)
    body,unlinked=invoke("unlink-done",frame(2,path,2),completion(unlink_pending,4),HEADER)
    need(body==result(2,1,4),"setup UNLINK result")
    body,failed=invoke("create-failed",frame(1,path,2),completion(pending,13),HEADER)
    need(body==result(1,1,13),"setup CREATE error")
    body,nul=invoke("local-NUL",frame(1,b"a\0b"),fresh,HEADER)
    need(body==result(1,2),"setup NUL error")
    return {"create_pending":pending,"held":held,"closing":closing,"closed":closed,"taken":taken,
            "unlink_pending":unlink_pending,"unlinked":unlinked,"failed":failed,"nul":nul}

def controls():
    rows=[]
    def add(name,expected=INVALID,**options):rows.append({"name":name,"expected":expected,**options})
    for size in range(64):add(f"short-header-{size}",wire_hex=frame()[:size].hex())
    add("bad-magic",wire_hex=(b"X"+frame()[1:]).hex())
    for value in (0,3,(1<<64)-1):add(f"bad-entry-operation-{value}",wire_words=[(8,value)])
    for value in (0,5,(1<<64)-1):add(f"bad-file-operation-{value}",wire_words=[(16,value)])
    for offset in (32,40,48,56):add(f"reserved-request-{offset}",wire_words=[(offset,23)])
    for value in (0,2,4,(1<<64)-1):add(f"bad-path-length-{value}",wire_words=[(24,value)])
    add("trailing-frame-byte",wire_hex=(frame(1,b"a/b")+b"x").hex())
    for kind in (3,4):add(f"lifecycle-path-{kind}",wire_hex=frame(kind,b"a/b").hex())
    for cap in (0,1,7,8,15,16,31,32,47):add(f"output-capacity-{cap}",CAPACITY,outcap=cap)
    for cap in (0,1,7,8,127,128,511,512,515):add(f"workspace-capacity-{cap}",CAPACITY,workcap=cap)
    add("fresh-exact-capacity",PENDING,workcap=516,outcap=48,after_words=[(24,1),(16,1)])
    add("fresh-extra-capacity",PENDING,workcap=1024,after_words=[(24,1)])
    for name in ("create_pending","held","closing","closed","taken","unlink_pending","unlinked","failed","nul"):
        add("restart-live-"+name,template=name,wire_hex=frame(1,b"a/b").hex())
    add("changed-resume-path",template="create_pending",wire_hex=frame(1,b"a/c",2).hex())
    add("changed-resume-operation",template="create_pending",wire_hex=frame(2,b"a/b",2).hex())
    for offset,value in ((0,0),(8,0),(8,2),(8,5),(16,0),(16,4),(32,4),(40,0),
                         (48,1),(56,1),(64,1),(72,4),(80,1),(88,0),(88,2),(88,3)):
        add(f"invalid-state-{offset}-{value}",template="create_pending",work_words=[(offset,value)])
    for offset in (96,127,224,511,512,515):
        add(f"invalid-state-byte-{offset}",template="create_pending",work_bytes=[(offset,1)])
    for offset,value in ((128,0),(136,0),(136,2),(144,0),(144,2),(144,4),
                         (152,0),(152,513),(160,2),(168,524864),(176,511),
                         (184,2),(192,1),(200,4),(208,1),(216,1)):
        add(f"invalid-slot-{offset}-{value}",template="create_pending",work_words=[(offset,value)])
    for fd in ((1<<64)-1,2147483648):
        add(f"invalid-create-fd-{fd}",template="create_pending",
            work_words=[(184,1),(192,fd),(208,23)])
    add("missing-create-capability",template="create_pending",work_words=[(184,1),(192,7)])
    add("oversized-errno",template="create_pending",work_words=[(184,1),(192,(-4096)&((1<<64)-1)),(200,4096)])
    add("errno-raw-mismatch",template="create_pending",work_words=[(184,1),(192,(-5)&((1<<64)-1)),(200,4)])
    add("error-has-capability",template="create_pending",
        work_words=[(184,1),(192,(-13)&((1<<64)-1)),(200,13),(208,23)])
    add("create-fd-zero-capability-max",HEADER,template="create_pending",
        work_words=[(184,1),(208,(1<<64)-1)],result_hex=result(1,0,0,(1<<64)-1).hex())
    add("effect-sequence-wrap",PENDING,template="create_pending",
        work_words=[(24,(1<<64)-1),(136,(1<<64)-1),(184,1),(192,(-4)&((1<<64)-1)),(200,4)],
        after_words=[(24,0),(136,0),(184,0),(192,0),(200,0),(208,0)])
    for name,kind in (("create_pending",1),("unlink_pending",2),("closing",3)):
        path=b"a/b" if kind<3 else b""
        add("ready-zero-"+name,PENDING,template=name,wire_hex=frame(kind,path,2).hex(),unchanged=True)
    for offset,value in ((48,0),(56,23),(64,1),(72,4),(80,24),(128,1)):
        add(f"invalid-held-{offset}-{value}",template="held",work_words=[(offset,value)])
    add("DROP-output-capacity-retains-held",CAPACITY,template="held",wire_hex=frame(3).hex(),outcap=47)
    add("TAKE-output-capacity-retains-held",CAPACITY,template="held",wire_hex=frame(4).hex(),outcap=47)
    add("DROP-workspace-capacity-retains-held",CAPACITY,template="held",wire_hex=frame(3).hex(),workcap=515)
    add("TAKE-workspace-capacity-retains-held",CAPACITY,template="held",wire_hex=frame(4).hex(),workcap=515)
    add("valid-DROP",PENDING,template="held",wire_hex=frame(3).hex(),after_words=[(8,3),(48,0),(56,23),(144,3),(152,23)])
    add("valid-TAKE",HEADER,template="held",wire_hex=frame(4).hex(),
        result_hex=result(4,0,0,23).hex(),after_words=[(8,4),(48,0),(56,0)])
    for template in ("create_pending","closing","closed","taken","unlink_pending","unlinked","failed","nul"):
        for kind in (3,4):add(f"invalid-lifecycle-{template}-{kind}",template=template,wire_hex=frame(kind).hex())
    add("caller-token-forbidden",template="held",wire_hex=frame(3).hex(),wire_words=[(32,23)])
    for offset,value in ((152,24),(160,1),(168,1),(176,1),(184,1),(56,0)):
        add(f"invalid-close-{offset}-{value}",template="closing",wire_hex=frame(3,b"",2).hex(),
            work_words=[(offset,value)] if offset!=184 else [(184,1),(192,1)])
    add("close-success-has-capability",template="closing",wire_hex=frame(3,b"",2).hex(),
        work_words=[(184,1),(208,23)])
    add("close-EINTR-ignored",HEADER,template="closing",wire_hex=frame(3,b"",2).hex(),
        work_words=[(184,1),(192,(-4)&((1<<64)-1)),(200,4)],result_hex=result(3).hex(),
        after_words=[(16,3),(48,0),(56,0),(128,0)])
    add("unlink-EINTR-not-retried",HEADER,template="unlink_pending",wire_hex=frame(2,b"a/b",2).hex(),
        work_words=[(184,1),(192,(-4)&((1<<64)-1)),(200,4)],result_hex=result(2,1,4).hex(),
        after_words=[(24,1),(16,3),(128,0)])
    for name,kind,body in (("held",1,result(1,0,0,23)),("closed",3,result(3)),
                           ("taken",4,result(4,0,0,23)),("unlinked",2,result(2,1,4)),
                           ("failed",1,result(1,1,13)),("nul",1,result(1,2))):
        path=b"a\0b" if name=="nul" else b"a/b" if kind<3 else b""
        add("completed-idempotent-"+name,HEADER,template=name,wire_hex=frame(kind,path,2).hex(),
            result_hex=body.hex(),unchanged=True)
    for name,kind,offset,value in (("closed",3,48,23),("closed",3,56,23),("closed",3,72,4),
                                  ("closed",3,80,23),("taken",4,80,0),("failed",1,64,0),
                                  ("unlinked",2,72,0),("nul",1,64,0)):
        path=b"a\0b" if name=="nul" else b"a/b" if kind<3 else b""
        add(f"invalid-completed-{name}-{offset}",template=name,wire_hex=frame(kind,path,2).hex(),
            work_words=[(offset,value)])
    need(len({r["name"] for r in rows})==len(rows),"unique registered controls")
    return rows
def execute_control(entries,spec,prepared):
    wire=frame(1,b"a/b",2 if "template" in spec else 1)
    if "wire_hex" in spec:wire=bytes.fromhex(spec["wire_hex"])
    for offset,value in spec.get("wire_words",[]):wire=mutate_word(wire,offset,value)
    work=prepared[spec["template"]] if "template" in spec else b"\xd3"*(required(b"a/b")+32)
    for offset,value in spec.get("work_words",[]):work=mutate_word(work,offset,value)
    for offset,value in spec.get("work_bytes",[]):work=work[:offset]+bytes([value])+work[offset+1:]
    if "workcap" in spec:
        cap=spec["workcap"];work=(work+b"\xd3"*max(0,cap-len(work)))[:cap]
    body,after=entries.invoke(spec["name"],"control","control","test",wire,work,spec["expected"],
        outcap=spec.get("outcap",64),unchanged=spec.get("unchanged",False),extent=required(b"a/b"))
    if spec["expected"]==HEADER:need(body==bytes.fromhex(spec["result_hex"]),"registered positive control result")
    for offset,value in spec.get("after_words",[]):need(U(after,offset)==value,"registered private state postcondition")
    return {"name":spec["name"],"expected_return":spec["expected"],
            "result":None if body is None else body.hex(),"spec_sha256":digest(canonical(spec))}
def expected_counts():
    specs=specifications();tests=controls()
    calls=sum(2+2*len(op["completions"]) for spec in specs for op in spec["operations"])+9+len(tests)
    return {"semantic_cases":len(specs),"semantic_operations":sum(len(s["operations"]) for s in specs),
            "native_control_cases":len(tests),"setup_entries":9,"actual_native_entries":calls,
            "complete_guarded_buffer_snapshots":calls*6}
def exercise(entries):
    specs=specifications();groups={};typed=0
    for spec in specs:
        execute_scenario(entries,spec);groups[spec["group"]]=groups.get(spec["group"],0)+1
        typed+=sum(len(op["completions"]) for op in spec["operations"])
    prepared=templates(entries);checks=controls()
    observed=[execute_control(entries,spec,prepared) for spec in checks]
    entries.finish();counts=expected_counts()
    need(entries.number==counts["actual_native_entries"] and entries.semantic==counts["semantic_cases"],
         "complete registered entry inventory")
    return {"counts":counts,"groups":groups,"typed_effect_completions":typed,"controls":observed,
            "guards":entries.guards,"invalid_refusals":sum(c["expected"]==INVALID for c in checks),
            "capacity_refusals":sum(c["expected"]==CAPACITY for c in checks),
            "positive_controls":sum(c["expected"] in (HEADER,PENDING) for c in checks)}

def admitted(top):
    top=Path(top).resolve(strict=True);raw=raw_file(top);outer=obj(raw)
    need(outer.get("schema")=="hepta.runtime.shell-capture-file.v1","capture file TOP manifest required")
    builder=load_py(ROOT/"scripts/hia_native_shell_capture_file_build.py","hia_capture_file_build_review")
    reviewed=builder.read_evidence(top,source_root=ROOT)
    need(reviewed.get("status")=="PASS","capture file native build refused")
    relative=outer.get("owner_manifest")
    need(type(relative) is str and relative and not Path(relative).is_absolute() and ".." not in Path(relative).parts,
         "owner manifest relative path")
    selected=top.parent.parent/relative;meta=obj(raw_file(selected))
    need(pin(selected)["sha256"]==outer.get("owner_manifest_sha256"),"owner manifest pin")
    need(meta.get("schema")=="hepta.runtime.native-module.v1"
         and meta.get("abi")=="hepta.runtime.borrowed-bytes.linux-x86_64.v1"
         and meta.get("target")=="linux-x86_64" and meta.get("compiler_commit")==COMPILER,
         "owner ABI/target/compiler")
    members={}
    for key in ("source","image"):
        members[key]=pin(basename(selected.parent,meta.get(key)))
        need(members[key]["sha256"]==meta.get(key+"_sha256")==outer.get(key+"_sha256"),"owner "+key+" bytes")
    need(members["source"]==pin(ROOT/"native/shell_capture_file.hepta"),"current HIA source differs")
    return {"manifest_path":str(top),"manifest":pinned(raw),"owner_manifest":pin(selected),
            "source":members["source"],"image":members["image"],"compiler_commit":COMPILER,
            "build_evidence":reviewed},selected,meta

def worker(folder):
    folder=Path(folder).resolve(strict=True)
    loader=load_py(folder/"hia_native_loader.py","hia_capture_file_worker_loader")
    manifest=folder/"native/manifest.json"
    with loader.NativeModule(manifest,manifest_sha256=pin(manifest)["sha256"]) as native:
        boundary=Entries(folder,native=native)
        try:result=exercise(boundary)
        finally:boundary.close()
    observed={"schema":"hepta.runtime.shell-capture-file-actual.v1",
              "driver":pin(SOURCE),
              "loader":pin(folder/"hia_native_loader.py"),"manifest":pin(manifest),
              "streams":{n:pin(folder/n) for n in STREAM_FILES},"results":result,**SCOPE}
    write_new(folder/"native-result.json",encoded(observed))
    print(json.dumps({"status":"PASS","counts":result["counts"],"result":pin(folder/"native-result.json")},sort_keys=True))

def artifact_names(meta):
    names={"state_driver.py","hia_native_loader.py","python.bin",
           "supplied-manifest.json","native/manifest.json","native/"+meta["source"],"native/"+meta["image"],
           "native-result.json","process.json","stdout.bin","stderr.bin",*STREAM_FILES}
    names.update("sources/"+n for n in SOURCE_FILES)
    return names

def run(top,folder):
    import subprocess
    top=Path(top).resolve(strict=True);folder=Path(folder).resolve()
    native,selected,meta=admitted(top);before=source_pins()
    folder.mkdir(parents=True,exist_ok=False)
    for name in SOURCE_FILES:write_new(folder/"sources"/name,raw_file(ROOT/name))
    write_new(folder/"state_driver.py",raw_file(SOURCE))
    write_new(folder/"hia_native_loader.py",raw_file(ROOT/"scripts/hia_native_loader.py"))
    write_new(folder/"supplied-manifest.json",raw_file(top))
    write_new(folder/"native/manifest.json",raw_file(selected))
    for key in ("source","image"):
        write_new(folder/"native"/meta[key],raw_file(basename(selected.parent,meta[key])))
    python=Path(sys.executable).resolve(strict=True);python_before=pin(python)
    write_new(folder/"python.bin",raw_file(python))
    command=[str(python),"-I","-B",str(folder/"state_driver.py"),"--_execute",str(folder)]
    environment={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"}
    start=time.time_ns();clock=time.monotonic_ns();timed_out=False
    with (folder/"stdout.bin").open("xb") as stdout,(folder/"stderr.bin").open("xb") as stderr:
        child=subprocess.Popen(command,cwd=folder,env=environment,stdout=stdout,stderr=stderr)
        try:child.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out=True;child.kill();child.wait()
    process={"schema":"hepta.runtime.shell-capture-file-process.v1","command":command,"cwd":str(folder),
             "environment":environment,"pid":child.pid,"exit_code":child.returncode,"timed_out":timed_out,
             "timeout_seconds":120,"started_unix_ns":start,"finished_unix_ns":time.time_ns(),
             "elapsed_ns":time.monotonic_ns()-clock,"stdout":pin(folder/"stdout.bin"),"stderr":pin(folder/"stderr.bin"),
             "python":{"path":str(python),"before":python_before,"after":pin(python)}}
    write_new(folder/"process.json",encoded(process))
    need(not timed_out and child.returncode==0 and raw_file(folder/"stderr.bin")==b"","actual capture file worker failed")
    need(source_pins()==before,"qualification source changed during execution")
    current,_,_=admitted(top);need(current==native,"native build changed during execution")
    actual=obj(raw_file(folder/"native-result.json"))
    report={"schema":"hepta.runtime.shell-capture-file-corpus.v1","status":"PASS",
            "recorded_directory":str(folder),"recorded_source_root":str(ROOT),"sources":before,
            "native":native,"counts":actual["results"]["counts"],
            "files":{n:pin(folder/n) for n in sorted(artifact_names(meta))},**SCOPE}
    write_new(folder/"report.json",encoded(report))
    return read_evidence(folder,native_manifest=top)

def read_evidence(folder,native_manifest=None):
    folder=Path(folder).resolve(strict=True);report=obj(raw_file(folder/"report.json"))
    need(report.get("schema")=="hepta.runtime.shell-capture-file-corpus.v1" and report.get("status")=="PASS",
         "capture file corpus schema/status")
    need(all(report.get(k) is v for k,v in SCOPE.items()),"capture file scope overstated")
    need(report.get("sources")==source_pins(),"qualification source changed")
    native,selected,meta=admitted(native_manifest or report["native"]["manifest_path"])
    for key in ("manifest","owner_manifest","source","image","compiler_commit","build_evidence"):
        need(report["native"].get(key)==native[key],"current native binding: "+key)
    required=artifact_names(meta)
    need(type(report.get("files")) is dict and set(report["files"])==required,"exact evidence file inventory")
    for name in required:need(pin(folder/name)==report["files"][name],"evidence bytes changed: "+name)
    for name in SOURCE_FILES:
        need(pin(folder/"sources"/name)==report["sources"][name],"retained qualification source: "+name)
    for local,current in (("state_driver.py",SOURCE),
                          ("hia_native_loader.py",ROOT/"scripts/hia_native_loader.py")):
        need(pin(folder/local)==pin(current),"actual worker source/cases/loader")
    need(pin(folder/"supplied-manifest.json")==native["manifest"]
         and pin(folder/"native/manifest.json")==native["owner_manifest"],"retained native manifests")
    for key in ("source","image"):need(pin(folder/"native"/meta[key])==native[key],"retained native member")
    process=obj(raw_file(folder/"process.json"));directory=report.get("recorded_directory")
    need(type(directory) is str and Path(directory).is_absolute(),"recorded corpus directory")
    python=process.get("python",{});path=python.get("path")
    need(type(path) is str and Path(path).is_absolute()
         and python.get("before")==python.get("after")==pin(folder/"python.bin"),"actual Python identity")
    command=[path,"-I","-B",str(Path(directory)/"state_driver.py"),"--_execute",directory]
    need(process.get("schema")=="hepta.runtime.shell-capture-file-process.v1"
         and process.get("command")==command and process.get("cwd")==directory
         and process.get("environment")=={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"},"actual worker command/context")
    need(type(process.get("exit_code")) is int and process["exit_code"]==0
         and process.get("timed_out") is False and process.get("timeout_seconds")==120,"actual worker completion")
    need(type(process.get("pid")) is int and process["pid"]>0
         and type(process.get("elapsed_ns")) is int and process["elapsed_ns"]>0
         and type(process.get("started_unix_ns")) is int and type(process.get("finished_unix_ns")) is int
         and process["finished_unix_ns"]>=process["started_unix_ns"],"actual worker timing")
    need(process.get("stdout")==pin(folder/"stdout.bin") and process.get("stderr")==pin(folder/"stderr.bin")
         and raw_file(folder/"stderr.bin")==b"","actual worker complete streams")
    actual=obj(raw_file(folder/"native-result.json"))
    need(actual.get("schema")=="hepta.runtime.shell-capture-file-actual.v1"
         and all(actual.get(k) is v for k,v in SCOPE.items()),"actual native result scope")
    for key,name in (("driver","state_driver.py"),("loader","hia_native_loader.py"),("manifest","native/manifest.json")):
        need(actual.get(key)==pin(folder/name),"native invocation source binding: "+key)
    need(actual.get("streams")=={n:pin(folder/n) for n in STREAM_FILES},"complete native stream binding")
    need(obj(raw_file(folder/"stdout.bin"))=={"status":"PASS","counts":expected_counts(),
                                             "result":pin(folder/"native-result.json")},"actual worker summary")
    boundary=Entries(folder,process=process)
    try:replayed=exercise(boundary)
    finally:boundary.close()
    need(replayed==actual.get("results"),"complete actual corpus results")
    need(report.get("counts")==replayed["counts"]==expected_counts(),"registered actual counts")
    checks=controls()
    domains=(sum(s["expected"]==INVALID for s in checks),sum(s["expected"]==CAPACITY for s in checks),
             sum(s["expected"] in (HEADER,PENDING) for s in checks))
    need((replayed["invalid_refusals"],replayed["capacity_refusals"],replayed["positive_controls"])==domains,
         "registered control domains")
    return {"status":"PASS","schema":"hepta.runtime.shell-capture-file-review.v1",
            "verification":"complete-byte-replay-with-current-native-build",
            "report_sha256":pin(folder/"report.json")["sha256"],"recorded_directory":directory,
            "counts":expected_counts(),"groups":replayed["groups"],"typed_effect_completions":replayed["typed_effect_completions"],
            "controls":replayed["controls"],"guards":replayed["guards"],
            "invalid_refusals":domains[0],"capacity_refusals":domains[1],"positive_controls":domains[2],
            "native":native,"sources":report["sources"],"native_entry_executed":True,
            "complete_semantic_request_stream":pin(folder/"requests.bin"),
            "complete_semantic_response_stream":pin(folder/"responses.bin"),
            "current_source_bytes_verified":True,**SCOPE}

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
                open("capture-file-audit-must-not-exist","wb")
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
