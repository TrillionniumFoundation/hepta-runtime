"""Actual guarded HIA mkdir state corpus and pure complete-byte reader.

Typed completion plans test the HIA state machine without claiming filesystem
execution. The independent OS fixture executes the fixed kernel effects.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,re,stat,struct,sys,time,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SOURCE=Path(__file__).resolve()
COMPILER="d3e2c90173cf733e42b299d0c4274df4b593a12f"
INVALID=0xffffffff
CAPACITY=0xfffffffe
PENDING=0xfffffffd
HEADER=32
SCOPE={"original_rust_compared":False,"filesystem_operations_executed":False,
       "global_atomic_statx_cache_qualified":False,"async_cancellation_qualified":False,
       "capture_prepare_qualified":False,"registry_concurrency_qualified":False,
       "production_activated":False,"whole_runtime_replaced":False,"old_stack_removal_qualified":False}
SOURCE_FILES=("native/shell_capture_mkdir.hepta","native/shell_capture_mkdir_abi.md",
              "native/shell_capture_mkdir_reuse.json","native/shell_capture_path.hepta",
              "scripts/hia_native_shell_capture_mkdir_build.py","scripts/hia_native_loader.py",
              "tests/hia_native/shell_capture_mkdir_state.py")
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
def required(path):return 512+10*(len(path)+1)
def mutate_word(raw,offset,value):return raw[:offset]+Q(value)+raw[offset+8:]


def frame(path=b"",seed=0,op=1):
    return b"HSHMKQ01"+Q(op)+Q(seed)+Q(len(path))+bytes(32)+path
def result(kind=0,value=0,cache=0):return b"HSHMKR01"+Q(kind)+Q(value)+Q(cache)
def completion(work,error=0,mode=0):
    raw=0 if error==0 else (1<<64)-error
    return work[:144]+Q(1)+Q(raw)+Q(error)+Q(mode)+work[176:]
def m(path,error=0):return [1,path.hex(),error,0]
def sx(path,error=0,mode=0o40755):return [2,path.hex(),error,0 if error else mode]
def probe(error):return [3,"",error,0]
def st(path,error=0,mode=0o40755):return [4,path.hex(),error,0 if error else mode]
def specifications():
    rows=[]
    def add(group,path,seed,steps,kind=0,value=0,cache=None,suffix=""):
        index=len(rows)+1
        rows.append({"name":f"{group}-{index:05d}"+suffix,"group":group,"path_hex":path.hex(),
                     "seed":seed,"steps":steps,"result":[kind,value,seed if cache is None else cache]})
    for path in (b"",b"/",b"//",b"////",b"/.",b"/./",b"//.///."):
        for seed in range(3):add("no-io",path,seed,[])
    for path in (b"\0",b"a\0b",b"/\0",b"\0/..",b"a/b\0/c",b"x"*383+b"\0",
                 b"x"*384+b"\0",b"/a/\0/",b"\xff/\0\xfe",b"\0"*4097):
        for seed in range(3):add("local-nul",path,seed,[],2)
    for error in range(1,4096):
        if error not in (2,17):add("mkdir-error-domain",b"a/b",0,[m(b"a/b",error)],1,error)
    ordinary=(b".",b"./",b".//.",b"a",b"new/./",b"new/..",b"a//b/",b"./a/./b/.",
              b"white/ \t\r\n",b"\xff/\xfe",b"relative:"+bytes(range(1,256)))
    for path in ordinary:
        for seed in range(3):add("first-full-path-success",path,seed,[m(path)])
    for value in range(1,256):
        path=b"raw/"+bytes([value])+b"X";add("all-nonzero-path-bytes",path,0,[m(path)])
    for size in (383,384,4095,4096,65537,1048577):
        path=b"x"*size;add("private-large-path",path,0,[m(path)])
    families=[
        [b"a/b/c",b"a/b",b"a"],
        [b"/a/b/c",b"/a/b",b"/a"],
        [b"./a/./b/.",b"./a",b"."],
        [b"a//b///c//",b"a//b",b"a"],
        [b"new/./"],
        [b"a/../b",b"a/..",b"a"],
        [b"../a",b".."],
        [b"//a//b/.",b"//a"],
        [b"/./a//b/.",b"/./a"],
        [b".//a/..//b",b".//a/..",b".//a",b"."],
        [b"./"],
        [b"\xff/\xfe/x",b"\xff/\xfe",b"\xff"],
        [b"space name/\t/line\n",b"space name/\t",b"space name"],
    ]
    for depth in (1,2,8,64,512):
        parts=[("p"+str(i)).encode() for i in range(depth)]
        families.append([b"/".join(parts[:i]) for i in range(depth,0,-1)])
    for chain in families:
        path=chain[0];missing=[m(part,2) for part in chain];reverse=list(reversed(chain))
        add("all-missing-reverse",path,0,missing+[m(part) for part in reverse])
        stops=range(len(chain)) if len(chain)<=8 else (0,1,len(chain)-1)
        for at in stops:
            prior=[m(part,2) for part in chain[:at]]
            rebuild=[m(part) for part in reversed(chain[:at])]
            add("ascent-success-stop",path,0,prior+[m(chain[at])]+rebuild)
            add("ascent-error-stop",path,0,prior+[m(chain[at],13)],1,13)
            for seed in range(3):
                meta=st(chain[at]) if seed==2 else sx(chain[at])
                add("ascent-existing-directory",path,seed,prior+[m(chain[at],17),meta]+rebuild,
                    cache=1 if seed==0 else seed)
        positions=range(len(chain)) if len(chain)<=8 else (0,len(chain)-1)
        for at in positions:
            prior=missing+[m(part) for part in reverse[:at]]
            for error in (2,4,13,20):
                add("rebuild-error-no-restart",path,0,prior+[m(reverse[at],error)],1,error)
            add("rebuild-existing-directory",path,0,
                prior+[m(reverse[at],17),sx(reverse[at])]+[m(part) for part in reverse[at+1:]],cache=1)
    path=b"existing"
    for seed in range(3):
        for filetype in range(16):
            for permissions in (0,1,0o555,0o777,0o7777):
                mode=(filetype<<12)|permissions
                meta=st(path,mode=mode) if seed==2 else sx(path,mode=mode)
                good=filetype==4
                add("metadata-file-type",path,seed,[m(path,17),meta],
                    0 if good else 1,0 if good else 17,1 if seed==0 else seed)
    errors=(1,2,4,5,9,12,13,14,17,20,22,36,38,40,75,95,116,110,4095)
    for error in errors:
        add("known-statx-error-preserves-mkdir",path,1,[m(path,17),sx(path,error)],1,17,1)
        add("stat64-error-preserves-mkdir",path,2,[m(path,17),st(path,error)],1,17,2)
        add("unknown-statx-present-probe",path,0,[m(path,17),sx(path,error),probe(14)],1,17,1)
        for probe_error in (0,1,4,12,38,4095):
            for tail in (st(path),st(path,13),st(path,mode=0o100600)):
                good=tail[2]==0 and tail[3]==0o40755
                add("unknown-statx-fallback",path,0,
                    [m(path,17),sx(path,error),probe(probe_error),tail],
                    0 if good else 1,0 if good else 17,2)
    for high in (1<<16,1<<24,1<<31,0xffff0000):
        add("stat64-high-mode-bits",path,2,[m(path,17),st(path,mode=high|0o40700)],cache=2)
    # Two EEXIST checks in one rebuild verify persisted HIA cache decisions.
    add("persist-unavailable",b"a/b",0,
        [m(b"a/b",2),m(b"a",2),m(b"a",17),sx(b"a",38),probe(38),st(b"a"),
         m(b"a/b",17),st(b"a/b")],cache=2)
    add("persist-present",b"a/b",0,
        [m(b"a/b",2),m(b"a",2),m(b"a",17),sx(b"a"),m(b"a/b",17),sx(b"a/b",4)],1,17,1)
    return rows

STREAM_FILES=("entries.jsonl","buffers.bin","requests.bin","responses.bin","case_records.jsonl")
class Entries:
    def __init__(self,folder,native=None,process=None):
        self.folder=Path(folder);self.native=native;self.process=process;self.number=0;self.semantic=0
        self.guards={"input_unchanged":0,"bilateral_boundaries_checked":0,"workspace_tails_unchanged":0,
                     "nonresult_outputs_unchanged":0,"success_tails_unchanged":0,"unchanged_workspace_checks":0}
        self.files={n:(self.folder/n).open("xb" if native is not None else "rb") for n in STREAM_FILES}
    def close(self):
        for stream in self.files.values():stream.close()
    def read_array(self,size):
        stream=self.files["buffers.bin"];header=stream.read(16)
        need(len(header)==16,"complete array record header")
        raw_size,stored=struct.unpack("<QQ",header)
        need(raw_size==size and 0<stored<=size+size//100+256,"bounded array extent")
        raw=stream.read(stored);need(len(raw)==stored,"truncated compressed array")
        inflater=zlib.decompressobj();decoded=inflater.decompress(raw,size+1)
        need(len(decoded)==size and inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,
             "complete bounded array decoding")
        return decoded
    def write_array(self,raw):
        compressed=zlib.compress(raw,1)
        self.files["buffers.bin"].write(struct.pack("<QQ",len(raw),len(compressed))+compressed)
    def invoke(self,name,group,category,step,wire,work,expected,*,outcap=64,unchanged=False):
        self.number+=1;caps=(len(wire),outcap,len(work))
        before=[a+body+b for (a,b),body in zip(GUARDS,(wire,b"\xa7"*outcap,work))]
        identity={"entry":self.number,"case":name,"group":group,"category":category,"step":step,
                  "capacities":list(caps),"expected_return":expected,"workspace_unchanged":unchanged}
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
            self.files["entries.jsonl"].write(canonical(row))
            for raw in full:self.write_array(raw)
        else:
            line=self.files["entries.jsonl"].readline();need(bool(line),"missing registered native entry")
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
        need(type(returned) is int and returned in (32,PENDING,INVALID,CAPACITY),"native returned unknown status")
        need(type(row.get("pid")) is int and row["pid"]>0 and type(row.get("started_unix_ns")) is int
             and row["started_unix_ns"]>0 and type(row.get("elapsed_ns")) is int and row["elapsed_ns"]>=0,
             "actual entry timing")
        for n,(a,b),raw in zip(caps,GUARDS,full[3:]):
            need(len(raw)==n+32 and raw[:16]==a and raw[-16:]==b,"bilateral native guard")
        need(full[0]==full[3],"native changed input")
        self.guards["input_unchanged"]+=1;self.guards["bilateral_boundaries_checked"]+=1
        if len(wire)>=64:
            tail=min(len(work),required(wire[64:]))
            need(full[2][16+tail:-16]==full[5][16+tail:-16],"workspace tail changed")
            self.guards["workspace_tails_unchanged"]+=1
        if returned==32:
            output=full[4][16:-16];need(len(output)>=32 and output[:8]==b"HSHMKR01","native result header")
            need(U(output,8)<=2 and U(output,24)<=2,"native result tag/cache")
            if U(output,8)==1:need(1<=U(output,16)<=4095,"native raw OS error domain")
            else:need(U(output,16)==0,"native non-OS result has raw errno")
            need(full[4][48:-16]==full[1][48:-16],"success output tail changed")
            body=output[:32];self.guards["success_tails_unchanged"]+=1
        else:
            need(full[4]==full[1],"nonresult changed complete output")
            body=None;self.guards["nonresult_outputs_unchanged"]+=1
        if unchanged or returned in (INVALID,CAPACITY):
            need(full[2]==full[5],"refusal or ready-zero changed workspace")
            self.guards["unchanged_workspace_checks"]+=1
        need(returned==expected,"registered native return: "+name+"/"+step)
        return body,full[5][16:-16]
    def record(self,spec,first,body):
        self.semantic+=1
        req=self.files["requests.bin"];resp=self.files["responses.bin"];records=self.files["case_records.jsonl"]
        path=bytes.fromhex(spec["path_hex"]);wire=frame(path,spec["seed"])
        row={"case_index":self.semantic,"name":spec["name"],"group":spec["group"],
             "spec_sha256":digest(canonical(spec)),"first_entry":first,"last_entry":self.number,
             "request_offset":req.tell(),"request_bytes":len(wire),"request_sha256":digest(wire),
             "response_offset":resp.tell(),"response_bytes":32,"response_sha256":digest(body),
             "typed_effects":len(spec["steps"])}
        packet=Q(len(wire))+wire;answer=Q(32)+Q(32)+body
        if self.native is not None:req.write(packet);resp.write(answer);records.write(canonical(row))
        else:
            need(req.read(len(packet))==packet,"complete registered semantic request stream")
            need(resp.read(len(answer))==answer,"result stream differs from actual output arrays")
            need(records.readline()==canonical(row),"complete registered case record")
    def finish(self):
        if self.native is None:
            for name,stream in self.files.items():need(stream.read(1)==b"","extra evidence stream bytes: "+name)
        else:
            for stream in self.files.values():stream.flush()

def expected_slot(sequence,action,path_offset,pathlen):
    arg=511 if action==1 else 0 if action==4 else 4095
    return b"HSHMKFX1"+Q(sequence)+Q(action)+Q(path_offset)+Q(pathlen)+Q(arg)+bytes(48)
def check_effect(work,sequence,step,original):
    action,pathhex,error,mode=step;path=bytes.fromhex(pathhex);offset=0 if action==3 else 513+len(original)
    need(U(work,64)==int.from_bytes(b"HSHMKW01","little") and U(work,72)==1,
         "owner pending state")
    need(work[96:192]==expected_slot(sequence,action,offset,len(path)),"registered complete effect slot")
    need(work[512:512+len(original)+1]==original+b"\0","retained original raw path")
    if action!=3:need(work[offset:offset+len(path)+1]==path+b"\0","registered exact effect C string")

def execute_scenario(entries,spec):
    path=bytes.fromhex(spec["path_hex"]);start=entries.number+1
    name=spec["name"];group=spec["group"];resume=frame(path,0,2)
    body,work=entries.invoke(name,group,"semantic","start",frame(path,spec["seed"]),
                            b"\xd3"*(required(path)+32),PENDING if spec["steps"] else 32)
    for index,step in enumerate(spec["steps"]):
        check_effect(work,index+1,step,path)
        _,polled=entries.invoke(name,group,"semantic",f"pending-{index}",resume,work,PENDING,unchanged=True)
        need(polled==work,"ready-zero poll changed state")
        _,_,error,mode=step
        body,work=entries.invoke(name,group,"semantic",f"complete-{index}",resume,
                                completion(work,error,mode),PENDING if index+1<len(spec["steps"]) else 32)
    need(body==result(*spec["result"]),"registered semantic result: "+name)
    repeated,again=entries.invoke(name,group,"semantic","completed-repeat",resume,work,32,unchanged=True)
    need(repeated==body and again==work,"completed invocation is not idempotent")
    entries.record(spec,start,body)

def templates(entries):
    path=b"a/b";resume=frame(path,0,2);result_templates={}
    _,work=entries.invoke("template-chain","setup","setup","mkdir",frame(path),
                          b"\xd3"*(required(path)+32),PENDING)
    check_effect(work,1,m(path),path);result_templates["mkdir"]=work
    _,work=entries.invoke("template-chain","setup","setup","statx",resume,completion(work,17),PENDING)
    check_effect(work,2,sx(path),path);result_templates["statx"]=work
    _,work=entries.invoke("template-chain","setup","setup","probe",resume,completion(work,38),PENDING)
    check_effect(work,3,probe(14),path);result_templates["probe"]=work
    _,work=entries.invoke("template-chain","setup","setup","stat64",resume,completion(work,38),PENDING)
    check_effect(work,4,st(path),path);result_templates["stat64"]=work
    body,work=entries.invoke("template-chain","setup","setup","done",resume,completion(work,0,0o40755),32)
    need(body==result(0,0,2),"template final semantic result");result_templates["done"]=work
    _,work=entries.invoke("template-descend","setup","setup","start",frame(path),
                          b"\xd3"*(required(path)+32),PENDING)
    _,work=entries.invoke("template-descend","setup","setup","parent",resume,completion(work,2),PENDING)
    check_effect(work,2,m(b"a"),path)
    _,work=entries.invoke("template-descend","setup","setup","reverse",resume,completion(work,2),PENDING)
    check_effect(work,3,m(b"a"),path);result_templates["descend"]=work
    return result_templates

def controls():
    rows=[]
    def add(name,**fields):rows.append({"name":name,"expected":INVALID,**fields})
    wire=frame(b"a/b")
    for size in range(64):add(f"short-header-{size}",wire_hex=wire[:size].hex())
    for offset,value in ((0,0),(8,0),(8,3),(8,(1<<64)-1),(16,3),(16,(1<<64)-1),
                         (24,2),(24,4),(24,(1<<64)-1),(32,1),(40,1),(48,1),(56,1)):
        add(f"request-word-{offset}-{value}",wire_words=[[offset,value]])
    add("trailing-byte",wire_hex=(wire+b"x").hex())
    add("resume-uninitialized",wire_hex=frame(b"a/b",0,2).hex())
    add("resume-seed-one",template="mkdir",wire_words=[[16,1]])
    add("changed-path",template="mkdir",wire_hex=frame(b"a/c",0,2).hex())
    add("changed-path-length",template="mkdir",wire_hex=frame(b"a",0,2).hex())
    add("duplicate-start-pending",template="mkdir",wire_words=[[8,1]])
    add("duplicate-start-completed",template="done",wire_words=[[8,1]])
    words=((64,0),(72,0),(80,0),(80,(1<<64)-1),(88,0),(88,5),
           (192,0),(192,4),(200,0),(200,4),(208,3),(216,5),(224,1),(232,3),
           (240,1),(248,1),(256,1),(264,1),(272,4),(280,3),(288,551),(296,1),
           (96,0),(104,2),(112,0),(112,5),(112,2),(120,0),(128,0),(136,0),
           (144,2),(152,1),(160,4),(168,1),(176,1),(184,1),(512,0))
    for offset,value in words:
        add(f"state-slot-word-{offset}-{value}",template="mkdir",work_words=[[offset,value]])
    for name,patch in (
        ("errno-with-zero-raw",[[144,1],[160,4]]),
        ("negative-raw-with-zero-errno",[[144,1],[152,(1<<64)-4]]),
        ("errno-too-large",[[144,1],[152,(1<<64)-4096],[160,4096]]),
        ("errno-unsigned-negative",[[144,1],[152,1],[160,(1<<64)-1]]),
        ("error-carries-mode",[[144,1],[152,(1<<64)-4],[160,4],[168,1]]),
        ("mkdir-success-carries-mode",[[144,1],[168,1]])):
        add(name,template="mkdir",work_words=patch)
    add("effect-cstring-byte",template="mkdir",work_bytes=[[516,ord("z")]])
    add("effect-cstring-terminator",template="mkdir",work_bytes=[[519,1]])
    add("statx-mode-not-u16",template="statx",work_words=[[144,1],[168,65536]])
    add("statx-unavailable-wrong-phase",template="statx",work_words=[[232,2]])
    add("probe-success-carries-mode",template="probe",work_words=[[144,1],[168,1]])
    add("probe-present-wrong-phase",template="probe",work_words=[[232,1]])
    add("stat64-mode-not-u32",template="stat64",work_words=[[144,1],[168,1<<32]])
    add("stat64-present-wrong-phase",template="stat64",work_words=[[232,1]])
    add("reverse-stack-too-long",template="descend",work_words=[[520,4]])
    add("reverse-stack-not-decreasing",template="descend",work_words=[[528,3]])
    add("reverse-current-differs",template="descend",work_words=[[200,2]])
    add("reverse-empty-remaining",template="descend",work_words=[[224,0]])
    add("done-invalid-kind",template="done",work_words=[[256,3]])
    add("done-ok-with-errno",template="done",work_words=[[264,1]])
    add("done-live-slot",template="done",work_words=[[96,1]])
    for path in (b"",b"x",b"\0",b"a/b/c",b"/"):
        for outcap in (0,31):
            add(f"output-capacity-{path.hex()}-{outcap}",wire_hex=frame(path).hex(),outcap=outcap,expected=CAPACITY)
        for cap in (0,511,required(path)-1):
            add(f"workspace-capacity-{path.hex()}-{cap}",wire_hex=frame(path).hex(),workcap=cap,expected=CAPACITY)
    add("completion-output-capacity",template="mkdir",outcap=31,
        work_words=[[144,1],[152,(1<<64)-4],[160,4]],expected=CAPACITY)
    add("completion-workspace-capacity",template="mkdir",workcap=551,
        work_words=[[144,1],[152,(1<<64)-4],[160,4]],expected=CAPACITY)
    add("exact-capacity-positive",workcap=552,outcap=32,expected=PENDING)
    add("ready-zero-positive",template="mkdir",expected=PENDING,unchanged=True)
    add("errno-four-positive",template="mkdir",work_words=[[144,1],[152,(1<<64)-4],[160,4]],
        expected=32,result_hex=result(1,4,0).hex())
    add("statx-directory-positive",template="statx",work_words=[[144,1],[168,0o40755]],
        expected=32,result_hex=result(0,0,1).hex())
    add("stat64-file-positive",template="stat64",work_words=[[144,1],[168,0o100644]],
        expected=32,result_hex=result(1,17,2).hex())
    add("done-repeat-positive",template="done",expected=32,result_hex=result(0,0,2).hex(),unchanged=True)
    return rows

def execute_control(entries,spec,prepared):
    path=b"a/b";wire=frame(path,0,2 if "template" in spec else 1)
    if "wire_hex" in spec:wire=bytes.fromhex(spec["wire_hex"])
    for offset,value in spec.get("wire_words",[]):wire=mutate_word(wire,offset,value)
    if "template" in spec:work=prepared[spec["template"]]
    else:work=b"\xd3"*(required(wire[64:])+32)
    for offset,value in spec.get("work_words",[]):work=mutate_word(work,offset,value)
    for offset,value in spec.get("work_bytes",[]):work=work[:offset]+bytes([value])+work[offset+1:]
    if "workcap" in spec:
        cap=spec["workcap"];work=(work+b"\xd3"*max(0,cap-len(work)))[:cap]
    body,after=entries.invoke(spec["name"],"control","control","test",wire,work,spec["expected"],
                             outcap=spec.get("outcap",64),unchanged=spec.get("unchanged",False))
    if spec["expected"]==32:need(body==bytes.fromhex(spec["result_hex"]),"registered positive control result")
    return {"name":spec["name"],"expected_return":spec["expected"],
            "result":None if body is None else body.hex(),"spec_sha256":digest(canonical(spec))}

def expected_counts():
    semantic=specifications();checks=controls()
    count=sum(2+2*len(spec["steps"]) for spec in semantic)+8+len(checks)
    return {"semantic_cases":len(semantic),"native_control_cases":len(checks),"setup_entries":8,
            "actual_native_entries":count,"complete_guarded_buffer_snapshots":6*count}
def exercise(entries):
    semantic=specifications();checks=controls();groups={}
    for spec in semantic:
        execute_scenario(entries,spec);groups[spec["group"]]=groups.get(spec["group"],0)+1
    prepared=templates(entries)
    results=[execute_control(entries,spec,prepared) for spec in checks]
    entries.finish();counts=expected_counts()
    need(entries.number==counts["actual_native_entries"] and entries.semantic==counts["semantic_cases"],
         "complete registered state counts")
    refusal=sum(spec["expected"]==INVALID for spec in checks)
    capacity=sum(spec["expected"]==CAPACITY for spec in checks)
    return {"counts":counts,"groups":groups,"typed_effect_completions":sum(len(s["steps"]) for s in semantic),
            "invalid_refusals":refusal,"capacity_refusals":capacity,"positive_controls":len(checks)-refusal-capacity,
            "controls":results,"guards":entries.guards}
def admitted(top):
    top=Path(top).resolve(strict=True);raw=raw_file(top);outer=obj(raw)
    need(outer.get("schema")=="hepta.runtime.shell-capture-mkdir.v1","capture mkdir TOP manifest required")
    builder=load_py(ROOT/"scripts/hia_native_shell_capture_mkdir_build.py","hia_capture_mkdir_build_review")
    reviewed=builder.read_evidence(top,source_root=ROOT)
    need(reviewed.get("status")=="PASS","capture mkdir native build refused")
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
    need(members["source"]==pin(ROOT/"native/shell_capture_mkdir.hepta"),"current HIA source differs")
    return {"manifest_path":str(top),"manifest":pinned(raw),"owner_manifest":pin(selected),
            "source":members["source"],"image":members["image"],"compiler_commit":COMPILER,
            "build_evidence":reviewed},selected,meta

def worker(folder):
    folder=Path(folder).resolve(strict=True)
    loader=load_py(folder/"hia_native_loader.py","hia_capture_mkdir_worker_loader")
    manifest=folder/"native/manifest.json"
    with loader.NativeModule(manifest,manifest_sha256=pin(manifest)["sha256"]) as native:
        boundary=Entries(folder,native=native)
        try:result=exercise(boundary)
        finally:boundary.close()
    observed={"schema":"hepta.runtime.shell-capture-mkdir-actual.v1",
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
    process={"schema":"hepta.runtime.shell-capture-mkdir-process.v1","command":command,"cwd":str(folder),
             "environment":environment,"pid":child.pid,"exit_code":child.returncode,"timed_out":timed_out,
             "timeout_seconds":120,"started_unix_ns":start,"finished_unix_ns":time.time_ns(),
             "elapsed_ns":time.monotonic_ns()-clock,"stdout":pin(folder/"stdout.bin"),"stderr":pin(folder/"stderr.bin"),
             "python":{"path":str(python),"before":python_before,"after":pin(python)}}
    write_new(folder/"process.json",encoded(process))
    need(not timed_out and child.returncode==0 and raw_file(folder/"stderr.bin")==b"","actual capture mkdir worker failed")
    need(source_pins()==before,"qualification source changed during execution")
    current,_,_=admitted(top);need(current==native,"native build changed during execution")
    actual=obj(raw_file(folder/"native-result.json"))
    report={"schema":"hepta.runtime.shell-capture-mkdir-corpus.v1","status":"PASS",
            "recorded_directory":str(folder),"recorded_source_root":str(ROOT),"sources":before,
            "native":native,"counts":actual["results"]["counts"],
            "files":{n:pin(folder/n) for n in sorted(artifact_names(meta))},**SCOPE}
    write_new(folder/"report.json",encoded(report))
    return read_evidence(folder,native_manifest=top)

def read_evidence(folder,native_manifest=None):
    folder=Path(folder).resolve(strict=True);report=obj(raw_file(folder/"report.json"))
    need(report.get("schema")=="hepta.runtime.shell-capture-mkdir-corpus.v1" and report.get("status")=="PASS",
         "capture mkdir corpus schema/status")
    need(all(report.get(k) is v for k,v in SCOPE.items()),"capture mkdir scope overstated")
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
    need(process.get("schema")=="hepta.runtime.shell-capture-mkdir-process.v1"
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
    need(actual.get("schema")=="hepta.runtime.shell-capture-mkdir-actual.v1"
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
             sum(s["expected"] in (32,PENDING) for s in checks))
    need((replayed["invalid_refusals"],replayed["capacity_refusals"],replayed["positive_controls"])==domains,
         "registered control domains")
    return {"status":"PASS","schema":"hepta.runtime.shell-capture-mkdir-review.v1",
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
                open("capture-mkdir-audit-must-not-exist","wb")
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
