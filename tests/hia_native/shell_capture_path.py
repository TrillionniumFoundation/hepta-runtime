"""Actual native capture-path corpus and complete-byte evidence reader.

Only input generation, transport capacities, and evidence validation live here.
Unix Path and capture-name semantics are executed by HIA and the separate
original Rust projection oracle.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,re,stat,struct,sys,time,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SOURCE=Path(__file__).resolve()
COMPILER="d3e2c90173cf733e42b299d0c4274df4b593a12f"
INVALID=0xffffffff
CAPACITY=0xfffffffe
HEADER=80
SCOPE={"original_rust_compared":False,"filesystem_operations_executed":False,
       "process_observations_executed":False,"global_atomic_sequence_advanced":False,
       "registry_concurrency_qualified":False,"production_activated":False,
       "whole_runtime_replaced":False,"old_stack_removal_qualified":False}
SOURCE_FILES=("native/shell_capture_path.hepta","native/shell_capture_path_abi.md",
              "native/shell_capture_path_reuse.json","native/shell_gate.hepta",
              "scripts/hia_native_shell_capture_path_build.py","scripts/hia_native_loader.py",
              "tests/hia_native/shell_capture_path_cases.py","tests/hia_native/shell_capture_path.py")
EXPECTED_COUNTS={"semantic_cases":49075,"native_control_cases":90,
                 "actual_native_entries":49165,"complete_guarded_buffer_snapshots":294990}
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
def initial_capacity(wire):return 512+3*len(wire)
def mutate_word(raw,offset,value):return raw[:offset]+Q(value)+raw[offset+8:]

class Entries:
    """Stream complete arrays; replay reads bytes and never loads native code."""
    def __init__(self,folder,cases,native=None,process=None):
        self.folder=Path(folder);self.cases=cases;self.native=native;self.process=process
        self.number=0;self.semantic=0;self.guards={"input_unchanged":0,"bilateral_boundaries_checked":0,
            "workspace_tails_unchanged":0,"refusal_outputs_unchanged":0,"success_tails_unchanged":0}
        mode="xb" if native is not None else "rb"
        self.files={name:(self.folder/name).open(mode) for name in
                    ("entries.jsonl","buffers.bin","requests.bin","responses.bin","case_records.jsonl")}
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
    def invoke(self,name,group,category,wire,expected=80,*,outcap=None,workcap=160,outfill=0xa7,workfill=0xd3):
        self.number+=1
        if outcap is None:outcap=initial_capacity(wire)
        caps=(len(wire),outcap,workcap)
        before=[left+body+right for (left,right),body in zip(GUARDS,
                  (wire,bytes([outfill])*outcap,bytes([workfill])*workcap))]
        identity={"entry":self.number,"case":name,"group":group,"category":category,
                  "capacities":list(caps),"expected_return":expected,
                  "output_fill":outfill,"workspace_fill":workfill}
        if self.native is not None:
            import ctypes
            arrays=[ctypes.create_string_buffer(raw,len(raw)) for raw in before]
            arguments=[]
            for buffer,size in zip(arrays,caps):arguments.extend((ctypes.addressof(buffer)+16,size))
            start=time.time_ns();clock=time.monotonic_ns()
            with self.native._lock:returned=self.native._entry(*arguments)
            elapsed=time.monotonic_ns()-clock;full=before+[buffer.raw for buffer in arrays]
            row={**identity,"return_u64":returned,"started_unix_ns":start,"elapsed_ns":elapsed,
                 "pid":os.getpid(),"arrays":{key:pinned(raw) for key,raw in zip(ARRAY_NAMES,full)}}
            self.files["entries.jsonl"].write(canonical(row))
            for raw in full:self.write_array(raw)
        else:
            line=self.files["entries.jsonl"].readline();need(bool(line),"missing registered native entry")
            row=obj(line);need(canonical(row)==line,"canonical native entry row")
            need(set(row)==set(identity)|{"return_u64","started_unix_ns","elapsed_ns","pid","arrays"},"exact native entry fields")
            for key,value in identity.items():
                need(type(row.get(key)) is type(value) and row[key]==value,"registered native entry: "+key)
            need(all(type(n) is int for n in row["capacities"]),"native capacity scalar types")
            full=[self.read_array(n+32) for n in caps+caps]
            need(full[:3]==before,"registered input and initialized arrays")
            need(row.get("arrays")=={key:pinned(raw) for key,raw in zip(ARRAY_NAMES,full)},"complete array pins")
            returned=row.get("return_u64")
            if self.process is not None:
                need(row.get("pid")==self.process["pid"] and row.get("elapsed_ns",0)<=self.process["elapsed_ns"],
                     "entry/actual worker process binding")
        need(type(returned) is int and returned in (80,INVALID,CAPACITY),"native returned unknown status")
        need(type(row.get("pid")) is int and row["pid"]>0
             and type(row.get("started_unix_ns")) is int and row["started_unix_ns"]>0
             and type(row.get("elapsed_ns")) is int and row["elapsed_ns"]>=0,"actual entry timing")
        for n,(left,right),raw in zip(caps,GUARDS,full[3:]):
            need(len(raw)==n+32 and raw[:16]==left and raw[-16:]==right,"bilateral native guard")
        need(full[0]==full[3],"native changed input")
        need(full[2][144:-16]==full[5][144:-16],"workspace tail changed")
        self.guards["input_unchanged"]+=1;self.guards["bilateral_boundaries_checked"]+=1
        self.guards["workspace_tails_unchanged"]+=1
        if returned==80:
            output=full[4][16:-16]
            need(len(output)>=80 and output[:8]==b"HSHCPR01","native response header")
            extent=U(output,16);need(80<=extent<=len(output),"complete response extent")
            body=output[:extent];decoded=self.cases.decode_body(body)
            need(decoded["op"]==U(wire,8),"response operation differs")
            need(full[4][16+extent:-16]==full[1][16+extent:-16],"success output tail changed")
            self.guards["success_tails_unchanged"]+=1
        else:
            need(full[4]==full[1],"refusal changed complete output")
            if returned==INVALID or workcap<128:need(full[5]==full[2],"preflight refusal changed workspace")
            self.guards["refusal_outputs_unchanged"]+=1;body=None
        need(returned==expected,"registered native return: "+name)
        return body
    def semantic_record(self,spec,wire,body):
        self.semantic+=1
        req=self.files["requests.bin"];resp=self.files["responses.bin"];records=self.files["case_records.jsonl"]
        row={"case_index":self.semantic,"entry":self.number,"name":spec["name"],"group":spec["group"],
             "op":spec["fields"]["op"],"request_offset":req.tell(),"request_bytes":len(wire),
             "request_sha256":digest(wire),"response_offset":resp.tell(),"response_bytes":len(body),
             "response_sha256":digest(body)}
        packet=Q(len(wire))+wire;answer=Q(80)+Q(len(body))+body
        if self.native is not None:
            req.write(packet);resp.write(answer);records.write(canonical(row))
        else:
            need(req.read(len(packet))==packet,"complete registered semantic request stream")
            need(resp.read(len(answer))==answer,"native response stream differs from actual output arrays")
            need(records.readline()==canonical(row),"complete registered case record")
    def finish(self):
        if self.native is None:
            for name,stream in self.files.items():need(stream.read(1)==b"","extra evidence stream bytes: "+name)
        else:
            for stream in self.files.values():stream.flush()

def exercise(boundary):
    c=boundary.cases;specs=c.specifications()
    need(len(specs)==49075,"registered semantic specification count")
    for spec in specs:
        wire=c.frame(**spec["fields"])
        body=boundary.invoke(spec["name"],spec["group"],"semantic",wire)
        boundary.semantic_record(spec,wire,body)
    controls=[]
    def call(name,raw,expected=INVALID,**kwargs):
        body=boundary.invoke(name,"transport-control","control",raw,expected,**kwargs)
        controls.append({"name":name,"entry":boundary.number,"expected_return":expected,
                         "output_capacity":kwargs.get("outcap",initial_capacity(raw)),
                         "workspace_capacity":kwargs.get("workcap",160),
                         "body":pinned(body) if body is not None else None})
        return body
    simple=c.frame(op=1,first=b"a",second=b"a")
    for n in (0,1,7,8,16,24,32,40,48,56,63):call("short-frame-"+str(n),simple[:n])
    call("bad-magic",b"BADPATH!"+simple[8:])
    for n in (0,4,(1<<64)-1):call("unknown-op-"+str(n),mutate_word(simple,8,n))
    for n in (1,(1<<64)-1):call("reserved-"+str(n),mutate_word(simple,56,n))
    for offset in (40,48):
        for n in (U(simple,offset)+1,(1<<64)-1):
            call("extent-"+str(offset)+"-"+str(n),mutate_word(simple,offset,n))
    call("truncated-payload",simple[:-1]);call("trailing-payload",simple+b"x")
    for op in (1,2):
        raw=c.frame(op=op,first=b"a")
        for offset in (16,24,32):
            for n in (1,(1<<64)-1):
                call("unused-"+str(op)+"-"+str(offset)+"-"+str(n),mutate_word(raw,offset,n))
    call("parent-second",c.frame(op=2,first=b"a",second=b"b"))
    capture=c.frame(op=3,tmpdir_present=1,first=b"/tmp",pid=123,seq=9)
    for n in (2,(1<<64)-1):call("tmpdir-presence-"+str(n),mutate_word(capture,16,n))
    for n in (1<<32,(1<<64)-1):call("pid-outside-u32-"+str(n),mutate_word(capture,24,n))
    call("capture-second",c.frame(op=3,tmpdir_present=1,first=b"a",second=b"b"))
    call("absent-tmpdir-payload",c.frame(op=3,first=b"a"))
    samples=(c.frame(op=1,first=b"a//b",second=b"a/b"),
             c.frame(op=2,first=b"a//b/c"),
             c.frame(op=3,pid=(1<<32)-1,seq=(1<<64)-1))
    for op,raw in enumerate(samples,1):
        for cap in (0,1,7,64,127):call("workspace-"+str(op)+"-"+str(cap),raw,CAPACITY,workcap=cap)
        for cap in (0,1,7,8,16,64,79):call("output-header-"+str(op)+"-"+str(cap),raw,CAPACITY,outcap=cap)
    for op,raw in enumerate(samples,1):
        body=call("capacity-baseline-"+str(op),raw,80)
        call("one-short-"+str(op),raw,CAPACITY,outcap=len(body)-1)
        exact=call("exact-capacity-"+str(op),raw,80,outcap=len(body),workcap=128,outfill=0,workfill=0xff)
        extra=call("extra-capacity-"+str(op),raw,80,outcap=len(body)+37,workcap=192,outfill=0x5a,workfill=0xff)
        need(exact==body==extra,"capacity changed complete response")
    counts={"semantic_cases":len(specs),"native_control_cases":len(controls),
            "actual_native_entries":boundary.number,"complete_guarded_buffer_snapshots":boundary.number*6}
    need(counts==EXPECTED_COUNTS,"registered corpus counts")
    boundary.finish()
    return normalized({"counts":counts,"semantic_counts":c.counts(specs),"controls":controls,
                       "guards":boundary.guards,"malformed_refusals":sum(x["expected_return"]==INVALID for x in controls),
                       "capacity_refusals":sum(x["expected_return"]==CAPACITY for x in controls),
                       "positive_controls":sum(x["expected_return"]==80 for x in controls)})

def admitted(top):
    top=Path(top).resolve(strict=True);raw=raw_file(top);outer=obj(raw)
    need(outer.get("schema")=="hepta.runtime.shell-capture-path.v1","capture path TOP manifest required")
    builder=load_py(ROOT/"scripts/hia_native_shell_capture_path_build.py","hia_capture_path_build_review")
    reviewed=builder.read_evidence(top,source_root=ROOT)
    need(reviewed.get("status")=="PASS","capture path native build refused")
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
    need(members["source"]==pin(ROOT/"native/shell_capture_path.hepta"),"current HIA source differs")
    return {"manifest_path":str(top),"manifest":pinned(raw),"owner_manifest":pin(selected),
            "source":members["source"],"image":members["image"],"compiler_commit":COMPILER,
            "build_evidence":reviewed},selected,meta

STREAM_FILES=("entries.jsonl","buffers.bin","requests.bin","responses.bin","case_records.jsonl")
def worker(folder):
    folder=Path(folder).resolve(strict=True)
    loader=load_py(folder/"hia_native_loader.py","hia_capture_path_worker_loader")
    cases=load_py(folder/"shell_capture_path_cases.py","hia_capture_path_worker_cases")
    manifest=folder/"native/manifest.json"
    with loader.NativeModule(manifest,manifest_sha256=pin(manifest)["sha256"]) as native:
        boundary=Entries(folder,cases,native=native)
        try:result=exercise(boundary)
        finally:boundary.close()
    observed={"schema":"hepta.runtime.shell-capture-path-actual.v1",
              "driver":pin(SOURCE),"cases":pin(folder/"shell_capture_path_cases.py"),
              "loader":pin(folder/"hia_native_loader.py"),"manifest":pin(manifest),
              "streams":{n:pin(folder/n) for n in STREAM_FILES},"results":result,**SCOPE}
    write_new(folder/"native-result.json",encoded(observed))
    print(json.dumps({"status":"PASS","counts":result["counts"],"result":pin(folder/"native-result.json")},sort_keys=True))

def artifact_names(meta):
    names={"state_driver.py","shell_capture_path_cases.py","hia_native_loader.py","python.bin",
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
    write_new(folder/"shell_capture_path_cases.py",raw_file(ROOT/"tests/hia_native/shell_capture_path_cases.py"))
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
    process={"schema":"hepta.runtime.shell-capture-path-process.v1","command":command,"cwd":str(folder),
             "environment":environment,"pid":child.pid,"exit_code":child.returncode,"timed_out":timed_out,
             "timeout_seconds":120,"started_unix_ns":start,"finished_unix_ns":time.time_ns(),
             "elapsed_ns":time.monotonic_ns()-clock,"stdout":pin(folder/"stdout.bin"),"stderr":pin(folder/"stderr.bin"),
             "python":{"path":str(python),"before":python_before,"after":pin(python)}}
    write_new(folder/"process.json",encoded(process))
    need(not timed_out and child.returncode==0 and raw_file(folder/"stderr.bin")==b"","actual capture path worker failed")
    need(source_pins()==before,"qualification source changed during execution")
    current,_,_=admitted(top);need(current==native,"native build changed during execution")
    actual=obj(raw_file(folder/"native-result.json"))
    report={"schema":"hepta.runtime.shell-capture-path-corpus.v1","status":"PASS",
            "recorded_directory":str(folder),"recorded_source_root":str(ROOT),"sources":before,
            "native":native,"counts":actual["results"]["counts"],
            "files":{n:pin(folder/n) for n in sorted(artifact_names(meta))},**SCOPE}
    write_new(folder/"report.json",encoded(report))
    return read_evidence(folder,native_manifest=top)

def read_evidence(folder,native_manifest=None):
    folder=Path(folder).resolve(strict=True);report=obj(raw_file(folder/"report.json"))
    need(report.get("schema")=="hepta.runtime.shell-capture-path-corpus.v1" and report.get("status")=="PASS",
         "capture path corpus schema/status")
    need(all(report.get(k) is v for k,v in SCOPE.items()),"capture path scope overstated")
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
                          ("hia_native_loader.py",ROOT/"scripts/hia_native_loader.py"),
                          ("shell_capture_path_cases.py",ROOT/"tests/hia_native/shell_capture_path_cases.py")):
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
    need(process.get("schema")=="hepta.runtime.shell-capture-path-process.v1"
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
    need(actual.get("schema")=="hepta.runtime.shell-capture-path-actual.v1"
         and all(actual.get(k) is v for k,v in SCOPE.items()),"actual native result scope")
    for key,name in (("driver","state_driver.py"),("cases","shell_capture_path_cases.py"),
                     ("loader","hia_native_loader.py"),("manifest","native/manifest.json")):
        need(actual.get(key)==pin(folder/name),"native invocation source binding: "+key)
    need(actual.get("streams")=={n:pin(folder/n) for n in STREAM_FILES},"complete native stream binding")
    need(obj(raw_file(folder/"stdout.bin"))=={"status":"PASS","counts":EXPECTED_COUNTS,
                                             "result":pin(folder/"native-result.json")},"actual worker summary")
    cases=load_py(ROOT/"tests/hia_native/shell_capture_path_cases.py","hia_capture_path_reader_cases")
    boundary=Entries(folder,cases,process=process)
    try:replayed=exercise(boundary)
    finally:boundary.close()
    need(replayed==actual.get("results"),"complete actual corpus results")
    need(report.get("counts")==replayed["counts"]==EXPECTED_COUNTS,"registered actual counts")
    need((replayed["malformed_refusals"],replayed["capacity_refusals"],replayed["positive_controls"])==(42,39,9),
         "registered control domains")
    return {"status":"PASS","schema":"hepta.runtime.shell-capture-path-review.v1",
            "verification":"complete-byte-replay-with-current-native-build",
            "report_sha256":pin(folder/"report.json")["sha256"],"recorded_directory":directory,
            "counts":EXPECTED_COUNTS,"semantic_counts":replayed["semantic_counts"],
            "controls":replayed["controls"],"guards":replayed["guards"],
            "malformed_refusals":42,"capacity_refusals":39,"positive_controls":9,
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
                open("capture-path-audit-must-not-exist","wb")
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
