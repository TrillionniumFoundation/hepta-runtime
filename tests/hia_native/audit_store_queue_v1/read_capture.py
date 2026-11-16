"""Complete fixed-source evidence reader. No code mapping, subprocesses or writes."""
from pathlib import Path
import gzip, hashlib, json, stat, struct, sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from build import verify_source,pin,COMPILER
from cases import domain,controls,index,encoded
from projection import selected,project,expected
from original import FLAGS,TESTS,source_identity,check_tests
GROW=0xffffffd0
def require(value,message):
    if not value:raise ValueError(message)
def read(path):
    path=Path(path)
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and path.resolve()==path.absolute(),"ordinary complete evidence file")
    return path.read_bytes()
def parse(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            require(key not in result,"duplicate JSON field")
            result[key]=value
        return result
    def constant(value):raise ValueError("nonfinite JSON")
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
def safe(name):
    require(isinstance(name,str) and name and not Path(name).is_absolute()
        and all(x not in ("",".","..") for x in name.split("/")) and "\\" not in name,"unsafe evidence path")
    return name
def process(row,folder,name,timeout):
    require(row["name"]==name and row["completed"] is True and row["timed_out"] is False
        and row["exit_code"]==0 and row["timeout_seconds"]==timeout
        and 0<=row["elapsed_seconds"]<timeout,"actual process result or budget differs")
    require(all(type(row[k]) is int and row[k]>0 for k in ("pid","parent_pid","pgid"))
        and row["pid"]==row["pgid"] and row["pid"]!=row["parent_pid"],"actual process identity differs")
    require(row["stdin"] is None,"unexpected original/native stdin")
    for suffix in ("stdout","stderr"):
        identity=row[suffix]
        require(identity["file"]==name+"."+suffix and pin(read(folder/identity["file"]))==
            {k:identity[k] for k in ("bytes","sha256")},"complete process stream differs")
    require(row["stderr"]["bytes"]==0,"successful process stderr differs")
    return read(folder/row["stdout"]["file"])
def build_evidence(folder,source_sha):
    report=parse(read(folder/"BUILD.json"))
    require(report["schema"]=="hepta.runtime.audit-store-queue.build.v1"
        and report["source_manifest_sha256"]==source_sha and report["compiler_sha256"]==COMPILER
        and report["semantic_execution"] is False and report["whole_runtime_replaced"] is False,"build source/scope differs")
    require(report["module"]=="modules/audit-store-queue/manifest.json","module path differs")
    bootstrap=parse(read(folder/"bootstrap/bootstrap.json"))
    require(bootstrap["schema"]=="hepta.runtime.native-bootstrap.v1"
        and bootstrap["generation_sha256"]==COMPILER and bootstrap["qualification"]=="development_fixed_point"
        and bootstrap["dependency"]["commit"]=="d3e2c90173cf733e42b299d0c4274df4b593a12f"
        and bootstrap["dependency"]["tree"]=="8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49","compiler binding differs")
    for label in ("B1","B2","B3"):
        require(pin(read(folder/"bootstrap"/(label+".image.bin")))==dict(bytes=673413,sha256=COMPILER),
                "complete retained compiler differs")
    closure=bootstrap["dependency"]["files"]
    require({p.relative_to(folder/"compiler-source").as_posix()
        for p in (folder/"compiler-source").rglob("*") if p.is_file()}==set(closure),"compiler source set differs")
    for name,digest in closure.items():
        require(hashlib.sha256(read(folder/"compiler-source"/safe(name))).hexdigest()==digest,"compiler source changed")
    module=folder/report["module"]
    raw=read(module);require(pin(raw)==report["module_manifest"],"module manifest changed")
    meta=parse(raw);source=read(ROOT/"native/audit_store_queue.hepta")
    require(meta["schema"]=="hepta.runtime.native-module.v1" and meta["name"]=="audit-store-queue"
        and meta["abi"]=="hepta.runtime.borrowed-bytes.linux-x86_64.v1"
        and meta["target"]=="linux-x86_64" and meta["source"]=="audit-store-queue.hepta"
        and meta["image"]=="module.image.bin" and meta["compiler_sha256"]==COMPILER
        and meta["compiler_commit"]==bootstrap["dependency"]["commit"] and meta["standalone"] is None
        and meta["buffer_profile"]=="history.v1" and meta["qualification"]=="development_fixed_point",
        "actual module identity differs")
    require((meta["input_capacity"],meta["output_capacity"],meta["workspace_capacity"])==
        (128<<20,128<<20,256<<20),"actual module capacities differ")
    require(read(module.parent/meta["source"])==source==read(module.parent/"module.input.bin")
        and meta["source_sha256"]==hashlib.sha256(source).hexdigest(),"actual compiler source differs")
    image=read(module.parent/meta["image"])
    require(meta["image_sha256"]==hashlib.sha256(image).hexdigest(),"complete image differs")
    receipt=parse(read(module.parent/"module.receipt.json"));built=parse(read(module.parent/"build.json"))
    require(built["compile_receipt"]==receipt and built["compiler_dependency"]==bootstrap["dependency"],
        "compiler receipt custody differs")
    require(receipt["status"]=="returned" and receipt["abi_status"]==0 and receipt["source_unchanged"] is True
        and receipt["forbidden_compiler_modules_loaded"]==[] and receipt["format"]=="flat-x86-64",
        "compiler return differs")
    require(receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER
        and receipt["input_bytes"]==len(source)
        and receipt["input_sha256"]==receipt["source_sha256"]==hashlib.sha256(source).hexdigest()
        and receipt["core_u32"]==receipt["result_u64"]==receipt["produced_bytes"]==len(image)
        and receipt["produced_sha256"]==hashlib.sha256(image).hexdigest(),"compiler output binding differs")
    stdout=parse(read(module.parent/"module.stdout.log"))
    keys={"abi_status","core_u32","forbidden_compiler_modules_loaded","image_sha256","limits","loader_operations",
          "native_elapsed_ns","output_sha256","output_unchanged","result_u64","return_encoding","source_sha256",
          "source_unchanged","status","workspace_header"}
    require(set(stdout)==keys and stdout=={k:receipt[k] for k in keys},"actual compiler stdout differs")
    full=read(module.parent/"module.output.bin")
    require(pin(full)["sha256"]==receipt["output_sha256"] and len(full)==receipt["limits"]["output_capacity"]
        and full[:len(image)]==image and full[len(image):]==b"\xa5"*(len(full)-len(image))
        and read(module.parent/"module.stderr.log")==b"","complete compiler output or unused tail differs")
    return dict(status="PASS",image=pin(image),compiler_sha256=COMPILER,
                compiler_source_files=len(closure),matching_source_cold_qualified=False),meta

def native_evidence(folder,source_sha,pid,meta):
    report=parse(read(folder/"CAPTURE.json"))
    require(report["schema"]=="hepta.runtime.audit-store-queue.native-capture.v1"
        and report["status"]=="COMPLETE_PRIVATE_NATIVE_CAPTURE" and report["source_manifest_sha256"]==source_sha
        and report["source_unchanged"] is True,"native capture binding differs")
    names={"complete-domain.json.gz","complete-controls.json","source-manifest.json",
           "complete-buffers.bin.gz","calls.jsonl"}
    require(set(report["files"])==names and {p.name for p in folder.iterdir()}==names|{"CAPTURE.json"},
            "complete native file set differs")
    for name,identity in report["files"].items():require(pin(read(folder/name))==identity,"complete native file changed")
    require(read(folder/"source-manifest.json")==read(ROOT/"SOURCE_MANIFEST.json"),"retained source differs")
    fixed=parse(read(ROOT/"DOMAIN.json"));require(index()==fixed,"frozen source domain differs")
    planned=domain();private=controls()
    require(gzip.decompress(read(folder/"complete-domain.json.gz"))==encoded(planned)
        and read(folder/"complete-controls.json")==encoded(private),"complete frozen domain differs")
    rows=[parse(line) for line in read(folder/"calls.jsonl").splitlines()]
    counts=dict(semantic_calls=0,private_controls=0,actual_calls=0,growth_calls=0,physical_bytes=0)
    projection=[]
    with gzip.open(folder/"complete-buffers.bin.gz","rb") as stream:
        def call(wire,before_o,before_w,scenario,ordinal,kind):
            header=stream.read(48);require(len(header)==48,"incomplete actual buffer record")
            result,*lengths=struct.unpack("<6Q",header)
            require(lengths==[len(wire),len(before_o),len(before_o),len(before_w),len(before_w)],
                    "actual physical buffer extents differ")
            pieces=[]
            for length in lengths:
                value=stream.read(length);require(len(value)==length,"truncated physical buffer")
                pieces.append(value)
            require(pieces[0]==wire and pieces[1]==before_o and pieces[3]==before_w,
                    "actual input or full prior session state differs")
            n=counts["actual_calls"];require(n<len(rows),"missing actual-call ledger row")
            wanted=dict(call=n+1,scenario=scenario,ordinal=ordinal,kind=kind,result=result,pid=pid,
                        buffers={name:pin(value) for name,value in zip(
                            ("input","output_before","output_after","workspace_before","workspace_after"),pieces)})
            require(rows[n]==wanted,"physical record and complete ledger disagree")
            counts["actual_calls"]+=1;counts["physical_bytes"]+=sum(lengths)
            return result,pieces[2],pieces[4]
        for scenario,case in enumerate(planned["scenarios"]):
            old_o=bytes(128);old_w=bytes(case["initial_workspace"])
            for ordinal,row in enumerate(case["rows"]):
                if "workspace_patch" in row:
                    patch=row["workspace_patch"];value=bytes.fromhex(patch["data_hex"]);offset=patch["offset"]
                    require(offset+len(value)<=len(old_w),"frozen fault patch extent differs")
                    old_w=old_w[:offset]+value+old_w[offset+len(value):]
                    continue
                wire=bytes.fromhex(row["request_hex"]);state=bytes.fromhex(row["state_hex"])
                need=max(128,len(state))
                while len(old_w)<need:
                    result,after_o,after_w=call(wire,old_o,old_w,case["name"],ordinal,"semantic")
                    require(result==GROW and after_w==old_w
                        and after_o==struct.pack("<8s3Q",b"HGRWS002",1,need,0)+old_o[32:],
                        "growth changed state, unused output, or exact requested extent")
                    capacity=max(need,2*len(old_w))
                    require(capacity<=meta["workspace_capacity"],"growth escaped admitted capacity")
                    old_w+=bytes(capacity-len(old_w));old_o=bytes(128);counts["growth_calls"]+=1
                result,after_o,after_w=call(wire,old_o,old_w,case["name"],ordinal,"semantic")
                require(result==row["result"]==128 and after_o==bytes.fromhex(row["output_hex"])
                    and after_w==state+bytes(len(old_w)-len(state)),"actual complete semantic buffers differ")
                if selected(scenario,ordinal,row):projection.append(project(scenario,after_o,after_w))
                old_o,old_w=after_o,after_w;counts["semantic_calls"]+=1
        for ordinal,row in enumerate(private):
            old_o=b"\xa6"*row["output_capacity"];old_w=bytes.fromhex(row["state_hex"])
            result,after_o,after_w=call(bytes.fromhex(row["request_hex"]),old_o,old_w,row["name"],ordinal,"private-control")
            require(result==row["expected_result"] and old_o==after_o and old_w==after_w,
                    "private refusal wrote complete output or state")
            counts["private_controls"]+=1
        require(stream.read(1)==b"" and counts["actual_calls"]==len(rows),"trailing complete capture bytes or ledger rows")
    require(counts==report["counts"] and counts["semantic_calls"]==1933 and counts["private_controls"]==68
        and counts["actual_calls"]==2144 and counts["growth_calls"]==143,"complete native call domain differs")
    projected=b"".join(projection);require(projected==expected(planned),"selected actual projection differs")
    return dict(status="PASS",counts=counts,projection_records=748,projection=pin(projected)),projected

def original_evidence(folder,source_sha,outer,projection):
    report=parse(read(folder/"CAPTURE.json"));identity=source_identity()
    require(report["schema"]=="hepta.runtime.audit-store-queue.original.v2" and report["status"]=="PASS"
        and report["source_manifest_sha256"]==source_sha and report["source_identity"]==identity
        and report["source_unchanged"] is True and report["original_tests"]==5
        and report["projection_records"]==748 and report["process_count"]==5
        and report["limited_original_projection_pass"] is True
        and report["all_native_boundaries_original_compared"] is False
        and report["concurrent_native_lock_qualified"] is False
        and report["whole_runtime_replaced"] is False,"original scope or source differs")
    for name in ("audit_store_lock.rs.txt","audit_store_tests.rs.txt","original_tests.rs","trace.rs"):
        require(read(folder/"project"/name)==read(ROOT/"reference"/name),"compiled original source changed")
    for name in ("tests","trace"):
        raw=read(folder/name);require(pin(raw)==report["binaries"][name]
            and raw[:5]==b"\x7fELF\x02" and raw[5]==1 and raw[18:20]==b"\x3e\x00","original ELF differs")
    records=parse(read(folder/"processes/processes.json"))
    require([r["name"] for r in records]==["rustc-version","tests-build","trace-build","tests","trace"],
        "original process domain differs")
    old_source=Path(outer["cwd"])
    old_output=Path(outer["argv"][outer["argv"].index("--output")+1])
    rust_bin=Path(outer["argv"][outer["argv"].index("--rust-bin")+1]);rustc=rust_bin/"rustc"
    argv=[
        [str(rustc),"--version","--verbose"],
        [str(rustc),*FLAGS,"--test","-C","incremental="+str(old_output/"incremental/tests"),
            str(old_output/"project/original_tests.rs"),"-o",str(old_output/"tests")],
        [str(rustc),*FLAGS,"-C","incremental="+str(old_output/"incremental/trace"),
            str(old_output/"project/trace.rs"),"-o",str(old_output/"trace")],
        [str(old_output/"tests"),"--test-threads=1"],[str(old_output/"trace")]]
    outputs=[]
    for n,(row,command,budget) in enumerate(zip(records,argv,(60,900,900,180,180),strict=True)):
        require(row["argv"]==command and row["parent_pid"]==outer["pid"]
            and row["cwd"]==str(old_output/"project" if n in (1,2) else old_source),"original actual process attribution differs")
        outputs.append(process(row,folder/"processes",row["name"],budget))
    require(outputs[0].decode()==report["rustc_version"] and outputs[0].startswith(b"rustc 1.95.0 "),
            "actual Rust version differs")
    require(outputs[1]==outputs[2]==b"","unexpected successful compiler stdout")
    check_tests(outputs[3])
    trace=read(folder/"trace.bin")
    require(trace==outputs[4]==projection and pin(trace)==report["trace"],"unchanged original and actual HIA projection differ")
    return dict(status="PASS",unchanged_original_tests=5,observable_projection_records=748,
        comparison=pin(trace),limited_original_projection_pass=True,
        all_native_boundaries_original_compared=False,concurrent_native_lock_qualified=False)
def verify(output,require_controls=False):
    source=verify_source();output=Path(output);gate=parse(read(output/"GATE.json"))
    require(gate["source_manifest_sha256"]==source and gate["whole_runtime_replaced"] is False,"gate source differs")
    records=parse(read(output/"processes/processes.json"))
    require([r["name"] for r in records[:3]]==["native-build","native-domain","original"]
        and len(records) in (3,4,5,6),"qualification process domain differs")
    old_source=Path(gate["execution_source_root"]);old_output=Path(gate["execution_output_root"])
    require(old_source.is_absolute() and old_output.is_absolute(),"producer roots differ")
    commands=[
        ["-I","-B",str(old_source/"build.py"),"--hepta",gate["hepta_root"],"--output",str(old_output/"build")],
        ["-I","-B",str(old_source/"run_native.py"),"--build",str(old_output/"build"),"--output",str(old_output/"native")],
        ["-I","-B",str(old_source/"original.py"),"--rust-bin",gate["rust_bin"],"--output",str(old_output/"original")]]
    for row,tail,budget in zip(records[:3],commands,(180,180,900),strict=True):
        require(Path(row["argv"][0]).is_absolute() and row["argv"][1:]==tail
            and row["cwd"]==str(old_source),"actual qualification argv differs")
        observed=parse(process(row,output/"processes",row["name"],budget))
        target={"native-build":"build/BUILD.json","native-domain":"native/CAPTURE.json","original":"original/CAPTURE.json"}[row["name"]]
        require(observed==parse(read(output/target)),"actual producer stdout differs from retained report")
    built,meta=build_evidence(output/"build",source)
    native,projection=native_evidence(output/"native",source,records[1]["pid"],meta)
    original=original_evidence(output/"original",source,records[2],projection)
    result=dict(status="COMPLETE_NATIVE_AND_LIMITED_ORIGINAL_AUDIT_QUEUE_PASS",
        source_manifest_sha256=source,build=built,native=native,original=original,
        all_native_boundaries_original_compared=False,concurrent_native_lock_qualified=False,
        public_audit_qualified=False,whole_runtime_replaced=False)
    if require_controls:
        from reader_controls import verify_controls
        result["reader_controls"]=verify_controls(output,source,records)
    for position in (3,5):
        if len(records)<=position:continue
        row=records[position]
        name="readonly-baseline" if position==3 else "readonly-complete"
        tail=["-I","-B",str(old_source/"verify_readonly.py"),"--output",str(old_output),
              "--source-manifest-sha256",source]
        if position==5:tail+=["--require-controls"]
        require(row["name"]==name and row["cwd"]==str(old_source)
            and Path(row["argv"][0]).is_absolute() and row["argv"][1:]==tail,"actual read-only command differs")
        proof=parse(process(row,output/"processes",name,180))
        require(proof["source_bound_guard"] is True and proof["before"]==proof["after"]
            and len(proof["probes"])==12 and proof["native_or_rust_executions"]==proof["reader_writes"]==0
            and proof["pid"]==row["pid"] and proof["ppid"]==row["parent_pid"] and proof["pgid"]==row["pgid"],
            "actual complete read-only proof differs")
        for key in ("status","source_manifest_sha256","build","native","original"):
            require(proof["evidence"][key]==result[key],"actual complete read-only admission differs")
    return result
