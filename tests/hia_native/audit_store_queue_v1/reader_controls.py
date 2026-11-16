"""Frozen complete-reader refusals and two relocated admissions; no HIA/Rust replay."""
from pathlib import Path
import argparse, gzip, hashlib, json, os, shutil, stat, struct, sys, time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
import read_capture
from read_capture import require,read,parse,safe
from build import pin,verify_source
from cases import encoded
from read_only_guard import guarded
NAMES=("native-input","native-output","native-workspace-before","native-workspace-after",
       "native-refusal-write","native-trailing-physical","native-trailing-ledger","native-process-id",
       "frozen-domain","original-trace","original-test-result","missing-original-binary",
       "process-timeout","process-budget","compiler-image","compiler-source")
MUTABLE=("GATE.json","processes/processes.json")
def inventory(root):
    result={}
    for path in sorted(root.rglob("*")):
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),"ordinary artifact tree")
        if stat.S_ISREG(info.st_mode):
            result[path.relative_to(root).as_posix()]={**pin(read(path)),"mode":stat.S_IMODE(info.st_mode)}
    return result
def mutate(root,name):
    backup={}
    def change(relative,raw):
        path=root/safe(relative)
        if relative not in backup:
            backup[relative]=(read(path),stat.S_IMODE(path.stat().st_mode))
        if raw is None:path.unlink()
        else:path.write_bytes(raw)
    def root_stream(kind,report):
        relative="processes/"+kind+".stdout"
        raw=(json.dumps(report,sort_keys=True)+"\n").encode()
        change(relative,raw)
        rows=parse(read(root/"processes/processes.json"))
        row=next(r for r in rows if r["name"]==kind)
        row["stdout"].update(pin(raw))
        change("processes/processes.json",encoded(rows))
    def native_sync():
        report=parse(read(root/"native/CAPTURE.json"))
        for rel in report["files"]:report["files"][rel]=pin(read(root/"native"/rel))
        change("native/CAPTURE.json",encoded(report));root_stream("native-domain",report)
    def ledger_write(rows):
        change("native/calls.jsonl",b"".join((json.dumps(r,sort_keys=True,separators=(",",":"))+"\n").encode() for r in rows))
    if name in NAMES[:5]:
        piece={"native-input":0,"native-output":2,"native-workspace-before":3,
               "native-workspace-after":4,"native-refusal-write":2}[name]
        raw=bytearray(gzip.decompress(read(root/"native/complete-buffers.bin.gz")))
        rows=[parse(x) for x in read(root/"native/calls.jsonl").splitlines()]
        offset=0;done=False
        for row in rows:
            result,*lengths=struct.unpack_from("<6Q",raw,offset)
            begin=offset+48+sum(lengths[:piece])
            selected=(row["kind"]=="private-control" if name=="native-refusal-write" else
                      row["kind"]=="semantic" and result==128)
            if selected and lengths[piece]>0:
                raw[begin+lengths[piece]-1]^=1
                key=("input","output_before","output_after","workspace_before","workspace_after")[piece]
                row["buffers"][key]=pin(bytes(raw[begin:begin+lengths[piece]]))
                done=True;break
            offset+=48+sum(lengths)
        require(done,"frozen mutation selector missing")
        change("native/complete-buffers.bin.gz",gzip.compress(raw,mtime=0))
        ledger_write(rows);native_sync()
    elif name=="native-trailing-physical":
        raw=gzip.decompress(read(root/"native/complete-buffers.bin.gz"))+b"x"
        change("native/complete-buffers.bin.gz",gzip.compress(raw,mtime=0));native_sync()
    elif name=="native-trailing-ledger":
        raw=read(root/"native/calls.jsonl")
        change("native/calls.jsonl",raw+raw.splitlines(keepends=True)[-1]);native_sync()
    elif name=="native-process-id":
        rows=[parse(x) for x in read(root/"native/calls.jsonl").splitlines()]
        for row in rows:row["pid"]+=1
        ledger_write(rows);native_sync()
    elif name=="frozen-domain":
        raw=gzip.decompress(read(root/"native/complete-domain.json.gz"))
        change("native/complete-domain.json.gz",gzip.compress(raw+b" ",mtime=0));native_sync()
    elif name in ("original-trace","original-test-result"):
        kind="trace" if name=="original-trace" else "tests"
        relative="original/processes/"+kind+".stdout";raw=read(root/relative)
        if kind=="trace":raw=raw[:-1]+bytes([raw[-1]^1])
        else:
            require(b" ... ok\n" in raw,"frozen original test output missing")
            raw=raw.replace(b" ... ok\n",b" ... FAILED\n",1)
        change(relative,raw)
        rows=parse(read(root/"original/processes/processes.json"))
        next(r for r in rows if r["name"]==kind)["stdout"].update(pin(raw))
        change("original/processes/processes.json",encoded(rows))
        if kind=="trace":
            change("original/trace.bin",raw)
            report=parse(read(root/"original/CAPTURE.json"));report["trace"]=pin(raw)
            change("original/CAPTURE.json",encoded(report));root_stream("original",report)
    elif name=="missing-original-binary":change("original/tests",None)
    elif name in ("process-timeout","process-budget"):
        rows=parse(read(root/"processes/processes.json"))
        if name=="process-timeout":rows[1]["timed_out"]=True
        else:rows[1]["timeout_seconds"]=181
        change("processes/processes.json",encoded(rows))
    elif name=="compiler-image":
        rel="build/modules/audit-store-queue/module.image.bin";raw=read(root/rel)
        change(rel,raw[:-1]+bytes([raw[-1]^1]))
    elif name=="compiler-source":
        rel="build/compiler-source/examples/hia_bootstrap/selfhost.hepta";raw=read(root/rel)
        change(rel,raw+b"\n")
    else:raise ValueError("unknown frozen reader mutation")
    return backup
def restore(root,backup):
    for name,(raw,mode) in backup.items():
        (root/name).write_bytes(raw);(root/name).chmod(mode)

def save_proof(folder,name,proof):
    raw=encoded(proof);packed=gzip.compress(raw,compresslevel=1,mtime=0)
    path=folder/(name+".json.gz");path.write_bytes(packed)
    require(gzip.decompress(read(path))==raw,"retained complete guard proof differs")
    return dict(file=path.name,packed=pin(packed),complete=pin(raw),entries=len(proof["before"]),
        guard_refusals=len(proof["probes"]),native_or_rust_executions=0,reader_writes=0)
def run(capture,folder):
    source=verify_source();started=time.monotonic()
    require(not folder.exists(),"reader controls output already exists")
    admitted=inventory(capture)
    work=capture.parent/(capture.name+"-reader-work")
    work.mkdir(exist_ok=False)
    locations=[]
    for name in ("one","two"):
        path=work/name
        shutil.copytree(capture,path,copy_function=shutil.copy2)
        require(inventory(path)==admitted,"complete relocated tree differs")
        locations.append(path)
    folder.mkdir()
    for name in MUTABLE:
        target=folder/"inputs"/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(read(capture/name));target.chmod(admitted[name]["mode"])
    report=dict(schema="hepta.runtime.audit-store-queue.reader-controls.v2",status="RUNNING",
        source_manifest_sha256=source,execution=dict(pid=os.getpid(),parent_pid=os.getppid(),
        pgid=os.getpgrp(),cwd=str(ROOT)),admitted_files=admitted,mutable_inputs=list(MUTABLE),
        controls=[],relocations=[],post_refusal=[],native_or_rust_executions=0,reader_writes=0,
        whole_runtime_replaced=False)
    def progress(): (folder/"result.json").write_bytes(encoded(report))
    progress()
    for path in locations:
        proof=guarded(lambda:read_capture.verify(path),roots=[ROOT,path],foreign_path=Path("/dev/null"))
        row=dict(name=path.name,status="PASS",proof=save_proof(folder,"relocation-"+path.name,proof),
            files=len(admitted),same_complete_source_and_artifact_identity=True)
        report["relocations"].append(row);progress()
    path=locations[0]
    for n,name in enumerate(NAMES):
        backup=mutate(path,name)
        try:
            def refuse():
                try:read_capture.verify(path)
                except (ValueError,AssertionError,FileNotFoundError) as exc:
                    return dict(status="REFUSED",error_type=type(exc).__name__,message=str(exc))
                raise RuntimeError("complete reader admitted frozen mutation: "+name)
            proof=guarded(refuse,roots=[ROOT,path],foreign_path=Path("/dev/null"))
            report["controls"].append(dict(name=name,status="REFUSED",
                proof=save_proof(folder,"negative-"+str(n+1).zfill(2),proof),
                refusal=proof["evidence"]))
            progress()
        finally:restore(path,backup)
    for path in locations:
        require(inventory(path)==admitted,"restored complete relocation differs")
        proof=guarded(lambda:read_capture.verify(path),roots=[ROOT,path],foreign_path=Path("/dev/null"))
        report["post_refusal"].append(dict(name=path.name,status="PASS",
            proof=save_proof(folder,"post-refusal-"+path.name,proof),
            files=len(admitted),same_complete_source_and_artifact_identity=True))
        progress()
    require(verify_source()==source,"reader source changed")
    report.update(status="PASS",elapsed_seconds=time.monotonic()-started)
    progress()
    print(json.dumps(dict(status="PASS",refusals=len(NAMES),relocations=2,post_refusal=2,
        native_or_rust_executions=0,reader_writes=0),sort_keys=True))
def verify_controls(output,source,records):
    folder=output/"reader-controls";report=parse(read(folder/"result.json"))
    require(report["schema"]=="hepta.runtime.audit-store-queue.reader-controls.v2"
        and report["status"]=="PASS" and report["source_manifest_sha256"]==source
        and report["native_or_rust_executions"]==report["reader_writes"]==0
        and report["whole_runtime_replaced"] is False,"complete reader controls scope differs")
    require(tuple(row["name"] for row in report["controls"])==NAMES
        and all(row["status"]=="REFUSED" for row in report["controls"]),"reader negative domain differs")
    require(report["mutable_inputs"]==list(MUTABLE),"mutable input custody differs")
    for name,identity in report["admitted_files"].items():
        path=folder/"inputs"/safe(name) if name in MUTABLE else output/safe(name)
        require({**pin(read(path)),"mode":stat.S_IMODE(path.stat().st_mode)}==identity,
                "admitted complete reader input differs")
    previous=parse(read(folder/"inputs/processes/processes.json"))
    require(len(previous)==4 and previous==records[:4],"actual pre-control process prefix differs")
    old_gate=parse(read(folder/"inputs/GATE.json"));current=parse(read(output/"GATE.json"))
    for key in ("source_manifest_sha256","execution_source_root","execution_output_root","hepta_root","rust_bin"):
        require(old_gate[key]==current[key],"actual pre-control source or roots changed")
    require(len(records)>=5 and records[4]["name"]=="reader-controls","actual reader controls process missing")
    row=records[4]
    require(row["pid"]==report["execution"]["pid"] and row["parent_pid"]==report["execution"]["parent_pid"]
        and row["pgid"]==report["execution"]["pgid"] and row["cwd"]==report["execution"]["cwd"]
        and row["cwd"]==current["execution_source_root"],"actual reader controls attribution differs")
    old_source=Path(row["cwd"]);old_output=Path(current["execution_output_root"])
    require(Path(row["argv"][0]).is_absolute() and row["argv"][1:]==
        ["-I","-B",str(old_source/"reader_controls.py"),"--capture",str(old_output),
         "--output",str(old_output/"reader-controls")],"actual reader control command differs")
    observed=parse(read_capture.process(row,output/"processes","reader-controls",180))
    require(observed==dict(status="PASS",refusals=len(NAMES),relocations=2,post_refusal=2,
        native_or_rust_executions=0,reader_writes=0),"actual reader controls stdout differs")
    for group in ("relocations","post_refusal"):
        require([r["name"] for r in report[group]]==["one","two"],"two complete relocation domain differs")
        for row in report[group]:
            require(row["status"]=="PASS" and row["files"]==len(report["admitted_files"])
                and row["same_complete_source_and_artifact_identity"] is True,"complete relocation not admitted")
    for row in report["relocations"]+report["controls"]+report["post_refusal"]:
        identity=row["proof"];raw=read(folder/safe(identity["file"]))
        require(pin(raw)==identity["packed"],"complete packed guard proof differs")
        raw=gzip.decompress(raw);require(pin(raw)==identity["complete"],"complete guard proof differs")
        proof=parse(raw)
        require(proof["source_bound_guard"] is True and len(proof["probes"])==identity["guard_refusals"]==12
            and proof["before"]==proof["after"] and len(proof["before"])==identity["entries"]
            and proof["native_or_rust_executions"]==proof["reader_writes"]==0,"complete guard evidence differs")
        if row["status"]=="REFUSED":
            require(proof["evidence"]==row["refusal"] and row["refusal"]["status"]=="REFUSED",
                    "actual injected refusal differs")
        else:
            require(proof["evidence"]["status"]=="COMPLETE_NATIVE_AND_LIMITED_ORIGINAL_AUDIT_QUEUE_PASS"
                and proof["evidence"]["source_manifest_sha256"]==source,"complete relocation proof differs")
    return dict(status="PASS",refusals=len(NAMES),relocations=2,post_refusal=2,
        complete_guard_proofs=20,native_or_rust_executions=0,reader_writes=0)
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    run(a.capture.resolve(strict=True),a.output.absolute())
