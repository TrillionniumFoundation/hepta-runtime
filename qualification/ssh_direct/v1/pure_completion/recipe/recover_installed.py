#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Only the missing second-relocation original comparison; no applications or controls."""
from pathlib import Path,PurePosixPath
from decimal import Decimal
import argparse,hashlib,importlib.util,os,stat,sys,tarfile,time,traceback,zipfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,pin,raw_pin,need,stable,unpack,inventories
from common import source_evidence
PREFIX="filesystem-public/original-controls/relocated-two"
def normalized(name):
    if name in(".","./"):return "."
    n=name[2:]if name.startswith("./")else name;p=PurePosixPath(n)
    need(not p.is_absolute()and".."not in p.parts and p.as_posix()==n.rstrip("/"),"canonical frozen TAR member");return n.rstrip("/")
def inflate(a,inputs):
    need(not a.tar.exists(),"fresh whole original uncompressed TAR")
    before=stable(a.original_zip);need(pin(a.original_zip)==inputs["original"]["zip"],"all bytes of immutable original failure ZIP")
    h=hashlib.sha256();size=0
    with zipfile.ZipFile(a.original_zip)as z:
        names=[x.filename for x in z.infolist()];need(len(names)==len(set(names))and"failure-evidence.tar"in names,"fixed whole original archive")
        manifest=decode(z.read("manifest.json"))
        need(manifest["status"]=="COMPLETE"and manifest["archive"]["complete"]is True and manifest["original_failure_reclassified_as_pass"]is False,"original failed run remains failed")
        need({k:manifest["archive"]["archive"][k]for k in("bytes","sha256")}==inputs["original"]["tar"],"complete original TAR receipt")
        with z.open("failure-evidence.tar")as incoming,a.tar.open("xb")as out:
            while block:=incoming.read(1<<20):h.update(block);size+=len(block);out.write(block)
    need(dict(bytes=size,sha256=h.hexdigest())==inputs["original"]["tar"],"whole 10.8 GB original TAR bytes")
    need(stable(a.original_zip)==before,"immutable original ZIP not changed")
    result=dict(status="COMPLETE_ORIGINAL_FAILURE_TAR_INFLATED_AND_HASHED",zip=inputs["original"]["zip"],tar=inputs["original"]["tar"],
        source_metadata=stable(a.original_zip),tar_metadata=stable(a.tar),applications_executed=0)
    (a.output/"INFLATE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
def metadata(a,inputs):
    root=unpack(a.metadata_zip,a.stage/"metadata",inputs["bound_metadata"]);bound=decode((root/"BIND.json").read_bytes())
    need(bound["second_native_phase_complete"]is True and bound["second_full_phase_complete"]is False and bound["second_process_receipt_present"]is False,"only missing frozen second original-comparison phase")
    need(pin(root/"MEMBERS.json")==inputs["member_index"],"complete earlier original TAR member index")
    return root,bound,decode((root/"MEMBERS.json").read_bytes())
def extract(a,inputs):
    original=decode((a.output/"INFLATE.json").read_bytes());need(stable(a.tar)==tuple(original["tar_metadata"]),"same fully hashed original TAR")
    meta,bound,index=metadata(a,inputs);wanted={r["path"]:r for r in index["tar"]};need(len(wanted)==110036,"all original TAR metadata")
    bundle=a.output/"owned-second-relocation";need(not bundle.exists(),"new second relocation physical root");bundle.mkdir(mode=0o700)
    selected=[];dirs=[];seen=set();logical=0
    with tarfile.open(a.tar,"r:")as t:
        for m in t:
            name=normalized(m.name);need(name in wanted and name not in seen,"all original TAR members");seen.add(name);r=wanted[name]
            need((m.mode,m.uid,m.gid,m.size,m.mtime,m.type.decode(),m.linkname,m.pax_headers)==
                (r["mode"],r["uid"],r["gid"],r["size"],r["mtime"],r["type"],r["linkname"],r["pax"]),"whole original TAR header binding")
            if not(name==PREFIX or name.startswith(PREFIX+"/")):continue
            relative=""if name==PREFIX else name[len(PREFIX)+1:]
            dst=bundle if not relative else bundle/relative
            need(m.isdir()or m.isfile(),"second bundle ordinary complete files and directories")
            ns=int(Decimal(m.pax_headers.get("mtime",str(m.mtime)))*1000000000)
            row=dict(path=relative,kind="dir"if m.isdir()else"file",mode=m.mode,mtime_ns=ns,bytes=m.size)
            if m.isdir():dst.mkdir(parents=True,exist_ok=True);dirs.append((dst,row))
            else:
                dst.parent.mkdir(parents=True,exist_ok=True);h=hashlib.sha256();n=0
                with t.extractfile(m)as incoming,dst.open("xb")as out:
                    while b:=incoming.read(1<<20):h.update(b);n+=len(b);out.write(b)
                need(n==m.size and h.hexdigest()==r["sha256"],"every original second-bundle file byte")
                row["sha256"]=h.hexdigest();logical+=n;os.chmod(dst,m.mode);os.utime(dst,ns=(ns,ns))
            selected.append(row)
    need(seen==set(wanted)and stable(a.tar)==tuple(original["tar_metadata"]),"complete original header set and unchanged hashed TAR")
    for dst,row in reversed(dirs):os.chmod(dst,row["mode"]);os.utime(dst,ns=(row["mtime_ns"],row["mtime_ns"]))
    files=[r for r in selected if r["kind"]=="file"];subdirs=[r for r in selected if r["kind"]=="dir"and r["path"]]
    need(dict(files=len(files),directories=len(subdirs),logical_file_bytes=logical)==inputs["expected_bundle"],"full original second bundle scope")
    for row in selected:
        dst=bundle/row["path"];s=dst.lstat()
        need((stat.S_ISREG(s.st_mode)if row["kind"]=="file"else stat.S_ISDIR(s.st_mode))and stat.S_IMODE(s.st_mode)==row["mode"]and s.st_mtime_ns==row["mtime_ns"],"complete second bundle installed metadata")
    known=decode((a.source/"KNOWN_SOURCES.json").read_bytes());source_rows=[]
    for r in known:
        if r["path"].startswith(PREFIX+"/"):
            rel=r["path"][len(PREFIX)+1:];path=bundle/rel;frozen=a.source/"retained-sources"/rel
            need(pin(path)=={k:r[k]for k in("bytes","sha256")}and path.read_bytes()==frozen.read_bytes(),"all actual reader source bytes frozen before execution")
            source_rows.append(dict(path=rel,**pin(path)))
    mapping=decode((bundle/"mapping.json").read_bytes())
    for name,expected in mapping["copy_pins"].items():need(pin(bundle/name)==expected,"every original physical input copy pin")
    copied=a.output/"prior-completed-evidence";copied.mkdir()
    for p in sorted((meta/"retained-controls").rglob("*")):
        dst=copied/p.relative_to(meta/"retained-controls")
        if p.is_dir():dst.mkdir(parents=True,exist_ok=True)
        else:dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(p.read_bytes());need(pin(dst)==pin(p),"complete retained prior receipt bytes")
    result=dict(status="ONLY_MISSING_SECOND_COMPARISON_INPUTS_READY",bundle=str(bundle.resolve()),mapping=pin(bundle/"mapping.json"),
        complete_files=len(files),complete_directories=len(subdirs),logical_bytes=logical,source_files=source_rows,
        archive_inputs=inputs,metadata_binding=bound,completed_refusals_replayed=0,completed_first_relocation_replayed=0,second_standalone_native_phase_replayed=0)
    (a.output/"EXTRACTED_FILES.json").write_bytes(canonical(selected));(a.output/"READY.json").write_bytes(canonical(result))
    print(canonical({k:result[k]for k in("status","complete_files","complete_directories","logical_bytes","completed_refusals_replayed","completed_first_relocation_replayed","second_standalone_native_phase_replayed")}).decode(),end="")
def finish(a,inputs):
    ready=decode((a.output/"READY.json").read_bytes());bundle=Path(ready["bundle"]);prior=a.output/"prior-completed-evidence"
    need(ready["archive_inputs"]==inputs,"same frozen recovery plan");binding=source_evidence(a.source);snap=inventories(bundle)
    old_native=(prior/"relocation-2/NATIVE-EVIDENCE.json").read_bytes()
    need(old_native==(prior/"NATIVE-BASELINE.json").read_bytes(),"retain completed second standalone native phase byte-for-byte")
    original_metadata=decode((bundle/"mapping.json").read_bytes());forbidden=[Path(p)for p in original_metadata["blocked_original_paths"]if p.startswith("/")]
    attempts=[]
    def audit(event,args):
        if event.startswith(("subprocess.","os.exec","os.spawn","os.posix_spawn"))or event in("os.system","ctypes.dlopen"):
            raise PermissionError("no application/compiler/control process permitted in pure continuation")
        if event!="open"or not args or not isinstance(args[0],(str,bytes,os.PathLike)):return
        path=Path(os.fsdecode(args[0])).absolute()
        if path.is_relative_to(bundle):return
        if any(path==p or path.is_relative_to(p)for p in forbidden):
            attempts.append(str(path));raise PermissionError("old execution-path access denied in second relocation")
    sys.addaudithook(audit)
    process=dict(schema="hepta.installed.second-original-phase.process.v1",argv=sys.argv,pid=os.getpid(),cwd=os.getcwd(),python=str(Path(sys.executable).resolve()),
        interpreter=pin(Path(sys.executable).resolve()),started_ns=time.time_ns(),timeout_seconds=180,status="STARTED",
        operation="unchanged actual test_native_evidence.admit_bundle",standalone_native_phase_replayed=False,applications=0)
    receipt=a.output/"CONTINUATION_PROCESS.json";receipt.write_bytes(canonical(process));began=time.monotonic_ns()
    try:
        path=bundle/"admission/test_native_evidence.py";raw=path.read_bytes()
        need(pin(path)==dict(bytes=33908,sha256="48cf4f1cd230d7a3662d9e0d60dad8013efefbc67f77fff2dab718de3afdd7e3"),"exact original already reviewed pure entry")
        spec=importlib.util.spec_from_file_location("_actual_unfinished_second_relocation",path);module=importlib.util.module_from_spec(spec)
        exec(compile(raw,str(path),"exec"),module.__dict__)
        proof=module.admit_bundle(bundle)
        encoded=module.canonical(proof);baseline=(prior/"BASELINE.json").read_bytes()
        need(encoded==baseline and decode(encoded)==decode(baseline),"entire unchanged original second comparison equals original baseline")
        need(not attempts,"no old execution path/live fixture access")
        (a.output/"EVIDENCE.json").write_bytes(encoded);(a.output/"NATIVE-EVIDENCE.json").write_bytes(old_native)
        need(inventories(bundle)==snap and source_evidence(a.source)==binding,"pure continuation changed input/source bytes or metadata")
        result=dict(status="INSTALLED_SECOND_RELOCATION_COMPLETE",second_native_phase="retained original completed proof; not rerun",
            missing_original_phase="unchanged actual original admit_bundle completed once",original_comparison=pin(a.output/"EVIDENCE.json"),
            native_only=pin(a.output/"NATIVE-EVIDENCE.json"),whole_original_object_equal=True,whole_native_object_equal=True,
            original_path_read_attempts=0,completed_refusals_preserved=42,completed_first_relocation_preserved=True,
            completed_refusals_replayed=0,completed_first_relocation_replayed=0,second_standalone_native_phase_replayed=0,
            new_hia_applications=0,new_rust_applications=0,new_compilers=0,new_pure_phase_invocations=1,old_failures=inputs["old_failures"],
            public_scope_expanded=False,inputs=inputs,source=binding)
        (a.output/"RESULT.json").write_bytes(canonical(result));process["status"]="COMPLETE";process["exit_code"]=0
        print(canonical(result).decode(),end="")
    except BaseException:
        process["status"]="FAILED_OR_UNKNOWN";process["exception"]=traceback.format_exc();raise
    finally:
        process["finished_ns"]=time.time_ns();process["elapsed_ns"]=time.monotonic_ns()-began;receipt.write_bytes(canonical(process))
def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("inflate","extract","finish"))
    for n in("source","output","stage","tar","original_zip","metadata_zip"):p.add_argument("--"+n.replace("_","-"),type=Path,required=True)
    a=p.parse_args();need(os.environ.get("GITHUB_ACTIONS")=="true","CI-only complete artifact reading")
    inputs=decode((a.source/"INSTALLED_INPUTS.json").read_bytes());source_evidence(a.source)
    if a.mode=="inflate":need(not a.output.exists()and not a.stage.exists(),"fresh entire pure recovery");a.output.mkdir();a.stage.mkdir();inflate(a,inputs)
    elif a.mode=="extract":extract(a,inputs)
    else:finish(a,inputs)
if __name__=="__main__":main()
