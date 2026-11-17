#!/usr/bin/env python3
"""Independent complete uploaded write evidence admission; no application or control replay."""
from pathlib import Path,PurePosixPath
import argparse,gzip,hashlib,os,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from readonly import guarded
from read_capture import verify as compare
import capture_archive_input as archive_input
def frozen(digest):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==digest,"frozen independent write reader")
    return source_evidence(ROOT),decode((ROOT/"BINDING.json").read_bytes())
def process(row,folder,success=True):
    require(row["pid"]==row["pgid"]and row["completed"]and not row["timed_out"]
        and row["exit_code"]==(0 if success else 1)and row["stdin"]is None
        and 0<=row["elapsed_seconds"]<=row["timeout_seconds"]and row["timeout_seconds"]in(60,180),
        "complete bounded natural recorded process")
    streams={}
    for kind in("stdout","stderr"):
        item=row[kind];require(item["file"]==row["name"]+"."+kind,"recorded stream path")
        path=folder/item["file"];require(pin(path)=={k:item[k]for k in("bytes","sha256")},"every complete recorded stream")
        streams[kind]=path.read_bytes()
    if success:require(streams["stderr"]==b"","successful recorded process diagnostic")
    return streams
def guard_identity(value):
    require(value["status"]=="READONLY_PASS"and value["before"]==value["after"]
        and value["native_executed"]is False and value["rust_executed"]is False and value["evidence_written"]is False
        and len(value["before"])==value["entries"]and len(value["probes"])==11
        and all(p["rejected"]for p in value["probes"]),"complete retained pure guard outcome")
def rebound_guard(value,source,capture,old_source,old_work):
    guard_identity(value);roots=[]
    for raw in value["roots"]:
        path=PurePosixPath(raw)
        if str(path)==old_source:root=source
        else:
            require(path.is_relative_to(PurePosixPath(old_work)),"retained guard owned root")
            root=capture/path.relative_to(PurePosixPath(old_work)).as_posix()
        require(root.is_dir(),"complete retained guard root exists");roots.append(root)
    actual=[]
    for number,root in enumerate(roots):
        for p in [root,*sorted(root.rglob("*"))]:
            mode=p.lstat().st_mode;require(stat.S_ISDIR(mode)or stat.S_ISREG(mode),"ordinary full guard copy")
            row=dict(root=number,path="."if p==root else p.relative_to(root).as_posix(),mode=stat.S_IMODE(mode))
            if p.is_file():row.update(pin(p))
            actual.append(row)
    recorded=[]
    for old in value["before"]:
        row=dict(root=old["root"],path=old["path"],mode=stat.S_IMODE(old["mode"]))
        if stat.S_ISREG(old["mode"]):row.update(bytes=old["bytes"],sha256=old["sha256"])
        else:require(stat.S_ISDIR(old["mode"]),"saved guard ordinary entry")
        recorded.append(row)
    require(actual==recorded,"every saved pure guard file/directory/byte/mode rebound")
    return dict(entries=len(actual),guards=11)
def runtime(source,folder):
    value=decode((folder/"RUNTIME.json").read_bytes())
    require(value["status"]=="SOURCE_AND_RUNTIME_ONLY_PASS"and value["source"]==source_evidence(source)
        and value["python"]==dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
        and value["python_version"]==[3,12,3]and value["signal_profile"]=={"13":1,"25":1}
        and value["original_write_application_calls"]==value["native_write_application_calls"]==0,
        "complete actual runtime/source preflight")
    require({p.name for p in folder.iterdir()}=={"RUNTIME.json"}|{r["copy"]for r in value["modules"].values()},
        "whole actual module set")
    for name,row in value["modules"].items():
        require(pin(folder/row["copy"])=={k:row[k]for k in("bytes","sha256")}and row["interpreter"]==value["python"],
            "actual full standard-library module bytes")
        if row["kind"]=="built-in-elf":require(row["origin"]=="built-in"and row["copy"]=="python.elf"
            and {k:row[k]for k in("bytes","sha256")}==value["python"],"actual builtin in fixed interpreter")
        else:require(row["kind"]=="module-file","declared module source class")
    return value
def build_proof(source,capture):
    bound=decode((source/"BUILD_REUSE.json").read_bytes());folder=capture/"build-evidence"
    proof=decode((folder/"RETIREMENT_PROOF.json").read_bytes());manifest=decode((folder/"ARTIFACT_MANIFEST.json").read_bytes())
    unpacked=decode((folder/"UNPACK.json").read_bytes());read=decode((capture/"BUILD_READ.json").read_bytes());guard_identity(read)
    require(proof["status"]=="COMPLETE_ARCHIVE_EQUALITY_BEFORE_RETIREMENT"and proof["all_file_bytes_modes_and_directories_equal"]
        and proof["application_calls"]==0 and not(capture/"original").exists(),"explicit full equality before retired copy cleanup")
    require(pin(capture/"download/complete.zip")==proof["archive"]=={k:bound["artifact"][k]for k in("bytes","sha256")},
        "complete original build archive retained and read")
    require(pin(capture/"production/binary-write-body-callable.elf")==proof["retained_executable"]==bound["elf"],
        "complete unchanged actual production ELF")
    require(pin(folder/"ARTIFACT_MANIFEST.json")==proof["manifest"]and pin(folder/"UNPACK.json")==proof["unpack"]
        and pin(capture/"BUILD_READ.json")==proof["read"],"complete original build indexes and pure read")
    require(manifest["gate_status"]=="PASS"and manifest["git_head"]==bound["commit"]
        and manifest["schema"]=="hepta.runtime.binary-write-body-build.complete-archive.v1"
        and len(manifest["files"])==proof["files"]==bound["tar"]["logical_files"]
        and len(manifest["directories"])==proof["directories"]==bound["tar"]["directories"]
        and sum(v["bytes"]for v in manifest["files"].values())==proof["logical_bytes"]==bound["tar"]["logical_bytes"],
        "complete original archived build set")
    require(unpacked["all_objects_fully_read"]and unpacked["all_logical_files_and_directories_restored"]
        and read["evidence"]["status"]=="COMPLETE_QUALIFIED_BUILD_REUSE_PASS"and read["evidence"]["application_calls"]==0,
        "retained full build reread made no applications")
    return dict(status="COMPLETE_BUILD_ARCHIVE_AND_RETIREMENT_BOUND",logical_files=proof["files"],
        logical_bytes=proof["logical_bytes"],prior_guard_entries=read["entries"],prior_guard_probes=11)
def controls(source,capture,old_source,old_work):
    folder=capture/"controls";value=decode((folder/"CONTROLS.json").read_bytes())
    require(value["status"]=="PHYSICAL_CONTROLS_PASS"and value["refusals"]==8 and value["admissions"]==2
        and value["application_calls"]==value["control_replays"]==0 and value["all_variants_retained"],
        "retained actual physical control outcomes")
    plan=decode((source/"DOMAIN.json").read_bytes())["fixed_physical_controls"]
    names=plan["negative"]+plan["relocations"];require([r["name"]for r in value["controls"]]==names,"all frozen physical variants")
    processes=decode((folder/"processes/processes.json").read_bytes());require([r["process"]for r in value["controls"]]==processes,
        "all physical reader process receipts")
    seen=0
    for row in value["controls"]:
        name=row["name"];root=folder/name
        streams=process(row["process"],folder/"processes")
        require(decode(streams["stdout"])==row["result"]and row["expected"]==
            ("REFUSED"if name in plan["negative"]else"ADMITTED")and row["result"]["evidence"]["status"]==row["expected"],
            "whole original physical result process binding")
        mapped=rebound_guard(row["result"],source,capture,old_source,old_work);seen+=mapped["entries"]
        base_files={p.relative_to(source).as_posix():pin(p)for p in source.rglob("*")if p.is_file()}
        changed_files={p.relative_to(root/"source").as_posix():pin(p)for p in(root/"source").rglob("*")if p.is_file()}
        require(set(base_files)==set(changed_files),"whole physical source copy set")
        if name=="source-bytes":
            path="trusted-build/native/binary_write_body.hepta"
            require((root/"source"/path).read_bytes()==(source/path).read_bytes()+b"\n"
                and all(changed_files[p]==base_files[p]for p in base_files if p!=path),"precise retained source mutation")
        else:require(base_files==changed_files,"all exact unmodified physical source bytes")
        require((root/"runtime/RUNTIME.json").read_bytes()==(capture/"runtime/RUNTIME.json").read_bytes(),"complete runtime copied unchanged")
        if name in plan["relocations"]:
            original={p.relative_to(capture/"cases/0").as_posix():pin(p)for p in(capture/"cases/0").rglob("*")if p.is_file()}
            relocated={p.relative_to(root/"data").as_posix():pin(p)for p in(root/"data").rglob("*")if p.is_file()}
            require(original==relocated,"whole relocation data bytes admitted without replay")
    return dict(status="ALL_PHYSICAL_VARIANTS_AND_PRIOR_READERS_REBOUND",refusals=8,admissions=2,
        prior_guards=110,entries=seen,new_control_executions=0)
def source_failure(work,bound):
    import io,zipfile
    path=work/"source-failure/download/complete.zip"
    require(pin(path)=={k:bound["artifact"][k]for k in("bytes","sha256")},"whole initial source-only failure ZIP")
    files={}
    with zipfile.ZipFile(path)as archive:
        for member in archive.infolist():
            archive_input.safe(member.filename);require(not member.is_dir()and member.filename not in files,"ordinary source failure member")
            raw=archive.read(member);require(len(raw)==member.file_size,"full source failure member");files[member.filename]=raw
    require(set(files)=={"GATE.json","processes/processes.json","processes/runtime-source.stdout","processes/runtime-source.stderr","runtime/base64.py"},
        "entire initial source-only failure set")
    gate=decode(files["GATE.json"]);rows=decode(files["processes/processes.json"])
    require(gate["status"]=="FAIL"and gate["source"]["manifest"]["sha256"]==bound["manifest_sha256"]
        and gate["applications"]==[]and not gate["replay_permitted"]and gate["processes"]==rows and len(rows)==1,
        "historical source-only failure had no applications")
    row=rows[0];require(row["name"]=="runtime-source"and row["exit_code"]==1 and row["completed"]and not row["timed_out"]
        and row["pid"]==row["pgid"]and row["timeout_seconds"]==180 and row["stdin"]is None,"source-only failed process custody")
    for stream in("stdout","stderr"):
        raw=files["processes/runtime-source."+stream]
        require(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())=={k:row[stream][k]for k in("bytes","sha256")},
            "complete initial source failure streams")
    require(files["processes/runtime-source.stdout"]==b""and b"module 'binascii' has no attribute '__file__'"in files["processes/runtime-source.stderr"],
        "exact original source collector failure")
    return dict(status="COMPLETE_INITIAL_SOURCE_FAILURE_RETAINED",files=len(files),bytes=sum(map(len,files.values())),application_calls=0)
def verify(work,name):
    bound=archive_input.binding(ROOT,name);retained=work/"capture"
    archive=archive_input.verify(ROOT,retained,name)
    base=retained/"original/restored";source=base/"source";capture=base/"run";qualified=ROOT/"qualified"
    a={p.relative_to(source).as_posix():pin(p)for p in source.rglob("*")if p.is_file()}
    b={p.relative_to(qualified).as_posix():pin(p)for p in qualified.rglob("*")if p.is_file()}
    require(a==b and pin(source/"SOURCE_MANIFEST.json")["sha256"]==bound["manifest_sha256"],"all complete frozen actual source files")
    source_evidence(source);runtime_input=runtime(source,capture/"runtime");build=build_proof(source,capture)
    gate=decode((capture/"GATE.json").read_bytes());processes=decode((capture/"processes/processes.json").read_bytes())
    require(gate["status"]==bound["gate_status"]and gate["group"]==int(name)and gate["source"]==source_evidence(source)
        and gate["processes"]==processes and gate["application_replays"]==gate["prior_completed_applications_replayed"]==0,
        "retained complete original gate including historical pure failure")
    domain=decode((source/"DOMAIN.json").read_bytes());group=next(r for r in domain["groups"]if r["id"]==int(name));cases=group["cases"]
    require([(r["case"],r["role"],r["status"])for r in gate["applications"]]==
        [(i,role,"PASS")for i in cases for role in("original","native")],"every original/native capture completed exactly once")
    failed_names={r["stage"]for r in gate["failures"]};expected_fail={"pure-read-53","pure-read-54","pure-read-55"}if name=="19"else set()
    require(failed_names==expected_fail,"exact preserved non-application failure extent")
    old_source=processes[0]["cwd"];argv=processes[0]["argv"];old_work=str(PurePosixPath(argv[argv.index("--output")+1]).parent)
    require(PurePosixPath(old_work).name=="write-actual-"+name,"actual original owned capture root")
    for row in processes:
        success=row["name"]not in failed_names;streams=process(row,capture/"processes",success)
        if not success:
            require(streams["stdout"]==b""and b"ValueError:"in streams["stderr"],"complete failed pure reader evidence")
        require(row["timeout_seconds"]==(60 if row["name"].startswith("capture-")else 180),"fixed process budget")
    previous=[]
    for row in gate["reads"]:
        result=row["result"];streams=process(row["process"],capture/"processes")
        require(decode(streams["stdout"])==result and result["evidence"]["case"]==row["case"],"complete prior successful pure read")
        previous.append(rebound_guard(result,source,capture,old_source,old_work))
    require([r["case"]for r in gate["reads"]]==([]if name=="19"else cases),"retained successful comparison set")
    result=[compare(source,capture/"cases"/str(i),i,runtime_input)for i in cases]
    initial=source_failure(work,decode((ROOT/"BINDING.json").read_bytes())["initial_source_failure"])if name=="0"else None
    physical=controls(source,capture,old_source,old_work)if name=="0"else None
    if name!="0":require(gate["controls"]is None and not(capture/"controls").exists(),"no undeclared physical controls")
    else:require(gate["controls"]==decode((capture/"controls/CONTROLS.json").read_bytes()),"whole control gate binding")
    return dict(status="COMPLETE_INDEPENDENT_WRITE_UPLOAD_PASS",group=int(name),archive=archive,build=build,
        actual=result,physical=physical,initial_source_failure=initial,retained_successful_readers=previous,preserved_pure_failures=sorted(failed_names),
        original_capture_invocations=sum(domain["cases"][i]["requests"]for i in cases),
        native_capture_invocations=sum(domain["cases"][i]["requests"]for i in cases),
        new_application_executions=0,completed_controls_replayed=0,whole_runtime_replaced=False)
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","restore","read"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();before,bindings=frozen(a.source_manifest_sha256);bound=bindings["groups"][a.group];work=a.work.absolute()
    if a.stage=="fetch":
        result=archive_input.fetch(work/"capture",bound)
        if a.group=="0":result["initial_source_failure"]=archive_input.fetch(work/"source-failure",bindings["initial_source_failure"])
    elif a.stage=="restore":result=archive_input.unpack(work/"capture",bound)
    else:result=guarded(lambda:verify(work,a.group),roots=[ROOT,work/"capture"]+([work/"source-failure"]if a.group=="0"else[]))
    require(source_evidence(ROOT)==before,"frozen independent source unchanged")
    print(encoded(result).decode(),end="")
