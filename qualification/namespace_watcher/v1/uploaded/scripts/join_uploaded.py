"""Join every uploaded V5 byte to a fresh complete pure read, without application replay."""
import argparse,hashlib,io,json,os,stat,sys,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/"reader"))
from reader_common import read,loads,encoded,pin,git,require,files,source,integer
from read_only_guard import guarded
from read_pairs import exact,elapsed
from read_producer import process
from evidence_controls import PROBES
def outer_source():
    m=loads(read(ROOT/"SOURCE_MANIFEST.json"));require(m["schema"]=="hepta.namespace-watcher.uploaded-source.v1",
        "exact independently frozen uploaded reader source")
    wanted={}
    for row in m["files"]:
        name=row["path"];p=Path(name);require(not p.is_absolute()and".."not in p.parts,"relative frozen source")
        body=read(ROOT/p);require(pin(body)=={k:row[k]for k in("bytes","sha256")}and git(body)==row["git_blob"]
            and row["mode"]=="100644","every complete frozen source byte")
        wanted[name]=dict(**pin(body),mode=0o644)
    require(files(ROOT,("SOURCE_MANIFEST.json",))==wanted,"whole independent source set")
    return pin(read(ROOT/"SOURCE_MANIFEST.json"))
def guard_proof(saved,scope,pid,ppid,pgid):
    require(saved["schema"]=="hepta.runtime.scope-span-readonly.v2"and saved["source_bound_guard"]is True
        and saved["native_or_rust_executions"]==saved["reader_writes"]==0
        and type(saved["native_or_rust_executions"])is int and type(saved["reader_writes"])is int
        and (saved["pid"],saved["ppid"],saved["pgid"])==(pid,ppid,pgid)
        and pid==pgid!=ppid and saved["before"]==saved["after"]and saved["before"],
        "complete actual owned read-only process and unchanged before/after capture")
    require([p["name"]for p in saved["probes"]]==list(PROBES)and
        all(set(p)=={"name","refusal","guard_event"}and p["refusal"]=="owner-export read-only guard: "+p["guard_event"]
            for p in saved["probes"]),"every actual fixed read-only refusal")
    wanted={}
    for index,records in enumerate(scope):
        directories={"."}
        for name,row in records.items():
            wanted[str(index)+":"+name]=row;directories.update(p.as_posix()for p in Path(name).parents)
        for name in directories:wanted[str(index)+":"+name]=None
    require(set(saved["before"])==set(wanted),"entire saved guard scope, no missing source/evidence member")
    for name,row in saved["before"].items():
        require(set(row)=={"mode","inode","device","bytes","mtime_ns","ctime_ns","sha256"}and
            all(type(row[k])is int and row[k]>=0 for k in set(row)-{"sha256"}),"complete captured metadata fields")
        expected=wanted[name]
        if expected is None:require(stat.S_ISDIR(row["mode"])and row["sha256"]is None,"captured ordinary guard directory")
        else:require(stat.S_ISREG(row["mode"])and stat.S_IMODE(row["mode"])==expected["mode"]and
            row["bytes"]==expected["bytes"]and row["sha256"]==expected["sha256"],"whole saved guard file bytes/modes")
def receipt(folder,name,argv,cwd,guard,scope):
    rows=loads(read(folder/"processes/processes.json"));require(len(rows)==1,"entire one owned pure process")
    row=rows[0];streams=process(row,dict(name=name,argv=argv,cwd=str(cwd),timeout=180),folder/"processes",guard["ppid"])
    require(streams["stderr"]==b""and row["pid"]==guard["pid"]and row["pgid"]==guard["pgid"],
        "complete successful reader stderr and matching owned process")
    guard_proof(guard,scope,row["pid"],row["parent_pid"],row["pgid"])
    require(set(files(folder/"processes"))=={"processes.json",name+".stdout",name+".stderr"},
        "no unclaimed pure reader stream")
    return row,streams
def semantic(folder,cwd,bundle_recorded,scope,expected):
    report=loads(read(folder/"GUARDED.json"))
    row,streams=receipt(folder,"semantic-reader",["/usr/bin/python3","-I","-B",str(cwd/"qualify.py"),
        "--bundle",str(bundle_recorded),"--output",str(Path(row_output(folder,cwd))/"GUARDED.json")],
        cwd,report,scope)
    summary=loads(streams["stdout"]);elapsed(summary["elapsed_seconds"],row["elapsed_seconds"])
    exact({k:v for k,v in summary.items()if k!="elapsed_seconds"},
        dict(status="COMPLETE_WATCHER_SEMANTIC_READ_PASS",cases=58,operations=984,
            guard_probes=12,files=len(report["before"]),complete_buffer_bytes=expected["complete_buffer_bytes"],
            reader_native_or_rust_executions=0),"whole actual semantic reader stdout")
    evidence=report["evidence"]
    require(evidence["status"]=="COMPLETE_WATCHER_SEMANTIC_READ_PASS"and
        all(evidence[k]==expected[k]for k in("cases","operations","application_processes","complete_buffer_bytes"))
        and evidence["reader_native_executions"]==evidence["reader_rust_executions"]==
        evidence["reader_application_executions"]==0,"whole original completed semantic domain")
    return dict(evidence=evidence,process=row,guard=pin(read(folder/"GUARDED.json")))
def row_output(folder,cwd):
    # Actual original CLI output belongs to the recorded source's sibling.
    if cwd==ROOT/"reader":return folder
    require(folder.name in("reader","relocated-reader"),"whole original semantic output role")
    return cwd.parent/folder.name
def control_read(folder,cwd,bundle_recorded,controls_recorded,scope):
    raw=read(folder/"processes/physical-controls-read.stdout");report=loads(raw)
    row,streams=receipt(folder,"physical-controls-read",["/usr/bin/python3","-I","-B",str(cwd/"evidence_controls.py"),
        "--phase","verify","--bundle",str(bundle_recorded),"--output",str(controls_recorded/"evidence")],
        cwd,report,scope)
    require(streams["stdout"]==raw and report["evidence"]["status"]=="COMPLETE_PHYSICAL_CONTROLS_READ_PASS"
        and report["evidence"]["physical_refusals"]==16 and report["evidence"]["whole_group_admissions"]==2
        and report["evidence"]["retained_guard_probes"]==216 and
        report["evidence"]["reader_native_executions"]==report["evidence"]["reader_rust_executions"]==
        report["evidence"]["reader_application_executions"]==0,"whole actual uploaded physical controls read")
    return dict(evidence=report["evidence"],process=row,guard=pin(raw))
def uploaded_bytes(uploaded,archive):
    binding=loads(read(ROOT/"UPLOADED-PINS.json"));raw=read(archive)
    require(pin(raw)==binding["uploaded"]["zip"],"complete pinned uploaded reader ZIP independently read")
    expected={};count=0
    with zipfile.ZipFile(io.BytesIO(raw))as z:
        require(len(set(z.namelist()))==len(z.infolist()),"whole unique uploaded ZIP")
        for member in z.infolist():
            name=member.filename;p=Path(name.rstrip("/"))
            require(not p.is_absolute()and".."not in p.parts and p.as_posix()==name.rstrip("/"),"whole uploaded ordinary path")
            if member.is_dir():continue
            body=z.read(member);require(len(body)==member.file_size and read(uploaded/name)==body,
                "every complete uploaded source/control/process/buffer byte")
            mode=stat.S_IMODE((member.external_attr>>16)&0xffff)or 0o644
            expected[name]=dict(**pin(body),mode=mode);count+=len(body)
    require(files(uploaded)==expected and len(expected)==binding["uploaded"]["files"],"whole uploaded file set/modes")
    return dict(zip=pin(raw),files=len(expected),logical_bytes=count)
def verify(bundle,uploaded,fresh,controls_read,archive,capture_zip):
    outer=outer_source();binding=loads(read(ROOT/"UPLOADED-PINS.json"));wanted=binding["expected"]
    require(source()==binding["uploaded"]["source_sha256"]and
        files(uploaded/"source")==files(ROOT/"reader"),"every independently frozen old reader source")
    upload=uploaded_bytes(uploaded,archive)
    require(pin(read(capture_zip))==binding["capture"]["zip"],"whole unchanged captured original/native archive")
    scopes=[files(bundle),files(ROOT/"reader")]
    ctl=loads(read(uploaded/"controls/evidence/CONTROLS.json"));old=Path(ctl["source_root"])
    require(old.is_absolute()and old.parts[-2:]==("namespace-watcher-semantic-reader-v5","source"),
        "exact original producer source-root attribution")
    require(ctl["bundle"]==str(old.parent/"retained/complete")and ctl["output_root"]==str(old.parent/"controls/evidence"),
        "same source-bound original control paths")
    one=semantic(uploaded/"reader",old,old.parent/"retained/complete",scopes,wanted)
    two=semantic(uploaded/"relocated-reader",old,old.parent/"relocated/complete",scopes,wanted)
    new=semantic(fresh,ROOT/"reader",bundle,scopes,wanted)
    exact(one["evidence"],two["evidence"],"both complete original physical-root semantic results")
    exact(one["evidence"],new["evidence"],"whole uploaded semantic result independently rebuilt without replay")
    controls_scope=scopes+[files(uploaded/"controls")]
    original_controls=control_read(uploaded/"controls-read",old,old.parent/"retained/complete",
        old.parent/"controls",controls_scope)
    current_controls=control_read(controls_read,ROOT/"reader",bundle,uploaded/"controls",controls_scope)
    exact(original_controls["evidence"],current_controls["evidence"],
        "every complete uploaded physical refusal/admission independently rebuilt")
    require(all(ctl[k]==wanted[k]for k in("physical_refusals","whole_group_admissions","guard_probes","full_cloned_bytes")),
        "whole actual physical-control totals")
    return dict(status="COMPLETE_UPLOADED_WATCHER_SEMANTIC_AND_CONTROLS_PASS",source=outer,
        uploaded=upload,capture_zip=binding["capture"]["zip"],cases=58,operations=984,
        application_processes=39,complete_buffer_bytes=wanted["complete_buffer_bytes"],
        physical_refusals=16,whole_group_admissions=2,retained_physical_guard_probes=216,
        full_cloned_bytes=wanted["full_cloned_bytes"],
        original_semantic=one,relocated_semantic=two,independent_semantic=new,
        original_controls=original_controls,independent_controls=current_controls,
        reader_native_executions=0,reader_rust_executions=0,reader_application_executions=0,
        completed_application_replays=0,namespace_version_qualified=False,public_handler_qualified=False)
def run(args):
    # All imports are source-only. Warm deterministic ZIP machinery before guard.
    outer_source();source()
    with zipfile.ZipFile(io.BytesIO(read(args.archive)))as z:z.namelist()
    started=time.monotonic()
    roots=[args.bundle,args.uploaded,ROOT,args.fresh,args.controls_read,args.archive.parent]
    result=guarded(lambda:verify(args.bundle,args.uploaded,args.fresh,args.controls_read,args.archive,args.capture_zip),
        roots=roots,foreign_path="/home/runner/work/_temp/namespace-watcher-semantic-reader-v5/retained/complete/CAPTURE.json")
    require(time.monotonic()-started<=180,"whole independent upload reader unchanged deadline")
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes(encoded(result))
    e=result["evidence"];print(encoded({k:e[k]for k in("status","cases","operations","application_processes",
        "complete_buffer_bytes","physical_refusals","whole_group_admissions","retained_physical_guard_probes",
        "completed_application_replays")}|dict(guard_probes=len(result["probes"]),files=len(result["before"]),
        elapsed_seconds=time.monotonic()-started)).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in("bundle","uploaded","fresh","controls-read","archive","capture-zip","output"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    for name in("bundle","uploaded","fresh","controls_read","archive","capture_zip"):
        setattr(a,name,getattr(a,name).resolve(strict=True))
    a.output=a.output.absolute();run(a)
