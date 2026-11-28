"""Retained physical rehashed refusals and complete ordinary relocation admissions."""
import argparse,copy,os,stat,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from reader_common import read,loads,encoded,pin,files,source,require,integer
import qualify,legacy_build,read_pairs,read_trace,read_outer,read_native,read_producer,evidence_mutations
from read_only_guard import guarded
NAMES=evidence_mutations.NAMES
PROBES=("python-file-write","descriptor-open","descriptor-write","metadata-mode","metadata-time",
    "directory-create","subprocess","shell","native-dlopen","native-mmap","producer-or-foreign-read","unadmitted-file-descriptor")
ORDER=("admission-one",)+NAMES+("admission-two",)
def physical(root):
    identities=files(root)
    return {name:read(root/name)for name in identities},{name:row["mode"]for name,row in identities.items()}
def prepare(bundle):
    identity=source();prepared=qualify.prepare(bundle);admission=legacy_build.verify(bundle/"retained",prepared["build"])
    m=loads(read(bundle/"run/CAPTURE.json"));d=loads(read(ROOT/"DOMAIN.json"))
    require(read(bundle/"source/DOMAIN.json")==read(ROOT/"DOMAIN.json")and
        m["status"]=="PRODUCERS_PASS_READBACK_PENDING"and
        m["source_manifest_sha256"]==pin(read(ROOT/"PRODUCER-SOURCE.json"))["sha256"],
        "same exact completed source and full control-domain attribution")
    command=next(r for r in loads(read(bundle/"run/processes/processes.json"))if r["name"]=="paired-ordinary")
    cases=[c for c in d["cases"]if c["group"]=="ordinary"];require(cases,"original ordinary full cases retained")
    data,modes=physical(bundle/"run/paired-ordinary");baseline={"group/"+n:b for n,b in data.items()}
    baseline_modes={"group/"+n:mode for n,mode in modes.items()}
    expected={n[len("paired-ordinary/"):]:row for n,row in m["files"].items()if n.startswith("paired-ordinary/")}
    require({n:dict(**pin(b),mode=modes[n])for n,b in data.items()}==expected,"entire actual baseline group, not a fabricated reduced case")
    for name,row in files(ROOT).items():baseline["source/"+name]=read(ROOT/name);baseline_modes["source/"+name]=row["mode"]
    return dict(bundle=bundle,identity=identity,admission=admission,m=m,command=command,cases=cases,
        baseline=baseline,modes=baseline_modes,producer=dict(python_resolved="/usr/bin/python3.12"))
def check(root,state):
    source(root/"source",read(ROOT/"SOURCE.json"))
    pair=read_pairs.verify(root/"group",state["m"],state["command"],state["cases"],state["producer"])
    traces=[read_trace.verify(root/"group/roles"/name,role,pair["commands"])for name,role in zip(read_pairs.ROLES,pair["roles"])]
    outer=[read_outer.verify(t,pair["commands"],r)for t,r in zip(traces,pair["roles"])]
    kernel=read_trace.compare(traces,state["cases"])
    native=[read_native.verify(root/"group/roles"/name/"capture",pair,i,state["m"],state["admission"],traces[i])
        for i,name in enumerate(read_pairs.ROLES[:2])]
    read_pairs.exact(native[0]["turns"],native[1]["turns"],"complete observed/off native turn counts")
    require(native[0]["private_owner_calls"]==native[1]["private_owner_calls"],"complete observed/off private callbacks")
    return dict(status="COMPLETE_ORDINARY_GROUP_ADMISSION",pair=pair["summary"],kernel=kernel,outer=outer,native=native)
def try_check(root,state):
    try:return dict(accepted=True,report=check(root,state))
    except ValueError as error:return dict(accepted=False,exception=type(error).__name__,message=str(error))
def copy_exact(data,modes,root):
    root.mkdir(parents=True,exist_ok=False)
    for name,body in data.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("xb")as stream:stream.write(body)
        path.chmod(modes[name])
def expected(state,name):
    return state["baseline"]if name.startswith("admission-")else evidence_mutations.mutate(state["baseline"],name)
def compare_tree(root,data,modes):
    require(files(root)=={n:dict(**pin(b),mode=modes[n])for n,b in data.items()},
        "complete retained physical control bytes/modes, no omitted or extra file")
    # Read all source and evidence members, not only the changed file or a summary.
    for name,body in data.items():require(read(root/name)==body,"entire reconstructed actual control member "+name)
def altered_files(before,after):
    require(set(before)==set(after),"physical mutation preserves the complete admitted file set")
    return {n:dict(before=pin(before[n]),after=pin(after[n]))for n in sorted(before)if before[n]!=after[n]}
def guard_admission(saved,pid,ppid,pgid,expected_files):
    require(saved["schema"]=="hepta.runtime.scope-span-readonly.v2"and saved["source_bound_guard"]is True
        and type(saved["native_or_rust_executions"])is int and type(saved["reader_writes"])is int
        and saved["native_or_rust_executions"]==saved["reader_writes"]==0
        and type(saved["pid"])is int and saved["pid"]==pid and saved["ppid"]==ppid and saved["pgid"]==pgid
        and saved["before"]==saved["after"]and saved["before"],
        "complete original actual readonly guard and owned process")
    require([p["name"]for p in saved["probes"]]==list(PROBES)and
        all(set(p)=={"name","refusal","guard_event"}and p["refusal"]=="owner-export read-only guard: "+p["guard_event"]
            for p in saved["probes"]),"all twelve original guard refusals")
    wanted={}
    for index,records in enumerate((expected_files,files(ROOT))):
        dirs={"."}
        for name,item in records.items():
            wanted[str(index)+":"+name]=item
            dirs.update(p.as_posix()for p in Path(name).parents)
        for name in dirs:wanted[str(index)+":"+name]=None
    require(set(saved["before"])==set(wanted),"entire exact captured guard scope includes both full source and physical clone")
    for name,row in saved["before"].items():
        require(set(row)=={"mode","inode","device","bytes","mtime_ns","ctime_ns","sha256"}and
            all(type(row[k])is int and row[k]>=0 for k in set(row)-{"sha256"}),
            "whole exact original snapshot metadata")
        expected=wanted[name]
        if expected is None:require(stat.S_ISDIR(row["mode"])and row["sha256"]is None,"whole captured guard directory")
        else:require(stat.S_ISREG(row["mode"])and stat.S_IMODE(row["mode"])==expected["mode"]and
            row["bytes"]==expected["bytes"]and row["sha256"]==expected["sha256"],
            "each captured full guard file matches the physically retained bytes")
def create(bundle,output):
    started=time.monotonic();state=prepare(bundle);output.mkdir(parents=True,exist_ok=False);rows=[];seen=set()
    report=dict(schema="hepta.namespace-watcher.physical-controls.v1",status="RUNNING",source_sha256=state["identity"],
        producer_source_sha256=state["m"]["source_manifest_sha256"],source_root=str(ROOT),bundle=str(bundle),output_root=str(output),
        pid=os.getpid(),ppid=os.getppid(),pgid=os.getpgrp(),deadline_seconds=180,
        native_executions=0,rust_executions=0,application_executions=0,scope="complete ordinary group clone controls; full 58-case admissions remain separate",
        order=list(ORDER),rows=rows)
    (output/"CONTROLS.json").write_bytes(encoded(report))
    try:
        for index,name in enumerate(ORDER):
            clone=output/("%02d-%s"%(index,name));data=expected(state,name);copy_exact(data,state["modes"],clone)
            for relative in data:
                info=(clone/relative).stat();key=(info.st_dev,info.st_ino)
                require(key not in seen,"all physical control clones have distinct ordinary-file inodes");seen.add(key)
            changes=altered_files(state["baseline"],data)
            require(bool(changes)==(not name.startswith("admission-")),"actual fixed admission/refusal mutation")
            result=guarded(lambda:try_check(clone,state),roots=[clone,ROOT],foreign_path=state["m"]["producer_root"]+"/CAPTURE.json")
            guard_admission(result,os.getpid(),os.getppid(),os.getpgrp(),files(clone))
            require(result["evidence"]["accepted"]==name.startswith("admission-"),"actual physical admission/refusal outcome "+name)
            row=dict(index=index,name=name,clone=clone.name,changes=changes,files=files(clone),guard=result)
            rows.append(row);(output/"CONTROLS.json").write_bytes(encoded(report))
        report.update(status="COMPLETE_PHYSICAL_CONTROLS_PASS",elapsed_seconds=time.monotonic()-started,
            physical_refusals=len(NAMES),whole_group_admissions=2,guard_probes=12*len(ORDER),
            full_cloned_bytes=sum(sum(x["bytes"]for x in r["files"].values())for r in rows))
        require(report["elapsed_seconds"]<=180 and source()==state["identity"],"whole unchanged evidence-control deadline and source")
        (output/"CONTROLS.json").write_bytes(encoded(report))
        print(encoded({k:report[k]for k in("status","elapsed_seconds","physical_refusals","whole_group_admissions","guard_probes","full_cloned_bytes")}).decode(),end="")
    except BaseException as error:
        report.update(status="FAIL",elapsed_seconds=time.monotonic()-started,exception=repr(error))
        (output/"CONTROLS.json").write_bytes(encoded(report));raise
    return report
def verify(bundle,output,state):
    require(state["bundle"]==bundle and state["identity"]==source(),"same preloaded exact reader and actual completed bundle")
    r=loads(read(output/"CONTROLS.json"));require(r["schema"]=="hepta.namespace-watcher.physical-controls.v1"
        and r["status"]=="COMPLETE_PHYSICAL_CONTROLS_PASS"and r["source_sha256"]==state["identity"]
        and r["producer_source_sha256"]==state["m"]["source_manifest_sha256"]
        and r["order"]==list(ORDER)and r["scope"]=="complete ordinary group clone controls; full 58-case admissions remain separate"
        and type(r["deadline_seconds"])is int and r["deadline_seconds"]==180
        and all(type(r[k])is int and r[k]==0 for k in("native_executions","rust_executions","application_executions")),
        "whole actual pure-controls report and unchanged domain")
    read_pairs.elapsed(r["elapsed_seconds"],180)
    require(all(integer(r[k],1)for k in("pid","ppid","pgid"))and r["pid"]==r["pgid"]!=r["ppid"],
        "actual separately owned pure-controls process")
    for path in("source_root","bundle","output_root"):require(Path(r[path]).is_absolute()and".."not in Path(r[path]).parts,"original attribution path")
    require(len(r["rows"])==len(ORDER)and {p.name for p in output.iterdir()}==
        {"CONTROLS.json"}|{"%02d-%s"%(i,n)for i,n in enumerate(ORDER)},"all complete physical clones and no additions")
    process_folder=output.parent/"processes";process_rows=loads(read(process_folder/"processes.json"))
    require(output.name=="evidence"and len(process_rows)==1,"complete original single owned evidence-control process")
    row=process_rows[0];wanted=dict(name="physical-controls",argv=["/usr/bin/python3","-I","-B",
        str(Path(r["source_root"])/"evidence_controls.py"),"--phase","create","--bundle",r["bundle"],"--output",r["output_root"]],
        cwd=r["source_root"],timeout=180)
    streams=read_producer.process(row,wanted,process_folder,r["ppid"])
    require(row["pid"]==r["pid"]and row["pgid"]==r["pgid"]and streams["stderr"]==b"",
        "actual complete controls receipt and observed PID chain")
    read_pairs.exact(loads(streams["stdout"]),{k:r[k]for k in("status","elapsed_seconds","physical_refusals",
        "whole_group_admissions","guard_probes","full_cloned_bytes")},"whole actual controls process stdout")
    proofs=[];seen=set()
    for index,(name,row)in enumerate(zip(ORDER,r["rows"])):
        require(set(row)=={"index","name","clone","changes","files","guard"}and type(row["index"])is int and
            row["index"]==index and row["name"]==name and row["clone"]=="%02d-%s"%(index,name),"fixed control partition")
        clone=output/row["clone"];data=expected(state,name)
        compare_tree(clone,data,state["modes"]);require(files(clone)==row["files"]and
            altered_files(state["baseline"],data)==row["changes"],"complete original changed-byte closure")
        for relative in data:
            info=(clone/relative).stat();key=(info.st_dev,info.st_ino)
            require(key not in seen,"independent physical clone file identity");seen.add(key)
        guard_admission(row["guard"],r["pid"],r["ppid"],r["pgid"],row["files"])
        outcome=try_check(clone,state);read_pairs.exact(outcome,row["guard"]["evidence"],"same complete physical readonly control verdict")
        require(outcome["accepted"]==name.startswith("admission-"),"all original physical mutations still reject")
        proofs.append(dict(name=name,accepted=outcome["accepted"],changes=row["changes"],files=len(row["files"])))
    require(r["physical_refusals"]==len(NAMES)and r["whole_group_admissions"]==2 and
        r["guard_probes"]==12*len(ORDER)and r["full_cloned_bytes"]==
        sum(sum(x["bytes"]for x in row["files"].values())for row in r["rows"]),"complete independently reconstructed controls totals")
    return dict(status="COMPLETE_PHYSICAL_CONTROLS_READ_PASS",source_sha256=state["identity"],physical_refusals=len(NAMES),
        whole_group_admissions=2,retained_guard_probes=r["guard_probes"],proofs=proofs,
        reader_native_executions=0,reader_rust_executions=0,reader_application_executions=0)
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--phase",choices=("create","verify"),required=True)
    p.add_argument("--bundle",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    bundle=a.bundle.resolve(strict=True)
    if a.phase=="create":create(bundle,a.output.absolute())
    else:
        state=prepare(bundle)
        result=guarded(lambda:verify(bundle,a.output.resolve(strict=True),state),
            roots=[bundle,ROOT,a.output.resolve(strict=True).parent],foreign_path=state["m"]["producer_root"]+"/CAPTURE.json")
        print(encoded(result).decode(),end="")
