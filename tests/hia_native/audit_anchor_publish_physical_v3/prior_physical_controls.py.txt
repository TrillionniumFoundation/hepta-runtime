"""Two complete relocated admissions and fifteen real rehashed physical refusals."""
from pathlib import Path
import os
import physical_common as pc
import bundle,mutations

ADMISSIONS=("one","nested/two")
PROBES=("python-file-write","descriptor-open","descriptor-write","metadata-mode","metadata-time","directory-create",
        "subprocess","shell","native-dlopen","native-mmap","producer-or-foreign-read","unadmitted-file-descriptor")

def guarded_proof(proof,evidence):
    pc.check(proof["before"]==proof["after"] and proof["evidence"]==evidence and proof["source_bound_guard"] is True and
             proof["native_or_rust_executions"]==proof["reader_writes"]==0 and
             tuple(p["name"] for p in proof["probes"])==PROBES and
             all(type(p["guard_event"]) is str and p["guard_event"] and p["refusal"].startswith("owner-export read-only guard: ") for p in proof["probes"]),
             "all original guard branches and complete unchanged metadata/bytes")

def refused(folder,prepared):
    try:bundle.verify(folder,prepared)
    except ValueError as failure:return dict(refused=True,error=str(failure))
    raise ValueError("source-derived physical mutation accepted")

def run(retained,output):
    original=retained/"restored/prior/source";prepared=bundle.prepare(original);identity=pc.source()
    output.mkdir(parents=True,exist_ok=False);base=output/"baseline";bundle.make_bundle(retained,base)
    baseline=bundle.verify(base,prepared);old=bundle.custody(retained,baseline);rows=[]
    for name in (*ADMISSIONS,*mutations.NAMES):
        admitted=name in ADMISSIONS;relative=name if admitted else "refusals/"+name;target=output/relative
        before=bundle.copy_files(base,target);changed={} if admitted else mutations.changes(base,name)
        for n,raw in changed.items():(target/n).write_bytes(raw)
        operation=(lambda:bundle.verify(target,prepared)) if admitted else (lambda:refused(target,prepared))
        proof=prepared["guard"].guarded(operation,roots=bundle.roots(target,prepared),foreign_path=str(base/"BUNDLE.json"))
        observed=proof["evidence"];guarded_proof(proof,observed)
        if admitted:pc.check(observed==baseline,"entire relocated original/control verdict identical")
        filename=name.replace("/","-")+".json";(output/filename).write_bytes(pc.enc(proof))
        rows.append(dict(name=name,admission=admitted,relative=relative,proof=filename,physical=pc.files(target),
                         changes={n:pc.pin(b) for n,b in changed.items()},evidence=observed))
    pc.check(pc.source()==identity,"complete physical-control source remains unchanged")
    report=dict(schema="hepta.audit-anchor-publish.physical-controls.v1",status="PASS",source_manifest_sha256=identity,
                names=list(mutations.NAMES),admissions=2,refusals=len(mutations.NAMES),rows=rows,baseline=baseline,prior_verification=old,
                pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),source_root=str(pc.ROOT),retained_root=str(retained),output_root=str(output),
                native_or_rust_executions=0,reader_writes_during_verification=0)
    (output/"CONTROLS.json").write_bytes(pc.enc(report))
    return summary(output,report)

def summary(output,report):
    return dict(status="COMPLETE_PHYSICAL_PUBLISHER_CONTROLS_PASS",admissions=report["admissions"],refusals=report["refusals"],
                names=report["names"],guard_probes=12*len(report["rows"]),report=pc.pin(pc.read(output/"CONTROLS.json")),
                source_manifest_sha256=report["source_manifest_sha256"],native_or_rust_executions=0)

def verify(retained,output,prepared):
    report=pc.loads(pc.read(output/"CONTROLS.json"));base=output/"baseline"
    pc.check(report["schema"]=="hepta.audit-anchor-publish.physical-controls.v1" and report["status"]=="PASS" and
             report["source_manifest_sha256"]==pc.source() and report["names"]==list(mutations.NAMES) and
             report["admissions"]==2 and report["refusals"]==len(mutations.NAMES) and len(report["rows"])==2+len(mutations.NAMES) and
             report["native_or_rust_executions"]==report["reader_writes_during_verification"]==0,"exact complete physical-control scope")
    baseline=bundle.verify(base,prepared);old=bundle.custody(retained,baseline)
    pc.check(report["baseline"]==baseline and report["prior_verification"]==old,"same complete original and actual control evidence")
    base_files=pc.files(base)
    for name,row in zip((*ADMISSIONS,*mutations.NAMES),report["rows"],strict=True):
        admitted=name in ADMISSIONS;relative=name if admitted else "refusals/"+name;folder=output/relative
        pc.check(row["name"]==name and row["admission"] is admitted and row["relative"]==relative and row["proof"]==name.replace("/","-")+".json",
                 "ordered exact physical-control identity")
        pc.check(set(row["changes"])<=set(base_files),"only admitted bundle paths are mutated")
        compressed={n:pc.read(folder/n) for n in row["changes"] if n.endswith(".bin.gz")}
        changed={} if admitted else mutations.changes(base,name,compressed=compressed)
        pc.check(set(compressed)=={n for n in changed if n.endswith(".bin.gz")},"only exact actual compressed mutation paths")
        expected=dict(base_files)
        for n,raw in changed.items():expected[n]=dict(**pc.pin(raw),mode=base_files[n]["mode"])
        pc.check(pc.files(folder)==row["physical"]==expected and row["changes"]=={n:pc.pin(b) for n,b in changed.items()},
                 "whole retained physical copy equals exact rehashed source mutation")
        observed=bundle.verify(folder,prepared) if admitted else refused(folder,prepared)
        pc.check(observed==row["evidence"] and (not admitted or observed==baseline),"unchanged complete reader decision")
        guarded_proof(pc.loads(pc.read(output/row["proof"])),observed)
    return dict(status="COMPLETE_PHYSICAL_PUBLISHER_CONTROLS_PASS",admissions=2,refusals=len(mutations.NAMES),
                guard_probes=12*(2+len(mutations.NAMES)),baseline=baseline,prior_verification=old,
                native_or_rust_executions=0,reader_writes=0)
