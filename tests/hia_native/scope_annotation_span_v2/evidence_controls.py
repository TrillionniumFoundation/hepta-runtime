"""Retain every old admission control, plus physical rehash and allocation refusals."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import shutil
import struct
import sys
import time
from parallel_reader import launch_workers, read_workers

ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
import qualify as q
from read_capture import SHA,PACK,parse,read,pin,file_pin,jsonlines,require
from read_only_guard import guarded

NAMES=("native-status", "native-case-omitted", "native-call-count", "native-reference-inflation", "native-process-pid",
    "native-input-changed", "native-result-changed", "native-call-owner", "native-partial-output",
    "native-truncated-footer", "native-unclaimed-record", "shared-constructor-extent", "constructor-growth-required",
    "constructor-refusal-lifecycle", "control-omitted", "control-budget-changed", "control-patch-changed",
    "control-original-inflation", "control-input-changed", "control-complete-workspace-changed",
    "process-timed-out", "process-not-complete", "process-source-command", "process-deadline", "foreign-copy-symlink",
    "buffer-chunk-rehashed", "module-image-rehashed", "child-handoff-rehashed", "observation-rehashed",
    "value-growth-minimum", "value-initial-output-admission",
    "owner-initial-output-admission", "owner-initial-input-admission")


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def lines(rows):return b"".join((json.dumps(r,sort_keys=True,separators=(",",":"))+"\n").encode() for r in rows)
def edit(raw,fn):value=parse(raw);fn(value);return encoded(value)
def editlines(raw,fn):value=[parse(r) for r in raw.splitlines()];fn(value);return lines(value)



def worker(capture, output, worker_name, baseline_sha):
    baseline_raw=read(output/"inputs/BASELINE.json")
    require(SHA(baseline_raw)==baseline_sha,"worker baseline seal differs")
    data=parse(baseline_raw)
    source_sha=q.verify_source()
    require(source_sha==data["source_manifest_sha256"] and str(ROOT)==data["source_root"],
            "worker source differs")
    require(str(capture)==data["capture_root"] and str(output)==data["output_root"]
            and os.getppid()==data["parent_pid"] and os.getpgrp()==data["parent_pgid"],
            "worker launch ownership differs")
    require(worker_name in ("one","two"),"unknown reader worker")
    selected=tuple(data["partition"][worker_name])
    require(selected==NAMES[0 if worker_name=="one" else 1::2],"worker control partition differs")
    semantic={key:bytes.fromhex(value) for key,value in data["semantic_recoveries"].items()}
    baseline=data["baseline"]
    identities=data["admitted_files"]
    files=set(identities)
    one=output/"copies"/worker_name
    two=output/"copies"/("two" if worker_name=="one" else "one")
    folder=output/"workers"/worker_name
    folder.mkdir(parents=True,exist_ok=False)
    started=time.monotonic_ns()
    report=dict(schema="hepta.scope-annotation-span.reader-worker.v1",status="RUNNING",
                name=worker_name,baseline_sha256=baseline_sha,source_manifest_sha256=source_sha,
                controls=[],relocations=[],post_refusal=[],native_processes_executed=0,
                original_processes_executed=0,
                execution=dict(pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),
                               cwd=str(Path.cwd()),started_monotonic_ns=started))
    save=lambda:(folder/"result.json").write_bytes(encoded(report))
    save()
    def native(directory):
        q.process_custody(directory,source_sha)
        return q.native_evidence(directory/"native",directory/"build",source_sha)[0]
    def controls(directory):
        q.process_custody(directory,source_sha)
        return q.controls_evidence(directory/"controls",directory/"build",source_sha,semantic)
    def build(directory):
        return q.build_evidence(directory/"build",source_sha)
    def complete(directory):
        return dict(native=native(directory),controls=controls(directory),build=build(directory))
    def checked(directory,reader):
        answer=guarded(lambda:reader(directory),roots=[ROOT,directory],foreign_path=Path("/dev/null"))
        require(len(answer["probes"])==12 and answer["before"]==answer["after"],"reader guard differs")
        return answer
    def retain_proof(answer, prefix):
        raw=encoded(answer)
        proof_name=prefix+"-"+worker_name+".json.gz"
        (output/proof_name).write_bytes(gzip.compress(raw,compresslevel=1,mtime=0))
        return dict(name=worker_name,status="PASS",files=len(files),
                    same_complete_source_and_artifact_identity=True,processes_executed=0,
                    guard_refusals=12,unchanged_entries=len(answer["before"]),
                    proof_file=proof_name,proof=pin(raw))
    try:
        answer=checked(one,complete)
        require(answer["evidence"]==baseline,"complete relocated reader differs")
        report["relocations"].append(retain_proof(answer,"relocation"))
        save()
        def refuse(control_name,reader,changes):
            if control_name not in selected:
                return
            saved={p:read(one/p,256<<20) if (one/p).exists() else None for p in changes}
            changed={}
            try:
                for p,fn in changes.items():
                    raw=fn(saved[p]);(one/p).write_bytes(raw);changed[p]=pin(raw)
                def rejected(directory):
                    try:reader(directory)
                    except (ValueError,AssertionError,KeyError,EOFError,OSError,UnicodeDecodeError) as error:
                        return dict(name=control_name,status="REFUSED",error_type=type(error).__name__,reason=str(error)[:300])
                    raise RuntimeError("strict reader accepted mutation: "+control_name)
                answer=checked(one,rejected)
                row=answer["evidence"]
                row.update(changed_files=changed,guard_refusals=12,unchanged_entries=len(answer["before"]),
                           reader_pid=answer["pid"],reader_parent_pid=answer["ppid"],reader_pgid=answer["pgid"])
                report["controls"].append(row);save()
            finally:
                for p,raw in saved.items():
                    if raw is None:(one/p).unlink()
                    else:(one/p).write_bytes(raw)
        def first_packet(raw,fn):
            data=gzip.decompress(raw);size=struct.unpack_from("<Q",data)[0]
            first=bytearray(data[8:8+size]);fn(first)
            return gzip.compress(PACK(len(first))+bytes(first)+data[8+size:],compresslevel=1,mtime=0)
        path="native/CAPTURE.json"
        for name,fn in (
            ("native-status",lambda v:v.update(status="RUNNING")),
            ("native-case-omitted",lambda v:v.update(cases=v["cases"]-1)),
            ("native-call-count",lambda v:v.update(native_calls=v["native_calls"]-1)),
            ("native-reference-inflation",lambda v:v.update(original_execution=True)),
            ("native-process-pid",lambda v:v.update(execution_pid=v["execution_pid"]+1))):
            refuse(name,native,{path:lambda b,fn=fn:edit(b,fn)})
        refuse("native-input-changed",native,{"native/inputs.bin.gz":lambda b:first_packet(b,lambda x:x.__setitem__(48,91))})
        refuse("native-result-changed",native,{"native/observed.bin.gz":lambda b:first_packet(b,lambda x:x.__setitem__(48,1))})
        refuse("native-call-owner",native,{"native/calls.jsonl":lambda b:editlines(b,lambda rows:rows[0].update(owner="unbound"))})
        refuse("native-partial-output",native,{"native/calls.jsonl":lambda b:editlines(b,lambda rows:rows[0]["output_after"].update(bytes=1))})
        refuse("native-truncated-footer",native,{"native/observed.bin.gz":lambda b:b[:-6]})
        refuse("native-unclaimed-record",native,{"native/observed.bin.gz":lambda b:gzip.compress(gzip.decompress(b)+PACK(1)+b"x",compresslevel=1,mtime=0)})
        def constructor_extent(rows):
            row=next(r for r in rows if r["child"]==3);row["response_bytes"]+=1
        refuse("shared-constructor-extent",native,{"native/handoffs.jsonl":lambda b:editlines(b,constructor_extent)})
        def growth_extent(rows):
            actual=jsonlines(one/"controls/calls.jsonl")
            row=next(r for r in rows if r["kind"]==2 and actual[r["after_call"]-1]["owner"]=="text_result_constructor")
            row["after"]["bytes"]+=1
        refuse("constructor-growth-required",controls,{"controls/growth.jsonl":lambda b:editlines(b,growth_extent)})
        refuse("constructor-refusal-lifecycle",controls,{"controls/CAPTURE.json":lambda b:edit(b,lambda v:v["child_refusals"][0].update(expected_code=0))})
        path="controls/CAPTURE.json"
        for name,fn in (
            ("control-omitted",lambda v:v["refusals"].pop()),
            ("control-budget-changed",lambda v:v.update(physical_buffer_bytes=1)),
            ("control-patch-changed",lambda v:v["refusals"][9]["patches"][0].update(hex="00"*8)),
            ("control-original-inflation",lambda v:v.update(original_execution=True))):
            refuse(name,controls,{path:lambda b,fn=fn:edit(b,fn)})
        refuse("control-input-changed",controls,{"controls/000001/input.bin":lambda b:b"x"+b[1:]})
        first=jsonlines(one/"controls/buffers.jsonl")[0]["file"]
        refuse("control-complete-workspace-changed",controls,{"controls/"+first:lambda b:gzip.compress(b"x"+gzip.decompress(b)[1:],compresslevel=1,mtime=0)})
        for name,fn in (("process-timed-out",lambda p:p[1].update(timed_out=True)),
                        ("process-not-complete",lambda p:p[1].update(completed=False)),
                        ("process-source-command",lambda p:p[1]["argv"].__setitem__(3,p[1]["argv"][3]+".wrong")),
                        ("process-deadline",lambda p:p[1].update(timeout_seconds=181))):
            refuse(name,native,{"gate-processes/processes.json":lambda b,fn=fn:edit(b,fn)})
        if "foreign-copy-symlink" in selected:
            linked=one/"native/CAPTURE.json";saved=read(linked)
            linked.unlink();linked.symlink_to(two/"native/CAPTURE.json")
            try:
                try:native(one)
                except (ValueError,AssertionError,OSError) as error:
                    report["controls"].append(dict(name="foreign-copy-symlink",status="REFUSED",error_type=type(error).__name__,reason=str(error)[:300]))
                else:raise RuntimeError("foreign copy alias was admitted")
            finally:linked.unlink();linked.write_bytes(saved)
        rehashed_controls(one,refuse,native,build)
        def growth_minimum(rows):
            actual=jsonlines(one/"native/calls.jsonl")
            row=next(r for r in rows if r["kind"]==1 and actual[r["after_call"]-1]["owner"]=="serde_json_span")
            row["minimum"]+=1
        refuse("value-growth-minimum",native,{"native/growth.jsonl":lambda b:editlines(b,growth_minimum)})
        def initial_admission(rows):
            row=next(r for r in rows if r["owner"]=="serde_json_span" and r["admission"] is not None)
            row["admission"]["capacity"]+=8
        refuse("value-initial-output-admission",native,{"native/sessions.jsonl":lambda b:editlines(b,initial_admission)})
        def owner_capacity(rows):
            row=next(r for r in rows if r["owner"]=="scope_annotation_span" and r["admission"] is not None)
            row["admission"]["capacity"]+=8
        refuse("owner-initial-output-admission",native,{"native/sessions.jsonl":lambda b:editlines(b,owner_capacity)})
        def owner_input(rows):
            row=next(r for r in rows if r["owner"]=="scope_annotation_span" and r["admission"] is not None)
            row["admission"]["input_sha256"]="0"*64
        refuse("owner-initial-input-admission",native,{"native/sessions.jsonl":lambda b:editlines(b,owner_input)})

        require(tuple(row["name"] for row in report["controls"])==selected,"complete worker refusal domain changed")
        require(all(file_pin(one/n)==identities[n] for n in files),"worker physical copy was not exactly restored")
        answer=checked(one,complete)
        require(answer["evidence"]==baseline,"post-refusal complete read differs")
        report["post_refusal"].append(retain_proof(answer,"post-refusal"))
        report.update(status="READER_WORKER_PASS")
    except BaseException as error:
        report.update(status="FAIL",error=dict(type=type(error).__name__,message=str(error)))
        raise
    finally:
        report["execution"]["finished_monotonic_ns"]=time.monotonic_ns()
        report["elapsed_seconds"]=(report["execution"]["finished_monotonic_ns"]-started)/1e9
        save()
    print(json.dumps(dict(status=report["status"],name=worker_name,controls=len(selected),relocations=1,
                         native_processes_executed=0,original_processes_executed=0,
                         execution=report["execution"],result=pin(read(folder/"result.json"))),sort_keys=True))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--worker",choices=("one","two"))
    parser.add_argument("--baseline-sha")
    args=parser.parse_args()
    started=time.monotonic_ns()
    capture=args.capture.resolve(strict=True);output=args.output.absolute()
    if args.worker is not None:
        require(args.baseline_sha is not None,"worker needs its complete source-bound baseline")
        return worker(capture,output,args.worker,args.baseline_sha)
    require(args.baseline_sha is None,"parent cannot accept an external baseline")
    output.mkdir(parents=True,exist_ok=False)
    source_sha=q.verify_source()
    report=dict(schema="hepta.scope-annotation-span.reader-controls.v2",status="RUNNING",controls=[],relocations=[],
                post_refusal=[],source_manifest_sha256=source_sha,native_processes_executed=0,
                original_processes_executed=0,python_reader_workers=2,
                execution=dict(pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),
                               cwd=str(Path.cwd()),started_monotonic_ns=started))
    save=lambda:(output/"result.json").write_bytes(encoded(report))
    save()
    try:
        baseline_native,semantic=q.native_evidence(capture/"native",capture/"build",source_sha)
        baseline_controls=q.controls_evidence(capture/"controls",capture/"build",source_sha,semantic)
        baseline_build=q.build_evidence(capture/"build",source_sha)
        baseline=dict(native=baseline_native,controls=baseline_controls,build=baseline_build)
        files={"GATE.json"}
        for name in ("build","native","controls","gate-processes"):
            files.update(p.relative_to(capture).as_posix() for p in (capture/name).rglob("*") if p.is_file())
        identities={name:file_pin(capture/name) for name in sorted(files)}
        for name in ("GATE.json","gate-processes/processes.json"):
            target=output/"inputs"/name
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(read(capture/name))
        one,two=output/"copies/one",output/"copies/two"
        for destination in (one,two):
            destination.mkdir(parents=True)
            for name in sorted(files):
                source=capture/name;target=destination/name
                target.parent.mkdir(parents=True,exist_ok=True)
                with source.open("rb") as inp,target.open("xb") as out:shutil.copyfileobj(inp,out,1<<20)
                require(file_pin(target)==identities[name],"physical reader copy changed")
        data=dict(schema="hepta.scope-annotation-span.parallel-reader-baseline.v1",
                  source_manifest_sha256=source_sha,source_root=str(ROOT),capture_root=str(capture),
                  output_root=str(output),parent_pid=os.getpid(),parent_pgid=os.getpgrp(),
                  started_monotonic_ns=started,baseline=baseline,
                  semantic_recoveries={key:value.hex() for key,value in semantic.items()},
                  admitted_files=identities,partition=dict(one=list(NAMES[::2]),two=list(NAMES[1::2])))
        raw=encoded(data);(output/"inputs/BASELINE.json").write_bytes(raw)
        report["baseline"]=pin(raw)
        records=launch_workers(ROOT,capture,output,SHA(raw),started)
        report["worker_processes"]=pin(read(output/"worker-processes.json"))
        workers=read_workers(output,source_sha,baseline,NAMES,expected_parent=report["execution"],
                             semantic=semantic,expected_files=identities,
                             expected_roots=dict(source_root=str(ROOT),capture_root=str(capture),output_root=str(output)))
        controls_by_name={}
        for record in workers:
            report["relocations"]+=record["relocations"]
            report["post_refusal"]+=record["post_refusal"]
            for row in record["controls"]:
                require(row["name"] not in controls_by_name,"reader workers overlap")
                controls_by_name[row["name"]]=row
        require(set(controls_by_name)==set(NAMES),"reader worker union omitted a control")
        report["controls"]=[controls_by_name[name] for name in NAMES]
        require(all(file_pin(one/n)==identities[n] and file_pin(two/n)==identities[n] for n in files),
                "mutated physical copies were not exactly restored")
        require(q.verify_source()==source_sha,"reader worker source changed")
        report.update(status="READER_CONTROLS_PASS",admitted_files=identities,
                      mutable_input_snapshots=["GATE.json","gate-processes/processes.json"])
        shutil.rmtree(one);shutil.rmtree(two)
    except BaseException as error:
        report.update(status="FAIL",error=dict(type=type(error).__name__,message=str(error)))
        raise
    finally:
        report["execution"]["finished_monotonic_ns"]=time.monotonic_ns()
        report["elapsed_seconds"]=(report["execution"]["finished_monotonic_ns"]-started)/1e9
        save()
    require(report["elapsed_seconds"]<180,"complete reader parent exceeded its unchanged deadline")
    print(json.dumps(dict(status=report["status"],controls=len(NAMES),relocations=2,native_processes_executed=0,
                         original_processes_executed=0,python_reader_workers=2,
                         elapsed_seconds=report["elapsed_seconds"]),sort_keys=True))


def rehashed_controls(one,refuse,native,build):
    """Rewrite real files and matching envelopes; deeper custody must refuse."""
    def snapshot_change(descriptor,at):
        ledger=jsonlines(one/"native/buffers.jsonl")
        known={r["sha256"] for r in ledger}
        raw=bytearray(b"".join(gzip.decompress(read(one/"native/buffers"/(key+".gz"))) for key in descriptor["chunks"]))
        require(pin(raw)==dict(bytes=descriptor["bytes"],sha256=descriptor["sha256"]),"mutation input is not the full captured buffer")
        raw[at]^=1
        chunks,changes=[],{}
        for offset in range(0,len(raw),128<<10):
            chunk=bytes(raw[offset:offset+(128<<10)]);identity=SHA(chunk);chunks.append(identity)
            if identity not in known:
                compressed=gzip.compress(chunk,compresslevel=1,mtime=0)
                name="buffers/"+identity+".gz"
                ledger.append(dict(file=name,sha256=identity,bytes=len(chunk),compressed_bytes=len(compressed),compressed_sha256=SHA(compressed)))
                changes["native/"+name]=lambda _,value=compressed:value
                known.add(identity)
        changes["native/buffers.jsonl"]=lambda _,value=lines(ledger):value
        return dict(bytes=len(raw),sha256=SHA(raw),chunks=chunks),changes
    calls=jsonlines(one/"native/calls.jsonl")
    calls[0]["output_before"],changes=snapshot_change(calls[0]["output_before"],0)
    changes["native/calls.jsonl"]=lambda _,value=lines(calls):value
    refuse("buffer-chunk-rehashed",native,changes)

    top=parse(read(one/"build/BUILD.json"))
    member="scope_annotation_span"
    prefix="build/modules/"+member+"/"
    manifest=parse(read(one/(prefix+"manifest.json")))
    image=read(one/(prefix+"module.image.bin"));changed=bytes([image[0]^1])+image[1:]
    manifest["image_sha256"]=SHA(changed)
    receipt=parse(read(one/(prefix+"module.receipt.json")));receipt["produced_sha256"]=SHA(changed)
    metadata=parse(read(one/(prefix+"build.json")));metadata["compile_receipt"]=receipt
    top["members"][member]["manifest_sha256"]=SHA(encoded(manifest))
    rows={prefix+"module.image.bin":changed,prefix+"manifest.json":encoded(manifest),
          prefix+"module.receipt.json":encoded(receipt),prefix+"build.json":encoded(metadata),"build/BUILD.json":encoded(top)}
    refuse("module-image-rehashed",build,{name:(lambda _,value=raw:value) for name,raw in rows.items()})

    calls=jsonlines(one/"native/calls.jsonl");handoffs=jsonlines(one/"native/handoffs.jsonl")
    handoff=handoffs[0]
    next_owner=next(row for row in calls[handoff["last_child_call"]:] if row["session"]==handoff["owner_session"])
    before=next_owner["workspace_before"]
    old=b"".join(gzip.decompress(read(one/"native/buffers"/(key+".gz"))) for key in before["chunks"])
    response=bytearray(old[handoff["reply_at"]:handoff["reply_at"]+handoff["response_bytes"]]);response[32]^=1
    handoff["response_sha256"]=SHA(response)
    next_owner["workspace_before"],changes=snapshot_change(before,handoff["reply_at"]+32)
    changes["native/calls.jsonl"]=lambda _,value=lines(calls):value
    changes["native/handoffs.jsonl"]=lambda _,value=lines(handoffs):value
    refuse("child-handoff-rehashed",native,changes)

    original=gzip.decompress(read(one/"native/observed.bin.gz"))
    size=struct.unpack_from("<Q",original)[0]
    first=bytearray(original[8:8+size]);first[40+64]^=1
    stream=PACK(size)+bytes(first)+original[8+size:]
    compressed=gzip.compress(stream,compresslevel=1,mtime=0)
    indices=jsonlines(one/"native/cases.jsonl");indices[0]["observed_sha256"]=SHA(first)
    report=parse(read(one/"native/CAPTURE.json"));report["observed_sha256"]=SHA(stream)
    rows={"native/observed.bin.gz":compressed,"native/cases.jsonl":lines(indices),"native/CAPTURE.json":encoded(report)}
    refuse("observation-rehashed",native,{name:(lambda _,value=raw:value) for name,raw in rows.items()})



if __name__=="__main__":main()
