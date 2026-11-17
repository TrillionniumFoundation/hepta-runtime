"""Two owned pure-reader workers; complete streams, partitions, and parent custody."""
from pathlib import Path
import math,os,signal,subprocess,sys,time
import physical_common as pc

LIMIT_NS=180_000_000_000
SIGNALS={signal.SIGINT,signal.SIGTERM,signal.SIGHUP}

def parts(admissions,names):
    pc.check(len(admissions)==2 and len(names)==15,"unchanged two admissions and fifteen refusals")
    return ((admissions[0],*names[::2]),(admissions[1],*names[1::2]))

def child_summary(report,raw):
    return dict(status="OWNED_PHYSICAL_READER_PART_PASS",part=report["part"],names=report["names"],
                report=pc.pin(raw),pid=report["pid"],parent_pid=report["parent_pid"],pgid=report["pgid"],
                native_or_rust_executions=0)

def parent_identity(retained,output,identity,started):
    return dict(schema="hepta.namespace-fingerprint.physical-parent.v1",pid=os.getpid(),parent_pid=os.getppid(),
                pgid=os.getpgrp(),source_root=str(pc.ROOT),retained_root=str(retained),output_root=str(output),
                source_manifest_sha256=identity,started_ns=started,deadline_ns=started+LIMIT_NS,
                timeout_seconds=180,native_or_rust_executions=0)

def run(retained,output,identity,started,partitions):
    parent=parent_identity(retained,output,identity,started)
    (output/"PARENT.json").write_bytes(pc.enc(parent))
    process_root=output/"workers";process_root.mkdir()
    children=[];first=None
    try:
        for part,names in enumerate(partitions):
            folder=process_root/str(part);folder.mkdir()
            item=dict(part=part,names=list(names),folder=folder,process=None,streams=[],started_ns=time.monotonic_ns(),
                      completed=False,timed_out=False,finished_ns=None,argv=None,pgid=None)
            children.append(item)
            for suffix in ("stdout","stderr"):item["streams"].append((folder/suffix).open("wb"))
            argv=[sys.executable,"-I","-B",str(pc.ROOT/"physical_worker.py"),"--retained",str(retained),
                  "--output",str(output),"--part",str(part)];item["argv"]=argv
            # Register ownership before delivering an asynchronous start interruption.
            oldmask=signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
            try:
                item["process"]=subprocess.Popen(argv,cwd=pc.ROOT,stdin=subprocess.DEVNULL,
                    stdout=item["streams"][0],stderr=item["streams"][1],start_new_session=False)
                item["pgid"]=os.getpgid(item["process"].pid)
            finally:signal.pthread_sigmask(signal.SIG_SETMASK,oldmask)
            pc.check(item["pgid"]==os.getpgrp(),"worker inherits recorder-owned parent group")
        pending=list(children)
        while pending:
            now=time.monotonic_ns()
            if now>=parent["deadline_ns"]:
                for item in pending:item["timed_out"]=True
                raise TimeoutError("complete physical-control parent exceeded unchanged 180 seconds")
            for item in list(pending):
                code=item["process"].poll()
                if code is not None:
                    item["completed"]=True;item["finished_ns"]=now;pending.remove(item)
                    pc.check(code==0,"owned physical-reader worker failed: "+str(item["part"]))
            if pending:time.sleep(0.01)
    except BaseException as failure:first=failure
    finally:
        # No evidence write can skip any child kill, wait, or stream close.
        for item in children:
            process=item["process"]
            if process is not None:
                try:
                    if process.poll() is None:process.kill()
                except ProcessLookupError:pass
                except BaseException as failure:
                    if first is None:first=failure
        for item in children:
            process=item["process"]
            if process is not None:
                try:process.wait()
                except BaseException as failure:
                    if first is None:first=failure
            if item["finished_ns"] is None:item["finished_ns"]=time.monotonic_ns()
        for item in children:
            for stream in item["streams"]:
                try:stream.close()
                except BaseException as failure:
                    if first is None:first=failure
    records=[]
    for item in children:
        process=item["process"]
        try:
            row=dict(part=item["part"],names=item["names"],argv=item["argv"],cwd=str(pc.ROOT),
                     pid=None if process is None else process.pid,parent_pid=os.getpid(),pgid=item["pgid"],
                     exit_code=None if process is None else process.returncode,completed=item["completed"],
                     timed_out=item["timed_out"],started_ns=item["started_ns"],finished_ns=item["finished_ns"],
                     elapsed_ns=item["finished_ns"]-item["started_ns"],timeout_seconds=180,
                     stdout=pc.pin(pc.read(item["folder"]/"stdout")),stderr=pc.pin(pc.read(item["folder"]/"stderr")),
                     source_manifest_sha256=identity,native_or_rust_executions=0)
            records.append(row)
            (item["folder"]/"process.json").write_bytes(pc.enc(row))
        except BaseException as failure:
            if first is None:first=failure
    try:(process_root/"processes.json").write_bytes(pc.enc(records))
    except BaseException as failure:
        if first is None:first=failure
    if first is not None:raise first
    pc.check(time.monotonic_ns()<parent["deadline_ns"],"same whole-parent 180-second control budget")
    return parent,records

def verify(output,report,partitions):
    parent=pc.loads(pc.read(output/"PARENT.json"))
    expected={k:report[k] for k in ("pid","parent_pid","pgid","source_root","retained_root","output_root",
                                  "source_manifest_sha256","native_or_rust_executions")}
    pc.check(all(parent[k]==v and type(parent[k]) is type(v) for k,v in expected.items()),
             "worker parent roots/PIDs bound to actual top-level control report")
    pc.check(parent["schema"]=="hepta.namespace-fingerprint.physical-parent.v1" and
             all(type(parent[k]) is int and parent[k]>1 for k in ("pid","parent_pid","pgid")) and
             parent["pid"]==parent["pgid"]!=parent["parent_pid"] and
             type(parent["started_ns"]) is int and parent["started_ns"]>0 and
             type(parent["deadline_ns"]) is int and parent["deadline_ns"]==parent["started_ns"]+LIMIT_NS and
             type(parent["timeout_seconds"]) is int and parent["timeout_seconds"]==180 and
             type(parent["native_or_rust_executions"]) is int and parent["native_or_rust_executions"]==0,
             "exact real parent process and unchanged control deadline")
    records=pc.loads(pc.read(output/"workers/processes.json"))
    pc.check(len(records)==2 and report["worker_processes"]==records and
             report["parent_evidence"]==pc.pin(pc.read(output/"PARENT.json")),"two complete retained worker process records")
    baseline_raw=pc.read(output/"BASELINE.json");baseline=pc.loads(baseline_raw)
    pc.check(baseline==report["baseline"],"complete worker baseline equals recomputed verified evidence")
    allrows={};seen=set()
    for part,(names,row) in enumerate(zip(partitions,records,strict=True)):
        folder=output/"workers"/str(part);raw=pc.read(folder/"REPORT.json");child=pc.loads(raw)
        pc.check(row==pc.loads(pc.read(folder/"process.json")) and type(row["part"]) is int and row["part"]==part and
                 row["names"]==list(names) and row["cwd"]==parent["source_root"] and
                 len(row["argv"])==10 and type(row["argv"][0]) is str and row["argv"][0].startswith("/") and
                 row["argv"][1:]==["-I","-B",parent["source_root"]+"/physical_worker.py","--retained",parent["retained_root"],
                                  "--output",parent["output_root"],"--part",str(part)] and
                 type(row["exit_code"]) is int and row["exit_code"]==0 and row["completed"] is True and row["timed_out"] is False and
                 type(row["timeout_seconds"]) is int and row["timeout_seconds"]==180 and
                 type(row["native_or_rust_executions"]) is int and row["native_or_rust_executions"]==0 and
                 row["source_manifest_sha256"]==parent["source_manifest_sha256"],"exact actual worker command and success")
        pc.check(all(type(row[k]) is int and row[k]>1 for k in ("pid","parent_pid","pgid")) and
                 row["parent_pid"]==parent["pid"] and row["pgid"]==parent["pgid"] and
                 row["pid"] not in seen|{parent["pid"],parent["parent_pid"]},"actual two independent child PIDs in parent group")
        seen.add(row["pid"])
        pc.check(all(type(row[k]) is int for k in ("started_ns","finished_ns","elapsed_ns")) and
                 parent["started_ns"]<=row["started_ns"]<row["finished_ns"]<=parent["deadline_ns"] and
                 row["elapsed_ns"]==row["finished_ns"]-row["started_ns"] and 0<row["elapsed_ns"]<=LIMIT_NS,
                 "worker full elapsed custody inside original parent deadline")
        pc.check(child["schema"]=="hepta.namespace-fingerprint.physical-part.v1" and child["status"]=="PASS" and
                 type(child["part"]) is int and child["part"]==part and child["names"]==list(names) and
                 child["parent_evidence"]==pc.pin(pc.read(output/"PARENT.json")) and child["baseline"]==pc.pin(baseline_raw) and
                 all(child[k]==parent[k] for k in ("source_root","retained_root","output_root","source_manifest_sha256")) and
                 all(type(child[k]) is int and child[k]==row[k] for k in ("pid","parent_pid","pgid")) and
                 type(child["native_or_rust_executions"]) is int and child["native_or_rust_executions"]==0 and
                 len(child["rows"])==len(names),"complete worker report identities and full exact partition")
        for kind in ("stdout","stderr"):
            stream=pc.read(folder/kind)
            pc.check(pc.pin(stream)==row[kind] and stream==(pc.enc(child_summary(child,raw)) if kind=="stdout" else b""),
                     "whole actual worker streams")
        pc.check(set(pc.files(folder))=={"stdout","stderr","process.json","REPORT.json"},"complete worker evidence set")
        for name,item in zip(names,child["rows"],strict=True):
            pc.check(item["name"]==name and name not in allrows,"exact disjoint complete worker case ownership")
            allrows[name]=item
    pc.check(set(pc.files(output/"workers"))=={"processes.json"}|
             {str(i)+"/"+n for i in range(2) for n in ("stdout","stderr","process.json","REPORT.json")},
             "no unbound worker process evidence")
    pc.check(len(allrows)==17 and len(report["rows"])==17 and
             all(allrows[item["name"]]==item for item in report["rows"]),"full ordered result merge preserves every worker row")
    return dict(parent=parent,workers=records,owned_processes=2,whole_parent_timeout_seconds=180,
                native_or_rust_executions=0)
