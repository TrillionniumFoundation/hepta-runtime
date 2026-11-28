"""Two owned pure-reader workers; complete streams, partitions, and parent custody."""
from pathlib import Path
import math,os,signal,subprocess,sys,time
import recovery_common as pc

LIMIT_NS=180_000_000_000
SIGNALS={signal.SIGINT,signal.SIGTERM,signal.SIGHUP}

def parent_identity(complete,output,identity,started):
    return dict(schema="hepta.audit-anchor-publish.parallel-read-parent.v1",pid=os.getpid(),parent_pid=os.getppid(),
                pgid=os.getpgrp(),source_root=str(pc.ROOT),complete_root=str(complete),output_root=str(output),
                source_manifest_sha256=identity,started_ns=started,deadline_ns=started+LIMIT_NS,
                timeout_seconds=180,native_or_rust_executions=0)

def run(complete,output,identity,started,partitions):
    parent=parent_identity(complete,output,identity,started)
    (output/"admission").mkdir()
    (output/"admission/PARENT.json").write_bytes(pc.enc(parent))
    process_root=output/"parts";process_root.mkdir()
    children=[];first=None
    try:
        for part,names in enumerate(partitions):
            folder=process_root/str(part);folder.mkdir()
            item=dict(part=part,names=list(names),folder=folder,process=None,streams=[],started_ns=time.monotonic_ns(),
                      completed=False,timed_out=False,finished_ns=None,argv=None,pgid=None)
            children.append(item)
            for suffix in ("stdout","stderr"):item["streams"].append((folder/suffix).open("wb"))
            argv=[sys.executable,"-I","-B",str(pc.ROOT/"read_worker.py"),"--complete",str(complete),
                  "--output",str(folder),"--part",str(part)];item["argv"]=argv
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
                raise TimeoutError("complete parallel-read parent exceeded unchanged 180 seconds")
            for item in list(pending):
                code=item["process"].poll()
                if code is not None:
                    item["completed"]=True;item["finished_ns"]=now;pending.remove(item)
                    pc.check(code==0,"owned pure-reader worker failed: "+str(item["part"]))
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
