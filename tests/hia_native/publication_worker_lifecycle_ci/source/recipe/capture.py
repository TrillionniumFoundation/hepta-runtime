#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual owned locks, process/clone observations, complete protocol and filesystem bytes."""
from pathlib import Path
import argparse,fcntl,json,os,struct,sys,time,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require
from buffer_store import Writer
from body_filesystem import snapshot
from domain import body,cases,declaration,frame
from process import Process
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
def stat_fd(fd):
    s=os.fstat(fd)
    return dict(fd=fd,dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,nlink=s.st_nlink,uid=s.st_uid,gid=s.st_gid,size=s.st_size)
def blocked(pid,path):
    wanted=path.stat();children=Path("/proc/%d/task/%d/children"%(pid,pid)).read_text()
    rows=[];matching=[]
    for text in children.split():
        child=int(text);at=Path("/proc")/text
        try:
            raw=(at/"syscall").read_text();values=raw.split();row=dict(pid=child,syscall=raw)
            if len(values)>=3 and int(values[0],0)==73 and int(values[2],0)==2:
                fd=int(values[1],0);p=at/"fd"/str(fd);s=p.stat()
                row.update(fd=fd,dev=s.st_dev,ino=s.st_ino,path=os.readlink(p),
                    matching=(s.st_dev,s.st_ino)==(wanted.st_dev,wanted.st_ino))
                if row["matching"]:matching.append(child)
            rows.append(row)
        except (FileNotFoundError,ProcessLookupError,PermissionError,ValueError) as error:
            rows.append(dict(pid=child,error=type(error).__name__+":"+str(error)))
    return dict(parent=pid,path=str(path),dev=wanted.st_dev,ino=wanted.st_ino,
        children=children,rows=rows,matching=matching)

def capture_case(binary,case,output):
    output.mkdir();work=Path(case["root"]);work.mkdir(parents=True)
    for name in ("held","free","blocker"):(work/name).mkdir()
    store=Writer(output/"buffers");commands=[];host=[];shots=[];jobs={};taken={};dropped=set();locks={}
    process=None;success=False
    def save():
        (output/"COMMANDS.json").write_bytes(canonical(commands))
        (output/"HOST.json").write_bytes(canonical(host))
        (output/"FILESYSTEM.json").write_bytes(canonical(shots))
    def event(event_type,**fields):
        host.append(dict(event=event_type,after_commands=len(commands),monotonic_ns=time.monotonic_ns(),**fields));save()
    def shot(name):
        shots.append(dict(name=name,after_commands=len(commands),files=snapshot(work,store)));save()
    def lock(name):
        fd=os.open(work/name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locks[name]=fd
        event("holder_locked",name=name,identity=stat_fd(fd))
    def unlock(name):
        fd=locks.pop(name);before=stat_fd(fd)
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
        event("holder_unlocked",name=name,identity=before)
    def exchange(command,job=0,tag=0,payload=b"",argument=0,flags=0,label=None):
        raw=frame(command,job,tag,payload,argument,flags)
        first=(output/"process/journal.bin").stat().st_size;start=time.monotonic_ns()
        end=time.monotonic()+60
        process.send(raw,end);reply=process.frame(end)
        require(U(reply,24)==command and U(reply,32)==job and U(reply,48)==len(commands)+1,
            "actual complete exchange identity")
        commands.append(dict(number=len(commands),command=command,job=job,tag=tag,label=label,
            request=store.put(raw),response=store.put(reply),elapsed_ns=time.monotonic_ns()-start,
            journal_before=first,journal_after=(output/"process/journal.bin").stat().st_size))
        save();return reply
    def code(reply,want):require(U(reply,8)==want,"actual capability return differs from lifecycle ABI")
    def create():
        code(exchange(0,argument=case["limit"],flags=0 if case["observer"] else 1,label="create"),0)
    def submit(path,tag):
        reply=exchange(1,tag=tag,payload=body(work,path),label="submit:"+path)
        code(reply,320);v=reply[64:];require(len(v)==320 and U(v,16)==0 and U(v,32)>0,"actual enqueue")
        job=U(v,32);require(tag not in jobs and job not in jobs.values(),"private job uniqueness")
        jobs[tag]=job;return job
    def service():code(exchange(2,label="service"),0)
    def observe():
        reply=exchange(9,label="observe");code(reply,320)
        require(len(reply)==384 and reply[64:72]==b"HPTWR001","full actual pool observation")
        return reply[64:]
    def wait_blocked(name,count):
        deadline=time.monotonic()+60
        while True:
            process.remaining(deadline);service()
            row=blocked(process.p.pid,work/name)
            event("actual_flock_observation",required=count,observation=row)
            if len(row["matching"])>=count:return row
            require(process.p.poll() is None,"worker fixture exited while waiting for actual flock")
            time.sleep(.002)
    def take(tag,release=True):
        job=jobs[tag];deadline=time.monotonic()+60
        while True:
            process.remaining(deadline);reply=exchange(4,job=job,label="take:"+str(tag));code(reply,320)
            state=reply[64:384];require(state[:8]==b"HPTWR001","actual take state")
            if U(state,16)==0:break
            require(U(state,16)==2 and len(reply)==384,"actual pending response")
            time.sleep(.002)
        require(len(reply)>=448 and reply[384:392]==b"HPTWB001" and U(reply,392)==64
            and U(reply,400)==job and U(reply,432)==tag and len(reply)==448+U(reply,424),"whole actual result borrow")
        taken[tag]=reply
        if release:code(exchange(5,job=job,label="release:"+str(tag)),0)
        return reply
    def drop(tag):
        code(exchange(6,job=jobs[tag],label="drop:"+str(tag)),0);dropped.add(tag)
    def finish_jobs():
        for tag in list(jobs):
            if tag not in dropped and tag not in taken:take(tag)
        deadline=time.monotonic()+60
        while True:
            process.remaining(deadline);service();v=observe()
            if U(v,160)==0 and U(v,168)==0:return v
            time.sleep(.002)
    shot("initial")
    try:
        process=Process(binary,work,output/"process")
        event("process_started",pid=process.p.pid,binary=pin(binary))
        create();lock("held")
        name=case["name"]
        queued=name.startswith("queued") or name in ("close_queued","fifo_growth")
        if queued:
            lock("blocker");submit("blocker/slot.txt",999);wait_blocked("blocker",1)
        if name!="unpolled_drop":
            submit("held/a.txt",10)
            if queued:
                v=exchange(3,job=jobs[10],label="verify-enqueued-before-BEGIN");code(v,320)
                require(U(v,104)==1 and U(v,168)==0,"queue must retain an actual unbegun HIA job")
            else:wait_blocked("held",1)
            shot("actual-first-worker-suspended")
            if name=="two_started_drop_first":
                submit("held/b.txt",11);wait_blocked("held",2)
            if name in ("started_drop","queued_drop","two_started_drop_first",
                        "started_drop_then_second","queued_drop_then_second"):drop(10)
            if name=="invalid_lifecycle":
                before=exchange(11,label="state-before-invalid-release")
                code(exchange(5,job=jobs[10],label="release-before-take"),0xffffffff)
                after=exchange(11,label="state-after-invalid-release")
                require(before[64:]==after[64:],"invalid release changed complete HIA workspace")
                code(exchange(8,label="destroy-while-running"),0xfffffffd)
                code(exchange(3,job=0x7fffffffffffffff,label="unknown-issued-id"),0xffffffff)
            if name in ("fifo_growth","close_queued"):
                count=33 if name=="fifo_growth" else 3
                for number in range(11,10+count):submit("held/q-%02d.txt"%number,number)
                if name=="close_queued":
                    code(exchange(7,label="close-with-queue"),0)
                    denied=exchange(1,tag=4444,payload=body(work,"free/denied.txt"),label="submit-after-close")
                    code(denied,320);require(U(denied,80)==1 and U(denied,96)==0,"closed admission must reject actual new job")
            if queued:
                unlock("blocker");take(999);wait_blocked("held",1)
            unlock("held")
            if name in ("started_drop_then_second","queued_drop_then_second"):
                submit("free/c.txt",11);take(11)
            if name=="borrow_lifetime":
                first=take(10,release=False)
                before=exchange(15,job=jobs[10],label="borrowed-output-before-other-job")
                submit("free/c.txt",11);take(11)
                after=exchange(15,job=jobs[10],label="borrowed-output-after-other-job")
                require(before[64:]==after[64:] and first[448:]==after[64:64+U(first,424)],
                    "actual full borrowed output changed before release")
                code(exchange(6,job=jobs[10],label="drop-after-take"),0xffffffff)
                code(exchange(8,label="destroy-with-borrow"),0xfffffffd)
                code(exchange(5,job=jobs[10],label="release-held-borrow"),0)
                code(exchange(5,job=jobs[10],label="duplicate-release"),0xffffffff)
            if name=="invalid_lifecycle":
                take(10,release=False)
                code(exchange(4,job=jobs[10],label="duplicate-take"),0xffffffff)
                code(exchange(6,job=jobs[10],label="drop-after-take"),0xffffffff)
                code(exchange(5,job=jobs[10],label="release-valid"),0)
                code(exchange(3,job=jobs[10],label="poll-after-retirement"),0xffffffff)
        else:unlock("held")
        final=finish_jobs();shot("all-bodies-reaped")
        code(exchange(7,label="close-final"),0)
        code(exchange(8,label="destroy-final"),0)
        event("pool_destroyed",final_state=store.put(final))
        success=True
    except BaseException as error:
        (output/"FAILURE.json").write_bytes(canonical(dict(type=type(error).__name__,message=str(error),
            traceback=traceback.format_exc(),completed_commands=len(commands))))
        raise
    finally:
        for name in list(locks):unlock(name)
        if process is not None:process.finish(success)
        save()
    result=dict(status="ACTUAL_PRIVATE_NATIVE_WORKER_CAPTURED",case=case["case"],name=case["name"],
        observer=case["observer"],commands=len(commands),jobs=jobs,taken=sorted(taken),dropped=sorted(dropped),
        process=decode((output/"process/PROCESS.json").read_bytes()),
        files={n:pin(output/n) for n in ("COMMANDS.json","HOST.json","FILESYSTEM.json")},
        complete_buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
        public_async_qualified=False,full_sdk=False)
    (output/"RESULT.json").write_bytes(canonical(result));return result
def main():
    p=argparse.ArgumentParser();p.add_argument("--binary",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--observer",choices=("on","off","all"),default="all")
    a=p.parse_args();binary=a.binary.resolve(strict=True);root=a.output.absolute();root.mkdir(parents=True,exist_ok=False)
    plan=cases(root/"fixtures");chosen=[c for c in plan if a.observer=="all" or c["observer"]==(a.observer=="on")]
    (root/"PLAN.json").write_bytes(canonical(dict(declaration=declaration(),fixture_root=str(root/"fixtures"),
        cases=chosen,binary=pin(binary),binary_path=str(binary),observer=a.observer)))
    (root/"cases").mkdir();results=[]
    for case in chosen:
        row=capture_case(binary,case,root/"cases"/("%03d"%case["case"]));results.append(row)
        (root/"RESULTS.json").write_bytes(canonical(results))
        print(json.dumps({k:row[k] for k in ("status","case","name","observer","commands")}),flush=True)
    value=dict(status="PRIVATE_NATIVE_WORKER_CAPTURE_COMPLETE",cases=len(results),
        commands=sum(x["commands"] for x in results),observer=a.observer,process_limit_seconds=180,exchange_limit_seconds=60,
        original_rust_executed=False,public_async_qualified=False,full_sdk=False)
    (root/"SUMMARY.json").write_bytes(canonical(value));print(json.dumps(value,sort_keys=True))
if __name__=="__main__":main()
