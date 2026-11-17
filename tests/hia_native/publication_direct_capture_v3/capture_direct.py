#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual eight unchanged direct future cases on the fixed native caller entry."""
from pathlib import Path
import argparse,fcntl,json,os,sys,time,traceback
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require
from buffer_store import Writer
from body_filesystem import snapshot
from native_process import Process,blocked
from input_domain import cases,declaration,startup
from direct_inputs import gateway,auxiliary_body
def file_stat(fd):
    s=os.fstat(fd);return dict(fd=fd,dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,nlink=s.st_nlink,uid=s.st_uid,gid=s.st_gid,size=s.st_size)
def capture_case(binary,case,root):
    root.mkdir();work=Path(case["root"])
    require(work.is_absolute() and not work.exists(),"fresh exact original direct fixture path")
    work.mkdir(parents=True);(work/"held").mkdir();(work/"free").mkdir()
    config=dict(state_dir=str(root/"controller-state"),controller_workspace_roots=[str(work)],
        hosts={"fixture":dict(ssh_target="uncontacted-async-reference",remote_state_dir="/unused-runtime-state",
            allow_write=True,allowed_read_path_prefixes=["/allowed"],allowed_write_path_prefixes=["/allowed"],
            protected_path_prefixes=["/allowed/protected"])})
    config_path=root/"config.json";config_path.write_bytes(canonical(config));config_path.chmod(0o600)
    store=Writer(root/"buffers");rows=[];host=[];snapshots=[];aux=[];auxfs=[]
    def save():
        for name,value in (("COMMANDS",rows),("HOST",host),("FILESYSTEM",snapshots),("AUXILIARY",aux),("AUXILIARY_FILESYSTEM",auxfs)):
            (root/(name+".json")).write_bytes(canonical(value))
    def event(name,**fields):
        host.append(dict(event=name,after_commands=len(rows),monotonic_ns=time.monotonic_ns(),**fields));save()
    def fs(name):snapshots.append(dict(name=name,after_commands=len(rows),files=snapshot(work,store)));save()
    def extra(name,begin,**fields):
        aux.append(dict(kind=name,after_commands=len(rows),control_first=begin,control_count=len(process.controls)-begin,**fields));save()
    fs("initial");fd=os.open(work/"held",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locked=True
    event("holder_locked",directory=str(work/"held"),identity=file_stat(fd),flags=fcntl.LOCK_EX|fcntl.LOCK_NB)
    process=None;success=False;blockfd=None;blocklocked=False
    try:
        process=Process(binary,config_path,work,root/"process",store)
        event("process_started",pid=process.p.pid,binary=pin(binary))
        # These are explicitly auxiliary real native service carriers. The
        # original direct fixture uses serve_directly(None). Gateway Q03 gets
        # the unchanged None metadata itself; it does not read their peer state.
        for step in startup("legacy"):
            begin=len(process.controls)
            if step["kind"]=="send":result=process.send(step["session"],bytes.fromhex(step["wire_hex"]))
            else:result=dict(wire_hex=process.line(step["session"]).hex())
            extra("carrier-startup",begin,request=step,result=result)
        if case["mode"]=="queued":
            blockroot=root/"auxiliary-blocker";blockroot.mkdir()
            blockfd=os.open(blockroot,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            fcntl.flock(blockfd,fcntl.LOCK_EX|fcntl.LOCK_NB);blocklocked=True
            auxfs.append(dict(name="initial",files=snapshot(blockroot,store)));save()
            begin=len(process.controls);payload=auxiliary_body(blockroot/"slot.txt")
            response=process.control_command(10,0,payload)
            observation=process.wait_blocked(str(blockroot),1)
            extra("real-queue-slot-occupied",begin,input_hex=payload.hex(),holder=file_stat(blockfd),
                blocked=observation,operation=response["row"]["number"],outside_semantic_root=True)
        def command(step,source_step):
            nonlocal blocklocked
            request=dict(step,id=len(rows));start=time.monotonic_ns();begin=len(process.controls)
            kind=step["kind"];sid=step["session"]
            if kind=="cache":
                r=process.control_command(2,sid,bytes.fromhex(step["wire_hex"]))
                result=dict(output_hex=r["result"].hex())
            elif kind in ("direct_start","direct_unpolled_drop"):
                op=6 if kind=="direct_start" else 9
                r=process.control_command(op,sid,gateway(step),arg0=step["tag"])
                result=dict(tag=step["tag"],actual_operation=op,frame_hex=r["result"].hex())
            elif kind in ("direct_drop","direct_join"):
                op=7 if kind=="direct_drop" else 8
                r=process.control_command(op,sid,arg0=step["tag"])
                result=dict(tag=step["tag"],actual_operation=op,frame_hex=r["result"].hex())
            elif kind=="wait_events":result=process.wait_events(step["event"],step["count"])
            elif kind=="wait_blocked":result=process.wait_blocked(step["path"],step["count"])
            elif kind=="blocked_snapshot":
                process.advance();result=blocked(process.p.pid,step["path"])
                process.observations.append(result);process.save()
            elif kind=="release_blocker":
                require(blockfd is not None and blocklocked,"real auxiliary slot owner")
                identity=file_stat(blockfd);fcntl.flock(blockfd,fcntl.LOCK_UN);blocklocked=False
                r=process.control_command(11,sid)
                result=dict(actual_auxiliary_body_reaped_and_released=True,holder=identity)
                auxfs.append(dict(name="released",files=snapshot(root/"auxiliary-blocker",store)));save()
            elif kind=="finalize":
                for carrier in (0,1):
                    before=len(process.controls);result_eof=process.eof(carrier);result_drain=process.drain(carrier)
                    extra("carrier-eof",before,session=carrier,eof=result_eof,drain=result_drain)
                r=process.control_command(5,sid)
                result=dict(actual_runtime_finalized=True)
            else:raise ValueError("unexpected unchanged direct case operation: "+kind)
            observation=r["row"] if kind=="finalize" else process.snapshot(sid)
            row=dict(number=len(rows),source_step=source_step,request=store.put(canonical(request)),
                result=result,control_first=begin,control_count=len(process.controls)-begin,
                state_control=observation["number"],elapsed_ns=time.monotonic_ns()-start)
            rows.append(row);save();return result
        for number,step in enumerate(case["steps"]):
            if "local" not in step:command(step,number)
            elif step["local"]=="filesystem_snapshot":fs(step["name"])
            elif step["local"]=="unlock":
                require(locked,"one owned directory release");before=file_stat(fd)
                fcntl.flock(fd,fcntl.LOCK_UN);locked=False;event("holder_unlocked",identity=before)
            else:raise ValueError("unexpected direct local input")
        require(not locked and not blocklocked,"all test-owned flock guards released");success=True
    except BaseException as error:
        (root/"FAILURE.json").write_bytes(canonical(dict(type=type(error).__name__,message=str(error),
            traceback=traceback.format_exc(),completed_commands=len(rows))));raise
    finally:
        if locked:fcntl.flock(fd,fcntl.LOCK_UN);event("failure_holder_unlock",identity=file_stat(fd))
        os.close(fd);event("holder_fd_closed",fd=fd)
        if blockfd is not None:
            if blocklocked:fcntl.flock(blockfd,fcntl.LOCK_UN)
            os.close(blockfd)
        if process is not None:process.finish(success)
        save()
    result=dict(status="ACTUAL_NATIVE_DIRECT_FUTURE_CAPTURED",case=case["case"],name=case["name"],
        era=case["era"],mode=case["mode"],commands=len(rows),snapshots=len(snapshots),
        process=decode((root/"process/PROCESS.json").read_bytes()),
        files={n:pin(root/(n+".json")) for n in ("COMMANDS","HOST","FILESYSTEM","AUXILIARY","AUXILIARY_FILESYSTEM")},
        complete_buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
        production_source="7567502bf4e76b5975a689b988e9f96e1206462a",
        application_executed=True,comparison_complete=False,full_sdk=False)
    (root/"RESULT.json").write_bytes(canonical(result));return result
def main():
    p=argparse.ArgumentParser()
    for n in ("binary","output","original"):p.add_argument("--"+n,type=Path,required=True)
    p.add_argument("--first",type=int,required=True);p.add_argument("--count",type=int,required=True)
    a=p.parse_args();binary=a.binary.resolve(strict=True);a.output.mkdir(parents=True,exist_ok=False)
    original=decode((a.original/"PLAN.json").read_bytes())
    require(original["declaration"]==declaration() and original["cases"]==cases(original["fixture_root"]),"all original unchanged thirty inputs")
    require(22<=a.first<30 and 0<a.count<=30-a.first,"eight fixed direct-only inputs")
    selected=original["cases"][a.first:a.first+a.count]
    (a.output/"PLAN.json").write_bytes(canonical(dict(declaration=declaration(),fixture_root=original["fixture_root"],
        first=a.first,count=a.count,cases=selected,binary=pin(binary),binary_path=str(binary),original_plan=pin(a.original/"PLAN.json"))))
    (a.output/"cases").mkdir();results=[]
    for case in selected:
        row=capture_case(binary,case,a.output/"cases"/("%03d"%case["case"]))
        results.append(row);(a.output/"RESULTS.json").write_bytes(canonical(results))
        print(json.dumps({k:row[k] for k in ("status","case","name","commands")}),flush=True)
    (a.output/"SUMMARY.json").write_bytes(canonical(dict(status="NATIVE_DIRECT_CAPTURE_COMPLETE",
        first=a.first,count=a.count,cases=len(results),application_executed=True,comparison_complete=False,full_30_domain=False)))
if __name__=="__main__":main()
