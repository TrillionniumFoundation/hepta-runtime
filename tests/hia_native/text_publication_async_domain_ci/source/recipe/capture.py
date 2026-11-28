#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture actual original futures under owned directory locks, with no expected wire."""
from pathlib import Path
import argparse,fcntl,json,os,sys,time,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,sha
from buffer_store import Writer
from body_filesystem import snapshot
from observer_process import Process
from input_domain import cases,declaration

def file_stat(fd):
    x=os.fstat(fd)
    return dict(fd=fd,dev=x.st_dev,ino=x.st_ino,mode=x.st_mode,
        nlink=x.st_nlink,uid=x.st_uid,gid=x.st_gid,size=x.st_size)

def capture_case(binary,case,root):
    root.mkdir()
    work=Path(case["root"])
    work.mkdir(parents=True)
    (work/"held").mkdir();(work/"free").mkdir()
    require(work.is_absolute(),"owned fixture cwd must be absolute")
    config=dict(state_dir=str(root/"controller-state"),controller_workspace_roots=[str(work)],
        hosts={"fixture":dict(ssh_target="uncontacted-async-reference",remote_state_dir="/unused-runtime-state",
            allow_write=True,allowed_read_path_prefixes=["/allowed"],
            allowed_write_path_prefixes=["/allowed"],protected_path_prefixes=["/allowed/protected"])})
    config_path=root/"config.json"
    config_path.write_bytes(canonical(config));config_path.chmod(0o600)
    store=Writer(root/"buffers")
    rows=[];host=[];snapshots=[]
    def save():
        (root/"COMMANDS.json").write_bytes(canonical(rows))
        (root/"HOST.json").write_bytes(canonical(host))
        (root/"FILESYSTEM.json").write_bytes(canonical(snapshots))
    def host_event(event,**fields):
        host.append(dict(event=event,after_commands=len(rows),monotonic_ns=time.monotonic_ns(),**fields))
        save()
    def fs_snapshot(name):
        snapshots.append(dict(name=name,after_commands=len(rows),files=snapshot(work,store)))
        save()
    fs_snapshot("initial")
    fd=os.open(work/"held",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    locked=True
    host_event("holder_locked",directory=str(work/"held"),identity=file_stat(fd),
        flags=fcntl.LOCK_EX|fcntl.LOCK_NB)
    process=None;success=False
    try:
        process_root=root/"process";process_root.mkdir()
        process=Process([binary,"--async-fixture",config_path,case["mode"]],work,process_root,False)
        host_event("process_started",pid=process.p.pid,binary=pin(binary))
        def command(step,source_step):
            request=dict(step,id=len(rows))
            raw=canonical(request)
            start=time.monotonic_ns()
            deadline=time.monotonic()+60
            process.send(raw,deadline)
            response=process.line(deadline)
            value=decode(response)
            require((value["sequence"],value["id"],value["session"],value["kind"])
                ==(len(rows),request["id"],request["session"],request["kind"]),"observer response identity")
            rows.append(dict(number=len(rows),source_step=source_step,request=store.put(raw),
                response=store.put(response),elapsed_ns=time.monotonic_ns()-start))
            save()
            return value
        for number,step in enumerate(case["steps"]):
            if "local" not in step:
                command(step,number)
            elif step["local"]=="filesystem_snapshot":
                fs_snapshot(step["name"])
            elif step["local"]=="unlock":
                require(locked,"duplicate holder release")
                before=file_stat(fd)
                fcntl.flock(fd,fcntl.LOCK_UN)
                locked=False
                host_event("holder_unlocked",identity=before)
            elif step["local"]=="read_until_id":
                found=False
                for _ in range(step["max_lines"]):
                    response=command(dict(kind="read",session=step["session"]),number)
                    wire=bytes.fromhex(response["result"]["wire_hex"])
                    value=decode(wire)
                    if value.get("id")==step["request_id"]:
                        found=True;break
                require(found,"actual SDK barrier response not observed within frozen input window")
            else:
                raise ValueError("unknown local fixture action")
        require(not locked,"holder must be released before finalized exit")
        success=True
    except BaseException as error:
        (root/"FAILURE.json").write_bytes(canonical(dict(type=type(error).__name__,message=str(error),
            traceback=traceback.format_exc(),completed_commands=len(rows))))
        raise
    finally:
        if locked:
            fcntl.flock(fd,fcntl.LOCK_UN)
            host_event("failure_holder_unlock",identity=file_stat(fd))
        os.close(fd)
        host_event("holder_fd_closed",fd=fd)
        if process is not None:process.finish(success)
        save()
    result=dict(status="ACTUAL_ORIGINAL_LIFECYCLE_CAPTURED",case=case["case"],name=case["name"],
        era=case["era"],mode=case["mode"],commands=len(rows),snapshots=len(snapshots),
        process=decode((root/"process/PROCESS.json").read_bytes()),files=dict(
            commands=pin(root/"COMMANDS.json"),host=pin(root/"HOST.json"),filesystem=pin(root/"FILESYSTEM.json")),
        complete_buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
        native_executed=False,native_async_qualified=False,full_sdk=False)
    (root/"RESULT.json").write_bytes(canonical(result))
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--binary",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--first",type=int,default=0)
    p.add_argument("--count",type=int,default=30)
    a=p.parse_args()
    binary=a.binary.resolve(strict=True);output=a.output.absolute()
    output.mkdir(parents=True,exist_ok=False)
    plan=cases(output/"fixtures")
    require(0<=a.first<30 and 0<a.count<=30-a.first,"fixed case selection")
    selected=plan[a.first:a.first+a.count]
    (output/"PLAN.json").write_bytes(canonical(dict(declaration=declaration(),fixture_root=str(output/"fixtures"),
        first=a.first,count=a.count,cases=selected,binary=pin(binary),binary_path=str(binary))))
    (output/"cases").mkdir()
    result=[]
    for case in selected:
        value=capture_case(binary,case,output/"cases"/("%03d"%case["case"]))
        result.append(value)
        (output/"RESULTS.json").write_bytes(canonical(result))
        print(json.dumps({k:value[k] for k in ("status","case","name","era","mode","commands")}),flush=True)
    summary=dict(status="ORIGINAL_ASYNC_LIFECYCLE_CAPTURE_COMPLETE",cases=len(result),
        selected_first=a.first,selected_count=a.count,commands=sum(r["commands"] for r in result),
        full_domain=a.first==0 and a.count==30,native_executed=False,full_sdk=False,
        process_limit_seconds=180,exchange_limit_seconds=60)
    (output/"SUMMARY.json").write_bytes(canonical(summary))
    print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
