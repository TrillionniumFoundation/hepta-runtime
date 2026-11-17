#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Run unchanged input-only public lifecycle cases on two actual native pipes."""
from pathlib import Path
import argparse,fcntl,json,os,sys,time,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require
from buffer_store import Writer
from body_filesystem import snapshot
from native_process import Process
from input_domain import cases,declaration

def file_stat(fd):
    x=os.fstat(fd)
    return dict(fd=fd,dev=x.st_dev,ino=x.st_ino,mode=x.st_mode,
        nlink=x.st_nlink,uid=x.st_uid,gid=x.st_gid,size=x.st_size)

def capture_case(binary,case,root):
    root.mkdir()
    work=Path(case["root"]);require(work.is_absolute() and not work.exists(),"fresh owned exact input cwd")
    work.mkdir(parents=True);(work/"held").mkdir();(work/"free").mkdir()
    config=dict(state_dir=str(root/"controller-state"),controller_workspace_roots=[str(work)],
        hosts={"fixture":dict(ssh_target="uncontacted-async-reference",remote_state_dir="/unused-runtime-state",
            allow_write=True,allowed_read_path_prefixes=["/allowed"],
            allowed_write_path_prefixes=["/allowed"],protected_path_prefixes=["/allowed/protected"])})
    config_path=root/"config.json";config_path.write_bytes(canonical(config));config_path.chmod(0o600)
    store=Writer(root/"buffers")
    rows=[];host=[];snapshots=[]
    def save():
        (root/"COMMANDS.json").write_bytes(canonical(rows))
        (root/"HOST.json").write_bytes(canonical(host))
        (root/"FILESYSTEM.json").write_bytes(canonical(snapshots))
    def event(name,**fields):
        host.append(dict(event=name,after_commands=len(rows),monotonic_ns=time.monotonic_ns(),**fields));save()
    def fs(name):
        snapshots.append(dict(name=name,after_commands=len(rows),files=snapshot(work,store)));save()
    fs("initial")
    fd=os.open(work/"held",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locked=True
    event("holder_locked",directory=str(work/"held"),identity=file_stat(fd),flags=fcntl.LOCK_EX|fcntl.LOCK_NB)
    process=None;success=False
    try:
        process=Process(binary,config_path,work,root/"process",store)
        event("process_started",pid=process.p.pid,binary=pin(binary))
        def command(step,source_step):
            request=dict(step,id=len(rows));start=time.monotonic_ns();before=len(process.controls)
            kind=step["kind"];sid=step["session"]
            if kind=="cache":
                call=process.control_command(2,sid,bytes.fromhex(step["wire_hex"]))
                result=dict(output_hex=call["result"].hex())
            elif kind=="send":result=process.send(sid,bytes.fromhex(step["wire_hex"]))
            elif kind=="read":result=dict(wire_hex=process.line(sid).hex())
            elif kind=="wait_blocked":result=process.wait_blocked(step["path"],step["count"])
            elif kind=="wait_events":result=process.wait_events(step["event"],step["count"])
            elif kind=="eof":result=process.eof(sid)
            elif kind=="close_transport":result=process.eof(sid,drop_reader=True)
            elif kind=="drain":result=process.drain(sid)
            elif kind=="drive":
                process.advance(milliseconds=step["milliseconds"])
                result=dict(driven_milliseconds=step["milliseconds"])
            elif kind=="observe":result=dict(observed=True)
            elif kind=="finalize":
                call=process.control_command(5,sid)
                result=dict(actual_runtime_finalized=True)
            else:raise ValueError("private direct future domain is separate; unexpected public input "+kind)
            observation=call["row"] if kind=="finalize" else process.snapshot(sid)
            row=dict(number=len(rows),source_step=source_step,request=store.put(canonical(request)),
                result=result,control_first=before,control_count=len(process.controls)-before,
                state_control=observation["number"],elapsed_ns=time.monotonic_ns()-start)
            rows.append(row);save()
            return result
        for number,step in enumerate(case["steps"]):
            if "local" not in step:command(step,number)
            elif step["local"]=="filesystem_snapshot":fs(step["name"])
            elif step["local"]=="unlock":
                require(locked,"duplicate holder release");before=file_stat(fd)
                fcntl.flock(fd,fcntl.LOCK_UN);locked=False;event("holder_unlocked",identity=before)
            elif step["local"]=="read_until_id":
                found=False
                for _ in range(step["max_lines"]):
                    response=command(dict(kind="read",session=step["session"]),number)
                    if decode(bytes.fromhex(response["wire_hex"])).get("id")==step["request_id"]:
                        found=True;break
                require(found,"actual SDK barrier not observed within unchanged input window")
            else:raise ValueError("unadmitted local input")
        require(not locked,"holder remains at completion");success=True
    except BaseException as error:
        (root/"FAILURE.json").write_bytes(canonical(dict(type=type(error).__name__,message=str(error),
            traceback=traceback.format_exc(),completed_commands=len(rows))));raise
    finally:
        if locked:
            fcntl.flock(fd,fcntl.LOCK_UN);event("failure_holder_unlock",identity=file_stat(fd))
        os.close(fd);event("holder_fd_closed",fd=fd)
        if process is not None:process.finish(success)
        save()
    result=dict(status="ACTUAL_NATIVE_TWO_SESSION_CAPTURED",case=case["case"],name=case["name"],
        era=case["era"],mode=case["mode"],commands=len(rows),snapshots=len(snapshots),
        process=decode((root/"process/PROCESS.json").read_bytes()),
        files={k:pin(root/v) for k,v in (("commands","COMMANDS.json"),("host","HOST.json"),("filesystem","FILESYSTEM.json"))},
        complete_buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
        production_source="f8857cbd18b3dedb38718f68822c072053b03233",
        application_executed=True,comparison_complete=False,full_sdk=False)
    (root/"RESULT.json").write_bytes(canonical(result));return result

def main():
    p=argparse.ArgumentParser();p.add_argument("--binary",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--original",type=Path,required=True)
    p.add_argument("--first",type=int,required=True);p.add_argument("--count",type=int,required=True)
    a=p.parse_args();binary=a.binary.resolve(strict=True);output=a.output.absolute()
    output.mkdir(parents=True,exist_ok=False)
    original=decode((a.original/"PLAN.json").read_bytes())
    require(original["declaration"]==declaration() and original["cases"]==cases(original["fixture_root"]),"unchanged original input-only cases")
    require(0<=a.first<22 and 0<a.count<=22-a.first,"fixed complete public subset")
    selected=original["cases"][a.first:a.first+a.count]
    require(all(c["mode"]=="public" for c in selected),"public role input")
    (output/"PLAN.json").write_bytes(canonical(dict(declaration=declaration(),fixture_root=original["fixture_root"],
        first=a.first,count=a.count,cases=selected,binary=pin(binary),binary_path=str(binary),
        original_plan=pin(a.original/"PLAN.json"))))
    (output/"cases").mkdir();results=[]
    for case in selected:
        row=capture_case(binary,case,output/"cases"/("%03d"%case["case"]))
        results.append(row);(output/"RESULTS.json").write_bytes(canonical(results))
        print(json.dumps({k:row[k] for k in ("status","case","name","era","commands")}),flush=True)
    (output/"SUMMARY.json").write_bytes(canonical(dict(status="NATIVE_PUBLIC_LIFECYCLE_CAPTURE_COMPLETE",
        first=a.first,count=a.count,cases=len(results),commands=sum(r["commands"] for r in results),
        comparison_complete=False,full_30_domain=False,full_sdk=False)))
if __name__=="__main__":main()
