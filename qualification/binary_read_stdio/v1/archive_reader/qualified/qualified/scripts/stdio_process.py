#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Only bounded process/pipe custody; no file operation or expected-result decisions."""
from pathlib import Path
import errno,fcntl,gzip,hashlib,os,selectors,signal,time
from common import canonical,pin,require
class Sink:
    def __init__(self,path):
        self.path=Path(path);self.file=self.path.open("xb")
        self.stream=gzip.GzipFile(filename="",fileobj=self.file,mode="wb",compresslevel=1,mtime=0)
        self.digest=hashlib.sha256();self.count=0
    def put(self,raw):
        self.stream.write(raw);self.digest.update(raw);self.count+=len(raw)
    def finish(self):
        self.stream.close();self.file.close()
        return dict(raw=dict(bytes=self.count,sha256=self.digest.hexdigest()),compressed=pin(self.path),
            complete_raw_bytes_in_gzip=True,no_expanded_ordinary_copy_created=True)
def run(folder,argv,raw,*,observed,native,input_chunk,output_chunk,control=False):
    folder=Path(folder);folder.mkdir()
    sinks={n:Sink(folder/(n+".gz"))for n in("stdin","stdout","stderr","body","formatter")}
    pipes={};duplicates=[];actions=[];parent={};child=[];pid=None;status=None;failure=None;reaped=False
    selector=selectors.DefaultSelector();started=time.monotonic_ns();deadline=time.monotonic()+30
    row=dict(argv=[str(x)for x in argv],binary=pin(Path(argv[0])),observed=observed,native=native,
        fixed_journal_fds=[3,4]if observed else[],input_chunk_bytes=input_chunk,output_chunk_bytes=output_chunk,
        expected_input_bytes=len(raw),writes=[],completed=False,timed_out=False,timeout_seconds=30,
        parent_pid=os.getpid(),parent_pgid=os.getpgrp(),returncode=None,wait_status=None,
        same_outer_process_group=False,stdin_closed=False,stdin_broken_pipe=False,
        before_eof=None,after_reap_proc_absent=False,control=control)
    try:
        for name in("stdin","stdout","stderr")+(("body","formatter")if observed else()):
            read,write=os.pipe()
            if name=="stdin":parent[name]=write;child.append(read);source=read;target=0
            else:
                parent[name]=read;child.append(write);source=write
                target={"stdout":1,"stderr":2,"body":3,"formatter":4}[name]
            duplicate=fcntl.fcntl(source,fcntl.F_DUPFD_CLOEXEC,64);duplicates.append(duplicate)
            actions.append((os.POSIX_SPAWN_DUP2,duplicate,target))
        actions.extend((os.POSIX_SPAWN_CLOSE,fd)for fd in duplicates)
        env=dict(os.environ)
        for key in("GH_TOKEN","GITHUB_TOKEN","ACTIONS_RUNTIME_TOKEN","LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT"):env.pop(key,None)
        if native:env["PATH"]=""
        pid=os.posix_spawn(str(argv[0]),[str(x)for x in argv],env,file_actions=actions)
        row.update(pid=pid,child_pgid=os.getpgid(pid),same_outer_process_group=os.getpgid(pid)==os.getpgrp())
        require(row["same_outer_process_group"],"helper escaped bounded producer process group")
        for fd in child+duplicates:os.close(fd)
        child=[];duplicates=[]
        for name,fd in parent.items():
            os.set_blocking(fd,False)
            if name!="stdin":selector.register(fd,selectors.EVENT_READ,name)
        if raw:selector.register(parent["stdin"],selectors.EVENT_WRITE,"stdin")
        offset=0;eof_at=None;input_open=True;outputs={n for n in parent if n!="stdin"}
        while input_open or outputs or status is None:
            now=time.monotonic()
            if now>=deadline:row["timed_out"]=True;raise TimeoutError("helper exceeded frozen 30-second bound")
            if status is None:
                got,value=os.waitpid(pid,os.WNOHANG)
                if got:status=value;reaped=True
            if input_open and offset==len(raw)and eof_at is None:
                maps=b"";fds={};alive=False
                try:
                    proc=Path("/proc")/str(pid);maps=(proc/"maps").read_bytes()
                    fds={p.name:os.readlink(p)for p in sorted((proc/"fd").iterdir(),key=lambda p:int(p.name))}
                    alive=True
                except(FileNotFoundError,ProcessLookupError):pass
                (folder/"before-eof.maps").write_bytes(maps)
                row["before_eof"]=dict(alive=alive,fd=fds,maps=pin(folder/"before-eof.maps"),
                    output_bytes={n:sinks[n].count for n in("stdout","stderr","body","formatter")},
                    sent_bytes=offset,hold_milliseconds=5)
                eof_at=now+0.005
            if input_open and (status is not None or eof_at is not None and now>=eof_at):
                try:selector.unregister(parent["stdin"])
                except KeyError:pass
                os.close(parent["stdin"]);parent.pop("stdin");input_open=False;row["stdin_closed"]=True
            if not input_open and not outputs and status is not None:break
            timeout=min(0.05,deadline-time.monotonic())
            if input_open and eof_at is not None:timeout=min(timeout,max(0,eof_at-time.monotonic()))
            for key,mask in selector.select(max(0,timeout)):
                name=key.data
                if name=="stdin":
                    try:count=os.write(key.fd,memoryview(raw)[offset:offset+input_chunk])
                    except BlockingIOError:continue
                    except BrokenPipeError:
                        row["stdin_broken_pipe"]=True;selector.unregister(key.fd);os.close(key.fd)
                        parent.pop("stdin");input_open=False;row["stdin_closed"]=True;continue
                    require(count>0,"helper input made no progress")
                    sinks["stdin"].put(raw[offset:offset+count]);row["writes"].append(dict(offset=offset,count=count));offset+=count
                    if offset==len(raw):selector.unregister(key.fd)
                else:
                    try:part=os.read(key.fd,(1<<20)if name in("body","formatter")else output_chunk)
                    except BlockingIOError:continue
                    if part:sinks[name].put(part)
                    else:
                        selector.unregister(key.fd);os.close(key.fd);parent.pop(name);outputs.remove(name)
        require(reaped and status is not None,"helper child not reaped")
        row.update(returncode=os.waitstatus_to_exitcode(status),wait_status=status,completed=True)
    except BaseException as error:
        failure=error
    finally:
        selector.close()
        for fd in child+duplicates:
            try:os.close(fd)
            except OSError:pass
        if pid is not None and not reaped:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:_,status=os.waitpid(pid,0);reaped=True
            except ChildProcessError:pass
        for name,fd in list(parent.items()):
            if name!="stdin":
                try:
                    while part:=os.read(fd,1<<20):sinks[name].put(part)
                except(BlockingIOError,OSError):pass
            try:os.close(fd)
            except OSError:pass
        if status is not None:row.update(returncode=os.waitstatus_to_exitcode(status),wait_status=status)
        row["streams"]={name:sink.finish()for name,sink in sinks.items()}
        row["elapsed_ns"]=time.monotonic_ns()-started
        row["after_reap_proc_absent"]=pid is not None and not (Path("/proc")/str(pid)).exists()
        row["reaped"]=reaped
        if not (folder/"before-eof.maps").exists():(folder/"before-eof.maps").write_bytes(b"")
        if failure:row["failure"]=dict(type=type(failure).__name__,message=str(failure))
        (folder/"PROCESS.json").write_bytes(canonical(row))
    if failure:raise failure
    return row
