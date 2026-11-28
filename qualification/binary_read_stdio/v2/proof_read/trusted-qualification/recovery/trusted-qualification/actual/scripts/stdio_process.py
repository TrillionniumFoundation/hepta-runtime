#!/usr/bin/env python3
"""Bounded single-child pipe custody and passive kernel observation; no result injection."""
from pathlib import Path
import fcntl,gzip,hashlib,os,selectors,signal,sys,time
from common import canonical,pin,require
from stdio_trace import StdioTrace,BodyFrames
from kernel_trace import ptrace
class Sink:
    def __init__(self,path):
        self.path=Path(path);self.file=self.path.open("xb")
        self.stream=gzip.GzipFile(filename="",fileobj=self.file,mode="wb",compresslevel=1,mtime=0)
        self.digest=hashlib.sha256();self.count=0
    def put(self,raw):self.stream.write(raw);self.digest.update(raw);self.count+=len(raw)
    def finish(self):
        self.stream.close();self.file.close()
        return dict(raw=dict(bytes=self.count,sha256=self.digest.hexdigest()),compressed=pin(self.path),
            complete_raw_bytes_in_gzip=True,no_expanded_ordinary_copy_created=True)
def run(folder,argv,raw,*,observed,native,input_chunk,output_chunk,fault):
    folder=Path(folder);folder.mkdir()
    names=("stdin","stdout","stderr","body","formatter","ack")
    sinks={n:Sink(folder/(n+".gz"))for n in names}
    parent={};child=[];duplicates=[];actions=[];pid=None;status=None;failure=None;trace=None
    selector=selectors.DefaultSelector();started=time.monotonic_ns();deadline=time.monotonic()+60
    framer=BodyFrames()if observed else None;ack_sent=False
    launcher=Path(__file__).with_name("trace_launch.py").resolve(strict=True);python=Path(sys.executable).resolve(strict=True)
    mode="native-first-fstat"if native and fault else"normal"
    launch=[str(python),"-I","-S","-B",str(launcher),mode,*map(str,argv)]
    row=dict(argv=list(map(str,argv)),binary=pin(Path(argv[0])),observed=observed,native=native,fault=fault,
        launcher=pin(launcher),launcher_argv=launch,launcher_python=pin(python),
        fixed_journal_fds=[3,4,5]if observed else[],input_chunk_bytes=input_chunk,output_chunk_bytes=output_chunk,
        expected_input_bytes=len(raw),writes=[],completed=False,timed_out=False,timeout_seconds=60,
        parent_pid=os.getpid(),parent_pgid=os.getpgrp(),returncode=None,wait_status=None,
        same_outer_process_group=False,stdin_closed=False,stdin_broken_pipe=False,after_reap_proc_absent=False)
    try:
        pairs=[("stdin",0,True),("stdout",1,False),("stderr",2,False)]
        if observed:pairs += [("body",3,False),("formatter",4,False),("ack",5,True)]
        for name,target,to_child in pairs:
            read,write=os.pipe();source=read if to_child else write
            parent[name]=write if to_child else read;child.append(source)
            duplicate=fcntl.fcntl(source,fcntl.F_DUPFD_CLOEXEC,64);duplicates.append(duplicate)
            actions.append((os.POSIX_SPAWN_DUP2,duplicate,target))
        actions.extend((os.POSIX_SPAWN_CLOSE,fd)for fd in duplicates)
        env=dict(os.environ)
        for key in("GH_TOKEN","GITHUB_TOKEN","ACTIONS_RUNTIME_TOKEN","LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT"):env.pop(key,None)
        env["PATH"]="";env["PYTHONHASHSEED"]="0"
        pid=os.posix_spawn(str(python),launch,env,file_actions=actions)
        row.update(pid=pid,child_pgid=os.getpgid(pid),same_outer_process_group=os.getpgid(pid)==os.getpgrp())
        require(row["same_outer_process_group"],"target escaped bounded producer group")
        for fd in child+duplicates:os.close(fd)
        child=[];duplicates=[]
        trace=StdioTrace(pid,folder,observed=observed,expected_input_bytes=len(raw))
        trace.output_counts=lambda:{n:sinks[n].count for n in("stdout","stderr","body","formatter")}
        for name,fd in parent.items():
            os.set_blocking(fd,False)
            if name not in("stdin","ack"):selector.register(fd,selectors.EVENT_READ,name)
        if raw:selector.register(parent["stdin"],selectors.EVENT_WRITE,"stdin")
        offset=0;eof_at=None;input_open=True;outputs={n for n in parent if n not in("stdin","ack")}
        while input_open or outputs or trace.status is None:
            if time.monotonic()>=deadline:row["timed_out"]=True;raise TimeoutError("fixed 60-second helper budget")
            trace.pump();status=trace.status
            if input_open and trace.before_eof is not None and eof_at is None:
                require(offset==len(raw),"target consumed unsent input")
                eof_at=time.monotonic()+0.005
            if input_open and eof_at is not None and time.monotonic()>=eof_at:
                row["eof_mark"]=trace.mark("owned-stdin-eof",application=True)
                try:selector.unregister(parent["stdin"])
                except KeyError:pass
                os.close(parent.pop("stdin"));input_open=False;row["stdin_closed"]=True
            if observed and framer.final_ack and not ack_sent:
                require(os.write(parent["ack"],bytes(8))==8,"complete final lifecycle ACK")
                sinks["ack"].put(bytes(8));ack_sent=True
                row["lifecycle_ack"]=dict(bytes=8,hex=bytes(8).hex(),body_offset=framer.final_offset,
                    sent_after_full_final_frame=True)
            if not input_open and not outputs and status is not None:break
            for key,mask in selector.select(min(.0002,max(0,deadline-time.monotonic()))):
                name=key.data
                if name=="stdin":
                    try:count=os.write(key.fd,memoryview(raw)[offset:offset+input_chunk])
                    except BlockingIOError:continue
                    except BrokenPipeError:
                        row["stdin_broken_pipe"]=True;raise
                    require(count>0,"input write made no progress")
                    sinks["stdin"].put(raw[offset:offset+count]);row["writes"].append(dict(offset=offset,count=count));offset+=count
                    if offset==len(raw):selector.unregister(key.fd)
                else:
                    try:part=os.read(key.fd,(1<<20)if name in("body","formatter")else output_chunk)
                    except BlockingIOError:continue
                    if part:
                        sinks[name].put(part)
                        if name=="body":framer.put(part)
                    else:
                        selector.unregister(key.fd);os.close(parent.pop(name));outputs.remove(name)
        require(status is not None and trace.status==status,"target not naturally reaped")
        if observed:row["body_framing"]=framer.finish();require(ack_sent,"complete lifecycle release")
        row["kernel"]=trace.finish();row["before_eof"]=trace.before_eof;row["pre_exit"]=trace.pre_exit
        row.update(returncode=os.waitstatus_to_exitcode(status),wait_status=status,completed=True,reaped=True)
    except BaseException as e:failure=e
    finally:
        selector.close()
        for fd in child+duplicates:
            try:os.close(fd)
            except OSError:pass
        if pid is not None and(trace is None or trace.status is None):
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:
                while True:
                    _,value=os.waitpid(pid,0)
                    if os.WIFEXITED(value)or os.WIFSIGNALED(value):status=value;break
                    if os.WIFSTOPPED(value):ptrace(24,pid)
            except ChildProcessError:pass
        if failure and trace is not None:trace.close_failure()
        for name,fd in list(parent.items()):
            if name not in("stdin","ack"):
                try:
                    while part:=os.read(fd,1<<20):sinks[name].put(part)
                except(BlockingIOError,OSError):pass
            try:os.close(fd)
            except OSError:pass
        if status is not None:row.update(returncode=os.waitstatus_to_exitcode(status),wait_status=status)
        row["streams"]={name:sink.finish()for name,sink in sinks.items()}
        row["elapsed_ns"]=time.monotonic_ns()-started
        row["after_reap_proc_absent"]=pid is not None and not(Path("/proc")/str(pid)).exists()
        if failure:row["failure"]=dict(type=type(failure).__name__,message=str(failure))
        (folder/"PROCESS.json").write_bytes(canonical(row))
    if failure:raise failure
    return row
