#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""A first real public pending probe under an owned directory flock.

This captures actual native behavior only. It supplies no expected wire and
does not replace the complete22 public +8 direct original lifecycle domain.
"""
from pathlib import Path
import argparse,fcntl,hashlib,json,os,select,signal,stat,subprocess,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def raw(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n").encode()
def put(p,v):Path(p).write_bytes(raw(v))
def require(value,message):
    if not value:raise ValueError(message)
def pin(p):
    h=hashlib.sha256();n=0
    with Path(p).open("rb") as f:
        while b:=f.read(1<<20):n+=len(b);h.update(b)
    return dict(bytes=n,sha256=h.hexdigest())
def st(fd):
    s=os.fstat(fd);return dict(fd=fd,dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,nlink=s.st_nlink,uid=s.st_uid,gid=s.st_gid,size=s.st_size)
def meta():return {"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"publisher-async-reference","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}
def request(era,method,identifier,params):
    if era=="modern":params=dict(params,_meta=meta())
    return raw(dict(jsonrpc="2.0",method=method,id=identifier,params=params))
def wait_children(pid):
    value=(Path("/proc")/str(pid)/"task"/str(pid)/"children").read_text()
    return [int(s) for s in value.split()]
def inspect_blocked(pid,identity):
    try:
        p=Path("/proc")/str(pid);line=(p/"syscall").read_text();items=line.split()
        if len(items)<3 or int(items[0],0)!=73 or int(items[2],0)!=2:return None
        fd=int(items[1],0);s=(p/"fd"/str(fd)).stat()
        if (s.st_dev,s.st_ino)!=(identity["dev"],identity["ino"]):return None
        return dict(pid=pid,syscall=line,fd=fd,dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,fd_target=os.readlink(p/"fd"/str(fd)))
    except (FileNotFoundError,ProcessLookupError):return None
class Probe:
    def __init__(self,binary,config,work,out):
        self.out=out;self.start=time.monotonic();self.deadline=self.start+180
        self.pending=bytearray();self.events=[];self.responses=[];self.in_open=True;self.timed=False;self.success=False
        self.stdin=(out/"stdin").open("xb");self.stdout=(out/"stdout").open("xb");self.stderr=(out/"stderr").open("xb")
        self.observers=[];high=[]
        try:
            for name in ("bellman-journal","host-trace","publication-journal"):
                fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                try:h=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,20)
                finally:os.close(fd)
                high.append(h)
            env={k:v for k,v in os.environ.items() if not k.startswith("HEPTA_EFFECT_OWNER_")}
            self.command=[sys.executable,"-I","-S","-B",str(HERE/"fd_entry.py"),str(binary),str(config),*map(str,high)]
            self.p=subprocess.Popen(self.command,cwd=work,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=self.stderr,pass_fds=tuple(high),start_new_session=True,bufsize=0)
        finally:
            for h in high:os.close(h)
        os.set_blocking(self.p.stdin.fileno(),False);os.set_blocking(self.p.stdout.fileno(),False)
        self.event("started",pid=self.p.pid,process_group=self.p.pid,command=self.command)
    def event(self,kind,**values):
        self.events.append(dict(number=len(self.events),event=kind,monotonic_ns=time.monotonic_ns(),**values))
        put(self.out/"EVENTS.json",self.events)
    def left(self,limit):
        n=min(limit,self.deadline)-time.monotonic()
        if n<=0:self.timed=True;raise TimeoutError("unchanged60-second exchange/180-second process")
        return n
    def drain_ready(self,limit,interval=None):
        left=self.left(limit);ready,_,_=select.select([self.p.stdout],[],[],min(left,interval) if interval is not None else left)
        if not ready:return None
        b=os.read(self.p.stdout.fileno(),1<<20)
        if b:self.stdout.write(b);self.stdout.flush();self.pending.extend(b)
        return bool(b)
    def send(self,b):
        limit=time.monotonic()+60;self.stdin.write(b);self.stdin.flush()
        at=0
        while at<len(b):
            _,ready,_=select.select([], [self.p.stdin],[],self.left(limit))
            require(ready,"stdin deadline");n=os.write(self.p.stdin.fileno(),b[at:]);require(n>0,"short stdin");at+=n
        self.event("sent",bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),input=json.loads(b))
    def line(self,limit=None):
        limit=limit or time.monotonic()+60
        while b"\n" not in self.pending:require(self.drain_ready(limit),"stdout ended before complete response")
        n=self.pending.index(10)+1;b=bytes(self.pending[:n]);del self.pending[:n]
        row=dict(number=len(self.responses),wire_hex=b.hex(),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
        self.responses.append(row);put(self.out/"RESPONSES.json",self.responses);return json.loads(b)
    def until_id(self,identifier):
        for _ in range(16):
            if self.line().get("id")==identifier:return
        raise ValueError("barrier response not observed within fixed16-line bound")
    def blocked(self,identity):
        limit=time.monotonic()+60
        while True:
            self.left(limit);require(self.p.poll() is None,"native ended before actual worker flock")
            children=wait_children(self.p.pid)
            rows=[v for p in children if (v:=inspect_blocked(p,identity)) is not None]
            if rows:self.event("actual_worker_blocked",children=children,blocked=rows);return rows
            self.drain_ready(limit,.001)
    def reaped(self,children):
        limit=time.monotonic()+60
        while True:
            self.left(limit)
            alive=wait_children(self.p.pid) if self.p.poll() is None else []
            if not set(children)&set(alive):self.event("held_children_reaped",children=children);return
            self.drain_ready(limit,.001)
    def eof(self):
        if self.in_open:self.p.stdin.close();self.in_open=False;self.event("stdin_eof")
    def finish(self,success):
        cleanup=[];failure=None
        try:
            self.eof()
            if success:
                while True:
                    state=self.drain_ready(self.deadline)
                    if state is False:break
                while b"\n" in self.pending:self.line(self.deadline)
                require(not self.pending,"partial final public response")
                self.p.wait(timeout=self.left(self.deadline))
                require(self.p.returncode==0,"native public EOF returned nonzero")
        except BaseException as e:failure=e
        finally:
            if self.p.poll() is None:
                try:os.killpg(self.p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                try:self.p.wait(timeout=60)
                except BaseException as e:cleanup.append(repr(e))
            try:
                os.set_blocking(self.p.stdout.fileno(),True)
                while b:=os.read(self.p.stdout.fileno(),1<<20):self.stdout.write(b)
            except BaseException as e:cleanup.append(repr(e))
            self.p.stdout.close();self.stdin.close();self.stdout.close();self.stderr.close()
            group_absent=False
            try:os.killpg(self.p.pid,0)
            except ProcessLookupError:group_absent=True
            self.event("reaped",exit_code=self.p.returncode,process_group_absent=group_absent)
            report=dict(exit_code=self.p.returncode,timed_out=self.timed,elapsed_seconds=time.monotonic()-self.start,
                timeout_seconds=180,exchange_limit_seconds=60,expected_success=success,cleanup_errors=cleanup,
                completion_error=repr(failure) if failure else None,process_group_absent=group_absent,
                files={n:pin(self.out/n) for n in ("stdin","stdout","stderr","bellman-journal","host-trace","publication-journal")})
            put(self.out/"PROCESS.json",report)
        if failure:raise failure
        require(not cleanup and group_absent,"owned process cleanup incomplete")
def run(binary,root,era,action):
    root.mkdir();work=root/"fixture";work.mkdir();(work/"held").mkdir();(work/"free").mkdir()
    config=root/"config.json";put(config,dict(state_dir=str(root/"controller-state"),controller_workspace_roots=[str(work)],
        hosts={"fixture":dict(ssh_target="uncontacted-async-reference",remote_state_dir="/unused-runtime-state",allow_write=True,
            allowed_read_path_prefixes=["/allowed"],allowed_write_path_prefixes=["/allowed"],protected_path_prefixes=["/allowed/protected"])}))
    config.chmod(0o600);out=root/"process";out.mkdir()
    fd=os.open(work/"held",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    identity=st(fd);locked=True;proc=None;success=False
    try:
        proc=Probe(binary,config,work,out);proc.event("holder_locked",identity=identity)
        if era=="legacy":
            proc.send(raw(dict(jsonrpc="2.0",id=1,method="initialize",params=dict(protocolVersion="2025-11-25",
                capabilities={},clientInfo=dict(name="publisher-async-reference",version="1")))))
            proc.until_id(1);proc.send(raw(dict(jsonrpc="2.0",method="notifications/initialized")))
        else:proc.send(request(era,"tools/list",1,{}));proc.until_id(1)
        params=dict(path=str(work/"held/a.txt"),mode="create",content="ordinary publication: held/a.txt\n",expected_sha256="absent")
        proc.send(request(era,"tools/call",10,dict(name="text_file_write",arguments=params)))
        blocked=proc.blocked(identity)
        require(not (work/"held/a.txt").exists(),"held parent must precede publication")
        if action=="cancel_pending":
            p=dict(requestId=10,reason="owned ordinary cancellation observation",_meta=meta())
            proc.send(raw(dict(jsonrpc="2.0",method="notifications/cancelled",params=p)))
        proc.send(request(era,"ping",9000,{}));proc.until_id(9000)
        proc.event("ping_completed_while_actual_worker_blocked",blocked=blocked)
        if action=="eof_pending":
            proc.eof();until=time.monotonic()+.05
            while time.monotonic()<until:
                proc.drain_ready(proc.deadline,.001)
            proc.event("held_after_eof",process_alive=proc.p.poll() is None,
                blocked=[v for r in blocked if (v:=inspect_blocked(r["pid"],identity)) is not None])
        fcntl.flock(fd,fcntl.LOCK_UN);locked=False;proc.event("holder_unlocked",identity=st(fd))
        if action!="eof_pending":
            proc.reaped([r["pid"] for r in blocked])
            proc.send(request(era,"ping",9001,{}));proc.until_id(9001)
        success=True
    except BaseException as e:
        put(root/"FAILURE.json",dict(type=type(e).__name__,message=str(e),traceback=traceback.format_exc()))
        raise
    finally:
        if locked:
            fcntl.flock(fd,fcntl.LOCK_UN)
            if proc is not None:proc.event("failure_holder_unlocked",identity=st(fd))
        os.close(fd)
        if proc is not None:proc.finish(success)
    files=[]
    for p in sorted(work.rglob("*")):
        s=p.lstat();files.append(dict(path=p.relative_to(work).as_posix(),mode=stat.S_IMODE(s.st_mode),
            kind="directory" if p.is_dir() else "file",pin=pin(p) if p.is_file() else None))
    result=dict(status="ACTUAL_PUBLIC_PENDING_PROBE_CAPTURED",era=era,action=action,files=files,
        production_async_qualified=False,complete_original_domain=False,expected_wire_supplied=False)
    put(root/"RESULT.json",result);return result
def main():
    p=argparse.ArgumentParser();p.add_argument("--restored",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    require(os.environ.get("GITHUB_ACTIONS")=="true","native execution is restricted to CI")
    identity=json.loads((HERE/"BUILD_INPUT.json").read_bytes());binary=a.restored/"extracted"/identity["observed_binary"]["path"]
    require(pin(binary)=={k:identity["observed_binary"][k] for k in ("bytes","sha256")},"exact admitted native image")
    a.output.mkdir(parents=True,exist_ok=False);domain=json.loads((HERE/"DOMAIN.json").read_bytes())
    put(a.output/"DOMAIN.json",domain);put(a.output/"BUILD_INPUT.json",identity)
    result=[]
    for i,row in enumerate(domain["cases"]):
        item=run(binary.resolve(),a.output/("%02d-%s-%s"%(i,row["era"],row["action"])),**row)
        result.append(item);put(a.output/"RESULTS.json",result);print(json.dumps(item,sort_keys=True),flush=True)
    summary=dict(status="ACTUAL_PUBLIC_PENDING_DIAGNOSTIC_COMPLETE",processes=len(result),public_async_qualified=False,
        full_original_domain=False,source=identity["source"],binary=pin(binary))
    put(a.output/"SUMMARY.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
