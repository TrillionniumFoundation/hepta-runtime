# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact retained owned-process class, with only its import environment isolated."""
from pathlib import Path
import gzip,hashlib,json,os,select,signal,struct,subprocess,time
from common import canonical,pin,require
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]

class Process:
    def __init__(self,command,cwd,root,fence):
        self.root=root;self.started=time.monotonic();self.pending=b"";self.closed=False
        env={k:v for k,v in os.environ.items() if not k.startswith("HEPTA_EFFECT_OWNER_")}
        if fence:env["HEPTA_EFFECT_OWNER_FENCE_REQUIRED"]="1"
        self.stderr=(root/"stderr").open("xb")
        self.stdin=(root/"stdin").open("xb");self.stdout=(root/"stdout.gz").open("xb")
        self.gz=gzip.GzipFile(fileobj=self.stdout,mode="wb",compresslevel=1,mtime=0,filename="")
        self.command=list(map(str,command));self.cwd=str(cwd)
        self.p=subprocess.Popen(self.command,cwd=cwd,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=self.stderr,start_new_session=True,bufsize=0)
        os.set_blocking(self.p.stdin.fileno(),False);os.set_blocking(self.p.stdout.fileno(),False)
        self.total_out=0;self.out_hash=hashlib.sha256();self.timed=False
    def remaining(self,deadline):
        left=min(deadline,self.started+180)-time.monotonic()
        if left<=0:self.timed=True;raise TimeoutError("unchanged 60-second exchange / 180-second process bound")
        return left
    def send(self,raw,deadline):
        self.stdin.write(raw);self.stdin.flush();at=0
        while at<len(raw):
            _,ready,_=select.select([], [self.p.stdin],[],self.remaining(deadline))
            require(ready,"stdin deadline")
            count=os.write(self.p.stdin.fileno(),raw[at:])
            require(count>0,"short stdin write");at+=count
    def more(self,deadline):
        ready,_,_=select.select([self.p.stdout],[],[],self.remaining(deadline))
        require(ready,"stdout deadline")
        raw=os.read(self.p.stdout.fileno(),1<<20)
        if raw:self.gz.write(raw);self.total_out+=len(raw);self.out_hash.update(raw);self.pending+=raw
        return bool(raw)
    def take(self,count,deadline):
        while len(self.pending)<count:require(self.more(deadline),"native stdout ended before complete frame")
        raw,self.pending=self.pending[:count],self.pending[count:];return raw
    def frame(self,deadline):
        head=self.take(104,deadline);require(head[:8]==b"HFSFXR02","native carrier magic")
        length=U(head,32);require(length<=256<<20,"native response exceeds declared owned graph capacity")
        return head+self.take(length,deadline)
    def line(self,deadline):
        while b"\n" not in self.pending:require(self.more(deadline),"original stdout ended before complete line")
        count=self.pending.index(b"\n")+1
        raw,self.pending=self.pending[:count],self.pending[count:];return raw
    def finish(self,success):
        if self.closed:return
        self.closed=True;failure=None
        try:
            self.p.stdin.close()
            if success:
                require(not self.pending,"extra process output")
                while self.more(self.started+180):
                    require(not self.pending,"unexpected output at EOF")
                self.p.wait(timeout=self.remaining(self.started+180))
                require(self.p.returncode==0,"process nonzero at EOF")
        except BaseException as exc:failure=exc
        finally:
            if self.p.poll() is None:
                os.killpg(self.p.pid,signal.SIGKILL);self.p.wait()
            os.set_blocking(self.p.stdout.fileno(),True)
            while remaining := os.read(self.p.stdout.fileno(),1<<20):
                self.gz.write(remaining);self.total_out+=len(remaining);self.out_hash.update(remaining)
            self.p.stdout.close();self.stdin.close();self.gz.close();self.stdout.close();self.stderr.close()
            receipt=dict(command=self.command,cwd=self.cwd,pid=self.p.pid,exit_code=self.p.returncode,
                timed_out=self.timed,elapsed_seconds=time.monotonic()-self.started,timeout_seconds=180,
                exchange_limit_seconds=60,expected_success=success,cleanup_error=repr(failure) if failure else None,
                stdin=pin(self.root/"stdin"),stdout_gzip=pin(self.root/"stdout.gz"),stderr=pin(self.root/"stderr"),
                full_stdout=dict(bytes=self.total_out,sha256=self.out_hash.hexdigest()))
            (self.root/"PROCESS.json").write_bytes(canonical(receipt))
        if failure:raise failure
