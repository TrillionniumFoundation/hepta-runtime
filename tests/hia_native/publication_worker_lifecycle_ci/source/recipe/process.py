#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Owned process; exact retained pipe loops and budgets, fixed private journal FD3."""
from pathlib import Path
import gzip,hashlib,os,signal,struct,subprocess,time
from common import canonical,decode,pin,require
from retained_process import Process as Retained
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
class Process(Retained):
    def __init__(self,binary,cwd,root):
        self.root=Path(root);self.root.mkdir()
        self.started=time.monotonic();self.pending=b"";self.closed=False
        self.journal=(self.root/"journal.bin").open("xb",buffering=0)
        require(self.journal.fileno()==3,"fixed private journal FD3 must be free before fixture creation")
        self.stderr=(self.root/"stderr").open("xb")
        self.stdin=(self.root/"stdin").open("xb");self.stdout=(self.root/"stdout.gz").open("xb")
        self.gz=gzip.GzipFile(fileobj=self.stdout,mode="wb",compresslevel=1,mtime=0,filename="")
        self.command=[str(binary)];self.cwd=str(cwd)
        env={k:v for k,v in os.environ.items() if not k.startswith("HEPTA_EFFECT_OWNER_")}
        self.p=subprocess.Popen(self.command,cwd=cwd,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=self.stderr,start_new_session=True,bufsize=0,pass_fds=(3,))
        os.set_blocking(self.p.stdin.fileno(),False);os.set_blocking(self.p.stdout.fileno(),False)
        self.total_out=0;self.out_hash=hashlib.sha256();self.timed=False
    def frame(self,deadline):
        head=self.take(64,deadline)
        require(head[:8]==b"HPTWFR01" and U(head,56)==0,"complete private worker response header")
        size=U(head,16);require(size<=256<<20,"complete private worker output extent")
        return head+self.take(size,deadline)
    def finish(self,success):
        error=None
        try:super().finish(success)
        except BaseException as e:error=e
        finally:
            self.journal.close()
            path=self.root/"PROCESS.json"
            if path.exists():
                result=decode(path.read_bytes())
                result["journal"]=pin(self.root/"journal.bin")
                result["private_journal_fd"]=3
                try:os.killpg(self.p.pid,0);gone=False
                except ProcessLookupError:gone=True
                result["process_group_gone"]=gone
                path.write_bytes(canonical(result))
                if success:require(gone,"all owned clone workers must be reaped before fixture exit")
        if error:raise error
