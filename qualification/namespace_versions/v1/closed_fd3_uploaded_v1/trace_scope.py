"""Complete per-application ptrace custody; the filesystem observer stays untraced."""
import ctypes as C,errno,os,signal
from pathlib import Path
from common import encoded,read,require
TRACE="inotify_init1,inotify_add_watch,inotify_rm_watch,read,openat,fcntl,dup2,dup3,close,write,writev,exit_group,newfstatat,fstat,statx,prlimit64,setrlimit,mmap,munmap,mprotect,futex,clone,clone3,set_robust_list,rseq,getdents64"
READ_FDS=",".join(str(x)for x in [0,1,2,*range(32,320)])
def traced(argv,trace):
    return ["/usr/bin/strace","-qq","-f","--kill-on-exit","-s","65536","-xx","-v","-o",str(trace),
        "-e","trace="+TRACE,"-e","raw=read,write,writev","-e","read="+READ_FDS,*map(str,argv)]
def process_identity(pid):
    require(type(pid)is int and pid>0,"actual positive OS process identity")
    with (Path("/proc")/str(pid)/"stat").open("rb")as stream:raw=stream.read(65537)
    require(0<len(raw)<=65536,"complete bounded proc stat")
    end=raw.rfind(b")");require(end>0,"complete owned process stat")
    fields=raw[end+2:].split()
    require(int(raw[:raw.find(b" ")])==pid and len(fields)>=20,"exact live owned process stat")
    return dict(pid=pid,parent_pid=int(fields[1]),pgid=int(fields[2]),session=int(fields[3]),
        start_ticks=int(fields[19]),raw_hex=raw.hex())
class Reaper:
    def __init__(self):
        self.libc=C.CDLL(None,use_errno=True)
        self.prctl=self.libc.prctl
        self.prctl.argtypes=[C.c_int,C.c_ulong,C.c_ulong,C.c_ulong,C.c_ulong]
        self.prctl.restype=C.c_int
        value=C.c_int()
        require(self.prctl(37,C.addressof(value),0,0,0)==0 and value.value in(0,1),
            "actual Linux child-subreaper query")
        self.prior=value.value;self.active=False;self.reaped=[]
        require(self.prctl(36,1,0,0,0)==0,"actual owned child-subreaper installation")
        self.active=True
    def finish(self):
        try:
            while True:
                try:pid,status=os.waitpid(-1,0)
                except InterruptedError:continue
                except ChildProcessError:break
                self.reaped.append(dict(pid=pid,wait_status=status,
                    exit_code=os.waitstatus_to_exitcode(status)))
        finally:
            if self.active:
                self.active=False
                require(self.prctl(36,self.prior,0,0,0)==0,"restore actual prior child-subreaper state")
        return self.reaped
