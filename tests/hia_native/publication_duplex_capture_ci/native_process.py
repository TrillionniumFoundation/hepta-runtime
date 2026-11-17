#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Real two-session pipes, private observation socket and retained full bytes."""
from pathlib import Path
import fcntl,gzip,hashlib,json,os,select,signal,socket,struct,subprocess,sys,time
from common import canonical,pin,require,sha
HERE=Path(__file__).resolve().parent
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
def stat_fd(fd):
    s=os.fstat(fd);return dict(fd=fd,dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,nlink=s.st_nlink,uid=s.st_uid,gid=s.st_gid,size=s.st_size)
def children(pid):
    p=Path("/proc")/str(pid)/"task"/str(pid)/"children"
    try:return [int(x) for x in p.read_text().split()]
    except FileNotFoundError:return []
def blocked(pid,path):
    wanted=Path(path).stat();rows=[];matching=[]
    for child in children(pid):
        root=Path("/proc")/str(child)
        try:
            raw=(root/"syscall").read_text();parts=raw.split()
            row=dict(pid=child,syscall=raw)
            if len(parts)>=3 and int(parts[0],0)==73 and int(parts[2],0)==2:
                fd=int(parts[1],0);q=root/"fd"/str(fd);s=q.stat()
                row.update(fd=fd,dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,target=os.readlink(q))
                if (s.st_dev,s.st_ino)==(wanted.st_dev,wanted.st_ino):matching.append(child)
            rows.append(row)
        except (FileNotFoundError,ProcessLookupError,PermissionError) as e:
            rows.append(dict(pid=child,read_error=type(e).__name__,errno=e.errno))
    return dict(parent_pid=pid,path=str(path),dev=wanted.st_dev,ino=wanted.st_ino,matching_pids=matching,children=rows)

def retain_closed(path):
    """Lossless closed-byte retirement; verify every decompressed byte first."""
    path=Path(path);raw=pin(path);out=path.with_name(path.name+".gz")
    with path.open("rb") as source,out.open("xb") as target:
        with gzip.GzipFile(filename="",mode="wb",fileobj=target,mtime=0,compresslevel=1) as dest:
            while b:=source.read(1<<20):dest.write(b)
    h=hashlib.sha256();n=0
    with path.open("rb") as before,gzip.open(out,"rb") as after:
        while b:=before.read(1<<20):
            actual=after.read(len(b));require(actual==b,"complete closed stream compression")
            h.update(actual);n+=len(actual)
        require(not after.read(1),"compressed stream trailing bytes")
    require(raw==dict(bytes=n,sha256=h.hexdigest()) and pin(path)==raw,"closed source remained identical")
    compressed=pin(out);path.unlink()
    return dict(raw=raw,gzip=compressed,closed_before_compression=True,full_byte_reread=True)

class Process:
    def __init__(self,binary,config,work,root,store):
        self.root=Path(root);self.root.mkdir();self.work=str(Path(work));self.store=store;self.started=time.monotonic()
        self.sequence=0;self.controls=[];self.timed=False;self.closed=False
        self.wire=[bytearray(),bytearray()];self.wire_total=[0,0];self.peer_eof=[False,False]
        self.accepted=[0,0];self.last=None;self.observations=[];self.command_rows=[]
        self.streams={}
        for name in ("process.stdout","process.stderr","stdin-0","stdin-1","stdout-0","stdout-1","control.stdin","control.stdout"):
            self.streams[name]=(self.root/name).open("xb")
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        parent.setblocking(False);self.control=parent;self.control_pending=bytearray()
        ins=[];outs=[];high=[]
        try:
            for _ in range(2):ins.append(os.pipe2(os.O_CLOEXEC));outs.append(os.pipe2(os.O_CLOEXEC))
            journal=[]
            for name in ("bellman-journal","host-trace","publication-journal"):
                fd=os.open(self.root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600);journal.append(fd)
            native=[*journal,child.fileno(),ins[0][0],outs[0][1],ins[1][0],outs[1][1]]
            for fd in native:high.append(fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,32))
            for fd in journal:os.close(fd)
            env={k:v for k,v in os.environ.items() if not k.startswith("HEPTA_EFFECT_OWNER_")}
            self.command=[sys.executable,"-I","-S","-B",str(HERE/"fd_entry.py"),str(binary),str(config),*map(str,high)]
            self.p=subprocess.Popen(self.command,cwd=work,env=env,stdin=subprocess.DEVNULL,
                stdout=self.streams["process.stdout"],stderr=self.streams["process.stderr"],
                pass_fds=tuple(high),start_new_session=True,bufsize=0)
        finally:
            for fd in high:os.close(fd)
            child.close()
        self.input=[x[1] for x in ins];self.output=[x[0] for x in outs]
        for x in ins:os.close(x[0])
        for x in outs:os.close(x[1])
        for fd in [*self.input,*self.output]:os.set_blocking(fd,False)
        self.stream_identity=dict(inputs=[stat_fd(fd) for fd in self.input],
            outputs=[stat_fd(fd) for fd in self.output],control=stat_fd(parent.fileno()))
        self.save()
    def left(self,deadline):
        value=min(deadline,self.started+180)-time.monotonic()
        if value<=0:self.timed=True;raise TimeoutError("unchanged60s exchange /180s actual process")
        return value
    def save(self):
        (self.root/"CONTROLS.json").write_bytes(canonical(self.controls))
        (self.root/"OBSERVATIONS.json").write_bytes(canonical(self.observations))
    def poll(self,deadline,*,write_fd=None,delay=None):
        readers=[self.control,*[fd for fd in self.output if fd is not None]]
        writers=[] if write_fd is None else [write_fd]
        timeout=self.left(deadline)
        if delay is not None:timeout=min(timeout,delay)
        ready,writable,_=select.select(readers,writers,[],timeout)
        for fd in ready:
            if fd is self.control:
                b=self.control.recv(1<<20)
                require(b,"native control ended before explicit finalized reply")
                self.streams["control.stdout"].write(b);self.control_pending.extend(b)
            else:
                sid=self.output.index(fd);b=os.read(fd,1<<20)
                if b:
                    self.streams["stdout-"+str(sid)].write(b);self.wire[sid].extend(b);self.wire_total[sid]+=len(b)
                else:
                    os.close(fd);self.output[sid]=None;self.peer_eof[sid]=True
        return write_fd in writable
    def take_control(self,n,deadline):
        while len(self.control_pending)<n:self.poll(deadline)
        b=bytes(self.control_pending[:n]);del self.control_pending[:n];return b
    def control_command(self,op,sid=0,payload=b"",arg0=0,arg1=0,deadline=None):
        deadline=deadline or time.monotonic()+60;self.sequence+=1
        head=b"HAPFQ001"+struct.pack("<7Q",self.sequence,op,sid,len(payload),arg0,arg1,0);request=head+payload
        self.streams["control.stdin"].write(request);at=0;start=time.monotonic_ns()
        while at<len(request):
            if self.poll(deadline,write_fd=self.control):
                n=self.control.send(request[at:]);require(n>0,"control short send");at+=n
        h=self.take_control(128,deadline)
        require(h[:8]==b"HAPFR001" and (U(h,8),U(h,16),U(h,24),U(h,32))==(self.sequence,op,sid,0),"actual fixed control response")
        result_n,snap_n=U(h,40),U(h,48)
        require(result_n<=64<<20 and snap_n<=768<<20 and U(h,120)==12288 and U(h,56)<=32,"complete response bounds")
        result=self.take_control(result_n,deadline);co=self.take_control(4096,deadline)
        pms=[self.take_control(4096,deadline),self.take_control(4096,deadline)]
        require(co[:8]==b"HAPFC001" and U(co,8)==4096 and U(co,64)==self.sequence,"actual coordinator identity")
        require((U(h,64),U(h,72))==tuple(U(pm,328) for pm in pms),"actual session phase projection")
        require((U(h,96),U(h,104))==tuple(U(pm,1232) for pm in pms),"actual pipe read totals")
        snapshots=[]
        remain=snap_n
        if op in (3,5):
            for expected_sid in (0,1):
                sh=self.take_control(64,deadline)
                require(sh[:8]==b"HXLTR001" and (U(sh,8),U(sh,16),U(sh,24),U(sh,32),U(sh,40))==(self.sequence,op,expected_sid,0,0),"actual unchanged snapshot envelope")
                length=U(sh,48);require(length>=32 and length<=384<<20,"actual snapshot extent")
                raw=self.take_control(length,deadline);snapshots.append(dict(header=self.store.put(sh),body=self.store.put(raw)))
                remain-=64+length
        require(remain==0,"exact snapshot suffix")
        row=dict(number=len(self.controls),sequence=self.sequence,operation=op,session=sid,
            request=self.store.put(request),header=self.store.put(h),result=self.store.put(result),
            coordinator=self.store.put(co),pms=[self.store.put(pm) for pm in pms],snapshots=snapshots,
            elapsed_ns=time.monotonic_ns()-start)
        self.controls.append(row);self.save()
        self.last=dict(header=h,coordinator=co,pms=pms,result=result,row=row)
        return self.last
    def advance(self,*,milliseconds=0,deadline=None):
        return self.control_command(1,0,arg0=milliseconds,deadline=deadline)
    def events(self):
        require(self.last is not None,"no actual native observation")
        co=self.last["coordinator"];n=U(co,448);require(n<=32,"event table extent")
        return [dict(pool=U(co,512+i*64),job=U(co,520+i*64),engine=U(co,528+i*64),
            tag=U(co,536+i*64),stage=U(co,544+i*64),entered_trace=U(co,552+i*64),
            returned_trace=U(co,560+i*64),dropped_trace=U(co,568+i*64)) for i in range(n)]
    def send(self,sid,b):
        require(self.input[sid] is not None,"send after actual EOF")
        deadline=time.monotonic()+60;self.streams["stdin-"+str(sid)].write(b);at=0
        while at<len(b):
            if self.poll(deadline,write_fd=self.input[sid]):
                n=os.write(self.input[sid],b[at:]);require(n>0,"short public write");at+=n
        self.accepted[sid]+=len(b)
        while True:
            r=self.advance(deadline=deadline)
            if U(r["pms"][sid],1232)>=self.accepted[sid]:break
        return dict(bytes=len(b))
    def line(self,sid):
        deadline=time.monotonic()+60
        while b"\n" not in self.wire[sid]:
            require(not self.peer_eof[sid],"public response ended before a full line")
            self.advance(deadline=deadline);self.poll(deadline,delay=.001)
        n=self.wire[sid].index(10)+1;b=bytes(self.wire[sid][:n]);del self.wire[sid][:n]
        return b
    def eof(self,sid,*,drop_reader=False):
        require(self.input[sid] is not None,"duplicate actual EOF")
        os.close(self.input[sid]);self.input[sid]=None
        if drop_reader and self.output[sid] is not None:
            os.close(self.output[sid]);self.output[sid]=None;self.peer_eof[sid]=True
        self.advance()
        return dict(reader_writer_dropped=True) if drop_reader else dict(writer_shutdown=True)
    def drain(self,sid):
        require(self.input[sid] is None,"drain requires actual EOF")
        deadline=time.monotonic()+60;r=self.control_command(4,sid,deadline=deadline)
        while not self.peer_eof[sid]:self.poll(deadline)
        b=bytes(self.wire[sid]);self.wire[sid].clear()
        return dict(wire_hex=b.hex(),terminal=dict(actual_phase=U(r["pms"][sid],328),
            actual_eof_result=U(r["pms"][sid],1264),actual_pipe_closed=U(r["pms"][sid],1256)))
    def wait_blocked(self,path,count):
        deadline=time.monotonic()+60
        while True:
            self.advance(deadline=deadline)
            row=blocked(self.p.pid,path)
            if len(row["matching_pids"])>=count:
                self.observations.append(row);self.save();return row
            require(self.p.poll() is None,"native ended before owned flock observation")
            self.poll(deadline,delay=.001)
    def wait_events(self,event,count):
        deadline=time.monotonic()+60
        while True:
            self.advance(deadline=deadline);events=self.events()
            if event=="entered":n=len(events)
            elif event=="returned":n=sum(r["stage"]==2 for r in events)
            elif event=="dropped":n=sum(r["stage"]==3 for r in events)
            else:raise ValueError("native observer event outside frozen domain")
            if n>=count:return dict(event=event,count=n,actual_contexts=events)
            self.poll(deadline,delay=.001)
    def snapshot(self,sid):return self.control_command(3,sid)["row"]
    def finish(self,success):
        if self.closed:return
        self.closed=True;error=None;cleanup=[]
        try:
            if success:
                require(self.last is not None and U(self.last["header"],112)==1,"actual process runtime must be finalized")
                self.p.wait(timeout=self.left(self.started+180))
                require(self.p.returncode==0,"native final configuration teardown")
        except BaseException as e:error=e
        finally:
            if self.p.poll() is None:
                try:os.killpg(self.p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                try:self.p.wait(timeout=60)
                except BaseException as e:cleanup.append(repr(e))
            for i in range(2):
                if self.input[i] is not None:os.close(self.input[i]);self.input[i]=None
                if self.output[i] is not None:
                    try:
                        os.set_blocking(self.output[i],True)
                        while b:=os.read(self.output[i],1<<20):self.streams["stdout-"+str(i)].write(b)
                    except BaseException as e:cleanup.append(repr(e))
                    os.close(self.output[i]);self.output[i]=None
            self.control.close()
            for file in self.streams.values():file.close()
            group_absent=False
            try:os.killpg(self.p.pid,0)
            except ProcessLookupError:group_absent=True
            self.save()
            report=dict(command=self.command,cwd=self.work,pid=self.p.pid,exit_code=self.p.returncode,
                elapsed_seconds=time.monotonic()-self.started,timed_out=self.timed,
                timeout_seconds=180,exchange_limit_seconds=60,expected_success=success,
                completion_error=repr(error) if error else None,cleanup_errors=cleanup,
                process_group_absent=group_absent,stream_identity=self.stream_identity,
                files={name:retain_closed(self.root/name) for name in (*self.streams,"bellman-journal","host-trace","publication-journal")})
            (self.root/"PROCESS.json").write_bytes(canonical(report))
        if error:raise error
        require(not cleanup and group_absent,"owned native process cleanup")
