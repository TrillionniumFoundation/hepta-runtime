"""Trace only a freshly forked private fixture and its reported descendants.

There is no attach-to-an-existing-PID interface. Holds and completion injections
are explicit test actions; the unmodified kernel result remains in the log.
"""
from __future__ import annotations
from pathlib import Path
import ctypes
import errno
import gzip
import hashlib
import json
import os
import selectors
import signal
import stat
import struct
import time
import traceback

MASK=(1<<64)-1
WALL=0x40000000
TRACEME=0;GETREGS=12;SETREGS=13;SYSCALL=24;SETOPTIONS=0x4200
GETEVENTMSG=0x4201;GET_SYSCALL_INFO=0x420e
OPTIONS=1|2|4|8|16|64|0x100000
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.ptrace.restype=ctypes.c_long
LIBC.ptrace.argtypes=(ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p)


class Registers(ctypes.Structure):
    _fields_=[(name,ctypes.c_ulonglong)for name in (
        'r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi',
        'orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')]


def ptrace(request,pid,address=0,data=0):
    ctypes.set_errno(0)
    result=LIBC.ptrace(request,pid,ctypes.c_void_p(address),ctypes.c_void_p(data))
    error=ctypes.get_errno()
    if result==-1 and error:raise OSError(error,os.strerror(error))
    return result


def registers(pid):
    value=Registers();ptrace(GETREGS,pid,0,ctypes.addressof(value));return value


def set_registers(pid,value):ptrace(SETREGS,pid,0,ctypes.addressof(value))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def signed(word):return word-(1<<64)if word&(1<<63)else word
def u64(raw,at):return struct.unpack_from('<Q',raw,at)[0]


class Trace:
    def __init__(self,binary,work,wire,target,output,mode,policy,*,injections=(),fd0=False):
        self.binary=Path(binary).resolve(strict=True);self.work=Path(work).resolve(strict=True)
        self.target=os.fsencode(target);self.output=Path(output);self.output.mkdir(exist_ok=False)
        self.mode=mode;self.policy=policy;self.injections={(x['operation'],x['index']):dict(x)for x in injections}
        assert len(self.injections)==len(injections)
        assert mode in ('rust','native') and not any(self.work.iterdir())
        self.fd0=fd0;self.fd0_done=False;self.wire=wire;self.started=time.monotonic()
        self.events=[];self.owned=set();self.live=set();self.holds={};self.pending={};self.unadmitted={}
        self.mem={};self.target_fds=set();self.retired_fds=set();self.completed=0;self.calls={'open':0,'write':0,'close':0}
        self.stdout=bytearray();self.stderr=bytearray();self.publication_started=False
        self.cancel_sent=False;self.parent_pending=False;self.polls=0;self.wakes=0
        self.child_count=0;self.root_pid=None;self.exit_codes={};self.streams={};self.setup=[]
        self.child_syscall_seen=set()
        self.requested_payloads=gzip.open(self.output/'write-payloads.bin.gz','xb')
        self.event_stream=(self.output/'events.jsonl').open('x')
        self.selector=selectors.DefaultSelector();self.input_offset=0
        with gzip.open(self.output/'stdin.bin.gz','xb')as stream:stream.write(wire)
        self.record('profile',mode=mode,binary=str(self.binary),binary_identity=pin(self.binary.read_bytes()),
                    target_hex=self.target.hex(),timeout_seconds=60,
                    injected_completions=list(self.injections.values()),fd0_setup=fd0,
                    command=[str(self.binary)],cwd=str(self.work),umask=0o022,
                    environment={'PATH':'','LC_ALL':'C'},initial_directory_entries=[])

    def record(self,kind,**values):
        event=dict(index=len(self.events),kind=kind,elapsed_seconds=time.monotonic()-self.started,**values)
        self.events.append(event);self.event_stream.write(json.dumps(event,sort_keys=True)+'\n');self.event_stream.flush()
        return event

    def read(self,pid,address,length):
        assert pid in self.owned
        if pid not in self.mem:self.mem[pid]=os.open(f'/proc/{pid}/mem',os.O_RDONLY)
        raw=os.pread(self.mem[pid],length,address)
        if len(raw)!=length:raise RuntimeError('owned stopped process memory is incomplete')
        return raw

    def resume(self,pid,deliver=0):
        assert pid in self.live and pid not in self.holds
        ptrace(SYSCALL,pid,0,deliver)

    def hold(self,pid,event,reason):
        assert pid not in self.holds
        self.holds[pid]=dict(event=event,reason=reason)
        self.record('hold',tid=pid,event_index=event['index'],reason=reason)

    def release(self,pid,reason):
        hold=self.holds.pop(pid)
        self.record('release',tid=pid,held_event=hold['event']['index'],held_reason=hold['reason'],reason=reason)
        self.resume(pid)

    def cancel(self,reason):
        assert not self.cancel_sent and self.root_pid in self.live
        self.cancel_sent=True;self.record('cancel_signal_sent',tid=self.root_pid,reason=reason)
        os.kill(self.root_pid,signal.SIGUSR1)

    def force_wake(self,reason):
        assert self.mode in ('rust','native') and self.root_pid in self.live
        self.record('forced_wake_signal',tid=self.root_pid,reason=reason)
        os.kill(self.root_pid,signal.SIGUSR2)

    def observe_marker(self,pid,raw):
        if raw[:8]==b'HLCARP01':
            assert u64(raw,8)==128 and raw[72:]==bytes(56)
            event=dict(owner='rust',event=u64(raw,16),serial=u64(raw,24),poll=u64(raw,32),
                       wake=u64(raw,40),reported_tid=u64(raw,48),details=[u64(raw,56),u64(raw,64)])
            assert event['reported_tid']==pid
            if event['event']==1:self.parent_pending=False;self.polls=event['poll']
            elif event['event']==2:self.parent_pending=True
            elif event['event']==3:self.parent_pending=False
            elif event['event']==4:self.wakes=event['wake']
        elif raw[:8]==b'HLCASR01':
            assert u64(raw,8)==128 and u64(raw,120)==0
            event=dict(owner='native',action=u64(raw,16),life=u64(raw,24),generation=u64(raw,32),
                       sequence=u64(raw,40),accepted=u64(raw,48),completed=u64(raw,56),
                       result_kind=u64(raw,64),error=u64(raw,72),ticket_start=u64(raw,80),
                       ticket_end=u64(raw,88),phase=u64(raw,96),token=u64(raw,104),flags=u64(raw,112))
            if pid==self.root_pid:
                if event['life']==2:self.parent_pending=False
                elif event['action']==3 and event['life']==3:
                    self.parent_pending=True;self.polls+=1
        else:return None
        return self.record('marker_entry',tid=pid,raw_hex=raw.hex(),**event)

    def entry(self,pid,nr,args):
        assert pid not in self.pending
        item=dict(nr=nr,args=list(args),operation=None)
        event=None
        startup=None
        if pid!=self.root_pid and pid not in self.child_syscall_seen:
            self.child_syscall_seen.add(pid)
            startup=self.record('child_first_syscall',tid=pid,nr=nr)
        if nr in (2,257):
            pointer=args[0]if nr==2 else args[1]
            try:path=self.read(pid,pointer,len(self.target)+1)
            except OSError:path=b''
            except RuntimeError:path=b''
            if path==self.target+b'\0':
                if self.fd0 and not self.fd0_done:
                    regs=registers(pid);assert self.read(pid,regs.rip-2,2)==b'\x0f\x05'
                    original=bytes(regs);regs.orig_rax=3;regs.rdi=0;set_registers(pid,regs)
                    item.update(operation='fd0_setup',saved_registers=original)
                    self.pending[pid]=item
                    self.record('fd0_setup_entry',tid=pid,original_syscall=nr)
                    return None
                item['operation']='open';self.calls['open']+=1;index=self.calls['open']
                flags=args[1]if nr==2 else args[2];mode=args[2]if nr==2 else args[3]
                event=self.record('syscall_entry',tid=pid,operation='open',call=index,nr=nr,
                                  path_hex=self.target.hex(),flags=flags,mode=mode)
        elif nr==1 and args[0]in self.target_fds:
            item['operation']='write';self.calls['write']+=1;index=self.calls['write']
            raw=self.read(pid,args[1],args[2]);self.requested_payloads.write(struct.pack('<Q',len(raw))+raw)
            item['requested_payload']=pin(raw)
            event=self.record('syscall_entry',tid=pid,operation='write',call=index,nr=nr,fd=args[0],
                              length=args[2],payload=pin(raw),completed_before=self.completed)
        elif nr==3 and args[0]in self.target_fds|self.retired_fds:
            item['operation']='close';self.calls['close']+=1;index=self.calls['close']
            event=self.record('syscall_entry',tid=pid,operation='close',call=index,nr=nr,fd=args[0])
        elif nr in (18,20,74,75)and args[0]in self.target_fds:
            raise AssertionError('unexpected target descriptor I/O syscall '+str(nr))
        elif nr==1 and args[0]==2 and args[2]==128:
            raw=self.read(pid,args[1],128);event=self.observe_marker(pid,raw)
        elif nr==1 and args[0]==1:
            raw=self.read(pid,args[1],args[2]);self.publication_started=True
            event=self.record('stdout_write_entry',tid=pid,length=len(raw),payload=pin(raw),raw_hex=raw.hex())
        elif nr in (15,56,57,58,61,435):
            event=self.record('mechanism_syscall_entry',tid=pid,nr=nr)
        item['event']=event
        if item['operation'] in self.calls:
            index=self.calls[item['operation']];item['call']=index
            injection=self.injections.get((item['operation'],index))
            if injection:
                regs=registers(pid);kind=injection['kind'];item['injection']=injection
                if kind=='partial':
                    assert item['operation']=='write' and 0<injection['value']<args[2]
                    regs.rdx=injection['value']
                elif kind in ('errno','zero'):
                    assert item['operation']in ('open','write')
                    regs.orig_rax=MASK
                elif kind=='close_errno':assert item['operation']=='close'
                else:raise AssertionError('undeclared injection kind')
                set_registers(pid,regs)
                self.record('injection_prepared',tid=pid,operation=item['operation'],call=index,injection=injection)
        self.pending[pid]=item
        return event if event is not None else startup

    def returned(self,pid,result):
        item=self.pending.pop(pid,None)
        if item is None:return None
        operation=item['operation'];args=item['args']
        if operation=='fd0_setup':
            assert result==0
            regs=Registers.from_buffer_copy(item['saved_registers']);regs.rip-=2;regs.rax=item['nr'];set_registers(pid,regs)
            self.fd0_done=True;self.record('fd0_setup_completed',tid=pid,kernel_return=result,
                                         replay_original_syscall=True);return None
        if operation not in self.calls:
            if item['nr']in (15,56,57,58,61,435):
                return self.record('mechanism_syscall_exit',tid=pid,nr=item['nr'],kernel_return=result)
            return None
        injection=item.get('injection');visible=result;target_executed=True
        if injection and injection['kind']in ('errno','zero','close_errno'):
            if injection['kind']!='close_errno':
                assert result==-errno.ENOSYS;target_executed=False
            visible=0 if injection['kind']=='zero' else -injection['value']
            regs=registers(pid);regs.rax=visible&MASK;set_registers(pid,regs)
        if operation=='open'and visible>=0:
            self.target_fds.add(visible)
            if self.fd0:assert visible==0
        elif operation=='write'and visible>0:self.completed+=visible
        elif operation=='close':self.target_fds.discard(args[0]);self.retired_fds.add(args[0])
        return self.record('syscall_exit',tid=pid,operation=operation,call=item['call'],nr=item['nr'],
                           kernel_return=result,completion=visible,target_syscall_executed=target_executed,
                           injection=injection,completed_bytes=self.completed)

    def pipe_events(self,timeout=0):
        for key,mask in self.selector.select(timeout):
            fd=key.fd;name=key.data
            if name=='stdin':
                try:written=os.write(fd,self.wire[self.input_offset:])
                except BlockingIOError:continue
                except BrokenPipeError:
                    self.record('input_pipe_closed_early',written_bytes=self.input_offset)
                    self.selector.unregister(fd);os.close(fd);continue
                self.input_offset+=written
                if self.input_offset==len(self.wire):self.selector.unregister(fd);os.close(fd)
            else:
                try:raw=os.read(fd,1<<20)
                except BlockingIOError:continue
                if raw:
                    offset=len(getattr(self,name));getattr(self,name).extend(raw)
                    if name=='stdout':
                        self.record('stdout_read',offset=offset,bytes=len(raw),payload=pin(raw),raw_hex=raw.hex())
                else:self.selector.unregister(fd);os.close(fd)

    def spawn(self):
        source_r,source_w=os.pipe();output_r,output_w=os.pipe();error_r,error_w=os.pipe()
        pid=os.fork()
        if pid==0:
            try:
                os.setpgid(0,0);os.chdir(self.work);os.umask(0o022)
                os.dup2(source_r,0);os.dup2(output_w,1);os.dup2(error_w,2)
                for fd in (source_r,source_w,output_r,output_w,error_r,error_w):
                    if fd>2:os.close(fd)
                ptrace(TRACEME,0);os.kill(os.getpid(),signal.SIGSTOP)
                os.execve(self.binary,[str(self.binary)],{'PATH':'','LC_ALL':'C'})
            except BaseException:os._exit(126)
        self.root_pid=pid;self.owned.add(pid);self.live.add(pid)
        for fd in (source_r,output_w,error_w):os.close(fd)
        for fd,name,mask in ((source_w,'stdin',selectors.EVENT_WRITE),(output_r,'stdout',selectors.EVENT_READ),
                             (error_r,'stderr',selectors.EVENT_READ)):
            os.set_blocking(fd,False);self.selector.register(fd,mask,name)
        found,status=os.waitpid(pid,0);assert found==pid and os.WIFSTOPPED(status)and os.WSTOPSIG(status)==signal.SIGSTOP
        ptrace(SETOPTIONS,pid,0,OPTIONS);self.record('owned_root',pid=pid);self.resume(pid)

    def stopped(self,pid,status):
        if pid not in self.owned:
            assert pid not in self.unadmitted;self.unadmitted[pid]=status;return
        if os.WIFEXITED(status)or os.WIFSIGNALED(status):
            self.live.discard(pid);self.pending.pop(pid,None)
            self.exit_codes[pid]=os.waitstatus_to_exitcode(status)
            self.record('process_reaped',tid=pid,exit_code=self.exit_codes[pid]);return
        assert os.WIFSTOPPED(status)
        sig=os.WSTOPSIG(status);event=status>>16;observed=None
        if event in (1,2,3):
            child=ctypes.c_ulonglong();ptrace(GETEVENTMSG,pid,0,ctypes.addressof(child));child=child.value
            assert child not in self.owned
            self.owned.add(child);self.live.add(child);self.child_count+=1
            self.record('owned_descendant',parent=pid,pid=child,ptrace_event=event,ordinal=self.child_count)
            if child in self.unadmitted:self.stopped(child,self.unadmitted.pop(child))
        elif event in (4,6):self.record('process_event',tid=pid,ptrace_event=event)
        elif sig==(signal.SIGTRAP|0x80):
            raw=ctypes.create_string_buffer(128);size=ptrace(GET_SYSCALL_INFO,pid,128,ctypes.addressof(raw));data=raw.raw
            assert size>=33 and struct.unpack_from('<I',data,4)[0]==0xc000003e
            if data[0]==1:
                nr,*args=struct.unpack_from('<7Q',data,24);observed=self.entry(pid,nr,args)
            elif data[0]==2:observed=self.returned(pid,struct.unpack_from('<q',data,24)[0])
            else:raise AssertionError('unknown syscall stop type')
        elif sig!=signal.SIGSTOP:
            self.record('signal_delivery',tid=pid,signal=sig);self.resume(pid,sig);return
        if observed is not None:
            reason=self.policy.observe(self,observed)
            if reason:self.hold(pid,observed,reason);return
        self.resume(pid)

    def run(self):
        status='FAIL';failure=None;timed_out=False
        try:
            self.spawn()
            while self.live:
                if time.monotonic()-self.started>60:
                    timed_out=True;raise TimeoutError('unchanged 60-second owned process deadline')
                self.pipe_events(0)
                progress=False
                while True:
                    try:pid,value=os.waitpid(-1,os.WNOHANG|WALL)
                    except ChildProcessError:pid=0
                    if pid==0:break
                    progress=True;self.stopped(pid,value);self.policy.advance(self)
                self.policy.advance(self)
                if not progress:self.pipe_events(0.001)
            while self.selector.get_map():self.pipe_events(0.001)
            assert not self.unadmitted and self.input_offset==len(self.wire)
            assert self.exit_codes[self.root_pid]==0 and all(code==0 for code in self.exit_codes.values())
            assert not self.target_fds
            assert self.fd0_done==self.fd0
            assert {(row['operation'],row['call'])for row in self.events if row['kind']=='injection_prepared'}==set(self.injections)
            self.policy.finish(self);status='PASS'
        except BaseException as error:
            failure=dict(type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
            if self.root_pid is not None:
                try:os.killpg(self.root_pid,signal.SIGKILL)
                except ProcessLookupError:pass
            for pid in tuple(self.live):
                try:ptrace(SYSCALL,pid,0,signal.SIGKILL)
                except OSError:pass
            until=time.monotonic()+5
            while self.live and time.monotonic()<until:
                try:pid,value=os.waitpid(-1,os.WNOHANG|WALL)
                except ChildProcessError:break
                if pid and pid in self.owned:
                    if os.WIFEXITED(value)or os.WIFSIGNALED(value):self.live.discard(pid);self.exit_codes[pid]=os.waitstatus_to_exitcode(value)
                    else:
                        try:ptrace(SYSCALL,pid,0,signal.SIGKILL)
                        except OSError:pass
                self.pipe_events(0.001)
        finally:
            self.pipe_events(0)
            self.requested_payloads.close();self.event_stream.close()
            for key in tuple(self.selector.get_map().values()):
                try:os.close(key.fd)
                except OSError:pass
            self.selector.close()
            for fd in self.mem.values():os.close(fd)
            (self.output/'stdout.bin').write_bytes(self.stdout);(self.output/'stderr.bin').write_bytes(self.stderr)
            path=Path(os.fsdecode(self.target))
            body=path.read_bytes()if b'\0'not in self.target and path.is_file()else None
            if body is not None:
                with gzip.open(self.output/'file.bin.gz','xb')as stream:stream.write(body)
            entries=[]
            for entry in sorted(self.work.iterdir()):
                metadata=entry.lstat();kind='file'if stat.S_ISREG(metadata.st_mode)else 'other'
                entries.append(dict(name=entry.name,kind=kind,mode=stat.S_IMODE(metadata.st_mode),
                                    content=pin(entry.read_bytes())if kind=='file'else None))
            result=dict(schema='hepta.runtime.owned-create-trace.v2',status=status,error=failure,
                mode=self.mode,root_pid=self.root_pid,owned_pids=sorted(self.owned),exit_codes=self.exit_codes,
                timed_out=timed_out,timeout_seconds=60,elapsed_seconds=time.monotonic()-self.started,
                cancellation_sent=self.cancel_sent,syscall_counts=self.calls,completed_kernel_bytes=self.completed,
                file=None if body is None else pin(body),unreaped_owned_pids=sorted(self.live),
                stdout=pin(self.stdout),stderr=pin(self.stderr),stdin=pin(self.wire),
                input_delivered_bytes=self.input_offset,filesystem=dict(initial_entries=[],final_entries=entries),
                events=len(self.events),policy=self.policy.result(),
                raw_syscall_results_preserved=True,all_injections_explicit=True,
                public_handler_qualified=False,whole_runtime_replaced=False)
            (self.output/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
        if status!='PASS':raise RuntimeError(str(failure))
        return result
