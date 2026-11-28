#!/usr/bin/env python3
"""Qualification only: supervise syscalls of one freshly owned atomic writer.

Ordinary effects execute in the kernel. Error/zero completions are explicitly
tagged fault injections. RLIMIT_FSIZE exercises a real partial regular-file
write. Cancellation holds the selected actual syscall until the caller has
reported cancellation, then permits that already-started stage to finish.
No arbitrary process IDs or external files can be selected.
"""
from __future__ import annotations
import argparse,array,ctypes,errno,hashlib,json,os,resource,select,signal,socket,struct,sys,time
from pathlib import Path

class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
class Data(ctypes.Structure):
    _fields_=[('nr',ctypes.c_int),('arch',ctypes.c_uint),('ip',ctypes.c_uint64),('args',ctypes.c_uint64*6)]
class Notification(ctypes.Structure):
    _fields_=[('id',ctypes.c_uint64),('pid',ctypes.c_uint),('flags',ctypes.c_uint),('data',Data)]
class Response(ctypes.Structure):
    _fields_=[('id',ctypes.c_uint64),('value',ctypes.c_int64),('error',ctypes.c_int),('flags',ctypes.c_uint)]
class IoVec(ctypes.Structure):
    _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
MEMORY_READERS=set()

def sha(raw):return hashlib.sha256(raw).hexdigest()
def cstring(libc,pid,address):
    if address==0:return None
    value=bytearray()
    for _ in range(32769):
        count=min(256,4096-((address+len(value))&4095))
        target=ctypes.create_string_buffer(count)
        local,remote=IoVec(ctypes.addressof(target),count),IoVec(address+len(value),count)
        got=libc.process_vm_readv(pid,ctypes.byref(local),1,ctypes.byref(remote),1,0)
        if got<=0:
            original=ctypes.get_errno()
            try:
                fd=os.open(f'/proc/{pid}/mem',os.O_RDONLY|os.O_CLOEXEC)
                try:block=os.pread(fd,count,address+len(value))
                finally:os.close(fd)
                MEMORY_READERS.add('owned-proc-mem-pread')
            except OSError as e:
                raise OSError(original,'reading owned notification path') from e
            if not block:raise OSError(errno.EIO,'empty owned notification memory read')
        else:
            block=target.raw[:got];MEMORY_READERS.add('owned-process-vm-readv')
        end=block.find(b'\0')
        if end>=0:return bytes(value)+block[:end]
        value.extend(block)
    raise ValueError('owned path exceeds the qualification transport')

def supervise(executable,fixture,config,log,timeout):
    executable=Path(executable).resolve(strict=True);fixture=Path(fixture).resolve(strict=True)
    assert fixture.is_dir() and executable.is_file()
    libc=ctypes.CDLL(None,use_errno=True)
    libc.process_vm_readv.argtypes=[ctypes.c_int,ctypes.POINTER(IoVec),ctypes.c_ulong,ctypes.POINTER(IoVec),ctypes.c_ulong,ctypes.c_ulong]
    libc.process_vm_readv.restype=ctypes.c_ssize_t
    assert ctypes.sizeof(Notification)==80 and ctypes.sizeof(Response)==24
    if config.get('kill_parent') and libc.prctl(36,1,0,0,0):
        raise OSError(ctypes.get_errno(),'PR_SET_CHILD_SUBREAPER')
    parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    output_read,output_write=os.pipe();error_read,error_write=os.pipe()
    started=time.monotonic();pid=os.fork()
    if pid==0:
        parent.close();os.close(output_read);os.close(error_read)
        try:
            os.dup2(output_write,1);os.dup2(error_write,2)
            os.close(output_write);os.close(error_write)
            os.chdir(fixture)
            os.umask(config.get('umask',0o022))
            if config.get('blocked_cancel'):
                signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1})
            if 'file_size_limit' in config:
                value=config['file_size_limit'];assert type(value)is int and value>=0
                resource.setrlimit(resource.RLIMIT_FSIZE,(value,value));signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
            if libc.prctl(38,1,0,0,0):raise OSError(ctypes.get_errno(),'PR_SET_NO_NEW_PRIVS')
            code=[Filter(0x20,0,0,0)]
            for number in (1,3,82,87,90,257,262,332):
                code.extend((Filter(0x15,0,1,number),Filter(0x06,0,0,0x7fc00000)))
            code.append(Filter(0x06,0,0,0x7fff0000))
            instructions=(Filter*len(code))(*code);program=Program(len(code),instructions)
            listener=libc.syscall(317,1,8,ctypes.byref(program))
            if listener<0:raise OSError(ctypes.get_errno(),'seccomp notification unavailable')
            os.set_inheritable(listener,False)
            child.sendmsg([b'L'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[listener]))])
            os.execve(executable,[str(executable)],dict(os.environ))
        except BaseException as e:
            os.write(2,(str(e)+'\n').encode());os._exit(75)
    child.close();os.close(output_write);os.close(error_write)
    if not select.select([parent],[],[],5)[0]:
        os.kill(pid,9);os.waitpid(pid,0)
        raise RuntimeError('owned child did not install its notification filter')
    _,ancillary,_,_=parent.recvmsg(1,socket.CMSG_SPACE(4));parent.close()
    fds=array.array('i');fds.frombytes(ancillary[0][2][:4]);listener=fds[0]
    os.set_blocking(output_read,False);os.set_blocking(error_read,False)
    outputs=bytearray();errors=bytearray();events=[];counts={};status=None;failure=None;held=None;cancel_ack=None;death_worker=None;death_receipt=None
    relevant=[os.fsencode(fixture)]
    def owned(raw):
        if raw is None:return False
        if raw[:1]!=b'/':return True
        return any(raw==p or raw.startswith(p+b'/') for p in relevant)
    def send(note,response):
        if libc.ioctl(listener,0xc0182101,ctypes.byref(response)):
            raise OSError(ctypes.get_errno(),'replying to owned seccomp notification')
    def drain(fd,target):
        try:b=os.read(fd,65536)
        except BlockingIOError:return False
        if b:target.extend(b);return True
        return False
    try:
        while True:
            if time.monotonic()-started>timeout:raise TimeoutError('owned atomic writer exceeded qualification deadline')
            ended,wait=os.waitpid(pid,os.WNOHANG)
            if ended:
                status=wait
                while drain(output_read,outputs):pass
                while drain(error_read,errors):pass
                break
            ready,_,_=select.select([listener,output_read,error_read],[],[],0.02)
            if output_read in ready:drain(output_read,outputs)
            if error_read in ready:drain(error_read,errors)
            if held is not None and len(outputs)>=4:
                if outputs[:4]!=struct.pack('<I',0xfffffff7):raise AssertionError('cancellation did not publish the typed cancellation result')
                assert os.waitpid(pid,os.WNOHANG)[0]==0
                cancel_ack={'stdout_prefix_hex':outputs[:4].hex(),'worker_syscall_still_held':True,'elapsed':time.monotonic()-started}
                note,response,event=held
                event['cancel_acknowledged_before_kernel_release']=True
                send(note,response);held=None
            if listener not in ready:continue
            note=Notification()
            if libc.ioctl(listener,0xc0502100,ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR,errno.ENOENT):continue
                raise OSError(ctypes.get_errno(),'receiving owned seccomp notification')
            response=Response(note.id,0,0,1)
            nr=note.data.nr;a=list(note.data.args);kind=None;extra={}
            if nr in (257,262,332):
                path=cstring(libc,note.pid,a[1])
                if nr==332 and path is None and a[0]==0 and a[2]==0 and a[3]==0xfff and a[4]==0:
                    kind='statx_probe'
                elif nr==262 and path is None and a[0]==0 and a[3]==0:
                    kind='stat_probe_fallback'
                elif owned(path):
                    kind={257:'open',262:'stat',332:'statx'}[nr]
                    extra={'path_hex':path.hex(),'dirfd':ctypes.c_int(a[0]).value}
                    if nr==257:extra.update(flags=a[2],mode=a[3])
                    elif nr==332:extra.update(flags=a[2],mask=a[3])
                    else:extra.update(flags=a[3])
            elif nr in (82,87,90):
                path=cstring(libc,note.pid,a[0])
                if owned(path):
                    kind={82:'rename',87:'unlink',90:'chmod'}[nr];extra={'path_hex':path.hex()}
                    if nr==90:extra['mode']=a[1]
                    if nr==82:extra['destination_hex']=cstring(libc,note.pid,a[1]).hex()
            elif nr in (1,3) and a[0]>2:
                try:link=os.fsencode(os.readlink(f'/proc/{note.pid}/fd/{a[0]}'))
                except FileNotFoundError:link=None
                if link is not None and owned(link):
                    kind='write' if nr==1 else 'close';extra={'fd':a[0],'fd_path_hex':link.hex()}
                    if nr==1:extra['count']=a[2]
            if kind is not None:
                ordinal=counts.get(kind,0)+1;counts[kind]=ordinal
                event={'ordinal':ordinal,'kind':kind,'pid':note.pid,'syscall':nr,'ip':note.data.ip,'completion':'kernel_continue',**extra}
                for fault in config.get('faults',[]):
                    if fault['kind']==kind and fault.get('ordinal',1)==ordinal:
                        assert response.flags==1,'more than one fault for the same event'
                        if 'errno' in fault:
                            response.error=-fault['errno'];response.flags=0
                            event.update(completion='injected_errno_without_kernel_effect',errno=fault['errno'])
                        elif fault.get('return')==0:
                            response.flags=0;event.update(completion='injected_zero_without_kernel_effect',returned=0)
                        else:raise ValueError('undefined qualification fault')
                events.append(event)
                death=config.get('kill_parent')
                if death and death['kind']==kind and death.get('ordinal',1)==ordinal:
                    assert death_worker is None and note.pid!=pid and response.flags==1
                    death_worker=note.pid
                    os.kill(pid,signal.SIGKILL)
                    event['owned_parent_killed_before_kernel_release']=True
                    event['completion']='owned_parent_killed_before_kernel_release'
                    continue
                cancel=config.get('cancel')
                if cancel and cancel['kind']==kind and cancel.get('ordinal',1)==ordinal:
                    assert held is None and cancel_ack is None and response.flags==1
                    held=(note,response,event)
                    os.kill(pid,signal.SIGUSR1)
                    event['cancel_sent_to_invocation_owner']=True
                    continue
            send(note,response)
        assert held is None,'invocation ended with an unaccounted held effect'
        if config.get('cancel'):assert cancel_ack is not None
        if config.get('kill_parent'):
            assert death_worker is not None,'parent-death control was not reached'
            until=time.monotonic()+2
            while True:
                ended,child_status=os.waitpid(death_worker,os.WNOHANG)
                if ended:
                    assert os.waitstatus_to_exitcode(child_status)==-signal.SIGKILL
                    death_receipt={'worker_pid':death_worker,'exit_code':-signal.SIGKILL,'reaped':True,
                      'blocked_effect_completed':False,'parent_exit_code':os.waitstatus_to_exitcode(status)}
                    break
                if time.monotonic()>until:
                    os.kill(death_worker,signal.SIGKILL);os.waitpid(death_worker,0)
                    raise AssertionError('worker survived the owned parent-death boundary')
                time.sleep(0.005)
    except BaseException as e:
        failure=repr(e)
        raise
    finally:
        os.close(listener);os.close(output_read);os.close(error_read)
        if status is None:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            _,status=os.waitpid(pid,0)
        receipt={'schema':'hepta.runtime.atomic-write-kernel-trace.v1','executable_sha256':sha(executable.read_bytes()),'executable_bytes':executable.stat().st_size,
          'config':config,'events':events,'counts':counts,'cancel_ack':cancel_ack,'exit_code':os.waitstatus_to_exitcode(status),
          'parent_death':death_receipt,
          'stdout_bytes':len(outputs),'stdout_sha256':sha(outputs),'stderr_bytes':len(errors),'stderr_sha256':sha(errors),
          'memory_readers':sorted(MEMORY_READERS),'elapsed':time.monotonic()-started,'failure':failure,'status':'PASS' if failure is None and os.waitstatus_to_exitcode(status)==0 else 'FAIL'}
        Path(log).write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
        os.write(1,outputs);os.write(2,errors)
    return os.waitstatus_to_exitcode(status)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--executable',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True)
    p.add_argument('--config',type=Path,required=True);p.add_argument('--log',type=Path,required=True);p.add_argument('--timeout',type=float,default=15)
    a=p.parse_args();return supervise(a.executable,a.fixture,json.loads(a.config.read_bytes()),a.log,a.timeout)

if __name__=='__main__':raise SystemExit(main())
