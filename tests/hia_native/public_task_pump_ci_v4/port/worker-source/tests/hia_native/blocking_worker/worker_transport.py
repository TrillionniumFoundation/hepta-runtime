"""Owned process transport for the fixed private Bellman worker ELF."""
from __future__ import annotations
import ctypes,hashlib,json,os,queue,signal,struct,subprocess,threading,time
from pathlib import Path

def sha(b):return hashlib.sha256(b).hexdigest()
def frame(command,tag,job=0,hold=0,payload=b''):
    body=b'HBWKRQ01'+struct.pack('<7Q',command,tag,job,hold,len(payload),0,0)+payload
    return struct.pack('<Q',len(body))+body

class WorkerProcess:
    def __init__(self,executable,path,*,expected_sha,timeout=60):
        path.mkdir(mode=0o700)
        self.path=path;self.timeout=timeout;self.started=time.monotonic();self.deadline=self.started+timeout
        assert sha(executable.read_bytes())==expected_sha
        self.stdin=(path/'stdin.bin').open('xb');self.stdout=(path/'stdout.bin').open('xb');self.stderr=(path/'stderr.bin').open('xb')
        self.rows=[];self.events=queue.Queue();self.reader_error=None;self.process=None;self.thread=None
        self.receipt={'argv':[str(executable)],'cwd':str(path),'executable_sha256':expected_sha,'parent_pid':os.getpid(),
                      'timeout_seconds':timeout,'started':False,'timed_out':False,'parent_death_signal':signal.SIGKILL}
        try:
            # This supervisor may itself reach its original 60-second limit.
            # Its separately owned ELF process must then die as well; the ELF
            # already binds each actual worker to its own parent's lifetime.
            parent=os.getpid();libc=ctypes.CDLL(None,use_errno=True)
            libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
            libc.prctl.restype=ctypes.c_int
            def bind_parent():
                if libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:os._exit(125)
            self.process=subprocess.Popen([str(executable)],cwd=path,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,start_new_session=True,preexec_fn=bind_parent)
            self.receipt.update(started=True,pid=self.process.pid,pgid=self.process.pid)
            self.thread=threading.Thread(target=self._read,name='owned-native-stdout')
            self.thread.start()
        except BaseException:
            self.close();raise
    def _read_bytes(self,count):
        out=bytearray()
        while len(out)<count:
            value=self.process.stdout.read(count-len(out))
            if not value:break
            self.stdout.write(value);self.stdout.flush();out.extend(value)
        return bytes(out)
    def _read(self):
        try:
            while True:
                header=self._read_bytes(8)
                if not header:break
                assert len(header)==8,'partial output header'
                size=struct.unpack('<Q',header)[0];assert 192<=size<=128<<20,('output extent',size)
                body=self._read_bytes(size);assert len(body)==size,'partial output frame'
                words=struct.unpack_from('<8Q',body)
                assert body[:8]==b'HBPMSR01' and words[1]==len(body) and words[7]==0 and len(body)==192+words[6]
                event={'kind':words[2],'tag':words[3],'job':words[4],'code':words[5],'pool':body[64:192],'body':body[192:],
                       'raw':header+body}
                self.rows.append({k:v for k,v in event.items() if k not in {'pool','body','raw'}})
                self.events.put(event)
        except BaseException as exc:
            self.reader_error=exc;self.events.put(exc)
        finally:self.events.put(None)
    def send(self,*args,**kwargs):
        wire=frame(*args,**kwargs);self.stdin.write(wire);self.stdin.flush()
        self.process.stdin.write(wire);self.process.stdin.flush()
    def next(self):
        timeout=self.deadline-time.monotonic()
        if timeout<=0:self.receipt['timed_out']=True;raise TimeoutError('owned process deadline')
        try:event=self.events.get(timeout=timeout)
        except queue.Empty:self.receipt['timed_out']=True;raise TimeoutError('owned output deadline')
        if isinstance(event,BaseException):raise event
        if event is None:raise AssertionError(('native output ended',self.process.poll()))
        return event
    def close(self):
        failure=None
        try:
            if self.process is not None:
                if self.process.stdin is not None and not self.process.stdin.closed:
                    try:self.process.stdin.close()
                    except BrokenPipeError:pass
                try:self.process.wait(timeout=max(.001,self.deadline-time.monotonic()))
                except subprocess.TimeoutExpired:
                    self.receipt['timed_out']=True
                    raise
        except BaseException as exc:failure=exc
        finally:
            try:
                if self.process is not None:
                    try:os.killpg(self.process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    self.receipt['returncode']=self.process.wait()
            finally:
                if self.thread is not None:
                    while self.thread.is_alive():
                        try:self.thread.join(.1)
                        except BaseException as exc:
                            if failure is None:failure=exc
                for handle in [self.stdin,self.stdout,self.stderr]:handle.close()
                self.receipt['elapsed_seconds']=time.monotonic()-self.started
                self.receipt['outputs']=self.rows
                for name in ['stdin','stdout','stderr']:
                    raw=(self.path/(name+'.bin')).read_bytes();self.receipt[name]={'bytes':len(raw),'sha256':sha(raw)}
                if failure is not None:self.receipt['failure']={'type':type(failure).__name__,'message':str(failure)}
                if self.reader_error is not None:self.receipt['reader_failure']=repr(self.reader_error)
                (self.path/'process.json').write_text(json.dumps(self.receipt,indent=2,sort_keys=True)+'\n')
        if failure is not None:raise failure
        if self.reader_error is not None:raise self.reader_error
        assert self.receipt['returncode']==0 and not self.receipt['timed_out'],self.receipt

def decode_journal(raw):
    rows=[];at=0
    while at<len(raw):
        assert len(raw)-at>=16,('partial journal',at)
        magic=raw[at:at+8];size=struct.unpack_from('<Q',raw,at+8)[0]
        assert magic in {b'HBWPL001',b'HBCLOCK1',b'HBPWHLD1',b'HBWPEND1',b'HBWPROC1'},(at,magic)
        assert size>=16 and at+size<=len(raw),(at,size)
        if magic==b'HBWPL001':assert size==256
        if magic==b'HBCLOCK1':assert size==192
        if magic==b'HBPWHLD1':assert size==64
        if magic==b'HBWPROC1':assert size==64
        rows.append((magic,raw[at:at+size]));at+=size
    return rows
