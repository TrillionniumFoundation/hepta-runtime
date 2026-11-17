"""Mechanical all-lines stdio capture with no response-cardinality or exit-code oracle."""
from pathlib import Path
import json,os,selectors,signal,subprocess,time
from capture_common import RecordedPublicProcess,need,sha,dump,file_pin
class AllLines(RecordedPublicProcess):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.lines=[];self.line_end=0;self.input_closed=False
    def take_lines(self):
        values=super()._lines()
        for raw in values:
            row={'index':len(self.lines),'offset':self.line_end,'bytes':len(raw),'sha256':sha(raw)}
            self.lines.append(row);self.line_end+=len(raw)
        return values
    def _read(self,ready,key,responses):
        try:raw=os.read(key.fd,65536)
        except BlockingIOError:return
        if not raw:self.eof[key.data]=True;ready.unregister(key.fileobj);return
        self.streams[key.data].write(raw)
        if key.data=='stdout':self.pending.extend(raw);responses.extend(self.take_lines())
    @staticmethod
    def matches(raw,identifier):
        try:value=json.loads(raw)
        except (UnicodeDecodeError,ValueError):return False
        return type(value) is dict and 'id' in value and type(value['id']) is type(identifier) and value['id']==identifier
    def send(self,request,*,label,until=None,segments=None):
        need(not self.closed and not self.input_closed and type(request) is bytes,'actual stdio input bytes')
        begin=time.monotonic();starts={n:s.size for n,s in self.streams.items()};first_line=len(self.lines)
        self.streams['attempted-stdin'].write(request);written=0;replies=[];error=None;timed=False;transport=None;matched=False
        try:
            with selectors.DefaultSelector() as ready:
                if request:ready.register(self.process.stdin,selectors.EVENT_WRITE,'stdin')
                for name in ('stdout','stderr'):
                    if not self.eof[name]:ready.register(getattr(self.process,name),selectors.EVENT_READ,name)
                while True:
                    matched=until is not None and any(self.matches(raw,until) for raw in replies)
                    if self.eof['stdout']:transport='eof';break
                    if written==len(request) and (until is None or matched):transport='correlated' if matched else 'sent';break
                    if error is not None and until is None:transport='write-error';break
                    remaining=60-(time.monotonic()-begin)
                    if remaining<=0:timed=True;raise TimeoutError('actual all-lines exchange exceeded unchanged 60 seconds')
                    events=ready.select(remaining)
                    if not events:timed=True;raise TimeoutError('actual all-lines exchange exceeded unchanged 60 seconds')
                    events.sort(key=lambda item:item[0].data=='stdin')
                    for key,_ in events:
                        if key.data!='stdin':self._read(ready,key,replies);continue
                        try:count=os.write(key.fd,memoryview(request)[written:written+65536])
                        except BlockingIOError:continue
                        except BrokenPipeError as failure:
                            error={'type':type(failure).__name__,'errno':failure.errno,'message':str(failure)}
                            ready.unregister(self.process.stdin);continue
                        need(count>0,'actual all-lines stdin progress')
                        self.streams['stdin'].write(memoryview(request)[written:written+count]);written+=count
                        if written==len(request):ready.unregister(self.process.stdin)
        except BaseException as failure:
            error={'type':type(failure).__name__,'errno':getattr(failure,'errno',None),'message':str(failure)};transport='execution-failure';raise
        finally:
            record={'index':len(self.exchanges),'label':label,'deadline_seconds':60,'elapsed_seconds':time.monotonic()-begin,'timed_out':timed,'transport':transport,'error':error,
                'correlation_id':until,'matched_correlation':matched,'response_count_assumed':None,'segments':segments or [],
                'attempted_input':{'offset':starts['attempted-stdin'],'bytes':len(request),'sha256':sha(request)},
                'accepted_input':{'offset':starts['stdin'],'bytes':written,'sha256':sha(request[:written])},
                'stdout_range':{'offset':starts['stdout'],'bytes':self.streams['stdout'].size-starts['stdout']},
                'stderr_range':{'offset':starts['stderr'],'bytes':self.streams['stderr'].size-starts['stderr']},
                'line_range':{'first':first_line,'count':len(self.lines)-first_line},'stdout_eof':self.eof['stdout'],'stderr_eof':self.eof['stderr']}
            self._record_exchange(record)
        return record
    def close(self,*,failed=False):
        need(not self.closed,'double all-lines finalization');self.closed=True;begin=time.monotonic();timed=False;wait_timed=False;cleanup_error=None;killed=None;code=None;line_start=len(self.lines)
        def terminate():
            nonlocal killed
            if killed is None:killed=time.monotonic()
            try:os.killpg(self.process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        try:self.process.stdin.close()
        except (BrokenPipeError,OSError):pass
        self.input_closed=True
        if failed and self.process.poll() is None:terminate()
        try:
            with selectors.DefaultSelector() as ready:
                for name in ('stdout','stderr'):
                    if not self.eof[name]:ready.register(getattr(self.process,name),selectors.EVENT_READ,name)
                while ready.get_map():
                    remaining=60-(time.monotonic()-begin) if killed is None else 5-(time.monotonic()-killed)
                    if remaining<=0:
                        if killed is not None:break
                        timed=True;terminate();continue
                    events=ready.select(remaining)
                    if not events:
                        if killed is not None:break
                        timed=True;terminate();continue
                    for key,_ in events:self._read(ready,key,[])
            try:code=self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                wait_timed=True;terminate()
                try:code=self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:cleanup_error='owned stdio process not reaped after SIGKILL within five seconds'
        except BaseException as error:
            cleanup_error=repr(error);terminate()
            try:code=self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:wait_timed=True
        finally:
            self.process.stdout.close();self.process.stderr.close()
            streams={n:s.close() for n,s in self.streams.items()}
        journal=self._seal_exchanges();dump(self.output/'lines.json',self.lines)
        receipt={'schema':'hepta.runtime.complete-stdio-observer.v1','command':self.command,'native_argv':self.argv,'cwd':self.cwd,'environment':self.environment,'pid':self.process.pid,'exit_code':code,
            'timed_out':timed,'drain_deadline_seconds':60,'drain_elapsed_seconds':time.monotonic()-begin,'elapsed_seconds':time.monotonic()-self.started,
            'failure_cleanup_requested':failed,'start_error':None,'exchanges':len(self.exchanges),'streams':streams,'wait_deadline_seconds':5,'wait_timed_out':wait_timed,
            'cleanup_error':cleanup_error,'kill_cleanup_deadline_seconds':5,'kill_requested':killed is not None,'pipe_eof':dict(self.eof),'stdin_closed_by_driver':True,
            'trailing_stdout':{'offset':self.line_end,'bytes':len(self.pending),'sha256':sha(self.pending)},'complete_stdout_lines':len(self.lines),'lines':file_pin(self.output/'lines.json'),
            'drain_line_range':{'first':line_start,'count':len(self.lines)-line_start},'binary':file_pin(self.binary),'exchange_journal':journal,'response_count_assumed':None,'nonzero_exit_is_observed_data':True}
        dump(self.output/'process.json',receipt)
        need(not timed and not wait_timed and cleanup_error is None and all(self.eof.values()),'complete actual process termination and pipe EOF')
        return receipt
