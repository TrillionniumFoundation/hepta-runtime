"""All-lines public observer plus a fixed private setup/observation socket."""
from pathlib import Path
import gzip,hashlib,json,os,selectors,socket,subprocess,sys,time,traceback
from capture_common import Stream,need,sha,dump,file_pin
from all_lines import AllLines
import wait_observations
HERE=Path(__file__).resolve().parent
class EvidenceStream(Stream):
    def __init__(self,path):
        self.path=Path(path);self.file=self.path.open("xb")
        self.zipped=gzip.GzipFile(filename="",fileobj=self.file,mode="wb",compresslevel=1,mtime=0)
        self.digest=hashlib.sha256();self.size=0;self.closed=False
class Process(AllLines):
    def __init__(self,output,binary,cwd,config,side):
        self.output=Path(output).absolute();self.output.mkdir(mode=0o700,parents=True,exist_ok=False)
        self.binary=Path(binary).absolute();self.cwd=str(Path(cwd).absolute());self.started=time.monotonic()
        self.argv=[str(self.binary)]+(["--stdio-wait-fixture",str(config)] if side=="original" else ["--runtime-config",str(config)])
        self.trace=None;self.environment={"PATH":"","LC_ALL":"C"}
        self.streams={n:Stream(self.output/(n+".bin.gz")) for n in ("attempted-stdin","stdin","stdout","stderr")}
        self.pending=bytearray();self.scan_from=0;self.exchanges=[];self.eof={"stdout":False,"stderr":False}
        self.started_error=None;self.closed=False;self.process=None
        self.exchange_journal=self.output/"exchanges.jsonl";self.exchange_journal.touch(exist_ok=False)
        self.journal_records=0;self.journal_error=None;self.lines=[];self.line_end=0;self.input_closed=False
        self.side=side;self.sequence=0;self.control_closed=False
        self.controls=self.output/"controls";self.controls.mkdir()
        self.journal=(self.output/"worker-journal.raw").open("xb")
        self.host_trace=(self.output/"host-trace.raw").open("xb")
        self.control,parent_end=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        self.control.setblocking(False);parent_end.setblocking(True)
        self.command=[sys.executable,"-I","-S","-B",str(HERE/"fd_exec.py"),str(self.journal.fileno()),str(self.host_trace.fileno()),str(parent_end.fileno()),*self.argv]
        try:
            self.process=subprocess.Popen(self.command,cwd=self.cwd,env=self.environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(self.journal.fileno(),self.host_trace.fileno(),parent_end.fileno()),start_new_session=True)
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr):os.set_blocking(stream.fileno(),False)
        except BaseException as error:
            self.started_error=repr(error);self._save_failure();raise
        finally:parent_end.close()
        dump(self.output/"started.json",{"command":self.command,"native_argv":self.argv,"cwd":self.cwd,"environment":self.environment,"pid":self.process.pid,"binary":file_pin(self.binary),"fixed_capabilities":[3,4,5],"descriptor_source":"fd_exec.py","side":side})
    def command_control(self,operation,slot=0,payload=b"",label="control",absolute_deadline=None):
        import struct
        need(not self.closed and not self.control_closed,"live test control socket")
        self.sequence+=1;seq=self.sequence
        request=b"HXLTQ001"+struct.pack("<7Q",seq,operation,slot,len(payload),0,0,0)+payload
        prefix=self.controls/("%04d"%seq);prefix.with_suffix(".input.bin").write_bytes(request)
        stream=EvidenceStream(prefix.with_suffix(".output.bin.gz"));body=bytearray();written=0;extent=None;failure=None;result=None
        start=time.monotonic();first_line=len(self.lines);stdout_start=self.streams["stdout"].size;stderr_start=self.streams["stderr"].size
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(self.control,selectors.EVENT_READ|selectors.EVENT_WRITE,"control")
                for name in ("stdout","stderr"):
                    if not self.eof[name]:ready.register(getattr(self.process,name),selectors.EVENT_READ,name)
                while extent is None or len(body)<extent:
                    remaining=60-(time.monotonic()-start)
                    if absolute_deadline is not None:remaining=min(remaining,absolute_deadline-time.monotonic())
                    if remaining<=0:raise TimeoutError("actual control exchange exceeds unchanged60s")
                    events=ready.select(remaining)
                    if not events:raise TimeoutError("actual control exchange exceeds unchanged60s")
                    for key,mask in events:
                        if key.data!="control":self._read(ready,key,[]);continue
                        if mask&selectors.EVENT_WRITE and written<len(request):
                            try:n=self.control.send(memoryview(request)[written:])
                            except BlockingIOError:continue
                            need(n>0,"complete fixed command write progress");written+=n
                            if written==len(request):ready.modify(self.control,selectors.EVENT_READ,"control")
                        if mask&selectors.EVENT_READ:
                            amount=64-len(body) if len(body)<64 else min(1<<20,extent-len(body))
                            try:raw=self.control.recv(amount)
                            except BlockingIOError:continue
                            if not raw:raise EOFError("actual fixed control ended before complete reply")
                            stream.write(raw);body.extend(raw)
                            if len(body)==64:
                                need(body[:8]==b"HXLTR001","actual fixed control reply magic")
                                words=struct.unpack_from("<7Q",body,8)
                                need(words[:4]==(seq,operation,slot,0) and words[5]>=32 and words[4]<=1<<20 and words[5]<=32*(256<<20)+2048,"fixed reply identity and physical extents")
                                extent=64+words[4]+words[5]
            need(written==len(request) and len(body)==extent,"entire actual command/reply")
            result=wait_observations.frame(body,self.side)
            return result
        except BaseException as error:
            failure={"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()};raise
        finally:
            stored=stream.close()
            record={"sequence":seq,"operation":operation,"slot":slot,"label":label,"input":file_pin(prefix.with_suffix(".input.bin")),"output":stored,"deadline_seconds":60,"elapsed_seconds":time.monotonic()-start,"accepted_input_bytes":written,"actual_response_extent":extent,"complete":failure is None,"failure":failure,"decoded":result,"stdout_range":{"offset":stdout_start,"bytes":self.streams["stdout"].size-stdout_start},"stderr_range":{"offset":stderr_start,"bytes":self.streams["stderr"].size-stderr_start},"line_range":{"first":first_line,"count":len(self.lines)-first_line}}
            dump(prefix.with_suffix(".json"),record)
    def wait_lock(self,key,strong,label):
        start=time.monotonic();observations=[]
        while True:
            need(time.monotonic()-start<60,"actual readiness exceeds unchanged60s")
            state=self.command_control(3,label=label,absolute_deadline=start+60)
            observations.append(state["sequence"])
            need(time.monotonic()-start<60,"complete actual readiness exceeds unchanged60s")
            if state["state"]["locks"]["entries"].get(key)==strong:return {"observation_sequences":observations,"satisfied_by_actual_state":True,"state":state,"elapsed_seconds":time.monotonic()-start,"deadline_seconds":60}
    def close_control(self):
        need(not self.control_closed,"control already closed");self.control.close();self.control_closed=True
    def finish(self,*,failed=False):
        result=super().close(failed=failed)
        if not self.control_closed:self.close_control()
        self.journal.close();self.host_trace.close()
        records={}
        for name in ("worker-journal","host-trace"):
            raw=self.output/(name+".raw");out=EvidenceStream(self.output/(name+".bin.gz"))
            with raw.open("rb") as stream:
                while block:=stream.read(1<<20):out.write(block)
            stored=out.close()
            # Full byte-for-byte retained compressed copy before retiring raw.
            with raw.open("rb") as a,gzip.open(out.path,"rb") as b:
                while True:
                    x=a.read(1<<20);y=b.read(1<<20);need(x==y,"complete compressed trace retirement equality")
                    if not x:break
            need(file_pin(raw)==stored["uncompressed"],"complete trace identity")
            records[name]={**stored,"raw_retired_after_all_bytes_compared":True};raw.unlink()
        result["fixed_capabilities"]=records;result["fixed_control_commands"]=self.sequence
        dump(self.output/"complete-process.json",result)
        return result
