"""Complete native capture. Fixture actions and observers only; no edit model."""
from pathlib import Path
import ctypes,gzip,hashlib,json,os,selectors,stat,struct,subprocess,time

def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()+b'\n'
def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]

class Blobs:
    def __init__(self,root):self.root=root;self.pins={};(root/'blobs').mkdir()
    def add(self,raw):
        digest=sha(raw);name='blobs/'+digest+'.bin.gz'
        if name not in self.pins:
            with gzip.GzipFile(filename=str(self.root/name),mode='wb',compresslevel=1,mtime=0) as stream:stream.write(raw)
            self.pins[name]={'bytes':len(raw),'sha256':digest}
        assert self.pins[name]['bytes']==len(raw)
        return {'artifact':name,**self.pins[name]}

class Session:
    def __init__(self,root,name,elf,mode):
        self.root=root/name;self.root.mkdir();self.started_ns=time.monotonic_ns();self.command=[str(elf),mode]
        self.cwd=os.getcwd();self.timed_out=False;self.start_error=None;self.cleanup_killed=False
        try:self.p=subprocess.Popen(self.command,cwd=self.cwd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        except BaseException as error:
            ended=time.monotonic_ns();self.start_error=repr(error)
            (self.root/'process.json').write_bytes(canonical({'command':self.command,'cwd':self.cwd,'pid':None,
                'started_monotonic_ns':self.started_ns,'finished_monotonic_ns':ended,'elapsed_seconds':(ended-self.started_ns)/1e9,
                'start_error':self.start_error,'timed_out':False,'exit_code':None,'terminal_state':'start_error',
                'request_timeout_seconds':60,'streams':{}}))
            raise
        for stream in (self.p.stdin,self.p.stdout,self.p.stderr):os.set_blocking(stream.fileno(),False)
        process_status=Path(f'/proc/{self.p.pid}/status').read_bytes()
        self.umask=int(next(line.split()[1] for line in process_status.splitlines() if line.startswith(b'Umask:')),8)
        (self.root/'proc-status-at-start.txt').write_bytes(process_status)
        self.process_status_pin={'bytes':len(process_status),'sha256':sha(process_status)}
        (self.root/'started.json').write_bytes(canonical({'command':self.command,'cwd':self.cwd,'pid':self.p.pid,
            'started_monotonic_ns':self.started_ns,'request_timeout_seconds':60,'umask':self.umask,
            'proc_status_at_start':self.process_status_pin}))
        self.streams={n:gzip.GzipFile(filename=str(self.root/(n+'.bin.gz')),mode='wb',compresslevel=1,mtime=0) for n in ['stdin','stdout','stderr']}
        self.sizes={n:0 for n in self.streams};self.hashes={n:hashlib.sha256() for n in self.streams}
        self.pending=bytearray();self.offset=0;self.deadline=time.monotonic()+60;self.events=[];self.closed=False
        self.event_stream=(self.root/'messages.jsonl').open('wb',buffering=0)
        self.selector=selectors.DefaultSelector();self.selector.register(self.p.stdout,selectors.EVENT_READ,'stdout');self.selector.register(self.p.stderr,selectors.EVENT_READ,'stderr')
    def keep(self,name,raw):
        self.streams[name].write(raw);self.streams[name].flush();self.sizes[name]+=len(raw);self.hashes[name].update(raw)
    def pump(self):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:
            self.timed_out=True;raise TimeoutError('actual native request exceeded unchanged 60-second deadline')
        ready=self.selector.select(remaining)
        if not ready:
            self.timed_out=True;raise TimeoutError('actual native request exceeded unchanged 60-second deadline')
        for key,mask in ready:
            if key.data=='stdin':continue
            try:raw=os.read(key.fileobj.fileno(),65536)
            except BlockingIOError:continue
            if not raw:self.selector.unregister(key.fileobj);continue
            self.keep(key.data,raw)
            if key.data=='stdout':self.pending.extend(raw)
    def send(self,raw,*,framed=True):
        started=time.monotonic_ns()
        wire=struct.pack('<Q',len(raw))+raw if framed else raw
        before=self.sizes['stdin'];at=0
        self.selector.register(self.p.stdin,selectors.EVENT_WRITE,'stdin')
        try:
            while at<len(wire):
                try:n=os.write(self.p.stdin.fileno(),memoryview(wire)[at:at+65536])
                except BlockingIOError:self.pump();continue
                assert n>0;self.keep('stdin',memoryview(wire)[at:at+n]);at+=n
        finally:self.selector.unregister(self.p.stdin)
        return {'offset':before,'bytes':len(wire),'sha256':sha(wire),
                'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns()}
    def read(self,n):
        while len(self.pending)<n:
            if self.p.poll() is not None and not self.selector.get_map():raise EOFError('native fixture exited before complete response')
            self.pump()
        raw=bytes(self.pending[:n]);del self.pending[:n];self.offset+=n;return raw
    def message(self):
        at=self.offset;kind,n=struct.unpack('<2Q',self.read(16));body=self.read(n)
        record={'kind':kind,'offset':at,'bytes':16+n,'payload_bytes':n,'payload_sha256':sha(body),
                'observed_monotonic_ns':time.monotonic_ns()}
        self.events.append(record);self.event_stream.write(canonical(record));return kind,body,record
    def select(self,index):
        self.send(b'HBCSEL02'+struct.pack('<Q',index));kind,body,record=self.message()
        assert kind==6 and body==b'HBCSLR02'+struct.pack('<Q',index),(kind,body)
        return record
    def owner(self,slot,wire):
        request=self.send(b'HBCFXQ02'+struct.pack('<3Q',slot,len(wire),0)+wire)
        kind,body,event=self.message();assert kind==4 and len(body)>=32
        magic,target,ret,n=struct.unpack_from('<8s3Q',body);assert magic==b'HBCFXR02' and target==slot and n==len(body)-32
        return ret,body[32:],{'request':request,'response':event}
    def key(self,path):
        ret,body,event=self.owner(5,b'HRLKKEY1'+struct.pack('<7Q',1,len(path),0,0,0,0,0)+path)
        assert ret==len(body) and body[:8]==b'HRLKY001' and word(body,16)==len(body)-32
        return body[32:],event
    def cache(self,op,key=b'',value=b''):
        ret,body,event=self.owner(8,b'HVCACH01'+struct.pack('<5Q',op,0,len(key),len(value),0)+key+value)
        assert ret==len(body) and body[:8]==b'HVCAR001';return body,event
    def history(self,op):
        ret,body,event=self.owner(17,b'HHISTQ01'+struct.pack('<7Q',op,0,0,0,0,0,0))
        assert ret==64 and body[:8]==b'HHISTR01';return body,event
    def control(self,op):self.send(b'HBCACTL2'+struct.pack('<Q',op));return self.message()
    def finish(self):
        if self.closed:return
        self.p.stdin.close();self.deadline=time.monotonic()+60
        try:
            while self.selector.get_map():self.pump()
            code=self.p.wait(timeout=max(.01,self.deadline-time.monotonic()))
        except BaseException:
            self.cleanup_killed=True;self.p.kill();self.p.wait(timeout=10);raise
        finally:self.close_receipt()
        assert code==0,code
        assert not self.pending and self.sizes['stderr']==0,(len(self.pending),self.sizes['stderr'])
    def abort(self):
        if self.closed:return
        if self.p.poll() is None:self.cleanup_killed=True;self.p.kill()
        self.p.wait(timeout=10)
        for name,stream in [('stdout',self.p.stdout),('stderr',self.p.stderr)]:
            os.set_blocking(stream.fileno(),True)
            while raw:=stream.read(65536):self.keep(name,raw)
        self.close_receipt()
    def close_receipt(self):
        if self.closed:return
        self.closed=True
        for stream in self.streams.values():stream.close()
        self.selector.close()
        ended=time.monotonic_ns()
        receipt={'command':self.command,'cwd':self.cwd,'pid':self.p.pid,'exit_code':self.p.returncode,
                 'started_monotonic_ns':self.started_ns,'finished_monotonic_ns':ended,'elapsed_seconds':(ended-self.started_ns)/1e9,
                 'timed_out':self.timed_out,'start_error':self.start_error,'cleanup_killed':self.cleanup_killed,
                 'terminal_state':'signaled' if self.p.returncode is not None and self.p.returncode<0 else 'exited',
                 'request_timeout_seconds':60,'umask':self.umask,'proc_status_at_start':self.process_status_pin,
                 'streams':{n:{'bytes':self.sizes[n],'sha256':self.hashes[n].hexdigest()} for n in self.streams}}
        (self.root/'process.json').write_bytes(canonical(receipt));self.event_stream.close()

class Projector:
    def __init__(self,root,manifest,NativeModule):
        self.root=root;self.calls=[];self.offset=0;self.stream=gzip.GzipFile(filename=str(root/'projection.bin.gz'),mode='wb',compresslevel=1,mtime=0)
        self.index=(root/'projection.jsonl').open('wb',buffering=0)
        build=json.loads(manifest.read_bytes());self.modules={}
        for owner,name in [(1,'serde_json_span'),(2,'batch_edit_params')]:
            path=manifest.parent/next(m['manifest'] for m in build['members'] if m['name']==name)
            self.modules[owner]=NativeModule(path,manifest_sha256=sha(path.read_bytes()))
    def complete(self,owner,case,wire):
        workspace=bytes(16512 if owner==1 else 65536);capacity=32 if owner==1 else 64;calls=[]
        while True:
            started=time.monotonic_ns()
            with self.modules[owner].session(workspace_capacity=len(workspace),output_capacity=capacity) as session:
                ctypes.memmove(session._workspace,workspace,len(workspace));ctypes.memset(session._output,0xa5,capacity)
                invoked=time.monotonic_ns()
                code,out,after=session.invoke_raw(wire)
                returned=time.monotonic_ns()
            index=len(self.calls)+1;header=struct.pack('<8Q',index,owner,case,code,len(wire),capacity,len(workspace),0)
            digest=hashlib.sha256();length=0
            for part in [header,wire,workspace,b'\xa5'*capacity,out,after]:self.stream.write(part);digest.update(part);length+=len(part)
            row={'index':index,'owner':owner,'case_id':case,'offset':self.offset,'bytes':length,'sha256':digest.hexdigest(),'return_code':code,
                 'started_monotonic_ns':started,'invoked_monotonic_ns':invoked,'returned_monotonic_ns':returned,
                 'recorded_monotonic_ns':time.monotonic_ns()}
            self.stream.flush();self.index.write(canonical(row))
            self.calls.append(row);calls.append(index);self.offset+=length
            assert code==(32 if owner==1 else 64),(owner,case,hex(code))
            assert out[:8]==(b'HJSVR002' if owner==1 else b'HBPRR002')
            status=word(out,8);needed=word(out,24 if owner==1 else 48)
            if status==2:
                assert needed>len(workspace);workspace=after+bytes(needed-len(after));continue
            if status==3:
                assert needed>capacity;capacity=needed;workspace=after;continue
            assert status==0,(owner,case,status,out[:200]);assert needed==0
            n=(32+word(out,16)) if owner==1 else (64+word(out,16)+word(out,24))
            assert n<=len(out) and out[n:]==b'\xa5'*(len(out)-n)
            return out[:n],calls
    def project(self,case,raw):
        value,a=self.complete(1,case,b'HJSVS002'+struct.pack('<2Q',1,len(raw))+raw)
        typed,b=self.complete(2,case,b'HBPRQ002'+struct.pack('<2Q',len(value)-32,0)+value[32:])
        return typed,{'value':a,'typed':b}
    def finish(self):
        self.stream.close()
        for module in self.modules.values():module.close()
        self.index.close()

class Fixtures:
    def __init__(self):self.fds={}
    def relative(self,root,name):
        raw=name.encode();assert not raw.startswith(b'/') and b'..' not in raw.split(b'/')
        return root+b'/'+raw
    def actions(self,root,actions,blobs):
        for action in actions:
            path=self.relative(root,action['path']);kind=action['kind']
            if kind=='write':
                os.makedirs(os.path.dirname(path),exist_ok=True)
                with open(path,'wb') as stream:stream.write(blobs[action['blob']])
                fd=os.open(path,os.O_RDONLY);info=os.fstat(fd);old=self.fds.pop((info.st_dev,info.st_ino),None)
                if old is not None:os.close(old)
                self.fds[info.st_dev,info.st_ino]=fd
                os.chmod(path,action.get('mode',0o640))
            elif kind=='mkdir':os.mkdir(path)
            elif kind=='remove':
                mode=os.lstat(path).st_mode
                if stat.S_ISDIR(mode):os.rmdir(path)
                else:os.unlink(path)
            elif kind=='chmod':os.chmod(path,action['mode'])
            elif kind=='symlink':os.symlink(os.fsencode(action['target']),path)
            elif kind=='hardlink':os.link(self.relative(root,action['target']),path)
            elif kind=='fifo':os.mkfifo(path,action['mode'])
            else:raise AssertionError(kind)
    def tree(self,root,blobs):
        nodes=[]
        def walk(path,rel):
            info=os.lstat(path);row={'relative_hex':rel.hex(),'metadata':{'mode':info.st_mode,'size':info.st_size,
                'dev':info.st_dev,'ino':info.st_ino,'nlink':info.st_nlink,'uid':info.st_uid,'gid':info.st_gid}}
            if stat.S_ISREG(info.st_mode):
                try:
                    with open(path,'rb') as stream:raw=stream.read()
                    row['content']={'ok':True,'blob':blobs.add(raw)}
                except OSError as error:
                    fd=self.fds.get((info.st_dev,info.st_ino))
                    if fd is None:row['content']={'ok':False,'errno':error.errno}
                    else:
                        parts=[];at=0
                        while piece:=os.pread(fd,65536,at):parts.append(piece);at+=len(piece)
                        row['content']={'ok':True,'blob':blobs.add(b''.join(parts)),'fixture_retained_fd':True,'pathname_errno':error.errno}
            elif stat.S_ISLNK(info.st_mode):row['target_hex']=os.readlink(path).hex()
            nodes.append(row)
            if stat.S_ISDIR(info.st_mode):
                for name in sorted(os.listdir(path)):walk(path+b'/'+name,(rel+b'/' if rel else b'')+name)
        walk(root,b'');return {'root_hex':root.hex(),'nodes':nodes}
    def close(self):
        for fd in self.fds.values():os.close(fd)
        self.fds.clear()

def decode_history(raw,blobs):
    magic,version,used,ns,nq,total,poison,end=struct.unpack_from('<8s7Q',raw)
    assert magic==b'HHISTA01' and version==1 and 64<=end<=used<=len(raw)
    entries={};at=64;count=0
    while at<end:
        kn,vn=struct.unpack_from('<2Q',raw,at);at+=16
        key=raw[at:at+kn];at+=kn;value=raw[at:at+vn];at+=vn
        key.decode();value.decode();entries.setdefault(key,[]).append(blobs.add(value));count+=1
    assert at==end and count==ns
    order=[]
    while at<used:
        kn=word(raw,at);at+=8;key=raw[at:at+kn];at+=kn;key.decode();order.append(key.hex())
    assert at==used and len(order)==nq and not any(raw[used:])
    assert sum(v['bytes'] for values in entries.values() for v in values)==total
    return {'poisoned':bool(poison),'total_bytes':total,'order_hex':order,
            'entries':[{'key_hex':k.hex(),'values':v} for k,v in sorted(entries.items())]}

def decode_cache(raw,blobs):
    magic,version,used,count,poison,a,b,c=struct.unpack_from('<8s7Q',raw)
    assert magic==b'HVCSTA01' and version==1 and not(a or b or c) and 64<=used<=len(raw)
    at=64;entries=[]
    for _ in range(count):
        kn,vn=struct.unpack_from('<2Q',raw,at);at+=16
        key=raw[at:at+kn];at+=kn;value=raw[at:at+vn];at+=vn;key.decode();value.decode()
        entries.append({'key_hex':key.hex(),'value':blobs.add(value)})
    assert at==used and not any(raw[used:])
    return {'poisoned':bool(poison),'entries':sorted(entries,key=lambda x:x['key_hex'])}
