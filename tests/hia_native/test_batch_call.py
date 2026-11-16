"""Native-first complete local batch captures; no Rust expectations at runtime."""
from pathlib import Path
import argparse,gzip,hashlib,importlib.util,json,os,select,stat,struct,sys,time,traceback

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(Path(__file__).parent))
from hia_native_loader import NativeModule
from batch_call_capture import Session,Projector,Fixtures,Blobs,canonical,sha,word,decode_cache,decode_history
spec=importlib.util.spec_from_file_location('_batch_original_input',Path(__file__).with_name('batch_call_oracle')/'cases.py')
inputs=importlib.util.module_from_spec(spec);spec.loader.exec_module(inputs)
spec=importlib.util.spec_from_file_location('_batch_original_control_input',Path(inputs.__file__).with_name('control_inputs.py'))
control_inputs=importlib.util.module_from_spec(spec);spec.loader.exec_module(control_inputs)

def receipt(path):
    digest=hashlib.sha256();size=0
    with path.open('rb') as stream:
        while block:=stream.read(1<<20):digest.update(block);size+=len(block)
    return {'bytes':size,'sha256':digest.hexdigest()}

class Capture:
    def __init__(self,manifest,output,partition):
        self.manifest=manifest;self.output=output;self.partition=partition;output.mkdir(parents=True,exist_ok=False)
        process_status=Path('/proc/self/status').read_bytes()
        self.fixture_umask=int(next(line.split()[1] for line in process_status.splitlines() if line.startswith(b'Umask:')),8)
        (output/'fixture-proc-status-at-start.txt').write_bytes(process_status)
        self.fixture_process_status={'bytes':len(process_status),'sha256':sha(process_status)}
        self.blobs=Blobs(output);self.fixtures=Fixtures();self.projector=Projector(output,manifest,NativeModule)
        self.rows=[];self.sessions={};self.created={};self.current=None;self.events=[];self.sources={}
        self.wire_meta=json.loads(manifest.read_bytes());self.elf=manifest.parent/self.wire_meta['elf']
        for p in [Path(__file__),Path(__file__).with_name('batch_call_capture.py'),Path(inputs.__file__),Path(control_inputs.__file__),ROOT/'scripts/hia_native_loader.py']:
            self.sources[str(p)]=receipt(p)
        (output/'files').mkdir(mode=0o700);(output/'sessions').mkdir()
        with (output/'input.bin').open('wb') as stream:self.input_count=inputs.write_input(stream)
        self.rows_file=(output/'native-cases.jsonl').open('wb',buffering=0)
    def session(self,mode):
        if mode not in self.sessions:
            self.sessions[mode]=Session(self.output/'sessions',mode,self.elf,'--async' if mode=='async' else '--sync')
            self.created[mode]={0}
        return self.sessions[mode]
    def select(self,s,mode,session):
        native=0 if session==0 else 2
        assert session in (0,1)
        event=s.select(native);self.created[mode].add(session)
        return event
    def states(self,s,mode,session,fixture):
        ret,history,event=s.owner(17,b'');assert ret==0
        hist={'raw':self.blobs.add(history),'wire':event,'decoded':decode_history(history,self.blobs)}
        caches=[]
        for number in sorted(self.created[mode]):
            self.select(s,mode,number);ret,raw,event=s.owner(8,b'');assert ret==0
            caches.append({'session':number,'raw':self.blobs.add(raw),'wire':event,**decode_cache(raw,self.blobs)})
        self.select(s,mode,session)
        ret,locks,event=s.owner(18,b'HRFLOCK1'+struct.pack('<7Q',7,0,0,0,0,0,0))
        assert ret==64 and locks[:8]==b'HRFLKR01'
        return {'history':hist,'caches':caches,'locks':{'raw':self.blobs.add(locks),'wire':event},
                'tree':self.fixtures.tree(fixture,self.blobs),'descriptors':self.fd_snapshot(s.p.pid)}
    def fd_snapshot(self,pid):
        rows=[]
        for name in sorted(os.listdir(f'/proc/{pid}/fd'),key=int):
            path=f'/proc/{pid}/fd/{name}'
            try:target=os.readlink(path);mode=os.stat(path).st_mode
            except FileNotFoundError:continue
            rows.append({'fd':int(name),'target_hex':os.fsencode(target).hex(),'mode':mode})
        return rows
    def hook(self,event):
        count=self.counts.get(event,0)+1;self.counts[event]=count
        for index,hook in enumerate(self.meta['hooks']):
            if hook['event']==event and hook['occurrence']==count:
                assert index not in self.hook_used
                self.fixtures.actions(self.cwd,hook['actions'],self.case_blobs);self.hook_used.append(index)
                self.events.append({'kind':'mutation','hook':index,'event':event,'occurrence':count})
    def messages(self,s):
        while True:
            kind,body,wire=s.message()
            if kind==1:
                magic,gen,seq,slot,ret,n,phase,z=struct.unpack_from('<8s7Q',body)
                assert magic==b'HBCIO002' and z==0 and n==len(body)-64
                native=body[64:];event={'kind':'child','generation':gen,'sequence':seq,'slot':slot,'return_code':ret,'phase':phase,
                                     'body':self.blobs.add(native),'wire':wire}
                self.events.append(event)
                if slot==1 and phase in (4,15):self.hook('exists')
                if slot in (2,3) and phase in (10,16):self.hook('read')
                if slot==17 and phase==18:self.hook('history')
                s.send(b'HBCACK02'+struct.pack('<3Q',gen,seq,0),framed=False)
                continue
            if kind in (7,8):
                assert len(body)==160
                magic,gen,seq,a,b,c,d,e=struct.unpack_from('<8s7Q',body)
                assert magic==(b'HBCATE02' if kind==7 else b'HBCATB02')
                assert body[64:72]==b'HIAATFX1' and word(body,144)==1
                self.events.append({'kind':'atomic-effect' if kind==7 else 'atomic-await','header':[gen,seq,a,b,c,d,e],
                                    'effect':self.blobs.add(body[64:]),'wire':wire})
                if kind==8:
                    assert a in (1,2,3,4,5)
                    self.hook({1:'atomic_metadata',2:'atomic_write',3:'atomic_permissions',4:'atomic_rename',5:'atomic_cleanup'}[a])
                    s.send(b'HBCATA02'+struct.pack('<3Q',gen,seq,a),framed=False)
                continue
            assert kind in (2,3),(kind,body[:100])
            ret=word(body,0)
            assert len(body)>=72 and ret in (64,0xfffffff0),(hex(ret),body[:100],self.meta['case_id'])
            magic,status,gen,seq,target,n,aux,z=struct.unpack_from('<8s7Q',body,8)
            assert magic==b'HBCAR002' and z==0 and n==len(body)-72
            return {'kind':kind,'native_return':ret,'status':status,'generation':gen,'sequence':seq,'target':target,
                    'aux':aux,'body':self.blobs.add(body[72:]),'wire':wire}
    def wait_blocked(self,s):
        deadline=min(s.deadline,time.monotonic()+15)
        while time.monotonic()<deadline:
            children=Path(f'/proc/{s.p.pid}/task/{s.p.pid}/children').read_text().split()
            if len(children)==1:
                child=children[0];wchan=Path(f'/proc/{child}/wchan').read_text()
                if 'wait_for_partner' in wchan:
                    return {'pid':int(child),'parent':s.p.pid,'wchan':wchan,'syscall':Path(f'/proc/{child}/syscall').read_text(),
                            'descriptors':self.fd_snapshot(int(child))}
            time.sleep(.002)
        raise AssertionError('actual owned native worker did not block in FIFO open')
    def fifo_write(self,path,data,deadline):
        fd=os.open(path,os.O_WRONLY|os.O_NONBLOCK);at=0
        try:
            while at<len(data):
                try:n=os.write(fd,memoryview(data)[at:at+65536]);assert n>0;at+=n
                except BlockingIOError:
                    assert time.monotonic()<deadline
                    select.select([], [fd], [], max(.001,deadline-time.monotonic()))
        finally:os.close(fd)
        return at
    def fifo_read(self,path,pid,deadline):
        fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK);parts=[]
        try:
            while True:
                assert time.monotonic()<deadline
                try:raw=os.read(fd,65536)
                except BlockingIOError:raw=None
                if raw:parts.append(raw);continue
                state=Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1].split()[0]
                if raw==b'' and state=='Z':break
                select.select([fd],[],[],.002)
        finally:os.close(fd)
        return b''.join(parts)
    def followup(self,s,mode,session,fixture,metadata):
        row=control_inputs.cancel_followup(metadata);meta=row['metadata'];blobs=row['blobs']
        assert meta['session']==session and not meta['reset_history'] and not meta['reset_cache']
        old=(self.meta,self.case_blobs,self.events,self.hook_used,self.counts)
        self.meta=dict(meta,case_id=metadata['case_id'],hooks=[]);self.case_blobs=blobs;self.events=[];self.hook_used=[];self.counts={}
        s.deadline=time.monotonic()+60
        self.fixtures.actions(self.cwd,meta['initial'],blobs)
        before=self.states(s,mode,session,fixture)
        typed,projection=self.projector.project(metadata['case_id'],inputs.canonical(meta['params']))
        path=typed[64:64+word(typed,16)];resolved=path if path.startswith(b'/') else self.cwd+b'/'+path
        request=b'HBCALQ02'+struct.pack('<7Q',1,0,0,len(typed),len(resolved),0,0)+typed+resolved
        # START consumes an already projected typed frame. Fixture creation,
        # prior-state observations and the separate projection owner are not
        # part of this private caller exchange. They remain inside the suite's
        # unchanged 180-second process deadline and retain their own receipts.
        exchange_started=time.monotonic_ns();s.deadline=exchange_started/1e9+60
        request_wire=s.send(request);result=self.messages(s)
        while result['kind']==3:
            s.send(b'HBCACTL2'+struct.pack('<Q',3));result=self.messages(s)
        assert result['kind']==2 and result['status'] in (0,3),result
        exchange_finished=time.monotonic_ns()
        if exchange_finished-exchange_started>60_000_000_000:
            s.timed_out=True;raise TimeoutError('complete private caller exchange exceeded unchanged 60-second deadline')
        s.deadline=time.monotonic()+60
        after=self.states(s,mode,session,fixture)
        record={'input_metadata':meta,'input_blobs':[self.blobs.add(x) for x in blobs],
                'input_record_sha256':sha(inputs.record(meta,blobs)),'typed':self.blobs.add(typed),
                'projection_calls':projection,'request':self.blobs.add(request),'request_wire':request_wire,
                'result':result,'before':before,'after':after,'events':self.events,'io_counts':self.counts}
        record['caller_exchange']={'started_monotonic_ns':exchange_started,'finished_monotonic_ns':exchange_finished,
                                  'timeout_seconds':60,'elapsed_seconds':(exchange_finished-exchange_started)/1e9}
        self.meta,self.case_blobs,self.events,self.hook_used,self.counts=old
        return record
    def run_case(self,row):
        meta=row['metadata'];self.meta=meta;self.case_blobs=row['blobs'];self.events=[];self.hook_used=[];self.counts={}
        mode=meta['execution'];assert mode in ('sync','async');s=self.session(mode);s.deadline=time.monotonic()+60
        self.select(s,mode,meta['session'])
        directory=('sequence-'+meta['sequence']) if meta['sequence'] else ('case-'+str(meta['case_id']).zfill(4))
        fixture=os.fsencode(self.output/'files'/directory);os.makedirs(fixture,exist_ok=bool(meta['sequence']))
        suffix=bytes.fromhex(meta['workdir_rel_hex']);assert not suffix.startswith(b'/') and b'..' not in suffix.split(b'/')
        self.cwd=fixture+(b'/'+suffix if suffix else b'');os.makedirs(self.cwd,exist_ok=True)
        self.fixtures.actions(self.cwd,meta['initial'],row['blobs'])
        if meta['reset_history']:s.history(4);s.history(0)
        if meta['reset_cache']:s.cache(5)
        raw=inputs.canonical(meta['params']);typed,projection=self.projector.project(meta['case_id'],raw)
        plen=word(typed,16);path=typed[64:64+plen]
        resolved=path if path.startswith(b'/') else self.cwd+b'/'+path
        if meta['cache'] is not None:
            key,_=s.key(resolved);s.cache(2,key,row['blobs'][meta['cache']])
        before=self.states(s,mode,meta['session'],fixture)
        request=b'HBCALQ02'+struct.pack('<7Q',1,0,0,len(typed),len(resolved),0,0)+typed+resolved
        exchange_started=time.monotonic_ns();s.deadline=exchange_started/1e9+60
        request_wire=s.send(request);result=self.messages(s);cancel=None
        if mode=='sync':assert result['kind']==2 and result['status'] in (0,3),result
        else:
            stage=meta['cancel']['stage'];wanted=2 if stage=='first_read' else 19
            while result['kind']==3 and result['target']!=wanted:
                s.send(b'HBCACTL2'+struct.pack('<Q',3));result=self.messages(s)
            assert result['kind']==3 and result['target']==wanted,result
            blocked=self.wait_blocked(s);s.send(b'HBCACTL2'+struct.pack('<Q',2));result=self.messages(s)
            assert result['kind']==2 and result['status']==4,result
            if stage=='first_read':
                transferred=row['blobs'][meta['cancel']['transfer_blob']]
                assert self.fifo_write(resolved,transferred,s.deadline)==len(transferred)
            else:
                temp=self.cwd+b'/.octofs_tmp_file.tmp';transferred=self.fifo_read(temp,blocked['pid'],s.deadline)
            s.send(b'HBCACTL2'+struct.pack('<Q',3));late=self.messages(s)
            assert late['kind']==2 and late['status']==7,late
            cancel={'blocked':blocked,'transfer':self.blobs.add(transferred),'late':late}
        exchange_finished=time.monotonic_ns()
        if exchange_finished-exchange_started>60_000_000_000:
            s.timed_out=True;raise TimeoutError('complete private caller exchange exceeded unchanged 60-second deadline')
        s.deadline=time.monotonic()+60
        assert sorted(self.hook_used)==list(range(len(meta['hooks']))),(meta['case_id'],self.hook_used,meta['hooks'])
        after=self.states(s,mode,meta['session'],fixture)
        if cancel is not None:cancel['followup']=self.followup(s,mode,meta['session'],fixture,meta)
        entry={'case_id':meta['case_id'],'name':meta['name'],'domain':meta['domain'],'sequence':meta['sequence'],'session':meta['session'],
               'case_input_sha256':sha(inputs.record(meta,row['blobs'])),'fixture_root_hex':fixture.hex(),'workdir_hex':self.cwd.hex(),
               'process':mode,'typed':self.blobs.add(typed),'projection_calls':projection,'request':self.blobs.add(request),'request_wire':request_wire,
               'result':result,'before':before,'after':after,'events':self.events,'hook_used':self.hook_used,'io_counts':self.counts,
               'cancel':cancel,'public_handler_executed':False,'original_reference_status':'NOT_RUN'}
        entry['caller_exchange']={'started_monotonic_ns':exchange_started,'finished_monotonic_ns':exchange_finished,
                                 'timeout_seconds':60,'elapsed_seconds':(exchange_finished-exchange_started)/1e9}
        self.rows.append(entry);self.rows_file.write(canonical(entry))
        print(json.dumps({'case_id':meta['case_id'],'name':meta['name'],'native_status':result['status'],'body_bytes':result['body']['bytes']}),flush=True)
    def finish(self,success):
        for session in self.sessions.values():
            if success:session.finish()
            else:session.abort()
        self.fixtures.close();self.projector.finish();self.rows_file.close()
        assert self.sources=={p:receipt(Path(p)) for p in self.sources}
        result={'schema':'hepta.runtime.batch-call-native.v1','status':'PASS' if success else 'FAIL','partition':self.partition,
                'cases':len(self.rows),'full_input_cases':self.input_count,'input':receipt(self.output/'input.bin'),
                'projection_calls':len(self.projector.calls),'processes':len(self.sessions),'blobs':self.blobs.pins,
                'fixture_umask':self.fixture_umask,'fixture_proc_status_at_start':self.fixture_process_status,
                'post_cancel_followup_calls':sum(x['cancel'] is not None for x in self.rows),
                'manifest':str(self.manifest),'manifest_sha256':sha(self.manifest.read_bytes()),'sources':self.sources,
                'original_reference_status':'NOT_RUN','public_handler_replaced':False,'whole_runtime_replaced':False}
        (self.output/'result.json').write_bytes(canonical(result));return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--partition',choices=['all','small','wide','async'],default='all');args=parser.parse_args()
    capture=Capture(args.manifest.resolve(),args.output.resolve(),args.partition);error=None
    try:
        for row in inputs.iter_cases():
            meta=row['metadata'];part='async' if meta['execution']=='async' else ('wide' if meta['large'] else 'small')
            if args.partition in ('all',part):capture.run_case(row)
    except BaseException:error=traceback.format_exc();(capture.output/'failure.txt').write_text(error)
    try:result=capture.finish(error is None)
    except BaseException:
        extra=traceback.format_exc();(capture.output/'finish-failure.txt').write_text(extra)
        if error is None:error=extra
        result={'status':'FAIL','finish_error':extra}
    print(json.dumps({'status':result['status'],'cases':result.get('cases'),'error':error}),flush=True)
    if error:raise SystemExit(1)

if __name__=='__main__':main()
