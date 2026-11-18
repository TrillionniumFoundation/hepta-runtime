"""Actual original/native threads; every complete command frame is retained."""
from pathlib import Path
import argparse,hashlib,json,os,select,struct,subprocess,time,traceback
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
ENCODE=lambda obj:(json.dumps(obj,sort_keys=True,indent=2)+'\n').encode()

class Session:
    def __init__(self,executable,directory):
        self.directory=directory;directory.mkdir(mode=0o700,parents=True)
        self.process=subprocess.Popen([str(executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            bufsize=0,env=dict(os.environ,PATH=''))
        self.started=time.monotonic();self.sent={};self.received={};self.records=[];self.milestones=[]
        self.stdin=bytearray();self.stdout=bytearray();self.buffer=bytearray();self.app=0;self.probes=0
        self.thread_ids=[];self.closed=False
    def send(self,actor,command,mode=0,nanos=0,*,probe=False):
        if probe:self.probes+=1;tag=1000000000+self.probes
        else:self.app+=1;tag=self.app
        wire=struct.pack('<8s7Q',b'HRALC001',tag,actor,command,mode,nanos,0,0)
        self.sent[tag]=dict(actor=actor,command=command,probe=probe)
        self.stdin.extend(wire);self.process.stdin.write(wire);self.process.stdin.flush();return tag
    def feed(self,raw):
        self.stdout.extend(raw);self.buffer.extend(raw)
        while len(self.buffer)>=80:
            frame=bytes(self.buffer[:80]);del self.buffer[:80]
            value=struct.unpack('<8s9Q',frame);magic,tag,actor,command,status,*rest=value
            assert magic==b'HRALO001' and tag in self.sent and tag not in self.received,value
            assert actor==self.sent[tag]['actor'] and command==self.sent[tag]['command']
            assert status in (0,5,6,7) and rest[-1]==0,value
            if command!=6:assert rest==[0]*5,value
            self.received[tag]=(frame,value)
            self.records.append(dict(tag=tag,frame_hex=frame.hex(),probe=self.sent[tag]['probe']))
    def receive(self,tag,timeout=5):
        deadline=time.monotonic()+timeout
        while tag not in self.received:
            left=deadline-time.monotonic()
            assert left>0 and select.select([self.process.stdout],[],[],left)[0],('response deadline',tag,self.process.poll())
            raw=os.read(self.process.stdout.fileno(),65536);assert raw,('early process EOF',tag,self.process.poll())
            self.feed(raw)
        if not self.thread_ids:
            self.thread_ids=sorted(int(p.name) for p in Path('/proc',str(self.process.pid),'task').iterdir())
            assert len(self.thread_ids)==5,self.thread_ids
        return self.received[tag][1]
    def expect(self,tag,status):
        value=self.receive(tag);assert value[4]==status,(tag,value,status);return value
    def call(self,actor,command,status=0,mode=0,nanos=0):
        return self.expect(self.send(actor,command,mode,nanos),status)
    def acquire(self,actor,kind,*,mode=None,nanos=None):
        mode=(1 if kind==2 else 0) if mode is None else mode
        nanos=(10000000000 if mode==1 else 0) if nanos is None else nanos
        return self.call(actor,kind,5,mode,nanos)
    def enqueue(self,actor,kind,*,mode=None,nanos=None):
        mode=(1 if kind==2 else 0) if mode is None else mode
        nanos=(10000000000 if mode==1 else 0) if nanos is None else nanos
        return self.send(actor,kind,mode,nanos)
    def release(self,actor,kind):return self.call(actor,3 if kind==2 else 4)
    def pending(self,*tags):
        while select.select([self.process.stdout],[],[],0)[0]:
            raw=os.read(self.process.stdout.fileno(),65536);assert raw;self.feed(raw)
        assert all(tag not in self.received for tag in tags),('response passed a custody barrier',tags)
    def barrier(self,actor,*,tickets=None,poison=None,readers=None,waiting=None):
        wanted=dict(tickets=tickets,poison=poison,readers=readers,waiting=waiting)
        deadline=time.monotonic()+5
        while True:
            value=self.receive(self.send(actor,6,probe=True))
            actual=dict(tickets=value[5],poison=value[6],readers=value[7],waiting=value[8])
            if all(value is None or actual[key]==value for key,value in wanted.items()):
                self.milestones.append(dict(wanted=wanted,observed=actual));return actual
            assert time.monotonic()<deadline,('queue milestone',wanted,actual)
            time.sleep(0.001)
    def close(self,expected=None):
        self.process.stdin.close();self.process.stdin=None
        raw,stderr=self.process.communicate(timeout=5);self.feed(raw)
        assert self.process.returncode==0 and not stderr and not self.buffer,(self.process.returncode,stderr,bytes(self.buffer))
        assert set(self.sent)==set(self.received),set(self.sent)-set(self.received)
        for tag,status in (expected or {}).items():assert self.received[tag][1][4]==status
        self.closed=True
        result=dict(exit_code=0,pid=self.process.pid,reaped=True,elapsed_seconds=time.monotonic()-self.started,
            real_linux_tasks=self.thread_ids,observed_task_count=len(self.thread_ids),worker_threads=4,
            requests=len(self.sent),application_requests=self.app,observation_probes=self.probes,
            stdin_bytes=len(self.stdin),stdin_sha256=SHA(self.stdin),stdout_bytes=len(self.stdout),stdout_sha256=SHA(self.stdout),
            stderr_bytes=len(stderr),stderr_sha256=SHA(stderr),milestones=self.milestones,
            application_frames={str(tag):frame.hex() for tag,(frame,_) in self.received.items() if not self.sent[tag]['probe']},
            response_arrival_order=[row['tag'] for row in self.records],all_submitted_requests_completed=True,
            real_thread_join_and_guard_cleanup_on_eof=True)
        (self.directory/'stdin.bin').write_bytes(self.stdin);(self.directory/'stdout.bin').write_bytes(self.stdout)
        (self.directory/'stderr.bin').write_bytes(stderr);(self.directory/'result.json').write_bytes(ENCODE(result));return result
    def abort(self):
        if self.closed:return
        self.process.kill();raw,stderr=self.process.communicate();self.stdout.extend(raw)
        (self.directory/'stdin.bin').write_bytes(self.stdin);(self.directory/'stdout.bin').write_bytes(self.stdout)
        (self.directory/'stderr.bin').write_bytes(stderr)
        (self.directory/'partial.json').write_bytes(ENCODE(dict(pid=self.process.pid,exit_code=self.process.returncode,
            reaped=True,records=self.records,milestones=self.milestones)))

def definitions():
    for kind in (1,2):yield ('serial-'+str(kind),'serial',kind)
    for kind in (1,2):yield ('ticket-overflow-'+str(kind),'ticket_overflow',kind)
    for command in (3,4,5):yield ('reader-underflow-'+str(command),'reader_underflow',command)
    for pattern in ((1,1,1),(1,1,2),(1,2,1),(1,2,2),(2,1,1),(2,1,2)):
        yield ('fifo-'+''.join(map(str,pattern)),'fifo',pattern)
    yield ('four-adjacent-readers','four_readers',None)
    yield ('writer-after-three-readers','three_readers',None)
    for poison in ('none','queue','inner','reader'):
        for kind in (1,2):yield (f'preexpired-{poison}-{kind}','preexpired',(poison,kind))
    for kind in (1,2):yield ('queued-deadline-'+str(kind),'queued_deadline',kind)
    for name in ('middle_deadline','finish_expired','shared_panic','finish_before_peer_panic','exclusive_panic',
            'queue_poison_finish','queue_poison_waiter','inner_wouldblock','inner_panic_shared','spurious',
            'eof_cascade','queue_preflight'):
        yield (name,name,None)

def exercise(s,kind,data):
    if kind=='serial':
        for _ in range(24):s.acquire(0,data);s.release(0,data)
        s.barrier(0,tickets=24,poison=0,readers=0,waiting=0)
    elif kind=='fifo':
        a,b,c=data;s.acquire(0,a)
        one=s.enqueue(1,b);s.barrier(0,tickets=2,waiting=1)
        two=s.enqueue(2,c);s.barrier(0,tickets=3,waiting=2);s.pending(one,two)
        s.release(0,a);s.expect(one,5)
        if b==2 and c==2:
            s.expect(two,5);s.barrier(0,poison=0,readers=2,waiting=0)
            s.release(1,b);s.release(2,c)
        else:
            s.barrier(0,poison=8 if b==1 else 0,readers=1 if b==2 else 0,waiting=1)
            s.pending(two);s.release(1,b);s.expect(two,5);s.release(2,c)
        s.barrier(0,tickets=3,poison=0,readers=0,waiting=0)
    elif kind=='four_readers':
        for actor in range(4):s.acquire(actor,2)
        s.barrier(0,tickets=4,poison=0,readers=4,waiting=0)
        for actor in range(4):s.release(actor,2)
        s.barrier(0,poison=0,readers=0,waiting=0)
    elif kind=='three_readers':
        for actor in range(3):s.acquire(actor,2)
        writer=s.enqueue(3,1);s.barrier(0,tickets=4,poison=0,readers=3,waiting=1)
        s.release(0,2);s.release(1,2);s.barrier(0,readers=1,waiting=1);s.pending(writer)
        s.release(2,2);s.expect(writer,5);s.release(3,1);s.barrier(0,poison=0,readers=0,waiting=0)
    elif kind=='preexpired':
        poison,access=data
        if poison=='queue':s.call(0,7)
        elif poison=='inner':s.call(0,8)
        elif poison=='reader':s.acquire(0,2);s.call(0,5)
        s.call(1,access,6,2,0)
        s.barrier(0,tickets=1 if poison=='reader' else 0,poison={'none':0,'queue':1,'inner':2,'reader':4}[poison],readers=0,waiting=0)
    elif kind=='queued_deadline':
        s.acquire(0,1);timed=s.enqueue(1,data,mode=1,nanos=250000000)
        s.barrier(0,tickets=2,waiting=1);s.expect(timed,6)
        s.barrier(0,poison=8,readers=0,waiting=0);s.release(0,1)
        s.acquire(1,data);s.release(1,data);s.barrier(0,tickets=3,poison=0,readers=0,waiting=0)
    elif kind=='middle_deadline':
        s.acquire(0,1);one=s.enqueue(1,1);s.barrier(0,waiting=1)
        two=s.enqueue(2,2,mode=1,nanos=250000000);s.barrier(0,waiting=2)
        three=s.enqueue(3,2);s.barrier(0,tickets=4,waiting=3);s.expect(two,6)
        s.barrier(0,waiting=2);s.release(0,1);s.expect(one,5);s.pending(three)
        s.release(1,1);s.expect(three,5);s.release(3,2);s.barrier(0,tickets=4,poison=0,readers=0,waiting=0)
    elif kind=='finish_expired':
        s.acquire(0,2,mode=1,nanos=500000000);time.sleep(0.6);s.call(0,3,6)
        s.barrier(0,poison=0,readers=0,waiting=0);s.acquire(1,1);s.release(1,1)
    elif kind=='shared_panic':
        s.acquire(0,2);s.acquire(1,2);s.call(0,5);s.call(1,3,7)
        s.call(2,1,7);s.call(2,2,7,1,10000000000)
        s.barrier(0,tickets=2,poison=4,readers=0,waiting=0)
    elif kind=='finish_before_peer_panic':
        s.acquire(0,2);s.acquire(1,2);finished=s.call(0,3)
        s.call(1,5);assert finished[4]==0;s.call(2,1,7)
        s.barrier(0,tickets=2,poison=4,readers=0,waiting=0)
    elif kind=='exclusive_panic':
        s.acquire(0,1);one=s.enqueue(1,1);s.barrier(0,waiting=1)
        two=s.enqueue(2,2);s.barrier(0,waiting=2);s.call(0,5)
        s.expect(one,7);s.expect(two,7);s.barrier(0,tickets=3,poison=2,readers=0,waiting=0)
    elif kind=='ticket_overflow':
        maximum=(1<<64)-1;s.call(0,16,mode=maximum-1)
        s.acquire(1,data);s.release(1,data)
        s.call(1,data,7,1 if data==2 else 0,10000000000 if data==2 else 0)
        s.barrier(0,tickets=maximum,poison=0,readers=0,waiting=0)
    elif kind=='reader_underflow':
        s.acquire(0,2);s.call(1,17,mode=0);s.call(0,data,7 if data==3 else 0)
        s.barrier(1,tickets=1,poison=4,readers=0,waiting=0);s.call(2,1,7)
    elif kind=='queue_poison_finish':
        s.acquire(0,2);s.call(1,7);s.call(0,3,7)
        s.call(2,1,7);s.barrier(1,tickets=1,poison=1,readers=0,waiting=0)
    elif kind=='queue_poison_waiter':
        s.acquire(0,1);one=s.enqueue(1,1);s.barrier(0,waiting=1)
        s.call(2,7);s.call(2,9);s.expect(one,7);s.release(0,1)
        s.barrier(2,tickets=2,poison=1,readers=0,waiting=0)
    elif kind=='inner_wouldblock':
        s.call(0,10);s.call(1,1,7);s.barrier(2,tickets=1,poison=0,readers=0,waiting=0)
        s.call(0,11);s.acquire(1,1);s.release(1,1);s.barrier(0,tickets=2,poison=0,readers=0,waiting=0)
    elif kind=='inner_panic_shared':
        s.call(0,10);s.call(0,12);s.call(1,2,7,1,10000000000)
        s.call(1,1,7);s.barrier(0,tickets=1,poison=2,readers=0,waiting=0)
    elif kind=='spurious':
        s.acquire(0,1);one=s.enqueue(1,1);s.barrier(0,waiting=1)
        for _ in range(8):s.call(2,9);s.pending(one)
        s.release(0,1);s.expect(one,5);s.release(1,1);s.barrier(0,tickets=2,poison=0,readers=0,waiting=0)
    elif kind=='eof_cascade':
        s.acquire(0,1);one=s.enqueue(1,1);s.barrier(0,waiting=1)
        two=s.enqueue(2,2);s.barrier(0,waiting=2);s.pending(one,two)
        return s.close({one:5,two:5})
    elif kind=='queue_preflight':
        s.call(0,14);s.call(1,1,6,2,0);s.call(2,2,6,2,0)
        one=s.enqueue(3,1,mode=1,nanos=500000000);time.sleep(0.1);s.pending(one)
        time.sleep(0.6);s.pending(one);s.call(0,15);s.expect(one,6)
        s.barrier(0,tickets=0,poison=0,readers=0,waiting=0)
    else:raise AssertionError(kind)
    return s.close()

def run(executable,directory,kind,data):
    session=Session(executable,directory)
    try:return exercise(session,kind,data)
    except BaseException:session.abort();raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--oracle',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,mode=0o700)
    executable_paths={'native':args.native.resolve(strict=True)}
    if args.oracle:executable_paths['original']=args.oracle.resolve(strict=True)
    pins={k:dict(bytes=p.stat().st_size,sha256=SHA(p.read_bytes())) for k,p in executable_paths.items()}
    results=[];started=time.monotonic()
    try:
        for index,(name,kind,data) in enumerate(definitions()):
            row=dict(name=name)
            for implementation in ('original','native'):
                if implementation in executable_paths:
                    row[implementation]=run(executable_paths[implementation],args.output/f'{index:02d}-{name}'/implementation,kind,data)
            if args.oracle:
                assert row['original']['application_frames']==row['native']['application_frames'],('application frames',name)
                assert row['original']['milestones']==row['native']['milestones'],('queue milestones',name,row['original']['milestones'],row['native']['milestones'])
            results.append(row)
        for key,path in executable_paths.items():assert SHA(path.read_bytes())==pins[key]['sha256']
        result=dict(schema='hepta.request-audit.actual-thread-lock-comparison.v1',status='PASS',cases=len(results),results=results,
            actual_native_processes=len(results),actual_original_processes=len(results) if args.oracle else 0,
            native_requests=sum(r['native']['requests'] for r in results),
            original_requests=sum(r['original']['requests'] for r in results) if args.oracle else 0,
            application_requests_per_implementation=sum(r['native']['application_requests'] for r in results),
            native_workers_per_process=4,all_actual_application_frames_equal=bool(args.oracle),
            all_actual_queue_milestones_equal=bool(args.oracle),observation_probe_count_and_arrival_order_compared=False,
            source_executables=pins,executable_bytes_unchanged=True,elapsed_seconds=time.monotonic()-started,
            native_language_unwind_qualified=False,panic_poison_injected_as_typed_native_guard_reason=True,
            whole_runtime_replaced=False,production_activated=False)
        (args.output/'result.json').write_bytes(ENCODE(result))
        print(json.dumps({k:v for k,v in result.items() if k not in ('results','source_executables')},sort_keys=True))
    except BaseException:
        (args.output/'failure.json').write_bytes(ENCODE(dict(status='FAIL',completed_cases=len(results),completed=results,
            source_executables=pins,traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-started)))
        raise
if __name__=='__main__':main()
