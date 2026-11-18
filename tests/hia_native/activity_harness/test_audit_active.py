"""Compare real Rust reference lifetimes and four native HIA-owner workers."""
from pathlib import Path
import argparse,hashlib,json,os,select,struct,subprocess,sys,time,traceback
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
ENCODE=lambda obj:(json.dumps(obj,sort_keys=True,indent=2)+'\n').encode()
class Session:
    def __init__(self,executable,directory):
        self.directory=directory;directory.mkdir(parents=True,mode=0o700)
        self.process=subprocess.Popen([str(executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,env=dict(os.environ,PATH=''))
        self.started=time.monotonic();self.sent={};self.received={};self.stdin=bytearray();self.stdout=bytearray();self.buffer=bytearray()
        self.thread_ids=[];self.closed=False;self.phases=[];self.commuting_tags=set();self.deferred_tags=[];self.order=[]
    def send(self,actor,op,token=0,id='',flag=0):
        tag=len(self.sent)+1;name=id.encode();wire=b'HRAAQ001'+struct.pack('<7Q',op,token,len(name),flag,0,0,0)+name
        assert len(wire)<=320 and actor in range(4)
        frame=b'HRAAC001'+struct.pack('<7Q',tag,actor,len(wire),0,0,0,0)+wire+bytes(320-len(wire))
        self.sent[tag]=dict(actor=actor,op=op,token=token,id=id,flag=flag)
        self.stdin.extend(frame);assert self.process.stdin.write(frame)==len(frame);self.process.stdin.flush();return tag
    def feed(self,raw):
        self.stdout.extend(raw);self.buffer.extend(raw)
        while len(self.buffer)>=96:
            frame=bytes(self.buffer[:96]);del self.buffer[:96]
            assert frame[:8]==b'HRAAO001' and frame[32:40]==b'HRAAR001'
            tag,actor,size=struct.unpack_from('<3Q',frame,8)
            assert tag in self.sent and tag not in self.received and size==64
            assert actor==self.sent[tag]['actor']
            values=struct.unpack_from('<7Q',frame,40);assert values[0] in (0,38,39,40,41)
            self.received[tag]=(values,frame[32:].hex(),frame.hex());self.order.append(tag)
    def receive(self,tag):
        deadline=time.monotonic()+10
        while tag not in self.received:
            left=deadline-time.monotonic();assert left>0 and select.select([self.process.stdout],[],[],left)[0],('response deadline',tag,self.process.poll())
            raw=os.read(self.process.stdout.fileno(),65536);assert raw,('early EOF',tag,self.process.poll());self.feed(raw)
        if not self.thread_ids:
            self.thread_ids=sorted(int(p.name) for p in Path('/proc',str(self.process.pid),'task').iterdir());assert len(self.thread_ids)==5,self.thread_ids
        return self.received[tag][0]
    def close(self):
        self.process.stdin.close();self.process.stdin=None
        raw,stderr=self.process.communicate(timeout=10);self.feed(raw)
        assert self.process.returncode==0 and not stderr and not self.buffer,(self.process.returncode,stderr,bytes(self.buffer))
        assert set(self.sent)==set(self.received)
        if self.deferred_tags:
            rows=[self.received[t][0] for t in self.deferred_tags]
            assert sorted(r[1] for r in rows)==[1,2,3,4] and sorted(r[-1] for r in rows)==[1,2,3,4]
            assert all(r[0]==0 and r[1]==r[2] and r[4]==1 for r in rows)
            self.phases.append(dict(name='eof-drained-pins',native_result_multiset=sorted(self.received[t][1] for t in self.deferred_tags)))
        self.closed=True
        result=dict(pid=self.process.pid,exit_code=0,reaped=True,requests=len(self.sent),elapsed_seconds=time.monotonic()-self.started,
            observed_linux_tasks=self.thread_ids,observed_task_count=len(self.thread_ids),worker_threads=4,
            stdin_bytes=len(self.stdin),stdin_sha256=SHA(self.stdin),stdout_bytes=len(self.stdout),stdout_sha256=SHA(self.stdout),
            stderr_bytes=len(stderr),stderr_sha256=SHA(stderr),all_submitted_requests_completed=True,
            thread_join_and_lease_cleanup_on_eof=True,response_arrival_order=self.order,
            exact_frames={str(t):self.received[t][2] for t in self.received if t not in self.commuting_tags},
            commuting_tags=sorted(self.commuting_tags),commuting_phases=self.phases)
        (self.directory/'stdin.bin').write_bytes(self.stdin);(self.directory/'stdout.bin').write_bytes(self.stdout);(self.directory/'stderr.bin').write_bytes(stderr)
        (self.directory/'result.json').write_bytes(ENCODE(result));return result
    def abort(self):
        if self.closed:return
        self.process.kill();raw,stderr=self.process.communicate();self.stdout.extend(raw)
        (self.directory/'stdin.bin').write_bytes(self.stdin);(self.directory/'stdout.bin').write_bytes(self.stdout);(self.directory/'stderr.bin').write_bytes(stderr)
        (self.directory/'partial.json').write_bytes(ENCODE(dict(pid=self.process.pid,exit_code=self.process.returncode,reaped=True,sent=self.sent,received=self.received,phases=self.phases)))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('native','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--oracle',type=Path);args=parser.parse_args();args.output.mkdir(parents=True,mode=0o700)
    sys.path.insert(0,str(Path(__file__).resolve().parent));from audit_active_cases import definitions,exercise
    items=list(definitions());assert len(items)==36 and len({r[0] for r in items})==36
    executables={'native':args.native.resolve(strict=True)}
    if args.oracle:executables['original']=args.oracle.resolve(strict=True)
    pins={k:SHA(p.read_bytes()) for k,p in executables.items()};started=time.monotonic();done=[]
    try:
        for name,kind,data in items:
            pair={}
            for label,path in executables.items():
                session=Session(path,args.output/name/label)
                try:exercise(session,kind,data);pair[label]=session.close()
                finally:session.abort()
            if 'original' in pair:
                a,b=pair['native'],pair['original'];assert a['requests']==b['requests']
                assert a['exact_frames']==b['exact_frames'],('exact frames',name)
                assert a['commuting_tags']==b['commuting_tags'] and a['commuting_phases']==b['commuting_phases'],('commuting operations',name)
                if not a['commuting_tags']:assert a['stdin_sha256']==b['stdin_sha256']
            done.append(dict(name=name,kind=kind,requests=pair['native']['requests'],commuting_operations=len(pair['native']['commuting_tags']),
                exact_tagged_frames=len(pair['native']['exact_frames']),processes={k:{x:v for x,v in row.items() if x not in ('exact_frames','response_arrival_order','commuting_phases')} for k,row in pair.items()}))
        assert {k:SHA(p.read_bytes()) for k,p in executables.items()}==pins
        report=dict(schema='hepta.request-audit.actual-active-registry-comparison.v1',status='PASS',cases=len(done),
            requests_per_implementation=sum(x['requests'] for x in done),exact_tagged_frames_per_implementation=sum(x['exact_tagged_frames'] for x in done),
            commuting_operations_per_implementation=sum(x['commuting_operations'] for x in done),
            actual_native_processes=len(done),actual_original_processes=len(done) if args.oracle else 0,
            real_four_worker_threads_observed=True,all_submitted_commands_completed=True,
            exact_noncommuting_frames_equal=bool(args.oracle),commuting_phase_multisets_equal=bool(args.oracle),
            original_arc_weak_atomic_and_mutex_executed=bool(args.oracle),shared_private_transport_gate=True,
            native_language_unwind_qualified=False,unserialized_original_interleavings_qualified=False,
            public_request_dispatch_qualified=False,audit_storage_closed=False,whole_runtime_replaced=False,production_activated=False,
            source_executables=pins,elapsed_seconds=time.monotonic()-started,results=done)
        (args.output/'result.json').write_bytes(ENCODE(report));print(json.dumps({k:v for k,v in report.items() if k!='results'},sort_keys=True))
    except BaseException:
        (args.output/'failure.json').write_bytes(ENCODE(dict(status='FAIL',completed=len(done),results=done,traceback=traceback.format_exc())));raise
if __name__=='__main__':main()
