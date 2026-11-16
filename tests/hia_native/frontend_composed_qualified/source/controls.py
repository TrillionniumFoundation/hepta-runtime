"""Observe native pending ABI controls with explicit test-owned private records.

No worker, SDK, original Rust or public transport is executed by this fixture.
Complete inputs, capacities, outputs and workspaces are saved for pure reading.
"""
from pathlib import Path
import argparse, ctypes, hashlib, json, struct, sys, time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'source/scripts'))
from hia_native_loader import NativeModule
CALL=0xfffffff0
GROW=0xffffffd0
word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
pin=lambda raw:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def put(raw,at,value):struct.pack_into('<Q',raw,at,value)
def frame(magic,*values):return magic+struct.pack('<'+'Q'*len(values),*values)
def control(domain,command,sequence=None):
    return frame(b'HBLFRQ01',command,domain['tag'],domain['job'],
                 domain['sequence'] if sequence is None else sequence,0,0,0)

def base(domain,workcap,outcap):
    raw=bytearray(workcap)
    for at,value in [(0,int.from_bytes(b'HRMCFS02','little')),(8,97),(16,domain['sequence']),
                     (24,len(bytes.fromhex(domain['input_hex']))),(32,outcap),(40,workcap),
                     (112,11),(384,4096),(1280,int.from_bytes(b'HBLFRS01','little')),
                     (1288,domain['tag']),(1296,domain['job']),(1320,domain['sequence'])]:
        put(raw,at,value)
    return raw

class Capture:
    def __init__(self,path):
        path.mkdir();self.path=path;self.blobs=path/'blobs';self.blobs.mkdir()
        self.calls=[];self.events=[];self.log=(path/'calls.jsonl').open('x')
        self.event_log=(path/'events.jsonl').open('x')
    def blob(self,raw):
        identity=pin(raw);p=self.blobs/identity['sha256']
        if not p.exists():p.write_bytes(raw)
        return identity
    def invoke(self,session,source,name):
        before_o=session._output.raw[:session.output_capacity]
        before_w=session._workspace.raw[:session.workspace_capacity]
        code,out,work=session.invoke_raw(source)
        row=dict(index=len(self.calls),case=name,code=code,input=self.blob(source),
            output_capacity=session.output_capacity,workspace_capacity=session.workspace_capacity,
            before_output=self.blob(before_o),before_workspace=self.blob(before_w),
            output=self.blob(out),workspace=self.blob(work))
        self.calls.append(row);self.log.write(json.dumps(row,sort_keys=True)+'\n');self.log.flush()
        return code,out,work
    def event(self,**row):
        row=dict(index=len(self.events),after_call_index=len(self.calls)-1,**row);self.events.append(row)
        self.event_log.write(json.dumps(row,sort_keys=True)+'\n');self.event_log.flush()
    def close(self):self.log.close();self.event_log.close()

def install(session,raw):
    assert len(raw)==session.workspace_capacity
    ctypes.memmove(session._workspace,bytes(raw),len(raw))

def step(module,session,source,name,capture,limit):
    for _ in range(limit):
        code,out,work=capture.invoke(session,source,name)
        if code!=GROW:return session,code,out,work
        assert out[:8]==b'HGRWS002' and word(out,24)==0
        kind,needed=word(out,8),word(out,16)
        old=session;oc=old.output_capacity;wc=old.workspace_capacity
        if kind==1:assert needed>wc;wc=needed
        elif kind==2:assert needed>oc;oc=needed
        else:raise AssertionError(('unrepresentable growth',kind,needed))
        session=module.session(output_capacity=oc,workspace_capacity=wc)
        ctypes.memmove(session._output,old._output,old.output_capacity)
        ctypes.memmove(session._workspace,old._workspace,old.workspace_capacity)
        capture.event(kind='relocation',case=name,growth_kind=kind,required=needed,
            old_output_capacity=old.output_capacity,new_output_capacity=oc,
            old_workspace_capacity=old.workspace_capacity,new_workspace_capacity=wc,
            workspace_address_changed=ctypes.addressof(session._workspace)!=ctypes.addressof(old._workspace),
            output_address_changed=ctypes.addressof(session._output)!=ctypes.addressof(old._output))
        old.close()
    raise AssertionError('frozen continuation turn limit exceeded')

def action(work):
    row=struct.unpack_from('<14Q',work,256)
    assert work[256:264]==b'HRMCFA02' and row[2]==14 and row[3]==0
    assert row[8:]==(0,0,0,0,0,0)
    _,sequence,target,mode,start,size,dst,capacity,*_=row
    assert start>=4096 and size<=len(work)-start
    assert dst>=4096 and capacity<=len(work)-dst
    return sequence,work[start:start+size],dst,capacity

def acknowledge(session,reply,code,capture,name):
    work=session._workspace.raw[:session.workspace_capacity]
    seq,request,dst,capacity=action(work)
    assert len(reply)<=capacity
    after=bytearray(work);put(after,320,seq);put(after,328,code);put(after,352,len(reply))
    after[dst:dst+len(reply)]=reply
    capture.event(kind='test_owned_child_acknowledgment',case=name,sequence=seq,
        request=capture.blob(request),reply=capture.blob(reply),code=code,
        before_workspace=capture.blob(work),after_workspace=capture.blob(bytes(after)))
    install(session,after)

def run_case(module,capture,domain,row):
    name=row['name'];source=bytes.fromhex(domain['input_hex'])
    session=module.session(output_capacity=row['outcap'],workspace_capacity=row['workcap'])
    try:
        ctypes.memset(session._output,0xcc,session.output_capacity)
        work=base(domain,row['workcap'],row['outcap'])
        if 'control' in row:work[1344:1408]=control(domain,row['control'])
        for at,value in row['changes']:put(work,at,value)
        install(session,work)
        session,code,out,work=step(module,session,source,name,capture,domain['max_turns'])
        expected=row['expect']
        if expected=='invalid':assert code==0xffffffff,(name,hex(code))
        elif expected=='short':assert code==0xfffffffe,(name,hex(code))
        elif expected=='pending':assert code==64 and out==frame(b'HRCMFR02',4,0,0,0,0,domain['sequence'],0)
        elif expected=='child':
            assert code==CALL,(name,hex(code))
            seq,request,_,_=action(work)
            assert seq==domain['sequence']+1
            assert request==frame(b'HBLCLQ01',row['control'],domain['tag'],0,0,0,0,0)
        else:raise AssertionError(expected)
        return dict(name=name,expect=expected,code=code)
    finally:session.close()

def lifecycle(module,capture,domain,name):
    source=bytes.fromhex(domain['input_hex']);poll=name.startswith('poll-')
    wc=4096 if name.endswith('workspace-relocation') else 8192
    session=module.session(output_capacity=64,workspace_capacity=wc)
    try:
        ctypes.memset(session._output,0xcc,64)
        work=base(domain,wc,64);work[1344:1408]=control(domain,2 if poll else 3);install(session,work)
        session,code,out,work=step(module,session,source,name,capture,domain['max_turns'])
        assert code==CALL
        seq,request,_,_=action(work)
        assert request==frame(b'HBLCLQ01',2 if poll else 3,domain['tag'],0,0,0,0,0)
        # An unacknowledged continuation cannot be mistaken for another host turn.
        bad_code,_,bad_work=capture.invoke(session,source,name)
        assert bad_code==0xffffffff and word(bad_work,16)==seq
        reply=frame(b'HBLCLR01',3 if poll else 4,domain['tag'],domain['job'],0,0,0,0)
        acknowledge(session,reply,64,capture,name)
        session,code,out,work=step(module,session,source,name,capture,domain['max_turns'])
        if poll:
            assert code==64 and out==frame(b'HRCMFR02',4,0,0,0,0,seq,0)
            stale=bytearray(work);stale[1344:1408]=control(domain,2);install(session,stale)
            code,out,work=capture.invoke(session,source,name)
            assert code==0xffffffff and word(work,16)==seq
        else:
            assert code==CALL
            next_seq,request,_,_=action(work)
            assert next_seq==seq+1 and request==frame(b'HBLRET01',1,domain['tag'],0,0,0,0,0)
            acknowledge(session,frame(b'HBLRTR01',domain['tag'],0,0),32,capture,name)
            session,code,out,work=step(module,session,source,name,capture,domain['max_turns'])
            assert code==64 and out==frame(b'HRCMFR02',0,0,0,0,0,next_seq,0)
            assert word(work,8)==0 and work[1280:1408]==bytes(128)
        return dict(name=name,poll=poll,retired=not poll,real_worker_executed=False)
    finally:session.close()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True);p.add_argument('--capture',type=Path,required=True)
    a=p.parse_args();a.capture=a.capture.absolute();assert not a.capture.exists()
    manifest=json.loads((ROOT/'package-manifest.json').read_bytes())
    for name,identity in manifest['files'].items():assert pin((ROOT/name).read_bytes())==identity,name
    build=json.loads((a.build/'build.json').read_bytes());domain=json.loads((ROOT/'domain.json').read_bytes())
    capture=Capture(a.capture);started=time.monotonic()
    report=dict(status='RUNNING',source_manifest=pin((ROOT/'package-manifest.json').read_bytes()),
        domain=pin((ROOT/'domain.json').read_bytes()),controls=[],lifecycle=[],
        public_qualified=False,real_workers_executed=0,rust_executions=0)
    try:
        with NativeModule(Path(build['manifest']),manifest_sha256=build['manifest_sha256']) as module:
            for row in domain['cases']:report['controls'].append(run_case(module,capture,domain,row))
            for name in domain['lifecycle']:report['lifecycle'].append(lifecycle(module,capture,domain,name))
        report['status']='NATIVE_PENDING_ABI_CONTROLS_PASS'
    except BaseException as exc:
        report['status']='FAIL';report['error']=str(exc);raise
    finally:
        report.update(calls=len(capture.calls),events=len(capture.events),wall_seconds=time.monotonic()-started)
        capture.close();(a.capture/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        print(json.dumps({k:report[k] for k in ('status','calls','events','wall_seconds')},sort_keys=True))

if __name__=='__main__':main()
