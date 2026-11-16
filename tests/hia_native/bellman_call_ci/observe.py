"""Execute complete private caller continuations with one real shared worker."""
from __future__ import annotations
import argparse,contextlib,ctypes,hashlib,json,os,signal,struct,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'source/scripts'))
sys.path.insert(0,str(ROOT/'reference/params'))
from hia_native_loader import NativeModule
from native_observe import originals
from worker_transport import WorkerProcess,frame,decode_journal
CALL=0xfffffff0;GROW=0xffffffd0;DELIVERY=0xffffffcd;INVALID=0xffffffff
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def u64(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def put(raw,at,value):struct.pack_into('<Q',raw,at,value)
def wire(command,tag,payload=b''):return b'HBLCLQ01'+struct.pack('<7Q',command,tag,len(payload),0,0,0,0)+payload
def write(path,value):
    with path.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
def source_check():
    manifest=json.loads((ROOT/'package-manifest.json').read_bytes())
    for name,expected in manifest['files'].items():
        p=ROOT/name;assert not p.is_symlink() and pin(p.read_bytes())==expected,name
    return pin((ROOT/'package-manifest.json').read_bytes())

class Capture:
    def __init__(self,path):
        self.path=path;path.mkdir();self.blobs=path/'blobs';self.blobs.mkdir()
        self.calls=[];self.actions=[];self.log=(path/'calls.jsonl').open('x');self.action_log=(path/'actions.jsonl').open('x')
    def blob(self,raw):
        value=pin(raw);p=self.blobs/value['sha256']
        if not p.exists():p.write_bytes(raw)
        return value
    def invoke(self,session,request,*,case,role):
        before_output=session._output.raw[:session.output_capacity]
        before_work=session._workspace.raw[:session.workspace_capacity]
        code,out,work=session.invoke_raw(request)
        row=dict(index=len(self.calls),case=case,role=role,code=code,input=self.blob(request),
            output_capacity=session.output_capacity,workspace_capacity=session.workspace_capacity,
            before_output=self.blob(before_output),before_workspace=self.blob(before_work),
            output=self.blob(out),workspace=self.blob(work))
        self.calls.append(row);self.log.write(json.dumps(row,sort_keys=True)+'\n');self.log.flush()
        return code,out,work
    def action(self,value):
        value=dict(index=len(self.actions),**value);self.actions.append(value)
        self.action_log.write(json.dumps(value,sort_keys=True)+'\n');self.action_log.flush();return value['index']
    def close(self):self.log.close();self.action_log.close()

class Bridge:
    def __init__(self,modules,capture,process):
        self.modules=modules;self.capture=capture;self.process=process;self.ready={};self.commands=[];self.controls=[]
    def remember(self,event):
        assert event['kind']==2 and event['job'] not in self.ready
        self.ready[event['job']]=event
    def control(self,request,case):
        assert request[:8]==b'HBWKRQ01' and len(request)==64+u64(request,40)
        values=struct.unpack_from('<7Q',request,8)
        assert values[5:]==(0,0)
        command,tag,job,hold,size=values[:5]
        expected=frame(command,tag,job=job,hold=hold,payload=request[64:]);assert expected[8:]==request
        before=len(self.commands);self.commands.append(dict(case=case,command=command,tag=tag,job=job,hold=hold,input=self.capture.blob(request)))
        self.process.send(command,tag,job=job,hold=hold,payload=request[64:])
        while True:
            event=self.process.next()
            if event['kind']==2:self.remember(event);continue
            assert event['kind']==1 and event['tag']==tag
            response=event['raw'][8:]
            self.commands[before]['output']=self.capture.blob(response)
            return response
    def await_ready(self,job):
        while job not in self.ready:self.remember(self.process.next())
        return self.ready[job]
    def child(self,target,request,case):
        if target==2:return self.control(request,case)
        assert target in (0,1)
        name=('bellman_params_callable','bellman_diagnostic_callable')[target]
        outcap=128 if target==0 else 64;workcap=65536
        for attempt in range(8):
            with self.modules[name].session(output_capacity=outcap,workspace_capacity=workcap) as session:
                ctypes.memset(session._output,0xcc,outcap)
                code,out,work=self.capture.invoke(session,request,case=case,role=name)
            if code==GROW:
                assert out[:8]==b'HGRWS002' and u64(out,24)==0
                kind=u64(out,8);needed=u64(out,16)
                if kind==1:assert needed>workcap;workcap=needed
                elif kind==2:assert needed>outcap;outcap=needed
                else:raise AssertionError(('child growth kind',kind))
                continue
            assert code<0xffff0000 and code<=len(out),(case,name,hex(code))
            return out[:code]
        raise AssertionError('child did not finish within frozen 8 growth attempts')

class Caller:
    def __init__(self,module,bridge,capture,name,outcap=64,workcap=4096):
        self.module=module;self.bridge=bridge;self.capture=capture;self.name=name
        self.session=module.session(output_capacity=outcap,workspace_capacity=workcap);self.completed={};self.last_sequence=0
    def close(self):self.session.close()
    def grow(self,kind,needed):
        old=self.session;outcap=old.output_capacity;workcap=old.workspace_capacity
        if kind==1:assert needed>workcap;workcap=needed
        elif kind==2:assert needed>outcap;outcap=needed
        else:raise AssertionError(('caller cannot grow',kind,needed))
        new=self.module.session(output_capacity=outcap,workspace_capacity=workcap)
        ctypes.memmove(new._output,old._output,old.output_capacity)
        ctypes.memmove(new._workspace,old._workspace,old.workspace_capacity)
        self.session=new;old.close()
    def acknowledge(self,work):
        action=work[256:368];words=struct.unpack('<14Q',action)
        magic,seq,target,mode,offset,size,dst,capacity,ack,code,r0,r1,extent,r2=words
        assert action[:8]==b'HBLCAC01' and ack==code==r0==r1==extent==r2==0
        assert offset>=4096 and size<=len(work)-offset and dst>=4096 and capacity<=len(work)-dst
        request=work[offset:offset+size]
        if mode==0:
            assert seq>self.last_sequence and seq not in self.completed
            response=self.bridge.child(target,request,self.name);self.last_sequence=seq
            self.completed[seq]=(target,request,response)
        else:
            assert mode==1 and seq==self.last_sequence and seq in self.completed
            old_target,old_request,response=self.completed[seq]
            assert old_target==target and old_request==request
        outcome=DELIVERY if len(response)>capacity else len(response)
        patched=bytearray(work);put(patched,320,seq);put(patched,328,outcome);put(patched,352,len(response))
        if outcome!=DELIVERY:patched[dst:dst+len(response)]=response
        index=self.capture.action(dict(case=self.name,sequence=seq,target=target,mode=mode,
            descriptor=self.capture.blob(action),request=self.capture.blob(request),reply=self.capture.blob(response),
            outcome=outcome,whole_workspace_before=self.capture.blob(work),whole_workspace_after=self.capture.blob(patched)))
        ctypes.memmove(self.session._workspace,bytes(patched),len(patched));return index
    def step(self,request):
        indices=[];actions=[]
        for turn in range(64):
            code,out,work=self.capture.invoke(self.session,request,case=self.name,role='bellman_call')
            indices.append(len(self.capture.calls)-1)
            if code==GROW:
                assert out[:8]==b'HGRWS002' and u64(out,24)==0
                self.grow(u64(out,8),u64(out,16));continue
            if code==CALL:actions.append(self.acknowledge(work));continue
            assert code==64,(self.name,hex(code),out[:64].hex(),work[:192].hex())
            assert out[:8]==b'HBLCLR01' and out[40:64]==bytes(24) and u64(out,16)==u64(request,16)
            size=64+u64(out,32);assert size<=len(out);result=out[:size]
            return result,dict(calls=indices,actions=actions)
        raise AssertionError('caller did not finish within frozen 64 continuation turns')

def decoded_body(response):
    body=response[192:];assert body[:8]==b'HBWKBOD1' and len(body)==u64(body,8)
    core,commit,render=[u64(body,x) for x in (16,24,32)]
    assert len(body)==96+core+commit+render
    return body,body[96:96+core],body[96+core:96+core+commit],body[96+core+commit:]

def ordinary(args,modules,capture,bridge):
    rows=[];domain=json.loads((ROOT/'domain.json').read_bytes())
    assert pin((args.reference/'original.stdout').read_bytes())==domain['original_output']
    for index,original,canonical,expected in originals(args.reference,ROOT/'reference/params'):
        assert {key:original[key] for key in domain['cases'][index]}==domain['cases'][index]
        if original['group']!=args.group:continue
        name=original['name'];tag=index+1;before=len(bridge.commands);first_call=len(capture.calls);first_action=len(capture.actions)
        caller=Caller(modules['bellman_call'],bridge,capture,name)
        try:
            result,start=caller.step(wire(1,tag,canonical));status=u64(result,8)
            if original['status']==1:
                assert status==1 and result[64:]==b'failed to deserialize parameters: '+expected
                assert len(bridge.commands)==before and u64(result,24)==0
                transitions=[start]
            else:
                assert status==3 and len(result)==64 and u64(result,24)>0
                job=u64(result,24);event=bridge.await_ready(job)
                assert event['tag']==tag
                result,finish=caller.step(wire(2,tag));status=u64(result,8);transitions=[start,finish]
                commands=bridge.commands[before:]
                assert [r['command'] for r in commands]==[1,2,4]
                submit=(capture.blobs/commands[0]['input']['sha256']).read_bytes();assert submit[64:]==expected
                taken=(capture.blobs/commands[-1]['output']['sha256']).read_bytes();body,core,commit,render=decoded_body(taken)
                code=u64(taken,40);assert code==u64(body,72)==u64(taken,144)
                if code==0:
                    assert status==0 and render[:8]==b'HBLMRS01' and result[64:]==render[64:]
                    value=json.loads(result[64:]);assert len(value)==36
                    sample,start_ns,finish_ns=[u64(body,k) for k in (88,40,48)]
                    assert start_ns<=sample<=finish_ns
                    seconds,nanos=divmod(sample-start_ns,1000000000)
                    expected_float=float(seconds)+float(nanos)/1e9
                    assert struct.pack('<d',expected_float)==body[56:64]==struct.pack('<d',value['native_operation_wall_seconds'])
                else:
                    assert status==2 and not render
            rows.append(dict(index=index,name=name,group=args.group,parameter_status=original['status'],result_status=status,
                request=capture.blob(wire(1,tag,canonical)),expected_typed=capture.blob(expected),result=capture.blob(result),
                calls=list(range(first_call,len(capture.calls))),actions=list(range(first_action,len(capture.actions))),
                commands=list(range(before,len(bridge.commands))),transitions=transitions))
        finally:caller.close()
    assert len(rows)==(680 if args.group=='ordinary' else 3)
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True);p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--bridge',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--group',choices=('ordinary','unicode'),required=True);a=p.parse_args()
    source=source_check();a.output=a.output.absolute();capture=Capture(a.output)
    domain=json.loads((ROOT/'domain.json').read_bytes());limit=domain[a.group+'_deadline_seconds'];start=time.monotonic()
    worker_pin=json.loads((ROOT/'worker-pin.json').read_bytes());component=a.bridge/'component.json'
    assert pin(component.read_bytes())==worker_pin['component']
    executable=(a.bridge/'bellman-worker.elf').resolve(strict=True);assert pin(executable.read_bytes())==worker_pin['executable']
    report=dict(status='RUNNING',source_manifest=source,group=a.group,timeout_seconds=limit,whole_runtime_replaced=False,public_handler_qualified=False)
    process=None
    try:
        with contextlib.ExitStack() as stack:
            built=json.loads((a.build/'build.json').read_bytes());assert built['status']=='BUILD_PASS' and built['fresh_components']==3
            modules={name:stack.enter_context(NativeModule(Path(row['manifest']),manifest_sha256=row['sha256'])) for name,row in built['files'].items()}
            process=WorkerProcess(executable,a.output/'worker',expected_sha=worker_pin['executable']['sha256'],timeout=limit)
            bridge=Bridge(modules,capture,process)
            try:rows=ordinary(a,modules,capture,bridge)
            finally:process.close()
            report.update(status='COMPOSITION_PASS_REQUIRES_FRESH_ORIGINAL',cases=rows,commands=bridge.commands,
                case_count=len(rows),actual_calls=len(capture.calls),actual_actions=len(capture.actions),
                worker_processes=1,worker_ready_events=len(bridge.ready),worker_commands=len(bridge.commands),
                full_original_handler_compared=False,wall_seconds=time.monotonic()-start)
            assert report['wall_seconds']<=limit
    except BaseException as exc:
        report.update(status='FAIL',exception=type(exc).__name__+': '+str(exc),wall_seconds=time.monotonic()-start);raise
    finally:
        capture.close();report.update(calls=pin((a.output/'calls.jsonl').read_bytes()),actions=pin((a.output/'actions.jsonl').read_bytes()))
        write(a.output/'report.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in ('cases','commands')},sort_keys=True))
if __name__=='__main__':main()
