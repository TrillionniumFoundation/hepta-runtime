"""Private ABI controls, same-context reuse and actual shared-worker cancellation."""
from __future__ import annotations
import argparse,contextlib,ctypes,json,os,signal,struct,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from observe import Capture,Bridge,Caller,NativeModule,WorkerProcess,source_check,pin,u64,put,wire,write,frame,originals,CALL,GROW,DELIVERY,INVALID
BUSY=b'native Bellman planning capacity exhausted; no work admitted'

def abi_controls(module,bridge,capture,canonical):
    controls=[];request=wire(1,10001,canonical)
    def raw(name,value,output,workspace,expected,atomic=True):
        with module.session(output_capacity=len(output),workspace_capacity=len(workspace)) as session:
            ctypes.memmove(session._output,output,len(output));ctypes.memmove(session._workspace,workspace,len(workspace))
            code,out,work=capture.invoke(session,value,case=name,role='private-control')
        assert code==expected,(name,hex(code),hex(expected))
        if atomic:assert out==output and work==workspace,name
        controls.append(dict(name=name,call=len(capture.calls)-1,expected=expected,atomic=atomic))
        return out,work
    bad=[('empty',b''),('short-header',request[:63]),('truncated-payload',request[:-1]),('trailing',request+b'x'),('bad-magic',b'X'+request[1:]),
        ('poll-before-start',wire(2,10001)),('cancel-before-start',wire(3,10001))]
    for offset,value in [(8,0),(8,4),(16,0),(24,0),(24,(1<<64)-1),(32,1),(40,1),(48,1),(56,1)]:
        changed=bytearray(request);put(changed,offset,value);bad.append((f'input-word-{offset}-{value}',bytes(changed)))
    for name,value in bad:raw(name,value,b'\xa5'*64,bytes(4096),INVALID)
    for capacity in (0,1,31):raw('short-output-'+str(capacity),request,b'\xa5'*capacity,bytes(4096),0xfffffffe)
    for capacity in (32,63):
        out,work=raw('grow-initial-output-'+str(capacity),request,b'\xa5'*capacity,bytes(4096),GROW,False)
        assert out==b'HGRWS002'+struct.pack('<3Q',2,64,0)+b'\xa5'*(capacity-32)
        expected=bytearray(4096);put(expected,392,64);put(expected,400,2);assert work==expected
    for capacity in (0,1,4095):
        out,work=raw('grow-initial-workspace-'+str(capacity),request,b'\xa5'*64,bytes(capacity),GROW,False)
        assert out==b'HGRWS002'+struct.pack('<3Q',1,4096,0)+b'\xa5'*32 and work==bytes(capacity)
    seed=Caller(module,bridge,capture,'valid-parameter-ack-seed')
    try:
        for _ in range(32):
            code,out,work=capture.invoke(seed.session,request,case=seed.name,role='control-seed')
            if code==GROW:seed.grow(u64(out,8),u64(out,16));continue
            assert code==CALL and u64(work,272)==0
            action=seed.acknowledge(work)
            if capture.actions[action]['outcome']!=DELIVERY:break
        else:raise AssertionError('valid parameter acknowledgement not reached')
        output=seed.session._output.raw[:seed.session.output_capacity]
        workspace=seed.session._workspace.raw[:seed.session.workspace_capacity]
        assert u64(workspace,320)==u64(workspace,264) and u64(workspace,328)==u64(workspace,352)
        reply=u64(workspace,304);assert workspace[reply:reply+8]==b'HBLPAT01'
        mutations=[('state-magic',0,1),('phase',8,77),('context-tag',24,10002),('active-command',40,2),('input-length',64,len(request)+1),
            ('wrong-child-target',272,1),('bad-delivery-mode',280,2),('wrong-input-offset',288,u64(workspace,288)+1),
            ('wrong-input-extent',296,u64(workspace,296)+1),('wrong-output-offset',304,reply+1),
            ('wrong-output-capacity',312,u64(workspace,312)+1),('missing-ack',320,0),('future-ack',320,u64(workspace,320)+1),
            ('wrong-child-code',328,u64(workspace,328)-1),('reserved-80',336,1),('reserved-88',344,1),
            ('wrong-child-extent',352,u64(workspace,352)-1),('reserved-104',360,1),
            ('typed-magic',reply,0),('typed-status',reply+8,2),('typed-required',reply+24,1),
            ('graph-magic',reply+128,0),('graph-count',reply+136,u64(workspace,reply+136)+1)]
        for offset in range(40,128,8):mutations.append(('typed-reserved-'+str(offset),reply+offset,1))
        for name,offset,value in mutations:
            altered=bytearray(workspace);put(altered,offset,value);raw(name,request,output,bytes(altered),INVALID)
        changed=bytearray(request);changed[-1]^=1;raw('owned-input-changed',bytes(changed),output,workspace,INVALID)
        altered=bytearray(workspace);put(altered,328,0xfffffffc);raw('private-resource-propagation',request,output,bytes(altered),0xfffffffc)
    finally:seed.close()
    return controls

def complete(caller,bridge,tag,payload):
    result,start=caller.step(wire(1,tag,payload));parts=[start]
    if u64(result,8)==3:
        bridge.await_ready(u64(result,24));result,finish=caller.step(wire(2,tag));parts.append(finish)
    return result,parts

def partial_journal(path):
    data=path.read_bytes();rows=[];at=0
    while len(data)-at>=16:
        size=u64(data,at+8);assert size>=16
        if size>len(data)-at:break
        rows.append(data[at:at+size]);at+=size
    return rows

def stop_after_begin(process,job,capture):
    deadline=time.monotonic()+10;pid=None;clock=False
    while time.monotonic()<deadline:
        for row in partial_journal(process.path/'stderr.bin'):
            if row[:8]==b'HBWPROC1' and u64(row,24)==job and u64(row,40)==1:pid=u64(row,32)
            if row[:8]==b'HBCLOCK1' and u64(row,16)==job:clock=True
            if row[:8]==b'HBWPL001' and u64(row,24)==5 and u64(row,48)==job:raise AssertionError('wide job completed before stop admission')
        if pid and clock:break
        time.sleep(.001)
    assert pid and clock,'actual worker did not reach first deadline observation'
    os.kill(pid,signal.SIGSTOP)
    try:
        while time.monotonic()<deadline:
            status=Path('/proc')/str(pid)/'status';raw=status.read_bytes()
            if any(line.startswith(b'State:') and b'T' in line for line in raw.splitlines()):
                for row in partial_journal(process.path/'stderr.bin'):
                    assert not (row[:8]==b'HBWPL001' and u64(row,24)==5 and u64(row,48)==job),'job already completed'
                return pid,dict(job=job,pid=pid,actual_status=capture.blob(raw),first_clock_observed=True,hold_wire_unchanged=True)
            time.sleep(.001)
        raise AssertionError('actual worker did not stop')
    except BaseException:
        os.kill(pid,signal.SIGCONT);raise

def lifecycle(module,bridge,capture,known,invalid,empty,wide,graph):
    rows=[];tag=20001
    caller=Caller(module,bridge,capture,'same-context-valid-invalid-valid')
    try:
        results=[]
        for payload,status in ((known,0),(invalid,1),(known,0)):
            result,parts=complete(caller,bridge,tag,payload);assert u64(result,8)==status
            results.append(dict(tag=tag,result=capture.blob(result),transitions=parts));tag+=1
        rows.append(dict(name=caller.name,results=results))
    finally:caller.close()
    held=[]
    for _ in range(2):
        result=bridge.control(frame(1,tag,hold=1,payload=graph)[8:],'fill-two-real-worker-permits');tag+=1
        assert u64(result,40)==128 and u64(result,80)==0 and u64(result,104)==2
        held.append(u64(result,32))
    for label,payload,status in [('invalid-before-admission',invalid,1),('empty-valid-while-busy',empty,2),('valid-while-busy',known,2)]:
        context=Caller(module,bridge,capture,label);before=len(bridge.commands)
        try:result,parts=context.step(wire(1,tag,payload))
        finally:context.close()
        assert u64(result,8)==status
        assert len(bridge.commands)-before==(0 if status==1 else 1)
        if status==2:assert result[64:]==BUSY
        rows.append(dict(name=label,tag=tag,result=capture.blob(result),transitions=[parts]));tag+=1
    cancelled=bridge.control(frame(3,tag,job=held[0])[8:],'external-held-cancel');tag+=1
    assert u64(cancelled,112)==1 and u64(cancelled,120)==1 and u64(cancelled,160)==2
    context=Caller(module,bridge,capture,'cancelled-worker-still-occupies-permit')
    try:result,parts=context.step(wire(1,tag,known));assert u64(result,8)==2 and result[64:]==BUSY
    finally:context.close()
    rows.append(dict(name=context.name,tag=tag,result=capture.blob(result),transitions=[parts]));tag+=1
    for job in held:bridge.control(frame(7,tag,job=job)[8:],'release-real-qualification-gate');tag+=1
    for job in held:bridge.await_ready(job)
    bridge.control(frame(4,tag,job=held[1])[8:],'take-surviving-held-job');tag+=1
    context=Caller(module,bridge,capture,'own-cancel-and-reuse-with-held-real-worker');stopped=None
    try:
        pending,started=context.step(wire(1,tag,wide));assert u64(pending,8)==3;job=u64(pending,24)
        stopped,stop=stop_after_begin(bridge.process,job,capture)
        cancelled,parts=context.step(wire(3,tag));assert u64(cancelled,8)==4 and len(cancelled)==64
        response=(capture.blobs/bridge.commands[-1]['output']['sha256']).read_bytes()
        assert u64(response,112)==1 and u64(response,120)==1 and u64(response,160)==1
        tag+=1;reused,reuse_parts=complete(context,bridge,tag,known);assert u64(reused,8)==0
        os.kill(stopped,signal.SIGCONT);stopped=None;bridge.await_ready(job)
        rows.append(dict(name=context.name,stopped=stop,pending=capture.blob(pending),cancelled=capture.blob(cancelled),
            reused=capture.blob(reused),transitions=[started,parts]+reuse_parts));tag+=1
    finally:
        if stopped is not None:os.kill(stopped,signal.SIGCONT)
        context.close()
    statistics=bridge.control(frame(5,tag)[8:],'post-cancellation-pool-statistics');tag+=1
    assert u64(statistics,160)==0
    context=Caller(module,bridge,capture,'eof-with-actual-pending-worker')
    try:pending,parts=context.step(wire(1,tag,wide));assert u64(pending,8)==3
    finally:context.close()
    rows.append(dict(name=context.name,pending=capture.blob(pending),transitions=[parts],completion_expected_at_owned_eof=True))
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('build','reference','bridge','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();source=source_check();a.output=a.output.absolute();capture=Capture(a.output)
    expected=json.loads((ROOT/'worker-pin.json').read_bytes());component=json.loads((a.bridge/'component.json').read_bytes())
    assert pin((a.bridge/'component.json').read_bytes())==expected['component']
    domain=json.loads((ROOT/'domain.json').read_bytes());limit=domain['lifecycle_deadline_seconds'];start=time.monotonic();report=dict(status='RUNNING',source_manifest=source)
    try:
        chosen={}
        for index,row,canonical,body in originals(a.reference,ROOT/'reference/params'):
            if row['name'] in ('core-original-known','root-type-0','empty-states','core-original-maximum-4096'):chosen[row['name']]=(canonical,body)
        known,graph=chosen['core-original-known'];invalid=chosen['root-type-0'][0];empty=chosen['empty-states'][0];wide=chosen['core-original-maximum-4096'][0]
        with contextlib.ExitStack() as stack:
            build=json.loads((a.build/'build.json').read_bytes());modules={name:stack.enter_context(NativeModule(Path(row['manifest']),manifest_sha256=row['sha256'])) for name,row in build['files'].items()}
            process=WorkerProcess((a.bridge/'bellman-worker.elf').resolve(strict=True),a.output/'worker',expected_sha=expected['executable']['sha256'],timeout=limit)
            bridge=Bridge(modules,capture,process)
            try:
                controls=abi_controls(modules['bellman_call'],bridge,capture,known)
                rows=lifecycle(modules['bellman_call'],bridge,capture,known,invalid,empty,wide,graph)
            finally:process.close()
            report.update(status='PRIVATE_CALLER_CONTROL_LIFECYCLE_PASS',controls=controls,groups=rows,commands=bridge.commands,
                control_count=len(controls),lifecycle_groups=len(rows),calls=len(capture.calls),actions=len(capture.actions),
                actual_worker_instances=1,wall_seconds=time.monotonic()-start,timeout_seconds=limit,
                full_original_handler_compared=False,public_handler_qualified=False,whole_runtime_replaced=False)
            assert report['wall_seconds']<=limit
    except BaseException as exc:report.update(status='FAIL',exception=type(exc).__name__+': '+str(exc));raise
    finally:capture.close();write(a.output/'report.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in ('controls','groups','commands')},sort_keys=True))
if __name__=='__main__':main()
