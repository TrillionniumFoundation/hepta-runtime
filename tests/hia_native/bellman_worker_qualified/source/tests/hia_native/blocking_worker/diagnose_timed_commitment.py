"""Compare HIA writes to retained fresh original Serde writes; clocks are typed controls."""
from __future__ import annotations
import argparse
import ctypes
import json
from pathlib import Path
import struct
import sys
import time
from diagnose_timed_core import Capture, ORIGINAL_SHA, Q, YIELD, sha
DEADLINE = 0xfffffde1

def wire_for(value):
    out = bytearray(b'HBCMT001' + bytes.fromhex(ORIGINAL_SHA) + b'HIABELL1' + struct.pack('<Q', len(value['states'])))
    for state in value['states']:
        for action in state['actions']:
            raw = bytearray(120)
            if action is not None:
                if action['kind'] == 'terminal':
                    struct.pack_into('<Qd', raw, 0, 1, action['value'])
                else:
                    struct.pack_into('<QQQ', raw, 0, 2, 0, len(action['branches']))
                    for i, branch in enumerate(action['branches']):
                        struct.pack_into('<dQdd', raw, 24 + i * 32, branch['probability'], branch['successor'], branch['reward'], branch['fee'])
            out.extend(raw)
    return bytes(out)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',required=True,type=Path)
    p.add_argument('--build',required=True,type=Path)
    p.add_argument('--trace',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--all-timeouts',action='store_true')
    a=p.parse_args()
    sys.path.insert(0,str(a.source_root/'scripts'))
    from hia_native_loader import NativeModule
    def module(name):
        path=a.build/'modules'/name/'manifest.json'
        return NativeModule(path,manifest_sha256=sha(path.read_bytes()))
    old,current=module('commitment'),module('timed-commitment')
    trace_lines=(a.trace/'processes/writer-trace.stdout').read_bytes().splitlines()
    input_lines=(a.trace/'writer.inputs.jsonl').read_bytes().splitlines()
    assert len(trace_lines)==len(input_lines)==6
    capture=Capture(a.output)
    rows=[]; started=time.monotonic(); atomic=0; timeout_cases=0
    try:
        for case,(input_line,line) in enumerate(zip(input_lines,trace_lines)):
            observed=json.loads(line);assert observed['index']==case
            trace=observed['trace'];fragments=[bytes.fromhex(x) for x in trace['write_calls']]
            canonical=bytes.fromhex(trace['canonical_hex']);assert b''.join(fragments)==canonical
            assert sha(canonical)==trace['request_sha256'] and trace['original_source_sha256']==ORIGINAL_SHA
            wire=wire_for(json.loads(input_line));capacity=128+len(canonical)+16
            with old.session(output_capacity=capacity,workspace_capacity=32768) as previous:
                ctypes.memset(previous._output,0xcc,capacity)
                old_code,old_output,_=capture.invoke(previous,wire,case=case,phase='old')
                assert old_code==128+len(canonical) and old_output[128:old_code]==canonical
                assert old_output[16:48].hex()==trace['request_sha256']
            controls=[None]
            if a.all_timeouts:controls.extend(range(len(fragments)))
            else:controls.extend(sorted({0,len(fragments)//2,len(fragments)-1}))
            for timeout_at in controls:
                with current.session(output_capacity=capacity,workspace_capacity=32768) as session:
                    start=1000000000000+case*100000000000;job=case+1;t=session.workspace_capacity-512
                    init=b'HBTCIN01'+struct.pack('<7Q',job,start,1,0,0,0,0)
                    code,out,work=capture.invoke(session,init,case=case,phase='initialize')
                    assert code==64 and out[:8]==b'HBTCIR01'
                    ctypes.memset(session._output,0xcc,capacity)
                    stage='success' if timeout_at is None else 'deadline-'+str(timeout_at)
                    seen=[];prefix=0
                    while True:
                        code,out,work=capture.invoke(session,wire,case=case,phase=stage)
                        if code!=YIELD:break
                        assert out==bytes([0xcc])*capacity
                        effect=struct.unpack_from('<16Q',work,t+256)
                        assert effect[0]==int.from_bytes(b'HBTCEF01','little') and effect[1]==len(seen)+1 and effect[2:4]==(1,job)
                        assert effect[6:8]==(start,start+30000000000) and effect[8]==prefix and not any(effect[13:])
                        size=effect[9];fragment=work[t+224:t+224+size]
                        assert fragment==fragments[len(seen)] and work[t+224+size:t+256]==bytes(32-size),(case,len(seen),fragment)
                        now=start+len(seen)+1
                        if timeout_at==len(seen):now=start+30000000000
                        ack=b'HBTCAK01'+struct.pack('<7Q',effect[1],1,job,now,0,0,0)
                        if timeout_at is None and case==3 and not seen:
                            for offset,value in [(0,0),(8,2),(16,2),(24,job+1),(32,start-1),(40,1),(48,1),(56,1)]:
                                bad=bytearray(ack);struct.pack_into('<Q',bad,offset,value)
                                ctypes.memmove(ctypes.addressof(session._workspace)+t+384,bytes(bad),64)
                                before=bytes(session._workspace.raw[:session.workspace_capacity]);prior=bytes(session._output.raw[:capacity])
                                result,after_o,after_w=capture.invoke(session,wire,case=case,phase='bad-ack-'+str(offset))
                                assert result==0xffffffff and before==after_w and prior==after_o
                                atomic+=1
                        ctypes.memmove(ctypes.addressof(session._workspace)+t+384,ack,64)
                        seen.append(fragment)
                        if now<start+30000000000:prefix+=size
                    if timeout_at is None:
                        assert seen==fragments and code==old_code and out==old_output,(case,hex(code),hex(old_code))
                        rows.append({'case':case,'writes':len(seen),'canonical_bytes':len(canonical),'request_sha256':sha(canonical),
                                     'input_sha256':sha(wire),'output_sha256':sha(out)})
                    else:
                        assert len(seen)==timeout_at+1 and code==DEADLINE and out==bytes([0xcc])*capacity
                        assert Q.unpack_from(work,t+128)[0]==prefix and work[16384:16384+prefix]==b''.join(fragments[:timeout_at])
                        timeout_cases+=1
                    (a.output/'progress.json').write_text(json.dumps({'case':case,'control':stage,'calls':len(capture.rows)})+'\n')
        report={'schema':'hepta.runtime.bellman-timed-commitment.diagnostic.v1','status':'PASS','cases':len(rows),
                'actual_native_calls':len(capture.rows),'original_write_boundaries':sum(x['writes'] for x in rows),
                'synthetic_deadline_refusals':timeout_cases,'atomic_ack_refusals':atomic,'rows':rows,
                'complete_buffer_bytes':capture.bytes,'unique_buffer_bytes':capture.unique_bytes,
                'source_sha256':current.metadata['source_sha256'],'image_sha256':current.metadata['image_sha256'],
                'original_trace_stdout_sha256':sha((a.trace/'processes/writer-trace.stdout').read_bytes()),
                'elapsed_seconds':time.monotonic()-started,'rust_executed':False,'actual_kernel_deadline_qualified':False}
        (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print(json.dumps({k:v for k,v in report.items() if k!='rows'},sort_keys=True))
    finally:
        capture.close();old.close();current.close()

if __name__=='__main__':main()
