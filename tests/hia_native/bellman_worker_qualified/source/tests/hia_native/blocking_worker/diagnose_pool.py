"""Actual HIA permit transitions; this does not simulate actual OS workers."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from diagnose_timed_core import Capture


def frame(command, job=0, now=0, argument=0):
    return b"HBPWRQ01" + struct.pack("<7Q", command, job, now, argument, 0, 0, 0)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root",type=Path,required=True)
    p.add_argument("--build",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    sys.path.insert(0,str(a.source_root/'scripts'))
    from hia_native_loader import NativeModule
    path=a.build/'modules/worker-pool/manifest.json'
    module=NativeModule(path,manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    capture=Capture(a.output)
    sessions=[]
    controls=0
    groups=[]

    def session(capacity=512, output=160):
        s=module.session(output_capacity=output,workspace_capacity=capacity)
        sessions.append(s)
        ctypes.memset(s._output,0xcc,output)
        return s

    def call(s, command, job=0, now=0, argument=0, status=0):
        code,out,w=capture.invoke(s,frame(command,job,now,argument),case=len(groups),phase='pool')
        assert code==128,(command,job,hex(code))
        words=struct.unpack_from('<16Q',out)
        assert words[:4]==(int.from_bytes(b'HBPWRS01','little'),128,status,command),words
        assert words[4]==job or command==1
        assert out[128:]==bytes([0xcc])*(s.output_capacity-128)
        assert words[12]==struct.unpack_from('<Q',w,24)[0]
        assert words[13]==struct.unpack_from('<Q',w,64)[0]
        return words

    def refuse(s,wire,expected=0xffffffff):
        nonlocal controls
        before_o=s._output.raw[:s.output_capacity]
        before_w=s._workspace.raw[:s.workspace_capacity]
        code,out,w=capture.invoke(s,wire,case=len(groups),phase='atomic-refusal')
        assert code==expected and out==before_o and w==before_w,(hex(code),hex(expected))
        controls+=1

    try:
        s=session();call(s,0)
        a1=call(s,1)[4];b1=call(s,1)[4]
        assert(a1,b1)==(1,2)
        call(s,1,status=1)
        # No cancellation can split acquisition and actual submission within
        # the original first poll. The mechanical bridge must finish that edge.
        refuse(s,frame(6,a1));refuse(s,frame(9))
        call(s,2,a1);call(s,2,b1)
        call(s,3,a1,100);call(s,3,b1,101)
        call(s,4,a1,status=3)
        cancelled=call(s,6,a1)
        assert cancelled[6:8]==(1,1) and cancelled[12]==2
        call(s,1,status=1)
        finished=call(s,5,b1,102,200)
        assert finished[5]==4 and finished[7]==0 and finished[12]==1
        c1=call(s,1)[4]
        assert c1==3
        taken=call(s,7,b1);assert taken[6]==2 and taken[11]==0
        reaped=call(s,8,b1);assert reaped[13]==2
        call(s,2,c1);call(s,3,c1,200);call(s,5,c1,201,272)
        call(s,8,c1);taken=call(s,7,c1);assert taken[13]==1
        call(s,5,a1,103,200);done=call(s,8,a1);assert done[12:14]==(0,0)
        for old in [a1,b1,c1]:
            for command in [2,3,4,5,6,7,8,11,12]:
                refuse(s,frame(command,old,1000 if command in (3,5,12) else 0,1 if command in (11,12) else 0))
        groups.append('worker-owned-permit-outlives-caller-and-precedes-reap')

        # Complete results are distinct from occupied permits: 40 active
        # callers can retain ready results while each released permit is reused.
        pending=[]
        for i in range(40):
            before=s._workspace.raw[:s.workspace_capacity]
            code,out,w=capture.invoke(s,frame(1),case=len(groups),phase='admit-or-grow')
            if code==0xffffffd0:
                assert out[:8]==b'HGRWS002' and struct.unpack_from('<Q',out,8)[0]==1 and w==before
                required=struct.unpack_from('<Q',out,16)[0]
                assert required==struct.unpack_from('<Q',w,72)[0]+128
                grown=session(required+128)
                ctypes.memset(grown._workspace,0xa7,grown.workspace_capacity)
                ctypes.memmove(grown._workspace,w,len(w))
                s=grown
                job=call(s,1)[4]
            else:
                assert code==128 and struct.unpack_from('<Q',out,16)[0]==0
                job=struct.unpack_from('<Q',out,32)[0]
            call(s,2,job);call(s,3,job,10000+i);call(s,5,job,11000+i,128)
            call(s,8,job);pending.append(job)
        stats=call(s,10);assert stats[12]==0 and stats[13]==40
        for job in reversed(pending):call(s,7,job)
        assert call(s,10)[13]==0
        groups.append('ready-results-growth-and-stale-id-isolation')

        job=call(s,1)[4];call(s,2,job);call(s,3,job,50000)
        call(s,9)
        assert call(s,10)[12]==1
        call(s,1,status=2)
        call(s,5,job,51000,200)
        assert call(s,10)[12]==0
        call(s,8,job);assert call(s,10)[13]==0
        groups.append('eof-cancels-callers-and-drains-permits')

        f=session();call(f,0)
        job=call(f,1)[4]
        refused=call(f,11,job,0,12,status=5);assert refused[11]==257 and refused[12]==0
        call(f,7,job)
        job=call(f,1)[4];call(f,2,job);call(f,6,job)
        failed=call(f,12,job,77,9);assert failed[11]==513 and failed[13]==0
        job=call(f,1)[4];call(f,2,job);call(f,3,job,1);call(f,12,job,2,9);call(f,7,job)
        assert call(f,10)[13]==0
        groups.append('explicit-mechanical-failure-custody')

        high=session();call(high,0)
        job=call(high,1)[4];call(high,2,job)
        refuse(high,frame(3,job,18446744043709551616))
        entered=call(high,3,job,18446744043709551615)
        assert entered[9]==18446744073709551615
        refuse(high,frame(5,job,18446744043709551614,200))
        call(high,5,job,18446744073709551615,200);call(high,7,job);call(high,8,job)
        groups.append('exact-thirty-second-anchor-and-overflow-refusal')

        clean=session();call(clean,0)
        for size in [0,1,7,8,63,65]:refuse(clean,(frame(10)+bytes(65))[:size])
        for offset in [0,40,48,56]:
            wire=bytearray(frame(10));wire[offset]^=1;refuse(clean,bytes(wire))
        for command in [0,13,2,3,4,5,6,7,8,11,12]:refuse(clean,frame(command))
        snapshot=clean._workspace.raw[:clean.workspace_capacity]
        for offset in range(0,128,8):
            mutated=bytearray(snapshot);mutated[offset]^=1
            ctypes.memmove(clean._workspace,bytes(mutated),len(mutated))
            # Closed=1 is a valid state with no live records; all other lone
            # word mutations break a declared invariant.
            if offset==16:call(clean,10)
            else:refuse(clean,frame(10))
            ctypes.memmove(clean._workspace,snapshot,len(snapshot))
        for capacity in [0,1,127]:
            small=session(512,capacity);refuse(small,frame(0),0xfffffffe)
            small=session(capacity,160);refuse(small,frame(0),0xfffffffe)
        groups.append('complete-buffer-invalid-state-and-capacity-atomicity')
        report={'schema':'hepta.runtime.blocking-worker-pool.diagnostic.v1','status':'PASS','groups':groups,
                'native_calls':len(capture.rows),'atomic_refusals':controls,'complete_buffer_bytes':capture.bytes,
                'source_sha256':module.metadata['source_sha256'],'image_sha256':module.metadata['image_sha256'],
                'synthetic_events':True,'actual_worker_qualified':False,'rust_executed':False}
        (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print(json.dumps(report,sort_keys=True))
    finally:
        capture.close()
        for s in sessions:s.close()
        module.close()


if __name__=='__main__':main()
