"""Actual HIA elapsed conversion with complete buffers and recovery controls."""
from __future__ import annotations
import argparse,ctypes,json,struct,sys
from pathlib import Path
from diagnose_timed_core import Capture,sha
from worker_cases import duration_cases

def frame(start,now):return b'HBELRQ01'+struct.pack('<3Q',start,now,0)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source-root','build','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.source_root/'scripts'))
    from hia_native_loader import NativeModule
    manifest=a.build/'modules/elapsed/manifest.json';capture=Capture(a.output);sessions=[];controls=0;results=[]
    with NativeModule(manifest,manifest_sha256=sha(manifest.read_bytes())) as module:
        try:
            session=module.session(output_capacity=40,workspace_capacity=32);sessions.append(session)
            ctypes.memset(session._output,0xa5,40);ctypes.memset(session._workspace,0x5a,32)
            for case,ns in enumerate(duration_cases()):
                for start in [0,(1<<64)-1-ns]:
                    code,out,work=capture.invoke(session,frame(start,start+ns),case=case,phase='ordinary')
                    seconds,nanos=divmod(ns,1000000000);expected=struct.unpack('<Q',struct.pack('<d',float(seconds)+float(nanos)/1e9))[0]
                    assert code==24 and out==b'HBELRS01'+struct.pack('<2Q',expected,ns)+bytes([0xa5])*16 and work==bytes([0x5a])*32
                results.append({'nanoseconds':ns,'bits':expected})
            base=frame(1,2);mutations=[b'',base[:7],base[:31],base+b'X',b'X'+base[1:],frame(2,1)]
            for offset in range(24,32):
                wire=bytearray(base);wire[offset]=1;mutations.append(bytes(wire))
            for wire in mutations:
                before_out=session._output.raw[:40];before_work=session._workspace.raw[:32]
                code,out,work=capture.invoke(session,wire,case=controls,phase='invalid')
                assert code==0xffffffff and out==before_out and work==before_work
                code,out,work=capture.invoke(session,base,case=controls,phase='recovery');assert code==24
                controls+=1
            for size in [0,1,7,8,23]:
                small=module.session(output_capacity=size,workspace_capacity=0);sessions.append(small)
                ctypes.memset(small._output,0xa5,size)
                code,out,work=capture.invoke(small,base,case=controls,phase='capacity')
                assert code==0xfffffffd and out==bytes([0xa5])*size and work==b'';controls+=1
            report={'status':'NATIVE_ELAPSED_PASS','cases':len(results),'native_calls':len(capture.rows),'controls':controls,
                    'complete_buffer_bytes':capture.bytes,'image_sha256':module.metadata['image_sha256'],
                    'source_sha256':module.metadata['source_sha256'],'results':results,'original_executed':False}
            (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
            print(json.dumps({k:v for k,v in report.items() if k!='results'},sort_keys=True))
        finally:
            capture.close()
            for session in sessions:session.close()

if __name__=='__main__':main()
