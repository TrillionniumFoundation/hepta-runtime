"""All numerical deadline edges and complete-buffer continuation controls."""
from __future__ import annotations
import argparse,ctypes,json,struct,sys
from pathlib import Path
from diagnose_timed_core import Capture,sha,YIELD,DEADLINE

INVALID=0xffffffff
CAPACITY=0xfffffffd
START=1000000000000
END=START+30000000000

def initial(job=1,start=START):return b'HBTMIN01'+struct.pack('<7Q',job,start,1,0,0,0,0)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source-root','build','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.source_root/'scripts'));sys.path.insert(0,str(Path(__file__).parent/'reference'))
    from hia_native_loader import NativeModule
    from qualify_bellman import terminal,pack_graph
    graph=[[terminal(float(i+1))]+[None]*5 for i in range(3)];wire=pack_graph(graph)
    expected=[[1,1,i] for i in range(3)]+[[2,2,0]]+[[1,3,i] for i in range(3)]+[[1,4,i] for i in range(3)]+[[1,5,0]]
    manifest=a.build/'modules/timed-core/manifest.json';capture=Capture(a.output);sessions=[];rows=[];atomic=0
    with NativeModule(manifest,manifest_sha256=sha(manifest.read_bytes())) as module:
        def session(output=360,workspace=856):
            s=module.session(output_capacity=output,workspace_capacity=workspace);sessions.append(s);ctypes.memset(s._output,0xcc,output);return s
        def call(s,data,phase):return capture.invoke(s,data,case=len(rows),phase=phase)
        def refuse(s,data,phase,code=INVALID):
            nonlocal atomic
            before_o=s._output.raw[:s.output_capacity];before_w=s._workspace.raw[:s.workspace_capacity]
            result,out,work=call(s,data,phase);assert result==code and out==before_o and work==before_w,(phase,hex(result));atomic+=1
        try:
            # Every original state/final checkpoint refuses exactly at end.
            # The companion success trace supplies end-1 to every clock.
            for stop in [None,*range(10),'after-end','commit-error']:
                s=session();result,_,_=call(s,initial(),'init');assert result==64
                ctypes.memset(s._output,0xcc,360);clock=0;effects=[]
                while True:
                    code,out,work=call(s,wire,'resume')
                    if code!=YIELD:break
                    assert out==bytes([0xcc])*360
                    e=struct.unpack_from('<16Q',work,600);effects.append(list(e[2:3]+e[4:6]))
                    assert e==(int.from_bytes(b'HBTMEF01','little'),len(effects),*expected[len(effects)-1][:1],1,*expected[len(effects)-1][1:],START,END,len(wire),360,344,0,0,0,0,0)
                    now=0;child=0
                    if e[2]==1:
                        now=END-1
                        if stop==clock:now=END
                        elif stop=='after-end' and clock==0:now=END+1
                        clock+=1
                    elif stop=='commit-error':child=0xfffffde1
                    ack=b'HBTMAK01'+struct.pack('<7Q',e[1],e[2],1,now,child,0,0)
                    ctypes.memmove(ctypes.addressof(s._workspace)+728,ack,64)
                if stop is None:assert code==344 and effects==expected
                elif stop=='commit-error':assert code==0xfffffde1 and effects==expected[:4] and out==bytes([0xcc])*360
                else:assert code==DEADLINE and out==bytes([0xcc])*360
                refuse(s,wire,'terminal-resume');refuse(s,initial(),'terminal-reinitialize')
                rows.append({'domain':'clock-edge','stop':stop,'code':code,'effects':effects})

            s=session();call(s,initial(),'init');ctypes.memset(s._output,0xcc,360);code,_,work=call(s,wire,'resume');assert code==YIELD
            saved=work;ack=b'HBTMAK01'+struct.pack('<7Q',1,1,1,START+1,0,0,0)
            for offset,value in [(0,0),(8,2),(16,2),(24,2),(32,START-1),(40,1),(48,1),(56,1)]:
                bad=bytearray(ack);struct.pack_into('<Q',bad,offset,value);ctypes.memmove(ctypes.addressof(s._workspace)+728,bytes(bad),64)
                refuse(s,wire,'bad-ack-'+str(offset))
            restored=bytearray(saved);restored[728:792]=ack;saved=bytes(restored)
            ctypes.memmove(s._workspace,saved,len(saved))
            for offset in [0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152,248,256,264,272,280,288,296,304,312,320,328,336,344,376,448,504]:
                mutated=bytearray(saved);mutated[344+offset]^=1
                if offset==40:struct.pack_into('<Q',mutated,344+offset,START+2)
                ctypes.memmove(s._workspace,bytes(mutated),len(mutated))
                refuse(s,wire,'bad-state-'+str(offset));ctypes.memmove(s._workspace,saved,len(saved))
            for data in [b'',wire[:-1],wire+b'X',b'X'+wire[1:],wire[:8]+struct.pack('<Q',2)+wire[16:]]:refuse(s,data,'bad-resume-input')
            ctypes.memmove(ctypes.addressof(s._workspace)+728,ack,64);code,_,_=call(s,wire,'valid-ack-recovery');assert code==YIELD
            ctypes.memmove(ctypes.addressof(s._workspace)+728,ack,64);refuse(s,wire,'stale-ack')
            rows.append({'domain':'ack-state-input-atomicity','recovered':True})

            for data in [initial(0),initial(start=18446744043709551616),b'X'+initial()[1:],initial()[:-1],initial()+b'X']:
                s=session();refuse(s,data,'bad-initial')
            for offset in [24,32,40,48,56]:
                data=bytearray(initial());struct.pack_into('<Q',data,offset,2);s=session();refuse(s,bytes(data),'bad-init-word-'+str(offset))
            for offset in range(0,512,8):
                s=session();ctypes.memmove(ctypes.addressof(s._workspace)+344+offset,struct.pack('<Q',1),8);refuse(s,initial(),'dirty-init-'+str(offset))
            for out,work in [(0,856),(1,856),(63,856),(360,0),(360,639),(360,641)]:
                s=session(out,work);refuse(s,initial(),'capacity',CAPACITY)
            s=session(64,640);code,_,_=call(s,initial(),'minimum-init');assert code==64;refuse(s,wire,'numerical-capacity',CAPACITY)
            rows.append({'domain':'initial-state-and-capacity'})
            report={'status':'NATIVE_TIMED_CORE_CONTROLS_PASS','groups':rows,'native_calls':len(capture.rows),'atomic_refusals':atomic,
                    'complete_buffer_bytes':capture.bytes,'unique_buffer_bytes':capture.unique_bytes,
                    'source_sha256':module.metadata['source_sha256'],'image_sha256':module.metadata['image_sha256'],
                    'synthetic_clock_acknowledgements':True,'actual_kernel_deadline_qualified':False,'rust_executed':False}
            (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))
        finally:
            capture.close()
            for s in sessions:s.close()

if __name__=='__main__':main()
