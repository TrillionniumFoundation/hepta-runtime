"""Initial real-kernel smoke. No fresh original or full-worker qualification claim."""
from __future__ import annotations
import argparse,json,struct,sys
from pathlib import Path
from worker_transport import WorkerProcess,decode_journal,sha

def main():
    p=argparse.ArgumentParser();p.add_argument('--bridge',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    component=json.loads((a.bridge/'component.json').read_bytes());exe=a.bridge/'bellman-worker.elf'
    graph=b'HIABELL1'+struct.pack('<Q',1)+struct.pack('<Qd',1,2.5)+bytes(720-16)
    proc=WorkerProcess(exe,a.output,expected_sha=component['executable_sha256'])
    try:
        proc.send(5,1);stats=proc.next();assert stats['kind']==1 and stats['code']==128 and struct.unpack_from('<Q',stats['pool'],96)[0]==0
        proc.send(1,2,payload=graph);admitted=proc.next();assert admitted['kind']==1 and admitted['job']==1 and struct.unpack_from('<Q',admitted['pool'],40)[0]==2,admitted
        ready=proc.next();assert ready['kind']==2 and ready['job']==1 and ready['code']==0,ready
        proc.send(4,3,job=1);taken=proc.next();assert taken['kind']==1 and taken['code']==0 and taken['job']==1,taken
        body=taken['body'];head=struct.unpack_from('<12Q',body)
        assert body[:8]==b'HBWKBOD1' and head[1]==len(body) and head[2]==200 and len(body)==96+sum(head[2:5])
        core=body[96:96+head[2]];commit=body[96+head[2]:96+head[2]+head[3]];render=body[96+head[2]+head[3]:]
        assert core[:8]==b'HIABPLN1' and commit[:8]==b'HBCMTRES' and render[:8]==b'HBLMRS01'
        value=json.loads(render[64:]);assert len(value)==36 and value['states']==[{'action':0,'q':[2.5,None,None,None,None,None],'value':2.5}]
        assert value['native_operation_wall_seconds']==struct.unpack('<d',struct.pack('<Q',head[7]))[0]
        assert head[5]<=head[11]<=head[6]
        seconds,nanos=divmod(head[11]-head[5],1000000000)
        assert value['native_operation_wall_seconds']==float(seconds)+float(nanos)/1e9
        assert head[6]>=head[5] and value['native_operation_wall_seconds']>0
        proc.send(5,4);after=proc.next();assert struct.unpack_from('<Q',after['pool'],96)[0]==0
    finally:proc.close()
    journal=decode_journal((a.output/'stderr.bin').read_bytes())
    final=[raw for magic,raw in journal if magic==b'HBWPEND1'];assert len(final)==1
    assert struct.unpack_from('<Q',final[0],64+24)[0]==0 and struct.unpack_from('<Q',final[0],64+64)[0]==0
    report={'status':'REAL_KERNEL_SMOKE_PASS','source_sha256':component['sources'],'executable_sha256':sha(exe.read_bytes()),
            'journal_records':len(journal),'clock_records':sum(m==b'HBCLOCK1' for m,_ in journal),'response_bytes':proc.receipt['stdout']['bytes'],
            'actual_worker_qualified':False,'original_executed':False,'public_handler_qualified':False}
    (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
