"""Actual owned workers, cancellation, retained results and real clock boundaries."""
from __future__ import annotations
import argparse,json,struct,time
from pathlib import Path
from worker_transport import WorkerProcess
from worker_evidence import decode_body,verify_process,words
from worker_cases import graph_cases

def graph(value):return b'HIABELL1'+struct.pack('<Q',1)+struct.pack('<Qd',1,float(value))+bytes(704)

class Client:
    def __init__(self,process):self.process=process;self.tag=0;self.ready={}
    def call(self,command,job=0,hold=0,payload=b''):
        self.tag+=1;tag=self.tag;self.process.send(command,tag,job=job,hold=hold,payload=payload)
        while True:
            value=self.process.next()
            if value['kind']==2:
                assert value['job'] not in self.ready;self.ready[value['job']]=value;continue
            assert value['tag']==tag
            return value
    def completion(self,job):
        while job not in self.ready:
            value=self.process.next();assert value['kind']==2 and value['job'] not in self.ready
            self.ready[value['job']]=value
        return self.ready.pop(job)
    def submit(self,value,hold=0,refused=False):
        event=self.call(1,hold=hold,payload=graph(value));w=words(event['pool'])
        assert event['code']==128 and w[2]==int(refused)
        if refused:assert event['job']==0;return 0
        assert w[5]==2 and event['job']==w[4]
        return event['job']
    def stats(self):
        event=self.call(5);assert event['code']==128
        return words(event['pool'])
    def release(self,job):return self.call(7,job)
    def take(self,job,value=None,code=0):
        ready=self.completion(job);assert ready['code']==code,(job,ready['code'],code)
        event=self.call(4,job);assert event['code']==code
        h,parts,result=decode_body(event['body'])
        if value is not None:assert result['states']==[{'action':0,'q':[float(value),None,None,None,None,None],'value':float(value)}]
        return h,parts,result

def lifetime(client):
    assert client.stats()[12:14]==[0,0]
    a=client.submit(1,1);b=client.submit(2,1)
    assert (a,b)==(1,2);client.submit(99,refused=True)
    cancelled=client.call(3,a);w=words(cancelled['pool']);assert w[6:8]==[1,1] and w[12]==2
    client.submit(99,refused=True)
    client.release(a);assert client.completion(a)['code']==0
    assert client.stats()[12]==1
    c=client.submit(3,1);assert c==3
    invalid=client.call(4,a);assert invalid['code']==0xffffffff and invalid['body']==b''
    client.release(b);client.release(c);client.take(b,2);client.take(c,3)
    assert client.stats()[12]==0
    # A ready but unconsumed result retains its own mapping, not a worker permit.
    d=client.submit(4);ready=client.completion(d);client.ready[d]=ready
    e=client.submit(5,1);f=client.submit(6,1);client.submit(99,refused=True)
    assert client.stats()[12]==2
    client.take(d,4);assert client.stats()[12]==2
    client.release(e);client.release(f);client.take(f,6);client.take(e,5)

def retained(client):
    jobs=[]
    for i in range(40):
        job=client.submit(i+.25);ready=client.completion(job);client.ready[job]=ready;jobs.append((job,i+.25))
    assert client.stats()[12:14]==[0,40]
    for job,value in reversed(jobs):client.take(job,value)
    assert client.stats()[12]==0

def eof_drain(client):
    # Both holds are physically released before EOF; the parent then drops
    # callers and drains the already admitted work without taking results.
    a=client.submit(1,1);b=client.submit(2,1)
    client.release(a);client.release(b)

def ordinary(client,cohort):
    from qualify_bellman import pack_graph,reference
    cases=graph_cases();bounds=[0,91,182,273,363];rows=[]
    for index in range(bounds[cohort],bounds[cohort+1]):
        name,description,error=cases[index]
        response=client.call(1,payload=pack_graph(description));pw=words(response['pool'])
        assert response['code']==128 and pw[2]==0 and pw[5]==2
        job=response['job'];h,parts,result=client.take(job,code=error or 0)
        if error is None:
            assert parts[0]==reference(description),(name,'full core frame differs')
            assert result['state_count']==len(description) and result['native_operation_wall_seconds']>=0
        rows.append({'case':index,'name':name,'job':job,'code':error or 0})
        (client.process.path/'ordinary.progress.json').write_text(json.dumps(rows,sort_keys=True)+'\n')
    return rows

def held(client,mode):
    job=client.submit(7,mode)
    # Wait for the actual bridge journal to observe the selected boundary.
    process=client.process
    while True:
        raw=(process.path/'stderr.bin').read_bytes()
        marker=b'HBPWHLD1'+struct.pack('<Q',64)+struct.pack('<Q',job)
        if marker in raw:break
        assert time.monotonic()<process.deadline-31
        time.sleep(.005)
    event=client.call(2,job);w=words(event['pool'])
    assert w[7]==1 and w[12]==1
    if mode==1:
        assert w[5]==2 and w[8:10]==[0,0]
        until=time.monotonic()+30.025
    else:
        assert w[5]==3 and w[9]-w[8]==30000000000
        until=w[9]/1e9+.025
    while True:
        remaining=until-time.monotonic()
        if remaining<=0:break
        time.sleep(min(.25,remaining))
    # Deadline expiry by itself cannot release a still-running permit.
    assert client.stats()[12]==1
    client.release(job)
    code={1:0,2:0xfffffdf0,3:0xfffffde1,4:0}[mode]
    h,parts,result=client.take(job,7 if code==0 else None,code)
    if mode==1:assert result['native_operation_wall_seconds']<30
    if mode==4:assert result['native_operation_wall_seconds']>=30

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bridge',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--group',choices=['lifetime','retained','eof','held1','held2','held3','held4','ordinary0','ordinary1','ordinary2','ordinary3'],required=True);a=p.parse_args()
    component=json.loads((a.bridge/'component.json').read_bytes())
    process=WorkerProcess(a.bridge/'bellman-worker.elf',a.output,expected_sha=component['executable_sha256'])
    try:
        client=Client(process)
        if a.group.startswith('held'):held(client,int(a.group[-1]))
        elif a.group.startswith('ordinary'):
            graph_cases()
            ordinary(client,int(a.group[-1]))
        else:{'lifetime':lifetime,'retained':retained,'eof':eof_drain}[a.group](client)
    finally:process.close()
    report=verify_process(a.output,component);report['group']=a.group
    (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
