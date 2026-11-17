"""Read complete owned Bellman worker streams without executing native code."""
from __future__ import annotations
import hashlib,json,struct
from pathlib import Path
from worker_transport import decode_journal

INVALID=0xffffffff
GROW=0xffffffd0

def sha(value):return hashlib.sha256(value).hexdigest()
def words(value):
    assert len(value)%8==0
    return list(struct.unpack('<'+'Q'*(len(value)//8),value))
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def packets(raw):
    result=[];at=0
    while at<len(raw):
        assert len(raw)-at>=8,('partial packet header',at)
        size=struct.unpack_from('<Q',raw,at)[0];assert size<=128<<20 and at+8+size<=len(raw)
        result.append(raw[at+8:at+8+size]);at+=8+size
    assert at==len(raw)
    return result

class Pool:
    """Independent integer reference of the private permit and result lifetime."""
    def __init__(self):
        self.header=[0]*16;self.slots=[];self.capacity=4096;self.initialized=False
    def retire(self,slot):
        if slot[1]==4 and slot[2]!=0 and slot[9]==1:
            slot[:]=[0]*16;self.header[8]-=1;self.header[10]+=1
    def response(self,command,job=0,slot=None,status=0):
        result=[int.from_bytes(b'HBPWRS01','little'),128,status,command,job]+[0]*7
        if slot is not None:result[5:12]=[slot[1],slot[2],slot[3],slot[4],slot[5],slot[8],slot[9]|(slot[10]<<8)]
        result.extend([self.header[3],self.header[8],self.header[4],self.header[5]])
        assert len(result)==16
        return struct.pack('<16Q',*result)
    def invoke(self,request):
        r=words(request);assert len(r)==8 and request[:8]==b'HBPWRQ01' and r[5:]==[0,0,0]
        command,job,now,arg=r[1:5]
        assert command<=12 and (command in [3,5,12] or now==0) and (command in [5,11,12] or arg==0)
        if command==0:
            assert not self.initialized and r[2:]==[0]*6
            self.initialized=True;self.header[0]=int.from_bytes(b'HBPWST01','little');self.header[9]=128
            return 128,self.response(0)
        assert self.initialized
        if command==10:return 128,self.response(command)
        if command==9:
            assert not any(s[1]==1 for s in self.slots)
            self.header[2]=1
            for s in self.slots:
                if s[0] and not s[2]:s[2]=1;self.header[6]+=1;self.retire(s)
            return 128,self.response(command)
        if command==1:
            if self.header[2]:return 128,self.response(command,status=2)
            if self.header[3]==2:return 128,self.response(command,status=1)
            if self.header[1]==(1<<64)-1:return 128,self.response(command,status=5)
            slot=next((s for s in self.slots if s[0]==0),None)
            if slot is None:
                required=self.header[9]+128
                if required>self.capacity:
                    result=b'HGRWS002'+struct.pack('<3Q',1,required,0)+bytes(96)
                    self.capacity=(required+4095)&~4095
                    return GROW,result
                slot=[0]*16;self.slots.append(slot);self.header[9]+=128
            self.header[1]+=1;slot[:4]=[self.header[1],1,0,1];self.header[3]+=1;self.header[8]+=1
            return 128,self.response(command,slot[0],slot)
        slot=next((s for s in self.slots if s[0]==job and job!=0),None)
        if slot is None:return INVALID,bytes(128)
        phase,caller=slot[1:3]
        if command==2:
            if phase!=1:return INVALID,bytes(128)
            slot[1]=2;self.header[4]+=1
        elif command==3:
            if phase!=2 or now>(1<<64)-1-30000000000:return INVALID,bytes(128)
            slot[1]=3;slot[4:6]=[now,now+30000000000];self.header[11]+=1
        elif command==4:
            if caller!=0:return INVALID,bytes(128)
            return 128,self.response(command,job,slot,0 if phase==4 else 3)
        elif command==5:
            if phase!=3 or now<slot[4]:return INVALID,bytes(128)
            slot[1]=4;slot[3]=0;slot[6]=now;slot[8]=arg;self.header[3]-=1;self.header[5]+=1
        elif command==6:
            if phase==1 or caller==2:return INVALID,bytes(128)
            if caller==0:slot[2]=1;self.header[6]+=1
        elif command==7:
            if caller!=0:return INVALID,bytes(128)
            if phase!=4:return 128,self.response(command,job,slot,3)
            slot[2]=2;self.header[7]+=1
        elif command==8:
            if phase!=4 or slot[9]:return INVALID,bytes(128)
            slot[9]=1
        elif command==11:
            if phase!=1 or not 1<=arg<=4095:return INVALID,bytes(128)
            slot[1]=4;slot[3]=0;slot[8:11]=[arg,1,1];self.header[3]-=1;self.header[5]+=1;self.header[12]+=1
            return 128,self.response(command,job,slot,5)
        elif command==12:
            if phase not in [2,3] or arg==0 or now<slot[4]:return INVALID,bytes(128)
            slot[1]=4;slot[3]=0;slot[6]=now;slot[8:11]=[arg,1,2];self.header[3]-=1;self.header[5]+=1
        result=bytearray(self.response(command,job,slot))
        if command in [6,7,8,12]:
            self.retire(slot);struct.pack_into('<Q',result,104,self.header[8])
        assert 0<=self.header[3]<=2
        return 128,bytes(result)
    def complete_state(self):
        values=self.header+[v for s in self.slots for v in s]
        result=struct.pack('<'+'Q'*len(values),*values)
        assert len(result)==self.header[9] and len(result)<=self.capacity
        return result+bytes(self.capacity-len(result))

def decode_body(body):
    assert len(body)>=96 and body[:8]==b'HBWKBOD1'
    h=words(body[:96]);assert h[1]==len(body)==96+sum(h[2:5])
    at=96;parts=[]
    for size in h[2:5]:parts.append(body[at:at+size]);at+=size
    if h[9]==0:
        core,commit,render=parts
        assert core[:8]==b'HIABPLN1' and commit[:8]==b'HBCMTRES' and render[:8]==b'HBLMRS01'
        rh=words(render[:64]);assert rh[1]==0 and rh[2]==len(render)-64 and rh[3:]==[0]*5
        value=json.loads(render[64:]);assert len(value)==36
        assert h[5]<=h[11]<=h[6]
        secs,nanos=divmod(h[11]-h[5],1000000000)
        expected=float(secs)+float(nanos)/1e9
        assert struct.unpack('<Q',struct.pack('<d',expected))[0]==h[7]
        assert value['native_operation_wall_seconds']==expected
    else:
        assert parts[2]==b'' and h[7]==h[11]==0
        value=None
    return h,parts,value

def verify_process(path,component,*,expected_group=None):
    receipt=json.loads((path/'process.json').read_bytes())
    assert receipt['started'] and receipt['returncode']==0 and not receipt['timed_out']
    assert receipt['timeout_seconds']==60 and receipt['elapsed_seconds']<=60
    assert receipt['pid']==receipt['pgid'] and receipt['pid']>0 and receipt['parent_pid']>0
    assert receipt['executable_sha256']==component['executable_sha256']
    raw={name:(path/(name+'.bin')).read_bytes() for name in ['stdin','stdout','stderr']}
    for name,b in raw.items():assert receipt[name]=={'bytes':len(b),'sha256':sha(b)}
    requests={};replies={};ready={};bodies={};all_output=[]
    for b in packets(raw['stdin']):
        assert len(b)>=64 and b[:8]==b'HBWKRQ01'
        r=words(b[:64]);assert len(b)==64+r[5] and r[6:]==[0,0] and r[1] in range(1,8)
        assert r[2] not in requests and r[2]>0
        assert (r[1]==1 and r[3]==0 and r[4]<=4) or (r[1]!=1 and r[4:]==[0,0,0,0])
        requests[r[2]]=(r,b[64:])
    jobs={}
    for b in packets(raw['stdout']):
        assert len(b)>=192 and b[:8]==b'HBPMSR01'
        h=words(b[:64]);assert h[1]==len(b)==192+h[6] and h[7]==0 and h[2] in [1,2]
        event={'kind':h[2],'tag':h[3],'job':h[4],'code':h[5]};all_output.append(event)
        if h[2]==1:
            assert h[3] in requests and h[3] not in replies
            replies[h[3]]=b;r,payload=requests[h[3]]
            if r[1]==1 and h[4]:
                assert h[5]==128 and b[64:72]==b'HBPWRS01'
                pool=words(b[64:192]);assert pool[2]==0 and pool[4]==h[4] and pool[5]==2
                assert h[4] not in jobs;jobs[h[4]]={'tag':h[3],'payload':payload,'hold':r[4]}
            if h[6]:
                assert r[1]==4 and h[4] not in bodies and h[4] in jobs
                body,parts,value=decode_body(b[192:]);assert body[9]==h[5] and body[10]==jobs[h[4]]['hold']
                bodies[h[4]]=(body,parts,value)
        else:
            assert h[4] not in ready and h[6]==0
            ready[h[4]]=b
    assert set(replies)==set(requests)
    assert receipt['outputs']==all_output
    assert set(ready)==set(jobs)
    pool=Pool();sequence=0;clones={};reaped={};starts={};finishes={};clock_counts={};core_clocks={};writer_clocks={};holds={};final=None;growth=0
    for magic,b in decode_journal(raw['stderr']):
        h=words(b[:64])
        if magic==b'HBWPL001':
            actor,command=struct.unpack_from('<2Q',b,16);code,seq=struct.unpack_from('<2Q',b,96)
            sequence+=1;assert seq==sequence and b[240:]==bytes(16)
            request=b[32:96];r=words(request);assert r[1]==command
            expected_code,expected=pool.invoke(request);assert (code,b[112:240])==(expected_code,expected),(sequence,command,code,expected_code)
            if code==GROW:growth+=1
            if command in [3,5]:assert actor==clones[r[2]],('worker role',command,actor,clones)
            else:assert actor==receipt['pid'],('parent role',command,actor)
            if command==2:assert r[2] in clones
            if command==3:
                assert r[2] not in starts;starts[r[2]]=r[3]
            if command==5:
                assert r[2] not in finishes;finishes[r[2]]=(r[3],r[4])
            if command in [8,12]:assert r[2] in reaped
        elif magic==b'HBWPROC1':
            assert h[2]==receipt['pid'] and h[7]==0 and h[3] in jobs
            if h[5]==1:
                assert h[4]>0 and h[4]!=receipt['pid'] and h[3] not in clones and h[6]==0
                clones[h[3]]=h[4]
            elif h[5]==2:
                assert h[3] in clones and h[4]==clones[h[3]] and h[3] not in reaped
                reaped[h[3]]=h[6]
            else:raise AssertionError(('unqualified mechanical failure',h))
        elif magic==b'HBCLOCK1':
            job,actor,owner,now=h[2:6];assert h[6:]==[0,0] and actor==clones[job] and job in starts and job not in finishes
            d=words(b[64:]);assert len(d)==16 and d[2]==1 and d[3]==job and d[6:8]==[starts[job],starts[job]+30000000000]
            assert now>=starts[job]
            old=clock_counts.get(job,(0,0));assert now>=old[1];clock_counts[job]=(old[0]+1,now)
            if owner==1:
                assert b[64:72]==b'HBTMEF01' and d[4] in [1,3,4,5] and d[11:]==[0]*5
                core_clocks.setdefault(job,[]).append((d,now))
            elif owner==2:
                assert b[64:72]==b'HBTCEF01' and d[13:]==[0,0,0]
                assert 1<=d[9]<=32 and d[8]<=8<<20
                writer_clocks.setdefault(job,[]).append((d,now))
            else:raise AssertionError(owner)
        elif magic==b'HBPWHLD1':
            assert h[2] in jobs and h[3]==clones[h[2]] and h[4]==jobs[h[2]]['hold'] and h[6:]==[0,0]
            assert h[2] not in holds;holds[h[2]]=h
        elif magic==b'HBWPEND1':
            assert final is None and h[2]==pool.capacity and h[3]==receipt['pid'] and h[4]==sequence and h[5:]==[0]*3
            assert b[64:]==pool.complete_state();assert pool.header[3]==pool.header[8]==0
            final=b
    assert final is not None and set(clones)==set(reaped)==set(jobs)==set(starts)==set(finishes)
    assert all(status==0 for status in reaped.values())
    for job,info in jobs.items():
        if info['hold']:assert job in holds
        rr=words(ready[job][64:192]);assert rr[3]==5 and rr[4]==job and rr[5]==4 and rr[7]==0
        assert rr[8]==starts[job] and rr[9]==starts[job]+30000000000 and rr[10]==finishes[job][1]
        cs=core_clocks.get(job,[]);ws=writer_clocks.get(job,[])
        assert [d[1] for d,n in ws]==list(range(1,len(ws)+1))
        for previous,current in zip(ws,ws[1:]):assert current[0][8]==previous[0][8]+previous[0][9]
        # Cancellation retires interest, not the worker or its CLOCK trace.
        # COMPLETE and READY still bind every checkpoint even without TAKE.
        if job in clock_counts:assert clock_counts[job][1]<=finishes[job][0]
        result_code=finishes[job][1]
        if result_code==0:
            count=struct.unpack_from('<Q',info['payload'],8)[0]
            expected=[(1,i) for i in range(count)]+[(3,i) for i in range(count)]+[(4,i) for i in range(count)]+[(5,0)]
            assert [(d[4],d[5]) for d,n in cs]==expected
            assert ws and all(now<starts[job]+30000000000 for d,now in cs+ws)
            assert [d[1] for d,n in cs]==list(range(1,count+1))+list(range(count+2,3*count+3))
            assert ws[0][0][8]==0
            last=ws[-1][0]
            assert last[4:6]==[14,count] and last[9:13]==[1,0,0,2]
        elif result_code==0xfffffdf0:
            assert cs and cs[-1][1]>=starts[job]+30000000000
        elif result_code==0xfffffde1:
            assert ws and ws[-1][1]>=starts[job]+30000000000
        if job in bodies:
            bh,parts,value=bodies[job];assert bh[5]==starts[job] and bh[6:7]==[finishes[job][0]] and bh[8]==clock_counts.get(job,(0,0))[0]
            if bh[9]==0:
                assert bh[11]>=clock_counts[job][1]
                assert ws[-1][0][8]+ws[-1][0][9]==len(parts[1])-128
    return {'status':'READ_ONLY_PROCESS_PASS','jobs':len(jobs),'pool_calls':sequence,'clock_calls':sum(v[0] for v in clock_counts.values()),
            'physical_clones':len(clones),'physical_reaps':len(reaped),'held_jobs':len(holds),'growth_calls':growth,
            'complete_stream_bytes':sum(len(v) for v in raw.values()),'streams':receipt['stdin']|{'output_sha256':receipt['stdout']['sha256'],'journal_sha256':receipt['stderr']['sha256']},
            'actual_rust_executed':False,'public_handler_qualified':False}
