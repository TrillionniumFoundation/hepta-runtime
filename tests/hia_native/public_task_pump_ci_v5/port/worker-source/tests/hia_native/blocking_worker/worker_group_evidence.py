"""Read actual process journals and unchanged complete caller fixture assertions."""
from __future__ import annotations
import json,sys,types
from pathlib import Path
from worker_common import BASE,read,document,require,sha
from worker_evidence import verify_process,packets,words

GROUPS=('lifetime','retained','eof','ordinary0','ordinary1','ordinary2','ordinary3','held1','held2','held3','held4')
JOBS={'lifetime':6,'retained':40,'eof':2,'ordinary0':91,'ordinary1':91,'ordinary2':91,'ordinary3':90,'held1':1,'held2':1,'held3':1,'held4':1}

def verify_group(folder,root,component,group):
    require(group in GROUPS,'unknown actual worker group')
    evidence=verify_process(folder,component);evidence['group']=group
    require(evidence==document(folder/'report.json'),'complete process reader/report differs')
    require(evidence['jobs']==JOBS[group],'actual job domain shrank')
    receipt=document(folder/'process.json')
    require(receipt.get('parent_death_signal')==9,'qualification supervisor lifetime is unbound')
    if group.startswith('held'):require(receipt['elapsed_seconds']>=30,'real held interval missing')
    inputs=packets(read(folder/'stdin.bin'));outputs=packets(read(folder/'stdout.bin'));progress={}
    class TapePath:
        def __init__(self,name=''):self.name=name
        def __truediv__(self,name):return TapePath(name)
        def read_bytes(self):
            require(self.name=='stderr.bin','unadmitted fixture read');return read(folder/self.name)
        def write_text(self,text):
            require(self.name=='ordinary.progress.json','unadmitted fixture write intent');progress[self.name]=text.encode();return len(text)
    class Process:
        def __init__(self):self.input_at=0;self.output_at=0;self.path=TapePath();self.deadline=0
        def send(self,command,tag,*,job=0,hold=0,payload=b''):
            import struct
            expected=b'HBWKRQ01'+struct.pack('<7Q',command,tag,job,hold,len(payload),0,0)+payload
            require(self.input_at<len(inputs) and inputs[self.input_at]==expected,'whole actual input fixture differs')
            self.input_at+=1
        def next(self):
            require(self.output_at<len(outputs),'missing actual caller event');raw=outputs[self.output_at];self.output_at+=1;h=words(raw[:64])
            return {'kind':h[2],'tag':h[3],'job':h[4],'code':h[5],'pool':raw[64:192],'body':raw[192:],'raw':raw}
    class Clock:
        calls=0 if group=='held1' else 1
        @classmethod
        def monotonic(cls):cls.calls+=1;return 0 if cls.calls==1 else 100000000000000.0
        @staticmethod
        def sleep(*args):raise AssertionError('readonly fixture requested a real wait')
    path=root/BASE/'diagnose_worker.py';namespace={'__name__':'readonly_worker_fixture','__file__':str(path)}
    previous=list(sys.path)
    try:
        sys.path.insert(0,str(path.parent));sys.path.insert(0,str(path.parent/'reference'))
        exec(compile(read(path),str(path),'exec'),namespace);namespace['time']=Clock
        process=Process();client=namespace['Client'](process)
        if group.startswith('held'):namespace['held'](client,int(group[-1]))
        elif group.startswith('ordinary'):namespace['ordinary'](client,int(group[-1]))
        else:namespace[{'eof':'eof_drain'}.get(group,group)](client)
        require(process.input_at==len(inputs),'unclaimed actual control input')
        remaining=outputs[process.output_at:]
        require((group=='eof' and all(words(r[:64])[2]==2 for r in remaining)) or not remaining,'unclaimed caller event')
        if group.startswith('ordinary'):require(progress=={'ordinary.progress.json':read(folder/'ordinary.progress.json')},'whole ordered original cohort differs')
        else:require(not progress,'unexpected semantic stream')
    finally:sys.path[:]=previous
    return evidence|{'source_driver_sha256':sha(read(path)),'complete_fixture_inputs':len(inputs),'writes_performed':False,'native_or_rust_executed':False}
