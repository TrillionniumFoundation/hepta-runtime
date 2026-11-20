#!/usr/bin/env python3
"""Run all original domains and interface controls with unchanged fixed deadlines."""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from common import inputs,source_evidence,pin,save,require


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--images',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.absolute();images=a.images.resolve(strict=True)
    require(not out.exists(),'fresh complete capture directory')
    frozen=source_evidence();domain,data=inputs()
    groups=list(dict.fromkeys(row['group']for row in data['plan_cases']))
    require(len(groups)==24,'complete unchanged planner groups')
    jobs=[('typed','typed',None)]+[('plan-'+name,'plan',name)for name in groups]+[('parent-interface','interface',None),('controls','controls',None)]
    out.mkdir(parents=True)
    began=time.monotonic_ns();deadline=time.monotonic()+1800
    rows=[]
    for label,mode,group in jobs:
        require(time.monotonic()<deadline,'complete 1800-second domain deadline')
        command=[sys.executable,'-I','-S','-B',str(ROOT/'scripts/capture_worker.py'),'--images',str(images),'--output',str(out/label),'--mode',mode]
        if group is not None:command+=['--group',group]
        started=time.monotonic_ns();timed_out=False;cleanup=False
        with (out/(label+'.stdout')).open('xb')as stdout,(out/(label+'.stderr')).open('xb')as stderr:
            child=subprocess.Popen(command,stdout=stdout,stderr=stderr,start_new_session=True)
            try:code=child.wait(timeout=min(60,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out=True;os.killpg(child.pid,signal.SIGTERM)
                try:code=child.wait(timeout=5);cleanup=True
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid,signal.SIGKILL);code=child.wait(timeout=5);cleanup=True
        row=dict(label=label,mode=mode,group=group,argv=command,returncode=code,elapsed_ns=time.monotonic_ns()-started,
                 limit_seconds=60,cleanup_seconds=5,timed_out=timed_out,cleanup_used=cleanup,
                 stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr')))
        save(out/(label+'.process.json'),row);rows.append(row)
        progress=dict(schema='hepta.runtime.binary-write-adapter.run.v1',source=frozen,images=pin(images/'IMAGES.json'),
                      completed=rows,declared_jobs=[x[0]for x in jobs],whole_limit_seconds=1800,elapsed_ns=time.monotonic_ns()-began,
                      status='RUNNING',original_rust_executions=0,parent_effects_executed=0,
                      public_binary_write_registered=False,whole_runtime_replaced=False)
        save(out/'RUN.json',progress)
        if timed_out or code!=0:
            progress['status']='HOLD';save(out/'RUN.json',progress)
            raise ValueError('complete original capture stopped; raw failure retained: '+label)
        require(source_evidence()==frozen,'whole source stayed frozen between processes')
        print(json.dumps(dict(label=label,status='CAPTURE_COMPLETE',elapsed_ns=row['elapsed_ns']),sort_keys=True),flush=True)
    progress['elapsed_ns']=time.monotonic_ns()-began
    require(progress['elapsed_ns']<=1800*1_000_000_000,'original whole capture bound')
    progress['status']='COMPLETE_CAPTURE_AWAITING_DATA_READER'
    save(out/'RUN.json',progress)


if __name__=='__main__':main()
