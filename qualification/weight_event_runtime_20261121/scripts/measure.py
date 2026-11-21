"""Create-only subprocess receipt; compilation and scientific work remain separate."""
import argparse
import json
import os
from pathlib import Path
import resource
import subprocess
import time

ROOT=Path(os.environ['HEPTA_EVENT_STUDY_DIR']).resolve()


def main():
    p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--scope',choices=['compilation','science'],required=True);p.add_argument('command',nargs=argparse.REMAINDER);a=p.parse_args()
    command=a.command[1:] if a.command[:1]==['--'] else a.command
    env=dict(os.environ,OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',MKL_NUM_THREADS='1',NUMEXPR_NUM_THREADS='1',CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='1')
    env['PATH']=os.environ['HEPTA_EVENT_RUST_BIN']+os.pathsep+env['PATH']
    env['CARGO_HOME']=os.environ['HEPTA_EVENT_CARGO_HOME']
    env['CARGO_TARGET_DIR']=os.environ['HEPTA_EVENT_TARGET_DIR']
    previous=[]
    for path in (ROOT/'evidence').glob('PROCESS_*.json'):
        row=json.loads(path.read_text())
        if row['scope']=='science':previous.append(row)
    used_cpu=sum(r['child_CPU_seconds'] for r in previous);used_wall=sum(r['wall_seconds'] for r in previous)
    cpu_budget=120-used_cpu if a.scope=='science' else 120
    wall_budget=180-used_wall if a.scope=='science' else 180
    if min(cpu_budget,wall_budget)<=1:raise RuntimeError('frozen cumulative science budget exhausted')
    def limit():
        os.sched_setaffinity(0,{int(os.environ['HEPTA_EVENT_CPU'])})
        resource.setrlimit(resource.RLIMIT_CPU,(int(cpu_budget),int(cpu_budget)+1))
    before=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.monotonic()
    stdout=ROOT/'evidence'/('PROCESS_'+a.label+'.stdout');stderr=ROOT/'evidence'/('PROCESS_'+a.label+'.stderr')
    timed_out=False
    with stdout.open('xb') as out,stderr.open('xb') as err:
        try:result=subprocess.run(command,cwd=ROOT,env=env,stdout=out,stderr=err,timeout=wall_budget,preexec_fn=limit);code=result.returncode
        except subprocess.TimeoutExpired:timed_out=True;code=-999
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    row=dict(scope=a.scope,command=command,exit_code=code,timeout=timed_out,wall_seconds=time.monotonic()-start,
             child_CPU_seconds=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,peak_child_RSS_KiB=after.ru_maxrss,
             previous_science_CPU_seconds=used_cpu,previous_science_wall_seconds=used_wall)
    with (ROOT/'evidence'/('PROCESS_'+a.label+'.json')).open('x') as f:json.dump(row,f,indent=2);f.write('\n')
    print(json.dumps(row));print(stderr.read_text()[-3000:]);print(stdout.read_text()[:1500]);raise SystemExit(code)


if __name__=='__main__':main()
