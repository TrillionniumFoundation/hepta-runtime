"""Synthetic actual-process tests, authorized only under their own frozen parent."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def pin(path):
    path=Path(path).resolve();raw=path.read_bytes();return dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def save(path,value):
    with Path(path).open('x') as f:json.dump(value,f,indent=2);f.write('\n')


def main():
    p=argparse.ArgumentParser();p.add_argument('--contract',required=True);a=p.parse_args();outer=json.loads(Path(a.contract).read_text())
    source=Path(__file__).resolve().parent;root=Path(outer['attempt_root'])/'output';root.mkdir(exist_ok=False)
    rows=[]
    for mode in ['normal','nonzero','missing','orphan','aggregate','sleep','launch_error']:
        location=root/mode;location.mkdir();attempt=location/'attempt001';result=attempt/'RESULTS.json'
        command=[sys.executable,str(source/'supervisor_probe.py'),mode,str(result)]
        if mode=='launch_error':command=[str(location/'nonexistent-program')]
        limits=dict(CPU_soft=1,CPU_hard=2,wall_hard=0.3 if mode=='sleep' else 10,address_space_bytes=256*1024*1024,affinity=outer['limits']['affinity'],threads=1)
        contract=dict(schema='hepta.native-closure-contract.v1',scope='synthetic_supervisor_'+mode,automatic_retry=False,cwd=str(location),attempt_root=str(attempt),
                      command=command,source_pins=[pin(source/'run_bounded.py'),pin(source/'supervisor_probe.py')],limits=limits,environment={'PYTHONDONTWRITEBYTECODE':'1'},required_result_status='PASS',result_path=str(result))
        save(location/'CONTRACT.json',contract);save(location/'ADMISSION.json',dict(status='AUTHORIZED_ONE_EXECUTION',scope=contract['scope'],contract_pin=pin(location/'CONTRACT.json'),authorization='synthetic control within separately admitted test-only stage'))
        completed=subprocess.run([sys.executable,str(source/'run_bounded.py'),'--contract',str(location/'CONTRACT.json'),'--admission',str(location/'ADMISSION.json')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        row=json.loads((attempt/'PROCESS.json').read_text())
        expected=mode=='normal'
        if (completed.returncode==0)!=expected or (row['status']=='COMPLETED')!=expected:raise ValueError('wrong process result: '+mode)
        if row['descendant_CPU_accounting_complete']!=expected or (row['actual_descendant_CPU_seconds'] is not None)!=expected:raise ValueError('failure CPU was treated as complete')
        if row['residual_descendants_after_cleanup']:raise ValueError('owned group still has descendants')
        if mode=='orphan' and (not row['residual_descendants_before_cleanup'] or not row['adopted_descendants_reaped']):raise ValueError('orphan cleanup did not execute')
        if mode=='aggregate' and (row['stop_reason'] not in ['CPU_soft','CPU_soft_at_final_reap'] or row['observed_CPU_lower_bound_seconds']<0.95):raise ValueError('aggregate soft limit was not enforced')
        if mode=='sleep' and 'wall' not in row['stop_reason']:raise ValueError('wall limit was not enforced')
        if mode=='launch_error' and (not row['error'] or row['returncode'] is not None):raise ValueError('launch exception was not receipted')
        rows.append(dict(mode=mode,status='PASS',process_pin=pin(attempt/'PROCESS.json'),observed_status=row['status'],stop_reason=row['stop_reason']))
    save(root/'RESULTS.json',dict(schema='hepta.owner-ci-supervisor-controls.v1',status='PASS',controls=rows,real_model_calls=0,root_owner_calls=0))


if __name__=='__main__':main()
