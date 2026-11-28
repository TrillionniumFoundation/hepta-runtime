"""Portable CI-only fresh original plus complete HIA catalog recipe."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import extract_declarations
import read_catalog

PROCESS_NAMES=('original-capture','native-build','native-matrix','native-controls','evidence-controls')
TIMEOUTS={'original-capture':3600,'native-build':300,'native-matrix':180,'native-controls':180,'evidence-controls':180}

def pin(path):
    raw=Path(path).read_bytes()
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def save(path,value):
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def record_process(folder,name,command,cwd):
    timeout=TIMEOUTS[name];folder.mkdir(exist_ok=True)
    stdout=folder/(name+'.stdout');stderr=folder/(name+'.stderr')
    row={'name':name,'command':command,'cwd':str(cwd),'timeout_seconds':timeout,'start_error':None,
        'exit_code':None,'timed_out':False,'environment':{'PYTHONDONTWRITEBYTECODE':'1','LC_ALL':'C'}}
    env=os.environ.copy();env.update(row['environment'])
    process=None;started=time.monotonic()
    try:
        with stdout.open('xb') as out,stderr.open('xb') as err:
            try:
                process=subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
                row['pid']=process.pid
            except BaseException as error:
                row['start_error']=repr(error);raise
            try:row['exit_code']=process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row['timed_out']=True;raise
    finally:
        try:
            if process is not None and process.poll() is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                finally:row['exit_code']=process.wait()
        finally:
            row['elapsed_seconds']=time.monotonic()-started
            row['stdout']={'path':stdout.name,**pin(stdout)}
            row['stderr']={'path':stderr.name,**pin(stderr)}
            save(folder/(name+'.process.json'),row)
    read_catalog.need(row['exit_code']==0 and not row['timed_out'] and row['start_error'] is None,'actual process '+name)
    return row

def snapshot_source(source,destination):
    reader,_,_,_=read_catalog.source_check(source)
    destination.mkdir()
    for name in reader.files:
        path=destination/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(reader.raw(name))
    read_catalog.source_check(destination)

def verify(output):
    output=Path(output).absolute();r=read_catalog.Reader(output)
    report=r.document('result.json')
    read_catalog.need(report['schema']=='hepta.runtime.catalog-policy-recipe.v2' and report['status']=='PASS','recipe completed')
    read_catalog.need(report['fresh_original_build'] is True and report['target_commit']==read_catalog.TARGET,'fresh exact target reference')
    read_catalog.need(report['process_names']==list(PROCESS_NAMES),'fixed process inventory')
    read_catalog.need(all(report[k] is False for k in ('whole_runtime_replaced','production_activated','old_stack_removal_qualified','tool_bodies_qualified')),'private scope retained')
    producer=Path(report['producer_root']);need=read_catalog.need
    process_rows=[]
    for name in PROCESS_NAMES:
        row=r.document('processes/'+name+'.process.json')
        need(row['name']==name and row['exit_code']==0 and row['timed_out'] is False and row['start_error'] is None,'actual successful process '+name)
        need(row['timeout_seconds']==TIMEOUTS[name] and 0<=row['elapsed_seconds']<=TIMEOUTS[name]+2,'unchanged actual deadline '+name)
        need(row['environment']=={'PYTHONDONTWRITEBYTECODE':'1','LC_ALL':'C'},'controlled native process environment')
        need(type(row['pid']) is int and row['pid']>0 and row['cwd']==str(producer),'producer process identity')
        command=row['command'];need(command[:3]==[report['python'],'-I','-B'],'Python entry flags')
        path={'original-capture':'reference/capture.py','native-build':'build_catalog.py','native-matrix':'qualify_catalog_policy.py','native-controls':'qualify_controls.py','evidence-controls':'check_evidence.py'}[name]
        need(command[3]==str(producer/'source'/path),'fixed exact recipe driver')
        for stream in ('stdout','stderr'):
            record=row[stream];need(record['path']==name+'.'+stream,'fixed process stream path')
            r.raw('processes/'+record['path'],{'bytes':record['bytes'],'sha256':record['sha256']})
        process_rows.append(row)
    # Strict command tails preserve exact target/output and all buffer-owner paths.
    expected={
        'original-capture':['--target',report['target_root'],'--output',str(producer/'original')],
        'native-build':['--source',str(producer/'source'),'--hepta',report['hepta_root'],'--output',str(producer/'build')],
        'native-matrix':['--source',str(producer/'source'),'--build',str(producer/'build'),'--runtime',str(producer/'source/runtime_support'),'--evidence',str(producer/'original'),'--output',str(producer/'native')],
        'native-controls':['--source',str(producer/'source'),'--build',str(producer/'build'),'--runtime',str(producer/'source/runtime_support'),'--output',str(producer/'controls')],
        'evidence-controls':['--source',str(producer/'source'),'--build',str(producer/'build'),'--native',str(producer/'native'),'--controls',str(producer/'controls'),'--original',str(producer/'original'),'--output',str(producer/'evidence-controls')],
    }
    for row in process_rows:need(row['command'][4:]==expected[row['name']],'complete process argument custody '+row['name'])
    source,asset,_,raw_input=read_catalog.source_check(output/'source')
    need(report['source_profile']==pin(output/'source/source-profile.json'),'source-profile identity')
    native=read_catalog.verify(output/'source',output/'build',output/'native',output/'original')
    controls=read_catalog.controls_check(output/'source',output/'controls')
    evidence_controls=read_catalog.evidence_controls_check(output/'source',output/'build',output/'native',output/'evidence-controls')
    derived=r.document('declarations-extraction.json')
    need(derived['expected_handler_outputs_exported'] is False and derived['input_sha256']==read_catalog.sha(raw_input),'independent declarations export')
    need(r.raw('derived/declarations.json')==(output/'source/declarations.json').read_bytes() and r.raw('derived/catalog-input.json')==raw_input,'fresh original declaration bytes')
    for relative,expected_pin in derived['observations'].items():
        observed=(output/'original'/relative).read_bytes();need(expected_pin=={'bytes':len(observed),'sha256':read_catalog.sha(observed)},'fresh declaration observation pin')
    result={'schema':'hepta.runtime.catalog-policy-recipe-readonly.v2','status':'PASS','process_launches':0,
        'fresh_original_build':True,'actual_handler_comparisons':216,'ordinary_schemas':119,'frozen_schemas':17,
        'unique_abi_inputs':18,'matrix_native_calls':498,'control_native_calls':403,'processes':process_rows,
        'original':native['original_reader'],'native':native,'controls':controls,'evidence_controls':evidence_controls,
        'whole_runtime_replaced':False,'production_activated':False,'old_stack_removal_qualified':False,'tool_bodies_qualified':False}
    return result

def run(source,hepta,target,output):
    read_catalog.need(os.environ.get('GITHUB_ACTIONS')=='true','fresh Rust reference is CI-only')
    source=source.resolve(strict=True);hepta=hepta.resolve(strict=True);target=target.resolve(strict=True);output=output.absolute()
    read_catalog.source_check(source);output.mkdir(parents=True,exist_ok=False)
    report={'schema':'hepta.runtime.catalog-policy-recipe.v2','status':'RUNNING','producer_root':str(output),
        'python':sys.executable,'hepta_root':str(hepta),'target_root':str(target),'target_commit':read_catalog.TARGET,
        'process_names':list(PROCESS_NAMES),'fresh_original_build':False,'whole_runtime_replaced':False,
        'production_activated':False,'old_stack_removal_qualified':False,'tool_bodies_qualified':False}
    save(output/'result.json',report)
    try:
        snapshot_source(source,output/'source');source=output/'source';report['source_profile']=pin(source/'source-profile.json')
        commands={
            'original-capture':[sys.executable,'-I','-B',str(source/'reference/capture.py'),'--target',str(target),'--output',str(output/'original')],
            'native-build':[sys.executable,'-I','-B',str(source/'build_catalog.py'),'--source',str(source),'--hepta',str(hepta),'--output',str(output/'build')],
            'native-matrix':[sys.executable,'-I','-B',str(source/'qualify_catalog_policy.py'),'--source',str(source),'--build',str(output/'build'),'--runtime',str(source/'runtime_support'),'--evidence',str(output/'original'),'--output',str(output/'native')],
            'native-controls':[sys.executable,'-I','-B',str(source/'qualify_controls.py'),'--source',str(source),'--build',str(output/'build'),'--runtime',str(source/'runtime_support'),'--output',str(output/'controls')],
            'evidence-controls':[sys.executable,'-I','-B',str(source/'check_evidence.py'),'--source',str(source),'--build',str(output/'build'),'--native',str(output/'native'),'--controls',str(output/'controls'),'--original',str(output/'original'),'--output',str(output/'evidence-controls')],
        }
        record_process(output/'processes','original-capture',commands['original-capture'],output)
        read_catalog.reference_module(source).verify(output/'original')
        derived=extract_declarations.extract(output/'original',output/'derived');save(output/'declarations-extraction.json',derived)
        for name in ('declarations.json','catalog-input.json'):
            read_catalog.need((output/'derived'/name).read_bytes()==(source/name).read_bytes(),'fresh declarations unchanged '+name)
        for name in PROCESS_NAMES[1:]:record_process(output/'processes',name,commands[name],output)
        report.update(status='PASS',fresh_original_build=True);save(output/'result.json',report)
        checked=verify(output);save(output/'verification.json',checked)
        return checked
    except BaseException as exc:
        report.update(status='FAIL',error={'type':type(exc).__name__,'message':str(exc)})
        save(output/'result.json',report);raise

def main():
    p=argparse.ArgumentParser();p.add_argument('--phase',choices=('all','verify'),required=True)
    p.add_argument('--source',type=Path,default=Path(__file__).resolve().parent)
    p.add_argument('--hepta',type=Path);p.add_argument('--target',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.phase=='all':result=run(a.source,a.hepta,a.target,a.output)
    else:result=verify(a.output)
    print(json.dumps({k:v for k,v in result.items() if k not in ('processes','original','native','controls','evidence_controls')},sort_keys=True))

if __name__=='__main__':main()
