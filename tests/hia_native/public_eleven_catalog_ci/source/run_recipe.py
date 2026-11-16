"""Actual original/HIA catalog recipe; --phase verify only reads evidence."""
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
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import static_common as c

PROCESSES=(('original-capture',3600),('projection-build',300),('projection-native',180),
    ('static-build',300),('static-native',180),('sdk-projection',300),('evidence-controls',180))

def record_process(folder,name,command,cwd,timeout,*,env=None,stdin=None):
    folder.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',LC_ALL='C') if env is None else env
    row={'name':name,'command':command,'cwd':str(cwd),'timeout_seconds':timeout,
        'pid':None,'parent_pid':os.getpid(),'exit_code':None,'timed_out':False,'start_error':None,
        'started_ns':time.monotonic_ns(),'stdin':None if stdin is None else c.pin(stdin.read_bytes())}
    child=None;input_handle=None
    try:
        if stdin is not None:input_handle=stdin.open('rb')
        with (folder/(name+'.stdout')).open('xb')as out,(folder/(name+'.stderr')).open('xb')as err:
            try:
                child=subprocess.Popen(command,cwd=cwd,env=env,stdin=input_handle if input_handle else subprocess.DEVNULL,
                    stdout=out,stderr=err,start_new_session=True)
                row['pid']=child.pid;row['pgid']=os.getpgid(child.pid)
            except BaseException as error:row['start_error']=repr(error);raise
            try:row['exit_code']=child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:row['timed_out']=True;raise
    finally:
        try:
            if child is not None and child.poll() is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                finally:row['exit_code']=child.wait()
        finally:
            if input_handle:input_handle.close()
            row['finished_ns']=time.monotonic_ns()
            for stream in ('stdout','stderr'):row[stream]=c.pin((folder/(name+'.'+stream)).read_bytes())
            c.put(folder/(name+'.process.json'),row)
    assert row['exit_code']==0 and row['timed_out']is False and row['start_error']is None,(name,row)
    return row

def run(hepta,target,output):
    assert os.environ.get('GITHUB_ACTIONS')=='true','fresh Rust recipe is CI-only'
    sources,_=c.source_check();output.mkdir(parents=True,exist_ok=False)
    source=output/'source';source.mkdir()
    for name in sources.files:
        dest=source/name;dest.parent.mkdir(parents=True,exist_ok=True);c.put(dest,sources.raw(name))
    report={'schema':'hepta.runtime.catalog-eleven-recipe.v1','status':'RUNNING','producer_root':str(output),
        'producer_pid':os.getpid(),'producer_parent_pid':os.getppid(),
        'source_profile':c.pin((source/'source-profile.json').read_bytes()),'target_root':str(target),
        'hepta_root':str(hepta),'python':sys.executable,'processes':list(PROCESSES),
        'public_all_configuration_qualified':False,'whole_runtime_replaced':False,'production_activated':False}
    c.put(output/'recipe-start.json',report)
    commands={
        'original-capture':['pipeline/policy_base/reference/capture.py','--target',str(target),'--output',str(output/'original')],
        'projection-build':['pipeline/build_projection.py','--hepta',str(hepta),'--output',str(output/'projection-build')],
        'projection-native':['pipeline/capture_projection.py','--build',str(output/'projection-build'),'--output',str(output/'projection-native')],
        'static-build':['build_static.py','--hepta',str(hepta),'--projection-build',str(output/'projection-build'),
            '--projection-capture',str(output/'projection-native'),'--bootstrap',str(output/'projection-build/bootstrap'),'--output',str(output/'static-build')],
        'static-native':['capture_static.py','--build',str(output/'static-build'),'--output',str(output/'static-native')],
        'sdk-projection':['reference_projection.py','--target',str(target),'--original',str(output/'original'),'--output',str(output/'sdk-original')],
        'evidence-controls':['evidence_controls.py','--output',str(output),'--controls',str(output/'evidence-controls')],
    }
    try:
        for name,limit in PROCESSES:
            args=commands[name]
            record_process(output/'processes',name,[sys.executable,'-I','-B',str(source/args[0]),*args[1:]],output,limit)
        report['status']='PASS';c.put(output/'result.json',report)
        from verify_recipe import verify
        value=verify(output);c.put(output/'verification.json',value)
        return value
    except BaseException as error:
        c.put(output/'FAILURE.json',{'error_type':type(error).__name__,'message':str(error)})
        raise

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--phase',choices=['all','verify'],required=True)
    p.add_argument('--hepta',type=Path);p.add_argument('--target',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.phase=='all':result=run(a.hepta.resolve(strict=True),a.target.resolve(strict=True),a.output.absolute())
    else:
        from verify_recipe import verify
        result=verify(a.output.resolve(strict=True))
    print(json.dumps({k:v for k,v in result.items()if k not in ('source_files','build_files','native_files','cases','processes')},sort_keys=True))
