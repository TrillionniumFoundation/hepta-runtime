#!/usr/bin/env python3
"""Run the complete inherited file domain under its unchanged group deadline."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
PIN = lambda raw: {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    command=[sys.executable,str(ROOT/'qualify_files.py'),'--native',str(args.executable.resolve()),
        '--output',str(out/'capture'),'--large']
    report={'schema':'hepta.runtime.rebuilt-batch-callable-files-process.v1','status':'RUNNING',
        'command':command,'cwd':str(ROOT),'timeout_seconds':180,'stdin':PIN(b''),
        'executable_pin':PIN(args.executable.read_bytes()),'source_inputs':{'files':{}},
        'fresh_current_original_compared':False,'public_batch_qualified':False,
        'full_async_cancellation_qualified':False}
    names=['run_native_files.py','qualify_files.py','body_observations.py','file-corpus-author-proof.json','corpus-inputs.json']
    names+=list(json.loads((ROOT/'corpus-inputs.json').read_bytes())['files'])
    names+=['runtime_support/scripts/hia_native_loader.py']
    report['source_inputs']['files']={name:PIN((ROOT/name).read_bytes()) for name in sorted(set(names))}
    process=None;started=time.monotonic()
    def save(): (out/'process.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    save()
    try:
        with (out/'stdout').open('xb') as stdout,(out/'stderr').open('xb') as stderr:
            process=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
            report.update(pid=process.pid,process_group=os.getpgid(process.pid));save()
            try:
                code=process.wait(timeout=180)
                report.update(returncode=code,timed_out=False,reaped=True)
            except subprocess.TimeoutExpired:
                report['timed_out']=True
                os.killpg(process.pid,signal.SIGKILL)
                report['returncode']=process.wait();report['reaped']=True
                raise
        assert code==0,code
        observed=json.loads((out/'capture/native/result.json').read_bytes())
        assert observed['status']=='PASS' and observed['requests']==926
        from body_observations import read_native
        with gzip.open(out/'states.jsonl.gz','xb',compresslevel=1) as stream:
            report['state_observations']=read_native(out/'capture/native/stderr.bin',926,stream)
        assert report['source_inputs']['files']=={n:PIN((ROOT/n).read_bytes()) for n in report['source_inputs']['files']}
        report['status']='PASS'
    except BaseException as error:
        report.update(status='FAIL',error=repr(error))
        raise
    finally:
        if process is not None and process.poll() is None:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
        report['elapsed_seconds']=time.monotonic()-started
        report['artifacts']={name:PIN((out/name).read_bytes()) for name in ('stdout','stderr','states.jsonl.gz') if (out/name).exists()}
        save()
    print(json.dumps({key:report[key] for key in ('status','elapsed_seconds','state_observations')},sort_keys=True))


if __name__=='__main__':main()
