"""Continue only pure readers and physical evidence controls on the retained completed producer."""
from pathlib import Path
import argparse
import gzip
import io
import json
import sys
import tarfile
import tomllib
ADAPTER=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ADAPTER))
import read_adapter

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def child(phase,restored,output):
    capture=restored/'run/semantic'
    reader,controls,guard=read_adapter.install(restored/'source')
    import reader_cli
    reader_cli.prepare()
    output.mkdir(parents=True,exist_ok=True)
    if phase=='controls':
        value=controls.run(capture,output/'controls')
        summary=dict(status=value['status'],admissions=value['admissions'],refusals=value['refusals'],
                     native_or_rust_executions=0)
    else:
        roots=[capture,restored/'source']+([output/'controls'] if phase=='final' else [])
        value=guard.guarded(lambda:reader.verify(capture,output/'controls' if phase=='final' else None),
            roots=roots,foreign_path=str(output/'unadmitted-copy/CAPTURE.json'))
        summary=dict(status=value['evidence']['status'],probes=len(value['probes']),
                     physical_entries=len(value['before']),evidence=value['evidence'],
                     native_or_rust_executions=0,reader_writes=0)
    (output/(phase+'-read.json')).write_bytes(encoded(value))
    print(encoded(summary).decode(),end='')

def parent(phase,restored,output):
    read_adapter.check_adapter()
    sys.path.insert(0,str(restored/'source'))
    from process import Recorder,environment
    env,_=environment(__import__('os').environ)
    recorder=Recorder(ADAPTER,output/'processes'/phase,env)
    try:
        raw,row=recorder.run('readonly-'+phase,[sys.executable,'-I','-B',ADAPTER/'recover.py','--child',
            '--phase',phase,'--restored',restored,'--output',output],timeout=180)
        print(raw.decode(),end='')
    finally:
        error=recorder.directory/('readonly-'+phase+'.stderr')
        if error.is_file():sys.stderr.write(error.read_text())

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--child',action='store_true');p.add_argument('--phase',choices=('semantic','controls','final'),required=True)
    p.add_argument('--restored',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    (child if a.child else parent)(a.phase,a.restored.resolve(strict=True),a.output.absolute())
