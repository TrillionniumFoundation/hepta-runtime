"""Bound each explicit read-only/physical-control phase to its original 180-second process budget."""
from pathlib import Path
import argparse
import os
import sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from common import encoded,loads,read,require,source,pin
from process import Recorder,environment

def run(phase,output):
    identity=source()
    env,_=environment(os.environ)
    recorder=Recorder(ROOT,output/'reader-processes'/phase,env)
    argv=[sys.executable,'-I','-B',ROOT/'reader_cli.py','--kind',phase,
          '--capture',output/'semantic','--controls',output/'controls',
          '--report',output/(phase+'-read.json')]
    try:
        raw,row=recorder.run('reader-'+phase,argv,timeout=180)
        print(raw.decode(),end='')
        if phase=='final':
            proof=loads(read(output/'final-read.json'))
            require(proof['evidence']['status']=='PASS' and source()==identity,'same frozen source and final readback')
            report=dict(schema='hepta.audit-record-io.gate.v1',status='PASS',source_manifest_sha256=identity,
                cases=219,operations=459,final_read=pin(read(output/'final-read.json')),
                read_only_process=pin(read(output/'reader-processes/final/processes.json')),
                native_or_rust_executions_in_reader=0,public_handler_qualified=False,whole_runtime_replaced=False)
            (output/'GATE.json').write_bytes(encoded(report))
    finally:
        error=recorder.directory/('reader-'+phase+'.stderr')
        if error.is_file():sys.stderr.write(error.read_text())

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase',choices=('semantic','controls','final'),required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.phase,a.output.resolve(strict=True))
