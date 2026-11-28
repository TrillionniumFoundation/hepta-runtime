"""Explicit fixed read-only phases; all report writes occur after the guard has ended."""
from pathlib import Path
import argparse
import gzip
import io
import sys
import tarfile
import tomllib
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from common import encoded,require
import read_capture
import read_only_guard
import reader_controls

def prepare():
    # Preload normal library paths before audit hooks; no filesystem or semantic execution.
    require(gzip.decompress(gzip.compress(b'prepared'))==b'prepared','gzip preload')
    require(tomllib.loads('value=1')['value']==1,'TOML preload')
    with tarfile.open(fileobj=io.BytesIO(bytes(10240)),mode='r:') as stream:
        require(list(stream)==[],'TAR preload')

def run(kind,capture,controls,report):
    prepare()
    if kind=='controls':
        value=reader_controls.run(capture,controls)
        summary=dict(status='PASS',admissions=value['admissions'],refusals=value['refusals'],
                     native_or_rust_executions=0,reader_writes_outside_guard=True)
    else:
        roots=[capture,ROOT]+([controls] if kind=='final' else [])
        value=read_only_guard.guarded(lambda:read_capture.verify(capture,controls if kind=='final' else None),
            roots=roots,foreign_path=str(report.parent/'unadmitted-producer-copy'/'CAPTURE.json'))
        summary=dict(status=value['evidence']['status'],native_or_rust_executions=0,
                     reader_writes=0,guard_probes=len(value['probes']),
                     physical_entries=len(value['before']),evidence=value['evidence'])
    report.parent.mkdir(parents=True,exist_ok=True)
    report.write_bytes(encoded(value))
    print(encoded(summary).decode(),end='')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kind',choices=('semantic','controls','final'),required=True)
    p.add_argument('--capture',type=Path,required=True);p.add_argument('--controls',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();run(a.kind,a.capture.resolve(strict=True),a.controls.absolute(),a.report.absolute())
