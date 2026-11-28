"""Run the frozen pure pending reader under a full filesystem/native guard."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, sys, time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ['package','build','capture']:p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args();reader=load('pending_reader',ROOT/'verify.py');guard=load('pending_guard',ROOT/'read_only_guard.py')
    started=time.monotonic()
    result=guard.guarded(lambda:reader.verify(a.package.resolve(),a.build.resolve(),a.capture.resolve()),
        roots=[a.package,a.build,a.capture],foreign_path=Path('/dev/null'))
    assert result['before']==result['after'] and len(result['probes'])==11
    print(json.dumps(dict(status='READ_ONLY_PENDING_ABI_PASS',evidence=result['evidence'],
        unchanged_entries=len(result['before']),guard_refusals=len(result['probes']),
        native_executions=0,rust_executions=0,reader_writes=0,wall_seconds=time.monotonic()-started),sort_keys=True))
if __name__=='__main__':main()
