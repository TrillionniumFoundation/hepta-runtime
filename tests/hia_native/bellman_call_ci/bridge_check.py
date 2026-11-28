"""Admit every fresh worker build byte and its fixed callable component."""
from pathlib import Path
import hashlib,importlib,json,sys
ROOT=Path(__file__).resolve().parent
WORKER=ROOT/'worker-source'
def worker_reader():
    # The qualified worker has its own worker_transport/worker_evidence names.
    # Keep that complete dependency graph separate from the caller observer.
    folder=WORKER/'tests/hia_native/blocking_worker'
    names={p.stem for p in folder.glob('*.py')}
    saved={name:sys.modules[name] for name in names if name in sys.modules}
    previous_path=sys.path[:]
    for name in names:sys.modules.pop(name,None)
    sys.path.insert(0,str(folder))
    try:reader=importlib.import_module('worker_build_evidence').verify_build
    finally:
        for name in names:sys.modules.pop(name,None)
        sys.modules.update(saved);sys.path[:]=previous_path
    return reader
verify_build=worker_reader()

def admit_bridge(bridge):
    pins=json.loads((ROOT/'worker-pin.json').read_bytes())
    fixed=json.loads((WORKER/'native/bellman_worker_component.json').read_bytes())
    assert hashlib.sha256((WORKER/'native/bellman_worker_component.json').read_bytes()).hexdigest()==pins['fixed_component_sha256']
    built=verify_build(bridge.parent,WORKER,pins['source_pins_sha256'])
    actual=json.loads((bridge/'component.json').read_bytes())
    assert set(actual)==set(fixed)
    for key in fixed:
        if key!='assembler_tools':assert actual[key]==fixed[key],key
    raw=(bridge/'bellman-worker.elf').read_bytes()
    assert {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}==pins['executable']
    assert built['executable_sha256']==pins['executable']['sha256'] and built['native_or_rust_executed'] is False
    return actual,built
