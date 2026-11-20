"""Run the complete DATA reader under the unchanged original 11-capability guard."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, sys, time
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import read_integration_capture as reader

p = argparse.ArgumentParser()
p.add_argument('--root', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
work = a.root.resolve(strict=True)
qualified = work / 'qualified'
reader.readers(qualified)  # Finish lazy Python imports before guard activation.
path = qualified / 'qualification/binary_params/v1/source/scripts/readonly.py'
spec = importlib.util.spec_from_file_location('original_typed_readonly_guard', path)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
origins = json.loads((work / 'CAPTURE_ORIGINS.json').read_bytes())
oldroot = Path(origins['runtime_audit_root'])
roots = [work / n for n in ('candidate', 'qualified', 'integration-third', 'rog-evidence', 'rog-input', 'reference-build')]
roots.append(work.parent / Path(origins['compiler_source']).relative_to(oldroot))
refs = json.loads((work / 'reference-build/REFERENCES.json').read_bytes())
for row in refs.values():
    manifest = work.parent / Path(row['manifest']).relative_to(oldroot)
    roots.append(manifest.parent)
    request = json.loads((manifest.parent / 'module.request.json').read_bytes())
    roots.append((work.parent / Path(request['image']).relative_to(oldroot)).parent)
# A tiny, separately owned input directory avoids allowing unrelated work files.
# The origin JSON and readers are copied byte for byte before this guard starts.
metadata = work / 'data-reader-inputs'
roots.append(metadata)
original_load = reader.load_json
def load_json(path):
    if path == work / 'CAPTURE_ORIGINS.json':
        return original_load(metadata / 'CAPTURE_ORIGINS.json')
    return original_load(path)
reader.load_json = load_json
start = time.monotonic()
report = guard.guarded(lambda: reader.read_all(work / 'integration-third', work / 'candidate', qualified,
    work / 'rog-evidence', work / 'rog-input'), roots=roots)
assert time.monotonic() - start < 180, 'original pure-reader 180 second budget'
assert report['evidence']['status'] == 'INTEGRATION_DATA_PASS'
report['elapsed_seconds'] = time.monotonic() - start
report['timeout_seconds'] = 180
a.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'entries': report['entries'], 'probes': len(report['probes']),
    'elapsed_seconds': report['elapsed_seconds'], 'evidence': report['evidence']}, sort_keys=True))
