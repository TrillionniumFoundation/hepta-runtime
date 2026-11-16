"""Physical mutations, two complete relocations, and fresh post-refusal reads."""
from pathlib import Path
import argparse
import json
import shutil
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, encoded, envelope, files, loads, pin, read, require, source
from read_only_guard import guarded
import read_capture

ERRORS = {
    'native-image': 'native module identity',
    'original-source': 'all actual original source bytes and modes',
    'compiler-tail': 'complete compiler output and tail',
    'response-bytes': 'byte-exact original/native stdout',
    'owner-arena-tail': 'native cache used extent or complete tail differs',
    'wait-return': 'all actual physical wait returns',
    'missing-case': 'every ordinary case exactly once',
    'process-budget': 'actual process command and original budget',
}


def mutation(root, name):
    if name in ('native-image','original-source','compiler-tail'):
        path={'native-image':'native/modules/extract-body/module.image.bin',
              'original-source':'original/project/src/original_core.rs',
              'compiler-tail':'native/bootstrap/B3.output.bin'}[name]
        raw=bytearray(read(root/path));raw[-1 if name=='compiler-tail' else len(raw)//2]^=1
        return {path:bytes(raw)}
    if name=='process-budget':
        path='processes/processes.json';rows=loads(read(root/path))
        require(rows[2]['name']=='ordinary-pairs','source-owned process to mutate')
        rows[2]['timeout_seconds']=181;return {path:encoded(rows)}
    if name=='missing-case':
        path='paired/RESULT.json';report=loads(read(root/path));report['cases'].pop()
        return {path:encoded(report)}
    if name=='wait-return':
        path='capabilities/events.json';rows=loads(read(root/path))
        row=next(row for row in rows if row.get('code')==0xffffffdf)
        row['code']=0;return {path:encoded(rows)}
    require(name in ('response-bytes','owner-arena-tail'),'fixed physical mutation')
    import cases,read_paired,run_ordinary
    report_path='paired/RESULT.json';report=loads(read(root/report_path))
    case=report['cases'][0]['folder'];prefix='paired/'+case
    result_path=prefix+'/native/result.json';row=loads(read(root/result_path))
    stream='stdout' if name=='response-bytes' else 'stderr';path=prefix+'/native/'+stream+'.bin'
    raw=bytearray(read(root/path))
    if name=='response-bytes':
        at=raw.index(b'Appended');raw[at]=ord('B')
        requests=read_paired.framed(read(root/(prefix+'/native/stdin.bin')))
        outputs=read_paired.framed(bytes(raw));spec=cases.cases()[0];setup=row['setup_frames']
        row['responses']=[run_ordinary.response(request,response,spec['operations'][i-setup] if i>=setup else None)
            for i,(request,response) in enumerate(zip(requests,outputs,strict=True))]
    else:raw[-1]^=1
    row['streams'][stream]=pin(raw)
    changed={path:bytes(raw),result_path:encoded(row)}
    pair_path=prefix+'/PAIR.json';pair=loads(read(root/pair_path))
    pair['captures']['native']['receipt']=pin(changed[result_path]);changed[pair_path]=encoded(pair)
    report['cases'][0]=dict(folder=case,receipt=pin(changed[pair_path]),**pair)
    changed[report_path]=encoded(report)
    return changed


def refused(root, expected):
    envelope(root)
    try:
        read_capture.semantic(root)
    except ValueError as failure:
        require(str(failure) == expected, 'specific semantic refusal rather than an unrelated failure')
        return dict(status='REFUSED', reason=str(failure))
    raise ValueError('reader admitted a source-owned physical mutation')


def check_proof(proof, capture):
    require(proof['schema'] == 'hepta.runtime.scope-span-readonly.v2'
            and proof['source_bound_guard'] is True and proof['native_or_rust_executions'] == 0
            and proof['reader_writes'] == 0 and proof['before'] == proof['after'], 'complete inert guard proof')
    expected_names = ['python-file-write', 'descriptor-open', 'descriptor-write', 'metadata-mode',
                      'metadata-time', 'directory-create', 'subprocess', 'shell', 'native-dlopen',
                      'native-mmap', 'producer-or-foreign-read', 'unadmitted-file-descriptor']
    require([row['name'] for row in proof['probes']] == expected_names
            and all(row['refusal'].startswith('owner-export read-only guard: ') for row in proof['probes']),
            'all twelve explicit guard refusals')
    require(type(proof['pid']) is int and proof['pid'] > 1 and proof['ppid'] != proof['pid'], 'reader process identity')
    for index, root in enumerate((ROOT, capture)):
        expected = files(root)
        observed = {key.split(':', 1)[1]: row for key, row in proof['before'].items()
                    if key.startswith(str(index) + ':') and row['sha256'] is not None}
        require(set(observed) == set(expected), 'proof retained every protected file')
        for name, row in expected.items():
            old = observed[name]
            require(old['sha256'] == row['sha256'] and old['bytes'] == row['bytes']
                    and old['mode'] & 0o777 == row['mode'], 'proof binds every complete protected file')


def run(output, expected_source):
    require(source() == expected_source, 'fixed reader source')
    original = output / 'semantic'
    baseline = read_capture.semantic(original)
    control_root = output / 'controls'
    control_root.mkdir()
    rows = []
    for name in ERRORS:
        folder = control_root / name
        folder.mkdir()
        capture = folder / 'capture'
        shutil.copytree(original, capture)
        changed = mutation(original, name)
        mutations = {}
        for path, raw in changed.items():
            old = read(capture / path)
            mutations[path] = dict(before=pin(old), after=pin(raw))
            (capture / path).write_bytes(raw)
        envelope_data = loads(read(capture / 'CAPTURE.json'))
        envelope_data['files'] = files(capture, ('CAPTURE.json',))
        (capture / 'CAPTURE.json').write_bytes(encoded(envelope_data))
        proof = guarded(lambda: refused(capture, ERRORS[name]), roots=[ROOT, capture], foreign_path=Path('/dev/null'))
        check_proof(proof, capture)
        (folder / 'PROOF.json').write_bytes(encoded(proof))
        rows.append(dict(name=name, capture=str(capture.relative_to(output)),
                         mutations=mutations,
                         proof=dict(file=str((folder / 'PROOF.json').relative_to(output)), **pin(encoded(proof))),
                         evidence=proof['evidence']))
    admissions = []
    for name in ('relocation-a', 'relocation-b', 'post-refusal-a', 'post-refusal-b'):
        folder = control_root / name
        folder.mkdir()
        capture = folder / 'capture'
        shutil.copytree(original, capture)
        require(files(capture) == files(original), 'relocation retains complete bytes, modes and set')
        proof = guarded(lambda: read_capture.semantic(capture), roots=[ROOT, capture], foreign_path=Path('/dev/null'))
        check_proof(proof, capture)
        require(proof['evidence'] == baseline, 'same evidence after complete relocation or refusal')
        (folder / 'PROOF.json').write_bytes(encoded(proof))
        admissions.append(dict(name=name, capture=str(capture.relative_to(output)),
                               proof=dict(file=str((folder / 'PROOF.json').relative_to(output)), **pin(encoded(proof))),
                               evidence=proof['evidence']))
    result = dict(schema='hepta.extract-lines.reader-controls.v1', source_manifest_sha256=expected_source,
                  refusals=rows, admissions=admissions, guard_proofs=12, guards_per_proof=12,
                  native_or_rust_executions=0, reader_writes=0, whole_runtime_replaced=False)
    (output / 'CONTROLS.json').write_bytes(encoded(result))
    require(verify(output, baseline)['status'] == 'PASS', 'complete retained controls verify')
    print(encoded(dict(status='PASS', refusals=8, relocated_admissions=2,
                       post_refusal_admissions=2, guard_proofs=12, native_or_rust_executions=0)).decode(), end='')


def verify(output, baseline):
    report = loads(read(output / 'CONTROLS.json'))
    require(report['schema'] == 'hepta.extract-lines.reader-controls.v1'
            and report['source_manifest_sha256'] == source() and report['guard_proofs'] == 12
            and report['guards_per_proof'] == 12 and report['native_or_rust_executions'] == report['reader_writes'] == 0
            and report['whole_runtime_replaced'] is False, 'source-bound inert reader controls')
    require([row['name'] for row in report['refusals']] == list(ERRORS), 'all eight fixed physical mutations')
    require([row['name'] for row in report['admissions']] == ['relocation-a', 'relocation-b', 'post-refusal-a', 'post-refusal-b'],
            'two full relocations and two post-refusal admissions')
    original = output / 'semantic'
    original_files = files(original)
    for row in report['refusals'] + report['admissions']:
        name = row['name']
        require(row['capture'] == 'controls/' + name + '/capture'
                and row['proof']['file'] == 'controls/' + name + '/PROOF.json', 'fixed control paths')
        capture = output / row['capture']
        proof_raw = read(output / row['proof']['file'])
        require(pin(proof_raw) == {key: row['proof'][key] for key in ('bytes', 'sha256')}, 'complete guard proof bytes')
        proof = loads(proof_raw)
        check_proof(proof, capture)
        require(proof['evidence'] == row['evidence'], 'retained result and complete guard agree')
        if name in ERRORS:
            changed = mutation(original, name)
            expected_files = dict(original_files)
            for path, expected_raw in changed.items():
                expected_files[path] = dict(**pin(expected_raw), mode=original_files[path]['mode'])
            envelope_data = loads(read(original / 'CAPTURE.json'))
            envelope_data['files'] = {key: value for key, value in expected_files.items() if key != 'CAPTURE.json'}
            expected_files['CAPTURE.json'] = dict(**pin(encoded(envelope_data)), mode=original_files['CAPTURE.json']['mode'])
            require(files(capture) == expected_files and all(read(capture / path) == raw for path,raw in changed.items()),
                    'exact physical mutation and fully rebound envelope')
            require(row['mutations'] == {path:dict(before=pin(read(original/path)),after=pin(raw)) for path,raw in changed.items()},
                    'retained exact mutation payload')
            require(refused(capture, ERRORS[name]) == row['evidence'], 'independent physical refusal')
        else:
            require(files(capture) == original_files and read_capture.semantic(capture) == baseline == row['evidence'],
                    'complete relocated or post-refusal capture remains admissible')
    return dict(status='PASS', refusals=8, relocated_admissions=2, post_refusal_admissions=2,
                guard_proofs=12, guards_per_proof=12, native_or_rust_executions=0, reader_writes=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    run(args.output.resolve(strict=True), args.source_manifest_sha256)
