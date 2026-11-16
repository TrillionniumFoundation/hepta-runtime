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
    'callable-instructions': 'every composed instruction equals the frozen adapter and admitted HIA modules',
    'observer-required': 'observer-free native process and closed domain',
    'emitted-instructions': 'exact emitted instruction bytes',
    'returned-code': 'every actual controller step returned its full frame',
    'actual-thread-id': 'native response and independently observed actual TID',
    'output-tail': 'complete controller output tail',
    'missing-record': 'every actual journal record exactly once',
    'quiescent-tail': 'complete quiescent kernel tail',
    'compile-image': 'complete composed module binding',
    'process-budget': 'actual process command and original budget',
    'effect-frame': 'exact HIA-emitted mechanical effect',
    'queue-before': 'complete shared queue byte chain',
}


def mutation(root, name):
    if name == 'callable-instructions':
        path = 'callable-emission/callable.bin'
        raw = bytearray(read(root / path)); raw[0] ^= 1
        return path, bytes(raw)
    if name == 'observer-required':
        path = 'observer-free/CALLABLE.json'
        report = loads(read(root / path)); report['observer_pointer'] = 1
        return path, encoded(report)
    if name in ('emitted-instructions', 'compile-image'):
        path = ('emission/boundary.bin' if name == 'emitted-instructions'
                else 'build/modules/audit-store-controller/module.image.bin')
        data = bytearray(read(root / path))
        data[len(data) // 2] ^= 1
        return path, bytes(data)
    if name == 'process-budget':
        path = 'processes/processes.json'
        rows = loads(read(root / path))
        require(rows[-1]['name'] == 'native-threads', 'mutated actual-thread process exists')
        rows[-1]['timeout_seconds'] = 181
        return path, encoded(rows)
    path = 'threads/journal.jsonl'
    rows = [loads(line) for line in read(root / path).splitlines()]
    if name == 'missing-record':
        rows.remove(min(rows, key=lambda row: row['index']))
    elif name == 'quiescent-tail':
        row = next(row for row in rows if row['record'] == 'quiescent')
        data = bytearray.fromhex(row['kernel_hex']); data[-1] ^= 1
        row['kernel_hex'] = data.hex()
    elif name == 'actual-thread-id':
        row = next(row for row in rows if row['record'] == 'boundary')
        row['tid'] += 1
    elif name == 'queue-before':
        row = next(row for row in rows if row['record'] == 'controller' and row['queue_owned'] and not row['initial'])
        data = bytearray.fromhex(row['queue_before_hex']); data[96] ^= 1
        row['queue_before_hex'] = data.hex()
    else:
        row = next(row for row in rows if row['record'] == 'controller'
                   and (name != 'effect-frame' or int.from_bytes(bytes.fromhex(row['output_after_hex'])[8:16], 'little') == 1))
        if name == 'returned-code':
            row['returned'] = 511
        elif name in ('output-tail', 'effect-frame'):
            data = bytearray.fromhex(row['output_after_hex'])
            data[-1 if name == 'output-tail' else 264] ^= 1
            row['output_after_hex'] = data.hex()
        else:
            raise ValueError('unknown fixed mutation')
    return path, b''.join((json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode() for row in rows)


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
        path, raw = mutation(original, name)
        old = read(capture / path)
        (capture / path).write_bytes(raw)
        envelope_data = loads(read(capture / 'CAPTURE.json'))
        envelope_data['files'] = files(capture, ('CAPTURE.json',))
        (capture / 'CAPTURE.json').write_bytes(encoded(envelope_data))
        proof = guarded(lambda: refused(capture, ERRORS[name]), roots=[ROOT, capture], foreign_path=Path('/dev/null'))
        check_proof(proof, capture)
        (folder / 'PROOF.json').write_bytes(encoded(proof))
        rows.append(dict(name=name, capture=str(capture.relative_to(output)),
                         mutation=dict(file=path, before=pin(old), after=pin(raw)),
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
    result = dict(schema='hepta.audit-store-controller.reader-controls.v1', source_manifest_sha256=expected_source,
                  refusals=rows, admissions=admissions, guard_proofs=16, guards_per_proof=12,
                  native_or_rust_executions=0, reader_writes=0, whole_runtime_replaced=False)
    (output / 'CONTROLS.json').write_bytes(encoded(result))
    require(verify(output, baseline)['status'] == 'PASS', 'complete retained controls verify')
    print(encoded(dict(status='PASS', refusals=12, relocated_admissions=2,
                       post_refusal_admissions=2, guard_proofs=16, native_or_rust_executions=0)).decode(), end='')


def verify(output, baseline):
    report = loads(read(output / 'CONTROLS.json'))
    require(report['schema'] == 'hepta.audit-store-controller.reader-controls.v1'
            and report['source_manifest_sha256'] == source() and report['guard_proofs'] == 16
            and report['guards_per_proof'] == 12 and report['native_or_rust_executions'] == report['reader_writes'] == 0
            and report['whole_runtime_replaced'] is False, 'source-bound inert reader controls')
    require([row['name'] for row in report['refusals']] == list(ERRORS), 'all twelve fixed physical mutations')
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
            path, expected_raw = mutation(original, name)
            expected_files = dict(original_files)
            expected_files[path] = dict(**pin(expected_raw), mode=original_files[path]['mode'])
            envelope_data = loads(read(original / 'CAPTURE.json'))
            envelope_data['files'] = {key: value for key, value in expected_files.items() if key != 'CAPTURE.json'}
            expected_files['CAPTURE.json'] = dict(**pin(encoded(envelope_data)), mode=original_files['CAPTURE.json']['mode'])
            require(files(capture) == expected_files and read(capture / path) == expected_raw,
                    'exact physical mutation and fully rebound envelope')
            require(row['mutation'] == dict(file=path, before=pin(read(original / path)), after=pin(expected_raw)),
                    'retained exact mutation payload')
            require(refused(capture, ERRORS[name]) == row['evidence'], 'independent physical refusal')
        else:
            require(files(capture) == original_files and read_capture.semantic(capture) == baseline == row['evidence'],
                    'complete relocated or post-refusal capture remains admissible')
    return dict(status='PASS', refusals=12, relocated_admissions=2, post_refusal_admissions=2,
                guard_proofs=16, guards_per_proof=12, native_or_rust_executions=0, reader_writes=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    run(args.output.resolve(strict=True), args.source_manifest_sha256)
