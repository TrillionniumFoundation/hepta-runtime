"""Physical evidence-corruption controls; they never invoke a runtime target."""
from pathlib import Path
import hashlib, json, struct

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
NAMES = ('registry-output', 'registry-workspace', 'growth-preservation', 'missing-call',
         'projection-extent', 'original-token', 'original-send', 'original-context-id')


def mutation(name, native, original_raw):
    capture = json.loads((native / 'CAPTURE.json').read_bytes())
    changes = {}
    def selected(operation):
        return next(row for row in capture['calls'] if row['return_code'] == 160 and
            struct.unpack_from('<Q', (native / row['input']['path']).read_bytes(), 8)[0] == operation)
    def replace(pin, offset):
        raw = bytearray((native / pin['path']).read_bytes()); raw[offset] ^= 1; raw = bytes(raw)
        changes['native/' + pin['path']] = raw
        pin['bytes'], pin['sha256'] = len(raw), SHA(raw)
    if name == 'registry-output':
        replace(selected(2)['output'], 48)
    elif name == 'registry-workspace':
        replace(selected(2)['workspace'], 256 + 24)
    elif name == 'growth-preservation':
        i = next(i for i, row in enumerate(capture['calls']) if row['return_code'] == 0xffffffd0)
        replace(capture['calls'][i + 1]['before_workspace'], 128)
    elif name == 'missing-call':
        capture['calls'].remove(selected(11))
    elif name == 'projection-extent':
        capture['projections'][0]['return_code'] -= 1
    else:
        original = json.loads(original_raw)
        if name == 'original-token':
            event = next(e for e in original['events'] if e['action']['op'] == 'notify')
            event['after']['tasks'][0]['cancelled'] = False
        elif name == 'original-send':
            assert original['final']['sends']; original['final']['sends'].pop()
        elif name == 'original-context-id':
            original['events'][0]['after']['tasks'][0]['id'] = '17'
        else:
            raise AssertionError(name)
        changes['original.json'] = ENCODE(original)
        return changes
    changes['native/CAPTURE.json'] = ENCODE(capture)
    return changes


def refusal(case, folder):
    from reader import verify_case
    try:
        verify_case(case, json.loads((folder / 'original.json').read_bytes()), folder / 'native')
    except (AssertionError, ValueError, KeyError, IndexError) as error:
        return dict(refused=True, exception=type(error).__name__, message=str(error))
    raise RuntimeError('reader accepted changed evidence')


def verify_controls(source, run):
    from cases import cases
    index = 3; case = cases()[index]
    assert case['label'] == 'integer-cancel'
    native = run / 'native/case-003'
    original_raw = (run / 'reference/case-003/stdout.jsonl').read_bytes()
    base = {'native/' + p.name:p.read_bytes() for p in native.iterdir()}
    base['original.json'] = original_raw
    report = json.loads((run / 'CONTROLS.json').read_bytes())
    assert report['names'] == list(NAMES) and report['base_before'] == report['base_after']
    result = []
    for name in NAMES:
        folder = run / 'controls' / name
        expected = dict(base); changed = mutation(name, native, original_raw); expected.update(changed)
        actual = {p.relative_to(folder).as_posix():p.read_bytes() for p in folder.rglob('*') if p.is_file()}
        assert actual == expected
        actual_refusal = refusal(case, folder)
        stored = json.loads((run / 'control-readers' / (name + '.json')).read_bytes())
        assert stored['evidence'] == actual_refusal and stored['before'] == stored['after']
        assert stored['reader_writes'] == stored['native_or_rust_executions'] == 0
        assert len(stored['probes']) == 11 and stored['source_bound_guard']
        result.append(dict(name=name, refusal=actual_refusal, mutations={path:dict(
            before_sha256=SHA(base[path]), after_sha256=SHA(raw), bytes=len(raw)) for path, raw in changed.items()}))
    assert report['controls'] == result
    return result
