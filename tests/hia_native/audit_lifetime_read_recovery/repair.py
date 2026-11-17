"""Source-bound inert correction of one assertion-count registration."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
PRODUCER = '37310e4744addbab580cf4106545c54872c1b34f4990ebc675fe996c867648be'


def identity():
    raw = (ROOT / 'SOURCE_MANIFEST.json').read_bytes()
    manifest = json.loads(raw)
    actual = {}
    for path in sorted(ROOT.rglob('*')):
        if path.is_dir():
            continue
        assert path.is_file() and not path.is_symlink()
        name = path.relative_to(ROOT).as_posix()
        if name == 'SOURCE_MANIFEST.json':
            continue
        data = path.read_bytes()
        actual[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), mode=path.stat().st_mode & 0o777)
    assert actual == manifest['files']
    assert manifest['producer_source_sha256'] == PRODUCER
    return hashlib.sha256(raw).hexdigest()


def install(original):
    recovery = identity()
    original = Path(original).resolve(strict=True)
    sys.path.insert(0, str(original))
    import common
    import read_capture
    import reader_controls
    from read_only_guard import guarded
    assert common.ROOT == original and common.source() == PRODUCER
    binding = json.loads((ROOT / 'BINDING.json').read_bytes())
    for name, expected in binding['original_files'].items():
        assert common.pin(common.read(original / name)) == expected
    domain = common.loads(common.read(original / 'DOMAIN.json'))
    assert domain['checks_per_case']['capacity_beyond_512'] == 4
    cases = common.read(original / 'reference/cases.rs').decode()
    begin = cases.index('fn capacity_beyond_512()')
    end = cases.index('\nfn ', begin + 1)
    body = cases[begin:end]
    assert body.count('check(') == 5
    assert all(body.count('"' + label + '"') == 1 for label in binding['corrected_case_labels'])
    check_processes = read_capture.check_processes

    def corrected_processes(root, capture, supplied_domain):
        common.require(supplied_domain == domain, 'exact unchanged producer domain before explicit count correction')
        corrected = dict(supplied_domain, checks_per_case=dict(supplied_domain['checks_per_case']))
        corrected['checks_per_case']['capacity_beyond_512'] = 5
        return check_processes(root, capture, corrected)

    read_capture.check_processes = corrected_processes
    semantic = read_capture.semantic

    def corrected_semantic(root):
        result = semantic(root)
        result['reader_recovery_source_sha256'] = recovery
        result['producer_gate_status'] = 'FAIL'
        result['reader_correction'] = dict(case='capacity_beyond_512', original_expected=4, corrected_expected=5)
        return result

    read_capture.semantic = corrected_semantic

    def protected(operation, *, roots, foreign_path):
        assert len(roots) == 2 and Path(roots[0]).resolve() == original
        return guarded(operation, roots=[*roots, ROOT], foreign_path=foreign_path)

    old_check_proof = reader_controls.check_proof

    def check_proof(proof, capture):
        old_check_proof(proof, capture)
        expected = common.files(ROOT)
        observed = {key.split(':', 1)[1]: row for key, row in proof['before'].items()
                    if key.startswith('2:') and row['sha256'] is not None}
        common.require(set(observed) == set(expected), 'every explicit recovery source protected')
        for name, row in expected.items():
            old = observed[name]
            common.require(old['bytes'] == row['bytes'] and old['sha256'] == row['sha256']
                           and old['mode'] & 0o777 == row['mode'], 'complete protected recovery source bytes and modes')

    reader_controls.guarded = protected
    reader_controls.check_proof = check_proof
    return read_capture, reader_controls, protected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    parser.add_argument('--mode', choices=['read', 'controls'], default='read')
    parser.add_argument('--require-controls', action='store_true')
    args = parser.parse_args()
    assert identity() == args.source_manifest_sha256
    read_capture, controls, guarded = install(args.source)
    output = args.output.resolve(strict=True)
    if args.mode == 'controls':
        controls.run(output, PRODUCER)
    else:
        proof = guarded(lambda: read_capture.verify(output, require_controls=args.require_controls),
                        roots=[args.source.resolve(strict=True), output], foreign_path=Path('/dev/null'))
        assert proof['before'] == proof['after'] and len(proof['probes']) == 12
        assert proof['native_or_rust_executions'] == proof['reader_writes'] == 0
        print(json.dumps(proof, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
