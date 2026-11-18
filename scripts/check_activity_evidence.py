# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reject damaged current activity evidence, then restore and readmit every byte."""
from pathlib import Path
import argparse
import hashlib
import json
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_activity_qualification as native
import hia_native_activity_reference as reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('hepta', 'build', 'native', 'original', 'native-evidence', 'output'):
        parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--native-evidence-sha256', required=True)
    args = parser.parse_args()
    build, captured, originals = map(lambda path: path.resolve(strict=True),
        (args.build, args.native, args.original))
    output = args.output.resolve()
    native.require(not any(output.is_relative_to(path) for path in (ROOT, build, captured, originals)),
        'activity control output overlaps its immutable input trees')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / 'restoration').mkdir(mode=0o700)
    expected = args.native_evidence_sha256

    def admit():
        built = native.build_evidence(ROOT, build, hepta=args.hepta)
        actual = reference.captured_native(ROOT, build, captured, args.native_evidence, expected)
        old = {domain: reference.original_evidence(ROOT, build, captured, originals / domain,
            domain, args.native_evidence, expected) for domain in reference.DOMAINS}
        return {'build': built, 'native': actual, 'original': old}

    before = admit();bundle = native.object_at(build / 'audit-activity-build.json')
    module_path = native.confined(build, bundle['modules']['request_audit_active']['path'])
    metadata = native.object_at(module_path)
    graph = native.confined(build, bundle['graphs']['active_publication']['path'])
    graph_record = native.object_at(graph)
    scenarios = native.object_at(captured / 'active/result.json')['results']
    first = captured / 'active' / scenarios[0]['name'] / 'native'
    hot = native.object_at(captured / 'hot_cache/result.json')

    def changed_json(raw, update):
        value = json.loads(raw);update(value);return native.encoded(value)

    mutation = [
        ('owner-source', ROOT / 'native/request_audit_active.hepta', lambda raw: raw + b'\n'),
        ('borrowed-control-source', ROOT / native.HARNESS / 'test_audit_active_controls.py', lambda raw: raw + b'\n'),
        ('compiled-owner-image', module_path.parent / metadata['image'], lambda raw: bytes([raw[0] ^ 1]) + raw[1:]),
        ('complete-static-elf', graph.parent / graph_record['executable'], lambda raw: raw[:-1] + bytes([raw[-1] ^ 1])),
        ('packer-observer-empty', graph.parent / 'pack.stdout', lambda raw: b'{}\n'),
        ('native-process-exit', captured / 'processes/active/result.json',
            lambda raw: changed_json(raw, lambda row: row.update(exit_code=1))),
        ('native-process-timeout', captured / 'processes/hot_cache/result.json',
            lambda raw: changed_json(raw, lambda row: row.update(timed_out=True))),
        ('native-summary-empty', captured / 'processes/active/stdout', lambda raw: b'{}\n'),
        ('native-request-frame', first / 'stdin.bin', lambda raw: raw[:8] + bytes([raw[8] ^ 1]) + raw[9:]),
        ('native-response-frame', first / 'stdout.bin', lambda raw: raw[:40] + bytes([raw[40] ^ 1]) + raw[41:]),
        ('native-commuting-domain', captured / 'active/result.json',
            lambda raw: changed_json(raw, lambda row: row.update(commuting_operations_per_implementation=0))),
        ('cache-scripted-input', captured / 'hot_cache' / hot['inputs']['path'], lambda raw: raw + b'x'),
        ('cache-scripted-result', captured / 'hot_cache' / hot['native_results']['path'], lambda raw: raw[:-1]),
        ('publication-control-domain', captured / 'active_publication_controls/result.json',
            lambda raw: changed_json(raw, lambda row: row.update(checks=73))),
        ('fresh-original-summary', originals / 'active/complete-comparison.stdout', lambda raw: b'{}\n'),
        ('fresh-original-command', originals / 'active/complete-comparison.process.json',
            lambda raw: changed_json(raw, lambda row: row.update(command=['/bin/true']))),
        ('fresh-original-binary', originals / 'active/reference-build' / reference.BINS['active'],
            lambda raw: raw[:-1] + bytes([raw[-1] ^ 1])),
        ('fresh-original-count', originals / 'hot_cache/result.json',
            lambda raw: changed_json(raw, lambda row: row['comparison'].update(original_requests=0))),
    ]
    results = [];admissions = 1
    report = {'schema': 'hepta.audit-activity.evidence-controls.v1', 'status': 'RUNNING',
        'native_evidence_sha256': expected, 'controls': results, 'restored': False,
        'actual_native_executions_added': 0, 'actual_original_executions_added': 0,
        'production_activated': False, 'audit_storage_closed': False, 'whole_runtime_replaced': False}
    save = lambda: (output / 'result.json').write_bytes(native.encoded(report))
    save()
    try:
        for name, path, transform in mutation:
            raw = native.regular(path);mode = stat.S_IMODE(path.stat().st_mode);modified = transform(raw)
            native.require(modified != raw, 'empty activity evidence mutation')
            backup = output / 'restoration' / (name + '.bin')
            with backup.open('xb') as stream:
                stream.write(raw)
            (output / 'current-mutation.json').write_bytes(native.encoded({'name': name,
                'path': str(path), 'backup': str(backup), 'mode': mode,
                'before_sha256': hashlib.sha256(raw).hexdigest(),
                'after_sha256': hashlib.sha256(modified).hexdigest()}))
            rejected = None
            try:
                path.chmod(mode | stat.S_IWUSR);path.write_bytes(modified);path.chmod(mode)
                try:
                    admit()
                except (ValueError, AssertionError, KeyError, TypeError, IndexError, OSError,
                        UnicodeError, EOFError, json.JSONDecodeError) as error:
                    rejected = type(error).__name__ + ': ' + str(error)
            finally:
                path.chmod(mode | stat.S_IWUSR);path.write_bytes(raw);path.chmod(mode)
            native.require(rejected is not None, 'damaged activity evidence was admitted: ' + name)
            native.require(native.regular(path) == raw and stat.S_IMODE(path.stat().st_mode) == mode,
                'activity evidence restoration differs')
            native.require(admit() == before, 'complete activity readmission changed after restoration')
            admissions += 1;results.append({'name': name, 'rejected': True, 'reason': rejected,
                'restored_sha256': hashlib.sha256(raw).hexdigest(), 'restored_mode': mode});save()
        native.require(admit() == before, 'final complete activity evidence differs');admissions += 1
        report.update(status='PASS', damaged_evidence_refusals=len(results),
            complete_readmissions=admissions, restored=True,
            native_domains=len(native.DOMAINS), original_recipes=len(reference.DOMAINS))
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        save()
    print(json.dumps({key: value for key, value in report.items() if key != 'controls'}, sort_keys=True))


if __name__ == '__main__':
    main()
