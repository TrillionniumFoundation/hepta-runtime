# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reject changed real Stamp evidence and restore every byte before readmission."""
from pathlib import Path
import argparse
import copy
import json
import os
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hia_native_stamp_qualification as q
import hia_native_stamp_reference as reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'hepta', 'build', 'native', 'original', 'native-evidence', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--native-evidence-sha256', required=True)
    args = parser.parse_args();root = args.repo.resolve(strict=True);build = args.build.resolve(strict=True)
    native = args.native.resolve(strict=True);original = args.original.resolve(strict=True)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)

    def admit():
        return {'build': q.build_evidence(root, build, hepta=args.hepta),
            'native': reference.captured_native(root, build, native, args.native_evidence, args.native_evidence_sha256),
            'original': {domain: reference.original_evidence(root, build, native, original / domain, domain,
                args.native_evidence, args.native_evidence_sha256) for domain in reference.DOMAINS}}

    baseline = admit();baseline_sha = q.sha(q.encoded(baseline));rows = []
    report = {'schema': 'hepta.audit-stamp.evidence-controls.v1', 'status': 'RUNNING',
        'baseline_sha256': baseline_sha, 'controls': rows, 'rejections': 0, 'complete_readmissions': 1,
        'semantic_executions_added': 0, 'production_activated': False, 'whole_runtime_replaced': False}
    save = lambda: (args.output / 'result.json').write_bytes(q.encoded(report))
    save()

    def reject(name, path, change):
        raw = q.regular(path);mode = stat.S_IMODE(path.stat().st_mode);changed = change(raw)
        q.require(changed != raw, 'negative control did not change its evidence')
        error = None
        try:
            path.chmod(mode | stat.S_IWUSR);path.write_bytes(changed)
            try:
                admit()
            except (ValueError, KeyError, TypeError, AssertionError, OSError, UnicodeError) as caught:
                error = repr(caught)
            q.require(error is not None, 'changed Stamp evidence was accepted: ' + name)
        finally:
            path.write_bytes(raw);path.chmod(mode)
        q.require(q.regular(path) == raw and stat.S_IMODE(path.stat().st_mode) == mode
            and admit() == baseline, 'full original evidence did not return after restoration')
        rows.append({'name': name, 'path': str(path), 'original': {'bytes': len(raw), 'sha256': q.sha(raw)},
            'mutated_sha256': q.sha(changed), 'mode_restored': mode,
            'error': error, 'rejected': True, 'complete_readmission': True})
        report['rejections'] += 1;report['complete_readmissions'] += 1;save()

    def changed_json(update):
        def change(raw):
            value = json.loads(raw);update(value);return q.encoded(value)
        return change

    append = lambda raw: raw + b'\x00'
    bundle = q.object_at(build / 'audit-stamp-build.json')
    module = q.confined(build, bundle['modules']['request_audit_stamp']['path'])
    metadata = q.object_at(module);graph = q.confined(build, bundle['graphs']['stamp']['path'])
    old = original / 'stamp';old_build = old / 'reference-build'
    try:
        reject('compiled-source', module.parent / metadata['source'], append)
        reject('compiled-image', module.parent / metadata['image'], append)
        reject('static-embedded-image', graph.parent / q.object_at(graph)['executable'], append)
        reject('empty-packer-observer', graph.parent / 'pack.stdout', lambda raw: b'{}\n')
        reject('complete-compiler-output', module.parent / 'module.output.bin', append)
        reject('changed-native-deadline', native / 'processes/stamp/result.json',
            changed_json(lambda row: row.update(timeout_seconds=181)))
        reject('empty-actual-native-stdout', native / 'processes/stamp/stdout', lambda raw: b'{}\n')
        reject('complete-native-input', native / 'stamp/case-000/native/stdin.bin', append)
        reject('complete-native-output', native / 'stamp/case-000/native/stdout.bin', append)
        reject('changed-native-command', native / 'stamp/case-000/native/result.json',
            changed_json(lambda row: row['command'].append('unexpected')))
        reject('unreaped-native-process', native / 'stamp/case-000/native/result.json',
            changed_json(lambda row: row.update(child_reaped=False)))
        reject('unreached-kernel-control', native / 'stamp_kernel/case-000/native/kernel.json',
            changed_json(lambda row: row.update(all_selected_faults_reached=False)))
        reject('changed-native-external-seal', args.native_evidence, append)
        reject('fresh-original-binary', old_build / reference.BINS['stamp'], append)
        reject('changed-rust-version-stream', old_build / 'rust-version.stdout', append)
        reject('changed-original-replay-origin', old / 'comparison-stamp.process.json',
            changed_json(lambda row: row.update(cwd=str(original))))
        reject('complete-original-output', old / 'paired/stamp/case-000/original/stdout.bin', append)
        archives = sorted((old_build / 'registry-archives').glob('*.crate'))
        q.require(len(archives) == 22, 'complete locked registry absent before controls')
        reject('locked-package-archive', archives[0], append)
        reject('unchanged-original-source-block', old_build / 'reference/original_stamp.rs', append)
        q.require(len(rows) == 19 and all(row['rejected'] and row['complete_readmission'] for row in rows),
            'evidence control domain is incomplete')
        q.require(admit() == baseline, 'final full Stamp readmission differs')
        report.update(status='PASS', complete_readmissions=report['complete_readmissions'] + 1)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        save()
    print(json.dumps({'status': 'PASS', 'rejections': 19, 'complete_readmissions': 21,
        'semantic_executions_added': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
