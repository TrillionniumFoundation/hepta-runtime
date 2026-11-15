# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Mutate a quiescent owned qualification, restore it, and recheck every domain.

This evidence test executes no HIA or Rust. It must run only after the thirteen
native processes and all nine original processes have completed. The observed
source/build/native/original directories are temporarily modified in place.
"""
from pathlib import Path
import argparse
import json
import stat
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    for name in ('root', 'build', 'native', 'original', 'original-processes',
            'original-suite', 'native-evidence', 'native-evidence-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    root, build, native, original = [Path(getattr(args, key)).resolve(strict=True)
        for key in ('root', 'build', 'native', 'original')]
    suite_path = Path(args.original_suite).resolve(strict=True)
    processes = Path(args.original_processes).resolve(strict=True)
    evidence = Path(args.native_evidence).resolve(strict=True)
    output = Path(args.output).resolve()
    for observed in (root, build, native, original, processes):
        if output.is_relative_to(observed) or observed.is_relative_to(output):
            raise ValueError('control output overlaps an observed qualification')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / 'restoration').mkdir(mode=0o700)
    sys.path.insert(0, str(root / 'scripts'))
    import hia_native_result_storage_qualification as q
    import hia_native_result_storage_reference as r
    from result_storage_registry import encoded, regular, require, sha
    require(Path(q.__file__).resolve() == root / 'scripts/hia_native_result_storage_qualification.py'
        and Path(r.__file__).resolve() == root / 'scripts/hia_native_result_storage_reference.py',
        'evidence helper source root differs')
    original_pin, evidence_pin = q.pin(suite_path), q.pin(evidence)
    require(evidence_pin['sha256'] == args.native_evidence_sha256,
        'native evidence does not match the external seal')
    suite = q.object_at(suite_path)
    require(suite.get('schema') == 'hepta.result-storage.original-suite.v1'
        and suite.get('status') == 'PASS' and suite.get('sources_unchanged') is True
        and suite.get('domains') == 9 and suite.get('new_native_executions') == 0
        and suite.get('production_activated') is False and suite.get('result_storage_closed') is False
        and suite.get('native_evidence') == evidence_pin
        and set(suite['checks']) == set(suite['original_evidence']) == set(r.DOMAINS),
        'all original owners must complete before evidence controls')
    fixed_native = q.object_at(evidence)
    completed = {name: row['process_directory'] for name, row in fixed_native['domains'].items()}
    sources = q.source_pins(root)
    require(suite['sources'] == fixed_native['sources'] == sources,
        'native and original sources differ')
    started = time.monotonic()
    report = {'schema': 'hepta.result-storage.evidence-controls.v1', 'status': 'RUNNING',
        'script': q.pin(Path(__file__)), 'sources': sources, 'native_evidence': evidence_pin,
        'original_suite': original_pin, 'controls': [], 'complete_admissions': [],
        'new_native_executions': 0, 'new_original_executions': 0,
        'whole_runtime_replaced': False, 'production_activated': False,
        'result_storage_closed': False, 'requires_quiescent_owned_directories': True}
    save = lambda: (output / 'result.json').write_bytes(encoded(report))

    def selected_native(domain='storage_json', seal=None):
        return r.native_evidence(root, build, native, domain, evidence,
            args.native_evidence_sha256 if seal is None else seal)

    def original_domain(domain='storage_json'):
        folder = original / domain
        built = q.object_at(folder / 'build/result.json')
        command = [sys.executable, '-I', '-B', str(root / 'tests/hia_native/compare_result_storage_original.py'),
            '--root', str(root), '--build', str(build), '--native', str(native),
            '--output', str(folder), '--native-evidence', str(evidence),
            '--native-evidence-sha256', args.native_evidence_sha256,
            '--rustc', built['rustc_path'], '--cargo', built['cargo_path'], '--domain', domain]
        receipt, stdout, stderr = q.process_evidence(processes / domain, command, root)
        require(receipt == suite['checks'][domain] and not stderr,
            'external original completion differs')
        observed = r.original_evidence(root, build, native, folder, domain, evidence,
            args.native_evidence_sha256)
        require(observed == suite['original_evidence'][domain],
            'retained complete original admission differs')
        summary = {'status': 'PASS', 'domain': domain,
            'original_requests': observed['original_requests'],
            'original_processes': observed['original_processes'],
            'new_native_executions': 0, 'complete_original_native_bytes_equal': True}
        require(json.loads(stdout) == summary,
            'external original stdout does not describe the complete owner')
        return observed

    def complete(label):
        require(q.pin(evidence) == evidence_pin and q.pin(suite_path) == original_pin,
            'external evidence seals changed')
        require(q.native_evidence(root, build, native, completed) == fixed_native,
            'complete current native admission changed')
        observations = {name: original_domain(name) for name in r.DOMAINS}
        require(q.source_pins(root) == sources, 'source closure changed')
        report['complete_admissions'].append({'label': label, 'native_domains': len(completed),
            'original_domains': len(observations),
            'original_requests': sum(row['original_requests'] for row in observations.values()),
            'original_processes': sum(row['original_processes'] for row in observations.values()),
            'native_evidence': q.pin(evidence), 'original_suite': q.pin(suite_path)})
        save()

    def mutate(label, changes, validate):
        """Keep exact bytes/modes and restore them even if a refusal is missing."""
        originals = []
        row = {'name': label, 'passed': False, 'restored': False, 'files': []}
        try:
            for path, transform in changes:
                path = Path(path)
                require(path.is_file() and not path.is_symlink()
                    and any(path.is_relative_to(base) for base in (root, build, native, original, processes)),
                    'mutation target is not in the owned qualification')
                before = regular(path);mode = stat.S_IMODE(path.stat().st_mode)
                after = transform(before)
                require(type(after) is bytes and after != before, 'mutation did not change bytes')
                backup = output / 'restoration' / f'{len(report["controls"]):02d}-{len(originals):02d}.bin'
                with backup.open('xb') as stream:
                    stream.write(before)
                originals.append((path, before, mode))
                row['files'].append({'path': str(path), 'mode': mode, 'backup': str(backup),
                    'before': {'bytes': len(before), 'sha256': sha(before)},
                    'after': {'bytes': len(after), 'sha256': sha(after)}})
                # Keep an independently recoverable backup before any mutation.
                (output / 'current-mutation.json').write_bytes(encoded(row))
                path.chmod(mode | stat.S_IWUSR);path.write_bytes(after);path.chmod(mode)
            try:
                validate()
            except (ValueError, KeyError, TypeError, IndexError, UnicodeError, OSError) as error:
                row.update(passed=True, refusal_type=type(error).__name__, refusal=str(error))
            require(row['passed'], 'damaged evidence was admitted: ' + label)
        finally:
            for path, before, mode in reversed(originals):
                path.chmod(mode | stat.S_IWUSR);path.write_bytes(before);path.chmod(mode)
                require(regular(path) == before and stat.S_IMODE(path.stat().st_mode) == mode,
                    'mutation restoration failed: ' + str(path))
            row['restored'] = True
            report['controls'].append(row);save()

    def update(change):
        def transform(raw):
            value = json.loads(raw);change(value);return encoded(value)
        return transform

    def flip(raw):
        require(bool(raw), 'cannot flip an empty retained stream')
        at = len(raw) // 2
        return raw[:at] + bytes([raw[at] ^ 1]) + raw[at + 1:]

    def field(key, value):
        return update(lambda row: row.__setitem__(key, value))

    save()
    try:
        complete('before')
        bundle = q.object_at(build / 'result-storage-build.json')
        manifest = q.confined(build, bundle['modules']['storage_json']['path'])
        metadata = q.object_at(manifest)
        image = q.confined(manifest.parent, metadata['image'])
        graph = q.confined(build, bundle['graphs']['record_io']['path'])
        elf = q.confined(graph.parent, q.object_at(graph)['executable'])
        native_process = Path(completed['storage_json'])
        cases = [
            ('native-source-byte', root / 'native/request_storage_json.hepta', flip),
            ('native-image-byte', image, flip),
            ('static-elf-byte', elf, flip),
            ('compiler-empty-observer', manifest.parent / 'module.stdout.log', lambda _: b'{}\n'),
            ('native-complete-output', native / 'storage_json/native.stdout', flip),
            ('native-summary-count', native / 'storage_json/result.json', field('compared_cases', 4220)),
            ('native-completion-argv', native_process / 'result.json',
                update(lambda row: row['command'].append('--unobserved'))),
            ('native-completion-timeout', native_process / 'result.json', field('timed_out', True)),
            ('native-completion-stdout', native_process / 'stdout', flip),
        ]
        for label, path, transform in cases:
            mutate(label, [(path, transform)], selected_native)
        mutate('native-seal-byte', [(evidence, flip)], selected_native)
        mutate('native-resealed-missing-domain', [(evidence,
            update(lambda row: row['domains'].pop('archive_store_faults')))],
            lambda: selected_native(seal=q.pin(evidence)['sha256']))
        mutate('native-resealed-execution-count', [(evidence,
            field('new_original_executions_by_admission', 1))],
            lambda: selected_native(seal=q.pin(evidence)['sha256']))
        mutate('native-resealed-build-pin', [(evidence,
            update(lambda row: next(iter(row['build_artifacts'].values())).__setitem__('sha256', '0' * 64)))],
            lambda: selected_native(seal=q.pin(evidence)['sha256']))
        folder = original / 'storage_json';built = folder / 'build'
        registry = sorted((built / 'registry-archives').glob('*.crate'))[0]
        project_file = built / 'reference/Cargo.toml'
        original_cases = [
            ('original-comparison-status', folder / 'result.json', field('status', 'RUNNING')),
            ('original-reference-source', project_file, flip),
            ('original-locked-crate', registry, flip),
            ('original-elf-byte', built / r.BINS['storage_json'], flip),
            ('original-compile-command', built / 'compile.process.json',
                update(lambda row: row['command'].append('--unobserved'))),
            ('original-complete-input', folder / 'replay/complete.stdin', flip),
            ('original-complete-output', folder / 'replay/complete.stdout', flip),
            ('original-replay-cwd', folder / 'replay/complete.process.json', field('cwd', str(output))),
            ('original-replay-timeout', folder / 'replay/complete.process.json', field('timed_out', True)),
            ('original-outer-timeout', processes / 'storage_json/result.json', field('timed_out', True)),
        ]
        for label, path, transform in original_cases:
            mutate(label, [(path, transform)], original_domain)
        mutate('original-resealed-replay-command', [
            (folder / 'replay/complete.process.json', update(lambda row: row['command'].append('--unobserved'))),
            (folder / 'result.json', update(lambda row: row['replay']['checks']['complete']['command'].append('--unobserved'))),
        ], original_domain)
        mutate('original-filesystem-full-output',
            [(original / 'record_io/record_io/0000/complete-projected-output.bin', flip)],
            lambda: original_domain('record_io'))
        from result_storage_native_evidence import test_module
        raw_value = test_module(root, 'result_storage_raw_value')
        configuration = q.confined(build, bundle['graphs']['configuration']['path'])
        configuration = configuration.parent / q.object_at(configuration)['executable']
        for label, domain, name, transform in (
                ('native-raw-value-complete-input', 'safe_dto', 'native-owner.stdin.bin', flip),
                ('native-raw-value-complete-output', 'retention', 'native-owner.stdout.bin', flip),
                ('native-raw-value-completion', 'safe_dto', 'result.json', field('status', 'RUNNING'))):
            mutate(label, [(native / domain / 'raw-value' / name, transform)],
                lambda domain=domain: raw_value.native_evidence(root, domain, native / domain / 'raw-value', configuration))
        mutate('original-raw-value-complete-output',
            [(original / 'safe_dto/replay/raw-value/complete.stdout', flip)],
            lambda: original_domain('safe_dto'))
        mutate('original-raw-value-resealed-command', [
            (original / 'retention/replay/raw-value/complete.process.json',
                update(lambda row: row['command'].append('--unobserved'))),
            (original / 'retention/result.json',
                update(lambda row: row['replay']['checks']['raw-value/complete']['command'].append('--unobserved'))),
        ], lambda: original_domain('retention'))
        complete('after')
        require(len(report['controls']) == 30 and all(row['passed'] and row['restored'] for row in report['controls']),
            'fixed corruption domain is incomplete')
        report.update(status='PASS', rejected=len(report['controls']), complete_native_domains=13,
            complete_original_domains=9, restored_all_files=True, sources_unchanged=True)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started;save()
    print(json.dumps({key: report[key] for key in ('status', 'rejected', 'complete_native_domains',
        'complete_original_domains', 'new_native_executions', 'new_original_executions',
        'elapsed_seconds')}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
