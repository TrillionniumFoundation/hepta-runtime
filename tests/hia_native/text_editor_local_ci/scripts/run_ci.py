#!/usr/bin/env python3
"""Fresh private 75-image graph, exact Rust reference, seven unchanged profiles."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_check import verify as verify_source


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def identity(path):
    return {'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}


def preserve_registry_archives(reference_build):
    rows = json.loads((reference_build / 'registry-sources.json').read_bytes())
    directory = reference_build / 'registry-archives'
    directory.mkdir()
    records = {}
    for row in rows:
        key = row['name'] + '-' + row['version']
        assert key not in records and '/' not in key and '..' not in Path(key).parts
        source = Path(row['archive']).resolve(strict=True)
        assert source.is_file() and source.name == key + '.crate'
        raw = source.read_bytes()
        assert sha(raw) == row['checksum']
        destination = directory / (key + '.crate')
        destination.write_bytes(raw)
        assert destination.read_bytes() == raw
        records[key] = {'path': str(destination.relative_to(reference_build)),
                        'bytes': len(raw), 'sha256': sha(raw)}
    put(reference_build / 'registry-archives.json', {
        'schema': 'hepta.text-local.retained-registry-archives.v1',
        'archives': records, 'downloaded_registry_not_modified': True})
    return len(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--hepta', type=Path)
    parser.add_argument('--rust-bin', type=Path)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    source_result = verify_source(source)
    if args.check_only:
        print(json.dumps(source_result, sort_keys=True))
        return
    assert os.environ.get('CI') == 'true', 'Rust/HIA/native execution in this package is authorized only in CI'
    assert args.output is not None and args.hepta is not None and args.rust_bin is not None
    hepta = args.hepta.resolve(strict=True)
    rust_bin = args.rust_bin.resolve(strict=True)
    output = args.output.resolve()
    assert not output.exists() and not output.is_relative_to(source) and not output.is_relative_to(hepta)
    output.mkdir(parents=True)
    work = output / 'input'
    shutil.copytree(source, work)
    (output / 'processes').mkdir()
    (output / 'profiles').mkdir()
    manifest_sha = sha((source / 'source-manifest.json').read_bytes())
    put(output / 'paths.json', {'schema': 'hepta.text-local.ci-paths.v1',
        'execution_root': str(output), 'source_manifest_sha256': manifest_sha,
        'source_package': str(source), 'hepta_source': str(hepta), 'rust_bin': str(rust_bin)})
    deps = json.loads((work / 'ci/dependencies.json').read_bytes())
    started = time.monotonic()
    processes = []
    report = {'schema': 'hepta.text-local.complete-ci.v1', 'status': 'RUNNING',
        'source_manifest_sha256': manifest_sha, 'expected_profiles': deps['profiles'],
        'expected_cases': deps['expected_total_cases'], 'fresh_native_graph_built': False,
        'fresh_original_reference_built': False, 'profiles_executed': [],
        'retained_evidence_verified': False, 'ordinary_cases_verified': 0,
        'private_serial_local_four_command_qualified': False,
        'existing_binary_inputs': False, 'bootstrap_reused': False,
        'outer_subprocess_timeout_seconds': None, 'internal_native_original_timeout_seconds': 60,
        'internal_reference_step_timeout_seconds': 180,
        'full_sdk_qualified': False, 'full_136_route_qualified': False,
        'full_async_runtime_qualified': False, 'native_task_registry_qualified': False,
        'native_future_cancellation_qualified': False, 'fresh_cold_qualified': False,
        'public_text_editor_route': False, 'production_activated': False,
        'old_path_removed': False, 'whole_runtime_replaced': False}

    def save():
        put(output / 'RECIPE.json', report)

    def execute(label, command):
        assert label.replace('-', '').isalnum() and all(row['label'] != label for row in processes)
        argv = list(map(str, command))
        begin = time.monotonic()
        row = {'label': label, 'argv': argv, 'cwd': str(output),
               'outer_timeout_seconds': None, 'exit_code': None, 'pid': None}
        print(json.dumps({'stage': label, 'status': 'STARTED'}), flush=True)
        try:
            with (output / 'processes' / (label + '.stdout')).open('xb') as stdout, \
                 (output / 'processes' / (label + '.stderr')).open('xb') as stderr:
                # The preserved inner programs own their 60/180-second limits
                # and their setsid process groups. An outer killpg would not
                # reach those new sessions; no misleading outer deadline is added.
                process = subprocess.Popen(argv, cwd=output, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
                row['pid'] = process.pid
                row['exit_code'] = process.wait()
        except BaseException:
            row['driver_exception'] = traceback.format_exc()
            raise
        finally:
            row['elapsed_seconds'] = time.monotonic() - begin
            for stream in ('stdout', 'stderr'):
                path = output / 'processes' / (label + '.' + stream)
                if path.exists():
                    row[stream] = {'path': str(path.relative_to(output)), **identity(path)}
            processes.append(row)
            put(output / 'processes/index.json', processes)
            print(json.dumps({'stage': label, 'exit_code': row['exit_code'],
                              'elapsed_seconds': row['elapsed_seconds']}), flush=True)
        return row

    save()
    try:
        native_process = execute('fresh-native-75', [sys.executable, '-I', '-B', work / 'build_portable.py',
            '--source', work / 'source', '--hepta', hepta, '--output', output / 'native-build'])
        original_process = execute('fresh-original-reference', [sys.executable, '-I', '-B', work / 'build_reference_portable.py',
            '--reference', work / 'reference-v1', '--output', output / 'reference-build', '--toolchain', rust_bin])
        report['fresh_native_graph_built'] = native_process['exit_code'] == 0
        report['fresh_original_reference_built'] = original_process['exit_code'] == 0
        if (output / 'reference-build/registry-sources.json').is_file():
            report['registry_archives_retained'] = preserve_registry_archives(output / 'reference-build')
        save()
        assert report['fresh_native_graph_built'] and report['fresh_original_reference_built'], 'fresh build failed; original logs preserved'
        from verify_complete import check_builds
        builds = check_builds(work, output, output)
        native_manifest = output / builds['native_manifest_relative']
        for profile in deps['profile_order']:
            result = execute('profile-' + profile.replace('_', '-'), [sys.executable, '-I', '-B', work / 'qualify_portable.py',
                '--profile', profile, '--source', work / 'source', '--reference', work / 'reference-v1',
                '--original', output / 'reference-build', '--manifest', native_manifest,
                '--members', output / 'native-build/typed-members.json', '--output', output / 'profiles' / profile])
            report['profiles_executed'].append({'profile': profile, 'exit_code': result['exit_code'],
                                               'expected_cases': deps['profiles'][profile]})
            save()
        assert all(row['exit_code'] == 0 for row in report['profiles_executed']), 'one or more original comparison profiles failed'
        reader = execute('read-retained-evidence', [sys.executable, '-I', '-B', work / 'scripts/verify_complete.py',
            '--source', work, '--evidence', output])
        assert reader['exit_code'] == 0, 'read-only retained-evidence verification failed'
        verified = json.loads((output / 'processes/read-retained-evidence.stdout').read_bytes())
        assert verified['status'] == 'RETAINED_COMPLETE_LOCAL_EVIDENCE_PASS'
        assert verified['ordinary_cases'] == 357 and verified['actual_native_records'] == 1428
        put(output / 'verification.json', verified)
        assert verify_source(source) == source_result
        assert verify_source(work) == source_result
        report.update(status='PASS', retained_evidence_verified=True,
            ordinary_cases_verified=verified['ordinary_cases'],
            actual_native_records_verified=verified['actual_native_records'],
            private_serial_local_four_command_qualified=True,
            native_elf=verified['native_elf'], original_elf=verified['original_elf'],
            verification_sha256=sha((output / 'verification.json').read_bytes()),
            complete_compared_response_state_bytes=verified['complete_compared_response_state_bytes'],
            complete_compared_file_bytes=verified['complete_compared_file_bytes'],
            source_package_unchanged=True, working_source_unchanged=True)
    except BaseException:
        report.update(status='FAIL', failure=traceback.format_exc())
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started
        save()
    print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
