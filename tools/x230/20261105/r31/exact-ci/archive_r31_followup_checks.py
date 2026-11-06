#!/usr/bin/env python3
"""Local synthetic archive checks; never submit native jobs or run stored tools."""
import datetime
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
WORK = HERE.parent
spec = importlib.util.spec_from_file_location('followup_archive_under_test', HERE / 'archive_r31_followup.py')
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)
REAL_PINS = dict(archive.PINNED)


def fixture(root, passed):
    """Synthetic run metadata with real retained input/tool bytes where available.

    The only substituted frozen input pin is for an explicitly synthetic
    campaign-inputs file unavailable locally. This does not modify the archiver.
    All fixture archives remain inside a TemporaryDirectory and are deleted.
    """
    data = {name: b'{}\n' for name in archive.REQUIRED}
    with tarfile.open(WORK / 'r31_evidence/qualification-evidence-01.tar.gz') as original:
        names = {member.name for member in original}
        for name in REAL_PINS:
            if name in names:
                data[name] = original.extractfile(name).read()
    data['tools-01/r31_campaign.py'] = (HERE / 'recovery_v2/generated/r31_campaign.py').read_bytes()
    for name in ('terminal-original.json', 'read-envelope.json', 'stdout.log', 'stderr.log', 'remote-source-workflow.yml'):
        data['rust-ci-preflight-attempt-01/' + name] = (WORK / 'r31_exact_ci/failed_attempt_01' / name).read_bytes()
    for number, tools in [('01', WORK / 'r31_exact_ci/tools'), ('02', WORK / 'r31_exact_ci/attempt_02/tools')]:
        for path in tools.iterdir():
            if path.is_file():
                data['rust-ci-tools-' + number + '/' + path.name] = path.read_bytes()
    data['campaign-inputs-01.json'] = b'{"fixture_only":true}\n'
    plan = {'schema': 'hepta-r31-materialized-exact-rust-ci-plan/v1', 'attempt': '02',
            'qualification_job_id': archive.QUALIFICATION_JOB, 'fixture_only': True}
    data['rust-ci-plan-02.json'] = data['rust-ci-02/plan.json'] = archive.encoded(plan)

    def identity(name):
        raw = data[name]
        return {'path': str(archive.ROOT / name), 'bytes': len(raw), 'sha256': archive.sha(raw)}

    report = {'schema': 'hepta-r31-external-rust-ci/v1', 'attempt': '02', 'passed': passed,
        'plan': identity('rust-ci-plan-02.json'),
        'materializer': identity('rust-ci-tools-02/materialize_rust_ci_plan_01.py'),
        'auditor': identity('rust-ci-tools-02/audit_nextest_0137.py'),
        'launcher': identity('rust-ci-tools-02/run_rust_ci_01.py'),
        'stages': [], 'source_inputs_unchanged': passed, 'owned_children_closed': True,
        'hosted_actions_passed': False, 'automatic_retries': 0,
        'started_utc': 'synthetic-local-check', 'finished_utc': 'synthetic-local-check'}
    for index, name in enumerate(archive.STAGES if passed else archive.STAGES[:4]):
        stage_passed = passed or index < 3
        row = {'name': name, 'argv': ['synthetic-local-check'], 'passed': stage_passed,
            'returncode': 0 if stage_passed else 1, 'waited_and_reaped': True,
            'owned_process_absent': True, 'owned_process_group_absent': True, 'timed_out': False}
        for stream in ('stdout', 'stderr'):
            path = 'rust-ci-02/' + name + '.' + stream
            data[path] = ('synthetic ' + name + ' ' + stream + '\n').encode()
            row[stream] = identity(path)
        report['stages'].append(row)
    if passed:
        audit = {'verified': True, 'passed': 1653, 'failed': 0, 'ignored': 34, 'selected': 1687, 'retries': 0,
                 'fixture_only': True}
        report['nextest_output_audit'] = audit
        data['rust-ci-02/nextest-output-audit.json'] = archive.encoded(audit)
    else:
        report['error'] = {'type': 'SyntheticFailure', 'reason': 'failure retention check only'}
    data['rust-ci-02/report.json'] = archive.encoded(report)
    native = {'job_id': archive.CI_JOB, 'state': 'succeeded' if passed else 'failed',
        'exit_code': 0 if passed else 1, 'terminal_publication_confirmed': True,
        'automatic_retry': False, 'cancelled': False, 'timed_out': False,
        'output_complete': True, 'output_durable': True,
        'log_bytes': {name: {'seen': 0, 'stored': 0} for name in ('stdout', 'stderr')},
        'log_synced': {'stdout': True, 'stderr': True}, 'log_errors': {'stdout': None, 'stderr': None},
        'log_truncated': {'stdout': False, 'stderr': False}, 'fixture_only': True}
    data['rust-ci-native-02.json'] = archive.encoded(native)
    read = {'job_id': archive.CI_JOB, 'fixture_only': True}
    for name in ('stdout', 'stderr'):
        read[name] = {'offset': 0, 'next_offset': 0, 'size': 0, 'eof': True, 'bytes_hex': '', 'text': ''}
    data['rust-ci-native-read-02.json'] = archive.encoded(read)
    for name, raw in data.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    archive.PINNED = dict(REAL_PINS)
    archive.PINNED['campaign-inputs-01.json'] = archive.sha(data['campaign-inputs-01.json'])
    assert all(archive.sha(data[name]) == digest for name, digest in archive.PINNED.items())
    return archive.sha(data['rust-ci-plan-02.json'])


def rejected(call, text):
    try:
        call()
    except ValueError as error:
        assert text in str(error), str(error)
    else:
        raise AssertionError('expected rejection: ' + text)


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='r31-followup-local-check-') as temporary:
        base = Path(temporary)
        for passed in (False, True):
            root = base / ('passed' if passed else 'failed')
            root.mkdir()
            plan_sha = fixture(root, passed)
            result = archive.create_archive(root, 'exact-ci', plan_sha)
            verified = archive.verify_archive(Path(result['archive']), result['sha256'])
            assert result['reported_passed'] is passed and verified['reported_passed'] is passed
            assert result['receipt_binding_errors'] == verified['receipt_binding_errors'] == []
            assert (result['reported_nextest_counts'] is not None) is passed
            rejected(lambda: archive.create_archive(root, 'exact-ci', plan_sha), 'create-only')
            assert archive.sha(Path(result['archive']).read_bytes()) == result['sha256']
            rejected(lambda: archive.verify_archive(Path(result['archive']), '0' * 64), 'SHA256 differs')
            checks.append(('successful' if passed else 'failed') + '_original_result_round_trip_and_create_only')
        root = base / 'boundaries'
        root.mkdir()
        fixture(root, False)
        profile = root / 'rust-ci-02/profile'
        profile.mkdir()
        (profile / 'private.key').write_bytes(b'excluded profile fixture')
        target = root / 'rust-ci-02/target-build'
        target.mkdir()
        (target / 'candidate').write_bytes(b'\x7fELFexcluded')
        (root / 'rust-ci-02/elf-fixture').write_bytes(b'\x7fELFexcluded')
        selected, excluded = archive.collect(root, 'exact-ci')
        assert 'rust-ci-02/profile/' in excluded and 'rust-ci-02/target-build/' in excluded
        assert 'rust-ci-02/elf-fixture' in excluded
        assert all('private.key' not in name and 'elf-fixture' not in name for name in selected)
        checks.append('profile_target_and_elf_excluded')
        extra = root / 'rust-ci-02/extra.log'
        extra.symlink_to(root / 'rust-ci-02/report.json')
        rejected(lambda: archive.collect(root, 'exact-ci'), 'symlink input')
        extra.unlink()
        checks.append('symlink_rejected_without_following')
        extra.write_bytes(b'-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic marker\n')
        rejected(lambda: archive.collect(root, 'exact-ci'), 'private-key material')
        extra.unlink()
        checks.append('private_key_marker_rejected_before_archive_write')
        with extra.open('wb') as stream:
            stream.truncate(archive.MAX_FILE + 1)
        rejected(lambda: archive.collect(root, 'exact-ci'), 'file exceeds 8 MiB')
        extra.unlink()
        checks.append('oversized_file_rejected')
        data = bytearray((base / 'passed/exact-ci-evidence-01.tar.gz').read_bytes())
        data[-1] ^= 1
        corrupted = base / 'corrupted.tar.gz'
        corrupted.write_bytes(data)
        rejected(lambda: archive.verify_archive(corrupted, archive.sha(bytes(data[:-1]))), 'SHA256 differs')
        checks.append('corrupted_archive_rejected')
        archive.read_names(['rust-ci-native-read-02-000.json', 'rust-ci-native-read-02-001.json'])
        rejected(lambda: archive.read_names(['rust-ci-native-read-02-001.json']), 'contiguous from 000')
        rejected(lambda: archive.read_names(['rust-ci-native-read-02.json', 'rust-ci-native-read-02-000.json']), 'cannot be mixed')
        checks.append('native_read_pagination_inventory')
    archive.PINNED = REAL_PINS
    output = {'schema': 'hepta-r31-followup-archive-local-checks/v1', 'passed': True,
        'checked_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': checks,
        'script_sha256': archive.sha((HERE / 'archive_r31_followup.py').read_bytes()),
        'synthetic_run_metadata_only': True, 'native_calls': 0,
        'candidate_tests_or_benchmarks_run': False, 'archived_programs_executed': False,
        'fixture_archives_removed': True}
    print(json.dumps(output, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
