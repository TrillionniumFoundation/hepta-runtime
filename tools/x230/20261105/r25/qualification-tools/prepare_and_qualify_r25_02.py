#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Requalify the corrected fixture in fresh paths; preserve the failed original."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r25')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
OLD_SOURCE = ROOT / 'source'
NEW_SOURCE = ROOT / 'source-02'
NEW_TARGET = ROOT / 'target-build-02'
NEW_OUTPUT = ROOT / 'qualification-02'
OLD_REPORT_SHA = '3a376fe209f8721530b104434d9e602c7251290f4be0b932c45a525ec3543228'
OLD_MAP_SHA = '6458e4b707ecf42c22bada97864910dbc508db7cadb0560f471bf9185efa9226'
OLD_SUMMARY_SHA = 'ca3688f21091e00749c4e79356819dbd2c80aa8f421a535a058ffc18d0b9db74'
FIX_PATH = 'src/mcp/runtime/ssh_direct_cancellation_tests.rs'
FIX_BEFORE_SHA = 'ef56e7844a1d95c5de4d46d97cddbd2ee3661c17f761c6cc456b980f12544bfc'
FIX_AFTER_SHA = '5d3f850d932e0a2b40f299a011f0f47d120def145293a7b5297b040cd4800332'
FAILURE_NAME = 'mcp::runtime::ssh::direct::tests::cancellation_tests::public_start_reuse_and_cancel_keep_internal_reservation_selection'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def source_map(source):
    paths = [source / p for p in ('Cargo.toml', 'Cargo.lock', 'rustfmt.toml')]
    for directory in ('src', 'examples'):
        paths.extend(p for p in (source / directory).rglob('*') if p.is_file())
    return {str(p.relative_to(source)): sha(p) for p in sorted(paths) if p.is_file()}


def harness_map(source):
    return {p.name: sha(p) for p in sorted((source / 'tools/x230/20261028').glob('*.py'))}


def wait_for_compiler_quiescence():
    deadline = time.monotonic() + 300
    samples = []
    while True:
        active = []
        for path in Path('/proc').glob('[0-9]*/comm'):
            try:
                name = path.read_text().strip()
                if name in ('cargo', 'rustc', 'rust-lld', 'ld.lld'):
                    active.append({'pid': int(path.parent.name), 'name': name})
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
        samples.append({'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'active': active})
        if not active:
            return samples
        if time.monotonic() >= deadline:
            raise RuntimeError('compiler/cache quiescence unavailable; no cache copy or tests started')
        if len(samples) == 1:
            print(json.dumps({'waiting_for_compiler_quiescence': active}), flush=True)
        time.sleep(2)


def main():
    payload_path = ROOT / 'tools/requalification-02-input.json'
    payload = json.loads(payload_path.read_text())
    assert payload['schema'] == 'hepta-r25-fixture-requalification/v1'
    assert payload['original_job_id'] == '1a1aa7fa690-fc05-43af'
    status = payload['original_terminal_status']
    assert status['job_id'] == payload['original_job_id']
    assert status['state'] == 'failed' and status['exit_code'] == 1
    assert status['terminal_publication_confirmed'] is True
    assert status['output_complete'] is True and status['output_durable'] is True
    assert not status['automatic_retry'] and not status['cancelled'] and not status['timed_out']
    old_report_path = ROOT / 'qualification-01/report.json'
    old_map_path = ROOT / 'qualification-01/source-map.json'
    old_summary_path = ROOT / 'qualification-01/isolated-tests/summary.json'
    assert sha(old_report_path) == OLD_REPORT_SHA
    assert sha(old_map_path) == OLD_MAP_SHA
    assert sha(old_summary_path) == OLD_SUMMARY_SHA
    old_report = json.loads(old_report_path.read_text())
    assert old_report['qualified'] is False
    assert old_report['current_stage'] == 'isolated-tests'
    assert len(old_report['stages']) == 6
    assert all(s['returncode'] == 0 for s in old_report['stages'][:-1])
    assert old_report['stages'][-1]['returncode'] == 1
    summary = json.loads(old_summary_path.read_text())
    assert [summary[k] for k in ('passed', 'failed', 'ignored', 'selected', 'retries')] == [1652, 1, 34, 1687, 0]
    ledger = ROOT / 'qualification-01/isolated-tests/tests.jsonl'
    assert sha(ledger) == 'b7bade9c1eb9d47598e3a1c0b0c0d9aad675637238666006e5e1519502cc1251'
    failures = [json.loads(line) for line in ledger.read_text().splitlines()
                if json.loads(line).get('status') == 'failed']
    assert len(failures) == 1 and failures[0]['name'] == FAILURE_NAME
    old_map = json.loads(old_map_path.read_text())
    assert len(old_map) == 221 and source_map(OLD_SOURCE) == old_map == old_report['source_tested']
    assert old_map[FIX_PATH] == FIX_BEFORE_SHA
    harness = old_report['harness_before']
    assert len(harness) == 19 and harness_map(OLD_SOURCE) == harness
    old_text = (OLD_SOURCE / FIX_PATH).read_text()
    new_text = payload['corrected_fixture']
    assert len(new_text.encode()) == 15702 and hashlib.sha256(new_text.encode()).hexdigest() == FIX_AFTER_SHA
    before = '"remote_state_dir":"/fixture-operator", "allow_execute":true}'
    after = '"remote_state_dir":"/fixture-operator", "allow_execute":true, "allow_job_network":true}'
    assert old_text.count(before) == 1 and new_text == old_text.replace(before, after, 1)
    publication_path = BASE / 'final-publication-readback.json'
    assert sha(publication_path) == '38866c01fac54133c8a88e25bee90ea4a551e7273614f493bf44522a8273d3ca'
    publication = json.loads(publication_path.read_text())
    assert publication['commit'] == 'baab4def80be7af015b2e7a594cb302f66c4130e'
    assert publication['candidate_adopted'] is True
    for path in (NEW_SOURCE, NEW_TARGET, NEW_OUTPUT, ROOT / 'preparation-02.json'):
        assert not os.path.lexists(path), str(path)
    quiescence = wait_for_compiler_quiescence()
    cache = ROOT / 'target-build'
    cache_files = [p for p in cache.rglob('*') if p.is_file()]
    cache_bytes = sum(p.stat().st_size for p in cache_files)
    disk = os.statvfs(ROOT)
    available = disk.f_bavail * disk.f_frsize
    assert cache_files and available >= cache_bytes + 3 * 1024**3, (available, cache_bytes)
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    started = time.monotonic()
    shutil.copytree(OLD_SOURCE, NEW_SOURCE)
    (NEW_SOURCE / FIX_PATH).write_text(new_text)
    expected = dict(old_map)
    expected[FIX_PATH] = FIX_AFTER_SHA
    assert source_map(NEW_SOURCE) == expected
    assert source_map(OLD_SOURCE) == old_map
    assert harness_map(NEW_SOURCE) == harness_map(OLD_SOURCE) == harness
    cache_started = time.monotonic()
    shutil.copytree(cache, NEW_TARGET)
    preparation = {
        'schema': 'hepta-r25-requalification-preparation/v1', 'started_utc': started_utc,
        'original_job_id': payload['original_job_id'], 'original_qualification_passed': False,
        'original_report_sha256': OLD_REPORT_SHA, 'original_source_map_sha256': OLD_MAP_SHA,
        'original_test_summary_sha256': OLD_SUMMARY_SHA, 'original_counts': {k: summary[k] for k in ('passed','failed','ignored','selected','retries')},
        'failed_case': FAILURE_NAME, 'reason': 'test fixture omitted required explicit operator allow_job_network=true',
        'source': str(NEW_SOURCE), 'qualification_output': str(NEW_OUTPUT), 'target': str(NEW_TARGET),
        'source_before': old_map, 'candidate_compilation_inputs': expected,
        'harness_before': harness, 'compiler_quiescence_samples': quiescence,
        'source_changes': [{'path': FIX_PATH, 'before_sha256': FIX_BEFORE_SHA, 'sha256': FIX_AFTER_SHA, 'bytes': 15702}],
        'production_source_changed_from_attempt_01': False, 'test_assertions_changed': False,
        'previous_attempt_preserved': True, 'automatic_test_retries': 0,
        'cache_source': str(cache), 'cache_source_qualified': False, 'cache_reused': True,
        'cache_file_count': len(cache_files), 'cache_files_total_bytes': cache_bytes,
        'private_cache_copy_seconds': time.monotonic() - cache_started,
        'shared_hardlinks_created': False, 'disk_available_before_bytes': available,
        'preparation_seconds': time.monotonic() - started, 'production_services_modified': False,
        'input': {'path': str(payload_path), 'sha256': sha(payload_path)},
        'launcher': {'path': str(Path(__file__)), 'sha256': sha(Path(__file__))},
    }
    with (ROOT / 'preparation-02.json').open('x') as stream:
        json.dump(preparation, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'prepared': True, 'changed_source_paths': [FIX_PATH],
                      'production_source_changed': False, 'cache_copy_seconds': preparation['private_cache_copy_seconds']}), flush=True)
    command = ['/usr/bin/python3', '-B', str(NEW_SOURCE / 'tools/x230/20261028/qualify.py'),
               '--source', str(NEW_SOURCE), '--output', str(NEW_OUTPUT), '--target', str(NEW_TARGET),
               '--cargo-home', '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02',
               '--jobs', '2', '--stage-timeout', '3600']
    result = subprocess.run(command, cwd=NEW_SOURCE, timeout=10800)
    assert sha(old_report_path) == OLD_REPORT_SHA and source_map(OLD_SOURCE) == old_map
    assert harness_map(NEW_SOURCE) == harness_map(OLD_SOURCE) == harness
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
