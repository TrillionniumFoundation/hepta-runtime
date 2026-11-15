#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify a manifest-bound R25 snapshot copied privately from accepted R24."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r25')
BASE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
PUBLICATION_SHA = '38866c01fac54133c8a88e25bee90ea4a551e7273614f493bf44522a8273d3ca'
QUALIFICATION_SHA = 'bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971'
CAMPAIGN_SHA = '066952f12414e8f7291e21e58a77d53d4cd712104557bd6bdfdd7c383f9f1e2a'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    payload = json.load(sys.stdin)
    assert payload['schema'] == 'hepta-r25-source-install/v1'
    publication_path = BASE / 'final-publication-readback.json'
    assert sha(publication_path) == PUBLICATION_SHA
    publication = json.loads(publication_path.read_text())
    assert publication['schema'] == 'hepta-r24-final-publication-readback/v1'
    assert publication['commit'] == BASE_COMMIT == payload['baseline_commit']
    assert all(publication[key] is True for key in (
        'verified', 'candidate_adopted', 'source_changes_published', 'branch_and_pr_heads_match'))
    assert sha(BASE / 'campaign-01/report.json') == CAMPAIGN_SHA == publication['campaign_report_sha256']
    campaign = json.loads((BASE / 'campaign-01/report.json').read_text())
    assert campaign['passed'] is True and campaign['adoption_passed'] is True
    assert campaign['source_inputs_unchanged'] is True and campaign['inputs_unchanged'] is True
    assert publication['source_inputs_sha256'] == campaign['source_inputs_sha256']
    assert sha(BASE / 'qualification-01/report.json') == QUALIFICATION_SHA
    qualification = json.loads((BASE / 'qualification-01/report.json').read_text())
    assert qualification['qualified'] is True
    assert qualification['source_tested'] == qualification['source_after']
    for relative, expected in qualification['source_after'].items():
        assert sha(BASE / 'source' / relative) == expected, relative
    for value in qualification['binaries'].values():
        assert sha(Path(value['path'])) == value['sha256'], value['path']
    active = []
    for path in Path('/proc').glob('[0-9]*/comm'):
        try:
            name = path.read_text().strip()
            if name in ('cargo', 'rustc', 'rust-lld', 'ld.lld'):
                active.append({'pid': int(path.parent.name), 'name': name})
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    assert not active, active
    cache_files = [path for path in (BASE / 'target-build').rglob('*') if path.is_file()]
    cache_bytes = sum(path.stat().st_size for path in cache_files)
    assert cache_files and cache_bytes > 0
    disk = os.statvfs(BASE)
    available = disk.f_bavail * disk.f_frsize
    assert available >= cache_bytes + 3 * 1024**3, (available, cache_bytes)
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    started = time.monotonic()
    ROOT.mkdir(mode=0o700)
    (ROOT / 'source-install-input.json').write_text(json.dumps(payload, indent=2) + '\n')
    shutil.copytree(BASE / 'source', ROOT / 'source')
    (ROOT / 'tools').mkdir(mode=0o700)
    (ROOT / 'campaign-tools').mkdir(mode=0o700)
    changed = []
    seen = set()
    for row in payload['files']:
        relative = Path(row['path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        assert row['path'] not in seen
        seen.add(row['path'])
        path = ROOT / relative
        assert path.resolve().is_relative_to(ROOT)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if row.get('before_sha256') is not None:
            assert sha(path) == row['before_sha256'], row['path']
        else:
            assert not path.exists(), row['path']
        raw = row['text'].encode('utf-8')
        assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        path.write_bytes(raw)
        changed.append({key: row[key] for key in ('path', 'sha256', 'bytes')})
    expected_map = payload['candidate_compilation_inputs']
    assert set(expected_map) == set(qualification['source_after']) | set(payload.get('added_compilation_inputs', []))
    for relative, expected in expected_map.items():
        assert sha(ROOT / 'source' / relative) == expected, relative
    clone_started = time.monotonic()
    shutil.copytree(BASE / 'target-build', ROOT / 'target-build')
    preparation = {
        'schema': 'hepta-r25-preparation/v1', 'started_utc': started_utc,
        'baseline_commit': BASE_COMMIT, 'baseline_publication_sha256': PUBLICATION_SHA,
        'baseline_qualification_sha256': QUALIFICATION_SHA,
        'baseline_campaign_sha256': CAMPAIGN_SHA,
        'build_source_root': str(BASE), 'build_source_candidate_adopted': True,
        'build_source_compilation_inputs_verified': len(qualification['source_after']),
        'candidate_compilation_inputs_verified': len(expected_map),
        'cache_file_count': len(cache_files), 'cache_files_total_bytes': cache_bytes,
        'disk_available_before_bytes': available, 'files': changed,
        'private_cache_copy_seconds': time.monotonic() - clone_started,
        'preparation_seconds': time.monotonic() - started,
        'cache_reused': True, 'shared_hardlinks_created': False,
        'production_services_modified': False,
    }
    (ROOT / 'preparation.json').write_text(json.dumps(preparation, indent=2) + '\n')
    print(json.dumps({'prepared': True, 'files': changed,
                      'private_cache_copy_seconds': preparation['private_cache_copy_seconds']}), flush=True)
    command = ['/usr/bin/python3', '-B', str(ROOT / 'source/tools/x230/20261028/qualify.py'),
               '--source', str(ROOT / 'source'), '--output', str(ROOT / 'qualification-01'),
               '--target', str(ROOT / 'target-build'), '--cargo-home',
               '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02',
               '--jobs', '2', '--stage-timeout', '3600']
    result = subprocess.run(command, cwd=ROOT / 'source', timeout=10800)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
