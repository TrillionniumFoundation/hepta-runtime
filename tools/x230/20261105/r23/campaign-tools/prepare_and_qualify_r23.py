#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Create an isolated R23 candidate only after actual R22 publication readback."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r22')
ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r23')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    payload = json.load(sys.stdin)
    publication_path = BASE / 'final-publication-readback.json'
    publication = json.loads(publication_path.read_text())
    assert sha(publication_path) == payload['baseline_publication_sha256']
    assert publication['schema'] == 'hepta-r22-final-publication-readback/v1'
    assert publication['commit'] == payload['baseline_commit']
    assert all(publication[k] is True for k in ('verified', 'candidate_adopted', 'source_changes_published', 'branch_and_pr_heads_match'))
    assert publication['campaign_report_sha256'] == sha(BASE / 'campaign-01/report.json')
    campaign = json.loads((BASE / 'campaign-01/report.json').read_text())
    assert campaign['passed'] is True and campaign['adoption_passed'] is True
    assert publication['source_inputs_sha256'] == campaign['source_inputs_sha256']
    qualification = json.loads((BASE / 'qualification-01/report.json').read_text())
    assert qualification['qualified'] is True
    assert qualification['source_tested'] == qualification['source_after']
    for relative, digest in qualification['source_after'].items():
        assert sha(BASE / 'source' / relative) == digest, relative
    active = []
    for path in Path('/proc').glob('[0-9]*/comm'):
        try:
            name = path.read_text().strip()
            if name in ('cargo', 'rustc', 'rust-lld', 'ld.lld'):
                active.append({'pid': int(path.parent.name), 'name': name})
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    assert not active, active
    ROOT.mkdir(mode=0o700)
    started = time.monotonic()
    shutil.copytree(BASE / 'source', ROOT / 'source')
    (ROOT / 'campaign-tools').mkdir(mode=0o700)
    (ROOT / 'tools').mkdir(mode=0o700)
    changed = []
    for row in payload['files']:
        relative = Path(row['path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        path = ROOT / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if row.get('before_sha256') is not None:
            assert sha(path) == row['before_sha256'], row['path']
        else:
            assert not path.exists(), row['path']
        raw = base64.b64decode(row['data'], validate=True)
        assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        path.write_bytes(raw)
        changed.append({k: row[k] for k in ('path', 'sha256', 'bytes')})
    clone_started = time.monotonic()
    shutil.copytree(BASE / 'target-build', ROOT / 'target-build')
    preparation = {'schema': 'hepta-r23-preparation/v1',
                   'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'baseline_commit': payload['baseline_commit'],
                   'baseline_publication_sha256': payload['baseline_publication_sha256'],
                   'baseline_compilation_inputs_verified': len(qualification['source_after']),
                   'files': changed, 'private_cache_copy_seconds': time.monotonic() - clone_started,
                   'preparation_seconds': time.monotonic() - started,
                   'cache_reused': True, 'shared_hardlinks_created': False,
                   'production_services_modified': False}
    (ROOT / 'preparation.json').write_text(json.dumps(preparation, indent=2) + '\n')
    print(json.dumps({'prepared': True, 'files': changed, 'private_cache_copy_seconds': preparation['private_cache_copy_seconds']}), flush=True)
    command = ['/usr/bin/python3', '-B', str(ROOT / 'source/tools/x230/20261028/qualify.py'),
               '--source', str(ROOT / 'source'), '--output', str(ROOT / 'qualification-01'),
               '--target', str(ROOT / 'target-build'), '--cargo-home',
               '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02',
               '--jobs', '2', '--stage-timeout', '3600']
    result = subprocess.run(command, cwd=ROOT / 'source', timeout=10800)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
