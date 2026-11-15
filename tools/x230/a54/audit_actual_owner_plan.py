#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Audit one original A54 owner-recovery plan against actual qualified bindings.

This reads local downloaded originals only. No runtime, child, network, SSH,
private-key body or remote-directory operation is performed. Passing admission
is not a claim that any native fault-injection case has executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
BASE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01'
Q_SHA = '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'
ELF_SHA = 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'
MAP_SHA = '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'
PARENT_PLAN_SHA = 'cbd76b46e0a7e6c48eeefc70e47a7c20e707b4ea4edc4fc7674aff0d7dfb0c4c'
IDENTITY_SHA = '464d503f925044f7dd4f13288c31f7735ea427ee9f863531ecbb55a52238237b'
BINDING_SHA = '2c15c40362f9c085bf4cab79e47dcdcf3a5850b5cfc4d1c5463d39aafdc56e29'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--preparation-job-id', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    checks, receipts = [], {}

    def check(value, label):
        if not value:
            raise ValueError(label)
        checks.append({'check': label, 'passed': True})

    def read(path, expected):
        path = Path(path).absolute()
        check(path == path.resolve(strict=True) and path.is_file(), 'direct input: ' + str(path))
        before = path.stat()
        raw = path.read_bytes()
        check(before == path.stat() and len(raw) == before.st_size
              and digest(raw) == expected, 'unchanged exact input: ' + str(path))
        receipts[str(path)] = {'bytes': len(raw), 'sha256': expected}
        return raw

    check(re.fullmatch('[0-9a-f]{64}', args.plan_sha256) is not None,
          'actual complete plan SHA required')
    check(re.fullmatch('[0-9a-f]+-[0-9a-f]+-[0-9a-f]+', args.preparation_job_id) is not None,
          'actual original operator job identity required')
    raw = read(args.plan, args.plan_sha256)
    check(len(raw) <= 8192, 'bounded complete original plan')
    plan = json.loads(raw)
    previous = json.loads(read(ROOT / 'runtime-resume/docs/experiments/x230/a53/native-owner-plan.original.json',
                               PARENT_PLAN_SHA))
    q = json.loads(read(ROOT / 'runtime-resume/docs/experiments/x230/a54/qualification-r01.original.json', Q_SHA))
    bind = json.loads(read(ROOT / 'recovery-review/a54-qualification/actual-r01-acceptance/binding-manifest.json',
                           BINDING_SHA))
    check(q['qualified'] is True and q['current_stage'] == 'complete'
          and q['source_tested'] == q['source_after'] and len(q['source_tested']) == 175
          and [row['name'] for row in q['stages']] ==
          ['format', 'fmt-check', 'clean-package', 'clippy', 'test', 'release']
          and all(type(row['returncode']) is int and row['returncode'] == 0 for row in q['stages']),
          'complete original six-stage qualification')
    check(digest(json.dumps(q['source_tested'], sort_keys=True, separators=(',', ':')).encode()) == MAP_SHA
          and q['binary']['sha256'] == ELF_SHA, 'actual175 map and ELF')
    check(plan['qualification'] == {
        'path': BASE + '/qualification-a54-compact-view-r01/report.json',
        'sha256': Q_SHA, 'release_sha256': ELF_SHA, 'source_files': 175,
        'tested_map_compact_sha256': MAP_SHA}, 'complete actual qualification binding')
    allowed = {'attempt_nonce', 'harness_sha256', 'helper_sha256', 'local_out', 'qualification', 'remote_parent'}
    check(set(plan) == set(previous), 'original complete plan field set')
    changed = {key for key in plan if plan[key] != previous[key]}
    check(changed == allowed, 'only six declared identity/fixture binding changes from A53')
    for key in sorted(set(plan) - allowed):
        check(plan[key] == previous[key], 'original field unchanged: ' + key)
    check(plan['schema'] == 'hepta-native-remote-owner-plan/v1' and plan['ready'] is True
          and re.fullmatch('[0-9a-f]{64}', plan['attempt_nonce']) is not None,
          'ready plan with a fresh bounded nonce')
    check(plan['local_out'] == BASE + '/a54-native-owner-remote-r01'
          and plan['remote_parent'] == '/home/qq/hepta-runtime-native-owner-a54-r01',
          'exact new local and remote fixture scope')
    by_name = {Path(row['path']).name: row for row in bind['script_files']}
    for field, name in [('helper_sha256', 'remote_owner_custody_a54.py'),
                        ('harness_sha256', 'run_native_remote_owner_a54.py')]:
        row = by_name[name]
        body = read(row['path'], row['sha256'])
        check(len(body) == row['bytes'] and plan[field] == row['sha256'], 'actual frozen implementation: ' + name)
    check(plan['cases'] == ['controller-loss', 'reply-loss', 'owner-loss']
          and plan['execution_policy'] == {
              'business_launches': 3, 'controller_workers': 2, 'business_timeout_seconds': 90,
              'business_release_deadline_seconds': 75, 'helper_session_seconds': 150,
              'helper_cleanup_seconds': 20, 'ssh_cleanup_seconds': 40,
              'automatic_retry': False, 'service_changes': False, 'detached_fallback': False},
          'original three cases, deadlines and no-retry policy')
    identity = json.loads(read(ROOT / 'multihost-review/ai395-independent-identity.original.json', IDENTITY_SHA))
    check(all(plan['remote_identity'][key] == identity[key]
              for key in ('uid', 'home', 'hostname', 'boot_id', 'machine_id', 'machine'))
          and plan['remote_identity']['python_realpath'] == identity['python']
          and plan['controller_identity']['boot_id'] != identity['boot_id'],
          'original independent remote machine and distinct controller boot')
    check(plan['independent_admission']['sha256'] == IDENTITY_SHA
          and plan['independent_admission']['operator_job_id'] == '1a177d55de6-96a-1114',
          'same original independent operator provenance')
    check(digest(plan['business_code'].encode()) == plan['business_code_sha256']
          and plan['input_sha256'] == digest(('0123456789abcdef' * 256).encode()),
          'unchanged original business and 4096-byte stdin')
    for path, receipt in receipts.items():
        check(digest(Path(path).read_bytes()) == receipt['sha256'], 'final local input byte fence: ' + path)
    result = {'schema': 'hepta-a54-native-owner-plan-independent-audit/v1', 'passed': True,
              'original_plan': {'path': str(args.plan), 'bytes': len(raw), 'sha256': digest(raw)},
              'source_plan_preparation_job': args.preparation_job_id,
              'actual_qualification_sha256': Q_SHA, 'actual_release_sha256': ELF_SHA,
              'source_map_compact_sha256': MAP_SHA, 'source_files': 175,
              'changed_from_actual_a53_plan': sorted(changed), 'checks': checks,
              'input_receipts': receipts, 'remote_calls': 0, 'remote_writes': 0,
              'remote_processes_started': 0, 'private_key_contents_read': False,
              'native_acceptance_result_claimed': False,
              'fresh_remote_directory_existence_claimed': False,
              'freshness_enforced_by': 'root create-only preparation and frozen original helper/harness admission'}
    output = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    with args.out.open('xb') as stream:
        stream.write(output)
    print(json.dumps({'passed': True, 'checks': len(checks), 'path': str(args.out),
                      'bytes': len(output), 'sha256': digest(output)}))


if __name__ == '__main__':
    main()
