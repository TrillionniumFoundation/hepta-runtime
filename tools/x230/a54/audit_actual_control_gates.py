#!/usr/bin/env python3
"""Audit already captured A54 control-plane originals without remote activity.

This verifies complete report/input bytes and their receipt relationships. It
does not claim a new physical read of the 216 remote sources or raw test logs.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import stat

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / 'runtime-resume/docs/experiments/x230/a54'
BASE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01'
RUN = BASE + '/a54-control-plane-gates-r01'
PINS = {
    'control-gates.entry.original.json': (56019, '9a8912bfac4469b25aaf3e695e311b66df193f803b0fc17d8e8e3c6cfecc8d95'),
    'control-gates.worker.original.json': (35661, '0dd41c0ef472a96eb7cc6de70da3541d2ce19634d31e81fdfcdbf5b91068ae4b'),
    'control-gates.inputs.original.json': (253872, 'ba9bcdb49bd3abbcf41682aa93e5df053fae4a6b7294563de8bb6f3c5688b5ea'),
    'qualification-r01.original.json': (61986, '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'),
    'entry-r01.original.json': (59536, 'a98b564f5db07c64b497b68098902192f71f7be6884e687e68b38e9e41f3e6c3'),
    'worker-r01.original.json': (8109, 'b7ee93502f5ba0a3861e4578da8301ebac9af8ceb9e1b535ad2e5a8c6af73a90'),
}
SUPPLEMENT = ROOT / 'recovery-review/a52-control-plane-gates/a52-control-plane-gates-source-r01.json.gz'
SUPPLEMENT_SHA = '2011e4e7d08962c8cffdeffb80cde6a0994e65d281e25f02c884951869f0f4c0'
RUNNER = ROOT / 'recovery-review/a54-qualification/actual-r01-acceptance/run_a54_control_plane_gates_r01.py'
RUNNER_SHA = 'd15093bf0132c46886bb9fc8026f895b6f796877cf21a83d49d321cd5ce13924'
checks = []
inputs = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check(ok, label):
    checks.append({'check': label, 'passed': bool(ok)})
    if not ok:
        raise ValueError(label)


def stamp(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path, expected_sha=None, expected_bytes=None):
    path = path.absolute()
    check(path == path.resolve(strict=True), 'direct local input: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        check(stat.S_ISREG(before.st_mode), 'regular local input: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        check(stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
              and len(raw) == before.st_size, 'stable local input: ' + str(path))
    finally:
        os.close(fd)
    check((expected_sha is None or sha(raw) == expected_sha)
          and (expected_bytes is None or len(raw) == expected_bytes), 'pinned original: ' + str(path))
    inputs.append({'path': str(path), 'bytes': len(raw), 'sha256': sha(raw), 'identity': stamp(before)})
    return raw


def receipt(value, path, digest, size=None):
    ident = value['identity']
    return (value['path'] == path and value['sha256'] == digest
            and len(ident) == 9 and stat.S_ISREG(ident[2]) and ident[3:6] == [1000, 1000, 1]
            and value['bytes'] == ident[6] and (size is None or value['bytes'] == size))


def audit():
    raws = {name: read(DOC / name, digest, size) for name, (size, digest) in PINS.items()}
    e, w, i, q = [json.loads(raws[name]) for name in (
        'control-gates.entry.original.json', 'control-gates.worker.original.json',
        'control-gates.inputs.original.json', 'qualification-r01.original.json')]
    bundle = json.loads(gzip.decompress(read(SUPPLEMENT, SUPPLEMENT_SHA, 336156)))
    runner = read(RUNNER, RUNNER_SHA, 29779)
    parent = json.loads(read(ROOT / 'runtime-resume/docs/experiments/x230/a53/control-gates.entry.original.json',
                             '4be56319acb630933eb17f6255de2916acfc55e1e30d2c9e1180b21a5a72f857'))
    check(e['schema'] == 'hepta-a54-control-plane-gates-entry/v1'
          and w['schema'] == 'hepta-a54-control-plane-gates-worker/v1', 'actual A54 report schemas')
    check(all(v['passed'] is True and not v['errors'] and not v['unexecuted'] for v in (e, w)), 'original entry and worker complete successfully')
    check(e['qualified_source_files'] == 175 and e['supplemental_source_files'] == 43
          and e['combined_source_files'] == 216 and e['planned_test_commands'] == 15
          and e['precheck_counted_as_test'] is False, 'original fixed 15 tests plus dependency precheck')
    check(e['inputs_unchanged_after'] and e['output_writers_settled']
          and w['inputs_unchanged_before'] and w['inputs_unchanged_after'], 'original input and output fences settled')
    check(e['automatic_retry'] is False and e['service_changes'] is False
          and w['automatic_retry'] is False and e['source_writes_requested'] == e['rust_commands'] == e['remote_calls'] == 0,
          'no retry, service change, source write, Rust command or remote call in original test harness')
    check(e['interpreter'] == e['subprocess_python3_path'] == '/usr/bin/python3', 'original exact Python interpreter')
    check(receipt(e['inputs'], RUN + '/inputs.json', PINS['control-gates.inputs.original.json'][1], 253872), 'entry binds full original input manifest')
    check(receipt(e['worker_report'], RUN + '/worker-report.json', PINS['control-gates.worker.original.json'][1], 35661), 'entry binds exact worker original')
    env = e['environment']
    check(env == i['environment'] and env['agent_accesses'] == 0 and env['metadata_trace_enabled'] is False
          and env['stage_umask'] == '022' and env['removed_names_only'] == ['HEPTA_RUNTIME_JOB_ID', 'SSH_AUTH_SOCK'],
          'original clean no-agent no-trace environment')
    check(env['fixed_values'] == {'CARGO_BUILD_JOBS': '2', 'CARGO_HOME': '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02',
          'CARGO_INCREMENTAL': '0', 'CARGO_TARGET_DIR': BASE + '/target', 'PATH': '/usr/bin:/bin',
          'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'RUST_TEST_THREADS': '2',
          'TMPDIR': RUN + '/tmp', 'TOKIO_WORKER_THREADS': '2'}, 'original fixed worker environment values')
    qualified = i['qualified']
    check(q['qualified'] and q['current_stage'] == 'complete' and q['source_tested'] == q['source_after']
          and qualified['label'] == 'A54' and qualified['source_files'] == 175
          and qualified['source_map'] == q['source_tested'] and qualified['source'] == q['source'], 'complete actual qualification and identical 175-source map')
    check(sha((json.dumps(qualified['source_map'], sort_keys=True, indent=2) + '\n').encode())
          == qualified['source_map_sha256'] == 'caecddb1c64ba2ac377d32f7d6880b85fe7d0013ea62931672ae16098efacf4c', 'exact original pretty 175-source map identity')
    check(all(all(qualified[k][field] == q[k][field] for field in ('path', 'sha256', 'compiler_source'))
              and qualified[k]['fresh'] is False and q[k]['cached'] is False for k in ('binary', 'test_binary'))
          and q['binary']['sha256'] == 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'
          and q['test_binary']['sha256'] == '9ae6a1ca692bea236a09771e6b5ca58d7c99454f7f4d51ccf11f1d5f1cd161eb', 'original qualified release and test ELF receipts')
    expected_logs = qualified['logs']
    check(len(expected_logs) == len(q['stages']) == 6 and set(expected_logs) == {s['name'] for s in q['stages']}
          and all(stage['returncode'] == 0 and receipt(expected_logs[stage['name']],
                  BASE + '/qualification-a54-compact-view-r01/' + stage['name'] + '.log', stage['log_sha256'])
                  for stage in q['stages']), 'all six original qualification log receipt paths and hashes')
    supplement = {name: base64.b64decode(value, validate=True) for name, value in bundle['files'].items()}
    manifest_raw = base64.b64decode(bundle['manifest_base64'], validate=True)
    manifest = json.loads(manifest_raw)
    check(sha(manifest_raw) == bundle['manifest_sha256'] and len(supplement) == len(manifest['files']) == 43,
          'full original supplemental bundle and manifest bytes')
    check({r['path'] for r in manifest['files']} == set(supplement)
          and all(len(supplement[r['path']]) == r['bytes'] and sha(supplement[r['path']]) == r['sha256']
                  for r in manifest['files']), 'all 43 supplemental physical local bodies match original manifest')
    smap = {name: sha(raw) for name, raw in supplement.items()}
    overlap = sorted(set(smap) & set(q['source_tested']))
    check(overlap == ['Cargo.toml', 'src/mcp/runtime/fileio.py']
          and all(smap[name] == q['source_tested'][name] for name in overlap), 'only two byte-identical source overlaps')
    combined = {**q['source_tested'], **smap}
    check(len(combined) == 216 and combined == i['copy_map'], 'exact fixed 216-source combined map')
    check(set(i['source_receipts']) == set(q['source_tested']) and all(
          receipt(i['source_receipts'][name], qualified['source'] + '/' + name, digest)
          for name, digest in q['source_tested'].items()), 'all 175 qualified source receipt paths and hashes')
    check(set(i['copy_receipts']) == set(combined) and all(
          receipt(i['copy_receipts'][name], RUN + '/source/' + name, digest)
          for name, digest in combined.items()), 'all 216 test-copy receipt paths and hashes')
    check(all(i['copy_receipts'][name]['bytes'] == rec['bytes'] for name, rec in i['source_receipts'].items())
          and all(i['copy_receipts'][name]['bytes'] == len(raw) for name, raw in supplement.items()),
          'all test-copy byte lengths match original qualification or supplemental bodies')
    originals = {rec['path']: rec for rec in i['original_inputs']}
    expected_originals = {
        BASE + '/tools/run_a54_control_plane_gates_r01.py': (29779, RUNNER_SHA),
        BASE + '/tools/prepare_qualify_a44_owner_barrier_r01.py': (49453, '84e5fc48a688f83987425ff357428230083948703d419db4be1227d6b1ed8113'),
        BASE + '/tools/run_a41_native_validation_r07.py': (51497, '6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9'),
        BASE + '/tools/a52-control-plane-gates-source-r01.json.gz': (336156, SUPPLEMENT_SHA),
        BASE + '/qualification-a54-compact-view-r01/report.json': PINS['qualification-r01.original.json'],
        BASE + '/a54-compact-view-entry-r01/entry-report.json': PINS['entry-r01.original.json'],
        BASE + '/a54-compact-view-entry-r01/worker-report.json': PINS['worker-r01.original.json'],
    }
    for rec in [qualified['binary'], qualified['test_binary'], *expected_logs.values()]:
        expected_originals[rec['path']] = (rec['bytes'], rec['sha256'])
    check(len(originals) == len(i['original_inputs']) == len(expected_originals) == 15
          and set(originals) == set(expected_originals) and all(
              receipt(originals[path], path, digest, size) for path, (size, digest) in expected_originals.items()),
          'all 15 original frozen input receipts have exact membership, paths, byte counts and hashes')
    command_raw = base64.b64decode(bundle['commands_base64'], validate=True)
    check(sha(command_raw) == bundle['commands_sha256'], 'original command declaration bytes')
    command_argv = [shlex.split(line) for line in command_raw.decode().splitlines() if line.startswith('python3 ')]
    for argv in command_argv:
        argv[0] = '/usr/bin/python3'
    check(len(e['commands']) == len(w['commands']) == len(parent['commands']) == len(command_argv) == 16, 'exact 16 original command rows')
    output_names = {f'command-{n:02d}.{stream}' for n in range(16) for stream in ('stdout', 'stderr')}
    output_names |= {'qualifier-worker.stdout', 'qualifier-worker.stderr'}
    check(set(e['final_output_receipts']) == output_names, 'all 34 final output receipt names')
    rows = []
    for n, (ec, wc, pc, argv) in enumerate(zip(e['commands'], w['commands'], parent['commands'], command_argv)):
        check(ec == {**wc, 'final_output_unchanged': True}, f'command {n}: original worker to entry equality')
        check(all(ec[k] == pc[k] for k in ('name', 'argv', 'timeout_seconds')) and ec['argv'] == argv
              and ec['timeout_seconds'] == (30 if n == 0 else 300), f'command {n}: unchanged original workload and timeout')
        check(ec['index'] == n and ec['executed'] and ec['execution_count'] == 1 and ec['status'] == 'passed'
              and ec['returncode'] == 0 and ec['gate_clear'] and ec['original_child_reaped']
              and ec['child_signal_mask_restored_before_exec'] and ec['parent_thread_count_at_launch'] == 1,
              f'command {n}: original single execution, host admission, exit and reaping')
        check(all(ec[stream] == e['final_output_receipts'][f'command-{n:02d}.{stream}']
                  and receipt(ec[stream], RUN + f'/command-{n:02d}.{stream}', ec[stream]['sha256'])
                  for stream in ('stdout', 'stderr')), f'command {n}: final output receipt stability')
        check(receipt(ec['host_gate'], RUN + f'/command-{n:02d}.host-gate.json', ec['host_gate']['sha256']),
              f'command {n}: complete original host-gate receipt')
        if n == 0:
            check('unittest' not in ec, 'dependency precheck excluded from unittest count')
        else:
            check(ec['unittest']['reported_tests'] > 0 and ec['unittest']['reported_skips'] == 0
                  and ec['unittest']['result_detail'] == '', f'command {n}: reported unittest success without skips')
        rows.append({k: ec[k] for k in ('index', 'name', 'argv', 'timeout_seconds', 'returncode')}
                    | {'reported_tests': ec.get('unittest', {}).get('reported_tests', 0)})
    reported_tests = sum(c.get('unittest', {}).get('reported_tests', 0) for c in e['commands'])
    check(reported_tests == e['tests_reported'] == w['tests_reported'] == 284
          and e['skips_reported'] == w['skips_reported'] == 0, '284 reported unittest cases and zero reported skips')
    c = e['worker_custody']
    ident = c['original_identity']
    check(c['pid'] == c['actual_waitpid'] == ident['pid'] == ident['pgrp'] == ident['session'] == 2841560
          and c['raw_wait_status'] == c['returncode'] == 0 and os.waitstatus_to_exitcode(c['raw_wait_status']) == 0,
          'original worker PID and exact wait status')
    check(c['executed'] and c['execution_count'] == 1 and c['custody_known'] and not c['custody_unknown']
          and c['custody_retained_until_reap'] and c['group_quiet_before_reap'] and c['original_child_reaped']
          and c['pidfd_opened'] and not c['signals'] and c['worker_permit_may_have_been_sent']
          and c['worker_permit_send_attempted'] and c['worker_permit_sent'], 'original pidfd, GO, known custody, no signal and quiet reaping')
    snapshot = c['terminal_group_snapshot']
    check(not snapshot['errors'] and not snapshot['live'] and snapshot['members'] == [{**ident, 'state': 'Z'}],
          'original worker group terminal snapshot has only unreaped original zombie')
    expected_argv = ['/usr/bin/python3', '-B', BASE + '/tools/run_a54_control_plane_gates_r01.py', '--worker',
                     '--runner-sha', RUNNER_SHA, '--bundle-sha', SUPPLEMENT_SHA,
                     '--qualification-sha', PINS['qualification-r01.original.json'][1],
                     '--qualification-entry-sha', PINS['entry-r01.original.json'][1],
                     '--qualification-worker-sha', PINS['worker-r01.original.json'][1],
                     '--inputs-sha', PINS['control-gates.inputs.original.json'][1], '--permit-fd', '3']
    check(c['argv'] == expected_argv, 'worker admitted with exact original runner, source, qualification and manifest pins')
    for rec in inputs:
        path = Path(rec['path'])
        check(stamp(path.lstat()) == rec['identity'] and sha(path.read_bytes()) == rec['sha256'], 'unchanged local input at final fence: ' + rec['path'])
    return {'schema': 'hepta-a54-control-plane-independent-original-report-audit/v1', 'passed': True,
            'original_job_id': '1a17984e450-96a-127a', 'qualified_source_files': 175,
            'supplemental_files': 43, 'identical_overlap_paths': overlap, 'combined_source_files': 216,
            'python_test_commands': 15, 'dependency_precheck_commands': 1, 'tests_reported': reported_tests,
            'skips_reported': 0, 'commands': rows, 'local_input_receipts': inputs, 'checks': checks,
            'original_worker_finished_utc': c['finished_utc'], 'original_entry_finished_utc': e['finished_utc'],
            'scope': 'Complete captured original entry, worker and input manifest; local 43 supplemental bodies; original receipt and custody consistency',
            'remote_calls': 0, 'runtime_executions': 0, 'physical_remote_sources_reread_by_this_audit': 0,
            'raw_test_output_bodies_reread_by_this_audit': 0, 'rust_commands': 0,
            'not_proven': ['independent raw stdout/stderr replay', 'new remote physical source or ELF rehash',
                           'native owner recovery', 'six-host acceptance', 'performance improvement']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('refuse existing audit output')
    result = audit()
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    with args.out.open('xb') as stream:
        stream.write(raw)
    print(json.dumps({'path': str(args.out), 'passed': True, 'checks': len(checks), 'bytes': len(raw), 'sha256': sha(raw)}))
