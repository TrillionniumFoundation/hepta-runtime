#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One final R18 lifecycle acceptance after fresh-target qualification.

No throughput rerun: exact R14 runtime identity reuses its existing observation
evidence. This planned canary binds the final artifact to six new jobs and
checks cancellation, owned transport interruption and controller restart.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
R16 = Path('/home/qian/hepta-runtime-optimization-20261104-r16')
R18 = Path('/home/qian/hepta-runtime-optimization-20261104-r18')
TOOLS = R16 / 'measurement-tools'
OUT = R18 / 'recovery-control-01'
CANARY = R16 / 'r18-cancel-recovery-01'
SOCKET = Path('/home/qian/h18c1')
ADOPTION = R18 / 'final-adoption.json'
READY_SHA = '003990f5d4beb5b86e6c41fabda034d3d2c6b767da43072f554ab1d30affa52b'
MAP_SHA = 'b874f7f608cb394fe8b1e7ccb0a6eb240f37dc46ead2aa2c719e767c86e49593'
FREEZE_SHA = '95450caab4049b6badb3056f7430c2a7c7da68d8316d99b173b51d9af7a97ff8'
BASELINE_REPORT = Path('/home/qian/hepta-runtime-optimization-20261103-r14/qualification-01/report.json')
BASELINE_REPORT_SHA = 'd6a46164b30c6677cf49ec7eea156748a8445589c71034795d016a62795610cd'
EXPECTED = {
    'hepta-runtime': '51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d',
    'hepta-runtime-jobctl': '61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62',
    'native_process_driver': '551aa5ba0f990908d0143c34f513a0f1937f14198335c5e4a611a112b82f944e',
}
TOPOLOGY = R16 / 'benchmark-topology.json'
TOPOLOGY_SHA = '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287'
PROFILE = Path('/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json')
PROFILE_SHA = 'fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08'
JOBS = Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')
HEX = re.compile(r'[0-9a-f]{64}\Z')


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def bound(entry, expected_path):
    need(entry['path'] == str(expected_path) and HEX.fullmatch(entry['sha256']), 'artifact binding differs')
    need(expected_path.resolve() == expected_path and expected_path.is_file(), 'artifact must be a direct regular file')
    raw = expected_path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == entry['sha256'], 'artifact bytes changed: ' + str(expected_path))
    return raw


def gate():
    raw = ADOPTION.read_bytes()
    adoption = json.loads(raw)
    need(adoption['schema'] == 'hepta-x230-r18-final-adoption/v1' and adoption['accepted'] is True,
         'final adoption has not been independently accepted')
    need(adoption['workers'] == 2 and adoption['arena_max'] == 1, 'selected configuration changed')
    need(adoption['qualification_attempt'] == 'qualification-02' and adoption['rejected_attempts'] == ['qualification-01'],
         'the stale-cache attempt must not be accepted')
    qualification = json.loads(bound(adoption['qualification_report'], R18 / 'qualification-02/report.json'))
    verification_raw = bound(adoption['independent_verification'], R18 / 'independent-acceptance-02.json')
    verification = json.loads(verification_raw)
    need(verification.get('schema') == 'hepta-r18-independent-acceptance/v1'
         and verification.get('accepted') is True and verification.get('checks')
         and all(value is True for value in verification['checks'].values()), 'independent acceptance did not pass')
    need(verification['qualified_report_path'] == str(R18 / 'qualification-02/report.json')
         and verification['qualified_report_sha256'] == adoption['qualification_report']['sha256']
         and verification['source_map_sha256'] == MAP_SHA and verification['source_compile_input_count'] == 219,
         'independent acceptance binds different inputs')
    need(qualification.get('qualified') is True, 'fresh-target qualification incomplete')
    need(sha(R18 / 'implementation-ready.json') == READY_SHA and sha(R18 / 'source-map.json') == MAP_SHA
         and sha(R18 / 'source-freeze.json') == FREEZE_SHA, 'prepared one-file candidate changed')
    inputs = json.loads((R18 / 'source-map.json').read_bytes())
    need(isinstance(inputs, dict) and len(inputs) == 219
         and inputs == qualification['source_input'] == qualification['source_tested'] == qualification['source_after'],
         'qualified inputs differ')
    actual_paths = {str(p.relative_to(R18 / 'source')) for name in ['src', 'examples']
                    for p in (R18 / 'source' / name).rglob('*') if p.is_file()}
    actual_paths.update(['Cargo.toml', 'Cargo.lock', 'rustfmt.toml'])
    need(actual_paths == set(inputs), 'compiler input set changed')
    for relative, expected in inputs.items():
        rel = Path(relative)
        need(not rel.is_absolute() and '..' not in rel.parts and HEX.fullmatch(expected), 'unsafe source identity')
        source = R18 / 'source' / rel
        need(source.resolve() == source and sha(source) == expected, 'source bytes changed: ' + relative)
    need(sha(BASELINE_REPORT) == BASELINE_REPORT_SHA, 'preserved baseline report changed')
    old = json.loads(BASELINE_REPORT.read_bytes())['source_tested']
    need(set(inputs) == set(old) and {p for p in inputs if inputs[p] != old[p]} == {'src/bin/jobctl.rs'},
         'candidate is not exactly the one-file jobctl change')
    need(inputs['src/bin/jobctl.rs'] == 'c22fdcd5bafad3a2123d5817c27fd73e7b5c26001bf1a8bdd6f8dbacabc8b562',
         'jobctl source differs')
    for name, expected in EXPECTED.items():
        path = R18 / 'qualification-02' / name
        need(qualification['binaries'][name]['path'] == str(path)
             and qualification['binaries'][name]['sha256'] == expected and sha(path) == expected,
             'qualified artifact identity differs: ' + name)
        receipt = verification['binaries'][name]
        need(receipt['path'] == str(path) and receipt['actual_sha256'] == expected
             and receipt['expected_sha256'] == expected and receipt['byte_for_byte_equal'] is True,
             'independent artifact comparison differs: ' + name)
    need(sha(TOPOLOGY) == TOPOLOGY_SHA and sha(PROFILE) == PROFILE_SHA, 'historical topology/profile changed')
    validation = json.loads((TOOLS / 'harness-validation-02.json').read_bytes())
    need(validation.get('success') is True and len(validation['files']) == 12, 'measurement tool freeze differs')
    for name, expected in validation['files'].items():
        need(Path(name).name == name and sha(TOOLS / name) == expected, 'measurement script changed')
    return {'adoption_sha256': hashlib.sha256(raw).hexdigest(), 'qualification_report': adoption['qualification_report'],
            'independent_verification': adoption['independent_verification'], 'source_inputs': inputs,
            'binaries': EXPECTED, 'measurement_scripts': validation['files'], 'workers': 2, 'arena_max': 1}


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher-sha256', required=True)
    args = parser.parse_args()
    need(HEX.fullmatch(args.launcher_sha256), 'Mac source-byte receipt required')
    need(sys.platform == 'linux' and os.geteuid() == 1000, 'wrong execution host/account')
    need(OUT.resolve() == OUT and not OUT.exists(), 'control output must be fresh')
    OUT.mkdir(mode=0o700)
    report = {'schema': 'hepta-x230-r18-recovery-control/v1', 'started_utc': utc(), 'passed': False,
              'remote_launcher_sha256_reported_by_mac': args.launcher_sha256, 'stages': [],
              'automatic_rpc_retries': 0, 'automatic_stage_retries': 0, 'production_service_changes': False,
              'throughput_campaign_repeated': False}
    initial = None

    def save():
        temp = OUT / 'report.next'
        write_new(temp, (json.dumps(report, indent=2) + '\n').encode())
        os.replace(temp, OUT / 'report.json')

    def stage(name, command, timeout):
        need(gate() == initial, 'final accepted inputs changed')
        row = {'name': name, 'argv': command, 'cwd': str(TOOLS), 'timeout_seconds': timeout,
               'start_monotonic_ns': time.monotonic_ns(), 'script_sha256': sha(command[2]), 'returncode': None}
        report['stages'].append(row)
        save()
        print(json.dumps({'stage': name, 'state': 'started'}), flush=True)
        try:
            with (OUT / (name + '.stdout')).open('xb') as stdout, (OUT / (name + '.stderr')).open('xb') as stderr:
                process = subprocess.Popen(command, cwd=TOOLS, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
                row['pid'] = process.pid
                try:
                    row['returncode'] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    row['timed_out'] = True
                    process.kill()  # Only the direct stage child owned by this invocation.
                    row['returncode'] = process.wait(timeout=30)
                    raise
        finally:
            row['end_monotonic_ns'] = time.monotonic_ns()
            row['seconds'] = (row['end_monotonic_ns'] - row['start_monotonic_ns']) / 1e9
            for stream in ['stdout', 'stderr']:
                path = OUT / (name + '.' + stream)
                if path.exists():
                    row[stream] = {'file': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path)}
            save()
        need(row['returncode'] == 0 and gate() == initial, name + ' failed or inputs changed')
        print(json.dumps({'stage': name, 'returncode': row['returncode'], 'seconds': row['seconds']}), flush=True)

    try:
        save()
        need(not CANARY.exists() and not SOCKET.exists(), 'fresh canary output/socket paths required')
        initial = gate()
        report['gate'] = initial
        write_new(OUT / 'final-adoption.json', ADOPTION.read_bytes())
        SOCKET.mkdir(mode=0o700)
        stage('cancel-recovery', ['/usr/bin/python3', '-B', str(TOOLS / 'run_six_host_cancel_recovery.py'),
              '--candidate', str(R18 / 'qualification-02/hepta-runtime'), '--candidate-arena-max', '1',
              '--profile-template', str(PROFILE), '--topology', str(TOPOLOGY), '--frozen-jobs', str(JOBS),
              '--socket-parent', str(SOCKET), '--out', str(CANARY), '--workers', '2', '--interrupt-host', 'rog'], 600)
        stage('recovery-independent-audit', ['/usr/bin/python3', '-B', str(TOOLS / 'verify_cancel_recovery.py'),
              '--report', str(CANARY / 'report.json'), '--output', str(CANARY / 'independent-summary.json')], 180)
        proof = json.loads((CANARY / 'independent-summary.json').read_bytes())
        need(proof['verified'] is True and proof['candidate_sha256'] == EXPECTED['hepta-runtime']
             and proof['source_sha256'] == sha(CANARY / 'report.json'), 'recovery evidence identity differs')
        report['artifacts'] = [{'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}
                               for path in [CANARY / 'report.json', CANARY / 'independent-summary.json']]
        report['passed'] = True
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'reason': str(error)}
        write_new(OUT / 'control.error.txt', traceback.format_exc().encode())
    finally:
        report['finished_utc'] = utc()
        save()
        print(json.dumps({'passed': report['passed'], 'error': report.get('error'), 'report': str(OUT / 'report.json')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
