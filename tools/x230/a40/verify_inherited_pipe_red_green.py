#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Run the same bounded inherited-pipe fixture against two original runners.

This is a Linux functional fault check, not a performance comparison. The
fixture's self-expiring grandchild and subreaper cleanup remain unchanged.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def raw_constant(text, name):
    marker = 'const ' + name + ': &str = r#"'
    require(text.count(marker) == 1, 'missing or ambiguous Rust raw constant: ' + name)
    value = text.split(marker, 1)[1]
    require('"#;' in value, 'unterminated Rust raw constant: ' + name)
    return value.split('"#;', 1)[0]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def validate_common(observed):
    require(observed['schema'] == 'hepta-inherited-pipe-drain-fixture/v1', 'fixture schema differs')
    require(observed['cleanup'] == [] and observed['state']['runner_exception'] is None,
            'fixture rescue or runner exception cannot establish a product pass')
    require(observed['workload_popen_count'] == 1 and type(observed['workload_pid']) is int
            and observed['workload_pid'] > 0, 'expected exactly one original workload')
    originals = observed['originals']
    # These are the actual fields emitted by INHERITED_PIPE_FIXTURE. Recompute
    # from the complete returned UTF-8 bytes, rather than trusting its hashes.
    for name in ('request.json', 'child.json', 'exit.json', 'exit.witness.json',
                 'stdout.log', 'stderr.log', 'effect', 'descendant'):
        original = originals[name]
        require(isinstance(original, dict), 'missing original fixture file: ' + name)
        raw = original['utf8'].encode('utf-8')
        require(original['bytes'] == len(raw) and original['sha256'] == digest(raw),
                'original file hash/length differs: ' + name)
    request = json.loads(originals['request.json']['utf8'])
    receipt = json.loads(originals['exit.json']['utf8'])
    witness = json.loads(originals['exit.witness.json']['utf8'])
    require(receipt == observed['receipt'] and witness == observed['witness'],
            'parsed terminal values disagree with their exact original bytes')
    require(json.loads(originals['child.json']['utf8'])['pid'] == observed['workload_pid'],
            'child receipt is not the single original workload')
    require(originals['effect']['utf8'] == 'original leader executed once\n',
            'original effect marker differs')
    require(type(receipt.get('terminal_publication_protocol')) is int
            and receipt['terminal_publication_protocol'] == 1
            and type(witness.get('terminal_publication_protocol')) is int
            and witness['terminal_publication_protocol'] == 1,
            'terminal publication protocol differs')
    require(receipt['job_id'] == witness['job_id'] == request['job_id']
            and receipt['launch_nonce'] == witness['launch_nonce'] == request['launch_nonce']
            and witness['exit_sha256'] == originals['exit.json']['sha256'],
            'terminal witness is not bound to the original request and exact exit bytes')
    require(len(observed['adopted']) == 1
            and observed['adopted'][0]['pid'] == int(originals['descendant']['utf8']),
            'adopted process is not the one recorded original descendant')
    waits = observed['waits']
    require(len(waits) == 1 and waits[0]['phase'] == 'runner'
            and waits[0]['returned'] is True and waits[0]['returncode'] == 0,
            'expected exactly one product wait of the original successful leader')
    require(receipt['cancelled'] is False and receipt['timed_out'] is False
            and observed['state']['cancel_delivered_during_drain'] is False,
            'the fixed no-cancel fault changed its scope')
    return receipt


def validate_red(observed, receipt):
    require(observed['signals'] == [] and observed['adopted'][0]['returncode'] == 0,
            'baseline did not leave its original descendant to self-exit without a group signal')
    require(observed['state']['runner_exit'] == 74 and receipt['exit_code'] == 0
            and receipt.get('effect_outcome') != 'unknown'
            and receipt['output_complete'] is False and receipt['output_durable'] is False
            and any(observed['state']['readers_alive_at_runner_return'])
            and observed['state']['normal_drain_window_present'] is False
            and observed['final_status']['state'] == 'failed',
            'baseline did not reproduce the original incomplete pipe-drain outcome')


def validate_green(observed, receipt):
    signals = observed['signals']
    require(len(signals) == 1, 'candidate did not submit exactly one original-group signal')
    sent = signals[0]
    require(sent['phase'] == 'runner' and sent['signal'] == 9
            and sent['group'] == observed['workload_pid'] and sent['returned'] is True
            and sent['original_child_unreaped'] is True
            and sent['original_leader_exited'] is True and sent['leader_exit_code'] == 0,
            'candidate signal was not successful SIGKILL of the original unreaped leader group')
    require(observed['state']['runner_exit'] == 125 and receipt['exit_code'] == 125
            and receipt['effect_outcome'] == 'unknown' and receipt['automatic_retry'] is False
            and receipt['status_authoritative'] is False
            and receipt['output_complete'] is False and receipt['output_durable'] is False
            and receipt['child_reaped'] is True and receipt['child_exit_code'] == 0
            and receipt['child_group_signal'] == 'submitted'
            and receipt['supervisor_cleanup_errors'] == []
            and observed['adopted'][0]['returncode'] == -9
            and observed['state']['readers_alive_at_runner_return'] == [False, False]
            and observed['state']['normal_drain_window_present'] is True
            and observed['state']['cancellation_deadline'] is None
            and observed['final_status']['state'] == 'effect_unknown',
            'candidate did not preserve unknown/incomplete terminal state after original-group cleanup')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-source', type=Path, required=True)
    parser.add_argument('--candidate-source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    args.out.mkdir(parents=True, mode=0o700, exist_ok=False)
    fixture_path = args.candidate_source / 'src/mcp/runtime/jobs_output_durability_tests.rs'
    fixture_raw = fixture_path.read_bytes()
    fixture = raw_constant(fixture_raw.decode('utf-8'), 'INHERITED_PIPE_FIXTURE')
    ast.parse(fixture)
    report = {'schema': 'hepta-inherited-pipe-red-green/v1', 'passed': False,
              'fixture_source_sha256': digest(fixture_raw),
              'extracted_fixture_sha256': digest(fixture.encode('utf-8')), 'cases': [],
              'scope': 'same Linux fixture, source-extracted original runner, no performance claim'}
    try:
        for label, source in [('baseline', args.baseline_source), ('candidate', args.candidate_source)]:
            runtime_path = source / 'src/mcp/runtime/jobs.rs'
            source_raw = runtime_path.read_bytes()
            text = source_raw.decode('utf-8')
            private = raw_constant(text, 'PRIVATE_DIRECTORY_CODE')
            start = raw_constant(text, 'START_CODE')
            runner = private + '\n' + start.split("runner = r'''", 1)[1].split("\n'''\nrunner_path", 1)[0] + '\n'
            status = raw_constant(text, 'STATUS_CODE')
            final_status = 'def final_status(exit_data):' + status.split('def final_status(exit_data):', 1)[1].split('\ndef one_status():', 1)[0]
            ast.parse(runner)
            ast.parse(final_status)
            directory = args.out / label
            job = directory / 'state/jobs/inherited-pipe-durability'
            job.mkdir(parents=True, mode=0o700)
            payload = {'job': str(job.resolve()), 'runner': runner, 'status_function': final_status,
                       'cancel_overlap': False, 'ignore_term': True}
            input_raw = json.dumps(payload).encode('utf-8')
            (directory / 'input.json').write_bytes(input_raw)
            case = {'label': label, 'source_sha256': digest(source_raw),
                    'runner_sha256': digest(runner.encode('utf-8')),
                    'final_status_source_sha256': digest(final_status.encode('utf-8')),
                    'input_sha256': digest(input_raw), 'validated': False}
            report['cases'].append(case)
            began = time.monotonic()
            try:
                result = subprocess.run([sys.executable, '-I', '-S', '-c', fixture],
                                        input=input_raw, capture_output=True,
                                        timeout=45, start_new_session=True)
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b'', error.stderr or b''
                (directory / 'stdout.partial').write_bytes(stdout)
                (directory / 'stderr.partial').write_bytes(stderr)
                case.update(fixture_outcome='outer_timeout', timeout_seconds=45,
                            fixture_returncode=None, partial_capture=True,
                            fixture_descendant_cleanup_confirmed=False,
                            stdout_file='stdout.partial', stderr_file='stderr.partial',
                            stdout_sha256=digest(stdout), stderr_sha256=digest(stderr))
                raise RuntimeError(label + ' fixture timed out; partial output retained, no cleanup pass') from error
            finally:
                case['seconds'] = time.monotonic() - began
                case['source_sha256_after'] = digest(runtime_path.read_bytes())
                case['fixture_source_sha256_after'] = digest(fixture_path.read_bytes())
                case['inputs_unchanged'] = (case['source_sha256_after'] == digest(source_raw)
                    and case['fixture_source_sha256_after'] == digest(fixture_raw))
            (directory / 'stdout.json').write_bytes(result.stdout)
            (directory / 'stderr.log').write_bytes(result.stderr)
            case.update(fixture_outcome='returned', fixture_returncode=result.returncode,
                        stdout_file='stdout.json', stderr_file='stderr.log', partial_capture=False,
                        stdout_sha256=digest(result.stdout), stderr_sha256=digest(result.stderr))
            require(case['inputs_unchanged'], label + ' source changed after extracting the executed runner')
            if result.returncode:
                raise RuntimeError(label + ' fixture failed')
            observed = json.loads(result.stdout)
            case['observed'] = observed
            receipt = validate_common(observed)
            if label == 'baseline':
                validate_red(observed, receipt)
                case['expected_red_observed'] = True
            else:
                validate_green(observed, receipt)
                case['expected_green_observed'] = True
            case['validated'] = True
            print(json.dumps({k: v for k, v in case.items() if k != 'observed'}), flush=True)
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        (args.out / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
