#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Two fixed r07/A50 local small-archive blocks; no SSH, Cargo or retries.

The existing small native helper is unchanged. Qualification identities must be
frozen before execution. All 8192 measured and 8848 total requests belong to
this new experiment; earlier native, control and comparison failures are kept
separate. Numeric regression gates are preregistered in the bound protocol and
applied to the complete original records in an independent offline analysis.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import types


DEV_ROOT = Path('/home/qian/hepta-runtime-optimization-20261023')
BASE = DEV_ROOT / 'a41-phase-timing-20261025-r01'
EXPECTED_OUT = BASE / 'a50-small-archive-comparison-r01'
FINAL_BINDINGS_READY = True
NATIVE_SHA = 'd35bfe354d405b6efb2d2ca28e06bb6469016cc6cf0c611ca3c107b043ea0d32'
PROTOCOL_SHA = '3fd4104ad342c0403359a96baab757ec6b6db47992bc27b0c5b09ae40f615750'
ENTRY_PATH = BASE / 'a50-record-batches-entry-r01/entry-report.json'
ENTRY_SHA = '9db04a9a7626942447680107788cd1f7cd485c8870514f034adaa74fa8c0ffa1'
ENTRY_BYTES = 315291
ENTRY_SCHEMA = 'hepta-a50-record-batches-qualification-entry/v1'
WORKER_PATH = BASE / 'a50-record-batches-entry-r01/worker-report.json'
WORKER_SHA = '226d51e5214950f1c819b6205144fa3f5192e6f47973446eb40eeefd5f57b17b'
WORKER_BYTES = 24310
WORKER_SCHEMA = 'hepta-a50-record-batches-guarded-qualifier-worker/v1'

QUALIFICATION_CHAIN = BASE / 'tools/load_a46_qualification_chain_r01.py'
QUALIFICATION_CHAIN_SHA = '55a19e9e5d5bd2d514025fefe2cdf037b9a21f0fae1ed3f750c6b9af086cf7e0'
QUALIFICATIONS = {
    'r07': BASE / 'qualification-r07-recovery-only/report.json',
    'A50': BASE / 'qualification-a50-record-batches-r01/report.json',
}
CLEAR_ENV = ('SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'HEPTA_ARCHIVE_INDEX_TRACE',
             'HEPTA_REQUEST_AUDIT_TRACE', 'HEPTA_OBSERVATION_TRACE',
             'HEPTA_TEST_ARCHIVE_PAGE_SELECTOR_CHILD', 'HEPTA_A41_ARCHIVE_ROOT',
             'RUST_LOG', 'RUST_TEST_NOCAPTURE', 'PYTHONPATH', 'PYTHONHOME')
FROZEN_NATIVE = None
BLOCK_NAMES = ('block-0-r07-A50', 'block-1-A50-r07')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pinned_bootstrap(path, expected):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'direct bootstrap input required')
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == expected, 'bootstrap SHA differs: ' + str(path))
    return raw


def host_gate(native):
    snapshot = native.host_load()
    matching = [row for row in snapshot['processes'] if row['comm'] in
                ('cargo', 'cargo-clippy', 'clippy-driver', 'rustc', 'heptabao_server')
                and row['state'] not in ('Z', 'X', 'x')]
    return {'clear': snapshot['required_fields_present'] and not snapshot['errors'] and not matching,
            'matching_live_processes': matching, 'snapshot': snapshot,
            'scope': 'one local snapshot; not a continuous or remote-host load guarantee'}


def describe_calls(native, output, stage):
    """Retain all journal rows in the original; this summary never filters failures."""
    path = output / 'calls.jsonl'
    if not path.exists():
        stage['observed_calls'] = {'available': False, 'reason': 'journal not produced'}
        return
    info, raw = native.receipt(path, contents=True)
    rows = [json.loads(line) for line in raw.splitlines()]
    measured = [row for row in rows if row.get('purpose') == 'measured']
    per_source = {}
    for label in ('A', 'B'):
        selected = [row for row in measured if row.get('arm') == label]
        source = stage['cli_to_actual'][label]
        per_source[source['version']] = {'release_sha256': source['release_sha256'],
            'measured_attempted': len(selected),
            'successes': sum(row.get('okay') is True for row in selected),
            'failures': sum(row.get('okay') is not True for row in selected),
            'tool_counts': dict(collections.Counter(row.get('tool') for row in selected))}
    stage['observed_calls'] = {'available': True, 'original': info, 'total': len(rows),
        'measured': len(measured), 'all_failures': sum(row.get('okay') is not True for row in rows),
        'unclassified_measured_arms': sum(row.get('arm') not in ('A', 'B') for row in measured),
        'by_actual_source': per_source}
    stage['journal_coverage_exact'] = (
        len(rows) == 4424 and len(measured) == 4096
        and [(row.get('round'), row.get('index')) for row in measured]
        == [(i, j) for i in range(4) for j in range(1024)]
        and all(row.get('arm') == ['A', 'B', 'B', 'A'][row['round']]
                and row.get('concurrency') == 1 and row.get('write_attempts') == 1
                and row.get('automatic_retry') is False for row in measured))


def main(argv=None):
    global FROZEN_NATIVE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=EXPECTED_OUT)
    parser.add_argument('--protocol', type=Path, default=Path(__file__).absolute().with_name('small-archive-a50-r01.protocol.json'))
    args = parser.parse_args(argv)
    need(FINAL_BINDINGS_READY and isinstance(QUALIFICATION_CHAIN_SHA, str)
         and len(QUALIFICATION_CHAIN_SHA) == 64
         and all(c in '0123456789abcdef' for c in QUALIFICATION_CHAIN_SHA),
         'A50 explicit qualification-chain/release binding pending; experiment not started')
    os.umask(0o077)
    driver_path = BASE / 'tools/run_a41_native_validation.py'
    driver_raw = pinned_bootstrap(driver_path, NATIVE_SHA)
    native = types.ModuleType('frozen_native_for_small_a42_comparison')
    native.__file__ = str(driver_path)
    exec(compile(driver_raw, str(driver_path), 'exec'), native.__dict__)
    FROZEN_NATIVE = native
    chain_raw = pinned_bootstrap(QUALIFICATION_CHAIN, QUALIFICATION_CHAIN_SHA)
    qualification_chain = types.ModuleType('frozen_a43_explicit_qualification_chain')
    qualification_chain.__file__ = str(QUALIFICATION_CHAIN)
    exec(compile(chain_raw, str(QUALIFICATION_CHAIN), 'exec'), qualification_chain.__dict__)
    need(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(os, 'WNOWAIT')
         and hasattr(signal, 'pidfd_send_signal'), 'reviewed Linux child-custody APIs required')
    need(args.out == EXPECTED_OUT, 'only the fixed fresh A50 comparison output is admitted')
    out = native.direct(args.out, exists=False)
    out.mkdir(mode=0o700)
    report_path = out / 'report.json'
    report = {'schema': 'hepta-a50-small-archive-comparison/v1', 'phase': 'preflight',
        'started_utc': native.utc(), 'passed': False, 'complete': False, 'automatic_retries': 0,
        'performance_adoption_claimed': False, 'numeric_regression_threshold_preregistered': True,
        'multihost_acceptance_established': False, 'ssh_or_agent_used': False,
        'product_deadlines_modified': False, 'planned_new_measured_calls': 8192,
        'historical_call_rows_included_in_new_totals': False,
        'a42_multihost_validation_performed': False, 'causal_attribution_to_trace_claimed': False,
        'original_inputs': [],
        'stages': [{'name': name, 'kind': 'small', 'block': index, 'status': 'unexecuted',
                    'executed': False, 'execution_count': 0, 'budget_seconds': 300}
                   for index, name in enumerate(BLOCK_NAMES)]}
    bundles = {}

    def checkpoint():
        report['unexecuted'] = [s['name'] for s in report['stages'] if not s['executed']]
        native.save(report_path, report)

    def pin(path, expected=None, copy_name=None):
        info, raw = native.receipt(native.direct(path), contents=True)
        need(expected is None or info['sha256'] == expected, 'pinned input SHA differs: ' + str(path))
        report['original_inputs'].append(info)
        if copy_name:
            native.create(out / copy_name, raw)
        return info, raw

    checkpoint()
    try:
        protocol_raw = pinned_bootstrap(args.protocol, PROTOCOL_SHA)
        protocol = json.loads(protocol_raw)
        need(protocol.get('bindings_ready') is True, 'A50 final binding is not frozen')
        need(protocol['qualification_chain_loader_sha256'] == QUALIFICATION_CHAIN_SHA,
             'explicit qualification-chain validator binding differs')
        report['qualification_chain_loader'], _ = pin(QUALIFICATION_CHAIN, QUALIFICATION_CHAIN_SHA,
                                                      'qualification-chain-loader.original.py')
        report['protocol'], _ = pin(args.protocol, PROTOCOL_SHA, 'protocol.original.json')
        report['driver'], _ = pin(driver_path, NATIVE_SHA, 'native-driver.original.py')
        report['confirmation_driver'], _ = pin(Path(__file__).absolute(), copy_name='confirmation-driver.original.py')
        helper = BASE / 'tools/x230_small_archive_benchmark.py'
        report['helper'], _ = pin(helper, protocol['frozen_small_helper_sha256'], 'small-helper.original.py')
        for historical in protocol['historical_experiments_kept_separate']:
            pin(Path(historical['path']), historical['sha256'], historical['copy_name'])
        report['historical_experiments_kept_separate'] = protocol['historical_experiments_kept_separate']
        report['regression_gates'] = protocol['regression_gates']
        report['regression_decision_scope'] = 'No gate result is inferred from functional pass; apply frozen gates to all original new calls and controller observations offline.'
        report['qualification_entry'], entry_raw = pin(ENTRY_PATH, ENTRY_SHA, 'qualification-entry.original.json')
        report['qualification_worker'], worker_raw = pin(WORKER_PATH, WORKER_SHA, 'qualification-worker.original.json')
        need(len(entry_raw) == ENTRY_BYTES and len(worker_raw) == WORKER_BYTES, 'original guardian length differs')
        entry, worker = json.loads(entry_raw), json.loads(worker_raw)
        need(entry['schema'] == ENTRY_SCHEMA and entry['qualified'] is True
             and entry['passed'] is True and entry['guarded_qualification_complete'] is True
             and entry['parent_unchanged_after_attempt'] is True
             and entry['reused_dependencies_unchanged'] is True
             and not entry.get('error') and not entry.get('errors'), 'original A50 guardian is incomplete')
        need(worker['schema'] == WORKER_SCHEMA and worker['passed'] is True
             and worker['strict_fresh_artifacts_verified'] is True
             and worker['required_test_coverage_verified'] is True
             and worker['reused_dependencies_unchanged'] is True
             and not worker.get('error') and not worker.get('errors'), 'original A50 worker postchecks are incomplete')
        for version, path in QUALIFICATIONS.items():
            expected = protocol['bindings'][version]
            qualified_receipt, qualified_raw = pin(path, expected['qualification_sha256'])
            bundle = qualification_chain.load_qualification(native, path, version, out)
            compact = json.dumps(bundle['source_map'], sort_keys=True, separators=(',', ':')).encode()
            need(bundle['qualification_schema'] == expected['qualification_schema']
                 and bundle['source_files'] == expected['source_files']
                 and hashlib.sha256(compact).hexdigest() == expected['source_map_compact_sha256']
                 and bundle['binary']['sha256'] == expected['release_sha256'], 'qualified source/release binding differs')
            need(not out.is_relative_to(Path(bundle['source'])), 'output would alter qualified source')
            if version == 'A50':
                need(qualification_chain.same_receipt(qualified_receipt, bundle['report']), 'loaded qualification receipt changed')
                prepared = json.loads(qualified_raw)['source_input']
                need(set(prepared) == set(bundle['source_map'])
                     and qualification_chain.map_sha(prepared) == expected['prepared_source_map_compact_sha256'],
                     'prepared candidate source binding differs')
                for ref in (entry['qualification_report'], worker['qualifier_report'],
                            worker['strict_fresh_artifact_evidence']['qualification_report']):
                    need(qualification_chain.same_receipt(ref, bundle['report']), 'guardian qualification receipt differs')
                need(qualification_chain.same_receipt(entry['guarded_worker_report'], report['qualification_worker']),
                     'guardian final worker receipt differs')
                if 'worker_report' in entry:
                    need(qualification_chain.same_receipt(entry['worker_report'], report['qualification_worker']),
                         'guardian optional worker receipt differs')
                need(entry['source_after'] == bundle['source_map'], 'guardian/candidate source differs')
            bundles[version] = bundle
        report['qualifications'] = bundles
        env = dict(os.environ)
        for key in CLEAR_ENV:
            env.pop(key, None)
        env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        report['environment_policy'] = {'cleared': list(CLEAR_ENV), 'agent_or_ssh_probe': False}
        for block in protocol['blocks']:
            mapping = {key: {'version': block['cli_' + key],
                'release_sha256': bundles[block['cli_' + key]]['binary']['sha256'],
                'binary_path': bundles[block['cli_' + key]]['binary']['path']} for key in ('A', 'B')}
            output = out / block['name']
            native.direct(output, exists=False)
            command = ['/usr/bin/python3', '-B', '-s', str(helper),
                '--baseline', mapping['A']['binary_path'], '--candidate', mapping['B']['binary_path'],
                '--measured', '1024', '--workers', '2', '--out', str(output)]
            report['stages'][block['index']].update({'name': block['name'], 'kind': 'small', 'block': block['index'],
                'status': 'unexecuted', 'executed': False, 'execution_count': 0, 'argv': command,
                'output': str(output), 'budget_seconds': 300, 'cli_order': ['A', 'B', 'B', 'A'],
                'actual_order': block['actual_order'], 'cli_to_actual': mapping})
        checkpoint()
        for stage in report['stages']:
            report['phase'] = stage['name']
            stage.update(status='checking_inputs', started_utc=native.utc())
            output = Path(stage['output'])
            try:
                for bundle in bundles.values():
                    qualification_chain.assert_bundle_unchanged(native, bundle)
                for item in report['original_inputs']:
                    need(native.receipt(Path(item['path'])) == item, 'original input changed before block')
                gate = host_gate(native)
                path = out / (stage['name'] + '.host-before.json')
                native.create(path, native.canonical(gate))
                stage['host_before'] = native.receipt(path)
                stage['host_before_clear'] = gate['clear']
                need(gate['clear'], 'block not started: busy or incomplete local host snapshot')
                with (out / (stage['name'] + '.stdout')).open('xb') as stdout, (out / (stage['name'] + '.stderr')).open('xb') as stderr:
                    native.run_owned(stage['argv'], env, helper.parent, stdout, stderr, 300, stage, checkpoint)
                if (output / 'report.json').exists():
                    info, raw = native.receipt(output / 'report.json', contents=True)
                    stage['original_report'] = info
                    value = json.loads(raw)
                    # In this frozen validator, these two lookup keys denote
                    # expected CLI A/B hashes. Actual versions remain explicit
                    # above; block 1 reverses them, without relabeling raw JSON.
                    expected_cli = {'A40': stage['cli_to_actual']['A']['release_sha256'],
                                    'A41': stage['cli_to_actual']['B']['release_sha256']}
                    stage['validation'] = native.validate_stage(stage, value, output, expected_cli)
                    describe_calls(native, output, stage)
                    stage['actual_rounds'] = [{
                        'round': row['round'], 'cli_arm': row['arm'],
                        **stage['cli_to_actual'][row['arm']],
                        'measured_wall_seconds': row['measured_wall_seconds'],
                        'measured_controller_cpu_seconds': row['measured_controller_cpu_seconds'],
                        'whole_round_wait4': row['shutdown']['waited']}
                        for row in value['rounds']]
                need(stage.get('original_child_reaped') and stage.get('returncode') == 0
                     and not stage.get('timed_out') and stage.get('custody_retained_until_reap'),
                     'original helper failed or custody/reap is incomplete')
                need(stage.get('validation', {}).get('passed') is True and stage.get('journal_coverage_exact') is True,
                     'complete original 4096/4424 block coverage or validation failed')
                stage['status'] = 'passed'
            except BaseException as error:
                stage.update(status='failed', error=type(error).__name__ + ': ' + str(error))
            finally:
                stage['finished_utc'] = native.utc()
                errors = []
                for suffix in ('stdout', 'stderr'):
                    path = out / (stage['name'] + '.' + suffix)
                    if path.exists():
                        try:
                            stage[suffix] = native.receipt(path)
                        except BaseException as error:
                            errors.append(type(error).__name__ + ': ' + str(error))
                try:
                    gate = host_gate(native)
                    path = out / (stage['name'] + '.host-after.json')
                    native.create(path, native.canonical(gate))
                    stage['host_after'] = native.receipt(path)
                    stage['host_after_clear'] = gate['clear']
                    need(gate['clear'], 'after-block host snapshot busy or incomplete')
                except BaseException as error:
                    errors.append(type(error).__name__ + ': ' + str(error))
                try:
                    manifest = native.artifact_manifest(output)
                    path = out / (stage['name'] + '.artifacts.json')
                    native.create(path, native.canonical(manifest))
                    stage['original_artifacts_manifest'] = native.receipt(path)
                    stage['original_artifact_count'] = len(manifest)
                    if 'report.json' in manifest:
                        stage.setdefault('original_report', manifest['report.json'])
                    if 'observed_calls' not in stage:
                        describe_calls(native, output, stage)
                except BaseException as error:
                    errors.append(type(error).__name__ + ': ' + str(error))
                try:
                    for bundle in bundles.values():
                        qualification_chain.assert_bundle_unchanged(native, bundle)
                    stage['qualified_inputs_unchanged_after_block'] = True
                except BaseException as error:
                    errors.append(type(error).__name__ + ': ' + str(error))
                if errors:
                    stage.update(status='failed', evidence_errors=errors)
                checkpoint()
                print(json.dumps({'stage': stage['name'], 'status': stage['status'],
                    'executed': stage['executed'], 'returncode': stage.get('returncode')}), flush=True)
            need(stage['status'] == 'passed', 'fixed block failed; later block remains unexecuted, no retry')
        for item in report['original_inputs']:
            need(native.receipt(Path(item['path'])) == item, 'original input changed at experiment end')
        for stage in report['stages']:
            for key in ('stdout', 'stderr', 'host_before', 'host_after', 'original_report', 'original_artifacts_manifest'):
                item = stage[key]
                need(native.receipt(Path(item['path'])) == item, 'outer original changed: ' + key)
            expected = json.loads(Path(stage['original_artifacts_manifest']['path']).read_bytes())
            need(native.artifact_manifest(Path(stage['output'])) == expected, 'original artifact set/bytes/identity changed')
        report.update(phase='complete', passed=True, complete=True, originals_unchanged=True,
                      descriptive_comparison_eligible=True, new_measured_calls=8192, new_total_tool_calls=8848)
    except BaseException as error:
        report.update(phase='failed', passed=False, complete=False, descriptive_comparison_eligible=False,
                      error=type(error).__name__ + ': ' + str(error))
        for stage in report['stages']:
            if not stage['executed']:
                stage['unexecuted_reason'] = 'input, environment or earlier fixed-block failure; no retry'
    finally:
        report['finished_utc'] = native.utc()
        known_calls = sum(s.get('observed_calls', {}).get('measured', 0) for s in report['stages'])
        unknown = [s['name'] for s in report['stages'] if s['executed']
                   and s.get('observed_calls', {}).get('available') is not True]
        report['measured_rows_retained_in_readable_journals'] = known_calls
        report['measured_count_unknown_stages'] = unknown
        report['observed_measured_calls'] = None if unknown else known_calls
        report['final_source_maps'] = {}
        for version, bundle in bundles.items():
            try:
                actual = native.source_map(Path(bundle['source']))
                report['final_source_maps'][version] = actual
                need(actual == bundle['source_map'], 'final source differs: ' + version)
            except BaseException as error:
                report.update(phase='failed', passed=False, complete=False, descriptive_comparison_eligible=False)
                report.setdefault('final_integrity_errors', []).append(type(error).__name__ + ': ' + str(error))
        checkpoint()
        print(json.dumps({'report': str(report_path), 'passed': report['passed'], 'complete': report['complete'],
            'unexecuted': report['unexecuted'], 'observed_measured_calls': report['observed_measured_calls'],
            'multihost_acceptance_established': False}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    def stop_requested(signum, frame):
        raise KeyboardInterrupt('confirmation driver received signal ' + str(signum))
    signal.signal(signal.SIGTERM, stop_requested)
    raise SystemExit(main())
