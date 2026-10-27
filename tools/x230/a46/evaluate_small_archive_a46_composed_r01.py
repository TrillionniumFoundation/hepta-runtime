#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only numeric evaluation of an actual, complete composed A43 comparison.

Inputs are the pinned outer report, its frozen protocol, copied qualification
reports, both original child reports/journals and four original host snapshots.
No runtime, benchmark, shell, SSH or retry is executed. Only the exact reviewed
qualification-chain module identified by CHAIN_SHA is loaded to verify captured
composition originals; arbitrary evidence code is refused.
Only a new analysis file is written. Missing, failed or partial inputs cannot
pass. This report-level evaluation does not replace independent wire/original
fixture/binary/custody auditing and never authorizes performance adoption.
"""

import argparse
from collections import Counter
import datetime
from decimal import Decimal
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types


BASE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01'
REMOTE_ROOT = PurePosixPath(BASE + '/a46-small-archive-comparison-r01')
BLOCKS = ('block-0-r07-A42', 'block-1-A42-r07')
ORDER = ('A', 'B', 'B', 'A')
ACTUAL = ({'A': 'r07', 'B': 'A42'}, {'A': 'A42', 'B': 'r07'})
TOOLS = ('usage_stats', 'request_history', 'request_archive')
BUSY = ('cargo', 'cargo-clippy', 'clippy-driver', 'rustc', 'heptabao_server')
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_FILE = 16 * 1024 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_JSONL_ROWS = 4424
NATIVE_SHA = 'd35bfe354d405b6efb2d2ca28e06bb6469016cc6cf0c611ca3c107b043ea0d32'
HELPER_SHA = '98413b4b177ec3bf68b7fe67de153376465374a9e74690c337633b3b4a912ffb'
R07_QUALIFICATION_SHA = 'ab3481a57c69177d20f4d4feff31543dbc0a32b6f07892a0553879035b928cc9'
R07_MAP_SHA = '4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d'
R07_RELEASE_SHA = '7ab8d93d00f964e7e479ee7df7d25f40ede8e364f3914d30b9fa4b7b2ff867eb'
CHAIN_PATH = BASE + '/tools/load_a46_qualification_chain_r01.py'
CHAIN_SHA = '55a19e9e5d5bd2d514025fefe2cdf037b9a21f0fae1ed3f750c6b9af086cf7e0'
LEGACY_SCHEMA = 'runtime-candidate-qualification/v1'
COMPOSED_SCHEMA = 'hepta-runtime-composed-qualification/v1'
COMPOSITION_KIND = 'a42-r03-five-stages-plus-a46-release/v1'
EXPECTED_GATES = {
    'all_new_tool_calls_correct': 8848,
    'both_blocks_required': True,
    'candidate_over_baseline_measured_controller_cpu_max': 1.1,
    'candidate_over_baseline_measured_wall_max': 1.1,
    'cpu_quantization': '2 ticks per /proc endpoint, sum conservative intervals over every round; candidate upper/baseline lower must pass',
    'fd_scope': 'all endpoint counts retained; no continuous stability claim',
    'historical_drift_calibration_used': False,
    'measured_calls_each_arm': 4096,
    'memory_peak_guard': 'max candidate original wait4 maxRSS <= max(1.10*max baseline, max baseline+4096KiB)',
}


def need(value, message):
    if not value:
        raise ValueError(message)


def exact(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(right, dict):
        return left.keys() == right.keys() and all(exact(left[k], v) for k, v in right.items())
    if isinstance(right, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def integer(value, minimum=0):
    need(type(value) is int and value >= minimum, 'nonnegative integer field required')
    return value


def decimal(value, minimum=Decimal(0)):
    need(type(value) in (int, float) and math.isfinite(value), 'finite numeric field required')
    result = Decimal(str(value))
    need(result >= minimum, 'numeric field below permitted minimum')
    return result


def json_bytes(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def finite_float(text):
        value = float(text)
        need(math.isfinite(value), 'nonfinite JSON number')
        return value

    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite_float,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON constant')))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


class Inputs:
    def __init__(self, root):
        self.root = root
        self.receipts = {}
        self.total_bytes = 0

    def read(self, path, expected=None):
        path = Path(path)
        need(path.is_absolute() and path.resolve(strict=True) == path, 'direct absolute input required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_FILE,
                 'bounded single-link regular input required')
            parts, count = [], 0
            while True:
                part = os.read(fd, 65536)
                if not part:
                    break
                count += len(part)
                need(count <= MAX_FILE, 'input grew past bound')
                parts.append(part)
            raw = b''.join(parts)
            need(count == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
                 'input changed during read')
        finally:
            os.close(fd)
        row = {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw), 'identity': identity(before)}
        if expected is not None:
            need(HEX.fullmatch(expected['sha256']) is not None and integer(expected['bytes']) == row['bytes']
                 and expected['sha256'] == row['sha256'], 'original receipt differs: ' + str(path))
        prior = self.receipts.get(str(path))
        if prior is not None:
            need(row == prior, 'previously read input changed')
        else:
            self.total_bytes += len(raw)
            need(self.total_bytes <= MAX_INPUT_BYTES, 'complete input byte bound exceeded')
            self.receipts[str(path)] = row
        return raw

    def document(self, path, expected=None):
        value = json_bytes(self.read(path, expected))
        need(type(value) is dict, 'JSON object required')
        return value

    def original(self, receipt, relative):
        need(receipt['path'] == str(REMOTE_ROOT / relative), 'unexpected remote original path')
        return self.document(self.root / relative, receipt)

    def unchanged(self):
        for path, row in list(self.receipts.items()):
            self.read(Path(path), row)


def validate_protocol(protocol):
    need(protocol['schema'] == 'hepta-a42-small-archive-comparison-protocol/v1'
         and protocol['experiment_id'] == 'a46-small-archive-comparison-r01'
         and protocol['bindings_ready'] is True and protocol['out'] == str(REMOTE_ROOT),
         'new final A43 small protocol required')
    need(exact(protocol['regression_gates'], EXPECTED_GATES), 'frozen numeric gates differ')
    need(protocol['planned_new_measured_calls'] == 8192 and protocol['planned_new_total_tool_calls'] == 8848
         and protocol['planned_new_rounds'] == 8 and protocol['measured_per_round'] == 1024
         and protocol['concurrency'] == 1 and protocol['workers'] == 2
         and protocol['seed_records_per_round'] == 64 and protocol['helper_budget_seconds'] == 300,
         'fixed workload differs')
    need(protocol['automatic_retry'] is False and protocol['frozen_native_driver_sha256'] == NATIVE_SHA
         and protocol['frozen_small_helper_sha256'] == HELPER_SHA, 'frozen dependency/retry policy differs')
    need(len(protocol['blocks']) == 2, 'two opposite-order blocks required')
    for index, block in enumerate(protocol['blocks']):
        expected = {'index': index, 'name': BLOCKS[index], 'cli_A': ACTUAL[index]['A'],
                    'cli_B': ACTUAL[index]['B'], 'actual_order': [ACTUAL[index][arm] for arm in ORDER]}
        need(exact(block, expected), 'fixed block order differs')
    need(set(protocol['bindings']) == {'r07', 'A42'}, 'unexpected comparison versions')
    old = protocol['bindings']['r07']
    need(old['qualification_sha256'] == R07_QUALIFICATION_SHA
         and old['source_map_compact_sha256'] == R07_MAP_SHA and old['release_sha256'] == R07_RELEASE_SHA
         and old['source_files'] == 165 and old['qualification_schema'] == LEGACY_SCHEMA,
         'frozen r07 baseline differs')
    new = protocol['bindings']['A42']
    need(new['qualification_path'] == BASE + '/qualification-a46-a42-release-completion-r01/report.json'
         and new['source_files'] == 168 and new['qualification_schema'] == COMPOSED_SCHEMA
         and new['composition_kind'] == COMPOSITION_KIND
         and protocol['qualification_chain_loader_path'] == CHAIN_PATH
         and protocol['qualification_chain_loader_sha256'] == CHAIN_SHA,
         'explicit composed candidate and reviewed validator binding differs')
    for binding in protocol['bindings'].values():
        for key in ('qualification_sha256', 'source_map_compact_sha256', 'release_sha256'):
            need(type(binding[key]) is str and HEX.fullmatch(binding[key]), 'actual final identity missing: ' + key)
    need(new['release_sha256'] != old['release_sha256'], 'candidate release is not distinct')


def load_chain_validator(inputs, outer, protocol):
    need(protocol['qualification_chain_loader_path'] == CHAIN_PATH
         and protocol['qualification_chain_loader_sha256'] == CHAIN_SHA,
         'fixed reviewed qualification-chain module binding differs')
    ref = outer['qualification_chain_loader']
    need(ref['path'] == CHAIN_PATH and ref['sha256'] == CHAIN_SHA
         and sum(exact(item, ref) for item in outer['original_inputs']) == 1,
         'original qualification-chain module receipt missing or duplicated')
    raw = inputs.read(inputs.root / 'qualification-chain-loader.original.py', ref)
    need(digest(raw) == CHAIN_SHA, 'unreviewed qualification-chain code refused')
    # Only this exact reviewed definition-only module can run. No benchmark,
    # producer, captured helper, dynamic report path or native binary is loaded.
    module = types.ModuleType('a43_offline_frozen_qualification_chain')
    module.__file__ = CHAIN_PATH
    exec(compile(raw, CHAIN_PATH, 'exec'), module.__dict__)
    need(module.COMPOSED_SCHEMA == COMPOSED_SCHEMA and module.LEGACY_SCHEMA == LEGACY_SCHEMA
         and module.COMPOSITION_KIND == COMPOSITION_KIND, 'qualification validator schema contract differs')
    return module


def validate_composition(inputs, module, q, bundle):
    need(bundle['qualification_schema'] == COMPOSED_SCHEMA and bundle['composition_used'] is True
         and bundle['composition_kind'] == COMPOSITION_KIND, 'explicit composed bundle required')
    references = bundle['provenance_references']
    need(type(references) is list and 1 <= len(references) <= module.MAX_REFERENCES,
         'bounded complete retained qualification references required')
    retained = {}
    for item in references:
        ref = module.normalized_receipt(item)
        need(ref['path'] not in retained, 'duplicate retained qualification reference')
        retained[ref['path']] = ref
    expected = {}
    core = [bundle['report'], bundle['composition_witness'], *q['provenance'],
            *q['source_identity_before'].values()]
    for item in core:
        ref = module.normalized_receipt(item)
        need(ref['path'] not in expected or exact(expected[ref['path']], ref),
             'conflicting retained qualification reference')
        expected[ref['path']] = ref
    need(exact(retained, expected), 'report/witness/provenance/full source reference inventory differs')
    copies, paths, bodies = bundle['provenance_copies'], set(), {}
    need(type(copies) is list and len(copies) <= module.MAX_REFERENCES,
         'bounded captured provenance inventory required')
    binary_paths = {q['binary']['path'], q['test_binary']['path']}
    expected_copies = {path for path in retained if path not in binary_paths
                       and not PurePosixPath(path).is_relative_to(PurePosixPath(q['source']))}
    for pair in copies:
        need(type(pair) is dict and set(pair) == {'original', 'copy'}, 'captured provenance pair differs')
        original, copied = (module.normalized_receipt(pair[key]) for key in ('original', 'copy'))
        need(original['path'] in expected_copies and original['path'] not in bodies
             and exact(original, retained[original['path']]), 'captured original reference differs or duplicates')
        remote = PurePosixPath(copied['path'])
        need(remote.parent == REMOTE_ROOT and copied['path'] not in paths
             and copied['sha256'] == original['sha256'] and copied['bytes'] == original['bytes'],
             'captured composition copy is not a unique direct exact-body output')
        relative = remote.relative_to(REMOTE_ROOT)
        need(str(relative) == 'A42-qualification.original.json'
             or re.fullmatch(r'A42-composition-input-[0-9]{3}\.original', str(relative)),
             'unexpected captured composition filename')
        paths.add(copied['path'])
        bodies[original['path']] = inputs.read(inputs.root / relative, copied)
    need(set(bodies) == expected_copies, 'one or more complete composition originals are missing')
    need(exact(json_bytes(bodies[bundle['report']['path']]), q),
         'captured composed qualification differs from the pinned original')

    def fetch(ref):
        ref = module.normalized_receipt(ref)
        need(ref['path'] in bodies and exact(ref, retained[ref['path']]),
             'validator requested an uncaptured or altered qualification original')
        return bodies[ref['path']]

    checked = module.verify_composition_documents(q, bundle['report'], bundle['composition_witness'], fetch)
    need(exact(bundle['logs'], checked['logs']) and exact(bundle['source_map'], checked['source_map']),
         'runtime bundle differs from independently rechecked captured composition')
    summary = {key: checked[key] for key in ('prior_attempt_remains_failed', 'original_successful_stages',
                                            'new_release_executions', 'original_top_level_tests')}
    need(exact(bundle['composition_summary'], summary), 'reported composition summary differs from originals')
    for key in ('binary', 'test_binary'):
        need(module.same_receipt(q[key], bundle[key]), 'composed stable artifact receipt differs')
    return {**summary, 'schema': COMPOSED_SCHEMA, 'composition_kind': COMPOSITION_KIND,
            'explicit_composition_documents_verified': True, 'all_captured_originals_rehashed': True,
            'retained_reference_count': len(retained), 'captured_original_count': len(bodies),
            'source_and_binary_bodies_rehashed_by_this_evaluator': False,
            'validator_sha256': CHAIN_SHA}


def validate_qualifications(inputs, outer, protocol):
    need(set(outer['qualifications']) == {'r07', 'A42'}, 'both actual qualification bundles required')
    module = load_chain_validator(inputs, outer, protocol)
    result = {}
    for version in ('r07', 'A42'):
        binding = protocol['bindings'][version]
        bundle = outer['qualifications'][version]
        path = BASE + ('/qualification-r07-recovery-only/report.json' if version == 'r07'
                       else '/qualification-a46-a42-release-completion-r01/report.json')
        need(bundle['report']['path'] == path and bundle['report']['sha256'] == binding['qualification_sha256'],
             'qualified report binding differs')
        q = inputs.document(inputs.root / (version + '-qualification.original.json'), bundle['report'])
        if version == 'r07':
            need(q['schema'] == LEGACY_SCHEMA and q['qualified'] is True
                 and q['current_stage'] == 'complete' and not q.get('error')
                 and bundle['qualification_schema'] == LEGACY_SCHEMA and bundle['composition_used'] is False,
                 'actual successful ordinary baseline qualification required')
            need([stage['name'] for stage in q['stages']] == [name for name, _ in module.STAGES]
                 and all(type(stage['returncode']) is int and stage['returncode'] == 0 for stage in q['stages']),
                 'complete original six-stage ordinary qualification required')
            for stage, (_, tail) in zip(q['stages'], module.STAGES):
                need(stage['command'] == [module.CARGO, '+1.95.0'] + tail,
                     'ordinary qualification original stage command differs')
            result[version] = {'schema': LEGACY_SCHEMA, 'composition_used': False,
                               'original_successful_stages': 6}
        else:
            need(q['schema'] == COMPOSED_SCHEMA and q['composition_kind'] == COMPOSITION_KIND
                 and q['qualified'] is True, 'actual explicit witnessed composed qualification required')
            result[version] = validate_composition(inputs, module, q, bundle)
        source_map = q['source_tested']
        need(type(source_map) is dict and len(source_map) == binding['source_files']
             and source_map == q['source_after'] == bundle['source_map'] == outer['final_source_maps'][version]
             and digest(compact(source_map)) == binding['source_map_compact_sha256'],
             'complete formatted tested/after/report source maps differ')
        expected_source = BASE + ('/source-r07-recovery-only' if version == 'r07' else '/source-a42-fresh-cohort-r03')
        need(q['source'] == bundle['source'] == expected_source and bundle['source_files'] == len(source_map),
             'qualified source path/count differs')
        for key in ('binary', 'test_binary'):
            need(q[key]['cached'] is False and bundle[key]['fresh'] is False
                 and q[key]['sha256'] == bundle[key]['sha256'] and q[key]['path'] == bundle[key]['path'],
                 'fresh original artifact receipt differs')
        need(q['binary']['sha256'] == binding['release_sha256'], 'release pin differs')
    return result


def validate_host(inputs, stage, suffix):
    gate = inputs.original(stage['host_' + suffix], stage['name'] + '.host-' + suffix + '.json')
    snapshot = gate['snapshot']
    need(gate['clear'] is True and stage['host_' + suffix + '_clear'] is True
         and snapshot['required_fields_present'] is True and snapshot['errors'] == []
         and {'loadavg', 'stat', 'meminfo', 'uptime'} <= snapshot.keys(), 'host gate not complete/clear')
    busy = [row for row in snapshot['processes'] if row['comm'] in BUSY and row['state'] not in ('Z', 'X', 'x')]
    need(busy == [] and gate['matching_live_processes'] == [], 'busy process present in original host snapshot')


def validate_call(row, round_index, arm, purpose, index, tool):
    need(row['round'] == round_index and row['arm'] == arm and row['purpose'] == purpose
         and row['index'] == index and row['tool'] == tool and row['concurrency'] == 1,
         'fixed original call schedule differs')
    need(row['okay'] is True and row['sent'] is True and row['response_received'] is True
         and row['automatic_retry'] is False and type(row['write_attempts']) is int and row['write_attempts'] == 1,
         'failed, unreceived or replayed original call')
    for key in ('request_wire_sha256', 'response_wire_sha256', 'dto_sha256'):
        need(type(row[key]) is str and HEX.fullmatch(row[key]), 'original wire/DTO receipt missing')
    for key in ('request_wire_offset', 'response_wire_offset', 'start_monotonic_ns', 'response_received_monotonic_ns'):
        integer(row[key])
    integer(row['request_wire_bytes'], 1)
    integer(row['response_wire_bytes'], 1)
    elapsed = decimal(row['elapsed_ms'])
    derived = Decimal(row['response_received_monotonic_ns'] - row['start_monotonic_ns']) / Decimal(1000000)
    need(derived >= 0 and abs(elapsed - derived) <= Decimal('0.000000001'), 'call latency identity differs')
    need(decimal(row['caller_wall_ms']) >= elapsed, 'caller wall shorter than response duration')
    need(not any(key in row for key in ('error', 'error_type', 'response_transport_error')), 'call carries an error')


def round_calls(row, index, arm):
    need(row['round'] == index and row['arm'] == arm and row['complete'] is True
         and row['originals_unchanged'] is True, 'original round not complete')
    need(len(row['seeds']) == 64 and len(row['warmup']) == 8 and len(row['measured']) == 1024
         and len(row['validation']) == 10, 'complete original round coverage missing')
    for purpose, values in (('seed', row['seeds']), ('warmup', row['warmup']), ('measured', row['measured'])):
        for n, call in enumerate(values):
            validate_call(call, index, arm, purpose, n, 'host_list' if purpose == 'seed' else TOOLS[n % 3])
    validation_order = ('usage_stats', 'request_history', 'request_history', 'request_archive', 'request_archive')
    for n, call in enumerate(row['validation']):
        validate_call(call, index, arm, 'preflight' if n < 5 else 'postflight', n % 5, validation_order[n % 5])
    ids = [call['native_request_id'] for call in row['seeds']]
    need(len(set(ids)) == 64 and all(type(value) is str and HEX.fullmatch(value) for value in ids),
         '64 unique native seed identities required')
    calls = row['seeds'] + row['validation'][:5] + row['warmup'] + row['measured'] + row['validation'][5:]
    need([call['rpc_id'] for call in calls] == list(range(2, 1108)), 'original per-controller RPC sequence differs')
    summary = row['measured_summary']
    need(summary['attempted'] == summary['sent'] == summary['successes'] == 1024
         and summary['failures'] == 0 and summary['performance_valid'] is True, 'reported measured coverage differs')
    return calls, ids


def round_metrics(row, version, block):
    before, after = row['process_before_measured'], row['process_after_measured']
    hz = integer(before['cpu_tick_hz'], 1)
    need(after['cpu_tick_hz'] == hz and before['pid'] == after['pid'] == row['startup']['pid']
         and before['birth_ticks'] == after['birth_ticks'] == row['startup']['birth_ticks'],
         'original process generation/clock rate differs')
    ticks = []
    for point in (before, after):
        scaled = decimal(point['cpu_seconds']) * hz
        integral = scaled.to_integral_value()
        need(abs(scaled - integral) <= Decimal('0.0000001'), 'CPU endpoint is not a clock-tick value')
        ticks.append(int(integral))
        for key in ('rss_kib', 'hwm_kib', 'fd_count'):
            integer(point[key])
    need(ticks[1] >= ticks[0], 'CPU counter went backwards')
    observed = Decimal(ticks[1] - ticks[0]) / hz
    need(abs(decimal(row['measured_controller_cpu_seconds']) - observed) <= Decimal('0.000000001'),
         'reported measured CPU differs from original endpoints')
    margin = Decimal(4) / hz
    wall = decimal(row['measured_wall_seconds'])
    need(wall > 0, 'positive full measured round wall required')
    calls_wall = sum((decimal(call['caller_wall_ms']) / 1000 for call in row['measured']), Decimal(0))
    need(wall + Decimal('0.000000001') >= calls_wall, 'round wall excludes measured call costs')
    shutdown = row['shutdown']
    waited = shutdown['waited']
    need(shutdown['original_child_reaped'] is True and shutdown['method'] == 'stdin_eof'
         and shutdown['errors'] == [] and shutdown['reader_error'] is None and shutdown['unmatched'] == []
         and type(waited['exit_code']) is int and waited['exit_code'] == 0
         and waited['pid'] == before['pid'], 'normal original controller shutdown missing')
    whole_cpu = decimal(waited['total_cpu_seconds'])
    need(abs(whole_cpu - decimal(waited['user_cpu_seconds']) - decimal(waited['system_cpu_seconds'])) <= Decimal('0.000000001')
         and whole_cpu + Decimal(2) / hz >= decimal(after['cpu_seconds']), 'whole-life CPU receipt differs')
    rss = integer(waited['max_rss_kib'], 1)
    return {'block': block, 'round': row['round'], 'cli_arm': row['arm'], 'version': version,
            'measured_calls': 1024, 'wall_seconds': wall, 'cpu_observed_seconds': observed,
            'cpu_lower_seconds': max(Decimal(0), observed - margin), 'cpu_upper_seconds': observed + margin,
            'cpu_interval_margin_seconds': margin, 'cpu_tick_hz': hz,
            'whole_round_wait4_cpu_seconds': whole_cpu, 'whole_round_wait4_max_rss_kib': rss,
            'fd_endpoints': [before['fd_count'], after['fd_count']],
            'rss_endpoints_kib': [before['rss_kib'], after['rss_kib']]}


def evaluate(inputs, outer, protocol, result):
    validate_protocol(protocol)
    result['actual_outer_state'] = {key: outer.get(key) for key in ('phase', 'passed', 'complete',
        'observed_measured_calls', 'measured_count_unknown_stages', 'unexecuted', 'error')}
    result['all_stage_observations'] = [{key: stage.get(key) for key in ('name', 'status', 'executed',
        'returncode', 'timed_out', 'observed_calls', 'error', 'unexecuted_reason')} for stage in outer.get('stages', [])]
    need(outer['schema'] == 'hepta-a42-small-archive-comparison/v1' and outer['phase'] == 'complete'
         and outer['passed'] is True and outer['complete'] is True and outer['descriptive_comparison_eligible'] is True
         and outer['originals_unchanged'] is True and not outer.get('error') and not outer.get('final_integrity_errors'),
         'actual complete successful original comparison required')
    need(outer['unexecuted'] == [] and outer['measured_count_unknown_stages'] == []
         and outer['new_measured_calls'] == outer['observed_measured_calls'] == 8192
         and outer['new_total_tool_calls'] == 8848 and outer['automatic_retries'] == 0
         and outer['product_deadlines_modified'] is False and outer['ssh_or_agent_used'] is False,
         'complete fixed experiment counts/scope differ')
    need(outer['driver']['sha256'] == NATIVE_SHA and outer['helper']['sha256'] == HELPER_SHA
         and exact(outer['regression_gates'], EXPECTED_GATES), 'frozen report dependency/gate differs')
    result['qualification_chain_verification'] = validate_qualifications(inputs, outer, protocol)
    need(len(outer['stages']) == 2, 'two complete original stages required')
    metrics, all_seed_ids, all_rows = [], set(), []
    for block, stage in enumerate(outer['stages']):
        name = BLOCKS[block]
        need(stage['name'] == name and stage['block'] == block and stage['output'] == str(REMOTE_ROOT / name)
             and stage['status'] == 'passed' and stage['executed'] is True and stage['execution_count'] == 1
             and stage['budget_seconds'] == 300 and stage['returncode'] == 0 and stage['timed_out'] is False
             and stage['original_child_reaped'] is True and stage['custody_retained_until_reap'] is True
             and stage['pidfd_opened'] is True and stage['actual_waitpid'] == stage['helper_pid']
             and type(stage['raw_wait_status']) is int and stage['raw_wait_status'] == 0 and stage['signals'] == []
             and stage['journal_coverage_exact'] is True and stage['qualified_inputs_unchanged_after_block'] is True
             and stage['validation']['passed'] is True, 'original fixed-stage execution/custody incomplete')
        need(stage['cli_order'] == list(ORDER) and stage['actual_order'] == [ACTUAL[block][arm] for arm in ORDER],
             'recorded actual block order differs')
        for arm in ('A', 'B'):
            mapped = stage['cli_to_actual'][arm]
            version = ACTUAL[block][arm]
            need(mapped['version'] == version and mapped['release_sha256'] == protocol['bindings'][version]['release_sha256']
                 and mapped['binary_path'] == outer['qualifications'][version]['binary']['path'], 'actual CLI mapping differs')
        for suffix in ('before', 'after'):
            validate_host(inputs, stage, suffix)
        child = inputs.original(stage['original_report'], name + '/report.json')
        need(child['schema'] == 'hepta-x230-small-archive-abba/v1' and child['complete'] is True
             and child['comparison_valid'] is True and child['inputs_unchanged'] is True and child['script_unchanged'] is True
             and not any(key in child for key in ('error', 'cleanup_error', 'final_input_error')),
             'original child report incomplete or failed')
        need(child['order'] == list(ORDER) and child['measured_per_round'] == 1024
             and child['measured_planned'] == child['measured_attempted'] == 4096 and child['measured_unexecuted'] == 0
             and child['seed_records_per_round'] == 64 and child['warmup_per_round'] == 8 and child['workers'] == 2
             and child['query_client_wait_seconds'] == 10 and child['product_metadata_deadline_modified'] is False
             and child['automatic_retries'] == 0 and child['ssh_or_profile_used'] is False and len(child['rounds']) == 4,
             'original child schedule/budget differs')
        for arm in ('A', 'B'):
            need(child['inputs'][arm]['sha256'] == stage['cli_to_actual'][arm]['release_sha256']
                 and child['final_inputs'][arm]['sha256'] == child['inputs'][arm]['sha256'], 'original child release binding differs')
        need(child['script']['sha256'] == HELPER_SHA, 'original small helper differs')
        block_rows = []
        for index, row in enumerate(child['rounds']):
            arm = ORDER[index]
            rows, ids = round_calls(row, index, arm)
            need(all_seed_ids.isdisjoint(ids), 'native seed identity reused between fresh controllers')
            all_seed_ids.update(ids)
            block_rows.extend(rows)
            metrics.append(round_metrics(row, ACTUAL[block][arm], block))
        journal_raw = inputs.read(inputs.root / name / 'calls.jsonl', child['calls_file'])
        lines = journal_raw.splitlines()
        need(journal_raw.endswith(b'\n') and len(lines) == MAX_JSONL_ROWS, 'complete original journal framing/count differs')
        journal_rows = [json_bytes(line) for line in lines]
        need(exact(block_rows, journal_rows), 'embedded original rows differ from full original journal')
        all_rows.extend(journal_rows)
    need(len(metrics) == 8 and len(all_rows) == 8848 and len(all_seed_ids) == 512,
         'complete two-block/eight-round totals differ')
    purposes = Counter(row['purpose'] for row in all_rows)
    need(purposes == {'seed': 512, 'preflight': 40, 'warmup': 64, 'measured': 8192, 'postflight': 40},
         'complete all-purpose counts differ')
    arms = {}
    for version in ('r07', 'A42'):
        selected = [row for row in metrics if row['version'] == version]
        need(len(selected) == 4, 'four complete rounds per actual source required')
        data = {'rounds': 4, 'measured_calls': 4096,
                'whole_round_wait4_max_rss_kib': max(row['whole_round_wait4_max_rss_kib'] for row in selected)}
        for key in ('wall_seconds', 'cpu_observed_seconds', 'cpu_lower_seconds', 'cpu_upper_seconds',
                    'cpu_interval_margin_seconds', 'whole_round_wait4_cpu_seconds'):
            data[key] = sum((row[key] for row in selected), Decimal(0))
        data['successful_calls_per_second'] = Decimal(4096) / data['wall_seconds']
        arms[version] = data
    a, b = arms['r07'], arms['A42']
    wall_ratio = b['wall_seconds'] / a['wall_seconds']
    cpu_ratio = b['cpu_upper_seconds'] / a['cpu_lower_seconds'] if a['cpu_lower_seconds'] > 0 else None
    rss_limit = max(Decimal(a['whole_round_wait4_max_rss_kib']) * Decimal('1.10'),
                    Decimal(a['whole_round_wait4_max_rss_kib'] + 4096))
    gates = {'both_opposite_order_blocks_complete': True, 'all_8848_reported_and_journaled_calls_correct': True,
             'both_actual_arms_4096_measured': True, 'wall_ratio_at_most_1_10': wall_ratio <= Decimal('1.10'),
             'cpu_candidate_upper_over_baseline_lower_at_most_1_10': cpu_ratio is not None and cpu_ratio <= Decimal('1.10'),
             'wholelife_wait4_peak_rss_guard': Decimal(b['whole_round_wait4_max_rss_kib']) <= rss_limit}
    result.update(report_evaluation_complete=True, rounds=metrics, arms=arms, all_purpose_counts=dict(purposes),
                  measured_calls=8192, total_tool_calls=8848, gates=gates, numeric_gates_passed=all(gates.values()),
                  ratios={'wall_candidate_over_baseline': wall_ratio,
                          'cpu_candidate_upper_over_baseline_lower': cpu_ratio,
                          'cpu_observed_candidate_over_baseline': b['cpu_observed_seconds'] / a['cpu_observed_seconds']
                          if a['cpu_observed_seconds'] > 0 else None,
                          'rss_candidate_limit_kib': rss_limit}, passed=all(gates.values()))


def printable(value):
    if isinstance(value, Decimal):
        # Decimal strings preserve the exact computed comparison precision.
        return str(value)
    if isinstance(value, dict):
        return {key: printable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [printable(item) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--expected-report-sha256', required=True)
    parser.add_argument('--protocol', type=Path, required=True)
    parser.add_argument('--expected-protocol-sha256', required=True)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = {'schema': 'hepta-a46-small-composed-report-numeric-evaluation/v1',
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'passed': False, 'report_evaluation_complete': False, 'numeric_gates_passed': False,
              'performance_adoption_authorized': False, 'benchmark_or_runtime_executions': 0,
              'report_edits': 0, 'errors': [], 'raw_wire_and_fixture_originals_independently_audited': False,
              'qualified_binary_bodies_rehashed': False, 'qualified_source_bodies_rehashed': False,
              'historical_results_pooled': False, 'qualification_chain_validator_sha256': CHAIN_SHA,
              'measurement_scope': 'fixed native C1 RPC plus DTO/oracle and journal flush loop; not saturated server throughput',
              'cpu_scope': 'sum of all four controller /proc measurement intervals per actual source; two ticks per endpoint, candidate upper / baseline lower',
              'rss_scope': 'maximum of all four original whole-round wait4 peaks per actual source; not steady-state memory',
              'limits': ['Requires a separate complete original wire/fixture and qualified source/binary/custody audit before adoption.',
                         'Only the fixed SHA reviewed qualification-chain validator definitions are loaded; no producer, native driver, helper or benchmark is executed.',
                         'Every failed/partial original comparison is rejected whole; no successful subset or retry is evaluated.']}
    inputs = Inputs(args.evidence_root)
    try:
        need(args.evidence_root.is_absolute() and args.evidence_root.resolve(strict=True) == args.evidence_root
             and args.evidence_root.is_dir(), 'direct absolute evidence directory required')
        need(args.report == args.evidence_root / 'report.json'
             and args.protocol == args.evidence_root / 'protocol.original.json', 'exact original report/protocol paths required')
        need(HEX.fullmatch(args.expected_report_sha256) and HEX.fullmatch(args.expected_protocol_sha256), 'exact SHA pins required')
        outer_raw = inputs.read(args.report)
        need(digest(outer_raw) == args.expected_report_sha256, 'outer report SHA differs from supplied original pin')
        outer = json_bytes(outer_raw)
        protocol_raw = inputs.read(args.protocol)
        need(digest(protocol_raw) == args.expected_protocol_sha256 == outer['protocol']['sha256']
             and len(protocol_raw) == outer['protocol']['bytes'], 'protocol SHA/size differs from exact original report')
        protocol = json_bytes(protocol_raw)
        result['original_report_pin'] = args.expected_report_sha256
        result['original_protocol_pin'] = args.expected_protocol_sha256
        evaluate(inputs, outer, protocol, result)
    except Exception as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
        result.update(passed=False, numeric_gates_passed=False, report_evaluation_complete=False)
    try:
        inputs.unchanged()
        result['all_read_inputs_unchanged_at_end'] = True
    except Exception as error:
        result['errors'].append('final input fence: ' + type(error).__name__ + ': ' + str(error))
        result.update(passed=False, numeric_gates_passed=False, report_evaluation_complete=False,
                      all_read_inputs_unchanged_at_end=False)
    result['input_receipts'] = list(inputs.receipts.values())
    result['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    need(args.out.is_absolute() and args.out.parent.resolve(strict=True) == args.out.parent
         and not args.out.is_relative_to(args.evidence_root), 'new analysis must be outside original evidence directory')
    raw = (json.dumps(printable(result), indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'analysis': str(args.out), 'sha256': digest(raw), 'passed': result['passed'],
                      'report_evaluation_complete': result['report_evaluation_complete'],
                      'numeric_gates_passed': result['numeric_gates_passed'],
                      'performance_adoption_authorized': False, 'errors': result['errors']}), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
