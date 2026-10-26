#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Explicit legacy/composed qualification validation for A46 benchmarks.

This module never builds, launches a runtime, changes an old report or retries.
Legacy reports still use the frozen ordinary loader and require all six stages.
The one supported composition preserves the failed A42 r03 attempt and verifies
five original stages plus one independently witnessed release completion.
verify_composition_documents is pure apart from its supplied read-only fetch;
the runtime loader additionally hashes actual source and executable bodies.
"""

import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat


BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
SOURCE = BASE / 'source-a42-fresh-cohort-r03'
OLD_OUT = BASE / 'qualification-a42-fresh-cohort-r03'
OLD_PREP = BASE / 'a42-qualification-entry-r03'
OUT = BASE / 'qualification-a46-a42-release-completion-r01'
PREP = BASE / 'a46-release-completion-entry-r01'
LEGACY_SCHEMA = 'runtime-candidate-qualification/v1'
COMPOSED_SCHEMA = 'hepta-runtime-composed-qualification/v1'
COMPOSITION_KIND = 'a42-r03-five-stages-plus-a46-release/v1'
SOURCE_MAP_SHA = 'c1ae8a69901aee16e03871e920a6a7e321672c9b30b3a6e75d3560390b8c2e11'
PREFORMAT_MAP_SHA = '02edd61645f84ae6cbe3dd3d8977fe85b1c66a2ba813fb0a80a7c026a0a5ef86'
TEST_SHA = 'bf4f3fecfda0fb78cebaac83c7f154c3410371dee1f25172ebf92596aa33275a'
PROTOCOL_SHA = '849fb328c9e91bee6a14f3330a846593c0102bf2f4d9314eb5a1594e496aa47a'
A46_PROTOCOL_BYTES = 1648
OLD_ENTRY_SHA = '3667eef725327df895ce26d4c898d19cabc4774146577ca08726cd2d4602d5a0'
OLD_PIN = {
    'qualification': (40283, 'b7374df702c477f394b5f3ba2ed94337daa23f8dde54fb38370df6b2d5172b6d'),
    'worker': (7701, '27324028a7e49f165e3862f77df7a8c061414628a3b7355fa49ea423ee3d2cb9'),
    'entry': (284896, 'fcda21f276b6858341a80347c9e537423100195c1b4672a39e8f50153d72949f'),
}
CARGO = '/home/qian/.cargo/bin/cargo'
STAGES = (
    ('format', ['fmt', '--all']),
    ('fmt-check', ['fmt', '--all', '--', '--check']),
    ('clean-package', ['clean', '--offline', '--locked', '--package', 'hepta-runtime']),
    ('clippy', ['clippy', '--offline', '--locked', '--all-features', '--all-targets', '--', '-D', 'warnings']),
    ('test', ['test', '--offline', '--locked', '--all-features', '--message-format=json-render-diagnostics']),
    ('release', ['build', '--offline', '--locked', '--all-features', '--release', '--bins', '--message-format=json-render-diagnostics']),
)
BUSY = ('cargo', 'cargo-clippy', 'clippy-driver', 'rustc', 'heptabao_server')
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_TEXT = 16 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
MAX_REFERENCES = 1024
MAX_CACHED_TEXT = 128 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(b, dict):
        return a.keys() == b.keys() and all(exact(a[key], value) for key, value in b.items())
    if isinstance(b, list):
        return len(a) == len(b) and all(exact(x, y) for x, y in zip(a, b))
    return a == b


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def finite(text):
        value = float(text)
        need(math.isfinite(value), 'nonfinite JSON number')
        return value

    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON constant')))


def map_sha(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def normalized_receipt(value, historical_hardlinks=False):
    need(type(value) is dict, 'receipt object required')
    row = {key: value[key] for key in ('path', 'bytes', 'sha256', 'identity')}
    need(type(row['path']) is str and Path(row['path']).is_absolute()
         and Path(row['path']).is_relative_to(BASE) and '..' not in Path(row['path']).parts,
         'qualification reference outside the fixed development tree')
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE
         and type(row['sha256']) is str and HEX.fullmatch(row['sha256']), 'invalid bounded receipt')
    fields = row['identity']
    need(type(fields) is list and len(fields) == 9 and all(type(v) is int and v >= 0 for v in fields)
         and stat.S_ISREG(fields[2]) and fields[6] == row['bytes']
         and (fields[5] >= 1 if historical_hardlinks else fields[5] == 1), 'invalid regular-file stat9 receipt')
    return row


def same_receipt(a, b):
    return exact(normalized_receipt(a), normalized_receipt(b))


def utc_ns(value):
    instant = datetime.datetime.fromisoformat(value)
    need(instant.tzinfo is not None, 'timezone-qualified original time required')
    elapsed = instant.astimezone(datetime.timezone.utc) - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    return (elapsed.days * 86400 + elapsed.seconds) * 1000000000 + elapsed.microseconds * 1000


def verify_custody(row, exit_code):
    need(row.get('executed') is True and row.get('execution_count') == 1
         and row.get('original_child_reaped') is True and row.get('pidfd_opened') is True
         and type(row.get('pid')) is int and row['pid'] > 1 and row.get('actual_waitpid') == row['pid']
         and type(row.get('raw_wait_status')) is int and row['raw_wait_status'] == exit_code * 256
         and type(row.get('returncode')) is int and row['returncode'] == exit_code
         and row.get('custody_known') is True and row.get('custody_retained_until_reap') is True
         and row.get('group_quiet_before_reap') is True and row.get('signals') == []
         and row.get('worker_permit_sent') is True and row.get('outer_work_budget_exceeded') is False
         and not row.get('normal_worker_exit_left_live_group_or_observation_errors')
         and not row.get('error') and not row.get('cleanup_errors'), 'original worker custody/normal raw exit missing')
    initial, final = row['original_identity'], row['terminal_group_snapshot']
    need(initial['pid'] == initial['pgrp'] == initial['session'] == row['pid']
         and final['errors'] == [] and final['live'] == [], 'original group identity/quiet observation differs')
    original = [member for member in final['members'] if member['pid'] == row['pid']]
    need(len(original) == 1 and original[0]['start_ticks'] == initial['start_ticks']
         and original[0]['pgrp'] == original[0]['session'] == row['pid']
         and original[0]['state'] == 'Z', 'terminal group lacks the unreaped original worker identity')


def verify_gate(value, expected_clear):
    snapshot = value['snapshot']
    need(type(snapshot['processes']) is list and snapshot['required_fields_present'] is True
         and snapshot['errors'] == [] and {'loadavg', 'stat', 'meminfo', 'uptime'} <= snapshot.keys(),
         'complete original stage snapshot required')
    busy = [row for row in snapshot['processes'] if row['comm'] in BUSY and row['state'] not in ('Z', 'X', 'x')]
    memory = re.findall(r'^MemAvailable:\s+(\d+)\s+kB\s*$', snapshot['meminfo'], flags=re.MULTILINE)
    need(len(memory) == 1 and type(value['mem_available_kib']) is int
         and value['mem_available_kib'] == int(memory[0]) and type(value['disk_available_bytes']) is int
         and value['disk_available_bytes'] >= 0 and exact(value['matching_live_processes'], busy)
         and value['resource_errors'] == [] and value['resource_thresholds'] == {
             'mem_available_kib_min': 2097152, 'disk_available_bytes_min': 2147483648},
         'original stage resource projection differs')
    clear = not busy and value['mem_available_kib'] >= 2097152 and value['disk_available_bytes'] >= 2147483648
    need(value['clear'] is expected_clear and clear is expected_clear, 'original stage clear outcome differs')


def compiler_event(raw, source, artifact, is_test):
    matches = []
    for line in raw.splitlines():
        try:
            event = document(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if (type(event) is dict and event.get('reason') == 'compiler-artifact'
                and event.get('target', {}).get('name') == 'hepta-runtime'
                and event.get('profile', {}).get('test') is is_test):
            matches.append(event)
    need(len(matches) == 1, 'exactly one original compiler artifact required')
    event = matches[0]
    need(event.get('fresh') is False and event.get('manifest_path') == str(Path(source) / 'Cargo.toml')
         and event['target'].get('src_path') == artifact['compiler_source'] == str(Path(source) / 'src/main.rs')
         and type(event.get('executable')) is str and Path(event['executable']).is_absolute()
         and Path(event['executable']).is_relative_to(BASE / 'target'), 'fresh=false compiler/source binding differs')
    return event


def verify_composition_documents(q, report_receipt, witness_receipt, fetch):
    """Verify exact captured documents; fetch(ref) returns hash-bound original bytes.

    This does not itself claim that source/executable bodies were reread. Runtime
    load_qualification adds those checks. Offline callers must disclose that
    only their captured documents and original receipts were checked.
    """
    report_receipt = normalized_receipt(report_receipt)
    witness_receipt = normalized_receipt(witness_receipt)
    need(report_receipt['path'] == str(OUT / 'report.json')
         and witness_receipt['path'] == str(OUT / 'composition.witness.json'), 'unexpected composition publication path')
    need(q.get('schema') == COMPOSED_SCHEMA and q.get('composition_kind') == COMPOSITION_KIND
         and q.get('qualified') is True and q.get('source') == str(SOURCE)
         and q.get('original_r03_remains_failed') is True
         and q.get('original_source_after_was_not_written_or_invented') is True
         and q.get('previous_tests_are_not_reexecuted') is True and q.get('new_release_executions') == 1,
         'explicit original-failure-preserving composition required')
    mapping = q['source_tested']
    need(type(mapping) is dict and len(mapping) == 168 and exact(mapping, q['source_after'])
         and map_sha(mapping) == SOURCE_MAP_SHA, 'composed formatted source map differs')
    refs = {}
    need(type(q['provenance']) is list and 1 <= len(q['provenance']) <= MAX_REFERENCES,
         'bounded explicit provenance inventory required')
    for item in q['provenance']:
        ref = normalized_receipt(item)
        need(ref['path'] not in refs and not Path(ref['path']).is_relative_to(BASE / 'target'),
             'duplicate reference or mutable shared-target artifact in stable provenance')
        refs[ref['path']] = ref

    def bound(ref, path=None, pin=None):
        ref = normalized_receipt(ref)
        need(ref['path'] in refs and exact(ref, refs[ref['path']]), 'composition omitted or altered a required provenance reference')
        need(path is None or ref['path'] == str(path), 'required provenance path differs')
        if pin is not None:
            need((ref['bytes'], ref['sha256']) == pin, 'frozen original provenance pin differs')
        return ref

    def raw(ref, path=None, pin=None):
        checked = bound(ref, path, pin)
        value = fetch(checked)
        need(type(value) is bytes and len(value) == checked['bytes'] and sha(value) == checked['sha256'],
             'fetch did not return exact original bytes')
        return value

    def doc(ref, path=None, pin=None):
        value = document(raw(ref, path, pin))
        need(type(value) is dict, 'provenance JSON object required')
        return value

    prior, completion = q['prior_attempt'], q['release_completion']
    need(prior.get('qualified') is False and prior.get('release_executed') is False, 'original failure outcome was rewritten')
    old = doc(prior['qualification'], OLD_OUT / 'report.json', OLD_PIN['qualification'])
    old_worker = doc(prior['worker'], OLD_PREP / 'worker-report.json', OLD_PIN['worker'])
    old_entry = doc(prior['entry'], OLD_PREP / 'entry-report.json', OLD_PIN['entry'])
    need(old['schema'] == LEGACY_SCHEMA and old['qualified'] is False and old['current_stage'] == 'release'
         and old['source'] == str(SOURCE) and 'source_after' not in old and 'binary' not in old
         and old['error'] == 'A42 r03 cargo stage refused: busy/incomplete/resource-floor host gate; cargo not started'
         and exact(old['source_tested'], mapping) and len(old['source_input']) == 168
         and map_sha(old['source_input']) == PREFORMAT_MAP_SHA, 'original r03 failure/source meaning differs')
    need(old_worker['schema'] == 'hepta-a42-guarded-qualifier-worker/v1' and old_worker['passed'] is False
         and old_entry['schema'] == 'hepta-a42-qualification-entry/v1'
         and old_entry['passed'] is False and old_entry['qualified'] is False
         and old_entry['parent_unchanged_after_attempt'] is True
         and same_receipt(old_entry['qualification_report'], prior['qualification'])
         and same_receipt(old_entry['guarded_worker_report'], prior['worker']), 'original guardian/worker binding differs')
    verify_custody(old_entry['worker_custody'], 1)
    need(len(old['stages']) == 5 and len(old_worker['stages']) == 6 and len(q['stages']) == 6
         and set(prior['host_gates']) == {name for name, _ in STAGES}, 'original/composed stage coverage differs')
    logs = {}
    for index, (name, tail) in enumerate(STAGES):
        argv = [CARGO, '+1.95.0'] + tail
        recorded = old_worker['stages'][index]
        need(recorded['name'] == name and recorded['argv'] == argv and recorded['timeout_seconds'] == 1800
             and same_receipt(recorded['host_gate'], prior['host_gates'][name]), 'original guarded stage binding differs')
        gate = doc(prior['host_gates'][name], OLD_PREP / ('stage-%d-%s.host-gate.json' % (index, name)))
        verify_gate(gate, index < 5)
        if index == 5:
            need(recorded['executed'] is False and recorded['execution_count'] == 0 and recorded['gate_clear'] is False
                 and 'returncode' not in recorded and 'started_utc' not in recorded, 'old release was not a zero-execution refusal')
            need(raw(prior['release_log'], OLD_OUT / 'release.log') == b'', 'old unexecuted release log is nonempty')
            continue
        original_stage = old['stages'][index]
        stage = q['stages'][index]
        need(recorded['executed'] is True and recorded['execution_count'] == 1 and recorded['gate_clear'] is True
             and type(recorded['returncode']) is int and recorded['returncode'] == 0
             and original_stage['name'] == name and original_stage['command'] == argv
             and type(original_stage['returncode']) is int and original_stage['returncode'] == 0,
             'one of the five original stages did not succeed exactly once')
        log = bound(stage['log'], OLD_OUT / (name + '.log'))
        need(log['sha256'] == original_stage['log_sha256']
             and exact(stage, {**original_stage, 'origin': 'r03', 'log': log}), 'composed old stage was synthesized or relabeled')
        logs[name] = log
        raw(log)
    start_ns = utc_ns(old_worker['stages'][4]['started_utc'])
    identities = q['source_identity_before']
    need(type(identities) is dict and set(identities) == set(mapping)
         and exact(identities, q['source_identity_after']), 'composed source stat9 inventory changed')
    for relative, item in identities.items():
        ref = normalized_receipt(item)
        need(not Path(relative).is_absolute() and '..' not in Path(relative).parts
             and ref['path'] == str(SOURCE / relative) and ref['sha256'] == mapping[relative]
             and ref['identity'][7] <= start_ns and ref['identity'][8] <= start_ns,
             'source identity/hash or visible post-test change differs')
    old_test = q['test_binary']
    bound(old_test, OLD_OUT / 'hepta-runtime-tests')
    need(old_test['cached'] is False and old_test['sha256'] == TEST_SHA
         and all(exact(old_test[key], value) for key, value in old['test_binary'].items()), 'copied original test artifact differs')
    test_raw = raw(logs['test'])
    test_event = compiler_event(test_raw, SOURCE, old_test, True)
    results = re.findall(rb'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;[^\r\n]*', test_raw, re.MULTILINE)
    need(results and all(row[0] == b'ok' and int(row[2]) == 0 and int(row[4]) == 0 for row in results),
         'original test log contains failed/invalid suite results')
    top = [row for row in results if int(row[5]) == 0]
    need(sum(int(row[1]) for row in top) == 1264 and sum(int(row[3]) for row in top) == 23,
         'original top-level test totals differ; nested filtered results must not be recounted')
    new_worker = doc(completion['worker'], PREP / 'worker-report.json')
    new_entry = doc(completion['entry'], PREP / 'entry-report.json')
    need(new_worker['schema'] == 'hepta-a42-release-completion-worker/v1'
         and new_entry['schema'] == 'hepta-a42-release-completion-entry/v1', 'new completion record schema differs')
    for record in (new_worker, new_entry):
        need(record['passed'] is True and record['errors'] == [] and record['source'] == str(SOURCE)
             and record['source_unchanged'] is True and record['originals_unchanged'] is True
             and record['format_clean_test_executions'] == 0 and record['automatic_retry'] is False
             and record['service_changes'] is False and exact(record['source_identity_before'], identities)
             and exact(record['source_identity_after'], identities), 'new completion original/source scope differs')
    need(new_entry['release_custody_verified'] is True and new_entry['original_r03_remains_failed'] is True
         and same_receipt(new_entry['worker'], completion['worker'])
         and exact(new_worker['source_tested'], mapping) and exact(new_worker['source_after'], mapping)
         and exact(new_worker['input_receipts'], new_entry['input_receipts']), 'new guardian/worker/source links differ')
    verify_custody(new_entry['worker_custody'], 0)
    need(new_entry['budgets'] == {'worker_seconds': 1900, 'release_seconds': 1800, 'outer_seconds': 2100,
                                 'term_seconds': 30, 'kill_seconds': 30}
         and new_worker['release_budget_seconds'] == 1800 and new_worker['agent_accesses'] == 0,
         'new completion budget or agent scope differs')
    for ref in new_worker['input_receipts'].values():
        bound(ref)
    need(exact(new_worker['environment']['fixed_values'], old_worker['environment']['fixed_values'])
         and exact(new_entry['environment']['fixed_values'], old_worker['environment']['fixed_values']),
         'fixed build environment differs from original test configuration')
    need(len(new_worker['stages']) == 1, 'new completion reran or added a stage')
    release = new_worker['stages'][0]
    release_argv = [CARGO, '+1.95.0'] + STAGES[5][1]
    need(release['name'] == 'release' and release['argv'] == release_argv and release['timeout_seconds'] == 1800
         and release['executed'] is True and release['execution_count'] == 1
         and type(release['returncode']) is int and release['returncode'] == 0 and release['gate_clear'] is True
         and same_receipt(release['host_gate'], completion['host_gate'])
         and same_receipt(release['log'], completion['release_log'])
         and same_receipt(new_worker['release_log'], completion['release_log']), 'new release did not complete exactly once')
    verify_gate(doc(completion['host_gate'], PREP / 'stage-0-release.host-gate.json'), True)
    logs['release'] = bound(completion['release_log'], OUT / 'release.log')
    need(type(release['seconds']) in (int, float) and math.isfinite(release['seconds']) and release['seconds'] >= 0,
         'new release elapsed duration missing')
    expected_release = {'name': 'release', 'origin': 'a46_new_user_authorized_release_only', 'command': release_argv,
                        'returncode': 0, 'seconds': release['seconds'], 'log_sha256': logs['release']['sha256'],
                        'log': logs['release']}
    need(exact(q['stages'][5], expected_release), 'composed release stage differs from its original worker')
    artifact = q['binary']
    bound(artifact, OUT / 'hepta-runtime')
    need(artifact['cached'] is False and exact(artifact, new_worker['binary']) and exact(artifact, new_entry['binary']),
         'new copied release/guardian artifact differs')
    release_event = compiler_event(raw(logs['release']), SOURCE, artifact, False)
    need(exact(release_event, new_worker['compiler_artifact'])
         and release_event['executable'] == str(BASE / 'target/release/hepta-runtime'), 'new release compiler event differs')
    copying = new_worker['binary_copy_observation']
    historical = normalized_receipt(copying['source_target_receipt'], historical_hardlinks=True)
    need(historical['path'] == release_event['executable'] and historical['sha256'] == artifact['sha256']
         and historical['bytes'] == artifact['bytes'] and same_receipt(copying['copy_receipt'], artifact)
         and copying['scope'] == 'historical stable-descriptor copy only; shared target may be rebuilt later'
         and historical['path'] not in refs, 'new compiled-to-stable-copy observation differs')
    protocol = doc(completion['protocol'], BASE / 'a46-release-admission-r01/protocol.json',
                   (A46_PROTOCOL_BYTES, PROTOCOL_SHA))
    need(protocol['schema'] == 'hepta-a46-single-release-continuation/v1'
         and protocol['source'] == str(SOURCE) and protocol['source_files'] == 168
         and protocol['source_map_sha256'] == SOURCE_MAP_SHA
         and protocol['entry'] == str(BASE / 'tools/continue_a42_release_a46.py')
         and protocol['output'] == str(OUT) and protocol['worker_output'] == str(PREP)
         and protocol['maximum_release_executions'] == 1 and protocol['automatic_retry'] is False
         and protocol['previous_stage_reexecutions'] == 0
         and protocol['historical_windows_used_for_admission'] is False
         and protocol['release_argv'] == release_argv
         and protocol['release_seconds'] == 1800 and protocol['worker_seconds'] == 1900
         and protocol['outer_seconds'] == 2100 and protocol['cleanup_term_kill_seconds'] == [30, 30]
         and protocol['mem_available_kib_min'] == 2097152
         and protocol['disk_available_bytes_min'] == 2147483648
         and protocol['busy_names'] == list(BUSY)
         and protocol['fresh_worker_host_gate_required'] is True
         and protocol['source_bound_fresh_false_artifact_required'] is True
         and protocol['prior_failures_preserved'] is True
         and protocol['old_source_after_not_invented'] is True,
         'independent A46 release-completion policy differs')
    bound(completion['original_entry_helper'], BASE / 'tools/prepare_qualify_a42_fresh_cohort_r03.py', (57997, OLD_ENTRY_SHA))
    bound(completion['entry_helper'], BASE / 'tools/continue_a42_release_a46.py',
          (13433, 'b492d8d97224229a148b78b3ac5f153f0558eb6bfc38a3cca2bab088dafa9977'))
    point = doc(completion['a46_point_admission'], BASE / 'a46-release-admission-r01/snapshot.json')
    need(point['schema'] == 'hepta-a46-point-admission/v1'
         and point['historical_window_reused'] is False and point['release_executions'] == 0
         and completion['historical_windows_used_for_admission'] is False,
         'new A46 point admission was replaced by historical admission')
    verify_gate(point, True)
    current_gate = doc(completion['host_gate'], PREP / 'stage-0-release.host-gate.json')
    need(utc_ns(release['started_utc']) >= utc_ns(current_gate['snapshot']['utc'])
         >= utc_ns(new_worker['started_utc']) >= utc_ns(point['observed_utc'])
         >= utc_ns(old_entry['finished_utc']), 'A46 stage/admission ordering differs')
    # The original window proof documents do not exist for this new chain.
    # Complete source maps/stat9/mtime, old test logs/compiler artifacts and new
    # before/after worker identities were independently verified above instead.
    need(q['prior_r02_refusal_unchanged'] is True and q['prior_a45_no_clear_unchanged'] is True,
         'new composition did not preserve the previous failed attempts')
    for name, path, pin in (
            ('r02_refused_worker', BASE / 'a42-release-completion-entry-r02/worker-report.json',
             (221571, '8570cf262e8d5a30aa4fdadd88dd842fbb1b6b737c15528ae4d1f8942ddf256d')),
            ('r02_refused_entry', BASE / 'a42-release-completion-entry-r02/entry-report.json',
             (186023, 'ac3b0c077102e2d71f0ec7ea4452425a41101d635e2737ec9b3c1390be5b63d7')),
            ('a45_no_clear', BASE / 'a45-release-window-r01/report.json',
             (82166, 'b59b9897be4b15fec9e0899706aca9d82fcdeeb5cad1b5c74cc4df17dc231eaa'))):
        previous = doc(new_worker['input_receipts'][name], path, pin)
        if name == 'a45_no_clear':
            need(previous['status'] == 'no_clear_observed' and previous['clear_observed'] is False
                 and previous['snapshot_calls'] == 60, 'old A45 result differs')
        else:
            need(previous['passed'] is False, 'old r02 failure was rewritten')
            if name == 'r02_refused_worker':
                need(len(previous['stages']) == 1 and previous['stages'][0]['executed'] is False
                     and previous['stages'][0]['execution_count'] == 0, 'old release was executed')
    witness_raw = fetch(witness_receipt)
    need(type(witness_raw) is bytes and len(witness_raw) == witness_receipt['bytes']
         and sha(witness_raw) == witness_receipt['sha256'], 'composition witness bytes differ')
    witness = document(witness_raw)
    need(witness['schema'] == 'hepta-runtime-composed-qualification-witness/v1'
         and witness['report_path'] == report_receipt['path'] and witness['report_sha256'] == report_receipt['sha256']
         and witness['report_bytes'] == report_receipt['bytes'] and witness['report_file_fsync_completed'] is True
         and witness['report_directory_fsync_completed'] is True, 'composition publication acknowledgement missing')
    return {'source_map': mapping, 'source_identity': identities, 'logs': logs,
            'test_compiler_event': test_event, 'release_compiler_event': release_event,
            'provenance': list(refs.values()), 'prior_attempt_remains_failed': True,
            'original_successful_stages': 5, 'new_release_executions': 1,
            'original_top_level_tests': {'passed': 1264, 'failed': 0, 'ignored': 23},
            'composition_witness': witness_receipt}


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


class OriginalReader:
    def __init__(self):
        self.receipts = {}
        self.text = {}
        self.cached_bytes = 0

    def read(self, path, expected=None, contents=False):
        path = Path(path)
        need(path.is_absolute() and path.is_relative_to(BASE) and '..' not in path.parts
             and path.resolve(strict=True) == path, 'direct bounded-tree original path required')
        cap = MAX_TEXT if contents else MAX_FILE
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap,
                 'bounded single-link original required')
            hasher, count, chunks = hashlib.sha256(), 0, []
            while True:
                data = os.read(fd, 65536)
                if not data:
                    break
                count += len(data)
                need(count <= cap, 'original grew beyond bound')
                hasher.update(data)
                if contents:
                    chunks.append(data)
            need(count == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
                 'original changed during full descriptor hash')
        finally:
            os.close(fd)
        row = {'path': str(path), 'bytes': count, 'sha256': hasher.hexdigest(), 'identity': stamp(before)}
        if expected is not None:
            need(exact(row, normalized_receipt(expected)), 'original full bytes/stat9 differ: ' + str(path))
        prior = self.receipts.get(str(path))
        need(prior is None or exact(prior, row), 'previously read original changed')
        self.receipts[str(path)] = row
        need(len(self.receipts) <= MAX_REFERENCES, 'qualification reference count exceeded')
        raw = b''.join(chunks) if contents else None
        if contents:
            if str(path) not in self.text:
                self.cached_bytes += count
                need(self.cached_bytes <= MAX_CACHED_TEXT, 'captured qualification text bound exceeded')
            self.text[str(path)] = raw
        return row, raw

    def fetch(self, ref):
        ref = normalized_receipt(ref)
        if ref['path'] in self.text:
            need(exact(self.receipts[ref['path']], ref), 'cached original receipt differs')
            return self.text[ref['path']]
        return self.read(Path(ref['path']), ref, contents=True)[1]


def _legacy(native, path, label, output, q, initial):
    need([row['name'] for row in q['stages']] == [name for name, _ in STAGES]
         and all(type(row['returncode']) is int and row['returncode'] == 0 for row in q['stages']),
         'legacy qualification requires all six original successful stages')
    for row, (name, tail) in zip(q['stages'], STAGES):
        need(row['command'] == [CARGO, '+1.95.0'] + tail, 'legacy qualification original command differs')
    # The frozen original loader still performs full source/log/fresh artifact
    # validation. No unknown schema or composed report is routed through it.
    bundle = native.load_qualification(path, label, output)
    need(exact(bundle['report'], initial), 'legacy report changed during frozen ordinary load')
    bundle['qualification_schema'] = LEGACY_SCHEMA
    bundle['composition_used'] = False
    return bundle


def load_qualification(native, path, label, output):
    need(type(label) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,32}', label), 'bounded evidence label required')
    path, output = native.direct(Path(path)), native.direct(Path(output))
    reader = OriginalReader()
    initial, raw = reader.read(path, contents=True)
    q = document(raw)
    need(type(q) is dict, 'qualification object required')
    if q.get('schema') == LEGACY_SCHEMA:
        return _legacy(native, path, label, output, q, initial)
    need(q.get('schema') == COMPOSED_SCHEMA, 'unknown qualification schema; no fallback')
    need(path == OUT / 'report.json', 'only the explicit A42 release completion path is supported')
    witness, _ = reader.read(OUT / 'composition.witness.json', contents=True)
    checked = verify_composition_documents(q, initial, witness, reader.fetch)
    need(native.source_map(SOURCE) == checked['source_map'], 'current full source differs from the composed tested map')
    binary_paths = {q['binary']['path'], q['test_binary']['path']}
    references = {initial['path']: initial, witness['path']: witness}
    for ref in checked['provenance'] + list(checked['source_identity'].values()):
        ref = normalized_receipt(ref)
        need(ref['path'] not in references or exact(references[ref['path']], ref), 'conflicting qualification reference')
        references[ref['path']] = ref
    for ref in references.values():
        source_file = Path(ref['path']).is_relative_to(SOURCE)
        reader.read(Path(ref['path']), ref, contents=ref['path'] not in binary_paths and not source_file)
    for key in ('binary', 'test_binary'):
        need(os.access(q[key]['path'], os.X_OK), 'qualified stable executable is not executable')
    copies = []
    for index, ref in enumerate(sorted(references.values(), key=lambda row: row['path'])):
        if ref['path'] in binary_paths or Path(ref['path']).is_relative_to(SOURCE):
            continue
        name = (label + '-qualification.original.json' if ref['path'] == initial['path']
                else label + '-composition-input-%03d.original' % index)
        destination = output / name
        native.create(destination, reader.fetch(ref))
        copied, _ = reader.read(destination)
        need(copied['sha256'] == ref['sha256'] and copied['bytes'] == ref['bytes'], 'captured composition bytes differ')
        copies.append({'original': ref, 'copy': copied})
    artifacts = {}
    for key, event in (('binary', checked['release_compiler_event']), ('test_binary', checked['test_compiler_event'])):
        artifacts[key] = {**normalized_receipt(q[key]), 'fresh': False,
                          'compiler_source': q[key]['compiler_source'], 'compiler_profile': event['profile']}
    bundle = {'label': label, 'report': initial, 'source': str(SOURCE), 'source_map': checked['source_map'],
              'source_map_sha256': sha(native.canonical(checked['source_map'])), 'source_files': 168,
              'logs': checked['logs'], **artifacts, 'qualification_schema': COMPOSED_SCHEMA,
              'composition_kind': COMPOSITION_KIND, 'composition_used': True,
              'composition_witness': witness, 'provenance_references': list(references.values()),
              'provenance_copies': copies, 'composition_summary': {
                  key: checked[key] for key in ('prior_attempt_remains_failed', 'original_successful_stages',
                                               'new_release_executions', 'original_top_level_tests')}}
    assert_bundle_unchanged(native, bundle)
    return bundle


def assert_bundle_unchanged(native, bundle):
    mode = bundle.get('qualification_schema')
    if mode == LEGACY_SCHEMA:
        native.assert_bundle_unchanged(bundle)
        for ref in [bundle['report'], bundle['binary'], bundle['test_binary'], *bundle['logs'].values()]:
            need(stamp(Path(ref['path']).lstat()) == ref['identity'], 'legacy original stat9 changed')
        return
    need(mode == COMPOSED_SCHEMA and bundle.get('composition_kind') == COMPOSITION_KIND
         and bundle.get('composition_used') is True, 'unknown qualification bundle; no fallback')
    need(native.source_map(Path(bundle['source'])) == bundle['source_map'], 'composed current source changed')
    reader = OriginalReader()
    references = bundle['provenance_references']
    need(type(references) is list and 1 <= len(references) <= MAX_REFERENCES, 'composition reference inventory missing')
    expected = {}
    for ref in references + [copy['copy'] for copy in bundle['provenance_copies']]:
        ref = normalized_receipt(ref)
        need(ref['path'] not in expected, 'duplicate retained composition reference')
        expected[ref['path']] = ref
    for ref in [bundle['report'], bundle['composition_witness'], bundle['binary'], bundle['test_binary'], *bundle['logs'].values()]:
        need(ref['path'] in expected and same_receipt(ref, expected[ref['path']]), 'core composition reference omitted from fence')
    for ref in expected.values():
        reader.read(Path(ref['path']), ref)
    for key in ('binary', 'test_binary'):
        need(os.access(bundle[key]['path'], os.X_OK), 'composed executable access changed')
