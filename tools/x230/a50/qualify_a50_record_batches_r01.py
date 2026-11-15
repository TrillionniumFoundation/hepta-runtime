#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One independent A50 bounded-record-batch qualification from actual A48.

Preparation only until FINAL_BINDINGS_READY is frozen after source review.
Root serializes this new attempt after all other X230 work. The immutable A44
core supplies all six stages, source copying, fresh complete per-stage resource
gates and original-child custody. Immutable A46 definitions supply its pinned
loader, single initial observer and strict fresh=false artifact check; the old
A43 configure/main are never called. No old scheduling observation supplies
admission, and no prior failure or qualified tree is rewritten.

A48 is an ordinary, completed six-stage parent. Its original qualification,
guardian entry, worker, raw custody, logs and source are bound explicitly; no
composition schema is fabricated. All six A50 stages execute anew. Only the
new isolated source may be formatted. This qualification proves no gain.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import types
import zlib


BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
SHARED = BASE / 'tools/qualify_a43_a46.py'
SHARED_SHA = '7ce825966b413ab5e2d31979fbd5bb0e47a67a9105827d742ea986124610b176'
SHARED_BYTES = 17403
LEGACY = BASE / 'tools/prepare_qualify_a44_owner_barrier_r01.py'
LEGACY_SHA = '84e5fc48a688f83987425ff357428230083948703d419db4be1227d6b1ed8113'
LEGACY_BYTES = 49453
LEGACY_PROTOCOL = BASE / 'tools/a44-owner-barrier-qualification-r01.protocol.json'
LEGACY_PROTOCOL_SHA = '45185065cf0540296ea722bdfd4f000940338e466a6c936dfd34ca7cdbc5d50b'
LEGACY_PROTOCOL_BYTES = 8615

PARENT = BASE / 'source-a48-page-fullscan-r01'
PARENT_Q = BASE / 'qualification-a48-page-fullscan-r01/report.json'
PARENT_Q_SHA = '2787841b5242c22e314d46a4e99074fb0b91f04ed4240f230004b5d635c3cd0b'
PARENT_Q_BYTES = 59526
PARENT_MAP_SHA = 'be631e20eb7ec586c77807bb4e38b6529c5cda1fcc906eb1fac20f793c8c0ff1'
PARENT_INPUT_MAP_SHA = 'f7e2d63efdefd2001519de66e09a5b2ae0f2673db6c36522f56c0040191f332b'
PARENT_GIT_COMMIT = 'a9ba701676138f7e379dab07b38af27c72c46ed8'
PARENT_GIT_TREE = '40df74c05e8ea3a62aff157b1be571c09f5807a1'
PARENT_FILES = 168
PARENT_BINARY = PARENT_Q.parent / 'hepta-runtime'
PARENT_BINARY_SHA = '252cb58e08559d6cc68a5db19008c20ec858f7693a44ae353e60bbda81a2b386'
PARENT_BINARY_BYTES = 13517992
PARENT_TEST_SHA = '125d238ca27ad1a1c6f4610cd1bb8207d8078084a0771297170d344a1e81f0bc'
PARENT_ENTRY = BASE / 'a48-page-fullscan-entry-r01/entry-report.json'
PARENT_ENTRY_SHA = '871814ec2e5d3b870623fd6496a044626292efbc9b5658f488a6470e2a2cf851'
PARENT_ENTRY_BYTES = 309398
PARENT_WORKER = PARENT_ENTRY.parent / 'worker-report.json'
PARENT_WORKER_SHA = '758785ba8ecbaef30818cb21e7daa62ce45f3b86c575436c870c1e5f52dea940'
PARENT_WORKER_BYTES = 22281
PARENT_SCHEMA = 'runtime-candidate-qualification/v1'
PARENT_ENTRY_SCHEMA = 'hepta-a48-page-fullscan-qualification-entry/v1'
PARENT_WORKER_SCHEMA = 'hepta-a48-page-fullscan-guarded-qualifier-worker/v1'
PARENT_REQUIRED_TESTS = frozenset((
    'parallel_page_observation_rechecks_warm_off_page_originals',
    'late_off_page_content_change_discards_every_shared_page',
    'original_workers_expired_budget_does_not_detach_held_children',
    'async_metadata_timeout_retains_its_permit_until_original_children_join',
    'strict_walk_finishes_child_work_before_full_terminal_fences_in_both_layouts',
    'original_worker_second_spawn_failure_joins_the_first_waiting_thread',
    'original_worker_panic_resumes_through_the_coordinator_lock_after_all_joins',
    'original_workers_bound_submitted_unconsumed_work_to_one_per_lane',
    'both_async_timeouts_keep_all_admitted_permits_until_actual_io_cleanup',
    'completion_after_fixed_minimum_deadline_rejects_even_a_later_deadline_member',
    'fixed_cutoff_is_one_millisecond_and_new_members_never_extend_it',
    'a_final_epoch_change_discards_every_already_projected_page',
    'shared_page_projection_errors_stay_local_before_the_common_final_fence',
))

ATTEMPT = 'a50-record-batches-r01'
DEST = BASE / 'source-a50-record-batches-r01'
OUT = BASE / 'qualification-a50-record-batches-r01'
PREP = BASE / 'a50-record-batches-entry-r01'
INPUTS = BASE / 'a50-record-batches-inputs-r01'
PROTOCOL = INPUTS / 'protocol.json'
WINDOW = INPUTS / 'initial-observation.json'
GATE = INPUTS / 'initial-host-gate.json'
BUNDLE = BASE / 'tools/a50-record-batches-source-r01.json.gz'
PROTOCOL_SCHEMA = 'hepta-a50-record-batches-qualification-protocol/v1'
WINDOW_SCHEMA = 'hepta-a50-record-batches-start-observation/v1'
BUNDLE_SCHEMA = 'hepta-a50-record-batches-source-bundle/v1'
CHANGED = frozenset((
    'src/mcp/runtime/request_archive_content.rs',
    'src/mcp/runtime/request_archive_content_parallel_tests.rs',
))

# Freeze only after independent review and recomputation of the two-file overlay
# and complete 168-file map. A draft refuses before filesystem publication.
FINAL_BINDINGS_READY = True
CANDIDATE_MAP_SHA = 'e348cb3fb70a1d9dde8f97d722e65052c2ffba7807d409a2c822d75c314f4dd0'
BUNDLE_SHA = '338f1a7065e6aaa80b7872fc647699e46e557a4ddd7f2e11155c88de13511210'
BUNDLE_BYTES = 130633
COMPRESSED_SHA = '7554318acb173f277f882f1f5d85a477c414dbe397451aa3f7b108d571f341ae'
COMPRESSED_BYTES = 46526
OVERLAY_MANIFEST_SHA = '0ae8e62047cc0948f9e3acf0246db387b77888e0479a47f5eb9ac540bd0a7b9f'
OVERLAY_MANIFEST_BYTES = 10492


USER_INSTRUCTION = '在x230上连续冲优化hepta-runtime的并发吞吐，资源占用，多机协同能力，执行优化持久化与故障恢复设计，直到不能继续优化为止，然后推github'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def file_identity(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def pinned_shared():
    """Compile the already-reviewed A46 functions from one verified descriptor."""
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fd = None
    try:
        for part in SHARED.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(SHARED.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == SHARED_BYTES, 'shared A46 code kind or size differs')
        pieces, count = [], 0
        while count <= SHARED_BYTES:
            piece = os.read(fd, SHARED_BYTES + 1 - count)
            if not piece:
                break
            pieces.append(piece)
            count += len(piece)
        raw = b''.join(pieces)
        require(count == SHARED_BYTES and hashlib.sha256(raw).hexdigest() == SHARED_SHA,
                'shared A46 code SHA differs')
        require(file_identity(before) == file_identity(os.fstat(fd))
                == file_identity(os.stat(SHARED.name, dir_fd=parent, follow_symlinks=False)),
                'shared A46 code changed while loading')
        receipt = {'path': str(SHARED), 'bytes': count, 'sha256': SHARED_SHA,
                   'identity': file_identity(before)}
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
    shared = types.ModuleType('a50_reused_a46_qualification_functions')
    shared.__file__ = str(SHARED)
    exec(compile(raw, str(SHARED), 'exec'), shared.__dict__)
    return shared, receipt


def check_final_bindings():
    require(FINAL_BINDINGS_READY, 'A50 source binding draft; no attempt or worker permitted')
    for digest in (CANDIDATE_MAP_SHA, BUNDLE_SHA, COMPRESSED_SHA, OVERLAY_MANIFEST_SHA):
        require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest),
                'A50 final SHA binding missing')
    require(type(BUNDLE_BYTES) is int and 0 < BUNDLE_BYTES <= 1024 * 1024
            and type(COMPRESSED_BYTES) is int and 0 < COMPRESSED_BYTES <= 1024 * 1024
            and type(OVERLAY_MANIFEST_BYTES) is int and 0 < OVERLAY_MANIFEST_BYTES <= 1024 * 1024,
            'A50 final bounded input lengths missing')


def load_source_bundle(core, path, compressed=False):
    raw, receipt = core.original(path, COMPRESSED_SHA if compressed else BUNDLE_SHA, 1024 * 1024)
    if compressed:
        require(len(raw) == COMPRESSED_BYTES, 'A50 compressed source length differs')
        decoder = zlib.decompressobj(31)
        decoded = decoder.decompress(raw, BUNDLE_BYTES + 1)
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
                and len(decoded) == BUNDLE_BYTES and core.sha(decoded) == BUNDLE_SHA,
                'A50 bounded single-member source decode differs')
        raw = decoded
    require(len(raw) == BUNDLE_BYTES, 'A50 source bundle length differs')
    value = json.loads(raw)
    require(value['schema'] == BUNDLE_SCHEMA and value['attempt'] == ATTEMPT
            and value['parent_source'] == str(PARENT)
            and value['parent_qualification'] == {'path': str(PARENT_Q), 'sha256': PARENT_Q_SHA,
                                                'bytes': PARENT_Q_BYTES}
            and len(value['parent_source_map']) == PARENT_FILES
            and core.map_sha(value['parent_source_map']) == PARENT_MAP_SHA
            and len(value['candidate_source_map']) == PARENT_FILES
            and core.map_sha(value['candidate_source_map']) == CANDIDATE_MAP_SHA
            and set(value['changed_files']) == CHANGED
            and value['overlay_manifest']['sha256'] == OVERLAY_MANIFEST_SHA
            and value['overlay_manifest']['bytes'] == OVERLAY_MANIFEST_BYTES,
            'A50 source bundle binding differs')
    manifest_raw = base64.b64decode(value['overlay_manifest']['data_base64'], validate=True)
    require(len(manifest_raw) == OVERLAY_MANIFEST_BYTES
            and core.sha(manifest_raw) == OVERLAY_MANIFEST_SHA,
            'A50 retained source manifest differs')
    manifest = json.loads(manifest_raw)
    require(manifest.get('schema') == 'hepta-runtime-a50-source-overlay/v1'
            and manifest.get('parent_source_map_sha256') == PARENT_MAP_SHA
            and manifest.get('parent_qualification_report_sha256') == PARENT_Q_SHA
            and manifest.get('source_files') == PARENT_FILES
            and manifest.get('candidate_source_map_sha256') == CANDIDATE_MAP_SHA
            and {row['path'] for row in manifest['changed_files']} == CHANGED
            and len(manifest['changed_files']) == len(CHANGED)
            and manifest['new_tests']
            and PARENT_REQUIRED_TESTS <= set(manifest['required_existing_test_coverage']),
            'A50 overlay manifest parent, inventory or required tests differ')
    expected = dict(value['parent_source_map'])
    contents = {}
    for name, item in value['changed_files'].items():
        require(name in expected and not Path(name).is_absolute()
                and '..' not in Path(name).parts and str(Path(name)) == name,
                'A50 unsafe or newly introduced source member')
        data = base64.b64decode(item['data_base64'], validate=True)
        require(type(item['bytes']) is int and 0 < item['bytes'] <= core.MAX_FILE
                and len(data) == item['bytes'] and core.sha(data) == item['sha256']
                and item['parent_sha256'] == expected[name]
                and item['sha256'] != expected[name], 'A50 source overlay member differs')
        expected[name] = item['sha256']
        contents[name] = data
    require(expected == value['candidate_source_map'], 'A50 complete candidate delta coverage differs')
    for item in manifest['changed_files']:
        bound = value['changed_files'][item['path']]
        require(all(item[key] == bound[key] for key in ('parent_sha256', 'bytes', 'sha256')),
                'A50 source body and author manifest differ')
    require(expected.get('src/mcp/runtime/jobs.rs')
            == '643505d2ab9468bfff8c0d62cbc679471a9bbc17a83310a5881ada6056311f44'
            and 'src/mcp/runtime/jobs_owner_publication_tests.rs' not in expected,
            'A50 source unexpectedly contains A43 owner-barrier changes')
    return value, contents, raw, receipt


def receipt_fields(value):
    return {key: value[key] for key in ('path', 'bytes', 'sha256', 'identity')}


def read_bound(core, expected):
    path = Path(expected['path'])
    require(path.is_absolute() and path.is_relative_to(BASE) and '..' not in path.parts,
            'parent evidence outside the fixed development tree')
    raw, receipt = core.original(path, expected['sha256'])
    require(receipt == receipt_fields(expected), 'parent evidence receipt changed: ' + str(path))
    return raw, receipt


def normal_raw_custody(row):
    pid = row.get('pid')
    require(type(pid) is int and pid > 1 and row.get('actual_waitpid') == pid
            and type(row.get('raw_wait_status')) is int and row['raw_wait_status'] == 0
            and type(row.get('returncode')) is int and row['returncode'] == 0
            and row.get('executed') is True and row.get('execution_count') == 1
            and row.get('original_child_reaped') is True and row.get('pidfd_opened') is True
            and row.get('custody_known') is True and row.get('custody_retained_until_reap') is True
            and row.get('group_quiet_before_reap') is True and row.get('signals') == []
            and row.get('worker_permit_sent') is True and row.get('outer_work_budget_exceeded') is False
            and not row.get('normal_worker_exit_left_live_group_or_observation_errors')
            and not row.get('error') and not row.get('cleanup_errors'),
            'parent qualification original raw child completion differs')
    initial, terminal = row['original_identity'], row['terminal_group_snapshot']
    require(initial['pid'] == initial['pgrp'] == initial['session'] == pid
            and terminal['errors'] == [] and terminal['live'] == [],
            'parent qualification original session or quiet observation differs')
    original = [member for member in terminal['members'] if member['pid'] == pid]
    require(len(original) == 1 and original[0]['state'] in ('Z', 'X', 'x')
            and original[0]['start_ticks'] == initial['start_ticks']
            and original[0]['pgrp'] == original[0]['session'] == pid,
            'parent qualification final original process identity differs')


def parent_qualification(core, mapping, state):
    raw, receipt = core.original(PARENT_Q, PARENT_Q_SHA)
    entry_raw, entry_receipt = core.original(PARENT_ENTRY, PARENT_ENTRY_SHA)
    worker_raw, worker_receipt = core.original(PARENT_WORKER, PARENT_WORKER_SHA)
    require(len(raw) == PARENT_Q_BYTES and len(entry_raw) == PARENT_ENTRY_BYTES
            and len(worker_raw) == PARENT_WORKER_BYTES, 'A48 original evidence lengths differ')
    value, entry, worker = json.loads(raw), json.loads(entry_raw), json.loads(worker_raw)
    require(value.get('schema') == PARENT_SCHEMA and value.get('qualified') is True
            and value.get('current_stage') == 'complete' and not value.get('error')
            and not value.get('errors') and value.get('source') == str(PARENT)
            and value['source_tested'] == value['source_after'] == mapping
            and len(mapping) == PARENT_FILES and core.map_sha(mapping) == PARENT_MAP_SHA
            and set(value['source_input']) == set(mapping)
            and core.map_sha(value['source_input']) == PARENT_INPUT_MAP_SHA,
            'qualified ordinary A48 parent source binding differs')
    require(entry.get('schema') == PARENT_ENTRY_SCHEMA
            and entry.get('qualified') is True and entry.get('passed') is True
            and entry.get('guarded_qualification_complete') is True
            and entry.get('parent_unchanged_after_attempt') is True
            and entry.get('reused_dependencies_unchanged') is True
            and entry.get('source') == str(PARENT) and entry.get('output') == str(PARENT_Q.parent)
            and entry.get('source_after') == mapping
            and entry.get('source_preformat') == value['source_input']
            and entry.get('source_file_count') == PARENT_FILES
            and not entry.get('error') and not entry.get('errors')
            and worker.get('schema') == PARENT_WORKER_SCHEMA
            and worker.get('passed') is True
            and worker.get('strict_fresh_artifacts_verified') is True
            and worker.get('required_test_coverage_verified') is True
            and worker.get('reused_dependencies_unchanged') is True
            and not worker.get('error') and not worker.get('errors'),
            'ordinary A48 guardian or postchecks are incomplete')
    for reference in (entry['qualification_report'], worker['qualifier_report'],
                      worker['strict_fresh_artifact_evidence']['qualification_report']):
        require(receipt_fields(reference) == receipt, 'A48 guardian qualification receipt differs')
    require(receipt_fields(entry['guarded_worker_report']) == worker_receipt
            and ('worker_report' not in entry
                 or receipt_fields(entry['worker_report']) == worker_receipt),
            'A48 guardian final worker receipt differs')
    normal_raw_custody(entry['worker_custody'])
    rows, guarded = value['stages'], worker['stages']
    require(len(rows) == len(guarded) == len(core.STAGES), 'A48 six-stage coverage differs')
    evidence = {'schema': 'hepta-a50-ordinary-parent-proof/v1',
                'qualification_schema': PARENT_SCHEMA, 'composition_used': False,
                'qualification': receipt, 'guardian_entry': entry_receipt,
                'guardian_worker': worker_receipt, 'raw_worker_custody_verified': True,
                'source_map_compact_sha256': PARENT_MAP_SHA,
                'prepared_source_map_compact_sha256': PARENT_INPUT_MAP_SHA,
                'immutable_inputs': {},
                'historical_test_body_rehashed': False,
                'test_executable_scope': 'The SHA-pinned ordinary A48 report and original compiler event bind its copied historical test executable; that large body is not read by this wrapper. The unchanged 128 MiB original-input read budget is retained. All A50 tests and release are rebuilt anew.'}
    logs = {}
    for index, ((name, tail), row, stage) in enumerate(zip(core.STAGES, rows, guarded)):
        command = [core.CARGO, '+1.95.0'] + tail
        require(row['name'] == stage['name'] == name and row['command'] == stage['argv'] == command
                and type(row['returncode']) is int and row['returncode'] == 0
                and type(stage['returncode']) is int and stage['returncode'] == 0
                and stage.get('executed') is True and stage.get('execution_count') == 1
                and stage.get('gate_clear') is True and stage.get('timeout_seconds') == 1800
                and not stage.get('error') and not stage.get('errors'),
                'A48 original or guarded stage differs: ' + name)
        gate_raw, gate_receipt = read_bound(core, stage['host_gate'])
        require(gate_receipt['path'] == str(PARENT_ENTRY.parent /
                    ('stage-' + str(index) + '-' + name + '.host-gate.json')),
                'A48 original stage gate path differs')
        gate = json.loads(gate_raw)
        require(gate.get('clear') is True and gate.get('matching_live_processes') == []
                and gate.get('resource_errors') == []
                and gate.get('mem_available_kib', -1) >= core.MEM_MIN_KIB
                and gate.get('disk_available_bytes', -1) >= core.DISK_MIN_BYTES
                and gate.get('snapshot', {}).get('required_fields_present') is True
                and gate.get('snapshot', {}).get('errors') == [],
                'A48 original complete stage resource gate differs')
        log_raw, log_receipt = core.original(PARENT_Q.parent / (name + '.log'), row['log_sha256'])
        evidence['immutable_inputs']['gate_' + name] = gate_receipt
        evidence['immutable_inputs']['log_' + name] = log_receipt
        logs[name] = (log_raw, log_receipt)
        if name in ('test', 'release'):
            is_test = name == 'test'
            events = []
            for line in log_raw.splitlines():
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                if (isinstance(event, dict) and event.get('reason') == 'compiler-artifact'
                        and event.get('target', {}).get('name') == 'hepta-runtime'
                        and event.get('profile', {}).get('test') is is_test):
                    events.append(event)
            require(len(events) == 1 and events[0].get('fresh') is False
                    and events[0].get('manifest_path') == str(PARENT / 'Cargo.toml')
                    and events[0].get('target', {}).get('src_path') == str(PARENT / 'src/main.rs')
                    and Path(events[0]['executable']).is_relative_to(core.TARGET),
                    'A48 original compiler artifact is not exact source-bound fresh=false')
            strict = worker['strict_fresh_artifact_evidence']['compiler_artifacts'][name]
            key = 'test_binary' if is_test else 'binary'
            filename = 'hepta-runtime-tests' if is_test else 'hepta-runtime'
            digest = PARENT_TEST_SHA if is_test else PARENT_BINARY_SHA
            require(strict['fresh_strictly_false'] is True and strict['original_event'] == events[0]
                    and receipt_fields(strict['log']) == log_receipt
                    and strict['copied_artifact'] == value[key]
                    and value[key].get('cached') is False
                    and value[key].get('path') == str(PARENT_Q.parent / filename)
                    and value[key].get('sha256') == digest
                    and value[key].get('compiler_source') == str(PARENT / 'src/main.rs'),
                    'A48 copied artifact or guardian strict proof differs')
    coverage = worker['required_test_coverage']
    require(set(coverage['new_tests'] + coverage['required_existing_tests']) == PARENT_REQUIRED_TESTS
            and coverage['focused_reruns'] == 0
            and receipt_fields(coverage['test_log']) == logs['test'][1],
            'A48 original full-suite coverage proof differs')
    test_lines = set(logs['test'][0].decode('utf-8').splitlines())
    for name in PARENT_REQUIRED_TESTS:
        matched = coverage['successful_execution_lines'].get(name, [])
        pattern = re.compile(r'^test (?:\S+::)?' + re.escape(name) + r' \.\.\. ok$')
        require(matched and all(line in test_lines and pattern.fullmatch(line) for line in matched),
                'A48 required full-suite test proof differs: ' + name)
    evidence['required_original_tests_verified'] = sorted(PARENT_REQUIRED_TESTS)
    _, binary_receipt = core.original(PARENT_BINARY, PARENT_BINARY_SHA)
    require(binary_receipt['bytes'] == PARENT_BINARY_BYTES
            and os.access(PARENT_BINARY, os.X_OK), 'A48 parent release copy differs')
    evidence['immutable_inputs']['release_binary'] = binary_receipt
    evidence['test_executable_report_binding'] = value['test_binary']
    copies = {}
    for name, body in (('a48-qualification-entry.original.json', entry_raw),
                       ('a48-qualification-worker.original.json', worker_raw)):
        path = PREP / name
        if state:
            copy_raw, copied = read_bound(core, state['proof']['retained_guardian_copies'][name])
            require(copy_raw == body, 'retained A48 guardian copy changed')
        else:
            copied = core.create(path, body)
        copies[name] = copied
    evidence['retained_guardian_copies'] = copies
    if state:
        require(evidence == state['proof'], 'ordinary A48 parent evidence changed')
    else:
        state['proof'] = evidence
    return raw, receipt


def policy(core, old):
    result = {
        'schema': PROTOCOL_SCHEMA, 'attempt': ATTEMPT, 'bindings_ready': True,
        'independent_attempt': True, 'maximum_attempts': 1, 'automatic_retry': False,
        'user_instruction': USER_INSTRUCTION,
        'declared_scope': 'One new full six-stage A50 bounded32-record qualification under current user continuation; root serializes it after A49 and all other X230 work.',
        'paths': {'source': str(DEST), 'qualification': str(OUT), 'entry': str(PREP),
                  'target': str(core.TARGET), 'bundle': str(BUNDLE), 'protocol': str(PROTOCOL)},
        'parent': {'source': str(PARENT), 'source_files': PARENT_FILES,
                   'source_map_compact_sha256': PARENT_MAP_SHA,
                   'git_commit': PARENT_GIT_COMMIT, 'git_tree': PARENT_GIT_TREE,
                   'git_binding_scope': 'Root verified all 168 source Git blobs against the actual A48 qualified map; this local qualifier performs no GitHub operations.',
                   'qualification_path': str(PARENT_Q), 'qualification_sha256': PARENT_Q_SHA,
                   'qualification_bytes': PARENT_Q_BYTES, 'qualification_schema': PARENT_SCHEMA,
                   'composition_used': False,
                   'entry': {'path': str(PARENT_ENTRY), 'sha256': PARENT_ENTRY_SHA, 'bytes': PARENT_ENTRY_BYTES},
                   'worker': {'path': str(PARENT_WORKER), 'sha256': PARENT_WORKER_SHA, 'bytes': PARENT_WORKER_BYTES},
                   'release_binary': {'path': str(PARENT_BINARY), 'sha256': PARENT_BINARY_SHA,
                                      'bytes': PARENT_BINARY_BYTES}},
        'candidate': {'source_files': PARENT_FILES, 'source_map_compact_sha256': CANDIDATE_MAP_SHA,
                      'bundle_schema': BUNDLE_SCHEMA, 'changed_files': sorted(CHANGED),
                      'bundle_json_bytes': BUNDLE_BYTES, 'bundle_json_sha256': BUNDLE_SHA,
                      'bundle_gzip_bytes': COMPRESSED_BYTES, 'bundle_gzip_sha256': COMPRESSED_SHA,
                      'overlay_manifest_bytes': OVERLAY_MANIFEST_BYTES,
                      'overlay_manifest_sha256': OVERLAY_MANIFEST_SHA},
        'original_driver': {'path': str(LEGACY), 'sha256': LEGACY_SHA, 'bytes': LEGACY_BYTES},
        'original_policy': {'path': str(LEGACY_PROTOCOL), 'sha256': LEGACY_PROTOCOL_SHA,
                            'bytes': LEGACY_PROTOCOL_BYTES},
        'shared_functions': {'path': str(SHARED), 'sha256': SHARED_SHA, 'bytes': SHARED_BYTES,
                             'used': ['pinned_driver', 'observe_once', 'worker', 'verify_fresh_artifacts'],
                             'a43_configure_or_main_called': False},
        'helpers': old['helpers'], 'stages': old['stages'], 'budgets': old['budgets'],
        'build_jobs': 2, 'tokio_worker_threads': 2, 'rust_test_threads': 2, 'incremental': 0,
        'resource_gate': old['resource_gate'], 'custody': old['custody'],
        'initial_observation': {'path': str(WINDOW), 'gate_path': str(GATE), 'schema': WINDOW_SCHEMA,
                                'snapshot_calls': 1, 'requires_clear': True,
                                'wait_or_retry_when_busy': False,
                                'does_not_replace_per_stage_gates': True},
        'root_must_finish_other_x230_work_before_launch': True,
        'previous_window_not_reused_for_admission': True,
        'source_base_is_a48_not_a43': True,
        'frozen_parent_policy': 'The complete actual A48 source map and stat identities, ordinary six-stage report, guardian entry/worker/raw custody, six logs/stage gates and copied release body are verified before and after. Original guardian copies are retained. Only the isolated A50 tree may be formatted.',
        'parent_tests_scope': 'The historical A48 test executable is bound by its SHA-pinned ordinary report and exact fresh=false compiler event, not body-rehashed by this wrapper. The original 128 MiB read budget remains unchanged. All A50 tests and release are independently rebuilt with fresh=false artifacts.',
        'source_amendment_policy': old['source_amendment_policy'],
        'test_and_release_compiler_artifact_fresh_must_be_false': True,
        'test_coverage_policy': 'The one full-test log must contain successful execution lines for every new and required-existing test named in the SHA-pinned overlay manifest; no focused rerun substitutes for the full suite.',
        'report_schema_policy': 'A50 entry and worker schemas retain inherited_schema and reused-driver descriptions; the unmodified qualifier retains runtime-candidate-qualification/v1.',
        'retained_parent_copy': str(PREP / 'a48-qualification.original.json'),
        'benchmark_executions': 0, 'service_changes': False,
        'foreign_process_signal_or_priority_changes': False,
        'ssh_or_agent_access': False, 'git_add_commit_push_merge': False,
        'scope_limits': [
            'Each initial or stage gate is a complete point-in-time local observation; it is not a host lease.',
            'Only the original new worker session/group is covered by cleanup; escaped descendants and reboot are not established.',
            'The A48 parent is its actual completed ordinary six-stage attempt. No composed schema or inherited test/build completion is used for A50.',
            'A50 build/test qualification establishes no performance win, native multi-host result, power-loss result or production deployment.',
            'Original A44 helper diagnostic wording may remain in inherited errors; paths, source maps and new A50 report schemas identify this attempt.',
        ],
    }
    require(result['stages'] == [{'name': name, 'argv': [core.CARGO, '+1.95.0'] + tail,
                                 'timeout_seconds': 1800} for name, tail in core.STAGES]
            and result['budgets'] == {'worker_seconds': 6600, 'term_seconds': 30,
                                      'kill_seconds': 30, 'operator_outer_seconds': 7000},
            'inherited six-stage or resource budget differs')
    return result


def configure():
    check_final_bindings()
    shared, shared_receipt = pinned_shared()
    core, driver_receipt = shared.pinned_driver()
    require(driver_receipt['path'] == str(LEGACY) and driver_receipt['sha256'] == LEGACY_SHA
            and driver_receipt['bytes'] == LEGACY_BYTES, 'original driver differs')
    # This validates the unchanged library's original policy only. Its old
    # candidate and old scheduling-window entry are not used for A50 admission.
    old_raw, old_receipt = core.verify_protocol_binding()
    require(old_receipt['path'] == str(LEGACY_PROTOCOL) and len(old_raw) == LEGACY_PROTOCOL_BYTES
            and core.sha(old_raw) == LEGACY_PROTOCOL_SHA, 'original policy differs')
    old = json.loads(old_raw)
    policy_raw = core.canonical(policy(core, old))
    require(len(policy_raw) <= 65536, 'A50 protocol exceeds fixed bound')
    for module in (core, shared):
        for name in ('BASE', 'DEST', 'OUT', 'PREP', 'INPUTS', 'PROTOCOL', 'WINDOW', 'GATE',
                     'ATTEMPT', 'PROTOCOL_SCHEMA', 'WINDOW_SCHEMA'):
            setattr(module, name, globals()[name])
    for name in ('PARENT', 'PARENT_Q', 'PARENT_Q_SHA', 'PARENT_MAP_SHA', 'CANDIDATE_MAP_SHA',
                 'BUNDLE', 'BUNDLE_SHA', 'BUNDLE_BYTES', 'COMPRESSED_SHA', 'COMPRESSED_BYTES',
                 'CHANGED'):
        setattr(core, name, globals()[name])
    core.PROTOCOL_SHA, core.PROTOCOL_BYTES = core.sha(policy_raw), len(policy_raw)
    core.__file__ = str(Path(__file__).absolute())
    parent_state = {}
    dependency_receipts = {'shared_functions': shared_receipt, 'original_driver': driver_receipt,
                           'original_policy': old_receipt}
    original_checkpoint, original_create = core.checkpoint, core.create

    def checkpoint(path, value):
        schemas = {'hepta-a44-owner-barrier-qualification-entry/v1':
                       'hepta-a50-record-batches-qualification-entry/v1',
                   'hepta-a44-owner-barrier-guarded-qualifier-worker/v1':
                       'hepta-a50-record-batches-guarded-qualifier-worker/v1'}
        if value.get('schema') in schemas:
            value['inherited_schema'] = value['schema']
            value['schema'] = schemas[value['schema']]
        value.update(attempt=ATTEMPT, original_driver=driver_receipt,
                     shared_functions=shared_receipt, original_policy=old_receipt,
                     old_scheduling_window_used=False, a43_source_used=False)
        value['execution_description'] = 'Unchanged six-stage qualifier and original worker custody with independent A50 bounded-record-batch source bindings.'
        if path == PREP / 'entry-report.json':
            value['scheduling_scope'] = 'One independent A50 attempt after root serialization; fresh initial and per-stage complete gates.'
            value['retained_parent_copy'] = str(PREP / 'a48-qualification.original.json')
            value['parent_qualification_proof'] = parent_state.get('proof')
        if 'finished_utc' in value:
            try:
                verified = {}
                for key, expected in dependency_receipts.items():
                    _, actual = core.original(Path(expected['path']), expected['sha256'])
                    require(actual == expected, 'immutable helper changed: ' + key)
                    verified[key] = actual
                value['reused_dependencies_after'] = verified
                value['reused_dependencies_unchanged'] = True
            except BaseException as error:
                value['passed'] = False
                if 'qualified' in value:
                    value['qualified'] = False
                value['reused_dependencies_unchanged'] = False
                value.setdefault('errors', []).append('final dependency check: ' + type(error).__name__ + ': ' + str(error))
        return original_checkpoint(path, value)

    def create(path, raw):
        # The generic original main gives its parent receipt a r07 filename.
        # A50 records the actual ordinary A48 parent with a precise new name.
        if path == PREP / 'r07-qualification.original.json':
            path = PREP / 'a48-qualification.original.json'
        if path == WINDOW:
            observation = json.loads(raw)
            if 'root_a42_completion' in observation:
                observation['root_other_x230_work_completion'] = observation.pop('root_a42_completion')
                raw = core.canonical(observation)
        return original_create(path, raw)

    def verify_protocol():
        raw, receipt = core.original(PROTOCOL, core.PROTOCOL_SHA, 65536)
        require(raw == policy_raw, 'A50 independent protocol differs')
        return raw, receipt

    def verify_window():
        raw, receipt = core.original(WINDOW, cap=1024 * 1024)
        value = json.loads(raw)
        require(value.get('schema') == WINDOW_SCHEMA and value.get('attempt') == ATTEMPT
                and value.get('status') == 'clear_observed' and value.get('passed') is True
                and value.get('snapshot_calls') == 1 and value.get('errors') == []
                and value.get('automatic_retries') == 0 and value.get('old_window_used') is False
                and value.get('per_stage_gates_still_required') is True,
                'A50 single initial observation is not complete and clear')
        bound = value.get('gate', {})
        require(bound.get('path') == str(GATE), 'A50 initial gate path differs')
        gate_raw, gate_receipt = core.original(GATE, bound.get('sha256'), 1024 * 1024)
        require(gate_receipt == bound, 'A50 initial gate binding changed')
        gate = json.loads(gate_raw)
        require(gate.get('clear') is True and gate.get('matching_live_processes') == []
                and gate.get('resource_errors') == []
                and gate.get('resource_thresholds') == {
                    'mem_available_kib_min': core.MEM_MIN_KIB,
                    'disk_available_bytes_min': core.DISK_MIN_BYTES}
                and gate.get('mem_available_kib', -1) >= core.MEM_MIN_KIB
                and gate.get('disk_available_bytes', -1) >= core.DISK_MIN_BYTES
                and gate.get('snapshot', {}).get('required_fields_present') is True
                and gate.get('snapshot', {}).get('errors') == [],
                'A50 retained initial resource gate is incomplete or refused')
        return raw, receipt

    core.checkpoint, core.create = checkpoint, create
    core.load_bundle = lambda path, compressed=False: load_source_bundle(core, path, compressed)
    core.parent_qualification = lambda mapping: parent_qualification(core, mapping, parent_state)
    core.verify_protocol_binding, core.verify_scheduling_window = verify_protocol, verify_window
    return core, shared, policy_raw


def worker(core, shared, args):
    code = shared.worker(core, args)
    if code:
        return code
    raw, _ = core.original(PREP / 'worker-report.json')
    report = json.loads(raw)
    try:
        bundle, _, _, bundle_receipt = core.load_bundle(PREP / 'source-bundle.original.json')
        manifest = json.loads(base64.b64decode(bundle['overlay_manifest']['data_base64'], validate=True))
        required = manifest['new_tests'] + manifest['required_existing_test_coverage']
        require(manifest['new_tests'] and PARENT_REQUIRED_TESTS <= set(manifest['required_existing_test_coverage'])
                and required and len(required) == len(set(required))
                and all(type(name) is str and re.fullmatch(r'[a-z][a-z0-9_]*', name)
                        for name in required), 'source manifest test coverage names differ')
        log_raw, log_receipt = core.original(OUT / 'test.log')
        require(log_receipt == report['strict_fresh_artifact_evidence']['compiler_artifacts']['test']['log'],
                'full-test log changed after the strict fresh artifact check')
        lines = log_raw.decode('utf-8').splitlines()
        observed = {}
        for name in required:
            pattern = re.compile(r'^test (?:\S+::)?' + re.escape(name) + r' \.\.\. ok$')
            matching = [line for line in lines if pattern.fullmatch(line)]
            require(matching, 'required full-suite test did not report success: ' + name)
            observed[name] = matching
        report['required_test_coverage'] = {'source_bundle': bundle_receipt,
            'overlay_manifest_sha256': OVERLAY_MANIFEST_SHA, 'test_log': log_receipt,
            'new_tests': manifest['new_tests'],
            'required_existing_tests': manifest['required_existing_test_coverage'],
            'successful_execution_lines': observed, 'focused_reruns': 0}
        report['required_test_coverage_verified'] = True
    except BaseException as error:
        code = 1
        report['passed'] = False
        report['required_test_coverage_verified'] = False
        report['error'] = 'additional full-suite coverage check: ' + type(error).__name__ + ': ' + str(error)
    finally:
        report['finished_utc'] = core.utc()
        core.checkpoint(PREP / 'worker-report.json', report)
    return 0 if code == 0 and report.get('passed') is True else 1


def main(core, shared, policy_raw, args):
    require(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(os, 'WNOWAIT'),
            'native Linux original-child custody is required')
    os.umask(0o077)
    for path in (DEST, OUT, PREP, INPUTS):
        core.fresh(path)
    core.mkdir_new(INPUTS)
    core.create(PROTOCOL, policy_raw)
    if not shared.observe_once(core):
        print(json.dumps({'attempt': ATTEMPT, 'status': 'refused_before_preparation',
                          'initial_observation': str(WINDOW), 'worker_executions': 0,
                          'cargo_executions': 0, 'automatic_retry': False}), flush=True)
        return 2
    return core.main(args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--permit-fd', type=int)
    parser.add_argument('--expected-entry-sha')
    arguments = parser.parse_args()
    core, shared, policy_raw = configure()
    signal.signal(signal.SIGTERM, core.termination_handler)
    signal.signal(signal.SIGINT, core.termination_handler)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    if arguments.worker:
        raise SystemExit(worker(core, shared, arguments))
    require(arguments.permit_fd is None and arguments.expected_entry_sha is None,
            'worker-only arguments refused')
    raise SystemExit(main(core, shared, policy_raw, arguments))
