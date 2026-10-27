#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One independent A48 page full-scan qualification from the qualified A42 tree.

Preparation only until FINAL_BINDINGS_READY is frozen after the source review.
The root orchestrator must finish its other X230 work before launching this new
attempt. No old scheduling window or prior failed attempt supplies admission.
The immutable A44 driver provides the original six-stage qualifier facade,
source copying, fresh per-stage resource gates and original-child custody.
The immutable A46 wrapper provides only its file loader, one initial observer
and strict fresh=false artifact check; its A43 configure/main are never called.

This wrapper supplies new A48 source, parent-composition and protocol bindings.
It never patches an old driver, report, candidate, service or installed binary.
All six stages run again for A48; the composed A42 report is parent evidence,
not a substitute for a new A48 test, build or performance result.
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

PARENT = BASE / 'source-a42-fresh-cohort-r03'
PARENT_Q = BASE / 'qualification-a46-a42-release-completion-r01/report.json'
PARENT_Q_SHA = 'd6ee0938ef816c5f472edb967fe2764fc3bc05b4e958243e102f1d542c4fa46f'
PARENT_Q_BYTES = 238044
PARENT_MAP_SHA = 'c1ae8a69901aee16e03871e920a6a7e321672c9b30b3a6e75d3560390b8c2e11'
PARENT_FILES = 168
PARENT_BINARY = PARENT_Q.parent / 'hepta-runtime'
PARENT_BINARY_SHA = 'dde7f516d39ec8f6b7ee010e5747f55b0b10d742c419df22fd96ecbfffdd5299'
PARENT_BINARY_BYTES = 13517992
PARENT_TEST_SHA = 'bf4f3fecfda0fb78cebaac83c7f154c3410371dee1f25172ebf92596aa33275a'
PARENT_TEST_BYTES = 442697032
COMPOSED_SCHEMA = 'hepta-runtime-composed-qualification/v1'
COMPOSITION_KIND = 'a42-r03-five-stages-plus-a46-release/v1'

ATTEMPT = 'a48-page-fullscan-r01'
DEST = BASE / 'source-a48-page-fullscan-r01'
OUT = BASE / 'qualification-a48-page-fullscan-r01'
PREP = BASE / 'a48-page-fullscan-entry-r01'
INPUTS = BASE / 'a48-page-fullscan-inputs-r01'
PROTOCOL = INPUTS / 'protocol.json'
WINDOW = INPUTS / 'initial-observation.json'
GATE = INPUTS / 'initial-host-gate.json'
BUNDLE = BASE / 'tools/a48-page-fullscan-source-r01.json.gz'
PROTOCOL_SCHEMA = 'hepta-a48-page-fullscan-qualification-protocol/v1'
WINDOW_SCHEMA = 'hepta-a48-page-fullscan-start-observation/v1'
BUNDLE_SCHEMA = 'hepta-a48-page-fullscan-source-bundle/v1'
CHANGED = frozenset((
    'src/mcp/runtime/request_archive_index.rs',
    'src/mcp/runtime/request_archive_content.rs',
    'src/mcp/runtime/request_archive_content_parallel_tests.rs',
    'src/mcp/runtime/request_archive_page_batch_tests.rs',
))

# Frozen only after the independent source manifest and complete candidate map
# have been recomputed. A draft refuses before any filesystem publication.
FINAL_BINDINGS_READY = True
CANDIDATE_MAP_SHA = 'f7e2d63efdefd2001519de66e09a5b2ae0f2673db6c36522f56c0040191f332b'
BUNDLE_SHA = '3408b7d6cf6a905baab87153be2c38c543d1e202eda5c71214a965087c27b62a'
BUNDLE_BYTES = 204557
COMPRESSED_SHA = 'b17363aedf4de3bedb54e977f48e04a5e1e10d5a0aaf731c02eab36590569765'
COMPRESSED_BYTES = 72973
OVERLAY_MANIFEST_SHA = '8b29f56c4a8b9342623fddabc5d673fb7d29274b9864a4e1105c34583b1bb544'
OVERLAY_MANIFEST_BYTES = 5404

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
    shared = types.ModuleType('a48_reused_a46_qualification_functions')
    shared.__file__ = str(SHARED)
    exec(compile(raw, str(SHARED), 'exec'), shared.__dict__)
    return shared, receipt


def check_final_bindings():
    require(FINAL_BINDINGS_READY, 'A48 source binding draft; no attempt or worker permitted')
    for digest in (CANDIDATE_MAP_SHA, BUNDLE_SHA, COMPRESSED_SHA, OVERLAY_MANIFEST_SHA):
        require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest),
                'A48 final SHA binding missing')
    require(type(BUNDLE_BYTES) is int and 0 < BUNDLE_BYTES <= 1024 * 1024
            and type(COMPRESSED_BYTES) is int and 0 < COMPRESSED_BYTES <= 1024 * 1024
            and type(OVERLAY_MANIFEST_BYTES) is int and 0 < OVERLAY_MANIFEST_BYTES <= 1024 * 1024,
            'A48 final bounded input lengths missing')


def load_source_bundle(core, path, compressed=False):
    raw, receipt = core.original(path, COMPRESSED_SHA if compressed else BUNDLE_SHA, 1024 * 1024)
    if compressed:
        require(len(raw) == COMPRESSED_BYTES, 'A48 compressed source length differs')
        decoder = zlib.decompressobj(31)
        decoded = decoder.decompress(raw, BUNDLE_BYTES + 1)
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
                and len(decoded) == BUNDLE_BYTES and core.sha(decoded) == BUNDLE_SHA,
                'A48 bounded single-member source decode differs')
        raw = decoded
    require(len(raw) == BUNDLE_BYTES, 'A48 source bundle length differs')
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
            'A48 source bundle binding differs')
    manifest_raw = base64.b64decode(value['overlay_manifest']['data_base64'], validate=True)
    require(len(manifest_raw) == OVERLAY_MANIFEST_BYTES
            and core.sha(manifest_raw) == OVERLAY_MANIFEST_SHA,
            'A48 retained source manifest differs')
    expected = dict(value['parent_source_map'])
    contents = {}
    for name, item in value['changed_files'].items():
        require(name in expected and not Path(name).is_absolute()
                and '..' not in Path(name).parts and str(Path(name)) == name,
                'A48 unsafe or newly introduced source member')
        data = base64.b64decode(item['data_base64'], validate=True)
        require(type(item['bytes']) is int and 0 < item['bytes'] <= core.MAX_FILE
                and len(data) == item['bytes'] and core.sha(data) == item['sha256']
                and item['parent_sha256'] == expected[name]
                and item['sha256'] != expected[name], 'A48 source overlay member differs')
        expected[name] = item['sha256']
        contents[name] = data
    require(expected == value['candidate_source_map'], 'A48 complete candidate delta coverage differs')
    require(expected.get('src/mcp/runtime/jobs.rs')
            == '643505d2ab9468bfff8c0d62cbc679471a9bbc17a83310a5881ada6056311f44'
            and 'src/mcp/runtime/jobs_owner_publication_tests.rs' not in expected,
            'A48 source unexpectedly contains A43 owner-barrier changes')
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
            'parent release original raw child completion differs')
    initial, terminal = row['original_identity'], row['terminal_group_snapshot']
    require(initial['pid'] == initial['pgrp'] == initial['session'] == pid
            and terminal['errors'] == [] and terminal['live'] == [],
            'parent release original session or quiet observation differs')
    original = [member for member in terminal['members'] if member['pid'] == pid]
    require(len(original) == 1 and original[0]['state'] in ('Z', 'X', 'x')
            and original[0]['start_ticks'] == initial['start_ticks']
            and original[0]['pgrp'] == original[0]['session'] == pid,
            'parent release final original process identity differs')


def parent_qualification(core, mapping, state):
    raw, receipt = core.original(PARENT_Q, PARENT_Q_SHA)
    require(len(raw) == PARENT_Q_BYTES, 'A42 composed report length differs')
    value = json.loads(raw)
    require(value.get('schema') == COMPOSED_SCHEMA
            and value.get('composition_kind') == COMPOSITION_KIND
            and value.get('qualified') is True and not value.get('error')
            and value.get('source') == str(PARENT)
            and value['source_tested'] == value['source_after'] == mapping
            and len(mapping) == PARENT_FILES and core.map_sha(mapping) == PARENT_MAP_SHA
            and value['source_identity_before'] == value['source_identity_after']
            and set(value['source_identity_after']) == set(mapping)
            and value.get('previous_tests_are_not_reexecuted') is True
            and value.get('new_release_executions') == 1
            and value.get('original_r03_remains_failed') is True
            and value.get('original_source_after_was_not_written_or_invented') is True,
            'qualified A42 composed parent source binding differs')
    for name, digest in mapping.items():
        bound = value['source_identity_after'][name]
        require(bound['path'] == str(PARENT / name) and bound['sha256'] == digest,
                'A42 historical source identity map differs')
    rows = value['stages']
    require(len(rows) == len(core.STAGES), 'A42 composed stage coverage differs')
    evidence = {'composed_qualification': receipt, 'immutable_inputs': {},
                'test_executable_scope': 'The fixed parent report binds its original copied test executable; this wrapper does not rehash that 442697032-byte historical test executable. A48 tests are rebuilt and run afresh.'}
    for index, ((name, tail), row) in enumerate(zip(core.STAGES, rows)):
        require(row['name'] == name and row['command'] == [core.CARGO, '+1.95.0'] + tail
                and type(row['returncode']) is int and row['returncode'] == 0
                and row['origin'] == ('r03' if index < 5 else 'a46_new_user_authorized_release_only'),
                'A42 original composed stage differs: ' + name)
        log_raw, log_receipt = read_bound(core, row['log'])
        require(row['log_sha256'] == log_receipt['sha256'], 'A42 stage log SHA differs')
        evidence['immutable_inputs']['log_' + name] = log_receipt
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
                    and events[0].get('target', {}).get('src_path') == str(PARENT / 'src/main.rs'),
                    'A42 parent compiler artifact is not exact source-bound fresh=false')
    release = value['release_completion']
    entry_raw, entry_receipt = read_bound(core, release['entry'])
    worker_raw, worker_receipt = read_bound(core, release['worker'])
    entry, worker = json.loads(entry_raw), json.loads(worker_raw)
    require(entry.get('passed') is True and entry.get('errors') == []
            and entry.get('source') == str(PARENT) and entry.get('source_unchanged') is True
            and entry.get('originals_unchanged') is True
            and entry.get('release_custody_verified') is True
            and worker.get('passed') is True and worker.get('errors') == []
            and worker.get('source_unchanged') is True and worker.get('originals_unchanged') is True
            and worker['source_tested'] == worker['source_after'] == mapping
            and worker['compiler_artifact'].get('fresh') is False,
            'A42 release entry or worker evidence differs')
    normal_raw_custody(entry['worker_custody'])
    evidence['immutable_inputs']['release_entry'] = entry_receipt
    evidence['immutable_inputs']['release_worker'] = worker_receipt
    require(value['binary'].get('cached') is False
            and value['binary'].get('path') == str(PARENT_BINARY)
            and value['binary'].get('sha256') == PARENT_BINARY_SHA
            and value['binary'].get('bytes') == PARENT_BINARY_BYTES
            and value['binary'].get('compiler_source') == str(PARENT / 'src/main.rs')
            and value['test_binary'].get('cached') is False
            and value['test_binary'].get('path') == str(BASE / 'qualification-a42-fresh-cohort-r03/hepta-runtime-tests')
            and value['test_binary'].get('sha256') == PARENT_TEST_SHA
            and value['test_binary'].get('bytes') == PARENT_TEST_BYTES,
            'A42 copied artifact binding differs')
    _, binary_receipt = read_bound(core, value['binary'])
    evidence['immutable_inputs']['release_binary'] = binary_receipt
    evidence['test_executable_report_binding'] = value['test_binary']
    if state:
        require(evidence == state['proof'], 'parent report, log, custody or release copy changed')
    else:
        state['proof'] = evidence
    return raw, receipt


def policy(core, old):
    result = {
        'schema': PROTOCOL_SCHEMA, 'attempt': ATTEMPT, 'bindings_ready': True,
        'independent_attempt': True, 'maximum_attempts': 1, 'automatic_retry': False,
        'user_instruction': USER_INSTRUCTION,
        'declared_scope': 'One new full six-stage A48 qualification under current user continuation; root serializes it after all other X230 work.',
        'paths': {'source': str(DEST), 'qualification': str(OUT), 'entry': str(PREP),
                  'target': str(core.TARGET), 'bundle': str(BUNDLE), 'protocol': str(PROTOCOL)},
        'parent': {'source': str(PARENT), 'source_files': PARENT_FILES,
                   'source_map_compact_sha256': PARENT_MAP_SHA,
                   'qualification_path': str(PARENT_Q), 'qualification_sha256': PARENT_Q_SHA,
                   'qualification_bytes': PARENT_Q_BYTES, 'qualification_schema': COMPOSED_SCHEMA,
                   'composition_kind': COMPOSITION_KIND,
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
        'source_base_is_a42_not_a43': True,
        'frozen_parent_policy': 'The complete original A42 source map and stat identities, fixed composed report, original six logs, release custody reports and copied release binary are verified before and after. Only the isolated A48 tree may be formatted.',
        'parent_tests_scope': 'Original A42 test executable is identified by the SHA-pinned composed report, not rehashed by this wrapper. New A48 tests and release are separately rebuilt with strict fresh=false artifacts.',
        'source_amendment_policy': old['source_amendment_policy'],
        'test_and_release_compiler_artifact_fresh_must_be_false': True,
        'test_coverage_policy': 'The one full-test log must contain successful execution lines for every new and required-existing test named in the SHA-pinned overlay manifest; no focused rerun substitutes for the full suite.',
        'report_schema_policy': 'A48 entry and worker schemas retain inherited_schema and reused-driver descriptions; the unmodified qualifier retains runtime-candidate-qualification/v1.',
        'retained_parent_copy': str(PREP / 'a42-composed-qualification.original.json'),
        'benchmark_executions': 0, 'service_changes': False,
        'foreign_process_signal_or_priority_changes': False,
        'ssh_or_agent_access': False, 'git_add_commit_push_merge': False,
        'scope_limits': [
            'Each initial or stage gate is a complete point-in-time local observation; it is not a host lease.',
            'Only the original new worker session/group is covered by cleanup; escaped descendants and reboot are not established.',
            'The A42 composed parent remains a composition of its original five stages and a later release; it is not relabeled as a single uninterrupted attempt.',
            'A48 build/test qualification establishes no performance win, native multi-host result, power-loss result or production deployment.',
            'Original A44 helper diagnostic wording may remain in inherited errors; paths, source maps and new A48 report schemas identify this attempt.',
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
    # candidate and old scheduling-window entry are not used for A48 admission.
    old_raw, old_receipt = core.verify_protocol_binding()
    require(old_receipt['path'] == str(LEGACY_PROTOCOL) and len(old_raw) == LEGACY_PROTOCOL_BYTES
            and core.sha(old_raw) == LEGACY_PROTOCOL_SHA, 'original policy differs')
    old = json.loads(old_raw)
    policy_raw = core.canonical(policy(core, old))
    require(len(policy_raw) <= 65536, 'A48 protocol exceeds fixed bound')
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
                       'hepta-a48-page-fullscan-qualification-entry/v1',
                   'hepta-a44-owner-barrier-guarded-qualifier-worker/v1':
                       'hepta-a48-page-fullscan-guarded-qualifier-worker/v1'}
        if value.get('schema') in schemas:
            value['inherited_schema'] = value['schema']
            value['schema'] = schemas[value['schema']]
        value.update(attempt=ATTEMPT, original_driver=driver_receipt,
                     shared_functions=shared_receipt, original_policy=old_receipt,
                     old_scheduling_window_used=False, a43_source_used=False)
        value['execution_description'] = 'Unchanged six-stage qualifier and original worker custody with independent A48 page-fullscan source bindings.'
        if path == PREP / 'entry-report.json':
            value['scheduling_scope'] = 'One independent A48 attempt after root serialization; fresh initial and per-stage complete gates.'
            value['retained_parent_copy'] = str(PREP / 'a42-composed-qualification.original.json')
            value['parent_composition_proof'] = parent_state.get('proof')
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
        # A48 records the actual A42 composition with a precise new name.
        if path == PREP / 'r07-qualification.original.json':
            path = PREP / 'a42-composed-qualification.original.json'
        if path == WINDOW:
            observation = json.loads(raw)
            if 'root_a42_completion' in observation:
                observation['root_other_x230_work_completion'] = observation.pop('root_a42_completion')
                raw = core.canonical(observation)
        return original_create(path, raw)

    def verify_protocol():
        raw, receipt = core.original(PROTOCOL, core.PROTOCOL_SHA, 65536)
        require(raw == policy_raw, 'A48 independent protocol differs')
        return raw, receipt

    def verify_window():
        raw, receipt = core.original(WINDOW, cap=1024 * 1024)
        value = json.loads(raw)
        require(value.get('schema') == WINDOW_SCHEMA and value.get('attempt') == ATTEMPT
                and value.get('status') == 'clear_observed' and value.get('passed') is True
                and value.get('snapshot_calls') == 1 and value.get('errors') == []
                and value.get('automatic_retries') == 0 and value.get('old_window_used') is False
                and value.get('per_stage_gates_still_required') is True,
                'A48 single initial observation is not complete and clear')
        bound = value.get('gate', {})
        require(bound.get('path') == str(GATE), 'A48 initial gate path differs')
        gate_raw, gate_receipt = core.original(GATE, bound.get('sha256'), 1024 * 1024)
        require(gate_receipt == bound, 'A48 initial gate binding changed')
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
                'A48 retained initial resource gate is incomplete or refused')
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
        require(required and len(required) == len(set(required))
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
