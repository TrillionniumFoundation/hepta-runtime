#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One new A46 qualification of the unchanged A43 owner-barrier candidate.

Run only after the orchestrator has finished its A42 work. This is a new
explicitly requested attempt, with new source/output/entry paths and one fresh
initial host observation. It neither re-enables the A44 scheduling tranche nor
rewrites a prior refusal. Every Cargo stage retains its own immediate complete
host/resource gate and the original deadlines, argv, and worker custody code.

The pinned A44 module is reused as a library. Its old scheduling-window entry
is not called: two narrowly scoped binding callbacks select this new protocol
and this attempt's retained initial observation. Source preparation, the
qualifier, GuardedSubprocess, and pidfd/waitid/raw-waitpid custody are unchanged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import types


BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
LEGACY = BASE / 'tools/prepare_qualify_a44_owner_barrier_r01.py'
LEGACY_SHA = '84e5fc48a688f83987425ff357428230083948703d419db4be1227d6b1ed8113'
LEGACY_BYTES = 49453
LEGACY_PROTOCOL = BASE / 'tools/a44-owner-barrier-qualification-r01.protocol.json'
LEGACY_PROTOCOL_SHA = '45185065cf0540296ea722bdfd4f000940338e466a6c936dfd34ca7cdbc5d50b'
LEGACY_PROTOCOL_BYTES = 8615
ATTEMPT = 'a46-owner-barrier-r01'
DEST = BASE / 'source-a46-owner-barrier-r01'
OUT = BASE / 'qualification-a46-owner-barrier-r01'
PREP = BASE / 'a46-owner-barrier-entry-r01'
INPUTS = BASE / 'a46-owner-barrier-inputs-r01'
PROTOCOL = INPUTS / 'protocol.json'
WINDOW = INPUTS / 'initial-observation.json'
GATE = INPUTS / 'initial-host-gate.json'
PROTOCOL_SCHEMA = 'hepta-a46-owner-barrier-qualification-protocol/v1'
WINDOW_SCHEMA = 'hepta-a46-owner-barrier-start-observation/v1'
USER_INSTRUCTION = '在x230上连续冲优化hepta-runtime的并发吞吐，资源占用，多机协同能力，执行优化持久化与故障恢复设计，直到不能继续优化为止，然后推github'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def file_identity(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def pinned_driver():
    """Read the library from one bounded no-follow descriptor before executing it."""
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fd = None
    try:
        for part in LEGACY.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(LEGACY.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == LEGACY_BYTES, 'original driver kind or size differs')
        pieces, count = [], 0
        while count <= LEGACY_BYTES:
            piece = os.read(fd, LEGACY_BYTES + 1 - count)
            if not piece:
                break
            pieces.append(piece)
            count += len(piece)
        raw = b''.join(pieces)
        require(count == LEGACY_BYTES and hashlib.sha256(raw).hexdigest() == LEGACY_SHA,
                'original driver SHA differs')
        require(file_identity(before) == file_identity(os.fstat(fd))
                == file_identity(os.stat(LEGACY.name, dir_fd=parent, follow_symlinks=False)),
                'original driver changed while loading')
        receipt = {'path': str(LEGACY), 'bytes': count, 'sha256': LEGACY_SHA,
                   'identity': file_identity(before)}
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
    core = types.ModuleType('a46_reused_original_owner_qualification')
    core.__file__ = str(LEGACY)
    exec(compile(raw, str(LEGACY), 'exec'), core.__dict__)
    return core, receipt


def policy(core, old):
    # Retain the actual old policy's source/helper/resource/budget bindings.
    # Historical window receipts and claims about past execution counts are not
    # copied into this new attempt's scheduling evidence.
    preserved = ('automatic_retry', 'benchmark_executions', 'bindings_ready', 'budgets',
                 'build_jobs', 'candidate', 'custody', 'frozen_parent_policy', 'helpers',
                 'incremental', 'maximum_attempts', 'parent', 'resource_gate', 'stages',
                 'scope_limits', 'source_amendment_policy')
    result = {name: old[name] for name in preserved}
    result.update({
        'schema': PROTOCOL_SCHEMA,
        'attempt': ATTEMPT,
        'independent_attempt': True,
        'declared_scope': 'One new attempt under the current explicit user continuation, after the root finishes A42 work; prior A44 no-clear outcomes are retained and supply no admission.',
        'user_instruction': USER_INSTRUCTION,
        'paths': {'source': str(DEST), 'qualification': str(OUT), 'entry': str(PREP),
                  'target': str(core.TARGET), 'bundle': str(core.BUNDLE),
                  'protocol': str(PROTOCOL)},
        'original_driver': {'path': str(LEGACY), 'bytes': LEGACY_BYTES, 'sha256': LEGACY_SHA},
        'original_policy': {'path': str(LEGACY_PROTOCOL), 'bytes': LEGACY_PROTOCOL_BYTES,
                            'sha256': LEGACY_PROTOCOL_SHA},
        'initial_observation': {'path': str(WINDOW), 'gate_path': str(GATE),
                                'schema': WINDOW_SCHEMA, 'snapshot_calls': 1,
                                'requires_clear': True, 'wait_or_retry_when_busy': False,
                                'does_not_replace_per_stage_gates': True},
        'root_must_finish_a42_work_before_launch': True,
        'old_r02_reenabled': False,
        'old_a44_window_verifier_invoked': False,
        'reuse_a42_admission_quota': False,
        'previous_window_not_reused_for_admission': True,
        'test_and_release_compiler_artifact_fresh_must_be_false': True,
        'report_schema_policy': 'New A46 entry/worker schemas record inherited A44 schema; the original qualifier report stays unmodified.',
        'service_changes': False,
        'foreign_process_signal_or_priority_changes': False,
        'ssh_or_agent_access': False,
        'git_add_commit_push_merge': False,
        'github_push_requested_by_user': True,
    })
    return result


def configure():
    core, driver_receipt = pinned_driver()
    # Verify every inherited source/helper/stage/resource binding through the
    # original validator before rebinding this new attempt's scheduling paths.
    old_raw, old_receipt = core.verify_protocol_binding()
    require(old_receipt['path'] == str(LEGACY_PROTOCOL)
            and len(old_raw) == LEGACY_PROTOCOL_BYTES
            and core.sha(old_raw) == LEGACY_PROTOCOL_SHA,
            'original protocol binding differs')
    old = json.loads(old_raw)
    expected_policy = policy(core, old)
    policy_raw = core.canonical(expected_policy)
    core.DEST, core.OUT, core.PREP = DEST, OUT, PREP
    core.PROTOCOL = PROTOCOL
    core.PROTOCOL_SHA, core.PROTOCOL_BYTES = core.sha(policy_raw), len(policy_raw)
    # The original guardian copies and verifies its entry before GO. Point it at
    # this wrapper, whose worker re-verifies the immutable library above.
    core.__file__ = str(Path(__file__).absolute())
    prior_checkpoint = core.checkpoint

    def checkpoint(path, value):
        schemas = {
            'hepta-a44-owner-barrier-qualification-entry/v1':
                'hepta-a46-owner-barrier-qualification-entry/v1',
            'hepta-a44-owner-barrier-guarded-qualifier-worker/v1':
                'hepta-a46-owner-barrier-guarded-qualifier-worker/v1',
        }
        if value.get('schema') in schemas:
            value['inherited_schema'] = value['schema']
            value['schema'] = schemas[value['schema']]
        value['attempt'] = ATTEMPT
        value['original_driver'] = driver_receipt
        value['original_policy'] = old_receipt
        value['old_a44_scheduling_window_used'] = False
        return prior_checkpoint(path, value)

    def verify_protocol():
        raw, receipt = core.original(PROTOCOL, core.PROTOCOL_SHA, 65536)
        require(raw == policy_raw, 'new A46 protocol differs')
        return raw, receipt

    def verify_window():
        raw, receipt = core.original(WINDOW, cap=1024 * 1024)
        value = json.loads(raw)
        require(value.get('schema') == WINDOW_SCHEMA and value.get('attempt') == ATTEMPT
                and value.get('status') == 'clear_observed' and value.get('passed') is True
                and value.get('snapshot_calls') == 1 and value.get('errors') == []
                and value.get('automatic_retries') == 0
                and value.get('per_stage_gates_still_required') is True
                and value.get('old_window_used') is False,
                'new A46 initial observation is not clear')
        bound = value.get('gate', {})
        require(bound.get('path') == str(GATE), 'new initial gate path differs')
        gate_raw, gate_receipt = core.original(GATE, bound.get('sha256'), 1024 * 1024)
        require(gate_receipt == bound, 'new initial gate binding changed')
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
                'retained initial resource gate is incomplete or refused')
        return raw, receipt

    core.checkpoint = checkpoint
    core.verify_protocol_binding = verify_protocol
    core.verify_scheduling_window = verify_window
    return core, policy_raw


def observe_once(core):
    nraw, nreceipt = core.original(core.NATIVE, core.NATIVE_SHA)
    require(len(nraw) == 51497, 'original host observer length differs')
    native = core.module('a46_original_r07_initial_host_load', core.NATIVE, nraw)
    errors, matching, snapshot = [], [], None
    mem = disk = None
    try:
        snapshot = native.host_load()
        matching = [row for row in snapshot['processes']
                    if row['comm'] in core.BUSY_NAMES and row['state'] not in ('Z', 'X', 'x')]
        memory = re.findall(r'^MemAvailable:\s+(\d+)\s+kB\s*$',
                            snapshot['meminfo'], flags=re.MULTILINE)
        require(len(memory) == 1, 'MemAvailable unavailable or ambiguous')
        mem = int(memory[0])
        filesystem = os.statvfs(BASE)
        disk = filesystem.f_bavail * filesystem.f_frsize
    except (OSError, ValueError, TypeError, KeyError, IndexError, RuntimeError) as error:
        errors.append(type(error).__name__ + ': ' + str(error))
    clear = bool(snapshot is not None and snapshot.get('required_fields_present') is True
                 and snapshot.get('errors') == [] and not matching and not errors
                 and mem is not None and disk is not None
                 and mem >= core.MEM_MIN_KIB and disk >= core.DISK_MIN_BYTES)
    gate = {'clear': clear, 'matching_live_processes': matching, 'snapshot': snapshot,
            'mem_available_kib': mem, 'disk_available_bytes': disk,
            'resource_errors': errors, 'observer': nreceipt,
            'resource_thresholds': {'mem_available_kib_min': core.MEM_MIN_KIB,
                                    'disk_available_bytes_min': core.DISK_MIN_BYTES},
            'scope': 'one point-in-time local observation, not a lease or a replacement for fresh per-stage gates'}
    receipt = core.create(GATE, core.canonical(gate))
    result = {'schema': WINDOW_SCHEMA, 'attempt': ATTEMPT, 'observed_utc': core.utc(),
              'status': 'clear_observed' if clear else 'refused', 'passed': clear,
              'snapshot_calls': 1, 'gate': receipt, 'errors': errors,
              'automatic_retries': 0, 'old_window_used': False,
              'per_stage_gates_still_required': True,
              'root_a42_completion': 'orchestrator ordering requirement; this local snapshot does not establish it'}
    core.create(WINDOW, core.canonical(result))
    return clear


def verify_fresh_artifacts(core):
    qraw, qreceipt = core.original(OUT / 'report.json')
    qualification = json.loads(qraw)
    require(qualification.get('qualified') is True
            and qualification.get('current_stage') == 'complete'
            and qualification.get('source') == str(DEST), 'original qualifier did not complete')
    evidence = {'qualification_report': qreceipt, 'compiler_artifacts': {}}
    for stage, is_test, key, filename in (
            ('test', True, 'test_binary', 'hepta-runtime-tests'),
            ('release', False, 'binary', 'hepta-runtime')):
        raw, receipt = core.original(OUT / (stage + '.log'))
        events = []
        for line in raw.splitlines():
            try:
                event = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue
            if (isinstance(event, dict) and event.get('reason') == 'compiler-artifact'
                    and event.get('target', {}).get('name') == 'hepta-runtime'
                    and event.get('profile', {}).get('test') is is_test):
                events.append(event)
        require(len(events) == 1, stage + ' candidate compiler-artifact count differs')
        event = events[0]
        require(event.get('fresh') is False
                and event.get('manifest_path') == str(DEST / 'Cargo.toml'),
                stage + ' artifact is not strictly fresh=false/source-bound')
        copied = qualification.get(key, {})
        require(copied.get('cached') is False and copied.get('path') == str(OUT / filename)
                and copied.get('compiler_source') == event.get('target', {}).get('src_path')
                and Path(copied['compiler_source']).is_relative_to(DEST)
                and re.fullmatch(r'[0-9a-f]{64}', str(copied.get('sha256'))),
                stage + ' copied artifact qualification differs')
        require(Path(event['executable']).is_relative_to(core.TARGET),
                stage + ' compiler executable is outside the fixed target')
        evidence['compiler_artifacts'][stage] = {
            'original_event': event, 'log': receipt, 'copied_artifact': copied,
            'fresh_strictly_false': True,
        }
    return evidence


def worker(core, args):
    code = core.worker(args)
    if code:
        return code
    raw, _ = core.original(PREP / 'worker-report.json')
    report = json.loads(raw)
    try:
        report['strict_fresh_artifact_evidence'] = verify_fresh_artifacts(core)
        report['strict_fresh_artifacts_verified'] = True
        return 0
    except BaseException as error:
        report['passed'] = False
        report['strict_fresh_artifacts_verified'] = False
        report['error'] = 'additional artifact binding: ' + type(error).__name__ + ': ' + str(error)
        return 1
    finally:
        report['finished_utc'] = core.utc()
        core.checkpoint(PREP / 'worker-report.json', report)


def main(core, policy_raw, args):
    require(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(os, 'WNOWAIT'),
            'native Linux original-child custody is required')
    os.umask(0o077)
    for path in (DEST, OUT, PREP, INPUTS):
        core.fresh(path)
    core.mkdir_new(INPUTS)
    core.create(PROTOCOL, policy_raw)
    if not observe_once(core):
        print(json.dumps({'attempt': ATTEMPT, 'status': 'refused_before_preparation',
                          'initial_observation': str(WINDOW), 'worker_executions': 0,
                          'cargo_executions': 0, 'automatic_retry': False}), flush=True)
        return 2
    # Reuse the original implementation only after replacing the two scheduling
    # binding callbacks. Its actual source validation and custody remain intact.
    return core.main(args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--permit-fd', type=int)
    parser.add_argument('--expected-entry-sha')
    arguments = parser.parse_args()
    core, policy_raw = configure()
    signal.signal(signal.SIGTERM, core.termination_handler)
    signal.signal(signal.SIGINT, core.termination_handler)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    if arguments.worker:
        raise SystemExit(worker(core, arguments))
    require(arguments.permit_fd is None and arguments.expected_entry_sha is None,
            'worker-only arguments refused')
    raise SystemExit(main(core, policy_raw, arguments))
