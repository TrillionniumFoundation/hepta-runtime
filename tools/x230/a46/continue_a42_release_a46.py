#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""A46: one newly authorized release-only attempt; all earlier failures remain intact.

Reuse the frozen r02 release implementation and original raw-child custody.
The new point observation belongs only to this invocation. The worker still
requires its own fresh complete host gate immediately before the sole Cargo
execution. No historical observation grants admission and no failed attempt
is retried. The five successful r03 stages are verified, never rerun.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import types

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
ENTRY = BASE / 'tools/continue_a42_release_a46.py'
HELPER = BASE / 'tools/complete_a42_release_r02.py'
HELPER_SHA = 'ba8c0fbc771f9222fdce99b416c9a3ee2d26a4f5cdd19a8b508a0fee3f7463c6'
HELPER_BYTES = 41058
ADMISSION = BASE / 'a46-release-admission-r01'
PREP = BASE / 'a46-release-completion-entry-r01'
OUT = BASE / 'qualification-a46-a42-release-completion-r01'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def load_release():
    """Load only the exact retained helper, without invoking its old entrypoint."""
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fd = None
    try:
        for part in HELPER.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(HELPER.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == HELPER_BYTES, 'frozen release helper type/length differs')
        raw = bytearray()
        while len(raw) <= HELPER_BYTES:
            block = os.read(fd, min(65536, HELPER_BYTES + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        need(len(raw) == HELPER_BYTES and hashlib.sha256(raw).hexdigest() == HELPER_SHA
             and identity(before) == identity(os.fstat(fd))
             == identity(os.stat(HELPER.name, dir_fd=directory, follow_symlinks=False)),
             'frozen release helper changed')
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)
    module = types.ModuleType('a46_frozen_release_implementation')
    module.__file__ = str(HELPER)
    exec(compile(bytes(raw), str(HELPER), 'exec'), module.__dict__)
    return module


def protocol(release):
    return {'schema': 'hepta-a46-single-release-continuation/v1',
            'authorization': 'Current user continuation: one new A46 attempt; prior tranches unchanged.',
            'source': str(release.SOURCE), 'source_map_sha256': release.SOURCE_MAP_SHA,
            'source_files': 168, 'entry': str(ENTRY), 'output': str(OUT), 'worker_output': str(PREP),
            'maximum_release_executions': 1, 'automatic_retry': False,
            'previous_stage_reexecutions': 0, 'historical_windows_used_for_admission': False,
            'release_seconds': 1800, 'worker_seconds': 1900, 'outer_seconds': 2100,
            'cleanup_term_kill_seconds': [30, 30], 'release_argv': release.RELEASE_ARGV,
            'mem_available_kib_min': 2097152, 'disk_available_bytes_min': 2147483648,
            'busy_names': list(release.BUSY_NAMES), 'fresh_worker_host_gate_required': True,
            'source_bound_fresh_false_artifact_required': True,
            'prior_failures_preserved': True, 'old_source_after_not_invented': True}


def configure(release):
    # These are this new invocation's destinations, not edits to any old script.
    release.ENTRY, release.PREP, release.OUT = ENTRY, PREP, OUT
    release.__file__ = __file__
    need((release.RELEASE_SECONDS, release.WORKER_SECONDS, release.OUTER_SECONDS) == (1800, 1900, 2100)
         and (release.MEM_MIN_KIB, release.DISK_MIN_BYTES) == (2097152, 2147483648),
         'frozen release budgets/floors differ')
    fixed = dict(release.FIXED)
    fixed.update({
        'release_implementation': (HELPER, HELPER_BYTES, HELPER_SHA),
        'r02_refused_worker': (BASE / 'a42-release-completion-entry-r02/worker-report.json', 221571,
            '8570cf262e8d5a30aa4fdadd88dd842fbb1b6b737c15528ae4d1f8942ddf256d'),
        'r02_refused_entry': (BASE / 'a42-release-completion-entry-r02/entry-report.json', 186023,
            'ac3b0c077102e2d71f0ec7ea4452425a41101d635e2737ec9b3c1390be5b63d7'),
        'a45_no_clear': (BASE / 'a45-release-window-r01/report.json', 82166,
            'b59b9897be4b15fec9e0899706aca9d82fcdeeb5cad1b5c74cc4df17dc231eaa'),
    })

    def verify_inputs(core, observer, include_admission=True):
        originals, receipts = {}, {}
        for key, (path, size, digest) in fixed.items():
            raw, receipt = core.original(path, digest)
            need(len(raw) == size, 'frozen input length differs: ' + key)
            originals[key], receipts[key] = raw, receipt
        q, worker, guardian = (json.loads(originals[key]) for key in
                              ('qualification_r03', 'worker_r03', 'guardian_r03'))
        need(core.map_sha(q['source_input']) == release.PREFORMAT_MAP_SHA
             and len(q['source_input']) == 168, 'original preformat source differs')
        need(guardian['qualification_report'] == receipts['qualification_r03']
             and guardian['guarded_worker_report'] == receipts['worker_r03']
             and guardian['entry'] == receipts['r03_entry_script'], 'original guardian bindings differ')
        for index, (name, tail) in enumerate(core.STAGES):
            row = worker['stages'][index]
            need(row['name'] == name and row['argv'] == [core.CARGO, '+1.95.0'] + tail
                 and row['timeout_seconds'] == 1800, 'original guarded command/budget differs')
            if index < 5:
                need(q['stages'][index]['command'] == row['argv'], 'original command differs')
            expected = row['host_gate']
            path = release.OLD_PREP / ('stage-%d-%s.host-gate.json' % (index, name))
            need(expected['path'] == str(path), 'original stage gate path differs')
            raw, receipt = core.original(path, expected['sha256'])
            need(receipt == expected and json.loads(raw).get('clear') is (index < 5),
                 'original stage gate changed')
            originals['r03_gate_' + name], receipts['r03_gate_' + name] = raw, receipt
        # This exact frozen function checks all five logs, raw original worker
        # exit, test compiler fresh=false, 168-file map AND source mtime/ctime.
        proof = observer.tested_source_proof(originals)
        need(proof['source_map'] == q['source_tested'] and proof['source_files'] == 168
             and proof['source_map_sha256_compact'] == release.SOURCE_MAP_SHA,
             'present source is not original tested source')
        for name, expected in {**proof['logs'], 'release': proof['original_empty_release_log']}.items():
            raw, receipt = core.original(Path(expected['path']), expected['sha256'])
            need(receipt == expected and (name != 'release' or raw == b''), 'old log changed')
            originals['r03_log_' + name], receipts['r03_log_' + name] = raw, receipt
        receipts['old_test_binary'] = release.receipt_only(proof['original_copied_test_binary'])
        for name in ('qualifier-worker.stdout', 'qualifier-worker.stderr'):
            raw, receipt = core.original(release.OLD_PREP / name)
            originals['r03_' + name], receipts['r03_' + name] = raw, receipt
        failed_worker = json.loads(originals['r02_refused_worker'])
        need(failed_worker['passed'] is False and len(failed_worker['stages']) == 1
             and failed_worker['stages'][0]['executed'] is False
             and failed_worker['stages'][0]['execution_count'] == 0
             and json.loads(originals['r02_refused_entry'])['passed'] is False,
             'prior r02 refusal differs')
        no_clear = json.loads(originals['a45_no_clear'])
        need(no_clear['status'] == 'no_clear_observed' and no_clear['clear_observed'] is False
             and no_clear['snapshot_calls'] == 60, 'prior A45 result differs')
        if include_admission:
            for key, filename in (('a46_protocol', 'protocol.json'), ('a46_admission', 'snapshot.json')):
                raw, receipt = core.original(ADMISSION / filename)
                originals[key], receipts[key] = raw, receipt
            need(json.loads(originals['a46_protocol']) == protocol(release), 'A46 protocol differs')
            point = json.loads(originals['a46_admission'])
            need(point['schema'] == 'hepta-a46-point-admission/v1' and point['clear'] is True
                 and point['historical_window_reused'] is False,
                 'this invocation has no clear A46 point observation')
        raw, receipt = core.original(ENTRY)
        originals['completion_entry'], receipts['completion_entry'] = raw, receipt
        return {'q': q, 'worker': worker, 'guardian': guardian, 'proof': proof,
                'originals': originals, 'receipts': receipts}

    original_composed = release.composed

    def composed(core, inputs, worker_result, worker_receipt, entry_receipt):
        # Reuse the complete original stage/provenance construction. Aliases
        # here are only its input interface; the resulting report names A46.
        receipts = {**inputs['receipts'], 'release_completion_protocol': inputs['receipts']['a46_protocol'],
                    'window_report': inputs['receipts']['a46_admission'],
                    'window_snapshot': inputs['receipts']['a46_admission']}
        value = original_composed(core, {**inputs, 'receipts': receipts}, worker_result,
                                  worker_receipt, entry_receipt)
        completion = value['release_completion']
        completion.pop('window_report')
        completion.pop('window_snapshot')
        completion['a46_point_admission'] = inputs['receipts']['a46_admission']
        completion['historical_windows_used_for_admission'] = False
        value['composition_kind'] = 'a42-r03-five-stages-plus-a46-release/v1'
        value['stages'][-1]['origin'] = 'a46_new_user_authorized_release_only'
        value['prior_r02_refusal_unchanged'] = True
        value['prior_a45_no_clear_unchanged'] = True
        # Preserve the old protocol receipt too, even though A46 supplies the
        # prospective protocol in the reused composition interface above.
        value['provenance'] = release.deduplicated(value['provenance'] +
                                                  [inputs['receipts']['release_completion_protocol']])
        return value

    release.verify_inputs, release.composed = verify_inputs, composed
    return verify_inputs


def main():
    need(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(os, 'WNOWAIT'),
         'native Linux original-child custody required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--permit-fd', type=int)
    parser.add_argument('--expected-entry-sha')
    args = parser.parse_args()
    release = load_release()
    verify = configure(release)
    core, observer = release.support()
    signal.signal(signal.SIGTERM, core.termination_handler)
    signal.signal(signal.SIGINT, core.termination_handler)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    if args.worker:
        return release.worker(args, core, observer)
    need(args.permit_fd is None and args.expected_entry_sha is None, 'worker-only arguments refused')
    need(Path(__file__).absolute() == ENTRY, 'run the uploaded A46 entry itself')
    os.umask(0o077)
    for path in (ADMISSION, PREP, OUT):
        core.fresh(path)
    inputs = verify(core, observer, include_admission=False)
    native = release.loaded('a46_frozen_host_load', release.NATIVE, inputs['originals']['host_load_driver'])
    core.mkdir_new(ADMISSION)
    core.create(ADMISSION / 'protocol.json', core.canonical(protocol(release)))
    point = release.host_gate(native)
    point.update(schema='hepta-a46-point-admission/v1', observed_utc=release.utc(),
                 historical_window_reused=False, release_executions=0)
    receipt = core.create(ADMISSION / 'snapshot.json', core.canonical(point))
    if not point['clear']:
        core.create(ADMISSION / 'refusal.json', core.canonical({
            'schema': 'hepta-a46-admission-refusal/v1', 'passed': False,
            'snapshot': receipt, 'release_executions': 0, 'worker_invocations': 0,
            'automatic_retry': False, 'prior_attempts_unchanged': True}))
        print(json.dumps({'admission': str(ADMISSION), 'passed': False, 'release_executions': 0}), flush=True)
        return 2
    return release.main(core, observer)


if __name__ == '__main__':
    raise SystemExit(main())
