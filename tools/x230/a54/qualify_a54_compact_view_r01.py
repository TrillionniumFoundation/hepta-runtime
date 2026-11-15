#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Frozen A54 compact-view qualification; one new independent six-stage attempt.

The six original Cargo stages, two-worker bounds and guarded original-child
custody are reused. Every stage runs with umask 022 to expose implicit fixture
permission assumptions. This is a new attempt; all prior evidence stays immutable.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import types

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
CORE = BASE / 'tools/prepare_qualify_a44_owner_barrier_r01.py'
CORE_SHA = '84e5fc48a688f83987425ff357428230083948703d419db4be1227d6b1ed8113'
PARENT = BASE / 'source-a53-bounded-direct-ssh-r02'
PARENT_REPORT = BASE / 'qualification-a53-bounded-direct-ssh-r02/report.json'
DEST = BASE / 'source-a54-compact-view-r01'
OUT = BASE / 'qualification-a54-compact-view-r01'
PREP = BASE / 'a54-compact-view-entry-r01'
BUNDLE = BASE / 'tools/a54-compact-view-source-r01.json'
PARENT_REPORT_SHA = 'ab3a37ceb97667694c201d9b62556398e04e805010c8492af6a8f6f51486a72b'
PARENT_TREE_SHA = '84d5caea62cceaf41b59a354185c85439a6fa0e8'
PARENT_GIT_MAP_SHA = '064b5eb29fc33c45e98f8ec0feed7855dceb5ae75fc81ef91f47c48ff4f10ac9'
PARENT_PUBLICATION_SHA = '90323570f65036e3f354bfd9fc48735a44e01ef5f47bc13b8f07b3433f44a78e'
FINAL_BINDINGS_READY = True
CANDIDATE_MAP_SHA = '5b128908b61e4a3f5f8c1ed951ec184eddf2a9b79361e6a16d5a80b0ded98d88'
CHANGED = frozenset(('src/mcp/runtime/request_archive_codec.rs', 'src/mcp/runtime/request_archive_content.rs', 'src/mcp/runtime/request_archive_content_tests.rs'))


def require(value, message):
    if not value:
        raise RuntimeError(message)



def require_bindings():
    require(FINAL_BINDINGS_READY is True and type(CANDIDATE_MAP_SHA) is str
            and len(CANDIDATE_MAP_SHA) == 64
            and all(value in '0123456789abcdef' for value in CANDIDATE_MAP_SHA),
            'A54 candidate source and tests are not frozen; execution is disabled')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_core():
    raw = CORE.read_bytes()
    require(digest(raw) == CORE_SHA and len(raw) == 49453, 'original guarded core differs')
    core = types.ModuleType('a54_guarded_qualification_core')
    core.__file__ = str(CORE)
    exec(compile(raw, str(CORE), 'exec'), core.__dict__)
    core.DEST, core.OUT, core.PREP = DEST, OUT, PREP
    return core


def bundle(core, expected):
    raw, receipt = core.original(BUNDLE, expected, 2 * 1024 * 1024)
    value = json.loads(raw)
    require(value['schema'] == 'hepta-a54-compact-view-source/v1', 'source schema differs')
    require(value['repository_base_commit'] == 'b20bcf02cfe72b3873c5c03180e4028ea673067f', 'parent commit differs')
    require(len(value['parent_source_map']) == 175 and len(value['candidate_source_map']) == 175,
            'source inventory differs')
    require(core.map_sha(value['parent_source_map']) ==
            '91962e89b203621686cfa0d77567b13bd246092a99345681674bbafd46388c35',
            'actual A53 source map differs')
    require(value['repository_base_tree'] == PARENT_TREE_SHA
            and value['parent_qualification_sha256'] == PARENT_REPORT_SHA, 'parent tree/report binding differs')
    require(set(value['files']) == CHANGED and core.map_sha(value['candidate_source_map']) == CANDIDATE_MAP_SHA,
            'three-file candidate binding differs')
    require(set(value['parent_git_source_blob_map']) == set(value['parent_source_map'])
            and core.map_sha(value['parent_git_source_blob_map']) == PARENT_GIT_MAP_SHA,
            'published parent compiler blob map differs')
    proof = value['parent_publication']
    require(proof['checker_result']['sha256'] == PARENT_PUBLICATION_SHA
            and proof['check']['passed'] is True and proof['check']['full_tree_checked'] is True
            and proof['check']['commit_sha'] == value['repository_base_commit']
            and proof['check']['tree_sha'] == PARENT_TREE_SHA
            and proof['check']['compiler_files'] == 175
            and proof['check']['git_blob_map_compact_sha256'] == PARENT_GIT_MAP_SHA,
            'captured parent publication proof differs')
    expected_map = dict(value['parent_source_map'])
    contents = {}
    for name, item in value['files'].items():
        path = Path(name)
        require(str(path) == name and not path.is_absolute() and '..' not in path.parts
                and name.startswith('src/') and name.endswith('.rs'), 'unsafe overlay path')
        data = base64.b64decode(item['base64'], validate=True)
        require(len(data) == item['bytes'] and digest(data) == item['sha256'], 'overlay identity differs')
        require(item['parent_sha256'] == expected_map.get(name), 'overlay parent differs')
        expected_map[name] = digest(data)
        contents[name] = data
    require(expected_map == value['candidate_source_map'], 'incomplete source overlay')
    return value, contents, raw, receipt


def environment(core):
    env, receipt = core.clean_environment()
    for name in ['HEPTA_METADATA_TRACE']:
        env.pop(name, None)
    receipt['stage_umask'] = '022'
    receipt['metadata_trace_enabled'] = False
    return env, receipt


def worker(args, core):
    require(args.permit_fd is not None, 'original parent permit missing')
    try:
        require(os.read(args.permit_fd, 2) == b'G', 'original parent did not admit worker')
    finally:
        os.close(args.permit_fd)
    core.original(Path(__file__).absolute(), args.entry_sha)
    require(os.getpgrp() == os.getpid() and os.getsid(0) == os.getpid(), 'worker group identity differs')
    value, _, _, _ = bundle(core, args.bundle_sha)
    mapping, _, _ = core.source(DEST)
    require(mapping == value['candidate_source_map'], 'candidate changed before qualification')
    qraw, qreceipt = core.original(core.QUALIFIER, core.QUALIFIER_SHA)
    nraw, nreceipt = core.original(core.NATIVE, core.NATIVE_SHA)
    native = core.module('a54_original_native_host_gate', core.NATIVE, nraw)
    qualifier = core.module('a54_original_candidate_qualifier', core.QUALIFIER, qraw)
    env, env_receipt = environment(core)
    require(env == dict(os.environ), 'worker environment changed')
    report = {'schema': 'hepta-a54-compact-view-qualification-worker/v1',
              'started_utc': core.utc(), 'passed': False, 'stages': [],
              'qualifier': qreceipt, 'host_load_driver': nreceipt,
              'environment': env_receipt, 'automatic_retry': False,
              'service_changes': False, 'stage_umask': '022'}
    core.checkpoint(PREP / 'worker-report.json', report)

    class UmaskGuardedSubprocess(core.GuardedSubprocess):
        def run(self, argv, **kwargs):
            prior_mask = os.umask(0o022)
            try:
                return super().run(argv, **kwargs)
            finally:
                os.umask(prior_mask)

    facade = UmaskGuardedSubprocess(native, report, env)
    qualifier.subprocess = facade
    original_argv = sys.argv
    sys.argv = [str(core.QUALIFIER), '--source', str(DEST), '--output', str(OUT),
                '--target-dir', str(core.TARGET), '--cargo', core.CARGO,
                '--toolchain', '1.95.0', '--jobs', '2']
    try:
        qualifier.main()
        require(facade.next_stage == 6, 'six-stage coverage incomplete')
        raw, receipt = core.original(OUT / 'report.json')
        qualified = json.loads(raw)
        require(qualified['qualified'] is True and qualified['current_stage'] == 'complete'
                and qualified['source_input'] == value['candidate_source_map']
                and qualified['source_tested'] == qualified['source_after'], 'qualification failed')
        require(set(qualified['source_after']) == set(value['candidate_source_map']), 'formatted inventory differs')
        require(all(qualified['source_after'][name] == sha
                    for name, sha in value['candidate_source_map'].items() if name not in value['files']),
                'formatter changed unrelated parent source')
        report.update(passed=True, qualifier_report=receipt)
        return 0
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        return 1
    finally:
        sys.argv = original_argv
        report['finished_utc'] = core.utc()
        core.checkpoint(PREP / 'worker-report.json', report)


def main(args, core):
    value, changes, raw, receipt = bundle(core, args.bundle_sha)
    parent_raw, parent_receipt = core.original(PARENT_REPORT, args.parent_qualification_sha)
    parent = json.loads(parent_raw)
    require(parent['qualified'] is True and parent['current_stage'] == 'complete'
            and parent['source'] == str(PARENT)
            and parent['source_tested'] == parent['source_after'] == value['parent_source_map'],
            'parent qualification/source identity differs')
    parent_map, parent_files, bodies = core.source(PARENT, keep_bytes=True)
    require(parent_map == value['parent_source_map'], 'parent source changed')
    parent_git = {name: hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                  for name, data in bodies.items()}
    require(parent_git == value['parent_git_source_blob_map'], 'retained parent bytes differ from published compiler blobs')
    for path in (DEST, OUT, PREP):
        core.fresh(path)
    core.mkdir_new(PREP)
    core.create(PREP / 'source-bundle.original.json', raw)
    self_raw, self_receipt = core.original(Path(__file__).absolute(), args.entry_sha)
    core.create(PREP / 'entry.original.py', self_raw)
    core.mkdir_new(DEST)
    for name in sorted(value['candidate_source_map']):
        target = DEST / name
        relative_parent = Path(name).parent
        current = DEST
        for part in relative_parent.parts:
            current = current / part
            if not current.exists():
                core.mkdir_new(current)
        core.create(target, changes.get(name, bodies.get(name)))
    actual, _, _ = core.source(DEST)
    require(actual == value['candidate_source_map'], 'prepared source differs')
    env, env_receipt = environment(core)
    report = {'schema': 'hepta-a54-compact-view-qualification-entry/v1',
              'started_utc': core.utc(), 'qualified': False, 'errors': [],
              'source_bundle': receipt, 'entry': self_receipt, 'parent_qualification': parent_receipt,
              'parent_source': str(PARENT), 'parent_source_map': parent_map,
              'repository_base_commit': value['repository_base_commit'], 'repository_base_tree': PARENT_TREE_SHA,
              'parent_git_source_blob_map': parent_git, 'parent_publication': value['parent_publication'],
              'retained_parent_git_blobs_verified': True, 'github_calls': 0,
              'candidate_source': str(DEST), 'candidate_source_map': actual,
              'environment': env_receipt, 'automatic_retry': False,
              'service_changes': False, 'worker_custody': {'executed': False, 'execution_count': 0,
                  'original_child_reaped': False, 'signals': [], 'custody_unknown': False}}
    core.checkpoint(PREP / 'entry-report.json', report)
    argv = [sys.executable, str(Path(__file__).absolute()), '--worker',
            '--bundle-sha', args.bundle_sha, '--entry-sha', args.entry_sha,
            '--parent-qualification-sha', args.parent_qualification_sha]
    try:
        code = core.own_worker(argv, env, report)
        worker_report = json.loads((PREP / 'worker-report.json').read_bytes())
        require(code == 0 and worker_report['passed'] is True, 'guarded worker did not qualify')
        require(report['worker_custody']['original_child_reaped']
                and report['worker_custody']['group_quiet_before_reap']
                and not report['worker_custody']['signals'], 'original worker custody incomplete')
        after, after_files, _ = core.source(PARENT)
        require(after == parent_map and after_files == parent_files, 'parent source changed during qualification')
        for path, expected in ((PARENT_REPORT, parent_receipt), (BUNDLE, receipt),
                               (Path(__file__).absolute(), self_receipt)):
            _, current = core.original(path, expected['sha256'])
            require(current == expected, 'original qualification input changed: ' + str(path))
        report['parent_and_input_fence_unchanged'] = True
        report['qualified'] = True
        return 0
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
        return 1
    finally:
        report['finished_utc'] = core.utc()
        core.checkpoint(PREP / 'entry-report.json', report)
        print(json.dumps({'qualified': report['qualified'], 'report': str(PREP / 'entry-report.json'),
                          'errors': report['errors']}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--permit-fd', type=int)
    parser.add_argument('--parent-qualification-sha', required=True)
    parser.add_argument('--bundle-sha', required=True)
    parser.add_argument('--entry-sha', required=True)
    args = parser.parse_args()
    require_bindings()
    require(args.parent_qualification_sha == PARENT_REPORT_SHA, 'unbound parent qualification SHA')
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    def interrupted(signum, _frame):
        raise KeyboardInterrupt('qualification interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    core = load_core()
    sys.exit(worker(args, core) if args.worker else main(args, core))
