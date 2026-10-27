#!/usr/bin/python3
"""Validate actual A55 qualification originals against the frozen eight-file source.

No Rust, runtime, child or remote execution. All three actual report paths and
independent SHA256 pins are required for a qualified result. Expected 1337 is
never substituted for an observed test-log count by this validator.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re

WORKSPACE = Path(__file__).resolve().parents[2]
HEX = re.compile(r'[0-9a-f]{64}\Z')
BASE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01'
SOURCE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/source-a55-cstr-scan-r01'
QUALIFICATION = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/qualification-a55-cstr-scan-r01/report.json'
PREP = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/a55-cstr-scan-entry-r01'
PREPARED_MAP_SHA = '4c9823f8425bea0c1ffb02bb6817640353d6d5197fcc73d20593c076eb2129f5'
CHANGED = {'src/mcp/runtime/request_archive_content.rs', 'src/mcp/runtime/request_archive_content_tests.rs', 'src/mcp/runtime/request_archive_index.rs', 'src/mcp/runtime/request_archive_store.rs', 'src/mcp/runtime/request_archive_store_tests.rs', 'src/mcp/runtime/request_audit.rs', 'src/mcp/runtime/request_audit_tests.rs', 'src/mcp/runtime/request_metadata_trace.rs'}
ENTRY_FILE = 'ci-audit/a55/qualification-frozen-r01/qualify_a55_cstr_scan_r01.py'
ENTRY_FILE_SHA = '797b9e326bb55f697419728b14d3cf217e4409b92222dc3db4b25b2a5dbc6e3e'
ENTRY_BYTES = 14160
BUNDLE_FILE = 'ci-audit/a55/qualification-frozen-r01/a55-cstr-scan-source-r01.json'
BUNDLE_FILE_SHA = '68be84528187e7a8aad49e84f07098270e52c1d1e02121f4e250ce41ef5e478c'
BUNDLE_BYTES = 467429
PARENT_QUALIFICATION_SHA = '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'
PARENT_QUALIFICATION_BYTES = 61986
PARENT_COMMIT = '34b961941a211025f2083b9fd24470de32cb5b2f'
PARENT_TREE = '797878008d5ae6d8035766e53a3f6619b76a38c1'
PARENT_SOURCE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/source-a54-compact-view-r01'
PARENT_QUALIFICATION = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/qualification-a54-compact-view-r01/report.json'
PARENT_SOURCE_MAP_SHA = '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'
PARENT_GIT_MAP_SHA = 'e368fa01d47104de5ebc3c56efcb6da91c4f589e75df49bbf1dedf5a67f4c774'
PARENT_PUBLICATION_SHA = '90f94d0b99b376ee01b3a7e3ca7fb43b983195ad42dab8b39b0596226ec3358f'


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def read_pin(path, expected):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path and path.is_file(), 'direct original file required')
    raw = path.read_bytes()
    need(len(raw) <= 2 * 1024 * 1024 and HEX.fullmatch(expected) and sha(raw) == expected,
         'original input identity differs: ' + str(path))
    return raw


def preparation():
    """Validate the already frozen A55 overlay; this does not execute it."""
    entry_raw = read_pin(WORKSPACE / ENTRY_FILE, ENTRY_FILE_SHA)
    raw = read_pin(WORKSPACE / BUNDLE_FILE, BUNDLE_FILE_SHA)
    need(len(entry_raw) == ENTRY_BYTES and len(raw) == BUNDLE_BYTES, 'frozen A55 entry/bundle length differs')
    value = json.loads(raw)
    need(value['schema'] == 'hepta-a55-cstr-scan-source/v1'
         and value['ready_for_execution'] is True
         and value['repository_base_commit'] == PARENT_COMMIT
         and value['repository_base_tree'] == PARENT_TREE
         and value['parent_qualification_sha256'] == PARENT_QUALIFICATION_SHA,
         'frozen A55 source overlay parent differs')
    parent, candidate = value['parent_source_map'], value['candidate_source_map']
    need(len(parent) == len(candidate) == 175 and set(parent) == set(candidate)
         and sha(compact(parent)) == PARENT_SOURCE_MAP_SHA
         and sha(compact(candidate)) == PREPARED_MAP_SHA
         and set(value['files']) == CHANGED, 'frozen A55 reviewed-file overlay map differs')
    need(set(value['parent_git_source_blob_map']) == set(parent)
         and sha(compact(value['parent_git_source_blob_map'])) == PARENT_GIT_MAP_SHA,
         'frozen published A54 compiler blob map differs')
    proof = value['parent_publication']
    need(proof['checker_result']['sha256'] == PARENT_PUBLICATION_SHA
         and proof['check']['passed'] is True and proof['check']['performed'] is True
         and proof['check']['full_tree_checked'] is True
         and proof['check']['commit_sha'] == PARENT_COMMIT and proof['check']['tree_sha'] == PARENT_TREE
         and proof['check']['compiler_files'] == 175
         and proof['check']['git_blob_map_compact_sha256'] == PARENT_GIT_MAP_SHA,
         'frozen parent publication proof differs')
    expected = dict(parent)
    for name, item in value['files'].items():
        body = base64.b64decode(item['base64'], validate=True)
        need(type(item['bytes']) is int and len(body) == item['bytes']
             and sha(body) == item['sha256'] and item['parent_sha256'] == parent[name],
             'frozen A55 overlay body differs: ' + name)
        expected[name] = sha(body)
    need(candidate == expected, 'unaccounted A55 overlay change')
    return value


def require_receipt(receipt, path, expected, size):
    need(receipt['path'] == path and receipt['sha256'] == expected
         and type(receipt['bytes']) is int and receipt['bytes'] == size
         and type(receipt['identity']) is list and len(receipt['identity']) == 9
         and all(type(value) is int for value in receipt['identity']),
         'actual qualification input receipt differs: ' + path)


def verify_custody(row):
    pid = row['pid']
    need(type(pid) is int and pid > 1 and row['actual_waitpid'] == pid
         and type(row['raw_wait_status']) is int and row['raw_wait_status'] == 0
         and type(row['returncode']) is int and row['returncode'] == 0,
         'original qualification worker exit differs')
    need(type(row['execution_count']) is int and row['execution_count'] == 1
         and all(row[key] is True for key in ('executed', 'pidfd_opened', 'original_child_reaped',
                 'custody_known', 'custody_retained_until_reap', 'group_quiet_before_reap', 'worker_permit_sent'))
         and row['custody_unknown'] is False and row['signals'] == [],
         'original qualification custody is not complete')
    need(not any(row.get(key) for key in ('outer_work_budget_exceeded', 'error', 'cleanup_errors',
             'normal_worker_exit_left_live_group_or_observation_errors')), 'qualification cleanup error')
    initial, terminal = row['original_identity'], row['terminal_group_snapshot']
    need(initial['pid'] == initial['pgrp'] == initial['session'] == pid
         and terminal['errors'] == [] and terminal['live'] == [], 'qualification group identity differs')
    original = [member for member in terminal['members'] if member['pid'] == pid]
    need(len(original) == 1 and original[0]['state'] == 'Z'
         and original[0]['start_ticks'] == initial['start_ticks']
         and original[0]['pgrp'] == original[0]['session'] == pid, 'original terminal zombie identity differs')


def actual_bindings(args):
    names = ('qualification', 'entry', 'worker')
    supplied = [getattr(args, name) is not None for name in names]
    pins = [getattr(args, name + '_sha') is not None for name in names]
    need((not any(supplied + pins)) or all(supplied + pins), 'supply all three original reports and SHA pins')
    if not any(supplied):
        return None
    raws = {name: read_pin(getattr(args, name), getattr(args, name + '_sha')) for name in names}
    q, entry, worker = (json.loads(raws[name]) for name in names)
    frozen = preparation()
    prepared = frozen['candidate_source_map']
    need(len(prepared) == 175 and sha(compact(prepared)) == PREPARED_MAP_SHA, 'frozen A55 input map changed')
    need(q['schema'] == 'runtime-candidate-qualification/v1' and q['qualified'] is True
         and q['current_stage'] == 'complete' and q['service_changes'] is False
         and not q.get('error') and not q.get('errors') and q['source'] == SOURCE,
         'successful actual A55 ordinary qualification required')
    need(q['source_input'] == prepared and q['source_tested'] == q['source_after']
         and set(q['source_tested']) == set(prepared), 'A55 input/tested/after maps differ')
    need(all(type(value) is str and HEX.fullmatch(value) for value in q['source_tested'].values()),
         'actual tested source identities missing')
    need(all(q['source_tested'][name] == value for name, value in prepared.items() if name not in CHANGED),
         'formatter changed an unrelated parent file')
    for key, filename in (('binary', 'hepta-runtime'), ('test_binary', 'hepta-runtime-tests')):
        artifact = q[key]
        need(artifact['cached'] is False and artifact['compiler_source'] == SOURCE + '/src/main.rs'
             and artifact['path'] == str(Path(QUALIFICATION).parent / filename)
             and type(artifact['sha256']) is str and HEX.fullmatch(artifact['sha256']),
             'fresh actual compiler artifact identity missing: ' + key)
    need(entry['schema'] == 'hepta-a55-cstr-scan-qualification-entry/v1'
         and entry['qualified'] is True and entry['errors'] == [] and not entry.get('error')
         and entry['candidate_source'] == SOURCE and entry['candidate_source_map'] == prepared,
         'actual A55 entry differs')
    need(entry['parent_and_input_fence_unchanged'] is True
         and entry['retained_parent_git_blobs_verified'] is True
         and entry['repository_base_commit'] == PARENT_COMMIT
         and entry['repository_base_tree'] == PARENT_TREE,
         'A55 actual retained parent publication/input fence differs')
    need(entry['parent_source'] == PARENT_SOURCE
         and entry['parent_source_map'] == frozen['parent_source_map']
         and entry['parent_git_source_blob_map'] == frozen['parent_git_source_blob_map']
         and entry['parent_publication'] == frozen['parent_publication']
         and type(entry['github_calls']) is int and entry['github_calls'] == 0,
         'A55 actual parent report/source/publication differs')
    require_receipt(entry['entry'], BASE + '/tools/' + Path(ENTRY_FILE).name, ENTRY_FILE_SHA, ENTRY_BYTES)
    require_receipt(entry['source_bundle'], BASE + '/tools/' + Path(BUNDLE_FILE).name, BUNDLE_FILE_SHA, BUNDLE_BYTES)
    require_receipt(entry['parent_qualification'], PARENT_QUALIFICATION, PARENT_QUALIFICATION_SHA, PARENT_QUALIFICATION_BYTES)
    need(worker['schema'] == 'hepta-a55-cstr-scan-qualification-worker/v1'
         and worker['passed'] is True and not worker.get('error') and not worker.get('errors')
         and worker['stage_umask'] == '022', 'actual A55 worker differs')
    qr = worker['qualifier_report']
    need(qr['path'] == QUALIFICATION and qr['sha256'] == sha(raws['qualification'])
         and qr['bytes'] == len(raws['qualification']), 'worker qualification receipt differs')
    stages = ('format', 'fmt-check', 'clean-package', 'clippy', 'test', 'release')
    need(tuple(row['name'] for row in q['stages']) == stages and len(worker['stages']) == 6,
         'all six original stages required')
    for index, (qs, ws) in enumerate(zip(q['stages'], worker['stages'])):
        need(qs['name'] == ws['name'] and qs['command'] == ws['argv']
             and type(qs['returncode']) is int and qs['returncode'] == 0
             and type(ws['returncode']) is int and ws['returncode'] == 0
             and ws['executed'] is True and type(ws['execution_count']) is int and ws['execution_count'] == 1
             and ws['gate_clear'] is True and ws['timeout_seconds'] == 1800 and not ws.get('error'),
             'stage failed or original command/budget differs')
        gate = ws['host_gate']
        need(gate['path'] == PREP + '/stage-%d-%s.host-gate.json' % (index, ws['name'])
             and type(gate['bytes']) is int and gate['bytes'] > 0
             and type(gate['sha256']) is str and HEX.fullmatch(gate['sha256'])
             and len(gate['identity']) == 9, 'original six stage gate receipt missing')
    for value in (entry, worker):
        need(value['automatic_retry'] is False and value['service_changes'] is False, 'qualification retry/service policy differs')
        env = value['environment']
        need(env['stage_umask'] == '022' and env['metadata_trace_enabled'] is False and env['agent_accesses'] == 0
             and all(env['fixed_values'][key] == value for key, value in {
                 'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0',
                 'TOKIO_WORKER_THREADS': '2', 'RUST_TEST_THREADS': '2'}.items()), 'qualification environment differs')
    verify_custody(entry['worker_custody'])
    argv = entry['worker_custody']['argv']
    expected_argv = ['/usr/bin/python3', BASE + '/tools/' + Path(ENTRY_FILE).name, '--worker',
                     '--bundle-sha', BUNDLE_FILE_SHA, '--entry-sha', ENTRY_FILE_SHA,
                     '--parent-qualification-sha', PARENT_QUALIFICATION_SHA]
    need(type(argv) is list and len(argv) == len(expected_argv) + 2
         and argv[:-2] == expected_argv and argv[-2] == '--permit-fd'
         and type(argv[-1]) is str and argv[-1].isdigit(), 'actual A55 original worker argv differs')
    return {'ready': True, 'reports': {name: {'path': str(Path(getattr(args, name)).absolute()),
                'bytes': len(raws[name]), 'sha256': sha(raws[name])} for name in names},
            'prepared_map_sha': PREPARED_MAP_SHA, 'tested_map_sha': sha(compact(q['source_tested'])),
            'tested_map': q['source_tested'], 'release_sha': q['binary']['sha256']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qualification', 'entry', 'worker'):
        parser.add_argument('--' + name, required=True, type=Path)
        parser.add_argument('--' + name + '-sha', required=True)
    arguments = parser.parse_args()
    actual = actual_bindings(arguments)
    need(actual is not None and actual['ready'] is True, 'actual A55 qualification required')
    print(json.dumps(actual, sort_keys=True))
