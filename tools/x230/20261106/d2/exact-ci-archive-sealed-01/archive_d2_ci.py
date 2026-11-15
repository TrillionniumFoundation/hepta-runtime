#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Preserve one completed native D2 exact-CI attempt. Zero-extract verification rechecks retained bytes only.

No source, ELF, cache, runtime, benchmark, CI or auditor is executed or modified.
The collector source is published separately; its own credential-scanner literals are not tar members.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

MAX_TOTAL = 32 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
ROOT = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')
SOURCE_REFERENCE_SHA256 = 'e7a0787a110c50a93e18bf951c02f195e62752c532ea3f649f956ca1b06d018f'
VERIFY_REFERENCE_SHA256 = 'ca4c6b418dfe1141036a4bebc79e76d0f9563e40b93d3f64647bc9992c1d2c87'
SKIP_DIRS = {'.git',
 '.ssh',
 '__pycache__',
 'credentials',
 'keys',
 'profile',
 'secrets',
 'target',
 'target-build',
 'test-binaries'}
SKIP_FILES = {'agent.sock',
 'credentials.json',
 'id_ecdsa',
 'id_ed25519',
 'id_rsa',
 'known_hosts',
 'runtime-config.json',
 'runtime.json',
 'secrets.json',
 'ssh_config'}
PINNED = {'full-prerequisites-01/d2_prerequisites.py': {'bytes': 59048,
                                               'sha256': '2a04eb862c4efe1377a3b78dad33b99f43573d7c91dc66503ad5f08690b17da9'},
 'preparation.json': {'bytes': 68630,
                      'sha256': '0588e6b5e840a3f42ab520bb53b1fd2d440e0bd44ee9dc7febd2a0813256da7b'},
 'qualification-01/isolated-tests.audit.json': {'bytes': 1425113,
                                                'sha256': '5351b3f2e42788a364a876627cae16c4aa9a5b82b2f13ba3d76571ec8e6caa40'},
 'qualification-01/isolated-tests/summary.json': {'bytes': 6901,
                                                  'sha256': '8a5707ab41ba7b427568edfc18d2653edf28980cff69fd73fbffa6bb5437ff3b'},
 'qualification-01/report.json': {'bytes': 84034,
                                  'sha256': '1cc52b4a0a86719c2da933872046d52ff42a21dcabb4ff59a21f440bbb5b9702'},
 'qualification-01/source-map.json': {'bytes': 24368,
                                      'sha256': '4bdbae5e8dea5d7534b5bde6961b44eaeaf5524553a788e171fee9fb2ecf5209'},
 'qualification-native-read-01.json': {'bytes': 3818,
                                       'sha256': 'ff998979d894bcc8e044673cd6b679d50c255d793d62f797c68e47ab1c608f68'},
 'qualification-prerequisites-01.json': {'bytes': 6685,
                                         'sha256': '5a65dfb879fa0d6aa0b12640657f6947c6317e11deaabe9a66d7c4e950811580'},
 'qualification-terminal-status-01.json': {'bytes': 731,
                                           'sha256': '4b268e9d34b0e85e727a07e1586e772a1ee9a91c02a32a13f49332a815c9c1cf'},
 'rust-ci-actual-pins-01.json': {'bytes': 4641,
                                 'sha256': '174b362ecbe48087c559c8d18fb129caa1a962563c96e7cc0aa58037af899ee1'},
 'rust-ci-deployment-manifest-01.json': {'bytes': 2128,
                                         'sha256': '2aa7d73896263f9a3c2904209f178ca981e900771ba3fb0dfc4536fa6c02de95'},
 'rust-ci-launch-command-01.json': {'bytes': 434,
                                    'sha256': 'b1cbcdfec3914960dfd3f0e7adff6aaecb78166add6ad43123feb54420fbdf2d'},
 'rust-ci-seal-manifest-01.json': {'bytes': 5326,
                                   'sha256': 'fd2b2498dfab9bfebb77572a7d6f885248c908389d5e3d27ab0ae77c2ceb722b'},
 'rust-ci-tools-01/audit_nextest_0137.py': {'bytes': 8563,
                                            'sha256': '03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2'},
 'rust-ci-tools-01/canonical-workflow.yml': {'bytes': 7631,
                                             'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'},
 'rust-ci-tools-01/launch_exact_rust_ci_01.py': {'bytes': 6313,
                                                 'sha256': '5923d6217ad70a6c79c5fac5c127dc7c737bc2d17433152f09347a564177b978'},
 'rust-ci-tools-01/materialize_rust_ci_plan_01.py': {'bytes': 25732,
                                                     'sha256': '949051443631877d81bbe6b9d55b0d3d3d05c0c6825e2df311c62a82a6b016e4'},
 'rust-ci-tools-01/package-manifest-01.json': {'bytes': 1957,
                                               'sha256': '52c512b3d947c0c1b2bab1b8e8b1db77e7c60bdd41bf72cc935cf0ef73cb63d3'},
 'rust-ci-tools-01/run_rust_ci_01.py': {'bytes': 15182,
                                        'sha256': 'ba44655087b3ab674425f5cd3c78a5e43414a60a608c60b791ab9d2129740660'}}
CI_COMMANDS = {'cargo-version': ['cargo', '--version'],
 'rustc-version': ['rustc', '--version'],
 'nextest-version': ['cargo', 'nextest', '--version'],
 'cargo-check': ['cargo', 'check', '--locked', '--all-targets', '--all-features'],
 'nextest-list': ['cargo',
                  'nextest',
                  'list',
                  '--locked',
                  '--all-targets',
                  '--all-features',
                  '--message-format',
                  'json'],
 'nextest-run': ['cargo',
                 'nextest',
                 'run',
                 '--locked',
                 '--all-targets',
                 '--all-features',
                 '--test-threads',
                 '1',
                 '--retries',
                 '0',
                 '--no-fail-fast']}
CI_ENVIRONMENT = {'CARGO_BUILD_JOBS': '2',
 'CARGO_HOME': '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02',
 'CARGO_INCREMENTAL': '0',
 'CARGO_NET_OFFLINE': 'true',
 'CARGO_TARGET_DIR': '/home/qian/hepta-runtime-validation-cost-20261106-d2/target-build',
 'CARGO_TERM_COLOR': 'never',
 'NEXTEST_FINAL_STATUS_LEVEL': 'fail',
 'NEXTEST_STATUS_LEVEL': 'pass',
 'NEXTEST_SUCCESS_OUTPUT': 'never',
 'PATH': '/home/qian/hepta-runtime-optimization-20261105-r25/ci-toolchain/nextest-0.9.137/bin:/home/qian/.cargo/bin:/usr/local/bin:/usr/bin:/bin',
 'PYTHONDONTWRITEBYTECODE': '1',
 'PYTHONNOUSERSITE': '1',
 'RUSTUP_TOOLCHAIN': '1.95.0',
 'RUST_TEST_THREADS': '1',
 'TOKIO_WORKER_THREADS': '2'}
COUNT_KEYS = ('passed', 'failed', 'ignored', 'selected', 'retries')
FUTURE_PATHS = ('rust-ci-plan-01.json', 'rust-ci-01/report.json', 'rust-ci-01/nextest-output-audit.json',
                'rust-ci-native-01.json', 'rust-ci-installation-started-01.json', 'rust-ci-installation-01.json')
ACTUAL = {'counts': {'failed': 0, 'ignored': 34, 'passed': 1651, 'retries': 0, 'selected': 1685},
 'exit_code': 0,
 'files': {'rust-ci-01/nextest-output-audit.json': {'bytes': 719,
                                                    'sha256': 'fbbdd0530b0cc13cf027884ce41f5fa99254cf1f0fcba8e5cf591306cf5f9055'},
           'rust-ci-01/report.json': {'bytes': 14180,
                                      'sha256': '8dcfb62d03fe9425cc078879608fa9f6faba6655f0bacbf2964c497201690001'},
           'rust-ci-installation-01.json': {'bytes': 2559,
                                            'sha256': '0362cb987a83fa4a78149b98115bada342bd4a70f632b50b529da3f338458466'},
           'rust-ci-installation-started-01.json': {'bytes': 381,
                                                    'sha256': '9d5e53523b25dc406b131c07698ccd8fcd60098f84ac062d2342326e16b31868'},
           'rust-ci-native-01.json': {'bytes': 731,
                                      'sha256': '07b07fe57a38e5c68767d85c4f78f178a9110d227ac647e28331eb951a9eee29'},
           'rust-ci-native-read-01.json': {'bytes': 5138,
                                           'sha256': 'ea754013042bede6fef2e0c59188d49ff31653ff0bf1bc9c2e016deb77e41ef1'},
           'rust-ci-plan-01.json': {'bytes': 653511,
                                    'sha256': 'aa47815b5755665a3e068b5e09f3d4559c86562dff174f9f8020c3b4ebe5d625'}},
 'original_job_id': '1a1b0f08c41-fc05-7434',
 'outcome': 'passed',
 'read_pages': ['rust-ci-native-read-01.json'],
 'schema': 'hepta-d2-exact-ci-archive-actual-pins/v1',
 'sealed': True}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def stamp(value):
    return tuple(getattr(value, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def tool_sha256():
    path = Path(__file__).absolute()
    need(path.resolve(strict=True) == path, 'indirect archive tool')
    initial = path.lstat()
    need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size <= MAX_FILE,
         'unsafe/oversized archive tool')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stamp(before) == stamp(initial), 'archive tool changed before open')
        raw = stream.read(MAX_FILE + 1)
        need(len(raw) <= MAX_FILE and len(raw) == before.st_size
             and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             'archive tool changed while read')
    return sha(raw)


def native_terminal(value, job_id, state, exit_code):
    need(value.get('job_id') == job_id and value.get('state') == state
         and type(value.get('exit_code')) is int and value['exit_code'] == exit_code
         and all(value.get(key) is True for key in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and all(value.get(key) is False for key in ('automatic_retry', 'timed_out', 'cancelled'))
         and type(value.get('terminal_publication_protocol')) is int and value['terminal_publication_protocol'] == 1
         and value.get('log_synced') == {'stdout': True, 'stderr': True}
         and value.get('log_errors') == {'stdout': None, 'stderr': None}
         and value.get('log_truncated') == {'stdout': False, 'stderr': False},
         'complete durable original native terminal required: ' + job_id)
    for stream in ('stdout', 'stderr'):
        counts = value['log_bytes'][stream]
        need(set(counts) == {'seen', 'stored'} and all(type(n) is int and n >= 0 for n in counts.values())
             and counts['seen'] == counts['stored'], 'original native log byte counts differ: ' + job_id)


def native_stream_pages(pages, terminal):
    """Verify original read pages; never replace them with a fabricated single page."""
    assert isinstance(pages, list) and 1 <= len(pages) <= 16
    offsets = {'stdout': 0, 'stderr': 0}
    chunks = {'stdout': [], 'stderr': []}
    for index, page in enumerate(pages):
        assert page['job_id'] == terminal['job_id'] and page['audit_recorded'] is True
        for name in ('stdout', 'stderr'):
            channel = page[name]
            raw = bytes.fromhex(channel['bytes_hex'])
            total = terminal['log_bytes'][name]['stored']
            assert type(total) is int and 0 <= total <= 256 * 1024
            assert type(channel['offset']) is int and channel['offset'] == offsets[name]
            assert channel['size'] == total and len(raw) <= 16384
            assert channel['next_offset'] == channel['offset'] + len(raw) <= total
            assert channel['text'] == raw.decode('utf-8', errors='replace')
            assert channel['eof'] is (channel['next_offset'] == total)
            # A stream already at EOF may recur as an empty EOF on later calls.
            # A pending stream must make progress, with no gaps or overlaps.
            assert raw or offsets[name] == total
            if index + 1 == len(pages):
                assert channel['eof'] is True
            offsets[name] = channel['next_offset']
            chunks[name].append(raw)
    assert all(offsets[name] == terminal['log_bytes'][name]['stored'] for name in offsets)
    return {name: b''.join(parts) for name, parts in chunks.items()}


# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Pure byte/receipt interpretation. No archived Python is imported or executed.

def require_sealed():
    need(not sys.flags.optimize, 'Python optimized assertions are not supported')
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-d2-exact-ci-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True, 'UNSEALED: actual completed D2 exact-CI originals required')
    job = ACTUAL.get('original_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original native CI identity required')
    pages = ACTUAL.get('read_pages')
    need(type(pages) is list and 1 <= len(pages) <= 16 and len(set(pages)) == len(pages)
         and (pages == ['rust-ci-native-read-01.json']
              or pages == ['rust-ci-native-read-01-%03d.json' % i for i in range(len(pages))]),
         'original native read page names/order are unbound')
    need(ACTUAL.get('outcome') in {'passed', 'failed'} and type(ACTUAL.get('exit_code')) is int
         and ((ACTUAL['outcome'] == 'passed' and ACTUAL['exit_code'] == 0)
              or (ACTUAL['outcome'] == 'failed' and ACTUAL['exit_code'] != 0)),
         'actual CI outcome and exit status disagree')
    need(type(ACTUAL.get('files')) is dict
         and set(ACTUAL['files']) == set(FUTURE_PATHS) | set(pages), 'actual CI file inventory differs')
    for name, pin in ACTUAL['files'].items():
        need(pin is None or (type(pin) is dict and set(pin) == {'bytes', 'sha256'}
             and type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_FILE
             and type(pin['sha256']) is str and len(pin['sha256']) == 64
             and set(pin['sha256']) <= set('0123456789abcdef')), 'invalid actual receipt pin: ' + name)
    need(all(ACTUAL['files'][name] is not None for name in
             ['rust-ci-native-01.json', 'rust-ci-installation-started-01.json',
              'rust-ci-installation-01.json', *pages]), 'actual native/installation originals missing')
    if ACTUAL['outcome'] == 'passed':
        need(all(pin is not None for pin in ACTUAL['files'].values()), 'successful CI is missing raw receipts')
        counts = ACTUAL.get('counts')
        need(type(counts) is dict and set(counts) == set(COUNT_KEYS)
             and all(type(n) is int and n >= 0 for n in counts.values()) and counts['passed'] > 0
             and counts['failed'] == counts['retries'] == 0
             and counts['selected'] == counts['passed'] + counts['ignored'], 'actual complete CI counts required')
    else:
        need(ACTUAL.get('counts') is None, 'failed CI cannot inherit successful qualification counts')
    return ACTUAL


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'ci', 'this script archives only the original D2 exact-CI attempt')
    for name, pin in {**PINNED, **actual['files']}.items():
        if pin is None:
            need(name not in data, 'receipt declared absent appears in archive: ' + name)
        else:
            need(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin,
                 'original receipt identity differs: ' + name)

    def document(name):
        return json.loads(data[name])

    def identity(name):
        return {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}

    def bound_identity(pin, expected_name):
        need(pin == identity(expected_name), 'original report body identity differs: ' + expected_name)
        return pin

    foundation = document('qualification-prerequisites-01.json')
    need(foundation['schema'] == 'hepta-d2-c1-prerequisites/v1'
         and foundation['qualification_sealed'] is True and foundation['exact_ci_sealed'] is False
         and foundation['prerequisite_module'] == identity('full-prerequisites-01/d2_prerequisites.py'),
         'original Q-only foundation/canonical module differs')
    q = document('qualification-01/report.json')
    qmap = document('qualification-01/source-map.json')
    qs = document('qualification-01/isolated-tests/summary.json')
    qa = document('qualification-01/isolated-tests.audit.json')
    qcounts = {key: qs[key] for key in COUNT_KEYS}
    need(q['qualified'] is True and q['source_tested'] == q['source_after'] == qmap and len(qmap) == 222
         and qs['success'] is True and qa['success'] is True and qa['errors'] == []
         and {key: qa[key] for key in ('passed', 'failed', 'ignored', 'selected')} ==
             {key: qcounts[key] for key in ('passed', 'failed', 'ignored', 'selected')},
         'original qualified source/counts disagree')
    qnative = document('qualification-terminal-status-01.json')
    native_terminal(qnative, foundation['qualification_original_job_id'], 'succeeded', 0)
    qreads = []
    for pin in foundation['qualification_read_pages']:
        name = Path(pin['path']).relative_to(ROOT).as_posix()
        bound_identity(pin, name)
        qreads.append(document(name))
    native_stream_pages(qreads, qnative)
    for name in ('preparation.json', 'qualification-01/report.json', 'qualification-01/source-map.json',
                 'qualification-01/isolated-tests/summary.json', 'qualification-01/isolated-tests.audit.json',
                 'qualification-terminal-status-01.json'):
        bound_identity(foundation['artifact_map'][name], name)

    deployment = document('rust-ci-deployment-manifest-01.json')
    need(deployment['schema'] == 'hepta-d2-exact-ci-deployment/v1'
         and deployment['root'] == str(ROOT) and deployment['file_count_excluding_manifest'] == 11,
         'original deployment manifest differs')
    for row in deployment['files']:
        need({'bytes': row['bytes'], 'sha256': row['sha256']} == PINNED[row['path']],
             'original deployed member differs')

    terminal = document('rust-ci-native-01.json')
    state = 'succeeded' if actual['outcome'] == 'passed' else 'failed'
    native_terminal(terminal, actual['original_job_id'], state, actual['exit_code'])
    streams = native_stream_pages([document(name) for name in actual['read_pages']], terminal)
    ci = document('rust-ci-01/report.json') if actual['files']['rust-ci-01/report.json'] else None
    plan = document('rust-ci-plan-01.json') if actual['files']['rust-ci-plan-01.json'] else None
    audit = document('rust-ci-01/nextest-output-audit.json') if actual['files']['rust-ci-01/nextest-output-audit.json'] else None
    stages = []
    if ci is not None:
        need(ci['schema'] == 'hepta-d2-external-rust-ci/v1', 'unexpected CI receipt schema')
        need(type(ci['stages']) is list, 'original stage inventory is not a list')
        seen = set()
        for row in ci['stages']:
            name = row['name']
            need(name in CI_COMMANDS and name not in seen, 'unexpected/duplicate original CI stage')
            seen.add(name)
            logs = {}
            for channel in ('stdout', 'stderr'):
                pin = row.get(channel)
                if pin is not None:
                    logs[channel] = bound_identity(pin, 'rust-ci-01/' + name + '.' + channel)
            stages.append({'name': name, 'returncode': row.get('returncode'), 'passed': row.get('passed'),
                           'timed_out': row.get('timed_out'), 'waited_and_reaped': row.get('waited_and_reaped'),
                           'owned_process_absent': row.get('owned_process_absent'),
                           'owned_process_group_absent': row.get('owned_process_group_absent'), 'logs': logs})

    if actual['outcome'] == 'passed':
        need(ci['passed'] is True and ci.get('finished_utc') and not ci.get('error')
             and ci['automatic_retries'] == 0 and ci['production_services_modified'] is False
             and ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
             and ci['home_unchanged'] is True and ci['hosted_actions_passed'] is False
             and ci['original_qualification_job_id'] == foundation['qualification_original_job_id'],
             'original CI workflow did not completely close successfully')
        bound_identity(ci['plan'], 'rust-ci-plan-01.json')
        need(plan['schema'] == 'hepta-d2-materialized-exact-rust-ci-plan/v1'
             and plan['attempt'] == '01' and plan['executed'] is False and plan['hosted_actions_passed'] is False
             and plan['qualification_job_id'] == foundation['qualification_original_job_id']
             and plan['source'] == str(ROOT / 'source') and plan['source_files'] == qmap
             and plan['qualification_counts'] == qcounts == actual['counts'],
             'original exact-CI plan identifies another source/qualification')
        for key, name in (('qualification', 'qualification-01/report.json'), ('preparation', 'preparation.json'),
                          ('source_map', 'qualification-01/source-map.json'),
                          ('qualification_summary', 'qualification-01/isolated-tests/summary.json'),
                          ('qualification_independent_audit', 'qualification-01/isolated-tests.audit.json'),
                          ('qualification_terminal_status', 'qualification-terminal-status-01.json')):
            bound_identity(plan[key], name)
            need(plan[key] in plan['input_bindings'], 'original plan omits a Q input binding')
        need(identity('full-prerequisites-01/d2_prerequisites.py') in plan['input_bindings']
             and identity('qualification-prerequisites-01.json') in plan['input_bindings'],
             'original plan omits canonical module/Q-only foundation')
        need(plan['commands'] == [
                 {'workflow_step': 'Check all targets', 'argv': CI_COMMANDS['cargo-check'], 'cwd': str(ROOT / 'source')},
                 {'workflow_step': 'Test in isolated processes', 'argv': CI_COMMANDS['nextest-run'], 'cwd': str(ROOT / 'source')}]
             and plan['inventory_command']['argv'] == CI_COMMANDS['nextest-list']
             and plan['inventory_command']['cwd'] == str(ROOT / 'source')
             and ci['explicit_environment'] == plan['environment'] == CI_ENVIRONMENT,
             'original CI commands/environment differ')
        need([row['name'] for row in ci['stages']] == list(CI_COMMANDS), 'original six CI stages are incomplete')
        for row in ci['stages']:
            need(row['argv'] == CI_COMMANDS[row['name']] and row['cwd'] == str(ROOT / 'source')
                 and row['returncode'] == 0 and row['passed'] is True and row['timed_out'] is False
                 and row['waited_and_reaped'] is True and row['owned_process_absent'] is True
                 and row['owned_process_group_absent'] is True, 'original stage failed or was not closed')
            for channel in ('stdout', 'stderr'):
                bound_identity(row[channel], 'rust-ci-01/' + row['name'] + '.' + channel)
        need(data['rust-ci-01/nextest-version.stdout'].decode().splitlines()[0].startswith('cargo-nextest 0.9.137 '),
             'original nextest version differs')
        need(ci['nextest_output_audit'] == audit and audit['verified'] is True
             and {key: audit[key] for key in COUNT_KEYS} == actual['counts']
             and audit['completed_exact_case_count'] == actual['counts']['passed']
             and audit['progress_counter_complete'] is True
             and audit['raw_bytes'] == len(data['rust-ci-01/nextest-run.stderr'])
             and audit['raw_sha256'] == sha(data['rust-ci-01/nextest-run.stderr']),
             'original nextest audit/counts do not bind the retained raw stderr')
        inventory, expected = ci['structured_inventory'], plan['expected_nextest']
        need(inventory['verified'] is True and inventory['total'] == actual['counts']['selected']
             and inventory['ignored'] == actual['counts']['ignored']
             and inventory['case_inventory_sha256'] == audit['case_inventory_sha256'] == expected['case_inventory_sha256']
             and inventory['original_stdout'] == identity('rust-ci-01/nextest-list.stdout')
             and len(expected['exact_cases']) == actual['counts']['selected']
             and sum(row['ignored'] for row in expected['exact_cases']) == actual['counts']['ignored']
             and sha(json.dumps(expected['exact_cases'], sort_keys=True, separators=(',', ':')).encode())
                 == expected['case_inventory_sha256'], 'original complete unfiltered case inventory differs')
        bound_identity(plan['workflow_binding']['canonical'], 'rust-ci-tools-01/canonical-workflow.yml')
        bound_identity(ci['auditor'], 'rust-ci-tools-01/audit_nextest_0137.py')
        bound_identity(ci['launcher'], 'rust-ci-tools-01/run_rust_ci_01.py')
        bound_identity(ci['materializer'], 'rust-ci-tools-01/materialize_rust_ci_plan_01.py')
        for name, pin in plan['qualified_binaries'].items():
            need(pin['path'] == q['binaries'][name]['path'] and pin['sha256'] == q['binaries'][name]['sha256'],
                 'original qualified release identity differs')

    return {'schema': 'hepta-d2-exact-ci-evidence-compact/v1', 'kind': kind,
            'original_job_id': actual['original_job_id'], 'outcome': actual['outcome'],
            'native_state': terminal['state'], 'native_exit_code': terminal['exit_code'],
            'original_native_streams': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in streams.items()},
            'original_read_pages': [identity(name) for name in actual['read_pages']],
            'original_qualification_job_id': foundation['qualification_original_job_id'],
            'counts': actual['counts'], 'qualification_counts': qcounts,
            'reported_workflow_passed': None if ci is None else ci.get('passed'),
            'original_stage_outcomes': stages,
            'qualified_binary_sha256': {name: pin['sha256'] for name, pin in q['binaries'].items()},
            'compiler_input_count': len(qmap), 'source_map_sha256': sha(data['qualification-01/source-map.json']),
            'canonical_prerequisite_module': identity('full-prerequisites-01/d2_prerequisites.py'),
            'all_original_ci_directory_files_preserved_except_explicit_exclusions': True,
            'ci_reported_current_source_unchanged': None if ci is None else ci.get('source_inputs_unchanged'),
            'current_source_or_binary_bodies_rehashed_by_archiver': False,
            'archived_python_executed': False, 'auditor_rerun': False, 'tests_or_benchmarks_run': False,
            'hosted_actions_passed': False, 'performance_acceptance_claim': False, 'candidate_adopted': False}


def collect(root, kind):
    actual = require_sealed()
    need(kind == 'ci', 'this script archives only completed D2 exact-CI')
    need(root.is_absolute() and root.resolve() == root, 'indirect source root')
    payloads, excluded, snapshots = {}, {}, {}
    total = 0

    def file(path, required=False):
        nonlocal total
        relative = path.relative_to(root).as_posix()
        need(path.resolve(strict=True) == path, 'indirect source member: ' + relative)
        need(relative not in payloads, 'duplicate selected source member: ' + relative)
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'non-regular/link input: ' + relative)
        if path.name in SKIP_FILES or path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
            need(not required, 'required receipt has a credential filename')
            excluded[relative] = 'credential/configuration file'
            return
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stamp(before) == stamp(info), 'input changed before open: ' + relative)
            head = stream.read(4)
            if head == b'\x7fELF':
                need(not required, 'required receipt is an ELF')
                excluded[relative] = 'ELF executable'
                return
            need(before.st_size <= MAX_FILE, 'file exceeds 8 MiB: ' + relative)
            data = head + stream.read(MAX_FILE + 1 - len(head))
            need(len(data) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno()))
                 == stamp(path.lstat()), 'input changed while read: ' + relative)
        need(b'PRIVATE KEY-----' not in data and b'openssh-key-v1\x00' not in data,
             'private-key material detected; archive was not written: ' + relative)
        total += len(data)
        need(total <= MAX_TOTAL and len(payloads) < MAX_FILES, 'selected source bytes/files exceed archive limits')
        payloads[relative] = data
        snapshots[path] = stamp(info)

    def directory(path):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode), 'non-directory/symlink input: ' + str(path))
        snapshots[path] = stamp(info)
        for child in sorted(path.iterdir()):
            mode = child.lstat().st_mode
            need(not stat.S_ISLNK(mode), 'symlink input: ' + str(child))
            if stat.S_ISDIR(mode):
                if child.name in SKIP_DIRS:
                    excluded[child.relative_to(root).as_posix() + '/'] = 'excluded binary/profile/credential subtree'
                else:
                    directory(child)
            else:
                file(child)

    for name in PINNED:
        file(root / name, required=True)
    for name, pin in actual['files'].items():
        if pin is None:
            need(not os.path.lexists(root / name), 'receipt declared absent now exists: ' + name)
        elif not name.startswith('rust-ci-01/'):
            file(root / name, required=True)
    if os.path.lexists(root / 'rust-ci-01'):
        directory(root / 'rust-ci-01')
    need(all(stamp(path.lstat()) == expected for path, expected in snapshots.items()),
         'source changed during collection')
    return payloads, excluded


def create_archive(root, kind):
    require_sealed()
    need(kind == 'ci', 'this script archives only completed D2 exact-CI')
    base = root / 'rust-ci-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-d2-exact-ci-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
                'tool_sha256': tool_sha256(),
                'source_reference_sha256': SOURCE_REFERENCE_SHA256, 'verify_reference_sha256': VERIFY_REFERENCE_SHA256,
                'selected_bytes': sum(map(len, data.values())), 'excluded': excluded,
                'files': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in sorted(data.items())},
                'summary': compact, 'no_tests_or_benchmarks_run': True}
    manifest_raw, compact_raw = encoded(manifest), encoded(compact)
    need(len(manifest_raw) <= MAX_MANIFEST, 'manifest exceeds 2 MiB')
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in [('manifest.json', manifest_raw), *sorted(data.items())]:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.mtime = len(raw), 0o600, 0
                archive.addfile(entry, io.BytesIO(raw))
    archive_raw = buffer.getvalue()
    need(len(archive_raw) + len(manifest_raw) + len(compact_raw) <= MAX_TOTAL, 'combined archive/sidecars exceed 32 MiB')
    for path, raw in zip(outputs, (archive_raw, manifest_raw, compact_raw)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return {'archive': str(outputs[0]), 'bytes': len(archive_raw), 'sha256': sha(archive_raw),
            'manifest_sha256': sha(manifest_raw), 'counts': compact['counts'],
            'qualified_binary_sha256': compact['qualified_binary_sha256']}


def verify_archive(path, expected_sha):
    require_sealed()
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect archive path')
    initial = path.lstat()
    need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size <= MAX_TOTAL,
         'unsafe/oversized archive')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stamp(before) == stamp(initial), 'archive changed before open')
        raw = stream.read(MAX_TOTAL + 1)
        need(len(raw) <= MAX_TOTAL and len(raw) == before.st_size
             and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             'archive changed while read or exceeded 32 MiB')
    need(sha(raw) == expected_sha, 'archive SHA256 differs from the remote receipt')
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
        tar_raw = compressed.read(MAX_TAR + 1)
    need(len(tar_raw) <= MAX_TAR, 'expanded tar exceeds bounded size')
    data, manifest, manifest_sha, total = {}, None, None, 0
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode='r:') as archive:
        for number, entry in enumerate(archive):
            name = PurePosixPath(entry.name)
            need(entry.isfile() and not name.is_absolute() and '..' not in name.parts
                 and str(name) == entry.name and number <= MAX_FILES, 'unsafe/nonregular/oversized tar inventory')
            cap = MAX_MANIFEST if number == 0 else MAX_FILE
            need(0 <= entry.size <= cap, 'oversized tar member')
            value = archive.extractfile(entry).read(cap + 1)
            need(len(value) == entry.size, 'truncated tar member')
            if number == 0:
                need(entry.name == 'manifest.json', 'manifest must be first')
                manifest, manifest_sha = json.loads(value), sha(value)
                need(manifest['schema'] == 'hepta-d2-exact-ci-evidence-archive/v1'
                     and manifest['kind'] == 'ci'
                     and manifest.get('tool_sha256') == tool_sha256(),
                     'unexpected evidence manifest/tool identity')
            else:
                need(entry.name not in data and entry.name != 'manifest.json', 'duplicate tar member')
                need(not value.startswith(b'\x7fELF') and not any(part in SKIP_DIRS for part in name.parts)
                     and name.name not in SKIP_FILES and name.suffix.lower() not in {'.pem', '.key', '.p12', '.pfx'}
                     and b'PRIVATE KEY-----' not in value and b'openssh-key-v1\x00' not in value,
                     'excluded source/binary/profile/credential content appeared in archive')
                expected = manifest['files'].get(entry.name)
                need(expected == {'bytes': len(value), 'sha256': sha(value)}, 'manifest entry mismatch: ' + entry.name)
                data[entry.name] = value
                total += len(value)
                need(total <= MAX_TOTAL, 'total tar payload exceeds 32 MiB')
    need(manifest is not None and set(data) == set(manifest['files'])
         and sum(map(len, data.values())) == manifest['selected_bytes'], 'manifest membership/byte count differs')
    compact = summary(manifest['kind'], data)
    need(compact == manifest['summary'], 'compact summary differs from retained raw receipts')
    return {'verified': True, 'kind': manifest['kind'], 'archive': str(path), 'bytes': len(raw),
            'sha256': sha(raw), 'manifest_sha256': manifest_sha, 'files': len(data), 'selected_bytes': total,
            'original_job_id': compact['original_job_id'], 'counts': compact['counts'],
            'qualified_binary_sha256': compact['qualified_binary_sha256'], 'files_extracted': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--kind', choices=('ci',))
    mode.add_argument('--verify', type=Path)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    if args.verify is not None:
        need(args.expected_sha256 is not None, '--expected-sha256 from the remote archive receipt is required')
        result = verify_archive(args.verify.absolute(), args.expected_sha256)
    else:
        need(args.expected_sha256 is None, '--expected-sha256 is only for verification')
        result = create_archive(ROOT, args.kind)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AssertionError, tarfile.TarError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
