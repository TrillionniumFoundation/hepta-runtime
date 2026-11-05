#!/usr/bin/env python3
"""Cross-bind three completed R28 evidence packages, without executing their code.

The pinned independent QAs establish complete compression/member verification.
This local-only check links exact original members across those three packages.
It preserves both preflight failures, the rejected observation, and nonexecution.
"""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

WORK = Path('/workspace/scratch/806ba5f52f94')
HERE = Path(__file__).resolve().parent
OUTPUT = WORK / 'r25-integration-audit/r28-native-custody-preparation-01/three-companion-cross-verification-01.json'
XROOT = '/home/qian/hepta-runtime-optimization-20261105-r28'
MAC_ROOT = '/Users/qianqi/work'
OBS_JOB = '1a1acbbcbec-fc05-56a0'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
REFERENCE = ('r25-integration-audit/r26-cross-package-verification-01/crosscheck_formal_mac_01.py',
             12623, '92372b0d1f1d79c88399eb0de92e791fae54b5421ca7031f058bfe41a22391d6')
PLAN = ('r28-publication-draft-01/cross-package-binding-plan-01.json',
        1495, 'a10aa656ecba093512811960536d5ecde7c8b2552509f179ff253dc22edbfa2e')
GROUPS = {
    'qualification_ci': {
        'qa': ('benchmark-r28/qualification-ci-export-operations-01/assembled-01/verified-01/independent-verification-01.json',
               9585, '7342eed4ed17389eb57f5f40111438c5c4e339591ebb77c450a4fb1fe3ae2614'),
        'archive': ('benchmark-r28/qualification-ci-export-operations-01/assembled-01/qualification-ci-01.tar.xz',
                    1915620, '442586ded13a4cfde54531e6f05ddddcf26c2f53d40d15b04c5993ece5f04186'),
        'manifest': (2745831, '9ed5ce8099685e6fff9e1f0ecb2b7b980f6e2dc410cf2413bd189d72a8395a9d'),
        'mode': 'r:xz', 'members': 3830,
    },
    'performance': {
        'qa': ('benchmark-r28/performance-export-operations-01/assembled-01/verified-01/independent-verification-01.json',
               63895, '3940705478d677364c07d2c4b0b00cbd55fd4792828574b83ecfc2f08990e40d'),
        'archive': ('benchmark-r28/performance-export-operations-01/assembled-01/performance-01.tar.xz',
                    1704632, 'ba420b2e0a34a23b9d0330b3c5f38e743b08110d02db9c7dd599b25943070613'),
        'manifest': (4164831, 'bdb61667104eab4e6ab38feb341918ecab196e7dc3ea69cd8e921e18a95e9c63'),
        'mode': 'r:xz', 'members': 4155,
    },
    'mac': {
        'qa': ('benchmark-r28/mac-companion-operations-01/assembled-01/verified-01/independent-verification-01.json',
               6519, 'a1036182464f30a7afe8880ffe19077d45dddebd298948c9c52d4179b0e4972b'),
        'archive': ('benchmark-r28/mac-companion-operations-01/assembled-01/verified-01/formal-holders-01.tar.gz',
                    71892, 'fc7bf702c4b41e073b0cd37891f0b0970c7e30170b6aa3c0e2b92ef297ff4ce6'),
        'manifest': (21772, '6bd814eac4d4ba965db76914c3898b8daefa4024d0de3a0128f8988b784bcb72'),
        'mode': 'r:gz', 'members': 33,
    },
}
QUALIFICATION_LINKS = {
    'preparation02': ('preparation-02.json', 'root-receipts/preparation-02.json',
                      'qualification-reference/preparation-02.json', 96494,
                      '4ece02608c423456d0996de39c54129c6c759a1973a0e11f22b04f936b113cc3'),
    'terminal02': ('qualification-terminal-status-02.json', 'native-terminals/qualification-terminal-status-02.json',
                   'qualification-reference/qualification-terminal-status-02.json', 731,
                   '3325b116b998ddff0e586a3b983a2715339acb1b48e9215f5b92e9abfdde4946'),
    'report01': ('qualification-01/report.json', 'qualification/report.json',
                 'qualification-reference/qualification-01/report.json', 83735,
                 '9e564f3950575313034f55974303e56c236ac030e2c5f121d49791da0c4c09fa'),
    'source_map01': ('qualification-01/source-map.json', 'qualification/source-map.json',
                     'qualification-reference/qualification-01/source-map.json', 24278,
                     'da8cbdfef75c1c9fc5861e4fe0bd96aeb98f635e95fc122610021cd725db1d28'),
}
QUALIFICATION_OUTCOMES = {
    'qualification_failed01': ('1a1ac274e49-fc05-5286', 'failed', 1),
    'qualification02': ('1a1ac5d5a29-fc05-53d9', 'succeeded', 0),
    'rust_ci01': ('1a1ac8bfc0c-fc05-552c', 'succeeded', 0),
    'python_ci01': ('1a1ac97d8cb-fc05-55a2', 'failed', 1),
    'python_ci02': ('1a1acb64a3e-fc05-5682', 'succeeded', 0),
}
OBS_SOURCE = {'bytes': 64590, 'sha256': '52c2c2777d44d071896b6a25d5c9f178b66989e501abff63fb4fc2a01ee4b2d9'}
LIFE_SOURCE = {'bytes': 26760, 'sha256': '5a7f60e4d61ce69ed9962a47956045710908455c90fc3048035287232d4c84ce'}
HOLDER_SOURCE = {'bytes': 11374, 'sha256': '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'}
INNER_TERMINAL = {'bytes': 729, 'sha256': '3df7bbc9acc621a6c1eeaf85e4fe21870cb62ba5df0f423e2b67a6e8f236860e'}
EXPECTED_ABSENT = [XROOT + '/' + name for name in (
    'cancel-saturation-01', 'lifecycle-abba-01', 'lifecycle-campaign-01', 'lifecycle-inputs-01',
    'lifecycle-inputs-01.json', 'lifecycle-native-terminal-01.json', 'lifecycle-tool-tests-01')]


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read(path, expected=None):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, 'direct local original required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
             and before.st_size <= 16 * 1024**2, 'unsafe or oversized local original')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(before.st_size + 1)
        stamp = lambda value: {key: getattr(value, key) for key in FIELDS}
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'local original changed during read')
    finally:
        os.close(fd)
    identity = {'local_path': str(path), **pin(raw), 'descriptor_identity': stamp(before)}
    if expected is not None:
        need(all(identity[key] == expected[key] for key in ('bytes', 'sha256')), 'original pin mismatch')
    return identity, raw


def member(archive, name, expected):
    item = archive.getmember(name)
    need(item.isfile() and not item.linkname and item.size == expected['bytes'], 'fixed member type/size differs')
    with archive.extractfile(item) as stream:
        raw = stream.read(item.size + 1)
    need(pin(raw) == {key: expected[key] for key in ('bytes', 'sha256')}, 'fixed member bytes differ')
    return raw


def main():
    need(OUTPUT.parent.resolve(strict=True) == OUTPUT.parent and not os.path.lexists(OUTPUT),
         'fixed existing output parent and fresh proof required')
    inputs, selected_members = [], {}

    def bind(path, expected=None):
        identity, raw = read(path, expected)
        inputs.append(identity)
        return raw

    def fixed(row):
        return bind(WORK / row[0], {'bytes': row[1], 'sha256': row[2]})

    own_raw = bind(Path(__file__).absolute())
    fixed(REFERENCE)
    plan = json.loads(fixed(PLAN))
    need(plan['future_actual_output'] == str(OUTPUT)
         and plan['future_actual_output_schema'] == 'hepta-r28-three-companion-cross-verification/v1'
         and plan['fixed_terminal_inner'] == INNER_TERMINAL, 'original cross-binding plan differs')
    qas, manifests, payloads, archives, archive_proofs = {}, {}, {}, {}, {}
    with ExitStack() as stack:
        for group, spec in GROUPS.items():
            qa = json.loads(fixed(spec['qa']))
            need(qa['passed'] is True, 'original independent QA did not pass: ' + group)
            raw = fixed(spec['archive'])
            archive = stack.enter_context(tarfile.open(fileobj=io.BytesIO(raw), mode=spec['mode']))
            manifest_raw = member(archive, '_export-manifest.json',
                                  {'bytes': spec['manifest'][0], 'sha256': spec['manifest'][1]})
            manifest = json.loads(manifest_raw)
            if group == 'mac':
                rows = {row['path']: row for row in manifest['files']}
                need(len(rows) == len(manifest['files']) == 32, 'Mac original payload list differs')
                g = qa['groups']['formal']
                need({k: g['archive'][k] for k in ('bytes', 'sha256')} == pin(raw)
                     and g['archive_members'] == spec['members'] and g['payload_files'] == 32
                     and g['manifest_sha256'] == pin(manifest_raw)['sha256']
                     and all(g['gzip_integrity'][k] is True for k in
                             ('crc_and_isize_verified', 'exact_compressed_eof', 'single_gzip_member')),
                     'Mac archive does not bind complete original QA')
            else:
                rows = manifest['payloads']
                need(qa['archive'] == pin(raw) and qa['manifest'] == pin(manifest_raw)
                     and qa['archive_validation']['verified'] is True
                     and qa['archive_validation']['regular_members'] == spec['members']
                     and manifest['root'] == XROOT and manifest['exact_original_bytes_preserved'] is True,
                     'X230 archive does not bind complete original QA: ' + group)
            members = archive.getmembers()
            need(len(members) == spec['members'] == len(rows) + 1
                 and len({item.name for item in members}) == len(members)
                 and {item.name for item in members} == set(rows) | {'_export-manifest.json'}
                 and all(item.isfile() and not item.linkname for item in members),
                 'original verified member inventory differs: ' + group)
            qas[group], manifests[group], payloads[group], archives[group] = qa, manifest, rows, archive
            archive_proofs[group] = {'archive': pin(raw), 'manifest': pin(manifest_raw),
                                     'independent_QA': {'bytes': spec['qa'][1], 'sha256': spec['qa'][2]},
                                     'regular_members': len(members), 'payload_files': len(rows)}

        def selected(group, name, expected=None, source_path=None):
            row = payloads[group][name]
            if source_path is not None:
                need(row['source_path'] == source_path, 'original source path differs: ' + name)
            raw = member(archives[group], name, row)
            if expected is not None:
                need(pin(raw) == expected, 'fixed original body differs: ' + name)
            selected_members[group + ':' + name] = {'group': group, 'member': name, **pin(raw)}
            return raw

        qqa, pqa, mqa = (qas[k] for k in ('qualification_ci', 'performance', 'mac'))
        qm, pm, mm = (manifests[k] for k in ('qualification_ci', 'performance', 'mac'))
        need(qqa['schema'] == 'hepta-r28-qualification-ci-independent-verification/v1'
             and pqa['schema'] == 'hepta-r28-performance-independent-verification/v1'
             and mqa['schema'] == 'hepta-r28-mac-companion-independent-verification/v1'
             and qqa['original_negative_outcomes_preserved'] is True
             and qqa['performance_or_lifecycle_or_hosted_CI_inferred'] is False
             and pqa['original_observation_rejection_preserved'] is True
             and pqa['lifecycle_and_saturation_executed'] is False
             and pqa['hosted_CI_passed_inferred'] is False
             and mqa['original_negative_outcomes_preserved'] is True
             and mqa['runtime_adoption_assessed'] is False and mqa['hosted_actions_passed'] is False
             and all(x['candidate_adopted'] is False for x in (qqa, pqa, qm, pm)),
             'original outcomes or verification scope differ')
        need(qm['original_outcomes'] == qqa['original_outcomes']
             and pm['original_outcomes'] == pqa['original_outcomes']
             and qm['original_bindings'] == qqa['original_bindings']
             and pm['original_bindings'] == pqa['original_bindings'], 'original QA/manifest conclusions differ')
        outcome_proofs = {}
        need(set(qm['original_outcomes']) == set(QUALIFICATION_OUTCOMES), 'five original qualification/CI attempts differ')
        for name, (job, state, code) in QUALIFICATION_OUTCOMES.items():
            outcome = qm['original_outcomes'][name]
            native = outcome['native_outcome']
            need(outcome['executed'] is True and outcome['job_id'] == job
                 and outcome['original_report_finished'] is True and outcome['original_report_schema_matches'] is True
                 and native['state'] == state and type(native['exit_code']) is int and native['exit_code'] == code
                 and native['native_logs_lossless_complete'] is True
                 and all(native[k] is False for k in ('automatic_retry', 'cancelled', 'timed_out'))
                 and outcome['original_positive_report_and_closed_native'] is (code == 0),
                 'original negative/successful attempt changed: ' + name)
            outcome_proofs[name] = {'job_id': job, 'state': state, 'exit_code': code,
                                    'original_finished_report': True, 'complete_original_streams_verified_by_QA': True}
        need(qm['observed_absent_paths'] == [XROOT + '/python-ci-01'], 'original failed Python runner absence differs')

        links, linked_raw = {}, {}
        for label, (relative, qname, pname, size, digest) in QUALIFICATION_LINKS.items():
            expected = {'bytes': size, 'sha256': digest}
            a = selected('qualification_ci', qname, expected, XROOT + '/' + relative)
            b = selected('performance', pname, expected, XROOT + '/' + relative)
            need(a == b, 'qualification reference bytes differ between packages: ' + label)
            links[label] = {'original_path': XROOT + '/' + relative, 'qualification_ci_member': qname,
                            'performance_member': pname, **expected, 'exact_bytes_equal': True}
            linked_raw[label] = a
        preparation = json.loads(linked_raw['preparation02'])
        qualification = json.loads(linked_raw['report01'])
        qualified_map = json.loads(linked_raw['source_map01'])
        qualification_terminal = json.loads(linked_raw['terminal02'])
        need(preparation['passed'] is True and preparation['candidate_qualified'] is True
             and preparation['candidate_adopted'] is False and qualification['qualified'] is True
             and qualification_terminal['job_id'] == QUALIFICATION_OUTCOMES['qualification02'][0]
             and qualification_terminal['state'] == 'succeeded' and qualification_terminal['exit_code'] == 0
             and qualification['source_tested'] == qualification['source_after'] == preparation['source_tested'] == qualified_map
             and len(qualified_map) == 221 and len(qualification['harness_before']) == 19
             and len(qualification['stages']) == 8, 'actual qualified source/attempt differs')

        parent_raw = selected('performance', 'observation/report.json', {
            'bytes': 106682, 'sha256': '9fd45bf5f9987b849c637bdf3ed61f3b49b4f98b615dd914d16e0afa80822ba5'},
            XROOT + '/campaign-01/report.json')
        parent = json.loads(parent_raw)
        summary_raw = selected('performance', 'observation/summary.json', {
            'bytes': 13588, 'sha256': 'c1df02071f3ebecde73de47cc3fe62daef2908981486db40287a995daabf5a0c'},
            XROOT + '/campaign-01/summary.json')
        summary = json.loads(summary_raw)
        input_raw = selected('performance', 'root-receipts/campaign-inputs-01.json', {
            'bytes': 8735, 'sha256': 'baf3402f570532f2f12bd9ae3020abd4c8574fa46cb2498abd4ad4a25660f782'},
            XROOT + '/campaign-inputs-01.json')
        actual_input = json.loads(input_raw)
        need(parent['input_receipt'] == {'path': XROOT + '/campaign-inputs-01.json', **pin(input_raw)}
             and parent['summary'] == {'path': XROOT + '/campaign-01/summary.json', **pin(summary_raw)}
             and parent['passed'] is True and parent['observation_gate_passed'] is False
             and summary['observation_gate_passed'] is False and summary['performance_gates_passed'] is False
             and parent['rejection_reasons'] == summary['rejection_reasons'] == ['C1 regression gate']
             and parent['measurement_attribution_valid'] is True
             and all(parent[k] is True for k in ('source_inputs_unchanged', 'baseline_source_inputs_unchanged',
                                                'inputs_unchanged', 'correctness_stages_completed'))
             and parent['finished_utc'] and parent['qualified_source_maps_match_current_inputs'] == {'A': True, 'B': True},
             'actual completed observation rejection differs')
        source_inventory_raw = selected('performance', 'observation/source-inputs.json',
                                        {k: parent['source_inputs'][k] for k in ('bytes', 'sha256')},
                                        parent['source_inputs']['path'])
        source_inventory = json.loads(source_inventory_raw)
        need(source_inventory['file_count'] == 221 and source_inventory['root'] == XROOT + '/source'
             and {path: row['sha256'] for path, row in source_inventory['files'].items()} == qualified_map
             and source_inventory['sha256'] == parent['source_inputs_sha256'] == actual_input['source_inputs_sha256'],
             'qualified source map and measured source inventory differ')
        for label, field in (('preparation02', 'qualification_preparation'), ('terminal02', 'qualification_terminal_status')):
            descriptor = actual_input[field]
            need({k: descriptor[k] for k in ('path', 'bytes', 'sha256')}
                 == {'path': links[label]['original_path'], **pin(linked_raw[label])}, 'qualification input reference differs')
        need(actual_input['qualification_terminal_status']['job_id'] == qualification_terminal['job_id']
             and actual_input['qualification_reports'] == [{'path': links['report01']['original_path'],
                  **pin(linked_raw['report01']), 'success_field': 'qualified'}], 'qualification report input binding differs')
        for name, binary in parent['binaries']['B'].items():
            need({k: binary[k] for k in ('path', 'sha256')} == qualification['binaries'][name]
                 and {k: binary[k] for k in ('bytes', 'sha256')} == actual_input['candidate_binaries'][name],
                 'qualified and measured candidate binary identities differ')
        need(set(parent['binaries']['B']) == set(qualification['binaries']) == set(actual_input['candidate_binaries'])
             and parent['binaries']['A'] == actual_input['baseline']['binaries']
             and parent['baseline_publication_commit'] == actual_input['baseline']['publication_readback']['commit']
                == 'baab4def80be7af015b2e7a594cb302f66c4130e'
             and parent['baseline_publication_readback'] == {k: actual_input['baseline']['publication_readback'][k]
                                                             for k in ('path', 'bytes', 'sha256')},
             'accepted R24 baseline or measured binary set differs')
        c1 = [row for row in summary['cases'] if row['concurrency'] == 1]
        need(len(c1) == 1 and c1[0]['B_over_A']['calls_per_second'] == 0.920406142147403
             and c1[0]['throughput_regression_gate_passed'] is False
             and c1[0]['p95_regression_gate_passed'] is True
             and c1[0]['controller_cpu_regression_gate_passed'] is True,
             'original sole C1 throughput rejection differs')
        monitor = pqa['compiler_monitor_verification']
        need(pm['compiler_monitor_verification'] == monitor and monitor['independently_validated'] is True
             and monitor['independent_validation']['passed'] is True
             and monitor['original_audit_and_parent_bindings_match'] is True and monitor['source_bindings_match'] is True
             and monitor['unsupported_original_attribution'] is False,
             'previous independent raw monitor verification is not bound')

        terminal_raw = selected('performance', 'native-terminals/observation-native-terminal-01.json',
                                INNER_TERMINAL, XROOT + '/observation-native-terminal-01.json')
        wrapper_raw = selected('mac', 'native/observation01-terminal.json', {
            'bytes': 1064, 'sha256': 'caf70250b3408215baf89f0b588e56618bbdcbcd18517fd56e5e26a7e1799353'})
        wrapper = json.loads(wrapper_raw)
        content = wrapper['result']['content']
        need(wrapper['request'] == {'host': 'main', 'job_id': OBS_JOB}
             and wrapper['result'].get('isError', False) is False
             and len(content) == 1 and content[0]['type'] == 'text'
             and type(content[0]['text']) is str, 'original Mac status response wrapper differs')
        inner_raw = content[0]['text'].encode('utf-8')
        need(inner_raw == terminal_raw, 'sole original Mac text bytes differ from X230 terminal DTO')
        terminal = json.loads(inner_raw)
        need(terminal['job_id'] == OBS_JOB and terminal['state'] == 'succeeded'
             and type(terminal['exit_code']) is int and terminal['exit_code'] == 0
             and all(terminal[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
             and terminal['terminal_publication_protocol'] == 1
             and all(terminal[k] is False for k in ('automatic_retry', 'timed_out', 'cancelled')),
             'original observation strong native terminal differs')
        read_wrapper_raw = selected('mac', 'native/observation01-read.json', {
            'bytes': 1646, 'sha256': 'abd425abe2e3b1765d221e70ba57cd92a379bcb892931819c86805baa9b4b3bb'})
        read_wrapper = json.loads(read_wrapper_raw)
        content = read_wrapper['result']['content']
        need(read_wrapper['request'] == {'host': 'main', 'job_id': OBS_JOB, 'stdout_offset': 0,
                                         'stderr_offset': 0, 'limit': 16384}
             and read_wrapper['result'].get('isError', False) is False
             and len(content) == 1 and content[0]['type'] == 'text' and type(content[0]['text']) is str,
             'original full native read wrapper differs')
        original_read = json.loads(content[0]['text'])
        need(original_read['job_id'] == OBS_JOB, 'original read is for another job')
        streams = {}
        for stream, size in (('stdout', 299), ('stderr', 0)):
            row = original_read[stream]
            body = bytes.fromhex(row['bytes_hex'])
            need(row['offset'] == 0 and row['next_offset'] == row['size'] == len(body) == size
                 and row['eof'] is True and body.decode('utf-8') == row['text']
                 and terminal['log_bytes'][stream] == {'seen': size, 'stored': size}
                 and terminal['log_synced'][stream] is True and terminal['log_errors'][stream] is None
                 and terminal['log_truncated'][stream] is False
                 and selected('mac', 'native-decoded/observation01.' + stream) == body,
                 'original native stream/cursor/terminal bytes differ: ' + stream)
            streams[stream] = body

        staged = selected('mac', 'sources/observation01-campaign.py', OBS_SOURCE)
        need(staged == selected('mac', 'holders/observation01/remote-script.py', OBS_SOURCE)
             == selected('performance', 'campaign-tools/r28_campaign.py', OBS_SOURCE, XROOT + '/tools-02/r28_campaign.py'),
             'retained/staged/installed observation source bytes differ')
        need(selected('mac', 'sources/lifecycle01-campaign.py', LIFE_SOURCE)
             == selected('performance', 'campaign-tools/r28_lifecycle_campaign.py', LIFE_SOURCE,
                         XROOT + '/tools-02/r28_lifecycle_campaign.py'),
             'prepared but unexecuted lifecycle sources differ')
        selected('mac', 'sources/held_agent_campaign_02.py', HOLDER_SOURCE)
        holder_raw = selected('mac', 'holders/observation01/report.json', {
            'bytes': 9075, 'sha256': '288a748ae91e84b409b2bbd903c51bc83d5faca17963f0ddbc638d56a17ea8c9'})
        holder = json.loads(holder_raw)
        need(holder['remote_script_sha256'] == parent['launcher_sha256'] == actual_input['launcher_sha256']
                == OBS_SOURCE['sha256'] and holder['holder_script_sha256'] == HOLDER_SOURCE['sha256']
             and holder['passed'] is True and holder['remote_returncode'] == terminal['exit_code'] == 0
             and holder['automatic_ssh_retries'] == 0 and holder['timeout_seconds'] == 3600
             and holder['services_modified'] is False and holder['finished_utc']
             and all(holder[k] is True for k in ('owned_agent_reaped', 'owned_agent_directory_absent_after_context',
                                                'owned_agent_socket_absent_after_context')),
             'original source/holder outcome/cleanup differs')
        log_files = holder['log_files']
        need(len(log_files) == 21 and len({row['file'] for row in log_files}) == 21, 'original holder log inventory differs')
        for log in log_files:
            need('/' not in log['file'] and log['file'] not in ('.', '..'), 'non-flat original holder log')
            selected('mac', 'holders/observation01/' + log['file'], {k: log[k] for k in ('bytes', 'sha256')})
        need({name for name in payloads['mac'] if name.startswith('holders/observation01/')}
             == {'holders/observation01/' + row['file'] for row in log_files}
                | {'holders/observation01/report.json'}, 'extra or missing original holder file')
        forwarded = selected('mac', 'holders/observation01/forwarded.stdout')
        forwarded_stderr = selected('mac', 'holders/observation01/forwarded.stderr')
        footer = json.loads(forwarded.decode('utf-8').splitlines()[-1])
        expected_footer = {'error': None, 'observation_gate_passed': False, 'passed': True,
                           'rejection_reasons': ['C1 regression gate'], 'report': XROOT + '/campaign-01/report.json'}
        need(footer == expected_footer == mm['campaigns']['observation01']['remote_final_line']
             and footer['passed'] is parent['passed']
             and footer['observation_gate_passed'] is parent['observation_gate_passed']
             and footer['rejection_reasons'] == parent['rejection_reasons'],
             'original forwarded footer differs from X230 parent outcome')
        native_lines = streams['stdout'].decode('utf-8').splitlines()
        need(len(native_lines) == 2 and json.loads(native_lines[0]) == {
                'phase': 'owned_agent_ready', 'identity_count': 5, 'remote_script_sha256': OBS_SOURCE['sha256']}
             and json.loads(native_lines[1]) == mm['campaigns']['observation01']['native_holder_final_line'] == {
                'passed': True, 'remote_returncode': 0, 'owned_agent_reaped': True,
                'report': MAC_ROOT + '/hepta-runtime-r28-observation-evidence-01/report.json'},
             'original native ready/terminal footer differs')

        mac_base = WORK / 'benchmark-r28/mac-companion-operations-01/assembled-01'
        mac_manifest_original = bind(mac_base / 'formal/manifest.json', {
            'bytes': GROUPS['mac']['manifest'][0], 'sha256': GROUPS['mac']['manifest'][1]})
        need(member(archives['mac'], '_export-manifest.json', pin(mac_manifest_original)) == mac_manifest_original,
             'original transported Mac manifest differs')
        receipt_raw = bind(mac_base / 'receipt.json', {
            'bytes': 3755, 'sha256': 'd46b9066570399926ad05117c0cfa5a960371e52733ba8bb3f34555d91f41916'})
        receipt = json.loads(receipt_raw)
        mac_input = json.loads(selected('mac', 'inputs/actual-input-01.json'))
        need(receipt['passed'] is True and receipt['capture_complete'] is True
             and receipt['source_inputs_unchanged'] is True
             and pin(receipt_raw)['sha256'] == mqa['receipt_sha256']
             and receipt['original_outcomes'] == mm['campaigns'] == mqa['original_outcomes']
             and mac_input['holders'] == mm['declarations'] == mqa['declarations']
             and mac_input['all_originals_terminal_or_unexecuted'] is True,
             'original complete Mac capture/input/outcome binding differs')
        collector = selected('mac', 'tools/collect_mac_companion_01.py')
        consumer = selected('mac', 'tools/verify_mac_companion_01.py')
        need(pin(collector)['sha256'] == receipt['source_script_pins']['collector_sha256']
                == mqa['source_script_pins']['collector_sha256']
                == '457c62b162ccbd7463254e4c3ed42a969be8cca2b307481e40d77b375340bf46'
             and pin(consumer)['sha256'] == receipt['source_script_pins']['consumer_sha256']
                == mqa['source_script_pins']['consumer_sha256']
                == 'ad082087cae141302fd770c77bafe4d0fe64e62b582daccb32e7fd7d9404e5d6',
             'reviewed collector final absence predicate is not source bound')
        life = mac_input['holders']['lifecycle01']
        need(life['executed'] is False and all(life[k] is None for k in
                                              ('job_id', 'read_sha256', 'report_sha256', 'terminal_sha256'))
             and life['reason'] and mm['campaign_names'] == ['observation01']
             and mm['included_original_holders_complete'] is True
             and not any(name.startswith(('holders/lifecycle01/', 'native/lifecycle01-', 'native-decoded/lifecycle01.'))
                         for name in payloads['mac'])
             and pm['observed_absent_paths'] == EXPECTED_ABSENT
             and pm['original_outcomes']['lifecycle01']['executed'] is False
             and pm['original_outcomes']['lifecycle01']['success_inferred'] is False
             and pm['original_bindings']['lifecycle_executed'] is False
             and pm['original_bindings']['saturation_executed'] is False
             and pqa['candidate_disposition'] == pm['candidate_disposition']
                == 'observation_rejected_lifecycle_and_saturation_not_executed',
             'original unexecuted lifecycle/saturation evidence differs')

    for expected in inputs:
        need(read(expected['local_path'], expected)[0] == expected, 'original input changed after cross-binding')
    result = {
        'schema': 'hepta-r28-three-companion-cross-verification/v1', 'passed': True,
        'source': {'local_path': str(Path(__file__).absolute()), **pin(own_raw)},
        'archives': {group: proof['archive'] for group, proof in archive_proofs.items()},
        'independent_verifications': {group: proof['independent_QA'] for group, proof in archive_proofs.items()},
        'Mac_wrapper_inner_text_bytes_compared_without_reencoding': True,
        'three_verified_archive_identities': archive_proofs,
        'qualification_four_exact_original_links': links,
        'five_original_qualification_and_CI_outcomes': outcome_proofs,
        'qualified_and_measured_source_files': 221,
        'qualified_and_measured_candidate_binary_identities_match': True,
        'accepted_baseline_commit': 'baab4def80be7af015b2e7a594cb302f66c4130e',
        'observation': {
            'original_job_id': OBS_JOB, 'native_state': 'succeeded', 'native_exit_code': 0,
            'native_stdout': pin(streams['stdout']), 'native_stderr': pin(streams['stderr']),
            'terminal_outer_wrapper': pin(wrapper_raw), 'terminal_original_inner_text': pin(terminal_raw),
            'native_terminal_exact_inner_UTF8_bytes_equal': True, 'JSON_reencoding_used_for_terminal_equality': False,
            'Mac_retained_and_staged_source_equal_X230_installed_source': True,
            'original_holder_report': pin(holder_raw), 'original_holder_logs': 21,
            'forwarded_stdout': pin(forwarded), 'forwarded_stderr': pin(forwarded_stderr),
            'forwarded_complete_streams_bound_to_original_holder': True,
            'forwarded_footer_matches_X230_parent': True,
            'X230_report_body_hash_present_in_Mac_footer': False,
            'X230_parent': pin(parent_raw), 'X230_summary': pin(summary_raw), 'X230_actual_input': pin(input_raw),
            'original_holder_passed': True, 'original_parent_passed': True,
            'original_observation_gate_passed': False, 'original_rejection_reasons': ['C1 regression gate'],
            'original_C1_throughput_ratio': c1[0]['B_over_A']['calls_per_second'],
            'raw_monitor_independent_QA_bound': True,
            'original_owned_agent_and_paths_closed': True,
        },
        'nonexecution': {
            'lifecycle_executed': False, 'saturation_executed': False,
            'X230_original_observed_absent_paths': EXPECTED_ABSENT,
            'Mac_declared_unexecuted_evidence_directory': MAC_ROOT + '/hepta-runtime-r28-lifecycle-evidence-01',
            'Mac_absence_basis': 'Pinned original collector requires absence before and after capture; original complete capture receipt, unchanged inputs and independent QA are bound. No standalone live probe is invented.',
            'Mac_collector_source_sha256': pin(collector)['sha256'],
            'prepared_lifecycle_source_equal_across_packages': True,
        },
        'selected_original_members': selected_members, 'original_inputs': inputs,
        'original_failed_qualification_and_Python_preflight_preserved': True,
        'original_observation_rejection_preserved': True, 'candidate_adopted': False,
        'native_original_request_result_custody_separate_required': True,
        'current_host_probe_performed': False, 'new_performance_reanalysis_performed': False,
        'archive_code_executed': False, 'archive_members_extracted_to_paths': False,
        'workloads_or_tests_reexecuted': False, 'hosted_CI_passed_inferred': False,
        'host_RPC_calls': 0, 'git_mutations': 0,
    }
    raw = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with OUTPUT.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'passed': True, 'proof': {'local_path': str(OUTPUT), **pin(raw)},
                      'archives': 3, 'original_observation_gate_passed': False,
                      'lifecycle_and_saturation_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
