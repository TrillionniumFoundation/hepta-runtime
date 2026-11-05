#!/usr/bin/env python3
"""Bind three completed R29 evidence archives without executing archived code.

Pinned original independent QAs establish full compression/member verification.
This check links exact original receipts, two holder streams and the preserved
lifecycle rejection; it does not rerun a workload or infer hosted CI or adoption.
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
OUTPUT = WORK / 'r25-integration-audit/r29-native-custody-final-01/three-companion-cross-verification-01.json'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
PLAN = {'local_path': 'r25-lifecycle-audit/r29-cross-package-verification-01/cross-plan-01.json', 'bytes': 10870, 'sha256': '11d5b55581024dce9f2555791e0ef4d37aaed9b0f46f579b99501022cd5cb91a'}


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
        return bind(WORK / row['local_path'], {k: row[k] for k in ('bytes', 'sha256')})

    own_raw = bind(Path(__file__).absolute())
    plan = json.loads(fixed(PLAN))
    need(plan['schema'] == 'hepta-r29-three-companion-cross-plan/v1'
         and plan['output_schema'] == 'hepta-r29-three-companion-cross-verification/v1'
         and plan['output'] == str(OUTPUT), 'fixed cross-binding plan differs')
    fixed(plan['reference'])
    root, groups = plan['root'], plan['groups']
    need(root == '/home/qian/hepta-runtime-optimization-20261105-r29'
         and set(groups) == {'qualification_ci', 'performance', 'mac'}, 'fixed scope differs')
    qas, manifests, payloads, archives, archive_proofs = {}, {}, {}, {}, {}
    with ExitStack() as stack:
        for group, spec in groups.items():
            qa = json.loads(fixed(spec['qa']))
            need(qa['passed'] is True, 'original independent QA did not pass: ' + group)
            raw = fixed(spec['archive'])
            archive = stack.enter_context(tarfile.open(fileobj=io.BytesIO(raw), mode=spec['mode']))
            manifest_raw = member(archive, '_export-manifest.json', spec['manifest'])
            manifest = json.loads(manifest_raw)
            if group == 'mac':
                rows = {row['path']: row for row in manifest['files']}
                need(len(rows) == len(manifest['files']) == 58, 'Mac original payload list differs')
                g = qa['groups']['formal']
                need({k: g['archive'][k] for k in ('bytes', 'sha256')} == pin(raw)
                     and g['archive_members'] == spec['members'] and g['payload_files'] == 58
                     and g['manifest_sha256'] == pin(manifest_raw)['sha256']
                     and all(g['gzip_integrity'][k] is True for k in
                             ('crc_and_isize_verified', 'exact_compressed_eof', 'single_gzip_member')),
                     'Mac archive does not bind complete original QA')
            else:
                rows = manifest['payloads']
                need(qa['archive'] == pin(raw) and qa['manifest'] == pin(manifest_raw)
                     and qa['archive_validation']['verified'] is True
                     and qa['archive_validation']['regular_members'] == spec['members']
                     and manifest['root'] == root and manifest['exact_original_bytes_preserved'] is True,
                     'X230 archive does not bind complete original QA: ' + group)
            members = archive.getmembers()
            need(len(members) == spec['members'] == len(rows) + 1
                 and len({item.name for item in members}) == len(members)
                 and {item.name for item in members} == set(rows) | {'_export-manifest.json'}
                 and all(item.isfile() and not item.linkname for item in members),
                 'original verified member inventory differs: ' + group)
            qas[group], manifests[group], payloads[group], archives[group] = qa, manifest, rows, archive
            archive_proofs[group] = {'archive': pin(raw), 'manifest': pin(manifest_raw),
                                    'independent_QA': {k: spec['qa'][k] for k in ('bytes', 'sha256')},
                                    'regular_members': len(members), 'payload_files': len(rows)}

        def selected(group, name, expected=None, source_path=None):
            row = payloads[group][name]
            if source_path is not None:
                need(row['source_path'] == source_path, 'original source path differs: ' + name)
            raw = member(archives[group], name, row)
            if expected is not None:
                need(pin(raw) == {k: expected[k] for k in ('bytes', 'sha256')},
                     'fixed original body differs: ' + name)
            selected_members[group + ':' + name] = {'group': group, 'member': name, **pin(raw)}
            return raw

        qqa, pqa, mqa = (qas[k] for k in ('qualification_ci', 'performance', 'mac'))
        qm, pm, mm = (manifests[k] for k in ('qualification_ci', 'performance', 'mac'))
        need(qqa['schema'] == 'hepta-r29-qualification-ci-independent-verification/v1'
             and pqa['schema'] == 'hepta-r29-performance-independent-verification/v1'
             and mqa['schema'] == 'hepta-r29-mac-companion-independent-verification/v1'
             and qqa['original_negative_outcomes_preserved'] is True
             and qqa['performance_or_lifecycle_or_hosted_CI_inferred'] is False
             and pqa['original_outcomes_preserved'] is True and pqa['hosted_CI_passed_inferred'] is False
             and mqa['original_negative_outcomes_preserved'] is True
             and mqa['runtime_adoption_assessed'] is False and mqa['hosted_actions_passed'] is False
             and all(x['candidate_adopted'] is False for x in (qqa, pqa, qm, pm)),
             'original outcomes or verification scope differ')
        need(qm['original_outcomes'] == qqa['original_outcomes']
             and pm['original_outcomes'] == pqa['original_outcomes']
             and qm['original_bindings'] == qqa['original_bindings']
             and pm['original_bindings'] == pqa['original_bindings'], 'original QA/manifest conclusions differ')
        outcome_proofs = {}
        need(set(qm['original_outcomes']) == set(plan['qualification_jobs']), 'three original qualification/CI attempts differ')
        for name, job in plan['qualification_jobs'].items():
            outcome = qm['original_outcomes'][name]
            native = outcome['native_outcome']
            need(outcome['executed'] is True and outcome['job_id'] == job
                 and outcome['original_report_finished'] is True and outcome['original_report_schema_matches'] is True
                 and native['state'] == 'succeeded' and type(native['exit_code']) is int and native['exit_code'] == 0
                 and native['native_logs_lossless_complete'] is True
                 and all(native[k] is False for k in ('automatic_retry', 'cancelled', 'timed_out'))
                 and outcome['original_positive_report_and_closed_native'] is True,
                 'original successful attempt changed: ' + name)
            outcome_proofs[name] = {'job_id': job, 'state': 'succeeded', 'exit_code': 0,
                                   'original_finished_report': True, 'complete_original_streams_verified_by_QA': True}
        need(qm['observed_absent_paths'] == [], 'unexpected qualification/CI original absence')

        links, linked_raw = {}, {}
        for label, row in plan['qualification_links'].items():
            expected = {k: row[k] for k in ('bytes', 'sha256')}
            a = selected('qualification_ci', row['qc_member'], expected, row['original_path'])
            b = selected('performance', row['performance_member'], expected, row['original_path'])
            need(a == b, 'qualification original bytes differ between packages: ' + label)
            links[label] = {**row, 'exact_bytes_equal': True}
            linked_raw[label] = a
        preparation = json.loads(linked_raw['preparation01'])
        qualification = json.loads(linked_raw['report01'])
        qualified_map = json.loads(linked_raw['source_map01'])
        qualification_terminal = json.loads(linked_raw['terminal01'])
        need(preparation['passed'] is True and preparation['candidate_qualified'] is True
             and preparation['candidate_adopted'] is False and qualification['qualified'] is True
             and qualification_terminal['job_id'] == plan['qualification_jobs']['qualification01']
             and qualification_terminal['state'] == 'succeeded' and qualification_terminal['exit_code'] == 0
             and qualification['source_tested'] == qualification['source_after'] == preparation['source_tested'] == qualified_map
             and len(qualified_map) == 221 and len(qualification['harness_before']) == 19
             and len(qualification['stages']) == 8, 'actual qualified source/attempt differs')

        parents, parent_raws, actual_inputs, input_raws, campaign_proofs = {}, {}, {}, {}, {}
        need(set(plan['campaigns']) == set(pm['original_outcomes']) == {'observation01', 'lifecycle01'},
             'two original campaign outcomes required')
        for name, spec in plan['campaigns'].items():
            parent_raw = selected('performance', spec['parent_member'], spec['parent'], spec['parent_path'])
            input_raw = selected('performance', spec['input_member'], spec['input'], spec['input_path'])
            parent, actual_input = json.loads(parent_raw), json.loads(input_raw)
            parents[name], parent_raws[name] = parent, parent_raw
            actual_inputs[name], input_raws[name] = actual_input, input_raw
            outcome = pm['original_outcomes'][name]
            native = outcome['native_outcome']
            positive = spec['exit_code'] == 0
            need(outcome['executed'] is True and outcome['job_id'] == spec['job_id']
                 and outcome['original_report_finished'] is True and outcome['original_report_schema_matches'] is True
                 and native['state'] == spec['state'] and type(native['exit_code']) is int
                 and native['exit_code'] == spec['exit_code'] and native['native_logs_lossless_complete'] is True
                 and all(native[k] is False for k in ('automatic_retry', 'cancelled', 'timed_out'))
                 and outcome['original_positive_report_and_closed_native'] is positive,
                 'original executed campaign result differs: ' + name)
            need(parent['input_receipt'] == {'path': spec['input_path'], **pin(input_raw)}
                 and parent['passed'] is positive and parent['measurement_attribution_valid'] is True
                 and all(parent[k] is True for k in ('source_inputs_unchanged', 'baseline_source_inputs_unchanged', 'inputs_unchanged'))
                 and parent['finished_utc'] and parent['qualified_source_maps_match_current_inputs'] == {'A': True, 'B': True},
                 'original completed campaign/source binding differs: ' + name)
            source_inventory_raw = selected('performance', spec['inventory_member'], parent['source_inputs'],
                                            parent['source_inputs']['path'])
            source_inventory = json.loads(source_inventory_raw)
            need(source_inventory['file_count'] == 221 and source_inventory['root'] == root + '/source'
                 and {path: row['sha256'] for path, row in source_inventory['files'].items()} == qualified_map
                 and source_inventory['sha256'] == parent['source_inputs_sha256'] == actual_input['source_inputs_sha256'],
                 'qualified source map and measured source inventory differ: ' + name)
            for label, field in (('preparation01', 'qualification_preparation'), ('terminal01', 'qualification_terminal_status')):
                need({k: actual_input[field][k] for k in ('path', 'bytes', 'sha256')}
                     == {'path': links[label]['original_path'], **pin(linked_raw[label])},
                     'qualification input reference differs: ' + name)
            need(actual_input['qualification_terminal_status']['job_id'] == qualification_terminal['job_id'],
                 'qualification original job differs: ' + name)
            report_binding = {'path': links['report01']['original_path'], **pin(linked_raw['report01'])}
            if name == 'observation01':
                need(actual_input['qualification_reports'] == [{**report_binding, 'success_field': 'qualified'}],
                     'observation qualification report binding differs')
            else:
                need(actual_input['qualification_report'] == report_binding, 'lifecycle qualification report binding differs')
            for binary_name, binary in parent['binaries']['B'].items():
                need({k: binary[k] for k in ('path', 'sha256')} == qualification['binaries'][binary_name]
                     and {k: binary[k] for k in ('bytes', 'sha256')} == actual_input['candidate_binaries'][binary_name],
                     'qualified and measured candidate binaries differ: ' + name)
            need(set(parent['binaries']['B']) == set(qualification['binaries']) == set(actual_input['candidate_binaries']),
                 'candidate binary inventory differs: ' + name)
            monitor = pqa['compiler_monitor_verification'][name]
            need(pm['compiler_monitor_verification'][name] == monitor and monitor['independently_validated'] is True
                 and monitor['independent_validation']['passed'] is True
                 and monitor['original_audit_and_parent_bindings_match'] is True and monitor['source_bindings_match'] is True
                 and monitor['unsupported_original_attribution'] is False and monitor['raw_ledger_present'] is True,
                 'previous independent raw monitor verification is not bound: ' + name)
            prefix = spec['parent_member'].rsplit('/', 1)[0]
            for field, filename in (('ledger', 'compiler-monitor.json'), ('independent_audit', 'compiler-monitor.audit.json')):
                descriptor = parent['compiler_monitor'][field]
                selected('performance', prefix + '/' + filename, descriptor, descriptor['path'])

            terminal_raw = selected('performance', 'native-terminals/' + spec['short'] + '-native-terminal-01.json',
                                    spec['terminal'], root + '/' + spec['short'] + '-native-terminal-01.json')
            mac_terminal_raw = selected('mac', 'native/' + name + '-terminal.json', spec['terminal'])
            wrapper_raw = fixed(spec['status_wrapper'])
            wrapper = json.loads(wrapper_raw)
            content = wrapper['result']['content']
            need(wrapper['request'] == {'host': 'main', 'job_id': spec['job_id']}
                 and wrapper['result'].get('isError', False) is False
                 and len(content) == 1 and content[0]['type'] == 'text' and type(content[0]['text']) is str,
                 'original Mac status wrapper differs: ' + name)
            inner_raw = content[0]['text'].encode('utf-8')
            need(inner_raw == terminal_raw == mac_terminal_raw == fixed(spec['terminal']),
                 'original Mac text bytes differ from Mac archive/X230 terminal: ' + name)
            terminal = json.loads(inner_raw)
            need(terminal['job_id'] == spec['job_id'] and terminal['state'] == spec['state']
                 and type(terminal['exit_code']) is int and terminal['exit_code'] == spec['exit_code']
                 and all(terminal[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
                 and terminal['terminal_publication_protocol'] == 1
                 and all(terminal[k] is False for k in ('automatic_retry', 'timed_out', 'cancelled')),
                 'original strong native terminal differs: ' + name)
            read_wrapper_raw = fixed(spec['read_wrapper'])
            read_wrapper = json.loads(read_wrapper_raw)
            content = read_wrapper['result']['content']
            need(read_wrapper['request'] == {'host': 'main', 'job_id': spec['job_id'], 'stdout_offset': 0,
                                             'stderr_offset': 0, 'limit': 16384}
                 and read_wrapper['result'].get('isError', False) is False
                 and len(content) == 1 and content[0]['type'] == 'text' and type(content[0]['text']) is str,
                 'original full native read wrapper differs: ' + name)
            original_read_raw = content[0]['text'].encode('utf-8')
            need(original_read_raw == selected('mac', 'native/' + name + '-read.json', spec['read']) == fixed(spec['read']),
                 'original native read text differs from Mac archived DTO: ' + name)
            original_read = json.loads(original_read_raw)
            need(original_read['job_id'] == spec['job_id'], 'original read is for another job: ' + name)
            streams = {}
            for stream, size in (('stdout', spec['native_stdout_bytes']), ('stderr', 0)):
                row = original_read[stream]
                body = bytes.fromhex(row['bytes_hex'])
                need(row['offset'] == 0 and row['next_offset'] == row['size'] == len(body) == size
                     and row['eof'] is True and body.decode('utf-8') == row['text']
                     and terminal['log_bytes'][stream] == {'seen': size, 'stored': size}
                     and terminal['log_synced'][stream] is True and terminal['log_errors'][stream] is None
                     and terminal['log_truncated'][stream] is False
                     and selected('mac', 'native-decoded/' + name + '.' + stream) == body,
                     'original native stream/cursor/terminal bytes differ: ' + name + ':' + stream)
                streams[stream] = body

            staged = selected('mac', 'sources/' + name + '-campaign.py', spec['source'])
            need(staged == selected('mac', 'holders/' + name + '/remote-script.py', spec['source'])
                 == selected('performance', spec['source_member'], spec['source'], spec['source_path']),
                 'retained/staged/installed launcher bytes differ: ' + name)
            selected('mac', 'sources/held_agent_campaign_02.py', plan['holder_source'])
            holder_raw = selected('mac', 'holders/' + name + '/report.json', spec['holder'])
            need(holder_raw == fixed(spec['holder']), 'Mac original report body differs: ' + name)
            holder = json.loads(holder_raw)
            need(holder['remote_script_sha256'] == parent['launcher_sha256'] == actual_input['launcher_sha256']
                    == spec['source']['sha256'] and holder['holder_script_sha256'] == plan['holder_source']['sha256']
                 and holder['passed'] is positive and holder['remote_returncode'] == terminal['exit_code'] == spec['exit_code']
                 and holder['automatic_ssh_retries'] == 0 and holder['timeout_seconds'] == 3600
                 and holder['services_modified'] is False and holder['finished_utc']
                 and all(holder[k] is True for k in ('owned_agent_reaped', 'owned_agent_directory_absent_after_context',
                                                    'owned_agent_socket_absent_after_context')),
                 'original source/holder outcome/cleanup differs: ' + name)
            log_files = holder['log_files']
            need(len(log_files) == 21 and len({row['file'] for row in log_files}) == 21,
                 'original holder log inventory differs: ' + name)
            for log in log_files:
                need('/' not in log['file'] and log['file'] not in ('.', '..'), 'non-flat original holder log')
                selected('mac', 'holders/' + name + '/' + log['file'], log)
            need({key for key in payloads['mac'] if key.startswith('holders/' + name + '/')}
                 == {'holders/' + name + '/' + row['file'] for row in log_files} | {'holders/' + name + '/report.json'},
                 'extra or missing original holder file: ' + name)
            forwarded = selected('mac', 'holders/' + name + '/forwarded.stdout')
            forwarded_stderr = selected('mac', 'holders/' + name + '/forwarded.stderr')
            footer = json.loads(forwarded.decode('utf-8').splitlines()[-1])
            expected_footer = {'passed': positive, 'report': spec['parent_path']}
            if name == 'observation01':
                expected_footer.update(error=None, observation_gate_passed=True, rejection_reasons=[])
            else:
                expected_footer.update(error=parent['error'], adoption_passed=False)
            need(footer == expected_footer == mm['campaigns'][name]['remote_final_line']
                 and footer['passed'] is parent['passed'], 'original forwarded footer differs from parent: ' + name)
            native_lines = streams['stdout'].decode('utf-8').splitlines()
            need(len(native_lines) == 2 and json.loads(native_lines[0]) == {
                    'phase': 'owned_agent_ready', 'identity_count': 5, 'remote_script_sha256': spec['source']['sha256']}
                 and json.loads(native_lines[1]) == mm['campaigns'][name]['native_holder_final_line'] == {
                    'passed': positive, 'remote_returncode': spec['exit_code'], 'owned_agent_reaped': True,
                    'report': spec['mac_directory'] + '/report.json'},
                 'original native ready/terminal footer differs: ' + name)
            declaration = mm['declarations'][name]
            need(declaration['executed'] is True and declaration['job_id'] == spec['job_id']
                 and declaration['terminal_sha256'] == pin(terminal_raw)['sha256']
                 and declaration['read_sha256'] == pin(original_read_raw)['sha256']
                 and declaration['report_sha256'] == pin(holder_raw)['sha256']
                 and mm['campaigns'][name]['current_owned_directory_absent'] is True
                 and mm['campaigns'][name]['current_owned_socket_absent'] is True,
                 'original Mac declaration/cleanup differs: ' + name)
            campaign_proofs[name] = {
                'original_job_id': spec['job_id'], 'native_state': spec['state'], 'native_exit_code': spec['exit_code'],
                'native_stdout': pin(streams['stdout']), 'native_stderr': pin(streams['stderr']),
                'terminal_outer_wrapper': pin(wrapper_raw), 'terminal_original_inner_text': pin(terminal_raw),
                'read_outer_wrapper': pin(read_wrapper_raw), 'read_original_inner_text': pin(original_read_raw),
                'native_terminal_and_read_exact_inner_UTF8_bytes_equal': True,
                'JSON_reencoding_used_for_equality': False,
                'Mac_retained_and_staged_source_equal_X230_installed_source': True,
                'original_holder_report': pin(holder_raw), 'original_holder_logs': 21,
                'forwarded_stdout': pin(forwarded), 'forwarded_stderr': pin(forwarded_stderr),
                'forwarded_complete_streams_bound_to_original_holder': True,
                'forwarded_footer_matches_X230_parent': True,
                'X230_report_body_hash_present_in_Mac_footer': False,
                'X230_parent': pin(parent_raw), 'X230_actual_input': pin(input_raw),
                'original_holder_passed': positive, 'original_parent_passed': positive,
                'raw_monitor_independent_QA_bound': True,
                'original_owned_agent_and_paths_closed': True,
            }

        obs, life = parents['observation01'], parents['lifecycle01']
        oi, li = actual_inputs['observation01'], actual_inputs['lifecycle01']
        summary_spec = plan['additional_members']['observation/summary.json']
        summary_raw = selected('performance', 'observation/summary.json', summary_spec, summary_spec['source_path'])
        summary = json.loads(summary_raw)
        need(obs['summary'] == {'path': summary_spec['source_path'], **pin(summary_raw)}
             and obs['observation_gate_passed'] is True and summary['observation_gate_passed'] is True
             and summary['performance_gates_passed'] is True and obs['correctness_stages_completed'] is True
             and obs['rejection_reasons'] == summary['rejection_reasons'] == []
             and obs['binaries']['A'] == oi['baseline']['binaries']
             and obs['baseline_publication_commit'] == oi['baseline']['publication_readback']['commit']
                == plan['accepted_baseline_commit']
             and obs['baseline_publication_readback'] == {k: oi['baseline']['publication_readback'][k]
                                                        for k in ('path', 'bytes', 'sha256')},
             'original passed observation or accepted R24 baseline differs')
        need(life['binaries'] == obs['binaries']
             and li['observation_campaign'] == {'path': plan['campaigns']['observation01']['parent_path'],
                                               **pin(parent_raws['observation01'])}
             and life['observation_compiler_monitor_gate'] == li['materialization']['observation_compiler_monitor_gate']
             and life['observation_compiler_monitor_gate']['passed'] is True
             and life['observation_compiler_monitor_gate']['ledger'] == obs['compiler_monitor']['ledger']
             and life['observation_compiler_monitor_gate']['independent_audit'] == obs['compiler_monitor']['independent_audit']
             and life['adoption_passed'] is False and life['error'] == {
                 'reason': 'normal-lifecycle-abba returned nonzero; original output retained', 'type': 'RuntimeError'}
             and [(row['name'], row['returncode']) for row in life['stages']]
                 == [('lifecycle-tool-tests', 0), ('normal-lifecycle-abba', 1)],
             'actual observation-to-lifecycle admission or original rejection differs')
        for name, parent in parents.items():
            need(all(row['waited_and_reaped'] is True and row['owned_process_absent'] is True
                     and row['owned_process_group_absent'] is True for row in parent['stages']),
                 'original parent stage cleanup differs: ' + name)
        normal_spec = plan['additional_members']['lifecycle-abba/report.json']
        normal_raw = selected('performance', 'lifecycle-abba/report.json', normal_spec, normal_spec['source_path'])
        gate_spec = plan['additional_members']['lifecycle-abba/gates.json']
        gates_raw = selected('performance', 'lifecycle-abba/gates.json', gate_spec, gate_spec['source_path'])
        original_output_bindings = life['stages'][1]['output_bindings']
        need({'path': normal_spec['source_path'], **pin(normal_raw)} in original_output_bindings
             and {'path': gate_spec['source_path'], **pin(gates_raw)} in original_output_bindings,
             'original normal lifecycle report/gates are not parent-bound')
        gates = json.loads(gates_raw)
        required_failures = [[name, gate] for name, row in gates['comparisons'].items()
                             if row['adoption_required'] is True
                             for gate, passed in row['gates'].items() if passed is False]
        need(gates['verified'] is True and gates['passed'] is False
             and required_failures == [['concurrent_cancel', 'throughput']]
             and gates['comparisons']['concurrent_cancel']['B_over_A_rpc_per_second'] == 0.9235250428578928
             and gates['comparisons']['same_key_after_cancel']['adoption_required'] is False
             and pm['observed_absent_paths'] == plan['expected_absent_paths'] == [root + '/cancel-saturation-01']
             and pm['original_bindings']['campaigns']['lifecycle01']['saturation_stage_entered'] is False
             and pm['original_bindings']['campaigns']['lifecycle01']['saturation_audit_stage_entered'] is False
             and pqa['candidate_disposition'] == pm['candidate_disposition']
                == 'lifecycle_failed_incomplete_or_rejected_original_retained',
             'original required cancellation rejection/saturation absence differs')

        mac_manifest_original = fixed(plan['mac_manifest'])
        need(member(archives['mac'], '_export-manifest.json', pin(mac_manifest_original)) == mac_manifest_original,
             'original transported Mac manifest differs')
        receipt_raw = fixed(plan['mac_receipt'])
        receipt = json.loads(receipt_raw)
        mac_input = json.loads(selected('mac', 'inputs/actual-input-01.json'))
        need(receipt['passed'] is True and receipt['capture_complete'] is True
             and receipt['source_inputs_unchanged'] is True
             and pin(receipt_raw)['sha256'] == mqa['receipt_sha256']
             and receipt['original_outcomes'] == mm['campaigns'] == mqa['original_outcomes']
             and mac_input['holders'] == mm['declarations'] == mqa['declarations']
             and mac_input['all_originals_terminal_or_unexecuted'] is True
             and set(mm['campaign_names']) == {'observation01', 'lifecycle01'} and len(mm['campaign_names']) == 2
             and mm['included_original_holders_complete'] is True,
             'original complete Mac capture/input/outcome binding differs')
        collector = selected('mac', 'tools/collect_mac_companion_01.py')
        consumer = selected('mac', 'tools/verify_mac_companion_01.py')
        need(pin(collector)['sha256'] == receipt['source_script_pins']['collector_sha256']
                == mqa['source_script_pins']['collector_sha256'] == plan['collector_sha256']
             and pin(consumer)['sha256'] == receipt['source_script_pins']['consumer_sha256']
                == mqa['source_script_pins']['consumer_sha256'] == plan['consumer_sha256'],
             'reviewed Mac collector/consumer are not source bound')

    for expected in inputs:
        need(read(expected['local_path'], expected)[0] == expected, 'original input changed after cross-binding')
    result = {
        'schema': 'hepta-r29-three-companion-cross-verification/v1', 'passed': True,
        'source': {'local_path': str(Path(__file__).absolute()), **pin(own_raw)},
        'archives': {group: proof['archive'] for group, proof in archive_proofs.items()},
        'independent_verifications': {group: proof['independent_QA'] for group, proof in archive_proofs.items()},
        'Mac_wrapper_inner_text_bytes_compared_without_reencoding': True,
        'three_verified_archive_identities': archive_proofs,
        'qualification_four_exact_original_links': links,
        'three_original_qualification_and_CI_outcomes': outcome_proofs,
        'qualified_and_measured_source_files': 221,
        'qualified_and_measured_candidate_binary_identities_match': True,
        'accepted_baseline_commit': plan['accepted_baseline_commit'],
        'campaigns': campaign_proofs,
        'original_observation_gate_passed': True,
        'original_lifecycle_rejection_preserved': True,
        'original_required_lifecycle_gate_failures': required_failures,
        'original_concurrent_cancel_throughput_ratio': gates['comparisons']['concurrent_cancel']['B_over_A_rpc_per_second'],
        'observation_to_lifecycle_original_admission_bound': True,
        'saturation_submitted': False,
        'X230_original_observed_absent_paths': plan['expected_absent_paths'],
        'original_summary': pin(summary_raw), 'original_normal_lifecycle_report': pin(normal_raw),
        'original_normal_lifecycle_gates': pin(gates_raw),
        'selected_original_members': selected_members, 'original_inputs': inputs,
        'candidate_adopted': False,
        'native_original_request_result_custody_separate_required': True,
        'current_host_probe_performed': False, 'new_performance_reanalysis_performed': False,
        'archive_code_executed': False, 'archive_members_extracted_to_paths': False,
        'workloads_or_tests_reexecuted': False, 'hosted_CI_passed_inferred': False,
        'cross_host_clock_ordering_inferred': False,
        'host_RPC_calls': 0, 'git_mutations': 0,
    }
    raw = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with OUTPUT.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'passed': True, 'proof': {'local_path': str(OUTPUT), **pin(raw)},
                      'archives': 3, 'original_observation_gate_passed': True,
                      'original_lifecycle_rejection_preserved': True, 'saturation_submitted': False}, sort_keys=True))


if __name__ == '__main__':
    main()
