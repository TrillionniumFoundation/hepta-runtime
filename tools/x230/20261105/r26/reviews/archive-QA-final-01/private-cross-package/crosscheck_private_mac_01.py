#!/usr/bin/env python3
"""Bind the two actual failed Mac diagnostic holders to verified private07 bytes.

Local fixed evidence only. Requires an actual successful full private07 consumer
receipt. No archived code, workload, host RPC, Git operation or new performance
analysis. The original negative outcomes remain negative.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

WORK = Path('/workspace/scratch/806ba5f52f94')
HERE = Path(__file__).resolve().parent
XROOT = '/home/qian/hepta-runtime-optimization-20261105-r25'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
CASES = {
    'phase02': ('02', '1a1ab6ef44c-fc05-4dd3',
                '776fef341b0006af71277e4a2fe0aae31410475182f2f8a299747eb36be3b0b3',
                '144f126a85a93f6bad3564a89d624e2963847456a56baeb869de6531c0dacc2e',
                '7fdf83d5cf82da25e71e012c0ceacac108706921ff543bd556d40bd07a681804', False),
    'phase03': ('03', '1a1abddc5a0-fc05-5108',
                '79989ebf185f9d2cead0ba60ecd1a7edebd91ca8c07c541cdab5ef64d1f69fbf',
                'dd685c28403e4814aedd15a5329bf01bd8957dfdcc4b4f45e6401ca86444425e',
                'b91b8ed1df8a0d698a7d46fa6f3d3575658cd8d42542fded9911af18a98b2619', True),
}


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-qa', required=True, type=Path)
    parser.add_argument('--private-qa-sha256', required=True)
    args = parser.parse_args()
    need(re.fullmatch(r'[0-9a-f]{64}', args.private_qa_sha256), 'actual full private07 QA SHA required')
    output = HERE / 'private-cross-package-proof-01.json'
    need(not os.path.lexists(output), 'fresh cross-package proof required')
    inputs = []

    def bind(path, expected=None):
        identity, raw = read(path, expected)
        inputs.append(identity)
        return raw

    bind(Path(__file__).absolute())
    qa_raw = bind(args.private_qa)
    need(pin(qa_raw)['sha256'] == args.private_qa_sha256, 'actual full QA source differs')
    qa = json.loads(qa_raw)
    need(qa['schema'] == 'hepta-private07-independent-downloaded-archive-verification/v1'
         and qa['passed'] is True and qa['original_outcomes_preserved'] is True
         and qa['capacity_attribution_allowed'] is False and qa['production_adoption_made_here'] is False
         and qa['original_unknown_installation_preserved'] is True
         and qa['phase03']['original_positive_chain_reproduced'] is False,
         'actual complete private07 negative-preserving full QA required')
    xraw = bind(qa['archive']['source_path'], {'bytes': 7150445,
         'sha256': '4292ad42e87728630f4a6d9a42a34a8447836f20b07ce095415f91c0f897d1bd'})
    need(pin(xraw) == {key: qa['archive'][key] for key in ('bytes', 'sha256')}
         and qa['independent_archive_validation']['verified'] is True
         and qa['independent_archive_validation']['regular_members'] == 4136,
         'exact original private archive/member closure differs')
    export_report = json.loads(bind(WORK / 'r25-capacity-audit/actual-private-export-07/report.json', {
         'bytes': 40086, 'sha256': 'da54b40a6e32106b4862a7bb4143a096e667840b663fbae3be544ce1dd110413'}))
    mroot = WORK / 'r25-integration-audit/r26-mac-companion-actual-capture-01'
    mqa = json.loads(bind(mroot / 'verified-01/independent-verification-01.json', {
         'bytes': 16243, 'sha256': 'd77ff03153267a2f1cf7504cc05f14b51897b5a2efe9708c6347d90887f3c380'}))
    need(mqa['passed'] is True and mqa['original_negative_outcomes_preserved'] is True
         and mqa['runtime_adoption_assessed'] is False, 'complete original Mac QA required')
    mraw = bind(mroot / 'verified-01/diagnostic-holders-01.tar.gz', {
         'bytes': 42124, 'sha256': 'b2b4f9f23bb8203146804ef6a51cc1747a385859adae66cfd96755d32e06f975'})
    mmraw = bind(mroot / 'diagnostics/manifest.json')
    need(pin(mraw) == {key: mqa['groups']['diagnostics']['archive'][key] for key in ('bytes', 'sha256')}
         and pin(mmraw)['sha256'] == mqa['groups']['diagnostics']['manifest_sha256'],
         'exact diagnostic Mac archive/manifest differs')
    mm = json.loads(mmraw)
    mf = {row['path']: row for row in mm['files']}
    need(len(mf) == len(mm['files']) == 58 and mm['campaign_names'] == ['phase02', 'phase03'],
         'original two-holder diagnostic member inventory differs')
    proofs = {}
    with tarfile.open(fileobj=io.BytesIO(xraw), mode='r:gz') as x, \
         tarfile.open(fileobj=io.BytesIO(mraw), mode='r:gz') as mac:
        xmraw = x.extractfile('_export-manifest.json').read()
        need(pin(xmraw) == {'bytes': 3917165,
             'sha256': '5f2b154503e728914625cc9f3b22ec840d0e9a5e3dd8c323f6200ff72641df5a'}
             and pin(xmraw) == {key: qa['manifest'][key] for key in ('bytes', 'sha256')},
             'exact embedded private manifest differs')
        xm = json.loads(xmraw)
        need(xm['baseline_adoption_status'] == 'qualified_but_unadopted_R25'
             and xm['production_candidate'] is False and xm['capacity_admission_made_here'] is False
             and xm['phase03'] == export_report['phase03'] == qa['phase03'],
             'original unadopted diagnostic/negative disposition changed')
        need(mac.extractfile('_export-manifest.json').read() == mmraw, 'embedded Mac manifest differs')

        def original(path, expected=None):
            need(path.startswith(XROOT + '/'), 'cross-package original path outside fixed R25 diagnostic root')
            rows = [(name, row) for name, row in xm['files'].items() if row['source_path'] == path]
            need(rows, 'fixed original absent from private archive: ' + path)
            bodies = [member(x, name, row) for name, row in rows]
            need(all(b == bodies[0] for b in bodies), 'duplicate original bytes differ')
            if expected is not None:
                need(pin(bodies[0]) == {key: expected[key] for key in ('bytes', 'sha256')},
                     'report-bound original member bytes differ')
            return bodies[0], {'source_path': path, 'members': [name for name, _ in rows], **pin(bodies[0])}

        for kind, (revision, job_id, script_sha, bootstrap_sha, wrapper_sha, monitor_passed) in CASES.items():
            selected = {}
            source_path = XROOT + '/mechanism-monitor-bootstrap-' + revision + '.py'
            source, selected['bootstrap_source'] = original(source_path, {'bytes': 7133, 'sha256': script_sha})
            retained = member(mac, 'holders/' + kind + '/remote-script.py', mf['holders/' + kind + '/remote-script.py'])
            staged = member(mac, 'sources/' + kind + '-campaign.py', mf['sources/' + kind + '-campaign.py'])
            need(source == retained == staged, 'Mac retained/staged and installed bootstrap bytes differ')
            holder = json.loads(member(mac, 'holders/' + kind + '/report.json', mf['holders/' + kind + '/report.json']))
            terminal_raw = member(mac, 'native/' + kind + '-terminal.json', mf['native/' + kind + '-terminal.json'])
            terminal = json.loads(terminal_raw)
            need(terminal['job_id'] == job_id and terminal['state'] == 'failed'
                 and type(terminal['exit_code']) is int and terminal['exit_code'] == 1
                 and terminal['output_complete'] is True and terminal['output_durable'] is True
                 and terminal['terminal_publication_confirmed'] is True,
                 'original failed native outcome changed')
            need(holder['remote_script_sha256'] == script_sha and holder['passed'] is False
                 and holder['remote_returncode'] == 1 and holder['owned_agent_reaped'] is True
                 and holder['owned_agent_directory_absent_after_context'] is True
                 and holder['owned_agent_socket_absent_after_context'] is True,
                 'original held-source/result/cleanup binding differs')
            forwarded = member(mac, 'holders/' + kind + '/forwarded.stdout', mf['holders/' + kind + '/forwarded.stdout'])
            lines = [json.loads(line) for line in forwarded.decode('utf-8').splitlines()]
            need(len(lines) == 3 and lines[0]['phase'] == 'source_bound_bootstrap_entered'
                 and lines[2]['phase'] == 'source_bound_bootstrap_finished'
                 and lines[2] == mm['campaigns'][kind]['remote_final_line']
                 and lines[2]['passed'] is False and lines[2]['wrapper_returncode'] == 1,
                 'three original source/bootstrap/wrapper footer records differ')
            final_path = XROOT + '/mechanism-monitor-bootstrap-report-' + revision + '.json'
            need(lines[2]['report']['path'] == final_path and lines[2]['report']['sha256'] == bootstrap_sha,
                 'original bootstrap footer path/hash differs')
            final_raw, selected['bootstrap_report'] = original(final_path, lines[2]['report'])
            final = json.loads(final_raw)
            entry_raw, selected['bootstrap_entry'] = original(lines[0]['entry']['path'], lines[0]['entry'])
            entry = json.loads(entry_raw)
            wrapper_raw, selected['wrapper_report'] = original(lines[1]['report']['path'], lines[1]['report'])
            wrapper = json.loads(wrapper_raw)
            need(pin(wrapper_raw)['sha256'] == wrapper_sha and lines[1]['passed'] is False
                 and lines[1]['attribution_allowed'] is False, 'failed original wrapper footer changed')
            need(final['schema'] == entry['schema'] == 'hepta-r25-phase-stdin-bootstrap/v2'
                 and final['holder_supplied_stdin_sha256'] == entry['holder_supplied_stdin_sha256'] == script_sha
                 and final['installed_bootstrap_source']['path'] == source_path
                 and pin(source) == {key: final['installed_bootstrap_source'][key] for key in ('bytes', 'sha256')}
                 and final['source_descriptors_stable'] is True
                 and final['expected_unchanged_holder_sha256'] == holder['holder_script_sha256']
                 and final['passed'] is entry['passed'] is False
                 and entry['wrapper_invocations'] == 0 and entry['wrapper_returncode'] is None
                 and final['wrapper_invocations'] == 1 and final['wrapper_returncode'] == 1,
                 'original bootstrap entry/final source/outcome chain changed')
            need(final['entry_receipt'] == lines[0]['entry']
                 and lines[0]['holder_supplied_stdin_sha256'] == script_sha
                 and lines[0]['wrapper_sha256'] == final['installed_wrapper_source']['sha256'],
                 'source-bound entered record differs')
            wrapped_source, selected['wrapper_source'] = original(final['installed_wrapper_source']['path'], final['installed_wrapper_source'])
            need(pin(wrapped_source) == {key: wrapper['actual_wrapper_source'][key] for key in ('bytes', 'sha256')}
                 and wrapper['actual_wrapper_source']['path'] == final['installed_wrapper_source']['path']
                 and wrapper['transmitted_bootstrap_source']['path'] == source_path
                 and wrapper['transmitted_bootstrap_source']['sha256'] == script_sha,
                 'wrapper and transmitted bootstrap source chain differs')
            need(wrapper['passed'] is False and wrapper['attribution_allowed'] is False
                 and wrapper['parent_invocations'] == 1 and wrapper['parent_returncode'] == 1
                 and wrapper['monitor_passed'] is monitor_passed
                 and wrapper['original_parent_streams_custody_passed'] is True
                 and wrapper['original_parent_stream_custody_errors'] == [], 'original wrapper rejection/custody changed')
            parent_raw, selected['parent_report'] = original(wrapper['original_parent_report']['path'], wrapper['original_parent_report'])
            parent = json.loads(parent_raw)
            original(wrapper['original_parent_source']['path'], wrapper['original_parent_source'])
            need(parent['passed'] is False and parent['attribution_allowed'] is False
                 and bool(parent['finished_utc']), 'completed original parent rejection changed')
            for stream in ('stdout', 'stderr'):
                row = wrapper['original_parent_' + stream]
                _, selected['parent_' + stream] = original(row['path'], row)
            phase03_original_native_text_equal = None
            if kind == 'phase03':
                input_raw, selected['export_input'] = original(export_report['input']['source_path'], export_report['input'])
                operation = json.loads(input_raw)['phase03']['operation']
                need(operation['job_id'] == job_id and operation['executed'] is True
                     and operation['terminal_raw'].encode('utf-8') == terminal_raw,
                     'private archived original native text differs from Mac terminal bytes')
                phase03_original_native_text_equal = True
            proofs[kind] = {'original_job_id': job_id, 'original_native_state': 'failed', 'original_native_exit_code': 1,
                'Mac_retained_and_staged_source_equal_installed_bootstrap': True,
                'all_three_forwarded_original_records_bound': True,
                'bootstrap_wrapper_parent_reports_and_sources_bound': True,
                'parent_original_stream_bytes_bound': True,
                'original_monitor_passed': monitor_passed,
                'original_parent_passed': False, 'original_wrapper_passed': False,
                'original_holder_passed': False, 'original_owned_agent_and_paths_closed': True,
                'phase03_terminal_exact_text_equal_archived_export_input': phase03_original_native_text_equal,
                'phase02_native_terminal_not_duplicated_in_private_archive': kind == 'phase02',
                'phase02_native_proof_scope': 'Already fully verified original Mac terminal and holder stream; complete request/start/read chain belongs to native custody' if kind == 'phase02' else None,
                'fixed_X230_members': selected, 'current_host_probe_performed': False}
    for expected in inputs:
        need(read(expected['local_path'], expected)[0] == expected, 'original input changed after cross-binding')
    result = {'schema': 'hepta-private-diagnostic-mac-X230-cross-package-binding/v1', 'passed': True,
        'private_two_original_holders_bound': proofs, 'original_inputs': inputs,
        'private07_full_archive_QA_required_and_bound': True,
        'both_original_failed_outcomes_preserved': True, 'baseline': 'qualified_but_unadopted_R25',
        'capacity_attribution_allowed': False, 'production_adoption_made_here': False,
        'full_native_operations_custody_still_required': True,
        'new_performance_reanalysis_performed': False, 'archive_code_executed': False,
        'archive_members_extracted_to_paths': False, 'host_RPC_calls': 0, 'git_mutations': 0}
    body = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with output.open('xb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'passed': True, 'proof': {'local_path': str(output), **pin(body)},
                      'private_holders': 2, 'both_original_failed_outcomes_preserved': True}, sort_keys=True))


if __name__ == '__main__':
    main()
