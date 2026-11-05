#!/usr/bin/env python3
"""Bind the actual R26 X230 archive members to the three original Mac holders.

Local fixed evidence only. No archived code, workload, host RPC or Git operation.
The two private diagnostic holders require the separate private07 archive later.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

WORK = Path('/workspace/scratch/806ba5f52f94')
HERE = Path(__file__).resolve().parent
XROOT = '/home/qian/hepta-runtime-optimization-20261105-r26'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
CASES = {
    'observation01': ('observation', 'campaign-01/report.json', 'tools-03/r26_campaign.py',
                      'observation-native-terminal-01.json', '1a1ab9c71ee-fc05-4f01', True,
                      'd9ae83138d356e1e5b6b03176040955b8e231c8c69c051a224cd7468fabc6d7f'),
    'lifecycle01': ('lifecycle', 'lifecycle-campaign-01/report.json', 'tools-03/r26_lifecycle_campaign.py',
                    'lifecycle-native-terminal-01.json', '1a1ababc175-fc05-4f94', False,
                    '95fe29cf6c69fc98f65d3c12e7c819d9c5a6817c587aad7b7dea7a34093d6270'),
    'lifecycle02': ('lifecycle', 'lifecycle-campaign-02/report.json', 'tools-04/r26_lifecycle_campaign.py',
                    'lifecycle-native-terminal-02.json', '1a1abcac847-fc05-509a', False,
                    '50b745129004ba2e8f85e179bf41930c84588f8bbbf015f3cbc03479b20dcb79'),
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
    output = HERE / 'formal-cross-package-proof-01.json'
    need(not os.path.lexists(output), 'fresh cross-package proof required')
    inputs = []

    def bind(path, expected=None):
        identity, raw = read(path, expected)
        inputs.append(identity)
        return raw

    xqa = json.loads(bind(WORK / 'benchmark-r26/verified-full-export-02/full-archive-verification-01.json', {
        'bytes': 13313, 'sha256': '46475164121d2d832c658fc8c9a9b417bdc480295a527d989ec70dde7ef0bbfc'}))
    mqa = json.loads(bind(WORK / 'r25-integration-audit/r26-mac-companion-actual-capture-01/verified-01/independent-verification-01.json', {
        'bytes': 16243, 'sha256': 'd77ff03153267a2f1cf7504cc05f14b51897b5a2efe9708c6347d90887f3c380'}))
    need(xqa['passed'] is True and xqa['original_outcomes_preserved'] is True
         and xqa['adoption_decision_made_here'] is False and mqa['passed'] is True
         and mqa['original_negative_outcomes_preserved'] is True and mqa['runtime_adoption_assessed'] is False,
         'original complete archive verification receipts differ')
    archives, manifests, compressed = {}, {}, {}
    for group, record in xqa['archives'].items():
        raw = bind(record['archive']['source_path'], record['archive'])
        compressed[group] = raw
        manifest_raw = bind(record['manifest']['local_path'], record['manifest'])
        manifests[group] = json.loads(manifest_raw)
        need(record['independent_validation']['verified'] is True, 'original X230 member QA incomplete')
        archives[group] = {'archive': {key: record['archive'][key] for key in ('bytes', 'sha256')},
                           'regular_members': record['independent_validation']['regular_members']}
    need(sum(row['regular_members'] for row in archives.values()) == 9581, 'four-archive member count differs')
    mac_root = WORK / 'r25-integration-audit/r26-mac-companion-actual-capture-01'
    mac_raw = bind(mac_root / 'verified-01/formal-holders-01.tar.gz', mqa['groups']['formal']['archive'])
    mac_manifest_raw = bind(mac_root / 'formal/manifest.json')
    need(hashlib.sha256(mac_manifest_raw).hexdigest() == mqa['groups']['formal']['manifest_sha256'],
         'original formal manifest differs')
    mac_manifest = json.loads(mac_manifest_raw)
    mac_files = {row['path']: row for row in mac_manifest['files']}
    need(len(mac_files) == len(mac_manifest['files']) == 85, 'formal manifest inventory differs')
    proofs = {}
    with tarfile.open(fileobj=io.BytesIO(mac_raw), mode='r:gz') as mac:
        need(mac.extractfile('_export-manifest.json').read() == mac_manifest_raw, 'embedded formal manifest differs')
        for kind, (group, report_relative, source_relative, terminal_relative, job_id, expected_passed, report_sha) in CASES.items():
            wanted_paths = {
                'report': XROOT + '/' + report_relative,
                'source': XROOT + '/' + source_relative,
                'terminal': XROOT + '/' + terminal_relative,
            }
            # Lifecycle01's source was installed and archived in the observation group.
            source_group = 'observation' if kind == 'lifecycle01' else group
            chosen, original_bodies = {}, {}
            for label, path in wanted_paths.items():
                current_group = source_group if label == 'source' else group
                rows = [(name, row) for name, row in manifests[current_group]['files'].items()
                        if row['source_path'] == path]
                need(rows, 'fixed X230 source/report/terminal absent: ' + path)
                with tarfile.open(fileobj=io.BytesIO(compressed[current_group]), mode='r:gz') as archive:
                    values = [member(archive, name, row) for name, row in rows]
                need(all(value == values[0] for value in values), 'duplicate original source bytes disagree')
                original_bodies[label] = values[0]
                chosen[label] = {'archive_group': current_group, 'members': [name for name, _ in rows],
                                 'original_path': path, **pin(values[0])}
            parent = json.loads(original_bodies['report'])
            need(pin(original_bodies['report'])['sha256'] == report_sha and parent['passed'] is expected_passed,
                 'original completed R26 decision differs')
            terminal = json.loads(original_bodies['terminal'])
            need(terminal['job_id'] == job_id and terminal['state'] == ('succeeded' if expected_passed else 'failed')
                 and type(terminal['exit_code']) is int and terminal['exit_code'] == (0 if expected_passed else 1),
                 'original native result differs')
            native_name = 'native/' + kind + '-terminal.json'
            need(member(mac, native_name, mac_files[native_name]) == original_bodies['terminal'],
                 'Mac and X230 packages contain different original terminal bytes')
            holder_name = 'holders/' + kind + '/report.json'
            holder = json.loads(member(mac, holder_name, mac_files[holder_name]))
            source_name = 'holders/' + kind + '/remote-script.py'
            retained = member(mac, source_name, mac_files[source_name])
            staged_name = 'sources/' + kind + '-campaign.py'
            need(retained == member(mac, staged_name, mac_files[staged_name]) == original_bodies['source'],
                 'Mac retained/staged source differs from installed X230 parent')
            need(holder['remote_script_sha256'] == parent['launcher_sha256'] == pin(retained)['sha256']
                 and holder['passed'] is expected_passed and holder['remote_returncode'] == terminal['exit_code']
                 and holder['owned_agent_reaped'] is True
                 and holder['owned_agent_directory_absent_after_context'] is True
                 and holder['owned_agent_socket_absent_after_context'] is True,
                 'original held-source/result/cleanup binding differs')
            forwarded_name = 'holders/' + kind + '/forwarded.stdout'
            forwarded = member(mac, forwarded_name, mac_files[forwarded_name])
            footer = json.loads(forwarded.decode('utf-8').splitlines()[-1])
            need(footer == mac_manifest['campaigns'][kind]['remote_final_line']
                 and footer['report'] == wanted_paths['report'] and footer['passed'] is parent['passed'],
                 'original forwarded report footer differs from archived X230 report')
            if kind == 'observation01':
                need(footer['observation_gate_passed'] is parent['observation_gate_passed'] is True
                     and footer['rejection_reasons'] == parent['rejection_reasons'] == [], 'observation gate differs')
            else:
                need(footer['adoption_passed'] is parent['adoption_passed'] is False
                     and footer['error'] == parent['error'], 'original rejected lifecycle footer differs')
            input_pin = parent['input_receipt']
            input_rows = [(name, row) for name, row in manifests[group]['files'].items()
                          if row['source_path'] == input_pin['path']]
            need(input_rows, 'actual parent input is absent from the X230 archive')
            with tarfile.open(fileobj=io.BytesIO(compressed[group]), mode='r:gz') as archive:
                for name, row in input_rows:
                    need(pin(member(archive, name, row)) == {key: input_pin[key] for key in ('bytes', 'sha256')},
                         'actual parent input differs from its original report binding')
            proofs[kind] = {'original_job_id': job_id, 'native_state': terminal['state'],
                            'native_exit_code': terminal['exit_code'], 'original_parent_passed': parent['passed'],
                            'fixed_X230_members': chosen,
                            'Mac_retained_and_staged_source_equal_X230_installed_source': True,
                            'exact_native_terminal_bytes_equal': True, 'forwarded_footer_matches_parent': True,
                            'parent_actual_input_members': [name for name, _ in input_rows],
                            'original_owned_agent_and_paths_closed': True, 'current_host_probe_performed': False}
    for expected in inputs:
        need(read(expected['local_path'], expected)[0] == expected, 'original input changed after cross-binding')
    result = {'schema': 'hepta-r26-formal-mac-X230-cross-package-binding/v1', 'passed': True,
              'formal_three_original_holders_bound': proofs, 'four_X230_verified_archive_identities': archives,
              'original_inputs': inputs, 'original_failed_lifecycle_results_preserved': True,
              'private_diagnostic_holders_pending_private07_full_archive': ['phase02', 'phase03'],
              'all_seven_archives_and_native_custody_complete': False, 'candidate_adopted': False,
              'new_performance_reanalysis_performed': False, 'archive_code_executed': False,
              'archive_members_extracted_to_paths': False, 'host_RPC_calls': 0, 'git_mutations': 0}
    raw = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with output.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'passed': True, 'proof': {'local_path': str(output), **pin(raw)},
                      'formal_holders': 3, 'private_holders_still_pending': 2}, sort_keys=True))


if __name__ == '__main__':
    main()
