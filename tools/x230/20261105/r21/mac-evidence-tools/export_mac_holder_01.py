#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Export closed R21 Mac holder evidence without SSH, credentials or workloads.

Only the fixed campaign directory, known installed source files/receipts and
this exporter are read. The X230 report is never opened by this program.
"""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import traceback

sys.dont_write_bytecode = True
ROOT = Path('/Users/qianqi/work/hepta-runtime-x230-r21-20261105')
CAMPAIGN = ROOT / 'campaign-01'
X230_REPORT = '/home/qian/hepta-runtime-optimization-20261105-r21/campaign-control-01/report.json'
HOLDER_SHA = '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'
LEGACY_HOLDER_SHA = '287d5026951923728c9b7661f5e3f843045791fbdb0b766c396b7331d45e5dce'
BOOTSTRAP_SHA = 'de42d946174b996d14c5e04892c0eeea9436d578d7ded6e2f8c0298b8bf5d0b1'
INSTALL_SHA = '43e80b18f9dbf944dedd7fd72ec2168ceaea4d8c3975421e4025f72d73eeaab3'
HEX = re.compile(r'[0-9a-f]{64}\Z')
LOG_NAME = re.compile(r'(?:report\.json|report\.next|remote-script\.py|forwarded\.(?:stdout|stderr)|'
                      r'owned-agent\.stderr|holder\.error\.txt|identity-discovery-[0-9]{2,}\.stderr|'
                      r'identity-load-[0-9]{2,}\.(?:stdout|stderr))\Z')
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def stamp(info):
    return {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
            'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def directory(path):
    need(path.is_absolute() and path.resolve() == path, 'directory path is not direct/canonical: ' + str(path))
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
         and info.st_mode & 0o022 == 0, 'directory owner/mode/type differs: ' + str(path))


def read(path):
    need(path.is_absolute() and path.resolve() == path, 'input path is not direct/canonical: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
             and before.st_mode & 0o022 == 0 and before.st_size <= MAX_FILE,
             'input owner/mode/type/link/size differs: ' + str(path))
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_FILE + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'input changed during read: ' + str(path))
        return raw, {'original_path': str(path), 'size': len(raw), 'sha256': sha(raw),
                     'mode': stat.S_IMODE(before.st_mode), 'source_stamp': stamp(before)}
    finally:
        os.close(fd)


def inventory():
    directory(CAMPAIGN)
    rows = []
    for path in sorted(CAMPAIGN.iterdir()):
        info = path.lstat()
        rows.append({'name': path.name, 'mode': info.st_mode, 'inode': info.st_ino,
                     'permitted_name': bool(LOG_NAME.fullmatch(path.name)),
                     'regular': stat.S_ISREG(info.st_mode)})
    return rows


def absent_owned_path(path):
    """Metadata only; permission and other errors remain unknown, never absent."""
    try:
        info = os.lstat(path)
        return {'path': path, 'absent': False, 'mode': info.st_mode, 'uid': info.st_uid}
    except FileNotFoundError:
        return {'path': path, 'absent': True}
    except OSError as error:
        return {'path': path, 'absent': None, 'error_type': type(error).__name__, 'errno': error.errno}


def json_strings(value):
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return set().union(*(json_strings(item) for item in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(json_strings(item) for item in value)) if value else set()
    return set()


def terminal_line(raw):
    lines = [line for line in raw.decode('utf-8').splitlines() if line.strip()]
    need(bool(lines), 'forwarded stdout has no final nonempty line')
    value = json.loads(lines[-1])
    need(isinstance(value, dict), 'forwarded final line is not a JSON object')
    return value


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def archive(path, payloads, manifest_raw):
    with path.open('xb') as output:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for name, raw, mode in [('_export-manifest.json', manifest_raw, 0o600)] + [
                        (name, item['raw'], item['identity']['mode']) for name, item in sorted(payloads.items())]:
                    member = tarfile.TarInfo(name)
                    member.size, member.mode, member.mtime = len(raw), mode, 0
                    member.uid = member.gid = 0
                    member.uname = member.gname = ''
                    tar.addfile(member, io.BytesIO(raw))
        output.flush()
        os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('success', 'failed'), required=True)
    parser.add_argument('--expected-report-sha256')
    parser.add_argument('--expected-bootstrap-sha256')
    parser.add_argument('--terminal-confirmed', action='store_true', required=True)
    parser.add_argument('--out', type=Path, default=ROOT / 'export-holder-01')
    args = parser.parse_args()
    need(sys.platform == 'darwin' and os.geteuid() != 0, 'run as the existing non-root Mac operator')
    need(args.terminal_confirmed, 'caller must independently confirm the holder is terminal before exporting')
    for value in (args.expected_report_sha256, args.expected_bootstrap_sha256):
        need(value is None or HEX.fullmatch(value), 'expected identity is not lowercase SHA256')
    if args.mode == 'success':
        need(args.expected_report_sha256 and args.expected_bootstrap_sha256 == BOOTSTRAP_SHA,
             'success export requires actual report SHA and the frozen actual bootstrap SHA')
    directory(ROOT)
    out = args.out.absolute()
    need(out.parent == ROOT and re.fullmatch(r'export-holder-[0-9]{2}', out.name)
         and not os.path.lexists(out), 'export output must be a new direct export-holder-NN directory')
    os.umask(0o077)
    out.mkdir(mode=0o700)
    payloads, read_errors, validation_errors, checks = {}, [], [], {}
    before_inventory, after_inventory, cleanup = None, None, None
    holder_report, final_stdout = None, None
    started = utc()

    def retain(path, name):
        try:
            raw, identity = read(path)
            need(sum(item['identity']['size'] for item in payloads.values()) + len(raw) <= MAX_TOTAL,
                 'total evidence exceeds explicit export budget')
            need(name not in payloads, 'duplicate archive member')
            payloads[name] = {'raw': raw, 'identity': {'path': name, **identity}}
        except Exception as error:
            read_errors.append({'path': str(path), 'archive_member': name,
                                'type': type(error).__name__, 'reason': str(error)})

    def check(name, value):
        checks[name] = bool(value)
        if not value:
            validation_errors.append({'check': name, 'state': 'failed_or_unknown'})

    try:
        try:
            before_inventory = inventory()
            for row in before_inventory:
                if not row['permitted_name'] or not row['regular']:
                    read_errors.append({'path': str(CAMPAIGN / row['name']),
                                        'reason': 'unpermitted filename or nonregular entry; contents not read'})
                else:
                    retain(CAMPAIGN / row['name'], 'campaign-01/' + row['name'])
        except Exception as error:
            read_errors.append({'path': str(CAMPAIGN), 'type': type(error).__name__, 'reason': str(error)})
        fixed = [('held_agent_campaign_02.py', 'sources/held_agent_campaign_02.py'),
                 ('campaign-bootstrap-01.py', 'sources/campaign-bootstrap-01.py'),
                 ('held_agent_campaign.py', 'legacy/held_agent_campaign.py'),
                 ('holder-installed-01.json', 'installations/holder-installed-01.json'),
                 ('campaign-tools-installed-01.json', 'installations/campaign-tools-installed-01.json')]
        for name, member in fixed:
            retain(ROOT / name, member)
        retain(Path(__file__).absolute(), 'exporter/export_mac_holder_01.py')

        def item(name):
            need(name in payloads, 'required captured file absent: ' + name)
            return payloads[name]

        try:
            current = item('sources/held_agent_campaign_02.py')['identity']
            bootstrap = item('sources/campaign-bootstrap-01.py')['identity']
            legacy = item('legacy/held_agent_campaign.py')['identity']
            install = item('installations/campaign-tools-installed-01.json')
            legacy_install = json.loads(item('installations/holder-installed-01.json')['raw'])
            install_value = json.loads(install['raw'])
            check('actual_holder02_source_pinned', current['sha256'] == HOLDER_SHA and current['size'] == 11374)
            check('actual_bootstrap_source_pinned', bootstrap['sha256'] == BOOTSTRAP_SHA
                  and bootstrap['size'] == 1929
                  and (args.expected_bootstrap_sha256 is None or bootstrap['sha256'] == args.expected_bootstrap_sha256))
            check('legacy_holder_and_install_retained', legacy['sha256'] == LEGACY_HOLDER_SHA
                  and legacy['size'] == 10636 and legacy_install.get('passed') is True
                  and LEGACY_HOLDER_SHA in json_strings(legacy_install))
            check('actual_combined_install_receipt_pinned', install['identity']['sha256'] == INSTALL_SHA
                  and install['identity']['size'] == 569 and install_value.get('passed') is True
                  and {HOLDER_SHA, BOOTSTRAP_SHA} <= json_strings(install_value))
            report_item = item('campaign-01/report.json')
            holder_report = json.loads(report_item['raw'])
            check('actual_holder_report_sha_pinned', args.expected_report_sha256 is not None
                  and report_item['identity']['sha256'] == args.expected_report_sha256)
            check('holder_report_terminal_success', holder_report.get('schema') == 'hepta-x230-r21-held-agent-campaign/v1'
                  and bool(holder_report.get('finished_utc')) and holder_report.get('passed') is True
                  and holder_report.get('remote_returncode') == 0 and type(holder_report.get('remote_returncode')) is int
                  and 'error' not in holder_report and holder_report.get('foreground_timed_out') is not True
                  and holder_report.get('remote_completion_unknown') is not True)
            check('holder_sources_bound', holder_report.get('holder_script_sha256') == HOLDER_SHA
                  and holder_report.get('remote_script_sha256') == BOOTSTRAP_SHA
                  and item('campaign-01/remote-script.py')['raw'] == item('sources/campaign-bootstrap-01.py')['raw'])
            check('holder_no_retries_services_or_sensitive_dumps', holder_report.get('automatic_ssh_retries') == 0
                  and holder_report.get('services_modified') is False and holder_report.get('key_bytes_retained') is False
                  and holder_report.get('complete_environment_retained') is False
                  and holder_report.get('ssh_configuration_dump_retained') is False)
            check('owned_agent_reaped_and_absence_recorded', holder_report.get('owned_agent_reaped') is True
                  and type(holder_report.get('owned_agent_returncode')) is int
                  and holder_report.get('owned_agent_directory_absent_after_context') is True
                  and holder_report.get('owned_agent_socket_absent_after_context') is True)
            start = holder_report.get('foreground_start_monotonic_ns')
            end = holder_report.get('foreground_end_monotonic_ns')
            check('foreground_owned_child_completion_fields_consistent',
                  type(holder_report.get('foreground_pid')) is int and holder_report['foreground_pid'] > 1
                  and type(holder_report.get('owned_agent_pid')) is int and holder_report['owned_agent_pid'] > 1
                  and type(start) is int and type(end) is int and end >= start
                  and holder_report.get('foreground_seconds') == (end - start) / 1e9)
            owned_dir, owned_socket = holder_report.get('owned_agent_directory'), holder_report.get('owned_agent_socket')
            owned_valid = isinstance(owned_dir, str) and bool(re.fullmatch(r'/tmp/hr19a-[A-Za-z0-9_-]+', owned_dir))
            owned_valid = owned_valid and owned_socket == owned_dir + '/agent.sock'
            check('owned_cleanup_paths_scoped_to_original_holder', owned_valid)
            if owned_valid:
                cleanup = {'directory': absent_owned_path(owned_dir), 'socket': absent_owned_path(owned_socket),
                           'scope': 'read-only metadata snapshots at export; no cleanup operation or signal'}
            check('owned_directory_and_socket_currently_absent', cleanup is not None
                  and cleanup['directory']['absent'] is True and cleanup['socket']['absent'] is True)
            rows = holder_report.get('log_files')
            expected = {row['name'] for row in before_inventory or []} - {'report.json'}
            names = [row.get('file') for row in rows] if isinstance(rows, list) and all(isinstance(row, dict) for row in rows) else []
            check('terminal_report_lists_every_original_log', isinstance(rows, list) and len(names) == len(set(names))
                  and set(names) == expected and 'report.next' not in expected)
            if checks['terminal_report_lists_every_original_log']:
                check('every_original_log_matches_recorded_size_and_sha', all(
                    item('campaign-01/' + row['file'])['identity']['size'] == row['bytes']
                    and item('campaign-01/' + row['file'])['identity']['sha256'] == row['sha256'] for row in rows))
            final_stdout = terminal_line(item('campaign-01/forwarded.stdout')['raw'])
            check('forwarded_final_line_closes_report_path_and_status', final_stdout.get('passed') is True
                  and final_stdout.get('report') == X230_REPORT and final_stdout.get('error') is None
                  and type(final_stdout.get('native_regression_screen_passed')) is bool)
            # False native performance screen remains an honest completed transport,
            # not an exporter failure and never an adoption decision.
        except Exception as error:
            validation_errors.append({'type': type(error).__name__, 'reason': str(error), 'state': 'unknown_or_invalid'})

        for name, entry in payloads.items():
            try:
                raw, identity = read(Path(entry['identity']['original_path']))
                need(raw == entry['raw'] and identity == {k: v for k, v in entry['identity'].items() if k != 'path'},
                     'captured input changed before packaging')
            except Exception as error:
                read_errors.append({'path': entry['identity']['original_path'], 'archive_member': name,
                                    'type': type(error).__name__, 'reason': str(error)})
        try:
            after_inventory = inventory()
            need(before_inventory == after_inventory, 'campaign directory file set or identities changed')
        except Exception as error:
            read_errors.append({'path': str(CAMPAIGN), 'type': type(error).__name__, 'reason': str(error)})
        manifest = {'schema': 'hepta-r21-mac-holder-export/v1', 'mode': args.mode, 'started_utc': started,
                    'root': str(ROOT), 'campaign': str(CAMPAIGN), 'terminal_confirmed_by_caller': True,
                    'checks_before_archive': checks, 'validation_errors': validation_errors, 'read_errors': read_errors,
                    'files': [entry['identity'] for _, entry in sorted(payloads.items())],
                    'source_inventory_before': before_inventory, 'source_inventory_after_collection': after_inventory,
                    'current_owned_cleanup_metadata': cleanup, 'forwarded_final_line': final_stdout,
                    'actual_holder_report_sha256': payloads.get('campaign-01/report.json', {}).get('identity', {}).get('sha256'),
                    'expected_holder_report_sha256': args.expected_report_sha256,
                    'x230_report_path_observed': final_stdout.get('report') if isinstance(final_stdout, dict) else None,
                    'x230_report_bytes_read': False, 'x230_report_sha256': None,
                    'cross_package_report_identity_binding_required': True, 'runtime_adoption_assessed': False,
                    'foreground_reap_scope': 'Original holder communicate()/returncode path is source-bound; no separate foreground_waited_and_reaped field exists.',
                    'sensitive_paths_opened': False, 'agent_socket_contents_read': False,
                    'new_ssh_or_workload_or_cleanup_started': False,
                    'scope': 'Original readable Mac evidence only. Failure mode may preserve incomplete or mismatched inputs; the receipt determines complete export status. No independent X230 report read is claimed.'}
        manifest_raw = encode(manifest)
        write_new(out / 'manifest.json', manifest_raw)
        archive_path = out / 'holder-evidence-01.tar.gz'
        archive(archive_path, payloads, manifest_raw)
        final_errors = []
        for name, entry in payloads.items():
            try:
                raw, identity = read(Path(entry['identity']['original_path']))
                need(raw == entry['raw'] and identity == {k: v for k, v in entry['identity'].items() if k != 'path'},
                     'captured input changed after packaging')
            except Exception as error:
                final_errors.append({'path': entry['identity']['original_path'], 'archive_member': name,
                                     'type': type(error).__name__, 'reason': str(error)})
        try:
            need(inventory() == before_inventory, 'campaign directory changed after packaging')
        except Exception as error:
            final_errors.append({'path': str(CAMPAIGN), 'type': type(error).__name__, 'reason': str(error)})
        archive_raw = archive_path.read_bytes()
        readable_preserved = bool(payloads) and not final_errors
        complete = readable_preserved and not read_errors and not validation_errors and all(checks.values())
        succeeded = complete if args.mode == 'success' else readable_preserved
        receipt = {'schema': 'hepta-r21-mac-holder-export-receipt/v1', 'finished_utc': utc(), 'mode': args.mode,
                   'export_succeeded': succeeded, 'complete_success_evidence_verified': complete,
                   'readable_evidence_preserved': readable_preserved, 'files': len(payloads),
                   'archive_members': len(payloads) + 1,
                   'archive': {'path': str(archive_path), 'size': len(archive_raw), 'sha256': sha(archive_raw)},
                   'manifest': {'path': str(out / 'manifest.json'), 'size': len(manifest_raw), 'sha256': sha(manifest_raw)},
                   'validation_errors': validation_errors, 'read_errors': read_errors, 'after_archive_errors': final_errors,
                   'x230_report_bytes_read': False, 'x230_report_sha256': None,
                   'native_regression_screen_passed_observed': final_stdout.get('native_regression_screen_passed') if isinstance(final_stdout, dict) else None,
                   'runtime_adoption_assessed': False, 'automatic_retries': 0,
                   'failure_scope': 'An exported failure or unknown remains a failure/unknown. Export success does not assert campaign or adoption success.'}
        write_new(out / 'receipt.json', encode(receipt))
        print(json.dumps(receipt, sort_keys=True), flush=True)
        return 0 if succeeded else 1
    except BaseException as error:
        write_new(out / 'export.error.txt', traceback.format_exc().encode())
        receipt = {'schema': 'hepta-r21-mac-holder-export-receipt/v1', 'finished_utc': utc(), 'mode': args.mode,
                   'export_succeeded': False, 'complete_success_evidence_verified': False,
                   'error': {'type': type(error).__name__, 'reason': str(error)},
                   'read_errors': read_errors, 'validation_errors': validation_errors,
                   'x230_report_bytes_read': False, 'runtime_adoption_assessed': False, 'automatic_retries': 0}
        if not os.path.lexists(out / 'receipt.json'):
            write_new(out / 'receipt.json', encode(receipt))
        print(json.dumps(receipt, sort_keys=True), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
