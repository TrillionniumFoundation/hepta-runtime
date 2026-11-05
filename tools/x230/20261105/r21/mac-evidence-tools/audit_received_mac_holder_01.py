#!/usr/bin/env python3
"""Verify the actual closed R21 Mac export and restore it to a fresh local tree.

No network, subprocesses, execution of archived code, or adoption decision.
Current Mac cleanup is a pinned exporter metadata witness, not a local /tmp probe.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import traceback

REMOTE = '/Users/qianqi/work/hepta-runtime-x230-r21-20261105'
X230_REPORT = '/home/qian/hepta-runtime-optimization-20261105-r21/campaign-control-01/report.json'
INPUTS = {
    'holder-evidence-01.tar.gz': (15653, 'bbab5b09ddd974f042a20e1265b85f6bded98715f74eb656cb571f28b2aec436'),
    'manifest.json': (26128, 'da93ee402918083472e5d239febffa975f2c3821de98e2340e14d69fedc13134'),
    'receipt.json': (1133, '5b99b2f820a751b256f9c5409c4aff5df247bac394bf9346c944a79e4ccc72e5'),
    'holder-exporter-installed-01.json': (958, 'e3dd3d3edfb9c25b4818c7e3186fbf555d06ad98ce0ff761644057148af233e2'),
}
PAYLOAD_PINS = {
    'campaign-01/report.json': (9075, '085d95d9f8aad6c23fb70a69f0860d0f16798f0f05c260776f44a91f7f967c6e'),
    'sources/held_agent_campaign_02.py': (11374, '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'),
    'sources/campaign-bootstrap-01.py': (1929, 'de42d946174b996d14c5e04892c0eeea9436d578d7ded6e2f8c0298b8bf5d0b1'),
    'legacy/held_agent_campaign.py': (10636, '287d5026951923728c9b7661f5e3f843045791fbdb0b766c396b7331d45e5dce'),
    'installations/campaign-tools-installed-01.json': (569, '43e80b18f9dbf944dedd7fd72ec2168ceaea4d8c3975421e4025f72d73eeaab3'),
    'installations/holder-installed-01.json': (707, '1289d5c9782a89238e90ef69c05bd1ed8c7009610f4497c19de8d091cfd03f65'),
    'exporter/export_mac_holder_01.py': (21697, '57871a6197cfb59086b26d5f4b80832c5f015c00989a1029e9be07fccb97b7d1'),
}
LOG_NAME = re.compile(r'(?:report\.json|remote-script\.py|forwarded\.(?:stdout|stderr)|owned-agent\.stderr|identity-discovery-[0-9]{2,}\.stderr|identity-load-[0-9]{2,}\.(?:stdout|stderr))\Z')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def read(path):
    if path.resolve() != path:
        raise ValueError('noncanonical input: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 4 * 1024 * 1024:
            raise ValueError('input is not a bounded ordinary file: ' + str(path))
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key)
                for after in (os.fstat(fd), path.lstat()) for key in keys):
            raise ValueError('input changed: ' + str(path))
        return raw
    finally:
        os.close(fd)


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)


def tool_object(record):
    result = record['result']
    if result.get('isError'):
        raise ValueError('recorded MCP error')
    return load_json(''.join(row['text'] for row in result['content'] if row['type'] == 'text'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.absolute()
    os.umask(0o077)
    output = root / 'independent-verification-01.json'
    destination = root / 'extracted'
    if root.resolve() != root or not root.is_dir() or os.path.lexists(output) or os.path.lexists(destination):
        raise ValueError('require canonical input root and fresh output/destination')
    checks, notes, restored, inputs = {}, {}, {}, {}
    report = {'schema': 'hepta-r21-mac-holder-offline-audit/v1', 'passed': False,
              'checks': checks, 'root': str(root), 'tool_sha256': digest(read(Path(__file__).resolve())),
              'remote_operations_performed_by_auditor': False, 'archived_code_executed': False,
              'x230_report_bytes_read': False, 'x230_report_sha256': None,
              'cross_package_report_identity_binding_required': True, 'runtime_adoption_assessed': False}

    def check(name, value):
        checks[name] = bool(value)
        if not checks[name]:
            raise ValueError(name)

    try:
        inputs = {name: read(root / name) for name in INPUTS}
        check('four_exact_received_inputs', all((len(inputs[name]), digest(inputs[name])) == pin for name, pin in INPUTS.items()))
        manifest, receipt, exporter_install = (load_json(inputs[name]) for name in ('manifest.json', 'receipt.json', 'holder-exporter-installed-01.json'))
        check('producer_export_complete_without_errors', manifest['schema'] == 'hepta-r21-mac-holder-export/v1'
              and receipt['schema'] == 'hepta-r21-mac-holder-export-receipt/v1'
              and manifest['mode'] == receipt['mode'] == 'success'
              and receipt['export_succeeded'] is True and receipt['complete_success_evidence_verified'] is True
              and receipt['files'] == 28 and receipt['archive_members'] == 29
              and receipt['readable_evidence_preserved'] is True and receipt['automatic_retries'] == 0
              and all(value is True for value in manifest['checks_before_archive'].values())
              and len(manifest['checks_before_archive']) == 15
              and not any(receipt[key] for key in ('read_errors', 'validation_errors', 'after_archive_errors'))
              and not manifest['read_errors'] and not manifest['validation_errors'])
        check('receipt_binds_received_archive_and_manifest', all(
            (receipt[key]['size'], receipt[key]['sha256']) == INPUTS[name]
            and receipt[key]['path'] == REMOTE + '/export-holder-01/' + name
            for key, name in (('archive', 'holder-evidence-01.tar.gz'), ('manifest', 'manifest.json'))))
        records = manifest['files']
        by_name = {row['path']: row for row in records}
        check('manifest_exact_28_unique_files', len(records) == len(by_name) == 28)
        with tarfile.open(fileobj=io.BytesIO(inputs['holder-evidence-01.tar.gz']), mode='r:gz') as tar:
            members = tar.getmembers()
            names = [member.name for member in members]
            check('tar_exact_29_unique_members', len(names) == len(set(names)) == 29
                  and names[0] == '_export-manifest.json' and set(names) == set(by_name) | {'_export-manifest.json'})
            for member in members:
                name = member.name
                pure = PurePosixPath(name)
                if (not name or name.startswith('/') or '\\' in name or '\x00' in name
                        or any(part in ('', '.', '..') for part in name.split('/')) or str(pure) != name
                        or not member.isfile() or member.issym() or member.islnk() or member.pax_headers
                        or member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname or member.gname
                        or member.size < 0 or member.size > 2 * 1024 * 1024):
                    raise ValueError('unsafe or noncanonical archive member: ' + name)
                raw = tar.extractfile(member).read()
                if len(raw) != member.size:
                    raise ValueError('short archive member: ' + name)
                if name == '_export-manifest.json':
                    if raw != inputs['manifest.json'] or member.mode != 0o600:
                        raise ValueError('embedded manifest differs')
                else:
                    row = by_name[name]
                    source_stamp = row['source_stamp']
                    if ((len(raw), digest(raw), member.mode) != (row['size'], row['sha256'], row['mode'])
                            or row['mode'] != 0o600 or source_stamp['st_nlink'] != 1
                            or not stat.S_ISREG(source_stamp['st_mode']) or source_stamp['st_uid'] != 501
                            or stat.S_IMODE(source_stamp['st_mode']) != row['mode'] or source_stamp['st_size'] != len(raw)):
                        raise ValueError('member identity mismatch: ' + name)
                restored[name] = raw
        check('all_payload_bytes_and_modes_match', len(restored) == 29)
        check('all_frozen_sources_and_report_match', all((len(restored[name]), digest(restored[name])) == pin for name, pin in PAYLOAD_PINS.items()))
        check('original_path_mapping_exact', all(row['original_path'] == REMOTE + '/' +
            (name if name.startswith('campaign-01/') else name.split('/', 1)[1]) for name, row in by_name.items()))
        holder = load_json(restored['campaign-01/report.json'])
        campaign_names = {name.split('/', 1)[1] for name in by_name if name.startswith('campaign-01/')}
        expected_logs = {row['file']: row for row in holder['log_files']}
        check('complete_original_campaign_inventory_and_logs', len(campaign_names) == 22
              and all(LOG_NAME.fullmatch(name) for name in campaign_names)
              and len(expected_logs) == len(holder['log_files']) == 21
              and set(expected_logs) == campaign_names - {'report.json'}
              and all((len(restored['campaign-01/' + name]), digest(restored['campaign-01/' + name])) == (row['bytes'], row['sha256']) for name, row in expected_logs.items())
              and manifest['source_inventory_before'] == manifest['source_inventory_after_collection']
              and {row['name'] for row in manifest['source_inventory_before']} == campaign_names
              and all(row['permitted_name'] is True and row['regular'] is True for row in manifest['source_inventory_before']))
        bootstrap_sha = PAYLOAD_PINS['sources/campaign-bootstrap-01.py'][1]
        holder_sha = PAYLOAD_PINS['sources/held_agent_campaign_02.py'][1]
        check('holder_terminal_success_and_exact_sources', holder['schema'] == 'hepta-x230-r21-held-agent-campaign/v1'
              and holder['passed'] is True and holder['remote_returncode'] == 0 and type(holder['remote_returncode']) is int
              and holder.get('error') is None and holder.get('foreground_timed_out') is not True
              and holder.get('remote_completion_unknown') is not True and bool(holder['finished_utc'])
              and holder['holder_script_sha256'] == holder_sha and holder['remote_script_sha256'] == bootstrap_sha
              and restored['campaign-01/remote-script.py'] == restored['sources/campaign-bootstrap-01.py'])
        check('foreground_completion_and_agent_reap_recorded', holder['foreground_pid'] > 1 and holder['owned_agent_pid'] > 1
              and holder['owned_agent_reaped'] is True and holder['owned_agent_returncode'] == 2
              and holder['foreground_end_monotonic_ns'] >= holder['foreground_start_monotonic_ns']
              and holder['foreground_seconds'] == (holder['foreground_end_monotonic_ns'] - holder['foreground_start_monotonic_ns']) / 1e9)
        owned_directory = holder['owned_agent_directory']
        cleanup = manifest['current_owned_cleanup_metadata']
        check('recorded_cleanup_and_export_absence_witnesses', re.fullmatch(r'/tmp/hr19a-[A-Za-z0-9_-]+', owned_directory)
              and holder['owned_agent_socket'] == owned_directory + '/agent.sock'
              and holder['owned_agent_directory_absent_after_context'] is True
              and holder['owned_agent_socket_absent_after_context'] is True
              and cleanup['directory'] == {'path': owned_directory, 'absent': True}
              and cleanup['socket'] == {'path': holder['owned_agent_socket'], 'absent': True})
        check('no_retries_or_sensitive_dump_assertions', holder['automatic_ssh_retries'] == 0
              and all(holder[key] is False for key in ('services_modified', 'key_bytes_retained', 'complete_environment_retained', 'ssh_configuration_dump_retained'))
              and all(manifest[key] is False for key in ('sensitive_paths_opened', 'agent_socket_contents_read', 'new_ssh_or_workload_or_cleanup_started')))
        log_rows = holder['identity_discovery'] + holder['identity_loads']
        check('all_identity_operation_streams_preserved', len(holder['identity_discovery']) == holder['configured_target_count'] == 7
              and len(holder['identity_loads']) == holder['configured_identity_count'] == 5
              and all(row['returncode'] == 0 and all(stream not in row or row[stream] == expected_logs[row[stream]['file']]
                  for stream in ('stdout', 'stderr')) for row in log_rows))
        footer = load_json([line for line in restored['campaign-01/forwarded.stdout'].decode().splitlines() if line.strip()][-1])
        check('footer_closes_transport_and_retains_failed_native_screen', footer == manifest['forwarded_final_line']
              and footer['passed'] is True and footer['native_regression_screen_passed'] is False and footer['error'] is None
              and footer['report'] == X230_REPORT and receipt['native_regression_screen_passed_observed'] is False)
        current_install = load_json(restored['installations/campaign-tools-installed-01.json'])
        legacy_install = load_json(restored['installations/holder-installed-01.json'])
        check('both_historical_install_receipts_and_exporter_install_bound', current_install['passed'] is True
              and legacy_install['passed'] is True and exporter_install['passed'] is True and exporter_install['executed'] is False
              and exporter_install['protected_originals_unchanged'] is True
              and exporter_install['sha256'] == PAYLOAD_PINS['exporter/export_mac_holder_01.py'][1]
              and exporter_install['size'] == PAYLOAD_PINS['exporter/export_mac_holder_01.py'][0]
              and all(digest(restored[name]) == exporter_install['protected_sha256'][original]
                  for name, original in ((name, name if name.startswith('campaign-01/') else name.split('/', 1)[1])
                      for name in PAYLOAD_PINS if not name.startswith('exporter/'))))
        check('cross_package_scope_is_explicit', manifest['x230_report_bytes_read'] is False and manifest['x230_report_sha256'] is None
              and receipt['x230_report_bytes_read'] is False and receipt['x230_report_sha256'] is None
              and manifest['cross_package_report_identity_binding_required'] is True
              and manifest['runtime_adoption_assessed'] is False and receipt['runtime_adoption_assessed'] is False)
        operations = root / 'operations'
        info = tool_object(load_json(read(operations / 'archive-file-info-01.json')))
        recorded_chunk = load_json(read(operations / 'archive-binary-read-0000.json'))
        chunk = tool_object(recorded_chunk)
        decoded = base64.b64decode(chunk['data_base64'], validate=True)
        check('complete_pinned_version_binary_transfer_replayed', decoded == inputs['holder-evidence-01.tar.gz']
              and chunk['version'] == info['version'] == recorded_chunk['request']['expected_version']
              and chunk['offset'] == 0 and chunk['next_offset'] == chunk['size'] == len(decoded) and chunk['eof'] is True
              and chunk['chunk_sha256'] == info['sha256'] == digest(decoded) and recorded_chunk['request']['limit'] == 32768)
        metadata = tool_object(load_json(read(operations / 'metadata-read-batch-01.json')))
        check('all_external_text_inputs_replayed_from_raw_receipt', len(metadata['files']) == 3 and metadata['truncated'] is False
              and all(row['text'].encode() == inputs[PurePosixPath(row['path']).name]
                  and (row['size'], row['sha256']) == INPUTS[PurePosixPath(row['path']).name] and row['eof'] is True for row in metadata['files']))
        durable_logs = {}
        for stage, job_id in (('install', '1a1a99296e6-fc05-3611'), ('export', '1a1a99326a1-fc05-3617')):
            status = tool_object(load_json(read(operations / (stage + '-status-01.json'))))
            streams = tool_object(load_json(read(operations / (stage + '-read-01.json'))))
            check(stage + '_durable_job_terminal_without_retry', status['job_id'] == job_id and status['state'] == 'succeeded'
                  and status['exit_code'] == 0 and status['terminal_publication_confirmed'] is True
                  and status['output_complete'] is True and status['output_durable'] is True
                  and status['automatic_retry'] is False and status['timed_out'] is False
                  and all(value is None for value in status['log_errors'].values())
                  and all(value is False for value in status['log_truncated'].values()) and streams['job_id'] == job_id)
            for stream in ('stdout', 'stderr'):
                record = streams[stream]
                raw = bytes.fromhex(record['bytes_hex'])
                if raw.decode() != record['text'] or len(raw) != record['size'] or record['offset'] != 0 or record['next_offset'] != len(raw) or record['eof'] is not True:
                    raise ValueError('incomplete durable stream: ' + stage + '/' + stream)
                durable_logs[stage + '.' + stream] = raw
        check('export_stdout_equals_original_receipt', load_json(durable_logs['export.stdout']) == receipt)
        destination.mkdir(mode=0o700)
        for name, raw in sorted(restored.items()):
            path = destination.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_new(path, raw)
        stream_dir = root / 'durable-logs'
        stream_dir.mkdir(mode=0o700)
        for name, raw in durable_logs.items():
            write_new(stream_dir / name, raw)
        check('fresh_local_restore_exact_set_and_bytes', {str(path.relative_to(destination)) for path in destination.rglob('*') if path.is_file()} == set(restored)
              and all(read(destination / name) == raw for name, raw in restored.items()))
        check('received_inputs_unchanged_after_audit', all(read(root / name) == raw for name, raw in inputs.items()))
        report.update(passed=True, payload_files=28, archive_members=29, campaign_files=22, original_log_files=21,
                      archive_sha256=INPUTS['holder-evidence-01.tar.gz'][1], archive_size=15653,
                      archive_git_blob_sha1=hashlib.sha1(b'blob 15653\0' + inputs['holder-evidence-01.tar.gz']).hexdigest(),
                      manifest_sha256=INPUTS['manifest.json'][1], holder_report_sha256=PAYLOAD_PINS['campaign-01/report.json'][1],
                      holder_passed=True, remote_returncode=0, owned_agent_returncode=2, owned_agent_reaped=True,
                      owned_directory_absent_recorded=True, owned_socket_absent_recorded=True,
                      export_cleanup_metadata_absent=True, foreground_seconds=holder['foreground_seconds'],
                      foreground_reap_scope=manifest['foreground_reap_scope'],
                      native_regression_screen_passed=False, forwarded_final_line=footer,
                      extracted_root=str(destination), files=[{key: row[key] for key in ('path', 'original_path', 'size', 'sha256', 'mode')} for row in records])
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
        report['traceback'] = traceback.format_exc()
    report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write_new(output, (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'passed': report['passed'], 'checks': len(checks), 'output': str(output),
                      'sha256': digest(read(output)), 'error': report.get('error'),
                      'native_regression_screen_passed': report.get('native_regression_screen_passed')}, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
