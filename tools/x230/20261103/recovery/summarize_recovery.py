#!/usr/bin/env python3
"""Archive a supplied recovery report without altering any original report bytes."""
import argparse
import base64
from collections import Counter
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
from zoneinfo import ZoneInfo


def sha(data):
    return hashlib.sha256(data).hexdigest()


def utc_time(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()


def et_time(value):
    return datetime.datetime.fromtimestamp(value, ZoneInfo('America/New_York')).isoformat()


def summarize(source, destination, label):
    original = source.read_bytes()
    report = json.loads(original)
    booleans, errors, credential_fields = {}, {}, []
    decoded = []
    patterns = [re.compile(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----'),
                re.compile(rb'\bgh[pousr]_[A-Za-z0-9_]{20,}\b'),
                re.compile(rb'\bgithub_pat_[A-Za-z0-9_]{20,}\b'),
                re.compile(rb'\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b'),
                re.compile(rb'(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._-]{12,}')]
    secret_keys = {'private_key', 'access_token', 'refresh_token', 'client_secret', 'api_key', 'authorization', 'password'}

    def walk(value, path='', include_verdicts=True):
        if isinstance(value, dict):
            if isinstance(value.get('base64'), str):
                raw = base64.b64decode(value['base64'], validate=True)
                if len(raw) != value.get('bytes') or sha(raw) != value.get('sha256'):
                    raise ValueError('embedded evidence digest mismatch: ' + path)
                decoded.append((path, raw))
                try:
                    nested = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    nested = None
                if nested is not None:
                    walk(nested, path + '.decoded_json', False)
            for key, item in value.items():
                here = path + '.' + key if path else key
                if key.lower() in secret_keys and item not in (None, '', False, {}, []):
                    credential_fields.append(here)
                if include_verdicts and key.lower() in {'error', 'errors', 'warning', 'warnings', 'reader_error', 'cleanup_error', 'final_check_error', 'report_save_error', 'final_controller_record_errors'} and item not in (None, '', False, {}, []):
                    errors[here] = item
                walk(item, here, include_verdicts)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f'{path}[{index}]', include_verdicts)
        elif isinstance(value, bool) and include_verdicts:
            booleans[path] = value

    walk(report)
    scan_hits = []
    for name, raw in [('original_report', original), *decoded]:
        for pattern in patterns:
            if pattern.search(raw):
                scan_hits.append({'source': name, 'pattern': pattern.pattern.decode()})
    if credential_fields or scan_hits:
        raise ValueError('possible credential content; preserve original and review without redaction: ' + json.dumps({'fields': credential_fields, 'patterns': scan_hits}))

    def artifact(files, name):
        item = files.get(name)
        return None if item is None else {'bytes': item['bytes'], 'sha256': item['sha256']}

    def decoded_json(files, name):
        return json.loads(base64.b64decode(files[name]['base64'], validate=True))

    retained = {row['host']: row for row in report.get('retained_controller_records', [])}
    hosts = {}
    for host, data in report['hosts'].items():
        before = data.get('before_crash_independent', {})
        after = data.get('after_crash_independent', {})
        terminal = data.get('terminal', {})
        before_files = before.get('proof', {}).get('files', {})
        after_files = after.get('proof', {}).get('files', {})
        terminal_files = terminal.get('independent_proof', {}).get('files', {})
        ids = {'report': data.get('job_id'), 'launch': data.get('launch', {}).get('job', {}).get('id'),
               'before_crash_status': data.get('before_crash_running', {}).get('status', {}).get('job_id'),
               'recovered_status': data.get('recover_same_original', {}).get('first_status', {}).get('job_id'),
               'same_key_lookup': data.get('recover_same_original', {}).get('same_key_reuse', {}).get('job', {}).get('id'),
               'terminal_status': terminal.get('status', {}).get('job_id'),
               'retained_controller_receipt': retained.get(host, {}).get('job_id')}
        nonces = {'before_crash': before.get('launch_nonce'), 'after_crash': after.get('launch_nonce'),
                  'terminal_status': terminal.get('status', {}).get('launch_nonce')}
        payloads = {}
        for stage, files in [('before_crash', before_files), ('after_crash', after_files), ('terminal', terminal_files)]:
            if files.get('request.json'):
                payloads[stage] = decoded_json(files, 'request.json')
                ids[stage + '_remote_request'] = payloads[stage].get('job_id')
                nonces[stage + '_remote_request'] = payloads[stage].get('launch_nonce')
        for name in ('exit.json', 'exit.witness.json'):
            if terminal_files.get(name):
                payloads[name] = decoded_json(terminal_files, name)
                ids[name] = payloads[name].get('job_id')
                nonces[name] = payloads[name].get('launch_nonce')
        request_refs = {name: artifact(files, 'request.json') for name, files in (
            ('before_crash', before_files), ('after_crash', after_files), ('terminal', terminal_files))}
        reused = data.get('recover_same_original', {}).get('same_key_reuse', {})
        launch_hash = data.get('launch', {}).get('record_sha256')
        final_hash = retained.get(host, {}).get('sha256')
        hosts[host] = {
            'reported_hostname': data.get('prepare', {}).get('hostname'),
            'executable': data.get('executable'), 'ssh_target': data.get('ssh_target'),
            'source_job_id': data.get('source_job_id'), 'source_record_sha256': data.get('source_record_sha256'),
            'idempotency_key': data.get('idempotency_key'), 'request_sha256': data.get('request_sha256'),
            'job_id_observations': ids, 'all_observed_job_ids_match': bool(data.get('job_id')) and all(value == data['job_id'] for value in ids.values()),
            'launch_nonce_observations': nonces, 'all_observed_launch_nonces_match': bool(before.get('launch_nonce')) and all(value == before['launch_nonce'] for value in nonces.values()),
            'remote_request_artifacts': request_refs,
            'remote_request_bytes_unchanged': bool(request_refs['before_crash']) and all(value == request_refs['before_crash'] for value in request_refs.values()),
            'controller_receipt_sha256_at_launch': launch_hash, 'controller_receipt_sha256_after_shutdown': final_hash,
            'controller_receipt_bytes_unchanged': bool(launch_hash) and launch_hash == final_hash and retained.get(host, {}).get('original_bytes_unchanged') is True,
            'same_key_reused': reused.get('reused'), 'same_key_retried_launch': reused.get('retried_launch'),
            'same_key_launch_result': reused.get('launch'),
            'execution_count_reported': terminal.get('execution_count'),
            'original_identity_preserved_reported': terminal.get('original_identity_preserved'),
            'terminal_publication_confirmed_reported': terminal.get('terminal_publication_confirmed'),
            'terminal_status': terminal.get('status'), 'outputs': terminal.get('outputs'),
            'exit_artifact': artifact(terminal_files, 'exit.json'),
            'exit_witness_artifact': artifact(terminal_files, 'exit.witness.json'),
            'witness_matches_exact_exit_bytes': bool(terminal_files.get('exit.json')) and payloads.get('exit.witness.json', {}).get('exit_sha256') == terminal_files['exit.json']['sha256'],
            'execution_marker_artifacts': {stage: artifact(files, 'execution-marker') for stage, files in (
                ('before_crash', before_files), ('after_crash', after_files), ('terminal', terminal_files))},
        }

    transport = report.get('transport_interruption', {})
    transport_summary = {key: value for key, value in transport.items() if key not in ('original_identity_proof', 'observation_rounds')}
    transport_summary['observation_rounds'] = [{
        'name': round_['name'], 'rows': [{key: value for key, value in row.items() if key != 'status'} | {
            'state': row.get('status', {}).get('state'), 'job_id': row.get('status', {}).get('job_id'),
            'audit_recorded': row.get('status', {}).get('audit_recorded')}
            for row in round_.get('rows', [])]}
        for round_ in transport.get('observation_rounds', [])]

    def call_summary(rows, key):
        counts = Counter(row.get(key) for row in rows)
        return {'calls': len(rows), 'okay': sum(row.get('okay') is True for row in rows),
                'not_okay': sum(row.get('okay') is not True for row in rows),
                'automatic_retries': sum(row.get('automatic_retry') is True for row in rows),
                'by_kind': dict(counts), 'failures': [row for row in rows if row.get('okay') is not True]}

    archive_name = f'recovery-{label}.json.gz'
    compressed = gzip.compress(original, compresslevel=9, mtime=0)
    summary = {
        'schema': 'hepta-x230-recovery-evidence-summary/v1', 'label': label,
        'provenance': {'original_filename': source.name, 'original_bytes': len(original),
                       'original_sha256': sha(original), 'original_schema': report.get('schema'),
                       'archive_filename': archive_name, 'archive_bytes': len(compressed),
                       'archive_sha256': sha(compressed), 'lossless_decompression_verified': gzip.decompress(compressed) == original,
                       'source_commit': None, 'source_commit_note': 'The original report does not record a Git commit; no commit binding is inferred.'},
        'time': {'started_unix': report['started_unix'], 'finished_unix': report['finished_unix'],
                 'started_utc': utc_time(report['started_unix']), 'finished_utc': utc_time(report['finished_unix']),
                 'started_america_new_york': et_time(report['started_unix']), 'finished_america_new_york': et_time(report['finished_unix']),
                 'elapsed_seconds': report['finished_unix'] - report['started_unix']},
        'reported_passed': report.get('passed'), 'reported_phase': report.get('phase'),
        'scope': report.get('scope'), 'not_covered': report.get('not_covered'),
        'boundaries': {'transport': 'Optional interruption target: ' + str(transport.get('requested_host')) + '. Only the proved private SSH master of this test controller may be interrupted; observed signal/isolation results are retained separately. This is not a WAN partition.',
                       'controller_restart': 'Only this test controller was SIGKILLed. The same six remote original jobs remained running, then completed after explicit gate release.',
                       'durability': 'Original controller receipts, remote requests/nonces, persisted output, exit records and exact exit witness hashes are compared. This is not a host reboot or physical power-loss proof.',
                       'performance': 'This is a bounded fault-recovery canary, not an A/B throughput or long-duration stability benchmark.'},
        'environment_and_artifacts': {key: report.get(key) for key in (
            'controller_hostname', 'candidate_sha256', 'first_startup', 'restart_startup', 'runtime_config',
            'profile', 'script_sha256', 'benchmark_helper_sha256', 'interruption_helper_sha256',
            'remote_helper_sha256', 'workload_sha256', 'ssh_wrapper_sha256',
            'target_timeout_seconds', 'release_gate_timeout_seconds', 'stdin_bytes', 'stdin_sha256')},
        'host_identity_checks': hosts, 'transport_interruption': transport_summary,
        'controller_restart_original_jobs_preserved': report.get('controller_restart_original_jobs_preserved'),
        'controller_crash_receipt': report.get('intentional_crash'), 'restarted_controller_shutdown': report.get('shutdown'),
        'native_calls': call_summary(report.get('native_calls', []), 'tool'),
        'independent_ssh_calls': call_summary(report.get('ssh_calls', []), 'mode'),
        'effect_counts': {key: report.get(key) for key in ('new_start_call_count', 'same_key_lookup_call_count',
            'automatic_rpc_retries', 'remote_cleanup_operations', 'production_service_mutations')},
        'all_original_report_boolean_fields': booleans,
        'all_nonempty_report_error_warning_fields': errors,
        'resource_measurement_limitations': ['Original sampled peaks and process-tree CPU are explicitly lower bounds.',
            'Resource sampler errors by controller phase: ' + json.dumps({phase: report.get(phase, {}).get('resources', {}).get('errors', []) for phase in ('intentional_crash', 'shutdown')}) + '. Any errors remain visible and prevent treating those samples as complete process-tree measurements.'],
        'content_review': {'private_key_or_known_token_pattern_hits': scan_hits,
            'nonempty_structured_credential_fields': credential_fields,
            'embedded_base64_artifacts_checked': len(decoded), 'embedded_hash_and_length_checks': 'all matched',
            'scan_scope': 'Original UTF-8 report plus every embedded base64 artifact; structured credential-key review also covers decoded JSON request/exit records.',
            'original_bytes_modified_or_redacted': False,
            'qualification': 'No detected private-key blocks, known token patterns, or nonempty structured credential fields. This is a bounded content review, not a universal secret-detection guarantee.'},
    }
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / archive_name
    summary_path = destination / f'recovery-{label}-summary.json'
    for path, content in [(archive, compressed), (summary_path, (json.dumps(summary, indent=2, ensure_ascii=False) + '\n').encode())]:
        if path.exists():
            if path.read_bytes() != content:
                if path != summary_path:
                    raise FileExistsError(path)
                previous = json.loads(path.read_bytes())
                if previous.get('schema') != summary['schema'] or previous.get('label') != label or previous.get('provenance', {}).get('original_sha256') != sha(original):
                    raise FileExistsError(path)
                temporary = path.with_suffix('.next')
                with temporary.open('xb') as handle:
                    handle.write(content)
                temporary.replace(path)
        else:
            with path.open('xb') as handle:
                handle.write(content)
    if source.read_bytes() != original or gzip.decompress(archive.read_bytes()) != original:
        raise ValueError('archive verification failed')
    print(json.dumps({'summary': str(summary_path), 'archive': str(archive), 'original_sha256': sha(original),
                      'archive_sha256': sha(compressed), 'reported_passed': summary['reported_passed'],
                      'all_job_ids_match': all(h['all_observed_job_ids_match'] for h in hosts.values()),
                      'all_nonces_match': all(h['all_observed_launch_nonces_match'] for h in hosts.values()),
                      'all_receipts_unchanged': all(h['controller_receipt_bytes_unchanged'] for h in hosts.values()),
                      'nonempty_error_warning_fields': errors, 'boolean_fields': len(booleans),
                      'embedded_artifacts_checked': len(decoded)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--label', choices=('baseline', 'candidate'), required=True)
    arguments = parser.parse_args()
    summarize(arguments.source, arguments.destination, arguments.label)
