#!/usr/bin/env python3
"""Recompute original native request/terminal/read coverage from a fixed local inventory."""
import argparse
import hashlib
import json
from pathlib import Path

TERMINAL = {'succeeded', 'failed', 'cancelled', 'timed_out', 'effect_unknown'}
UNKNOWN_INSTALL = None


# Exact walker from the earlier reviewed audit_existing_native_logs_02.py.
def walk(value, pointer='$', depth=0):
    if depth > 16:
        return
    if isinstance(value, dict):
        yield pointer, value
        for key, child in value.items():
            path = pointer + '.' + key
            if isinstance(child, (dict, list)):
                yield from walk(child, path, depth + 1)
            elif key in ('text', 'response_text', 'raw_response_text') and isinstance(child, str):
                try:
                    decoded = json.loads(child)
                except (ValueError, UnicodeError):
                    continue
                yield from walk(decoded, path + '[decoded]', depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value[:256]):
            yield from walk(child, pointer + '[' + str(index) + ']', depth + 1)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def strong(value):
    return (value.get('state') in TERMINAL and type(value.get('exit_code')) is int
        and all(value.get(k) is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
        and value.get('terminal_publication_protocol') == 1
        and value.get('log_synced') == {'stdout': True, 'stderr': True}
        and value.get('log_errors') == {'stdout': None, 'stderr': None}
        and value.get('log_truncated') == {'stdout': False, 'stderr': False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise ValueError('fresh coverage output required')
    raw_index = args.inventory.read_bytes()
    index = json.loads(raw_index)
    if index['schema'] != 'hepta-r29-native-custody-input-snapshot/v1':
        raise ValueError('fixed original inventory required')
    allowed_jobs = set(index['operation_jobs'])
    if index['excluded_job'] in allowed_jobs or not allowed_jobs:
        raise ValueError('fixed operation scope differs')
    records, requests, referenced_jobs = {}, [], set()
    for item in index['files']:
        path = Path(item['source_path'])
        raw = path.read_bytes()
        if identity(raw) != {k: item[k] for k in ('bytes', 'sha256')}:
            raise ValueError('frozen original changed: ' + str(path))
        if path.suffix != '.json':
            continue
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            continue
        for pointer, dto in walk(value):
            source = {'path': str(path), 'sha256': item['sha256'], 'json_pointer': pointer}
            if all(k in dto for k in ('host', 'executable', 'args', 'idempotency_key')) and 'request_digest' not in dto:
                requests.append((source, dto))
            job = dto.get('job')
            if isinstance(job, dict) and all(k in job for k in ('id', 'host', 'args', 'idempotency_key', 'request_digest')):
                if job['id'] not in allowed_jobs:
                    referenced_jobs.add(job['id'])
                    if job['id'] == index['excluded_job'] or 'r29' in job['idempotency_key'].lower():
                        raise ValueError('unexpected current-operation start in fixed custody scope: ' + job['id'])
                    continue
                record = records.setdefault(job['id'], {'starts': [], 'status': [], 'reads': []})
                record['starts'].append((source, dto))
            job_id = dto.get('job_id')
            if not isinstance(job_id, str):
                continue
            if job_id not in allowed_jobs:
                referenced_jobs.add(job_id)
                continue
            if 'log_bytes' in dto and 'terminal_publication_confirmed' in dto:
                records.setdefault(job_id, {'starts': [], 'status': [], 'reads': []})['status'].append((source, dto))
            if all(isinstance(dto.get(k), dict) and 'bytes_hex' in dto[k] for k in ('stdout', 'stderr')):
                records.setdefault(job_id, {'starts': [], 'status': [], 'reads': []})['reads'].append((source, dto))
    for job_id in allowed_jobs:
        records.setdefault(job_id, {'starts': [], 'status': [], 'reads': []})
    results, gaps = {}, []
    for job_id, record in sorted(records.items()):
        terminals = [(s, v) for s, v in record['status'] if strong(v)]
        final = max(terminals, key=lambda pair: pair[1].get('at_unix_ms', 0))[1] if terminals else None
        if final:
            critical = ('state', 'exit_code', 'log_bytes', 'automatic_retry', 'cancelled', 'timed_out')
            if any(any(v.get(k) != final.get(k) for k in critical) for _, v in terminals):
                raise ValueError('original strong terminal records disagree: ' + job_id)
        declaration = index['operation_jobs'][job_id]
        if final and (final['state'], final['exit_code']) != (declaration['expected_state'], declaration['expected_exit_code']):
            raise ValueError('declared original outcome differs: ' + job_id)
        starts = record['starts']
        start_jobs = [row['job'] for _, row in starts]
        if any(row['host'] != declaration['host'] or row['idempotency_key'] != declaration['idempotency_key'] for row in start_jobs):
            raise ValueError('declared original host/key differs: ' + job_id)
        hosts = {row['host'] for row in start_jobs}
        if len(hosts) > 1:
            raise ValueError('original host identity conflicts: ' + job_id)
        host = next(iter(hosts)) if hosts else None
        matched_requests = []
        for source, request in requests:
            if any(request['idempotency_key'] == job['idempotency_key']
                   and request['host'] == job['host'] and request['executable'] == job['executable']
                   and request['args'] == job['args'] and request.get('cwd') == job.get('cwd')
                   for job in start_jobs):
                matched_requests.append(source)
        streams = {}
        for channel in ('stdout', 'stderr'):
            pages = []
            for source, dto in record['reads']:
                value = dto[channel]
                body = bytes.fromhex(value['bytes_hex'])
                if not (all(type(value[k]) is int and value[k] >= 0 for k in ('offset', 'next_offset', 'size'))
                        and value['size'] >= value['next_offset'] == value['offset'] + len(body)
                        and value['text'] == body.decode('utf-8') and type(value['eof']) is bool):
                    raise ValueError('original native read page differs: ' + job_id)
                pages.append((value['offset'], body, value['eof'], source))
            counts = final['log_bytes'][channel] if final else None
            stored = counts['stored'] if counts else None
            if counts and not (set(counts) == {'seen', 'stored'} and all(type(v) is int and v >= 0 for v in counts.values())):
                raise ValueError('original terminal byte counts invalid: ' + job_id)
            end = max([offset + len(body) for offset, body, _, _ in pages] + [0])
            bound = max(end, stored or 0)
            if bound > 32 * 1024**2:
                raise ValueError('original native stream exceeds fixed bound')
            body, seen = bytearray(bound), bytearray(bound)
            for offset, page, _, _ in pages:
                for pos, byte in enumerate(page, offset):
                    if seen[pos] and body[pos] != byte:
                        raise ValueError('overlapping original read pages disagree: ' + job_id)
                    body[pos], seen[pos] = byte, 1
            covered = sum(seen)
            eof = stored is not None and any(offset + len(page) == stored and at_eof for offset, page, at_eof, _ in pages)
            complete = bool(final and stored is not None and end <= stored and covered == stored and eof
                            and counts['seen'] == stored)
            streams[channel] = {'stored_bytes': stored, 'covered_bytes': covered,
                'original_eof_proved': eof, 'complete_lossless_original_read': complete,
                'reconstructed_sha256': hashlib.sha256(body).hexdigest() if complete else None,
                'pages': [{'offset': o, **identity(b), 'eof': e, 'source': s} for o, b, e, s in pages]}
        unknown = job_id == UNKNOWN_INSTALL
        if unknown and (final or any(j.get('launch_state') != 'launch_unknown' for j in start_jobs)):
            raise ValueError('preserved unknown installation unexpectedly changed')
        closed = bool(final and all(v['complete_lossless_original_read'] for v in streams.values()))
        row = {'host': host, 'original_state': final['state'] if final else None,
            'original_exit_code': final['exit_code'] if final else None,
            'strong_terminal_sources': [s for s, _ in terminals],
            'start_sources': [s for s, _ in starts], 'exact_request_sources': matched_requests,
            'original_start_request_binding_present': bool(starts and matched_requests),
            'request_digests_preserved': sorted({j['request_digest'] for j in start_jobs}),
            'request_digest_algorithm_not_recomputed': True,
            'both_native_streams_lossless': closed, 'streams': streams,
            'preserved_launch_unknown_exception': unknown,
            'unknown_operation_terminal_not_inferred_from_separate_probe': unknown}
        results[job_id] = row
        if not unknown and (not closed or not row['original_start_request_binding_present']):
            missing = []
            if not final: missing.append('strong_terminal')
            if not closed: missing.append('complete_original_native_read')
            if not starts: missing.append('original_start_response')
            if not matched_requests: missing.append('exact_original_request')
            gaps.append({'job_id': job_id, 'host': host, 'missing': missing,
                         'stdout_stored': streams['stdout']['stored_bytes'], 'stderr_stored': streams['stderr']['stored_bytes']})
    result = {'schema': 'hepta-r29-original-native-custody-coverage/v1',
        'inventory': {'path': str(args.inventory), **identity(raw_index)}, 'jobs': results,
        'job_count': len(results), 'gaps': gaps,
        'all_observed_native_operations_accounted_for': not gaps,
        'explicit_unknown_installation': UNKNOWN_INSTALL,
        'all_three_companions_verified': index['all_three_companions_verified'],
        'referenced_prior_job_ids_not_counted_as_current_operations': sorted(referenced_jobs),
        'final_publication_custody_ready': False,
        'archive_QA_and_final_file_scope_still_required': True,
        'original_files_modified': False, 'host_calls': 0, 'new_native_requests_sent': 0}
    with args.out.open('xb') as stream:
        stream.write((json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'jobs': len(results), 'gaps': gaps, 'output': str(args.out),
                      'three_companions_verified': index['all_three_companions_verified']}, sort_keys=True))


if __name__ == '__main__':
    main()
