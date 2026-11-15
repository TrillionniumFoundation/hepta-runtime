#!/usr/bin/env python3
"""Read fixed original archive bytes and verify twelve recorded Controller/writer closures."""
import argparse
from collections import Counter
import datetime
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

ARCHIVE_BYTES = 3961240
ARCHIVE_SHA = '30ff7e2dae12aa00a0048c9808610a76b17b4a37daa9de32dfab1fea06f2c9c9'
REMOTE_ROOT = '/home/qian/hepta-runtime-optimization-20261106-r36/'
ROUNDS = ('round-0-A', 'round-1-B', 'round-2-B', 'round-3-A')
GENERATIONS = (
    ('first-controller', 'first_startup', 'intentional_crash', -9, 'already_exited'),
    ('after-crash-controller', 'after_crash_startup', 'after_cancel_shutdown', 0, 'stdin_eof'),
    ('after-cancel-controller', 'after_cancel_startup', 'shutdown', 0, 'stdin_eof'),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {'bytes': len(raw), 'sha256': digest(raw)}


def stamp(info):
    return {name: getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def read_direct(path, maximum):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise ValueError('expected bounded direct regular input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(raw) != before.st_size or stamp(before) != stamp(after) or stamp(after) != stamp(path.lstat()):
        raise ValueError('input changed during bounded read')
    return raw, stamp(before)


def raw_process_identity(value):
    raw = value['raw_stat']
    left, right = raw.find('('), raw.rfind(') ')
    fields = raw[right + 2:].split()
    if left < 0 or right < left or len(fields) < 20:
        return False
    return (int(raw[:left].strip()) == value['pid'] and int(fields[19]) == value['birth_ticks']
            and int(fields[1]) == value['ppid'] and fields[0] not in ('Z', 'X'))


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=root / 'r36-evidence-download/r36-evidence-01.tar.xz')
    parser.add_argument('--trusted-tools', type=Path, default=root / 'r36-control/lifecycle-tools-01')
    parser.add_argument('--out', type=Path, default=root / 'r36-independent-review/raw-controller-closure-review.json')
    args = parser.parse_args()
    if os.path.lexists(args.out):
        raise ValueError('review output must be fresh')
    checks, selected, generations, rounds = [], {}, [], []

    def check(name, value, observed=None):
        record = {'name': name, 'passed': bool(value)}
        if observed is not None:
            record['observed'] = observed
        checks.append(record)
        if not value:
            raise ValueError('independent closure check failed: ' + name)

    archive_raw, archive_stat = read_direct(args.archive, ARCHIVE_BYTES)
    check('archive_exact_observed_bytes_sha256', len(archive_raw) == ARCHIVE_BYTES and digest(archive_raw) == ARCHIVE_SHA)
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=512 * 1024**2)
    expanded = decoder.decompress(archive_raw, max_length=512 * 1024**2 + 1)
    check('single_bounded_xz_sha256_stream', len(expanded) <= 512 * 1024**2 and decoder.eof
          and not decoder.unused_data and decoder.check == lzma.CHECK_SHA256)
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        members = archive.getmembers()
        check('first_manifest', bool(members) and members[0].name == '_export-manifest.json')
        check('canonical_regular_member_headers', all(m.type == tarfile.REGTYPE and not m.linkname and not m.pax_headers
              and m.mode == 0o600 and m.uid == m.gid == m.mtime == 0 and not m.uname and not m.gname
              and str(PurePosixPath(m.name)) == m.name and not PurePosixPath(m.name).is_absolute()
              and '..' not in PurePosixPath(m.name).parts and '\\' not in m.name for m in members))
        manifest_raw = archive.extractfile(members[0]).read()
        manifest = json.loads(manifest_raw)
        payloads = manifest['payloads']
        check('canonical_full_member_order', [m.name for m in members] == ['_export-manifest.json'] + sorted(payloads))
        check('scope_root', manifest['root'] + '/' == REMOTE_ROOT)

        def body(name):
            if name in selected:
                return selected[name]['body']
            check('listed_payload:' + name, name in payloads)
            member = archive.getmember(name)
            check('selected_regular_bounded:' + name, member.type == tarfile.REGTYPE and member.size <= 32 * 1024**2)
            raw = archive.extractfile(member).read()
            identity = pin(raw)
            check('payload_hash:' + name, all(identity[k] == payloads[name][k] for k in ('bytes', 'sha256')))
            selected[name] = {'body': raw, **identity}
            return raw

        def identity_matches(name, expected):
            raw = body(name)
            return all(pin(raw)[key] == expected[key] for key in ('bytes', 'sha256'))

        def json_lines(name):
            raw = body(name)
            lines = raw.splitlines(keepends=True)
            check('complete_json_lines:' + name, bool(lines) and all(line.endswith(b'\n') and line.strip() for line in lines))
            return raw, lines, [json.loads(line) for line in lines]

        trusted = {}
        tool_manifest_name = 'r36/lifecycle-tools-01/lifecycle-tools-manifest-01.json'
        tool_manifest = json.loads(body(tool_manifest_name))
        for name in ('run_six_host_cancel_recovery_timed.py', 'x230_observation_benchmark.py', 'observation_resources.py'):
            raw, _ = read_direct(args.trusted_tools / name, 262144)
            trusted[name] = pin(raw)
            check('trusted_local_equals_pinned_archived_tool:' + name,
                  raw == body('r36/lifecycle-tools-01/' + name) and trusted[name] == tool_manifest['files'][name])
        inner_name = 'r36/lifecycle-abba-01/report.json'
        inner = json.loads(body(inner_name))
        index_name = 'r36/lifecycle-abba-01/round-index.json'
        index = json.loads(body(index_name))
        outer_name = 'r36/lifecycle-campaign-01/report.json'
        outer = json.loads(body(outer_name))
        check('original_rejection_preserved', inner['passed'] is False and outer['passed'] is False and outer['adoption_passed'] is False)
        normal_stage = [s for s in outer['stages'] if s['name'] == 'normal-lifecycle-abba']
        check('one_original_normal_lifecycle_stage', len(normal_stage) == 1)
        original_unknown = normal_stage[0]['independent_controller_cleanup']
        check('outer_unknown_preserved', original_unknown == 'unknown; stage-group absence is insufficient and no workload is retried')
        check('inner_tools_manifest_bound', identity_matches(tool_manifest_name, inner['tools_manifest']))
        check('closed_abba_round_index', index['closed'] is True and index['round_count'] == 4 and index['order'] == 'ABBA'
              and [r['directory'] for r in index['rounds']] == list(ROUNDS))
        check('inner_round_index_bound', identity_matches(index_name, inner['round_index']))
        bindings = {b['path'].removeprefix(REMOTE_ROOT): b for b in normal_stage[0]['output_bindings']}
        check('outer_inner_report_binding', identity_matches(inner_name, bindings['lifecycle-abba-01/report.json']))
        check('outer_round_index_binding', identity_matches(index_name, bindings['lifecycle-abba-01/round-index.json']))

        identities = []
        for round_position, round_name in enumerate(ROUNDS):
            base = 'r36/lifecycle-abba-01/' + round_name + '/'
            report_name = base + 'report.json'
            report = json.loads(body(report_name))
            check(round_name + ':round_report_bound', identity_matches(report_name, index['rounds'][round_position]['report']))
            check(round_name + ':complete_successful_canary_report', report['passed'] is True and report['phase'] == 'completed'
                  and report['phases'][-1]['phase'] == 'completed'
                  and not any(k in report for k in ('error', 'cleanup_error', 'final_check_error', 'interrupted_shutdown')))
            check(round_name + ':local_tool_identity', report['script_sha256'] == trusted['run_six_host_cancel_recovery_timed.py']['sha256']
                  and report['helper_hashes']['benchmark'] == trusted['x230_observation_benchmark.py']['sha256'])
            check(round_name + ':original_checks_and_no_retries', all(report[k] is True for k in
                  ('source_originals_unchanged', 'binary_unchanged', 'current_agent_unchanged', 'topology_manifest_unchanged'))
                  and report['automatic_rpc_retries'] == 0)
            check(round_name + ':all_native_calls_map_to_exact_generation', all(row['controller_directory'] in
                  {g[0] for g in GENERATIONS} for row in report['native_calls']))
            round_rows = []
            for generation_index, (directory, start_key, close_key, exit_code, method) in enumerate(GENERATIONS):
                prefix = round_name + ':' + directory
                start, close = report[start_key], report[close_key]
                identity = (start['pid'], start['birth_ticks'])
                identities.append(identity)
                check(prefix + ':startup_identity_positive', all(type(x) is int and x > 0 for x in identity))
                allocator = start['allocator_environment']
                check(prefix + ':startup_allocator_identity', (allocator['pid'], allocator['birth_ticks']) == identity
                      and allocator['status'] == 'verified')
                check(prefix + ':expected_waited_exit', close['exit_code'] == exit_code and close['shutdown_method'] == method)
                check(prefix + ':reader_and_observed_survivor_receipt', close['reader_error'] is None
                      and close['unmatched_responses'] == 0 and close['observed_descendant_survivors'] == [])
                resources, transport = close['resources'], close['transport_capture']
                check(prefix + ':writers_finished_receipt', resources['sampler_error'] is None and transport['reader_eof'] is True)
                expected_files = {'raw': 'transport-responses.jsonl', 'index': 'transport-responses.index.jsonl', 'resource': 'resource-samples.jsonl'}
                check(prefix + ':writer_filenames', transport['raw']['file'] == expected_files['raw']
                      and transport['index']['file'] == expected_files['index'] and resources['trace']['file'] == expected_files['resource'])
                raw_name = base + directory + '/' + expected_files['raw']
                index_member = base + directory + '/' + expected_files['index']
                resource_name = base + directory + '/' + expected_files['resource']
                stderr_name = base + directory + '/stderr.log'
                check(prefix + ':raw_writer_final_hash', identity_matches(raw_name, transport['raw']))
                check(prefix + ':index_writer_final_hash', identity_matches(index_member, transport['index']))
                check(prefix + ':resource_writer_final_hash', identity_matches(resource_name, resources['trace']))
                body(stderr_name)
                raw_bytes, frames, replies = json_lines(raw_name)
                _, _, entries = json_lines(index_member)
                _, _, samples = json_lines(resource_name)
                check(prefix + ':final_frame_and_index_count', len(frames) == len(entries) == transport['frames'])
                check(prefix + ':final_resource_record_count', len(samples) == resources['trace']['records'] == resources['samples'])
                offset = 0
                frame_checks = []
                for frame_number, (frame, reply, entry) in enumerate(zip(frames, replies, entries)):
                    frame_checks.append(entry['sequence'] == frame_number and entry['offset'] == offset
                        and entry['bytes'] == len(frame) and entry['sha256'] == digest(frame)
                        and entry['complete_line'] is True and entry['has_id'] is True and reply['id'] == entry['rpc_id']
                        and entry['read_start_monotonic_ns'] <= entry['received_monotonic_ns'])
                    offset += len(frame)
                check(prefix + ':every_indexed_frame_covers_exact_bytes_to_eof', all(frame_checks) and offset == len(raw_bytes))
                init = start['initialize_rpc']
                init_trace = init['transport_response']
                check(prefix + ':startup_initialize_to_first_frame', init['request_id'] == 1 and init_trace['file'] == expected_files['raw']
                      and {k: v for k, v in init_trace.items() if k != 'file'} == entries[0] and entries[0]['rpc_id'] == 1)
                calls = [r for r in report['native_calls'] if r['controller_directory'] == directory]
                observed_sequences = {0}
                call_checks = []
                for row in calls:
                    rpc = row['rpc']
                    proof = rpc['transport_response']
                    sequence = proof['sequence']
                    call_checks.append(row['okay'] is True and row['automatic_retry'] is False and 0 < sequence < len(entries)
                        and proof['file'] == expected_files['raw']
                        and {k: v for k, v in proof.items() if k != 'file'} == entries[sequence]
                        and rpc['request_id'] == entries[sequence]['rpc_id'])
                    observed_sequences.add(sequence)
                check(prefix + ':native_calls_and_initialize_cover_complete_wire', all(call_checks)
                      and len(calls) + 1 == len(entries) and observed_sequences == set(range(len(entries))))
                check(prefix + ':resource_sample_sequence', [s['sample'] for s in samples] == list(range(len(samples))))
                check(prefix + ':resource_time_endpoints', resources['first_sample_monotonic_ns'] == samples[0]['start_monotonic_ns']
                      and resources['last_sample_monotonic_ns'] == samples[-1]['end_monotonic_ns']
                      and all(s['start_monotonic_ns'] <= s['end_monotonic_ns'] for s in samples)
                      and all(a['end_monotonic_ns'] <= b['start_monotonic_ns'] for a, b in zip(samples, samples[1:])))
                processes = [p for sample in samples for p in sample['processes']]
                controller = [p for p in processes if p['scope'] == 'controller']
                check(prefix + ':startup_pid_birth_matches_all_controller_samples', bool(controller)
                      and all((p[side]['pid'], p[side]['birth_ticks']) == identity for p in controller for side in ('before', 'after')))
                check(prefix + ':retained_raw_proc_identity_matches', all(raw_process_identity(p[side]) for p in processes for side in ('before', 'after')))
                check(prefix + ':controller_scope_matches_root_identity', all((p['scope'] == 'controller') ==
                      ((p['before']['pid'], p['before']['birth_ticks']) == identity) for p in processes))
                missing = [m for sample in samples for m in sample['missing']]
                error_counts = Counter(m['stage'] + ':' + m['type'] for m in missing)
                check(prefix + ':all_missing_observations_retained', dict(error_counts) == resources['error_counts']
                      and missing[:16] == resources['errors'])
                seen = {}
                for p in processes:
                    ident = (p['before']['pid'], p['before']['birth_ticks'])
                    prior = seen.get(ident, p['scope'])
                    seen[ident] = p['scope'] if prior == p['scope'] else 'mixed_descendants'
                check(prefix + ':recorded_seen_generations_match_trace', len(seen) == resources['sampled_process_generations']
                      and dict(Counter(seen.values())) == resources['sampled_process_generations_by_scope'])
                if generation_index < 2:
                    next_start = report[GENERATIONS[generation_index + 1][1]]['start_monotonic_ns']
                    check(prefix + ':writers_end_before_next_generation_starts', resources['last_sample_monotonic_ns'] < next_start
                          and entries[-1]['received_monotonic_ns'] < next_start)
                row = {'round': round_name, 'generation_directory': directory, 'startup_field': start_key, 'closure_field': close_key,
                       'pid': identity[0], 'birth_ticks': identity[1], 'exit_code': close['exit_code'], 'shutdown_method': close['shutdown_method'],
                       'reader_eof': transport['reader_eof'], 'reader_error': close['reader_error'],
                       'sampler_error': resources['sampler_error'], 'unmatched_responses': close['unmatched_responses'],
                       'recorded_observed_descendant_survivors': close['observed_descendant_survivors'],
                       'observed_process_generations': len(seen), 'observed_descendant_generations': len(seen) - 1,
                       'transport_frames': len(frames), 'native_call_count': len(calls), 'resource_records': len(samples),
                       'controller_process_observations': len(controller), 'all_process_observations': len(processes),
                       'trace_missing_observations': len(missing), 'trace_unexpected_missing_observations': sum(m.get('expected_exit_race') is not True for m in missing),
                       'files': {name: {k: selected[name][k] for k in ('bytes', 'sha256')} for name in (raw_name, index_member, resource_name, stderr_name)},
                       'original_sampling_limitations': resources['limitations']}
                generations.append(row)
                round_rows.append(row)
            rounds.append({'round': round_name, 'report': {**pin(body(report_name)), 'member': report_name},
                           'original_passed': report['passed'], 'generations_verified': len(round_rows),
                           'transport_frames': sum(r['transport_frames'] for r in round_rows),
                           'resource_records': sum(r['resource_records'] for r in round_rows)})
        check('twelve_distinct_controller_generations', len(identities) == len(set(identities)) == 12)
    check('archive_unchanged_during_review', stamp(args.archive.lstat()) == archive_stat)
    result = {
        'schema': 'hepta-r36-raw-controller-closure-review/v1', 'review_passed': True,
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'reviewer': '/root/repair_evidence_capture',
        'scope': 'Four original lifecycle ABBA rounds, twelve recorded Controller generations and their completed local wire/index/resource writers; no new live process probe.',
        'archive': {'bytes': ARCHIVE_BYTES, 'sha256': ARCHIVE_SHA}, 'manifest': pin(manifest_raw),
        'trusted_local_tools': trusted, 'canonical_archive_members': len(members),
        'selected_member_payload_hashes_recomputed': len(selected),
        'selected_members': {name: {k: row[k] for k in ('bytes', 'sha256')} for name, row in sorted(selected.items())},
        'all_archive_payload_hashes_recomputed_by_this_review': False,
        'rounds': rounds, 'generations': generations,
        'totals': {'controller_generations': len(generations), 'intentional_sigkill_generations': sum(r['exit_code'] == -9 for r in generations),
                   'normal_eof_generations': sum(r['exit_code'] == 0 and r['shutdown_method'] == 'stdin_eof' for r in generations),
                   'transport_frames': sum(r['transport_frames'] for r in generations),
                   'native_calls': sum(r['native_call_count'] for r in generations),
                   'resource_records': sum(r['resource_records'] for r in generations),
                   'trace_unexpected_missing_observations': sum(r['trace_unexpected_missing_observations'] for r in generations)},
        'check_count': len(checks), 'checks': checks,
        'outer_original_independent_controller_cleanup': original_unknown,
        'outer_original_unknown_rewritten': False,
        'source_semantics': [
            'The timed canary explicitly waits for the first SIGKILLed Controller before close; the later two close calls require exit zero and stdin EOF.',
            'Controller.close joins and checks the reader thread, flushes/fsyncs/closes both wire files, closes stderr, then calls Resources.stop before constructing the closure receipt.',
            'Resources.stop joins and checks its sampler thread, flushes/fsyncs/closes the resource trace, then returns final byte/hash/record counts.',
            'The final canary checkpoint atomically replaces and directory-fsyncs the report before a successful return.',
        ],
        'limitations': [
            'This verifies retained original closure receipts and their complete raw-file bindings, not a new live process inventory.',
            'The original outer independent_controller_cleanup unknown is preserved; this is a separate narrower supplement.',
            'An empty observed_descendant_survivors list covers sampled PID/start-tick generations only. Sampling can miss short-lived or reparented descendants.',
            'No claim is made that every possible SSH process or all remote workload processes were independently observed absent by this review.',
            'Resource missing observations are retained; sampler_error=null does not imply each per-process resource read succeeded.',
            'Performance gates and acceptance are unchanged; this report is not a new performance measurement.',
        ],
        'candidate_accepted': False, 'mandatory_lifecycle_gates_passed': False,
        'archive_extracted_by_this_review': False, 'archive_code_executed': False,
        'paths_inside_archive_followed_on_filesystem': False, 'live_process_absence_rechecked': False,
        'remote_operations': 0, 'performance_workloads_executed': 0,
    }
    with args.out.open('x') as output:
        output.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    raw, _ = read_direct(args.out, 4 * 1024**2)
    print(json.dumps({'review_passed': True, 'check_count': len(checks), 'totals': result['totals'], 'output': str(args.out), **pin(raw)}))


if __name__ == '__main__':
    main()
