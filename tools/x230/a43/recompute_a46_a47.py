#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only verification of the archived A43 A46/A47 evidence and arithmetic.

No runtime, subprocess, SSH, workload, signal or network call is made. The
optional --source-root hashes the 166 prepared-source inputs in a checkout.
Without it, source-body validation is explicitly left to the retained source
object proof and a separate checkout/tree verification. Executable bodies and
whole-host gate sidecars are not present in this compact archive.
"""
import argparse
import hashlib
import io
import json
import math
from pathlib import Path
import re
import stat
import statistics
import tarfile
import zlib


EXPECTED_MEMBERS = {
    'qualification/report.json': '4d11845e1306869cb3ca13a402e00c3aa600605eda79c861cc2e98a9892a7617',
    'qualification/entry-report.json': '141606221523fd4ee6588b7d304fa47caacb4c48d6601f316ff2ddee3b2c91fb',
    'qualification/worker-report.json': '9d94a5878b654b4d8563721fd68a00f0285eba4d51db1bdd70235fa0b5ae1294',
    'qualification/test.log': 'a8fa1e071e03e001b8e55046887c7ba15fd4bc5b8092ff59cd1186579776a211',
    'lifecycle/report.json': 'd0d7aa1a783a7f8cd79147362b739fdbc3cadc5f6ec23fd3c73150c08825d611',
}
SOURCE_MAP = 'b9eaddec7cb30de7e18f2131bebeee98145e3d41e00243b13ec50f6fe01c0d9b'


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def map_sha(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def near(a, b, label):
    need(math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-12), 'numeric mismatch: ' + label)


def original_task(task):
    need(task['reaped'] is True and task['actual_wait4_pid'] == task['pid']
         and task['pidfd_opened'] is True and task['original_identity_bound_before_go'] is True
         and task['timed_out'] is False and not task.get('close_errors')
         and not task.get('cleanup_errors') and not task.get('error'), 'original task custody/completion differs')


def observed_result(observed, expected_exit=None):
    for value in observed['files'].values():
        raw = value['text'].encode()
        need(len(raw) == value['receipt']['bytes'] and sha(raw) == value['receipt']['sha256'],
             'retained fixture text does not match its original receipt')
    starts, ends = observed['business_starts'], observed['business_completions']
    if expected_exit is None:
        need(not starts and not ends and not observed['effect_exists'] and observed['terminal'] is None,
             'pre-business cut has business or terminal evidence')
        return
    need(len(starts) == len(ends) == 1 and observed['effect_exists'], 'business start/completion/effect missing')
    effect = json.loads(observed['files']['effect.json']['text'])
    need(starts[0]['token'] == ends[0]['token'] == effect['token']
         and ends[0]['exit_code'] == expected_exit, 'business token/exit binding differs')
    terminal, witness = observed['terminal'], observed['witness']
    need(terminal == json.loads(observed['files']['exit.json']['text'])
         and witness == json.loads(observed['files']['exit.witness.json']['text'])
         and terminal['exit_code'] == expected_exit
         and terminal['output_complete'] is True and terminal['output_durable'] is True
         and witness['exit_sha256'] == observed['files']['exit.json']['receipt']['sha256'],
         'terminal/witness binding differs')


def archive_members(directory):
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    archive = manifest['archive']
    need(archive['filename'] == 'original-evidence.tar.gz', 'unexpected archive name')
    compressed = (directory / archive['filename']).read_bytes()
    need(len(compressed) == archive['stored_bytes'] <= 2 * 1024 * 1024
         and sha(compressed) == archive['stored_sha256'], 'archive compressed bytes differ')
    decoder = zlib.decompressobj(31)
    raw = decoder.decompress(compressed, 8 * 1024 * 1024 + 1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
         and len(raw) == archive['tar_bytes'] <= 8 * 1024 * 1024
         and sha(raw) == archive['tar_sha256'], 'bounded single-member gzip decode differs')
    declared = {item['archive_member']: item for item in manifest['original_members']}
    need(set(declared) == set(EXPECTED_MEMBERS), 'manifest member inventory differs')
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as bundle:
        for member in bundle.getmembers():
            need(member.isfile() and member.name in declared and member.name not in result,
                 'unexpected, duplicate or nonregular tar member')
            expected = declared[member.name]
            need(member.size == expected['original_bytes'] <= 5 * 1024 * 1024,
                 'original member length differs')
            stream = bundle.extractfile(member)
            need(stream is not None, 'member stream missing')
            body = stream.read(member.size + 1)
            need(len(body) == member.size and sha(body) == expected['original_sha256']
                 == EXPECTED_MEMBERS[member.name], 'original member SHA differs')
            result[member.name] = body
    need(set(result) == set(EXPECTED_MEMBERS), 'archive incomplete')
    return manifest, result


def verify(directory, summary_path, source_root):
    manifest, raw = archive_members(directory)
    q = json.loads(raw['qualification/report.json'])
    entry = json.loads(raw['qualification/entry-report.json'])
    worker = json.loads(raw['qualification/worker-report.json'])
    lifecycle = json.loads(raw['lifecycle/report.json'])
    summary = json.loads(summary_path.read_bytes())
    need(q['qualified'] is True and q['current_stage'] == 'complete'
         and entry['qualified'] is True and entry['passed'] is True and entry['errors'] == []
         and worker['passed'] is True and worker['strict_fresh_artifacts_verified'] is True,
         'qualification did not pass')
    need(q['source_tested'] == q['source_after'] == entry['source_after']
         == summary['source']['tested_source_map']
         and len(q['source_after']) == 166 and map_sha(q['source_after']) == SOURCE_MAP,
         'qualified source map differs')
    need(entry['parent_unchanged_after_attempt'] is True
         and entry['parent_source_before'] == entry['parent_source_after'], 'parent changed')
    names = ['format', 'fmt-check', 'clean-package', 'clippy', 'test', 'release']
    need([row['name'] for row in q['stages']] == names
         == [row['name'] for row in worker['stages']], 'six-stage inventory differs')
    for stage, guarded in zip(q['stages'], worker['stages']):
        need(stage['returncode'] == guarded['returncode'] == 0
             and guarded['gate_clear'] is True and guarded['executed'] is True
             and guarded['execution_count'] == 1, 'stage execution failed')
    custody = entry['worker_custody']
    need(custody['original_child_reaped'] is True and custody['actual_waitpid'] == custody['pid']
         and custody['raw_wait_status'] == custody['returncode'] == 0
         and custody['custody_retained_until_reap'] is True and custody['group_quiet_before_reap'] is True,
         'qualification original raw worker exit differs')
    for evidence in worker['strict_fresh_artifact_evidence']['compiler_artifacts'].values():
        need(evidence['fresh_strictly_false'] is True and evidence['original_event']['fresh'] is False,
             'compiler artifact was not strictly fresh=false')
    test_text = raw['qualification/test.log'].decode()
    rows = [list(map(int, row)) for row in re.findall(
        r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',
        test_text, flags=re.MULTILINE)]
    need([row for row in rows if row[4] == 0] == [[18, 0, 0, 0, 0], [1215, 0, 23, 0, 0], [8, 0, 0, 0, 0]],
         'top-level test counts differ')
    for line in summary['qualification']['seven_owner_publication_tests_success_lines'].values():
        need(test_text.splitlines().count(line) == 1, 'owner-publication test success line differs')
    need(lifecycle['passed'] is True and lifecycle['comparison_valid'] is True
         and lifecycle['inputs_unchanged'] is True and lifecycle['errors'] == []
         and lifecycle['automatic_retries'] == 0 and len(lifecycle['correctness']) == 10,
         'lifecycle completeness differs')
    for case in lifecycle['correctness']:
        need(case['passed'] is True and case['original_job_files_unchanged'] is True,
             'correctness case failed')
        for phase in ('original', 'restart', 'same_key', 'status_run'):
            need(case[phase]['passed'] is True and case[phase]['error'] is None
                 and case[phase]['unexecuted'] == 0 and len(case[phase]['tasks']) == 1,
                 'correctness auxiliary task differs')
            original_task(case[phase]['tasks'][0])
        original = case['original']['tasks'][0]
        is_cut = case['case'].startswith('after_')
        expected_exit = None if is_cut else int(case['case'].split('-')[1])
        observed_result(case['observed_original'], expected_exit)
        need(case['restart']['tasks'][0]['returncode'] == 1
             and case['same_key']['tasks'][0]['returncode'] == (1 if is_cut else 0),
             'restart or same-key boundary differs')
        if is_cut:
            need(original['raw_wait_status'] == 9 and original['returncode'] == -9
                 and original['cut_sigkill_sent'] is True
                 and original['cut_observation']['observed_popen_calls_before_cut'] == 0
                 and [item['signal'] for item in original['signals']] == ['SIGKILL'],
                 'declared real SIGKILL evidence differs')
        else:
            need(original['returncode'] == expected_exit
                 and original['raw_wait_status'] == expected_exit * 256, 'business raw exit differs')
    cells = lifecycle['performance']
    need(len(cells) == 8 and [(cell['round'], cell['arm'], cell['concurrency']) for cell in cells]
         == [(r, arm, c) for r, arm in enumerate(('r07', 'a43', 'a43', 'r07')) for c in (1, 4)],
         'fixed ABBA cell order differs')
    for cell in cells:
        need(cell['planned'] == cell['attempted'] == cell['successes'] == len(cell['jobs']) == 16
             and cell['failures'] == cell['unexecuted'] == 0, 'measured cell incomplete')
        for job in cell['jobs']:
            task, observed = job['task'], job['observed']
            original_task(task)
            need(task['raw_wait_status'] == task['returncode'] == 0 and task['signals'] == [],
                 'measured original raw completion differs')
            observed_result(observed, 0)
            near(observed['submit_to_business_start_ms'],
                 (observed['business_starts'][0]['monotonic_ns'] - task['started_monotonic_ns']) / 1e6, 'business start')
            near(observed['submit_to_business_completion_ms'],
                 (observed['business_completions'][0]['monotonic_ns'] - task['started_monotonic_ns']) / 1e6, 'business completion')
    comparison = {}
    for concurrency in (1, 4):
        arms = {}
        for arm in ('r07', 'a43'):
            selected = [cell for cell in cells if cell['arm'] == arm and cell['concurrency'] == concurrency]
            jobs = [job for cell in selected for job in cell['jobs']]
            values = {'jobs': len(jobs), 'pooled_jobs_per_second': len(jobs) / sum(cell['seconds'] for cell in selected),
                'whole_lifecycle_wait4_cpu_seconds': sum(job['task']['wait4_rusage']['ru_utime']
                    + job['task']['wait4_rusage']['ru_stime'] for job in jobs),
                'harness_cpu_seconds': sum(cell['harness_cpu_seconds'] for cell in selected),
                'max_wait4_ru_maxrss_kib': max(job['task']['wait4_rusage']['ru_maxrss'] for job in jobs),
                'median_submit_to_start_ms': statistics.median(job['observed']['submit_to_business_start_ms'] for job in jobs),
                'median_submit_to_complete_ms': statistics.median(job['observed']['submit_to_business_completion_ms'] for job in jobs),
                'median_submit_to_supervisor_reap_ms': statistics.median(job['task']['elapsed_ms'] for job in jobs)}
            for key, value in values.items():
                near(value, lifecycle['comparison'][str(concurrency)][arm][key], 'raw comparison ' + key)
                near(value, summary['lifecycle']['comparison_by_concurrency'][str(concurrency)][arm][key], 'summary ' + key)
            arms[arm] = values
        comparison[str(concurrency)] = arms
    proof_binding = manifest['qualified_source_object_map']
    proof_raw = (directory / proof_binding['filename']).read_bytes()
    need(len(proof_raw) == proof_binding['bytes'] and sha(proof_raw) == proof_binding['sha256'], 'source object proof changed')
    proof = json.loads(proof_raw)
    need(proof['all_qualified_sources_sha256_match'] is True and proof['source_files'] == 166
         and {row['path']: row['sha256'] for row in proof['rows']} == q['source_after'], 'source object map differs')
    source_rehashed = False
    if source_root is not None:
        for row in proof['rows']:
            relative = Path(row['path'])
            need(not relative.is_absolute() and '..' not in relative.parts, 'unsafe source path')
            path = source_root / relative
            need(stat.S_ISREG(path.lstat().st_mode), 'source member is not a regular file')
            body = path.read_bytes()
            git_blob = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
            need(len(body) == row['bytes'] and sha(body) == row['sha256'] and git_blob == row['git_blob_sha'],
                 'actual repository source differs: ' + row['path'])
        source_rehashed = True
    return {'schema': 'hepta-a43-offline-evidence-recomputation/v1', 'passed': True,
        'exact_original_members_verified': len(raw), 'top_level_tests_passed': 1241,
        'top_level_tests_failed': 0, 'top_level_tests_ignored': 23,
        'correctness_cases_passed': 10, 'measured_jobs_passed': 128, 'comparison': comparison,
        'qualified_source_map_compact_sha256': SOURCE_MAP, 'source_bodies_rehashed': source_rehashed,
        'executable_bodies_rehashed': False, 'host_gate_sidecars_rehashed': False,
        'runtime_or_workload_executions': 0,
        'scope': 'Archived-record integrity, case boundaries and arithmetic; not an independent rerun or stable performance/adoption gate.'}


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', type=Path,
                        default=root / 'docs/experiments/x230/evidence/a43-a46-a47')
    parser.add_argument('--summary', type=Path, default=root / 'docs/experiments/x230/a43-a46-a47-summary.json')
    parser.add_argument('--source-root', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence_dir, args.summary, args.source_root), sort_keys=True, indent=2))
