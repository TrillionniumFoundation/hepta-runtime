#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Restore one complete campaign archive and run its seven frozen offline audits.

No runtime, workload runner, SSH connection or compiler is executed. Original
evidence and producer summaries remain unchanged; replay uses fresh outputs.
"""
import argparse
import ast
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import time
import traceback

ROOT = '/home/qian/hepta-runtime-optimization-20261105-r21'
TREES = ('campaign-control-01', 'native-observation-01', 'native-boundary-01', 'lifecycle-abba-01')
PROGRAM_SHA = '7cef87d976488ea63c5970f90b2e695bad835b1e01293aaaa5eeaee575e962a2'
CAMPAIGN_MANIFEST_SHA = '5e74bf124730a8dae41b30b2296ed0481277d4baa72139a4aab628b04a343afd'
LIFECYCLE_MANIFEST_SHA = '445a325931f2a9147401ea241782a29617480c2047c6d5b760f2e59f9037cb1f'
PLAN_SHA = 'aa4ad30b746b267d005c675f81ba634c43cd81a6f5893963445949abaa6e82f6'
CHAIN_SHA = '29542f436269549936ecc24cd5d65b7f994200ede963f4b4cf9c4556483644b8'
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024 * 1024


def need(value, reason):
    if not value:
        raise ValueError(reason)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def create(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)


def direct(path):
    path = path.absolute()
    need(path.resolve() == path, 'indirect input/output path')
    return path


def fingerprint(path):
    path = direct(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'unsafe ordinary file')
    digest, count = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
            count += len(block)
        end = os.fstat(stream.fileno())
    stamp = lambda x: tuple(getattr(x, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    need(count == before.st_size and stamp(before) == stamp(end) == stamp(path.lstat()), 'file changed during read')
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest()}


def safe_name(name):
    path = Path(name)
    need(isinstance(name, str) and name and not path.is_absolute() and path.as_posix() == name
         and all(part not in ('', '.', '..') for part in path.parts), 'unsafe archive member')
    return path


def load(path):
    return json.loads(path.read_bytes())


def scan_archive(archive, expected_manifest_sha, destination=None):
    seen, total, manifest, manifest_raw = set(), 0, None, None
    with tarfile.open(archive, mode='r|gz') as tar:
        for number, member in enumerate(tar):
            name = member.name
            safe_name(name)
            need(member.isreg() and not member.issym() and not member.islnk()
                 and name not in seen and 0 <= member.size <= MAX_FILE, 'duplicate/special/oversized member')
            seen.add(name)
            if number == 0:
                need(name == '_export-manifest.json' and member.size <= 16 * 1024 * 1024, 'manifest must be first')
                manifest_raw = tar.extractfile(member).read()
                need(len(manifest_raw) == member.size and hashlib.sha256(manifest_raw).hexdigest() == expected_manifest_sha, 'embedded manifest differs')
                manifest = json.loads(manifest_raw)
                need(manifest['schema'] == 'hepta-r21-campaign-export/v1' and manifest['root'] == ROOT
                     and manifest['file_count'] == len(manifest['files']) <= 50000
                     and set(manifest['raw_trees']) == set(TREES), 'export manifest contract differs')
                for relative, row in manifest['files'].items():
                    path = safe_name(relative)
                    need(path.parts[0] in ('r21', 'inputs') and type(row['bytes']) is int
                         and 0 <= row['bytes'] <= MAX_FILE and HEX.fullmatch(row['sha256']), 'invalid manifest payload identity')
                need(sum(row['bytes'] for row in manifest['files'].values()) <= MAX_TOTAL, 'manifest payload budget exceeded')
                if destination is not None:
                    create(destination / name, manifest_raw)
                continue
            need(manifest is not None and name in manifest['files'], 'unexpected archive payload')
            expected = manifest['files'][name]
            need(member.size == expected['bytes'], 'member byte count differs')
            digest, count = hashlib.sha256(), 0
            stream = tar.extractfile(member)
            output = None
            try:
                if destination is not None:
                    path = destination / name
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    output = path.open('xb')
                while block := stream.read(1024 * 1024):
                    digest.update(block)
                    count += len(block)
                    if output is not None:
                        output.write(block)
                need(count == member.size and digest.hexdigest() == expected['sha256'], 'payload hash differs: ' + name)
                total += count
                need(total <= MAX_TOTAL, 'decompressed budget exceeded')
            finally:
                stream.close()
                if output is not None:
                    output.close()
    need(manifest is not None and seen == set(manifest['files']) | {'_export-manifest.json'}, 'archive omitted expected payload')
    if destination is not None:
        for tree in manifest['raw_trees'].values():
            for directory in tree['directories']:
                relative = safe_name('r21/' + directory['path'])
                need(relative.parts[1] in TREES, 'empty-directory record outside raw roots')
                (destination / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    return manifest, {'payload_files': len(manifest['files']), 'archive_members': len(seen), 'payload_bytes': total,
                      'manifest_bytes': len(manifest_raw), 'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest()}


def audit_stage(name, tool, report, output, extra, original, directory, input_option='--report'):
    stdout, stderr = directory / (name + '.stdout'), directory / (name + '.stderr')
    need(input_option in ('--report', '--index'), 'unsupported original auditor input option')
    command = [sys.executable, '-B', str(tool), input_option, str(report), '--output', str(output), *extra]
    row = {'name': name, 'argv': command, 'tool': fingerprint(tool), 'started_utc': now(),
           'timeout_seconds': 180, 'automatic_retry': False, 'waited_and_reaped': False,
           'original_analysis': fingerprint(original), 'passed': False}
    child = None
    started = time.monotonic()
    try:
        with stdout.open('xb') as sout, stderr.open('xb') as serr:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=sout, stderr=serr,
                                     cwd=tool.parent, env={'PATH': '/usr/bin:/bin', 'LANG': 'C',
                                     'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'})
            row['pid'] = child.pid
            try:
                row['returncode'] = child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                row['timed_out'] = True
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                raise
            row['waited_and_reaped'] = True
        need(row['returncode'] == 0, 'original offline auditor failed')
        result = load(output)
        accepted = result.get('verified') is True or (result.get('evidence_verified') is True and result.get('diagnostic_passed') is True)
        row['equals_original_analysis'] = result == load(original)
        row['output'] = fingerprint(output)
        need(accepted and row['equals_original_analysis'], 'original/replayed audit result differs or rejects')
        row['passed'] = True
    except BaseException as error:
        row['error'] = {'type': type(error).__name__, 'message': str(error)}
        create(directory / (name + '.error.txt'), traceback.format_exc().encode())
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        if child is not None:
            row.update(returncode=child.returncode, waited_and_reaped=child.returncode is not None)
        row.update(seconds=time.monotonic() - started, finished_utc=now())
        for stream, path in (('stdout', stdout), ('stderr', stderr)):
            if path.exists():
                row[stream] = fingerprint(path)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--expected-archive-sha256', required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--expected-campaign-report-sha256', required=True)
    parser.add_argument('--expected-candidate-sha256', required=True)
    parser.add_argument('--extract-root', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    args = parser.parse_args()
    need(all(HEX.fullmatch(value) for key, value in vars(args).items() if key.startswith('expected_')), 'invalid expected SHA256')
    archive, extracted, out = map(direct, (args.archive, args.extract_root, args.output_root))
    need(not os.path.lexists(extracted) and not os.path.lexists(out)
         and not extracted.is_relative_to(out) and not out.is_relative_to(extracted)
         and not archive.is_relative_to(extracted) and not archive.is_relative_to(out), 'fresh nonoverlapping outputs required')
    os.umask(0o077)
    out.mkdir(mode=0o700, parents=True)
    result = {'schema': 'hepta-r21-campaign-offline-replay/v1', 'passed': False, 'started_utc': now(),
              'workloads_run': False, 'builds_run': False, 'network_requests': 0, 'automatic_retries': 0,
              'audits': [], 'mac_holder_evidence_included': False,
              'scope': 'Original frozen offline auditors and deterministic statistics; no runtime is executed and omitted ELF bodies are not independently rehashed locally.'}
    try:
        result['archive'] = fingerprint(archive)
        need(result['archive']['sha256'] == args.expected_archive_sha256, 'complete archive SHA differs')
        manifest, result['archive_verification'] = scan_archive(archive, args.expected_manifest_sha256)
        result['producer_campaign_passed'] = manifest['campaign_passed']
        result['producer_campaign_terminal_stage'] = manifest['campaign_terminal_stage']
        result['capture_identity_errors'] = manifest.get('identity_errors', [])
        need(manifest['expected_campaign_report_sha256'] == args.expected_campaign_report_sha256
             and manifest['expected_candidate_sha256'] == args.expected_candidate_sha256, 'CLI/report/runtime bindings differ')
        extracted.mkdir(mode=0o700, parents=True)
        restored_manifest, restored = scan_archive(archive, args.expected_manifest_sha256, extracted)
        need(restored_manifest == manifest and restored == result['archive_verification'], 'restore differs from full prevalidation')
        evidence = extracted / 'r21'
        need({p.relative_to(extracted).as_posix() for p in extracted.rglob('*') if p.is_file()}
             == set(manifest['files']) | {'_export-manifest.json'}, 'restored membership differs')
        result['all_payloads_restored'] = True
        for name in TREES:
            tree = manifest['raw_trees'][name]
            actual = sorted(p.relative_to(evidence).as_posix() for p in (evidence / name).rglob('*') if p.is_file())
            need(actual == tree['files'], 'raw tree has extra/missing files')
        pinned = {'campaign-tools/run_six_host_campaign_01.py': PROGRAM_SHA,
                  'campaign-tools/manifest.freeze-01.json': CAMPAIGN_MANIFEST_SHA,
                  'lifecycle-tools/lifecycle-tools-manifest-01.json': LIFECYCLE_MANIFEST_SHA,
                  'measurement-plan-01.json': PLAN_SHA, 'component-chain-01.json': CHAIN_SHA,
                  'campaign-control-01/report.json': args.expected_campaign_report_sha256}
        for name, expected in pinned.items():
            need(fingerprint(evidence / name)['sha256'] == expected, 'fixed source/report pin differs: ' + name)
        for name, item in load(evidence / 'campaign-tools/manifest.freeze-01.json')['files'].items():
            actual = fingerprint(evidence / name)
            need(actual['bytes'] == item['bytes'] and actual['sha256'] == item['sha256'], 'campaign tool manifest differs')
        tools = evidence / 'lifecycle-tools'
        for name, item in load(tools / 'lifecycle-tools-manifest-01.json')['files'].items():
            actual = fingerprint(tools / name)
            need(actual['bytes'] == item['bytes'] and actual['sha256'] == item['sha256'], 'lifecycle tool manifest differs')
        campaign = load(evidence / 'campaign-control-01/report.json')
        result['producer_campaign_passed'] = campaign['passed']
        result['producer_campaign_terminal_stage'] = campaign['current_stage']
        sources = {row['source_path']: row for row in manifest['files'].values()}
        omissions = {row['source_path']: row for row in manifest['omitted_elf_bytes']}
        r19 = '/home/qian/hepta-runtime-optimization-20261104-r19'
        names = ('hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver')
        allowed_elfs = {base + '/' + qualification + '/' + name for base, qualification in ((r19, 'qualification-02'), (ROOT, 'qualification-01')) for name in names}
        allowed_elfs |= {ROOT + '/target-fresh-01/release/' + ('examples/native_process_driver' if name == 'native_process_driver' else name) for name in names}
        need(set(omissions) == allowed_elfs and not set(sources).intersection(allowed_elfs), 'ELF omission set differs')
        bound = []

        def inspect(value):
            if isinstance(value, dict):
                if isinstance(value.get('path'), str) and HEX.fullmatch(str(value.get('sha256', ''))):
                    path = value['path']
                    actual = sources.get(path, omissions.get(path))
                    need(actual is not None, 'campaign binding absent from archive/witness: ' + path)
                    count = value.get('bytes', value.get('size'))
                    need(actual['sha256'] == value['sha256'] and (count is None or actual['bytes'] == count), 'archived campaign binding differs')
                    bound.append({'path': path, 'elf_body_omitted': path in omissions})
                for child in value.values():
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)

        inspect(campaign)
        result['campaign_bindings_verified'] = bound
        result['omitted_elf_witnesses'] = manifest['omitted_elf_bytes']
        result['omitted_elf_scope'] = 'Nine remote complete-hash/stamp witnesses checked against archived proof; local ELF bodies are unavailable, so this is not local machine-code verification.'
        specifications = [('native', tools / 'analyze_native_observation.py', evidence / 'native-observation-01', []),
                          ('boundary', evidence / 'boundary-tools/audit_native_boundary.py', evidence / 'native-boundary-01', ['--harness-root', str(tools)])]
        for number, arm in enumerate('ABBA'):
            specifications.append((f'lifecycle-{number}-{arm}', tools / 'verify_cancel_recovery.py',
                                   evidence / f'lifecycle-abba-01/round-{number}-{arm}', []))
        for name, tool, directory, extra in specifications:
            if not (directory / 'report.json').is_file() or not (directory / 'independent-summary.json').is_file():
                result['audits'].append({'name': name, 'passed': False, 'not_run': 'original report/summary absent in retained terminal attempt'})
                continue
            result['audits'].append(audit_stage(name, tool, directory / 'report.json', out / (name + '.json'),
                                               extra, directory / 'independent-summary.json', out))
        # The existing summary CLI takes --index instead of --report. Use a
        # fixed, literal adapter solely for that argument name in a fresh copy
        # of argv, without editing or importing the original summary source.
        lifecycle = evidence / 'lifecycle-abba-01'
        if (lifecycle / 'round-index.json').is_file() and (lifecycle / 'summary.json').is_file():
            result['audits'].append(audit_stage('lifecycle-summary', tools / 'summarize_lifecycle_abba_01.py',
                                               lifecycle / 'round-index.json', out / 'lifecycle-summary.json', [], lifecycle / 'summary.json', out,
                                               input_option='--index'))
        else:
            result['audits'].append({'name': 'lifecycle-summary', 'passed': False, 'not_run': 'closed lifecycle index/summary absent'})
        need(len(result['audits']) == 7 and all(row['passed'] is True for row in result['audits']), 'one or more original offline audits rejected or could not run')
        native = load(out / 'native.json')
        boundary = load(out / 'boundary.json')
        summary = load(out / 'lifecycle-summary.json')
        counts = {key: native[key] for key in ('measured_calls', 'warmup_calls', 'preflight_restart_calls', 'total_calls', 'failed_calls')}
        expected = {'measured_calls': 2304, 'warmup_calls': 288, 'preflight_restart_calls': 72, 'total_calls': 2664, 'failed_calls': 0}
        result['native_counts'] = {'actual': counts, 'expected_fixed_protocol': expected, 'matches': counts == expected,
                                   'scope': 'Warmup and all 72 preflight/restart calls are excluded from the performance denominator; a deviation is retained and fails, not normalized away.'}
        need(counts == expected, 'native cardinality differs from frozen protocol; inspect retained actual counts')
        program = (evidence / 'campaign-tools/run_six_host_campaign_01.py').read_bytes()
        pure_names = {'need', 'finite_positive', 'native_decision', 'native_metrics'}
        definitions = [node for node in ast.parse(program).body if isinstance(node, ast.FunctionDef) and node.name in pure_names]
        need({node.name for node in definitions} == pure_names, 'frozen pure statistic functions absent')
        namespace = {'math': math}
        exec(compile(ast.Module(body=definitions, type_ignores=[]), str(evidence / 'campaign-tools/run_six_host_campaign_01.py'), 'exec'), namespace)
        decision = namespace['native_decision'](native)
        metrics = namespace['native_metrics'](load(evidence / 'native-observation-01/report.json'), native)
        need(decision == campaign['native_regression_screen'] and metrics == campaign['native_metrics'], 'replayed native gate/pair metrics differ from original campaign')
        result['native_regression_screen'] = decision
        result['native_metrics'] = metrics
        result['native_resource_observations'] = native['resources']
        need(boundary['evidence_verified'] is boundary['diagnostic_passed'] is boundary['drain_and_recovery_passed'] is True
             and sum(boundary['counts'].values()) == 64 and boundary['counts'].get('other_error', 0) == 0
             and boundary['counts'] == campaign['boundary_evidence']['counts'], 'C32 classification/recovery differs')
        result['boundary_counts'] = boundary['counts']
        result['boundary_scope'] = '64 attempts in two C32 bursts; exact capacity refusals remain separate from successes and do not enter successful-throughput numerators.'
        need(summary['total_new_starts'] == 24 and summary['total_same_key_lookups'] == 48
             and summary['total_cancellations'] == 48 and summary['round_count'] == 4, 'lifecycle fixed effects differ')
        result['lifecycle'] = summary
        need(campaign['passed'] is True and campaign['current_stage'] == 'completed'
             and campaign['native_regression_screen_passed'] == decision['passed'], 'producer campaign did not complete successfully')
        for name, row in manifest['files'].items():
            actual = fingerprint(extracted / name)
            need(actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256'], 'original extracted evidence changed during replay')
        need(fingerprint(archive) == result['archive'], 'archive changed during replay')
        result.update(passed=True, all_original_payloads_unchanged=True,
                      native_regression_screen_passed=decision['passed'], adoption_decision_made_here=False)
        result['measurement_scope'] = {
            'native_cpu': 'Synchronous same-controller /proc counters per completed measured observation call; excludes SSH and remote CPU.',
            'native_rate_p95': 'Original pooled raw-call nearest-rank p95 and total calls divided by sum of same-arm cell windows; no mean of round rates.',
            'lifecycle_cpu': 'Existing same PID/start-ticks phase counters; excludes SSH and remote CPU; prepare has no active controller.',
            'lifecycle_wall': 'Whole C6 phase including confirmations, original bounded polling and independent SSH inspections.',
            'rss_io': 'Original sampled controller/process-tree/resource traces and their recorded errors; no new peak, per-call RSS reduction or synchronized cluster-total estimator.',
            'inference': 'One finite shared-host ABBA; two samples per arm; no significance, global optimality or maximum sustainable launch-rate claim.'}
    except BaseException as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
        create(out / 'error.txt', traceback.format_exc().encode())
    finally:
        result['finished_utc'] = now()
        create(out / 'report.json', encode(result))
        print(json.dumps({'passed': result['passed'], 'report': fingerprint(out / 'report.json'),
                          'audits': len(result['audits']), 'error': result.get('error')}, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
