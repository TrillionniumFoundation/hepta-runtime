#!/usr/bin/env python3
"""One-off X230 R4 evidence export. Never runs a benchmark, SSH or a compiler.

Only final-result selection is configurable. Source directories stay below the
fixed experiment root; two native canary roots are derived from its report nonce.
Original bytes are retained, including rejected historical experiments. This is
an evidence subset, not an export of binaries, trust files or fixture state.
"""
import argparse
import codecs
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

ROOT = Path('/home/qian/hepta-runtime-optimization-20261028')
OLD = Path('/home/qian/hepta-runtime-optimization-20261023')
Q4_SHA = '431af6273220311b8e7bd9c4542bc0daf4db291c21e6525ec252e6ed4da0aa8b'
R4B_RELEASE = '5cadde76ecfa7f5de5be9450668a249968cce5d81b810df672e5f38a9c1bae5e'
CONTROL_ELF = '73e538f910786b4675975305ec25188eadf6b23a5a1cc14725bfe8d3efdea3fe'
MICRO_HISTORY = (
    ('microbench-r4a-abba-r01', 'rust-r4a', '41b23384b05166bd34c1db4f0503795ee4fb8b8e6048443fc14a21f2d742ea8c',
     '09e987f2c2a8f5f456578b409befb83a6b10aed6399bf4a75bb6d13a006da1da', 'ABBA'),
    ('microbench-r4b-abba-r02', 'rust-r4b', '51e68dba0e81f539005451b8ea85c127628206e365630d416e182be1ffcd842c',
     'c9069ee70d10f72a36660a6f87c0039da38eeb194356e2da1e2fa009f0c62a07', 'ABBAABBA'),
)
GATES = ('format', 'fmt-check', 'harness-tests', 'clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release')
NATIVE_STAGES = ('small-archive-abba', 'inherited-pipes', 'six-running-recovery',
                 'file-abba-0-baseline', 'file-abba-1-candidate', 'file-abba-2-candidate',
                 'file-abba-3-baseline', 'candidate-c8-soak-120s')
MAX_FILE = 512 * 1024 * 1024
MAX_PLAIN = 1024 * 1024 * 1024
BLOCKED_PARTS = {'.ssh', '.git', 'ssh', 'keys', 'trust', 'config', 'profile', 'state',
                 'jobs', 'request-audit', 'test-binaries', 'target'}
PRIVATE_KEY = re.compile(rb'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|openssh-key-v1\x00|PuTTY-User-Key-File:')
SECRET_ASSIGNMENT = re.compile(
    rb'(?i)\b(?:[a-z][a-z0-9_]*_)?(?:api_key|access_token|refresh_token|client_secret|'
    rb'password|secret_access_key|session_token|private_key|github_token|gh_token)'
    rb'[\\\"\x27]*\s*[:=]\s*[\\\"\x27]*[a-z0-9+/=_-]{8,}')
TOKEN = re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16})\b')


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


@contextlib.contextmanager
def opened(path, directory=False):
    """Open every component without following a symlink, including ancestors."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute direct path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        result = os.open(path.name, flags, dir_fd=fd)
    finally:
        os.close(fd)
    try:
        info = os.fstat(result)
        need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'special file refused: ' + str(path))
        if not directory:
            need(info.st_nlink == 1 and info.st_size <= MAX_FILE, 'linked or oversized evidence refused: ' + str(path))
        yield result, info
    finally:
        os.close(result)


def screen(stream, path):
    """Reject binary/key/credential payloads; never redact original evidence."""
    decoder, tail, size = codecs.getincrementaldecoder('utf-8')('strict'), b'', 0
    while block := stream.read(65536):
        size += len(block)
        need(size <= MAX_PLAIN, 'expanded log exceeds bound: ' + str(path))
        data = tail + block
        need(b'\x00' not in block and not data.startswith(b'\x7fELF'), 'binary payload refused: ' + str(path))
        need(not PRIVATE_KEY.search(data) and not SECRET_ASSIGNMENT.search(data) and not TOKEN.search(data),
             'possible private-key/credential content; export refused: ' + str(path))
        try:
            decoder.decode(block)
        except UnicodeError:
            raise ValueError('non-UTF-8 evidence refused: ' + str(path)) from None
        tail = data[-512:]
    try:
        decoder.decode(b'', final=True)
    except UnicodeError:
        raise ValueError('non-UTF-8 evidence refused: ' + str(path)) from None


def inspect(path, expected=None, capture=False):
    path = Path(path)
    with opened(path) as (fd, before), os.fdopen(os.dup(fd), 'rb') as stream:
        digest, size, chunks = hashlib.sha256(), 0, []
        while block := stream.read(65536):
            digest.update(block)
            size += len(block)
            need(size <= MAX_FILE, 'evidence grew beyond bound')
            if capture:
                chunks.append(block)
        info = {'path': str(path), 'bytes': size, 'sha256': digest.hexdigest(), 'identity': stamp(before)}
        stream.seek(0)
        if path.name.endswith('.gz'):
            with gzip.GzipFile(fileobj=stream) as plain:
                screen(plain, path)
        else:
            screen(stream, path)
        need(size == before.st_size and stamp(os.fstat(fd)) == stamp(before), 'evidence changed while reading: ' + str(path))
    with opened(path) as (_, current):
        need(stamp(current) == info['identity'], 'evidence path rebound: ' + str(path))
    if expected:
        for key in ('path', 'bytes', 'sha256', 'identity'):
            if key in expected:
                need(info[key] == expected[key], 'recorded receipt differs (' + key + '): ' + str(path))
    return info, b''.join(chunks) if capture else None


def relative(name):
    need(isinstance(name, str) and name and '\\' not in name, 'unsafe relative name')
    path = PurePosixPath(name)
    need(not path.is_absolute() and all(part not in ('', '.', '..') for part in name.split('/')), 'unsafe relative path')
    return path


def named_root(name, prefix):
    need(isinstance(name, str) and re.fullmatch(re.escape(prefix) + r'[a-z0-9-]*', name), 'unexpected experiment directory')
    return ROOT / name


def sha_value(value):
    need(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'explicit SHA-256 required')
    return value


class Collection:
    def __init__(self):
        self.entries, self.roots, self.excluded, self.validation = {}, set(), [], {}

    def root(self, directory):
        with opened(directory, directory=True):
            pass
        self.roots.add(Path(directory))

    def add(self, root, alias, name, expected=None, capture=False):
        root, rel = Path(root), relative(name)
        need(root in self.roots, 'unapproved evidence root')
        need(not set(rel.parts) & BLOCKED_PARTS, 'private/state directory refused')
        key, path = str(relative(alias) / rel), root / rel
        if key in self.entries:
            entry = self.entries[key]
            need(entry['source_path'] == str(path), 'export path collision')
            if expected:
                for field in ('path', 'sha256', 'bytes', 'identity'):
                    if field in expected:
                        actual = entry['source_path'] if field == 'path' else entry[field]
                        need(actual == expected[field], 'conflicting expected receipt')
            if not capture:
                return entry, None
            # A second parse must not replace the first observed file identity.
            expected = {'path': entry['source_path'], **{field: entry[field] for field in ('bytes', 'sha256', 'identity')}}
        info, raw = inspect(path, expected, capture)
        self.entries[key] = {'source_path': info['path'], 'export_relative': key,
                             **{field: info[field] for field in ('bytes', 'sha256', 'identity')}}
        return self.entries[key], raw

    def json(self, root, alias, name, expected=None):
        _, raw = self.add(root, alias, name, expected, True)
        value = json.loads(raw)
        need(isinstance(value, dict), 'object report required: ' + name)
        return value

    def flat(self, root, alias, allowed, subdirs=()):
        self.root(root)
        with opened(root, directory=True) as (fd, _):
            items = sorted(os.scandir(fd), key=lambda item: item.name)
        for item in items:
            path = Path(root) / item.name
            mode = path.lstat().st_mode
            need(not stat.S_ISLNK(mode), 'symlink refused in evidence directory: ' + str(path))
            if stat.S_ISDIR(mode):
                if item.name in subdirs:
                    self.flat(path, alias + '/' + item.name, isolated_name)
                else:
                    self.excluded.append({'source_path': str(path), 'reason': 'directory outside evidence selection'})
            else:
                need(stat.S_ISREG(mode), 'special file in evidence directory: ' + str(path))
                if allowed(item.name):
                    self.add(root, alias, item.name)
                else:
                    self.excluded.append({'source_path': str(path), 'reason': 'basename not in evidence allowlist'})


ISOLATED = {'summary.json', 'cargo-artifacts.jsonl', 'source-manifest.input', 'commands.jsonl', 'tests.jsonl'}


def isolated_name(name):
    return name in ISOLATED or re.fullmatch(r'(?:binary-\d{3}-(?:list|ignored)|case-\d{6})\.(?:stdout|stderr)\.log\.gz', name) is not None


def history_name(name):
    return name in {'report.json', 'source-map.json', 'retained-artifacts.jsonl', 'cargo-no-run.jsonl',
                    'control-source-diff.json', 'isolated-tests.audit.json', 'runtime.sha256', 'release.sha256', 'binary.sha256'} or re.fullmatch(
        r'(?:format|fmt-check|clippy|test-build|release|release-build|registry-tests|maintenance-tests|slow-retirement-reproduction)\.(?:stdout|stderr)', name) is not None


def qualification(c, directory, alias, expected_sha, runtime_sha, passed, ignored, source=None):
    c.root(directory)
    q = c.json(directory, alias, 'report.json', {'sha256': sha_value(expected_sha)})
    need(q.get('schema') == 'hepta-x230-composed-qualification/v1' and q.get('qualified') is True
         and not q.get('error') and q.get('automatic_test_retries') == 0, 'qualification incomplete')
    stages = q.get('stages', [])
    need([s.get('name') for s in stages] == list(GATES) and all(s.get('returncode') == 0 for s in stages), 'qualification gates differ')
    if source is not None:
        need(q.get('source') == str(source), 'final qualification belongs to another source')
    need(q.get('source_tested') and q['source_tested'] == q.get('source_after')
         and q.get('harness_before') == q.get('harness_after'), 'qualification input maps differ')
    need(q['binaries']['hepta-runtime']['sha256'] == sha_value(runtime_sha), 'release receipt differs')
    source_map = c.json(directory, alias, 'source-map.json')
    need(source_map == q['source_tested'], 'source-map differs from qualification')
    for stage in stages:
        for stream in ('stdout', 'stderr'):
            name = 'cargo-no-run.jsonl' if (stage['name'], stream) == ('test-build', 'stdout') else stage['name'] + '.' + stream
            c.add(directory, alias, name, {'sha256': stage[stream + '_sha256']})
    c.add(directory, alias, 'retained-artifacts.jsonl')
    audit = c.json(directory, alias, 'isolated-tests.audit.json')
    need(audit.get('schema') == 'hepta-isolated-libtest-audit/v1' and audit.get('success') is True
         and audit.get('expected_filter') == '' and audit.get('passed') == passed and audit.get('executed') == passed
         and audit.get('failed') == 0 and audit.get('ignored') == ignored and not audit.get('errors')
         and not audit.get('fatal_error') and audit.get('evidence') == str(directory / 'isolated-tests'), 'full test audit differs')
    need(audit.get('auditor_sha256') == q['harness_after']['audit_isolated_tests.py'], 'auditor source binding differs')
    evidence = directory / 'isolated-tests'
    c.root(evidence)
    for name, digest in audit['input_sha256'].items():
        need(name in ISOLATED, 'unexpected audited evidence input')
        c.add(evidence, alias + '/isolated-tests', name, {'sha256': digest})
    need(c.json(evidence, alias + '/isolated-tests', 'source-manifest.input') == source_map, 'audited source manifest differs')
    for command in audit['commands']:
        name = command['stdout_gzip']
        need(isolated_name(name) and name.endswith('.stdout.log.gz'), 'unsafe audited log')
        for stream in ('stdout', 'stderr'):
            filename = name if stream == 'stdout' else name.removesuffix('.stdout.log.gz') + '.stderr.log.gz'
            c.add(evidence, alias + '/isolated-tests', filename, {'sha256': command[stream]['gzip_sha256']})
    summary = c.json(evidence, alias + '/isolated-tests', 'summary.json')
    need(summary.get('success') is True and summary.get('passed') == passed and summary.get('failed') == 0
         and summary.get('ignored') == ignored and summary.get('filter') == '' and summary.get('retries') == 0, 'isolated summary differs')
    c.flat(evidence, alias + '/isolated-tests', isolated_name)
    c.validation[alias] = {'qualified': True, 'gates': 8, 'rust_passed': passed, 'failed': 0, 'ignored': ignored,
                           'report_sha256': expected_sha, 'runtime_receipt_sha256': runtime_sha}
    return q


def microbench(c, directory, alias, expected_sha, candidate_sha, order, source=None):
    c.root(directory)
    value = c.json(directory, alias, 'report.json', {'sha256': sha_value(expected_sha)})
    need(value.get('schema') == 'hepta-registry-microbench-abba/v1' and value.get('passed') is True
         and value.get('automatic_retries') == 0 and value.get('order') == order
         and re.fullmatch(r'(?:ABBA){1,4}', order), 'microbench incomplete')
    variants = value['variants']
    need(variants['A']['sha256'] == CONTROL_ELF and variants['B']['sha256'] == sha_value(candidate_sha), 'microbench ELF receipts differ')
    if source is not None:
        need(variants['B']['source'] == str(source), 'final microbench belongs to another source')
    samples = value.get('samples', [])
    need(len(samples) == len(order) and ''.join(s['arm'] for s in samples) == order, 'microbench process inventory differs')
    for sample in samples:
        waves = sample.get('waves', [])
        need(sample.get('passed') is True and sample.get('executed') is True and sample.get('exit_code') == 0
             and sample.get('timed_out') is False and len(waves) == 36
             and sum(w.get('successes', 0) for w in waves) == 156
             and all(w.get('failures') == 0 for w in waves), 'microbench original sample incomplete')
    c.flat(directory, alias, lambda name: name in {'report.json', 'commands.jsonl', 'baseline-source-map.json', 'candidate-source-map.json'}
           or re.fullmatch(r'(?:[AB]-inventory|sample-\d{2}-[AB])\.(?:stdout|stderr)\.log\.gz', name) is not None)
    for name in ('commands.jsonl', 'baseline-source-map.json', 'candidate-source-map.json'):
        c.add(directory, alias, name)
    for sample in [*value['enumerations'], *samples]:
        for stream in ('stdout', 'stderr'):
            name = sample[stream + '_gzip']
            need(Path(name).name == name and name.endswith('.' + stream + '.log.gz'), 'unsafe microbench log name')
            c.add(directory, alias, name)
    c.validation[alias] = {'passed': True, 'processes': len(order), 'waves': 36 * len(order), 'calls': 156 * len(order), 'report_sha256': expected_sha}
    return value


def cohort(c, directory, alias, expected_sha=None, runtime_sha=None, source=None):
    c.root(directory)
    value = c.json(directory, alias, 'report.json', {'sha256': sha_value(expected_sha)} if expected_sha else None)
    need(value.get('schema') == 'hepta-registry-cohort-abba/v1' and value.get('passed') is True
         and value.get('order') == 'ABBA' and value.get('automatic_retries') == 0
         and not value.get('error') and not value.get('summary_error'), 'cohort comparison incomplete')
    if runtime_sha:
        need(value['variants']['B']['binary']['sha256'] == runtime_sha, 'cohort used another release')
    if source is not None:
        need(value['variants']['B']['source'] == str(source), 'cohort belongs to another source')
    rows = value.get('rounds', [])
    need(len(rows) == 4 and ''.join(row['arm'] for row in rows) == 'ABBA', 'cohort round inventory differs')
    total = 0
    for index, row in enumerate(rows):
        name = f'round-{index}-{row["arm"]}'
        output = directory / name
        need(row.get('passed') is True and row.get('started') is True and row.get('directory') == str(output)
             and row.get('all_job_receipts_unchanged') is True, 'cohort round incomplete')
        phases = row['phases']
        need(phases and all(p.get('completed') is True and p['result']['passed'] is True
                           and p['result']['successes'] == p['planned_calls'] for p in phases), 'cohort phases incomplete')
        total += sum(p['planned_calls'] for p in phases)
        c.root(output)
        c.add(output, alias + '/' + name, 'events.jsonl.gz', row['events_receipt'])
        resources = row['shutdown']['resources']
        c.add(output, alias + '/' + name, 'resource-samples.jsonl', resources['raw_samples'])
        c.add(output, alias + '/' + name, 'resource-errors.jsonl', {'sha256': resources['error_log_sha256'], 'bytes': resources['error_log_bytes']})
        c.add(output, alias + '/' + name, 'load-samples.jsonl', row['load_samples']['report'])
        for filename in ('stderr.log', 'denied-ssh.jsonl', 'jobs-input-sha256.json'):
            c.add(output, alias + '/' + name, filename)
    for label in ('baseline', 'candidate'):
        c.add(directory, alias, label + '-source-manifest.input.json')
    c.validation[alias] = {'passed': True, 'rounds': 4, 'calls': total, 'raw_call_ping_journals': 'all four original events.jsonl.gz retained'}
    return value


def qualified_libtest_binding(c, directory, variant):
    summary = c.json(directory / 'isolated-tests', 'qualification-final/isolated-tests', 'summary.json')
    audit = c.json(directory, 'qualification-final', 'isolated-tests.audit.json')

    def lib_target(row):
        target = row.get('target')
        return isinstance(target, dict) and target.get('name') == 'hepta_runtime' and target.get('kind') == ['lib']

    binaries = [row for row in summary.get('binaries', []) if lib_target(row)]
    need(summary.get('schema') == 'hepta-isolated-libtest/v1' and len(binaries) == 1,
         'final qualification must contain one hepta_runtime libtest')
    binary = binaries[0]
    path, digest = binary.get('path'), binary.get('sha256')
    need(isinstance(path, str) and Path(path).parent == directory / 'test-binaries'
         and str(Path(path)) == path and Path(path).name not in {'.', '..'}, 'qualified libtest is outside retained test-binaries')
    need(variant.get('binary') == path and variant.get('sha256') == sha_value(digest),
         'final microbench did not use the qualified libtest path/hash')
    receipts = [row for row in audit.get('binaries', []) if row.get('path') == path]
    need(len(receipts) == 1 and receipts[0].get('recorded_before_sha256') == digest
         and receipts[0].get('current_after_sha256') == digest, 'qualified libtest audit before/after receipt differs')
    need(summary.get('artifacts_path') == str(directory / 'retained-artifacts.jsonl')
         and summary.get('artifacts_sha256') == audit['input_sha256']['cargo-artifacts.jsonl'],
         'qualified libtest artifact stream binding differs')
    _, raw = c.add(directory, 'qualification-final', 'retained-artifacts.jsonl',
                   {'sha256': summary['artifacts_sha256']}, capture=True)
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    artifacts = [row for row in events if row.get('reason') == 'compiler-artifact' and lib_target(row)
                 and row.get('profile', {}).get('test') is True and row.get('executable')]
    need(artifacts and all(row['executable'] == path and row['target'] == binary['target'] for row in artifacts),
         'qualified libtest retained test artifact differs')
    return {'path': path, 'sha256': digest, 'target_name': 'hepta_runtime', 'target_kind': ['lib'],
            'profile_test': True, 'audit_before_after_sha256_match': True,
            'retained_artifacts_sha256': summary['artifacts_sha256'], 'binary_bytes_exported': False}


def assertions(value):
    return isinstance(value, dict) and value.get('passed') is True and bool(value.get('assertions')) and all(x is True for x in value['assertions'].values())


def argv_value(argv, option):
    need(isinstance(argv, list) and argv.count(option) == 1, 'ambiguous helper option: ' + option)
    index = argv.index(option)
    need(index + 1 < len(argv), 'missing helper option value')
    return argv[index + 1]


def helper_log(rel):
    parts, name = relative(rel).parts, PurePosixPath(rel).name
    if set(parts) & BLOCKED_PARTS or re.search(r'(^|[._-])(env|environment|config|request|credentials|private|key)([._-]|$)', name, re.I):
        return False
    return name in {'report.json', 'calls.jsonl', 'events.jsonl', 'events.jsonl.gz', 'resource-errors.jsonl', 'resource-samples.jsonl'} \
        or re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:log|stdout|stderr)(?:\.gz)?', name) is not None \
        or re.fullmatch(r'(?:[A-Za-z0-9_.-]+[.-])?(?:calls|events|pings|resources?|resource-errors|resource-samples|wire|stdio|stdout|stderr)[A-Za-z0-9_.-]*\.(?:jsonl|txt|raw|bin)(?:\.gz)?', name) is not None


def native(c, directory, alias, expected_sha, final_q_sha, runtime_sha, extended=False):
    c.root(directory)
    value = c.json(directory, alias, 'report.json', {'sha256': sha_value(expected_sha)})
    schema = 'hepta-x230-extended-file-soak/v1' if extended else 'hepta-x230-composed-native-validation/v1'
    need(value.get('schema') == schema and all(value.get(k) is True for k in ('passed', 'complete', 'final_input_integrity_passed'))
         and value.get('automatic_retries') == 0 and not value.get('error') and not value.get('failed_stage')
         and not value.get('unexecuted'), 'native/extended validation incomplete')
    candidate = value['qualifications']['candidate']
    need(candidate['report']['sha256'] == final_q_sha and candidate['binary']['sha256'] == runtime_sha, 'native qualification/release binding differs')
    stages = value.get('stages', [])
    names = ('candidate-c8-extended-file-soak',) if extended else NATIVE_STAGES
    need([s.get('name') for s in stages] == list(names), 'native stage coverage differs')
    if not extended:
        need(re.fullmatch(r'[0-9a-f]{24}', value['nonce']), 'invalid native nonce')
    for index, stage in enumerate(stages):
        need(stage.get('status') == 'passed' and stage.get('executed') is True and stage.get('execution_count') == 1
             and stage.get('original_child_reaped') is True and stage.get('custody_retained_until_reap') is True
             and stage.get('returncode') == 0 and stage.get('timed_out') is False and assertions(stage.get('validation'))
             and not stage.get('error') and not stage.get('evidence_errors'), 'native stage failed or lost custody')
        need(all(stage[k].get('clear') is True for k in ('hostload_before_gate', 'hostload_after_gate', 'hostload_samples')), 'native load gate failed')
        if index:
            need(stages[index - 1]['end_monotonic_ns'] <= stage['start_monotonic_ns'], 'native stages overlap')
        if extended:
            need(stage.get('kind') == 'soak' and assertions(stage['validation'].get('native_structure'))
                 and type(value['soak_seconds']) is int and 360 <= value['soak_seconds'] <= 900
                 and argv_value(stage['argv'], '--soak-seconds') == str(value['soak_seconds']), 'extended soak coverage differs')
            output, stage_alias = directory / 'file-soak', alias + '/file-soak'
        elif stage['name'] in ('inherited-pipes', 'six-running-recovery'):
            suffix, kind = ('pipes', 'pipe') if stage['name'] == 'inherited-pipes' else ('recovery', 'recovery')
            need(stage['kind'] == kind, 'external canary kind differs')
            output = OLD / ('x230-20261028-' + value['nonce'] + '-' + suffix)
            stage_alias = alias + '/stage-output/' + stage['name']
        else:
            output, stage_alias = directory / stage['name'], alias + '/stage-output/' + stage['name']
        need(stage.get('output') == str(output) and argv_value(stage['argv'], '--out') == str(output), 'unapproved native helper output')
        c.root(output)
        expected_names = {'stdout': 'helper.stdout' if extended else stage['name'] + '.stdout',
                          'stderr': 'helper.stderr' if extended else stage['name'] + '.stderr',
                          'original_artifacts_manifest': 'helper.artifacts.json' if extended else stage['name'] + '.artifacts.json',
                          'hostload_before': 'hostload-before.json' if extended else stage['name'] + '.hostload-before.json',
                          'hostload_after': 'hostload-after.json' if extended else stage['name'] + '.hostload-after.json'}
        for key, name in expected_names.items():
            c.add(directory, alias, name, stage[key])
        sample_name = 'hostload-samples.jsonl' if extended else stage['name'] + '.hostload-samples.jsonl'
        c.add(directory, alias, sample_name, stage['hostload_samples']['report'])
        c.add(output, stage_alias, 'report.json', stage['original_report'])
        manifest = c.json(directory, alias, expected_names['original_artifacts_manifest'], stage['original_artifacts_manifest'])
        for rel, receipt in manifest.items():
            relpath = relative(rel)
            need(receipt.get('path') == str(output / relpath), 'artifact manifest path escapes original output')
            if helper_log(rel):
                c.add(output, stage_alias, rel, receipt)
            else:
                c.excluded.append({'source_path': str(output / relpath), 'reason': 'original artifact outside evidence basename/path allowlist'})
        need('report.json' in manifest, 'helper report omitted from original artifact manifest')
        if stage['kind'] in ('small', 'file_abba', 'soak'):
            need('calls.jsonl' in manifest, 'raw helper calls missing')
        if stage['kind'] in ('file_abba', 'soak'):
            need('round-0-on/controller/stderr.log' in manifest, 'controller stderr missing')
    for name in ('candidate-qualification.original.json', 'candidate-test-audit.original.json'):
        c.add(directory, alias, name)
    if not extended:
        c.add(directory, alias, 'baseline-qualification.original.json')
    c.validation[alias] = {'passed': True, 'stages': len(stages), 'report_sha256': expected_sha,
                           'configured_soak_seconds': value.get('soak_seconds'), 'artifact_scope': 'allowlisted evidence subset; original complete artifact manifests retained'}
    return value


def remote_lease(c, directory, alias, expected_sha, report_path, report_sha, kind):
    c.root(directory)
    value = c.json(directory, alias, 'report.json', {'sha256': sha_value(expected_sha)})
    need(value.get('schema') == 'hepta-forwarded-validation-remote-lease/v1' and value.get('role') == 'remote'
         and value.get('passed') is True and value.get('phase') == 'complete' and value.get('report_kind') == kind
         and value.get('launch_attempts') == 1 and value.get('automatic_retries') == 0
         and not value.get('error') and not value.get('cleanup_error') and not value.get('evidence_error')
         and value['child'].get('original_child_reaped') is True and value['child'].get('custody_retained_until_reap') is True
         and value['child'].get('returncode') == 0, 'remote lease incomplete')
    need(value['native_report']['path'] == str(report_path) and value['native_report']['sha256'] == report_sha,
         'remote lease binds another validation report')
    c.add(report_path.parent, 'extended' if kind == 'extended-soak' else 'native',
          'report.json', value['native_report'])
    admission = c.json(directory, alias, 'admission.json')
    need(admission.get('nonce') == value.get('nonce') and admission.get('report_kind') == kind, 'remote lease admission differs')
    for name in ('runner.stdout', 'runner.stderr', 'heartbeats.jsonl'):
        c.add(directory, alias, name, value[name.replace('.', '_')])
    c.validation[alias] = {'passed': True, 'report_kind': kind, 'report_sha256': expected_sha,
                           'main_lease_scope': 'not on X230; main-host receipt must be joined separately'}


def load_config(path, expected):
    need(path.parent == ROOT and re.fullmatch(r'r4-export-config(?:-[a-z0-9-]+)?\.json', path.name), 'config must be a named file directly under fixed root')
    info, raw = inspect(path, {'sha256': sha_value(expected)}, True)
    value = json.loads(raw)
    need(set(value) == {'final_source', 'qualification', 'microbench', 'cohort', 'native', 'extended'}, 'unexpected config fields')
    named_root(value['final_source'], 'source-r4')
    layouts = {'qualification': {'directory', 'report_sha256', 'runtime_sha256', 'rust_passed', 'rust_ignored'},
               'microbench': {'directory', 'report_sha256', 'test_elf_sha256', 'order'},
               'cohort': {'directory', 'report_sha256', 'runtime_sha256'},
               'native': {'directory', 'report_sha256', 'lease_directory', 'lease_report_sha256'},
               'extended': {'directory', 'report_sha256', 'lease_directory', 'lease_report_sha256'}}
    prefixes = {'qualification': 'qualification-r4', 'microbench': 'microbench-r4', 'cohort': 'cohort-r4', 'native': 'native-r4', 'extended': 'extended-r4'}
    for key, fields in layouts.items():
        row = value[key]
        need(isinstance(row, dict) and set(row) == fields, 'unexpected config section fields: ' + key)
        named_root(row['directory'], prefixes[key])
        for name, item in row.items():
            if name.endswith('sha256'):
                sha_value(item)
        if 'lease_directory' in row:
            named_root(row['lease_directory'], key + '-lease-r4')
    need(all(type(value['qualification'][key]) is int and value['qualification'][key] >= 0 for key in ('rust_passed', 'rust_ignored'))
         and value['qualification']['rust_passed'] > 0, 'explicit test counts required')
    need(value['cohort']['runtime_sha256'] == value['qualification']['runtime_sha256'],
         'final cohort must use the exact qualified release ELF SHA-256')
    return value, info


def build_collection(config):
    c = Collection()
    qualification(c, ROOT / 'qualification-r4', 'qualification-r4', Q4_SHA, R4B_RELEASE, 1513, 25)
    for name in ('control-r4', 'diagnostic-r4a', 'diagnostic-r4b', 'diagnostic-r4b-r02',
                 'diagnostic-r4c-release', 'diagnostic-r4d-release', 'diagnostic-r4e-release'):
        directory = ROOT / name
        c.flat(directory, name, history_name, ('registry-tests', 'maintenance-tests'))
        c.add(directory, name, 'report.json')
    for directory, alias, digest, elf, order in MICRO_HISTORY:
        microbench(c, ROOT / directory, alias, digest, elf, order)
    # R4b's completed correct-but-slower run remains historical evidence.
    cohort(c, ROOT / 'cohort-r4-abba-r01', 'cohort-r4b')
    c.root(ROOT)
    c.add(ROOT, 'cohort-r4b', 'cohort-r4b-compact.json.gz', {'sha256': '79c3d270a9475637f0caa572629f2bf4d9fe2ad8b2f3f5ab2d45138b9e3df75c'})
    # R4c completed correctly; CPU optimization continued with a separate R4d.
    # Its early release is not a formally qualified executable.
    cohort(c, ROOT / 'cohort-r4c-abba-r01', 'cohort-r4c',
           '809dbe7ce144979c7b7b547d6a1b2bbde7f6e8dc15351306b5e840e48959862f')
    c.add(ROOT, 'cohort-r4c', 'cohort-r4c-diagnostic-compact.json.gz',
          {'sha256': '45ede27ba8fd2efb972cb65b19836d70248361b06cb4847d53d15a7b7bebae6d', 'bytes': 6434})
    c.validation['cohort-r4c'].update(evidence_role='completed early release diagnostic; further CPU optimization continued',
                                     qualification_claim=False, correctness_rejected=False)
    # R4d's calls completed correctly, but early registration did not meet the
    # CPU objective and was not adopted. R4e is a separate R4c-based candidate.
    cohort(c, ROOT / 'cohort-r4d-abba-r01', 'cohort-r4d',
           'cd335fc1eecf67787ab4b6a9e7d92d179a319b31c5b8570b1c2cff6370eafc71')
    c.add(ROOT, 'cohort-r4d', 'cohort-r4d-diagnostic-compact.json.gz',
          {'sha256': '2fb8fed79ed588063c83473593f8b38b26cd7400b40bdfa7063af8e8afc4e569', 'bytes': 6416})
    c.validation['cohort-r4d'].update(evidence_role='completed early-registration release diagnostic; CPU objective unmet',
                                     qualification_claim=False, correctness_rejected=False, early_registration_adopted=False)
    source = ROOT / config['final_source']
    q, m, co = config['qualification'], config['microbench'], config['cohort']
    final_q = qualification(c, ROOT / q['directory'], 'qualification-final', q['report_sha256'], q['runtime_sha256'], q['rust_passed'], q['rust_ignored'], source)
    final_micro = microbench(c, ROOT / m['directory'], 'rust-final', m['report_sha256'], m['test_elf_sha256'], m['order'], source)
    compiler_inputs = {key: value for key, value in final_q['source_tested'].items() if key != 'rustfmt.toml'}
    need(final_micro['variants']['B']['source_map'] == compiler_inputs, 'microbench/final qualified compiler inputs differ')
    c.validation['rust-final']['qualified_test_elf_receipt'] = qualified_libtest_binding(c, ROOT / q['directory'], final_micro['variants']['B'])
    c.validation['rust-final']['qualification_report_sha256'] = q['report_sha256']
    final_cohort = cohort(c, ROOT / co['directory'], 'cohort', co['report_sha256'], co['runtime_sha256'], source)
    need(final_cohort['variants']['B']['source_map'] == final_q['source_tested'], 'diagnostic cohort/final qualified compiler inputs differ')
    c.validation['cohort']['qualification_claim'] = final_cohort.get('qualification_claim')
    c.validation['cohort'].update(source_binding='identical compiler-input map and exact release ELF SHA-256 as final qualification',
                                 release_sha256_matches_qualification=True, runtime_sha256=q['runtime_sha256'],
                                 qualification_report_sha256=q['report_sha256'])
    for key, extended in (('native', False), ('extended', True)):
        row = config[key]
        directory = ROOT / row['directory']
        native(c, directory, key, row['report_sha256'], q['report_sha256'], q['runtime_sha256'], extended)
        remote_lease(c, ROOT / row['lease_directory'], key + '-lease', row['lease_report_sha256'],
                     directory / 'report.json', row['report_sha256'], 'extended-soak' if extended else 'native')
    return c


class HashedReader:
    def __init__(self, stream):
        self.stream, self.digest, self.size = stream, hashlib.sha256(), 0

    def read(self, size=-1):
        block = self.stream.read(size)
        self.digest.update(block)
        self.size += len(block)
        return block


def tar_info(name, size):
    info = tarfile.TarInfo(name)
    info.size, info.mtime, info.mode = size, 0, 0o600
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    return info


def export(c, config, config_info, output):
    need(output.parent == ROOT and re.fullmatch(r'export-r4(?:-[a-z0-9-]+)?', output.name), 'output must be a fresh export-r4 directory under fixed root')
    with opened(ROOT, directory=True):
        pass
    need(not os.path.lexists(output), 'output already exists; no overwrite or retry into old evidence')
    collector, _ = inspect(Path(__file__).absolute())
    metadata = {'schema': 'hepta-r4-evidence-subset/v1', 'source_root': str(ROOT),
        'collector_sha256': collector['sha256'], 'config_receipt': config_info, 'final_selection': config,
        'validation': c.validation, 'entries': [c.entries[k] for k in sorted(c.entries)],
        'excluded': sorted(c.excluded, key=lambda x: (x['source_path'], x['reason'])),
        'scope': 'Original-byte evidence subset. Original complete artifact manifests are included; not all manifested payloads are exported.',
        'excluded_content': ['ELF/test executables', 'private SSH keys and trust files', 'runtime/profile/input configurations', 'original request payloads', 'job/state trees', 'environment dumps'],
        'content_screening': 'Reject non-text/ELF, private-key markers and common credential assignments, including inside gzip; never redact.',
        'main_host_lease': 'Not collected here. Join separately using main remote_completion.report_sha256 and the exported remote report.',
        'archive': {'file': 'evidence-package.tar.gz', 'gzip_mtime': 0, 'tar_mtime': 0, 'uid': 0, 'gid': 0, 'mode': '0600'}}
    raw = (json.dumps(metadata, indent=2, sort_keys=True) + '\n').encode()
    os.umask(0o077)
    output.mkdir(mode=0o700)
    with (output / 'manifest.json').open('xb') as manifest:
        manifest.write(raw)
        manifest.flush()
        os.fsync(manifest.fileno())
    temporary = output / 'evidence-package.tar.gz.partial'
    with temporary.open('xb') as dest:
        with gzip.GzipFile(filename='', mode='wb', fileobj=dest, mtime=0, compresslevel=6) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                archive.addfile(tar_info('metadata.json', len(raw)), io.BytesIO(raw))
                for key in sorted(c.entries):
                    entry = c.entries[key]
                    with opened(entry['source_path']) as (fd, before), os.fdopen(os.dup(fd), 'rb') as stream:
                        need(stamp(before) == entry['identity'], 'source changed before packing: ' + key)
                        reader = HashedReader(stream)
                        archive.addfile(tar_info(key, entry['bytes']), reader)
                        need(reader.size == entry['bytes'] and reader.digest.hexdigest() == entry['sha256']
                             and stamp(os.fstat(fd)) == entry['identity'], 'source changed while packing: ' + key)
        dest.flush()
        os.fsync(dest.fileno())
    for entry in c.entries.values():
        with opened(entry['source_path']) as (_, info):
            need(stamp(info) == entry['identity'], 'source changed after packing: ' + entry['export_relative'])
    # Re-check the two non-evidence inputs too; publication happens only afterward.
    need(inspect(Path(config_info['path']))[0]['sha256'] == config_info['sha256'], 'export config changed')
    need(inspect(Path(__file__).absolute())[0]['sha256'] == collector['sha256'], 'collector changed')
    archive_path = output / 'evidence-package.tar.gz'
    os.rename(temporary, archive_path)
    with archive_path.open('rb') as stream:
        package_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    result = {'archive': str(archive_path), 'archive_sha256': package_sha,
              'manifest': str(output / 'manifest.json'), 'manifest_sha256': hashlib.sha256(raw).hexdigest(),
              'entries': len(c.entries), 'original_bytes': sum(x['bytes'] for x in c.entries.values()),
              'archive_bytes': archive_path.stat().st_size}
    with (output / 'package.json').open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    with opened(output, directory=True) as (fd, _):
        os.fsync(fd)
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True, help='fresh export-r4[-suffix] directly below fixed root')
    args = parser.parse_args()
    output = args.out if args.out.is_absolute() else ROOT / args.out
    config, info = load_config(args.config, args.config_sha256)
    collection = build_collection(config)
    collection.root(ROOT)
    collection.add(ROOT, 'collector-input', args.config.name, info)
    export(collection, config, info, output)


if __name__ == '__main__':
    main()
