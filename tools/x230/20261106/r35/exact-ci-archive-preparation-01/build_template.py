#!/usr/bin/env python3
"""Create a new R35 exact-CI archive template by source/JSON/AST operations only."""
import ast
import hashlib
import json
from pathlib import Path
import pprint

BASE = Path('/tmp/hepta-runtime-recovery-20261106')
OUT = BASE / 'r35-exact-ci-archive-template-01'
REFERENCE = BASE / 'r34-exact-ci-archive-sealed-01/archive_r34_exact_ci.py'
REFERENCE_SHA = '616b19b3f4859954a08f79e1e038a79bfe59465c7c9ab7ebe6fcbce57833b9e8'
ROOT = '/home/qian/hepta-runtime-optimization-20261106-r35'
Q = BASE / 'r35-qualified-originals-01'
PREP = BASE / 'r35-qualification-prep-01/sealed-01'
CI = BASE / 'r35-exact-ci-sealed-01'
CI_JOB = '1a1af88c330-fc05-696f'
Q_JOB = '1a1af619097-fc05-6813'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def functions(text):
    return {n.name: ast.get_source_segment(text, n) for n in ast.parse(text).body if isinstance(n, ast.FunctionDef)}


def assignment(text, name, expression):
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    need(len(nodes) == 1, 'unique assignment required: ' + name)
    lines = text.splitlines(keepends=True)
    n = nodes[0]
    lines[n.lineno - 1:n.end_lineno] = [name + ' = ' + expression + '\n']
    return ''.join(lines)


ACTUAL_HELPERS = r'''
def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r35-exact-ci-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True and ACTUAL.get('ci_job_id') == CI_JOB,
         'UNSEALED: complete original R35 exact-CI receipts are required')
    archive_sha = ACTUAL.get('qualification_archive_sha256')
    need(type(archive_sha) is str and re.fullmatch(r'[0-9a-f]{64}', archive_sha),
         'actual completed qualification archive reference required')
    files = ACTUAL.get('files')
    need(type(files) is dict and len(files) <= MAX_FILES, 'actual CI receipt inventory required')
    native_reads = read_names(files)
    need(set(files) == set(FUTURE_CORE) | {FUTURE_AUDIT} | set(native_reads),
         'actual CI receipt names differ from the original fixed namespace')
    for name, pin in files.items():
        if pin is None:
            need(name == FUTURE_AUDIT, 'only a genuinely absent nextest audit can have a null pin')
        else:
            need(type(pin) is dict and set(pin) == {'bytes', 'sha256'}
                 and type(pin['bytes']) is int and 0 < pin['bytes'] <= MAX_FILE
                 and type(pin['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', pin['sha256']),
                 'invalid actual original CI receipt identity: ' + name)
    need(all(files[name] is not None for name in FUTURE_CORE)
         and all(files[name] is not None for name in native_reads), 'core original CI receipt is absent')
    need(type(ACTUAL.get('reported_passed')) is bool, 'original reported CI outcome is unbound')
    counts = ACTUAL.get('reported_nextest_counts')
    need(counts is None or (type(counts) is dict and set(counts) == {'passed', 'failed', 'ignored', 'selected', 'retries'}),
         'reported original CI count shape differs')
    terminal_identity = ACTUAL.get('native_terminal')
    need(type(terminal_identity) is dict and set(terminal_identity) == {'state', 'exit_code'}
         and terminal_identity['state'] in {'succeeded', 'failed', 'cancelled', 'timed_out'}
         and (terminal_identity['exit_code'] is None or type(terminal_identity['exit_code']) is int),
         'actual original CI terminal outcome is unbound')
    return ACTUAL


def bind_actual_receipts(data, expected_plan_sha):
    actual = require_sealed()
    need(expected_plan_sha == actual['files']['rust-ci-plan-01.json']['sha256'],
         'plan argument differs from sealed original CI plan')
    for name, pin in actual['files'].items():
        need((name not in data) if pin is None else
             (name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin),
             'actual original CI receipt presence/identity differs: ' + name)
    need(read_names(data) == read_names(actual['files']), 'native read receipt membership differs')
    report = json.loads(data['rust-ci-01/report.json'])
    native = json.loads(data['rust-ci-native-01.json'])
    audit = report.get('nextest_output_audit')
    counts = None if not isinstance(audit, dict) else {
        key: audit.get(key) for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    need(report.get('passed') == actual['reported_passed']
         and counts == actual['reported_nextest_counts']
         and {key: native.get(key) for key in ('state', 'exit_code')} == actual['native_terminal'],
         'reported outcome/counts/native state differ from original sealed bytes')
    return actual
'''

SEALER = r'''#!/usr/bin/env python3
"""Seal a new local R35 CI collector from original completed receipts; never run the collector."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint
import re
import stat

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / 'archive_r35_exact_ci.py'
TEMPLATE_PIN = __TEMPLATE_PIN__
ROOT = '/home/qian/hepta-runtime-optimization-20261106-r35'
CI_JOB = '1a1af88c330-fc05-696f'
Q_JOB = '1a1af619097-fc05-6813'
CORE = ('rust-ci-plan-01.json', 'rust-ci-01/report.json', 'rust-ci-native-01.json')
AUDIT = 'rust-ci-01/nextest-output-audit.json'
READ_RE = re.compile(r'rust-ci-native-read-01(?:-[0-9]{3})?\.json\Z')
LIMIT = 8 * 1024 * 1024
COUNTS = ('passed', 'failed', 'ignored', 'selected', 'retries')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def read_local(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'direct absolute original required')
    initial = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    stamp = lambda value: tuple(getattr(value, key) for key in fields)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= LIMIT
             and stamp(before) == stamp(initial), 'unsafe/oversized original')
        raw = stream.read(LIMIT + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             'original changed while read')
    return raw


__ORIGINAL_PURE_RECEIPT_HELPERS__


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    template_raw = read_local(TEMPLATE)
    need(identity(template_raw) == TEMPLATE_PIN, 'reviewed unsealed collector differs')
    input_raw = read_local(args.receipts)
    inputs = json.loads(input_raw)
    need(inputs.get('schema') == 'hepta-r35-exact-ci-archive-seal-input/v1'
         and inputs.get('ci_job_id') == CI_JOB and type(inputs.get('files')) is dict,
         'actual original CI identity/locations required')
    archive_sha = inputs.get('qualification_archive_sha256')
    need(type(archive_sha) is str and re.fullmatch(r'[0-9a-f]{64}', archive_sha),
         'actual completed qualification archive SHA required')
    read_files = read_names(inputs['files'])
    need(set(inputs['files']) == set(CORE) | {AUDIT} | set(read_files)
         and len(inputs['files']) <= 8192, 'original CI receipt names differ')
    bodies, pins, copies = {}, {}, {}
    for name, row in inputs['files'].items():
        if row is None:
            need(name == AUDIT, 'only genuinely absent later audit may be null')
            pins[name] = None
            continue
        need(type(row) is dict and set(row) == {'local_path', 'bytes', 'sha256'}
             and type(row['local_path']) is str and type(row['bytes']) is int and 0 < row['bytes'] <= LIMIT
             and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']),
             'exact original local receipt identity required: ' + name)
        body = read_local(row['local_path'])
        need(identity(body) == {key: row[key] for key in ('bytes', 'sha256')}, 'original differs: ' + name)
        bodies[name], pins[name], copies[name] = body, identity(body), dict(row, remote_path=ROOT + '/' + name)
    need(all(name in bodies for name in CORE) and all(name in bodies for name in read_files),
         'core original plan/report/terminal/read missing; never fabricate a preflight report')
    plan = json.loads(bodies['rust-ci-plan-01.json'])
    report = json.loads(bodies['rust-ci-01/report.json'])
    native = json.loads(bodies['rust-ci-native-01.json'])
    native_view = terminal(native, CI_JOB)
    stream_proof = streams_from_reads(native, [json.loads(bodies[name]) for name in read_files])
    need(plan.get('schema') == 'hepta-r35-materialized-exact-rust-ci-plan/v1'
         and plan.get('attempt') == '01' and plan.get('qualification_job_id') == Q_JOB
         and report.get('schema') == 'hepta-r35-external-rust-ci/v1'
         and report.get('attempt') == '01' and type(report.get('passed')) is bool,
         'original CI plan/report schema or attempt differs')
    audit = report.get('nextest_output_audit')
    counts = None if not isinstance(audit, dict) else {key: audit.get(key) for key in COUNTS}
    actual = {'schema': 'hepta-r35-exact-ci-archive-actual-pins/v1', 'sealed': True,
        'ci_job_id': CI_JOB, 'qualification_archive_sha256': archive_sha, 'files': pins,
        'reported_passed': report['passed'], 'reported_nextest_counts': counts,
        'native_terminal': {key: native.get(key) for key in ('state', 'exit_code')}}
    text = template_raw.decode('utf-8')
    found = [node for node in ast.parse(text).body if isinstance(node, ast.Assign) and len(node.targets) == 1
             and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'ACTUAL']
    need(len(found) == 1 and isinstance(found[0].value, ast.Constant) and found[0].value.value is None,
         'unsealed ACTUAL assignment required')
    lines = text.splitlines(keepends=True)
    node = found[0]
    lines[node.lineno - 1:node.end_lineno] = ['ACTUAL = ' + pprint.pformat(actual, sort_dicts=True) + '\n']
    sealed = ''.join(lines).encode()
    ast.parse(sealed)
    for name, row in copies.items():
        need(identity(read_local(row['local_path'])) == pins[name], 'original changed before seal')
    need(read_local(TEMPLATE) == template_raw and read_local(args.receipts) == input_raw, 'seal inputs changed')
    out = args.out
    need(out.is_absolute() and out.parent.resolve(strict=True) == out.parent and not os.path.lexists(out),
         'fresh direct output directory required')
    out.mkdir(mode=0o700)
    seal = {'schema': 'hepta-r35-exact-ci-archive-local-seal/v1', 'status': 'sealed_not_executed',
        'template': TEMPLATE_PIN, 'collector': identity(sealed), 'input': identity(input_raw),
        'actual': actual, 'original_copies': copies, 'native_terminal_view': native_view,
        'original_native_streams': stream_proof, 'qualification_archive_reference_independently_rehashed': False,
        'qualification_archive_reference_source': 'actual original archive digest supplied by coordinator',
        'collector_or_auditor_or_ci_executed': False, 'remote_calls': 0,
        'outcome_scope': 'raw original state preserved; collector later reports binding errors without inventing CI success'}
    for name, raw in [('archive_r35_exact_ci.py', sealed), ('actual-pins.json', encoded(actual)), ('seal-manifest.json', encoded(seal))]:
        with (out / name).open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({'status': 'sealed_not_executed', 'collector': identity(sealed),
                     'original_ci_job': CI_JOB, 'reported_passed': report['passed'],
                     'reported_nextest_counts': counts, 'collector_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
'''


def main():
    need(not OUT.exists(), 'fresh template output required')
    reference_raw = REFERENCE.read_bytes()
    need(identity(reference_raw)['sha256'] == REFERENCE_SHA, 'original R34 collector differs')
    original = reference_raw.decode()
    normalized = original.replace('R34', 'R35').replace('r34', 'r35')
    local_sources = {
        'candidate/candidate.patch': PREP / 'candidate/candidate.patch',
        'preparation.json': Q / 'preparation.json',
        'prepare_qualify.py': PREP / 'prepare_qualify.py',
        'qualification-01/isolated-tests/summary.json': Q / 'isolated-summary.json',
        'qualification-01/report.json': Q / 'qualification-report.json',
        'qualification-01/source-map.json': Q / 'source-map.json',
        'qualification-input.json': PREP / 'qualification-input.json',
        'qualification-terminal-status-01.json': Q / 'qualification-terminal-status-01.json',
        'rust-ci-qualification-bindings-01.json': CI / 'rust-ci-qualification-bindings-01.json',
        'rust-ci-sealed-01/actual-pins.json': CI / 'actual-pins.json',
        'rust-ci-sealed-01/seal-manifest.json': CI / 'seal-manifest.json',
        'tools-01/r35_campaign.py': BASE / 'r35-observation-template-01/generated/r35_campaign.py',
    }
    for p in sorted((CI / 'tools').iterdir()):
        need(p.is_file(), 'unexpected sealed tool subtree')
        local_sources['rust-ci-tools-01/' + p.name] = p
    need(len(local_sources) == 18, 'fixed selection differs')
    fixed = {name: identity(path.read_bytes()) for name, path in sorted(local_sources.items())}
    text = assignment(normalized, 'REFERENCE_SHA', repr(REFERENCE_SHA))
    text = assignment(text, 'QUALIFICATION_JOB', repr(Q_JOB))
    text = assignment(text, 'CI_JOB', repr(CI_JOB))
    text = assignment(text, 'PINNED', pprint.pformat({n: pin['sha256'] for n, pin in fixed.items()}, sort_dicts=True))
    text = assignment(text, 'QUALIFICATION_ARCHIVE_SHA', "None if ACTUAL is None else ACTUAL['qualification_archive_sha256']")
    index = text.index('QUALIFICATION_ARCHIVE_SHA =')
    text = text[:index] + "ACTUAL = None\nFUTURE_CORE = ('rust-ci-plan-01.json', 'rust-ci-01/report.json', 'rust-ci-native-01.json')\nFUTURE_AUDIT = 'rust-ci-01/nextest-output-audit.json'\n" + text[index:]
    position = text.index('def collect(')
    text = text[:position] + ACTUAL_HELPERS.lstrip() + '\n\n' + text[position:]
    for name, signature in [('collect', 'def collect(root, kind):\n'), ('create_archive', 'def create_archive(root, kind, expected_plan_sha):\n'), ('verify_archive', 'def verify_archive(path, expected_sha):\n')]:
        need(text.count(signature) == 1, 'unique collector entry required')
        text = text.replace(signature, signature + '    require_sealed()\n', 1)
    sig = 'def summary(kind, data, expected_plan_sha):\n'
    text = text.replace(sig, sig + '    bind_actual_receipts(data, expected_plan_sha)\n', 1)
    ast.parse(text)
    before, after = functions(normalized), functions(text)
    for name in before:
        restored = after[name]
        if name in ('collect', 'create_archive', 'verify_archive'):
            restored = restored.replace('    require_sealed()\n', '', 1)
        elif name == 'summary':
            restored = restored.replace('    bind_actual_receipts(data, expected_plan_sha)\n', '', 1)
        need(restored == before[name], 'original function body changed: ' + name)
    collector_raw = text.encode()
    pure = '\n\n\n'.join(functions(original)[n] for n in ('read_names', 'terminal', 'streams_from_reads'))
    sealer = SEALER.replace('__TEMPLATE_PIN__', repr(identity(collector_raw))).replace('__ORIGINAL_PURE_RECEIPT_HELPERS__', pure).encode()
    ast.parse(sealer)
    for n in ('read_names', 'terminal', 'streams_from_reads'):
        need(functions(sealer.decode())[n] == functions(original)[n], 'receipt helper changed in sealer')
    actual_example = {'schema': 'hepta-r35-exact-ci-archive-actual-pins/v1', 'sealed': False,
        'ci_job_id': CI_JOB, 'qualification_archive_sha256': None,
        'files': {n: None for n in ('rust-ci-plan-01.json', 'rust-ci-01/report.json', 'rust-ci-01/nextest-output-audit.json', 'rust-ci-native-01.json', 'rust-ci-native-read-01.json')},
        'reported_passed': None, 'reported_nextest_counts': None, 'native_terminal': None,
        'note': 'Unsealed. Known started job is not a terminal or successful CI result. All outcome/count/file pins come from actual original receipts.'}
    receipts_example = {'schema': 'hepta-r35-exact-ci-archive-seal-input/v1', 'ci_job_id': CI_JOB,
        'qualification_archive_sha256': None,
        'files': {n: {'local_path': None, 'bytes': None, 'sha256': None} for n in actual_example['files']},
        'note': 'Fill only after original CI is terminal. Audit entry may be null only if truly absent. For paged native reads, replace the single entry with contiguous original -000, -001 names. Core original plan/report/terminal/read cannot be synthesized.'}
    static = {'schema': 'hepta-r35-exact-ci-archive-static-preparation/v1',
        'reference': identity(reference_raw), 'collector': identity(collector_raw), 'sealer': identity(sealer),
        'original_functions_preserved_after_only_round_and_four_entry_guards': sorted(before),
        'original_IO_terminal_streams_bounds_exclusions_preserved': True,
        'fixed_input_count': len(fixed), 'fixed_inputs_rehashed_from_local_originals': True,
        'future_ACTUAL_is_None': True, 'future_CI_counts_outcomes_and_original_receipt_pins_null': True,
        'known_qualification_counts_are_reference_only': {'passed':1645,'failed':0,'ignored':34,'selected':1679,'retries':0},
        'known_started_CI_job': CI_JOB, 'source_programs_imported_or_executed': False,
        'collector_sealer_auditor_CI_executed': False, 'remote_calls':0,
        'method':'Source extraction, JSON/raw hash and AST comparisons only; no target import or execution.'}
    outputs = {
        'archive_r35_exact_ci.py': collector_raw, 'seal_collector.py': sealer,
        'actual-pins.example.json': encoded(actual_example), 'receipt-locations.example.json': encoded(receipts_example),
        'fixed-inputs.json': encoded({'root': ROOT, 'files': {n:dict(pin,local_path=str(local_sources[n])) for n,pin in fixed.items()}}),
        'STATIC_CHECKS.json': encoded(static), 'reference-r34/archive_r34_exact_ci.py': reference_raw,
        'build_template.py': Path(__file__).read_bytes(),
    }
    OUT.mkdir(mode=0o700)
    (OUT/'reference-r34').mkdir(mode=0o700)
    for name, body in outputs.items():
        with (OUT/name).open('xb') as stream: stream.write(body)
    manifest = {'schema':'hepta-r35-exact-ci-archive-unsealed-template/v1','sealed':False,
        'files':{n:identity(b) for n,b in sorted(outputs.items())}, 'fixed_input_count':len(fixed),
        'future_actual':actual_example,'maximum_total_bytes':64*1024*1024,'maximum_file_bytes':8*1024*1024,
        'maximum_manifest_bytes':2*1024*1024,'maximum_files':8192,
        'collector_or_sealer_or_CI_executed':False,'remote_calls':0}
    with (OUT/'unsealed-manifest.json').open('xb') as stream: stream.write(encoded(manifest))
    print(json.dumps({'output':str(OUT),'collector':identity(collector_raw),'sealer':identity(sealer),'fixed_inputs':len(fixed),'collector_executed':False},sort_keys=True))


if __name__ == '__main__':
    main()
