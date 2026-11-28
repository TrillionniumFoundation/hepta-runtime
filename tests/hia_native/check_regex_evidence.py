"""Negative controls for retained *actual* configuration/regex evidence.

Run only after both real original recipes finish. No native image or reference
program is executed here. Altered fixture files are always restored before the
next case; this checker never operates on an active qualification workspace.
"""
from pathlib import Path
from contextlib import contextmanager
import argparse, copy, gzip, hashlib, json, os, sys, time

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encode = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def completed(folder, aggregate, name):
    found = [row for row in aggregate['checks'] if row['name'] == name]
    if len(found) != 1:
        raise ValueError('exactly one actual process required: ' + name)
    row = found[0]
    stdout = (folder / (name + '.stdout')).read_bytes()
    stderr = (folder / (name + '.stderr')).read_bytes()
    if (row['exit_code'] != 0 or row['timed_out'] is not False or row.get('start_error')
            or row.get('cleanup_timed_out', False) is not False
            or (sha(stdout), sha(stderr)) != (row['stdout_sha256'], row['stderr_sha256'])):
        raise ValueError('actual completion/output receipt differs: ' + name)
    summary = json.loads(stdout)
    if 'summary' in row and row['summary'] != summary:
        raise ValueError('actual stdout summary differs: ' + name)
    return row, summary


@contextmanager
def altered(path, raw):
    assert path.is_file() and not path.is_symlink()
    before = path.read_bytes()
    mode = path.stat().st_mode & 0o777
    assert before != raw
    try:
        path.write_bytes(raw)
        yield
    finally:
        path.write_bytes(before)
        path.chmod(mode)
        assert path.read_bytes() == before and path.stat().st_mode & 0o777 == mode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    root = args.repo.resolve(strict=True)
    output = args.output.resolve(strict=True)
    report_path = args.report.resolve(strict=True)
    assert report_path.is_relative_to(output)
    assert not args.receipt.exists()
    sys.path[:0] = [str(root / 'scripts'), str(root / 'tests/hia_native')]
    import hia_native_config_qualification as q
    aggregate = json.loads(report_path.read_bytes())
    original_report = report_path.read_bytes()
    source_before = q.source_pins(root)
    started = time.monotonic()
    baseline = q.native_evidence(root, output, aggregate, completed)
    original_config = q.original_evidence(root, output, aggregate, completed)
    original_regex = q.regex_original_evidence(root, output, aggregate, completed)
    controls = []

    def reject(name, operation):
        start = time.monotonic()
        try:
            operation()
        except (AssertionError, ValueError, KeyError) as error:
            controls.append({'name': name, 'rejected': True, 'exception': type(error).__name__,
                             'message': str(error), 'elapsed_seconds': time.monotonic() - start})
        else:
            raise AssertionError('altered evidence was admitted: ' + name)

    def native(variant):
        return q.native_evidence(root, output, variant, completed)

    bad = copy.deepcopy(aggregate)
    bad['checks'] = [x for x in bad['checks'] if x['name'] != 'test_regex_nfa_1.py']
    reject('missing-complete-nfa-half', lambda: native(bad))
    bad = copy.deepcopy(aggregate)
    bad['checks'].append(copy.deepcopy(next(x for x in bad['checks'] if x['name'] == 'test_regex_nfa_0.py')))
    reject('duplicated-actual-suite', lambda: native(bad))
    for key, value, name in [
        ('exit_code', -9, 'sigkill-cannot-be-pass'),
        ('timed_out', True, 'timeout-cannot-be-pass'),
        ('stdout_sha256', '0' * 64, 'changed-completed-stdout'),
        ('timeout_seconds', 181, 'extended-suite-budget'),
    ]:
        bad = copy.deepcopy(aggregate)
        next(x for x in bad['checks'] if x['name'] == 'test_regex_syntax.py')[key] = value
        reject(name, lambda: native(bad))
    bad = copy.deepcopy(aggregate)
    next(x for x in bad['checks'] if x['name'] == 'test_regex_nfa_0.py')['command'].append('--shards=4')
    reject('changed-actual-suite-command', lambda: native(bad))

    path = root / 'native/regex_nfa.hepta'
    with altered(path, path.read_bytes() + b'\n'):
        reject('changed-native-source', lambda: native(aggregate))
    bundle = json.loads((output / 'build/config-build.json').read_bytes())
    manifest_path = Path(bundle['executables']['mcp']['path'])
    assert manifest_path.is_relative_to(output)
    manifest = json.loads(manifest_path.read_bytes())
    path = manifest_path.parent / manifest['executable']
    raw = path.read_bytes()
    with altered(path, raw[:-1] + bytes([raw[-1] ^ 1])):
        reject('changed-real-embedded-image', lambda: native(aggregate))
    path = output / 'regex-native/nfa-0/native-output.txt'
    raw = path.read_bytes()
    with altered(path, (b'1' if raw[:1] != b'1' else b'2') + raw[1:]):
        reject('changed-actual-native-corpus', lambda: native(aggregate))

    # Rehash all small receipts accompanying a duplicated case index. Admission
    # must still inspect the exact partition, rather than accept those hashes.
    index_path = output / 'regex-native/nfa-0/case-indices.json'
    result_path = output / 'regex-native/nfa-0/native-corpus.json'
    stdout_path = output / 'test_regex_nfa_0.py.stdout'
    indices = json.loads(index_path.read_bytes())
    indices[1] = indices[0]
    new_index = (json.dumps(indices, separators=(',', ':')) + '\n').encode()
    summary = json.loads(result_path.read_bytes())
    summary['case_indices_sha256'] = sha(new_index)
    new_summary = encode(summary)
    bad = copy.deepcopy(aggregate)
    row = next(x for x in bad['checks'] if x['name'] == 'test_regex_nfa_0.py')
    row['stdout_sha256'] = sha(new_summary)
    row['stdout_bytes'] = len(new_summary)
    if 'summary' in row:
        row['summary'] = summary
    with altered(index_path, new_index), altered(result_path, new_summary), altered(stdout_path, new_summary):
        reject('rehash-does-not-admit-duplicated-case', lambda: native(bad))

    path = output / 'regex-original/report.json'
    changed = json.loads(path.read_bytes())
    changed['records'] = [x for x in changed['records'] if x['name'] != 'match']
    with altered(path, encode(changed)):
        reject('missing-full-original-match-replay', lambda: q.regex_original_evidence(root, output, aggregate, completed))
    path = output / 'regex-original/match.stdout.gz'
    raw = gzip.decompress(path.read_bytes())
    damaged = raw[:-2] + (b'0' if raw[-2:-1] != b'0' else b'1') + raw[-1:]
    with altered(path, gzip.compress(damaged, mtime=0)):
        reject('changed-full-original-output', lambda: q.regex_original_evidence(root, output, aggregate, completed))
    path = output / 'config-original/regex-mcp/report.json'
    changed = json.loads(path.read_bytes())
    changed['refusals'][0]['processes'].pop()
    with altered(path, encode(changed)):
        reject('missing-original-startup-refusal-side', lambda: q.original_evidence(root, output, aggregate, completed))

    assert q.native_evidence(root, output, aggregate, completed) == baseline
    assert q.original_evidence(root, output, aggregate, completed) == original_config
    assert q.regex_original_evidence(root, output, aggregate, completed) == original_regex
    assert q.source_pins(root) == source_before and report_path.read_bytes() == original_report
    result = {'schema': 'hepta.runtime.regex-evidence-controls.v1', 'status': 'PASS',
              'negative_controls': controls, 'negative_control_count': len(controls),
              'actual_baseline_admissions': 6, 'native_calls_added': 0, 'original_processes_added': 0,
              'source_and_artifacts_restored': True, 'source_pins': source_before,
              'checker_sha256': sha(Path(__file__).read_bytes()),
              'actual_process_report_sha256': sha(original_report),
              'elapsed_seconds': time.monotonic() - started,
              'unconstrained_regex_resources_closed': False}
    args.receipt.write_bytes(encode(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
