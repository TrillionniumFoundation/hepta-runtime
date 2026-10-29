import hashlib
import json
import re
from pathlib import Path

root = Path('/home/qian/hepta-runtime-optimization-20261028')
qdir = root / 'qualification-r4e'
source = root / 'source-r4e'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def load(path):
    return json.loads(path.read_bytes())

q = load(qdir / 'report.json')
audit = load(qdir / 'isolated-tests.audit.json')
summary = load(qdir / 'isolated-tests/summary.json')
source_map = load(qdir / 'source-map.json')
assert q['qualified'] is True and not q.get('error') and q['automatic_test_retries'] == 0
assert [row['name'] for row in q['stages']] == ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']
assert all(row['returncode'] == 0 for row in q['stages'])
assert q['source'] == str(source)
assert source_map == q['source_input'] == q['source_tested'] == q['source_after']
assert sha(qdir / 'source-map.json') == '7b5903e0e11666b926ff8dbdba28e3009c2ab4382f8e579d0c54bea1f4410c25'
assert len(source_map) == 192 and all(sha(source / name) == digest for name, digest in source_map.items())
harness = {p.name: sha(p) for p in sorted((source / 'tools/x230/20261028').glob('*.py'))}
assert len(harness) == 19 and harness == q['harness_before'] == q['harness_after']
assert audit['schema'] == 'hepta-isolated-libtest-audit/v1' and audit['success'] is True
assert audit['expected_filter'] == '' and audit['failed'] == 0
assert audit['executed'] == audit['passed'] > 0 and not audit['errors'] and not audit.get('fatal_error')
assert summary['success'] is True and summary['filter'] == '' and summary['retries'] == 0
assert all(summary[k] == audit[k] for k in ('passed', 'failed', 'ignored', 'selected'))
assert load(qdir / 'isolated-tests/source-manifest.input') == source_map
library = [row for row in summary['binaries'] if row['target']['name'] == 'hepta_runtime' and row['target']['kind'] == ['lib']]
assert len(library) == 1
library = library[0]
elf = Path(library['path'])
assert elf.parent == qdir / 'test-binaries'
matching = [row for row in audit['binaries'] if row['path'] == str(elf)]
assert len(matching) == 1
assert sha(elf) == library['sha256'] == matching[0]['recorded_before_sha256'] == matching[0]['current_after_sha256']
cargo = [json.loads(line) for line in (qdir / 'retained-artifacts.jsonl').read_text().splitlines() if line.strip()]
matching_cargo = [row for row in cargo if row.get('reason') == 'compiler-artifact' and row.get('profile', {}).get('test') is True and row.get('executable') == str(elf)]
assert len(matching_cargo) == 1 and matching_cargo[0]['target'] == library['target']
control_cargo_path = root / 'control-r4/test-build.stdout'
control_cargo = [json.loads(line) for line in control_cargo_path.read_text().splitlines() if line.strip()]
control_library = [row for row in control_cargo if row.get('reason') == 'compiler-artifact' and row.get('profile', {}).get('test') is True and row.get('target', {}).get('name') == 'hepta_runtime' and row['target']['kind'] == ['lib']]
assert len(control_library) == 1 and control_library[0]['profile'] == matching_cargo[0]['profile']
assert sha(root / 'control-r4/hepta-runtime-lib-tests') == '73e538f910786b4675975305ec25188eadf6b23a5a1cc14725bfe8d3efdea3fe'
assert matching_cargo[0]['profile']['opt_level'] == '1' and matching_cargo[0]['profile']['debuginfo'] == 0
assert set(q['binaries']) == {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
assert all(sha(Path(value['path'])) == value['sha256'] for value in q['binaries'].values())
tests = [json.loads(line) for line in (qdir / 'isolated-tests/tests.jsonl').read_text().splitlines()]
selected_tests = [row for row in tests if 'registry_coalescing_tests::' in row['name'] or 'maintenance::' in row['name']]
python_log = (qdir / 'harness-tests.stderr').read_text()
python_count = re.findall(r'Ran (\d+) tests? in', python_log)
assert len(python_count) == 1 and '\nOK\n' in python_log
result = {'schema': 'hepta-r4e-final-qualified-bindings/v1', 'qualified': True,
          'qualification': {'path': str(qdir / 'report.json'), 'sha256': sha(qdir / 'report.json')},
          'audit': {'path': str(qdir / 'isolated-tests.audit.json'), 'sha256': sha(qdir / 'isolated-tests.audit.json')},
          'source': str(source), 'source_map_sha256': sha(qdir / 'source-map.json'),
          'compiler_inputs': len(source_map), 'harness_files': len(harness),
          'harness_sha256': harness,
          'rust': {k: audit[k] for k in ('selected', 'passed', 'failed', 'ignored', 'executed')},
          'python_passed': int(python_count[0]), 'test_executables': len(summary['binaries']),
          'libtest': {'path': str(elf), 'sha256': sha(elf)}, 'binaries': q['binaries'],
          'test_build_profile': matching_cargo[0]['profile'],
          'baseline_test_build_profile': control_library[0]['profile'],
          'baseline_cargo_stream_sha256': sha(control_cargo_path),
          'diagnostic_runtime_sha256': '8469fe7afdf560f4c501e5162cd7926957fade695118e9b9b72f1594ed861248',
          'diagnostic_runtime_equals_qualified': q['binaries']['hepta-runtime']['sha256'] == '8469fe7afdf560f4c501e5162cd7926957fade695118e9b9b72f1594ed861248',
          'selected_case_outcomes': [{k: row[k] for k in ('name', 'status', 'executed', 'attempt')} for row in selected_tests],
          'stages': [{k: row[k] for k in ('name', 'returncode', 'seconds')} for row in q['stages']]}
output = root / 'qualification-r4e-bindings.json'
with output.open('x') as stream:
    json.dump(result, stream, indent=2)
    stream.write('\n')
print(json.dumps(result), flush=True)
print(json.dumps({'binding_file': str(output), 'sha256': sha(output)}), flush=True)
