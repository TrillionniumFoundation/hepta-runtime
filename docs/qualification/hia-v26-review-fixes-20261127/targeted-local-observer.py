"""Observe the exact embedded executable fixtures and retained mapping checks."""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import platform
import subprocess
import time

repo = Path('/tmp/runtime-v26-review-fixes-589c')
out = repo / 'docs/qualification/hia-v26-review-fixes-20261127'

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

def raw_constant(text, name):
    return text.split(f'const {name}: &str = r#"', 1)[1].split('"#;', 1)[0]

source = (repo / 'src/mcp/runtime/jobs.rs').read_text()
fixture_source = (repo / 'src/mcp/runtime/jobs_native_executable_tests.rs').read_text()
private = raw_constant(source, 'PRIVATE_DIRECTORY_CODE')
start = raw_constant(source, 'START_CODE')
helper = 'def pin_native_workload_executable' + start.split('def pin_native_workload_executable', 1)[1].split('\ndef exec_native_job_owner', 1)[0]
fixture = raw_constant(fixture_source, 'FIXTURE')
mac = json.loads(Path('/workspace/scratch/589c0a6dd85b/runtime-pr159-mac-validation-initial.json').read_bytes())
for path, expected in mac['after_format'].items():
    assert pin((repo / path).read_bytes()) == expected, path

report = {
    'schema': 'hepta.runtime.pr159-review-targeted-local.v1',
    'recorded_utc': datetime.now(timezone.utc).isoformat(),
    'base_commit': '0ce79ce0e47225073fdc5394651df942eb6b98b1',
    'source_files': mac['after_format'],
    'cargo_lock': pin((repo / 'Cargo.lock').read_bytes()),
    'observer': {'path': Path(__file__).name, **pin(Path(__file__).read_bytes())},
    'platform': platform.platform(),
    'python': subprocess.check_output(['/usr/bin/python3', '--version'], text=True).strip(),
    'checks': [],
    'rust_test_wrappers_executed': False,
    'linux_http_rust_test_executed': False,
    'whole_native_delivery_qualified': False,
    'scope': 'Exact embedded Python fixture and production helper bytes executed; Rust wrappers and HTTP tests await Linux CI.',
}

def run(name, argv, stdin=b'', expected=0):
    started = time.monotonic_ns()
    result = subprocess.run(argv, input=stdin, cwd=repo, capture_output=True, timeout=60)
    logs = {}
    for stream in ('stdout', 'stderr'):
        raw = getattr(result, stream)
        target = out / (name + '.' + stream)
        with target.open('xb') as output:
            output.write(raw)
        logs[stream] = {'path': target.name, **pin(raw)}
    row = {'name': name, 'argv': argv, 'stdin': pin(stdin), 'elapsed_ns': time.monotonic_ns() - started,
           'returncode': result.returncode, 'expected_returncode': expected, 'logs': logs}
    if name.startswith('executable-') and result.returncode == 0:
        row['result'] = json.loads(result.stdout)
    report['checks'].append(row)
    (out / 'targeted-local.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(name, result.returncode, flush=True)
    assert result.returncode == expected, row

for case in ('venv', 'refusals'):
    payload = json.dumps({'case': case, 'private': private, 'pin': helper}).encode()
    run('executable-' + case, ['/usr/bin/python3', '-I', '-B', '-c', fixture], payload)
run('mapping', ['/usr/bin/python3', '-B', 'scripts/rea_compatibility_ledger.py', 'check-mapping'])
run('strict-open', ['/usr/bin/python3', '-B', 'scripts/rea_compatibility_ledger.py', 'check-mapping', '--require-parity'], expected=3)
run('ledger-tests', ['/usr/bin/python3', '-B', 'tests/rea_compatibility_ledger_tests.py', '-v'])
for path, expected in report['source_files'].items():
    assert pin((repo / path).read_bytes()) == expected, path
report['source_files_preserved'] = True
report['passed'] = True
(out / 'targeted-local.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print('TARGETED_LOCAL_PASS')
