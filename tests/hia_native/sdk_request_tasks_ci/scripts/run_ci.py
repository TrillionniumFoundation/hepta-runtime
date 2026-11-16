"""Fresh two-owner HIA build, current SDK reference, captures and strict readback."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys, time
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_source import check
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True, type=Path)
    for name in ('hepta', 'rust-bin', 'output'):
        p.add_argument('--' + name, type=Path)
    p.add_argument('--check-only', action='store_true'); a = p.parse_args()
    source = a.source.resolve(strict=True); source_pin = check(source)
    if a.check_only:
        print(json.dumps(dict(status='SOURCE_CHECK_PASS', source=source_pin), sort_keys=True)); return
    assert os.environ.get('CI') == 'true', 'The complete fresh recipe runs only in CI.'
    assert all((a.hepta, a.rust_bin, a.output))
    output = a.output.absolute(); assert not output.exists(); output.mkdir(parents=True)
    processes = output / 'processes'; processes.mkdir()
    recipe = dict(schema='hepta.sdk-request-tasks.recipe.v1', status='RUNNING',
        source_manifest=source_pin, stages=[], native_cases_completed=0,
        public_registry_integrated=False, full_async_runtime_qualified=False, full_sdk_qualified=False,
        async_rw_transport_qualified=False, real_worker_executed=False,
        production_activated=False, old_path_removed=False)
    def checkpoint():
        put(output / 'RECIPE.json', recipe)
    def stage(label, argv):
        begin = time.monotonic()
        # Case deadlines remain internal at 60 s. Build commands keep their
        # existing inner deadlines; the CI job is the only overall deadline.
        result = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (processes / (label + '.stdout')).write_bytes(result.stdout)
        (processes / (label + '.stderr')).write_bytes(result.stderr)
        recipe['stages'].append(dict(label=label, argv=[str(x) for x in argv], exit_code=result.returncode,
            elapsed_seconds=time.monotonic() - begin, stdout_bytes=len(result.stdout), stdout_sha256=SHA(result.stdout),
            stderr_bytes=len(result.stderr), stderr_sha256=SHA(result.stderr)))
        checkpoint(); assert result.returncode == 0, label
        return result.stdout
    checkpoint()
    try:
        stage('reproduce-author', [sys.executable, '-I', '-B', source / 'authoring/author_registry.py',
            '--source', source, '--hepta', a.hepta, '--check'])
        stage('fresh-native-build', [sys.executable, '-I', '-B', source / 'scripts/build_registry.py',
            '--source', source, '--hepta', a.hepta, '--output', output / 'native-build'])
        stage('fresh-current-reference', [sys.executable, '-I', '-B', source / 'scripts/run_reference.py',
            '--source', source, '--rust-bin', a.rust_bin, '--output', output / 'reference'])
        corpus = json.loads((source / 'tests/CORPUS.json').read_bytes())
        native_processes = []; logs = output / 'native-processes'; logs.mkdir()
        for index, case in enumerate(corpus):
            label = 'case-' + str(index).zfill(3)
            command = [sys.executable, '-I', '-B', source / 'scripts/run_native.py', '--source', source,
                '--build', output / 'native-build', '--original', output / 'reference',
                '--case-index', str(index), '--output', output / 'native' / label]
            begin = time.monotonic(); timed_out = False
            try:
                result = subprocess.run([str(x) for x in command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                out, err, code = result.stdout, result.stderr, result.returncode
            except subprocess.TimeoutExpired as error:
                out, err, code, timed_out = error.stdout or b'', error.stderr or b'', None, True
            (logs / (label + '.stdout')).write_bytes(out); (logs / (label + '.stderr')).write_bytes(err)
            native_processes.append(dict(index=index, label=case['label'], exit_code=code, timed_out=timed_out,
                deadline_seconds=60, elapsed_seconds=time.monotonic() - begin,
                runner_sha256=SHA((source / 'scripts/run_native.py').read_bytes()),
                stdout=dict(bytes=len(out), sha256=SHA(out)), stderr=dict(bytes=len(err), sha256=SHA(err))))
            put(output / 'native-processes.json', native_processes)
            assert code == 0 and not timed_out and not err, label
            assert json.loads(out)['status'] == 'PASS'
            recipe['native_cases_completed'] += 1; checkpoint()
        stage('physical-reader-controls', [sys.executable, '-I', '-B', source / 'scripts/run_reader_controls.py',
            '--source', source, '--run', output])
        raw = stage('complete-readonly', [sys.executable, '-I', '-B', source / 'scripts/verify_complete.py',
            '--source', source, '--run', output])
        report = json.loads(raw); assert report['status'] == 'READONLY_CURRENT_SDK_TASKS110_PASS'
        recipe.update(status='PASS', verification=report['evidence']); checkpoint()
    except BaseException as error:
        recipe.update(status='FAIL', error=repr(error)); checkpoint(); raise
    print(json.dumps(dict(status='FRESH_CURRENT_SDK_TASKS110_PASS', cases=110,
        native_calls=recipe['verification']['native_calls'], g1_projections=recipe['verification']['g1_projections'],
        source=source_pin, full_async_runtime_qualified=False, public_registry_integrated=False), sort_keys=True))


if __name__ == '__main__':
    main()
