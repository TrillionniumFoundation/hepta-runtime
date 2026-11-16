"""Build and run the exact current SDK observer only in Rust 1.95 CI."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess, sys, time
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from check_source import check
from exact_rust_build import Recorder, build_exact_oracle

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NAME = 'current-sdk-request-task-oracle'


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'rust-bin', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    a = p.parse_args()
    assert os.environ.get('CI') == 'true', 'Rust build and execution require CI.'
    source = a.source.resolve(strict=True); output = a.output.absolute(); rust = a.rust_bin.resolve(strict=True)
    source_pin = check(source); assert not output.exists()
    shutil.copytree(source / 'reference', output)
    corpus = json.loads((source / 'tests/CORPUS.json').read_bytes())
    put(output / 'CORPUS.json', corpus)
    inputs = json.loads((source / 'SOURCE_INPUTS.json').read_bytes())
    summary = dict(schema='hepta.sdk-request-tasks.original-summary.v1', status='RUNNING',
        source_manifest=source_pin, cases_expected=len(corpus), cases_completed=0,
        actual_target_sdk_built=False, actual_target_sdk_executed=False)
    processes = []
    try:
        env = dict(PATH=str(rust) + os.pathsep + os.environ.get('PATH', ''),
                   RUSTC=str(rust / 'rustc'), CARGO_TARGET_DIR=str(output / 'rust-build'))
        seed = (output / 'cache-seed/Cargo.lock').read_bytes()
        prefetch = Recorder(output, 'evidence/cache-prefetch', env)
        version = prefetch.run('rustc-version', [rust / 'rustc', '--version', '--verbose'])
        assert version.decode().splitlines()[0].startswith('rustc 1.95.0 ')
        prefetch.run('cargo-fetch-locked', [rust / 'cargo', 'fetch', '--locked', '--manifest-path',
            output / 'cache-seed/Cargo.toml'])
        assert (output / 'cache-seed/Cargo.lock').read_bytes() == seed
        binary, build, _ = build_exact_oracle(output, 'oracle', NAME, rust)
        subset = json.loads((output / 'evidence/target-lock-subset.json').read_bytes())
        sdk = next(row for row in subset['registry_source_verification'] if row['name'] == 'rmcp')
        assert sdk['version'] == '3.9.0' and sdk['checksum'] == inputs['registry_checksum']
        prefix = 'reference/original-sdk/'
        for path, pin in inputs['origins'].items():
            if path.startswith(prefix):
                assert sdk['source_files'][path[len(prefix):]] == pin['sha256'], path
        metadata = json.loads((output / 'evidence/rust-build-processes/metadata-offline.stdout').read_bytes())
        archives = output / 'registry-archives'; archives.mkdir(); custody = []
        for package in metadata['packages']:
            if not package.get('source'):
                continue
            crate = Path(package['manifest_path']).parent
            original = crate.parent.parent.parent / 'cache' / crate.parent.name / (crate.name + '.crate')
            raw = original.read_bytes(); path = archives / (crate.name + '.crate'); path.write_bytes(raw)
            custody.append(dict(name=package['name'], version=package['version'], source=package['source'],
                path=str(path.relative_to(output)), bytes=len(raw), sha256=SHA(raw)))
        retained = output / 'reference-bin' / NAME; retained.parent.mkdir()
        shutil.copyfile(binary, retained); retained.chmod(0o500)
        assert SHA(retained.read_bytes()) == build['binary_sha256']
        build.update(registry_archive_custody=custody, retained_binary_relative_path=str(retained.relative_to(output)))
        put(output / 'BUILD.json', build); summary['actual_target_sdk_built'] = True
        for index, case in enumerate(corpus):
            folder = output / ('case-' + str(index).zfill(3)); folder.mkdir()
            data = (json.dumps(case, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
            (folder / 'stdin.jsonl').write_bytes(data)
            began = time.monotonic(); timed_out = False
            try:
                result = subprocess.run([str(retained)], input=data, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, cwd=output, env={'PATH': '', 'LC_ALL': 'C.UTF-8'}, timeout=60)
                stdout, stderr, code = result.stdout, result.stderr, result.returncode
            except subprocess.TimeoutExpired as error:
                stdout, stderr, code, timed_out = error.stdout or b'', error.stderr or b'', None, True
            (folder / 'stdout.jsonl').write_bytes(stdout); (folder / 'stderr.txt').write_bytes(stderr)
            processes.append(dict(index=index, label=case['label'], folder=folder.name,
                exit_code=code, timed_out=timed_out, deadline_seconds=60,
                elapsed_seconds=time.monotonic() - began, executable_sha256=build['binary_sha256'],
                stdin=dict(bytes=len(data), sha256=SHA(data)), stdout=dict(bytes=len(stdout), sha256=SHA(stdout)),
                stderr=dict(bytes=len(stderr), sha256=SHA(stderr))))
            put(output / 'processes.json', processes)
            assert code == 0 and not timed_out and not stderr, case['label']
            assert len(stdout.splitlines()) == 1 and json.loads(stdout)['label'] == case['label']
            summary['cases_completed'] += 1; put(output / 'SUMMARY.json', summary)
        build['actual_target_sdk_executed'] = True; put(output / 'BUILD.json', build)
        summary.update(status='CAPTURED', actual_target_sdk_executed=True)
    except BaseException as error:
        summary.update(status='FAIL', error=repr(error)); raise
    finally:
        put(output / 'SUMMARY.json', summary)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
