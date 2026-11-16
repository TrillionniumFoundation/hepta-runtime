"""Fresh native emission and actual-thread gate with independent reader custody."""
from pathlib import Path
import argparse
import os
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from common import encoded, loads, pin, read, require, seal, source
from process import Recorder, environment


def run(hepta, output, rust_bin, expected_source):
    identity = source()
    require(identity == expected_source, 'explicit frozen source identity')
    domain = loads(read(ROOT / 'DOMAIN.json'))
    output.mkdir(parents=True, exist_ok=False)
    semantic = output / 'semantic'
    semantic.mkdir()
    threads = semantic / 'threads'
    threads.mkdir()
    env, env_receipt = environment(os.environ, rust_bin)
    env.update(HIA_AUDIT_SYNC_IMAGE=str(semantic / 'emission/boundary.bin'),
               HIA_AUDIT_SYNC_JOURNAL=str(threads / 'journal.jsonl'))
    recorder = Recorder(ROOT, semantic / 'processes', env)
    python = str(Path(sys.executable).resolve(strict=True))
    rustc = str(rust_bin / 'rustc')
    rustfmt = str(rust_bin / 'rustfmt')
    fixture = str(ROOT / 'reference/sync_tests.rs')
    test_binary = str(threads / 'sync-tests')
    manifest = semantic / 'build/modules/audit-native-sync/manifest.json'
    recipes = [
        ('format', [rustfmt, '--check', '--edition', '2021', '--config',
                    'hard_tabs=true,max_width=100', fixture]),
        ('compiler-version', [rustc, '--version', '--verbose']),
        ('native-build', [python, '-B', str(ROOT / 'build.py'), '--hepta', str(hepta),
                          '--output', str(semantic / 'build')]),
        ('emit-boundary', [python, '-B', str(ROOT / 'emit.py'), '--manifest', str(manifest),
                           '--output', str(semantic / 'emission')]),
        ('rust-build', [rustc, *domain['rust_profile'], '--crate-name', 'audit_native_sync_tests',
                        '--target', 'x86_64-unknown-linux-gnu', fixture, '-o', test_binary]),
        ('actual-threads', [test_binary, '--test-threads=1', '--nocapture']),
    ]
    started = time.monotonic()
    metadata = dict(schema='hepta.audit-native-sync.capture.v1', status='INCOMPLETE',
                    source_manifest_sha256=identity, domain=pin(read(ROOT / 'DOMAIN.json')),
                    source_root=str(ROOT), producer_root=str(semantic), python=python,
                    rust_bin=str(rust_bin), compiler_root=str(hepta),
                    rustc=pin(read(Path(rustc))), rustfmt=pin(read(Path(rustfmt))),
                    git_head=os.environ.get('GITHUB_SHA'), run_id=os.environ.get('GITHUB_RUN_ID'),
                    environment=env_receipt, native_os_boundary_only=True,
                    audit_queue_controller_qualified=False, public_handler_qualified=False,
                    whole_runtime_replaced=False)
    try:
        for name, argv in recipes:
            raw, _ = recorder.run(name, argv, timeout=domain['process_budgets'][name])
            if name == 'compiler-version':
                version = raw.decode()
                require('\nrelease: 1.95.0\n' in version and '\nhost: x86_64-unknown-linux-gnu\n' in version,
                        'exact Rust 1.95.0 host compiler')
        require(source() == identity, 'frozen source remains unchanged')
        metadata.update(status='PASS', elapsed_seconds=time.monotonic() - started)
        seal(semantic, metadata)
        readers = Recorder(ROOT, output / 'reader-processes', env)
        readers.run('readonly-semantic', [python, '-B', str(ROOT / 'verify_readonly.py'),
                    '--output', str(output), '--source-manifest-sha256', identity], timeout=180)
        readers.run('reader-controls', [python, '-B', str(ROOT / 'reader_controls.py'),
                    '--output', str(output), '--source-manifest-sha256', identity], timeout=180)
        readers.run('readonly-complete', [python, '-B', str(ROOT / 'verify_readonly.py'),
                    '--output', str(output), '--source-manifest-sha256', identity,
                    '--require-controls'], timeout=180)
        result = dict(schema='hepta.audit-native-sync.gate.v1', status='COMPLETE_NATIVE_OS_BOUNDARY_PASS',
                      source_manifest_sha256=identity, actual_thread_tests=domain['actual_thread_tests'],
                      actual_calls=domain['calls'], contexts=domain['context_count'],
                      physical_refusals=domain['physical_refusals'], emitter_calls=7,
                      reader_refusals=8, relocated_admissions=2, post_refusal_admissions=2,
                      elapsed_seconds=time.monotonic() - started, native_os_boundary_only=True,
                      audit_queue_controller_qualified=False, public_handler_qualified=False,
                      whole_runtime_replaced=False)
        (output / 'GATE.json').write_bytes(encoded(result))
        print(encoded(result).decode(), end='')
    except BaseException as failure:
        metadata.update(status='FAIL', elapsed_seconds=time.monotonic() - started,
                        failure_type=type(failure).__name__, failure=str(failure))
        if not (semantic / 'CAPTURE.json').exists():
            seal(semantic, metadata)
        (output / 'GATE.json').write_bytes(encoded(dict(metadata, files_omitted_from_gate=True)))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-bin', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    run(args.hepta.resolve(strict=True), args.output.absolute(), args.rust_bin.resolve(strict=True),
        args.source_manifest_sha256)
