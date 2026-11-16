"""Fresh composed HIA controller and unchanged original actual-thread gate."""
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
from recipes import recipes


def run(hepta, sync_source, output, rust_bin, expected_source):
    identity = source()
    require(identity == expected_source, 'explicit frozen source identity')
    domain = loads(read(ROOT / 'DOMAIN.json'))
    output.mkdir(parents=True, exist_ok=False)
    semantic = output / 'semantic'
    semantic.mkdir()
    threads = semantic / 'threads'
    threads.mkdir()
    env, env_receipt = environment(os.environ, rust_bin)
    env.update(HIA_AUDIT_CALLABLE_IMAGE=str(semantic / 'callable-emission/callable.bin'),
               HIA_AUDIT_CONTROLLER_IMAGE=str(semantic / 'build/modules/audit-store-controller/module.image.bin'),
               HIA_AUDIT_SYNC_IMAGE=str(semantic / 'emission/boundary.bin'),
               HIA_AUDIT_CONTROLLER_JOURNAL=str(threads / 'journal.jsonl'),
               HIA_AUDIT_ORIGINAL_OBSERVATIONS=str(threads / 'original-observations.jsonl'))
    recorder = Recorder(ROOT, semantic / 'processes', env)
    python = str(Path(sys.executable).resolve(strict=True))
    started = time.monotonic()
    metadata = dict(schema='hepta.audit-store-controller.capture.v1', status='INCOMPLETE',
                    source_manifest_sha256=identity, domain=pin(read(ROOT / 'DOMAIN.json')),
                    source_root=str(ROOT), producer_root=str(semantic), python=python,
                    rust_bin=str(rust_bin), compiler_root=str(hepta), sync_source_root=str(sync_source),
                    rustc=pin(read(rust_bin / 'rustc')), rustfmt=pin(read(rust_bin / 'rustfmt')),
                    git_head=os.environ.get('GITHUB_SHA'), run_id=os.environ.get('GITHUB_RUN_ID'),
                    environment=env_receipt, scope=domain['scope'],
                    public_handler_qualified=False, whole_runtime_replaced=False)
    try:
        for name, argv in recipes(ROOT, semantic, python, rust_bin, hepta, sync_source, domain):
            raw, _ = recorder.run(name, argv, timeout=domain['process_budgets'][name])
            if name == 'compiler-version':
                version = raw.decode()
                require('\nrelease: 1.95.0\n' in version and '\nhost: x86_64-unknown-linux-gnu\n' in version,
                        'exact Rust 1.95.0 host compiler')
        require(source() == identity, 'frozen source remains unchanged')
        metadata.update(status='PASS', elapsed_seconds=time.monotonic() - started)
        seal(semantic, metadata)
        readers = Recorder(ROOT, output / 'reader-processes', env)
        for name, script, extra in (
            ('readonly-semantic', 'verify_readonly.py', []),
            ('reader-controls', 'reader_controls.py', []),
            ('readonly-complete', 'verify_readonly.py', ['--require-controls']),
        ):
            readers.run(name, [python, '-B', str(ROOT / script), '--output', str(output),
                        '--source-manifest-sha256', identity, *extra], timeout=180)
        result = dict(schema='hepta.audit-store-controller.gate.v1',
                      status='COMPLETE_HIA_NATIVE_AUDIT_CALLABLE_PASS',
                      source_manifest_sha256=identity, original_tests=len(domain['original_cases']),
                      native_tests=len(domain['native_cases']), contexts=domain['context_count'],
                      actors=domain['actor_count'], api_completions=domain['api_completions'],
                      observer_free_calls=15, observer_free_refusals=9, runtime_effect_pump_rust_required=False,
                      reader_refusals=len(domain['reader_refusals']), relocated_admissions=2,
                      post_refusal_admissions=2, elapsed_seconds=time.monotonic() - started,
                      scope=domain['scope'], public_handler_qualified=False, whole_runtime_replaced=False)
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
    parser.add_argument('--sync-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-bin', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    run(args.hepta.resolve(strict=True), args.sync_source.resolve(strict=True), args.output.absolute(),
        args.rust_bin.resolve(strict=True), args.source_manifest_sha256)
