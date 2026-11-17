"""Fresh complete HIA lifetime build and paired actual-process qualification."""
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
    require(identity == expected_source, 'explicit complete fixed source identity')
    domain = loads(read(ROOT / 'DOMAIN.json'))
    output.mkdir(parents=True, exist_ok=False)
    semantic = output / 'semantic'
    semantic.mkdir()
    (semantic / 'threads').mkdir()
    env, env_receipt = environment(os.environ, rust_bin)
    env.update(HIA_LIFETIME_CALLABLE=str(semantic / 'lifetime-emission/callable/image.bin'),
               HIA_LIFETIME_REFS=str(semantic / 'lifetime-emission/refs/image.bin'),
               HIA_LIFETIME_SYNC=str(semantic / 'sync-emission/boundary.bin'))
    recorder = Recorder(ROOT, semantic / 'processes', env)
    python = str(Path(sys.executable).resolve(strict=True))
    started = time.monotonic()
    metadata = dict(schema='hepta.audit-lifetime.capture.v1', status='INCOMPLETE',
                    source_manifest_sha256=identity, domain=pin(read(ROOT / 'DOMAIN.json')),
                    source_root=str(ROOT), producer_root=str(semantic), python=python,
                    rust_bin=str(rust_bin), compiler_root=str(hepta), sync_source_root=str(sync_source),
                    rustc=pin(read(rust_bin / 'rustc')), rustfmt=pin(read(rust_bin / 'rustfmt')),
                    git_head=os.environ.get('GITHUB_SHA'), run_id=os.environ.get('GITHUB_RUN_ID'),
                    environment=env_receipt, scope=domain['scope'],
                    public_handler_qualified=False, whole_runtime_replaced=False)
    try:
        for name, argv in recipes(ROOT, semantic, python, rust_bin, hepta, sync_source, domain):
            if name in {'native-' + case.replace('_', '-') for case in domain['cases']}:
                case = argv[-1]
                require(case in domain['cases'], 'native case belongs to frozen domain')
                recorder.env['HIA_LIFETIME_JOURNAL'] = str(semantic / 'threads' / (case + '.jsonl'))
            raw, _ = recorder.run(name, argv, timeout=domain['process_budgets'][name])
            if name == 'compiler-version':
                require('\nrelease: 1.95.0\n' in raw.decode() and '\nhost: x86_64-unknown-linux-gnu\n' in raw.decode(),
                        'exact reference toolchain release and host')
        require(source() == identity, 'frozen source remains unchanged')
        metadata.update(status='PASS', elapsed_seconds=time.monotonic() - started)
        seal(semantic, metadata)
        readers = Recorder(ROOT, output / 'reader-processes', env)
        for name, script, extra in (
            ('readonly-semantic', 'verify_readonly.py', []),
            ('reader-controls', 'reader_controls.py', []),
            ('readonly-complete', 'verify_readonly.py', ['--require-controls']),
        ):
            readers.run(name, [python, '-I', '-B', ROOT / script, '--output', output,
                              '--source-manifest-sha256', identity, *extra], timeout=180)
        result = dict(schema='hepta.audit-lifetime.gate.v1', status='COMPLETE_PRIVATE_HIA_AUDIT_LIFETIME_PASS',
                      source_manifest_sha256=identity, paired_cases=len(domain['cases']),
                      actual_allocations=sum(domain['allocations_per_case'].values()),
                      reader_refusals=len(domain['reader_refusals']), relocated_admissions=2,
                      post_refusal_admissions=2, elapsed_seconds=time.monotonic() - started,
                      runtime_effect_pump_rust_required=False, scope=domain['scope'],
                      public_handler_qualified=False, whole_runtime_replaced=False)
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
