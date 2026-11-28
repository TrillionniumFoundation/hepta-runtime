"""Fresh CI-only native/reference execution and fixed inert-reader qualification."""
from pathlib import Path
import argparse
import json
import os
import shutil
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from common import encoded, files, loads, pin, read, require, seal, source
from domain import cases, domain, stdin_bytes
from process import Recorder, environment


def run(hepta, output, rust, expected):
    identity = source()
    require(identity == expected, 'explicit frozen audit codec source identity')
    specification = domain()
    output.mkdir(parents=True, exist_ok=False)
    semantic = output / 'semantic'
    semantic.mkdir()
    shutil.copytree(ROOT, semantic / 'source')
    shutil.copytree(ROOT / 'reference', semantic / 'reference')
    temporary = output.parent / (output.name+'-build-temporary')
    temporary.mkdir()
    env, environment_receipt = environment(os.environ, rust, temporary / 'target')
    env['CARGO_HOME'] = str(temporary / 'cargo-home')
    recorder = Recorder(ROOT, semantic / 'processes', env)
    python = str(Path(sys.executable).resolve(strict=True))
    budget = specification['process_budgets']
    started = time.monotonic()
    metadata = dict(schema='hepta.audit-json.capture.v1', status='INCOMPLETE', source_manifest_sha256=identity,
        source_root=str(ROOT), producer_root=str(semantic), build_temporary=str(temporary), python=python,
        rust_bin=str(rust), compiler_root=str(hepta), git_head=os.environ.get('GITHUB_SHA'),
        run_id=os.environ.get('GITHUB_RUN_ID'), environment=environment_receipt,
        rustc=pin(read(rust / 'rustc')), cargo=pin(read(rust / 'cargo')), rustfmt=pin(read(rust / 'rustfmt')),
        scope='private actual audit Record/ArchiveAnchor JSON codec',
        public_handler_qualified=False, whole_runtime_replaced=False)
    commands = []
    def command(name, argv, *, stdin=None, cwd=ROOT):
        commands.append(dict(name=name, argv=[str(value) for value in argv], cwd=str(cwd), timeout=budget[name]))
        return recorder.run(name, argv, cwd=cwd, stdin=stdin, timeout=budget[name])[0]
    try:
        command('format', [rust/'rustfmt', '--check', '--edition', '2021', '--config', 'hard_tabs=true,max_width=100',
                           ROOT/'reference/oracle.rs', ROOT/'reference/original_types.rs'])
        version = command('toolchain', [rust/'rustc', '--version', '--verbose'])
        require(b'\nrelease: 1.95.0\n' in version and b'\nhost: x86_64-unknown-linux-gnu\n' in version,
                'exact original test toolchain release and target')
        command('cargo-version', [rust/'cargo', '--version', '--verbose'])
        command('native-build', [python, '-I', '-B', ROOT/'build_native.py', '--hepta', hepta, '--output', semantic/'build'])
        reference = semantic/'reference'
        command('rust-fetch', [rust/'cargo', 'fetch', '--locked', '--manifest-path', reference/'Cargo.toml'], cwd=reference)
        command('rust-vendor', [rust/'cargo', 'vendor', '--locked', '--offline', '--versioned-dirs',
                '--manifest-path', reference/'Cargo.toml', semantic/'vendor'], cwd=reference)
        packages = [value for value in tomllib.loads(read(reference/'Cargo.lock').decode())['package'] if 'source' in value]
        crate_root = semantic/'crates'
        crate_root.mkdir()
        for package in packages:
            archive = package['name']+'-'+package['version']+'.crate'
            matches = list((temporary/'cargo-home/registry/cache').glob('*/'+archive))
            require(len(matches) == 1, 'exact fetched crate archive')
            raw = read(matches[0])
            require(pin(raw)['sha256'] == package['checksum'], 'locked exact crate archive checksum')
            (crate_root/archive).write_bytes(raw)
        config = ['--config', 'source.crates-io.replace-with="fixed-vendor"', '--config',
                  'source.fixed-vendor.directory='+json.dumps(str(semantic/'vendor'))]
        command('rust-build', [rust/'cargo', 'build', '--frozen', '--verbose', '--target', 'x86_64-unknown-linux-gnu',
                              '--manifest-path', reference/'Cargo.toml', *config], cwd=reference)
        binary = temporary/'target/x86_64-unknown-linux-gnu/debug/hia-audit-json-reference'
        require(read(binary).startswith(b'\x7fELF'), 'actual original compiled ELF')
        shutil.copy2(binary, semantic/'original')
        concrete = cases()
        data = stdin_bytes(concrete)
        original = command('original', [semantic/'original'], stdin=data)
        actual = command('native', [python, '-I', '-B', ROOT/'native_process.py', '--manifest',
            semantic/'build/modules/audit-json/manifest.json', '--output', semantic/'native'], stdin=data)
        require(original == actual, 'complete actual original and HIA process stdout equality')
        require(source() == identity and files(ROOT) == files(semantic/'source'), 'complete frozen source unchanged')
        metadata.update(status='PASS', cases=len(concrete), original_binary=pin(read(semantic/'original')),
                        commands=commands, elapsed_seconds=time.monotonic()-started)
        seal(semantic, metadata)
        readers = Recorder(ROOT, output/'reader-processes', env)
        for name, script, extra in (
            ('readonly_semantic', 'verify_readonly.py', []),
            ('reader_controls', 'reader_controls.py', []),
            ('readonly_complete', 'verify_readonly.py', ['--require-controls']),
        ):
            raw, row = readers.run(name.replace('_','-'), [python, '-I', '-B', ROOT/script,
                '--output', output, '--source-manifest-sha256', identity, *extra], timeout=budget[name])
        result = dict(schema='hepta.audit-json.gate.v1', status='COMPLETE_PRIVATE_HIA_AUDIT_JSON_PASS',
            source_manifest_sha256=identity, actual_original_cases=len(concrete), actual_hia_calls=len(concrete),
            original_binary=metadata['original_binary'], elapsed_seconds=time.monotonic()-started,
            runtime_rust_required=False, runtime_python_required=False,
            public_handler_qualified=False, whole_runtime_replaced=False)
        (output/'GATE.json').write_bytes(encoded(result))
        print(encoded(result).decode(), end='')
    except BaseException as failure:
        metadata.update(status='FAIL', failure_type=type(failure).__name__, failure=str(failure),
                        commands=commands, elapsed_seconds=time.monotonic()-started)
        if not (semantic/'CAPTURE.json').exists():
            seal(semantic, metadata)
        (output/'GATE.json').write_bytes(encoded(metadata))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('hepta','output','rust-bin'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    run(args.hepta.resolve(strict=True), args.output.absolute(), args.rust_bin.resolve(strict=True),
        args.source_manifest_sha256)
