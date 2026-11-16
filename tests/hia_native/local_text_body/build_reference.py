"""Fresh locked target-Rust build for the isolated Local body reference."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_reference


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--support', type=Path, required=True)
    parser.add_argument('--toolchain', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    output = args.output.resolve(); output.mkdir(exist_ok=False)
    sys.path.insert(0, str(args.support.resolve() / 'scripts'))
    import hia_native_local_create_async_qualification as controls
    import hia_native_local_create_qualification as base
    rustc = (args.toolchain / 'rustc').resolve(strict=True)
    cargo = (args.toolchain / 'cargo').resolve(strict=True)
    environment, binding = controls.reference_environment(os.environ, rustc)
    before = {'rustc': base.compiler_identity(rustc), 'cargo': base.compiler_identity(cargo)}
    verified = verify_reference.verify(source)
    project = output / 'source'; project.mkdir()
    for relative in verified['files']:
        member=Path(relative).relative_to('reference')
        destination=project/member; destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes((source/relative).read_bytes())
    target = output / 'target'
    assert not target.exists()
    config = ['--config', 'build.rustc=' + json.dumps(str(rustc))]
    commands = {
        'body-rust-version': [str(rustc), '--version', '--verbose'],
        'body-cargo-version': [str(cargo), '--version'],
        'body-cargo-metadata': [str(cargo), *config, 'metadata', '--locked', '--format-version=1',
            '--filter-platform', 'x86_64-unknown-linux-gnu', '--manifest-path', str(project / 'Cargo.toml')],
        'body-rust-build': [str(cargo), *config, 'build', '--locked', '--release', '--target',
            'x86_64-unknown-linux-gnu', '--manifest-path', str(project / 'Cargo.toml'), '--target-dir', str(target)],
    }
    report = dict(schema='hepta.runtime.local-text-body-reference-development.v1', status='BUILDING',
        source_verification=verified, compiler_before=before, environment_binding=binding,
        support_files={name: pin((args.support / 'scripts' / name).read_bytes()) for name in (
            'hia_native_local_create_async_qualification.py', 'hia_native_local_create_qualification.py')},
        fresh_target_directory=True, processes=[], public_handler_qualified=False,
        native_comparison_performed=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)
    began = time.monotonic()
    def save():
        (output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    save()
    try:
        for name, command in commands.items():
            started = time.monotonic()
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=environment,start_new_session=True)
            timed_out = False
            try:
                try: stdout, stderr = child.communicate(timeout=180)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    try: os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                    stdout, stderr = child.communicate(timeout=10)
            finally:
                if child.poll() is None:
                    try: os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait(timeout=10)
            for label, raw in (('stdout', stdout), ('stderr', stderr)):
                (output / (name + '.' + label)).write_bytes(raw)
            report['processes'].append(dict(name=name, command=command, deadline_seconds=180,
                exit_code=child.returncode, timed_out=timed_out, elapsed_seconds=time.monotonic() - started,
                pid=child.pid,process_group=child.pid,process_reaped=child.poll() is not None,
                stdout=pin(stdout), stderr=pin(stderr), environment_binding=binding))
            save()
            assert not timed_out and child.returncode == 0, (name, stderr.decode('utf-8', 'replace'))
            print(json.dumps(dict(name=name, status='PASS', elapsed_seconds=report['processes'][-1]['elapsed_seconds'])), flush=True)
        metadata = json.loads((output / 'body-cargo-metadata.stdout').read_bytes())
        packages = {package['id']: package for package in metadata['packages']}
        assert len(packages) == len(metadata['packages']) == 5
        features = {packages[node['id']]['name']: node['features'] for node in metadata['resolve']['nodes']}
        assert features == {'anyhow': ['default', 'std'], 'bytes': ['default', 'std'], 'pin-project-lite': [],
            'tokio': ['bytes', 'default', 'fs', 'io-util', 'rt', 'sync'], 'hepta-local-text-body-original-oracle': []}
        binary = target / 'x86_64-unknown-linux-gnu/release/hepta-local-text-body-original-oracle'
        report['executable'] = dict(path=str(binary), **pin(binary.read_bytes()))
        report['compiler_after'] = {'rustc': base.compiler_identity(rustc), 'cargo': base.compiler_identity(cargo)}
        assert report['compiler_after'] == before and verify_reference.verify(source) == verified
        assert all(pin((project / name.removeprefix('reference/')).read_bytes()) == {
            key: identity[key] for key in ('bytes', 'sha256')}
            for name, identity in verified['files'].items())
        report.update(status='FRESH_LOCAL_TEXT_BODY_REFERENCE_BUILD_PASS', source_unchanged=True,
                      features=features, fresh_locked_builds=1)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - began; save()
    print(json.dumps({key: report[key] for key in ('status', 'executable', 'elapsed_seconds',
        'public_handler_qualified', 'native_comparison_performed')}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
