# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh actual HIA archive_stamp against unchanged Rust methods and full Namespace."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import traceback

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pins(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        if path.is_file():
            assert not path.is_symlink()
            raw = path.read_bytes();result[str(path.relative_to(directory))] = dict(bytes=len(raw), sha256=SHA(raw))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'runtime', 'hepta', 'rust-bin', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    root, runtime, rust = args.source.resolve(strict=True), args.runtime.resolve(strict=True), args.rust_bin.resolve(strict=True)
    out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    temporary = out / 'temporary';temporary.mkdir(mode=0o700)
    os.environ['TMPDIR'] = str(temporary)
    sys.path[:0] = [str(root / 'scripts'), str(runtime / 'scripts')]
    from hia_native_build import NativeBuild
    report = dict(schema='hepta.request-audit.fresh-archive-stamp.v1', status='FAIL', checks=[],
        whole_runtime_replaced=False, production_activated=False, old_stack_removal_qualified=False,
        result_storage_closed=False, audit_storage_closed=False, public_request_dispatch_qualified=False,
        temporary_directory=str(temporary), child_contracts_scripted=False, real_archive_executed=False,
        concurrent_cache_interleavings_qualified=False, native_language_unwind_qualified=False,
        shared_private_owner_gate=True, real_hot_filesystem_executed=True,
        standalone_native_process_qualified=False)
    save = lambda: (out / 'result.json').write_bytes(ENCODE(report))
    save();started = time.monotonic()
    env = dict(os.environ, PATH=str(rust) + ':' + os.environ.get('PATH', ''), RUSTC=str(rust / 'rustc'),
        RUSTDOC=str(rust / 'rustdoc'), PYTHONDONTWRITEBYTECODE='1', CARGO_TARGET_DIR=str(out / 'target'))

    def run(name, command, timeout=180):
        command = [str(value) for value in command];start = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        timed = False
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed = True;process.kill();stdout, stderr = process.communicate()
        (out / (name + '.stdout.log')).write_bytes(stdout);(out / (name + '.stderr.log')).write_bytes(stderr)
        row = dict(name=name, command=command, pid=process.pid, exit_code=process.returncode, reaped=True,
            timed_out=timed, timeout_seconds=timeout, elapsed_seconds=time.monotonic() - start,
            stdout_bytes=len(stdout), stdout_sha256=SHA(stdout), stderr_bytes=len(stderr), stderr_sha256=SHA(stderr))
        report['checks'].append(row);save();assert process.returncode == 0 and not timed, row
        return stdout

    try:
        report['source_files'] = pins(root)
        helpers = ('scripts/hia_native_build.py', 'scripts/hia_native_loader.py')
        report['runtime_helpers'] = {name: dict(bytes=len((runtime / name).read_bytes()), sha256=SHA((runtime / name).read_bytes())) for name in helpers}
        composition = json.loads((root / 'native/request_audit_stamp_composition.json').read_bytes())
        assert SHA((root / 'native/request_audit_stamp.hepta').read_bytes()) == composition['source_sha256']
        version = run('rust-version', [rust / 'rustc', '-vV'], 30)
        assert version.startswith(b'rustc 1.95.0 ') and b'release: 1.95.0\n' in version
        run('cargo-version', [rust / 'cargo', '--version'], 30)
        project = out / 'reference';shutil.copytree(root / 'reference-v1', project)
        reference = json.loads((root / 'reference-v1/reference-inputs.json').read_bytes())

        def verify_reference():
            for name, pin in reference['files'].items():
                raw = (project / name).read_bytes();assert (len(raw), SHA(raw)) == (pin['bytes'], pin['sha256'])
            for row in reference['original_blocks']:
                raw = (root / 'original' / row['source']).read_bytes();assert SHA(raw) == row['source_sha256']
                part = raw[row['offset']:row['offset'] + row['bytes']]
                target = (project / row['target']).read_bytes()
                assert SHA(part) == row['sha256'] and target[row['target_offset']:row['target_offset'] + row['bytes']] == part
        verify_reference()
        metadata = json.loads(run('cargo-metadata', [rust / 'cargo', 'metadata', '--manifest-path', project / 'Cargo.toml',
            '--format-version', '1', '--locked', '--offline'], 30))
        packages = [p for p in metadata['packages'] if p.get('source')]
        assert len(packages) == 22
        assert {(p['name'], p['version'], p['source']) for p in packages} == {
            (p['name'], p['version'], p['source']) for p in reference['original_registry_packages']}
        report['original_blocks'] = reference['original_blocks']
        assert len(report['original_blocks']) == 4
        report['registry_sources'] = {}
        for package in packages:
            location = Path(package['manifest_path']).parent
            expected = next(p for p in reference['original_registry_packages'] if
                p['name'] == package['name'] and p['version'] == package['version'])
            archive = location.parents[2] / 'cache' / location.parent.name / (location.name + '.crate')
            assert SHA(archive.read_bytes()) == expected['checksum']
            archived_files = set()
            with tarfile.open(archive) as package_archive:
                for member in package_archive:
                    if member.isdir():
                        continue
                    parts = Path(member.name).parts
                    assert member.isfile() and parts[0] == location.name and len(parts) > 1
                    assert not Path(member.name).is_absolute() and '..' not in parts
                    relative = '/'.join(parts[1:]);assert relative not in archived_files
                    archived_files.add(relative)
                    assert (location / relative).read_bytes() == package_archive.extractfile(member).read()
            actual_sources = pins(location)
            assert set(actual_sources) - archived_files <= {'.cargo-ok', '.cargo-checksum.json'}
            report['registry_sources'][package['name'] + '@' + package['version']] = {
                'package_checksum': expected['checksum'], 'archive_bytes': archive.stat().st_size,
                'verified_archive_members': len(archived_files), 'source_sha256': actual_sources}
        run('rustfmt-oracle', [rust / 'rustfmt', '--check', '--edition', '2021', '--config', 'hard_tabs=true,skip_children=true', project / 'oracle.rs'], 30)
        from build_audit_stamp import build_audit_stamp
        manifest = build_audit_stamp(root, runtime, args.hepta.resolve(strict=True), out / 'build')
        bundle = json.loads(manifest.read_bytes())
        from hepta.hia_agent_assembly import assemble_program
        import copy
        for composition_path in [root / 'native/request_audit_stamp_composition.json']:
            raw = composition_path.with_name(composition_path.name.replace('_composition.json', '.hepta')).read_bytes()
            composed = json.loads(composition_path.read_bytes());assert SHA(raw) == composed['source_sha256']
            functions = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
            for imported in composed['imports']:
                dependency = root / 'dependencies' / Path(imported['source']).name
                raw = dependency.read_bytes();assert SHA(raw) == imported['sha256']
                original = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
                relocation = imported['relocation']
                for old, new in relocation.items():
                    assert SHA(json.dumps(original[old], sort_keys=True, separators=(',', ':')).encode()) == imported['functions'][old]
                    expected = copy.deepcopy(original[old]);expected['name'] = new
                    for block in expected['blocks']:
                        for operation in block['ops']:
                            if operation['op'] == 'call':operation['attrs']['function'] = relocation[operation['attrs']['function']]
                    assert functions[new] == expected
        report['imported_functions_exact'] = True
        import ast
        a = ast.parse((root / 'dependencies/author_legacy_source.py').read_text())
        b = ast.parse((root / 'scripts/borrow_builder.py').read_text())
        a = next(n for n in ast.walk(a) if isinstance(n, ast.ClassDef) and n.name == 'BorrowBuilder')
        b = next(n for n in ast.walk(b) if isinstance(n, ast.ClassDef) and n.name == 'BorrowBuilder')
        assert ast.dump(a, include_attributes=False) == ast.dump(b, include_attributes=False)
        report['authoring_builder_class_exact'] = True
        report['native_bundle'] = dict(path=str(manifest.relative_to(out)), sha256=SHA(manifest.read_bytes()), **bundle)
        controls = json.loads(run('borrowed-receipt-controls', [sys.executable, '-I', '-B', root / 'scripts/test_audit_stamp_controls.py',
            '--manifest', manifest.parent / bundle['modules']['stamp']['manifest'], '--runtime', runtime,
            '--output', out / 'controls']))
        assert controls['status'] == 'PASS' and controls['checks'] == 41
        assert controls['rejection_controls'] == 38 and controls['synthetic_completion_controls'] == 3
        assert controls['original_executed'] is False and controls['real_filesystem_effects'] is False
        report['borrowed_receipt_controls'] = controls
        run('cargo-build', [rust / 'cargo', 'build', '--manifest-path', project / 'Cargo.toml', '--release',
            '--locked', '--offline', '--bin', 'hia-audit-stamp-reference'])
        executable = out / 'target/release/hia-audit-stamp-reference'
        assert executable.read_bytes().startswith(b'\x7fELF')
        report['original_executable'] = dict(path=str(executable.relative_to(out)), bytes=executable.stat().st_size,
            sha256=SHA(executable.read_bytes()))
        comparison = {}
        for name, extra in (('ordinary', []), ('kernel', ['--kernel'])):
            result = json.loads(run('actual-' + name + '-comparison', [sys.executable, '-I', '-B', root / 'scripts/test_audit_stamp.py',
                '--native', manifest.parent / bundle['executable'], '--original', executable,
                '--output', out / name, *extra]))
            assert result['status'] == 'PASS' and result['original_executed'] and result['full_wire_comparison']
            assert result['full_original_namespace_module'] and result['real_filesystem_effects']
            assert result['paired_processes'] == result['native_processes'] and result['paired_processes'] > 0
            comparison[name] = result
        assert comparison['ordinary']['paired_processes'] == 36 and comparison['ordinary']['requests_per_side'] == 117
        report['standalone_native_process_qualified'] = True
        verify_reference();assert pins(root) == report['source_files']
        assert {name: dict(bytes=len((runtime / name).read_bytes()), sha256=SHA((runtime / name).read_bytes())) for name in helpers} == report['runtime_helpers']
        for package in packages:
            assert pins(Path(package['manifest_path']).parent) == report['registry_sources'][
                package['name'] + '@' + package['version']]['source_sha256']
        report.update(status='PASS', comparison=comparison, original_sources_unchanged=True,
            source_unchanged=True, registry_sources_unchanged=True, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report['error'] = repr(error);(out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:
        save()
    print(json.dumps({key: report[key] for key in ('schema', 'status', 'comparison', 'elapsed_seconds',
        'source_unchanged', 'original_sources_unchanged', 'registry_sources_unchanged', 'result_storage_closed',
        'audit_storage_closed', 'whole_runtime_replaced', 'production_activated', 'old_stack_removal_qualified')}, sort_keys=True))


if __name__ == '__main__':
    main()
