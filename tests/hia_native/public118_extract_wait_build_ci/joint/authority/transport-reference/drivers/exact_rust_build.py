"""Build an isolated fixture from the exact application's locked registry sources.

This helper executes only on an explicitly selected CI/build host. It does not
fetch dependencies: the host must provide a populated Cargo registry cache.
"""
from pathlib import Path
import hashlib, io, json, os, subprocess, tarfile, time, tomllib

sha = lambda raw: hashlib.sha256(raw).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


class Recorder:
    def __init__(self, root, directory, env=None):
        self.root = Path(root).resolve(strict=True)
        self.directory = self.root / directory
        self.directory.mkdir(parents=True, exist_ok=False)
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        if env:
            self.env.update(env)
        self.records = []

    def run(self, label, argv, *, cwd=None, stdin=None, timeout=180):
        assert label.replace('-', '').isalnum()
        assert all(row['label'] != label for row in self.records)
        cwd = self.root if cwd is None else Path(cwd)
        begin = time.monotonic()
        timed_out = False
        try:
            result = subprocess.run([str(x) for x in argv], cwd=cwd,
                env=self.env, input=stdin, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=timeout)
            out, err, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            out, err, code, timed_out = error.stdout or b'', error.stderr or b'', None, True
        (self.directory / (label + '.stdout')).write_bytes(out)
        (self.directory / (label + '.stderr')).write_bytes(err)
        self.records.append({'label': label, 'argv': [str(x) for x in argv],
            'cwd': str(cwd), 'exit_code': code, 'timed_out': timed_out,
            'timeout_seconds': timeout, 'elapsed_seconds': time.monotonic() - begin,
            'stdin_sha256': sha(stdin) if stdin is not None else None,
            'stdout_bytes': len(out), 'stdout_sha256': sha(out),
            'stderr_bytes': len(err), 'stderr_sha256': sha(err)})
        put(self.directory / 'processes.json', self.records)
        if code != 0 or timed_out:
            raise RuntimeError('recorded build/qualification command failed: ' + label)
        return out


def build_exact_oracle(root, project_relative, binary_name, rust_bin, *,
                       evidence_prefix='', target_relative='rust-build'):
    root = Path(root).resolve(strict=True)
    rust_bin = Path(rust_bin).resolve(strict=True)
    project = root / project_relative
    target = root / target_relative
    assert not target.exists(), 'a fresh Rust target directory is required'
    env = {'PATH': str(rust_bin) + os.pathsep + os.environ.get('PATH', ''),
           'RUSTC': str(rust_bin / 'rustc'), 'CARGO_TARGET_DIR': str(target)}
    rec = Recorder(root, 'evidence/' + evidence_prefix + 'rust-build-processes', env)
    version = rec.run('rustc-version', [rust_bin / 'rustc', '--version', '--verbose'])
    assert version.decode().splitlines()[0].startswith('rustc 1.95.0 ')
    rec.run('cargo-version', [rust_bin / 'cargo', '--version', '--verbose'])
    target_lock = (root / 'target/Cargo.lock').read_bytes()
    lock = project / 'Cargo.lock'
    assert not lock.exists(), 'the fixture lock must be derived afresh from the target seed'
    lock.write_bytes(target_lock)
    (rec.directory / 'lock-before-metadata.toml').write_bytes(target_lock)
    metadata_raw = rec.run('metadata-offline', [rust_bin / 'cargo', 'metadata',
        '--offline', '--format-version', '1'], cwd=project)
    metadata = json.loads(metadata_raw)
    lock_raw = lock.read_bytes()
    target_packages = {(p['name'], p['version'], p.get('source')): p.get('checksum')
        for p in tomllib.loads(target_lock.decode())['package'] if p.get('source')}
    retained = []
    for package in tomllib.loads(lock_raw.decode())['package']:
        if not package.get('source'):
            assert package['name'] == binary_name
            continue
        key = package['name'], package['version'], package['source']
        assert target_packages.get(key) == package['checksum'], key
        retained.append({k: package[k] for k in ('name', 'version', 'source', 'checksum')})
    source_receipts = []
    for package in metadata['packages']:
        if not package.get('source'):
            continue
        expected = target_packages[(package['name'], package['version'], package['source'])]
        crate = Path(package['manifest_path']).parent
        archive_path = crate.parent.parent.parent / 'cache' / crate.parent.name / (crate.name + '.crate')
        archived = archive_path.read_bytes()
        assert sha(archived) == expected, package['name']
        files = {}
        with tarfile.open(fileobj=io.BytesIO(archived), mode='r:gz') as archive:
            for member in archive.getmembers():
                parts = Path(member.name).parts
                assert parts and parts[0] == crate.name and '..' not in parts
                if member.isdir():
                    continue
                assert member.isfile(), (package['name'], member.name)
                relative = Path(*parts[1:])
                raw = archive.extractfile(member).read()
                assert (crate / relative).read_bytes() == raw, (package['name'], str(relative))
                files[str(relative)] = sha(raw)
        source_receipts.append({'name': package['name'], 'version': package['version'],
            'source': package['source'], 'checksum': expected, 'archive_sha256': sha(archived),
            'files_verified': len(files), 'source_files': files})
    subset = {'schema': 'hepta.target-lock-subset.source-rebuild.v1',
        'target_lock_sha256': sha(target_lock), 'fixture_lock_sha256': sha(lock_raw),
        'retained_registry_packages': retained, 'registry_source_verification': source_receipts,
        'all_retained_exactly_match_target': True, 'offline_resolution': True}
    put(root / ('evidence/' + evidence_prefix + 'target-lock-subset.json'), subset)
    assert not target.exists(), 'metadata unexpectedly created the target directory'
    rec.run('cargo-build-locked-offline', [rust_bin / 'cargo', 'build', '--locked', '--offline'], cwd=project)
    assert lock.read_bytes() == lock_raw
    binary = target / 'debug' / binary_name
    receipt = {'schema': 'hepta.actual-target-oracle.source-rebuild.v1',
        'rust_version': version.decode(), 'binary_sha256': sha(binary.read_bytes()),
        'binary_relative_path': str(binary.relative_to(root)),
        'source_sha256': sha((project / 'main.rs').read_bytes()),
        'project_files': {p.name: sha(p.read_bytes()) for p in sorted(project.iterdir()) if p.is_file()},
        'fixture_lock_sha256': sha(lock_raw), 'fresh_target_dir': True,
        'actual_target_sdk_built': True, 'actual_target_sdk_executed': False,
        'offline_resolution': True, 'all_retained_exactly_match_target': True}
    return binary, receipt, rec
