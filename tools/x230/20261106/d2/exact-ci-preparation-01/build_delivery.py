#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Package already sealed CI bytes; never install or execute a target tool."""
import argparse
import ast
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
from build_templates import ROOT, identity, encode, replace_assignments, namespace

HERE = Path(__file__).resolve().parent
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sealed', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.sealed.resolve(strict=True)
    seal = json.loads((source / 'seal-manifest.json').read_bytes())
    assert seal['schema'] == 'hepta-d2-exact-rust-ci-sealed-delivery/v1'
    assert seal['status'] == 'sealed_not_executed' and seal['ci_executed'] is False
    assert seal['root'] == ROOT and seal['compiler_input_count'] == 222
    files = {}
    for path in sorted((source / 'tools').iterdir()):
        assert path.is_file() and not path.is_symlink()
        raw = path.read_bytes()
        assert identity(raw) == seal['files'][path.name]
        files['rust-ci-tools-01/' + path.name] = raw
    assert len(files) == 6
    additional = {
        'full-prerequisites-01/d2_prerequisites.py': 'prerequisites/d2_prerequisites.py',
        'qualification-prerequisites-01.json': 'qualification-prerequisites-01.json',
        'rust-ci-actual-pins-01.json': 'actual-pins.json',
        'rust-ci-seal-manifest-01.json': 'seal-manifest.json',
        'rust-ci-launch-command-01.json': 'launch-command.json'}
    for target, local in additional.items():
        files[target] = (source / local).read_bytes()
    assert identity(files['full-prerequisites-01/d2_prerequisites.py']) == {
        key: seal['foundation'][key] for key in ('bytes', 'sha256')}
    assert identity(files['qualification-prerequisites-01.json']) == {
        key: seal['qualification_prerequisites'][key] for key in ('bytes', 'sha256')}
    manifest = {'schema': 'hepta-d2-exact-ci-deployment/v1', 'root': ROOT,
        'file_count_excluding_manifest': len(files),
        'files': [dict(path=name, **identity(raw)) for name, raw in sorted(files.items())],
        'ci_executed': False, 'performance_acceptance_claim': False}
    manifest_raw = encode(manifest)
    files['rust-ci-deployment-manifest-01.json'] = manifest_raw
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            row = tarfile.TarInfo(name)
            row.size, row.mode, row.uid, row.gid, row.mtime = len(raw), 0o600, 0, 0, 0
            row.uname = row.gname = ''
            archive.addfile(row, io.BytesIO(raw))
    tar_raw = tar_buffer.getvalue()
    assert len(tar_raw) <= 1024 * 1024
    compressed = io.BytesIO()
    with gzip.GzipFile(filename='', fileobj=compressed, mode='wb', mtime=0) as stream:
        stream.write(tar_raw)
    archive_raw = compressed.getvalue()
    reference = (HERE / 'references-d1/install_exact_ci.py').read_bytes()
    # Exact source identity is checked against its original Git blob.
    assert hashlib.sha1(b'blob ' + str(len(reference)).encode() + b'\0' + reference).hexdigest() == 'cb3e156d418d3ccd26d86642cc79fb24fd225b70'
    installer = namespace(reference.decode()).replace('rust-ci-prerequisites-01', 'full-prerequisites-01')
    installer = replace_assignments(installer, {'ARCHIVE_BYTES': repr(len(archive_raw)),
        'ARCHIVE_SHA256': repr(identity(archive_raw)['sha256']),
        'MANIFEST_SHA256': repr(identity(manifest_raw)['sha256'])})
    assert installer.count('total == 136003') == 1
    installer = installer.replace('total == 136003', 'total == ' + str(sum(map(len, files.values()))))
    ast.parse(installer)
    outputs = {'deployment.tar.gz': archive_raw, 'deployment.tar.gz.base64': base64.b64encode(archive_raw),
               'deployment-manifest.json': manifest_raw, 'install_exact_ci.py': installer.encode()}
    outputs['archive-identity.json'] = encode({'schema': 'hepta-d2-exact-ci-transport/v1',
        'files': {name: identity(raw) for name, raw in outputs.items()},
        'base64_has_terminal_newline': False, 'expanded_tar_bytes': len(tar_raw),
        'member_count': len(files), 'selected_bytes': sum(map(len, files.values())),
        'installer_executed': False, 'ci_executed': False})
    assert not os.path.lexists(args.output)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in outputs.items():
        with (args.output / name).open('xb') as stream:
            stream.write(raw)
    print(json.dumps({'output': str(args.output), 'archive': identity(archive_raw),
                      'members': len(files), 'installer_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
