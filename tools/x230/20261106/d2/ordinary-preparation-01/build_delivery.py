#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Package a locally sealed D2 ordinary launch; never install or execute it."""
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

HERE = Path(__file__).resolve().parent
ROOT = '/home/qian/hepta-runtime-validation-cost-20261106-d2'


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def replace_assignments(text, replacements):
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    spans, seen = [], set()
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in replacements:
                assert name not in seen
                seen.add(name)
                spans.append((offsets[node.lineno - 1] + node.col_offset,
                              offsets[node.end_lineno - 1] + node.end_col_offset,
                              name + ' = ' + replacements[name]))
    assert seen == set(replacements)
    for start, end, replacement in sorted(spans, reverse=True):
        text = text[:start] + replacement + text[end:]
    ast.parse(text)
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sealed', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.sealed.resolve(strict=True)
    seal = json.loads((source / 'seal-manifest.json').read_bytes())
    assert seal['schema'] == 'hepta-d2-ordinary-input-seal/v1' and seal['purpose'] == 'launch'
    assert seal['ordinary_executed_by_sealer'] is False
    mapping = {
        'tools/launch_ordinary_01.py': 'ordinary-tools-01/launch_ordinary_01.py',
        'tools/qualify_ordinary_01.py': 'ordinary-tools-01/qualify_ordinary_01.py',
        'tools/verify_ordinary_01.py': 'ordinary-tools-01/verify_ordinary_01.py',
        'tools/package-manifest-01.json': 'ordinary-tools-01/package-manifest-01.json',
        'ordinary-prerequisites-01.json': 'ordinary-prerequisites-01.json',
        'actual-seal-request.json': 'ordinary-seal-request-01.json',
        'seal-manifest.json': 'ordinary-seal-manifest-01.json',
        'launch-command.json': 'ordinary-launch-command-01.json'}
    files = {}
    for local, target in mapping.items():
        raw = (source / local).read_bytes()
        if local != 'seal-manifest.json':
            assert identity(raw) == seal['files'][local]
        if local.endswith('.py'):
            ast.parse(raw)
        files[target] = raw
    assert len(files) == 8
    manifest = {'schema': 'hepta-d2-ordinary-deployment/v1', 'root': ROOT,
        'file_count_excluding_manifest': len(files),
        'files': [dict(path=name, **identity(raw)) for name, raw in sorted(files.items())],
        'ordinary_executed': False, 'compiler_started': False, 'performance_acceptance_claim': False}
    manifest_raw = encode(manifest)
    files['ordinary-deployment-manifest-01.json'] = manifest_raw
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, raw in sorted(files.items()):
            row = tarfile.TarInfo(name)
            row.size, row.mode, row.uid, row.gid, row.mtime = len(raw), 0o600, 0, 0, 0
            row.uname = row.gname = ''
            tar.addfile(row, io.BytesIO(raw))
    expanded = plain.getvalue()
    assert len(expanded) <= 1024 * 1024
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode='wb', mtime=0, filename='') as stream:
        stream.write(expanded)
    archive_raw = compressed.getvalue()
    reference = (HERE / 'references/install_ordinary.py').read_bytes()
    assert hashlib.sha1(b'blob ' + str(len(reference)).encode() + b'\0' + reference).hexdigest() == 'f3a1de7ee1a0888029fa953a96b55f8afa4919c8'
    installer = reference.decode().replace('/home/qian/hepta-runtime-phase-cost-20261106-d1', ROOT)
    installer = installer.replace('hepta-d1-ordinary-', 'hepta-d2-ordinary-').replace('D1 root', 'D2 root')
    for schema in ('deployment', 'installation-claim', 'create-only-install'):
        installer = installer.replace('hepta-d2-ordinary-' + schema + '/v2', 'hepta-d2-ordinary-' + schema + '/v1')
    installer = replace_assignments(installer, {'ARCHIVE_BYTES': repr(len(archive_raw)),
        'ARCHIVE_SHA256': repr(identity(archive_raw)['sha256']),
        'MANIFEST_SHA256': repr(identity(manifest_raw)['sha256'])})
    assert installer.count('total == 51281') == 1
    installer = installer.replace('total == 51281', 'total == ' + str(sum(map(len, files.values()))))
    ast.parse(installer)
    outputs = {'deployment.tar.gz': archive_raw, 'deployment.tar.gz.base64': base64.b64encode(archive_raw),
               'deployment-manifest.json': manifest_raw, 'install_ordinary.py': installer.encode()}
    outputs['archive-identity.json'] = encode({'schema': 'hepta-d2-ordinary-deployment-archive/v1',
        'files': {name: identity(raw) for name, raw in outputs.items()},
        'expanded_tar_bytes': len(expanded), 'member_count': len(files),
        'member_bytes': sum(map(len, files.values())), 'base64_has_terminal_newline': False,
        'installer_executed': False, 'ordinary_executed': False, 'compiler_started': False})
    assert not os.path.lexists(args.output)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in outputs.items():
        with (args.output / name).open('xb') as stream:
            stream.write(raw)
    print(json.dumps({'output': str(args.output), 'archive': identity(archive_raw),
                      'members': len(files), 'installer_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
