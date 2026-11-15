#!/usr/bin/env python3
"""Restore frozen archive bytes and their identical embedded outer manifests.

The transport may use bounded binary_read chunks instead of prewritten base64
pieces. Every chunk and final file is checked against frozen identities. No
original JSON is parsed and rewritten to reconstruct an external manifest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile

from package_x230_evidence import directory_fd, source_file, identity, need, encoded, verify, parts
from publication_transfer import hashes, write_new


def publish_bytes(target, raw, expected):
    target = Path(target)
    actual = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
              'git_blob_sha1': hashlib.sha1(f'blob {len(raw)}\0'.encode() + raw, usedforsecurity=False).hexdigest()}
    need(actual == {k: expected[k] for k in actual}, 'restored original bytes differ from frozen remote index')
    if target.exists() or target.is_symlink():
        need(hashes(target) == actual, 'existing staged file differs')
    else:
        write_new(target, raw)
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', required=True)
    parser.add_argument('--state', required=True)
    parser.add_argument('--stage-root', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    index_raw, state_raw = Path(args.index).read_bytes(), Path(args.state).read_bytes()
    index_rows = json.loads(index_raw)['files']
    for entry in index_rows:
        parts(entry['repo_path'])
    need(len({e['repo_path'] for e in index_rows}) == len(index_rows), 'duplicate indexed repo path')
    index = {e['repo_path']: e for e in index_rows}
    state = json.loads(state_raw)
    need(state['all_file_bytes_received'], 'binary stream is incomplete')
    need(len({e['repo_path'] for e in state['files']}) == len(state['files']), 'duplicate binary archive path')
    stage = Path(args.stage_root).absolute()
    receipt = {'schema': 'hepta-publication-binary-restore/v1',
               'index_sha256': hashlib.sha256(index_raw).hexdigest(),
               'state_sha256': hashlib.sha256(state_raw).hexdigest(), 'files': [],
               'original_json_bytes_rewritten': False}
    for file in state['files']:
        parts(file['repo_path'])
        expected = index[file['repo_path']]
        need(file['repo_path'].endswith('.tar.gz') and file['position'] == expected['bytes'], 'unexpected archive or length')
        target = stage / file['repo_path']
        need(target.is_relative_to(stage), 'archive destination is outside stage')
        with directory_fd(str(target.parent), create=True):
            pass
        fd, temporary = tempfile.mkstemp(prefix='.binary-restore-', dir=target.parent)
        try:
            offset = 0
            with os.fdopen(fd, 'wb') as output:
                for chunk in file['chunks']:
                    need(chunk['offset'] == offset and chunk['next_offset'] - offset == chunk['bytes'], 'binary chunk ordering differs')
                    path = Path(chunk['local_path']).absolute()
                    with source_file(str(path.parent), path.name) as (stream, before):
                        raw = stream.read(65537)
                        need(len(raw) == chunk['bytes'] <= 65536 and hashlib.sha256(raw).hexdigest() == chunk['sha256'], 'binary chunk bytes changed')
                        need(before == identity(os.fstat(stream.fileno())), 'binary chunk mutated while reading')
                        output.write(raw)
                    offset = chunk['next_offset']
                output.flush()
                os.fsync(output.fileno())
            actual = hashes(temporary)
            need(offset == expected['bytes'] and actual == {k: expected[k] for k in actual}, 'whole archive identity differs')
            if target.exists() or target.is_symlink():
                need(hashes(target) == actual, 'existing staged archive differs')
            else:
                os.link(temporary, target, follow_symlinks=False)
            Path(temporary).unlink()
        finally:
            Path(temporary).unlink(missing_ok=True)
        receipt['files'].append({'repo_path': file['repo_path'], 'restored_from': 'version-pinned binary_read chunks',
                                 'version': file['version'], 'chunks': len(file['chunks']), **actual})
        manifest_repo = file['repo_path'][:-7] + '.manifest.json'
        manifest_expected = index[manifest_repo]
        with tarfile.open(target, 'r|gz') as archive:
            member = archive.next()
            need(member is not None and member.isreg() and member.name.startswith('_publication/') and member.name.endswith('/manifest.json'), 'first tar member is not the original manifest')
            need(member.size == manifest_expected['bytes'] <= 32 * 1024 * 1024, 'embedded manifest size differs')
            raw = archive.extractfile(member).read(member.size + 1)
            member_path = member.name
        manifest_target = stage / manifest_repo
        manifest_actual = publish_bytes(manifest_target, raw, manifest_expected)
        checked = verify(target, manifest_target)
        need(checked['archive_sha256'] == expected['sha256'] and checked['archive_bytes'] == expected['bytes']
             and checked['manifest_sha256'] == manifest_expected['sha256'], 'published archive/manifest changed after restoration')
        receipt['files'].append({'repo_path': manifest_repo, 'restored_from': 'byte-identical first tar member',
                                 'archive_repo_path': file['repo_path'], 'archive_sha256': actual['sha256'],
                                 'member': member_path, 'archive_member_verification': checked, **manifest_actual})
    receipt['passed'] = True
    write_new(args.output, encoded(receipt))
    print(json.dumps({'receipt': str(args.output), 'files': len(receipt['files']), **hashes(args.output)}, sort_keys=True))


if __name__ == '__main__':
    main()
