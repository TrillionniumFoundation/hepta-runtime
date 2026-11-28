"""Create an immutable local Git/source checkpoint without changing main/index."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--repository', type=Path, required=True)
    p.add_argument('--parent', required=True)
    p.add_argument('--prefix', required=True)
    p.add_argument('--branch', required=True)
    p.add_argument('--author', type=Path, action='append', default=[])
    a = p.parse_args()
    source = a.source.resolve(strict=True)
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    repo = a.repository.resolve(strict=True)
    payload = {'source/' + path.relative_to(source).as_posix(): path.read_bytes()
               for path in sorted(source.rglob('*')) if path.is_file()}
    for author in a.author:
        payload['authoring/' + author.name] = author.read_bytes()
    rows = []
    for name, data in sorted(payload.items()):
        rows.append({'path': name, 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()})
    manifest = {'schema': 'hepta.runtime.host-pump.source-checkpoint.v2',
        'runtime_execution_at_source_freeze': False, 'fresh_ci_qualified': False,
        'full_async_qualified': False, 'full_sdk_qualified': False,
        'files': rows, 'file_count': len(rows), 'total_bytes': sum(x['bytes'] for x in rows)}
    encoded = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    (out / 'SOURCE_MANIFEST.json').write_bytes(encoded)
    payload['SOURCE_MANIFEST.json'] = encoded
    with tarfile.open(out / 'source.tar.gz', 'w:gz', format=tarfile.PAX_FORMAT) as t:
        for name, data in sorted(payload.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            member.mtime = 0
            t.addfile(member, io.BytesIO(data))
    with tarfile.open(out / 'source.tar.gz', 'r:gz') as t:
        assert len(t.getmembers()) == len(payload)
        for member in t:
            assert member.isfile() and t.extractfile(member).read() == payload[member.name]

    def git(*args, data=None, env=None):
        result = subprocess.run(['git', *args], cwd=repo, input=data,
                                capture_output=True, env=env, check=True)
        return result.stdout.decode().strip()

    fd, index = tempfile.mkstemp(prefix='hia-pump-source-index-', dir='/tmp')
    os.close(fd)
    os.unlink(index)
    env = dict(os.environ, GIT_INDEX_FILE=index)
    try:
        git('read-tree', a.parent, env=env)
        installed = []
        for path, data in sorted(payload.items()):
            blob = git('hash-object', '-w', '--stdin', data=data)
            if subprocess.run(['git', 'cat-file', 'blob', blob], cwd=repo,
                              capture_output=True, check=True).stdout != data:
                raise ValueError(('Git readback differs', path))
            target = a.prefix + '/' + path
            git('update-index', '--add', '--cacheinfo', '100644,' + blob + ',' + target, env=env)
            installed.append({'path': target, 'git_blob': blob,
                              'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        tree = git('write-tree', env=env)
        commit = git('commit-tree', tree, '-p', a.parent,
                     '-m', 'Freeze task pump observation source before native execution')
        git('update-ref', 'refs/heads/' + a.branch, commit, '')
    finally:
        if Path(index).exists():
            Path(index).unlink()
    receipt = {'commit': commit, 'tree': tree, 'parent': a.parent,
        'branch': a.branch, 'prefix': a.prefix, 'remote_published': False,
        'source_manifest_sha256': hashlib.sha256(encoded).hexdigest(),
        'archive_sha256': hashlib.sha256((out / 'source.tar.gz').read_bytes()).hexdigest(),
        'published_rows': installed}
    (out / 'GIT_CHECKPOINT.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in receipt.items() if k != 'published_rows'}))


if __name__ == '__main__':
    main()
