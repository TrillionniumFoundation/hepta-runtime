"""Verify complete archive parts and restore exact logical bytes in a fresh directory."""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, os, re, tarfile


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--parts', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    before = json.loads((a.parts / 'EVIDENCE.json').read_bytes())
    assert before['schema'] == 'hepta.runtime.binary-owners.evidence-parts.v1'
    assert not a.output.exists(), 'fresh restoration directory required'
    a.output.mkdir(parents=True)
    archive = a.output / 'assembled.tar.xz'
    digest, size = hashlib.sha256(), 0
    with archive.open('xb') as out:
        for number, row in enumerate(before['parts'], 1):
            assert row['path'] == 'evidence.tar.xz.part' + str(number)
            source = a.parts / row['path']
            raw = source.read_bytes()
            assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
            out.write(raw); digest.update(raw); size += len(raw)
    assert size == before['archive_bytes'] and digest.hexdigest() == before['archive_sha256']
    objects = a.output / 'objects'; objects.mkdir()
    seen, manifest = {}, None
    with tarfile.open(archive, 'r|xz') as tar:
        for member in tar:
            assert member.isfile() and member.name not in seen and member.mode == 0o644
            if member.name == 'artifact-manifest.json':
                raw = tar.extractfile(member).read()
                assert hashlib.sha256(raw).hexdigest() == before['manifest_sha256']
                manifest = json.loads(raw)
                (a.output / 'artifact-manifest.json').write_bytes(raw)
                seen[member.name] = member.size
                continue
            assert re.fullmatch(r'objects/[0-9a-f]{64}', member.name) and 0 < member.size <= 1 << 20
            path = a.output / member.name
            with tar.extractfile(member) as origin, path.open('xb') as out:
                while raw := origin.read(1 << 20):
                    out.write(raw)
            assert path.stat().st_size == member.size and sha(path) == member.name[8:]
            seen[member.name] = member.size
            tar.members.clear()
    assert manifest and manifest['schema'] == 'hepta.runtime.binary-owners.complete-chunk-archive.v1'
    assert {key[8:]: size for key, size in seen.items() if key.startswith('objects/')} == manifest['objects']
    assert len(manifest['files']) == before['logical_files'] == manifest['logical_file_count']
    used, total = set(), 0
    restored = a.output / 'restored'; restored.mkdir()
    for name, row in manifest['files'].items():
        relative = PurePosixPath(name)
        assert name == relative.as_posix() and not relative.is_absolute() and '..' not in relative.parts
        assert relative.parts[0] == 'runtime-audit' and 0 <= row['mode'] <= 0o777
        target = restored / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as out:
            for h in row['chunks']:
                assert h in manifest['objects']
                used.add(h)
                out.write((objects / h).read_bytes())
        target.chmod(row['mode'])
        assert target.stat().st_size == row['bytes'] and sha(target) == row['sha256']
        total += row['bytes']
    assert used == set(manifest['objects']) and total == before['logical_bytes'] == manifest['logical_bytes']
    result = {'status': 'COMPLETE_EVIDENCE_RESTORED', 'logical_files': len(manifest['files']), 'logical_bytes': total,
              'archive_sha256': before['archive_sha256'], 'root': str(restored.resolve()),
              'application_or_compiler_executions': 0, 'whole_runtime_qualified': False}
    (a.output / 'RESTORED.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
