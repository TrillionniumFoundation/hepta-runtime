#!/usr/bin/env python3
"""Bind all closed cold-archive members to the original external manifest."""
import argparse
import collections
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

PINS = {
    'archive': '340ef4dc2396c21f65dab9b314f4a23ef828383df72e3d80943eea395660255f',
    'manifest': '2ea1e747d9963e0515b70193d0c0b24883971c00a5e4b4e749224300f2bee1a9',
    'extraction_receipt': '32d60a39ffea4fe08c03822e083bfe06506801a86cb52d20513b9034cff1f020',
    'audit_receipt': '9979f4e4ae891058947cf6132bd1ecb2a07382e98e4a9ece96961baf0142037a'}
REMOTE = PurePosixPath('/home/qian/hepta-runtime-optimization-20261105-r20')
EXTRAS = {'baseline-jobs.rs': '/home/qian/hepta-runtime-optimization-20261104-r19/source/src/mcp/runtime/jobs.rs',
          'candidate-jobs.rs': str(REMOTE / 'source/src/mcp/runtime/jobs.rs'),
          'coldprocess_probe_02.py': str(REMOTE / 'tools/coldprocess_probe_02.py'),
          'measurement-plan-01.json': str(REMOTE / 'measurement-plan-01.json')}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(p):
    s = p.lstat()
    need(stat.S_ISREG(s.st_mode) and p.resolve() == p, 'input is not an ordinary canonical file')
    return (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'manifest', 'extraction-receipt', 'audit-receipt', 'extracted', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root, output = args.extracted.absolute(), args.output.absolute()
    need(root.resolve() == root and not os.path.lexists(output) and not output.is_relative_to(root), 'fresh receipt outside extracted input required')
    bound, raw, stamps = {}, {}, {}
    for key, expected in PINS.items():
        path = getattr(args, key).absolute(); before = stamp(path); data = path.read_bytes()
        need(stamp(path) == before and sha(data) == expected, 'pinned input differs: ' + key)
        raw[key] = data; stamps[path] = (before, data)
        bound[key] = {'path': str(path), 'bytes': len(data), 'sha256': sha(data)}
    manifest, extraction, audit = (json.loads(raw[key], object_pairs_hook=pairs)
                                   for key in ('manifest', 'extraction_receipt', 'audit_receipt'))
    need(manifest['schema'] == 'hepta-r20-cold-export/v1' and len(manifest['files']) == 840, 'manifest schema/count')
    need(extraction['passed'] is True and extraction['output'] == str(root) and audit['passed'] is True
         and all(value is True for value in audit['checks'].values()), 'prior local receipts not successful')
    by_name = {}
    for row in manifest['files']:
        name = row['path']; path = PurePosixPath(name)
        need(name not in by_name and not path.is_absolute() and path.as_posix() == name
             and all(p not in ('', '.', '..') for p in name.split('/')), 'duplicate/unsafe manifest path')
        expected_original = EXTRAS.get(name, str(REMOTE / name))
        need(row['original_path'] == expected_original, 'original path binding differs')
        by_name[name] = row
    need(set(EXTRAS).issubset(by_name) and set(by_name) == set(extraction['files']), 'manifest/extraction file sets differ')
    matched, archive_modes, private_local_modes = [], collections.Counter(), collections.Counter()
    with tarfile.open(fileobj=io.BytesIO(raw['archive']), mode='r:gz') as bundle:
        members = bundle.getmembers()
        need(len(members) == 840 and len({m.name for m in members}) == 840 and {m.name for m in members} == set(by_name), 'archive exact member set')
        for member in members:
            row = by_name[member.name]
            need(member.isreg() and not member.issparse() and not member.linkname, 'invalid archive member type')
            payload = bundle.extractfile(member)
            need(payload is not None, 'missing archive payload')
            with payload:
                content = payload.read(member.size + 1)
            need(member.size == row['size'] == len(content) and sha(content) == row['sha256'] and member.mode == row['mode'],
                 'archive size/SHA256/mode differs: ' + member.name)
            need(extraction['files'][member.name] == {'bytes': row['size'], 'sha256': row['sha256'], 'archive_mode': row['mode']},
                 'extraction receipt differs')
            path = root / member.name; before = stamp(path); local = path.read_bytes()
            need(stamp(path) == before and local == content, 'local extracted bytes differ')
            stamps[path] = (before, local)
            if member.name.startswith('coldprocess-probe-01/'):
                relative = member.name[len('coldprocess-probe-01/'):]
                need(audit['verified_cold_files'][relative] == {'bytes': row['size'], 'sha256': row['sha256']}, 'offline audit file binding differs')
            matched.append(member.name); archive_modes[member.mode] += 1; private_local_modes[stat.S_IMODE(before[3])] += 1
    need(len(matched) == 840 and len(audit['verified_cold_files']) == 836, 'binding denominator')
    need(archive_modes == {0o600: 839, 0o644: 1} and
         by_name['coldprocess-probe-01/fixtures/unsafe_owner/state/jobs/unsafe_owner/started.json']['mode'] == 0o644,
         'remote fault-fixture mode differs')
    need({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} == set(by_name), 'local file set differs')
    need(all(stamp(p) == before and p.read_bytes() == data for p, (before, data) in stamps.items()), 'input changed during verification')
    report = {'schema': 'hepta-r20-cold-external-manifest-binding/v1', 'passed': True,
              'tool_sha256': sha(Path(__file__).read_bytes()), 'inputs': bound,
              'checks': {'manifest_sha256_pinned': True, 'archive_sha256_pinned': True,
                         'all_840_member_sets_size_sha256_modes_equal': True, 'all_original_paths_bound': True,
                         'all_840_local_extracted_bytes_equal': True, 'all_836_offline_audit_file_hashes_equal': True,
                         'unsafe_owner_remote_mode_0644_preserved_in_archive': True, 'all_inputs_stable': True},
              'members_verified': 840, 'cold_files_verified': 836, 'external_inputs_verified': 4,
              'archive_mode_counts': {oct(k): v for k, v in sorted(archive_modes.items())},
              'private_local_mode_counts': {oct(k): v for k, v in sorted(private_local_modes.items())},
              'mode_scope': 'Manifest original modes are checked against each tar header. Local files deliberately use private 0600; no mode mutation or workload was performed.',
              'workloads_started': False, 'remote_calls': 0}
    encoded = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    with output.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps({'passed': True, 'output': str(output), 'sha256': sha(encoded), 'members_verified': 840}))


if __name__ == '__main__':
    main()
