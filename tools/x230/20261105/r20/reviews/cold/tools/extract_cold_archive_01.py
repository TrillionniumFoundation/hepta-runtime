#!/usr/bin/env python3
"""Safely unpack the one closed, SHA-pinned X230 R20 cold-process archive."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

ARCHIVE_SHA = '340ef4dc2396c21f65dab9b314f4a23ef828383df72e3d80943eea395660255f'
INPUTS = {'baseline-jobs.rs', 'candidate-jobs.rs', 'coldprocess_probe_02.py', 'measurement-plan-01.json'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(path):
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode), 'input is not a regular file')
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    args = p.parse_args()
    archive, output, receipt = (x.absolute() for x in (args.archive, args.output, args.receipt))
    need(archive.resolve() == archive and output.parent.resolve() == output.parent and
         receipt.parent.resolve() == receipt.parent, 'paths must be canonical and free of links')
    need(not os.path.lexists(output) and not os.path.lexists(receipt), 'output and receipt must be fresh')
    need(not receipt.is_relative_to(output) and not archive.is_relative_to(output), 'output overlap')
    before = stamp(archive); raw = archive.read_bytes()
    need(stamp(archive) == before and len(raw) == 186554 and sha(raw) == ARCHIVE_SHA, 'archive identity or stability')
    names, inventory = set(), {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as bundle:
        members = bundle.getmembers()
        need(len(members) == 840, 'archive member count')
        for m in members:
            path = PurePosixPath(m.name)
            need(m.isreg() and not m.issparse() and not m.linkname and not any('sparse' in k.lower() for k in m.pax_headers),
                 'non-regular/link/sparse member: ' + m.name)
            need(bool(m.name) and not path.is_absolute() and path.as_posix() == m.name and
                 all(part not in ('', '.', '..') for part in m.name.split('/')) and
                 re.fullmatch(r'[A-Za-z0-9_./-]+', m.name) is not None, 'unsafe member path: ' + m.name)
            need(m.name not in names, 'duplicate member: ' + m.name)
            need(m.name in INPUTS or m.name.startswith('coldprocess-probe-01/'), 'unexpected member: ' + m.name)
            need(type(m.size) is int and 0 <= m.size <= 4 * 1024 * 1024, 'member size bound')
            names.add(m.name)
        need(sum(m.size for m in members) == 2416726 and INPUTS.issubset(names) and len(names - INPUTS) == 836,
             'archive total or closed input set')
        for name in names:
            need(not any(parent.as_posix() in names for parent in PurePosixPath(name).parents), 'file/ancestor collision')
        os.mkdir(output, 0o700)
        for m in members:
            target = output.joinpath(*PurePosixPath(m.name).parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            need(target.parent.resolve().is_relative_to(output), 'directory escape')
            stream = bundle.extractfile(m)
            need(stream is not None, 'missing file payload')
            with stream:
                data = stream.read(m.size + 1)
            need(len(data) == m.size, 'payload size differs')
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'wb') as dest:
                dest.write(data)
            need(target.read_bytes() == data and stat.S_ISREG(target.lstat().st_mode), 'extracted bytes differ')
            inventory[m.name] = {'bytes': len(data), 'sha256': sha(data), 'archive_mode': m.mode}
    actual = {q.relative_to(output).as_posix() for q in output.rglob('*') if q.is_file()}
    need(actual == names and not any(q.is_symlink() for q in output.rglob('*')), 'extracted set differs')
    need(stamp(archive) == before and archive.read_bytes() == raw, 'archive changed during extraction')
    report = {'schema': 'hepta-r20-cold-archive-extraction/v1', 'passed': True,
              'tool_sha256': sha(Path(__file__).read_bytes()),
              'archive': {'path': str(archive), 'bytes': len(raw), 'sha256': sha(raw)},
              'output': str(output), 'members': 840, 'cold_files': 836, 'inputs': sorted(INPUTS),
              'external_manifest_checked': False, 'workloads_started': False,
              'mode_scope': 'Archived modes are recorded; local private extraction modes do not attest remote execution-time modes.',
              'files': inventory}
    encoded = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    with receipt.open('xb') as f:
        f.write(encoded)
    print(json.dumps({'passed': True, 'output': str(output), 'receipt': str(receipt), 'receipt_sha256': sha(encoded)}))


if __name__ == '__main__':
    main()
