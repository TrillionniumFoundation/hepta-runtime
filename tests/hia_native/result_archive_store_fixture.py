# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fixture-only setup and verified projection of process-specific directory identities."""
from pathlib import Path
import hashlib
import json
import os
import re
import stat

from result_archive_store_cases import ANCHOR, MARKER, STORE, ARCHIVE

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
PAIR = re.compile(rb'("device"\s*:\s*)([0-9]+)(\s*,\s*"inode"\s*:\s*)([0-9]+)')


def identity(path):
    value = path.stat()
    return dict(device=value.st_dev, inode=value.st_ino)


def write(path, raw, mode=0o600):
    path.write_bytes(raw)
    path.chmod(mode)


def setup(directory, row):
    directory.mkdir(mode=0o700)
    (directory / 'root').mkdir(mode=0o700)
    (directory / 'legacy').mkdir(mode=0o700)
    if row['initialized']:initialize(directory)


def initialize(directory, marker=True):
    (directory / STORE).mkdir(mode=0o700)
    (directory / ARCHIVE).mkdir(mode=0o700)
    for index in range(256):
        (directory / ARCHIVE / f'{index:02x}').mkdir(mode=0o700)
    anchor = dict(schema=2, root=identity(directory / 'root'), legacy=identity(directory / 'legacy'),
        store=identity(directory / STORE), archive=identity(directory / ARCHIVE),
        shards=[identity(directory / ARCHIVE / f'{index:02x}') for index in range(256)])
    raw = json.dumps(anchor, separators=(',', ':')).encode()
    write(directory / ANCHOR, raw)
    if marker:write(directory / MARKER, json.dumps(dict(schema=2, anchor_sha256=SHA(raw)), separators=(',', ':')).encode())

def mutate(directory, change):
    action = change['action']
    path = directory / change.get('path', MARKER)
    if action == 'chmod':
        path.chmod(change['mode'])
    elif action == 'rename':
        path.rename(directory / change['target'])
    elif action == 'remove':
        if path.is_dir() and not path.is_symlink():path.rmdir()
        else:path.unlink()
    elif action == 'write':
        write(path, bytes.fromhex(change['data']))
    elif action == 'marker':
        write(directory / MARKER, json.dumps(dict(schema=2, anchor_sha256=change['digest']), separators=(',', ':')).encode())
    elif action == 'anchor_pin':
        anchor = json.loads((directory / ANCHOR).read_bytes())
        if change['field'] == 'shards':anchor['shards'][change['index']] = change['replacement']
        else:anchor[change['field']] = change['replacement']
        write(directory / ANCHOR, json.dumps(anchor, separators=(',', ':')).encode())
    elif action in ('node', 'replace', 'symlink'):
        if action in ('replace', 'symlink'):
            if path.is_dir() and not path.is_symlink():path.rmdir()
            else:path.unlink()
        kind = change.get('kind', 'symlink')
        if kind == 'directory':path.mkdir(mode=0o700)
        elif kind == 'file':write(path, b'preserved unrelated bytes')
        elif kind == 'fifo':os.mkfifo(path, 0o600)
        elif kind in ('symlink', 'dangling'):
            path.symlink_to(change.get('target', 'absent-target' if kind == 'dangling' else '.'))
        else:raise AssertionError(change)
    else:raise AssertionError(change)


class Fixture:
    def __init__(self, directory, evidence):
        self.directory = directory
        self.evidence = evidence
        self.by_identity = {}
        self.generations = {}
        self.pins = []
        self.digests = {}
        self.snapshots = set()
        self.verified_created_anchors = []

    def register(self, path):
        value = path.lstat()
        pair = (value.st_dev, value.st_ino)
        if pair not in self.by_identity:
            relative = str(path.relative_to(self.directory))
            generation = self.generations.get(relative, 0) + 1
            self.generations[relative] = generation
            token = relative + '#' + str(generation)
            fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            check = os.fstat(fd)
            assert (check.st_dev, check.st_ino) == pair
            self.by_identity[pair] = token
            self.pins.append((fd, pair, token))
        return value, self.by_identity[pair]

    def entries(self):
        values = []
        def visit(path):
            value, token = self.register(path)
            name = str(path.relative_to(self.directory))
            values.append((path, name, value, token))
            if stat.S_ISDIR(value.st_mode):
                try:children = sorted(path.iterdir())
                except PermissionError:return
                for child in children:visit(child)
        for path in sorted(self.directory.iterdir()):visit(path)
        return values

    def project_anchor(self, raw):
        def pair(match):
            identity = (int(match[2]), int(match[4]))
            token = self.by_identity.get(identity)
            if token is None:return match[0]
            name = token.encode()
            return match[1] + b'@device(' + name + b')' + match[3] + b'@inode(' + name + b')'
        return PAIR.sub(pair, raw)

    def verify_created_anchor(self):
        raw = (self.directory / ANCHOR).read_bytes()
        anchor = json.loads(raw)
        assert set(anchor) == {'schema', 'root', 'legacy', 'store', 'archive', 'shards'}
        assert anchor['schema'] == 2 and len(anchor['shards']) == 256
        for field, name in (('root', 'root'), ('legacy', 'legacy'), ('store', STORE), ('archive', ARCHIVE)):
            assert anchor[field] == identity(self.directory / name)
        for index in range(256):
            assert anchor['shards'][index] == identity(self.directory / ARCHIVE / f'{index:02x}')
        assert raw == json.dumps(anchor, separators=(',', ':')).encode()
        digest = SHA(raw)
        marker = (self.directory / MARKER).read_bytes()
        assert marker == json.dumps(dict(schema=2, anchor_sha256=digest), separators=(',', ':')).encode()
        assert not list((self.directory / 'root').glob('.result-anchor-*.tmp'))
        self.verified_created_anchors.append(dict(bytes=len(raw), sha256=digest, identities=260,
            marker_sha256=SHA(marker), compact_serde_field_order=True))

    def snapshot(self):
        entries = self.entries()
        readable = {}
        for path, name, info, token in entries:
            if stat.S_ISREG(info.st_mode):
                try:readable[name] = path.read_bytes()
                except PermissionError:pass
        for name, raw in readable.items():
            if Path(name).name == Path(ANCHOR).name:
                normalized = self.project_anchor(raw)
                self.digests[SHA(raw)] = SHA(normalized)
        rows = []
        for path, name, info, token in entries:
            record = dict(path=name, identity=token, mode=stat.S_IMODE(info.st_mode),
                owner_matches_euid=info.st_uid == os.geteuid(), links=info.st_nlink)
            if stat.S_ISDIR(info.st_mode):
                record['kind'] = 'directory'
                try:list(path.iterdir())
                except PermissionError:record['contents_unreadable'] = True
            elif stat.S_ISLNK(info.st_mode):
                record.update(kind='symlink', target=os.readlink(path))
            elif stat.S_ISFIFO(info.st_mode):record['kind'] = 'fifo'
            elif stat.S_ISREG(info.st_mode):
                record['kind'] = 'file'
                if name not in readable:
                    record.update(bytes=info.st_size, unreadable=True)
                else:
                    raw = readable[name]
                    normalized = raw
                    if Path(name).name == Path(ANCHOR).name:normalized = self.project_anchor(raw)
                    if Path(name).name == Path(MARKER).name:
                        for digest, canonical in self.digests.items():
                            normalized = normalized.replace(digest.encode(), canonical.encode())
                    record.update(projected_bytes=len(normalized), projected_sha256=SHA(normalized))
            else:raise AssertionError((name, info.st_mode))
            rows.append(record)
        raw = ENCODE(rows);digest = SHA(raw)
        if digest not in self.snapshots:
            folder = self.evidence / 'snapshots';folder.mkdir(exist_ok=True)
            (folder / (digest + '.json')).write_bytes(raw);self.snapshots.add(digest)
        return digest

    def descriptors(self, process):
        assert process.poll() is None
        rows = []
        for path in sorted((Path('/proc') / str(process.pid) / 'fd').iterdir()):
            try:target = os.readlink(path)
            except FileNotFoundError:continue
            if target == '/dev/urandom':raise AssertionError('random source still open at reply')
            if not (target == str(self.directory) or target.startswith(str(self.directory) + '/')):continue
            info = path.stat()
            assert stat.S_ISDIR(info.st_mode), ('non-directory retained at reply', target)
            pair = (info.st_dev, info.st_ino)
            assert pair in self.by_identity, (target, pair)
            rows.append(dict(fd=int(path.name), device=pair[0], inode=pair[1], identity=self.by_identity[pair]))
        assert process.poll() is None
        return rows

    def finish(self):
        proof = []
        for fd, pair, token in self.pins:
            check = os.fstat(fd)
            assert (check.st_dev, check.st_ino) == pair
            proof.append(dict(device=pair[0], inode=pair[1], identity=token))
            os.close(fd)
        (self.evidence / 'identities.json').write_bytes(ENCODE(proof))
        return dict(pinned_identities=len(proof), verified_created_anchors=self.verified_created_anchors,
            unique_snapshots=len(self.snapshots))
