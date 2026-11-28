"""Actual HIA map/lease/FIFO sequences; original Rust replay is mandatory separately."""
from __future__ import annotations
import argparse
from collections import deque
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(os.environ.get('HIA_REFERENCE_RUNTIME', ROOT))
sys.path.insert(0, str(REFERENCE / 'scripts'))
from hia_native_loader import NativeModule

INVALID, CAPACITY, STATE = 0xffffffff, 0xfffffffe, 0xfffffff9
COUNTS = {'native_calls': 0, 'reference_rows': 0, 'original_owner_operations': 0,
          'lifecycle_operations': 0, 'growth_refusals': 0, 'frame_refusals': 0,
          'capacity_refusals': 0, 'state_refusals': 0, 'refusal_fixture_initializations': 0}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def request(op, ident=0, key=b''):
    return struct.pack('<8s7Q', b'HRFLOCK1', op, ident, len(key), 0, 0, 0, 0) + key

def response(op, code=0, lease=0, node=0, count=0, strong=0, woken=0):
    return struct.pack('<8s7Q', b'HRFLKR01', op, code, lease, node, count, strong, woken)

def decode(raw):
    values = struct.unpack('<8s7Q', raw)
    assert values[0] == b'HRFLKR01'
    return values[1:]

class Model:
    """Independent expectation; this never executes in an emitted native image."""
    def __init__(self):
        self.nodes = {}
        self.leases = {}
        self.next_node = 1
        self.next_lease = 1
        self.active = False

    def call(self, op, ident, key):
        if op == 0:
            assert not self.active
            self.active = True
            return response(op)
        assert self.active
        if op == 9:
            assert not self.leases
            self.active = False
            self.nodes.clear()
            return response(op)
        if op == 7:
            return response(op, count=len(self.nodes), strong=len(self.leases))
        woken = 0
        if op == 1:
            if len(self.nodes) > 1024:
                self.nodes = {key: node for key, node in self.nodes.items() if node['refs']}
            if key not in self.nodes:
                self.nodes[key] = {'id': self.next_node, 'refs': 0, 'owner': None, 'queue': deque()}
                self.next_node += 1
            node = self.nodes[key]
            ident = self.new_lease(node)
        else:
            lease = self.leases[ident]
            node = lease['node']
            state = lease['state']
            if op == 2:
                ident = self.new_lease(node)
            elif op == 3:
                assert state != 'held'
                if state == 'idle':
                    if node['owner'] is None:
                        node['owner'] = ident
                        lease['state'] = 'held'
                    else:
                        node['queue'].append(ident)
                        lease['state'] = 'queued'
                elif state == 'reserved':
                    assert node['owner'] == ident
                    lease['state'] = 'held'
                if lease['state'] == 'queued':
                    return response(op, 1, ident, node['id'], len(self.nodes), node['refs'] + 1)
            elif op == 4:
                assert state != 'held'
                woken = self.cancel(ident)
            elif op == 5:
                assert state == 'held'
                woken = self.release(ident)
            elif op == 6:
                woken = self.release(ident) if state == 'held' else self.cancel(ident)
                node['refs'] -= 1
                del self.leases[ident]
            else:
                raise AssertionError(op)
        return response(op, 0, ident, node['id'], len(self.nodes), node['refs'] + 1, woken)

    def new_lease(self, node):
        ident = self.next_lease
        self.next_lease += 1
        self.leases[ident] = {'node': node, 'state': 'idle'}
        node['refs'] += 1
        return ident

    def release(self, ident):
        lease = self.leases[ident]
        node = lease['node']
        assert node['owner'] == ident
        lease['state'] = 'idle'
        node['owner'] = None
        if not node['queue']:
            return 0
        following = node['queue'].popleft()
        self.leases[following]['state'] = 'reserved'
        node['owner'] = following
        return following

    def cancel(self, ident):
        lease = self.leases[ident]
        if lease['state'] == 'queued':
            lease['node']['queue'].remove(ident)
            lease['state'] = 'idle'
        elif lease['state'] == 'reserved':
            return self.release(ident)
        else:
            assert lease['state'] == 'idle'
        return 0

class Corpus:
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(mode=0o700)
        self.requests = gzip.open(directory / 'requests.bin.gz', 'xb')
        self.outputs = gzip.open(directory / 'native-output.bin.gz', 'xb')
        self.domains = gzip.open(directory / 'domains.jsonl.gz', 'xb')
        self.growth = []

    def row(self, session, wire, actual):
        COUNTS['reference_rows'] += 1
        op = struct.unpack_from('<Q', wire, 8)[0]
        domain = 'lifecycle_operations' if op in (0, 9) else 'original_owner_operations'
        COUNTS[domain] += 1
        self.requests.write(struct.pack('<QQ', session, len(wire)) + wire)
        self.outputs.write(actual)
        self.domains.write((json.dumps({'ordinal': COUNTS['reference_rows'], 'session': session,
            'op': op, 'domain': domain}, sort_keys=True) + '\n').encode())

    def close(self):
        for stream in (self.requests, self.outputs, self.domains):
            stream.close()
        (self.directory / 'growth.json').write_text(json.dumps(self.growth, sort_keys=True, indent=2) + '\n')

class Session:
    next_id = 0
    def __init__(self, module, corpus, workspace=4096):
        Session.next_id += 1
        self.sid = Session.next_id
        self.module = module
        self.corpus = corpus
        self.native = module.session(output_capacity=64, workspace_capacity=workspace)
        self.model = Model()
        self.peak_workspace = workspace
        self.call(0)

    def call(self, op, ident=0, key=b''):
        wire = request(op, ident, key)
        while True:
            used = struct.unpack('<Q', ctypes.string_at(ctypes.addressof(self.native._workspace) + 16, 8))[0]
            reserve = ((len(key) + 111) & ~15) + 96 if op == 1 else 96 if op == 2 else 0
            expect_growth = op in (1, 2) and self.native.workspace_capacity - used < reserve
            before = ctypes.string_at(self.native._workspace, self.native.workspace_capacity) if expect_growth else None
            actual = self.native.invoke(wire)
            COUNTS['native_calls'] += 1
            values = decode(actual)
            if values[1] != 2:
                break
            assert expect_growth and before is not None
            after = ctypes.string_at(self.native._workspace, self.native.workspace_capacity)
            assert after == before
            required = values[3]
            assert required > self.native.workspace_capacity
            self.corpus.growth.append({'session': self.sid, 'before_reference_row': COUNTS['reference_rows'] + 1,
                'request_sha256': sha(wire), 'output_hex': actual.hex(), 'state_sha256': sha(before),
                'old_capacity': self.native.workspace_capacity, 'required_capacity': required})
            COUNTS['growth_refusals'] += 1
            capacity = max(required, self.native.workspace_capacity * 2)
            replacement = self.module.session(output_capacity=64, workspace_capacity=capacity)
            ctypes.memmove(replacement._workspace, self.native._workspace, self.native.workspace_capacity)
            self.native.close()
            self.native = replacement
            self.peak_workspace = max(self.peak_workspace, capacity)
        expected = self.model.call(op, ident, key)
        assert actual == expected, (self.sid, COUNTS, op, ident, key[:100], values, decode(expected))
        self.corpus.row(self.sid, wire, actual)
        return values

    def acquire(self, key):
        return self.call(1, key=key)[2]

    def clone(self, ident):
        return self.call(2, ident)[2]

    def close(self):
        for ident in list(self.model.leases):
            self.call(6, ident)
        self.call(9)
        assert ctypes.string_at(self.native._workspace, self.native.workspace_capacity) == bytes(self.native.workspace_capacity)
        self.native.close()

def fifo_cases(module, corpus):
    session = Session(module, corpus)
    first = session.acquire(b'/shared\0key')
    second = session.clone(first)
    session.call(3, first)
    session.call(3, second)
    third = session.acquire(b'/shared\0key')
    session.call(3, third)
    session.call(5, first)
    fourth = session.clone(first)
    session.call(3, fourth)
    session.call(4, second)
    session.call(3, third)
    session.call(6, third)
    session.call(3, fourth)
    session.close()
    for count in (1, 2, 3, 8, 31, 80):
        session = Session(module, corpus)
        holder = session.acquire(b'fifo')
        session.call(3, holder)
        waiters = [session.clone(holder) for _ in range(count)]
        for ident in waiters:
            session.call(3, ident)
            session.call(3, ident)
        for ident in waiters[1::3]:
            session.call(4, ident)
        session.call(5, holder)
        for ident in waiters:
            state = session.model.leases[ident]['state']
            if state == 'reserved' and ident % 2:
                session.call(4, ident)
            elif state in ('reserved', 'queued'):
                result = session.call(3, ident)
                if result[1] == 0:
                    session.call(5, ident)
        session.close()

def sweep_cases(module, corpus):
    session = Session(module, corpus)
    for index in range(1024):
        ident = session.acquire(f'idle-{index}'.encode())
        session.call(6, ident)
    assert session.call(7)[4] == 1024
    ident = session.acquire(b'idle-last')
    session.call(6, ident)
    assert session.call(7)[4] == 1025
    ident = session.acquire(b'idle-0')
    assert session.call(7)[4] == 1
    session.call(6, ident)
    session.close()
    session = Session(module, corpus)
    held = [session.acquire(f'held-{index}'.encode()) for index in range(2051)]
    assert session.call(7)[4] == 2051
    for ident in held[:5]:
        session.call(3, ident)
    clones = [session.clone(ident) for ident in held[:5]]
    for ident in clones:
        session.call(3, ident)
    for ident in held[5:]:
        session.call(6, ident)
    session.acquire(b'next')
    assert session.call(7)[4] == 6
    session.close()

def random_cases(module, corpus):
    rng = random.Random(0x8fe043b1)
    for _ in range(12):
        session = Session(module, corpus)
        keys = [b'', b'a', b'\0', b'a\0b', '甲/乙/🙂'.encode()] + [f'key-{i}'.encode() for i in range(40)]
        for _ in range(1400):
            if not session.model.leases or (len(session.model.leases) < 130 and rng.randrange(5) == 0):
                session.acquire(rng.choice(keys))
                continue
            ident = rng.choice(list(session.model.leases))
            state = session.model.leases[ident]['state']
            options = [2, 6, 7]
            options += [5] if state == 'held' else [3, 4]
            op = rng.choice(options)
            session.call(op, 0 if op == 7 else ident)
        session.close()

def reuse_and_large_keys(module, corpus):
    session = Session(module, corpus)
    for round_index in range(12):
        for index in range(1100):
            ident = session.acquire(f'cycle-{round_index}-{index}'.encode())
            session.call(6, ident)
        assert session.peak_workspace <= 1 << 20
    session.close()
    session = Session(module, corpus)
    for key in (b'', b'\0', '汉字🙂\0'.encode(), b'a' * (5 << 20), '🙂'.encode() * ((5 << 20) // 4)):
        first = session.acquire(key)
        second = session.acquire(key)
        assert session.model.leases[first]['node'] is session.model.leases[second]['node']
        session.call(3, first)
        session.call(3, second)
        session.call(6, first)
        session.call(3, second)
        session.call(6, second)
    session.close()

def refusal_cases(module):
    bad = [b'', b'HRFLOCK1', request(8), request(10), request(1, 1, b'key'), request(2), request(3),
           request(0, 1), request(7, 1), request(9, 1), request(2, 1, b'extra')]
    good = request(1, key=b'a')
    bad.extend(good[:size] for size in range(9, 64))
    for value in (b'\xff', b'\xc0\x80', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\xf0\x9f'):
        bad.append(request(1, key=value))
    for at in (32, 40, 48, 56):
        wire = bytearray(request(1));wire[at] = 1;bad.append(bytes(wire))
    for wire in bad:
        code, output, work = module.invoke_raw(wire, output_capacity=64, workspace_capacity=256,
                                              output_fill=0xa5, workspace_fill=0x5a)
        COUNTS['native_calls'] += 1;COUNTS['frame_refusals'] += 1
        assert code == INVALID and output == b'\xa5' * 64 and work == b'\x5a' * 256
    for output_capacity, workspace_capacity in ((0, 256), (63, 256), (64, 0), (64, 255)):
        code, output, work = module.invoke_raw(request(0), output_capacity=output_capacity,
            workspace_capacity=workspace_capacity, output_fill=0xa5, workspace_fill=0x5a)
        COUNTS['native_calls'] += 1;COUNTS['capacity_refusals'] += 1
        assert code == CAPACITY and output == b'\xa5' * output_capacity and work == b'\x5a' * workspace_capacity
    with module.session(output_capacity=64, workspace_capacity=4096) as state:
        state.invoke(request(0));COUNTS['native_calls'] += 1;COUNTS['refusal_fixture_initializations'] += 1
        for wire in (request(0), request(2, 999), request(3, 999), request(4, 999), request(5, 999), request(6, 999)):
            before = ctypes.string_at(state._workspace, 4096)
            ctypes.memset(state._output, 0xa5, 64)
            code, output, work = state.invoke_raw(wire)
            COUNTS['native_calls'] += 1;COUNTS['state_refusals'] += 1
            assert code == STATE and output == b'\xa5' * 64 and work == before

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, default=os.environ.get('HIA_FILE_LOCK_STATE_MANIFEST'))
    parser.add_argument('--bundle', type=Path, default=os.environ.get('HIA_FILE_LOCK_MANIFEST'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    artifacts = None
    if args.bundle is not None:
        from hia_native_file_lock_build import inspect_bundle
        artifacts = inspect_bundle(args.bundle, source_root=ROOT)
        selected = args.bundle.resolve(strict=True).parent / 'state.json'
        assert args.manifest is None or args.manifest.resolve(strict=True) == selected
        args.manifest = selected
    assert args.manifest is not None
    started = time.monotonic()
    corpus = Corpus(args.output)
    try:
        with NativeModule(args.manifest, manifest_sha256=sha(args.manifest.read_bytes())) as module:
            assert module.metadata['source_sha256'] == sha((ROOT / 'native/file_lock_state.hepta').read_bytes())
            for test in (fifo_cases, sweep_cases, random_cases, reuse_and_large_keys):
                test(module, corpus)
            refusal_cases(module)
            identity = {'source_sha256': module.metadata['source_sha256'], 'image_sha256': module.metadata['image_sha256'],
                'manifest_sha256': sha(args.manifest.read_bytes()), 'compiler_commit': module.metadata['compiler_commit']}
    finally:
        corpus.close()
    executable = replay_executable(args.bundle, args.output) if args.bundle is not None else None
    files = {}
    for path in args.output.iterdir():
        raw = path.read_bytes()
        files[path.name] = {'bytes': len(raw), 'sha256': sha(raw)}
        if path.suffix == '.gz':
            raw = gzip.decompress(raw)
            files[path.name].update(raw_bytes=len(raw), raw_sha256=sha(raw))
    result = {'schema': 'hepta.runtime.file-lock-state-native.v1', 'status': 'PASS',
        'counts': COUNTS, 'groups': 6 if executable else 5, 'identity': identity, 'corpus': files,
        'source_sha256': {path: sha((ROOT / path).read_bytes()) for path in
            ('native/file_lock_state.hepta', 'native/file_lock_state_composition.json', 'tests/hia_native/test_file_lock_state.py')},
        'elapsed': time.monotonic() - started, 'actual_filesystem_effects': 0,
        'original_rust_status': 'PENDING', 'native_cross_thread_serialization_proved': False,
        'complete_canonical_file_lock_owner': False, 'production_activated': False,
        'bundle_artifacts': artifacts, 'persistent_executable': executable}
    if args.bundle is not None:
        assert inspect_bundle(args.bundle, source_root=ROOT) == artifacts
    (args.output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))

def replay_executable(bundle, directory):
    """Execute all sessions through the real growing native transport."""
    binary = bundle.resolve(strict=True).parent / 'file-lock-state.elf'
    before = sha(binary.read_bytes())
    count, sessions = 0, set()
    framed_path = directory / 'elf-request.bin'
    with gzip.open(directory / 'requests.bin.gz', 'rb') as source, framed_path.open('xb') as framed:
        while header := source.read(16):
            assert len(header) == 16
            sid, size = struct.unpack('<QQ', header)
            wire = source.read(size)
            assert len(wire) == size
            framed.write(header[8:] + wire)
            sessions.add(sid)
            count += 1
    assert count == 51829 and len(sessions) == 23
    started = time.monotonic()
    with framed_path.open('rb') as incoming, (directory / 'elf.stdout').open('xb') as out, (directory / 'elf.stderr').open('xb') as err:
        result = subprocess.run([str(binary)], stdin=incoming, stdout=out, stderr=err, timeout=180)
    assert result.returncode == 0 and (directory / 'elf.stderr').read_bytes() == b''
    with (directory / 'elf.stdout').open('rb') as actual, gzip.open(directory / 'native-output.bin.gz', 'rb') as expected:
        for _ in range(count):
            assert actual.read(4) == struct.pack('<I', 64)
            assert actual.read(64) == expected.read(64)
        assert actual.read() == b'' and expected.read() == b''
    assert sha(binary.read_bytes()) == before
    return {'command': [str(binary)], 'timeout_seconds': 180, 'exit_code': result.returncode,
        'elapsed': time.monotonic() - started, 'executable_sha256': before,
        'actual_elf_requests': count, 'sessions': len(sessions), 'actual_original_calls': 0,
        'stdin_file': framed_path.name, 'stdout_file': 'elf.stdout', 'stderr_file': 'elf.stderr',
        'stdin_sha256': sha(framed_path.read_bytes()), 'stdout_sha256': sha((directory / 'elf.stdout').read_bytes())}

if __name__ == '__main__':
    main()
