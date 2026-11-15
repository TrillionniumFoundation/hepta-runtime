"""Actual three-image native file-lock calls; no production semantic fallback."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / 'scripts', ROOT / 'tests/hia_native'):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import file_lock_key_cases
from file_lock_fixture import snapshot, retire
from hia_native_file_lock_service_build import inspect_bundle

OPTIONS = None
RESULTS = {}
ARTIFACTS = None
SOURCES = ('native/file_lock_service.hepta', 'native/file_lock_service_composition.json',
    'native/file_lock_service_packer.hepta', 'native/file_lock_service_layout.json',
    'native/file_lock_key.hepta', 'native/file_lock_state.hepta',
    'tests/hia_native/test_file_lock_service.py', 'tests/hia_native/file_lock_key_cases.py',
    'tests/hia_native/file_lock_fixture.py', 'scripts/hia_native_file_lock_service_build.py')


def record(path):
    value = Path(path).read_bytes()
    return {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}


def request(op, ident=0, *, path=b'', host=b'', port=0, kind=0):
    return struct.pack('<8s7Q', b'HRLKSRV1', op, ident, kind, len(path), len(host), port, 0) + path + host


class Client:
    def __init__(self, executable, cwd, folder, session):
        self.folder = Path(folder); self.folder.mkdir()
        self.session = session
        self.command = [str(executable)]
        self.cwd = str(Path(cwd).resolve(strict=True))
        self.errors = (self.folder / 'native.stderr').open('wb')
        self.process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.errors, bufsize=0, cwd=cwd)
        self.inputs = gzip.open(self.folder / 'requests.bin.gz', 'wb')
        self.outputs = gzip.open(self.folder / 'native-wire.bin.gz', 'wb')
        self.semantic = gzip.open(self.folder / 'native-output.bin.gz', 'wb')
        self.sent = self.received = 0
        self.tids = set(); self.tags = set()
        self.closed = False
        self.started = time.monotonic()

    def send(self, wire):
        self.sent += 1
        tag = self.sent
        frame = struct.pack('<QQ', len(wire), tag) + wire
        self.inputs.write(frame)
        view = memoryview(frame)
        while view:
            count = os.write(self.process.stdin.fileno(), view)
            assert count > 0
            view = view[count:]
        return tag

    def exact(self, size):
        value = bytearray(); deadline = time.monotonic() + 30
        while len(value) < size:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.process.stdout], [], [], left)[0]:
                raise AssertionError('native lock response exceeded control deadline')
            block = os.read(self.process.stdout.fileno(), size - len(value))
            if not block:
                raise AssertionError(('native lock transport ended', self.process.poll(), self.received, self.sent))
            value.extend(block)
        return bytes(value)

    def receive(self):
        header = self.exact(20)
        tag, tid, code = struct.unpack('<QQI', header)
        assert 0 < tag <= self.sent and tag not in self.tags and tid > 0
        assert code in (64, 0xffffffff, 0xfffffffe, 0xfffffff9)
        answer = self.exact(64) if code == 64 else b''
        self.outputs.write(header + answer)
        self.semantic.write(struct.pack('<QI', tag, code) + answer)
        self.tags.add(tag); self.tids.add(tid); self.received += 1
        return tag, tid, code, answer

    def call(self, wire):
        tag = self.send(wire)
        actual, tid, code, answer = self.receive()
        assert actual == tag and code == 64, (tag, actual, code)
        assert answer[:8] == b'HRFLKR01'
        return struct.unpack('<7Q', answer[8:]), answer, tid

    def finish(self):
        assert self.sent == self.received
        self.process.stdin.close()
        assert self.process.wait(timeout=10) == 0
        assert self.process.stdout.read() == b''
        for stream in (self.inputs, self.outputs, self.semantic, self.errors): stream.close()
        assert (self.folder / 'native.stderr').read_bytes() == b''
        self.closed = True
        result = {'status': 'PASS', 'session': self.session, 'actual_elf_requests': self.received,
            'native_thread_ids': sorted(self.tids), 'elapsed': time.monotonic() - self.started,
            'command': self.command, 'cwd': self.cwd, 'exit_code': 0,
            'response_timeout_seconds': 30, 'shutdown_timeout_seconds': 10,
            'files': {name: record(self.folder / name) for name in
                ('requests.bin.gz', 'native-wire.bin.gz', 'native-output.bin.gz', 'native.stderr')}}
        (self.folder / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        return result

    def abort(self):
        if not self.closed:
            if self.process.poll() is None: self.process.kill()
            self.process.wait()
            for stream in (self.inputs, self.outputs, self.semantic, self.errors): stream.close()


class Service(unittest.TestCase):
    def test_01_complete_state_corpus(self):
        out = OPTIONS.output / 'state'; out.mkdir()
        source = OPTIONS.state_corpus
        with gzip.open(source / 'requests.bin.gz', 'rb') as inputs, gzip.open(source / 'native-output.bin.gz', 'rb') as outputs:
            active = None; rows = 0; sessions = []
            try:
                while header := inputs.read(16):
                    self.assertEqual(len(header), 16)
                    sid, length = struct.unpack('<QQ', header)
                    wire, expected = inputs.read(length), outputs.read(64)
                    self.assertEqual(len(wire), length); self.assertEqual(len(expected), 64)
                    op, ident, count = struct.unpack_from('<3Q', wire, 8)
                    if op == 0:
                        self.assertIsNone(active)
                        active = Client(OPTIONS.executable, out, out / f'session-{sid}', sid)
                        continue
                    if op == 9:
                        sessions.append(active.finish()); active = None
                        continue
                    changed = request(op, ident, kind=1 if op == 1 else 0, path=wire[64:])
                    _, actual, _ = active.call(changed)
                    self.assertEqual(actual, expected, (sid, rows, op, ident))
                    rows += 1
                self.assertEqual(outputs.read(), b'')
                self.assertIsNone(active)
            finally:
                if active is not None: active.abort()
        self.assertEqual(rows, 51783); self.assertEqual(len(sessions), 23)
        RESULTS['state'] = {'status': 'PASS', 'actual_elf_requests': rows, 'sessions': sessions,
            'original_reference_bridge_rows': rows, 'excluded_fixture_lifecycle_rows': 46,
            'input_source': record(source / 'requests.bin.gz'), 'expected_source': record(source / 'native-output.bin.gz')}

    def test_02_complete_canonical_to_state(self):
        out = OPTIONS.output / 'canonical'; out.mkdir()
        fixture = file_lock_key_cases.setup(out / 'fixture')
        before = snapshot(fixture)
        client = Client(OPTIONS.executable, fixture, out / 'process', 1)
        keys = 0
        try:
            for domain, wire in file_lock_key_cases.requests():
                kind, path_size, host_size, port = struct.unpack_from('<4Q', wire, 8)
                frame = request(1, kind=kind, path=wire[64:64 + path_size],
                    host=wire[64 + path_size:], port=port)
                values, _, _ = client.call(frame)
                self.assertEqual(values[:2], (1, 0)); self.assertGreater(values[2], 0)
                self.assertEqual(values[5], 2)
                released, _, _ = client.call(request(6, values[2]))
                self.assertEqual(released, (6, 0, values[2], values[3], values[4], 1, 0))
                keys += 1
            status, _, _ = client.call(request(7)); self.assertEqual(status[5], 0)
            actual = client.finish()
        finally: client.abort()
        self.assertEqual(keys, 89715)
        self.assertEqual(snapshot(fixture), before)
        archived = retire(fixture, out / 'fixture.json.gz')
        RESULTS['canonical'] = {'status': 'PASS', 'key_requests': keys,
            'actual_elf_requests': 2 * keys + 1, 'process': actual, 'fixture': archived,
            'fresh_original_status': 'PENDING'}

    def test_03_real_shared_threads(self):
        out = OPTIONS.output / 'concurrent'; out.mkdir()
        fixture = out / 'fixture'; fixture.mkdir(); (fixture / 'file').write_bytes(b'original')
        (fixture / 'file').chmod(0o644)
        (fixture / 'alias').symlink_to('file')
        before_fixture = snapshot(fixture)
        client = Client(OPTIONS.executable, fixture, out / 'process', 1)
        observations = []
        try:
            for round_index in range(128):
                aliases = (b'file', b'./file', b'alias', os.fsencode(fixture / 'file'))
                tags = [client.send(request(1, kind=1, path=path)) for path in aliases]
                answers = [client.receive() for _ in tags]
                self.assertEqual({row[0] for row in answers}, set(tags))
                self.assertTrue(all(row[2] == 64 for row in answers))
                vals = [struct.unpack('<7Q', row[3][8:]) for row in answers]
                self.assertEqual(len({v[2] for v in vals}), 4)
                self.assertEqual(len({v[3] for v in vals}), 1)
                leases = [v[2] for v in vals]
                poll_tags = [client.send(request(3, ident)) for ident in leases]
                polled = [client.receive() for _ in poll_tags]
                self.assertTrue(all(row[2] == 64 for row in polled))
                values = [struct.unpack('<7Q', row[3][8:]) for row in polled]
                self.assertEqual(sum(v[1] == 0 for v in values), 1)
                held = next(v[2] for v in values if v[1] == 0)
                pending = [v[2] for v in values if v[1] == 1]
                for ident in pending: client.call(request(4, ident))
                unlocked, _, _ = client.call(request(5, held)); self.assertEqual(unlocked[-1], 0)
                for ident in leases: client.call(request(6, ident))
                observations.append({'round': round_index, 'admissions': tags, 'polls': poll_tags,
                    'held': held, 'cancelled': pending})
            leases = []
            for group in range(520):
                tags = [client.send(request(1, kind=1, path=f'growth-{group}-{i}'.encode())) for i in range(4)]
                rows = [client.receive() for _ in tags]
                self.assertEqual({r[0] for r in rows}, set(tags))
                self.assertTrue(all(r[2] == 64 for r in rows))
                leases.extend(struct.unpack_from('<Q', r[3], 24)[0] for r in rows)
            self.assertEqual(len(set(leases)), 2080)
            status, _, _ = client.call(request(7)); self.assertEqual(status[5], 2080)
            self.assertGreaterEqual(status[4], 2080)
            for start in range(0, len(leases), 4):
                tags = [client.send(request(6, ident)) for ident in leases[start:start + 4]]
                rows = [client.receive() for _ in tags]
                self.assertEqual({r[0] for r in rows}, set(tags)); self.assertTrue(all(r[2] == 64 for r in rows))
            status, _, _ = client.call(request(7)); self.assertEqual(status[5], 0)
            actual = client.finish()
            self.assertEqual(len(actual['native_thread_ids']), 4)
        finally: client.abort()
        self.assertEqual(snapshot(fixture), before_fixture)
        archived = retire(fixture, out / 'fixture.json.gz')
        (out / 'schedule.json').write_text(json.dumps(observations, sort_keys=True, indent=2) + '\n')
        RESULTS['concurrent'] = {'status': 'PASS', 'process': actual, 'alias_mutual_exclusion_rounds': 128,
            'retained_growth_leases': 2080, 'schedule': record(out / 'schedule.json'), 'fixture': archived,
            'automatic_await_scheduler_closed': False, 'fresh_original_status': 'PENDING'}


def main():
    global OPTIONS, ARTIFACTS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=os.environ.get('HIA_FILE_LOCK_SERVICE_MANIFEST'))
    parser.add_argument('--executable', type=Path)
    parser.add_argument('--state-corpus', type=Path, default=os.environ.get('HIA_FILE_LOCK_STATE_CORPUS_DIR'))
    parser.add_argument('--output', type=Path, default=os.environ.get('HIA_FILE_LOCK_SERVICE_CORPUS_DIR'))
    OPTIONS = parser.parse_args()
    if OPTIONS.state_corpus is None or OPTIONS.output is None:
        parser.error('complete state corpus and new output directory are required')
    if OPTIONS.bundle is not None:
        OPTIONS.bundle = OPTIONS.bundle.resolve(strict=True)
        ARTIFACTS = inspect_bundle(OPTIONS.bundle, source_root=ROOT)
        selected = OPTIONS.bundle.parent / 'file-lock-service.elf'
        if OPTIONS.executable is not None and OPTIONS.executable.resolve(strict=True) != selected:
            parser.error('executable override differs from the inspected bundle')
        OPTIONS.executable = selected
    elif OPTIONS.executable is None:
        parser.error('source-bound bundle is required; an explicit executable is development-only')
    OPTIONS.executable = OPTIONS.executable.resolve(strict=True)
    OPTIONS.output = OPTIONS.output.resolve(); OPTIONS.output.mkdir()
    OPTIONS.state_corpus = OPTIONS.state_corpus.resolve(strict=True)
    sources_before = {name: record(ROOT / name) for name in SOURCES}
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Service)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    assert sources_before == {name: record(ROOT / name) for name in SOURCES}
    if OPTIONS.bundle is not None:
        assert inspect_bundle(OPTIONS.bundle, source_root=ROOT) == ARTIFACTS
    value = {'schema': 'hepta.runtime.file-lock-service-native.v1',
        'status': 'PASS' if result.wasSuccessful() else 'FAIL', 'groups': result.testsRun,
        'elapsed': time.monotonic() - started, 'results': RESULTS,
        'executable': record(OPTIONS.executable), 'bundle_artifacts': ARTIFACTS,
        'bundle_path': None if OPTIONS.bundle is None else str(OPTIONS.bundle),
        'state_corpus': str(OPTIONS.state_corpus), 'sources': sources_before, 'actual_original_calls': 0,
        'original_status': 'PENDING', 'production_activated': False, 'full_edit_chain_closed': False}
    (OPTIONS.output / 'result.json').write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    summary = {key: value[key] for key in ('status', 'groups', 'elapsed', 'actual_original_calls', 'original_status')}
    summary['result'] = record(OPTIONS.output / 'result.json')
    print(json.dumps(summary))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__': main()
