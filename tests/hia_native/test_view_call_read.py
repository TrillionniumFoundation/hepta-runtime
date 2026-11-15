#!/usr/bin/env python3
"""Actual HIA read owner and ELF I/O; completion controls are separate evidence.

This fixture does not dispatch MCP view or perform cache/range logic. All ELF
input, output and effect bytes are retained without truncation.
"""
from __future__ import annotations
import ctypes
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('_view_call_loader', ROOT / 'scripts/hia_native_loader.py')
loader = importlib.util.module_from_spec(spec); spec.loader.exec_module(loader)
INVALID, CAPACITY, GROW, PENDING, CANCEL_WAIT = 0xffffffff, 0xfffffffe, 0xffffffd0, 0xfffffff0, 0xffffffef
MAX = (1 << 64) - 1
COUNTS = dict(direct_calls=0, direct_sessions=0, driver_relocations=0, private_completion_controls=0,
              private_counter_faults=0,
              elf_processes=0, actual_effect_receipts=0, actual_read_attempts=0,
              actual_read_bytes=0, actual_opens=0, actual_closes=0)
EVENTS, PROCESSES = [], []
CAPTURE = RAW_CALLS = None

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def frame(operation, generation=0, path=b'', reserved=(0, 0, 0, 0)):
    return struct.pack('<8s7Q', b'HVRDQ001', operation, generation, len(path), *reserved) + path

def response(raw):
    assert len(raw) >= 80 and raw[:8] == b'HVRDR001'
    keys = ('generation', 'operation', 'outcome', 'errno', 'mode', 'metadata_size',
            'snapshot_offset', 'snapshot_length', 'read_attempts')
    return dict(zip(keys, struct.unpack_from('<9Q', raw, 8)))

class Arena:
    def __init__(self, module, workspace=131072, output=80):
        self.module = module
        self.session = module.session(workspace_capacity=workspace, output_capacity=output)
        COUNTS['direct_sessions'] += 1; self.identity = COUNTS['direct_sessions']
        EVENTS.append(dict(kind='session_create', session=self.identity, workspace=workspace,
                           output=output, after_call=COUNTS['direct_calls']))

    def snapshot(self):
        return ctypes.string_at(self.session._workspace, self.session.workspace_capacity)

    def write(self, offset, raw):
        assert 0 <= offset <= self.session.workspace_capacity - len(raw)
        ctypes.memmove(ctypes.addressof(self.session._workspace) + offset, raw, len(raw))

    def word(self, offset, value=None):
        if value is not None: self.write(offset, struct.pack('<Q', value))
        return struct.unpack_from('<Q', self.snapshot(), offset)[0]

    def call(self, wire):
        ctypes.memset(self.session._output, 0xa5, self.session.output_capacity)
        code, out, state = self.session.invoke_raw(wire)
        COUNTS['direct_calls'] += 1
        RAW_CALLS.write(struct.pack('<7Q', COUNTS['direct_calls'], self.identity, len(wire),
                                   self.session.workspace_capacity, self.session.output_capacity,
                                   code, len(out)) + wire + out + state)
        if code != 80: assert out == b'\xa5' * self.session.output_capacity
        return code, out[:code] if code < 0xffff0000 else b''

    def effect(self):
        raw = self.snapshot()[512:640]; assert raw[:8] == b'HVRDFX01'
        names = ('magic', 'sequence', 'generation', 'kind', 'a', 'b', 'c', 'd',
                 'completion_sequence', 'completion_generation', 'result', 'errno',
                 'mode', 'size', 'reserved0', 'reserved1')
        return dict(zip(names, struct.unpack('<8s15Q', raw)))

    def complete(self, result=0, errno=0, mode=0, size=0, data=b''):
        effect = self.effect(); assert effect['completion_sequence'] == 0
        if errno: result = (-errno) & MAX
        if data:
            assert effect['kind'] == 3 and len(data) == result <= effect['c']
            self.write(effect['b'], data)
        self.write(576, struct.pack('<8Q', effect['sequence'], effect['generation'],
                                    result, errno, mode, size, 0, 0))
        COUNTS['private_completion_controls'] += 1
        EVENTS.append(dict(kind='private_completion_control', session=self.identity,
                           sequence=effect['sequence'], generation=effect['generation'],
                           effect_kind=effect['kind'], result=result, errno=errno, mode=mode,
                           size=size, data_bytes=len(data), data_sha256=sha(data), after_call=COUNTS['direct_calls']))

    def relocate(self):
        old = self.session; record = self.snapshot()[640:664]
        assert record[:8] == b'HVRDG001'
        sequence, required = struct.unpack_from('<2Q', record, 8)
        assert sequence == self.word(136) and required > old.workspace_capacity
        capacity = max(required, old.workspace_capacity * 2)
        new = self.module.session(workspace_capacity=capacity, output_capacity=old.output_capacity)
        ctypes.memmove(new._workspace, old._workspace, old.workspace_capacity)
        self.session = new; old.close(); COUNTS['driver_relocations'] += 1
        EVENTS.append(dict(kind='relocation', session=self.identity, sequence=sequence,
                           required=required, capacity=capacity, after_call=COUNTS['direct_calls']))

    def advance(self, wire):
        while True:
            code, output = self.call(wire)
            if code != GROW: return code, output
            self.relocate()

    def refuse(self, wire, expected=INVALID):
        before = self.snapshot(); code, output = self.call(wire)
        assert (code, output) == (expected, b''), (code, expected)
        assert self.snapshot() == before

    def close(self):
        EVENTS.append(dict(kind='session_close', session=self.identity, after_call=COUNTS['direct_calls']))
        self.session.close()

def parse_receipts(raw):
    assert len(raw) % 128 == 0
    rows, slot, sequence = [], MAX, 0
    for at in range(0, len(raw), 128):
        fields = struct.unpack_from('<8s15Q', raw, at); assert fields[0] == b'HVRDACK1'
        seq, gen, kind, a, b, c, d, result, normalized, errno, mode, size, before, after, duplicate = fields[1:]
        assert seq == sequence + 1 == duplicate and gen > 0 and kind in (1, 2, 3, 4)
        assert before == slot
        signed = result if result < 1 << 63 else result - (1 << 64)
        if signed < 0: assert errno == -signed and normalized == result and mode == size == 0
        else: assert errno == 0
        if kind == 1:
            assert a == 4096 and c == 1024 and d == 144 and slot == MAX == after
            assert normalized == (0 if signed >= 0 else result)
        elif kind == 2:
            assert a == 4096 and c == os.O_CLOEXEC and d == 0 and slot == MAX
            assert after == (result if signed >= 0 else MAX)
            assert normalized == (0 if signed >= 0 else result)
            if signed >= 0: COUNTS['actual_opens'] += 1
        elif kind == 3:
            assert a == 0 and c == 65536 and d == 0 and slot != MAX and after == slot
            assert normalized == result and (signed < 0 or signed <= 65536)
            COUNTS['actual_read_attempts'] += 1; COUNTS['actual_read_bytes'] += max(0, signed)
        else:
            assert a == b == c == d == 0 and slot != MAX and after == MAX
            COUNTS['actual_closes'] += 1
            assert normalized == (0 if signed >= 0 else result)
        rows.append(dict(sequence=seq, generation=gen, kind=kind, result=signed,
                         errno=errno, mode=mode, size=size, before=before, after=after))
        slot, sequence = after, seq
    assert slot == MAX, 'ELF fixture leaked its retained descriptor'
    COUNTS['actual_effect_receipts'] += len(rows)
    return rows

def run_elf(elf, name, frames, *, cwd=None, expected_exit=0):
    wire = b''.join(struct.pack('<Q', len(value)) + value for value in frames)
    command = [str(elf)]; started = time.monotonic()
    proc = subprocess.run(command, input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          cwd=cwd, timeout=45)
    elapsed = time.monotonic() - started
    for extension, raw in (('input.bin.gz', wire), ('stdout.bin.gz', proc.stdout), ('stderr.bin.gz', proc.stderr)):
        with gzip.open(CAPTURE / (name + '.' + extension), 'xb') as stream: stream.write(raw)
    row = dict(name=name, command=command, cwd=str(cwd) if cwd else None, timeout_seconds=45,
               elapsed_seconds=elapsed, exit_code=proc.returncode, input_bytes=len(wire),
               input_sha256=sha(wire), stdout_bytes=len(proc.stdout), stdout_sha256=sha(proc.stdout),
               stderr_bytes=len(proc.stderr), stderr_sha256=sha(proc.stderr))
    PROCESSES.append(row); COUNTS['elf_processes'] += 1
    assert proc.returncode == expected_exit, row
    receipts = parse_receipts(proc.stderr); out, at = [], 0
    while at < len(proc.stdout):
        code, length = struct.unpack_from('<2Q', proc.stdout, at); at += 16
        payload = proc.stdout[at:at + length]; assert len(payload) == length; at += length
        assert code == 80 or length == 0
        if code == 80: assert length == 80 + response(payload)['snapshot_length']
        out.append((code, payload))
    assert at == len(proc.stdout)
    return out, receipts

class ReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_VIEW_READ_MANIFEST']).resolve()
        cls.fixture = Path(os.environ['HIA_VIEW_READ_FIXTURE_MANIFEST']).resolve()
        cls.module = loader.NativeModule(cls.manifest, manifest_sha256=sha(cls.manifest.read_bytes()))
        cls.fixture_meta = json.loads(cls.fixture.read_text()); cls.elf = cls.fixture.parent / cls.fixture_meta['elf']
        assert sha(cls.elf.read_bytes()) == cls.fixture_meta['elf_sha256']
        assert cls.fixture_meta['owner_manifest_sha256'] == sha(cls.manifest.read_bytes())
        assert cls.fixture_meta['owner_image_sha256'] == cls.module.metadata['image_sha256']
        cls.identities = {str(path): sha(path.read_bytes()) for path in (
            cls.manifest, cls.fixture, cls.elf, Path(__file__),
            cls.manifest.parent / cls.module.metadata['source'], cls.manifest.parent / cls.module.metadata['image'])}

    @classmethod
    def tearDownClass(cls):
        assert cls.identities == {path: sha(Path(path).read_bytes()) for path in cls.identities}
        cls.module.close()

    def test_01_malformed_and_borrowed_capacity(self):
        valid = frame(1, path=b'file')
        mutations = [valid[:i] for i in (0, 7, 8, 16, 24, 32, 63)]
        mutations += [b'badmagic' + valid[8:], frame(0), frame(5), frame(1, generation=1, path=b'file'),
                      frame(3), frame(4), valid + b'x']
        for i in range(4):
            words = [0] * 4; words[i] = 1; mutations.append(frame(1, path=b'file', reserved=words))
        for wire in mutations:
            arena = Arena(self.module)
            try: arena.refuse(wire)
            finally: arena.close()
        for workspace, output in [(4095, 80), (4096, 79), (0, 80)]:
            arena = Arena(self.module, workspace, output)
            try: arena.refuse(valid, CAPACITY)
            finally: arena.close()

    def test_02_pending_identity_and_completion_refusals(self):
        arena = Arena(self.module); wire = frame(1, path=b'file')
        try:
            self.assertEqual(arena.call(wire)[0], PENDING)
            before = arena.snapshot(); effect = arena.effect()
            self.assertEqual(arena.call(wire)[0], PENDING); self.assertEqual(arena.snapshot(), before)
            for other in (frame(1, path=b'fild'), frame(2, path=b'file'), frame(3, effect['generation'] + 1), frame(4, effect['generation'])):
                arena.refuse(other)
            arena.complete(mode=stat.S_IFREG | 0o600, size=123); admitted = arena.snapshot()
            for offset, value in [(576, effect['sequence'] + 1), (584, effect['generation'] + 1),
                                  (624, 1), (632, 1), (536, 3), (544, 4097)]:
                arena.write(0, admitted); arena.word(offset, value); arena.refuse(wire)
            arena.write(0, admitted); code, result = arena.call(wire)
            self.assertEqual(code, 80); self.assertEqual(response(result)['metadata_size'], 123)
            frozen = arena.snapshot(); self.assertEqual(arena.call(wire), (code, result)); self.assertEqual(arena.snapshot(), frozen)
            self.assertEqual(response(arena.call(frame(4, effect['generation']))[1])['outcome'], 5)
        finally: arena.close()

    def test_03_stat_errors_cancel_drop_and_reuse(self):
        arena = Arena(self.module); wire = frame(1, path=b'first')
        try:
            self.assertEqual(arena.call(wire)[0], PENDING); gen = arena.effect()['generation']; cancel = frame(3, gen)
            self.assertEqual(arena.call(cancel)[0], CANCEL_WAIT); arena.complete(mode=stat.S_IFREG | 0o600, size=7)
            result = response(arena.call(cancel)[1]); self.assertEqual(result['outcome'], 4); self.assertEqual(result['snapshot_length'], 0)
            self.assertEqual(response(arena.call(frame(4, gen))[1])['outcome'], 5)
            self.assertEqual(arena.call(frame(1, path=b'next'))[0], PENDING); self.assertEqual(arena.effect()['generation'], gen + 1)
            arena.refuse(cancel); arena.complete(MAX, errno=2)
            result = response(arena.call(frame(1, path=b'next'))[1]); self.assertEqual((result['outcome'], result['errno']), (1, 2))
        finally: arena.close()

    def test_04_utf8_fragments_eintr_and_retained_snapshot(self):
        arena = Arena(self.module, workspace=8192); wire = frame(2, path=b'file')
        try:
            self.assertEqual(arena.advance(wire)[0], PENDING); arena.complete(); self.assertEqual(arena.advance(wire)[0], PENDING)
            self.assertEqual(arena.effect()['kind'], 3)
            pieces = [b'a\x00\r', b'\n\xf0', b'\x9f', b'\x99\x82', b'\xe4\xb8', b'\xad']
            for index, piece in enumerate(pieces):
                if index == 2:
                    old_sequence = arena.effect()['sequence']; arena.complete(MAX, errno=4)
                    self.assertEqual(arena.advance(wire)[0], PENDING); self.assertGreater(arena.effect()['sequence'], old_sequence)
                arena.complete(len(piece), data=piece); self.assertEqual(arena.advance(wire)[0], PENDING)
            arena.complete(); self.assertEqual(arena.advance(wire)[0], PENDING); self.assertEqual(arena.effect()['kind'], 4)
            arena.complete(MAX, errno=4); code, raw = arena.call(wire); value = response(raw)
            self.assertEqual(code, 80); self.assertEqual(value['outcome'], 0); self.assertEqual(value['read_attempts'], len(pieces) + 2)
            start, size = value['snapshot_offset'], value['snapshot_length']; self.assertEqual(arena.snapshot()[start:start + size], b''.join(pieces))
            before = arena.snapshot(); arena.refuse(frame(2, path=b'other')); self.assertEqual(arena.call(wire), (80, raw)); self.assertEqual(arena.snapshot(), before)
            self.assertEqual(response(arena.call(frame(4, value['generation']))[1])['outcome'], 5)
            self.assertEqual(arena.snapshot()[start:start + size], b'\0' * size)
        finally: arena.close()

    def test_05_invalid_utf8_read_error_precedence(self):
        for final_errno, expected in [(0, (3, 0)), (5, (1, 5))]:
            arena = Arena(self.module); wire = frame(2, path=b'file')
            try:
                self.assertEqual(arena.advance(wire)[0], PENDING); arena.complete(); self.assertEqual(arena.advance(wire)[0], PENDING)
                arena.complete(3, data=b'\xff\x00a'); self.assertEqual(arena.advance(wire)[0], PENDING)
                arena.complete(MAX if final_errno else 0, errno=final_errno); self.assertEqual(arena.advance(wire)[0], PENDING)
                self.assertEqual(arena.effect()['kind'], 4); arena.complete(); value = response(arena.call(wire)[1])
                self.assertEqual((value['outcome'], value['errno']), expected); self.assertEqual(value['snapshot_length'], 0)
            finally: arena.close()

    def test_06_cancel_late_open_and_late_read(self):
        for phase in ('open', 'read'):
            arena = Arena(self.module); wire = frame(2, path=b'file')
            try:
                self.assertEqual(arena.advance(wire)[0], PENDING); gen = arena.effect()['generation']
                if phase == 'read': arena.complete(); self.assertEqual(arena.advance(wire)[0], PENDING)
                cancel = frame(3, gen); self.assertEqual(arena.call(cancel)[0], CANCEL_WAIT); arena.refuse(frame(4, gen))
                arena.complete(3 if phase == 'read' else 0, data=b'xyz' if phase == 'read' else b'')
                self.assertEqual(arena.advance(cancel)[0], PENDING); self.assertEqual(arena.effect()['kind'], 4); arena.complete()
                result = response(arena.call(cancel)[1]); self.assertEqual((result['outcome'], result['snapshot_length']), (4, 0)); self.assertEqual(arena.word(104), 0)
                self.assertEqual(response(arena.call(frame(4, gen))[1])['outcome'], 5)
                self.assertEqual(arena.advance(wire)[0], PENDING); self.assertEqual(arena.effect()['generation'], gen + 1); arena.refuse(cancel)
            finally: arena.close()

    def test_07_actual_elf_files_utf8_links_and_growth(self):
        with tempfile.TemporaryDirectory(prefix='view-read-files-', dir=CAPTURE) as tmp:
            directory = Path(tmp); content = b'alpha\r\n\0' + '中🙂'.encode()
            values = [(b'empty', b''), (b'text', content), (b'split', b'a' * 65535 + '🙂\n中'.encode()),
                      (b'invalid', b'a' * 65535 + b'\xf0\x9f\x99'),
                      (b'big', b'first\n' + b'q' * ((17 << 20) + 3) + b'\nlast\n'), (b'raw-\xff', b'raw\n')]
            for name, value in values:
                with open(os.fsencode(directory) + b'/' + name, 'wb') as stream: stream.write(value)
            os.symlink(b'text', os.fsencode(directory) + b'/symlink'); os.link(directory / 'text', directory / 'hardlink')
            values += [(b'symlink', content), (b'hardlink', content)]
            for index, (name, value) in enumerate(values):
                output, receipts = run_elf(self.elf, f'file-{index}', [frame(1, path=name), frame(4, 1), frame(2, path=name), frame(4, 2)], cwd=directory)
                self.assertEqual(len(output), 4); self.assertEqual(response(output[0][1])['metadata_size'], len(value)); self.assertTrue(stat.S_ISREG(response(output[0][1])['mode']))
                result = response(output[2][1]); self.assertEqual(result['generation'], 2)
                if name == b'invalid': self.assertEqual((result['outcome'], result['snapshot_length']), (3, 0))
                else: self.assertEqual(result['outcome'], 0); self.assertEqual(output[2][1][80:], value)
                self.assertEqual([row['kind'] for row in receipts if row['kind'] in (1, 2, 4)], [1, 2, 4])
                self.assertEqual(sum(row['kind'] == 3 for row in receipts), result['read_attempts'])

    def test_08_actual_elf_os_errors_and_nul_no_effect(self):
        with tempfile.TemporaryDirectory(prefix='view-read-errors-', dir=CAPTURE) as tmp:
            directory = Path(tmp); (directory / 'dir').mkdir()
            values = [(b'absent', 1, 1, 2), (b'absent', 2, 1, 2), (b'dir', 2, 1, 21),
                      (b'a\0b', 1, 2, 0), (b'a\0b', 2, 2, 0), (b'x' * 300, 1, 1, 36)]
            for index, (name, operation, outcome, errno) in enumerate(values):
                output, receipts = run_elf(self.elf, f'error-{index}', [frame(operation, path=name), frame(4, 1)], cwd=directory)
                value = response(output[0][1]); self.assertEqual((value['outcome'], value['errno'], value['snapshot_length']), (outcome, errno, 0))
                if b'\0' in name: self.assertEqual(receipts, [])

    def test_09_private_counter_exhaustion_preserves_refusal_state(self):
        # These are explicit private-state fault controls, not original Rust
        # requests or a claim that normal callers can reach these counters.
        for name, offsets, read_pending, capacity in [
            ('initial-generation', (8,), False, 131072),
            ('initial-effect-sequence', (32,), False, 131072),
            ('initial-growth-sequence', (136,), False, 4096),
            ('completed-read-count', (152,), True, 131072),
            ('closing-effect-sequence', (32, 520), True, 131072),
            ('next-window-growth-sequence', (136,), True, 131072),
        ]:
            with self.subTest(counter=name):
                arena = Arena(self.module, workspace=capacity); wire = frame(2, path=b'file')
                try:
                    if read_pending:
                        self.assertEqual(arena.advance(wire)[0], PENDING)
                        arena.complete()
                        self.assertEqual(arena.advance(wire)[0], PENDING)
                        self.assertEqual(arena.effect()['kind'], 3)
                    for offset in offsets: arena.word(offset, MAX)
                    COUNTS['private_counter_faults'] += 1
                    EVENTS.append(dict(kind='private_counter_fault', session=arena.identity,
                                       control=name, writes=[[offset, MAX] for offset in offsets],
                                       after_call=COUNTS['direct_calls']))
                    if read_pending:
                        data = b'x' * 65536 if name == 'next-window-growth-sequence' else b''
                        arena.complete(len(data), data=data)
                    arena.refuse(wire, CAPACITY)
                finally:
                    arena.close()

def main():
    global CAPTURE, RAW_CALLS
    location = os.environ.get('HIA_VIEW_READ_CAPTURE_DIR') or os.environ['HIA_VIEW_CALL_CAPTURE_DIR']
    CAPTURE = Path(location).resolve(); CAPTURE.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with gzip.open(CAPTURE / 'read-direct-calls.bin.gz', 'xb') as RAW_CALLS:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReadTests))
    summary = dict(schema='hepta.runtime.view-read-native-tests.v1', status='PASS' if result.wasSuccessful() else 'FAIL',
                   test_groups=result.testsRun, expected_groups=9, skipped=len(result.skipped), failures=len(result.failures),
                   errors=len(result.errors), counts=COUNTS, elapsed_seconds=time.monotonic()-started,
                   test_sha256=sha(Path(__file__).read_bytes()), processes=PROCESSES, events=EVENTS,
                   identities=getattr(ReadTests, 'identities', {}), original_rust_comparison='separate recipe',
                   public_mcp_route_replaced=False, whole_view_replaced=False, whole_runtime_replaced=False)
    (CAPTURE / 'read-native-result.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
    print(json.dumps(summary, sort_keys=True))
    return 0 if result.wasSuccessful() and result.testsRun == 9 and not result.skipped else 1

if __name__ == '__main__':
    raise SystemExit(main())
