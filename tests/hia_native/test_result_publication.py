"""Actual HIA owner and ELF publication qualification; no semantic fallback.

Direct relocation is a test transport. ELF receipts separately establish native
write/ACK behavior. Complete semantic input/output pairs are retained for the
independent original-Rust replay. Private counter fault cases are not Rust inputs.
"""
from __future__ import annotations
import ctypes
import fcntl
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import resource
import select
import selectors
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
ORACLE_CASES = ROOT / 'tests/hia_native/result_publication_oracle/cases.py'
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeCapacityError, NativeModule, NativeRejected

INVALID, CAPACITY, STATE, GROW = 0xffffffff, 0xfffffffe, 0xfffffffd, 0xffffffd0
MIN_WORK, INITIAL_WORK, WINDOW = 73728, 131072, 65536
OUTPUT, MAX = WINDOW + 64, (1 << 64) - 1
WARNING = '⚠️ '.encode()
COUNTS = dict(native_calls=0, successful_calls=0, invalid_refusals=0,
              capacity_refusals=0, state_refusals=0, growth_requests=0,
              other_refusals=0,
              driver_mapping_relocations=0, sessions=0, semantic_cases=0,
              semantic_output_bytes=0, actual_elf_processes=0,
              partial_acknowledgements=0, repeated_pulls=0,
              private_counter_fault_cases=0, kernel_write_receipts=0,
              kernel_partial_writes=0, kernel_eagain=0,
              kernel_allocation_failures=0, elf_owner_frames=0)
CAPTURE = CALLS = EVENTS = SEMANTIC = None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def frame(op, generation=0, sequence=0, arg0=0, arg1=0, payload=b'', reserved=0):
    return b'HRPQ0001' + struct.pack('<7Q', op, generation, sequence, arg0,
                                    arg1, len(payload), reserved) + payload


def response(raw):
    assert len(raw) >= 64 and raw[:8] == b'HRPR0001', raw[:64].hex()
    status, generation, phase, a, b, confirmed, flags = struct.unpack_from('<7Q', raw, 8)
    assert status == 0 and phase <= 5 and flags <= 3, raw[:64].hex()
    assert bool(flags & 1) == bool(confirmed), raw[:64].hex()
    return dict(generation=generation, phase=phase, arg0=a, arg1=b,
                confirmed=confirmed, flags=flags, payload=raw[64:])


def event(kind, **fields):
    if EVENTS is not None:
        EVENTS.write((json.dumps(dict(kind=kind, **fields), sort_keys=True) + '\n').encode())


def record_call(arena, wire, code, output):
    COUNTS['native_calls'] += 1
    key = {INVALID: 'invalid_refusals', CAPACITY: 'capacity_refusals', STATE: 'state_refusals',
           GROW: 'growth_requests'}.get(code, 'successful_calls' if code < 0xffff0000 else 'other_refusals')
    COUNTS[key] += 1
    if CALLS is not None:
        CALLS.write(struct.pack('<7Q', COUNTS['native_calls'], arena.identity,
                                arena.session.workspace_capacity, arena.session.output_capacity,
                                len(wire), code, len(output)))
        CALLS.write(wire); CALLS.write(output)


def cases_module():
    spec = importlib.util.spec_from_file_location('publication_independent_cases', ORACLE_CASES)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected(base, hints=(), mode=0, is_error=False, prefix=b''):
    composed = base
    if hints:
        composed += b'\n\n' + b''.join(WARNING + hint + b'\n' for hint in hints)
    if mode == 0:
        return composed
    quoted = json.dumps(composed.decode('utf-8'), ensure_ascii=False, separators=(',', ':')).encode()
    if mode == 1:
        return quoted
    suffix = b'}],"isError":' + (b'true' if is_error else b'false') + b'}'
    if mode == 2:
        return b'{"content":[{"type":"text","text":' + quoted + suffix
    assert mode == 3 and prefix
    return prefix + quoted + suffix + b'}'


def segments(raw):
    at = 0
    for size in (1, 2, 3, 5, 7, 251, 4093, 65537):
        if at == len(raw):
            return
        yield raw[at:at + size]
        at = min(at + size, len(raw))
    while at < len(raw):
        yield raw[at:at + 262147]
        at += 262147


def construction_frames(base, hints=(), mode=0, is_error=False, prefix=b''):
    yield frame(1, arg0=mode, arg1=int(is_error))
    def chunks(op, value):
        for at in range(0, len(value), 65521):
            yield frame(op, 1, payload=value[at:at + 65521])
    if mode == 3:
        yield from chunks(13, prefix)
    yield from chunks(2, base)
    yield frame(3, 1)
    for hint in hints:
        yield frame(4, 1); yield from chunks(5, hint); yield frame(6, 1)
    yield frame(7, 1)


def framed_stream(frames):
    return b''.join(struct.pack('<Q', len(wire)) + wire for wire in frames)


def save_process(name, wire, output, receipts, **metadata):
    if CAPTURE is not None:
        folder = CAPTURE / 'elf'; folder.mkdir(exist_ok=True)
        streams = {}
        for suffix, data in (('input', wire), ('stdout', output), ('stderr', receipts)):
            (folder / f'{name}.{suffix}.bin.gz').write_bytes(gzip.compress(data, mtime=0))
            streams['stdin' if suffix == 'input' else suffix] = dict(file=f'elf/{name}.{suffix}.bin.gz',
                  bytes=len(data), sha256=sha(data))
        (folder / f'{name}.json').write_text(json.dumps(dict(schema='hepta.runtime.result-publication-elf-process.v1',
               name=name, **streams, **metadata), indent=2, sort_keys=True) + '\n')


def save_publisher_case(case, run_id, actual):
    if CAPTURE is not None:
        folder = CAPTURE / 'publisher'; folder.mkdir(exist_ok=True)
        logical = cases_module().encode_cases([case])
        path = folder / f'{run_id}.input.bin.gz'
        path.write_bytes(gzip.compress(logical, mtime=0))
        row = dict(case_id=case['case_id'], run_id=run_id, mode=case['mode'], is_error=case['is_error'],
                   input_path=str(path.relative_to(CAPTURE)), input_bytes=len(logical), input_sha256=sha(logical),
                   output_path=f'elf/{run_id}.stdout.bin.gz', output_bytes=len(actual), output_sha256=sha(actual))
        with (CAPTURE / 'publisher-cases.jsonl').open('a') as stream:
            stream.write(json.dumps(row, sort_keys=True) + '\n')


def read_receipts(raw, *, allow_error=False):
    assert len(raw) % 64 == 0, raw.hex()
    parsed, confirmed, sequence, offset = [], 0, None, 0
    for at in range(0, len(raw), 64):
        rec = raw[at:at + 64]
        assert rec[:8] == b'HRPWACK1', rec.hex()
        gen, seq, off, attempted, result, actual_confirmed, ack = struct.unpack_from('<7Q', rec, 8)
        assert gen == 1 and seq > 0 and 0 < attempted <= WINDOW
        signed = result if result < (1 << 63) else result - (1 << 64)
        if sequence is not None:
            if seq == sequence:
                assert off == offset
            else:
                assert seq == sequence + 1 and off == 0
        sequence = seq
        COUNTS['kernel_write_receipts'] += 1
        if signed > 0:
            assert signed <= attempted and ack == 64
            confirmed += signed; offset = off + signed
            if signed < attempted:
                COUNTS['kernel_partial_writes'] += 1
        else:
            assert ack == MAX and (signed in (-4, -11) or allow_error)
            offset = off
            if signed == -11:
                COUNTS['kernel_eagain'] += 1
        assert actual_confirmed == confirmed, (actual_confirmed, confirmed)
        parsed.append(dict(generation=gen, sequence=seq, offset=off, attempted=attempted,
                           result=signed, confirmed=confirmed, ack_return=ack))
    return parsed, confirmed


def run_publisher(elf, name, wire, *, nonblocking=False, hold_until_eagain=False, broken=False, timeout=60):
    """Retain a parent descriptor to the same OFD, then verify its flags."""
    read_fd, write_fd = os.pipe()
    fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
    original_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
    if nonblocking:
        fcntl.fcntl(write_fd, fcntl.F_SETFL, original_flags | os.O_NONBLOCK)
    before_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
    if broken:
        os.close(read_fd); read_fd = None
    else:
        os.set_blocking(read_fd, False)
    output, receipts, error, code, after_flags = bytearray(), bytearray(), None, None, None
    command = [str(elf), '--publish-fixture']
    timed_out = False
    child = None
    try:
        with tempfile.TemporaryFile() as source:
            source.write(wire); source.seek(0)
            child = subprocess.Popen(command, stdin=source, stdout=write_fd,
                                     stderr=subprocess.PIPE, close_fds=True)
            COUNTS['actual_elf_processes'] += 1
            os.set_blocking(child.stderr.fileno(), False)
            deadline = time.monotonic() + timeout
            released = not hold_until_eagain
            with selectors.DefaultSelector() as ready:
                ready.register(child.stderr.fileno(), selectors.EVENT_READ, 'receipts')
                if read_fd is not None and released:
                    ready.register(read_fd, selectors.EVENT_READ, 'output')
                while True:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        raise TimeoutError(f'publisher timeout: {name}')
                    for key, _ in ready.select(0.1):
                        try:
                            data = os.read(key.fd, 997 if key.data == 'output' else 65536)
                        except BlockingIOError:
                            continue
                        if data:
                            (output if key.data == 'output' else receipts).extend(data)
                        elif key.data == 'receipts':
                            ready.unregister(key.fd)
                    if not released:
                        for at in range(0, len(receipts) - 63, 64):
                            if struct.unpack_from('<Q', receipts, at + 40)[0] == (1 << 64) - 11:
                                released = True
                                ready.register(read_fd, selectors.EVENT_READ, 'output')
                                break
                    if child.poll() is not None:
                        code = child.wait()
                        for fd, target in ((read_fd, output), (child.stderr.fileno(), receipts)):
                            if fd is None:
                                continue
                            while True:
                                try:
                                    data = os.read(fd, 65536)
                                except BlockingIOError:
                                    break
                                if not data:
                                    break
                                target.extend(data)
                        break
            after_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
            if hold_until_eagain:
                assert released, 'backpressure test did not observe a kernel EAGAIN receipt'
    except BaseException as exc:
        error = repr(exc)
        raise
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill(); child.wait()
            child.stderr.close()
        if after_flags is None:
            after_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
        save_process(name, wire, bytes(output), bytes(receipts), command=command,
                     elf_sha256=sha(elf.read_bytes()), timeout_seconds=timeout, timeout_scope='whole-process',
                     timed_out=timed_out, returncode=code if code is not None else (child.returncode if child else None),
                     before_flags=before_flags, after_flags=after_flags, error=error,
                     parent_set_nonblocking=nonblocking, broken_pipe=broken)
        os.close(write_fd)
        if read_fd is not None:
            os.close(read_fd)
    assert after_flags == before_flags, (name, before_flags, after_flags)
    return code, bytes(output), bytes(receipts)


class ElfOwner:
    """Interactive actual static owner fixture; buffers here only frame I/O."""
    def __init__(self, elf, name):
        self.name, self.inputs, self.outputs = name, bytearray(), bytearray()
        self.command, self.elf_sha256, self.timed_out = [str(elf), '--owner-fixture'], sha(elf.read_bytes()), False
        self.stderr = tempfile.TemporaryFile()
        self.child = subprocess.Popen(self.command, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=self.stderr)
        os.set_blocking(self.child.stdin.fileno(), False)
        COUNTS['actual_elf_processes'] += 1

    def read(self, count):
        result = bytearray(); deadline = time.monotonic() + 20
        while len(result) < count:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.child.stdout], [], [], left)[0]:
                self.timed_out = True
                raise TimeoutError('owner read timeout')
            chunk = os.read(self.child.stdout.fileno(), count - len(result))
            assert chunk, ('owner early EOF', self.child.poll())
            result.extend(chunk)
        self.outputs.extend(result)
        return bytes(result)

    def call(self, wire):
        record = struct.pack('<Q', len(wire)) + wire
        self.inputs.extend(record)
        position, deadline = 0, time.monotonic() + 20
        while position < len(record):
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([], [self.child.stdin], [], left)[1]:
                self.timed_out = True
                raise TimeoutError('owner write timeout')
            try:
                count = os.write(self.child.stdin.fileno(), record[position:])
            except BlockingIOError:
                continue
            assert count > 0
            position += count
        code, length = struct.unpack('<QQ', self.read(16))
        assert length <= OUTPUT
        raw = self.read(length)
        COUNTS['elf_owner_frames'] += 1
        return code, raw

    def ok(self, wire):
        code, raw = self.call(wire)
        assert code == len(raw) and code >= 64 and code < 0xffff0000, hex(code)
        return response(raw)

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.child.stdin.close()
        if kind is not None and self.child.poll() is None:
            self.child.kill()
        try:
            code = self.child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.timed_out = True; self.child.kill(); code = self.child.wait()
        self.stderr.seek(0); errors = self.stderr.read()
        save_process(self.name, bytes(self.inputs), bytes(self.outputs), errors,
                     command=self.command, elf_sha256=self.elf_sha256, timeout_seconds=20,
                     timeout_scope='each-stream-io', teardown_timeout_seconds=5, timed_out=self.timed_out,
                     returncode=code, error=repr(value) if value else None, mode='owner-fixture')
        self.child.stdout.close(); self.stderr.close()
        if kind is None:
            assert code == 0 and not errors, (code, errors)


class Arena:
    def __init__(self, module, *, workspace=INITIAL_WORK, output=OUTPUT):
        self.module = module
        self.session = module.session(workspace_capacity=workspace, output_capacity=output)
        self.generation = 0
        COUNTS['sessions'] += 1
        self.identity = COUNTS['sessions']
        event('direct_arena_create', session=self.identity, workspace_capacity=workspace,
              output_capacity=output, after_native_call=COUNTS['native_calls'])

    def snapshot(self):
        return ctypes.string_at(self.session._workspace, self.session.workspace_capacity)

    def word(self, offset, value=None):
        ptr = ctypes.addressof(self.session._workspace) + offset
        if value is not None:
            event('private_counter_injection', session=self.identity, offset=offset,
                  value=value, after_native_call=COUNTS['native_calls'])
            ctypes.memmove(ptr, struct.pack('<Q', value), 8)
        return struct.unpack('<Q', ctypes.string_at(ptr, 8))[0]

    def once(self, wire):
        ctypes.memset(self.session._output, 0xa5, self.session.output_capacity)
        try:
            raw = self.session.invoke(wire)
            code = len(raw)
        except NativeCapacityError:
            code, raw = CAPACITY, b''
        except NativeRejected as exc:
            code, raw = exc.code, b''
        if code >= 0xffff0000:
            assert ctypes.string_at(self.session._output, self.session.output_capacity) == b'\xa5' * self.session.output_capacity
        record_call(self, wire, code, raw)
        return code, raw

    def relocate(self):
        old = self.session
        record = ctypes.string_at(ctypes.addressof(old._workspace) + 512, 24)
        assert record[:8] == b'HRPGRO01', record.hex()
        sequence, required = struct.unpack_from('<QQ', record, 8)
        assert sequence and sequence == self.word(240) and required > old.workspace_capacity
        capacity = max(required, old.workspace_capacity * 2)
        assert capacity <= self.module.metadata['workspace_capacity'], capacity
        new = self.module.session(workspace_capacity=capacity, output_capacity=old.output_capacity)
        ctypes.memmove(new._workspace, old._workspace, old.workspace_capacity)
        assert ctypes.string_at(ctypes.addressof(new._workspace) + old.workspace_capacity,
                                capacity - old.workspace_capacity) == b'\0' * (capacity - old.workspace_capacity)
        COUNTS['driver_mapping_relocations'] += 1
        event('direct_driver_relocation', session=self.identity, previous=old.workspace_capacity,
              capacity=capacity, growth_sequence=sequence, required=required)
        self.session = new; old.close()

    def call(self, op, *, generation=None, sequence=0, arg0=0, arg1=0, payload=b''):
        if generation is None:
            generation = self.generation
        wire = frame(op, generation, sequence, arg0, arg1, payload)
        while True:
            code, raw = self.once(wire)
            if code != GROW:
                break
            self.relocate()
        assert code < 0xffff0000, (op, hex(code), len(payload))
        value = response(raw)
        if op == 1:
            assert value['generation'] > self.generation
            self.generation = value['generation']
        assert value['generation'] == self.generation
        if op != 9:
            assert value['payload'] == b''
        return value

    def refuse(self, wire, codes):
        before = self.snapshot()
        code, raw = self.once(wire)
        after = self.snapshot()
        if (after != before or code not in codes) and CAPTURE is not None:
            for label, body in (('before', before), ('after', after)):
                (CAPTURE / f'refusal-{COUNTS["native_calls"]}-{label}.bin.gz').write_bytes(gzip.compress(body, mtime=0))
        assert code in codes, (hex(code), [hex(x) for x in codes], wire[:64].hex())
        assert not raw and after == before, 'refusal changed the private object'
        return code

    def create(self, mode=0, is_error=False):
        return self.call(1, generation=0, arg0=mode, arg1=int(is_error))

    def append(self, op, raw):
        for chunk in segments(raw):
            self.call(op, payload=chunk)

    def construct(self, base, hints=(), mode=0, is_error=False, prefix=b''):
        self.create(mode, is_error)
        if mode == 3:
            self.append(13, prefix)
        self.append(2, base); self.call(3)
        for hint in hints:
            self.call(4); self.append(5, hint); self.call(6)
        value = self.call(7)
        assert (value['phase'], value['arg0'], value['arg1']) == (2, len(base), len(hints))

    def publish(self, *, start=True, repeat=False):
        if start:
            self.call(8)
        chunks, confirmed = [], 0
        while True:
            value = self.call(9)
            assert value['confirmed'] == confirmed and len(value['payload']) <= WINDOW
            if repeat:
                assert self.call(9) == value
                COUNTS['repeated_pulls'] += 1
            if not value['payload']:
                assert value['phase'] == 4
                break
            chunks.append(value['payload'])
            acknowledged = self.call(10, sequence=value['arg0'], arg0=value['arg1'], arg1=len(value['payload']))
            confirmed += len(value['payload'])
            assert acknowledged['confirmed'] == confirmed
        return b''.join(chunks)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        event('direct_arena_close', session=self.identity, after_native_call=COUNTS['native_calls'])
        self.session.close()


class ResultPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_RESULT_PUBLICATION_MANIFEST']).resolve()
        cls.module = NativeModule(cls.manifest, manifest_sha256=sha(cls.manifest.read_bytes()))
        assert cls.module.metadata['source_sha256'] == sha((ROOT / 'native/result_publication.hepta').read_bytes())
        assert cls.module.metadata['workspace_capacity'] >= 32 << 20

    @classmethod
    def tearDownClass(cls):
        cls.module.close()

    def fixture(self):
        path = Path(os.environ.get('HIA_RESULT_PUBLICATION_FIXTURE_MANIFEST',
                    str(self.manifest.parents[2] / 'result-publication/manifest.json'))).resolve()
        meta = json.loads(path.read_bytes()); elf = path.parent / meta['elf']
        self.assertEqual(sha(elf.read_bytes()), meta['elf_sha256'])
        self.assertEqual(meta['owner_source_sha256'], self.module.metadata['source_sha256'])
        self.assertEqual(meta['owner_manifest_sha256'], sha(self.manifest.read_bytes()))
        image = (self.manifest.parent / self.module.metadata['image']).read_bytes()
        self.assertEqual(elf.read_bytes()[meta['image_offset']:], image)
        event('actual_elf_identity', manifest=str(path), manifest_sha256=sha(path.read_bytes()),
              elf_sha256=meta['elf_sha256'], owner_image_sha256=sha(image))
        return elf

    def test_01_shared_complete_semantic_cases(self):
        corpus = cases_module()
        largest_input = largest_output = 0
        for case in corpus.iter_cases():
            with self.subTest(case=case['case_id'], name=case['name']):
                event('semantic_begin', case_id=case['case_id'], name=case['name'])
                with Arena(self.module) as arena:
                    arena.construct(case['base'], case['hints'], case['mode'], case['is_error'], case['prefix'])
                    actual = arena.publish()
                    self.assertEqual(actual, expected(case['base'], case['hints'], case['mode'], case['is_error'], case['prefix']))
                    arena.call(12)
                largest_input = max(largest_input, len(case['base']) + sum(map(len, case['hints'])))
                largest_output = max(largest_output, len(actual))
                COUNTS['semantic_cases'] += 1; COUNTS['semantic_output_bytes'] += len(actual)
                if CAPTURE is not None:
                    data = corpus.encode_cases([case]); folder = CAPTURE / 'semantic'; folder.mkdir(exist_ok=True)
                    inp = folder / f'{case["case_id"]:04d}.input.bin.gz'
                    out = folder / f'{case["case_id"]:04d}.native-output.bin.gz'
                    inp.write_bytes(gzip.compress(data, mtime=0)); out.write_bytes(gzip.compress(actual, mtime=0))
                    row = dict(case_id=case['case_id'], name=case['name'], mode=case['mode'], is_error=case['is_error'],
                               prefix_bytes=len(case['prefix']), base_bytes=len(case['base']), hint_count=len(case['hints']),
                               input_path=str(inp.relative_to(CAPTURE)), input_bytes=len(data), input_sha256=sha(data),
                               output_path=str(out.relative_to(CAPTURE)), output_bytes=len(actual), output_sha256=sha(actual))
                    SEMANTIC.write(json.dumps(row, sort_keys=True) + '\n'); SEMANTIC.flush()
                event('semantic_complete', case_id=case['case_id'], output_bytes=len(actual))
        self.assertEqual(COUNTS['semantic_cases'], 90)
        self.assertGreater(largest_input, 16 << 20); self.assertGreater(largest_output, 16 << 20)

    def test_02_utf8_fragments_invalid_retry(self):
        value = ('\0\t\n\r"\\é中🙂\U0010ffff⚠️ \u2028\u2029').encode()
        for split in range(len(value) + 1):
            with self.subTest(split=split), Arena(self.module) as arena:
                arena.create(1)
                arena.call(2, payload=value[:split]); arena.call(2, payload=value[split:]); arena.call(3); arena.call(4)
                arena.call(5, payload=value[:split]); arena.call(5, payload=value[split:]); arena.call(6); arena.call(7)
                self.assertEqual(arena.publish(), expected(value, [value], 1))
        malformed = (b'\x80', b'\xc0\x80', b'\xc1\xbf', b'\xe0\x80\x80', b'\xed\xa0\x80',
                     b'\xf0\x80\x80\x80', b'\xf4\x90\x80\x80', b'\xf5\x80\x80\x80', b'\xff')
        with Arena(self.module) as arena:
            arena.create()
            for raw in malformed:
                arena.refuse(frame(2, arena.generation, payload=raw), (INVALID,))
            arena.call(2, payload=b'\xf0\x9f')
            arena.refuse(frame(3, arena.generation), (STATE,))
            arena.refuse(frame(2, arena.generation, payload=b'x'), (INVALID,))
            arena.call(2, payload=b'\x99\x82'); arena.call(3); arena.call(4)
            arena.call(5, payload=b'\xe4')
            arena.refuse(frame(6, arena.generation), (STATE,))
            arena.call(5, payload=b'\xb8\xad'); arena.call(6); arena.call(7)
            self.assertEqual(arena.publish(), expected('🙂'.encode(), ['中'.encode()]))

    def test_03_frames_zero_workspaces_unused_fields(self):
        with Arena(self.module) as arena:
            good = frame(1)
            for size in (0, 1, 7, 8, 63):
                arena.refuse(good[:size], (CAPACITY,))
            bad = [b'BADMAGIC' + good[8:], good + b'x', frame(0), frame(14), frame(MAX),
                   frame(1, generation=1), frame(1, sequence=1), frame(1, arg0=4), frame(1, arg1=2),
                   frame(1, reserved=1), frame(1, payload=b'x')]
            for size in (1, 1 << 63, MAX):
                damaged = bytearray(good); struct.pack_into('<Q', damaged, 48, size); bad.append(bytes(damaged))
            for wire in bad:
                arena.refuse(wire, (INVALID,))
            arena.create()
            for op in (2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13):
                for field in ('sequence', 'arg0', 'arg1', 'reserved'):
                    arena.refuse(frame(op, arena.generation, **{field: 1}), (INVALID,))
        for output in (0, 1, 63):
            with Arena(self.module, output=output) as arena:
                arena.refuse(frame(1), (CAPACITY,))
        for size in (0, 1, 511, MIN_WORK - 1):
            with Arena(self.module, workspace=size) as arena:
                arena.refuse(frame(1), (CAPACITY,))
        with Arena(self.module, workspace=MIN_WORK) as arena:
            arena.construct(b''); self.assertEqual(arena.publish(), b'')

    def test_04_phase_refusals_preserve_constructed_data(self):
        with Arena(self.module) as arena:
            arena.create()
            for op in (5, 6, 7, 8, 9, 10, 13):
                arena.refuse(frame(op, arena.generation), (STATE,))
            arena.refuse(frame(1), (STATE,))
            arena.call(2, payload=b'base'); arena.call(3)
            arena.refuse(frame(3, arena.generation), (STATE,))
            arena.refuse(frame(2, arena.generation, payload=b'extra'), (STATE,))
            arena.call(4)
            arena.refuse(frame(4, arena.generation), (STATE,))
            arena.refuse(frame(7, arena.generation), (STATE,))
            arena.call(5, payload=b'hint'); arena.call(6); arena.call(4); arena.call(6); arena.call(7)
            for op in (2, 3, 4, 5, 6, 7, 9, 10, 13):
                arena.refuse(frame(op, arena.generation), (STATE,))
            self.assertEqual(arena.publish(), expected(b'base', [b'hint', b'']))

    def test_05_growth_retry_preserves_prior_object(self):
        with Arena(self.module) as arena:
            arena.create(); arena.call(2, payload=b'owned-prefix')
            wire = frame(2, arena.generation, payload=b'G' * INITIAL_WORK)
            before = bytearray(arena.snapshot()); code, raw = arena.once(wire)
            self.assertEqual((code, raw), (GROW, b'')); after = bytearray(arena.snapshot())
            for start, end in ((240, 248), (512, 536)):
                before[start:end] = after[start:end]
            self.assertEqual(before, after)
            arena.refuse(frame(2, arena.generation, payload=b'\xff'), (INVALID,))
            arena.relocate(); code, raw = arena.once(wire)
            self.assertEqual(code, 64); self.assertEqual(response(raw)['arg0'], 12 + INITIAL_WORK)
            arena.call(3); arena.call(7)
            self.assertEqual(arena.publish(), b'owned-prefix' + b'G' * INITIAL_WORK)

    def test_06_pending_pull_partial_ack_and_stale_ack(self):
        base, hints = 'B\0"\\\n🙂'.encode(), [b'', b'duplicate', b'duplicate']
        with Arena(self.module) as arena:
            arena.construct(base, hints, 1); arena.call(8); pulled = arena.call(9)
            self.assertEqual(arena.call(9), pulled); COUNTS['repeated_pulls'] += 1
            seq, offset, pending = pulled['arg0'], pulled['arg1'], pulled['payload']
            for gen, sequence, off, size in ((arena.generation + 1, seq, offset, 1),
                    (arena.generation, seq + 1, offset, 1), (arena.generation, seq, offset + 1, 1),
                    (arena.generation, seq, offset, 0), (arena.generation, seq, offset, len(pending) + 1),
                    (arena.generation, seq, offset, MAX)):
                arena.refuse(frame(10, gen, sequence, off, size), (STATE,))
            arena.call(10, sequence=seq, arg0=offset, arg1=1); COUNTS['partial_acknowledgements'] += 1
            arena.refuse(frame(10, arena.generation, seq, offset, 1), (STATE,))
            result = bytearray(pending[:1])
            while True:
                pulled = arena.call(9)
                self.assertEqual(arena.call(9), pulled); COUNTS['repeated_pulls'] += 1
                if not pulled['payload']:
                    self.assertEqual(pulled['phase'], 4); break
                size = min(3, len(pulled['payload'])); result += pulled['payload'][:size]
                arena.call(10, sequence=pulled['arg0'], arg0=pulled['arg1'], arg1=size)
                if size < len(pulled['payload']):
                    COUNTS['partial_acknowledgements'] += 1
            self.assertEqual(bytes(result), expected(base, hints, 1))
            arena.refuse(frame(10, arena.generation, seq, offset, 1), (STATE,))

    def test_07_cancel_drop_reuse_and_independent_arenas(self):
        with Arena(self.module) as arena:
            arena.construct(b'unpublished'); arena.call(8)
            retired = arena.call(11)
            self.assertEqual((retired['phase'], retired['confirmed'], retired['flags']), (5, 0, 2))
            event('cancel_without_write', publisher_started=True, acknowledged_bytes=0, syscall_write_count=0)
        for retire in (11, 12):
            with self.subTest(retire=retire), Arena(self.module) as arena:
                arena.construct(b'old-generation'); arena.call(8); pulled = arena.call(9)
                arena.call(10, sequence=pulled['arg0'], arg1=2); old = arena.generation
                retired = arena.call(retire)
                self.assertEqual((retired['phase'], retired['confirmed'], retired['flags']), (5, 2, 3))
                arena.refuse(frame(10, old, pulled['arg0'], 2, 1), (STATE,))
                arena.construct(b'new-generation'); self.assertGreater(arena.generation, old)
                for op in (2, 8, 9, 10, 11, 12):
                    arena.refuse(frame(op, old), (STATE,))
                self.assertEqual(arena.publish(), b'new-generation')
        with Arena(self.module) as left, Arena(self.module) as right:
            left.construct(b'left'); right.construct(b'right')
            self.assertEqual(right.publish(), b'right'); self.assertEqual(left.publish(), b'left')

    def test_08_output_capacity_private_counter_overflow(self):
        with Arena(self.module) as arena:
            arena.construct(b'body'); arena.call(8)
            arena.session.output_capacity = OUTPUT - 1
            arena.refuse(frame(9, arena.generation), (CAPACITY,))
            arena.session.output_capacity = OUTPUT
            self.assertEqual(arena.publish(start=False), b'body')
            arena.call(12); arena.word(8, MAX)
            arena.refuse(frame(1), (STATE,)); COUNTS['private_counter_fault_cases'] += 1
        for mode, operation, offset in ((0, 2, 64), (3, 13, 136), (0, 5, None)):
            with self.subTest(counter=offset, op=operation), Arena(self.module) as arena:
                arena.create(mode)
                if operation == 5:
                    arena.call(3); arena.call(4); offset = arena.word(104) + 24
                original = arena.word(offset); arena.word(offset, MAX)
                arena.refuse(frame(operation, arena.generation, payload=b'x'), (CAPACITY,))
                arena.word(offset, original); COUNTS['private_counter_fault_cases'] += 1
        with Arena(self.module) as arena:
            arena.construct(b'body'); arena.call(8); arena.word(160, MAX)
            arena.refuse(frame(9, arena.generation), (STATE,)); arena.word(160, 0); pulled = arena.call(9)
            arena.word(144, MAX)
            arena.refuse(frame(10, arena.generation, pulled['arg0'], pulled['arg1'], 1), (STATE,))
            arena.word(144, 0); self.assertEqual(arena.publish(start=False), b'body')
            COUNTS['private_counter_fault_cases'] += 2
        event('private_counter_faults_complete', cases=COUNTS['private_counter_fault_cases'], original_rust_domain=False)

    def test_09_actual_publisher_backpressure_and_shared_fd_flags(self):
        elf = self.fixture()
        selected = {case['case_id']: case for case in cases_module().iter_cases() if case['case_id'] in (0, 3, 20, 87, 89)}
        for cid in (87, 89, 3, 20, 0):
            with self.subTest(case_id=cid):
                case = selected[cid]; name = f'original-case-{cid:04d}'
                args = (case['base'], case['hints'], case['mode'], case['is_error'], case['prefix'])
                wire = framed_stream(construction_frames(*args))
                code, out, receipts = run_publisher(elf, name, wire, nonblocking=cid in (87, 89),
                                                   hold_until_eagain=cid == 87, timeout=120)
                self.assertEqual(code, 0); self.assertEqual(out, expected(*args))
                parsed, confirmed = read_receipts(receipts); self.assertEqual(confirmed, len(out))
                if cid == 87:
                    self.assertGreater(sum(0 < r['result'] < r['attempted'] for r in parsed), 0)
                    self.assertGreater(sum(r['result'] == -11 for r in parsed), 0)
                if cid == 0:
                    self.assertEqual(parsed, [])
                save_publisher_case(case, name, out)

    def test_10_actual_fixture_errors_leave_output_and_flags_unchanged(self):
        elf = self.fixture()
        examples = (
            ('early-eof', [frame(1), frame(2, 1, payload=b'private-unsealed')]),
            ('unfinished-utf8-seal', [frame(1), frame(2, 1, payload=b'\xf0\x9f'), frame(3, 1)]),
            ('illegal-lifecycle-command', [*construction_frames(b'sealed-private'), frame(10, 1)]),
        )
        for name, frames in examples:
            with self.subTest(name=name):
                code, out, receipts = run_publisher(elf, name, framed_stream(frames))
                self.assertNotEqual(code, 0); self.assertEqual((out, receipts), (b'', b''))
        for nonblocking in (False, True):
            with self.subTest(broken_pipe_nonblocking=nonblocking):
                code, out, receipts = run_publisher(elf, f'broken-pipe-{int(nonblocking)}',
                         framed_stream(construction_frames(b'committed-tool-result')),
                         broken=True, nonblocking=nonblocking)
                self.assertNotEqual(code, 0); self.assertEqual(out, b'')
                parsed, confirmed = read_receipts(receipts, allow_error=True)
                self.assertEqual(confirmed, 0)
                self.assertEqual([r['result'] for r in parsed], [-32])
                self.assertEqual([r['ack_return'] for r in parsed], [MAX])

    def test_11_actual_allocation_failure_retry_late_ack_and_reuse(self):
        elf = self.fixture()
        with ElfOwner(elf, 'resource-failure-retry-lifecycle') as owner:
            owner.ok(frame(1)); owner.ok(frame(2, 1, payload=b'owned-prefix'))
            previous_limit = resource.prlimit(owner.child.pid, resource.RLIMIT_AS)
            vm_bytes = int(Path(f'/proc/{owner.child.pid}/statm').read_text().split()[0]) * os.sysconf('SC_PAGE_SIZE')
            resource.prlimit(owner.child.pid, resource.RLIMIT_AS, (vm_bytes, previous_limit[1]))
            rejected = frame(2, 1, payload=b'G' * 60000)
            try:
                self.assertEqual(owner.call(rejected), (0xfffffffc, b''))
                COUNTS['kernel_allocation_failures'] += 1
                # The object must still accept a fitting append after real ENOMEM.
                state = owner.ok(frame(2, 1, payload=b'+'))
                self.assertEqual(state['arg0'], 13)
            finally:
                resource.prlimit(owner.child.pid, resource.RLIMIT_AS, previous_limit)
            state = owner.ok(rejected); self.assertEqual(state['arg0'], 60013)
            owner.ok(frame(3, 1)); owner.ok(frame(7, 1)); owner.ok(frame(8, 1))
            first = owner.ok(frame(9, 1)); self.assertEqual(first['payload'], b'owned-prefix+' + b'G' * 60000)
            owner.ok(frame(10, 1, first['arg0'], 0, 2))
            cancelled = owner.ok(frame(11, 1))
            self.assertEqual((cancelled['phase'], cancelled['confirmed']), (5, 2))
            self.assertEqual(owner.call(frame(10, 1, first['arg0'], 2, 1)), (STATE, b''))
            self.assertEqual(owner.ok(frame(1))['generation'], 2)
            self.assertEqual(owner.call(frame(10, 1, first['arg0'], 2, 1)), (STATE, b''))
            owner.ok(frame(2, 2, payload=b'new')); owner.ok(frame(3, 2)); owner.ok(frame(7, 2)); owner.ok(frame(8, 2))
            second = owner.ok(frame(9, 2)); self.assertEqual(second['payload'], b'new')
            owner.ok(frame(10, 2, second['arg0'], 0, 3))
            self.assertEqual(owner.ok(frame(9, 2))['phase'], 4)
            dropped = owner.ok(frame(12, 2)); self.assertEqual((dropped['phase'], dropped['confirmed']), (5, 3))
            self.assertEqual(owner.call(frame(12, 2)), (STATE, b''))
        event('actual_resource_failure', syscall='mremap', cause='RLIMIT_AS',
              address_space_limit=vm_bytes, original_rlimit_as=previous_limit, native_return=0xfffffffc,
              unchanged_prior_body_observed=True, successful_same_operation_after_limit_restore=True)


def main():
    global CAPTURE, CALLS, EVENTS, SEMANTIC
    capture = os.environ.get('HIA_RESULT_PUBLICATION_CORPUS_DIR')
    if capture:
        CAPTURE = Path(capture).resolve(); CAPTURE.mkdir(parents=True, exist_ok=False)
        CALLS = gzip.open(CAPTURE / 'actual-native-calls.bin.gz', 'wb')
        EVENTS = gzip.open(CAPTURE / 'events.jsonl.gz', 'wb')
        SEMANTIC = (CAPTURE / 'semantic-cases.jsonl').open('w')
    started = time.monotonic()
    owner_manifest = Path(os.environ['HIA_RESULT_PUBLICATION_MANIFEST']).resolve()
    fixture_manifest = Path(os.environ.get('HIA_RESULT_PUBLICATION_FIXTURE_MANIFEST',
                              str(owner_manifest.parents[2] / 'result-publication/manifest.json'))).resolve()
    fixture_meta = json.loads(fixture_manifest.read_bytes())
    identity_paths = dict(test=Path(__file__), owner_source=ROOT / 'native/result_publication.hepta',
                          owner_manifest=owner_manifest, fixture_manifest=fixture_manifest,
                          fixture_elf=fixture_manifest.parent / fixture_meta['elf'], semantic_input_generator=ORACLE_CASES)
    identities = {key: dict(path=str(path.resolve()), sha256=sha(path.read_bytes())) for key, path in identity_paths.items()}
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ResultPublicationTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    for stream in (CALLS, EVENTS, SEMANTIC):
        if stream is not None:
            stream.close()
    identities_unchanged = all(sha(path.read_bytes()) == identities[key]['sha256'] for key, path in identity_paths.items())
    passed = (result.wasSuccessful() and result.testsRun == 11 and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses and identities_unchanged
              and COUNTS['semantic_cases'] == 90 and COUNTS['actual_elf_processes'] == 11
              and COUNTS['kernel_partial_writes'] > 0 and COUNTS['kernel_eagain'] > 0
              and COUNTS['kernel_allocation_failures'] == 1 and COUNTS['other_refusals'] == 0)
    report = dict(schema='hepta.runtime.result-publication-native-test.v1',
                  status='PASS' if passed else 'FAIL', tests_run=result.testsRun,
                  failures=[dict(test=str(t), traceback=tb) for t, tb in result.failures],
                  errors=[dict(test=str(t), traceback=tb) for t, tb in result.errors],
                  skipped=len(result.skipped), elapsed_seconds=round(time.monotonic() - started, 6), counts=COUNTS,
                  identities=identities, identities_unchanged_during_run=identities_unchanged,
                  test_sha256=identities['test']['sha256'], owner_source_sha256=identities['owner_source']['sha256'],
                  manifest_sha256=identities['owner_manifest']['sha256'],
                  actual_static_publication_exercised=COUNTS['actual_elf_processes'] > 0,
                  native_allocation_failure_exercised=COUNTS['kernel_allocation_failures'] > 0, original_rust_replay=False,
                  production_scheduler_replaced=False, whole_runtime_replaced=False,
                  raw_call_record='7*u64(ordinal,session,workspace_capacity,output_capacity,input_len,native_return,output_len)+input+output',
                  elf_write_receipt='HRPWACK1+7*u64(generation,sequence,pending_offset,attempted_bytes,raw_syscall_result,confirmed_after,ack_return)',
                  direct_session_rules='New session IDs begin with zeroed storage; relocation preserves all old bytes and zero-extends within the same ID. Private counter injections are logged after their preceding direct call ordinal.',
                  original_semantic_case_count=90, expected_elf_process_count=11,
                  expected_test_groups=11)
    if CAPTURE:
        report['files'] = {str(p.relative_to(CAPTURE)): dict(bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
                           for p in sorted(CAPTURE.rglob('*')) if p.is_file()}
        (CAPTURE / 'native-result.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
