"""Byte dispatch controls only; policy/directory replies are explicit test fixtures."""
from pathlib import Path
import ctypes
import hashlib
import os
import struct
import sys
ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(os.environ.get("HIA_REFERENCE_RUNTIME", ROOT))
sys.path.insert(0, str(REFERENCE / "scripts"))
from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
INVALID, CAPACITY, CALL = 0xffffffff, 0xfffffffe, 0xfffffff0
ACTION, REQUEST, REPLY, PATH = 256, 4096, 67117056, 201338880
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
sha = SHA
q = lambda magic, *values: struct.pack("<8s" + "Q" * len(values), magic, *values)


def invoke(session, wire):
    try:
        raw = session.invoke(wire)
        return (len(raw), raw)
    except (NativeRejected, NativeCapacityError) as error:
        return (error.code, b'')


class ParameterBridge:

    def __init__(self, owner, value):
        self.owner, self.value = (owner, value)
        self.entries = self.calls = 0

    def read(self, offset, size):
        return ctypes.string_at(ctypes.addressof(self.owner._workspace) + offset, size)

    def write(self, offset, raw):
        ctypes.memmove(ctypes.addressof(self.owner._workspace) + offset, raw, len(raw))

    def word(self, offset, value=None):
        cell = ctypes.c_uint64.from_address(ctypes.addressof(self.owner._workspace) + offset)
        if value is None:
            return cell.value
        cell.value = value

    def enter(self, wire):
        self.entries += 1
        return invoke(self.owner, wire)

    def complete(self):
        magic, seq, child, reserved, start, size, output, capacity, ack, code, zero, zero2 = struct.unpack('<8s11Q', self.read(ACTION, 96))
        assert magic == b'HMWDPA01' and seq > 0 and (child == 1)
        assert reserved == ack == code == zero == zero2 == 0
        assert start == REQUEST and output == REPLY and (capacity == 64 << 20)
        assert 24 <= size <= (8 << 20) + 24
        raw = self.read(start, size)
        assert raw[:8] == b'HSJVAL01' and struct.unpack_from('<2Q', raw, 8) == (1, size - 24)
        self.calls += 1
        child_code, reply = invoke(self.value, raw)
        self.write(REPLY, reply)
        self.word(ACTION + 64, seq)
        self.word(ACTION + 72, child_code)
        return dict(sequence=seq, child_code=child_code, input_bytes=len(raw), input_sha256=SHA(raw), output_bytes=len(reply), output_sha256=SHA(reply))

    def run(self, wire):
        first, raw = self.enter(wire)
        if first != CALL:
            return (first, raw, None)
        child = self.complete()
        code, raw = self.enter(wire)
        assert code != CALL
        return (code, raw, child)


class ClientBridge:

    def __init__(self, context, value):
        self.context, self.value = (context, value)
        self.entries = 0
        self.value_calls = 0

    def read(self, at, size):
        return ctypes.string_at(ctypes.addressof(self.context._workspace) + at, size)

    def write(self, at, raw):
        ctypes.memmove(ctypes.addressof(self.context._workspace) + at, raw, len(raw))

    def word(self, at, value=None):
        cell = ctypes.c_uint64.from_address(ctypes.addressof(self.context._workspace) + at)
        if value is None:
            return cell.value
        cell.value = value

    def request(self):
        row = struct.unpack('<8s11Q', self.read(ACTION, 96))
        magic, sequence, child, reserved, start, size, output, capacity, ack, code, zero, zero2 = row
        assert magic == b'HRCMCA01' and sequence > 0 and (child == 1)
        assert reserved == ack == code == zero == zero2 == 0
        assert start == REQUEST and output == REPLY and (capacity == 64 << 20)
        assert 24 <= size <= (8 << 20) + 24 and start + size <= output
        raw = self.read(start, size)
        assert raw[:8] == b'HSJVAL01' and struct.unpack_from('<2Q', raw, 8) == (1, size - 24)
        return (sequence, raw)

    def complete(self, sequence, code, raw):
        assert 0 <= code <= 4294967295 and len(raw) <= 64 << 20
        self.write(REPLY, raw)
        self.word(ACTION + 64, sequence)
        self.word(ACTION + 72, code)

    def enter(self, wire):
        self.entries += 1
        return invoke(self.context, wire)

    def run(self, wire):
        calls = []
        for _ in range(3):
            code, raw = self.enter(wire)
            if code != CALL:
                return (code, raw, calls)
            sequence, request = self.request()
            self.value_calls += 1
            child_code, reply = invoke(self.value, request)
            calls.append(dict(sequence=sequence, input_bytes=len(request), input_sha256=sha(request), code=child_code, output_bytes=len(reply), output_sha256=sha(reply)))
            self.complete(sequence, child_code, reply)
        raise AssertionError('unbounded selector continuation')


def state_frame(op, raw=b''):
    return q(b'HRSWQ001', op, len(raw), 0) + raw


class ContextBridge:

    def __init__(self, context, state, client):
        self.context, self.state, self.client = (context, state, client)
        self.calls = []

    def read(self, at, size):
        return ctypes.string_at(ctypes.addressof(self.context._workspace) + at, size)

    def write(self, at, data):
        ctypes.memmove(ctypes.addressof(self.context._workspace) + at, data, len(data))

    def word(self, at, value=None):
        cell = ctypes.c_uint64.from_address(ctypes.addressof(self.context._workspace) + at)
        if value is None:
            return cell.value
        cell.value = value

    def reset(self, current=None, poisoned=False, claimed=False):
        ctypes.memset(self.context._workspace, 0, 512)
        ctypes.memset(self.state._workspace, 0, 64)
        assert self.state.invoke(state_frame(1, b'/fixture-root')) == q(b'HRSWR001', 0, 0, 0)
        if current is not None:
            self.state.invoke(state_frame(3, current))
        if poisoned:
            self.state.invoke(state_frame(6))
        if claimed:
            self.state.invoke(state_frame(5))
        self.calls = []

    def request(self):
        row = struct.unpack('<8s11Q', self.read(ACTION, 96))
        magic, sequence, child, reserved, source, size, output, capacity, ack, code, zero, zero2 = row
        assert magic == b'HRSCPA01' and sequence > 0 and (child in (1, 2, 3, 4))
        assert reserved == ack == code == zero == zero2 == 0
        assert source == REQUEST and output == REPLY and (0 < size <= (16 << 20) + 40)
        assert capacity == {1: 32, 2: (64 << 20) + 32, 3: 128 << 20, 4: 128 << 20}[child]
        assert source + size <= output and output + capacity <= PATH
        wire = self.read(source, size)
        return dict(sequence=sequence, child=child, wire=wire, output=output, capacity=capacity)

    def complete(self, request, code, raw):
        assert 0 <= code <= 4294967295 and len(raw) <= request['capacity']
        self.write(request['output'], raw)
        self.word(ACTION + 64, request['sequence'])
        self.word(ACTION + 72, code)

    def dispatch(self, request, allows, is_dir):
        child, wire = (request['child'], request['wire'])
        if child == 1:
            assert wire[:8] == b'HRSWQ001' and struct.unpack_from('<Q', wire, 8)[0] in (3, 5)
            code, raw = invoke(self.state, wire)
        elif child == 2:
            assert wire[:8] == b'HRCMCQ01'
            code, raw, _ = self.client.run(wire)
        elif child == 3:
            assert wire[:8] == b'HRLPCQ01' and struct.unpack_from('<2Q', wire, 8) == (1, len(wire) - 24)
            message = b'' if allows else b'fixture installed-policy refusal'
            raw = q(b'HLPCR001', int(not allows), 0, len(message)) + message
            code = len(raw)
        else:
            assert wire[:8] == b'HRCANQ01' and struct.unpack_from('<2Q', wire, 8) == (3, len(wire) - 24)
            assert wire[24:25] == b'/'
            raw = q(b'HRCANR01', 2, 0, int(is_dir), 0)
            code = len(raw)
        self.calls.append({'child': child, 'request_sha256': sha(wire), 'request_bytes': len(wire), 'response_sha256': sha(raw), 'response_bytes': len(raw), 'code': code})
        return (code, raw)

    def run(self, wire, allows, is_dir):
        self.calls = []
        for _ in range(6):
            code, raw = invoke(self.context, wire)
            if code != CALL:
                return (code, raw, list(self.calls))
            request = self.request()
            result, payload = self.dispatch(request, allows, is_dir)
            self.complete(request, result, payload)
        raise AssertionError('unbounded context continuation')

    def current(self):
        raw = self.state.invoke(state_frame(2))
        assert raw[:8] == b'HRSWR001' and struct.unpack_from('<3Q', raw, 8) == (1, 0, len(raw) - 32)
        return raw[32:]
