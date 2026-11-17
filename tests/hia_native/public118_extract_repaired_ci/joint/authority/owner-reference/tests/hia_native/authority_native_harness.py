"""Qualification transport for native HIA owners; never a production dispatcher.

Header authentication, token admission, hashing, binding and crypto are native
HIA. This test harness supplies explicit lifecycle events and a closed fixture
OS adapter. The separate source-owned ELF probe exercises actual native syscalls.
"""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT
sys.path.insert(0, str(RUNTIME / "scripts"))
from hia_native_loader import NativeModule

CALL, EFFECT, FATAL = 0xffffffe0, 0xfffffff0, 0xffffffe8


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def frame(op=1, headers=(), payload=b""):
    raw = bytearray(b"HRAUTR01" + struct.pack("<3Q", op, len(headers), len(payload)))
    for name, value in headers:
        raw.extend(struct.pack("<2Q", len(name), len(value)))
        raw.extend(name)
        raw.extend(value)
    raw.extend(payload)
    return bytes(raw).hex().encode()


def response(raw):
    wire = bytes.fromhex(raw.decode("ascii"))
    assert len(wire) >= 4
    return struct.unpack_from("<I", wire)[0], wire[4:]


def inspect_loaded(root_manifest, loader_manifest, scope_manifest):
    """Admit every actual loaded image before mapping any executable memory."""
    def require(condition, message):
        if not condition:
            raise ValueError('authority fixture loaded identity: ' + message)
    def same(a, b):
        return json.dumps(a, sort_keys=True, separators=(',', ':')) == json.dumps(b, sort_keys=True, separators=(',', ':'))
    profile_raw = (ROOT / 'native/authority_profile.json').read_bytes()
    require(sha(profile_raw) == '927cb5e16d8c3fcb9f4d61dc00c4aa48ae09592fec8e28cb2ba3deb4b0950b92', 'fixed authority profile differs')
    authority = json.loads(profile_raw)
    scope_path = Path(scope_manifest)
    scope_raw = scope_path.read_bytes()
    scope = json.loads(scope_raw)
    require(scope.get('schema') == 'hepta.runtime.native-composition.v1' and len(scope.get('members', [])) == 8
            and len(scope.get('profile', [])) == 8 and scope.get('compiler_commit') == authority['compiler_commit']
            and scope.get('compiler_sha256') == authority['compiler_sha256'], 'fixture scope/compiler differs')
    keys = ('id', 'name', 'source_sha256', 'flags', 'call_mask', 'input_capacity', 'output_capacity', 'workspace_capacity')
    effective = [{key: row[key] for key in keys} for row in authority['members']]
    effective[7] = {'id': 7, 'name': 'scope-entropy-fixture', 'flags': 0, 'call_mask': 0,
        'input_capacity': 48, 'output_capacity': 128, 'workspace_capacity': 128,
        'source_sha256': 'cf33465aa3e26fde3e7c28d092f566000d2e0e01eb824cfbc4bf8f9325b23675'}
    expected_scope = [dict(row) for row in effective[:8]]
    expected_scope[0] = dict(expected_scope[0], name='scope-hex-fixture', call_mask=192,
        source_sha256='b4a6aab4cb9657db2c3cd3879ab2492565d636c6cbfeb345e4d81ad7a6713eb5')
    expected_scope[3]['output_capacity'] = 32
    require(same(scope['profile'], expected_scope), 'fixture scope capability table differs')
    paths, loaded = [], []
    for index in range(9):
        path = Path(root_manifest) if index == 0 else Path(loader_manifest) if index == 8 else scope_path.parent / f'module_{index:02d}.json'
        raw = path.read_bytes()
        metadata = json.loads(raw)
        if 1 <= index <= 7:
            row = scope['members'][index]
            require(row.get('manifest') == path.name and row.get('manifest_sha256') == sha(raw), 'fixture scope child manifest differs')
        for key in ('source', 'image'):
            require(type(metadata.get(key)) is str and Path(metadata[key]).name == metadata[key], 'child artifact escaped its directory')
        source = (path.parent / metadata['source']).read_bytes()
        image = (path.parent / metadata['image']).read_bytes()
        source_name = 'tests/hia_native/scope_entropy_fixture.hepta' if index == 7 else authority['members'][index]['source']
        expected_image = 'e7fd77ba95a5f8ad13de09e1e06455437002b8305b5533b4f9ba9d7a97ed632d' if index == 7 else authority['members'][index]['image_sha256']
        require(source == (ROOT / source_name).read_bytes() and sha(source) == effective[index]['source_sha256'] == metadata.get('source_sha256')
                and sha(image) == expected_image == metadata.get('image_sha256'), 'actual source/image differs from the fixed owner')
        if 1 <= index <= 7:
            require(row.get('source_sha256') == sha(source) and row.get('image_sha256') == sha(image), 'fixture scope row disagrees with the loaded owner')
        expected_metadata = {'schema': 'hepta.runtime.native-module.v1', 'abi': 'hepta.runtime.borrowed-bytes.linux-x86_64.v1',
            'target': 'linux-x86_64', 'compiler_commit': authority['compiler_commit'], 'compiler_sha256': authority['compiler_sha256'],
            'input_capacity': 8 << 20, 'output_capacity': 8 << 20, 'workspace_capacity': 32 << 20, 'standalone': None}
        require(same({key: metadata.get(key) for key in expected_metadata}, expected_metadata), 'native compiler/ABI profile differs')
        if index != 7:
            require(len(image) == authority['members'][index]['image_bytes'], 'native image byte length differs')
        loaded.append({'id': index, 'manifest_sha256': sha(raw), 'source_sha256': sha(source), 'image_sha256': sha(image),
            'image_bytes': len(image), 'compiler_commit': metadata['compiler_commit'], 'compiler_sha256': metadata['compiler_sha256'],
            'effective_profile': effective[index]})
        paths.append(path)
    observation = {'schema': 'hepta.runtime.authority.loaded-fixture.v1', 'authority_profile_sha256': sha(profile_raw),
        'fixture_scope_manifest_sha256': sha(scope_raw), 'fixture_entropy': True, 'members': loaded}
    return paths, effective, observation


class Modules:
    def __init__(self, root_manifest, loader_manifest, scope_manifest):
        self.modules = {}
        paths, self.profile, self.loaded_artifacts = inspect_loaded(root_manifest, loader_manifest, scope_manifest)
        try:
            for index, path in enumerate(paths):
                self.modules[index] = NativeModule(path, manifest_sha256=self.loaded_artifacts['members'][index]['manifest_sha256'])
        except BaseException:
            self.close()
            raise

    def close(self):
        for module in self.modules.values():
            module.close()


class Harness:
    def __init__(self, modules, *, mode=2, entropy_seed=7, entropy_fail=0, owner_error=0):
        self.bundle, self.mode = modules, mode
        self.work = {}
        self.native_entries = [0] * 9
        self.calls, self.effects = [], []
        self.event, self.ticket, self.token_path = 0, 1, b""
        self.fd = None
        self.fd_closed = False
        self.loader_sequence = 0
        self.owner_error = owner_error
        self.completion_fault = None
        for row in modules.profile:
            capacity = row["workspace_capacity"]
            buffer = ctypes.create_string_buffer(capacity + 16)
            ctypes.memset(ctypes.addressof(buffer) + capacity, 0x6b, 16)
            self.work[row["id"]] = (buffer, capacity)
        # The entropy leaf is deliberately the frozen deterministic test fixture.
        control = b"HRTESTE1" + struct.pack("<5Q", 1, entropy_seed, entropy_fail, 0, 0)
        assert self.direct(7, control)[0] == 0

    def address(self, module):
        return ctypes.addressof(self.work[module][0])

    def get(self, module, offset):
        return struct.unpack("<Q", ctypes.string_at(self.address(module) + offset, 8))[0]

    def put(self, module, offset, value):
        ctypes.memmove(self.address(module) + offset, struct.pack("<Q", value), 8)

    def bytes(self, module, offset=0, count=None):
        if count is None:
            count = self.work[module][1] - offset
        return ctypes.string_at(self.address(module) + offset, count)

    def enter(self, module, source, size, output, capacity, active=()):
        assert module not in active and len(active) < 8
        row = self.bundle.profile[module]
        assert size <= row["input_capacity"] and capacity <= row["output_capacity"]
        buffer, count = self.work[module]
        address, b = self.address(module), count - 256
        before = ctypes.string_at(source, size)
        if row["flags"] in (1, 8):
            self.put(module, b + 120, self.event if module == 0 else 3)
            self.put(module, b + 128, module)
            self.put(module, b + 136, len(active))
        if module == 0:
            self.put(module, b + 160, self.mode)
            self.put(module, b + 168, self.ticket)
        if module == 8:
            assert active == (0,) and self.event in (0, 4)
            request = ctypes.string_at(source, size)
            op = struct.unpack_from("<Q", request, 8)[0]
            if op == 1:
                assert self.event == 0 and self.mode == 2 and request[24:] == self.token_path
            self.put(module, b + 144, self.event)
            self.put(module, b + 152, 0)
            self.put(module, b + 160, self.mode)
            self.put(module, b + 168, 0 if op == 1 else self.ticket)
        for _ in range(300):
            code = self.bundle.modules[module]._entry(ctypes.c_void_p(source), size,
                ctypes.c_void_p(output), capacity, buffer, count)
            self.native_entries[module] += 1
            assert ctypes.string_at(source, size) == before
            assert self.bytes(module, count, 16) == b"\x6b" * 16
            assert 0 <= code <= 0xffffffff
            if code == EFFECT:
                assert module == 8 and row["flags"] == 8
                self.loader_effect()
                continue
            if code != CALL:
                assert code >= 0xffff0000 or code <= capacity
                return code
            assert row["flags"] == 1
            values = struct.unpack("<14Q", self.bytes(module, b, 112))
            magic, sequence, target, region, start, length, outregion, outat, outcap, reserved, result, ack, done, denied = values
            assert magic == int.from_bytes(b"HIACAL01", "little") and sequence != 0
            assert row["call_mask"] & (1 << target) and target not in (*active, module)
            assert region in (0, 2) and outregion == 2
            assert reserved == result == ack == done == denied == 0
            input_base, bound = (source, size) if region == 0 else (address, b)
            assert length <= bound and start <= bound - length and outcap <= b and outat <= b - outcap
            inp, dest = input_base + start, address + outat
            assert not length or not outcap or inp + length <= dest or dest + outcap <= inp
            returned = self.enter(target, inp, length, dest, outcap, (*active, module))
            self.calls.append({"caller": module, "target": target, "input_bytes": length,
                               "output_capacity": outcap, "result": returned})
            self.put(module, b + 80, returned)
            self.put(module, b + 88, sequence)
            self.put(module, b + 96, 1)
            self.put(module, b + 104, 0)
            if self.completion_fault is not None:
                self.completion_fault(self, module, target, b)
        raise AssertionError("native authority continuation bound exceeded")

    def loader_effect(self):
        fields = struct.unpack("<10Q", self.bytes(8, 256, 80))
        magic, seq, dest, size, flags, action, result, error, ack, done = fields
        assert magic == int.from_bytes(b"HIALOD01", "little")
        assert seq == self.loader_sequence + 1 and flags == result == error == ack == done == 0
        self.loader_sequence = seq
        result = error = 0
        try:
            if action in (1, 7):
                assert self.fd is None
                if action == 1:
                    assert dest == 512 and self.bytes(8, dest, size) == self.token_path + b"\0"
                    self.fd = os.open(self.token_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                else:
                    assert dest == size == 0
                    if self.owner_error:
                        raise OSError(self.owner_error, "declared owner entropy fixture refusal")
                    self.fd = os.open("/dev/urandom", os.O_RDONLY | os.O_CLOEXEC)
            elif action == 2:
                assert self.fd is not None and dest == size == 0
                result = os.geteuid()
            elif action in (3, 5):
                assert self.fd is not None and size == 144 and dest == (131840 if action == 3 else 132096)
                st = os.fstat(self.fd)
                raw = bytearray(144)
                struct.pack_into("<QQQIII", raw, 0, st.st_dev, st.st_ino, st.st_nlink, st.st_mode, st.st_uid, st.st_gid)
                struct.pack_into("<Q", raw, 48, st.st_size)
                struct.pack_into("<4q", raw, 88, st.st_mtime_ns // 10**9, st.st_mtime_ns % 10**9,
                                 st.st_ctime_ns // 10**9, st.st_ctime_ns % 10**9)
                ctypes.memmove(self.address(8) + dest, bytes(raw), len(raw))
            elif action == 4:
                assert self.fd is not None and 135168 <= dest < 139266 and 0 < size <= 139266 - dest
                raw = os.read(self.fd, size)
                ctypes.memmove(self.address(8) + dest, raw, len(raw))
                result = len(raw)
            elif action == 6:
                assert self.fd is not None and dest == size == 0
                held, self.fd = self.fd, None
                os.close(held)
            else:
                raise AssertionError("unknown fixed loader effect")
        except OSError as failure:
            error = failure.errno
        self.effects.append({"action": action, "sequence": seq, "result": result, "errno": error})
        self.put(8, 304, result)
        self.put(8, 312, error)
        self.put(8, 320, seq)
        self.put(8, 328, 1)

    def direct(self, module, wire, capacity=None):
        capacity = self.bundle.profile[module]["output_capacity"] if capacity is None else capacity
        source = ctypes.create_string_buffer(wire or b"\0")
        output = ctypes.create_string_buffer(capacity + 16)
        ctypes.memset(ctypes.addressof(output) + capacity, 0xa5, 16)
        code = self.enter(module, ctypes.addressof(source), len(wire), ctypes.addressof(output), capacity)
        assert source.raw[:len(wire)] == wire and output.raw[capacity:capacity + 16] == b"\xa5" * 16
        return code, output.raw[:code] if code <= capacity else b""

    def startup(self, path=b""):
        self.event, self.ticket, self.token_path = 0, 1, os.fsencode(path)
        return self.direct(0, self.token_path if self.mode == 2 else b"")

    def request(self, wire, capacity=None):
        self.event = 1
        return self.direct(0, wire, capacity)

    def reconnect(self):
        self.event, self.ticket = 4, self.ticket + 1
        return self.direct(0, b"")

    def shutdown(self):
        self.event = 2
        return self.direct(0, b"")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        for buffer, count in self.work.values():
            ctypes.memset(buffer, 0, count)
