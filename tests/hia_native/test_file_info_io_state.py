#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual HIA IO state with declared, test-only synthetic syscall completions.

The IO owner and SHA child execute their pinned native images. This suite
checks ordering and uncommon kernel results. It does not claim actual OS
effects; test_info_service.py and the deadline suite supply that evidence.
"""
from __future__ import annotations
import ctypes, errno, hashlib, importlib.util, json, os, struct, sys, types, unittest
from pathlib import Path

ROOT = Path(os.environ.get('HIA_RUNTIME_REPO', Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule

WORK = 8 << 20
OUTPUT = 75776
CALL = 0xffffffe0
EFFECT = 0xfffffff0
COUNTS = dict(native_io_calls=0, native_sha_calls=0, synthetic_effects=0, requests=0,
              original_metadata_controls=0)
METADATA_SHA = '24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3'


def opened(path):
    path = Path(path)
    return NativeModule(path, manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def stat_bytes(*, size=3, inode=2, mode=0o640, uid=34, gid=56, links=2, mtime=3, ctime=5):
    raw = bytearray(144)
    for offset, value in [(0, 1), (8, inode), (16, links), (48, size),
                          (88, mtime), (96, 4), (104, ctime), (112, 6)]:
        struct.pack_into('<Q', raw, offset, value)
    struct.pack_into('<III', raw, 24, 0o100000 | mode, uid, gid)
    return bytes(raw)


def request(path=b'/fixture/value', identity=1):
    return b'HIARD001' + struct.pack('<13Q', identity, 3, 0, 0, 0, *(0,) * 7, len(path)) + path


def decode(raw):
    assert raw[:8] == b'HIARR001' and len(raw) >= 128
    words = struct.unpack('<15Q', raw[8:128])
    identity, status, error, size, offset, following, eof = words[:7]
    assert len(raw) == 128 + size
    assert offset == following == eof == 0
    if status:
        assert size == 0 and raw[56:] == bytes(72)
        return dict(identity=identity, status=status, error=error)
    assert raw[128:136] == b'HIAINF01' and raw[176:192] == bytes(16)
    uid, gid, mode, links, count, reserved, reserved2 = struct.unpack('<7Q', raw[136:192])
    assert count <= 256 and reserved == reserved2 == 0
    attrs = []
    at = 256
    for _ in range(count):
        length = struct.unpack_from('<Q', raw, at)[0]
        at += 8
        name = raw[at:at + length].decode('utf-8')
        at += length
        attrs.append((name, raw[at:at + 32]))
        at += 32
    assert at == len(raw)
    return dict(identity=identity, status=0, error=0, version=words[7:14],
                mode=words[14], uid=uid, gid=gid, capture_mode=mode, links=links,
                attrs=attrs, sha256=raw[192:224], acl_sha256=raw[224:256])


class Fixture:
    def __init__(self, owner, codec, *, data=b'abc', attrs=(), stats=None,
                 fault=None, chunks=None, names=None):
        self.owner = owner
        self.codec = codec
        self.output = ctypes.create_string_buffer(OUTPUT + 16)
        self.work = ctypes.create_string_buffer(WORK + 16)
        self.base = ctypes.addressof(self.work)
        self.sha_output = ctypes.create_string_buffer(128 + 16)
        self.sha_work = ctypes.create_string_buffer(1184 + 16)
        self.data = data
        self.attrs = list(attrs)
        self.stats = stats or {}
        self.fault = fault
        self.chunks = list(chunks or ())
        self.names = names
        self.events = []
        self.next_handle = 0
        self.handles = {}
        self.sequence = 0
        self.call_sequence = 0
        assert self.run(b'/fixture') == b''
        self.events.clear()

    def get(self, offset):
        return struct.unpack('<Q', ctypes.string_at(self.base + offset, 8))[0]

    def put(self, offset, value):
        ctypes.memmove(self.base + offset, struct.pack('<Q', value), 8)

    def write(self, offset, data):
        assert 0 <= offset <= WORK - len(data)
        ctypes.memmove(self.base + offset, data, len(data))

    def native(self, wire):
        raw = ctypes.create_string_buffer(wire, max(1, len(wire)))
        ctypes.memset(ctypes.addressof(self.output) + OUTPUT, 0xa5, 16)
        ctypes.memset(self.base + WORK, 0x5a, 16)
        result = self.owner._entry(raw, len(wire), self.output, OUTPUT, self.work, WORK)
        COUNTS['native_io_calls'] += 1
        assert raw.raw == (wire or b'\0')
        assert ctypes.string_at(ctypes.addressof(self.output) + OUTPUT, 16) == b'\xa5' * 16
        assert ctypes.string_at(self.base + WORK, 16) == b'\x5a' * 16
        assert result <= 0xffffffff
        return result

    def child(self):
        b = WORK - 256
        values = struct.unpack('<14Q', ctypes.string_at(self.base + b, 112))
        magic, seq, target, region, start, size, out_region, out_start, capacity, *pending = values
        assert magic == int.from_bytes(b'HIACAL01', 'little')
        assert seq == self.call_sequence + 1 and target == 2 and region == out_region == 2
        assert pending == [0] * 5 and capacity == 128
        assert start == 1064960 and 24 <= size <= (1 << 20) + 152 and out_start == 2121728
        self.call_sequence = seq
        wire = ctypes.string_at(self.base + start, size)
        raw = ctypes.create_string_buffer(wire)
        ctypes.memset(ctypes.addressof(self.sha_output) + 128, 0xa5, 16)
        ctypes.memset(ctypes.addressof(self.sha_work) + 1184, 0x5a, 16)
        result = self.codec._entry(raw, size, self.sha_output, 128, self.sha_work, 1184)
        COUNTS['native_sha_calls'] += 1
        assert raw.raw == wire + b'\0'
        assert ctypes.string_at(ctypes.addressof(self.sha_output) + 128, 16) == b'\xa5' * 16
        assert ctypes.string_at(ctypes.addressof(self.sha_work) + 1184, 16) == b'\x5a' * 16
        assert result in (32, 128)
        self.write(out_start, ctypes.string_at(self.sha_output, result))
        self.put(b + 80, result)
        self.put(b + 88, seq)
        self.put(b + 96, 1)
        self.put(b + 104, 0)

    def effect(self):
        magic, seq, action, handle, offset, size, argument, reserved = struct.unpack(
            '<8Q', ctypes.string_at(self.base + 256, 64))
        stage = self.get(16)
        assert magic == int.from_bytes(b'HIAFX001', 'little')
        assert seq == self.sequence + 1 and reserved == 0
        self.sequence = seq
        event = dict(stage=stage, action=action, handle=handle, offset=offset, size=size)
        self.events.append(event)
        COUNTS['synthetic_effects'] += 1
        error = 0 if self.fault is None else (self.fault(self, event) or 0)
        value = new_handle = 0
        if action == 6:
            assert handle in self.handles
            del self.handles[handle]
        if not error:
            if action in (1, 2, 3, 11):
                self.next_handle += 1
                new_handle = (self.next_handle << 8) | 1
                self.handles[new_handle] = dict(position=0, file=action == 3)
            elif action == 4:
                self.write(offset, self.stats.get(stage, stat_bytes(size=len(self.data))))
            elif action == 7:
                assert handle in self.handles and self.handles[handle]['file']
                start = self.handles[handle]['position']
                take = min(size, self.chunks.pop(0) if self.chunks else size)
                part = self.data[start:start + take]
                self.handles[handle]['position'] += len(part)
                self.write(offset, part)
                value = len(part)
            elif action == 8:
                names = self.names if self.names is not None else b''.join(name + b'\0' for name, _ in self.attrs)
                assert len(names) <= size
                self.write(offset, names)
                value = len(names)
            elif action == 9:
                name = ctypes.string_at(self.base + argument)
                event['name'] = name
                part = dict(self.attrs)[name]
                assert len(part) <= size
                self.write(offset, part)
                value = len(part)
            elif action == 10:
                assert stage == 55 and handle == offset == size == argument == 0
                assert self.get(2192) == 0
            elif action == 12:
                assert stage == 56 and handle == offset == argument == 0
                assert 128 <= size <= OUTPUT and self.get(2192) == 2
                assert len(self.handles) == 1
                value = size
            elif action != 6:
                raise AssertionError(('unrecognized effect', action, stage))
        self.put(320, value)
        self.put(328, error)
        self.put(336, new_handle)
        self.put(344, seq)
        self.put(352, 1)

    def run(self, raw):
        for _ in range(2000):
            result = self.native(raw)
            if result == CALL:
                self.child()
            elif result == EFFECT:
                self.effect()
            else:
                assert result < 0xffff0000 and result <= OUTPUT, hex(result)
                return ctypes.string_at(self.output, result)
        raise AssertionError('unbounded native continuation')

    def info(self, raw=None):
        COUNTS['requests'] += 1
        result = decode(self.run(request() if raw is None else raw))
        assert len(self.handles) == 1, ('per-request handles leaked', self.handles)
        return result

    def close(self):
        assert self.run(b'') == b''
        assert not self.handles


class InfoIoStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_SERVICE_MANIFEST']).resolve(strict=True)
        cls.metadata = json.loads(cls.manifest.read_bytes())
        cls.members = {}
        for identity in (2, 3):
            entry = cls.metadata['members'][identity]
            path = cls.manifest.parent / entry['manifest']
            assert hashlib.sha256(path.read_bytes()).hexdigest() == entry['manifest_sha256']
            if identity == 3 and os.environ.get('HIA_INFO_IO_MANIFEST'):
                path = Path(os.environ['HIA_INFO_IO_MANIFEST']).resolve(strict=True)
            cls.members[identity] = opened(path)
            if identity == 3:
                cls.owner_manifest = path
        source = Path(os.environ.get('HIA_INFO_IO_SOURCE', ROOT / 'native/io_policy.hepta'))
        assert hashlib.sha256(source.read_bytes()).hexdigest() == cls.members[3].metadata['source_sha256']
        original = ROOT / 'src/mcp/runtime/file_metadata.py'
        assert hashlib.sha256(original.read_bytes()).hexdigest() == METADATA_SHA
        spec = importlib.util.spec_from_file_location('hia_info_io_metadata_reference', original)
        cls.original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.original)

    @classmethod
    def tearDownClass(cls):
        for module in cls.members.values():
            module.close()
        assert hashlib.sha256((ROOT / 'src/mcp/runtime/file_metadata.py').read_bytes()).hexdigest() == METADATA_SHA

    def fixture(self, **kwargs):
        instance = Fixture(self.members[3], self.members[2], **kwargs)
        self.addCleanup(instance.close)
        return instance

    def test_eof_hashing_ignores_initial_size_and_partial_read_boundaries(self):
        data = b'\x00\xffabc' * 100
        for size in (0, 1, 499, 500, 10000000):
            fixture = self.fixture(data=data, chunks=[1, 63, 2, 64, 11],
                                   stats={stage: stat_bytes(size=size) for stage in (40, 41, 46, 49, 50, 51, 54)})
            result = fixture.info()
            self.assertEqual((result['status'], result['version'][2], result['sha256']),
                             (0, size, hashlib.sha256(data).digest()))
            self.assertEqual(len([e for e in fixture.events if e['stage'] == 44]), 7)

    def test_fingerprint_reopen_and_capture_fences_preserve_order(self):
        for stage, status in [(46, 7), (50, 13), (54, 18)]:
            fixture = self.fixture(stats={stage: stat_bytes(inode=9)})
            result = fixture.info()
            self.assertEqual((result['status'], result['error']), (status, 0))
            stages = [e['stage'] for e in fixture.events]
            self.assertEqual(stages.count(stage), 1)
            if stage < 51:
                self.assertNotIn(52, stages)
        # Original metadata_capture starts its own identity interval after the
        # reopened version check. A mutation in that gap is not re-rejected.
        capture = stat_bytes(mode=0o2751, uid=99, gid=101, links=3, ctime=77)
        fixture = self.fixture(stats={51: capture, 54: capture})
        result = fixture.info()
        self.assertEqual((result['mode'], result['capture_mode'], result['uid'], result['gid'], result['links']),
                         (0o640, 0o2751, 99, 101, 3))
        self.assertEqual(result['version'][5], 5)
        stages = [e['stage'] for e in fixture.events]
        self.assertLess(stages.index(47), stages.index(48))
        self.assertLess(stages.index(50), stages.index(51))
        self.assertLess(stages.index(51), stages.index(52))
        self.assertLess(stages.index(52), stages.index(54))

    def test_xattr_reads_keep_kernel_order_and_summary_sorts(self):
        attrs = [(b'user.z', b'last'), (b'user.a', b'first'),
                 (b'system.posix_acl_access', b'owned ACL fixture'), ('user.\u96ea'.encode(), b'')]
        fixture = self.fixture(attrs=attrs)
        result = fixture.info()
        self.assertEqual([e['name'] for e in fixture.events if e['action'] == 9], [n for n, _ in attrs])
        self.assertEqual(result['attrs'], [(n.decode(), hashlib.sha256(v).digest()) for n, v in sorted(attrs)])
        self.assertEqual(result['acl_sha256'], hashlib.sha256(attrs[2][1]).digest())
        self.assertEqual([e['stage'] for e in fixture.events if e['action'] not in (10, 12)][-3:], [54, 90, 92])

    def test_xattr_count_budget_checks_after_257th_get(self):
        attrs = [(('user.%03d' % i).encode(), b'') for i in range(257)]
        fixture = self.fixture(attrs=attrs)
        self.assertEqual(fixture.info()['status'], 17)
        self.assertEqual(len([e for e in fixture.events if e['action'] == 9]), 257)
        self.assertNotIn(54, [e['stage'] for e in fixture.events])

        def last_get_fails(fixture, event):
            if event['action'] == 9 and fixture.get(2080) == 256:
                return errno.EACCES
        fixture = self.fixture(attrs=attrs, fault=last_get_fails)
        result = fixture.info()
        self.assertEqual((result['status'], result['error']), (16, errno.EACCES))
        self.assertEqual(len([e for e in fixture.events if e['action'] == 9]), 257)

    def test_xattr_value_budget_exact_boundary_and_first_failure(self):
        block = bytes(range(256)) * 256
        attrs = [(('user.%03d' % i).encode(), block if i < 64 else b'') for i in range(256)]
        fixture = self.fixture(attrs=attrs)
        result = fixture.info()
        self.assertEqual(len(result['attrs']), 256)
        self.assertEqual(result['attrs'][0][1], hashlib.sha256(block).digest())
        too_much = attrs[:64] + [(b'user.overflow', b'x')]
        fixture = self.fixture(attrs=too_much)
        self.assertEqual(fixture.info()['status'], 17)
        self.assertEqual(len([e for e in fixture.events if e['action'] == 9]), 65)
        self.assertNotIn(54, [e['stage'] for e in fixture.events])

        def overflow_get_fails(fixture, event):
            if event['action'] == 9 and fixture.get(2088) == 4194304:
                return errno.EIO
        fixture = self.fixture(attrs=too_much, fault=overflow_get_fails)
        result = fixture.info()
        self.assertEqual((result['status'], result['error']), (16, errno.EIO))

    def test_scalar_name_refusal_occurs_after_capture(self):
        fixture = self.fixture(attrs=[(b'user.invalid\xff', b'secret')])
        result = fixture.info()
        self.assertEqual(result['status'], 14)
        self.assertIn(54, [e['stage'] for e in fixture.events])
        self.assertEqual(ctypes.string_at(fixture.output, 128)[32:], bytes(96))
        for names in (b'user.no-terminator', b'\0', b'x' * 256 + b'\0'):
            fixture = self.fixture(names=names)
            self.assertEqual((fixture.info()['status']), 16)
            self.assertNotIn(53, [e['stage'] for e in fixture.events])

    def test_syscall_errors_keep_no_result_and_retire_handles(self):
        for stage, status in [(39, 3), (40, 8), (41, 8), (44, 8), (46, 8),
                              (47, 9), (48, 3), (49, 8), (50, 8), (51, 8),
                              (52, 16), (53, 16), (54, 8)]:
            def fail_at(fixture, event):
                return errno.EIO if event['stage'] == stage else 0
            fixture = self.fixture(attrs=[(b'user.value', b'value')], fault=fail_at)
            result = fixture.info()
            self.assertEqual((result['status'], result['error']), (status, errno.EIO), stage)
            self.assertEqual(len(fixture.handles), 1)

    def test_finalizers_override_earlier_errors_in_original_order(self):
        for faults, expected in [({44: errno.EIO}, (8, errno.EIO)),
                                 ({44: errno.EIO, 90: errno.EACCES}, (9, errno.EACCES)),
                                 ({44: errno.EIO, 90: errno.EACCES, 92: errno.EBADF}, (9, errno.EBADF)),
                                 ({47: errno.EINTR, 92: errno.EIO}, (9, errno.EIO))]:
            fixture = self.fixture(fault=lambda _, event: faults.get(event['stage'], 0))
            result = fixture.info()
            self.assertEqual((result['status'], result['error']), expected)
            self.assertEqual([e['stage'] for e in fixture.events if e['action'] == 6][-1], 92)

    def test_malformed_request_has_no_effect_and_session_recovers(self):
        fixture = self.fixture()
        for offset in (24, 32, 40, 48, 56, 64, 72, 80, 88, 96):
            raw = bytearray(request())
            struct.pack_into('<Q', raw, offset, 1)
            before = len(fixture.events)
            result = fixture.info(bytes(raw))
            self.assertEqual(result['status'], 10)
            self.assertEqual(len(fixture.events), before)
        self.assertEqual(fixture.info()['status'], 0)

    def test_exact_original_metadata_budget_order_with_declared_os_fixtures(self):
        small = [(('user.%03d' % i).encode(), b'') for i in range(257)]
        block = b'v' * 65536
        large = [(('user.%03d' % i).encode(), block) for i in range(64)]
        cases = [(small[:256], None, 0), (small, None, 17), (small, 256, 16),
                 (large, None, 0), (large + [(b'user.overflow', b'x')], None, 17),
                 (large + [(b'user.overflow', b'x')], 64, 16)]
        for attrs, fail_index, status in cases:
            calls = []
            names = [name.decode() for name, _ in attrs]
            values = {name.decode(): value for name, value in attrs}
            def getxattr(fd, name):
                self.assertEqual(fd, 11)
                calls.append(name)
                if fail_index is not None and len(calls) - 1 == fail_index:
                    raise OSError(errno.EACCES, 'declared fixture failure')
                return values[name]
            prior = self.original.os
            self.original.os = types.SimpleNamespace(listxattr=lambda fd: names, getxattr=getxattr)
            try:
                if status == 0:
                    self.assertEqual(self.original.metadata_xattrs(11), values)
                elif status == 17:
                    with self.assertRaisesRegex(ValueError, '^metadata budget exceeded$'):
                        self.original.metadata_xattrs(11)
                else:
                    with self.assertRaises(OSError) as caught:
                        self.original.metadata_xattrs(11)
                    self.assertEqual(caught.exception.errno, errno.EACCES)
            finally:
                self.original.os = prior
            COUNTS['original_metadata_controls'] += 1
            count = 0
            def fault(fixture, event):
                nonlocal count
                if event['action'] == 9:
                    index = count
                    count += 1
                    if index == fail_index:
                        return errno.EACCES
            fixture = self.fixture(attrs=attrs, fault=fault)
            result = fixture.info()
            self.assertEqual(result['status'], status)
            self.assertEqual(count, len(calls))
            self.assertEqual([event['name'].decode() for event in fixture.events
                              if event['action'] == 9 and 'name' in event],
                             calls if fail_index is None else calls[:-1])


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(InfoIoStateTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    proof = dict(schema='hepta.runtime.native-info-io-state-test.v1', status='pass', counts=COUNTS,
                 manifest_sha256=hashlib.sha256(InfoIoStateTests.manifest.read_bytes()).hexdigest(),
                 io_source_sha256=InfoIoStateTests.members[3].metadata['source_sha256'],
                 io_manifest_sha256=hashlib.sha256(InfoIoStateTests.owner_manifest.read_bytes()).hexdigest(),
                 codec_source_sha256=InfoIoStateTests.metadata['members'][2]['source_sha256'],
                 original_metadata_source_sha256=METADATA_SHA,
                 os_effects='declared synthetic completions; actual ELF tests are separate')
    if os.environ.get('HIA_INFO_IO_STATE_RESULT'):
        Path(os.environ['HIA_INFO_IO_STATE_RESULT']).write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(proof, sort_keys=True))

