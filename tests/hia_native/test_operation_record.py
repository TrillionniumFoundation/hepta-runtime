"""Actual native record continuations and original-owner differential corpus.

All key/nonce/payload values are synthetic. Direct continuation transport is
test code; the separate fixed-image ELF runs the same HIA owner without it.
This does not qualify a trusted scope, entropy, nonce ledger, or public tool.
"""
from pathlib import Path
import ctypes
import gzip
import hashlib
import hmac
import json
import os
import random
import struct
import subprocess
import sys
import unittest

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SOURCE_ROOT = Path(os.environ.get('HIA_RECORD_SOURCE_ROOT', Path(__file__).resolve().parents[2]))
ROOT = Path(os.environ.get('HIA_REFERENCE_RUNTIME', SOURCE_ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule

INVALID, CAPACITY, PAYLOAD, BINDING, INTEGRITY = range(0xffffffff, 0xfffffffa, -1)
CHILD, CALL = 0xfffffff8, 0xffffffe0
WORK = 3 << 20
B = WORK - 256
U64 = (1 << 64) - 1
ORIGINAL_SHA = 'a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633'
FIELDS = [b'1' * 64, b'2' * 64, b'binary_read', b'3' * 64, b'4' * 64, b'5' * 64]
PREFIX = b'hepta-runtime/native-operation/'
KEY = bytes(range(32))
NONCE = bytes(range(12))
COUNTS = {'requests': 0, 'native_controller_calls': 0, 'native_leaf_calls': 0,
          'aad_reference_cases': 0, 'preflight_reference_cases': 0, 'seal_reference_cases': 0,
          'open_reference_cases': 0, 'binding_refusals': 0, 'integrity_refusals': 0,
          'admission_refusals': 0, 'capacity_refusals': 0, 'child_contract_refusals': 0,
          'exact_capacity_successes': 0, 'codec_cleanup_reference_calls': 0,
          'actual_elf_requests': 0}
CORPUS = []


def sha(value):
    return hashlib.sha256(value).hexdigest()


def frame(op, tail=b'', *, fields=FIELDS, kind=1, timestamp=(1 << 100) + 123):
    return (b'HRREC001' + struct.pack('<11Q', op, 0, kind, timestamp & U64,
                                    timestamp >> 64, *map(len, fields)) + b''.join(fields) + tail)


def aad(fields=FIELDS, kind=1, timestamp=(1 << 100) + 123):
    values = [PREFIX + b'result-aad/v1', b'HEPTAOP1', b'chacha20_poly1305',
              b'serialized-native-sdk-result-family/v1'] + fields
    values += [b'native_result' if kind == 1 else b'native_error']
    return b''.join(len(v).to_bytes(4, 'big') + v for v in values) + timestamp.to_bytes(16, 'big')


def record_key(key=KEY, fields=FIELDS):
    prk = hmac.digest(PREFIX + b'record-key/extract/v1', key, 'sha256')
    return hmac.digest(prk, PREFIX + b'record-key/expand/v1' + fields[0] + fields[5] + b'\x01', 'sha256')


def seal(payload, *, key=KEY, nonce=NONCE, fields=FIELDS, kind=1, timestamp=(1 << 100) + 123, inner=None):
    if inner is None:
        inner = b'HOPIN001' + len(payload).to_bytes(8, 'big') + hashlib.sha256(payload).digest() + payload
    cipher = ChaCha20Poly1305(record_key(key, fields)).encrypt(nonce, inner, aad(fields, kind, timestamp))
    return b'HEPTAOP1' + nonce + cipher


def open_module(path):
    path = Path(path)
    return NativeModule(path, manifest_sha256=sha(path.read_bytes()))


class Harness:
    """Generic continuation copying only; no record or crypto implementation."""
    def __init__(self, modules):
        self.modules = modules
        self.work = ctypes.create_string_buffer(WORK + 16)
        self.address = ctypes.addressof(self.work)
        ctypes.memset(self.address, 0x5a, WORK + 16)
        ctypes.memset(self.address + B, 0, 256)
        self.put(0, 0)
        self.put(B + 120, 3)
        self.put(B + 128, 1)
        self.put(B + 136, 1)
        self.leaf_work = {}
        for target, count in [(2, 2048), (3, 1184), (4, 512)]:
            buf = ctypes.create_string_buffer(count + 16)
            ctypes.memset(ctypes.addressof(buf) + count, 0x6b, 16)
            self.leaf_work[target] = (buf, count)
        self.sequence = 0
        self.retired = False
        self.trace = []
        self.snapshots = []

    def get(self, at):
        return struct.unpack('<Q', ctypes.string_at(self.address + at, 8))[0]

    def put(self, at, value):
        ctypes.memmove(self.address + at, struct.pack('<Q', value), 8)

    def invoke(self, raw, capacity, *, fault=None):
        assert not self.retired, 'fatal child-contract faults require destruction of the whole bundle'
        source = ctypes.create_string_buffer(raw + b'\x7c' * 16)
        out = ctypes.create_string_buffer(capacity + 16)
        ctypes.memset(ctypes.addressof(out), 0xa5, capacity + 16)
        before = ctypes.string_at(self.address, B)
        high = 0
        before_trace = len(self.trace)
        for step in range(12):
            returned = self.modules[1]._entry(source, len(raw), out, capacity, self.work, WORK)
            COUNTS['native_controller_calls'] += 1
            assert source.raw == raw + b'\x7c' * 16 + b'\0'
            assert ctypes.string_at(self.address + WORK, 16) == b'\x5a' * 16
            assert ctypes.string_at(ctypes.addressof(out) + capacity, 16) == b'\xa5' * 16
            if returned != CALL:
                COUNTS['requests'] += 1
                assert returned >= 0xffff0000 or returned <= capacity
                actual = ctypes.string_at(out, returned) if returned < 0xffff0000 else b''
                assert ctypes.string_at(ctypes.addressof(out) + len(actual), capacity - len(actual)) == b'\xa5' * (capacity - len(actual))
                after = ctypes.string_at(self.address, B)
                if high:
                    assert after[:high] == bytes(high), 'record-private secret-bearing prefix was not cleared'
                    assert after[high:] == before[high:], 'record untouched workspace tail changed'
                else:
                    assert after == before, 'admission or pure AAD changed private scratch'
                if returned == CHILD:
                    self.retired = True
                return returned, actual, len(self.trace) - before_trace
            phase = self.get(0)
            high = max(high, self.get(56))
            assert 2048 <= high <= B
            words = struct.unpack('<14Q', ctypes.string_at(self.address + B, 112))
            magic, seq, target, region, start, size, out_region, out_at, out_size, reserved, code, ack, done, denied = words
            assert magic == int.from_bytes(b'HIACAL01', 'little') and seq == self.sequence + 1
            assert target in (2, 3, 4) and region == out_region == 2
            assert start <= B - size and out_at <= B - out_size
            assert start + size <= out_at or out_at + out_size <= start
            assert reserved == code == ack == done == denied == 0
            self.sequence = seq
            wire = ctypes.string_at(self.address + start, size)
            leaf, count = self.leaf_work[target]
            code = self.modules[target]._entry(ctypes.c_void_p(self.address + start), size,
                                              ctypes.c_void_p(self.address + out_at), out_size, leaf, count)
            COUNTS['native_leaf_calls'] += 1
            assert ctypes.string_at(self.address + start, size) == wire
            assert ctypes.string_at(ctypes.addressof(leaf) + count, 16) == b'\x6b' * 16
            self.trace.append((phase, target, code, sha(wire)))
            self.snapshots.append((phase, target, bytes(leaf.raw[:count])))
            self.put(B + 80, code)
            self.put(B + 88, seq)
            self.put(B + 96, 1)
            self.put(B + 104, 0)
            if fault is not None:
                fault(self, phase, target, out_at, out_size)
        raise AssertionError('record continuation did not terminate')


class RecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_RECORD_MANIFEST'])
        cls.meta = json.loads(cls.manifest.read_bytes())
        assert cls.meta['schema'] == 'hepta.runtime.native-composition.v1'
        assert len(cls.meta['members']) == 5
        cls.proof = json.loads((SOURCE_ROOT / 'native/operation_record_composition.json').read_bytes())
        assert cls.meta['profile'] == [{k: v for k, v in row.items() if k != 'source'} for row in cls.proof['members']]
        assert cls.meta['compiler_commit'] == cls.proof['compiler_commit']
        assert cls.meta['compiler_sha256'] == cls.proof['compiler_sha256']
        for name, digest in cls.proof['crypto_source_provenance'].items():
            assert sha((ROOT / name).read_bytes()) == digest
        cls.modules = {}
        expected = [SOURCE_ROOT / 'tests/hia_native/record_hex_transport.hepta',
                    SOURCE_ROOT / 'native/operation_record.hepta', ROOT / 'native/operation_kdf.hepta',
                    ROOT / 'native/binary_codec.hepta', ROOT / 'native/operation_aead.hepta']
        assert sha((ROOT / 'src/mcp/runtime/operation_crypto.rs').read_bytes()) == ORIGINAL_SHA
        for index, (row, path) in enumerate(zip(cls.meta['members'], expected)):
            manifest = cls.manifest.parent / row['manifest']
            assert sha(manifest.read_bytes()) == row['manifest_sha256']
            assert sha(path.read_bytes()) == row['source_sha256'] == cls.meta['profile'][index]['source_sha256']
            cls.modules[index] = open_module(manifest)
        assert [(p['id'], p['flags'], p['call_mask'], p['workspace_capacity']) for p in cls.meta['profile']] == [
            (0, 1, 2, 16 << 20), (1, 1, 28, WORK), (2, 0, 0, 2048), (3, 0, 0, 1184), (4, 0, 0, 512)]
        assert cls.meta['packer']['source_sha256'] == sha((ROOT / 'native/composition_packer.hepta').read_bytes())
        cls.exe = cls.manifest.parent / cls.meta['executable']
        assert sha(cls.exe.read_bytes()) == cls.meta['executable_sha256']
        cls.reference_sources = {}
        for name in ['oracle_operation_record.rs', 'record_oracle/Cargo.toml', 'record_oracle/Cargo.lock',
                     'record_oracle/build.rs', 'record_oracle/original_access.rs']:
            path = Path(__file__).parent / name
            cls.reference_sources[name] = sha(path.read_bytes())
        code, digest, cls.empty_hash_workspace = cls.modules[3].invoke_raw(
            b'HRCODEC1' + struct.pack('<2Q', 1, 0), output_capacity=32, workspace_capacity=1184,
            workspace_fill=0x33)
        assert code == 32 and digest == hashlib.sha256(b'').digest()
        COUNTS['codec_cleanup_reference_calls'] += 1

    @classmethod
    def tearDownClass(cls):
        for module in cls.modules.values():
            module.close()
        for name, digest in cls.reference_sources.items():
            assert sha((Path(__file__).parent / name).read_bytes()) == digest
        if os.environ.get('HIA_RECORD_CORPUS_DIR'):
            assert len(cls.reference_sources) == 5, 'complete locked Rust recipe required for corpus export'
            folder = Path(os.environ['HIA_RECORD_CORPUS_DIR'])
            folder.mkdir(parents=True, exist_ok=False)
            raw = b''.join(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n' for row in CORPUS)
            packed = gzip.compress(raw, mtime=0)
            (folder / 'record_cases.jsonl.gz').write_bytes(packed)
            result = {'schema': 'hepta.runtime.native-operation-record-corpus.v1', 'counts': COUNTS,
                      'source_sha256': cls.modules[1].metadata['source_sha256'],
                      'image_sha256': cls.modules[1].metadata['image_sha256'],
                      'original_source_sha256': ORIGINAL_SHA, 'oracle_sources_sha256': cls.reference_sources,
                      'manifest_sha256': sha(cls.manifest.read_bytes()),
                      'composition_sha256': sha((SOURCE_ROOT / 'native/operation_record_composition.json').read_bytes()),
                      'test_sha256': sha(Path(__file__).read_bytes()),
                      'builder_sha256': sha((SOURCE_ROOT / 'scripts/hia_native_record_build.py').read_bytes()),
                      'composition_sources': [row['source_sha256'] for row in cls.meta['members']],
                      'python_reference': {'distribution': 'cryptography', 'version': cryptography.__version__,
                                           'algorithms': ['ChaCha20Poly1305', 'stdlib hmac SHA256', 'stdlib hashlib SHA256']},
                      'native_output_sha256': sha(''.join(str(row['code']) + ':' + row['output_hex'] + '\n' for row in CORPUS).encode()),
                      'corpus': {'file': 'record_cases.jsonl.gz', 'gzip_sha256': sha(packed),
                                 'raw_sha256': sha(raw), 'raw_bytes': len(raw), 'cases': len(CORPUS)}}
            (folder / 'native-corpus.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        print(json.dumps({'native_record_counts': COUNTS}, sort_keys=True))

    def setUp(self):
        self.h = Harness(self.modules)

    def case(self, wire, want=b'', *, error=None, capacity=None, export=True, token=None, fault=None):
        if capacity is None:
            capacity = len(want) + 19
            if error in (INTEGRITY, CHILD):
                capacity = max(capacity, 1048660)
        code, value, calls = self.h.invoke(wire, capacity, fault=fault)
        self.assertEqual(code, error if error is not None else len(want))
        self.assertEqual(value, b'' if error is not None else want)
        if error is not None:
            label = {BINDING: 'binding_refusals', INTEGRITY: 'integrity_refusals', CAPACITY: 'capacity_refusals',
                     CHILD: 'child_contract_refusals'}.get(error, 'admission_refusals')
            COUNTS[label] += 1
        if export:
            row = {'input_hex': wire.hex(), 'code': code, 'output_hex': value.hex()}
            if token is not None:
                row['verified_token_hex'] = token.hex()
            CORPUS.append(row)
        return calls

    def pair(self, payload, *, key=KEY, nonce=NONCE, fields=FIELDS, kind=1, timestamp=(1 << 100) + 123, token=None):
        options = dict(fields=fields, kind=kind, timestamp=timestamp)
        packet = seal(payload, key=key, nonce=nonce, **options)
        start = len(self.h.trace)
        self.case(frame(2, key + nonce + payload, **options), packet, token=token)
        COUNTS['seal_reference_cases'] += 1
        self.assertEqual([v[1] for v in self.h.trace[start:]], [2, 3, 3, 4])
        start = len(self.h.trace)
        self.case(frame(3, key + packet, **options), payload, token=token)
        COUNTS['open_reference_cases'] += 1
        self.assertEqual([v[1] for v in self.h.trace[start:]], [2, 4, 3, 3])
        self.assertEqual(bytes(self.h.leaf_work[3][0].raw[:1184]), self.empty_hash_workspace)
        self.assertEqual(bytes(self.h.leaf_work[2][0].raw[:2048]), bytes(2048))
        self.assertEqual(bytes(self.h.leaf_work[4][0].raw[:512]), bytes(512))
        return packet

    def test_binding_aad_and_full_u128_timestamp(self):
        timestamps = [0, 1, (1 << 32) - 1, (1 << 64) - 1, 1 << 64, (1 << 96) + 123, (1 << 128) - 1]
        for timestamp in timestamps:
            for kind in (1, 2):
                for tool in [b'a', b'binary_read', b'z_' + b'7' * 126]:
                    fields = list(FIELDS)
                    fields[2] = tool
                    self.case(frame(1, fields=fields, kind=kind, timestamp=timestamp), aad(fields, kind, timestamp))
                    COUNTS['aad_reference_cases'] += 1
        rng = random.Random(0x41414432303236)
        for _ in range(64):
            fields = [bytes(rng.choice(b'0123456789abcdef') for _ in range(64)) for _ in range(6)]
            fields[2] = bytes([rng.randrange(97, 123)]) + bytes(rng.choice(b'abcdefghijklmnopqrstuvwxyz_0123456789') for _ in range(rng.randrange(128)))
            timestamp, kind = rng.getrandbits(128), rng.choice([1, 2])
            self.case(frame(1, fields=fields, kind=kind, timestamp=timestamp), aad(fields, kind, timestamp))
            COUNTS['aad_reference_cases'] += 1
        for index in (0, 1, 3, 4, 5):
            for bad in [b'', b'a' * 63, b'a' * 65, b'A' * 64, b'g' * 64, b'_' * 64,
                        b'\0' + b'0' * 63, b'0' * 63 + b'\n', 'é'.encode() * 32]:
                fields = list(FIELDS)
                fields[index] = bad
                self.case(frame(1, fields=fields), error=BINDING)
        for tool in [b'', b'a' * 129, b'A', b'0a', b'_a', b'a-b', b'a.b', b'a/b', b'a\0b', b'a b',
                     b'a\nb', '读'.encode(), b'a' + 'é'.encode()]:
            fields = list(FIELDS)
            fields[2] = tool
            self.case(frame(1, fields=fields), error=BINDING)
        self.assertEqual(self.h.trace, [])

    def test_native_seal_open_boundaries_and_independent_reference(self):
        rng = random.Random(0x5245434f5244)
        sizes = [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 47, 48, 49, 55, 56, 57, 63, 64, 65,
                 111, 112, 113, 127, 128, 129, 255, 256, 257, 4095, 4096, 4097,
                 65535, 65536, 65537, 1048575, 1048576]
        for kind in [1, 2]:
            for size in sizes:
                self.pair(rng.randbytes(size), key=rng.randbytes(32), nonce=rng.randbytes(12),
                          kind=kind, timestamp=rng.getrandbits(128))
        for _ in range(96):
            fields = list(FIELDS)
            fields[0], fields[5] = rng.randbytes(32).hex().encode(), rng.randbytes(32).hex().encode()
            self.pair(rng.randbytes(rng.randrange(2049)), key=rng.randbytes(32), nonce=rng.randbytes(12),
                      fields=fields, kind=rng.choice([1, 2]), timestamp=rng.getrandbits(128))
        for fill in [0, 255]:
            self.pair(bytes([fill]) * 4097, key=bytes([fill]) * 32, nonce=bytes([fill]) * 12)
        for token in [b'A' * 32, b'!~fixture-record-verified-token-01', b'X' * 4096]:
            prk = hmac.digest(PREFIX + b'crypto/extract/v1', token, 'sha256')
            key = hmac.digest(prk, PREFIX + b'result-aead/v1' + b'\x01', 'sha256')
            self.pair(b'\x00synthetic original scope payload\xff', key=key, token=token)

    def test_original_admission_order_and_preflight(self):
        bad = list(FIELDS)
        bad[0] = b'X' * 64
        for size in [0, 1, 1048576]:
            value = b'p' * size
            self.case(frame(4, value), aad())
            COUNTS['preflight_reference_cases'] += 1
            self.case(frame(4, value, fields=bad), error=BINDING)
        for op, tail in [(4, b'x' * 1048577), (2, KEY + NONCE + b'x' * 1048577)]:
            self.case(frame(op, tail), error=PAYLOAD)
            self.case(frame(op, tail, fields=bad), error=PAYLOAD)
        for packet in [b'', b'HEPTAOP1', b'HEPTAOP1' + b'x' * 75, b'WRONGMAG' + b'x' * 76,
                       b'HEPTAOP1' + b'x' * (1048661 - 8)]:
            self.case(frame(3, KEY + packet, fields=bad), error=INTEGRITY)
        packet = seal(b'')
        self.case(frame(3, KEY + packet, fields=bad), error=BINDING)
        self.case(frame(2, KEY + NONCE, fields=bad), error=BINDING)
        self.assertEqual(self.h.trace, [])

    def test_frame_refusals_and_no_unbounded_field_arithmetic(self):
        wire = frame(1)
        for n in range(96):
            self.case(wire[:n], error=INVALID)
        for at, values in [(0, [0, U64]), (8, [0, 5, U64]), (16, [1, U64]), (24, [0, 3, U64])]:
            for value in values:
                changed = bytearray(wire)
                struct.pack_into('<Q', changed, at, value)
                self.case(bytes(changed), error=INVALID)
        for at in range(48, 96, 8):
            changed = bytearray(wire)
            struct.pack_into('<Q', changed, at, U64)
            self.case(bytes(changed), error=INVALID)
        self.case(wire + b'tail', error=INVALID)
        for length in [0, 1, 31, 32, 43]:
            self.case(frame(2, b'x' * length), error=INVALID)
        for length in [0, 1, 31]:
            self.case(frame(3, b'x' * length), error=INVALID)
        # Non-UTF-8 is outside the old String input domain; it is tested as a
        # native typed-byte refusal and excluded from original-owner corpus.
        fields = list(FIELDS)
        fields[1] = b'\xff' * 64
        self.case(frame(1, fields=fields), error=BINDING, export=False)
        self.assertEqual(self.h.trace, [])

    def test_authentication_and_authenticated_inner_validation(self):
        payload = b'PRIVATE_RECORD_PAYLOAD_KNOWN_MARKER\x00\xff'
        packet = seal(payload)
        for index in range(len(packet)):
            changed = bytearray(packet)
            changed[index] ^= 1
            self.case(frame(3, KEY + changed), error=INTEGRITY)
        for index in range(32):
            changed = bytearray(KEY)
            changed[index] ^= 1
            self.case(frame(3, changed + packet), error=INTEGRITY)
        for index in range(6):
            fields = list(FIELDS)
            fields[index] = (b'z' if index == 2 else b'9') + fields[index][1:]
            self.case(frame(3, KEY + packet, fields=fields), error=INTEGRITY)
        for timestamp in [0, 1, 1 << 64, 1 << 100, (1 << 128) - 1]:
            self.case(frame(3, KEY + packet, timestamp=timestamp), error=INTEGRITY)
        self.case(frame(3, KEY + packet, kind=2), error=INTEGRITY)
        correct = b'HOPIN001' + len(payload).to_bytes(8, 'big') + hashlib.sha256(payload).digest() + payload
        malformed = [b'BADINNER' + correct[8:], correct[:8] + (len(payload) + 1).to_bytes(8, 'big') + correct[16:],
                     correct[:8] + (1048577).to_bytes(8, 'big') + correct[16:],
                     correct[:8] + U64.to_bytes(8, 'big') + correct[16:],
                     correct[:16] + bytes(32) + payload, correct[:48] + payload[:-1],
                     correct[:48] + payload + b'x']
        for inner in malformed:
            self.case(frame(3, KEY + seal(payload, inner=inner)), error=INTEGRITY)
        # A correctly authenticated empty payload is a zero-byte success.
        self.case(frame(3, KEY + seal(b'')), b'')
        COUNTS['open_reference_cases'] += 1

    def test_capacity_refusals_and_exact_output(self):
        payload = b'exact-capacity-record'
        packet = seal(payload)
        pairs = [(frame(1), aad()), (frame(4, payload), aad()),
                 (frame(2, KEY + NONCE + payload), packet), (frame(3, KEY + packet), payload),
                 (frame(3, KEY + seal(b'')), b'')]
        for wire, expected in pairs:
            self.case(wire, expected, capacity=len(expected), export=False)
            COUNTS['exact_capacity_successes'] += 1
            if expected:
                before = len(self.h.trace)
                self.case(wire, error=CAPACITY, capacity=len(expected) - 1, export=False)
                self.assertEqual(len(self.h.trace), before)
        for size in [0, 1, 255, 2048, WORK - 1]:
            code, out, work = self.modules[1].invoke_raw(frame(1), output_capacity=1024, workspace_capacity=size,
                                                        output_fill=0xa5, workspace_fill=0x5a)
            COUNTS['native_controller_calls'] += 1
            COUNTS['requests'] += 1
            COUNTS['capacity_refusals'] += 1
            self.assertEqual(code, CAPACITY)
            self.assertEqual(out, b'\xa5' * 1024)
            self.assertEqual(work, b'\x5a' * size)

    def test_all_codec_workspace_bytes_are_overwritten_and_record_scratch_cleared(self):
        secret = b'RECORD_PRIVATE_HASH_BUFFER_MARKER_v1'
        module = self.modules[3]
        work = ctypes.create_string_buffer(1184 + 19 + 16)
        address = ctypes.addressof(work)
        ctypes.memset(address, 0x73, len(work))
        out = ctypes.create_string_buffer(48)
        for payload in [secret, b'']:
            wire = b'HRCODEC1' + struct.pack('<2Q', 1, 0) + payload
            source = ctypes.create_string_buffer(wire)
            code = module._entry(source, len(wire), out, 32, work, 1184 + 19)
            COUNTS['codec_cleanup_reference_calls'] += 1
            self.assertEqual(code, 32)
            self.assertEqual(out.raw[:32], hashlib.sha256(payload).digest())
            self.assertEqual(work.raw[1184:], b'\x73' * 35)
            if payload:
                self.assertIn(secret, work.raw[:1184])
                prior = work.raw[:1184]
        self.assertNotEqual(prior, self.empty_hash_workspace)
        self.assertEqual(work.raw[:1184], self.empty_hash_workspace)
        self.assertNotIn(secret, work.raw[:1184])
        self.pair(secret)
        first = next(raw for phase, target, raw in self.h.snapshots if phase == 1 and target == 3)
        self.assertIn(secret, first)
        for phase, target, raw in self.h.snapshots:
            if target == 3 and phase in (2, 6):
                self.assertEqual(raw, self.empty_hash_workspace)
            elif target in (2, 4):
                self.assertEqual(raw, bytes(len(raw)))
        self.assertNotIn(secret, ctypes.string_at(self.h.address, B))

    def test_complete_child_lengths_and_control_record_contract(self):
        payload = b'private-child-contract-fixture'
        sealed = frame(2, KEY + NONCE + payload)
        opened = frame(3, KEY + seal(payload))
        for wire, phases in [(sealed, [1, 2, 3, 4]), (opened, [3, 4, 5, 6])]:
            for phase in phases:
                for delta in [-1, 1]:
                    self.h = Harness(self.modules)
                    def fault(h, current, target, at, size, wanted=phase, change=delta):
                        if current == wanted:
                            h.put(B + 80, h.get(B + 80) + change)
                    self.case(wire, error=CHILD, fault=fault, export=False)
                    self.assertTrue(self.h.retired)
                for offset, value in [(8, 0), (16, 15), (24, 0), (32, U64), (40, U64),
                                      (48, 1), (56, U64), (64, U64), (72, 1),
                                      (80, 1 << 40), (88, 0), (96, 0), (104, 1), (120, 1), (128, 0)]:
                    self.h = Harness(self.modules)
                    def fault(h, current, target, at, size, wanted=phase, offset=offset, value=value):
                        if current == wanted:
                            h.put(B + offset, value)
                    self.case(wire, error=CHILD, fault=fault, export=False)
            self.h = Harness(self.modules)
            def corrupt_empty(h, current, target, at, size):
                if current in (2, 6):
                    ctypes.memset(h.address + at, 0, size)
            self.case(wire, error=CHILD, fault=corrupt_empty, export=False)
        self.h = Harness(self.modules)
        def impossible_seal_auth_error(h, phase, target, at, size):
            if phase == 4:
                h.put(B + 80, 0xfffffffc)
        self.case(sealed, error=CHILD, fault=impossible_seal_auth_error, export=False)
        # The bridge sequence cannot wrap. This terminal refusal occurs before
        # any yield, so inspect its admitted scratch explicitly rather than
        # letting the transport infer a high-water mark from an earlier call.
        h = Harness(self.modules)
        h.put(B + 8, U64)
        before = ctypes.string_at(h.address, B)
        source = ctypes.create_string_buffer(sealed)
        output = ctypes.create_string_buffer(512)
        ctypes.memset(ctypes.addressof(output), 0xa5, 512)
        code = self.modules[1]._entry(source, len(sealed), output, 512, h.work, WORK)
        COUNTS['native_controller_calls'] += 1
        COUNTS['requests'] += 1
        COUNTS['child_contract_refusals'] += 1
        self.assertEqual(code, CHILD)
        high = 2048 + 216
        self.assertEqual(ctypes.string_at(h.address, high), bytes(high))
        self.assertEqual(ctypes.string_at(h.address + high, B - high), before[high:])
        self.assertEqual(output.raw, b'\xa5' * 512)

    def test_persistent_composed_elf(self):
        payload = b'ELF\x00authenticated record\n\xff'
        packet = seal(payload)
        mutated = bytearray(packet)
        mutated[-1] ^= 1
        bad_inner = b'HOPIN001' + (len(payload) + 1).to_bytes(8, 'big') + hashlib.sha256(payload).digest() + payload
        pairs = [(frame(1), len(aad()), aad()), (frame(4, payload), len(aad()), aad()),
                 (frame(2, KEY + NONCE + payload), len(packet), packet),
                 (frame(3, KEY + packet), len(payload), payload),
                 (frame(3, KEY + mutated), INTEGRITY, b''),
                 (frame(3, KEY + seal(payload, inner=bad_inner)), INTEGRITY, b''),
                 (frame(3, KEY + seal(b'')), 0, b''),
                 (frame(2, KEY + NONCE, kind=2), 84, seal(b'', kind=2)),
                 (frame(3, KEY + seal(b'', kind=2), kind=2), 0, b'')]
        completed = subprocess.run([str(self.exe), '--local-read-profile', '/record-fixture'],
                                   input=b''.join(wire.hex().encode() + b'\n' for wire, _, _ in pairs),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors='replace'))
        self.assertEqual(completed.stderr, b'')
        rows = completed.stdout.splitlines()
        self.assertEqual(len(rows), len(pairs))
        for row, (_, code, expected) in zip(rows, pairs):
            number, value = row.split(b':')
            self.assertEqual(int(number, 16), code)
            self.assertEqual(bytes.fromhex(value.decode()), expected)
            COUNTS['actual_elf_requests'] += 1


if __name__ == '__main__':
    unittest.main()
