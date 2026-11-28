"""Native ChaCha20-Poly1305 against RFC 8439 and an independent library.

All keys, nonces and payloads are synthetic test data. This module does not
qualify nonce custody, result binding, record framing or production activation.
"""
from pathlib import Path
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

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import cryptography

ROOT = Path(os.environ.get('HIA_REFERENCE_RUNTIME', Path(__file__).resolve().parents[2]))
SOURCE_ROOT = Path(os.environ.get('HIA_AEAD_SOURCE_ROOT', ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule

INVALID, CAPACITY, BOUND, AUTHENTICATION = 0xffffffff, 0xfffffffe, 0xfffffffd, 0xfffffffc
COUNTS = {'native_calls': 0, 'encryption_reference_cases': 0, 'decryption_reference_cases': 0,
          'authentication_refusals': 0, 'admission_refusals': 0, 'capacity_refusals': 0,
          'exact_capacity_successes': 0, 'original_record_projection_cases': 0, 'elf_requests': 0}
CORPUS = []


def frame(op, key, nonce, aad, value):
    size = len(value) - (16 if op == 2 else 0)
    assert len(key) == 32 and len(nonce) == 12 and size >= 0
    return b'HRAEAD01' + struct.pack('<4Q', op, 0, len(aad), size) + key + nonce + bytes(4) + aad + value


class AeadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_AEAD_MANIFEST'])
        cls.module = NativeModule(cls.manifest, manifest_sha256=hashlib.sha256(cls.manifest.read_bytes()).hexdigest())
        cls.proof = json.loads((SOURCE_ROOT / 'native/operation_aead_composition.json').read_text())
        assert hashlib.sha256((SOURCE_ROOT / 'native/operation_aead.hepta').read_bytes()).hexdigest() == cls.proof['source_sha256'] == cls.module.metadata['source_sha256']
        assert hashlib.sha256((ROOT / cls.proof['original_source']).read_bytes()).hexdigest() == cls.proof['original_source_sha256']
        cls.reference_sources = {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                                 for name in ['oracle_operation_aead.rs', 'aead_oracle/Cargo.toml', 'aead_oracle/Cargo.lock',
                                              'aead_oracle/build.rs', 'aead_oracle/original_access.rs']}

    @classmethod
    def tearDownClass(cls):
        cls.module.close()
        for name, digest in cls.reference_sources.items():
            assert hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest() == digest
        if os.environ.get('HIA_AEAD_CORPUS_DIR'):
            folder = Path(os.environ['HIA_AEAD_CORPUS_DIR'])
            folder.mkdir(parents=True, exist_ok=False)
            raw = b''.join(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n' for row in CORPUS)
            packed = gzip.compress(raw, mtime=0)
            (folder / 'aead_cases.jsonl.gz').write_bytes(packed)
            metadata = {'schema': 'hepta.runtime.native-operation-aead-corpus.v1', 'counts': COUNTS,
                        'source_sha256': cls.module.metadata['source_sha256'], 'image_sha256': cls.module.metadata['image_sha256'],
                        'original_source_sha256': cls.proof['original_source_sha256'],
                        'oracle_sources_sha256': cls.reference_sources,
                        'python_reference': {'distribution': 'cryptography', 'version': cryptography.__version__, 'algorithm': 'ChaCha20Poly1305'},
                        'native_output_sha256': hashlib.sha256(''.join(str(row['code']) + ':' + row['output_hex'] + '\n' for row in CORPUS).encode()).hexdigest(),
                        'composition_sha256': hashlib.sha256((SOURCE_ROOT / 'native/operation_aead_composition.json').read_bytes()).hexdigest(),
                        'corpus': {'file': 'aead_cases.jsonl.gz', 'gzip_sha256': hashlib.sha256(packed).hexdigest(),
                                   'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_bytes': len(raw), 'cases': len(CORPUS)}}
            (folder / 'native-corpus.json').write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')

    def raw(self, wire, *, want=None, error=None, capacity=None, workspace=529, export=True, original=None):
        if capacity is None:
            capacity = 19 + len(want or b'')
        code, out, work = self.module.invoke_raw(wire, output_capacity=capacity, workspace_capacity=workspace,
                                                output_fill=0xa5, workspace_fill=0x5a)
        COUNTS['native_calls'] += 1
        if error is not None:
            self.assertEqual(code, error)
            self.assertEqual(out, b'\xa5' * capacity, 'refusal must not expose partial plaintext or ciphertext')
            if error == AUTHENTICATION:
                self.assertEqual(work[:512], bytes(512))
                self.assertEqual(work[512:], b'\x5a' * (workspace - 512))
                COUNTS['authentication_refusals'] += 1
            else:
                self.assertEqual(work, b'\x5a' * workspace)
                COUNTS['capacity_refusals' if error == CAPACITY else 'admission_refusals'] += 1
            value = b''
        else:
            self.assertEqual(code, len(want))
            value = out[:code]
            self.assertEqual(value, want)
            self.assertEqual(out[code:], b'\xa5' * (capacity - code))
            self.assertEqual(work[:512], bytes(512), 'secret-bearing workspace must be wiped')
            self.assertEqual(work[512:], b'\x5a' * (workspace - 512))
        if export:
            row = {'input_hex': wire.hex(), 'code': code, 'output_hex': value.hex()}
            if original is not None:
                row['original_record'] = original
            CORPUS.append(row)
        return value

    def pair(self, key, nonce, aad, message, expected=None):
        cipher = ChaCha20Poly1305(key).encrypt(nonce, message, aad)
        if expected is not None:
            self.assertEqual(cipher, expected)
        self.raw(frame(1, key, nonce, aad, message), want=cipher)
        COUNTS['encryption_reference_cases'] += 1
        self.assertEqual(ChaCha20Poly1305(key).decrypt(nonce, cipher, aad), message)
        self.raw(frame(2, key, nonce, aad, cipher), want=message)
        COUNTS['decryption_reference_cases'] += 1
        return cipher

    def test_rfc8439_known_answer(self):
        # RFC 8439, section 2.8.2: fixed published ciphertext and full tag.
        key = bytes(range(0x80, 0xa0))
        nonce = bytes.fromhex('070000004041424344454647')
        aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
        message = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        cipher = bytes.fromhex('d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6'
                               '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36'
                               '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc'
                               '3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691')
        self.pair(key, nonce, aad, message, expected=cipher)

    def test_block_padding_counter_and_length_boundaries(self):
        rng = random.Random(8439)
        sizes = [0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257]
        for aad_size in sizes:
            for size in sizes:
                self.pair(rng.randbytes(32), rng.randbytes(12), rng.randbytes(aad_size), rng.randbytes(size))
        for size in [4095, 4096, 4097, 16383, 16384, 16385, 65535, 65536, 65537]:
            self.pair(rng.randbytes(32), rng.randbytes(12), rng.randbytes(17), rng.randbytes(size))
        for fill in [0, 255]:
            self.pair(bytes([fill]) * 32, bytes([fill]) * 12, bytes([fill]) * 33, bytes([fill]) * 4097)
        for aad_size, size in [(1048576, 0), (0, 1048624), (1048576, 1048624)]:
            self.pair(rng.randbytes(32), rng.randbytes(12), bytes([size % 251]) * aad_size,
                      bytes([aad_size % 251]) * size)

    def test_seeded_independent_reference_cases(self):
        rng = random.Random(0xaead2026)
        for _ in range(256):
            self.pair(rng.randbytes(32), rng.randbytes(12), rng.randbytes(rng.randrange(1025)),
                      rng.randbytes(rng.randrange(4097)))

    def test_original_record_owner_interoperability_fixtures(self):
        # The locked Rust oracle calls complete original seal/open owners for
        # these projections. Python constructs an independent expected packet.
        prefix = b'hepta-runtime/native-operation/'
        mac = lambda key, value: hmac.digest(key, value, 'sha256')
        rng = random.Random(0x0f1a2026)
        for index, size in enumerate([0, 1, 15, 16, 17, 63, 64, 65, 1024, 65536, 1048576]):
            token = bytes(rng.randrange(33, 127) for _ in range(32 + index * 17))
            fields = [rng.randbytes(32).hex().encode() for _ in range(5)]
            operation, owner, policy, request, ledger = fields
            tool = b'read_multiple_files' if index % 2 else b'binary_read'
            kind = b'native_result' if index % 2 else b'native_error'
            accepted = [0, 1, (1 << 64) - 1, 1 << 64, (1 << 128) - 1][index % 5]
            nonce = rng.randbytes(12)
            payload = bytes([index]) * size
            prk = mac(prefix + b'crypto/extract/v1', token)
            root_key = mac(prk, prefix + b'result-aead/v1' + b'\x01')
            key = mac(mac(prefix + b'record-key/extract/v1', root_key),
                      prefix + b'record-key/expand/v1' + operation + ledger + b'\x01')
            pieces = [prefix + b'result-aad/v1', b'HEPTAOP1', b'chacha20_poly1305',
                      b'serialized-native-sdk-result-family/v1', operation, owner, tool,
                      policy, request, ledger, kind]
            aad = b''.join(len(value).to_bytes(4, 'big') + value for value in pieces) + accepted.to_bytes(16, 'big')
            inner = b'HOPIN001' + size.to_bytes(8, 'big') + hashlib.sha256(payload).digest() + payload
            cipher = ChaCha20Poly1305(key).encrypt(nonce, inner, aad)
            projection = {'token_hex': token.hex(), 'operation_id': operation.decode(), 'owner': owner.decode(),
                          'tool_name': tool.decode(), 'policy_binding': policy.decode(), 'request_binding': request.decode(),
                          'ledger_identity': ledger.decode(), 'payload_kind': kind.decode(),
                          'accepted_unix_ms': str(accepted), 'payload_hex': payload.hex()}
            self.raw(frame(1, key, nonce, aad, inner), want=cipher, original=projection)
            self.raw(frame(2, key, nonce, aad, cipher), want=inner, original=projection)
            bad = bytearray(cipher)
            bad[-1] ^= 0x80
            self.raw(frame(2, key, nonce, aad, bytes(bad)), error=AUTHENTICATION,
                     capacity=len(inner), original=projection)
            COUNTS['original_record_projection_cases'] += 3

    def test_authentication_failure_never_releases_plaintext(self):
        key, nonce, aad, message = bytes(range(32)), bytes(range(12)), bytes(range(33)), bytes(range(129))
        cipher = ChaCha20Poly1305(key).encrypt(nonce, message, aad)
        valid = frame(2, key, nonce, aad, cipher)
        positions = list(range(40, 84)) + list(range(88, len(valid)))
        for at in positions:
            damaged = bytearray(valid)
            damaged[at] ^= 1
            self.raw(bytes(damaged), error=AUTHENTICATION, capacity=len(message) + 19)
        for index in range(16):
            for bit in range(1, 8):
                damaged = bytearray(valid)
                damaged[len(valid) - 16 + index] ^= 1 << bit
                self.raw(bytes(damaged), error=AUTHENTICATION, capacity=len(message) + 19)
        for size in [0, 1, 15, 16, 17, 63, 64, 65, 4097]:
            message = b'm' * size
            cipher = bytearray(ChaCha20Poly1305(key).encrypt(nonce, message, aad))
            cipher[-1] ^= 0x80
            self.raw(frame(2, key, nonce, aad, bytes(cipher)), error=AUTHENTICATION, capacity=size)

    def test_admission_and_capacity_preserve_mutable_buffers(self):
        key, nonce, aad, message = b'k' * 32, b'n' * 12, b'aad', b'message'
        valid = frame(1, key, nonce, aad, message)
        for size in range(88):
            self.raw(valid[:size], error=INVALID)
        for at in list(range(8)) + list(range(16, 24)) + list(range(84, 88)):
            damaged = bytearray(valid)
            damaged[at] ^= 1
            self.raw(bytes(damaged), error=INVALID)
        for op in [0, 3, (1 << 64) - 1]:
            damaged = bytearray(valid)
            struct.pack_into('<Q', damaged, 8, op)
            self.raw(bytes(damaged), error=INVALID)
        for at, value in [(24, 1048577), (32, 1048625), (24, (1 << 64) - 1), (32, (1 << 64) - 1)]:
            damaged = bytearray(valid)
            struct.pack_into('<Q', damaged, at, value)
            self.raw(bytes(damaged), error=BOUND)
        cipher = ChaCha20Poly1305(key).encrypt(nonce, message, aad)
        encrypted = frame(2, key, nonce, aad, cipher)
        for wire in [valid[:-1], valid + b'x', encrypted[:-1], encrypted + b'x']:
            self.raw(wire, error=INVALID)
        for op, value, expected in [(1, message, cipher), (2, cipher, message),
                                     (1, b'', ChaCha20Poly1305(key).encrypt(nonce, b'', b'')),
                                     (2, ChaCha20Poly1305(key).encrypt(nonce, b'', b''), b'')]:
            actual_aad = aad if value in (message, cipher) else b''
            wire = frame(op, key, nonce, actual_aad, value)
            if expected:
                self.raw(wire, error=CAPACITY, capacity=len(expected) - 1, export=False)
            for workspace in [0, 1, 511]:
                self.raw(wire, error=CAPACITY, capacity=len(expected), workspace=workspace, export=False)
            self.raw(wire, want=expected, capacity=len(expected), workspace=512)
            COUNTS['exact_capacity_successes'] += 1

    def test_standalone_filter_without_runtime_libraries(self):
        metadata = self.module.metadata
        executable = self.manifest.parent / metadata['standalone']['path']
        self.assertEqual(hashlib.sha256(executable.read_bytes()).hexdigest(), metadata['standalone']['sha256'])
        key, nonce = b'k' * 32, b'n' * 12
        for message, aad in [(b'', b''), (b'message', b'bound-context'), (bytes(range(256)) * 17, b'a' * 65)]:
            cipher = ChaCha20Poly1305(key).encrypt(nonce, message, aad)
            for op, value, expected in [(1, message, cipher), (2, cipher, message)]:
                run = subprocess.run([str(executable)], input=frame(op, key, nonce, aad, value),
                                     capture_output=True, env={'PATH': '', 'LANG': 'C'}, timeout=20)
                self.assertEqual((run.returncode, run.stdout, run.stderr), (0, expected, b''))
                COUNTS['elf_requests'] += 1


if __name__ == '__main__':
    result = unittest.main(exit=False, verbosity=2)
    print(json.dumps({'status': 'PASS' if result.result.wasSuccessful() else 'FAIL', 'counts': COUNTS}, sort_keys=True))
    raise SystemExit(0 if result.result.wasSuccessful() else 1)
