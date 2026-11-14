"""Actual HIA SHA256/state/Base64 checks against independent standard libraries."""
from __future__ import annotations
import base64, binascii, copy, gzip, hashlib, itertools, json, os
from pathlib import Path
import random, struct, subprocess, sys, unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule

INVALID, CAPACITY, BOUND = 0xffffffff, 0xfffffffe, 0xfffffffd
MAX_CHUNK = 1 << 20
MAX_TOTAL = (1 << 61) - 1
COUNTS = {'native_calls': 0, 'rust_oracle_cases': 0, 'desktop_python_cases': 0, 'running_python_cases': 0}
CORPUS = []


def frame(op, payload=b''):
    return b'HRCODEC1' + struct.pack('<QQ', op, 0) + payload


def decode_reference(payload, mode):
    # Python 3.12.3 and 3.12.14 differ on surplus padding after full quartets.
    # Keep that choice explicit; mode 10 additionally checks canonical pad bits.
    candidate = payload
    if mode == 8:
        prefix = payload.rstrip(b'=')
        if prefix and len(prefix) % 4 == 0 and len(prefix) < len(payload):
            candidate = prefix
    try:
        output = base64.b64decode(candidate, validate=True)
        canonical = base64.b64encode(output)
        if mode >= 9 and len(payload) != len(canonical):
            return None
        if mode == 10 and payload != canonical:
            return None
        return output
    except (ValueError, binascii.Error):
        return None


class BinaryCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = os.environ.get('HIA_CODEC_MANIFEST')
        if not selected:
            from hia_native_build import NativeBuild
            selected = NativeBuild(os.environ['HIA_HEPTA_DIR'], os.environ['HIA_BUILD_ROOT']).compile(
                'binary-codec', ROOT / 'native/binary_codec.hepta', standalone='filter')
        cls.manifest = Path(selected).resolve(strict=True)
        cls.native = NativeModule(cls.manifest, manifest_sha256=hashlib.sha256(cls.manifest.read_bytes()).hexdigest())
        cls.metadata = cls.native.metadata
        assert cls.metadata['source_sha256'] == hashlib.sha256((ROOT / 'native/binary_codec.hepta').read_bytes()).hexdigest()
        try:
            base64.b64decode(b'AAAA=', validate=True)
            cls.python_policy = 8
        except ValueError:
            cls.python_policy = 9

    @classmethod
    def tearDownClass(cls):
        cls.native.close()
        target = os.environ.get('HIA_CODEC_CORPUS_DIR')
        if target:
            folder = Path(target)
            folder.mkdir(parents=True, exist_ok=True)
            raw = ''.join(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n' for row in CORPUS).encode()
            packed = gzip.compress(raw, mtime=0)
            (folder / 'codec_cases.jsonl.gz').write_bytes(packed)
            metadata = {'schema': 'hepta.runtime.native-codec-corpus.v1', 'counts': COUNTS,
                        'source_sha256': cls.metadata['source_sha256'], 'image_sha256': cls.metadata['image_sha256'],
                        'python_reference': sys.version, 'running_python_policy': cls.python_policy,
                        'oracle_source_sha256': hashlib.sha256(Path(__file__).with_name('oracle_binary_codec.rs').read_bytes()).hexdigest(),
                        'cargo_manifest_sha256': hashlib.sha256((ROOT / 'tests/hia_native/codec_oracle/Cargo.toml').read_bytes()).hexdigest(),
                        'cargo_lock_sha256': hashlib.sha256((ROOT / 'tests/hia_native/codec_oracle/Cargo.lock').read_bytes()).hexdigest(),
                        'composition_sha256': hashlib.sha256((ROOT / 'native/binary_codec_composition.json').read_bytes()).hexdigest(),
                        'corpus': {'file': 'codec_cases.jsonl.gz',
                        'gzip_sha256': hashlib.sha256(packed).hexdigest(), 'gzip_bytes': len(packed),
                        'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_bytes': len(raw)}}
            (folder / 'native-corpus.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')

    def call(self, op, payload=b'', *, want=None, error=None, capacity=None, workspace=None, export=True):
        if capacity is None:
            capacity = max(128, len(want or b'') + 13)
        if workspace is None:
            workspace = 1197 if op <= 6 else 17
        raw = frame(op, payload)
        code, output, scratch = self.native.invoke_raw(raw, output_capacity=capacity,
            workspace_capacity=workspace, output_fill=0xa5, workspace_fill=0x5a)
        COUNTS['native_calls'] += 1
        if error is not None:
            self.assertEqual(code, error, (op, payload[:80]))
            self.assertEqual(output, b'\xa5' * capacity)
            self.assertEqual(scratch, b'\x5a' * workspace)
            result = b''
        else:
            self.assertLess(code, 0xffff0000, (op, payload[:80], code))
            result = output[:code]
            if want is not None:
                self.assertEqual(result, want, (op, len(payload)))
            self.assertEqual(output[code:], b'\xa5' * (capacity - code))
            self.assertEqual(scratch[1184:] if op <= 6 else scratch,
                             b'\x5a' * (max(0, workspace - 1184) if op <= 6 else workspace))
        if export and op in (1, 2, 7, 8, 9, 10) and error != CAPACITY and len(payload) <= 1_398_104:
            CORPUS.append({'kind': 'call', 'op': op, 'input_hex': payload.hex(), 'code': code, 'output_hex': result.hex()})
            COUNTS['rust_oracle_cases'] += 1
            if op == 8:
                COUNTS['desktop_python_cases'] += 1
        if op == self.python_policy and error != CAPACITY:
            if len(payload) > 1_398_104:
                reference_code, reference_output = BOUND, b''
            else:
                try:
                    reference_output = base64.b64decode(payload, validate=True)
                    if len(reference_output) > MAX_CHUNK:
                        reference_code, reference_output = BOUND, b''
                    else:
                        reference_code = len(reference_output)
                except ValueError:
                    reference_code, reference_output = INVALID, b''
            self.assertEqual((code, result), (reference_code, reference_output))
            COUNTS['running_python_cases'] += 1
        return result

    def stream_digest(self, state, message, hexadecimal=False):
        expected = hashlib.sha256(message).hexdigest().encode() if hexadecimal else hashlib.sha256(message).digest()
        output = self.call(6 if hexadecimal else 5, state, want=expected, export=False)
        CORPUS.append({'kind': 'stream_digest', 'input_state_hex': state.hex(), 'message_hex': message.hex(),
                       'hexadecimal': hexadecimal, 'output_hex': output.hex()})
        COUNTS['rust_oracle_cases'] += 1
        return output

    def test_sha256_vectors_padding_and_chunk_boundaries(self):
        values = [b'', b'abc', b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
                  b'a' * 1_000_000, bytes(range(256)) * 4096]
        values += [bytes((i * 137 + 29) & 255 for i in range(n))
                   for n in (1, 2, 3, 31, 32, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 4095, 4096, 4097)]
        for value in values:
            self.call(1, value, want=hashlib.sha256(value).digest())
            self.call(2, value, want=hashlib.sha256(value).hexdigest().encode())
        self.assertEqual(hashlib.sha256(b'a' * 1_000_000).hexdigest(), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
        self.call(1, b'x' * (MAX_CHUNK + 1), error=BOUND)

    def test_stream_state_partition_invariance_and_forks(self):
        initial = self.call(3, export=False)
        expected = struct.pack('<8sQQ8I64sQ', b'HSHA2561', 0, 0,
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, bytes(64), 0)
        self.assertEqual(initial, expected)
        for n in (0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256):
            value = bytes((i * 17 + 93) & 255 for i in range(n))
            expected_state = self.call(4, initial + value, export=False)
            for split in range(n + 1):
                state = self.call(4, initial + value[:split], export=False)
                state = self.call(4, state + value[split:], want=expected_state, export=False)
            self.stream_digest(expected_state, value)
            self.stream_digest(expected_state, value, True)
            fork = self.call(4, expected_state + b'fork', export=False)
            self.stream_digest(fork, value + b'fork')
            self.stream_digest(expected_state, value)
        rng = random.Random(0x256b64)
        for _ in range(150):
            value = rng.randbytes(rng.randrange(2049))
            state, at = initial, 0
            while at < len(value):
                end = min(len(value), at + rng.randrange(1, 132))
                state = self.call(4, state + value[at:end], export=False)
                at = end
            self.stream_digest(state, value)
        value = bytes(range(256)) * 4096
        state = initial
        for _ in range(9):
            state = self.call(4, state + value, export=False)
        self.stream_digest(state, value * 9)

    def test_base64_roundtrip_and_exact_size_limits(self):
        values = [b'', *[bytes([v]) for v in range(256)], bytes(range(256)) * 4096]
        rng = random.Random(0xB64)
        values += [rng.randbytes(rng.randrange(1025)) for _ in range(300)]
        for value in values:
            encoded = base64.b64encode(value)
            self.call(7, value, want=encoded)
            for mode in (8, 9, 10):
                self.call(mode, encoded, want=value)
        self.call(7, b'x' * (MAX_CHUNK + 1), error=BOUND)
        for mode in (8, 9, 10):
            self.call(mode, b'A' * 1_398_104, error=BOUND)
            self.call(mode, b'A' * 1_398_105, error=BOUND, export=False)

    def test_base64_exhaustive_short_grammar_and_noncanonical_bits(self):
        inputs = [b'', b'AAAA=', b'AAAA====', b'AAAA=AAAA', b'Zh==', b'Zm9=', b'====',
                  b'AA==\r\n', b'AA\x00==', b'_w==', b'-w==', b'\xff===', b'\xc3\xa9==']
        alphabet = b'AZ0+/= \n'
        for size in range(1, 5):
            inputs.extend(bytes(row) for row in itertools.product(alphabet, repeat=size))
        alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        inputs.extend(b'A' + bytes([v]) + b'==' for v in alphabet)
        inputs.extend(b'AA' + bytes([v]) + b'=' for v in alphabet)
        for payload in inputs:
            for mode in (8, 9, 10):
                expected = decode_reference(payload, mode)
                self.call(mode, payload, want=expected, error=INVALID if expected is None else None)

    def test_capacity_state_validation_and_overflow_refuse_without_writes(self):
        initial = self.call(3, export=False)
        for op, body, capacity, workspace in ((1, b'abc', 31, 1184), (2, b'abc', 63, 1184),
                (3, b'', 127, 1184), (4, initial + b'abc', 127, 1184),
                (5, initial, 31, 1184), (6, initial, 63, 1184), (1, b'abc', 32, 1183),
                (7, b'ab', 3, 0), (8, b'YWI=', 1, 0), (10, b'YWI=', 1, 0)):
            self.call(op, body, error=CAPACITY, capacity=capacity, workspace=workspace, export=False)
        for offset, replacement in ((0, b'X'), (16, struct.pack('<Q', 64)), (24, b'X'),
                                    (56, b'X'), (120, b'X'), (8, struct.pack('<Q', MAX_TOTAL + 1))):
            state = bytearray(initial)
            state[offset:offset + len(replacement)] = replacement
            for op in (4, 5, 6):
                self.call(op, bytes(state), error=INVALID, capacity=0, workspace=0, export=False)
        self.call(3, b'x', error=INVALID, export=False)
        self.call(4, initial[:-1], error=INVALID, export=False)
        self.call(5, initial + b'x', error=INVALID, export=False)
        self.call(4, initial + b'x' * (MAX_CHUNK + 1), error=BOUND, export=False)
        state = bytearray(initial)
        struct.pack_into('<QQ', state, 8, MAX_TOTAL, 63)
        self.call(4, bytes(state) + b'x', error=BOUND, export=False)
        self.call(4, bytes(state), want=bytes(state), export=False)
        self.assertEqual(len(self.call(5, bytes(state), export=False)), 32)
        for raw in (b'', b'HRCODEC1', frame(0), frame(11), b'X' + frame(1)[1:], frame(1)[:16] + b'\x01' + bytes(7)):
            code, out, work = self.native.invoke_raw(raw, output_capacity=256, workspace_capacity=1200,
                                                    output_fill=0xa5, workspace_fill=0x5a)
            COUNTS['native_calls'] += 1
            self.assertEqual((code, out, work), (INVALID, b'\xa5' * 256, b'\x5a' * 1200))

    def test_upstream_hia_compression_has_only_function_index_relocation(self):
        sys.path.insert(0, os.environ['HIA_HEPTA_DIR'])
        from hepta.hia_agent_assembly import assemble_program
        source = (ROOT / 'native/binary_codec.hepta').read_bytes()
        composition = json.loads((ROOT / 'native/binary_codec_composition.json').read_bytes())
        self.assertEqual(hashlib.sha256(source).hexdigest(), composition['composed_source_sha256'])
        upstream = Path(os.environ['HIA_HEPTA_DIR']) / composition['upstream_source']
        self.assertEqual(hashlib.sha256(upstream.read_bytes()).hexdigest(), composition['upstream_source_sha256'])
        inverse = {v: k for k, v in composition['relocation'].items()}
        functions = assemble_program(source).as_dict()['functions']
        for original, relocated in composition['relocation'].items():
            function = copy.deepcopy(next(f for f in functions if f['name'] == relocated))
            function['name'] = original
            for block in function['blocks']:
                for instruction in block['ops']:
                    if instruction['op'] == 'call':
                        instruction['attrs']['function'] = inverse[instruction['attrs']['function']]
            actual = hashlib.sha256(json.dumps(function, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            self.assertEqual(actual, composition['upstream_functions_sha256'][original])

    def test_standalone_filter_without_runtime_libraries(self):
        executable = self.manifest.parent / self.metadata['standalone']['path']
        self.assertEqual(hashlib.sha256(executable.read_bytes()).hexdigest(), self.metadata['standalone']['sha256'])
        for op, payload, expected in ((1, b'abc', hashlib.sha256(b'abc').digest()),
                                      (7, b'abc\x00', b'YWJjAA=='), (10, b'YWJjAA==', b'abc\x00')):
            row = subprocess.run([str(executable)], input=frame(op, payload), capture_output=True,
                                  env={'PATH': '', 'LANG': 'C'}, timeout=10)
            self.assertEqual((row.returncode, row.stdout, row.stderr), (0, expected, b''))


if __name__ == '__main__':
    unittest.main(verbosity=2)
