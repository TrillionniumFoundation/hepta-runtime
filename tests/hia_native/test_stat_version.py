"""Exact native file-version formatting and canonical inverse qualification."""
from pathlib import Path
from types import SimpleNamespace
import argparse
import ast
import gzip
import hashlib
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
U64 = (1 << 64) - 1
MIN_I64, MAX_I64 = -(1 << 63), (1 << 63) - 1
INVALID, CAPACITY, NONCANONICAL = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
ORIGINAL_SHA = 'c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12'
COUNTS = {'native_calls': 0, 'original_version_calls': 0, 'canonical_inverse_cases': 0,
          'domain_rejections': 0, 'frame_rejections': 0, 'capacity_controls': 0, 'elf_cases': 0,
          'vm_cases': 0}
CORPUS = []


def packet(operation, payload):
    return b'HSTVER01' + struct.pack('<Q', operation) + payload


def signed(value):
    return value if value < (1 << 63) else value - (1 << 64)


def canonical_inverse(raw, reference):
    try:
        text = raw.decode('ascii')
        parts = text.split(':')
        if len(parts) != 5:
            return None
        dev, ino, size, mt, ct = map(int, parts)
        if not all(0 <= x <= U64 for x in (dev, ino, size)):
            return None
        ms, mn = divmod(mt, 1_000_000_000)
        cs, cn = divmod(ct, 1_000_000_000)
        if not MIN_I64 <= ms <= MAX_I64 or not MIN_I64 <= cs <= MAX_I64:
            return None
        obj = SimpleNamespace(st_dev=dev, st_ino=ino, st_size=size, st_mtime_ns=mt, st_ctime_ns=ct)
        if reference(obj).encode() != raw:
            return None
        return (dev, ino, size, ms & U64, mn, cs & U64, cn)
    except (ValueError, UnicodeDecodeError):
        return None


class StatVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ARGS.runtime / 'scripts'))
        from hia_native_loader import NativeModule
        original = ARGS.runtime / 'src/mcp/runtime/binary_file.py'
        source = original.read_bytes()
        if hashlib.sha256(source).hexdigest() != ORIGINAL_SHA:
            raise AssertionError('original version source drifted from the pinned runtime')
        function = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'version')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(original), 'exec'), namespace)
        cls.reference = staticmethod(namespace['version'])
        cls.manifest = Path(ARGS.manifest)
        cls.metadata = json.loads(cls.manifest.read_bytes())
        if hashlib.sha256(ARGS.source.read_bytes()).hexdigest() != cls.metadata['source_sha256']:
            raise AssertionError('native stat source identity differs')
        cls.module = NativeModule(cls.manifest, manifest_sha256=hashlib.sha256(cls.manifest.read_bytes()).hexdigest())
        cls.session = cls.module.session(output_capacity=128, workspace_capacity=256)

    @classmethod
    def tearDownClass(cls):
        cls.session.close()
        cls.module.close()
        if ARGS.corpus_dir:
            ARGS.corpus_dir.mkdir(parents=True, exist_ok=True)
            raw = b''.join(json.dumps(row, separators=(',', ':')).encode() + b'\n' for row in CORPUS)
            packed = gzip.compress(raw, mtime=0)
            (ARGS.corpus_dir / 'stat-version-cases.jsonl.gz').write_bytes(packed)
            metadata = {'schema': 'hepta.runtime.stat-version-corpus.v1', 'counts': COUNTS,
                        'source_sha256': cls.metadata['source_sha256'], 'image_sha256': cls.metadata['image_sha256'],
                        'original_source_sha256': ORIGINAL_SHA, 'cases': len(CORPUS),
                        'corpus_sha256': hashlib.sha256(packed).hexdigest(), 'raw_sha256': hashlib.sha256(raw).hexdigest()}
            (ARGS.corpus_dir / 'native-corpus.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')

    def invoke(self, raw, expected, category):
        actual = self.session.invoke(raw)
        COUNTS['native_calls'] += 1
        COUNTS[category] += 1
        self.assertEqual(actual, expected)
        if ARGS.corpus_dir:
            CORPUS.append({'request': raw.hex(), 'status': len(actual), 'output': actual.hex()})
        return actual

    def pair(self, fields):
        d, i, z, ms, mn, cs, cn = fields
        original = self.reference(SimpleNamespace(st_dev=d, st_ino=i, st_size=z,
                                  st_mtime_ns=signed(ms)*1_000_000_000+mn,
                                  st_ctime_ns=signed(cs)*1_000_000_000+cn)).encode()
        packed = struct.pack('<7Q', *fields)
        actual = self.invoke(packet(1, packed), original, 'original_version_calls')
        self.assertLessEqual(len(actual), 122)
        self.assertEqual(canonical_inverse(actual, self.reference), fields)
        self.invoke(packet(2, actual), packed, 'canonical_inverse_cases')

    def rejection(self, raw, code, category, capacity=128, workspace=256):
        result, output, _ = self.module.invoke_raw(raw, output_capacity=capacity,
                         workspace_capacity=workspace, output_fill=0xA5, workspace_fill=0x6B)
        COUNTS['native_calls'] += 1
        COUNTS[category] += 1
        self.assertEqual(result, code)
        self.assertEqual(output, b'\xA5' * capacity)
        if ARGS.corpus_dir:
            CORPUS.append({'request': raw.hex(), 'status': result, 'output': ''})

    def test_full_integer_and_timestamp_boundaries(self):
        seconds = [MIN_I64, MIN_I64+1, -(1<<53)-1, -(1<<53), -(1<<31)-1, -(1<<31),
                   -10, -2, -1, 0, 1, 2, 10, (1<<31)-1, 1<<31, (1<<53)-1,
                   1<<53, (1<<53)+1, MAX_I64-1, MAX_I64, 9_223_372_036]
        nanos = [0, 1, 9, 10, 99, 100, 999, 1000, 123456789, 999999998, 999999999]
        cases = [(s, n) for s in seconds for n in nanos]
        for index, (ms, mn) in enumerate(cases):
            cs, cn = cases[-index-1]
            self.pair((U64 if index % 2 else 0, index, U64-index, ms & U64, mn, cs & U64, cn))
        self.pair((U64, U64, U64, 1<<63, 0, 1<<63, 0))

    def test_random_full_domain(self):
        rng = random.Random(0x485354)
        for _ in range(5000):
            self.pair((rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64),
                       rng.getrandbits(64), rng.randrange(1_000_000_000),
                       rng.getrandbits(64), rng.randrange(1_000_000_000)))

    def test_noncanonical_and_out_of_domain_strings(self):
        strings = [b'', b'0:0:0:0', b'0:0:0:0:0:0', b'0:0:0:0:0\n', b'0:0:0:0:0 ',
                   b'-0:0:0:0:0', b'0:0:0:-0:0', b'0:0:0:+0:0', b'0:0:0:00:0',
                   b'0:0:0:01:0', b'0:0:0:-01:0', b'0:0:0:1.0:0', b'0:0:0:1e9:0',
                   b'0:0:0:0:\xff', b'0:0:0:0:\x00', b'x'*123,
                   b'0:0:0:9223372036854775808000000000:0',
                   b'0:0:0:-9223372036854775808000000001:0']
        for field in range(5):
            for bad in [b'', b'00', b'+1', b' 1', b'1 ', b'\t1', b'-0', b'1_0', b'\xc2\xb2']:
                parts = [b'0']*5; parts[field] = bad; strings.append(b':'.join(parts))
        for field in range(3):
            parts = [b'0']*5; parts[field] = str(U64+1).encode(); strings.append(b':'.join(parts))
        for text in strings:
            self.assertIsNone(canonical_inverse(text, self.reference))
            self.rejection(packet(2, text), NONCANONICAL, 'domain_rejections')

    def test_packet_and_capacity_refusal_is_atomic(self):
        valid = packet(1, struct.pack('<7Q', *(0,)*7))
        for length in range(len(valid)):
            self.rejection(valid[:length], INVALID, 'frame_rejections')
        for raw in [valid+b'x', b'BADMAGIC'+valid[8:], packet(0, b''), packet(3, b''),
                    packet(1, struct.pack('<7Q', 0, 0, 0, 0, 1_000_000_000, 0, 0)),
                    packet(1, struct.pack('<7Q', 0, 0, 0, 0, 0, 0, U64))]:
            self.rejection(raw, INVALID, 'frame_rejections')
        for raw, cap, workspace in [(valid, 8, 256), (packet(2,b'0:0:0:0:0'),55,256),
                                    (valid,128,255),(valid,0,256)]:
            self.rejection(raw, CAPACITY, 'capacity_controls', cap, workspace)
        self.assertEqual(self.module.invoke(valid, output_capacity=9, workspace_capacity=256), b'0:0:0:0:0')
        COUNTS['native_calls'] += 1; COUNTS['capacity_controls'] += 1

    def test_real_file_stat_and_static_elf(self):
        with tempfile.TemporaryDirectory(prefix='hia-version-') as tmp:
            path = Path(tmp)/'file'; path.write_bytes(b'file-version')
            for nanos in [0, -1, 1_000_000_001, 9_223_372_036_854_775_808]:
                os.utime(path, ns=(nanos, nanos))
                st = path.stat(); ms,mn=divmod(st.st_mtime_ns,1_000_000_000);cs,cn=divmod(st.st_ctime_ns,1_000_000_000)
                self.pair((st.st_dev,st.st_ino,st.st_size,ms & U64,mn,cs & U64,cn))
        elf = self.manifest.parent/self.metadata['standalone']['path']
        for fields in [(0,)*7, (1,2,3,U64,999999999,1<<63,0), (U64,U64,U64,(1<<63)-1,999999999,0,0)]:
            raw = packet(1,struct.pack('<7Q',*fields))
            expected = self.session.invoke(raw); COUNTS['native_calls'] += 1
            result = subprocess.run([str(elf)], input=raw, capture_output=True, env={'PATH':''}, timeout=10)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,expected,b''));COUNTS['elf_cases'] += 1

    def test_independent_vm_integer_boundaries(self):
        sys.path.insert(0, str(ARGS.hepta))
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        program = assemble_program(ARGS.source.read_bytes())
        cases = []
        for fields in [(0,)*7, (1,2,3,U64,999999999,1<<63,0),
                       (U64,U64,U64,(1<<63)-1,999999999,1<<63,1)]:
            d,i,z,ms,mn,cs,cn = fields
            text = self.reference(SimpleNamespace(st_dev=d,st_ino=i,st_size=z,
                st_mtime_ns=signed(ms)*1_000_000_000+mn,
                st_ctime_ns=signed(cs)*1_000_000_000+cn)).encode()
            words = struct.pack('<7Q',*fields)
            cases.extend([(packet(1,words),len(text),text,128),
                          (packet(2,text),56,words,128)])
        cases.extend([(packet(2,b'0:0:0:-0:0'),NONCANONICAL,None,128),
                      (packet(1,struct.pack('<7Q',*(0,)*7)),CAPACITY,None,8)])
        for raw,expected_status,expected,capacity in cases:
            owners = [_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(b'\xA5'*capacity)),
                      _Owner(-3,bytearray(b'\x6B'*256))]
            machine = _Machine(program,5_000_000,1<<20,None,128)
            code = machine.invoke(program.as_dict()['functions'][0],
                [_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
            self.assertEqual(code,expected_status)
            self.assertEqual(bytes(owners[1].data[:code]) if expected is not None else bytes(owners[1].data),
                             expected if expected is not None else b'\xA5'*capacity)
            COUNTS['vm_cases'] += 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_STAT_VERSION_MANIFEST'))
    parser.add_argument('--runtime',type=Path,default=Path(os.environ.get('HIA_REFERENCE_RUNTIME',ROOT)))
    parser.add_argument('--source',type=Path,default=ROOT/'native/stat_version.hepta')
    parser.add_argument('--corpus-dir',type=Path,default=os.environ.get('HIA_STAT_VERSION_CORPUS_DIR'))
    parser.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'))
    ARGS = parser.parse_args()
    if ARGS.manifest is None:parser.error('--manifest or HIA_STAT_VERSION_MANIFEST is required')
    if ARGS.hepta is None:parser.error('--hepta or HIA_HEPTA_DIR is required for independent VM checks')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(StatVersionTests))
    if result.wasSuccessful():print(json.dumps({'status':'PASS','counts':COUNTS,'original_source_sha256':ORIGINAL_SHA,
        'source_sha256':hashlib.sha256(ARGS.source.read_bytes()).hexdigest()},sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
