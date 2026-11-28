"""Execute the HIA nonce set against an independent set and original Rust owner.

This qualifies serial, trusted workspace transitions. The Python loader lock is
test transport; it does not qualify production scope locking or entropy.
"""
from pathlib import Path
import copy
import ctypes
import gzip
import hashlib
import json
import os
import random
import struct
import subprocess
import sys
import unittest

ROOT = Path(os.environ.get('HIA_REFERENCE_RUNTIME', Path(__file__).resolve().parents[2]))
SOURCE_ROOT = Path(os.environ.get('HIA_NONCE_SOURCE_ROOT', ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule, NativeRejected

INVALID, CAPACITY, BINDING, NONCE, STATE = 0xffffffff, 0xfffffffe, 0xfffffffd, 0xfffffffc, 0xfffffffb
WORKSPACE, LIMIT, SLOTS = 1576960, 16384, 32768
COUNTS = {'native_calls': 0, 'initializations': 0, 'destructions': 0,
          'accepted_reservations': 0, 'nonce_refusals': 0, 'admission_refusals': 0,
          'state_refusals': 0, 'capacity_refusals': 0, 'elf_requests': 0,
          'elf_processes': 0, 'composed_elf_requests': 0}
CORPUS = []


def frame(op, operation=b'0' * 64, ledger=b'1' * 64, nonce=bytes(12)):
    return b'HRNONC01' + struct.pack('<2Q', op, 0) + (operation + ledger + nonce if op == 2 else b'')


def key_for(wire):
    return hashlib.sha256(wire[24:152]).digest() + wire[152:164]


class NonceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_NONCE_MANIFEST'])
        cls.module = NativeModule(cls.manifest, manifest_sha256=hashlib.sha256(cls.manifest.read_bytes()).hexdigest())
        cls.proof = json.loads((SOURCE_ROOT / 'native/operation_nonce_composition.json').read_text())
        raw = (SOURCE_ROOT / 'native/operation_nonce.hepta').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == cls.proof['source_sha256'] == cls.module.metadata['source_sha256']
        assert hashlib.sha256((ROOT / cls.proof['original_source']).read_bytes()).hexdigest() == cls.proof['original_source_sha256']
        codec = (ROOT / cls.proof['import_source']).read_bytes()
        assert hashlib.sha256(codec).hexdigest() == cls.proof['import_source_sha256']
        sys.path.insert(0, os.environ['HIA_HEPTA_DIR'])
        from hepta.hia_agent_assembly import assemble_program
        old = {f['name']: f for f in assemble_program(codec).as_dict()['functions']}
        new = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
        reverse = {v: k for k, v in cls.proof['relocation'].items()}
        for name, destination in cls.proof['relocation'].items():
            value = copy.deepcopy(new[destination])
            value['name'] = name
            for block in value['blocks']:
                for op in block['ops']:
                    if op['op'] == 'call':
                        op['attrs']['function'] = reverse[op['attrs']['function']]
            assert value == old[name]
            canonical = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            assert hashlib.sha256(canonical).hexdigest() == cls.proof['imported_functions_sha256'][name]
        cls.reference_sources = {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                                 for name in ['oracle_operation_nonce.rs', 'nonce_oracle/Cargo.toml',
                                              'nonce_oracle/Cargo.lock', 'nonce_oracle/build.rs',
                                              'nonce_oracle/original_access.rs']}
        cls.composition_manifest = Path(os.environ['HIA_NONCE_COMPOSITION_MANIFEST'])
        cls.composition = json.loads(cls.composition_manifest.read_bytes())
        assert cls.composition['compiler_commit'] == cls.module.metadata['compiler_commit']
        assert cls.composition['compiler_sha256'] == cls.module.metadata['compiler_sha256']
        assert cls.composition['members'][1]['source_sha256'] == cls.proof['source_sha256']
        assert cls.composition['members'][1]['image_sha256'] == cls.module.metadata['image_sha256']
        fixture = (Path(__file__).parent / 'nonce_hex_transport.hepta').read_bytes()
        assert cls.composition['members'][0]['source_sha256'] == hashlib.sha256(fixture).hexdigest()
        assert cls.composition['packer']['source_sha256'] == hashlib.sha256((ROOT / 'native/composition_packer.hepta').read_bytes()).hexdigest()
        assert cls.composition['profile'][0]['call_mask'] == 2
        assert cls.composition['profile'][1]['flags'] == cls.composition['profile'][1]['call_mask'] == 0
        assert cls.composition['profile'][1]['workspace_capacity'] == WORKSPACE

    @classmethod
    def tearDownClass(cls):
        cls.module.close()
        for name, expected in cls.reference_sources.items():
            assert hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest() == expected
        if os.environ.get('HIA_NONCE_CORPUS_DIR'):
            folder = Path(os.environ['HIA_NONCE_CORPUS_DIR'])
            folder.mkdir(parents=True, exist_ok=False)
            raw = b''.join(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n' for row in CORPUS)
            packed = gzip.compress(raw, mtime=0)
            (folder / 'nonce_cases.jsonl.gz').write_bytes(packed)
            metadata = {'schema': 'hepta.runtime.native-operation-nonce-corpus.v1', 'counts': COUNTS,
                        'source_sha256': cls.module.metadata['source_sha256'],
                        'image_sha256': cls.module.metadata['image_sha256'],
                        'original_source_sha256': cls.proof['original_source_sha256'],
                        'oracle_sources_sha256': cls.reference_sources,
                        'composition_fixture': {'source_sha256': cls.composition['members'][0]['source_sha256'],
                            'manifest_sha256': hashlib.sha256(cls.composition_manifest.read_bytes()).hexdigest(),
                            'executable_sha256': cls.composition['executable_sha256'],
                            'requests': COUNTS['composed_elf_requests']},
                        'native_output_sha256': hashlib.sha256(''.join(f"{r['session']}:{r['code']}:{r['count']}\n" for r in CORPUS).encode()).hexdigest(),
                        'composition_sha256': hashlib.sha256((SOURCE_ROOT / 'native/operation_nonce_composition.json').read_bytes()).hexdigest(),
                        'corpus': {'file': 'nonce_cases.jsonl.gz', 'gzip_sha256': hashlib.sha256(packed).hexdigest(),
                                   'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_bytes': len(raw), 'cases': len(CORPUS)}}
            (folder / 'native-corpus.json').write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')

    def session(self, name):
        session = self.module.session(output_capacity=19, workspace_capacity=WORKSPACE + 17)
        self.addCleanup(session.close)
        ctypes.memset(session._output, 0xa5, 19)
        ctypes.memset(ctypes.addressof(session._workspace) + WORKSPACE, 0x5a, 17)
        session.test_name = name
        session.test_keys = None
        return session

    def call(self, session, wire, expected=0, *, export=True, preserve=False):
        before = bytes(session._workspace.raw[:WORKSPACE + 17]) if preserve else None
        try:
            value = session.invoke(wire)
            code = len(value)
        except NativeRejected as error:
            code = error.code
        self.assertEqual(code, expected)
        self.assertEqual(session._output.raw[:19], b'\xa5' * 19)
        self.assertEqual(ctypes.string_at(ctypes.addressof(session._workspace) + WORKSPACE, 17), b'\x5a' * 17)
        if preserve:
            self.assertEqual(session._workspace.raw[:WORKSPACE + 17], before)
        COUNTS['native_calls'] += 1
        op = struct.unpack_from('<Q', wire, 8)[0] if len(wire) >= 16 else None
        if code == 0:
            if op == 1:
                session.test_keys = set()
                COUNTS['initializations'] += 1
            elif op == 2:
                self.assertNotIn(key_for(wire), session.test_keys)
                session.test_keys.add(key_for(wire))
                COUNTS['accepted_reservations'] += 1
            elif op == 3:
                session.test_keys = None
                COUNTS['destructions'] += 1
        else:
            counter = {NONCE: 'nonce_refusals', STATE: 'state_refusals', CAPACITY: 'capacity_refusals'}.get(code, 'admission_refusals')
            COUNTS[counter] += 1
        count = struct.unpack('<Q', ctypes.string_at(ctypes.addressof(session._workspace) + 2056, 8))[0]
        if export:
            self.assertEqual(count, len(session.test_keys or ()))
            CORPUS.append({'session': session.test_name, 'input_hex': wire.hex(), 'code': code, 'count': count})
        return code

    def inspect_set(self, session):
        work = session._workspace.raw[:WORKSPACE]
        self.assertEqual(work[:2048], bytes(2048))
        self.assertEqual(work[2064:4096], bytes(2032))
        found = set()
        for slot in range(SLOTS):
            block = work[4096 + slot * 48:4096 + (slot + 1) * 48]
            if block[0] == 0:
                self.assertEqual(block, bytes(48))
            else:
                self.assertEqual(block[:4], b'\x01\0\0\0')
                self.assertNotIn(block[4:], found)
                found.add(block[4:])
        self.assertEqual(found, session.test_keys)

    def test_lifecycle_and_separate_scopes(self):
        first, other = self.session('lifecycle-one'), self.session('lifecycle-two')
        self.call(first, frame(2), STATE, preserve=True)
        self.call(first, frame(1))
        self.call(first, frame(1), STATE, preserve=True)
        self.call(other, frame(1))
        self.call(first, frame(2))
        self.call(other, frame(2))
        self.call(first, frame(2), NONCE, preserve=True)
        self.call(first, frame(3))
        self.assertEqual(first._workspace.raw[:WORKSPACE], bytes(WORKSPACE))
        self.call(first, frame(2), STATE, preserve=True)
        self.call(first, frame(3))
        self.call(first, frame(1))
        self.call(first, frame(2))
        self.call(other, frame(2), NONCE, preserve=True)
        self.inspect_set(first)
        self.inspect_set(other)

    def test_namespace_and_all_nonce_bytes(self):
        session = self.session('namespaces')
        self.call(session, frame(1))
        for operation, ledger in [(b'0' * 64, b'0' * 64), (b'f' * 64, b'0' * 64),
                                  (b'0' * 64, b'f' * 64), (b'f' * 64, b'f' * 64)]:
            for nonce in [bytes(12), b'\xff' * 12, bytes(range(12)), b'\n' * 12]:
                wire = frame(2, operation, ledger, nonce)
                self.call(session, wire)
                self.call(session, wire, NONCE, preserve=True)
        self.inspect_set(session)

    def test_seeded_serial_reference(self):
        rng = random.Random(0x4e4f4e4345)
        session = self.session('random')
        self.call(session, frame(1))
        identities = [rng.randbytes(32).hex().encode() for _ in range(17)]
        retained = []
        for index in range(1024):
            if retained and index % 4 == 0:
                wire = rng.choice(retained)
                self.call(session, wire, NONCE, preserve=True)
            else:
                wire = frame(2, rng.choice(identities), rng.choice(identities), rng.randbytes(12))
                self.call(session, wire)
                retained.append(wire)
        self.inspect_set(session)

    def test_collision_chain_wraps_at_last_slot(self):
        session = self.session('collision-wrap')
        self.call(session, frame(1))
        candidates = []
        namespace = hashlib.sha256(b'0' * 64 + b'1' * 64).digest()
        number = 0
        while len(candidates) < 8:
            nonce = number.to_bytes(12, 'little')
            bucket = int.from_bytes(hashlib.sha256(namespace + nonce).digest()[:4], 'big') & (SLOTS - 1)
            if bucket == SLOTS - 1:
                candidates.append(nonce)
            number += 1
        for index, nonce in enumerate(candidates):
            wire = frame(2, nonce=nonce)
            self.call(session, wire)
            at = 4096 + ((SLOTS - 1 + index) & (SLOTS - 1)) * 48
            self.assertEqual(ctypes.string_at(ctypes.addressof(session._workspace) + at + 4, 44), key_for(wire))
        for nonce in candidates:
            self.call(session, frame(2, nonce=nonce), NONCE, preserve=True)
        self.inspect_set(session)

    def test_exact_original_scope_budget(self):
        session = self.session('full-budget')
        self.call(session, frame(1))
        for number in range(LIMIT):
            self.call(session, frame(2, nonce=number.to_bytes(12, 'little')))
        for number in [0, LIMIT // 2, LIMIT - 1, LIMIT, LIMIT + 1]:
            self.call(session, frame(2, nonce=number.to_bytes(12, 'little')), NONCE, preserve=True)
        self.call(session, frame(2, operation=b'f' * 64, nonce=b'\xff' * 12), NONCE, preserve=True)
        self.inspect_set(session)

    def test_composed_elf_preserves_state_and_exact_budget(self):
        executable = self.composition_manifest.parent / self.composition['executable']
        expected_sha = self.composition['executable_sha256']
        self.assertEqual(hashlib.sha256(executable.read_bytes()).hexdigest(), expected_sha)
        large = [(frame(2), STATE), (frame(1), 0), (frame(1), STATE)]
        large += [(frame(2, nonce=number.to_bytes(12, 'little')), 0) for number in range(LIMIT)]
        large += [(frame(2), NONCE), (frame(2, nonce=LIMIT.to_bytes(12, 'little')), NONCE),
                  (frame(2, operation=b'f' * 64), NONCE), (frame(3), 0),
                  (frame(2), STATE), (frame(1), 0), (frame(2), 0), (frame(3), 0)]
        small = [(frame(1), 0), (frame(2), 0), (frame(2), NONCE), (frame(3), 0)]
        for cases in [large, small]:
            wire = b''.join(request.hex().encode() + b'\n' for request, _ in cases)
            expected = b''.join(f'{code:08x}:\n'.encode() for _, code in cases)
            run = subprocess.run([str(executable), '--local-read-profile', str(SOURCE_ROOT)], input=wire, capture_output=True,
                                 env={'PATH': '', 'LANG': 'C'}, timeout=45)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (0, expected, b''))
            COUNTS['elf_requests'] += len(cases)
            COUNTS['composed_elf_requests'] += len(cases)
            COUNTS['elf_processes'] += 1
        self.assertEqual(hashlib.sha256(executable.read_bytes()).hexdigest(), expected_sha)

    def test_admission_and_capacity_do_not_consume(self):
        session = self.session('admission')
        self.call(session, frame(1))
        valid = frame(2)
        for size in range(len(valid)):
            self.call(session, valid[:size], INVALID, preserve=True)
        for position in list(range(8)) + list(range(16, 24)):
            wire = bytearray(valid)
            wire[position] ^= 1
            self.call(session, bytes(wire), INVALID, preserve=True)
        for op in [0, 4, (1 << 64) - 1]:
            wire = bytearray(valid)
            struct.pack_into('<Q', wire, 8, op)
            self.call(session, bytes(wire), INVALID, preserve=True)
        for wire in [valid + b'x', frame(1) + b'x', frame(3) + b'x']:
            self.call(session, wire, INVALID, preserve=True)
        for position in range(24, 152):
            wire = bytearray(valid)
            wire[position] = ord('G') if position % 2 else 0xff
            self.call(session, bytes(wire), BINDING, preserve=True)
        for value in [0, 10, 32, 47, 58, 65, 96, 103, 127, 128, 255]:
            self.call(session, frame(2, operation=bytes([value]) * 64), BINDING, preserve=True)
        for op in [1, 2, 3]:
            for workspace in [0, 1, WORKSPACE - 1]:
                code, out, work = self.module.invoke_raw(frame(op), output_capacity=19,
                    workspace_capacity=workspace, output_fill=0xa5, workspace_fill=0x5a)
                self.assertEqual((code, out, work), (CAPACITY, b'\xa5' * 19, b'\x5a' * workspace))
                COUNTS['native_calls'] += 1
                COUNTS['capacity_refusals'] += 1
        self.call(session, valid)
        self.inspect_set(session)

    def test_private_state_faults_and_bounded_probe_refuse(self):
        session = self.session('state-faults')
        self.call(session, frame(1))
        self.call(session, frame(2))
        original = session._workspace.raw[:WORKSPACE + 17]
        for at, value in [(2048, 0), (2056, LIMIT + 1), (2064, 1), (2072, 1)]:
            ctypes.memmove(ctypes.addressof(session._workspace) + at, struct.pack('<Q', value), 8)
            self.call(session, frame(2, nonce=b'z' * 12), STATE, export=False, preserve=True)
            ctypes.memmove(session._workspace, original, len(original))
        wire = frame(2, nonce=b'x' * 12)
        slot = int.from_bytes(hashlib.sha256(key_for(wire)).digest()[:4], 'big') & (SLOTS - 1)
        for offset, value in [(0, 2), (1, 1), (2, 1), (3, 1)]:
            ctypes.memset(ctypes.addressof(session._workspace) + 4096 + slot * 48 + offset, value, 1)
            self.call(session, wire, STATE, export=False, preserve=True)
            ctypes.memmove(session._workspace, original, len(original))
        corrupt = (b'\x01\0\0\0' + bytes(44)) * SLOTS
        ctypes.memmove(ctypes.addressof(session._workspace) + 4096, corrupt, len(corrupt))
        self.call(session, wire, STATE, export=False, preserve=True)
        ctypes.memmove(session._workspace, original, len(original))
        self.call(session, wire)
        self.inspect_set(session)
        self.call(session, frame(3))
        ctypes.memset(session._workspace, 0x5a, WORKSPACE)
        self.call(session, frame(1), STATE, export=False, preserve=True)
        self.call(session, frame(3))
        self.assertEqual(session._workspace.raw[:WORKSPACE], bytes(WORKSPACE))

    def test_standalone_lifecycle_without_runtime_libraries(self):
        metadata = self.module.metadata
        executable = self.manifest.parent / metadata['standalone']['path']
        self.assertEqual(hashlib.sha256(executable.read_bytes()).hexdigest(), metadata['standalone']['sha256'])
        for op in [1, 3]:
            run = subprocess.run([str(executable)], input=frame(op), capture_output=True,
                                 env={'PATH': '', 'LANG': 'C'}, timeout=20)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b'', b''))
            COUNTS['elf_requests'] += 1
            COUNTS['elf_processes'] += 1


if __name__ == '__main__':
    result = unittest.main(exit=False, verbosity=2)
    print(json.dumps({'status': 'PASS' if result.result.wasSuccessful() else 'FAIL', 'counts': COUNTS}, sort_keys=True))
    raise SystemExit(0 if result.result.wasSuccessful() else 1)
