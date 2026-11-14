"""Run actual static ELFs for the closed HIA call/OS continuation boundary."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WIRE = 8 << 20


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Composition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hia_native_composition_build import ModuleSpec, build_composition
        from hia_native_loader import NativeModule
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-composition-tests-')
        cls.root = Path(cls.temporary.name)
        cls.build = Path(os.environ['HIA_BUILD_ROOT'])
        cls.hepta = Path(os.environ['HIA_HEPTA_DIR'])
        fixture = ROOT / 'tests/hia_native'
        cls.members = [ModuleSpec('probe', fixture / 'composition_probe.hepta', flags=1, call_mask=3, workspace_capacity=4096),
                       ModuleSpec('leaf', fixture / 'composition_leaf.hepta', workspace_capacity=4096),
                       ModuleSpec('masked-leaf', fixture / 'composition_leaf.hepta', workspace_capacity=4096)]
        cls.manifest = build_composition(cls.hepta, cls.build, cls.members, source_root=ROOT)
        cls.metadata = json.loads(cls.manifest.read_bytes())
        cls.exe = cls.manifest.parent / cls.metadata['executable']
        chain = [ModuleSpec('chain-' + str(i), fixture / 'composition_chain.hepta', flags=1,
                            call_mask=(1 << (i + 1)) if i < 9 else 0, workspace_capacity=4096) for i in range(10)]
        chain_manifest = build_composition(cls.hepta, cls.build, chain, source_root=ROOT)
        cls.chain_exe = chain_manifest.parent / json.loads(chain_manifest.read_bytes())['executable']
        p = cls.manifest.parent / cls.metadata['packer']['manifest']
        cls.packer = NativeModule(p, manifest_sha256=digest(p.read_bytes()))
        cls.native_runs = 0
        cls.native_frames = 0

    @classmethod
    def tearDownClass(cls):
        cls.packer.close()
        cls.temporary.cleanup()

    def run_elf(self, wire, *, executable=None, args=None, timeout=10):
        type(self).native_runs += 1
        type(self).native_frames += wire.count(b'\n') + int(bool(wire) and not wire.endswith(b'\n'))
        return subprocess.run([str(executable or self.exe), *(args if args is not None else ['--local-read-profile', str(self.root)])],
                              input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': ''}, timeout=timeout)

    def test_01_explicit_startup_profile(self):
        for args in ([], [str(self.root)], ['--local-read-profile'], ['--local-read-profile', str(self.root), 'extra'], ['--local-read-profiles', str(self.root)]):
            result = self.run_elf(b'', args=args)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (64, b'', b''))
        result = self.run_elf(b'C\n')
        self.assertEqual((result.returncode, result.stdout), (0, str(self.root).encode() + b'\n'))

    def test_02_regions_persistence_and_domain_results(self):
        result = self.run_elf(b'Efirst\nW\nE%\nE%\nE!\nElast\n')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'first\nwork\n1\n2\nX\nlast\n', b''))

    def test_03_call_admission_and_recovery(self):
        cases = [(b'T', b'1'), (b'M', b'1'), (b'R', b'2'), (b'O', b'4'),
                 (b'F', b'3'), (b'B', b'3'), (b'I', b'3'), (b'Q', b'3'), (b'L', b'3')]
        result = self.run_elf(b'\n'.join(mode for mode, _ in cases) + b'\nEok\n')
        expected = b'\n'.join(value for _, value in cases) + b'\nok\n'
        self.assertEqual((result.returncode, result.stdout), (0, expected))

    def test_04_invalid_continuations_fail_closed(self):
        for mode in (b'D', b'G', b'Z', b'Y', b'E~', b'E@', b'Ploop'):
            result = self.run_elf(mode + b'\n')
            self.assertEqual((result.returncode, result.stdout), (2, b''), mode)

    def test_05_bounded_nesting_and_resume(self):
        result = self.run_elf(b'0\n1\n7\n8\n9\n7\n', executable=self.chain_exe)
        self.assertEqual((result.returncode, result.stdout), (0, b'A\nB\nH\n2\n2\nH\n'))

    def test_06_eof_and_transport_boundaries(self):
        for wire, expected in ((b'', b''), (b'\n\n', b''), (b'Efinal', b'final\n'),
                               (b'Eone\nEtwo', b'one\ntwo\n')):
            result = self.run_elf(wire)
            self.assertEqual((result.returncode, result.stdout), (0, expected))
        wire = b'E' + b'a' * (WIRE - 1)
        for suffix in (b'', b'\n'):
            result = self.run_elf(wire + suffix, timeout=30)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, wire[1:] + b'\n')
        result = self.run_elf(wire + b'a\n', timeout=30)
        self.assertEqual((result.returncode, result.stdout), (2, b''))

    def test_07_partial_input_and_stdout_failure(self):
        process = subprocess.Popen([str(self.exe), '--local-read-profile', str(self.root)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': ''})
        type(self).native_runs += 1
        for part in (b'E', b'pa', b'rt', b'ial\n', b'E', b'last'):
            process.stdin.write(part)
            process.stdin.flush()
        process.stdin.close()
        self.assertEqual(process.stdout.read(), b'partial\nlast\n')
        self.assertEqual(process.wait(timeout=5), 0)
        process.stdout.close()
        process.stderr.close()
        process = subprocess.Popen([str(self.exe), '--local-read-profile', str(self.root)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': ''})
        type(self).native_runs += 1
        process.stdout.close()
        process.stdin.write(b'Eclosed\n')
        process.stdin.close()
        self.assertEqual(process.wait(timeout=5), 74)
        process.stderr.close()

    def pack_frame(self, images):
        wire = bytearray(b'HIABND01' + struct.pack('<3Q', len(images), 0, 0))
        for i, (raw, source_hash) in enumerate(images):
            wire.extend(struct.pack('<8Q', len(raw), WIRE, WIRE, 4096 if i < 2 else 32 << 20,
                                    1 if i == 0 else 0, 2 if i == 0 else 0, 0, 0))
            wire.extend(bytes.fromhex(source_hash))
            wire.extend(hashlib.sha256(raw).digest())
            wire.extend(raw)
        return wire

    def member_images(self):
        images = []
        for row in self.metadata['members'][:2]:
            meta = json.loads((self.manifest.parent / row['manifest']).read_bytes())
            images.append(((self.manifest.parent / meta['image']).read_bytes(), meta['source_sha256']))
        return images

    def test_08_native_packer_refusal_is_atomic(self):
        valid = self.pack_frame(self.member_images())
        bad = [b'', valid[:31], valid + b'x']
        for offset, value in ((0, 0), (8, 0), (8, 17), (16, 1), (24, 1),
                              (32, 0), (32, (1 << 64) - 1), (40, 0), (48, WIRE + 1),
                              (56, 0), (56, (32 << 20) + 1), (64, 3), (64, 0),
                              (72, 4), (80, 1), (88, 1)):
            wire = bytearray(valid)
            struct.pack_into('<Q', wire, offset, value)
            bad.append(bytes(wire))
        for wire in bad:
            code, output, _ = self.packer.invoke_raw(bytes(wire), output_capacity=1 << 20,
                                                   workspace_capacity=4096, output_fill=0xA5)
            self.assertEqual(code, 0xFFFFFFFF)
            self.assertEqual(output, b'\xA5' * len(output))
        code, output, _ = self.packer.invoke_raw(bytes(valid), output_capacity=32, workspace_capacity=4096, output_fill=0xA5)
        self.assertEqual((code, output), (0xFFFFFFFE, b'\xA5' * 32))

    def test_09_static_layout_and_aggregate_image(self):
        from tools.qualify_hia_selfhost_cli import inspect_executable
        raw = self.exe.read_bytes()
        self.assertEqual(inspect_executable(raw)['sha256'], digest(raw))
        service_path = os.environ.get('HIA_COMPOSITION_MANIFEST')
        if not service_path:
            self.fail('HIA_COMPOSITION_MANIFEST is required for the real aggregate-image control')
        service_path = Path(service_path)
        service = json.loads(service_path.read_bytes())
        source = json.loads((service_path.parent / service['members'][0]['manifest']).read_bytes())
        image = (service_path.parent / source['image']).read_bytes()
        images = self.member_images() + [(image, source['source_sha256'])] * 3
        wire = self.pack_frame(images)
        packed = self.packer.invoke(bytes(wire), output_capacity=WIRE, workspace_capacity=4096)
        self.assertGreater(len(packed), 1 << 20)
        inspect_executable(packed)
        path = self.root / 'aggregate.elf'
        path.write_bytes(packed)
        path.chmod(0o500)
        result = self.run_elf(b'Eaggregate\n', executable=path)
        self.assertEqual((result.returncode, result.stdout), (0, b'aggregate\n'))

    def test_10_cached_artifact_custody(self):
        from hia_native_composition_build import build_composition
        row = self.metadata['members'][1]
        metadata = json.loads((self.manifest.parent / row['manifest']).read_bytes())
        image = self.manifest.parent / metadata['image']
        original = image.read_bytes()
        try:
            image.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            with self.assertRaisesRegex(ValueError, 'image identity mismatch'):
                build_composition(self.hepta, self.build, self.members, source_root=ROOT)
        finally:
            image.write_bytes(original)
        self.assertEqual(build_composition(self.hepta, self.build, self.members, source_root=ROOT), self.manifest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root', type=Path, default=os.environ.get('HIA_BUILD_ROOT'))
    args, remaining = parser.parse_known_args()
    if not args.hepta or not args.build_root:
        parser.error('--hepta and --build-root or HIA_HEPTA_DIR/HIA_BUILD_ROOT are required')
    os.environ['HIA_HEPTA_DIR'] = str(args.hepta)
    os.environ['HIA_BUILD_ROOT'] = str(args.build_root)
    sys.path.insert(0, str(ROOT / 'scripts'))
    program = unittest.main(argv=[sys.argv[0], *remaining], exit=False)
    passed = program.result.wasSuccessful() and not program.result.skipped
    print(json.dumps({'status': 'PASS' if passed else 'FAIL',
                      'native_executions': getattr(Composition, 'native_runs', 0),
                      'native_frames': getattr(Composition, 'native_frames', 0),
                      'adapter': 'closed-native-multi-image'}))
    raise SystemExit(0 if passed else 1)
