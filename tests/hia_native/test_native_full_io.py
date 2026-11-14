"""Qualify full-file single-link reads through actual HIA-owned static ELF."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_native_io as reference_io
from test_native_io import Session, request, version, COUNTS

COUNTS['original_full_read_comparisons'] = 0


def full_request(path, *, identity=1, limit=65536, offset=0, expected=None):
    raw = request(path, identity=identity, offset=offset, limit=limit, version=expected)
    return raw[:16] + struct.pack('<Q', 2) + raw[24:]


class FullReadIo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reference_io.NativeIoTests.setUpClass.__func__(cls)
        source = Path(os.environ.get('HIA_REFERENCE_RUNTIME', ROOT)) / 'src/mcp/runtime/multi_read_host.py'
        cls.original_source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        if cls.original_source_sha256 != '6f83b3e1031642e9981310916181858941dec51bb1696a79087beeb60a6e3eb5':
            raise AssertionError('retained full-read reference changed')
        namespace = {'__name__': 'hia_original_full_read', '__file__': str(source),
                     'parent': cls.reference.parent, 'regular': cls.reference.regular, 'version': cls.reference.version}
        exec(compile(source.read_bytes(), str(source), 'exec'), namespace)
        cls.full_reference = staticmethod(namespace['multi_read'])

    def setUp(self):
        reference_io.NativeIoTests.setUp(self)

    def original(self, path, limit):
        return self.full_reference({'files': [{'root': str(self.root), 'path': str(path)}],
                                    'max_file_bytes': limit, 'max_response_bytes': 262144})['files'][0]

    def test_01_valid_full_files_match_original(self):
        examples = [b'', b'a', b'\0', b'\r\n', b'"\\\t', '雪🌍\u0085\U0010ffff'.encode(), b'line\nlast']
        examples += [b'a' * n for n in (2, 3, 4, 4095, 4096, 4097, 16384, 65535, 65536)]
        rng = random.Random(1007)
        alphabet = ['a', '\n', '\r', '\t', '\0', '雪', '🌍', '\u0085', '"', '\\']
        examples += [''.join(rng.choice(alphabet) for _ in range(rng.randrange(1, 200))).encode() for _ in range(24)]
        with Session(self.executable, self.root, env={'PATH': ''}) as session:
            for index, content in enumerate(examples):
                self.file.write_bytes(content)
                limit = max(1, len(content))
                actual = session.call(full_request(self.file, identity=index, limit=limit))
                old = self.original(self.file, limit)
                self.assertEqual(actual['status'], 0)
                self.assertEqual(actual['identity'], index)
                self.assertEqual(actual['data'], old['text'].encode())
                self.assertEqual((actual['offset'], actual['next_offset'], actual['eof']), (0, old['size'], True))
                self.assertEqual(actual['version'], version(self.file.stat()))
                self.assertEqual(hashlib.sha256(actual['data']).hexdigest(), old['sha256'])
                COUNTS['original_full_read_comparisons'] += 1

    def test_02_byte_ceiling_links_utf8_and_path_order(self):
        self.file.write_bytes(b'invalid\xff')
        with Session(self.executable, self.root) as session:
            self.assertEqual(session.call(full_request(self.file, limit=1))['status'], 12)
            self.assertEqual(session.call(full_request(self.file))['status'], 14)
            os.link(self.file, self.root / 'other-link')
            self.assertEqual(session.call(full_request(self.file, limit=1))['status'], 11)
            self.assertEqual(session.call(request(self.file, limit=1))['data'], b'i')
            (self.root / 'other-link').unlink()
            self.file.write_bytes(b'valid')
            for path, status in [(str(self.root) + '//data.bin', 1), (str(self.root) + '/./data.bin', 1),
                                 ('/' + str(self.file), 1), (str(self.file) + '/', 1), (self.root, 1),
                                 (self.base / 'outside', 2), (self.root / 'missing', 3), (self.root / '.hepta-data', 1)]:
                self.assertEqual(session.call(full_request(path))['status'], status, str(path))
            directory = self.root / 'directory'
            directory.mkdir()
            (self.root / 'link').symlink_to(self.file)
            self.assertEqual(session.call(full_request(directory))['status'], 4)
            self.assertEqual(session.call(full_request(self.root / 'link'))['status'], 3)
            for raw in [full_request(self.file, offset=1), full_request(self.file, limit=0),
                        full_request(self.file, limit=65537), full_request(self.file, expected=[0] * 7)]:
                self.assertEqual(session.call(raw)['status'], 10)
            raw = full_request(self.file)
            raw = raw[:40] + struct.pack('<Q', 2) + raw[48:]
            self.assertEqual(session.call(raw)['status'], 10)
            self.assertEqual(session.call(full_request(self.file))['data'], b'valid')

    def test_03_invalid_utf8_boundaries(self):
        invalid = [b'\x80', b'\xc0\x80', b'\xc1\xbf', b'\xc2', b'\xe0\x80\x80', b'\xe2\x82',
                   b'\xed\xa0\x80', b'\xf0\x80\x80\x80', b'\xf4\x90\x80\x80', b'\xf0\x9f\x8c', b'\xff']
        with Session(self.executable, self.root) as session:
            for tail in invalid:
                for prefix in (b'', b'a' * 4095):
                    self.file.write_bytes(prefix + tail)
                    actual = session.call(full_request(self.file))
                    self.assertEqual((actual['status'], actual['data']), (14, b''))
                    with self.assertRaises(UnicodeDecodeError):
                        self.original(self.file, 65536)
                    COUNTS['original_full_read_comparisons'] += 1

    def test_04_full_4096_byte_path(self):
        logical = str(self.root)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            while 4096 - len(logical.encode()) - 1 > 255:
                part = 'd' * 200
                os.mkdir(part, dir_fd=descriptor)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                logical += '/' + part
            name = 'f' * (4096 - len(logical.encode()) - 1)
            file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=descriptor)
            os.write(file, b'4096-byte absolute path')
            os.close(file)
            logical += '/' + name
            self.assertEqual(len(logical.encode()), 4096)
            with Session(self.executable, self.root) as session:
                actual = session.call(full_request(logical))
                old = self.original(logical, 65536)
                self.assertEqual((actual['status'], actual['data']), (0, old['text'].encode()))
                COUNTS['original_full_read_comparisons'] += 1
        finally:
            os.close(descriptor)

    def test_05_partial_reads_growth_and_eintr(self):
        for mode, content, limit, status in [('eintr', b'a' * 5000, 5000, 0),
                                             ('change', b'a' * 5000, 5000, 7),
                                             ('grow', b'a' * 65536, 65536, 7),
                                             ('hardlink', b'a' * 5000, 5000, 7),
                                             ('read_error', b'a' * 5000, 5000, 8)]:
            self.file.write_bytes(content)
            trace = self.base / (mode + '.trace')
            with Session(self.executable, self.root, trace=trace, injection=mode, fixture=self.file) as session:
                actual = session.call(full_request(self.file, limit=limit))
                self.assertEqual(actual['status'], status, mode)
                self.assertEqual(actual['data'], content if status == 0 else b'')
            events = json.loads(trace.read_bytes())
            reads = [v for v in events if v['syscall'] == 17]
            if mode == 'eintr':
                self.assertEqual([v['offset'] for v in reads[:2]], [0, 0])
                self.assertEqual((reads[-1]['offset'], reads[-1]['count']), (5000, 1))
            if mode == 'grow':
                self.assertEqual((reads[-1]['offset'], reads[-1]['count']), (65536, 1))
            if mode == 'hardlink':
                self.file.with_name(self.file.name + '.extra-link').unlink()

    def test_06_confirmation_and_utf8_error_order(self):
        for mode, content, status, injected in [('confirm_replace', b'valid', 13, True),
                                               ('confirm_symlink', b'valid', 3, True),
                                               ('confirm_replace', b'invalid\xff', 14, False)]:
            if self.file.is_symlink():
                self.file.unlink()
            self.file.write_bytes(content)
            trace = self.base / (mode + '-' + str(status) + '.trace')
            ordinal = len(self.root.parts) + 2
            with Session(self.executable, self.root, trace=trace, injection=mode, fixture=self.file,
                         close_ordinal=ordinal) as session:
                actual = session.call(full_request(self.file))
                self.assertEqual((actual['status'], actual['data']), (status, b''))
            events = json.loads(trace.read_bytes())
            changes = [v for v in events if v['mode'] == 'replaced_fixture_before_confirmation_open']
            self.assertEqual(bool(changes), injected)

    def test_07_close_failures_and_mixed_session_cleanup(self):
        self.file.write_bytes(b'valid')
        trace = self.base / 'close-full.trace'
        with Session(self.executable, self.root, trace=trace, injection='close', close_ordinal=len(self.root.parts)) as session:
            actual = session.call(full_request(self.file))
            self.assertEqual((actual['status'], actual['errno'], actual['data']), (9, 4, b''))
        events = json.loads(trace.read_bytes())
        self.assertEqual(sum(v['mode'] == 'injected_eintr' for v in events), 1)
        with Session(self.executable, self.root) as session:
            self.assertEqual(session.call(full_request(self.file))['status'], 0)
            before = len(os.listdir(f'/proc/{session.process.pid}/fd'))
            for i in range(30):
                packet = full_request(self.file, identity=0) if i % 3 == 0 else (request(self.file, limit=2) if i % 3 == 1 else full_request(self.root / 'missing'))
                actual = session.call(packet)
                self.assertEqual(actual['status'], 3 if i % 3 == 2 else 0)
            self.assertEqual(len(os.listdir(f'/proc/{session.process.pid}/fd')), before)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root', type=Path, default=os.environ.get('HIA_BUILD_ROOT'))
    args, other = parser.parse_known_args()
    if not args.hepta or not args.build_root:
        parser.error('--hepta and --build-root or HIA_HEPTA_DIR/HIA_BUILD_ROOT are required')
    os.environ['HIA_HEPTA_DIR'] = str(args.hepta)
    os.environ['HIA_BUILD_ROOT'] = str(args.build_root)
    program = unittest.main(argv=[sys.argv[0], *other], exit=False)
    success = program.result.wasSuccessful() and not program.result.skipped
    print(json.dumps({'status': 'PASS' if success else 'FAIL', 'native_full_io': COUNTS}, sort_keys=True))
    raise SystemExit(0 if success else 1)
