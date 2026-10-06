#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real descriptor/file/upload regressions using only disposable filesystem fixtures."""
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HELPER = pathlib.Path(__file__).resolve().parents[1] / 'src/mcp/runtime/binary_file.py'


class BinaryFiles(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-binary-test-')
        self.root = pathlib.Path(self.temp.name).resolve()
        self.path = self.root / 'file.bin'

    def tearDown(self): self.temp.cleanup()

    def rpc(self, op, fail=False, path=None, **args):
        request = {'root': str(self.root), 'path': str(path or self.path), 'op': op, **args}
        p = subprocess.run([sys.executable, str(HELPER)], input=json.dumps(request), text=True, capture_output=True, timeout=12)
        if fail:
            self.assertNotEqual(p.returncode, 0, p.stdout)
            return p.stderr
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def write(self, data, version='absent', **kw):
        return self.rpc('write', data_base64=base64.b64encode(data).decode(), expected_version=version, **kw)

    def chunk(self, data, offset=0, upload='fixture01', **kw):
        return self.rpc('upload_chunk', upload_id=upload, offset=offset,
                        data_base64=base64.b64encode(data).decode(), expected_version='absent', **kw)

    def commit(self, data, upload='fixture01', **kw):
        return self.rpc('upload_commit', upload_id=upload, size=len(data), sha256=hashlib.sha256(data).hexdigest(), **kw)

    def test_exact_binary_unicode_nul_roundtrip(self):
        data = bytes(range(256)) * 13 + '中文α'.encode()
        result = self.write(data); offset = 0; recovered = b''
        while True:
            page = self.rpc('read', offset=offset, limit=101, expected_version=result['version'])
            chunk = base64.b64decode(page['data_base64'], validate=True)
            self.assertEqual(page['chunk_sha256'], hashlib.sha256(chunk).hexdigest())
            recovered += chunk; offset = page['next_offset']
            if page['eof']: break
        self.assertEqual(recovered, data)
        self.assertEqual(self.rpc('info')['sha256'], hashlib.sha256(data).hexdigest())

    def test_empty_file_and_cursor_bounds(self):
        self.write(b'')
        self.assertTrue(self.rpc('read')['eof'])
        self.rpc('read', fail=True, offset=1)
        self.rpc('read', fail=True, offset=-1)

    def test_stale_write_create_only_and_permission_mode(self):
        first = self.write(b'original'); self.path.chmod(0o751)
        self.write(b'wrong', fail=True)
        self.write(b'wrong', first['version'], fail=True)
        new = self.write(b'replaced', self.rpc('info')['version'])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o751)
        self.assertEqual(new['sha256'], hashlib.sha256(b'replaced').hexdigest())

    def test_upload_large_atomic_and_idempotent_commit(self):
        data = bytes(range(256)) * (20 * 1024) + b'END'
        for offset in range(0, len(data), 1024 * 1024):
            piece = data[offset:offset+1024*1024]
            self.chunk(piece, offset)
            self.chunk(piece, offset)
            self.assertFalse(self.path.exists())
        result = self.commit(data)
        self.assertEqual(self.path.read_bytes(), data)
        again = self.commit(data)
        self.assertTrue(again['reused']); self.assertEqual(result['version'], again['version'])
        self.assertFalse(self.rpc('upload_abort', upload_id='fixture01')['aborted'])
        self.assertEqual(self.path.read_bytes(), data)

    def test_upload_replay_different_bytes_rejected(self):
        self.chunk(b'ABC')
        self.chunk(b'ABZ', fail=True)
        self.chunk(b'ABCDEF', fail=True)
        self.chunk(b'GAP', offset=99, fail=True)
        self.assertFalse(self.path.exists())
        self.commit(b'ABC')

    def test_commit_integrity_failure_preserves_destination(self):
        self.chunk(b'VALID')
        self.commit(b'INVALID', fail=True)
        self.assertFalse(self.path.exists())
        self.commit(b'VALID')

    def test_abort_tombstone_never_resumes(self):
        self.chunk(b'PART')
        self.assertTrue(self.rpc('upload_abort', upload_id='fixture01')['aborted'])
        self.chunk(b'PART', fail=True)
        self.commit(b'PART', fail=True)
        self.assertFalse(self.path.exists())

    def test_destination_change_after_commit_is_not_overwritten(self):
        self.chunk(b'VALUE'); self.commit(b'VALUE')
        self.path.write_bytes(b'NEWER')
        self.commit(b'VALUE', fail=True)
        self.assertEqual(self.path.read_bytes(), b'NEWER')

    def test_special_files_symlinks_and_root_rejected(self):
        self.path.symlink_to('/etc/hosts')
        self.rpc('read', fail=True); self.write(b'NO', fail=True)
        self.path.unlink(); os.mkfifo(self.path)
        self.rpc('read', fail=True); self.write(b'NO', fail=True)
        self.rpc('info', fail=True, path=self.root)
        self.rpc('info', fail=True, path=self.root/'..'/'outside')

    def test_lock_and_upload_sidecars_cannot_block_on_fifo(self):
        lock = self.root / ('.hepta-lock-' + hashlib.sha256(self.path.name.encode()).hexdigest()[:24])
        os.mkfifo(lock); self.write(b'NO', fail=True); lock.unlink()
        tag = hashlib.sha256((self.path.name+'\0fixture01').encode()).hexdigest()
        os.mkfifo(self.root / ('.hepta-upload-'+tag))
        self.chunk(b'NO', fail=True)

    def test_invalid_encoding_ids_and_size_rejected(self):
        self.rpc('write', fail=True, expected_version='absent', data_base64='not%base64')
        self.write(b'x'*(1024*1024+1), fail=True)
        self.chunk(b'x', upload='../escape', fail=True)
        self.chunk(b'x', offset=-1, fail=True)
        self.write(b'x', path=self.root/'.hepta-forbidden', fail=True)

    @unittest.skipUnless(hasattr(os, 'setxattr'), 'extended attribute support required')
    def test_xattrs_preserved_instead_of_silently_lost(self):
        self.path.write_bytes(b'WITH_METADATA')
        try: os.setxattr(self.path, 'user.hepta_fixture', b'KEEP')
        except OSError as e: self.skipTest(str(e))
        before = self.rpc('info')
        self.write(b'NEW_WITH_METADATA', before['version'])
        self.assertEqual(self.path.read_bytes(), b'NEW_WITH_METADATA')
        self.assertEqual(os.getxattr(self.path, 'user.hepta_fixture'), b'KEEP')
        self.assertEqual(before['metadata'], self.rpc('info')['metadata'])


if __name__ == '__main__': unittest.main(verbosity=2)
