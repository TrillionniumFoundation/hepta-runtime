#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Disposable native batch reads: exact UTF-8, response bounds and descriptor safety."""
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

RUNTIME = pathlib.Path(__file__).resolve().parents[1] / 'src/mcp/runtime'
HELPER = RUNTIME / 'multi_read_host.py'
sys.path.insert(0, str(RUNTIME))
spec = importlib.util.spec_from_file_location('hepta_multi_read_test_helper', HELPER)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class MultiRead(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-multi-read-')
        self.root = pathlib.Path(self.temp.name).resolve()
        self.a = self.root / 'a.txt'
        self.b = self.root / 'b.txt'
        self.a.write_bytes('中文α\n\0"\\'.encode())
        self.b.write_bytes(b'beta\r\n')

    def tearDown(self):
        self.temp.cleanup()

    def request(self, paths=None, **kw):
        return {'files': [{'root': str(self.root), 'path': str(p)}
                          for p in (paths if paths is not None else [self.a, self.b])],
                **kw}

    def rpc(self, fail=False, paths=None, **kw):
        p = subprocess.run([sys.executable, str(HELPER)],
            input=json.dumps(self.request(paths, **kw)), text=True,
            capture_output=True, timeout=10)
        if fail:
            self.assertNotEqual(p.returncode, 0, p.stdout)
            self.assertEqual(p.stdout, '', 'partial file text leaked on failure')
            return p.stderr
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def test_exact_complete_reads_have_independent_fingerprints(self):
        result = self.rpc()
        self.assertFalse(result['atomic_snapshot'])
        self.assertEqual(result['snapshot_scope'], 'independent_file')
        self.assertFalse(result['truncated'])
        for p, f in zip([self.a,self.b], result['files']):
            data = p.read_bytes()
            self.assertEqual(f['text'].encode(), data)
            self.assertEqual(f['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(f['size'], len(data))
            self.assertTrue(f['eof'])
            self.assertEqual(f['version'], M.version(p.stat()))

    def test_empty_file_is_full_success(self):
        self.a.write_bytes(b'')
        self.assertEqual(self.rpc(paths=[self.a])['files'][0]['text'], '')

    def test_missing_later_path_discloses_no_earlier_content(self):
        self.a.write_text('secret-first-file')
        err = self.rpc(fail=True, paths=[self.a,self.root/'missing'])
        self.assertNotIn('secret-first-file', err)

    def test_invalid_utf8_later_file_discloses_no_partial_content(self):
        self.b.write_bytes(b'bad\xffUTF8')
        self.assertIn('UnicodeDecodeError', self.rpc(fail=True))
        self.b.write_bytes(b'\xe4\xb8')
        self.assertIn('UnicodeDecodeError', self.rpc(fail=True))

    def test_file_byte_bound_never_truncates(self):
        self.a.write_bytes(b'a' * 65536)
        self.assertEqual(self.rpc(paths=[self.a], max_file_bytes=65536,
            max_response_bytes=262144)['files'][0]['size'], 65536)
        self.a.write_bytes(b'a' * 65537)
        self.assertIn('ceiling', self.rpc(paths=[self.a], fail=True, max_file_bytes=65536))
        self.a.write_bytes(b'a' * 16385)
        self.assertIn('ceiling', self.rpc(paths=[self.a], fail=True))

    def test_utf8_byte_limit_counts_bytes(self):
        self.a.write_text('中')
        self.assertIn('ceiling', self.rpc(paths=[self.a], fail=True, max_file_bytes=2))
        self.assertEqual(self.rpc(paths=[self.a], max_file_bytes=3)['files'][0]['text'], '中')

    def test_total_budget_counts_all_files_and_json_escaping(self):
        self.a.write_bytes(b'\\' * 2000)
        one = M.multi_read(self.request([self.a], max_response_bytes=262144))
        boundary = M._wire_size(one)
        self.assertGreater(boundary, 2 * len(self.a.read_bytes()))
        self.assertEqual(M.multi_read(self.request([self.a], max_response_bytes=boundary)), one)
        with self.assertRaises(ValueError):
            M.multi_read(self.request([self.a], max_response_bytes=boundary-1))
        self.b.write_bytes(b'\\' * 2000)
        self.rpc(paths=[self.a,self.b], fail=True, max_response_bytes=boundary+500)

    def test_nonfinite_invalid_and_oversize_budgets_are_rejected(self):
        for file_limit in [0, 65537, -1, 1.5, True]:
            with self.subTest(file_limit=file_limit):
                self.assertIn('request', self.rpc(fail=True, max_file_bytes=file_limit))
        for budget in [0, 1023, 262145, -1, 1.5, True]:
            with self.subTest(budget=budget):
                self.assertIn('request', self.rpc(fail=True, max_response_bytes=budget))

    def test_count_and_duplicate_paths(self):
        self.rpc(paths=[], fail=True)
        self.rpc(paths=[self.a]*17, fail=True)
        self.assertIn('distinct', self.rpc(paths=[self.a,self.a], fail=True))
        many=[]
        for n in range(16):
            p=self.root / str(n); p.write_text(str(n)); many.append(p)
        self.assertEqual(len(self.rpc(paths=many)['files']),16)

    def test_lexical_aliases_are_rejected_before_open(self):
        for path in ['relative', '/', str(self.root)+'/./a.txt',
                     str(self.root)+'//a.txt', str(self.root)+'/../a.txt',
                     str(self.a)+'\0']:
            with self.subTest(path=path):
                self.rpc(paths=[path], fail=True)

    def test_outside_root_and_root_target_are_rejected(self):
        self.rpc(paths=[self.root], fail=True)
        with tempfile.TemporaryDirectory(prefix='hepta-outside-') as d:
            outside=pathlib.Path(d)/'secret'; outside.write_text('private')
            self.assertIn('PermissionError', self.rpc(paths=[outside], fail=True))

    def test_symlink_leaf_parent_and_capability_root_are_rejected(self):
        leaf=self.root/'leaf'; leaf.symlink_to(self.a)
        self.rpc(paths=[leaf], fail=True)
        real=self.root/'real'; real.mkdir(); (real/'file').write_text('secret')
        alias=self.root/'alias'; alias.symlink_to(real, target_is_directory=True)
        self.rpc(paths=[alias/'file'], fail=True)
        q=self.request([alias/'file'])
        q['files'][0]['root']=str(alias)
        with self.assertRaises(OSError): M.multi_read(q)

    def test_symlinked_root_ancestor_is_rejected(self):
        alias=self.root/'alias-root'; alias.symlink_to(self.root, target_is_directory=True)
        q={'files':[{'root':str(alias),'path':str(alias/'a.txt')}]}
        with self.assertRaises(OSError): M.multi_read(q)

    def test_hardlink_rejected_including_alias_to_outside_root(self):
        with tempfile.TemporaryDirectory(prefix='hepta-outside-') as d:
            secret=pathlib.Path(d)/'secret'; secret.write_text('private')
            linked=self.root/'linked'; os.link(secret,linked)
            self.assertIn('hardlinked', self.rpc(paths=[linked], fail=True))
        alias=self.root/'same'; os.link(self.a,alias)
        self.assertIn('hardlinked', self.rpc(paths=[self.a], fail=True))

    def test_fifo_and_directory_reject_without_blocking(self):
        fifo=self.root/'fifo'; os.mkfifo(fifo)
        self.assertIn('regular', self.rpc(paths=[fifo], fail=True))
        directory=self.root/'directory'; directory.mkdir()
        self.assertIn('regular', self.rpc(paths=[directory], fail=True))

    def test_runtime_sidecars_are_not_targets(self):
        side=self.root/'.hepta-meta-secret'; side.write_text('never visible')
        self.assertIn('sidecars', self.rpc(paths=[side], fail=True))

    def test_concurrent_change_and_path_replacement_are_rejected(self):
        original_read = M.os.read
        changed = [False]
        def read_and_change(fd, limit):
            result = original_read(fd,limit)
            if not changed[0]:
                changed[0]=True
                self.a.write_bytes(b'changed')
            return result
        with mock.patch.object(M.os, 'read', side_effect=read_and_change):
            with self.assertRaisesRegex(ValueError,'changed'):
                M.multi_read(self.request([self.a]))
        self.a.write_bytes(b'original')
        original_parent=M.parent
        calls=[0]
        def parent_then_replace(root,path):
            calls[0]+=1
            if calls[0]==2:
                replacement=self.root/'replacement'; replacement.write_bytes(b'original')
                os.replace(replacement,self.a)
            return original_parent(root,path)
        with mock.patch.object(M,'parent',side_effect=parent_then_replace):
            with self.assertRaisesRegex(ValueError,'identity'):
                M.multi_read(self.request([self.a]))

    def test_embedded_source_needs_no_remote_helper_files(self):
        source = ("__name__ = 'hepta_multi_read_helpers'\n" +
            (RUNTIME/'file_metadata.py').read_text() + '\n' +
            (RUNTIME/'binary_file.py').read_text() + '\n' +
            HELPER.read_text() + '\nrun_multi_read()\n')
        p = subprocess.run([sys.executable, '-c', source], cwd=str(self.root),
            input=json.dumps(self.request()), text=True, capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)['files'][0]['text'], self.a.read_text())

    def test_errors_close_descriptors(self):
        fds=pathlib.Path('/proc/self/fd')
        if not fds.exists(): self.skipTest('Linux descriptor inventory unavailable')
        before=len(list(fds.iterdir()))
        self.a.write_bytes(b'\xff')
        for _ in range(30):
            with self.assertRaises(UnicodeDecodeError):
                M.multi_read(self.request([self.a]))
        self.assertEqual(len(list(fds.iterdir())),before)

if __name__ == '__main__':
    unittest.main()
