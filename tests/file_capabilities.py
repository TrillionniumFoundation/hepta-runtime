#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Descriptor traversal/atomic-write tests, without any privileged operations."""
import json, os, pathlib, subprocess, tempfile, unittest
CODE=(pathlib.Path(__file__).resolve().parents[1]/'src/mcp/runtime/fileio.py').read_text()
class Files(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name)/'work'; self.root.mkdir()
    def tearDown(self): self.tmp.cleanup()
    def call(self,op,path,**kwargs):
        return subprocess.run(['python3','-c',CODE],input=json.dumps(dict(root=str(self.root),path=str(path),op=op,**kwargs)),text=True,capture_output=True,timeout=5)
    def test_read_write_lossless(self):
        data='中文\nα\x00'.encode();p=self.root/'a'
        self.assertEqual(self.call('write',p,hex=data.hex()).returncode,0)
        self.assertEqual(bytes.fromhex(json.loads(self.call('read',p).stdout)['hex']),data)
    def test_symlink_read_denied(self):
        secret=pathlib.Path(self.tmp.name)/'secret';secret.write_text('NOT_VISIBLE')
        (self.root/'link').symlink_to(secret)
        p=self.call('read',self.root/'link');self.assertNotEqual(p.returncode,0);self.assertNotIn('NOT_VISIBLE',p.stdout)
    def test_symlink_parent_write_denied(self):
        outside=pathlib.Path(self.tmp.name)/'outside';outside.mkdir();(self.root/'link').symlink_to(outside,target_is_directory=True)
        self.assertNotEqual(self.call('write',self.root/'link'/'file',hex='61').returncode,0)
        self.assertFalse((outside/'file').exists())
    def test_write_replaces_link_not_target(self):
        outside=pathlib.Path(self.tmp.name)/'outside';outside.write_text('KEEP');(self.root/'link').symlink_to(outside)
        self.assertEqual(self.call('write',self.root/'link',hex='61').returncode,0)
        self.assertEqual(outside.read_text(),'KEEP');self.assertEqual((self.root/'link').read_text(),'a')
    def test_escape_denied(self): self.assertNotEqual(self.call('read',self.root/'..'/'secret').returncode,0)
    def test_directory_roundtrip(self):
        p=self.root/'a'/'b';self.assertEqual(self.call('mkdir',p).returncode,0)
        self.assertTrue(json.loads(self.call('metadata',p).stdout)['is_dir'])
        self.assertEqual(json.loads(self.call('list',self.root/'a').stdout)['entries'][0]['name'],'b')
    def test_nonregular_read_denied(self): self.assertNotEqual(self.call('read',self.root).returncode,0)
    def test_bound(self):
        p=self.root/'large';p.write_bytes(b'x'*1048577)
        self.assertNotEqual(self.call('read',p).returncode,0)
    def test_fifo_read_fails_without_blocking(self):
        p=self.root/'fifo';os.mkfifo(p)
        result=self.call('read',p)
        self.assertNotEqual(result.returncode,0)
if __name__=='__main__': unittest.main()
