#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Disposable inode, hard-link, mode-bit and real subprocess-crash recovery tests."""
import base64
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

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('inode_binary',ROOT/'src/mcp/runtime/binary_file.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
exec(compile((ROOT/'src/mcp/runtime/inode_patch.py').read_text(),'inode_patch.py','exec'),B.__dict__)


@unittest.skipUnless(sys.platform=='linux','qualified Linux inode semantics')
class InodePatch(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-inode-test-');self.root=pathlib.Path(self.temp.name).resolve();self.file=self.root/'a.bin';self.file.write_bytes(b'0123456789')
        self.alias=self.root/'alias.bin';os.link(self.file,self.alias)
        self.base={'op':'inode_patch','action':'apply','root':str(self.root),'path':str(self.file),'transaction_id':'transaction-01','acknowledge_non_atomic':True,'offset':2,'data_base64':base64.b64encode(b'ABC').decode(),'preserve_special_bits':False,'expected_version':B.version(self.file.stat()),'expected_sha256':hashlib.sha256(self.file.read_bytes()).hexdigest()}
    def tearDown(self):self.temp.cleanup()
    def call(self,**extra):return B.main({**self.base,**extra})
    def test_hard_links_and_already_open_descriptor_keep_identity(self):
        before=self.file.stat()
        with self.alias.open('rb') as opened:
            result=self.call();self.assertTrue(result['inode_preserved']);self.assertFalse(result['atomic_visibility'])
            self.assertEqual(opened.read(),b'01ABC56789');self.assertEqual(os.fstat(opened.fileno()).st_ino,before.st_ino)
        self.assertEqual(self.file.stat().st_ino,self.alias.stat().st_ino);self.assertEqual(self.file.stat().st_nlink,2)
        self.assertEqual(self.call()['reused'],True)
    def test_stale_hash_version_and_replay_changed_data_are_rejected(self):
        for extra in ({'expected_sha256':'0'*64},{'expected_version':'stale'},{'acknowledge_non_atomic':False},{'offset':9}):
            with self.assertRaises(ValueError):self.call(**extra)
        self.assertEqual(self.file.read_bytes(),b'0123456789');self.call()
        with self.assertRaises(ValueError):self.call(data_base64=base64.b64encode(b'DEF').decode())
        self.assertEqual(self.file.read_bytes(),b'01ABC56789')
    def test_special_mode_bits_require_explicit_and_remain_exact(self):
        self.file.chmod(0o6750);self.base['expected_version']=B.version(self.file.stat())
        with self.assertRaisesRegex(ValueError,'preserve_special_bits'):self.call()
        self.assertEqual(self.file.read_bytes(),b'0123456789')
        result=self.call(preserve_special_bits=True);self.assertTrue(result['metadata_preserved'])
        self.assertEqual(self.file.stat().st_mode&0o7777,0o6750);self.assertEqual(self.alias.stat().st_mode&0o7777,0o6750)
    def test_xattrs_and_acl_survive_same_inode_patch(self):
        os.setxattr(self.file,'user.hepta-fixture',b'private-fixture')
        if pathlib.Path('/usr/bin/setfacl').exists():subprocess.run(['/usr/bin/setfacl','-m','u:65534:r--',str(self.file)],check=True)
        expected={n:os.getxattr(self.file,n) for n in os.listxattr(self.file)};self.base['expected_version']=B.version(self.file.stat())
        self.call();self.assertEqual(expected,{n:os.getxattr(self.file,n) for n in os.listxattr(self.file)})
    def test_partial_write_recovers_original_bytes_not_duplicate_patch(self):
        def fail(fd,offset,data):os.pwrite(fd,data[:1],offset);os.fsync(fd);raise OSError('injected I/O failure')
        with mock.patch.object(B,'_inode_write',side_effect=fail):
            with self.assertRaises(OSError):self.call()
        self.assertEqual(self.file.read_bytes(),b'01A3456789');self.assertEqual(self.call(action='status')['state'],'prepared')
        result=self.call(action='recover');self.assertEqual(result['state'],'rolled_back');self.assertEqual(self.alias.read_bytes(),b'0123456789')
        with self.assertRaisesRegex(ValueError,'recovery'):self.call()
    def test_unrelated_concurrent_content_change_refuses_recovery(self):
        def fail(fd,offset,data):os.pwrite(fd,data[:1],offset);os.fsync(fd);raise OSError('fixture failure')
        with mock.patch.object(B,'_inode_write',side_effect=fail):
            with self.assertRaises(OSError):self.call()
        with self.file.open('r+b') as f:f.seek(9);f.write(b'Z')
        with self.assertRaisesRegex(ValueError,'unrelated'):self.call(action='recover')
        self.assertEqual(self.file.read_bytes(),b'01A345678Z')
    def test_actual_process_exit_between_write_and_receipt_is_reconciled(self):
        code="import importlib.util,pathlib,sys,os,json;s=importlib.util.spec_from_file_location('b',sys.argv[1]);b=importlib.util.module_from_spec(s);s.loader.exec_module(b);exec(compile(pathlib.Path(sys.argv[1]).with_name('inode_patch.py').read_text(),'inode_patch.py','exec'),b.__dict__);original=b._inode_write\ndef fail(fd,offset,data):\n original(fd,offset,data);os._exit(73)\nb._inode_write=fail;b.main(json.load(sys.stdin))"
        proc=subprocess.run([sys.executable,'-c',code,str(ROOT/'src/mcp/runtime/binary_file.py')],input=json.dumps(self.base),text=True,capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,73,proc.stderr);self.assertEqual(self.file.read_bytes(),b'01ABC56789')
        result=self.call(action='recover');self.assertEqual(result['state'],'committed');self.assertTrue(self.call()['reused'])
    def test_receipt_is_private_and_other_target_reuse_is_rejected(self):
        self.call();receipt=next(self.root.glob('.hepta-inode-*.json'));self.assertEqual(receipt.stat().st_mode&0o777,0o600)
        other=self.root/'other.bin';other.write_bytes(b'0123456789')
        with self.assertRaisesRegex(ValueError,'binding'):self.call(path=str(other),action='recover')
        self.assertEqual(other.read_bytes(),b'0123456789')
    def test_recovery_refuses_link_count_and_metadata_drift(self):
        self.call();self.alias.unlink()
        with self.assertRaisesRegex(ValueError,'link count'):self.call(action='recover')
    def test_final_symlink_never_becomes_a_write_target(self):
        link=self.root/'link';link.symlink_to(self.file)
        with self.assertRaises(OSError):self.call(path=str(link))
        self.assertEqual(self.file.read_bytes(),b'0123456789')

    def test_recovery_does_not_overwrite_later_acl_or_permissions(self):
        self.call();self.file.chmod(0o620)
        with self.assertRaisesRegex(ValueError,'rights change'):self.call(action='recover')
        self.assertEqual(self.file.stat().st_mode&0o777,0o620)
        self.assertEqual(self.file.read_bytes(),b'01ABC56789')



if __name__=='__main__':unittest.main(verbosity=2)
