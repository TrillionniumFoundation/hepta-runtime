#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Disposable real-file tests for ACL/xattr preservation and atomic failure."""
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('binary_meta',ROOT/'src/mcp/runtime/binary_file.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)


class Preservation(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-metadata-')
        self.root=pathlib.Path(self.temp.name).resolve();self.path=self.root/'data.bin'
        self.path.write_bytes(b'old content')
    def tearDown(self):self.temp.cleanup()
    def info(self):return B.main({'op':'info','root':str(self.root),'path':str(self.path)})
    def write(self,version=None):
        return B.main({'op':'write','root':str(self.root),'path':str(self.path),'expected_version':version or self.info()['version'],'data_base64':base64.b64encode(b'NEW content').decode()})
    def test_modes_owner_and_group_preserved(self):
        self.path.chmod(0o751);before=self.path.stat();self.write();after=self.path.stat()
        self.assertEqual((before.st_uid,before.st_gid,before.st_mode),(after.st_uid,after.st_gid,after.st_mode))
        self.assertEqual(self.path.read_bytes(),b'NEW content')
    @unittest.skipUnless(hasattr(os,'setxattr'),'Linux extended attributes')
    def test_binary_xattr_preserved_and_reported_as_hash_only(self):
        os.setxattr(self.path,'user.hepta',b'private\0value\xff')
        before=self.info();self.write(before['version']);after=self.info()
        self.assertEqual(before['metadata'],after['metadata'])
        self.assertEqual(os.getxattr(self.path,'user.hepta'),b'private\0value\xff')
        self.assertNotIn('private',json.dumps(after))
    @unittest.skipUnless(shutil.which('setfacl'),'Linux ACL utility')
    def test_named_posix_acl_preserved_exactly(self):
        subprocess.run(['setfacl','-m','u:65534:r--',str(self.path)],check=True)
        acl=os.getxattr(self.path,'system.posix_acl_access');before=self.info()
        self.write();after=self.info()
        self.assertEqual(os.getxattr(self.path,'system.posix_acl_access'),acl)
        self.assertEqual(before['metadata'],after['metadata'])
    @unittest.skipUnless(shutil.which('setfacl'),'Linux default ACL utility')
    def test_inherited_parent_acl_not_added_to_original(self):
        subprocess.run(['setfacl','-m','d:u:65534:r--',str(self.root)],check=True)
        self.assertNotIn('system.posix_acl_access',os.listxattr(self.path))
        self.write()
        self.assertNotIn('system.posix_acl_access',os.listxattr(self.path))
    def test_hardlinks_never_silently_split(self):
        other=self.root/'alias.bin';os.link(self.path,other)
        old=self.path.read_bytes();inode=self.path.stat().st_ino
        with self.assertRaisesRegex(ValueError,'hard links'):self.write()
        self.assertEqual(self.path.read_bytes(),old);self.assertEqual(other.read_bytes(),old)
        self.assertEqual(inode,self.path.stat().st_ino)
    @unittest.skipUnless(hasattr(os,'setxattr'),'Linux extended attributes')
    def test_metadata_copy_failure_leaves_original_content_and_rights(self):
        os.setxattr(self.path,'user.hepta',b'keep');before=self.path.read_bytes();version=self.info()['version']
        with mock.patch.object(B.os,'setxattr',side_effect=PermissionError('injected attribute copy failure')):
            with self.assertRaises(PermissionError):self.write(version)
        self.assertEqual(self.path.read_bytes(),before);self.assertEqual(self.info()['version'],version)
        self.assertEqual(os.getxattr(self.path,'user.hepta'),b'keep')
    def test_special_bits_not_silently_copied_or_removed(self):
        self.path.chmod(0o4751);old=self.info()['version']
        with self.assertRaisesRegex(ValueError,'special'):self.write(old)
        self.assertEqual(self.info()['version'],old)
    @unittest.skipUnless(hasattr(os,'setxattr'),'Linux attributes')
    def test_document_publication_uses_same_metadata_contract(self):
        spec=importlib.util.spec_from_file_location('doc_meta',ROOT/'src/mcp/runtime/document_local.py')
        doc=importlib.util.module_from_spec(spec);spec.loader.exec_module(doc)
        os.setxattr(self.path,'user.hepta',b'document-tag');before=self.info()
        doc.publish({'roots':[str(self.root)]},str(self.path),b'changed document',before['sha256'])
        self.assertEqual(self.info()['metadata'],before['metadata'])


if __name__=='__main__':unittest.main(verbosity=2)
