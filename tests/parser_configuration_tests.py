#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Explicit parser-setting upgrade tests in a fake home; no services are changed."""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('parser_config',ROOT/'deploy/configure-document-worker.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


class ParserConfiguration(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-parser-config-test-');self.home=pathlib.Path(self.temp.name)
        self.unit=self.home/'.config/systemd/user/hepta-runtime-operator.service';self.unit.parent.mkdir(parents=True);self.unit.write_text('[Service]\n')
        self.drop=self.unit.parent/(self.unit.name+'.d')/'50-native-documents.conf';self.drop.parent.mkdir()
        self.old=b'[Service]\nEnvironment="HEPTA_RUNTIME_DOCUMENT_PYTHON=/old/bin/python"\n';self.drop.write_bytes(self.old)
    def tearDown(self):self.temp.cleanup()
    def call(self,*args):
        with mock.patch.object(pathlib.Path,'home',return_value=self.home),mock.patch.object(M.os,'geteuid',return_value=1000),mock.patch.object(M.subprocess,'run',return_value=types.SimpleNamespace(stdout='{}')) as proc,mock.patch.object(sys,'argv',['configure','--python','/new/bin/python','--out',str(self.home/'result.json'),*args]),contextlib.redirect_stdout(io.StringIO()):
            M.main()
            self.assertNotIn('systemctl',str(proc.call_args_list))
        return json.loads((self.home/'result.json').read_text())
    def test_different_setting_requires_explicit_prior_hash(self):
        with self.assertRaises(RuntimeError):self.call()
        self.assertEqual(self.drop.read_bytes(),self.old)
    def test_stale_hash_refuses_change(self):
        with self.assertRaisesRegex(RuntimeError,'changed'):self.call('--expected-current-sha256','0'*64)
        self.assertEqual(self.drop.read_bytes(),self.old)
    def test_matching_hash_stages_only_dropin_without_restart(self):
        result=self.call('--require-formats','--expected-current-sha256',hashlib.sha256(self.old).hexdigest())
        self.assertTrue(result['staged']);self.assertTrue(result['formats_verified']);self.assertFalse(result['service_restarted'])
        self.assertIn(b'/new/bin/python',self.drop.read_bytes());self.assertEqual(result['new_sha256'],hashlib.sha256(self.drop.read_bytes()).hexdigest())
    def test_check_only_does_not_publish(self):
        result=self.call('--check-only','--expected-current-sha256',hashlib.sha256(self.old).hexdigest())
        self.assertFalse(result['staged']);self.assertEqual(self.drop.read_bytes(),self.old)
    def test_symlink_dropin_is_not_followed(self):
        outside=self.home/'outside';outside.write_bytes(self.old);self.drop.unlink();self.drop.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError,'symlink'):self.call('--expected-current-sha256',hashlib.sha256(self.old).hexdigest())
        self.assertEqual(outside.read_bytes(),self.old)


if __name__=='__main__':unittest.main(verbosity=2)
