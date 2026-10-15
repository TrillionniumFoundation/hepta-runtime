#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline tests for a private 50-tool stdio facade six-host harness.

This does not start a tunnel or execute operations. Hosted CI can run it
without any real workstation, SSH identity, installed native release or token.
"""
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
import dc_parity_full_facade_six_host_acceptance as M


class PinnedFacade(unittest.TestCase):
    def test_frozen_v4_contract_is_exact_additive_superset(self):
        v4=ROOT/'deploy/contracts/hepta-runtime-full-operator-v4.json'
        v3=ROOT/'deploy/contracts/hepta-runtime-full-operator-v3.json'
        a=json.loads(v4.read_text())
        b=json.loads(v3.read_text())
        self.assertEqual(M.digest(v4),M.CONTRACT_EXPECTED_SHA256)
        self.assertEqual(len(a['tools']),50)
        self.assertEqual(len(b['tools']),49)
        newer={x['name']:x for x in a['tools']}
        older={x['name']:x for x in b['tools']}
        self.assertEqual(set(newer)-set(older),{'directory_move'})
        for name,definition in older.items():
            self.assertEqual(newer[name],definition,'old tool changed: '+name)
        self.assertEqual(newer['directory_move']['annotations'],{
            'readOnlyHint':False,'destructiveHint':True,
            'idempotentHint':False,'openWorldHint':False,
        })

    def test_artifact_pins_are_exact_and_separately_provenanced(self):
        self.assertEqual(len(M.RELEASE_EXPECTED_SHA256),64)
        self.assertEqual(len(M.FACADE_EXPECTED_SHA256),64)
        self.assertEqual(M.RELEASE_SOURCE_HEAD,
                         '874e801b92c1ec2fb3093b1934a5535a12eb1e64')
        self.assertNotEqual(M.FACADE_EXPECTED_SHA256,M.RELEASE_EXPECTED_SHA256)
        self.assertNotEqual(M.FACADE_EXPECTED_SHA256,M.CONTRACT_EXPECTED_SHA256)

    def test_only_approved_six_targets_are_named(self):
        self.assertEqual(dict(M.HOSTS),{
            'main':'localhost','pocket4':'pocket4','rog':'rog',
            'mac':'macbook-pro','x230':'x230-ts','ai395':'ai395',
        })
        for name,alias in M.HOSTS:
            base='/private/tmp' if name=='mac' else '/tmp'
            cfg=M.validate_private_config(name,alias,base+'/isolated')
            self.assertEqual(cfg['ssh_target'],alias)
            self.assertEqual(cfg['allowed_read_path_prefixes'],[base])
            self.assertEqual(cfg['allowed_write_path_prefixes'],[base])
            self.assertEqual(cfg['remote_state_dir'],base+'/isolated')
            self.assertTrue(cfg['allow_execute'])
            self.assertTrue(cfg['allow_pty'])

    def test_candidate_file_validation_rejects_symlinks_and_world_writable(self):
        with tempfile.TemporaryDirectory() as d:
            a=pathlib.Path(d)/'candidate'
            a.write_bytes(b'fixture')
            a.chmod(0o600)
            self.assertEqual(M.exact_regular(a),a)
            with self.assertRaises(PermissionError):
                M.exact_regular(a,executable=True)
            a.chmod(0o700)
            self.assertEqual(M.exact_regular(a,executable=True),a)
            a.chmod(0o666)
            with self.assertRaises(PermissionError):
                M.exact_regular(a)
            a.chmod(0o600)
            link=pathlib.Path(d)/'link'
            link.symlink_to(a)
            with self.assertRaises(ValueError):
                M.exact_regular(link)


if __name__=='__main__':
    unittest.main(verbosity=2)
