#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Authentication and partial-observation tests; no real network or power actions."""
import hashlib
import hmac
import importlib.util
import json
import pathlib
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('observer',ROOT/'deploy/independent_observer.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
KEY=b'k'*32;CHALLENGE='a'*32


class IndependentObserver(unittest.TestCase):
    def response(self,boot='known-boot',proof=None):
        value=hmac.new(KEY,(CHALLENGE+'\0'+boot).encode(),hashlib.sha256).hexdigest() if proof is None else proof
        return (json.dumps({'boot_id':boot,'proof':value})+'\n').encode()
    def probe(self,response):
        connection=mock.Mock();connection.__enter__=mock.Mock(return_value=connection);connection.__exit__=mock.Mock(return_value=False);connection.recv.return_value=response
        with mock.patch.object(O.socket,'create_connection',return_value=connection),mock.patch.object(O.secrets,'token_hex',return_value=CHALLENGE):
            return O.probe('192.168.0.4',12000,KEY,'known-boot')
    def test_valid_challenge_and_boot_identity(self):
        result=self.probe(self.response());self.assertTrue(result['reachable']);self.assertTrue(result['identity_matches'])
    def test_wrong_proof_never_authenticates_response(self):
        result=self.probe(self.response(proof='0'*64));self.assertFalse(result['reachable']);self.assertIsNone(result['controller_boot_id'])
    def test_changed_boot_is_not_same_controller_session(self):
        result=self.probe(self.response(boot='another-boot'));self.assertTrue(result['reachable']);self.assertFalse(result['identity_matches'])
    def test_malformed_oversize_and_wrong_type_are_not_success(self):
        for data in (b'not-json\n',b'x'*4097,self.response(proof=55),b''):
            self.assertFalse(self.probe(data)['reachable'])
    def test_connection_failure_is_an_explicit_observation(self):
        with mock.patch.object(O.socket,'create_connection',side_effect=ConnectionRefusedError):
            result=O.probe('192.168.0.4',12000,KEY,'known-boot')
        self.assertFalse(result['reachable']);self.assertEqual(result['error'],'ConnectionRefusedError')
    def test_non_ssh_service_is_not_reported_as_ssh(self):
        connection=mock.Mock();connection.__enter__=mock.Mock(return_value=connection);connection.__exit__=mock.Mock(return_value=False);connection.recv.return_value=b'HTTP/1.1'
        with mock.patch.object(O.socket,'create_connection',return_value=connection):self.assertFalse(O.ssh_banner('192.168.0.4')['reachable'])


if __name__=='__main__':unittest.main(verbosity=2)
