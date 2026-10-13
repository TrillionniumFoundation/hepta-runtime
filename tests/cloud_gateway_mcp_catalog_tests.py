#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline public discovery/OAuth metadata smoke. Does not serve HTTP or login."""
import copy
import hashlib
import json
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
from mcp_tool_contract import ToolContract,make_contract
from cloud_gateway_mcp_catalog import (
    SCOPES, VERSION, discover_response, oauth_challenge,
    oauth_protected_resource_metadata,reviewed_public_tools,
    scopes_for_tool,tools_list_response,
)

CONTRACT=ROOT/'deploy/contracts/hepta-runtime-full-operator-v4.json'
RESOURCE='https://mcp.example.test/mcp'
ISSUER='https://auth.example.test'

class OfflinePublicCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract=ToolContract.load(CONTRACT,hashlib.sha256(CONTRACT.read_bytes()).hexdigest())
        cls.selected=frozenset({
            'host_list','directory_create','text_file_write','shell_start',
            'sudo_start','privileged_action','process_checkpoint',
        })

    def test_requires_deliberate_allowlist_not_default_full_exposure(self):
        for invalid in (frozenset(),{'host_list'},frozenset({'unknown_tool'}),
                        frozenset({'host_list','fake'})):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    reviewed_public_tools(self.contract,invalid)

    def test_selection_never_mutates_native_contract_and_preserves_annotations(self):
        native_snapshot=json.dumps(self.contract.tools,sort_keys=True)
        published=reviewed_public_tools(self.contract,self.selected)
        self.assertEqual(len(published),len(self.selected))
        self.assertEqual({t['name'] for t in published},set(self.selected))
        for item in published:
            original=self.contract.by_name[item['name']]
            original_fields={k:v for k,v in item.items() if k!='securitySchemes'}
            self.assertEqual(original_fields,original)
        self.assertEqual(json.dumps(self.contract.tools,sort_keys=True),native_snapshot)

    def test_per_tool_oauth_scopes_match_actual_tool_semantics(self):
        expected={
            'host_list':['hepta:connect'],
            'directory_create':['hepta:connect','hepta:write'],
            'text_file_write':['hepta:connect','hepta:write'],
            'shell_start':['hepta:connect','hepta:execute','hepta:write'],
            'sudo_start':['hepta:connect','hepta:execute','hepta:privileged','hepta:write'],
            'privileged_action':['hepta:connect','hepta:execute','hepta:privileged','hepta:write'],
            'process_checkpoint':['hepta:connect','hepta:execute','hepta:privileged','hepta:write'],
        }
        published=reviewed_public_tools(self.contract,self.selected)
        for tool in published:
            with self.subTest(name=tool['name']):
                self.assertEqual(tool['securitySchemes'],
                    [{'type':'oauth2','scopes':expected[tool['name']]}])
                self.assertEqual(scopes_for_tool(self.contract,tool['name']),
                    expected[tool['name']])
                if tool['name']=='host_list':
                    self.assertTrue(tool['annotations']['readOnlyHint'])
                if tool['name']=='shell_start':
                    self.assertTrue(tool['annotations']['destructiveHint'])

    def test_result_envelopes_are_protocol_complete_and_private(self):
        discover=discover_response('d0',self.contract,self.selected)
        tools=tools_list_response(13,self.contract,self.selected)
        for envelope in (discover,tools):
            self.assertEqual(envelope['jsonrpc'],'2.0')
            result=envelope['result']
            self.assertEqual(result['resultType'],'complete')
            self.assertEqual(result['cacheScope'],'private')
            self.assertEqual(result['ttlMs'],0)
            self.assertEqual(result['_meta']['io.modelcontextprotocol/serverInfo']['name'],
                             'hepta-public-gateway-candidate')
        self.assertEqual(discover['result']['supportedVersions'],[VERSION])
        self.assertEqual(len(tools['result']['tools']),7)

    def test_no_unreviewed_tool_even_if_native_catalog_has_50(self):
        full_set=frozenset(t['name'] for t in self.contract.tools)
        self.assertEqual(len(full_set),50)
        selection=reviewed_public_tools(self.contract,self.selected)
        self.assertNotIn('host_signal',{t['name'] for t in selection})
        self.assertNotIn('binary_patch_inode',{t['name'] for t in selection})
        self.assertEqual(len(reviewed_public_tools(self.contract,full_set)),50)
        # A full public catalog is possible only by an explicit reviewed grant;
        # this function never installs or publishes it.

    def test_contract_drift_rejected_even_if_new_definition_is_well_formed(self):
        native=copy.deepcopy(self.contract.tools)
        native[0]['description']+=' tampered'
        other=ToolContract(make_contract(native))
        with self.assertRaises(ValueError):
            reviewed_public_tools(other,self.selected)

    def test_existing_contract_in_memory_changes_cannot_be_published(self):
        contract=ToolContract.load(CONTRACT,hashlib.sha256(CONTRACT.read_bytes()).hexdigest())
        contract.by_name['shell_start']['annotations']['readOnlyHint']=True
        contract.by_name['shell_start']['annotations']['destructiveHint']=False
        with self.assertRaises(ValueError):
            reviewed_public_tools(contract,self.selected)
        contract=ToolContract.load(CONTRACT,hashlib.sha256(CONTRACT.read_bytes()).hexdigest())
        indexed=copy.deepcopy(contract.by_name['shell_start'])
        indexed['description']='Different unreviewed tool meaning'
        contract.by_name['shell_start']=indexed
        with self.assertRaises(ValueError):
            reviewed_public_tools(contract,self.selected)

    def test_resource_metadata_matches_exact_oauth_audience(self):
        meta=oauth_protected_resource_metadata(RESOURCE,ISSUER)
        self.assertEqual(meta['resource'],RESOURCE)
        self.assertEqual(meta['authorization_servers'],[ISSUER])
        self.assertEqual(meta['scopes_supported'],sorted(SCOPES))
        self.assertNotIn('client_secret',json.dumps(meta))

    def test_challenge_has_only_public_metadata_and_reason(self):
        for reason in ('invalid_token','insufficient_scope'):
            challenge=oauth_challenge(RESOURCE,reason)
            self.assertIn('resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource"',
                          challenge)
            self.assertIn('error="'+reason+'"',challenge)
            self.assertNotIn('Bearer secret',challenge)
        with self.assertRaises(ValueError):
            oauth_challenge(RESOURCE,'user_supplied_reason"\r\nAuthorization:')

    def test_resource_and_issuer_must_be_stable_https_origins(self):
        bad_resources=('http://mcp.example.test/mcp',
                       'https://localhost/mcp','https://127.0.0.1/mcp',
                       'https://user:pass@mcp.example.test/mcp',
                       'https://mcp.example.test/mcp?secret=1',
                       'https://mcp.example.test/mcp#foo',
                       'https://mcp.example.test/anything',
                       'https://mcp.example.test/mcp\r\nInjected: x')
        for bad in bad_resources:
            with self.subTest(resource=bad):
                with self.assertRaises(ValueError):
                    oauth_protected_resource_metadata(bad,ISSUER)
        for bad in ('http://auth.example.test','https://localhost',
                    'https://auth.example.test/tail',
                    'https://auth.example.test/?secret=1',
                    'https://user:secret@auth.example.test'):
            with self.subTest(issuer=bad):
                with self.assertRaises(ValueError):
                    oauth_protected_resource_metadata(RESOURCE,bad)

    def test_catalog_is_bounded_and_no_secret_data_created(self):
        doc=tools_list_response(14,self.contract,self.selected)
        raw=json.dumps(doc)
        self.assertLess(len(raw),128*1024)
        self.assertNotIn('Bearer ',raw)
        self.assertNotIn('client_secret',raw)
        self.assertNotIn('X-Hepta-Runtime-Token',raw)
        self.assertNotIn('token_file',raw)


if __name__=='__main__':
    unittest.main(verbosity=2)
