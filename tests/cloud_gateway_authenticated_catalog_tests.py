#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline per-identity MCP discovery acceptance, with fake OAuth/mTLS origins.

This tests only the caller-specific policy API. It does not implement, emulate,
or certify production OAuth, signed agent certificates or an HTTP listener.
"""
import dataclasses
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
from mcp_tool_contract import ToolContract, canonical
from cloud_gateway_policy import (
    AuthenticatedAgent, AuthenticatedUser, GatewayPolicy, OnceOnlyLedger,
    Rejected, TenantBinding,
)
from cloud_gateway_mcp_catalog import (
    VERSION, authenticated_discover_response, authenticated_tools_list_response,
)

CATALOG=ROOT/'deploy/contracts/hepta-runtime-full-operator-v4.json'
RESOURCE='https://gateway.example.test/mcp'
NOW=1700000000
ALLOWED=frozenset({
    'host_list','directory_create','text_file_write','shell_start',
    'sudo_start','privileged_action','process_checkpoint',
})
SCOPE_CONNECT=frozenset({'hepta:connect'})
SCOPE_WRITE=SCOPE_CONNECT|{'hepta:write'}
SCOPE_EXEC=SCOPE_WRITE|{'hepta:execute'}
SCOPE_PRIV=SCOPE_EXEC|{'hepta:privileged'}


class IdentitySpecificDiscovery(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-gateway-auth-catalog-')
        self.addCleanup(self.temp.cleanup)
        pathlib.Path(self.temp.name).chmod(0o700)
        self.contract=ToolContract.load(
            CATALOG,hashlib.sha256(CATALOG.read_bytes()).hexdigest())
        self.users={}
        self.agents={}
        self.bindings=[]
        self.add_user('alice','tenant-one','device-one',SCOPES=SCOPE_PRIV,
                      allowed=ALLOWED,elevated={'sudo_start'})
        self.add_user('bob','tenant-two','device-two',SCOPES=SCOPE_CONNECT,
                      allowed=frozenset({'host_list','directory_create'}))
        self.ledger=OnceOnlyLedger(pathlib.Path(self.temp.name)/'requests.sqlite3')
        self.refresh_policy()

    def add_user(self,name,tenant,device,*,SCOPES,allowed,elevated=frozenset()):
        subject='subject-'+name
        usr=AuthenticatedUser(issuer='https://auth.example.test',
            audience=RESOURCE,subject=subject,tenant=tenant,
            expires_at=NOW+500,scopes=frozenset(SCOPES))
        agent=AuthenticatedAgent(device_id=device,cert_sha256='1'*64,
            connection_generation=5,tenant=tenant,subject=subject,
            workspace_root='/srv/tenants/'+tenant+'/workspace',
            configured_host_aliases=frozenset({'main'}),
            native_catalog_sha256=self.contract.catalog_sha256,
            tenant_runtime_isolated=True)
        enrollment=TenantBinding(issuer=usr.issuer,audience=RESOURCE,
            subject=usr.subject,tenant=usr.tenant,device_id=device,
            cert_sha256=agent.cert_sha256,connection_generation=5,
            expires_at=NOW+2000,allowed_tools=frozenset(allowed),
            allowed_hosts=frozenset({'main'}),
            local_workspace_root=agent.workspace_root,
            elevated_tools=frozenset(elevated))
        self.users[name]=usr
        self.agents[name]=agent
        self.bindings.append(enrollment)

    def refresh_policy(self):
        def verifier(header):
            if not isinstance(header,str) or not header.startswith('Bearer fixture-'):
                raise ValueError('token fixture does not match')
            name=header.removeprefix('Bearer fixture-')
            try:return self.users[name]
            except KeyError as exc:raise ValueError('unknown fixture bearer') from exc
        self.policy=GatewayPolicy(self.contract,self.ledger,verifier,
            tuple(self.bindings),now=lambda:NOW,resource=RESOURCE)

    def listing(self,name,agent=None):
        return authenticated_tools_list_response(
            'list-12345678',self.policy,'Bearer fixture-'+name,
            self.agents[name] if agent is None else agent)

    def discovery(self,name,agent=None):
        return authenticated_discover_response(
            'discover-123',self.policy,'Bearer fixture-'+name,
            self.agents[name] if agent is None else agent)

    def names(self,response):
        result=response['result']
        self.assertEqual(result['resultType'],'complete')
        self.assertEqual(result['cacheScope'],'private')
        self.assertEqual(result['ttlMs'],0)
        return {tool['name'] for tool in result['tools']}

    def test_per_subject_scope_filters_are_precise_and_independent(self):
        self.assertEqual(self.names(self.listing('alice')),
            {'host_list','directory_create','text_file_write','shell_start','sudo_start'})
        self.assertEqual(self.names(self.listing('bob')),{'host_list'})
        for scopes,expected in [
            (SCOPE_EXEC,{'host_list','directory_create','text_file_write','shell_start'}),
            (SCOPE_WRITE,{'host_list','directory_create','text_file_write'}),
            (SCOPE_CONNECT,{'host_list'}),
        ]:
            self.users['alice']=dataclasses.replace(self.users['alice'],scopes=scopes)
            self.assertEqual(self.names(self.listing('alice')),expected)
        self.assertEqual(self.names(self.listing('bob')),{'host_list'})

    def test_no_tenant_confusion_or_anonymous_listing(self):
        with self.assertRaises(Rejected):
            self.listing('alice',self.agents['bob'])
        with self.assertRaises(Rejected):
            self.discovery('bob',self.agents['alice'])
        for fake in (None,'','Bearer invalid','Bearer fixture-nobody'):
            with self.subTest(bearer=fake):
                with self.assertRaises(Rejected):
                    authenticated_tools_list_response(
                        1,self.policy,fake,self.agents['alice'])

    def test_discover_and_tool_list_require_same_approved_binding(self):
        discovered=self.discovery('alice')
        self.assertEqual(discovered['result']['supportedVersions'],[VERSION])
        self.assertEqual(discovered['result']['capabilities']['tools'],
                         {'listChanged':False})
        self.assertEqual(discovered['result']['cacheScope'],'private')
        revoked=dataclasses.replace(self.bindings[0],revoked=True)
        self.bindings[0]=revoked
        self.refresh_policy()
        with self.assertRaises(Rejected):self.discovery('alice')
        with self.assertRaises(Rejected):self.listing('alice')
        self.assertEqual(self.names(self.listing('bob')),{'host_list'})

    def test_wrong_device_certificate_generation_and_catalog_do_not_list(self):
        agent=self.agents['alice']
        for change in ({'cert_sha256':'2'*64},
                       {'connection_generation':6},
                       {'native_catalog_sha256':'0'*64},
                       {'workspace_root':'/srv/tenants/tenant-two/workspace'},
                       {'tenant_runtime_isolated':False},
                       {'configured_host_aliases':frozenset({'main','rog'})}):
            with self.subTest(change=change):
                with self.assertRaises(Rejected):
                    self.listing('alice',dataclasses.replace(agent,**change))

    def test_no_privileged_name_without_enrollment_and_exact_scope(self):
        self.assertNotIn('privileged_action',self.names(self.listing('alice')))
        self.assertNotIn('process_checkpoint',self.names(self.listing('alice')))
        self.users['alice']=dataclasses.replace(self.users['alice'],scopes=SCOPE_EXEC)
        self.assertNotIn('sudo_start',self.names(self.listing('alice')))
        self.users['alice']=dataclasses.replace(self.users['alice'],scopes=SCOPE_PRIV)
        self.bindings[0]=dataclasses.replace(self.bindings[0],elevated_tools=frozenset())
        self.refresh_policy()
        self.assertNotIn('sudo_start',self.names(self.listing('alice')))

    def test_tool_projection_does_not_change_native_contract_schema(self):
        before=hashlib.sha256(canonical(self.contract.tools)).hexdigest()
        tools=self.listing('alice')['result']['tools']
        for published in tools:
            self.assertEqual(published['securitySchemes'],[{
                'type':'oauth2','scopes':sorted(published['securitySchemes'][0]['scopes'])
            }])
            other=dict(published)
            del other['securitySchemes']
            self.assertEqual(other,self.contract.by_name[published['name']])
        self.assertEqual(hashlib.sha256(canonical(self.contract.tools)).hexdigest(),before)
        self.assertEqual(len(self.contract.tools),50)

    def test_empty_enrolled_tool_selection_still_authenticated(self):
        self.bindings[1]=dataclasses.replace(self.bindings[1],allowed_tools=frozenset())
        self.refresh_policy()
        self.assertEqual(self.names(self.listing('bob')),set())
        self.assertEqual(self.discovery('bob')['result']['supportedVersions'],[VERSION])
        with self.assertRaises(Rejected):
            self.listing('alice',self.agents['bob'])


if __name__=='__main__':
    unittest.main(verbosity=2)
