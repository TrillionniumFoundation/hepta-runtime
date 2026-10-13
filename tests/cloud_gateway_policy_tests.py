#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Adversarial OFFLINE public-gateway policy tests (no endpoint or agent).

The trusted test verifier is deliberately NOT an OAuth implementation. No
public traffic is accepted or production credentials created by this suite.
"""
import dataclasses
import hashlib
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
from mcp_tool_contract import ToolContract
from cloud_gateway_policy import (
    AuthenticatedAgent, AuthenticatedUser, DispatchPermit, GatewayPolicy,
    OnceOnlyLedger, Rejected, TenantBinding,
)

CONTRACT=ROOT/'deploy/contracts/hepta-runtime-full-operator-v4.json'
RESOURCE='https://gateway.example.test/mcp'
NOW=1700000000
FINGERPRINT='3'*64
ROOT_PATH='/home/customer1/workspace'


class GatewayPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-gateway-policy-')
        pathlib.Path(self.temp.name).chmod(0o700)
        self.addCleanup(self.temp.cleanup)
        self.contract=ToolContract.load(CONTRACT,hashlib.sha256(CONTRACT.read_bytes()).hexdigest())
        self.assertEqual(len(self.contract.tools),50)
        self.user=AuthenticatedUser(
            issuer='https://issuer.example.test',audience=RESOURCE,
            subject='cust-001',tenant='tenant-001',expires_at=NOW+300,
            scopes=frozenset({'hepta:connect','hepta:write','hepta:execute'}),
        )
        self.agent=AuthenticatedAgent(
            device_id='device-001',cert_sha256=FINGERPRINT,
            connection_generation=9,
            tenant='tenant-001',subject='cust-001',
            workspace_root=ROOT_PATH,
            configured_host_aliases=frozenset({'main','pocket4'}),
            native_catalog_sha256=self.contract.catalog_sha256,
            tenant_runtime_isolated=True,
        )
        self.binding=TenantBinding(
            issuer=self.user.issuer,audience=RESOURCE,subject=self.user.subject,
            tenant=self.user.tenant,device_id=self.agent.device_id,
            cert_sha256=self.agent.cert_sha256,
            connection_generation=self.agent.connection_generation,
            expires_at=NOW+1000,
            allowed_tools=frozenset({
                'host_list','file_info','directory_create','text_file_write',
                'file_move','shell_start','sudo_start',
            }),
            allowed_hosts=frozenset({'main','pocket4'}),
            local_workspace_root=ROOT_PATH,
        )
        self.ledger=OnceOnlyLedger(pathlib.Path(self.temp.name)/'ledger.sqlite3')
        self.verified_tokens=[]
        def verifier(auth):
            self.verified_tokens.append(auth)
            if auth != 'Bearer _fixture_valid_only':
                raise ValueError('invalid token fixture')
            return self.user
        self.verifier=verifier
        self.policy=self.make_policy()

    def make_policy(self, binding=None, *, resource=RESOURCE, now=NOW):
        return GatewayPolicy(
            self.contract,self.ledger,self.verifier,
            (self.binding if binding is None else binding,),
            resource=resource, now=lambda:now,
        )

    def call(self,tool,arguments=None,*,call_id='qualified-00000001',agent=None,auth=None):
        return self.policy.prepare(
            'Bearer _fixture_valid_only' if auth is None else auth,
            self.agent if agent is None else agent,tool,
            {} if arguments is None else arguments,call_id,
        )

    def assert_denied(self,code,fn):
        with self.assertRaises(Rejected) as ctx:fn()
        self.assertEqual(ctx.exception.code,code)

    def test_in_memory_catalog_annotation_drift_cannot_relabel_writes(self):
        self.user=dataclasses.replace(self.user,
            scopes=frozenset({'hepta:connect','hepta:execute'}))
        # A frozen file hash is insufficient if live Python dictionaries are
        # later changed in memory: tools and by_name share mutable instances.
        self.contract.by_name['shell_start']['annotations']['readOnlyHint']=True
        self.contract.by_name['shell_start']['annotations']['destructiveHint']=False
        self.assert_denied('CATALOG_DRIFT',
            lambda:self.policy.authorized_tool_names(
                'Bearer _fixture_valid_only',self.agent))
        self.assert_denied('CATALOG_DRIFT',
            lambda:self.call('shell_start',{
                'host':'main','cwd':ROOT_PATH+'/run','command':'printf marker'},
                call_id='changed-catalog-0001'))

    def test_separately_mutated_tool_index_cannot_change_admission(self):
        # Mutating the index without mutating source tools must also be caught.
        self.contract.by_name['directory_create']=dict(
            self.contract.by_name['directory_create'])
        self.contract.by_name['directory_create']['annotations']=dict(
            self.contract.by_name['directory_create']['annotations'])
        self.contract.by_name['directory_create']['annotations']['readOnlyHint']=True
        self.assert_denied('CATALOG_DRIFT',
            lambda:self.policy.authorized_tool_names(
                'Bearer _fixture_valid_only',self.agent))
        self.assert_denied('CATALOG_DRIFT',
            lambda:self.call('directory_create',{'path':ROOT_PATH+'/new'},
                call_id='index-drift-00001'))

    def test_real_v4_contract_exactly_50_without_relabelled_writes(self):
        self.assertEqual(len(self.contract.tools),50)
        self.assertEqual(sum(not t['annotations']['readOnlyHint'] for t in self.contract.tools),31)
        self.assertFalse(self.contract.read_only('text_file_write'))
        self.assertFalse(self.contract.read_only('shell_start'))
        self.assertTrue(self.contract.read_only('host_list'))

    def test_read_only_listing_does_not_reserve_a_write(self):
        one=self.call('host_list',call_id='read-only-00001')
        two=self.call('host_list',call_id='read-only-00001')
        self.assertFalse(one.mutating)
        self.assertEqual(one,two)
        self.assertIsNone(self.ledger.state(one))

    def test_explicit_mutation_reserves_only_digest_and_internal_ids(self):
        args={'mode':'create','path':ROOT_PATH+'/new.txt',
              'content':'hello unicode 中文','expected_sha256':'absent'}
        permit=self.call('text_file_write',args,call_id='written-00000001')
        self.assertTrue(permit.mutating)
        self.assertEqual(len(permit.request_sha256),64)
        self.assertEqual(self.ledger.state(permit),'reserved')
        self.policy.mark_delivered(permit,confirmed=True)
        self.assertEqual(self.ledger.state(permit),'completed')
        self.assert_denied('RECONCILE_PRIOR_CALL',
            lambda:self.call('text_file_write',args,call_id='written-00000001'))
        raw=(pathlib.Path(self.temp.name)/'ledger.sqlite3').read_bytes()
        for sensitive in (b'hello unicode',b'new.txt',b'cust-001',b'tenant-001',b'_fixture_valid_only'):
            self.assertNotIn(sensitive,raw)

    def test_unknown_network_outcome_is_not_automatically_replayed(self):
        args={'mode':'create','path':ROOT_PATH+'/new.txt',
              'content':'once only','expected_sha256':'absent'}
        permit=self.call('text_file_write',args,call_id='uncertain-0000001')
        self.policy.mark_delivered(permit,confirmed=False)
        self.assertEqual(self.ledger.state(permit),'unknown')
        self.assert_denied('RECONCILE_PRIOR_CALL',
            lambda:self.call('text_file_write',args,call_id='uncertain-0000001'))

    def test_crash_between_reservation_and_delivery_still_blocks_replay(self):
        args={'mode':'create','path':ROOT_PATH+'/new.txt',
              'content':'crash once','expected_sha256':'absent'}
        permit=self.call('text_file_write',args,call_id='crash-000000001')
        fresh=OnceOnlyLedger(pathlib.Path(self.temp.name)/'ledger.sqlite3')
        self.assertEqual(fresh.state(permit),'reserved')
        different_gateway=GatewayPolicy(self.contract,fresh,self.verifier,
                                         (self.binding,),resource=RESOURCE,now=lambda:NOW)
        self.assert_denied('RECONCILE_PRIOR_CALL',
            lambda:different_gateway.prepare('Bearer _fixture_valid_only',
                self.agent,'text_file_write',args,'crash-000000001'))

    def test_no_duplicate_tool_writes_even_under_race(self):
        args={'mode':'create','path':ROOT_PATH+'/concurrent.txt',
              'content':'one','expected_sha256':'absent'}
        successes=[];failures=[]
        def attempt(_):
            try:
                permit=self.call('text_file_write',args,call_id='concurrent-00001')
                successes.append(permit)
            except Rejected as exc:
                failures.append(exc.code)
        with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(attempt,range(16)))
        self.assertEqual(len(successes),1)
        self.assertEqual(failures,['RECONCILE_PRIOR_CALL']*15)

    def test_native_agent_reconnect_cannot_resubmit_uncertain_write(self):
        args={'mode':'create','path':ROOT_PATH+'/once-on-reconnect.txt',
              'content':'first','expected_sha256':'absent'}
        before=self.call('text_file_write',args,call_id='same-after-reconn')
        self.assertEqual(self.ledger.state(before),'reserved')
        rotated_agent=dataclasses.replace(self.agent,connection_generation=10)
        rotated_binding=dataclasses.replace(self.binding,connection_generation=10)
        self.policy=self.make_policy(rotated_binding)
        self.assert_denied('RECONCILE_PRIOR_CALL',
            lambda:self.call('text_file_write',args,call_id='same-after-reconn',
                             agent=rotated_agent))
        self.assertEqual(self.ledger.state(before),'reserved')

    def test_independent_gateway_workers_share_durable_unique_reservation(self):
        path=pathlib.Path(self.temp.name)/'ledger.sqlite3'
        args={'mode':'create','path':ROOT_PATH+'/cross-worker.txt',
              'content':'once across workers','expected_sha256':'absent'}
        workers=[GatewayPolicy(self.contract,OnceOnlyLedger(path),self.verifier,
                               (self.binding,),resource=RESOURCE,
                               now=lambda:NOW) for _ in range(8)]
        sync=threading.Barrier(8)
        def attempt(policy):
            sync.wait(timeout=5)
            try:
                policy.prepare('Bearer _fixture_valid_only',self.agent,
                    'text_file_write',args,'cross-worker-0001')
                return 'reserved'
            except Rejected as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcome=list(pool.map(attempt,workers))
        self.assertEqual(outcome.count('reserved'),1)
        self.assertEqual(outcome.count('RECONCILE_PRIOR_CALL'),7)

    def test_changed_payload_same_operation_id_is_also_denied(self):
        self.call('directory_create',{'path':ROOT_PATH+'/one'},
                  call_id='one-request-00001')
        self.assert_denied('RECONCILE_PRIOR_CALL',lambda:
            self.call('directory_create',{'path':ROOT_PATH+'/two'},
                      call_id='one-request-00001'))

    def test_two_authorized_tenants_isolate_same_call_id_device_and_paths(self):
        second_user=AuthenticatedUser(
            issuer=self.user.issuer,audience=RESOURCE,
            subject='cust-002',tenant='tenant-002',expires_at=NOW+300,
            scopes=frozenset({'hepta:connect','hepta:write'}),
        )
        second_agent=AuthenticatedAgent(
            device_id='device-002',cert_sha256='a'*64,
            connection_generation=3,tenant='tenant-002',subject='cust-002',
            workspace_root='/home/customer2/workspace',
            configured_host_aliases=frozenset({'isolated-host'}),
            native_catalog_sha256=self.contract.catalog_sha256,
            tenant_runtime_isolated=True,
        )
        second_binding=TenantBinding(
            issuer=second_user.issuer,audience=RESOURCE,
            subject=second_user.subject,tenant=second_user.tenant,
            device_id=second_agent.device_id,cert_sha256=second_agent.cert_sha256,
            connection_generation=second_agent.connection_generation,
            expires_at=NOW+1000,allowed_tools=frozenset({'directory_create','host_list'}),
            allowed_hosts=frozenset({'isolated-host'}),
            local_workspace_root=second_agent.workspace_root,
        )
        def verify(auth):
            if auth=='Bearer fixture-alice':return self.user
            if auth=='Bearer fixture-bob':return second_user
            raise ValueError('invalid test token')
        gateway=GatewayPolicy(
            self.contract,self.ledger,verify,(self.binding,second_binding),
            resource=RESOURCE,now=lambda:NOW)
        request_id='shared-request-00001'
        alice=gateway.prepare('Bearer fixture-alice',self.agent,
            'directory_create',{'path':ROOT_PATH+'/alice'},request_id)
        bob=gateway.prepare('Bearer fixture-bob',second_agent,
            'directory_create',{'path':'/home/customer2/workspace/bob'},request_id)
        self.assertNotEqual(alice.tenant,bob.tenant)
        self.assertEqual(self.ledger.state(alice),'reserved')
        self.assertEqual(self.ledger.state(bob),'reserved')
        with self.assertRaises(Rejected) as error:
            gateway.prepare('Bearer fixture-alice',second_agent,'host_list',{},
                'cross-tenant-0001')
        self.assertEqual(error.exception.code,'TENANT_DEVICE_NOT_AUTHORIZED')
        with self.assertRaises(Rejected) as error:
            gateway.prepare('Bearer fixture-bob',second_agent,'directory_create',
                {'path':ROOT_PATH+'/stolen'},'cross-path-000001')
        self.assertEqual(error.exception.code,'PATH_OUTSIDE_TENANT_WORKSPACE')
        self.assertEqual(self.ledger.state(alice),'reserved')
        self.assertEqual(self.ledger.state(bob),'reserved')

    def test_mismatched_tenant_subject_and_issuer_fail_closed(self):
        for change in ({'tenant':'tenant-evil'},{'subject':'cust-evil'},
                       {'issuer':'https://evil.example.test'}):
            original=self.user
            self.user=dataclasses.replace(original,**change)
            try:
                self.assert_denied('TENANT_DEVICE_NOT_AUTHORIZED',
                    lambda:self.call('host_list'))
            finally:
                self.user=original

    def test_bad_oauth_bearer_audience_expiry_scope_denied(self):
        self.assert_denied('OAUTH_REQUIRED',
            lambda:self.call('host_list',auth='token without bearer prefix'))
        self.assert_denied('OAUTH_INVALID',
            lambda:self.call('host_list',auth='Bearer invalid-signature'))
        for change in ({'audience':'https://other.example.test/mcp'},
                       {'expires_at':NOW-1},{'scopes':frozenset()}):
            old=self.user
            self.user=dataclasses.replace(old,**change)
            try:
                self.assert_denied('OAUTH_INVALID',lambda:self.call('host_list'))
            finally:self.user=old

    def test_verified_user_scope_claim_must_be_frozenset_of_strings(self):
        original=self.user
        invalid=[
            'hepta:connect hepta:write hepta:execute hepta:privileged',
            ['hepta:connect','hepta:write'],
            {'hepta:connect':True},
            123,
            None,
            frozenset({'hepta:connect',23}),
        ]
        for scopes in invalid:
            with self.subTest(scopes=scopes):
                self.user=dataclasses.replace(original,scopes=scopes)
                self.assert_denied('OAUTH_INVALID',
                    lambda:self.policy.authorized_tool_names(
                        'Bearer _fixture_valid_only',self.agent))
        self.user=original
        self.assertIn('host_list',self.policy.authorized_tool_names(
            'Bearer _fixture_valid_only',self.agent))

    def test_untyped_verifier_expiry_and_agent_generation_fail_closed(self):
        original=self.user
        for bad in ('soon',float(NOW+100),None,True):
            with self.subTest(expiry=bad):
                self.user=dataclasses.replace(original,expires_at=bad)
                self.assert_denied('OAUTH_INVALID',
                    lambda:self.policy.authorized_tool_names(
                        'Bearer _fixture_valid_only',self.agent))
        self.user=original
        for generation in ('9',None,True):
            with self.subTest(generation=generation):
                agent=dataclasses.replace(self.agent,connection_generation=generation)
                self.assert_denied('AGENT_IDENTITY_INVALID',
                    lambda:self.policy.authorized_tool_names(
                        'Bearer _fixture_valid_only',agent))

    def test_revoked_or_expired_device_and_certificate_rotation_denied(self):
        revoked=dataclasses.replace(self.binding,revoked=True)
        self.policy=self.make_policy(revoked)
        self.assert_denied('TENANT_DEVICE_NOT_AUTHORIZED',lambda:self.call('host_list'))
        expired=dataclasses.replace(self.binding,expires_at=NOW-1)
        self.policy=self.make_policy(expired)
        self.assert_denied('TENANT_DEVICE_NOT_AUTHORIZED',lambda:self.call('host_list'))
        self.policy=self.make_policy()
        wrong=dataclasses.replace(self.agent,cert_sha256='a'*64)
        self.assert_denied('TENANT_DEVICE_NOT_AUTHORIZED',
            lambda:self.call('host_list',agent=wrong))
        wrong=dataclasses.replace(self.agent,connection_generation=8)
        self.assert_denied('TENANT_DEVICE_NOT_AUTHORIZED',
            lambda:self.call('host_list',agent=wrong))

    def test_agent_must_attest_exact_tenant_workspace_and_native_catalog(self):
        for change in (
            {'tenant':'tenant-other'},
            {'subject':'subject-other'},
            {'workspace_root':'/'},
            {'workspace_root':'/home/other/tenant'},
            {'configured_host_aliases':frozenset({'main','pocket4','rog'})},
            {'configured_host_aliases':frozenset({'main'})},
            {'native_catalog_sha256':'a'*64},
            {'tenant_runtime_isolated':False},
        ):
            with self.subTest(changed=change):
                self.assert_denied('AGENT_CONFIG_MISMATCH',
                    lambda:self.call('host_list',agent=dataclasses.replace(self.agent,**change)))

    def test_gateway_requires_reviewed_v4_catalog_not_silent_upgrade(self):
        from mcp_tool_contract import make_contract
        mutated=json.loads(json.dumps(json.loads(CONTRACT.read_text())['tools']))
        mutated[0]['description']+=' unreviewed schema change'
        with self.assertRaises(ValueError):
            GatewayPolicy(ToolContract(make_contract(mutated)),self.ledger,
                          self.verifier,(self.binding,),resource=RESOURCE,now=lambda:NOW)

    def test_unreviewed_tool_and_not_granted_tool_denied(self):
        self.assert_denied('TOOL_UNKNOWN',lambda:self.call('unreviewed_foo'))
        self.assert_denied('TOOL_NOT_GRANTED',lambda:self.call('privileged_action'))
        self.assert_denied('TOOL_NOT_GRANTED',lambda:self.call('document_write',{}))

    def test_host_alias_and_implicit_device_spoof_denied(self):
        self.assert_denied('HOST_NOT_ENROLLED',
            lambda:self.call('file_info',{'host':'rog','path':ROOT_PATH+'/test.txt'}))
        self.assert_denied('INVALID_ARGUMENTS',
            lambda:self.call('host_list',{'tenant':'tenant-evil'}))
        self.assert_denied('INVALID_ARGUMENTS',
            lambda:self.call('host_list',{'device_id':'device-evil'}))
        safe=self.call('file_info',{'host':'main','path':ROOT_PATH+'/f'})
        self.assertFalse(safe.mutating)

    def test_controller_path_traversal_and_remote_url_denied(self):
        invalid_paths=['/etc/passwd',ROOT_PATH+'-other/file',ROOT_PATH+'/../outside',
                       ROOT_PATH+'//double',ROOT_PATH+'/./dot',ROOT_PATH+'\\backslash',
                       'relative/path','ssh://rog/tmp/outside','sftp://rog/tmp',
                       '',123]
        for path in invalid_paths:
            with self.subTest(path=path):
                self.assert_denied('PATH_OUTSIDE_TENANT_WORKSPACE',
                    lambda:self.call('directory_create',{'path':path},
                                     call_id='path-test-0000001'))
        permit=self.call('directory_create',{'path':ROOT_PATH+'/new'},
                         call_id='path-test-0000001')
        self.assertTrue(permit.mutating)

    def test_shell_cwd_must_be_explicit_and_inside_tenant_root(self):
        base={'host':'main','command':'printf harmless'}
        for bad in (None,'/etc','/tmp',ROOT_PATH+'/../outside',
                    'ssh://other/root',ROOT_PATH+'-other/work','relative',123):
            with self.subTest(cwd=bad):
                params={**base}
                if bad is not None:params['cwd']=bad
                self.assert_denied('PATH_OUTSIDE_TENANT_WORKSPACE',
                    lambda:self.call('shell_start',params,
                                     call_id='cwd-negative-0001'))
        good=self.call('shell_start',{**base,'cwd':ROOT_PATH+'/run'},
                       call_id='cwd-positive-0001')
        self.assertTrue(good.mutating)

    def test_other_execution_cwd_paths_are_bounded_before_reservation(self):
        elevated=dataclasses.replace(self.binding,
            allowed_tools=self.binding.allowed_tools|{'process_start','pty_start'},
            elevated_tools=frozenset({'sudo_start'}))
        self.policy=self.make_policy(elevated)
        self.user=dataclasses.replace(self.user,
            scopes=self.user.scopes|{'hepta:privileged'})
        for name in ('process_start','pty_start','sudo_start'):
            baseline={'host':'main','executable':'/usr/bin/id','args':['-u']}
            for bad in (None,'/root','/tmp','relative',ROOT_PATH+'/../../etc'):
                with self.subTest(tool=name,cwd=bad):
                    params={**baseline}
                    if bad is not None:params['cwd']=bad
                    self.assert_denied('PATH_OUTSIDE_TENANT_WORKSPACE',
                        lambda:self.call(name,params,call_id='othercwd-negative-1'))
            self.assert_denied('HOST_NOT_ENROLLED',
                lambda:self.call(name,{'executable':'/usr/bin/id',
                    'cwd':ROOT_PATH+'/run'},call_id='missing-host-00001'))
            self.assertTrue(self.call(name,{**baseline,'cwd':ROOT_PATH+'/run'},
                    call_id='valid-'+name+'-0001').mutating)

    def test_generated_document_and_pdf_secondary_paths_cannot_escape(self):
        enabled=dataclasses.replace(self.binding,
            allowed_tools=self.binding.allowed_tools|{
                'pdf_edit','pdf_security','document_render'})
        self.policy=self.make_policy(enabled)
        paths={
            'pdf_edit':[
                {'path':ROOT_PATH+'/input.pdf','output_path':'/etc/output.pdf'},
                {'path':ROOT_PATH+'/input.pdf','output_path':ROOT_PATH+'/result.pdf',
                 'operations':[{'type':'insert','page_index':0,'source_path':'/etc/passwd'}]},
            ],
            'pdf_security':[
                {'path':ROOT_PATH+'/input.pdf','password_file':'/etc/secret'},
                {'path':ROOT_PATH+'/input.pdf','output_path':'/tmp/leak.pdf'},
                {'path':ROOT_PATH+'/input.pdf','output_owner_password_file':'/tmp/pw'},
                {'path':ROOT_PATH+'/input.pdf','trust_store_file':'/etc/ssl/certs/ca-certificates.crt'},
            ],
            'document_render':[
                {'path':ROOT_PATH+'/result.pdf','assets':[
                    {'name':'image','path':'/etc/shadow','sha256':'0'*64}]},
            ],
        }
        for tool,cases in paths.items():
            for args in cases:
                with self.subTest(tool=tool,args=args):
                    self.assert_denied('PATH_OUTSIDE_TENANT_WORKSPACE',
                        lambda:self.call(tool,args,call_id='second-path-neg-01'))
        for tool,args in [
            ('pdf_edit',{'path':ROOT_PATH+'/input.pdf','output_path':ROOT_PATH+'/result.pdf',
                         'operations':[{'type':'insert','page_index':0,
                                        'source_path':ROOT_PATH+'/asset.pdf'}]}),
            ('document_render',{'path':ROOT_PATH+'/result.pdf',
                 'assets':[{'name':'image','path':ROOT_PATH+'/img.png','sha256':'0'*64}]}),
        ]:
            self.assertTrue(self.call(tool,args,
                call_id='secondary-'+tool+'-0001').mutating)

    def test_invalid_nested_shape_fails_without_reserving_tool_write(self):
        enabled=dataclasses.replace(self.binding,
            allowed_tools=self.binding.allowed_tools|{'pdf_edit','document_render'})
        self.policy=self.make_policy(enabled)
        for tool,key in [('pdf_edit','operations'),('document_render','assets')]:
            for bad in ('not-an-array',[None],['string']):
                with self.subTest(tool=tool,bad=bad):
                    self.assert_denied('INVALID_ARGUMENTS',
                        lambda:self.call(tool,{'path':ROOT_PATH+'/f.pdf',key:bad},
                                         call_id='nested-shape-test-1'))

    def test_privileged_tool_requires_both_grant_and_scope(self):
        self.assert_denied('ELEVATED_ACTION_NOT_GRANTED',
            lambda:self.call('sudo_start',{'host':'main','executable':'/usr/bin/id'}))
        binding=dataclasses.replace(self.binding,elevated_tools=frozenset({'sudo_start'}))
        self.policy=self.make_policy(binding)
        self.assert_denied('ELEVATED_ACTION_NOT_GRANTED',
            lambda:self.call('sudo_start',{'host':'main','executable':'/usr/bin/id'}))
        self.user=dataclasses.replace(self.user,scopes=self.user.scopes|{'hepta:privileged'})
        p=self.call('sudo_start',{'host':'main','executable':'/usr/bin/id','cwd':ROOT_PATH+'/run'},
                    call_id='sudo-fixture-0001')
        self.assertTrue(p.mutating)

    def test_shell_needs_execution_scope_and_explicit_host(self):
        self.user=dataclasses.replace(self.user,scopes=frozenset({'hepta:connect','hepta:write'}))
        self.assert_denied('EXECUTE_SCOPE_REQUIRED',
            lambda:self.call('shell_start',{'host':'main','command':'echo test'}))
        self.user=dataclasses.replace(self.user,scopes=self.user.scopes|{'hepta:execute'})
        self.assert_denied('HOST_NOT_ENROLLED',
            lambda:self.call('shell_start',{'host':'other','command':'echo test'}))
        p=self.call('shell_start',{'host':'main','command':'echo test','cwd':ROOT_PATH+'/run'},
                    call_id='shell-fixture-00001')
        self.assertTrue(p.mutating)

    def test_write_needs_independent_scope(self):
        self.user=dataclasses.replace(self.user,scopes=frozenset({'hepta:connect','hepta:execute'}))
        self.assert_denied('WRITE_SCOPE_REQUIRED',
            lambda:self.call('directory_create',{'path':ROOT_PATH+'/x'}))

    def test_unknown_schema_argument_does_not_become_auth_metadata(self):
        self.assert_denied('INVALID_ARGUMENTS',
            lambda:self.call('directory_create',{'path':ROOT_PATH+'/x',
                         '_meta':{'tenant':'tenant-evil'}}))
        self.assert_denied('INVALID_ARGUMENTS',
            lambda:self.call('directory_create',{'path':ROOT_PATH+'/x','other':[]}))
        self.assert_denied('INVALID_ARGUMENTS',
            lambda:self.call('directory_create',{'path':ROOT_PATH+'/x','content':set()}))

    def test_oversized_untrusted_arguments_are_bounded(self):
        self.assert_denied('INVALID_ARGUMENTS',
            lambda:self.call('directory_create',{'path':ROOT_PATH+'/'+('x'*(4*1024*1024+5))}))

    def test_enrollment_rejects_global_root_unknown_tools_and_wildcards(self):
        for change in ({'local_workspace_root':'/'},{'local_workspace_root':'/tmp/../etc'},
                       {'allowed_tools':frozenset({'tool-not-in-v4'})},
                       {'tenant':'*'},
                       {'allowed_hosts':frozenset({'*'})},
                       {'cert_sha256':'bogus'},
                       {'connection_generation':True},
                       {'connection_generation':'9'},
                       {'expires_at':1700000500.0}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    self.make_policy(dataclasses.replace(self.binding,**change))

    def test_duplicate_device_enrollments_fail_even_if_permissions_differ(self):
        with self.assertRaises(ValueError):
            GatewayPolicy(self.contract,self.ledger,self.verifier,
                          (self.binding,self.binding),resource=RESOURCE,now=lambda:NOW)

    def test_enrolled_allowlists_are_immutable_exact_frozensets(self):
        for name in ('allowed_tools','allowed_hosts','elevated_tools'):
            old=getattr(self.binding,name)
            mutable=set(old)
            with self.subTest(allowlist=name):
                with self.assertRaises(ValueError):
                    self.make_policy(dataclasses.replace(self.binding,**{name:mutable}))
                # Construction must never retain a mutable object that can be
                # extended to publish a new tool/host after admin enrollment.
                mutable.add('unexpected-added-after-creation')
                self.assertNotIn('unexpected-added-after-creation',old)
        for name in ('allowed_tools','allowed_hosts','elevated_tools'):
            with self.subTest(malformed_allowlist=name):
                with self.assertRaises(ValueError):
                    self.make_policy(dataclasses.replace(self.binding,**{name:'host_list'}))

    def test_verified_agent_host_manifest_must_be_immutable_and_exact(self):
        for bad in (set(self.agent.configured_host_aliases),
                    list(self.agent.configured_host_aliases),
                    'main,pocket4'):
            with self.subTest(host_aliases=bad):
                agent=dataclasses.replace(self.agent,configured_host_aliases=bad)
                self.assert_denied('AGENT_IDENTITY_INVALID',
                    lambda:self.policy.authorized_tool_names(
                        'Bearer _fixture_valid_only',agent))
        self.assertIn('host_list',self.policy.authorized_tool_names(
            'Bearer _fixture_valid_only',self.agent))

    def test_ledger_private_and_symlink_fail_closed(self):
        path=pathlib.Path(self.temp.name)/'ledger.sqlite3'
        self.assertEqual(path.stat().st_mode & 0o077,0)
        other=pathlib.Path(self.temp.name)/'ref'
        other.symlink_to(path)
        with self.assertRaises(PermissionError):
            OnceOnlyLedger(other)
        path.chmod(0o644)
        with self.assertRaises(PermissionError):
            OnceOnlyLedger(path)

    def test_explicit_https_resource_required(self):
        for url in ('http://gateway.example.test/mcp','https://localhost/mcp',
                    'https://gateway.example.test/tool','https://gateway.example.test/mcp?x=y',
                    'https://user:pass@gateway.example.test/mcp'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    self.make_policy(resource=url)

    def test_tool_results_are_not_saved_in_sqlite(self):
        permit=self.call('directory_create',{'path':ROOT_PATH+'/scratch'},
                         call_id='no-results-00001')
        self.policy.mark_delivered(permit,confirmed=True)
        raw=(pathlib.Path(self.temp.name)/'ledger.sqlite3').read_bytes()
        self.assertNotIn(b'scratch',raw)
        self.assertNotIn(b'Bearer',raw)

    def test_repeated_finalization_is_rejected(self):
        permit=self.call('directory_create',{'path':ROOT_PATH+'/scratch'},
                         call_id='finalize-0000001')
        self.policy.mark_delivered(permit,confirmed=False)
        self.assert_denied('RECONCILE_PRIOR_CALL',
            lambda:self.policy.mark_delivered(permit,confirmed=True))


if __name__=='__main__':
    unittest.main(verbosity=2)
