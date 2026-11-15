#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real RS256 signatures against pinned offline JWKS: no real user tokens.

All keys are test-generated and discarded. No remote keys, OAuth service,
production agent or public listener is used. Model callers cannot supply a
verifier identity; only the verified JWT may be mapped into GatewayPolicy.
"""
import dataclasses
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
from cloud_gateway_jwt_verifier import InvalidAccessToken, VerifiedJwtAccessTokens
from cloud_gateway_policy import (
    AuthenticatedAgent, GatewayPolicy, OnceOnlyLedger, Rejected, TenantBinding,
)
from mcp_tool_contract import ToolContract

ISSUER='https://auth.example.test'
RESOURCE='https://gateway.example.test/mcp'
CLIENT='hepta-chatgpt-v1'
SCOPES='hepta:connect hepta:write hepta:execute'
CONTRACT=ROOT/'deploy/contracts/hepta-runtime-full-operator-v4.json'


class RealSignatureVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.now=int(time.time())

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-jwt-verifier-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name)
        self.root.chmod(0o700)
        self.jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwk.update({'kid':'test-key-1','use':'sig','alg':'RS256'})
        self.revoked=set()
        self.revocation_result=None
        self.revocation_calls=[]
        self.trust_file=self.root/'issuer-public-jwks.json'
        self.set_keys([self.jwk])
        self.verifier=self.make_verifier()

    def set_keys(self, keys):
        raw=json.dumps({'keys':keys},sort_keys=True).encode()
        self.trust_file.write_bytes(raw)
        self.trust_file.chmod(0o600)
        self.digest=hashlib.sha256(raw).hexdigest()

    def revocation(self, issuer, client, subject, tenant, jti):
        self.revocation_calls.append((issuer,client,subject,tenant,jti))
        if self.revocation_result is not None:
            return self.revocation_result
        return jti in self.revoked

    def make_verifier(self,**overrides):
        args={'issuer':ISSUER,'audience':RESOURCE,
              'allowed_clients':frozenset({CLIENT}),
              'jwks_file':self.trust_file,
              'expected_jwks_sha256':self.digest,
              'is_revoked_or_disallowed':self.revocation}
        args.update(overrides)
        return VerifiedJwtAccessTokens(**args)

    def claims(self,**overrides):
        values={'iss':ISSUER,'sub':'subject-alice','aud':RESOURCE,
                'client_id':CLIENT,'tenant':'tenant-one',
                'scope':SCOPES,'iat':self.now,'exp':self.now+300,
                'jti':'jwt-test-1234567890'}
        values.update(overrides)
        return values

    def token(self,claims=None,*,key=None,headers=None,algorithm='RS256'):
        hdr={'typ':'at+jwt','kid':'test-key-1'}
        if headers:hdr.update(headers)
        return jwt.encode(self.claims() if claims is None else claims,
                          self.key if key is None else key,
                          algorithm=algorithm,headers=hdr)

    def accept(self,token):
        return self.verifier('Bearer '+token)

    def assert_bad(self, token):
        with self.assertRaises(InvalidAccessToken) as cm:
            self.accept(token)
        self.assertEqual(str(cm.exception),'invalid OAuth access token')

    def test_real_rsa_signature_and_exact_scope_projection(self):
        subject=self.accept(self.token())
        self.assertEqual(subject.issuer,ISSUER)
        self.assertEqual(subject.audience,RESOURCE)
        self.assertEqual(subject.subject,'subject-alice')
        self.assertEqual(subject.tenant,'tenant-one')
        self.assertEqual(subject.scopes,frozenset(SCOPES.split(' ')))
        self.assertEqual(self.revocation_calls[-1][-1],'jwt-test-1234567890')

    def test_wrong_signer_with_same_key_id_is_denied(self):
        self.assert_bad(self.token(key=self.other))
        self.assertEqual(self.revocation_calls,[])

    def test_id_token_wrong_type_rejected_before_claim_verification(self):
        for typ in ('JWT','id+jwt',None):
            with self.subTest(typ=typ):
                self.assert_bad(self.token(headers={'typ':typ}))
        self.assertEqual(self.revocation_calls,[])

    def test_remote_jku_x5u_and_critical_headers_are_refused(self):
        for extra in ({'jku':'https://evil.example.test/jwks'},
                      {'x5u':'https://evil.example.test/cert'},
                      {'crit':['exp']},{'b64':False},{'kid':'unknown'}):
            with self.subTest(header=extra):
                # Skip payload cryptography for invalid encoding; any rejection
                # must be clean, without fetching or interpreting remote URLs.
                try: token=self.token(headers=extra)
                except (jwt.PyJWTError,ValueError):
                    continue
                self.assert_bad(token)

    def test_algorithm_confusion_and_none_signatures_refused(self):
        for a in ('none','HS256'):
            with self.subTest(alg=a):
                hdr={'alg':a,'typ':'at+jwt','kid':'test-key-1'}
                try:
                    token=jwt.encode(self.claims(),None if a=='none' else b'not-a-real-rsa-key' + b'-padding-to-32-bytes',
                                     algorithm=a,headers=hdr)
                except (jwt.PyJWTError,ValueError):
                    continue
                self.assert_bad(token)

    def test_expired_future_issue_old_issue_and_overlong_exp_refused(self):
        for changes in ({'exp':self.now-120},
                        {'iat':self.now+180},
                        {'iat':self.now-1800},
                        {'exp':self.now+3600},
                        # Valid relative-to-now checks must not admit a
                        # signed token whose ORIGINAL exp-iat exceeds 900s.
                        {'iat':self.now-300,'exp':self.now+800},
                        {'exp':self.now-1,'iat':self.now-500}):
            with self.subTest(claims=changes):
                self.assert_bad(self.token(self.claims(**changes)))

    def test_future_nbf_and_bad_time_types_fail_closed(self):
        for changes in ({'nbf':self.now+180},
                        {'nbf':'tomorrow'},
                        {'exp':float(self.now+180)},
                        {'iat':True}):
            with self.subTest(changes=changes):
                self.assert_bad(self.token(self.claims(**changes)))

    def test_missing_required_claims_are_refused(self):
        for name in ('iss','aud','sub','exp','iat','jti','client_id','scope','tenant'):
            with self.subTest(name=name):
                payload=self.claims()
                del payload[name]
                self.assert_bad(self.token(payload))

    def test_wrong_resource_issuer_client_and_subject_rejected(self):
        for changes in ({'iss':'https://other.example.test'},
                        {'aud':'https://other.example.test/mcp'},
                        {'aud':[RESOURCE,'https://other.example.test/mcp']},
                        {'client_id':'other-app'},
                        {'sub':'*'},
                        {'tenant':'../tenant-other'}):
            with self.subTest(changes=changes):
                self.assert_bad(self.token(self.claims(**changes)))

    def test_bad_scope_grants_are_never_coerced(self):
        for grant in ('hepta:connect  hepta:write',
                      'hepta:connect\thepta:write',
                      'hepta:connect hepta:connect',
                      'hepta:connect *',
                      ['hepta:connect','hepta:write'],
                      {'hepta:connect':True},''):
            with self.subTest(scope=str(grant)[:30]):
                self.assert_bad(self.token(self.claims(scope=grant)))

    def test_revocation_is_mandatory_and_fail_closed(self):
        self.revoked.add('jwt-test-1234567890')
        self.assert_bad(self.token())
        self.revoked.clear()
        self.revocation_result='False'
        self.assert_bad(self.token())
        self.revocation_result=None
        self.verifier=self.make_verifier(is_revoked_or_disallowed=lambda *_: (_ for _ in ()).throw(ConnectionError('revocation backend offline')))
        self.assert_bad(self.token())
        with self.assertRaises(ValueError):
            self.make_verifier(is_revoked_or_disallowed=None)

    def test_no_trust_file_rollback_symlink_or_writable_replacement(self):
        self.set_keys([dict(self.jwk)])
        pin=self.digest
        self.trust_file.write_text('{}')
        with self.assertRaises(ValueError):
            self.make_verifier(expected_jwks_sha256=pin)
        self.set_keys([self.jwk])
        self.trust_file.chmod(0o666)
        with self.assertRaises(PermissionError):
            self.make_verifier()
        self.trust_file.chmod(0o600)
        link=self.root/'issuer-link.json'
        link.symlink_to(self.trust_file)
        with self.assertRaises(OSError):
            self.make_verifier(jwks_file=link)

    def test_disallowed_key_type_duplicate_key_and_private_key_fields(self):
        for entries in ([self.jwk,self.jwk],
                        [{**self.jwk,'kty':'oct'}],
                        [{**self.jwk,'d':'private-parameter'}],
                        [{**self.jwk,'alg':'HS256'}],
                        [{**self.jwk,'use':'enc'}]):
            with self.subTest(entry=str(entries)[:40]):
                self.set_keys(entries)
                with self.assertRaises(ValueError):
                    self.make_verifier()

    def test_no_unbounded_or_unpinned_trust(self):
        self.set_keys([self.jwk])
        with self.assertRaises(ValueError):
            self.make_verifier(expected_jwks_sha256='0'*64)
        with self.assertRaises(ValueError):
            self.make_verifier(allowed_clients={'wildcard'})
        with self.assertRaises(ValueError):
            self.make_verifier(issuer='http://auth.example.test')
        with self.assertRaises(ValueError):
            self.make_verifier(audience='https://localhost/mcp')
        with self.assertRaises(ValueError):
            self.make_verifier(max_token_age_seconds=90000)

    def test_issuer_key_rotation_needs_new_pinned_digest(self):
        old=self.verifier
        public=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.other.public_key()))
        public.update({'kid':'test-key-2','use':'sig','alg':'RS256'})
        self.set_keys([public])
        with self.assertRaises(ValueError):
            self.make_verifier(expected_jwks_sha256=hashlib.sha256(json.dumps({'keys':[self.jwk]},sort_keys=True).encode()).hexdigest())
        self.verifier=self.make_verifier()
        token=self.token(key=self.other,headers={'kid':'test-key-2'})
        self.assertEqual(self.accept(token).subject,'subject-alice')
        with self.assertRaises(InvalidAccessToken):
            old('Bearer '+token)
        self.assert_bad(self.token())

    def test_real_signed_two_tenant_discovery_cannot_select_wrong_agent(self):
        contract=ToolContract.load(CONTRACT,hashlib.sha256(CONTRACT.read_bytes()).hexdigest())
        bindings=[]
        agents={}
        for subject,tenant,device,tools in (
            ('subject-alice','tenant-one','device-one',{'host_list','directory_create'}),
            ('subject-bob','tenant-two','device-two',{'host_list'}),
        ):
            binding=TenantBinding(
                issuer=ISSUER,audience=RESOURCE,subject=subject,tenant=tenant,
                device_id=device,cert_sha256='1'*64,connection_generation=8,
                expires_at=self.now+1800,allowed_tools=frozenset(tools),
                allowed_hosts=frozenset({'main'}),
                local_workspace_root='/srv/tenants/'+tenant+'/workspace',
            )
            bindings.append(binding)
            agents[tenant]=AuthenticatedAgent(
                device_id=device,cert_sha256='1'*64,
                connection_generation=8,tenant=tenant,subject=subject,
                workspace_root=binding.local_workspace_root,
                configured_host_aliases=frozenset({'main'}),
                native_catalog_sha256=contract.catalog_sha256,
                tenant_runtime_isolated=True,
            )
        policy=GatewayPolicy(
            contract,OnceOnlyLedger(self.root/'two-tenants.sqlite3'),
            self.verifier,tuple(bindings),resource=RESOURCE,now=lambda:self.now,
        )
        alice='Bearer '+self.token(self.claims(jti='jwt-alice-1234567890'))
        bob='Bearer '+self.token(self.claims(
            sub='subject-bob',tenant='tenant-two',scope='hepta:connect',
            jti='jwt-bob-123456789012'))
        self.assertEqual(policy.authorized_tool_names(alice,agents['tenant-one']),
                         frozenset({'host_list','directory_create'}))
        self.assertEqual(policy.authorized_tool_names(bob,agents['tenant-two']),
                         frozenset({'host_list'}))
        for token,agent in ((alice,agents['tenant-two']),
                            (bob,agents['tenant-one'])):
            with self.assertRaises(Rejected) as ctx:
                policy.authorized_tool_names(token,agent)
            self.assertEqual(ctx.exception.code,'TENANT_DEVICE_NOT_AUTHORIZED')
        # Extra signed scope is not a substitute for the enrolled tool grant.
        with self.assertRaises(Rejected):
            policy.prepare(bob,agents['tenant-two'],'directory_create',
                           {'path':'/srv/tenants/tenant-two/workspace/new'},
                           'two-tenant-mutation-0001')

    def test_no_network_jwks_lookup_from_bearer_header(self):
        from unittest.mock import patch
        with patch('urllib.request.urlopen',side_effect=AssertionError('network forbidden')):
            self.assertEqual(self.accept(self.token()).tenant,'tenant-one')
            self.assert_bad(self.token(headers={
                'jku':'https://attacker.example.test/public-keys.json'}))

    def test_malformed_bearer_encodings_and_header_spoofing_refused(self):
        token=self.token()
        for bad in ('',token,'bearer '+token,'Bearer  '+token,
                    'Bearer '+token+' extra','Bearer '+('A'*9000)):
            with self.subTest(bad=bad[:15]):
                with self.assertRaises(InvalidAccessToken):
                    self.verifier(bad)

    def test_verified_rs256_user_identity_integrates_with_tenant_policy(self):
        contract=ToolContract.load(CONTRACT,hashlib.sha256(CONTRACT.read_bytes()).hexdigest())
        root=self.root/'tenant-workspace'
        root.mkdir(mode=0o700)
        ledger=OnceOnlyLedger(self.root/'ledger.sqlite3')
        alias='main'
        binding=TenantBinding(
            issuer=ISSUER,audience=RESOURCE,subject='subject-alice',
            tenant='tenant-one',device_id='device-alice',cert_sha256='1'*64,
            connection_generation=5,expires_at=self.now+7200,
            allowed_tools=frozenset({'host_list','directory_create'}),
            allowed_hosts=frozenset({alias}),
            local_workspace_root='/srv/tenants/tenant-one/workspace',
        )
        agent=AuthenticatedAgent(
            device_id='device-alice',cert_sha256='1'*64,
            connection_generation=5,tenant='tenant-one',
            subject='subject-alice',
            workspace_root=binding.local_workspace_root,
            configured_host_aliases=frozenset({alias}),
            native_catalog_sha256=contract.catalog_sha256,
            tenant_runtime_isolated=True,
        )
        policy=GatewayPolicy(
            contract,ledger,self.verifier,(binding,),
            resource=RESOURCE,now=lambda:self.now,
        )
        token=self.token()
        self.assertEqual(policy.authorized_tool_names('Bearer '+token,agent),
                         frozenset({'host_list','directory_create'}))
        permit=policy.prepare('Bearer '+token,agent,'directory_create',
                              {'path':binding.local_workspace_root+'/scratch'},'jwt-policy-test-call-1')
        self.assertTrue(permit.mutating)
        self.assertEqual(ledger.state(permit),'reserved')
        policy.mark_delivered(permit,confirmed=False)
        self.assertEqual(ledger.state(permit),'unknown')
        self.revoked.add('jwt-test-1234567890')
        with self.assertRaises(Rejected) as ctx:
            policy.authorized_tool_names('Bearer '+token,agent)
        self.assertEqual(ctx.exception.code,'OAUTH_INVALID')

if __name__=='__main__':
    unittest.main(verbosity=2)
