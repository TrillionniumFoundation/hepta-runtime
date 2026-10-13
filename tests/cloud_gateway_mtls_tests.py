#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real ephemeral TLS 1.3 mutual-auth tests over socketpair, no listener.

CA, server and agent private keys are generated into account-private temporary
files, then discarded. No production trust keys, user tokens, public network or
native execution are touched. Isolation callback is an explicit TEST FIXTURE.
"""
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import socket
import ssl
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import jwt
from cloud_gateway_jwt_verifier import VerifiedJwtAccessTokens
from cloud_gateway_mtls import (
    ALPN, AgentPeerRejected, EnrolledAgent, VerifiedMtlsAgentPeers,
    private_enrollments_file,
)
from cloud_gateway_policy import (
    APPROVED_CATALOG_SHA256, AuthenticatedUser, GatewayPolicy,
    OnceOnlyLedger, Rejected, TenantBinding,
)
from mcp_tool_contract import ToolContract

NOW = int(time.time())
RESOURCE = "https://gateway.example.test/mcp"
ISSUER = "https://auth.example.test"
SERVER_HOST = "gateway.example.test"


def private_pem(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


class RealMutualTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hepta-agent-mtls-fixture-")
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.root.chmod(0o700)
        self.now = int(time.time())
        self.ca_cert = self.make_cert(self.ca_key, "test-local-ca", is_ca=True)
        self.server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.agent2_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.unknown_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.server_cert = self.make_cert(self.server_key, SERVER_HOST, role="server")
        self.agent_cert = self.make_cert(self.agent_key, "device-one", role="client")
        self.agent2_cert = self.make_cert(self.agent2_key, "device-two", role="client")
        self.unknown_cert = self.make_cert(self.unknown_key, "unenrolled-device", role="client")
        self.ca_file = self.root / "ca.pem"
        self.server_file = self.root / "server.pem"
        self.server_keyfile = self.root / "server.key"
        private_pem(self.ca_file, self.ca_cert.public_bytes(serialization.Encoding.PEM))
        private_pem(self.server_file, self.server_cert.public_bytes(serialization.Encoding.PEM))
        private_pem(self.server_keyfile, self.key_pem(self.server_key))
        self.agent_file, self.agent_keyfile = self.write_keypair("agent", self.agent_cert, self.agent_key)
        self.agent2_file, self.agent2_keyfile = self.write_keypair("agent2", self.agent2_cert, self.agent2_key)
        self.unknown_file, self.unknown_keyfile = self.write_keypair("unknown", self.unknown_cert, self.unknown_key)
        self.enrollment = EnrolledAgent(
            device_id="device-one",
            cert_sha256=self.fingerprint(self.agent_cert),
            connection_generation=7,
            tenant="tenant-one", subject="subject-one",
            workspace_root="/tenants/tenant-one/workspace",
            configured_host_aliases=frozenset({"main"}),
            native_catalog_sha256=APPROVED_CATALOG_SHA256,
            expires_at=self.now + 3600,
        )
        self.enrollment2 = dataclasses.replace(
            self.enrollment, device_id="device-two",
            cert_sha256=self.fingerprint(self.agent2_cert),
            tenant="tenant-two", subject="subject-two",
            workspace_root="/tenants/tenant-two/workspace",
            connection_generation=3,
        )
        self.revoked = False
        self.revocation_calls = 0
        self.isolated = True
        self.attestation_calls = 0
        self.server_context = self.make_server_context()
        self.client_context = self.make_client_context(self.agent_file, self.agent_keyfile)

    def make_cert(self, key, name, *, is_ca=False, role=None):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        issuer = subject if is_ca else self.ca_cert.subject
        signer = key if is_ca else self.ca_key
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=10))
                   .not_valid_after(now + datetime.timedelta(hours=12)))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        if role == "server":
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(SERVER_HOST)]), critical=False)
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        elif role == "client":
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        return builder.sign(private_key=signer, algorithm=hashes.SHA256())

    @staticmethod
    def key_pem(key):
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption())

    @staticmethod
    def fingerprint(cert):
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    def write_keypair(self, name, cert, key):
        cert_path, key_path = self.root / (name + ".pem"), self.root / (name + ".key")
        private_pem(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        private_pem(key_path, self.key_pem(key))
        return cert_path, key_path

    def make_server_context(self, *, alpn=True, require_client=True):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(self.server_file), str(self.server_keyfile))
        context.load_verify_locations(cafile=str(self.ca_file))
        context.verify_mode = ssl.CERT_REQUIRED if require_client else ssl.CERT_NONE
        if alpn:
            context.set_alpn_protocols([ALPN])
        return context

    def make_client_context(self, cert_path, key_path, *, alpn=True):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                             cafile=str(self.ca_file))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(cert_path), str(key_path))
        if alpn:
            context.set_alpn_protocols([ALPN])
        return context

    def handshake(self, client_context=None, server_context=None):
        server_raw, client_raw = socket.socketpair()
        server_raw.settimeout(4)
        client_raw.settimeout(4)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit((server_context or self.server_context).wrap_socket,
                                 server_raw, server_side=True)
            client = None
            try:
                client = (client_context or self.client_context).wrap_socket(
                    client_raw, server_hostname=SERVER_HOST)
                server = future.result(timeout=5)
            except BaseException:
                # OpenSSL may complete the client handshake first and fail the
                # server's client-cert verification shortly after; close both.
                if client is not None:
                    client.close()
                server_raw.close()
                client_raw.close()
                try:
                    result = future.result(timeout=5)
                    result.close()
                except BaseException:
                    pass
                raise
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        return server, client

    def revocation(self, enrolled):
        self.revocation_calls += 1
        return self.revoked

    def isolation(self, peer, enrolled):
        self.attestation_calls += 1
        return self.isolated

    def verifier(self, enrollments=None, **kw):
        args = {
            "enrollments": tuple(enrollments or (self.enrollment,)),
            "is_revoked_or_disallowed": self.revocation,
            "verify_current_tenant_runtime_isolation": self.isolation,
            "now": lambda: self.now,
        }
        args.update(kw)
        return VerifiedMtlsAgentPeers(**args)

    def test_real_verified_mutual_tls_yields_exact_typed_device(self):
        server, client = self.handshake()
        self.assertEqual(server.version(), "TLSv1.3")
        self.assertEqual(server.selected_alpn_protocol(), ALPN)
        agent = self.verifier().identify(server)
        self.assertEqual(agent.cert_sha256, self.enrollment.cert_sha256)
        self.assertEqual(agent.tenant, "tenant-one")
        self.assertEqual(agent.connection_generation, 7)
        self.assertEqual(agent.native_catalog_sha256, APPROVED_CATALOG_SHA256)
        self.assertTrue(agent.tenant_runtime_isolated)
        self.assertEqual(self.revocation_calls, 1)
        self.assertEqual(self.attestation_calls, 1)
        self.assertTrue(client.cipher())

    def test_two_certificates_are_cryptographically_bound_to_different_tenants(self):
        registry = self.verifier((self.enrollment, self.enrollment2))
        first, _ = self.handshake()
        second_context = self.make_client_context(self.agent2_file, self.agent2_keyfile)
        second, _ = self.handshake(second_context)
        a, b = registry.identify(first), registry.identify(second)
        self.assertEqual({a.tenant, b.tenant}, {"tenant-one", "tenant-two"})
        self.assertNotEqual(a.cert_sha256, b.cert_sha256)
        self.assertEqual(a.subject, "subject-one")
        self.assertEqual(b.subject, "subject-two")

    def test_same_ca_but_unenrolled_leaf_is_denied(self):
        client = self.make_client_context(self.unknown_file, self.unknown_keyfile)
        server, _ = self.handshake(client)
        with self.assertRaises(AgentPeerRejected):
            self.verifier().identify(server)

    def test_untrusted_certificate_fails_openssl_mutual_handshake(self):
        other_ca = self.make_other_ca()
        outsider_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "foreign-client")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(other_ca.subject)
                .public_key(outsider_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(hours=2))
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self.other_ca_key, hashes.SHA256()))
        file, key = self.write_keypair("foreign", cert, outsider_key)
        context = self.make_client_context(file, key)
        with self.assertRaises(ssl.SSLError):
            self.handshake(context)

    def make_other_ca(self):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other-ca")])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(self.other_ca_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(hours=2))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(self.other_ca_key, hashes.SHA256()))

    def test_alpn_downgrade_or_unverified_server_context_refused(self):
        server, _ = self.handshake(self.make_client_context(
            self.agent_file, self.agent_keyfile, alpn=False))
        with self.assertRaises(AgentPeerRejected):
            self.verifier().identify(server)
        server, _ = self.handshake(server_context=self.make_server_context(
            require_client=False))
        with self.assertRaises(AgentPeerRejected):
            self.verifier().identify(server)

    def test_plain_socket_or_raw_certificate_cannot_synthesize_identity(self):
        verifier = self.verifier()
        with self.assertRaises(AgentPeerRejected):
            verifier.identify(self.agent_cert.public_bytes(serialization.Encoding.DER))
        with self.assertRaises(AgentPeerRejected):
            verifier.identify({"cert_sha256": self.enrollment.cert_sha256})
        with socket.socket() as sock:
            with self.assertRaises(AgentPeerRejected):
                verifier.identify(sock)

    def test_live_revocation_and_isolation_must_recheck_every_request(self):
        server, _ = self.handshake()
        registry = self.verifier()
        registry.identify(server)
        self.revoked = True
        with self.assertRaises(AgentPeerRejected):
            registry.identify(server)
        self.assertEqual(self.revocation_calls, 2)
        self.revoked = False
        self.isolated = False
        with self.assertRaises(AgentPeerRejected):
            registry.identify(server)
        self.assertEqual(self.attestation_calls, 2)
        self.isolated = True
        self.assertEqual(registry.identify(server).device_id, "device-one")
        self.assertEqual(self.attestation_calls, 3)

    def test_nonboolean_or_failing_trusted_callbacks_are_deny_by_default(self):
        server, _ = self.handshake()
        for overrides in (
            {"is_revoked_or_disallowed": lambda _: "False"},
            {"is_revoked_or_disallowed": lambda _: (_ for _ in ()).throw(OSError("private secret"))},
            {"verify_current_tenant_runtime_isolation": lambda *_: "True"},
            {"verify_current_tenant_runtime_isolation": lambda *_: (_ for _ in ()).throw(OSError("private secret"))},
        ):
            with self.subTest(overrides=list(overrides)):
                with self.assertRaises(AgentPeerRejected) as caught:
                    self.verifier(**overrides).identify(server)
                self.assertNotIn("private secret", str(caught.exception))
        for missing in (
            {"is_revoked_or_disallowed": None},
            {"verify_current_tenant_runtime_isolation": None},
        ):
            with self.assertRaises(ValueError):
                self.verifier(**missing)

    def test_enrollment_revoked_and_expired_fail_closed(self):
        server, _ = self.handshake()
        for row in (
            dataclasses.replace(self.enrollment, revoked=True),
            dataclasses.replace(self.enrollment, expires_at=self.now),
            dataclasses.replace(self.enrollment, expires_at=self.now - 1),
            dataclasses.replace(self.enrollment, expires_at=self.now + 31*86400),
        ):
            with self.subTest(row=row.revoked):
                with self.assertRaises(AgentPeerRejected):
                    self.verifier((row,)).identify(server)

    def test_duplicate_device_or_certificate_and_mutable_aliases_denied(self):
        with self.assertRaises(ValueError):
            self.verifier((self.enrollment, self.enrollment))
        with self.assertRaises(ValueError):
            self.verifier((self.enrollment, dataclasses.replace(
                self.enrollment, cert_sha256=self.enrollment2.cert_sha256)))
        with self.assertRaises(ValueError):
            self.verifier((self.enrollment, dataclasses.replace(
                self.enrollment, device_id="other", tenant="other")))
        for row in (
            dataclasses.replace(self.enrollment, configured_host_aliases={"main"}),
            dataclasses.replace(self.enrollment, native_catalog_sha256="0"*64),
            dataclasses.replace(self.enrollment, workspace_root="/"),
            dataclasses.replace(self.enrollment, workspace_root="/tenants/../secrets"),
            dataclasses.replace(self.enrollment, workspace_root="/tenants/tenant-one/\nsecret"),
            dataclasses.replace(self.enrollment, connection_generation=True),
            dataclasses.replace(self.enrollment, expires_at=True),
        ):
            with self.assertRaises(ValueError):
                self.verifier((row,))

    def enrollment_file(self, rows=None):
        rows = rows or [self.enrollment]
        data = {"version": 1, "agents": [
            {**dataclasses.asdict(row),
             "configured_host_aliases": sorted(row.configured_host_aliases)}
            for row in rows
        ]}
        raw = json.dumps(data, sort_keys=True).encode()
        file = self.root / "enrollments.json"
        file.write_bytes(raw)
        file.chmod(0o600)
        return file, hashlib.sha256(raw).hexdigest()

    def test_private_enrollment_digest_symlink_and_modes(self):
        file, digest = self.enrollment_file()
        accepted = private_enrollments_file(file, digest)
        self.assertEqual(accepted, (self.enrollment,))
        with self.assertRaises(ValueError):
            private_enrollments_file(file, "0"*64)
        link = self.root / "symlink"
        link.symlink_to(file)
        with self.assertRaises(OSError):
            private_enrollments_file(link, digest)
        file.chmod(0o644)
        with self.assertRaises(PermissionError):
            private_enrollments_file(file, digest)
        file.chmod(0o666)
        with self.assertRaises(PermissionError):
            private_enrollments_file(file, digest)

    def test_pinned_file_duplicate_keys_or_invalid_aliases_fail(self):
        file, _ = self.enrollment_file()
        raw = file.read_bytes()
        corrupted = raw.replace(b'"version": 1', b'"version": 1, "version": 1')
        file.write_bytes(corrupted)
        with self.assertRaises(ValueError):
            private_enrollments_file(file, hashlib.sha256(corrupted).hexdigest())
        file, _ = self.enrollment_file()
        data = json.loads(file.read_text())
        data["agents"][0]["configured_host_aliases"] = ["main", "main"]
        file.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            private_enrollments_file(file, hashlib.sha256(file.read_bytes()).hexdigest())

    def test_real_cert_identity_is_accepted_only_by_its_own_tenant_policy(self):
        contract_path = ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json"
        contract = ToolContract.load(
            contract_path, hashlib.sha256(contract_path.read_bytes()).hexdigest())
        registry = self.verifier((self.enrollment, self.enrollment2))
        one, _ = self.handshake()
        second_context = self.make_client_context(self.agent2_file, self.agent2_keyfile)
        two, _ = self.handshake(second_context)
        first_agent, second_agent = registry.identify(one), registry.identify(two)
        with tempfile.TemporaryDirectory(prefix="hepta-mtls-ledger-") as d:
            pathlib.Path(d).chmod(0o700)
            ledger = OnceOnlyLedger(pathlib.Path(d) / "ledger.sqlite3")
            user = AuthenticatedUser(issuer=ISSUER, audience=RESOURCE,
                subject="subject-one", tenant="tenant-one",
                expires_at=self.now+120, scopes=frozenset({"hepta:connect","hepta:write"}))
            def verifier(header):
                if header != "Bearer fixture-token":
                    raise ValueError("invalid fixture")
                return user
            enrolled = []
            for row in (self.enrollment, self.enrollment2):
                enrolled.append(TenantBinding(
                    issuer=ISSUER, audience=RESOURCE,
                    subject=row.subject, tenant=row.tenant,
                    device_id=row.device_id, cert_sha256=row.cert_sha256,
                    connection_generation=row.connection_generation,
                    expires_at=row.expires_at,
                    allowed_tools=frozenset({"host_list","directory_create"}),
                    allowed_hosts=row.configured_host_aliases,
                    local_workspace_root=row.workspace_root,
                ))
            policy = GatewayPolicy(contract, ledger, verifier, tuple(enrolled),
                                   resource=RESOURCE, now=lambda: self.now)
            self.assertEqual(policy.authorized_tool_names(
                "Bearer fixture-token", first_agent),
                frozenset({"host_list","directory_create"}))
            with self.assertRaises(Rejected) as ctx:
                policy.authorized_tool_names("Bearer fixture-token", second_agent)
            self.assertEqual(ctx.exception.code, "TENANT_DEVICE_NOT_AUTHORIZED")
            permit = policy.prepare("Bearer fixture-token", first_agent,
                "directory_create", {"path":self.enrollment.workspace_root + "/folder"},
                "fixture-mtls-0001")
            self.assertTrue(permit.mutating)
            self.assertEqual(ledger.state(permit), "reserved")
            with self.assertRaises(Rejected) as ctx:
                policy.prepare("Bearer fixture-token", first_agent,
                    "directory_create", {"path":self.enrollment.workspace_root + "/folder"},
                    "fixture-mtls-0001")
            self.assertEqual(ctx.exception.code, "RECONCILE_PRIOR_CALL")


    def test_real_signed_oauth_jwt_plus_two_mtls_devices_enforce_one_tenant(self):
        oauth_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(oauth_key.public_key()))
        jwk.update({"kid":"jwt-test-key-1","use":"sig","alg":"RS256"})
        public_jwks = self.root / "oauth-public-jwks.json"
        public_jwks.write_text(json.dumps({"keys":[jwk]}))
        public_jwks.chmod(0o600)
        blocked_jti = set()
        def token_revoked(issuer,client,subject,tenant,jti):
            return jti in blocked_jti
        verifier = VerifiedJwtAccessTokens(
            issuer=ISSUER,audience=RESOURCE,
            allowed_clients=frozenset({"test-client-001"}),
            jwks_file=public_jwks,
            expected_jwks_sha256=hashlib.sha256(public_jwks.read_bytes()).hexdigest(),
            is_revoked_or_disallowed=token_revoked,
        )
        def signed_token(tenant,subject,jti):
            claims={"iss":ISSUER,"aud":RESOURCE,"sub":subject,
                "tenant":tenant,"client_id":"test-client-001",
                "scope":"hepta:connect hepta:write",
                "iat":self.now,"exp":self.now+120,"jti":jti}
            return "Bearer "+jwt.encode(claims,oauth_key,algorithm="RS256",
                headers={"kid":"jwt-test-key-1","typ":"at+jwt"})
        contract_path=ROOT/"deploy/contracts/hepta-runtime-full-operator-v4.json"
        contract=ToolContract.load(contract_path,hashlib.sha256(contract_path.read_bytes()).hexdigest())
        binding=[]
        for row in (self.enrollment,self.enrollment2):
            binding.append(TenantBinding(
                issuer=ISSUER,audience=RESOURCE,subject=row.subject,
                tenant=row.tenant,device_id=row.device_id,
                cert_sha256=row.cert_sha256,
                connection_generation=row.connection_generation,
                expires_at=row.expires_at,
                allowed_tools=frozenset({"host_list","directory_create"}),
                allowed_hosts=row.configured_host_aliases,
                local_workspace_root=row.workspace_root,
            ))
        with tempfile.TemporaryDirectory(prefix="hepta-combined-auth-") as d:
            pathlib.Path(d).chmod(0o700)
            ledger=OnceOnlyLedger(pathlib.Path(d)/"once.sqlite3")
            policy=GatewayPolicy(contract,ledger,verifier,tuple(binding),
                                 resource=RESOURCE,now=lambda:self.now)
            registry=self.verifier((self.enrollment,self.enrollment2))
            first,_=self.handshake()
            second,_=self.handshake(self.make_client_context(self.agent2_file,self.agent2_keyfile))
            agent1,agent2=registry.identify(first),registry.identify(second)
            token1=signed_token("tenant-one","subject-one","jwt-tenant-one-001")
            token2=signed_token("tenant-two","subject-two","jwt-tenant-two-002")
            self.assertEqual(policy.authorized_tool_names(token1,agent1),
                             frozenset({"host_list","directory_create"}))
            self.assertEqual(policy.authorized_tool_names(token2,agent2),
                             frozenset({"host_list","directory_create"}))
            for token,wrong_agent in ((token1,agent2),(token2,agent1)):
                with self.assertRaises(Rejected) as result:
                    policy.authorized_tool_names(token,wrong_agent)
                self.assertEqual(result.exception.code,"TENANT_DEVICE_NOT_AUTHORIZED")
            args={"path":self.enrollment.workspace_root+"/new"}
            permit=policy.prepare(token1,agent1,"directory_create",args,"mtls-signed-jwt-01")
            self.assertTrue(permit.mutating)
            self.assertEqual(ledger.state(permit),"reserved")
            with self.assertRaises(Rejected) as result:
                policy.prepare(token1,agent1,"directory_create",args,"mtls-signed-jwt-01")
            self.assertEqual(result.exception.code,"RECONCILE_PRIOR_CALL")
            with self.assertRaises(Rejected) as result:
                policy.prepare(token2,agent2,"directory_create",args,"mtls-tenant2-call-01")
            self.assertEqual(result.exception.code,"PATH_OUTSIDE_TENANT_WORKSPACE")
            blocked_jti.add("jwt-tenant-one-001")
            with self.assertRaises(Rejected) as result:
                policy.authorized_tool_names(token1,agent1)
            self.assertEqual(result.exception.code,"OAUTH_INVALID")
            self.assertEqual(policy.authorized_tool_names(token2,agent2),
                             frozenset({"host_list","directory_create"}))

    def test_certificate_rotation_keeps_cross_generation_write_replay_blocked(self):
        contract_path=ROOT/"deploy/contracts/hepta-runtime-full-operator-v4.json"
        contract=ToolContract.load(contract_path,hashlib.sha256(contract_path.read_bytes()).hexdigest())
        rotated=dataclasses.replace(self.enrollment,
            cert_sha256=self.fingerprint(self.agent2_cert),connection_generation=8)
        old_peer,_=self.handshake()
        new_peer,_=self.handshake(self.make_client_context(self.agent2_file,self.agent2_keyfile))
        old_agent=self.verifier((self.enrollment,)).identify(old_peer)
        new_agent=self.verifier((rotated,)).identify(new_peer)
        def binding(row):
            return TenantBinding(issuer=ISSUER,audience=RESOURCE,
                subject=row.subject,tenant=row.tenant,device_id=row.device_id,
                cert_sha256=row.cert_sha256,
                connection_generation=row.connection_generation,
                expires_at=row.expires_at,
                allowed_tools=frozenset({"directory_create"}),
                allowed_hosts=frozenset({"main"}),local_workspace_root=row.workspace_root)
        user=AuthenticatedUser(issuer=ISSUER,audience=RESOURCE,
            subject="subject-one",tenant="tenant-one",
            expires_at=self.now+120,scopes=frozenset({"hepta:connect","hepta:write"}))
        with tempfile.TemporaryDirectory(prefix="hepta-mtls-rotation-") as d:
            pathlib.Path(d).chmod(0o700)
            ledger=OnceOnlyLedger(pathlib.Path(d)/"once.sqlite3")
            def policy(row):
                return GatewayPolicy(contract,ledger,lambda _:user,(binding(row),),
                    resource=RESOURCE,now=lambda:self.now)
            args={"path":self.enrollment.workspace_root+"/new"}
            first=policy(self.enrollment)
            permit=first.prepare("Bearer fixture",old_agent,"directory_create",args,
                                 "rotation-replay-0001")
            self.assertEqual(ledger.state(permit),"reserved")
            second=policy(rotated)
            with self.assertRaises(Rejected) as result:
                second.prepare("Bearer fixture",new_agent,"directory_create",args,
                               "rotation-replay-0001")
            self.assertEqual(result.exception.code,"RECONCILE_PRIOR_CALL")
            permitted=second.prepare("Bearer fixture",new_agent,"directory_create",args,
                                     "rotation-new-call-02")
            self.assertEqual(ledger.state(permitted),"reserved")
            with self.assertRaises(Rejected) as result:
                first.authorized_tool_names("Bearer fixture",new_agent)
            self.assertEqual(result.exception.code,"TENANT_DEVICE_NOT_AUTHORIZED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
