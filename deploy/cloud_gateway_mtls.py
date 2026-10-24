#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline genuine mTLS peer-to-agent identity adapter, NOT a public server.

Accepts an already handshaken server-side SSLSocket only. OpenSSL must
validate the client's certificate against an explicitly configured issuer CA;
the adapter additionally pins the exact leaf certificate SHA256 to a private,
administrator-reviewed enrollment snapshot. Model/tool JSON cannot supply
an agent identity. Revocation and independent tenant runtime isolation
attestation are mandatory per-request callbacks and fail closed.

This component neither binds a port nor signs agent manifests, proves OS
isolation, issues certificates, or executes native tools. All missing
components require an independent release review.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import time
from typing import Callable

from cloud_gateway_policy import APPROVED_CATALOG_SHA256, AuthenticatedAgent

FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY = re.compile(r"[A-Za-z0-9_.:@-]{1,256}\Z")
ALPN = "hepta-agent/1"
MAX_ENROLLMENTS_BYTES = 64 * 1024
MAX_ENROLLMENT_FUTURE_SECONDS = 30 * 24 * 60 * 60


class AgentPeerRejected(PermissionError):
    """Generic failure. Never includes peer identity or certificate details."""


@dataclass(frozen=True)
class EnrolledAgent:
    device_id: str
    cert_sha256: str
    connection_generation: int
    tenant: str
    subject: str
    workspace_root: str
    configured_host_aliases: frozenset[str]
    native_catalog_sha256: str
    expires_at: int
    revoked: bool = False


def _bad(message: str):
    raise ValueError(message)


def _identity(value: object) -> bool:
    return type(value) is str and bool(IDENTITY.fullmatch(value)) and ".." not in value


def _valid_enrollment(value: EnrolledAgent) -> None:
    if not isinstance(value, EnrolledAgent):
        _bad("Agent enrollment must be a typed reviewed record")
    if not all(_identity(x) for x in (value.device_id, value.tenant, value.subject)):
        _bad("Malformed exact device / tenant enrollment")
    if (type(value.cert_sha256) is not str or not FINGERPRINT.fullmatch(value.cert_sha256)
        or value.native_catalog_sha256 != APPROVED_CATALOG_SHA256):
        _bad("Unapproved device certificate or native tool catalog")
    if (type(value.connection_generation) is not int or value.connection_generation <= 0
        or type(value.expires_at) is not int or value.expires_at <= 0
        or type(value.revoked) is not bool):
        _bad("Invalid generation, expiry or revocation")
    if (type(value.configured_host_aliases) is not frozenset
        or len(value.configured_host_aliases) > 64
        or any(not _identity(x) for x in value.configured_host_aliases)):
        _bad("Invalid immutable configured host aliases")
    root = value.workspace_root
    if (type(root) is not str or not root.startswith("/") or root == "/"
        or len(root.encode("utf-8")) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in root)
        or "//" in root or "\\" in root
        or any(part in (".", "..") for part in root.split("/"))
        or PurePosixPath(root).as_posix() != root):
        _bad("Invalid private absolute tenant workspace root")


def _strict_json(raw: bytes) -> object:
    def check_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate enrollment key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=check_pairs,
                      parse_constant=lambda _: _bad("Invalid JSON constant"))


def private_enrollments_file(path: str | Path, expected_sha256: str) -> tuple[EnrolledAgent, ...]:
    """Load pinned admin-approved device identities, never customer JSON."""
    if type(expected_sha256) is not str or not FINGERPRINT.fullmatch(expected_sha256):
        raise ValueError("Explicit enrollment file SHA256 required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
            or info.st_mode & 0o077):
            raise PermissionError("Private trusted-owner enrollment file required")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(MAX_ENROLLMENTS_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if (len(raw) > MAX_ENROLLMENTS_BYTES
        or hashlib.sha256(raw).hexdigest() != expected_sha256):
        raise ValueError("Enrollment file digest/size mismatch")
    doc = _strict_json(raw)
    if (not isinstance(doc, dict) or set(doc) != {"version", "agents"}
        or type(doc["version"]) is not int or doc["version"] != 1):
        raise ValueError("Unsupported enrollment document")
    rows = doc["agents"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128:
        raise ValueError("Expected 1..128 enrollment rows")
    fields = frozenset(EnrolledAgent.__dataclass_fields__)
    agents = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError("Enrollment rows must have exact reviewed fields")
        aliases = row["configured_host_aliases"]
        if type(aliases) is not list or any(type(x) is not str for x in aliases) or len(aliases) != len(set(aliases)):
            raise ValueError("Unique host aliases required")
        value = EnrolledAgent(**{**row, "configured_host_aliases": frozenset(aliases)})
        _valid_enrollment(value)
        agents.append(value)
    return tuple(agents)


class VerifiedMtlsAgentPeers:
    """Per-request extraction of agent identity from actual TLS peer credentials.

    Mandatory trusted callbacks:
    is_revoked_or_disallowed(enrollment) -> bool
    verify_current_tenant_runtime_isolation(peer_socket, enrollment) -> bool

    The second MUST independently attest a fresh signed runtime manifest and
    tenant OS isolation; certificate and static enrollment cannot prove either.
    """

    def __init__(
        self, enrollments: tuple[EnrolledAgent, ...], *,
        is_revoked_or_disallowed: Callable[[EnrolledAgent], bool],
        verify_current_tenant_runtime_isolation: Callable[[ssl.SSLSocket, EnrolledAgent], bool],
        now: Callable[[], int] | None = None,
    ):
        if type(enrollments) is not tuple or not enrollments:
            raise ValueError("Nonempty immutable enrollment tuple required")
        if (not callable(is_revoked_or_disallowed)
            or not callable(verify_current_tenant_runtime_isolation)):
            raise ValueError("Independent revocation and runtime attestation mandatory")
        pins = {}
        owners = set()
        for agent in enrollments:
            _valid_enrollment(agent)
            owner = (agent.tenant, agent.subject, agent.device_id)
            if agent.cert_sha256 in pins or owner in owners:
                raise ValueError("One certificate and device must have one exact enrollment")
            pins[agent.cert_sha256] = agent
            owners.add(owner)
        self._pins = pins
        self._revoked = is_revoked_or_disallowed
        self._is_isolated = verify_current_tenant_runtime_isolation
        self._now = now if now is not None else lambda: int(time.time())

    def identify(self, tls_peer: ssl.SSLSocket) -> AuthenticatedAgent:
        """Require TLS 1.3, trusted client certificate, exact pin and attestation.

        Caller cannot supply DER, fingerprint, or a synthetic AuthenticatedAgent.
        Invoke for every request and new connection; never cache across revocation.
        """
        try:
            if (not isinstance(tls_peer, ssl.SSLSocket)
                or tls_peer.server_side is not True
                or tls_peer.context.verify_mode != ssl.CERT_REQUIRED
                or tls_peer.version() != "TLSv1.3"
                or not tls_peer.cipher()
                or tls_peer.selected_alpn_protocol() != ALPN):
                raise ValueError("Not a verified mTLS agent socket")
            cert = tls_peer.getpeercert(binary_form=True)
            if type(cert) is not bytes or not cert or len(cert) > 16384:
                raise ValueError("Client peer certificate absent or oversized")
            agent = self._pins.get(hashlib.sha256(cert).hexdigest())
            now = self._now()
            if (type(now) is not int or agent is None or agent.revoked
                or agent.expires_at <= now
                or agent.expires_at > now + MAX_ENROLLMENT_FUTURE_SECONDS):
                raise ValueError("Unknown revoked expired or overlong enrollment")
            revoked = self._revoked(agent)
            if type(revoked) is not bool or revoked:
                raise ValueError("Live revocation denied")
            isolated = self._is_isolated(tls_peer, agent)
            if type(isolated) is not bool or not isolated:
                raise ValueError("Missing independent runtime isolation proof")
            return AuthenticatedAgent(
                device_id=agent.device_id, cert_sha256=agent.cert_sha256,
                connection_generation=agent.connection_generation,
                tenant=agent.tenant, subject=agent.subject,
                workspace_root=agent.workspace_root,
                configured_host_aliases=agent.configured_host_aliases,
                native_catalog_sha256=agent.native_catalog_sha256,
                tenant_runtime_isolated=True,
            )
        except Exception:
            raise AgentPeerRejected("authenticated agent peer rejected") from None
