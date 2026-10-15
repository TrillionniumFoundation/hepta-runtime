#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline asymmetric signature-verifying OAuth access-token adapter.

This is an explicit trusted identity ingress *component*, not an OAuth 2.1
authorization server, public HTTP listener, JWKS network fetcher, device
authenticator, or production revocation backend. The pinned JWKS is provisioned
out of band by the issuer administrator; token headers never control network
fetching or algorithm selection. A live revocation/consent checker is mandatory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, FrozenSet

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from cloud_gateway_https import public_https_url
from cloud_gateway_policy import AuthenticatedUser

# RFC 9068's mandatory interoperability algorithm. No HS*/none or algorithm
# chosen by a bearer header; support for another algorithm requires review.
ALGORITHM = "RS256"
ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})
SCOPE = re.compile(r"[A-Za-z0-9:._/-]{1,128}\Z")
IDENTITY = re.compile(r"[A-Za-z0-9_.:@-]{1,256}\Z")
KID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
JTI = re.compile(r"[A-Za-z0-9_.:-]{8,128}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_JWKS_BYTES = 65536
MAX_BEARER_CHARS = 8192


class InvalidAccessToken(ValueError):
    """Stable rejection without token, key or claim details."""


def _strict_json(raw: bytes) -> object:
    def duplicate_check(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JWKS field")
            value[key] = item
        return value

    def invalid_constant(_):
        raise ValueError("non-JSON numeric constant")
    return json.loads(raw, object_pairs_hook=duplicate_check,
                      parse_constant=invalid_constant)


def _pinned_public_jwks(path: str | Path, expected_sha256: str) -> dict[str, rsa.RSAPublicKey]:
    if not isinstance(expected_sha256, str) or not HASH.fullmatch(expected_sha256):
        raise ValueError("Explicit trust-file SHA256 is required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
            or info.st_mode & 0o022):
            raise PermissionError("Issuer trust file must not be group/other writable")
        with os.fdopen(fd, "rb") as file:
            fd = -1
            data = file.read(MAX_JWKS_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > MAX_JWKS_BYTES or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("Pinned issuer public key set changed")
    jwks = _strict_json(data)
    if not isinstance(jwks, dict) or set(jwks) != {"keys"}:
        raise ValueError("A JWKS with only a keys array is required")
    values = jwks["keys"]
    if not isinstance(values, list) or not 1 <= len(values) <= 16:
        raise ValueError("Expected 1..16 explicit issuer signing keys")
    keys = {}
    for item in values:
        if not isinstance(item, dict):
            raise ValueError("Invalid issuer signing key")
        kid = item.get("kid")
        if (not isinstance(kid, str) or not KID.fullmatch(kid)
            or kid in keys or item.get("kty") != "RSA"
            or item.get("alg") != ALGORITHM or item.get("use") != "sig"
            or item.get("key_ops") not in (None, ["verify"])
            or set(item) - {"kid", "kty", "n", "e", "alg", "use", "key_ops"}):
            raise ValueError("Unexpected RSA verification key identity or attributes")
        try:
            key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(item))
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError("Malformed issuer public signing key") from exc
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("Private or symmetric issuer key is forbidden")
        numbers = key.public_numbers()
        if not 2048 <= key.key_size <= 4096 or numbers.e != 65537:
            raise ValueError("Unsupported issuer RSA key strength")
        keys[kid] = key
    return keys


class VerifiedJwtAccessTokens:
    """Bounded, pinned RFC 9068 JWT verifier returning typed policy identities.

    The caller must provide a real revocation AND consent checker with signature:
      is_revoked_or_disallowed(issuer, client_id, subject, tenant, jti) -> bool
    True means deny; errors or non-boolean results also deny. There is no
    permissive default when the revocation service is unavailable.
    """

    def __init__(
        self, *,
        issuer: str, audience: str, allowed_clients: FrozenSet[str],
        jwks_file: str | Path, expected_jwks_sha256: str,
        is_revoked_or_disallowed: Callable[[str, str, str, str, str], bool],
        max_token_age_seconds: int = 900,
        leeway_seconds: int = 15,
    ):
        public_https_url(issuer, resource=False)
        public_https_url(audience, resource=True)
        if (type(allowed_clients) is not frozenset or not allowed_clients
            or len(allowed_clients) > 64
            or any(not isinstance(x, str) or not IDENTITY.fullmatch(x)
                   for x in allowed_clients)):
            raise ValueError("Immutable, exact OAuth client enrollment required")
        if not callable(is_revoked_or_disallowed):
            raise ValueError("Mandatory trusted token revocation/consent check missing")
        if (type(max_token_age_seconds) is not int or not 60 <= max_token_age_seconds <= 3600
            or type(leeway_seconds) is not int or not 0 <= leeway_seconds <= 30):
            raise ValueError("Invalid bounded access-token validity policy")
        self.issuer = issuer
        self.audience = audience
        self.allowed_clients = allowed_clients
        self.max_age = max_token_age_seconds
        self.leeway = leeway_seconds
        self.revocation = is_revoked_or_disallowed
        # Immutable in-memory trust snapshot. Provisioning/rotation must refresh
        # the trusted file AND its expected SHA under administrative review.
        self.keys = _pinned_public_jwks(jwks_file, expected_jwks_sha256)

    def __call__(self, authorization_header: str) -> AuthenticatedUser:
        try:
            return self._verify(authorization_header)
        except Exception as exc:
            # Do not expose token header/claims, revoked identity or key material.
            raise InvalidAccessToken("invalid OAuth access token") from None

    def _verify(self, authorization_header: str) -> AuthenticatedUser:
        if (not isinstance(authorization_header, str)
            or not authorization_header.startswith("Bearer ")
            or len(authorization_header) > MAX_BEARER_CHARS + 7):
            raise ValueError("unacceptable bearer envelope")
        token = authorization_header[7:]
        if (not token or len(token) > MAX_BEARER_CHARS
            or any(ch.isspace() for ch in token)):
            raise ValueError("invalid bearer encoding")
        header = jwt.get_unverified_header(token)
        if (not isinstance(header, dict) or header.get("alg") != ALGORITHM
            or header.get("typ") not in ACCESS_TOKEN_TYPES
            or not isinstance(header.get("kid"), str)
            or not KID.fullmatch(header["kid"])
            or set(header) - {"alg", "typ", "kid"}):
            raise ValueError("non-access-token JOSE header")
        key = self.keys.get(header["kid"])
        if key is None:
            raise ValueError("issuer signing key unavailable")
        claims = jwt.decode(
            token, key=key, algorithms=[ALGORITHM], issuer=self.issuer,
            audience=self.audience, leeway=self.leeway,
            options={"require": [
                "iss", "sub", "aud", "exp", "iat", "jti",
                "client_id", "scope", "tenant",
            ]},
        )
        if not isinstance(claims, dict) or type(claims.get("aud")) is not str:
            raise ValueError("Access token must target exactly one resource")
        if claims["aud"] != self.audience:
            raise ValueError("Token resource audience mismatch")
        # `iss` is independently checked by the signature library against the
        # configured HTTPS issuer; account/client/tenant IDs are opaque exact
        # labels, never URL path components or traversal strings.
        for k in ("sub", "client_id", "tenant"):
            v = claims.get(k)
            if (type(v) is not str or not IDENTITY.fullmatch(v)
                or v in (".", "..") or ".." in v):
                raise ValueError("Token identity claim invalid")
        if claims["client_id"] not in self.allowed_clients:
            raise ValueError("Unenrolled OAuth application")
        jti = claims.get("jti")
        if not isinstance(jti, str) or not JTI.fullmatch(jti):
            raise ValueError("Missing or invalid exact JWT identity")
        now = int(time.time())
        if (type(claims.get("iat")) is not int
            or type(claims.get("exp")) is not int
            or claims["iat"] > now + self.leeway
            or claims["iat"] < now - self.max_age - self.leeway
            or claims["exp"] <= now
            or claims["exp"] > now + self.max_age
            or claims["exp"] - claims["iat"] > self.max_age
            or claims["exp"] <= claims["iat"]):
            raise ValueError("Access token is stale, future-dated or overlong")
        if "nbf" in claims and type(claims["nbf"]) is not int:
            raise ValueError("Invalid not-before claim")
        scope = claims["scope"]
        if not isinstance(scope, str) or len(scope) > 4096 or not scope:
            raise ValueError("Missing scope string")
        scopes = scope.split(" ")
        if (not 1 <= len(scopes) <= 64 or len(scopes) != len(set(scopes))
            or any(not SCOPE.fullmatch(v) for v in scopes)):
            raise ValueError("Malformed scope grant")
        # This is a trusted in-process synchronous service, NOT a model
        # parameter. Never convert a revocation timeout/error into allow.
        revoked = self.revocation(
            self.issuer, claims["client_id"], claims["sub"],
            claims["tenant"], jti,
        )
        if type(revoked) is not bool or revoked:
            raise ValueError("Token authorization or revocation check denied")
        return AuthenticatedUser(
            issuer=self.issuer, audience=self.audience,
            subject=claims["sub"], tenant=claims["tenant"],
            expires_at=claims["exp"], scopes=frozenset(scopes),
        )
