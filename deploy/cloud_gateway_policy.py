#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Transport-independent PUBLIC GATEWAY *policy core*, not an HTTP MCP server.

This module deliberately has NO listener, authentication implementation, agent
network transport, OAuth tokens, or copy of hepta-runtime execution logic.
A future real HTTPS/OAuth 2.1 boundary must cryptographically verify the caller,
and a separately authenticated outbound-agent channel must verify device mTLS
identity. Only their already-verified identities may reach this object.

Until those required components exist and pass external/tenant review, this
source cannot be deployed, connected to ChatGPT, or sold as a public plugin.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import threading
import time
from typing import Callable, FrozenSet

from mcp_tool_contract import ToolContract, canonical

# Exact 50-tool v4 release; a new catalog requires an explicit review bump.
APPROVED_CATALOG_SHA256 = "63742708c287e8468d73f27ba85ecc6585afd4adcd76d06b618456730cfaf8ad"

NAME = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ALLOWED_OPERATION_ID = re.compile(r"[A-Za-z0-9_.:-]{8,128}\Z")
HIGH_PRIVILEGE = frozenset({
    "sudo_start", "host_signal", "process_checkpoint", "privileged_action",
})
# These are native file paths, not opaque identifiers. Controller-local
# workspace checks apply to EVERY known path-bearing parameter, including
# execution working directories, PDF outputs and password/trust files.
LOCAL_PATH_FIELDS = frozenset({
    "path", "source", "destination", "from_path", "append_path",
    "cwd", "output_path", "source_path", "password_file",
    "output_owner_password_file", "output_user_password_file", "trust_store_file",
})
# A public isolated agent must never choose its account home implicitly for
# operations that can launch an executable. The caller supplies a tenant-root
# cwd and the agent independently checks its own OS-enforced working root.
EXPLICIT_CWD_TOOLS = frozenset({
    "shell_start", "process_start", "pty_start", "sudo_start",
})
# Shell/PTY process execution additionally requires an isolated per-device agent
# with explicit OS authority; JSON path checks are not a sandbox.
EXECUTION_TOOLS = frozenset({
    "shell_start", "process_start", "pty_start", "pty_write", "sudo_start",
    "host_signal", "privileged_action", "process_checkpoint",
})


class Rejected(PermissionError):
    """A stable, credential-free denial safe to return to a frontend."""

    def __init__(self, code: str):
        if not re.fullmatch(r"[A-Z_]{4,60}", code):
            raise ValueError("invalid denial code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AuthenticatedUser:
    """Must be constructed ONLY by a genuine token-verifying ingress adapter."""

    issuer: str
    audience: str
    subject: str
    tenant: str
    expires_at: int
    scopes: FrozenSet[str]


@dataclass(frozen=True)
class AuthenticatedAgent:
    """From verified mTLS AND a validated per-tenant agent runtime manifest.

    The future network transport must cryptographically bind this attestation;
    a caller cannot simply submit these values in an MCP tool request.
    """

    device_id: str
    cert_sha256: str
    connection_generation: int
    tenant: str
    subject: str
    workspace_root: str
    configured_host_aliases: FrozenSet[str]
    native_catalog_sha256: str
    tenant_runtime_isolated: bool


@dataclass(frozen=True)
class TenantBinding:
    """Admin-enrolled exact tenant-user-device authorization; no wildcards."""

    issuer: str
    audience: str
    subject: str
    tenant: str
    device_id: str
    cert_sha256: str
    connection_generation: int
    expires_at: int
    allowed_tools: FrozenSet[str]
    allowed_hosts: FrozenSet[str]
    local_workspace_root: str
    elevated_tools: FrozenSet[str] = frozenset()
    revoked: bool = False


@dataclass(frozen=True)
class DispatchPermit:
    """Opaque internal decision. MUST NOT be serialized to an MCP caller."""

    tenant: str
    subject: str
    device_id: str
    connection_generation: int
    tool_name: str
    call_id: str
    request_sha256: str
    mutating: bool


class OnceOnlyLedger:
    """Durable admit-once guard. No raw arguments, tokens, results or credentials.

    A repeated request ID is rejected even if the original response was lost.
    There is deliberately no automatic result cache or silent retry of writes.
    A production deploy must preserve this DB across crashes and keep it private.
    """

    def __init__(self, path: str | Path):
        path = Path(path)
        if not path.is_absolute():
            raise ValueError("Ledger path must be absolute")
        parent = path.parent
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("Private account-owned ledger directory required")
        if path.is_symlink():
            raise PermissionError("Refuse a symlink ledger file")
        self._lock = threading.RLock()
        self.path = path
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS mutation_requests (
                    tenant_key TEXT NOT NULL,
                    subject_key TEXT NOT NULL,
                    device_key TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    call_id TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('reserved','completed','unknown')),
                    -- Connection generations rotate during reconnect. An old
                    -- unacknowledged write MUST remain blocked after reconnect.
                    PRIMARY KEY(tenant_key,subject_key,device_key,call_id)
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        # SQLite accesses a private account-owned database file in a private
        # directory. DB-specific storage permissions are checked after creation.
        # SQLite's default initial creation can inherit a process umask that
        # makes the database readable. Pre-create it without widening the
        # global process umask. The private parent excludes other user IDs.
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("Ledger must remain account-owned and private")
        db = sqlite3.connect(str(self.path), timeout=10)
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            db.close()
            raise PermissionError("Ledger must remain account-owned and private")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA journal_mode=DELETE")
        return db

    def reserve(self, permit: DispatchPermit) -> None:
        with self._lock, self._connect() as db:
            try:
                db.execute("""
                    INSERT INTO mutation_requests (
                        tenant_key,subject_key,device_key,generation,call_id,payload_sha256,state
                    ) VALUES (?,?,?,?,?,?, 'reserved')
                """, (
                    _digest_id(permit.tenant), _digest_id(permit.subject),
                    _digest_id(permit.device_id), permit.connection_generation,
                    permit.call_id, permit.request_sha256
                ))
            except sqlite3.IntegrityError as exc:
                raise Rejected("RECONCILE_PRIOR_CALL") from exc

    def finalize(self, permit: DispatchPermit, *, completed: bool) -> None:
        with self._lock, self._connect() as db:
            cur = db.execute("""
                UPDATE mutation_requests SET state=?
                WHERE tenant_key=? AND subject_key=? AND device_key=?
                AND generation=? AND call_id=? AND payload_sha256=? AND state='reserved'
            """, (
                "completed" if completed else "unknown",
                _digest_id(permit.tenant), _digest_id(permit.subject),
                _digest_id(permit.device_id), permit.connection_generation,
                permit.call_id, permit.request_sha256
            ))
            if cur.rowcount != 1:
                raise Rejected("RECONCILE_PRIOR_CALL")

    def state(self, permit: DispatchPermit) -> str | None:
        with self._lock, self._connect() as db:
            row = db.execute("""
                SELECT state FROM mutation_requests
                WHERE tenant_key=? AND subject_key=? AND device_key=?
                AND generation=? AND call_id=?
            """, (
                _digest_id(permit.tenant), _digest_id(permit.subject),
                _digest_id(permit.device_id), permit.connection_generation, permit.call_id
            )).fetchone()
            return row[0] if row else None


def _digest_id(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _identity_field(value: str) -> bool:
    return isinstance(value, str) and bool(NAME.fullmatch(value)) and "*" not in value


def _safe_path(root: str, path: str) -> bool:
    # Defense-in-depth only: the enrolled agent MUST recheck these paths using
    # its own fd-relative or canonical native workspace and symlink policy.
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        return False
    if path.startswith(("ssh://", "sftp://")):
        return False
    if not path.startswith("/") or "//" in path:
        return False
    raw_parts = path.split("/")
    if any(part in (".", "..") for part in raw_parts):
        return False
    return PurePosixPath(path).is_relative_to(PurePosixPath(root))


def _check_nested_file_sources(tool_name: str, arguments: dict,
                               tenant_root: str) -> None:
    """Check schema-known paths in structured PDF operations and assets.

    Never search content, form fields, model-written strings or arbitrary
    spreadsheets for words such as 'path': those are user *data*. Only known
    file-resource structures convey an additional local-path authority.
    """
    member = {"pdf_edit": ("operations", "source_path"),
              "document_render": ("assets", "path")}.get(tool_name)
    if member is None or member[0] not in arguments:
        return
    collection = arguments[member[0]]
    if not isinstance(collection, list) or any(not isinstance(v, dict) for v in collection):
        raise Rejected("INVALID_ARGUMENTS")
    for item in collection:
        if member[1] in item and not _safe_path(tenant_root, item[member[1]]):
            raise Rejected("PATH_OUTSIDE_TENANT_WORKSPACE")


class GatewayPolicy:
    """Decision only. Does not create a publicly reachable HTTP route."""

    def __init__(
        self, contract: ToolContract, ledger: OnceOnlyLedger,
        token_verifier: Callable[[str], AuthenticatedUser],
        bindings: tuple[TenantBinding, ...],
        *, now: Callable[[], int] | None = None,
        resource: str,
    ):
        if not contract.tools or contract.catalog_sha256 != APPROVED_CATALOG_SHA256:
            raise ValueError("Explicitly reviewed public v4 tool contract required")
        url = urlsplit(resource)
        if (url.scheme != "https" or not url.hostname or url.hostname in
            ("localhost", "127.0.0.1", "::1") or url.username or url.password
            or url.path != "/mcp" or url.query or url.fragment):
            raise ValueError("Explicit stable HTTPS /mcp resource required")
        self.contract = contract
        self.ledger = ledger
        self.token_verifier = token_verifier
        self.now = now if now is not None else lambda: int(time.time())
        self.resource = resource
        self.bindings: dict[tuple[str,str,str,str], TenantBinding] = {}
        for binding in bindings:
            if not all(_identity_field(x) for x in (
                binding.issuer, binding.audience, binding.subject,
                binding.tenant, binding.device_id,
            )):
                raise ValueError("Invalid, wildcard or missing enrollment identity")
            if not HEX64.fullmatch(binding.cert_sha256):
                raise ValueError("Exact sha256 mTLS certificate fingerprint required")
            if (type(binding.connection_generation) is not int
                or type(binding.expires_at) is not int
                or binding.connection_generation <= 0 or binding.expires_at <= 0):
                raise ValueError("Generation and expiration must be positive integers")
            root = binding.local_workspace_root
            if not isinstance(root, str) or not root.startswith("/") or root == "/" or not _safe_path(root, root):
                raise ValueError("Public tenant needs a private non-root absolute workspace")
            # Frozen dataclass fields alone do not freeze nested sets. Mutable
            # authorizations could otherwise be widened after enrollment and
            # silently affect subsequent tool discovery and dispatch.
            if any(type(items) is not frozenset for items in (
                    binding.allowed_tools, binding.elevated_tools, binding.allowed_hosts)):
                raise ValueError("Enrollment tool, elevated and host allowlists must be immutable frozensets")
            if not binding.allowed_tools <= contract.by_name.keys():
                raise ValueError("Enrolled tool names must be in the immutable catalog")
            if not binding.elevated_tools <= HIGH_PRIVILEGE:
                raise ValueError("Elevated scopes must name exact elevated operations")
            if not all(_identity_field(host) for host in binding.allowed_hosts):
                raise ValueError("Configured host aliases must be exact")
            key = (binding.issuer,binding.tenant,binding.subject,binding.device_id)
            if key in self.bindings:
                raise ValueError("Conflicting device enrollment")
            self.bindings[key] = binding

    def _authenticated_binding(self, authorization_header: str,
                               agent: AuthenticatedAgent):
        if not isinstance(authorization_header, str) or not authorization_header.startswith("Bearer "):
            raise Rejected("OAUTH_REQUIRED")
        # The verifier MUST validate issuer/JWKS signature, audience/resource,
        # expiry, token revocation and user consents per OAuth 2.1. This module
        # never parses user-supplied claims from an MCP request.
        try:
            user = self.token_verifier(authorization_header)
        except Exception as exc:
            raise Rejected("OAUTH_INVALID") from exc
        if not isinstance(user, AuthenticatedUser):
            raise Rejected("OAUTH_INVALID")
        now = self.now()
        # Dataclass annotations are not runtime validators. A poorly formed
        # verifier result with a string/list/dict `scopes` could otherwise
        # pass membership tests by substring/key lookup. Normalize and type
        # check all claims at the independently trusted verifier boundary.
        if (type(user.scopes) is not frozenset
            or any(not isinstance(scope,str) or not 1 <= len(scope) <= 128
                   for scope in user.scopes)
            or type(user.expires_at) is not int
            or not all(_identity_field(x) for x in
                       (user.issuer,user.audience,user.subject,user.tenant))
            or user.audience != self.resource
            or user.expires_at <= now or user.expires_at > now + 24*60*60
            or "hepta:connect" not in user.scopes):
            raise Rejected("OAUTH_INVALID")
        if (not isinstance(agent, AuthenticatedAgent)
            or not _identity_field(agent.device_id)
            or not isinstance(agent.cert_sha256,str)
            or not HEX64.fullmatch(agent.cert_sha256)
            or type(agent.connection_generation) is not int
            or agent.connection_generation <= 0
            or type(agent.configured_host_aliases) is not frozenset
            or not all(_identity_field(host) for host in agent.configured_host_aliases)
            or not _identity_field(agent.tenant)
            or not _identity_field(agent.subject)):
            raise Rejected("AGENT_IDENTITY_INVALID")
        binding = self.bindings.get((user.issuer,user.tenant,user.subject,agent.device_id))
        if (binding is None or binding.revoked or binding.expires_at <= now
            or binding.audience != self.resource
            or binding.cert_sha256 != agent.cert_sha256
            or binding.connection_generation != agent.connection_generation):
            raise Rejected("TENANT_DEVICE_NOT_AUTHORIZED")
        # Do not enroll the existing single-user controller as a public tenant:
        # its configured controller workspace can be the entire filesystem.
        # The future authenticated agent handshake MUST attest these attributes.
        if (agent.tenant != user.tenant or agent.subject != user.subject
            or agent.workspace_root != binding.local_workspace_root
            or agent.workspace_root == "/"
            or agent.native_catalog_sha256 != self.contract.catalog_sha256
            or agent.configured_host_aliases != binding.allowed_hosts
            or agent.tenant_runtime_isolated is not True):
            raise Rejected("AGENT_CONFIG_MISMATCH")
        return user, binding

    def _require_unchanged_native_catalog(self) -> None:
        # Neither Python's frozen dataclasses nor a file-level SHA protects
        # nested live tool dictionaries from accidental in-process mutation.
        # Check the reviewed digest AND the name index on each admission.
        try:
            if self.contract.catalog_sha256 != APPROVED_CATALOG_SHA256:
                raise ValueError('unexpected version')
            self.contract.verify_integrity()
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise Rejected("CATALOG_DRIFT") from exc

    def authorized_tool_names(self, authorization_header: str,
                              agent: AuthenticatedAgent) -> FrozenSet[str]:
        """An authenticated per-user discovery subset; no model-supplied ACL.

        The public /mcp adapter MUST call this for each tools/list, and invoke
        prepare independently before tools/call. No empty/anonymous fallback.
        """
        user,binding=self._authenticated_binding(authorization_header,agent)
        self._require_unchanged_native_catalog()
        approved=set()
        for name in binding.allowed_tools:
            if not self.contract.read_only(name) and 'hepta:write' not in user.scopes:
                continue
            if name in EXECUTION_TOOLS and 'hepta:execute' not in user.scopes:
                continue
            if name in HIGH_PRIVILEGE and (name not in binding.elevated_tools
                                           or 'hepta:privileged' not in user.scopes):
                continue
            approved.add(name)
        return frozenset(approved)

    def prepare(
        self, authorization_header: str, agent: AuthenticatedAgent,
        tool_name: str, arguments: dict, call_id: str,
    ) -> DispatchPermit:
        user,binding=self._authenticated_binding(authorization_header,agent)
        self._require_unchanged_native_catalog()
        if not isinstance(tool_name,str) or tool_name not in self.contract.by_name:
            raise Rejected("TOOL_UNKNOWN")
        if tool_name not in binding.allowed_tools:
            raise Rejected("TOOL_NOT_GRANTED")
        if not isinstance(arguments,dict):
            raise Rejected("INVALID_ARGUMENTS")
        try:
            if len(canonical(arguments)) > 4*1024*1024:
                raise Rejected("INVALID_ARGUMENTS")
        except (TypeError,ValueError,OverflowError) as exc:
            raise Rejected("INVALID_ARGUMENTS") from exc
        # Only literal schema property names may cross the tenancy boundary.
        schema_props = self.contract.by_name[tool_name]["inputSchema"].get("properties",{})
        if not isinstance(schema_props,dict) or any(k not in schema_props for k in arguments):
            raise Rejected("INVALID_ARGUMENTS")
        for k, val in arguments.items():
            if k == "host":
                if not isinstance(val,str) or val not in binding.allowed_hosts:
                    raise Rejected("HOST_NOT_ENROLLED")
            elif k in LOCAL_PATH_FIELDS:
                # The public agent never inherits the private controller's
                # home, generic filesystem roots, or implicit SSH paths.
                if not _safe_path(binding.local_workspace_root, val):
                    raise Rejected("PATH_OUTSIDE_TENANT_WORKSPACE")
        _check_nested_file_sources(tool_name, arguments, binding.local_workspace_root)
        mutated = not self.contract.read_only(tool_name)
        if mutated and "hepta:write" not in user.scopes:
            raise Rejected("WRITE_SCOPE_REQUIRED")
        if tool_name in EXECUTION_TOOLS and "hepta:execute" not in user.scopes:
            raise Rejected("EXECUTE_SCOPE_REQUIRED")
        if tool_name in HIGH_PRIVILEGE and (
            tool_name not in binding.elevated_tools or "hepta:privileged" not in user.scopes
        ):
            raise Rejected("ELEVATED_ACTION_NOT_GRANTED")
        if tool_name in EXECUTION_TOOLS and "host" in schema_props:
            if arguments.get("host") not in binding.allowed_hosts:
                raise Rejected("HOST_NOT_ENROLLED")
        if tool_name in EXPLICIT_CWD_TOOLS:
            if not _safe_path(binding.local_workspace_root, arguments.get("cwd")):
                raise Rejected("PATH_OUTSIDE_TENANT_WORKSPACE")
        if not isinstance(call_id,str) or not ALLOWED_OPERATION_ID.fullmatch(call_id):
            raise Rejected("INVALID_CALL_ID")
        digest = hashlib.sha256(canonical({
            "tool":tool_name,"arguments":arguments,
            "catalog":self.contract.catalog_sha256
        })).hexdigest()
        permit = DispatchPermit(
            tenant=user.tenant,subject=user.subject,device_id=agent.device_id,
            connection_generation=agent.connection_generation,tool_name=tool_name,
            call_id=call_id,request_sha256=digest,mutating=mutated,
        )
        if mutated:
            self.ledger.reserve(permit)
        return permit

    def mark_delivered(self, permit: DispatchPermit, *, confirmed: bool) -> None:
        if not permit.mutating:
            return
        self.ledger.finalize(permit, completed=confirmed)
