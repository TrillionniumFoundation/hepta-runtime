#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""OFFLINE public MCP catalog and OAuth metadata builder; no HTTP listener.

Takes tool definitions from the exact reviewed native v4 catalog. Adds truthful
per-tool OAuth security schemes, never changes tool names/parameters/annotations.
Requires an explicit reviewed list of public tools, not automatic publication
of all native shell/sudo operations. This module does NOT verify access tokens;
that belongs to a separate required OAuth 2.1 resource-server implementation.
"""
import copy
from urllib.parse import urlsplit, urlunsplit

from cloud_gateway_policy import (
    APPROVED_CATALOG_SHA256, EXECUTION_TOOLS, HIGH_PRIVILEGE,
    GatewayPolicy, AuthenticatedAgent,
)
from mcp_tool_contract import ToolContract

VERSION='2026-07-28'
SERVER_INFO='io.modelcontextprotocol/serverInfo'
SCOPES=frozenset({'hepta:connect','hepta:write','hepta:execute','hepta:privileged'})


def _valid_https_resource(url):
    if not isinstance(url,str) or any(ord(c)<32 for c in url):
        raise ValueError('HTTPS resource metadata cannot contain control characters')
    r=urlsplit(url)
    if (r.scheme!='https' or not r.hostname or r.hostname in ('localhost','127.0.0.1','::1')
        or r.username or r.password or r.path!='/mcp' or r.query or r.fragment):
        raise ValueError('Stable HTTPS /mcp public resource required')
    return r


def _valid_issuer(issuer):
    if not isinstance(issuer,str) or any(ord(c)<32 for c in issuer):
        raise ValueError('OAuth issuer must be a valid HTTPS origin')
    r=urlsplit(issuer)
    if (r.scheme!='https' or not r.hostname or r.hostname in ('localhost','127.0.0.1','::1')
        or r.username or r.password or r.query or r.fragment or r.path not in ('','/')):
        raise ValueError('OAuth issuer must be a stable HTTPS origin')
    return issuer.rstrip('/')


def _verify_reviewed_set(contract,approved):
    if not isinstance(contract,ToolContract) or contract.catalog_sha256!=APPROVED_CATALOG_SHA256:
        raise ValueError('Only immutable reviewed v4 native catalog is eligible')
    if not isinstance(approved,frozenset) or not approved:
        raise ValueError('A nonempty exact administrator-reviewed tool allowlist is mandatory')
    if not approved<=contract.by_name.keys():
        raise ValueError('Unreviewed or unknown public tool name')


def scopes_for_tool(contract,name):
    if name not in contract.by_name:
        raise ValueError('Unknown native tool')
    scopes={'hepta:connect'}
    if not contract.read_only(name):
        scopes.add('hepta:write')
    if name in EXECUTION_TOOLS:
        scopes.add('hepta:execute')
    if name in HIGH_PRIVILEGE:
        scopes.add('hepta:privileged')
    return sorted(scopes)


def reviewed_public_tools(contract,approved):
    """Return a new view; never mutate or relabel the private contract."""
    _verify_reviewed_set(contract,approved)
    result=[]
    for tool in contract.tools:
        if tool['name'] not in approved:
            continue
        if 'securitySchemes' in tool:
            raise ValueError('Unexpected embedded auth policy requires separate review')
        published=copy.deepcopy(tool)
        published['securitySchemes']=[{
            'type':'oauth2','scopes':scopes_for_tool(contract,tool['name'])
        }]
        result.append(published)
    return result


def _result(result,identity):
    return {
        'jsonrpc':'2.0','id':identity,
        'result':{
            'resultType':'complete','cacheScope':'private','ttlMs':0,
            '_meta':{SERVER_INFO:{
                'name':'hepta-public-gateway-candidate',
                'version':APPROVED_CATALOG_SHA256[:16]
            }},
            **result,
        },
    }


def discover_response(identity,contract,approved):
    _verify_reviewed_set(contract,approved)
    return _result({
        'supportedVersions':[VERSION],
        'capabilities':{'tools':{'listChanged':False}},
    },identity)


def tools_list_response(identity,contract,approved):
    tools=reviewed_public_tools(contract,approved)
    return _result({'tools':tools},identity)


def authenticated_tools_list_response(identity,policy,authorization_header,agent):
    """Only an attested agent plus a verified user may discover eligible tools.

    This is the REQUIRED catalog path for a future public ingress. The bare
    reviewed_public_tools helper is only for offline/admin approval flows and
    must never serve an anonymous or model-supplied allowlist. If the user has
    connect permission but no approved tool scopes, return zero tools rather
    than silently publishing privileged tool names.
    """
    if not isinstance(policy,GatewayPolicy):
        raise TypeError('Authenticated gateway policy instance required')
    approved=policy.authorized_tool_names(authorization_header,agent)
    if not approved:
        return _result({'tools':[]},identity)
    return tools_list_response(identity,policy.contract,approved)


def authenticated_discover_response(identity,policy,authorization_header,agent):
    """Validate same token and device admission before modern MCP discovery."""
    if not isinstance(policy,GatewayPolicy):
        raise TypeError('Authenticated gateway policy instance required')
    policy.authorized_tool_names(authorization_header,agent)
    if policy.contract.catalog_sha256!=APPROVED_CATALOG_SHA256:
        raise ValueError('Unreviewed native catalog')
    return _result({'supportedVersions':[VERSION],
                    'capabilities':{'tools':{'listChanged':False}}},identity)


def oauth_protected_resource_metadata(resource,issuer):
    r=_valid_https_resource(resource)
    issuer=_valid_issuer(issuer)
    return {
        'resource':resource,
        'authorization_servers':[issuer],
        'scopes_supported':sorted(SCOPES),
    }


def oauth_challenge(resource,reason):
    """Header VALUE only, for an unauthenticated caller.

    The actual HTTP adapter must emit 401 with this WWW-Authenticate value.
    The challenge itself never grants authority.
    """
    if reason not in ('invalid_token','insufficient_scope'):
        raise ValueError('Unknown authorization challenge reason')
    r=_valid_https_resource(resource)
    metadata=urlunsplit((r.scheme,r.netloc,
                         '/.well-known/oauth-protected-resource','',''))
    return (
        'Bearer resource_metadata="'+metadata+'", error="'+reason+'"'
    )
