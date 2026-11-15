#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Shared syntax-only public URL admission for offline Gateway policy/metadata.

A URL passing this check is NOT proof of DNS ownership, live HTTPS, PKI trust,
OAuth verification or absence of DNS rebinding. Those require the future
independent ingress and authenticated outbound agent.
"""
import ipaddress
import re
from urllib.parse import urlsplit

LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
NONPUBLIC_SUFFIXES = (
    'localhost', 'local', 'localdomain', 'lan', 'internal',
    'invalid', 'home.arpa',
)


def public_https_url(value, *, resource):
    """Admit a DNS-named HTTPS resource `/mcp` or an OAuth issuer origin.

    Use stable ordinary HTTPS on port 443, not a local/private IP, URL
    user-info, parser-ambiguous authority or a named host with local suffix.
    Offline fixtures use *.example.test DNS syntax without real DNS lookup.
    """
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError('Canonical public HTTPS URL required')
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ValueError('Whitespace and control characters are not allowed in public URLs')
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port  # Accessing this property rejects malformed ports.
    except ValueError as exc:
        raise ValueError('Invalid HTTPS host or port') from exc
    if (parsed.scheme != 'https' or not host or parsed.username is not None
        or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError('Public URL requires an HTTPS DNS origin without credentials or fragments')
    if port not in (None, 443):
        raise ValueError('Public HTTPS endpoints must use the standard port')
    host = host.lower()
    if len(host) > 253 or host.endswith('.'):
        raise ValueError('Invalid canonical public hostname')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError('IP literals are not accepted as public app origins')
    labels = host.split('.')
    if (len(labels) < 2 or any(not LABEL.fullmatch(label) for label in labels)
        or labels[-1].isdigit()):
        raise ValueError('Stable public DNS hostname required')
    if any(host == suffix or host.endswith('.' + suffix)
           for suffix in NONPUBLIC_SUFFIXES):
        raise ValueError('Local and special-use DNS names are not public origins')
    expected_authority = host + (':443' if port == 443 else '')
    if parsed.netloc.lower() != expected_authority:
        raise ValueError('Non-canonical HTTPS authority')
    if resource:
        if parsed.path != '/mcp':
            raise ValueError('Public MCP resource must be exactly /mcp')
    elif parsed.path not in ('', '/'):
        raise ValueError('OAuth issuer must be an HTTPS origin without a path')
    return parsed
