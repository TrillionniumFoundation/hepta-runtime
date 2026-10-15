#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline public Gateway HTTPS authority syntax checks, not network ownership."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'deploy'))
from cloud_gateway_https import public_https_url
from cloud_gateway_mcp_catalog import (
    oauth_protected_resource_metadata, oauth_challenge,
)

BAD_HOSTS = (
    '127.0.0.2', '10.9.8.7', '192.168.3.2', '172.16.0.1',
    '[::1]', '[fe80::1]', '[fc00::2]', '[::ffff:127.0.0.1]',
    '127.1', '127.0.1', 'localhost.localdomain',
    'agent.local', 'gateway.internal', 'gateway.lan',
    'example.invalid', 'example.home.arpa', 'localhost',
    'singlelabel', 'gateway.example.test.', 'bad_.example.test',
    '-bad.example.test', 'bad-.example.test',
)
BAD_PORTS = (':bad', ':0', ':22', ':80', ':8080', ':65536', ':0443')

class OfflineHttpsAuthority(unittest.TestCase):
    def test_public_resource_dns_fixtures_and_explicit_standard_port(self):
        for url in ('https://mcp.example.test/mcp',
                    'https://gateway.example.test:443/mcp',
                    'https://xn--bcher-kva.example/mcp'):
            with self.subTest(url=url):
                p = public_https_url(url, resource=True)
                self.assertEqual(p.scheme, 'https')
                self.assertEqual(p.path, '/mcp')

    def test_reject_every_observed_private_ip_and_special_dns_suffix(self):
        for host in BAD_HOSTS:
            with self.subTest(host=host):
                url = 'https://' + host + '/mcp'
                with self.assertRaises(ValueError):
                    public_https_url(url, resource=True)
                with self.assertRaises(ValueError):
                    oauth_challenge(url, 'invalid_token')
                with self.assertRaises(ValueError):
                    public_https_url('https://' + host, resource=False)

    def test_invalid_ports_never_survive_urlsplit_lazy_port_parse(self):
        for port in BAD_PORTS:
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    public_https_url('https://mcp.example.test'+port+'/mcp',resource=True)
                with self.assertRaises(ValueError):
                    oauth_protected_resource_metadata(
                        'https://mcp.example.test/mcp','https://auth.example.test'+port)

    def test_no_credentials_control_whitespace_or_ambiguous_authority(self):
        bad = (
            'https://user:pass@mcp.example.test/mcp',
            'https://mcp.example.test:/mcp',
            'https://mcp.example.test/mcp?q=1',
            'https://mcp.example.test/mcp#fragment',
            'https://mcp.example.test/mcp\nHeader: evil',
            ' https://mcp.example.test/mcp',
            'https://mcp.example.test/mcp ',
            'https://mcp.example.test/another',
            'https://mcp.example.test/mcp/../mcp',
            'http://mcp.example.test/mcp',
        )
        for url in bad:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    public_https_url(url,resource=True)

    def test_valid_issuer_origin_and_invalid_issuer_paths(self):
        for value in ('https://auth.example.test',
                      'https://auth.example.test/',
                      'https://auth.example.test:443'):
            with self.subTest(issuer=value):
                self.assertEqual(public_https_url(value,resource=False).scheme,'https')
                metadata = oauth_protected_resource_metadata(
                    'https://mcp.example.test/mcp',value)
                self.assertTrue(metadata['authorization_servers'][0].startswith('https://'))
        for bad in ('https://auth.example.test/mcp',
                    'https://auth.example.test/anything',
                    'https://auth.example.test/?x=1',
                    'https://127.0.0.2'):
            with self.subTest(issuer=bad):
                with self.assertRaises(ValueError):
                    oauth_protected_resource_metadata(
                        'https://mcp.example.test/mcp',bad)

if __name__ == '__main__':
    unittest.main(verbosity=2)
