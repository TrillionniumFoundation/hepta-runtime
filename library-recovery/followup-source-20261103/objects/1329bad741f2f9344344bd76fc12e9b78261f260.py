"""Local executable negative cases for proposed Hepta Runtime HTTP ingress policy.
Does not substitute for Rust compile / real bind tests on exact candidate.
"""
import ipaddress
import unittest


def permit_http_bind(address: str, has_private_token: bool) -> bool:
    """Reference model: refuse absent auth or non-loopback bind."""
    if not has_private_token:
        return False
    try:
        if address.startswith('['):
            host, port = address[1:].split(']:', 1)
        else:
            host, port = address.rsplit(':', 1)
        return ipaddress.ip_address(host).is_loopback and 1 <= int(port) <= 65535
    except (ValueError, IndexError):
        return False


class HttpMcpAdmission(unittest.TestCase):
    def test_loopback_with_token_only(self):
        for addr in ('127.0.0.1:12345', '[::1]:12345'):
            with self.subTest(addr=addr):
                self.assertTrue(permit_http_bind(addr, True))
                self.assertFalse(permit_http_bind(addr, False))

    def test_wildcard_remote_and_malformed_addresses_fail_closed(self):
        for addr in ('0.0.0.0:12345', '[::]:12345', '10.0.0.42:12345',
                     '192.168.1.2:12345', 'invalid:12345', '127.0.0.1:0'):
            with self.subTest(addr=addr):
                self.assertFalse(permit_http_bind(addr, True))

if __name__ == '__main__':
    unittest.main(verbosity=2)
