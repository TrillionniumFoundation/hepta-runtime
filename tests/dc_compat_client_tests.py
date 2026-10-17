# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""A timed-out computer action must retain its identity instead of replaying."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'deploy/hepta_computer_client.py'
spec = importlib.util.spec_from_file_location('hepta_computer_client', SOURCE)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def result(value, **extra):
    return {'content': [{'type': 'text', 'text': json.dumps(value)}], **extra}


class Proxy:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def dispatch(self, request):
        self.requests.append(request)
        return next(self.responses)


class ClientTests(unittest.TestCase):
    def test_deadline_preserves_original_receipt_without_action_replay(self):
        receipt = result({'status': 'running', 'call_id': 'accepted-once'})
        proxy = Proxy([{'result': receipt}])
        self.assertEqual(client.invoke(proxy, 'computer_key', {'keys': ['ENTER']}, 0), receipt)
        self.assertEqual(len(proxy.requests), 1)

    def test_polling_reads_same_call_and_preserves_original_failure(self):
        failure = result('Device disconnected after key submission', isError=True)
        proxy = Proxy([{'result': result({'status': 'running', 'call_id': 'one'})},
            {'result': result({'status': 'executing', 'call_id': 'one'})},
            {'result': result({'status': 'failed', 'call_id': 'one', 'result': failure})}])
        self.assertEqual(client.invoke(proxy, 'computer_key', {'keys': ['ENTER']}, 2), failure)
        self.assertEqual([x['params']['name'] for x in proxy.requests],
            ['computer_key', 'get_tool_result', 'get_tool_result'])
        self.assertTrue(all(x['params']['arguments'] == {'call_id': 'one'} for x in proxy.requests[1:]))
        self.assertEqual(len({x['id'] for x in proxy.requests}), 3)

    def test_unknown_terminal_receipt_is_returned_without_replaying(self):
        unknown = result({'status': 'unknown', 'call_id': 'one'})
        proxy = Proxy([{'result': result({'status': 'running', 'call_id': 'one'})}, {'result': unknown}])
        self.assertEqual(client.invoke(proxy, 'computer_mouse', {'action': 'click'}, 2), unknown)
        self.assertEqual(len(proxy.requests), 2)

    def test_transport_failure_is_not_retried(self):
        proxy = Proxy([{'error': {'code': -32000, 'message': 'Delivery unknown'}}])
        with self.assertRaisesRegex(RuntimeError, 'not retried'):
            client.invoke(proxy, 'computer_key', {'keys': ['ENTER']}, 1)
        self.assertEqual(len(proxy.requests), 1)

    def test_configuration_rejects_symlink_and_nonprivate_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'config.json'
            path.write_text('{"release":"/immutable/release"}')
            path.chmod(0o600)
            self.assertEqual(client.private_configuration(path)['release'], '/immutable/release')
            link = path.with_name('link'); link.symlink_to(path)
            with self.assertRaises(ValueError): client.private_configuration(link)
            path.chmod(0o644)
            with self.assertRaises(ValueError): client.private_configuration(path)


if __name__ == '__main__':
    unittest.main()
