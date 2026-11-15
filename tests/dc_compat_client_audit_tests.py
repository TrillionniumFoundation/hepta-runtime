# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent client/cutover regressions; fresh own process, no systemctl."""
import asyncio
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'deploy'))
from dc_compat.processes import ProcessManager
from dc_compat import maintenance as upgrade


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


client = load('hepta_computer_client_audit_fixture', REPO / 'deploy/hepta_computer_client.py')


def result(value):
    return {'content': [{'type': 'text', 'text': json.dumps(value)}]}


class Proxy:
    def __init__(self, replies):
        self.replies, self.requests = iter(replies), []

    def dispatch(self, request):
        self.requests.append(request)
        return next(self.replies)


class ClientAudit(unittest.TestCase):
    def test_poll_transport_failure_preserves_already_accepted_call_identity(self):
        identity = 'hepta-call-original-effect-owned-proof'
        proxy = Proxy([{'result': result({'status': 'running', 'call_id': identity,
            'automatic_retry': False, 'next_action': 'get_tool_result', 'provider': 'Hepta Runtime'})},
            {'error': {'code': -32070, 'message': 'Original result temporarily unavailable',
                'data': {'outcome': 'unavailable', 'automatic_retry': False}}}])
        try:
            reply = client.invoke(proxy, 'computer_key', {'keys': ['ENTER']}, 1)
        except RuntimeError as error:
            self.assertIn(identity, str(error), 'A poll error lost the accepted effect ID required for read-only resumption')
        else:
            self.assertIn(identity, json.dumps(reply), 'A poll error lost the accepted effect ID required for read-only resumption')
        self.assertEqual([item['params']['name'] for item in proxy.requests], ['computer_key', 'get_tool_result'])


class UpgradeGateAudit(unittest.IsolatedAsyncioTestCase):
    async def test_collector_unknown_with_real_live_child_must_refuse_owner_stop(self):
        with tempfile.TemporaryDirectory(prefix='hepta-upgrade-gate-audit-') as temporary:
            state = Path(temporary)
            manager = ProcessManager(state / 'processes', state, shell='/bin/sh')
            try:
                command = 'exec ' + shlex.quote(sys.executable) + ' -u -c ' + shlex.quote("import time;print('owned-private-child',flush=True);time.sleep(30)")
                # An actual output-journal failure is a supported route to an
                # unknown receipt while the process itself remains alive.
                with mock.patch.object(manager, '_write_all', side_effect=OSError('private fixture simulated disk failure')):
                    await manager.invoke('start_process', {'command': command, 'timeout_ms': 1000})
                session = next(iter(manager.sessions.values()))
                await asyncio.wait_for(asyncio.to_thread(session.collector.join), 2)
                self.assertEqual(session.metadata['state'], 'unknown')
                self.assertIsNone(session.process.poll(), 'Fixture must prove the child is genuinely alive')
                with self.assertRaises((AssertionError, RuntimeError, ValueError),
                        msg='Unknown collection state is not proof that this real child is safe to stop'):
                    upgrade.assert_no_live_workers(state)
                self.assertIsNone(session.process.poll())
            finally:
                await asyncio.to_thread(manager.close)


if __name__ == '__main__': unittest.main()
