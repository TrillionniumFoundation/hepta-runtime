import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kaggle_jobs import KaggleAdapter, submission_readiness
from kaggle_transport import AdapterError
from hepta_kaggle import main
from test_jobs import FakeTransport


class ReadinessTest(unittest.TestCase):
    def test_readiness_does_not_create_a_request_or_cloud_object(self):
        transport = FakeTransport()
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'uncreated-state'
            output = io.StringIO()
            with patch('hepta_kaggle.KaggleTransport', return_value=transport), contextlib.redirect_stdout(output):
                code = main(['--state-dir', str(state), 'readiness', '--request-id', 'task-1'])
            result = json.loads(output.getvalue())['result']
            self.assertEqual(code, 0)
            self.assertTrue(result['ready'])
            self.assertTrue(result['request_id_is_correlation_only'])
            self.assertTrue(result['submission_must_recheck'])
            self.assertFalse(result['owned_notebook_inventory']['target_checked'])
            self.assertFalse(result['cloud_mutation_performed'])
            self.assertFalse(state.exists())
            self.assertEqual([call[0] for call in transport.calls], ['list'])
            self.assertTrue(all(not call[2] for call in transport.calls))

    def test_private_placeholder_remains_blocked_with_diagnostic_receipt(self):
        transport = FakeTransport()
        transport.list_pages = {None: {'kernels': [
            {'ref': 'tester/owned-one'},
            {'title': '[Private Notebook]', 'lastRunTime': '2010-04-01T00:00:00Z'},
        ]}}
        result = submission_readiness(transport)
        self.assertFalse(result['ready'])
        self.assertEqual(result['error']['code'], 'NOTEBOOK_LIST_SCOPE')
        details = result['error']['details']
        self.assertEqual(details['item_number'], 2)
        self.assertTrue(details['redacted_private_placeholder'])
        self.assertFalse(details['all_pages_completed'])
        self.assertFalse(details['cloud_write_sent'])
        self.assertEqual(len(details['observed_page_sha256']), 64)
        self.assertNotIn('owned-one', json.dumps(result))

    def test_submit_still_blocks_placeholder_and_never_dispatches(self):
        transport = FakeTransport()
        transport.list_pages = {None: {'kernels': [{'title': '[Private Notebook]'}]}}
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            source = folder / 'test.py'
            source.write_text('print(1)\n')
            adapter = KaggleAdapter(transport, folder / 'state')
            with self.assertRaises(AdapterError) as error:
                adapter.submit(request_id='task-1', source=source)
            self.assertEqual(error.exception.code, 'NOTEBOOK_LIST_SCOPE')
            self.assertEqual(transport.count('submit'), 0)
            old = adapter.submit(request_id='task-1', source=source)
            self.assertEqual(old['remote_submission_state'], 'NOT_SENT')
            self.assertFalse(old['remote_effect_unknown'])
            self.assertEqual(transport.count('submit'), 0)

    def test_complete_paginated_inventory_required_for_readiness(self):
        transport = FakeTransport()
        transport.list_pages = {
            None: {'kernels': [{'ref': 'tester/one'}], 'nextPageToken': 'next'},
            'next': {'kernels': [{'ref': 'tester/two'}]},
        }
        result = submission_readiness(transport)
        self.assertTrue(result['ready'])
        self.assertEqual(result['owned_notebook_inventory']['pages'], 2)
        self.assertEqual(result['owned_notebook_inventory']['notebooks_seen'], 2)
        self.assertTrue(result['owned_notebook_inventory']['all_pages_completed'])

    def test_foreign_owner_and_unstable_pages_remain_blocked(self):
        for pages, expected in [
            ({None: {'kernels': [{'ref': 'other/notebook'}]}}, 'NOTEBOOK_LIST_SCOPE'),
            ({None: {'kernels': [], 'nextPageToken': 'loop'},
              'loop': {'kernels': [], 'nextPageToken': 'loop'}}, 'NOTEBOOK_LIST_PAGINATION'),
        ]:
            with self.subTest(error=expected):
                transport = FakeTransport()
                transport.list_pages = pages
                result = submission_readiness(transport)
                self.assertFalse(result['ready'])
                self.assertEqual(result['error']['code'], expected)

    def test_authentication_failure_is_not_inventory_success(self):
        transport = FakeTransport()
        transport.account = lambda: {'authenticated': False, 'username': 'tester'}
        result = submission_readiness(transport)
        self.assertFalse(result['ready'])
        self.assertFalse(result['authorization_verified'])
        self.assertEqual(result['error']['code'], 'ACCOUNT_UNVERIFIED')
        self.assertEqual(transport.calls, [])

    def test_blocked_readiness_cli_returns_nonzero_without_new_ledger(self):
        transport = FakeTransport()
        transport.list_pages = {None: {'kernels': [{}]}}
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'uncreated-state'
            output = io.StringIO()
            with patch('hepta_kaggle.KaggleTransport', return_value=transport), contextlib.redirect_stdout(output):
                code = main(['--state-dir', str(state), 'readiness'])
            self.assertEqual(code, 4)
            self.assertFalse(json.loads(output.getvalue())['result']['ready'])
            self.assertFalse(state.exists())


if __name__ == '__main__':
    unittest.main()
