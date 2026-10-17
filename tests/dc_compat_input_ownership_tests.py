# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Input ownership/expiry policy with an in-memory backend; never opens a GUI."""
import asyncio
import pathlib
import sys
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.computer import ComputerManager
from dc_compat.computer import _X11
from dc_compat.input_context import INPUT_CLIENT
from dc_compat.registry import ToolError, ToolRegistry
from dc_compat.http_server import JournalSession


class StubDesktop:
    def __init__(self):
        self.events = []

    def prepare_input(self, mask):
        self.events.append(('prepare', mask))

    def key(self, value, down):
        self.events.append(('key', value, down))

    def button(self, value, down):
        self.events.append(('button', value, down))

    def validate_position(self, x, y, stream):
        if not 0 <= x < 100 or not 0 <= y < 100:
            raise ToolError('Own fixture coordinates required')

    def move(self, x, y, stream):
        self.events.append(('move', x, y))

    def capabilities(self):
        return {'backend': 'stub', 'authorized': True}

    def windows(self):
        return {'windows': []}

    def clipboard(self, action, text):
        return 'own fixture'

    def close(self):
        self.events.append(('close',))


class InputOwnership(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.manager = ComputerManager({'backend': 'x11', 'display': ':not-opened'})
        self.desktop = self.manager.backend = StubDesktop()

    async def asyncTearDown(self):
        await self.manager.close()

    async def call(self, actor, name, args):
        context = INPUT_CLIENT.set(actor)
        try:
            result = await self.manager.invoke('computer_' + name, args)
            return result['structuredContent']['result']
        finally:
            INPUT_CLIENT.reset(context)

    async def test_held_control_blocks_other_session_before_any_os_call(self):
        await self.call('A', 'key', {'keys': ['CTRL'], 'action': 'down'})
        before = list(self.desktop.events)
        with self.assertRaisesRegex(ToolError, 'another MCP session'):
            await self.call('B', 'mouse', {'action': 'click', 'x': 10, 'y': 10})
        self.assertEqual(self.desktop.events, before)
        self.assertEqual(self.manager.held_keys, {'Control_L'})
        await self.call('A', 'mouse', {'action': 'click', 'x': 10, 'y': 10})
        await self.call('A', 'key', {'keys': ['CTRL'], 'action': 'up'})
        self.assertIsNone(self.manager.input_owner)

    async def test_implicit_gesture_capability_can_continue_across_cli_sessions(self):
        result = await self.call('CLI-1', 'mouse', {'action': 'down', 'button': 'left'})
        token = result['input_control']['input_lease']
        self.assertEqual(len(token), 64)
        await self.call('CLI-2', 'mouse', {'action': 'move', 'x': 20, 'y': 20, 'input_lease': token})
        await self.call('CLI-3', 'mouse', {'action': 'up', 'button': 'left', 'input_lease': token})
        self.assertEqual(self.manager.held_buttons, set())
        self.assertIsNone(self.manager.input_owner)

    async def test_invalid_capability_does_not_authorize_even_the_original_caller(self):
        await self.call('A', 'session', {'action': 'acquire_input'})
        before = list(self.desktop.events)
        with self.assertRaisesRegex(ToolError, 'does not own'):
            await self.call('A', 'mouse', {'action': 'move', 'x': 1, 'y': 1, 'input_lease': '0' * 64})
        self.assertEqual(before, self.desktop.events)

    async def test_explicit_lease_holds_entire_gesture_and_readers_stay_available(self):
        lease = await self.call('A', 'session', {'action': 'acquire_input', 'lease_seconds': 2})
        await self.call('A', 'mouse', {'action': 'click', 'x': 1, 'y': 1})
        with self.assertRaises(ToolError):
            await self.call('B', 'mouse', {'action': 'move', 'x': 2, 'y': 2})
        caps = await self.call('B', 'capabilities', {})
        self.assertTrue(caps['input_control']['reserved'])
        self.assertNotIn('input_lease', caps['input_control'])
        self.assertLess(caps['input_control']['expires_in_seconds'], 2)
        await self.call('B', 'session', {'action': 'release_input', 'input_lease': lease['input_lease']})
        await self.call('B', 'mouse', {'action': 'move', 'x': 2, 'y': 2})

    async def test_down_does_not_silently_extend_explicit_ttl(self):
        await self.call('A', 'session', {'action': 'acquire_input', 'lease_seconds': 1})
        deadline = self.manager.input_deadline
        await self.call('A', 'key', {'keys': ['CTRL'], 'action': 'down'})
        self.assertEqual(deadline, self.manager.input_deadline)

    async def test_expiry_releases_owned_key_and_button_before_competing_effect(self):
        lease = await self.call('A', 'session', {'action': 'acquire_input'})
        await self.call('A', 'key', {'keys': ['CTRL'], 'action': 'down'})
        await self.call('A', 'mouse', {'action': 'down', 'button': 'left'})
        self.manager.input_deadline = time.monotonic() - .01
        await self.call('B', 'mouse', {'action': 'move', 'x': 7, 'y': 8})
        events = self.desktop.events
        self.assertLess(events.index(('key', 'Control_L', False)), events.index(('move', 7, 8)))
        self.assertLess(events.index(('button', 'left', False)), events.index(('move', 7, 8)))
        with self.assertRaisesRegex(ToolError, 'stale'):
            await self.call('A', 'mouse', {'action': 'move', 'x': 8, 'y': 9, 'input_lease': lease['input_lease']})

    async def test_idle_expiry_releases_without_needing_another_request(self):
        await self.call('A', 'session', {'action': 'acquire_input', 'lease_seconds': 1})
        await self.call('A', 'mouse', {'action': 'down', 'button': 'left'})
        await asyncio.sleep(1.08)
        self.assertFalse(self.manager.held_buttons)
        self.assertIsNone(self.manager.input_owner)

    async def test_failed_expiry_cleanup_is_attempted_once_and_fences_new_input(self):
        await self.call('A', 'key', {'keys': ['CTRL'], 'action': 'down'})
        attempted = []
        def uncertain(value, down):
            attempted.append((value, down))
            raise ToolError('Unconfirmed own key release')
        self.desktop.key = uncertain
        self.manager.input_deadline = time.monotonic() - .01
        for _ in range(3):
            with self.assertRaises(ToolError):
                await self.call('B', 'mouse', {'action': 'move', 'x': 2, 'y': 2})
        self.assertEqual(attempted, [('Control_L', False)])
        self.desktop.key = lambda value, down: self.desktop.events.append(('key', value, down))
        await self.call('A', 'session', {'action': 'release_input'})

    async def test_duplicate_mouse_press_and_unowned_release_do_not_change_held_button(self):
        await self.call('A', 'mouse', {'action': 'down', 'button': 'left'})
        before = list(self.desktop.events)
        for args in ({'action': 'down'}, {'action': 'click', 'x': 1, 'y': 1},
                     {'action': 'double_click', 'x': 1, 'y': 1},
                     {'action': 'drag', 'x': 1, 'y': 1, 'to_x': 2, 'to_y': 2},
                     {'action': 'up', 'button': 'right'}):
            with self.assertRaises(ToolError):
                await self.call('A', 'mouse', args)
            self.assertEqual(before, self.desktop.events)
            self.assertEqual(self.manager.held_buttons, {'left'})
        await self.call('A', 'mouse', {'action': 'up', 'button': 'left'})

    async def test_release_input_does_not_close_clipboard_or_desktop(self):
        await self.call('A', 'session', {'action': 'acquire_input'})
        await self.call('A', 'key', {'keys': ['SHIFT'], 'action': 'down'})
        await self.call('A', 'session', {'action': 'release_input'})
        self.assertNotIn(('close',), self.desktop.events)
        self.assertFalse(self.manager.held_keys)

    async def test_close_cannot_drop_reservation_or_report_success_after_unconfirmed_release(self):
        await self.call('A', 'key', {'keys': ['CTRL'], 'action': 'down'})
        key = self.desktop.key
        def uncertain(value, down):
            raise ToolError('Unconfirmed own key release')
        self.desktop.key = uncertain
        with self.assertRaises(ToolError):
            await self.manager.close()
        self.assertFalse(self.manager.closed)
        self.assertEqual(self.manager.held_keys, {'Control_L'})
        self.assertEqual(self.manager.input_owner, 'A')
        self.assertTrue(self.manager.input_cleanup_failed)
        self.assertNotIn(('close',), self.desktop.events)
        self.desktop.key = key

    async def test_failed_atomic_key_release_keeps_original_caller_fenced(self):
        original = self.desktop.key
        def key(value, down):
            if not down:
                raise ToolError('Unconfirmed own key release')
            original(value, down)
        self.desktop.key = key
        with self.assertRaises(ToolError):
            await self.call('A', 'key', {'keys': ['CTRL'], 'action': 'press'})
        self.assertEqual(self.manager.input_owner, 'A')
        self.assertTrue(self.manager.input_cleanup_failed)
        before = list(self.desktop.events)
        for actor in ('A', 'B'):
            with self.assertRaises(ToolError):
                await self.call(actor, 'mouse', {'action': 'move', 'x': 1, 'y': 1})
        self.assertEqual(before, self.desktop.events)
        self.desktop.key = original
        await self.call('A', 'session', {'action': 'release_input'})

    async def test_failed_atomic_mouse_release_keeps_original_caller_fenced(self):
        original = self.desktop.button
        def button(value, down):
            if not down:
                raise ToolError('Unconfirmed own button release')
            original(value, down)
        self.desktop.button = button
        with self.assertRaises(ToolError):
            await self.call('A', 'mouse', {'action': 'click', 'x': 1, 'y': 1})
        self.assertEqual(self.manager.input_owner, 'A')
        self.assertTrue(self.manager.input_cleanup_failed)
        self.desktop.button = original
        await self.call('A', 'session', {'action': 'release_input'})

    async def test_renew_retains_capability_and_updates_deadline(self):
        lease = await self.call('A', 'session', {'action': 'acquire_input', 'lease_seconds': 1})
        renewed = await self.call('B', 'session', {'action': 'renew_input', 'lease_seconds': 3,
                                                'input_lease': lease['input_lease']})
        self.assertEqual(lease['input_lease'], renewed['input_lease'])
        self.assertGreater(renewed['expires_in_seconds'], 2.9)

    async def test_server_assigned_mcp_identity_is_inherited_by_effect_task(self):
        async def effect():
            await asyncio.sleep(.01)
            return {'content': [{'type': 'text', 'text': INPUT_CLIENT.get()}]}
        async def call(*args):
            return await asyncio.create_task(effect())
        registry = ToolRegistry([{'name': 'fixture', 'description': 'own stub',
                                 'inputSchema': {'type': 'object'}}])
        engine = SimpleNamespace(registry=registry, call=call, current_client={},
                                 journal=SimpleNamespace(observe_client=lambda value: None))
        sessions = [JournalSession(engine, actor) for actor in ('A', 'B')]
        for session in sessions:
            await session.dispatch({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                                    'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                                               'clientInfo': {'name': 'own-fixture', 'version': '1'}}})
        answers = await asyncio.gather(*(session.dispatch({'jsonrpc': '2.0', 'id': 2,
            'method': 'tools/call', 'params': {'name': 'fixture', 'arguments': {}}}) for session in sessions))
        self.assertEqual([answer['result']['content'][0]['text'] for answer in answers], ['A', 'B'])
        self.assertIsNone(INPUT_CLIENT.get())

    async def test_operator_shutdown_detaches_verified_independent_original_offer(self):
        backend = _X11({'display': ':not-opened'})
        actions = []
        status = dict(persistent_daemon=True, helper_alive=True, server_identity_verified=True,
                      owns_selection=True, serving_original=True, active_transaction_id=None)
        backend.selection = SimpleNamespace(persistent=True, status=lambda: status,
            detach=lambda: (actions.append('detach') or {'holder_stopped': False}),
            close=lambda: self.fail('Operator shutdown tried to stop the original offer'))
        backend.keyboard = SimpleNamespace(close=lambda: actions.append('keyboard-close'))
        backend.shutdown()
        self.assertEqual(actions, ['detach', 'keyboard-close'])
        self.assertIsNone(backend.selection)
        self.assertIsNone(backend.keyboard)

    async def test_public_close_still_refuses_to_drop_original_offer(self):
        backend = _X11({'display': ':not-opened'})
        backend.selection = SimpleNamespace(persistent=True,
            detach=lambda: self.fail('Public close silently detached'),
            close=lambda: {'closed': False, 'retained_original_offer': True, 'helper_alive': True})
        with self.assertRaises(ToolError):backend.close()
        self.assertIsNotNone(backend.selection)

    async def test_shutdown_cannot_detach_active_or_unverified_offer(self):
        for changes in ({'active_transaction_id': 'f' * 32}, {'server_identity_verified': False},
                        {'persistent_daemon': False}):
            backend = _X11({'display': ':not-opened'})
            status = dict(persistent_daemon=True, helper_alive=True, server_identity_verified=True,
                          owns_selection=True, serving_original=True, active_transaction_id=None)
            status.update(changes)
            backend.selection = SimpleNamespace(persistent=True, status=lambda: status,
                detach=lambda: self.fail('Unverified holder detached'),
                close=lambda: {'closed': False, 'helper_alive': True})
            with self.assertRaises(ToolError):backend.shutdown()


if __name__ == '__main__':
    unittest.main()
