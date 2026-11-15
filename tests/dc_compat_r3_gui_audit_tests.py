# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent R3/R4 GUI integration audit; private fixtures, no real desktop."""
import asyncio
import ctypes as C
import ctypes.util
import json
import os
from pathlib import Path
import queue
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.clipboard_transaction import ClipboardTransaction, ClipboardTransactionError
from dc_compat.computer import _Portal, ComputerManager
from dc_compat.computer_eis import UnrepresentableSymbol
from dc_compat.engine import Operator
from dc_compat.registry import ToolError, text_result
import dc_compat_clipboard_transaction_tests as clipboard_fixture
import dc_compat_computer_eis_tests as eis_fixture


class _RegionPeer:
    """An independent real EIS peer recording each event's target device."""
    def __init__(self, pointers):
        self.pointers, self.events, self.error = pointers, [], None
        self.ready, self.stop = queue.Queue(), threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()
        self.fd = self.ready.get(timeout=3)
        if isinstance(self.fd, Exception): raise self.fd

    def run(self):
        P, U, I, B, D, Z = eis_fixture.P, eis_fixture.U, eis_fixture.I, eis_fixture.B, eis_fixture.D, eis_fixture.Z
        lib = C.CDLL(ctypes.util.find_library('eis'))
        signatures = {
            'eis_new': (P, P), 'eis_unref': (P, P), 'eis_setup_backend_fd': (I, P),
            'eis_backend_fd_add_client': (I, P), 'eis_dispatch': (None, P), 'eis_get_event': (P, P),
            'eis_event_get_type': (I, P), 'eis_event_unref': (P, P), 'eis_event_get_client': (P, P),
            'eis_event_get_device': (P, P), 'eis_event_get_seat': (P, P), 'eis_client_connect': (None, P),
            'eis_client_new_seat': (P, P, C.c_char_p), 'eis_seat_configure_capability': (None, P, I),
            'eis_seat_add': (None, P), 'eis_seat_unref': (P, P), 'eis_seat_new_device': (P, P),
            'eis_device_configure_type': (None, P, I), 'eis_device_configure_name': (None, P, C.c_char_p),
            'eis_device_configure_capability': (None, P, I), 'eis_device_new_region': (P, P),
            'eis_region_set_offset': (None, P, U, U), 'eis_region_set_size': (None, P, U, U),
            'eis_region_set_physical_scale': (None, P, D),
            'eis_region_set_mapping_id': (None, P, C.c_char_p), 'eis_region_add': (None, P),
            'eis_region_unref': (P, P), 'eis_device_new_keymap': (P, P, I, I, Z),
            'eis_keymap_add': (None, P), 'eis_keymap_unref': (None, P), 'eis_device_add': (None, P),
            'eis_device_resume': (None, P), 'eis_device_unref': (P, P),
            'eis_event_pointer_get_absolute_x': (D, P), 'eis_event_pointer_get_absolute_y': (D, P),
            'eis_event_button_get_button': (U, P), 'eis_event_button_get_is_press': (B, P),
        }
        for name, signature in signatures.items(): eis_fixture._function(lib, name, *signature)
        context, devices, seats, names = lib.eis_new(None), [], [], {}
        created = False
        try:
            if lib.eis_setup_backend_fd(context): raise RuntimeError('Private region EIS setup failed')
            self.ready.put(lib.eis_backend_fd_add_client(context))
            while not self.stop.is_set():
                lib.eis_dispatch(context)
                while True:
                    event = lib.eis_get_event(context)
                    if not event: break
                    try:
                        kind = lib.eis_event_get_type(event)
                        if kind == 1:
                            client = lib.eis_event_get_client(event); lib.eis_client_connect(client)
                            seat = lib.eis_client_new_seat(client, b'private region audit')
                            seats.append(seat)
                            for cap in eis_fixture.CAPS: lib.eis_seat_configure_capability(seat, cap)
                            lib.eis_seat_add(seat)
                        elif kind == 3 and not created:
                            created = True; seat = lib.eis_event_get_seat(event)
                            specifications = list(self.pointers) + [('keyboard', [], (4,))]
                            for name, regions, capabilities in specifications:
                                device = lib.eis_seat_new_device(seat); devices.append(device); names[device] = name
                                lib.eis_device_configure_type(device, 1)
                                lib.eis_device_configure_name(device, name.encode())
                                for cap in capabilities: lib.eis_device_configure_capability(device, cap)
                                for descriptor in regions:
                                    rectangle, mapping = descriptor[:2]
                                    region = lib.eis_device_new_region(device)
                                    lib.eis_region_set_offset(region, *rectangle[:2]); lib.eis_region_set_size(region, *rectangle[2:])
                                    if mapping is not None: lib.eis_region_set_mapping_id(region, mapping.encode())
                                    if len(descriptor) == 3: lib.eis_region_set_physical_scale(region, descriptor[2])
                                    lib.eis_region_add(region); lib.eis_region_unref(region)
                                if 4 in capabilities:
                                    raw = eis_fixture.keymap_bytes(); fd = os.memfd_create('private-region-keymap', os.MFD_CLOEXEC)
                                    try:
                                        os.write(fd, raw); keymap = lib.eis_device_new_keymap(device, 1, fd, len(raw))
                                        lib.eis_keymap_add(keymap); lib.eis_keymap_unref(keymap)
                                    finally: os.close(fd)
                                lib.eis_device_add(device); lib.eis_device_resume(device)
                        elif kind in (400, 500):
                            name = names[lib.eis_event_get_device(event)]
                            if kind == 400:
                                self.events.append(('move', name, lib.eis_event_pointer_get_absolute_x(event), lib.eis_event_pointer_get_absolute_y(event)))
                            else:
                                self.events.append(('button', name, lib.eis_event_button_get_button(event), bool(lib.eis_event_button_get_is_press(event))))
                    finally: lib.eis_event_unref(event)
                time.sleep(.002)
        except Exception as error:
            self.error = error
            if self.ready.empty(): self.ready.put(error)
        finally:
            for device in devices: lib.eis_device_unref(device)
            for seat in seats: lib.eis_seat_unref(seat)
            lib.eis_unref(context)

    def wait(self, predicate):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.error: raise self.error
            if predicate(self.events): return self.events
            time.sleep(.005)
        raise AssertionError('Expected private region event did not arrive')

    def close(self):
        self.stop.set(); self.worker.join(3)
        if self.worker.is_alive(): raise AssertionError('Private region EIS peer did not close')


class ClipboardInputIndependence(unittest.TestCase):
    def test_original_clipboard_restoration_survives_input_transport_disconnect(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = clipboard_fixture.PrivatePortal(clipboard_fixture.ORIGINAL)
            portal = _Portal.__new__(_Portal)
            portal.context = None
            class Input:
                disconnected = False
                def pump(self):
                    if self.disconnected:
                        raise ToolError('Synthetic EIS disconnect, clipboard is still alive')
            portal.eis = Input()
            def pump(seconds):
                fixture.pump(seconds)
                portal._pump(0)
            manager = fixture.manager = ClipboardTransaction(fixture.call, pump, fixture.paste,
                lambda: fixture.session, Path(temporary) / 'state', max_snapshot_bytes=1024 * 1024,
                make_options=lambda mimes: {'mime_types': list(mimes)}, timeout_seconds=.15)
            fixture.initial()
            fixture.on_paste = lambda: setattr(portal.eis, 'disconnected', True)
            try:
                try:
                    receipt = manager.run('one attempted paste')
                except ClipboardTransactionError as error:
                    receipt = error.receipt
                self.assertTrue(receipt['original_bytes_offer_restored'],
                    'An independent input error prevented restoring a still-valid clipboard session')
                self.assertEqual(len(fixture.pastes), 1)
                self.assertEqual(fixture.sets[-1], tuple(clipboard_fixture.ORIGINAL))
            finally:
                portal.eis.disconnected = False
                fixture.close()


class Lifecycle(unittest.TestCase):
    def portal(self):
        portal = _Portal.__new__(_Portal)
        portal.session = '/private/fake/session'
        portal.streams, portal.devices, portal.clipboard_enabled = [], 3, True
        portal.clipboard_text = None
        portal.restore_lock = None
        portal.eis = None
        portal.eis_attempted = True
        portal.clipboard_transaction = None
        return portal

    def test_real_session_close_precedes_releasing_its_lazy_original_offer(self):
        portal = self.portal()
        actions = []
        actual = {'open': True}
        class Clipboard:
            def close(self):
                actions.append('release-offer')
                self_test.assertFalse(actual['open'], 'Lazy clipboard offer was dropped while actual portal session remained live')
        self_test = self
        portal.clipboard_transaction = Clipboard()
        def call(interface, method, signature, args, **kwargs):
            self.assertEqual(method, 'Close')
            actions.append('portal-close')
            actual['open'] = False
        portal._call = call
        portal.close()
        self.assertEqual(actions, ['portal-close', 'release-offer'])

    def test_eis_close_error_cannot_skip_clipboard_and_portal_cleanup(self):
        portal = self.portal()
        actions = []
        class Input:
            def close(self):
                actions.append('eis-close')
                raise RuntimeError('Synthetic EIS close failure')
        class Clipboard:
            def close(self):
                actions.append('clipboard-close')
        portal.eis, portal.clipboard_transaction = Input(), Clipboard()
        portal._call = lambda *args, **kwargs: actions.append('portal-close')
        try:
            portal.close()
        except (RuntimeError, ToolError):
            pass
        self.assertIn('portal-close', actions)
        self.assertIn('clipboard-close', actions)

    def test_session_revocation_releases_restore_lock_even_during_transaction(self):
        portal = self.portal()
        class ActiveClipboard:
            def reset(self):
                raise ToolError('Active transaction cannot be reset from a reentrant Closed signal')
        portal.clipboard_transaction = ActiveClipboard()
        with tempfile.TemporaryFile() as temporary:
            portal.restore_lock = os.dup(temporary.fileno())
            descriptor = portal.restore_lock
            try:
                try:
                    portal._session_closed(None, None, portal.session, None, None, None)
                except ToolError:
                    pass
                self.assertIsNone(portal.restore_lock, 'Reentrant Closed signal left the old restore lock held')
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            finally:
                if portal.restore_lock is not None:
                    os.close(portal.restore_lock)
                    portal.restore_lock = None


class WholeTextPreflight(unittest.TestCase):
    def portal(self, sender):
        portal = _Portal.__new__(_Portal)
        portal.session, portal.devices = '/private/session', 3
        portal.input_backend = 'eis'
        portal._ensure_eis = lambda: sender
        return portal

    def test_auto_unsupported_suffix_does_not_type_ascii_prefix_before_clipboard(self):
        events, transactions = [], []
        class Sender:
            def preflight_text(self, symbols):
                raise UnrepresentableSymbol('Whole string cannot fit this keymap')
            def key(self, *args, **kwargs):
                events.append(args)
        portal = self.portal(Sender())
        portal._type_via_clipboard = lambda text, keys: transactions.append((text, keys)) or {'method': 'clipboard'}
        result = portal.type_text('prefix 中文 👋', 'auto')
        self.assertEqual(events, [])
        self.assertEqual(transactions, [('prefix 中文 👋', ('CTRL', 'V'))])
        self.assertEqual(result['method'], 'clipboard')

    def test_keyboard_unsupported_suffix_neither_types_nor_falls_back(self):
        events = []
        class Sender:
            def preflight_text(self, symbols):
                raise UnrepresentableSymbol('Whole string cannot fit this keymap')
            def key(self, *args, **kwargs):
                events.append(args)
        portal = self.portal(Sender())
        portal._type_via_clipboard = lambda *args: self.fail('keyboard mode used clipboard')
        with self.assertRaises(UnrepresentableSymbol):
            portal.type_text('prefix 中文', 'keyboard')
        self.assertEqual(events, [])

    def test_later_keyboard_failure_never_claims_no_input_after_typed_prefix(self):
        events = []
        class Sender:
            def preflight_text(self, symbols):
                return None
            def key(self, symbol, down, **kwargs):
                if symbol == ord('b') and down:
                    raise UnrepresentableSymbol('Requested symbol changed layout; no input submitted')
                events.append((symbol, down))
        portal = self.portal(Sender())
        portal._type_via_clipboard = lambda *args: self.fail('Already submitted text was replayed through clipboard')
        with self.assertRaises(ToolError) as error:
            portal.type_text('ab', 'auto')
        self.assertIn((ord('a'), True), events)
        self.assertNotIn('no input submitted', str(error.exception),
            'Post-prefix failure wrongly advertises a safe-to-repeat unsubmitted string')


class PublicReceipt(unittest.IsolatedAsyncioTestCase):
    async def test_restore_failure_preserves_attempted_paste_in_public_error_receipt(self):
        manager = ComputerManager({'backend': 'x11', 'display': ':not-accessed'})
        manager.backend = _Portal.__new__(_Portal)
        receipt = {'paste_attempted': True, 'original_bytes_snapshot_complete': True,
            'original_bytes_offer_restored': False, 'restoration': 'restore_failed_private_backup_retained',
            'backup_retained': True, 'automatic_retry': False}
        async def call(name, *args):
            if name == 'prepare_input':
                return None
            raise ClipboardTransactionError('fixture_restore_failure', receipt)
        manager._call = call
        result = await manager.invoke('computer_type', {'text': 'private fixture input', 'mode': 'clipboard'})
        self.assertTrue(result['isError'])
        value = result['structuredContent']['result']
        self.assertTrue(value['submitted'])
        self.assertTrue(value['paste_attempted'])
        self.assertFalse(value['automatic_retry'])
        self.assertFalse(value['original_bytes_offer_restored'])

    async def test_cancelled_awaiter_does_not_replay_accepted_background_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = Operator(root / 'state', root, enable_computer=False, include_providers=False,
                             synchronous_wait=.01)
            started, release = asyncio.Event(), asyncio.Event()
            actions = []
            async def effect(name, arguments):
                actions.append('accepted-once')
                started.set()
                await release.wait()
                return text_result('immutable-original-result')
            owner.registry._handlers['get_prompts'] = effect
            try:
                waiting = asyncio.create_task(owner.call('get_prompts', {'action': 'get_prompt', 'promptId': 'onb2_02'}, 'same-private-rpc'))
                await started.wait()
                waiting.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await waiting
                release.set()
                if owner.tasks:
                    await asyncio.gather(*list(owner.tasks.values()))
                result = await owner.call('get_prompts', {'action': 'get_prompt', 'promptId': 'onb2_02'}, 'same-private-rpc')
                self.assertEqual(result['content'][0]['text'], 'immutable-original-result')
                self.assertEqual(actions, ['accepted-once'])
            finally:
                release.set()
                await owner.close()


class RealEisOwnership(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = eis_fixture.IntegratedEisTests()
        await self.fixture.asyncSetUp()

    async def asyncTearDown(self):
        await self.fixture.asyncTearDown()

    async def test_temporary_combo_and_real_drag_do_not_release_preexisting_ctrl(self):
        manager, server = self.fixture.manager, self.fixture.server
        await manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'down'})
        await manager.invoke('computer_key', {'keys': ['A'], 'action': 'press'})
        # Repeating an earlier held modifier in a new combo must not release it
        # from the new call's failure cleanup.
        with self.assertRaises(ToolError):
            await manager.invoke('computer_key', {'keys': ['CTRL', 'A'], 'action': 'press'})
        await manager.invoke('computer_mouse', {'action': 'drag', 'stream': 46,
            'x': 650, 'y': 630, 'to_x': 710, 'to_y': 650, 'duration_ms': 0})
        rows = await asyncio.to_thread(server.wait, lambda rows: ('button', 272, False) in rows)
        self.assertNotIn(('key', 29, False), rows)
        self.assertEqual(manager.held_keys, {'Control_L'})
        await manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'up'})
        rows = await asyncio.to_thread(server.wait, lambda rows: ('key', 29, False) in rows)
        self.assertLess(rows.index(('key', 29, True)), rows.index(('button', 272, True)))
        self.assertGreater(rows.index(('key', 29, False)), rows.index(('button', 272, False)))
        self.assertFalse(manager.held_keys)

    async def test_owned_shift_prevents_unicode_and_clipboard_without_releasing_it(self):
        manager, portal, server = self.fixture.manager, self.fixture.portal, self.fixture.server
        paste_calls = []
        portal._type_via_clipboard = lambda text, keys: paste_calls.append(text)
        await manager.invoke('computer_key', {'keys': ['SHIFT'], 'action': 'down'})
        for mode in ('auto', 'clipboard', 'keyboard'):
            with self.assertRaises(ToolError):
                await manager.invoke('computer_type', {'text': 'full 中文', 'mode': mode})
        with self.assertRaises(ToolError):
            await manager.invoke('computer_key', {'keys': ['SHIFT', 'A'], 'action': 'press'})
        self.assertEqual(paste_calls, [])
        self.assertEqual(manager.held_keys, {'Shift_L'})
        await asyncio.sleep(.02)
        self.assertNotIn(('key', 42, False), server.events)
        await manager.invoke('computer_key', {'keys': ['SHIFT'], 'action': 'up'})
        rows = await asyncio.to_thread(server.wait, lambda rows: ('key', 42, False) in rows)
        self.assertEqual([row for row in rows if row[0] == 'key'], [('key', 42, True), ('key', 42, False)])


class RealEisWithoutModifierEvents(unittest.IsolatedAsyncioTestCase):
    """The actual libeis peer deliberately never sends an initial modifiers event.

    Clipboard I/O uses anonymous real FDs and private spools. All production
    provider methods run on their genuine portal worker; no desktop bus exists.
    """
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hepta-no-modifiers-audit-')
        self.root = Path(self.temporary.name)
        self.server = eis_fixture.Server(send_modifiers=False)
        self.clipboard = clipboard_fixture.PrivatePortal(clipboard_fixture.ORIGINAL)
        self.manager = ComputerManager({'backend': 'portal'})
        self.portal = self.manager.backend
        self.portal.session = self.clipboard.session
        self.portal.devices, self.portal.clipboard_enabled = 3, True
        self.portal.streams = [{'stream': 46, 'position': [4480, 424], 'logical_size': [1920, 1080]}]
        self.calls = []
        def call(interface, method, signature, values, **kwargs):
            self.calls.append(method)
            if method == 'ConnectToEIS': return self.server.fd
            if method == 'Close': return ()
            return self.clipboard.call(interface, method, signature, values, fd=kwargs.get('fd', False))
        self.portal._call = call
        def setup():
            self.portal._ensure_eis()
            def pump(seconds):
                self.clipboard.pump(seconds)
                self.portal._pump(seconds)
            def paste(keys):
                # A complete all-format private backup must precede the very
                # first real key of an automatic clipboard fallback.
                snapshots = list((self.root / 'clipboard').glob('*/snapshot.json'))
                self.assertTrue(snapshots)
                self.assertTrue(all(json.loads(path.read_bytes())['complete'] for path in snapshots))
                self.portal._paste(keys)
                self.clipboard.paste(keys)
            self.clipboard.manager = self.portal.clipboard_transaction = ClipboardTransaction(
                self.portal._call, pump, paste, lambda: self.portal.session, self.root / 'clipboard',
                max_snapshot_bytes=4 * 1024 * 1024,
                make_options=lambda mimes: {'mime_types': list(mimes)}, timeout_seconds=.3)
            self.clipboard.initial()
        self.portal._audit_setup = setup
        self.portal._audit_diagnostics = lambda: self.portal.eis.diagnostics()
        def restore_read(mime):
            serial = self.clipboard.request(mime)
            self.clipboard.pump(0)
            return self.clipboard.wait_received(serial)
        self.portal._audit_restore_read = restore_read
        self.portal._audit_reset_offer = lambda: self.portal.clipboard_transaction.reset()
        self.portal._audit_initial_offer = self.clipboard.initial
        await self.portal.submit('_audit_setup')

    async def asyncTearDown(self):
        self.clipboard.release.set()
        await self.manager.close()
        await asyncio.to_thread(self.portal.worker.join, 2)
        self.assertFalse(self.portal.worker.is_alive())
        for worker in self.clipboard.threads:
            await asyncio.to_thread(worker.join, 2)
            self.assertFalse(worker.is_alive())
        self.server.close()
        self.temporary.cleanup()

    async def test_ready_without_modifiers_does_not_authorize_literal_or_invent_locks(self):
        diagnostics = await self.portal.submit('_audit_diagnostics')
        self.assertTrue(diagnostics['connected'])
        self.assertTrue(all(diagnostics['ready_capabilities'].values()))
        self.assertFalse(diagnostics['modifier_state_known'])
        self.assertFalse(diagnostics['exact_keyboard_text'])
        self.assertIsNone(diagnostics['locks'])
        self.assertEqual(diagnostics['physical_key_layout'], 'server_keymap_first_layout')
        for text in ('ASCII-only 123', 'ASCII prefix 中文🙂'):
            with self.assertRaises(UnrepresentableSymbol):
                await self.manager.invoke('computer_type', {'text': text, 'mode': 'keyboard'})
        await asyncio.sleep(.03)
        self.assertFalse(any(row[0] == 'key' for row in self.server.events))
        self.assertFalse(self.clipboard.sets)
        self.assertFalse(self.clipboard.reads)
        self.assertEqual(self.calls.count('ConnectToEIS'), 1)
        self.assertFalse(any(method.startswith('Notify') for method in self.calls))

    async def test_empty_auto_text_is_noop_without_clipboard_offer_or_physical_paste(self):
        for mode in ('auto', 'keyboard', 'clipboard'):
            with self.subTest(mode=mode):
                reply = await self.manager.invoke('computer_type', {'text': '', 'mode': mode})
                await asyncio.sleep(.02)
                self.assertEqual({'mime_reads': len(self.clipboard.reads), 'selection_changes': len(self.clipboard.sets),
                    'pastes': len(self.clipboard.pastes), 'wire_keys': sum(row[0] == 'key' for row in self.server.events)},
                    {'mime_reads': 0, 'selection_changes': 0, 'pastes': 0, 'wire_keys': 0},
                    'Empty input must not acquire clipboard ownership or submit paste keys')
                self.assertFalse(reply['structuredContent']['result']['submitted'])
                self.assertFalse(reply['structuredContent']['result']['clipboard_modified'])

    async def test_ascii_and_unicode_auto_use_complete_private_mime_snapshot_before_one_paste(self):
        for text in ('ASCII-only 123', 'ASCII prefix café 中文🙂'):
            with self.subTest(text=text):
                previous = len([row for row in self.server.events if row[0] == 'key'])
                self.clipboard.on_read = lambda mime: self.assertEqual(
                    len([row for row in self.server.events if row[0] == 'key']), previous)
                result = await self.manager.invoke('computer_type', {'text': text, 'mode': 'auto'})
                receipt = result['structuredContent']['result']
                self.assertEqual(receipt['method'], 'clipboard')
                self.assertTrue(receipt['original_bytes_snapshot_complete'])
                self.assertTrue(receipt['original_bytes_offer_restored'])
                self.assertTrue(receipt['paste_attempted'])
                self.assertFalse(receipt['automatic_retry'])
                self.assertFalse(receipt['original_owner_restored'])
                serial = self.clipboard.writes[-1]
                deadline = time.monotonic() + 2
                while serial not in self.clipboard.received and time.monotonic() < deadline:
                    await asyncio.sleep(.005)
                self.assertEqual(self.clipboard.received[serial], text.encode())
                for mime, raw in clipboard_fixture.ORIGINAL.items():
                    self.assertEqual(await self.portal.submit('_audit_restore_read', mime), raw)
                self.assertNotIn(clipboard_fixture.ORIGINAL['text/plain;charset=utf-8'].decode(), json.dumps(result))
        rows = await asyncio.to_thread(self.server.wait,
            lambda rows: sum(row == ('key', 29, False) for row in rows) == 2)
        expected = [('key', 29, True), ('key', 47, True), ('key', 47, False), ('key', 29, False)] * 2
        self.assertEqual([row for row in rows if row[0] == 'key'], expected)
        self.assertEqual(self.clipboard.pastes, [('CTRL', 'V'), ('CTRL', 'V')])
        self.assertEqual(set(self.clipboard.reads), set(clipboard_fixture.ORIGINAL))
        self.assertFalse(self.manager.held_keys)
        self.assertFalse((await self.portal.submit('_audit_diagnostics'))['modifier_state_known'])
        self.assertFalse(any(method.startswith('Notify') for method in self.calls))

    async def test_missing_offer_or_unreadable_mime_refuses_before_any_paste_or_selection_change(self):
        await self.portal.submit('_audit_reset_offer')
        missing = await self.manager.invoke('computer_type', {'text': 'whole ASCII 中文', 'mode': 'auto'})
        self.assertTrue(missing['isError'])
        self.assertFalse(missing['structuredContent']['result']['paste_attempted'])
        self.assertFalse(self.clipboard.sets)
        await self.portal.submit('_audit_initial_offer')
        self.clipboard.failed_read = 'image/png'
        failed = await self.manager.invoke('computer_type', {'text': 'whole ASCII 中文', 'mode': 'auto'})
        self.assertTrue(failed['isError'])
        self.assertFalse(failed['structuredContent']['result']['paste_attempted'])
        self.assertFalse(self.clipboard.sets)
        self.assertFalse(self.clipboard.pastes)
        self.assertFalse(any(row[0] == 'key' for row in self.server.events))

    async def test_explicit_physical_ctrl_a_v_and_preheld_ctrl_do_not_add_shift_or_release_early(self):
        await self.manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'down'})
        await self.manager.invoke('computer_key', {'keys': ['A']})
        await self.manager.invoke('computer_key', {'keys': ['V']})
        for action in ({'keys': ['CTRL', 'V']}, {'keys': ['CTRL', 'A'], 'action': 'down'}):
            with self.assertRaises(ToolError):
                await self.manager.invoke('computer_key', action)
        with self.assertRaises(ToolError):
            await self.manager.invoke('computer_type', {'text': 'never pasted', 'mode': 'auto'})
        rows = await asyncio.to_thread(self.server.wait, lambda rows: ('key', 47, False) in rows)
        self.assertEqual([row for row in rows if row[0] == 'key'],
            [('key', 29, True), ('key', 30, True), ('key', 30, False), ('key', 47, True), ('key', 47, False)])
        self.assertEqual(self.manager.held_keys, {'Control_L'})
        self.assertFalse(self.clipboard.sets)
        await self.manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'up'})
        await self.manager.invoke('computer_key', {'keys': ['CTRL', 'A']})
        await self.manager.invoke('computer_key', {'keys': ['CTRL', 'V']})
        rows = await asyncio.to_thread(self.server.wait,
            lambda rows: sum(row == ('key', 29, False) for row in rows) == 3)
        self.assertFalse(any(row[0] == 'key' and row[1] in (42, 54, 58, 69) for row in rows))
        self.assertFalse(self.manager.held_keys)

    async def test_later_actual_modifiers_wire_event_enables_exact_keyboard_without_clipboard(self):
        self.assertFalse((await self.portal.submit('_audit_diagnostics'))['modifier_state_known'])
        self.server.commands.put('unlock')
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            diagnostics = await self.portal.submit('_audit_diagnostics')
            if diagnostics['modifier_state_known']: break
            await asyncio.sleep(.005)
        self.assertTrue(diagnostics['modifier_state_known'])
        self.assertFalse(diagnostics['locks']['caps_lock'])
        reply = await self.manager.invoke('computer_type', {'text': 'Aa', 'mode': 'keyboard'})
        self.assertEqual(reply['structuredContent']['result']['method'], 'keyboard')
        rows = await asyncio.to_thread(self.server.wait,
            lambda rows: sum(row[0] == 'key' for row in rows) >= 6)
        self.assertEqual([row for row in rows if row[0] == 'key'],
            [('key', 42, True), ('key', 30, True), ('key', 30, False), ('key', 42, False), ('key', 30, True), ('key', 30, False)])
        self.assertFalse(self.clipboard.sets)
        self.assertFalse(self.clipboard.reads)
        self.assertFalse(self.manager.held_keys)


class RealEisRegionIdentity(unittest.TestCase):
    def connect(self, pointers):
        peer = _RegionPeer(pointers)
        self.addCleanup(peer.close)
        sender = eis_fixture.EisSender(peer.fd)
        self.addCleanup(sender.close)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            sender.pump()
            if len(sender.devices) == len(pointers) + 1 and all(info['ready'] for info in sender.devices.values()):
                return peer, sender
            time.sleep(.005)
        self.fail('Private region devices did not resume')

    def test_unique_geometry_targets_second_device_and_preserves_global_offset(self):
        peer, sender = self.connect([
            ('first-wrong-monitor', [((0, 0, 1920, 1080), None)], (2, 16, 32)),
            ('second-right-monitor', [((4480, 424, 1920, 1080), None)], (2, 16, 32))])
        sender.move(650, 630, {'position': [4480, 424], 'logical_size': [1920, 1080]})
        sender.button('left', True); sender.button('left', False)
        rows = peer.wait(lambda rows: ('button', 'second-right-monitor', 272, False) in rows)
        self.assertEqual(rows, [('move', 'second-right-monitor', 5130., 1054.),
            ('button', 'second-right-monitor', 272, True), ('button', 'second-right-monitor', 272, False)])

    def test_overlapping_unidentified_regions_never_choose_first_device(self):
        peer, sender = self.connect([
            ('first-ambiguous', [((0, 0, 1920, 1080), None)], (2, 16, 32)),
            ('second-ambiguous', [((0, 0, 1920, 1080), None)], (2, 16, 32))])
        with self.assertRaises(ToolError):
            sender.move(100, 200, {'position': [0, 0], 'logical_size': [1920, 1080]})
        time.sleep(.03)
        self.assertEqual(peer.events, [])
        self.assertIsNone(sender.pointer_device)

    def test_mapping_identity_wins_over_foreign_same_geometry_without_choosing_first(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                pointers = [
                    ('wrong-geometry-match', [((0, 0, 100, 100), 'foreign-resource')], (2, 16, 32)),
                    ('right-mapping-match', [((1000, 2000, 100, 100), 'target-resource')], (2, 16, 32))]
                peer, sender = self.connect(list(reversed(pointers)) if reverse else pointers)
                sender.move(12, 34, {'position': [0, 0], 'logical_size': [100, 100], 'mapping_id': 'target-resource'})
                sender.button('left', True); sender.button('left', False)
                rows = peer.wait(lambda rows: ('button', 'right-mapping-match', 272, False) in rows)
                self.assertEqual(rows, [('move', 'right-mapping-match', 1012., 2034.),
                    ('button', 'right-mapping-match', 272, True), ('button', 'right-mapping-match', 272, False)])

    def test_explicit_missing_mapping_cannot_fall_back_to_same_geometry(self):
        for mapping in (None, 'different-resource'):
            with self.subTest(mapping=mapping):
                peer, sender = self.connect([('not-the-resource', [((0, 0, 100, 100), mapping)], (2, 16, 32))])
                with self.assertRaises(ToolError):
                    sender.move(12, 34, {'position': [0, 0], 'logical_size': [100, 100], 'mapping_id': 'target-resource'})
                time.sleep(.02)
                self.assertEqual(peer.events, [])

    def test_complete_equivalent_mapped_clones_choose_newest_and_stay_on_that_device(self):
        regions = [((0, 0, 100, 100), 'left-resource', 1.0), ((100, 0, 200, 100), 'right-resource', 1.5)]
        peer, sender = self.connect([
            ('old-clone', regions, (2, 16, 32)),
            ('new-clone', list(reversed(regions)), (32, 2, 16))])
        sender.move(12, 34, {'position': [100, 0], 'logical_size': [200, 100], 'mapping_id': 'right-resource'})
        sender.button('left', True); sender.button('left', False)
        sender.move(56, 78, {'position': [0, 0], 'logical_size': [100, 100], 'mapping_id': 'left-resource'})
        rows = peer.wait(lambda rows: ('move', 'new-clone', 56., 78.) in rows)
        self.assertEqual(rows, [('move', 'new-clone', 112., 34.),
            ('button', 'new-clone', 272, True), ('button', 'new-clone', 272, False),
            ('move', 'new-clone', 56., 78.)])

    def test_held_button_owner_overrides_newest_equivalent_clone_through_drag_moves(self):
        regions = [((400, 200, 100, 100), 'same-resource')]
        peer, sender = self.connect([
            ('old-held-owner', regions, (2, 16, 32)),
            ('new-idle-clone', regions, (2, 16, 32))])
        # Press before any move. _device chooses the first live button device;
        # the next move must preserve that owner instead of canonical switching.
        sender.button('left', True)
        sender.move(10, 20, {'position': [400, 200], 'logical_size': [100, 100], 'mapping_id': 'same-resource'})
        sender.move(30, 40, {'position': [400, 200], 'logical_size': [100, 100], 'mapping_id': 'same-resource'})
        sender.button('left', False)
        rows = peer.wait(lambda rows: ('button', 'old-held-owner', 272, False) in rows)
        self.assertEqual(rows, [('button', 'old-held-owner', 272, True),
            ('move', 'old-held-owner', 410., 220.), ('move', 'old-held-owner', 430., 240.),
            ('button', 'old-held-owner', 272, False)])

    def test_non_equivalent_whole_inventory_scale_or_extra_capability_refuses_without_input(self):
        target = ((0, 0, 100, 100), 'target-resource', 1.0)
        neighbor = ((100, 0, 100, 100), 'neighbor-resource', 1.0)
        cases = [
            ([target, ((100, 0, 100, 100), 'foreign-neighbor', 1.0)], (2, 16, 32)),
            ([target, ((200, 0, 100, 100), 'neighbor-resource', 1.0)], (2, 16, 32)),
            ([((0, 0, 100, 100), 'target-resource', 2.0), neighbor], (2, 16, 32)),
            # Use a granted extra capability: libeis correctly filters unbound
            # relative/touch capabilities off the real wire for this sender.
            ([target, neighbor], (2, 4, 16, 32)),
        ]
        for regions, capabilities in cases:
            with self.subTest(regions=regions, capabilities=capabilities):
                peer, sender = self.connect([
                    ('reference', [target, neighbor], (2, 16, 32)),
                    ('not-equivalent', regions, capabilities)])
                with self.assertRaises(ToolError):
                    sender.move(12, 34, {'position': [0, 0], 'logical_size': [100, 100], 'mapping_id': 'target-resource'})
                time.sleep(.02)
                self.assertEqual(peer.events, [])

    def test_duplicate_mapping_different_size_is_not_filtered_out_to_fake_uniqueness(self):
        peer, sender = self.connect([
            ('same-size', [((0, 0, 100, 100), 'target-resource')], (2, 16, 32)),
            ('resize-transition', [((400, 0, 200, 100), 'target-resource')], (2, 16, 32))])
        with self.assertRaises(ToolError):
            sender.move(12, 34, {'position': [0, 0], 'logical_size': [100, 100], 'mapping_id': 'target-resource'})
        time.sleep(.02)
        self.assertEqual(peer.events, [])

    def test_duplicate_target_region_inside_one_device_is_not_an_equivalent_clone(self):
        region = ((0, 0, 100, 100), 'target-resource')
        peer, sender = self.connect([('malformed-duplicate', [region, region], (2, 16, 32))])
        with self.assertRaises(ToolError):
            sender.move(12, 34, {'position': [0, 0], 'logical_size': [100, 100], 'mapping_id': 'target-resource'})
        time.sleep(.02)
        self.assertEqual(peer.events, [])


if __name__ == '__main__':
    unittest.main()
