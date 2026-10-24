# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real libei/libeis on an anonymous private socket; no desktop connection."""
import ctypes as C
import ctypes.util
import asyncio
import base64
import os
import pathlib
import queue
import json
import subprocess
import tempfile
import sys
import threading
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.computer_eis import EisSender, XkbState, _function, P, U, I, B, D, Z, CAPS
from dc_compat.registry import ToolError
from dc_compat.computer import ComputerManager


def keymap_bytes():
    lib = C.CDLL(ctypes.util.find_library('xkbcommon'))
    _function(lib, 'xkb_context_new', P, I)
    _function(lib, 'xkb_keymap_new_from_names', P, P, P, I)
    _function(lib, 'xkb_keymap_get_as_string', P, P, I)
    _function(lib, 'xkb_keymap_unref', None, P)
    _function(lib, 'xkb_context_unref', None, P)
    context = lib.xkb_context_new(0)
    keymap = lib.xkb_keymap_new_from_names(context, None, 0)
    string = lib.xkb_keymap_get_as_string(keymap, 1)
    raw = C.string_at(string) + b'\0'
    libc = C.CDLL(None);_function(libc, 'free', None, P);libc.free(string)
    lib.xkb_keymap_unref(keymap);lib.xkb_context_unref(context)
    return raw


class Server:
    def __init__(self, *, locks=18, send_modifiers=True, geometry=(4480, 424, 1920, 1080), extra_geometry=None):
        self.locks, self.send_modifiers = locks, send_modifiers
        self.geometry = geometry
        self.extra_geometry = extra_geometry
        self.ready, self.commands = queue.Queue(), queue.Queue()
        self.events, self.error = [], None
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start();self.fd = self.ready.get(timeout=5)
        if isinstance(self.fd, Exception):
            raise self.fd

    def run(self):
        lib = C.CDLL(ctypes.util.find_library('eis'))
        specs = {
            'eis_new': (P, P), 'eis_unref': (P, P),
            'eis_setup_backend_fd': (I, P), 'eis_backend_fd_add_client': (I, P),
            'eis_dispatch': (None, P), 'eis_get_event': (P, P),
            'eis_event_get_type': (I, P), 'eis_event_unref': (P, P),
            'eis_event_get_client': (P, P), 'eis_event_get_seat': (P, P),
            'eis_event_seat_has_capability': (B, P, I),
            'eis_client_connect': (None, P), 'eis_client_disconnect': (None, P),
            'eis_client_new_seat': (P, P, C.c_char_p),
            'eis_seat_configure_capability': (None, P, I), 'eis_seat_add': (None, P),
            'eis_seat_unref': (P, P), 'eis_device_unref': (P, P),
            'eis_seat_new_device': (P, P), 'eis_device_configure_type': (None, P, I),
            'eis_device_configure_name': (None, P, C.c_char_p),
            'eis_device_configure_capability': (None, P, I),
            'eis_device_new_region': (P, P), 'eis_region_set_offset': (None, P, U, U),
            'eis_region_set_size': (None, P, U, U), 'eis_region_add': (None, P),
            'eis_region_unref': (P, P), 'eis_device_new_keymap': (P, P, I, I, Z),
            'eis_keymap_add': (None, P), 'eis_keymap_unref': (P, P),
            'eis_device_add': (None, P), 'eis_device_resume': (None, P),
            'eis_device_pause': (None, P),
            'eis_device_keyboard_send_xkb_modifiers': (None, P, U, U, U, U),
            'eis_event_pointer_get_absolute_x': (D, P),
            'eis_event_pointer_get_absolute_y': (D, P),
            'eis_event_button_get_button': (U, P), 'eis_event_button_get_is_press': (B, P),
            'eis_event_keyboard_get_key': (U, P), 'eis_event_keyboard_get_key_is_press': (B, P),
            'eis_event_scroll_get_discrete_dx': (I, P), 'eis_event_scroll_get_discrete_dy': (I, P),
        }
        for name, signature in specs.items():
            _function(lib, name, *signature)
        context = lib.eis_new(None);device = client = None
        owned_devices, owned_seats = [], []
        try:
            if lib.eis_setup_backend_fd(context) != 0:
                raise RuntimeError('private EIS backend failed')
            self.ready.put(lib.eis_backend_fd_add_client(context))
            while not self.stop.is_set():
                try:
                    command = self.commands.get_nowait()
                    if command == 'pause':lib.eis_device_pause(device)
                    elif command == 'resume':lib.eis_device_resume(device)
                    elif command == 'disconnect':lib.eis_client_disconnect(client)
                    elif command == 'unlock':lib.eis_device_keyboard_send_xkb_modifiers(device, 0, 0, 0, 0)
                except queue.Empty:
                    pass
                lib.eis_dispatch(context)
                while True:
                    event = lib.eis_get_event(context)
                    if not event:break
                    try:
                        kind = lib.eis_event_get_type(event)
                        if kind == 1:
                            client = lib.eis_event_get_client(event);lib.eis_client_connect(client)
                            seat = lib.eis_client_new_seat(client, b'private fixture seat')
                            owned_seats.append(seat)
                            for capability in CAPS:lib.eis_seat_configure_capability(seat, capability)
                            lib.eis_seat_add(seat)
                        elif kind == 3:
                            if not any(lib.eis_event_seat_has_capability(event, cap) for cap in CAPS):continue
                            seat = lib.eis_event_get_seat(event)
                            device = lib.eis_seat_new_device(seat);lib.eis_device_configure_type(device, 1)
                            owned_devices.append(device)
                            lib.eis_device_configure_name(device, b'private fixture device')
                            for capability in CAPS:lib.eis_device_configure_capability(device, capability)
                            region = lib.eis_device_new_region(device);lib.eis_region_set_offset(region, *self.geometry[:2]);lib.eis_region_set_size(region, *self.geometry[2:]);lib.eis_region_add(region);lib.eis_region_unref(region)
                            raw = keymap_bytes();fd = os.memfd_create('hepta-eis-fixture-keymap', os.MFD_CLOEXEC);os.write(fd, raw)
                            keymap = lib.eis_device_new_keymap(device, 1, fd, len(raw));os.close(fd);lib.eis_keymap_add(keymap);lib.eis_keymap_unref(keymap)
                            lib.eis_device_add(device)
                            if self.send_modifiers:lib.eis_device_keyboard_send_xkb_modifiers(device, 0, 0, self.locks, 0)
                            lib.eis_device_resume(device)
                            if self.extra_geometry is not None:
                                extra = lib.eis_seat_new_device(seat);owned_devices.append(extra)
                                lib.eis_device_configure_type(extra, 1);lib.eis_device_configure_name(extra, b'private secondary monitor')
                                for capability in (2, 16, 32):lib.eis_device_configure_capability(extra, capability)
                                region = lib.eis_device_new_region(extra)
                                lib.eis_region_set_offset(region, *self.extra_geometry[:2]);lib.eis_region_set_size(region, *self.extra_geometry[2:])
                                lib.eis_region_add(region);lib.eis_region_unref(region)
                                lib.eis_device_add(extra);lib.eis_device_resume(extra)
                        elif kind == 400:
                            self.events.append(('move', lib.eis_event_pointer_get_absolute_x(event), lib.eis_event_pointer_get_absolute_y(event)))
                        elif kind == 500:self.events.append(('button', lib.eis_event_button_get_button(event), bool(lib.eis_event_button_get_is_press(event))))
                        elif kind == 603:self.events.append(('scroll', lib.eis_event_scroll_get_discrete_dx(event), lib.eis_event_scroll_get_discrete_dy(event)))
                        elif kind == 700:self.events.append(('key', lib.eis_event_keyboard_get_key(event), bool(lib.eis_event_keyboard_get_key_is_press(event))))
                        elif kind == 100:self.events.append(('frame',))
                    finally:lib.eis_event_unref(event)
                time.sleep(.002)
        except Exception as error:
            self.error = error
            if self.ready.empty():self.ready.put(error)
        finally:
            for owned in owned_devices:lib.eis_device_unref(owned)
            for owned in owned_seats:lib.eis_seat_unref(owned)
            lib.eis_unref(context)

    def wait(self, predicate, timeout=2):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.error:raise self.error
            if predicate(self.events):return self.events
            time.sleep(.005)
        raise AssertionError('No expected private EIS wire event')

    def close(self):
        self.stop.set();self.worker.join(timeout=3)
        if self.worker.is_alive():raise AssertionError('Private EIS fixture did not close')


class XkbTests(unittest.TestCase):
    def setUp(self):self.state = XkbState(keymap_bytes())
    def tearDown(self):self.state.close()

    def test_unknown_modifiers_refuse_before_key(self):
        with self.assertRaises(ToolError):self.state.plan(ord('a'))

    def test_caps_lock_exact_text_without_changing_locks(self):
        self.state.modifiers(0, 0, 18, 0)
        before = self.state.masks()
        self.assertEqual(self.state.plan(ord('A')), (30, ()))
        self.assertEqual(self.state.plan(ord('a')), (30, (42,)))
        self.assertEqual(self.state.masks(), before)
        self.assertEqual(self.state.lock_state(), {'caps_lock': True, 'num_lock': True})

    def test_shortcut_letter_is_physical_and_no_shift(self):
        self.state.modifiers(0, 0, 0, 0)
        self.assertEqual(self.state.physical_plan(ord('A')), (30, ()))
        self.assertEqual(self.state.plan(ord('A')), (30, (42,)))

    def test_unsupported_unicode_refuses_instead_of_silent_drop(self):
        self.state.modifiers(0, 0, 0, 0)
        with self.assertRaises(ToolError):self.state.plan(0x01004e2d)


class EisTests(unittest.TestCase):
    def setUp(self):
        self.server = Server();self.sender = EisSender(self.server.fd)
    def tearDown(self):
        self.sender.close();self.server.close()

    def test_real_eis_handshake_region_and_frame(self):
        self.sender.move(650, 630, {'position': [4480, 424], 'logical_size': [1920, 1080]})
        events = self.server.wait(lambda events: ('move', 5130.0, 1054.0) in events and ('frame',) in events)
        self.assertIn(('move', 5130.0, 1054.0), events)
        self.assertTrue(self.sender.diagnostics()['locks']['caps_lock'])

    def test_region_inventory_is_read_only_and_reports_server_geometry(self):
        inventory = self.sender.diagnostics()['device_inventory']
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]['device_type'], 1)
        self.assertEqual(inventory[0]['capabilities'], [2, 4, 16, 32])
        self.assertTrue(inventory[0]['resumed'])
        self.assertEqual(inventory[0]['regions'], [
            {'rectangle': [4480, 424, 1920, 1080], 'mapping_id': None, 'physical_scale': 1.0}])
        self.assertFalse(any(info['emulating'] for info in self.sender.devices.values()))
        self.assertFalse(self.server.events)

    def test_foreign_region_refused_before_wire_input(self):
        with self.assertRaises(ToolError):self.sender.move(650, 630, {'position': [0, 0], 'logical_size': [1920, 1080]})
        time.sleep(.03);self.assertFalse(any(row[0] == 'move' for row in self.server.events))

    def test_buttons_scroll_and_cleanup_release(self):
        self.sender.button('left', True);self.sender.scroll('down', 3);self.sender.close()
        events = self.server.wait(lambda rows: ('button', 272, False) in rows)
        self.assertIn(('button', 272, True), events);self.assertIn(('scroll', 0, 360), events)

    def test_real_caps_lock_keyboard_and_physical_shortcut(self):
        self.sender.key(ord('a'), True, literal=True);self.sender.key(ord('a'), False, literal=True)
        self.sender.key(0xffe3, True);self.sender.key(ord('A'), True);self.sender.key(ord('A'), False);self.sender.key(0xffe3, False)
        events = self.server.wait(lambda rows: ('key', 29, False) in rows)
        keys = [row for row in events if row[0] == 'key']
        self.assertEqual(keys, [('key', 42, True), ('key', 30, True), ('key', 30, False), ('key', 42, False), ('key', 29, True), ('key', 30, True), ('key', 30, False), ('key', 29, False)])

    def test_full_text_preflight_prevents_partial_ascii_prefix(self):
        with self.assertRaises(ToolError):self.sender.preflight_text([ord('a'), 0x01004e2d])
        time.sleep(.03);self.assertFalse(any(row[0] == 'key' for row in self.server.events))

    def test_paused_device_refuses_without_reconnect_or_replay(self):
        self.server.commands.put('pause');time.sleep(.04);self.sender.pump()
        with self.assertRaises(ToolError):self.sender.key(ord('a'), True)
        self.assertFalse(self.sender.pressed)

    def test_server_disconnect_refuses_and_does_not_reconnect(self):
        self.server.commands.put('disconnect');time.sleep(.04)
        with self.assertRaises(ToolError):self.sender.move(5, 5, {'position': [4480, 424], 'logical_size': [1920, 1080]})
        self.assertTrue(self.sender.disconnected)

    def test_thread_confinement_refuses(self):
        errors = []
        def wrong_thread():
            try:self.sender.pump()
            except Exception as error:errors.append(error)
        thread = threading.Thread(target=wrong_thread);thread.start();thread.join()
        self.assertIsInstance(errors[0], ToolError)


class MultipleDeviceTests(unittest.TestCase):
    def test_selects_second_display_device_instead_of_first_pointer(self):
        server = Server(geometry=(1920, 424, 2560, 1440), extra_geometry=(4480, 424, 1920, 1080))
        sender = EisSender(server.fd)
        try:
            deadline = time.monotonic() + 2
            while (len(sender.devices) < 2 or not all(info['ready'] for info in sender.devices.values())) and time.monotonic() < deadline:
                sender.pump();time.sleep(.005)
            self.assertEqual(len(sender.devices), 2)
            sender.move(650, 630, {'position': [4480, 424], 'logical_size': [1920, 1080]})
            server.wait(lambda rows: ('move', 5130., 1054.) in rows)
            sender.button('left', True);sender.button('left', False)
            server.wait(lambda rows: ('button', 272, False) in rows)
        finally:sender.close();server.close()

    def test_duplicate_region_geometry_is_refused_before_input(self):
        server = Server(extra_geometry=(4480, 424, 1920, 1080))
        sender = EisSender(server.fd)
        try:
            deadline = time.monotonic() + 2
            while (len(sender.devices) < 2 or not all(info['ready'] for info in sender.devices.values())) and time.monotonic() < deadline:
                sender.pump();time.sleep(.005)
            self.assertEqual(len(sender.devices), 2)
            with self.assertRaises(ToolError):sender.move(650, 630, {'position': [4480, 424], 'logical_size': [1920, 1080]})
            self.assertFalse(any(row[0] == 'move' for row in server.events))
        finally:sender.close();server.close()


class CompositorWithoutModifiersTests(unittest.TestCase):
    def setUp(self):
        self.server = Server(send_modifiers=False)
        self.sender = EisSender(self.server.fd, timeout=.5)

    def tearDown(self):
        self.sender.close();self.server.close()

    def test_resumed_devices_authorize_without_inventing_lock_state(self):
        diagnostics = self.sender.diagnostics()
        self.assertTrue(diagnostics['connected'])
        self.assertTrue(all(diagnostics['ready_capabilities'].values()))
        self.assertFalse(diagnostics['modifier_state_known'])
        self.assertIsNone(diagnostics['locks'])
        self.assertFalse(diagnostics['exact_keyboard_text'])
        self.assertEqual(diagnostics['physical_key_layout'], 'server_keymap_first_layout')
        self.assertFalse(self.server.events)

    def test_pointer_and_physical_combo_are_usable_without_modifier_events(self):
        self.sender.move(650, 630, {'position': [4480, 424], 'logical_size': [1920, 1080]})
        self.sender.key(0xffe3, True);self.sender.key(ord('A'), True)
        self.sender.key(ord('A'), False);self.sender.key(0xffe3, False)
        rows = self.server.wait(lambda rows: ('key', 29, False) in rows)
        self.assertIn(('move', 5130., 1054.), rows)
        self.assertEqual([row for row in rows if row[0] == 'key'],
                         [('key', 29, True), ('key', 30, True), ('key', 30, False), ('key', 29, False)])
        self.assertFalse(self.sender.diagnostics()['modifier_state_known'])

    def test_literal_text_refuses_before_any_key_instead_of_assuming_caps_off(self):
        from dc_compat.computer_eis import UnrepresentableSymbol
        with self.assertRaises(UnrepresentableSymbol):
            self.sender.preflight_text([ord('H'), ord('e')])
        with self.assertRaises(UnrepresentableSymbol):
            self.sender.key(ord('H'), True, literal=True)
        time.sleep(.03)
        self.assertFalse(any(row[0] == 'key' for row in self.server.events))
        self.assertFalse(self.sender.pressed)


class IntegratedEisTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = Server()
        self.manager = ComputerManager({'backend': 'portal'})
        self.portal = self.manager.backend
        self.portal.session = '/fixture/authorized/session'
        self.portal.devices = 3
        self.portal.streams = [{'stream': 46, 'position': [4480, 424], 'logical_size': [1920, 1080]}]
        self.calls = []
        def call(interface, method, signature, values, **kwargs):
            self.calls.append(method)
            if method == 'ConnectToEIS':return self.server.fd
            if method == 'Close':return ()
            raise AssertionError('Unexpected portal action in private EIS fixture: ' + method)
        self.portal._call = call
        await self.portal.submit('_ensure_eis')

    async def asyncTearDown(self):
        await self.manager.close()
        await asyncio.to_thread(self.portal.worker.join, 2)
        self.assertFalse(self.portal.worker.is_alive())
        self.server.close()

    async def test_mcp_keyboard_respects_real_caps_lock_and_never_uses_notify(self):
        result = await self.manager.invoke('computer_type', {'text': 'Aa', 'mode': 'keyboard'})
        self.assertEqual(result['structuredContent']['result']['method'], 'keyboard')
        rows = await asyncio.to_thread(self.server.wait, lambda rows: sum(row[0] == 'key' for row in rows) >= 6)
        self.assertEqual([row for row in rows if row[0] == 'key'], [('key', 30, True), ('key', 30, False), ('key', 42, True), ('key', 30, True), ('key', 30, False), ('key', 42, False)])
        self.assertFalse(any(method.startswith('Notify') for method in self.calls))

    async def test_owned_modifier_stays_down_during_mouse_and_releases(self):
        await self.manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'down'})
        self.assertEqual(self.manager.held_keys, {'Control_L'})
        await self.manager.invoke('computer_mouse', {'action': 'click', 'stream': 46, 'x': 650, 'y': 630})
        await self.manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'up'})
        rows = await asyncio.to_thread(self.server.wait, lambda rows: ('key', 29, False) in rows)
        self.assertLess(rows.index(('key', 29, True)), rows.index(('button', 272, True)))
        self.assertGreater(rows.index(('key', 29, False)), rows.index(('button', 272, False)))
        self.assertFalse(self.manager.held_keys)

    async def test_press_does_not_release_a_modifier_held_by_earlier_call(self):
        await self.manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'down'})
        await self.manager.invoke('computer_key', {'keys': ['A']})
        self.assertEqual(self.manager.held_keys, {'Control_L'})
        self.assertFalse(any(row == ('key', 42, True) for row in self.server.events))
        await self.manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'up'})

    async def test_unowned_release_and_duplicate_aliases_refuse_before_key(self):
        for arguments in [{'keys': ['CTRL'], 'action': 'up'}, {'keys': ['CTRL', 'CONTROL'], 'action': 'down'}]:
            with self.assertRaises(ToolError):await self.manager.invoke('computer_key', arguments)
        self.assertFalse(self.manager.held_keys)
        self.assertFalse(any(row[0] == 'key' for row in self.server.events))

    async def test_unrepresentable_text_refuses_before_ascii_prefix(self):
        with self.assertRaises(ToolError):await self.manager.invoke('computer_type', {'text': 'prefix中', 'mode': 'keyboard'})
        self.assertFalse(any(row[0] == 'key' for row in self.server.events))

    async def test_disconnect_is_not_automatically_reconnected(self):
        self.server.commands.put('disconnect');await asyncio.sleep(.05)
        with self.assertRaises(ToolError):await self.manager.invoke('computer_key', {'keys': ['A']})
        self.assertEqual(self.calls.count('ConnectToEIS'), 1)

    async def test_exact_text_refuses_with_an_owned_shortcut_modifier(self):
        await self.manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'down'})
        with self.assertRaises(ToolError):await self.manager.invoke('computer_type', {'text': 'a'})
        self.assertEqual(self.manager.held_keys, {'Control_L'})
        await self.manager.invoke('computer_key', {'keys': ['CTRL'], 'action': 'up'})

    async def test_close_releases_owned_held_key(self):
        await self.manager.invoke('computer_key', {'keys': ['SHIFT'], 'action': 'down'})
        await self.manager.close()
        rows = await asyncio.to_thread(self.server.wait, lambda rows: ('key', 42, False) in rows)
        self.assertIn(('key', 42, True), rows)
        self.assertFalse(any(row[0] == 'key' and row[1] in (58, 69) for row in rows))

    async def test_failed_second_key_releases_new_modifier_without_replay(self):
        sender = self.portal.eis
        original = sender.key
        def fail_second(keysym, down, **kwargs):
            if keysym == ord('a') and down:
                raise RuntimeError('private fixture rejected second key')
            return original(keysym, down, **kwargs)
        sender.key = fail_second
        with self.assertRaises(ToolError):
            await self.manager.invoke('computer_key', {'keys': ['CTRL', 'A'], 'action': 'down'})
        rows = await asyncio.to_thread(self.server.wait, lambda rows: ('key', 29, False) in rows)
        self.assertEqual([row for row in rows if row[0] == 'key'], [('key', 29, True), ('key', 29, False)])
        self.assertFalse(self.manager.held_keys)

    async def test_failed_eis_cleanup_still_closes_the_portal(self):
        original = self.portal.eis.close
        def fail_after_cleanup():
            original()
            raise RuntimeError('private fixture cleanup fault')
        self.portal.eis.close = fail_after_cleanup
        with self.assertRaises(ToolError):await self.portal.submit('close')
        self.assertIn('Close', self.calls)
        self.assertIsNone(self.portal.session)

    async def test_unconfirmed_portal_close_preserves_offer_and_refuses_reconnect(self):
        original = self.portal._call
        class Offer:
            closed = False
            def close(self):self.closed = True
        offer = Offer();self.portal.clipboard_transaction = offer
        def fail_close(interface, method, signature, values, **kwargs):
            if method == 'Close':raise RuntimeError('private fixture unconfirmed close')
            return original(interface, method, signature, values, **kwargs)
        self.portal._call = fail_close
        try:
            with self.assertRaises(ToolError):await self.portal.submit('close')
            self.assertIsNotNone(self.portal.session)
            self.assertFalse(offer.closed)
            with self.assertRaises(ToolError):await self.portal.submit('_ensure_eis')
            self.assertEqual(self.calls.count('ConnectToEIS'), 1)
        finally:self.portal._call = original


class PrivatePortalEisTests(unittest.IsolatedAsyncioTestCase):
    async def test_unicode_auto_full_mime_restore_survives_eis_disconnect_after_paste(self):
        await self._full_mime_transaction(send_modifiers=True)

    async def test_old_compositor_without_modifiers_authorizes_and_ascii_auto_restores_full_mime(self):
        await self._full_mime_transaction(send_modifiers=False)

    async def _full_mime_transaction(self, *, send_modifiers):
        from dc_compat_computer_tests import PORTAL, wait_file
        from gi.repository import Gio, GLib
        original = {'text/plain;charset=utf-8': b'private original text', 'text/html': b'<b>original format</b>',
                    'image/png': b'\x89PNG\r\nprivate fixture', 'application/octet-stream': b'\x00\xff\x01opaque bytes'}
        server = Server(geometry=(0, 0, 800, 600), send_modifiers=send_modifiers)
        with tempfile.TemporaryDirectory(prefix='hepta-private-unicode-transaction-') as directory:
            path = pathlib.Path(directory)
            bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--print-address=1'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            address = (await asyncio.to_thread(bus.stdout.readline)).decode().strip()
            code = 'SOURCE_MIMES=' + repr(original) + '\n' + PORTAL.replace('import json,os,pathlib,sys,threading', 'import json,os,pathlib,sys,threading,base64')
            code = code.replace("if name=='SelectionRead':", "if name=='ConnectToEIS':\n  fds=Gio.UnixFDList.new();index=fds.append(int(os.environ['HEPTA_PRIVATE_EIS_FD']));invocation.return_value_with_unix_fd_list(GLib.Variant('(h)',(index,)),fds);return\n if name=='SelectionRead':")
            code = code.replace("os.write(write,received.encode())", "os.write(write,SOURCE_MIMES[values[1]])")
            code = code.replace("received=data.decode();record('transfer_received',[len(data)])", "received=base64.b64encode(data).decode();record('transfer_received',[values[1],received])")
            old = "if name=='SetSelection':GLib.idle_add(lambda:(bus.emit_signal(sender,P,C,'SelectionTransfer',GLib.Variant('(osu)',(session,'text/plain;charset=utf-8',1))),False)[1])"
            new = "if name=='SetSelection':GLib.idle_add(lambda:(bus.emit_signal(None,P,C,'SelectionOwnerChanged',GLib.Variant('(oa{sv})',(session,{'session_is_owner':GLib.Variant('b',True),'mime_types':GLib.Variant('(as)',(values[1]['mime_types'],))}))),False)[1])\n if name=='RequestClipboard':GLib.idle_add(lambda:(bus.emit_signal(None,P,C,'SelectionOwnerChanged',GLib.Variant('(oa{sv})',(session,{'session_is_owner':GLib.Variant('b',False),'mime_types':GLib.Variant('(as)',(list(SOURCE_MIMES),))}))),False)[1])\n if name=='RequestTransfer':GLib.idle_add(lambda:(bus.emit_signal(None,P,C,'SelectionTransfer',GLib.Variant('(osu)',(session,values[0],values[1]))),False)[1])"
            self.assertIn(old, code);code = code.replace(old, new)
            code = code.replace("('NotifyPointerMotionAbsolute',['o','a{sv}','u','d','d'],[])", "('ConnectToEIS',['o','a{sv}'],['h']),('NotifyPointerMotionAbsolute',['o','a{sv}','u','d','d'],[])")
            code = code.replace("[('Revoke',[],[]),('SetMode',['s'],[])]", "[('Revoke',[],[]),('SetMode',['s'],[]),('RequestTransfer',['s','u'],[])]")
            portal = subprocess.Popen([sys.executable, '-I', '-c', code, address, str(path / 'portal.json')], env=dict(os.environ, HEPTA_PRIVATE_EIS_FD=str(server.fd)), pass_fds=(server.fd,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.close(server.fd)
            manager = ComputerManager({'backend': 'portal', 'dbus_address': address, 'clipboard_state_dir': str(path / 'clipboard'), 'clipboard_max_snapshot_bytes': 1024 * 1024})
            peer = None
            try:
                await wait_file(path / 'portal.json')
                authorized = await manager.invoke('computer_session', {'action': 'authorize'})
                capabilities = authorized['structuredContent']['result']
                self.assertTrue(capabilities['authorized'])
                self.assertTrue(capabilities['features']['mouse'])
                self.assertTrue(capabilities['features']['key'])
                self.assertTrue(capabilities['features']['type'])
                self.assertEqual(capabilities['input_transport']['modifier_state_known'], send_modifiers)
                methods_before = json.loads((path / 'portal.json').read_text())['records']
                for mode in ('auto', 'keyboard', 'clipboard'):
                    empty = await manager.invoke('computer_type', {'text': '', 'mode': mode})
                    self.assertEqual(empty['structuredContent']['result'],
                                     {'method': 'none', 'submitted': False, 'characters': 0,
                                      'clipboard_modified': False, 'replayed': False})
                self.assertEqual(json.loads((path / 'portal.json').read_text())['records'], methods_before)
                self.assertFalse(any(row[0] == 'key' for row in server.events))
                if not send_modifiers:
                    self.assertIsNone(capabilities['input_transport']['locks'])
                    with self.assertRaises(ToolError):
                        await manager.invoke('computer_type', {'text': 'Hepta ASCII 7', 'mode': 'keyboard'})
                    self.assertFalse(any(row[0] == 'key' for row in server.events))
                peer = Gio.DBusConnection.new_for_address_sync(address, Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
                def request_transfer(mime, serial):
                    peer.call_sync('org.freedesktop.portal.Desktop', '/org/freedesktop/portal/desktop', 'org.hepta.Test', 'RequestTransfer', GLib.Variant('(su)', (mime, serial)), None, Gio.DBusCallFlags.NONE, 1000, None)
                text = 'Hepta真实Wayland café测试🙂' if send_modifiers else 'Hepta ASCII 7'
                task = asyncio.create_task(manager.invoke('computer_type', {'text': text}))
                await asyncio.to_thread(server.wait, lambda rows: ('key', 47, False) in rows)
                server.commands.put('disconnect');await asyncio.sleep(.04)
                request_transfer('text/plain;charset=utf-8', 1)
                result = await asyncio.wait_for(task, 3)
                receipt = result['structuredContent']['result']
                self.assertEqual(receipt['method'], 'clipboard')
                self.assertTrue(receipt['original_bytes_snapshot_complete'])
                self.assertTrue(receipt['original_bytes_offer_restored'])
                self.assertFalse(receipt['original_owner_restored'])
                pasted = await wait_file(path / 'portal.json', lambda value: any(row['method'] == 'transfer_received' and row['params'] == [1, base64.b64encode(text.encode()).decode()] for row in value['records']))
                self.assertTrue(pasted)
                for serial, (mime, raw) in enumerate(original.items(), 2):
                    request_transfer(mime, serial)
                    await wait_file(path / 'portal.json', lambda value: any(row['method'] == 'transfer_received' and row['params'] == [serial, base64.b64encode(raw).decode()] for row in value['records']))
                self.assertFalse(any(row['method'].startswith('Notify') for row in json.loads((path / 'portal.json').read_text())['records']))
                self.assertFalse(manager.held_keys)
            finally:
                if peer:peer.close_sync(None)
                await manager.close();await asyncio.to_thread(manager.backend.worker.join, 2)
                portal.terminate();await asyncio.to_thread(portal.wait, 3)
                bus.terminate();await asyncio.to_thread(bus.wait, 3)
                bus.stdout.close();server.close()

    async def test_real_private_dbus_fd_authorize_to_real_eis_input(self):
        from dc_compat_computer_tests import PORTAL, wait_file
        server = Server(geometry=(0, 0, 800, 600))
        with tempfile.TemporaryDirectory(prefix='hepta-private-portal-eis-') as directory:
            path = pathlib.Path(directory)
            bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--print-address=1'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            address = (await asyncio.to_thread(bus.stdout.readline)).decode().strip()
            self.assertNotEqual(address, os.environ.get('DBUS_SESSION_BUS_ADDRESS'))
            code = PORTAL.replace("if name=='SelectionRead':", "if name=='ConnectToEIS':\n  fds=Gio.UnixFDList.new();index=fds.append(int(os.environ['HEPTA_PRIVATE_EIS_FD']));invocation.return_value_with_unix_fd_list(GLib.Variant('(h)',(index,)),fds);return\n if name=='SelectionRead':")
            code = code.replace("('NotifyPointerMotionAbsolute',['o','a{sv}','u','d','d'],[])", "('ConnectToEIS',['o','a{sv}'],['h']),('NotifyPointerMotionAbsolute',['o','a{sv}','u','d','d'],[])")
            portal = subprocess.Popen([sys.executable, '-I', '-c', code, address, str(path / 'portal.json')],
                env=dict(os.environ, HEPTA_PRIVATE_EIS_FD=str(server.fd)), pass_fds=(server.fd,),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.close(server.fd)
            manager = ComputerManager({'backend': 'portal', 'dbus_address': address, 'clipboard': False})
            try:
                await wait_file(path / 'portal.json')
                result = await manager.invoke('computer_session', {'action': 'authorize'})
                caps = result['structuredContent']['result']
                self.assertEqual(caps['input_transport']['transport'], 'portal_eis_libei')
                self.assertTrue(caps['input_transport']['locks']['caps_lock'])
                await manager.invoke('computer_mouse', {'action': 'click', 'stream': 42, 'x': 123, 'y': 234})
                await manager.invoke('computer_type', {'text': 'Aa', 'mode': 'keyboard'})
                rows = await asyncio.to_thread(server.wait, lambda rows: ('key', 42, False) in rows)
                self.assertIn(('move', 123., 234.), rows)
                self.assertIn(('button', 272, False), rows)
                records = json.loads((path / 'portal.json').read_text())['records']
                methods = [row['method'] for row in records]
                self.assertEqual(methods.count('ConnectToEIS'), 1)
                self.assertFalse(any(method.startswith('Notify') for method in methods))
            finally:
                await manager.close();await asyncio.to_thread(manager.backend.worker.join, 2)
                portal.terminate();await asyncio.to_thread(portal.wait, 3)
                bus.terminate();await asyncio.to_thread(bus.wait, 3)
                bus.stdout.close();server.close()


if __name__ == '__main__':unittest.main()
