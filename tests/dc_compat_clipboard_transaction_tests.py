# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Private clipboard offers and real pipe FDs; never the user clipboard."""
import base64
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.clipboard_transaction import ClipboardTransaction, ClipboardTransactionError, CLIPBOARD, TEXT_MIMES
from dc_compat.registry import ToolError

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')
ORIGINAL = {'text/plain;charset=utf-8': '原始 private text\n'.encode(),
            'text/html': b'<p>original private <b>format</b></p>', 'image/png': PNG,
            'application/x-hepta-fixture-binary': bytes(range(256)) * 128}


class PrivatePortal:
    def __init__(self, original):
        self.original = dict(original)
        self.events, self.threads = deque(), []
        self.session = '/org/freedesktop/portal/desktop/session/private_fixture'
        self.manager = None
        self.sets, self.pastes, self.writes, self.done = [], [], [], []
        self.received, self.reads = {}, []
        self.serial = 0
        self.no_transfer = self.no_owner_signal = self.block_consumer = False
        self.failed_read = None
        self.stalled_read = None
        self.failed_restore = False
        self.on_read = self.on_paste = None
        self.release = threading.Event()

    def initial(self, mimes=None):
        self.manager.selection_changed(self.session, {'session_is_owner': False,
            'mime_types': list(self.original) if mimes is None else mimes})

    def external(self):
        self.manager.selection_changed(self.session, {'session_is_owner': False, 'mime_types': ['text/plain']})

    def _thread(self, function):
        worker = threading.Thread(target=function, daemon=True)
        self.threads.append(worker)
        worker.start()

    def request(self, mime, serial=None):
        self.serial += 1
        serial = self.serial if serial is None else serial
        self.events.append(lambda: self.manager.selection_transfer(self.session, mime, serial))
        return serial

    def call(self, interface, method, signature, values, *, fd=False):
        assert interface == CLIPBOARD
        if method == 'SelectionRead':
            mime = values[1]
            self.reads.append(mime)
            if self.on_read:
                self.on_read(mime)
            if mime == self.failed_read:
                raise RuntimeError('synthetic unreadable format')
            read, write = os.pipe()
            payload = self.original[mime]
            def provide():
                try:
                    if mime == self.stalled_read:
                        self.release.wait(3)
                    for offset in range(0, len(payload), 4096):
                        os.write(write, payload[offset:offset + 4096])
                except BrokenPipeError:
                    pass
                finally:
                    os.close(write)
            self._thread(provide)
            return read
        if method == 'SetSelection':
            mimes = tuple(values[1]['mime_types'])
            self.sets.append(mimes)
            if self.failed_restore and len(self.sets) == 2:
                raise RuntimeError('synthetic restoration failure')
            if not self.no_owner_signal:
                self.events.append(lambda: self.manager.selection_changed(self.session,
                    {'session_is_owner': True, 'mime_types': list(mimes)}))
            return ()
        if method == 'SelectionWrite':
            serial = values[1]
            self.writes.append(serial)
            read, write = os.pipe()
            def receive():
                if self.block_consumer:
                    self.release.wait(3)
                data = bytearray()
                try:
                    while True:
                        block = os.read(read, 65536)
                        if not block:
                            break
                        data.extend(block)
                    self.received[serial] = bytes(data)
                finally:
                    os.close(read)
            self._thread(receive)
            return write
        if method == 'SelectionWriteDone':
            self.done.append((values[1], values[2]))
            return ()
        raise AssertionError(method)

    def pump(self, seconds):
        while self.events:
            self.events.popleft()()
        if seconds:
            time.sleep(min(seconds, .001))

    def paste(self, keys):
        self.pastes.append(keys)
        if not self.no_transfer:
            self.request(TEXT_MIMES[0])
        if self.on_paste:
            self.on_paste()

    def wait_received(self, serial):
        deadline = time.monotonic() + 3
        while serial not in self.received and time.monotonic() < deadline:
            self.pump(.001)
        assert serial in self.received, 'private consumer did not finish'
        return self.received[serial]

    def close(self):
        self.release.set()
        self.session = None
        self.manager.close()
        for worker in self.threads:
            worker.join(3)


class Transactions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.portal = PrivatePortal(ORIGINAL)
        self.manager = self.portal.manager = ClipboardTransaction(self.portal.call, self.portal.pump,
            self.portal.paste, lambda: self.portal.session, self.root / 'private',
            max_snapshot_bytes=8 * 1024 * 1024, make_options=lambda formats: {'mime_types': list(formats)},
            timeout_seconds=.12)
        self.portal.initial()

    def tearDown(self):
        self.portal.close()
        self.tmp.cleanup()

    def restore_reads(self, expected):
        for mime, payload in expected.items():
            serial = self.portal.request(mime)
            self.portal.pump(0)
            self.assertEqual(self.portal.wait_received(serial), payload)
            self.assertIn((serial, True), self.portal.done)

    def test_all_mime_binary_html_png_and_unicode_exact_after_idle_restore(self):
        text = '事务中文 👩🏽‍💻\nline two'
        receipt = self.manager.run(text)
        self.assertEqual(self.portal.pastes, [('CTRL', 'V')])
        self.assertEqual(self.portal.wait_received(receipt['transfers'][0]['serial']), text.encode())
        self.assertTrue(receipt['original_bytes_snapshot_complete'])
        self.assertTrue(receipt['original_bytes_offer_restored'])
        self.assertFalse(receipt['original_owner_restored'])
        self.assertFalse(receipt['atomic_compare_and_set_available'])
        self.assertFalse(receipt['target_input_verified'])
        self.assertEqual(self.portal.sets, [TEXT_MIMES, tuple(ORIGINAL)])
        time.sleep(.01)
        self.restore_reads(ORIGINAL)
        public = json.dumps(receipt)
        for secret in ('original private', 'image/png', 'text/html', str(self.root)):
            self.assertNotIn(secret, public)
        for path in (self.root / 'private').rglob('*'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)

    def test_large_original_real_pipe_is_complete_and_later_served(self):
        self.portal.original = {'application/x-large': bytes(range(256)) * 8192}
        self.portal.initial()
        receipt = self.manager.run('large payload', ('CTRL', 'SHIFT', 'V'))
        self.assertTrue(receipt['original_bytes_offer_restored'])
        self.assertEqual(self.portal.pastes, [('CTRL', 'SHIFT', 'V')])
        self.restore_reads(self.portal.original)

    def test_missing_initial_complete_offer_refuses_before_mutation(self):
        self.manager.reset()
        with self.assertRaises(ClipboardTransactionError) as error:
            self.manager.run('never pasted')
        self.assertFalse(error.exception.receipt['clipboard_publication_attempted'])
        self.assertEqual(self.portal.reads, [])
        self.assertEqual(self.portal.sets, [])
        self.assertEqual(self.portal.pastes, [])

    def test_incomplete_format_signal_is_not_inferred_from_utf8(self):
        self.manager.selection_changed(self.portal.session, {'session_is_owner': False})
        with self.assertRaises(ClipboardTransactionError):
            self.manager.run('never pasted')
        self.assertEqual(self.portal.sets, [])

    def test_unreadable_one_of_many_formats_prevents_all_clipboard_writes(self):
        self.portal.failed_read = 'text/html'
        with self.assertRaises(ClipboardTransactionError) as error:
            self.manager.run('never pasted')
        self.assertFalse(error.exception.receipt['original_bytes_snapshot_complete'])
        self.assertEqual(self.portal.sets, [])
        self.assertEqual(self.portal.pastes, [])

    def test_source_read_stall_times_out_before_any_clipboard_mutation(self):
        self.portal.stalled_read = 'text/html'
        with self.assertRaises(ClipboardTransactionError) as error:
            self.manager.run('not pasted')
        self.assertEqual(error.exception.receipt['failure_reason'], 'transfer_or_owner_timeout')
        self.assertEqual(self.portal.sets, [])
        self.assertEqual(self.portal.pastes, [])

    def test_explicit_snapshot_budget_refuses_instead_of_truncating_or_pasting(self):
        self.manager.max_snapshot_bytes = 10
        with self.assertRaises(ClipboardTransactionError) as error:
            self.manager.run('never pasted')
        self.assertEqual(error.exception.receipt['failure_reason'], 'snapshot_budget_exceeded')
        self.assertEqual(self.portal.sets, [])
        self.assertEqual(self.portal.pastes, [])

    def test_external_change_while_reading_original_refuses_before_set(self):
        self.portal.on_read = lambda _: self.portal.events.append(self.portal.external)
        with self.assertRaises(ClipboardTransactionError):
            self.manager.run('never pasted')
        self.assertEqual(self.portal.sets, [])

    def test_external_change_after_paste_is_never_overwritten_by_restore(self):
        self.portal.on_paste = lambda: self.portal.events.append(self.portal.external)
        with self.assertRaises(ClipboardTransactionError) as error:
            self.manager.run('one attempted paste')
        receipt = error.exception.receipt
        self.assertTrue(receipt['backup_retained'])
        self.assertEqual(receipt['restoration'], 'external_owner_changed_not_overwritten')
        self.assertEqual(len(self.portal.sets), 1)
        self.assertEqual(len(self.portal.pastes), 1)

    def test_owner_change_queued_at_publication_is_checked_before_setselection(self):
        publish = self.manager._publish_offer
        def interrupted(offer, **options):
            self.portal.events.append(self.portal.external)
            return publish(offer, **options)
        with mock.patch.object(self.manager, '_publish_offer', interrupted):
            with self.assertRaises(ClipboardTransactionError):
                self.manager.run('not pasted')
        self.assertEqual(self.portal.sets, [])
        self.assertEqual(self.portal.pastes, [])

    def test_owner_change_queued_at_restoration_is_checked_before_setselection(self):
        publish = self.manager._publish_offer
        def interrupted(offer, **options):
            if offer.kind == 'restored_original':
                self.portal.events.append(self.portal.external)
            return publish(offer, **options)
        with mock.patch.object(self.manager, '_publish_offer', interrupted):
            with self.assertRaises(ClipboardTransactionError) as error:
                self.manager.run('one attempted paste')
        self.assertFalse(error.exception.receipt['original_bytes_offer_restored'])
        self.assertTrue(error.exception.receipt['backup_retained'])
        self.assertEqual(len(self.portal.sets), 1)
        self.assertEqual(len(self.portal.pastes), 1)

    def test_restore_exception_retains_complete_private_backup_and_reports_error(self):
        self.portal.failed_restore = True
        with self.assertRaises(ClipboardTransactionError) as error:
            self.manager.run('one paste')
        receipt = error.exception.receipt
        self.assertTrue(receipt['original_bytes_snapshot_complete'])
        self.assertTrue(receipt['backup_retained'])
        self.assertFalse(receipt['original_bytes_offer_restored'])
        self.assertEqual(receipt['restoration'], 'restore_failed_private_backup_retained')
        manifests = list((self.root / 'private').glob('clipboard-*/snapshot.json'))
        self.assertTrue(json.loads(manifests[0].read_bytes())['complete'])
        self.assertEqual(len(self.portal.pastes), 1)

    def test_no_consumer_transfer_times_out_restores_and_never_replays_paste(self):
        self.portal.no_transfer = True
        with self.assertRaises(ClipboardTransactionError) as error:
            self.manager.run('one paste')
        self.assertTrue(error.exception.receipt['original_bytes_offer_restored'])
        self.assertEqual(len(self.portal.pastes), 1)
        self.restore_reads(ORIGINAL)

    def test_write_timeout_reports_false_done_then_restores_without_replay(self):
        self.portal.block_consumer = True
        with self.assertRaises(ClipboardTransactionError) as error:
            self.manager.run('大' * 200000)
        self.assertTrue(error.exception.receipt['original_bytes_offer_restored'])
        self.assertEqual(len(self.portal.pastes), 1)
        self.assertFalse(error.exception.receipt['transfers'][0]['complete'])
        self.assertIn((error.exception.receipt['transfers'][0]['serial'], False), self.portal.done)

    def test_duplicate_transfer_serial_is_not_written_twice(self):
        receipt = self.manager.run('single transfer')
        serial = receipt['transfers'][0]['serial']
        self.manager.selection_transfer(self.portal.session, TEXT_MIMES[0], serial)
        self.assertEqual(self.portal.writes.count(serial), 1)
        self.assertEqual(sum(item[0] == serial for item in self.portal.done), 1)

    def test_repeated_transaction_reuses_original_snapshot_and_idle_offer(self):
        self.manager.run('first')
        self.manager.run('second')
        self.assertEqual(len(list((self.root / 'private').glob('clipboard-*'))), 1)
        self.assertEqual(len(self.portal.pastes), 2)
        self.restore_reads(ORIGINAL)

    def test_explicit_clipboard_set_can_be_snapshotted_and_restored(self):
        self.manager.offer_text('explicit original 中文')
        self.manager.run('temporary Unicode 👋')
        self.restore_reads({mime: 'explicit original 中文'.encode() for mime in TEXT_MIMES})

    def test_private_spool_mutation_refuses_before_sending_changed_original(self):
        self.manager.run('temporary')
        offer = self.manager.serving
        item = offer.entries['text/html']
        (self.root / 'private' / offer.backup_id / item['file']).write_bytes(b'changed unsafe original')
        serial = self.portal.request('text/html')
        self.portal.pump(0)
        self.assertIn((serial, False), self.portal.done)
        self.assertNotIn(serial, self.portal.writes)

    def test_replaced_private_root_refuses_before_any_clipboard_mutation(self):
        state = self.root / 'private'
        state.rename(self.root / 'detached-original-private')
        state.mkdir(mode=0o700)
        with self.assertRaises(ClipboardTransactionError):
            self.manager.run('not pasted')
        self.assertEqual(self.portal.sets, [])
        self.assertEqual(self.portal.pastes, [])

    def test_live_lazy_restore_offer_cannot_be_closed_early(self):
        self.manager.run('temporary')
        with self.assertRaises(ToolError):
            self.manager.close()
        with self.assertRaises(ToolError):
            self.manager.reset()
        self.restore_reads(ORIGINAL)

    def test_gnome_46_tuple_wrapped_mime_offer_is_complete_without_guessing(self):
        self.manager.selection_changed(self.portal.session, {'session_is_owner': False,
            'mime_types': (list(ORIGINAL),)})
        self.assertTrue(self.manager.run('known GNOME form')['original_bytes_offer_restored'])
        self.restore_reads(ORIGINAL)

    def test_empty_offer_cannot_be_restored_by_mutter_and_refuses_before_set(self):
        self.manager.selection_changed(self.portal.session, {'session_is_owner': False, 'mime_types': []})
        with self.assertRaises(ClipboardTransactionError):
            self.manager.run('not pasted')
        self.assertEqual(self.portal.sets, [])

    def test_administrator_metadata_budgets_refuse_whole_offer_without_truncation(self):
        self.manager.max_mime_types = 1
        self.portal.initial()
        with self.assertRaises(ClipboardTransactionError):
            self.manager.run('not pasted')
        self.assertEqual(self.portal.sets, [])
        self.manager.max_mime_types = 256
        self.manager.max_mime_name_bytes = 3
        self.portal.initial()
        with self.assertRaises(ClipboardTransactionError):
            self.manager.run('not pasted')
        self.assertEqual(self.portal.sets, [])


class PrivateDBus(unittest.TestCase):
    def test_real_private_bus_unix_fd_roundtrip_all_formats_and_idle_restore(self):
        if not shutil.which('dbus-daemon'):
            self.skipTest('private D-Bus dependency unavailable')
        try:
            from gi.repository import Gio, GLib
        except ImportError:
            self.skipTest('Gio dependency unavailable')
        temporary = tempfile.TemporaryDirectory()
        bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--print-address=1'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        address = bus.stdout.readline().decode().strip()
        self.assertNotEqual(address, os.environ.get('DBUS_SESSION_BUS_ADDRESS'))
        ready, stop = threading.Event(), threading.Event()
        received, workers, failures = {}, [], []
        session = '/org/freedesktop/portal/desktop/session/private_wire_fixture'
        portal_path = '/org/freedesktop/portal/desktop'
        shared = {}
        def producer(fd, data):
            try:
                for start in range(0, len(data), 4096):
                    os.write(fd, data[start:start + 4096])
            except BrokenPipeError:
                pass
            finally:
                os.close(fd)
        def receiver(fd, serial):
            data = bytearray()
            try:
                while True:
                    block = os.read(fd, 65536)
                    if not block:
                        break
                    data.extend(block)
                received[serial] = bytes(data)
            finally:
                os.close(fd)
        def spawn(function, *args):
            thread = threading.Thread(target=function, args=args, daemon=True)
            workers.append(thread)
            thread.start()
        def server():
            context = GLib.MainContext.new()
            context.push_thread_default()
            connection = None
            try:
                connection = Gio.DBusConnection.new_for_address_sync(address,
                    Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
                connection.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus',
                    'RequestName', GLib.Variant('(su)', ('org.freedesktop.portal.Desktop', 0)), None, Gio.DBusCallFlags.NONE, 2000, None)
                shared['server'] = connection
                methods = [('SetSelection', ['o', 'a{sv}'], []), ('SelectionRead', ['o', 's'], ['h']),
                    ('SelectionWrite', ['o', 'u'], ['h']), ('SelectionWriteDone', ['o', 'u', 'b'], [])]
                xml = '<node><interface name="' + CLIPBOARD + '">' + ''.join('<method name="' + name + '">' +
                    ''.join('<arg direction="in" type="' + kind + '"/>' for kind in ins) +
                    ''.join('<arg direction="out" type="' + kind + '"/>' for kind in outs) + '</method>'
                    for name, ins, outs in methods) + '</interface></node>'
                def dispatch(conn, sender, path, interface, method, params, invocation):
                    values = params.unpack()
                    if method == 'SetSelection':
                        invocation.return_value(GLib.Variant('()', ()))
                        connection.emit_signal(sender, portal_path, CLIPBOARD, 'SelectionOwnerChanged',
                            GLib.Variant('(oa{sv})', (session, {'session_is_owner': GLib.Variant('b', True),
                                'mime_types': GLib.Variant('as', values[1]['mime_types'])})))
                    elif method in ('SelectionRead', 'SelectionWrite'):
                        read, write = os.pipe()
                        handed = read if method == 'SelectionRead' else write
                        fds = Gio.UnixFDList.new()
                        index = fds.append(handed)
                        os.close(handed)
                        if method == 'SelectionRead':
                            spawn(producer, write, ORIGINAL[values[1]])
                        else:
                            spawn(receiver, read, values[1])
                        invocation.return_value_with_unix_fd_list(GLib.Variant('(h)', (index,)), fds)
                    else:
                        invocation.return_value(GLib.Variant('()', ()))
                info = Gio.DBusNodeInfo.new_for_xml(xml)
                connection.register_object(portal_path, info.interfaces[0], dispatch, None, None)
                ready.set()
                while not stop.wait(.001):
                    while context.pending():
                        context.iteration(False)
            except Exception as error:
                failures.append(type(error).__name__)
                ready.set()
            finally:
                if connection is not None:
                    connection.close_sync(None)
                context.pop_thread_default()
        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(4))
        self.assertEqual(failures, [])
        context = GLib.MainContext.new()
        context.push_thread_default()
        connection = Gio.DBusConnection.new_for_address_sync(address,
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
        manager = None
        state = {'session': session, 'serial': 0, 'paste_calls': 0}
        def call(interface, method, signature, values, *, fd=False):
            if fd:
                value, descriptors = connection.call_with_unix_fd_list_sync('org.freedesktop.portal.Desktop',
                    portal_path, interface, method, GLib.Variant(signature, values), None, Gio.DBusCallFlags.NONE, 2000, None, None)
                return descriptors.get(value.unpack()[0])
            return connection.call_sync('org.freedesktop.portal.Desktop', portal_path, interface, method,
                GLib.Variant(signature, values), None, Gio.DBusCallFlags.NONE, 2000, None).unpack()
        def pump(seconds):
            end = time.monotonic() + seconds
            while True:
                while context.pending():
                    context.iteration(False)
                if time.monotonic() >= end:
                    break
                time.sleep(.001)
        def request(mime):
            state['serial'] += 1
            shared['server'].emit_signal(connection.get_unique_name(), portal_path, CLIPBOARD, 'SelectionTransfer',
                GLib.Variant('(osu)', (session, mime, state['serial'])))
            return state['serial']
        def paste(keys):
            self.assertEqual(keys, ('CTRL', 'V'))
            state['paste_calls'] += 1
            request(TEXT_MIMES[0])
        try:
            manager = ClipboardTransaction(call, pump, paste, lambda: state['session'], Path(temporary.name) / 'state',
                max_snapshot_bytes=1024 * 1024, make_options=lambda formats: {'mime_types': GLib.Variant('as', list(formats))},
                timeout_seconds=2)
            def changed(conn, sender, path, iface, name, parameters):
                manager.selection_changed(*parameters.unpack())
            def transfer(conn, sender, path, iface, name, parameters):
                manager.selection_transfer(*parameters.unpack())
            connection.signal_subscribe('org.freedesktop.portal.Desktop', CLIPBOARD, 'SelectionOwnerChanged',
                portal_path, None, Gio.DBusSignalFlags.NONE, changed)
            connection.signal_subscribe('org.freedesktop.portal.Desktop', CLIPBOARD, 'SelectionTransfer',
                portal_path, None, Gio.DBusSignalFlags.NONE, transfer)
            connection.flush_sync(None)
            # Flush AddMatch before asking the private server to emit a signal.
            connection.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus',
                'GetId', None, None, Gio.DBusCallFlags.NONE, 2000, None)
            shared['server'].emit_signal(connection.get_unique_name(), portal_path, CLIPBOARD, 'SelectionOwnerChanged',
                GLib.Variant('(oa{sv})', (session, {'session_is_owner': GLib.Variant('b', False),
                    'mime_types': GLib.Variant('(as)', (list(ORIGINAL),))})))
            deadline = time.monotonic() + 2
            while manager.observed is None and time.monotonic() < deadline:
                pump(.01)
            receipt = manager.run('私有 wire Unicode 👩🏽‍💻')
            self.assertTrue(receipt['original_bytes_offer_restored'])
            expected = {receipt['transfers'][0]['serial']: '私有 wire Unicode 👩🏽‍💻'.encode()}
            for mime, data in ORIGINAL.items():
                expected[request(mime)] = data
                pump(.01)
            deadline = time.monotonic() + 3
            while not expected.keys() <= received.keys() and time.monotonic() < deadline:
                pump(.01)
            self.assertEqual({serial: received.get(serial) for serial in expected}, expected)
            self.assertEqual(state['paste_calls'], 1)
            self.assertEqual(failures, [])
        finally:
            state['session'] = None
            if manager is not None:
                manager.close()
            connection.close_sync(None)
            context.pop_thread_default()
            stop.set()
            thread.join(4)
            for worker in workers:
                worker.join(3)
            bus.terminate()
            bus.wait(timeout=4)
            bus.stdout.close()
            temporary.cleanup()


if __name__ == '__main__':
    unittest.main()
