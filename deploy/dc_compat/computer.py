# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent Linux GUI providers: genuine X11 or consented XDG portal/PipeWire.

The X11 provider refuses XWayland by default. The Wayland provider never falls
back to xdotool, Shell Eval, or an accessibility permission change. Its explicit
session authorization is the only operation that can open a portal dialog.
No Desktop Commander process, package, service, or credentials are used.
"""
from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import hmac
import fcntl
import io
import json
import math
import os
import pathlib
import queue
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import threading
import time
import uuid

from .registry import ToolError, text_result
from .clipboard_transaction import ClipboardTransactionError
from .x11_keyboard import X11KeyboardError, X11Unrepresentable
from .input_context import INPUT_CLIENT


def _tool(name, description, properties=None, required=()):
    return {'name': name, 'description': description,
            'inputSchema': {'type': 'object', 'properties': properties or {},
                            'required': list(required), 'additionalProperties': False}}


_number = {'type': 'number', 'minimum': 0, 'maximum': 100000}
COMPUTER_TOOLS = [
    _tool('computer_capabilities', 'Read actual GUI backend, permissions, screen streams and limitations; does not authorize or capture.'),
    _tool('computer_session', 'Authorize a Wayland RemoteDesktop/ScreenCast session through the system consent dialog, inspect it, or close it. restore_session defaults true to reuse the saved grant. false requires no active session and opens the standard chooser; the user must select every desired screen. A failed chooser preserves the saved grant. Active sessions are never silently closed or expanded.',
          {'action': {'enum': ['authorize', 'status', 'close', 'acquire_input', 'renew_input', 'release_input',
                              'clipboard_status', 'clipboard_backups', 'restore_clipboard']},
           'restore_session': {'type': 'boolean', 'default': True},
           'lease_seconds': {'type': 'integer', 'minimum': 1, 'maximum': 300},
           'snapshot_id': {'type': 'string', 'pattern': '^[0-9a-f]{32}$'},
           'expected_owner': {'type': 'integer', 'minimum': 0}}, ['action']),
    _tool('computer_screenshot', 'Capture PNG from the selected genuine X11 display or a user-granted Wayland PipeWire stream. Returns an MCP image. Coordinates are reported separately from resized image pixels.',
          {'stream': {'type': 'integer', 'minimum': 0}, 'max_width': {'type': 'integer', 'minimum': 64, 'maximum': 8192}}),
    _tool('computer_mouse', 'Move/click/drag/scroll in desktop logical coordinates. On Wayland choose a granted stream; coordinates are relative to its logical size.',
          {'action': {'enum': ['move', 'click', 'double_click', 'down', 'up', 'drag', 'scroll']},
           'x': _number, 'y': _number, 'to_x': _number, 'to_y': _number,
           'stream': {'type': 'integer', 'minimum': 0},
           'button': {'enum': ['left', 'middle', 'right']},
           'direction': {'enum': ['up', 'down', 'left', 'right']},
           'steps': {'type': 'integer', 'minimum': 1, 'maximum': 100},
           'duration_ms': {'type': 'integer', 'minimum': 0, 'maximum': 5000}}, ['action']),
    _tool('computer_key', 'Operate physical keys or a combination, such as ["CTRL", "A"]. action press (default) releases its own keys; down/up hold or release keys across mouse calls. Only this provider\'s keys are released. No automatic input replay.',
          {'keys': {'type': 'array', 'items': {'type': 'string', 'minLength': 1, 'maxLength': 40}, 'minItems': 1, 'maxItems': 8, 'uniqueItems': True},
           'action': {'enum': ['press', 'down', 'up']}}, ['keys']),
    _tool('computer_type', 'Insert exact text in the focused window. auto first checks the whole text against the current XKB layout/locks, then uses either existing keyboard mappings or a clipboard transaction that saves every supported original data format and restores it. Incomplete or unsupported clipboard snapshots refuse before modification. keyboard forbids clipboard use; clipboard explicitly chooses the transaction. No input replay.',
          {'text': {'type': 'string', 'maxLength': 16384}, 'mode': {'enum': ['auto', 'keyboard', 'clipboard']},
           'unicode_method': {'enum': ['gtk_hex'], 'description': 'Explicit GTK-compatible Unicode hexadecimal composition, only with mode=keyboard. Does not use the clipboard or change keymaps/locks. Choose only for a known compatible input method; no automatic toolkit detection.'},
           'paste_keys': {'type': 'array', 'items': {'type': 'string', 'minLength': 1, 'maxLength': 40}, 'minItems': 1, 'maxItems': 8, 'uniqueItems': True}}, ['text']),
    _tool('computer_window', 'List or focus exact desktop windows. X11 supports window IDs. Wayland does not expose a universal focus/list API: this provider reports that limitation instead of treating XWayland windows as the whole desktop.',
          {'action': {'enum': ['list', 'focus']}, 'window_id': {'type': 'string', 'pattern': '^[0-9]+$'}}, ['action']),
    _tool('computer_clipboard', 'Read or set UTF-8 clipboard text through X11 ownership or the explicitly granted Wayland Clipboard portal. Existing clipboard contents are private tool data.',
          {'action': {'enum': ['get', 'set']}, 'text': {'type': 'string', 'maxLength': 1048576}}, ['action']),
]

for _definition in COMPUTER_TOOLS:
    if _definition['name'] not in ('computer_capabilities', 'computer_screenshot'):
        _definition['inputSchema']['properties']['input_lease'] = {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}
        _definition['description'] += (' Input held across calls is reserved to its MCP session. '
            'computer_session acquire_input reserves a complete gesture; pass its input_lease when continuing '
            'through another CLI connection. Leases expire and release only provider-held keys/buttons.')
COMPUTER_TOOLS[1]['description'] += (' acquire_input/renew_input/release_input manage an exclusive input lease '
    '(lease_seconds defaults 30). clipboard_status/clipboard_backups inspect private X11 recovery metadata; '
    'restore_clipboard explicitly restores snapshot_id only if expected_owner=0 still matches an empty selection.')


def _png_result(raw, metadata, max_width=1920):
    from PIL import Image
    if len(raw) > 64 * 1024 * 1024:
        raise ToolError('Screenshot exceeds the image byte limit')
    with Image.open(io.BytesIO(raw)) as original:
        if original.width * original.height > 64 * 1024 * 1024:
            raise ToolError('Screenshot exceeds the pixel limit')
        image = original.convert('RGB')
        metadata = dict(metadata, capture_pixel_size=[image.width, image.height])
        if image.width > max_width:
            image = image.resize((max_width, max(1, round(image.height * max_width / image.width))), Image.Resampling.LANCZOS)
        target = io.BytesIO()
        image.save(target, format='PNG')
        metadata['image_pixel_size'] = [image.width, image.height]
    return {'content': [{'type': 'image', 'mimeType': 'image/png', 'data': base64.b64encode(target.getvalue()).decode('ascii')},
                        {'type': 'text', 'text': json.dumps(metadata, ensure_ascii=False)}],
            'structuredContent': metadata}


_KEYS = {'CTRL': 'Control_L', 'CONTROL': 'Control_L', 'ALT': 'Alt_L',
         'SHIFT': 'Shift_L', 'SUPER': 'Super_L', 'META': 'Super_L',
         'ENTER': 'Return', 'RETURN': 'Return', 'ESC': 'Escape', 'ESCAPE': 'Escape',
         'TAB': 'Tab', 'SPACE': 'space', 'BACKSPACE': 'BackSpace', 'DELETE': 'Delete',
         'HOME': 'Home', 'END': 'End', 'PAGEUP': 'Page_Up', 'PAGEDOWN': 'Page_Down',
         'LEFT': 'Left', 'RIGHT': 'Right', 'UP': 'Up', 'DOWN': 'Down', 'INSERT': 'Insert'}
_KEYS.update({'CAPSLOCK': 'Caps_Lock', 'NUMLOCK': 'Num_Lock', 'PRINTSCREEN': 'Print',
              'MENU': 'Menu', 'PAUSE': 'Pause', 'SCROLLLOCK': 'Scroll_Lock'})
_KEYSYMS = {'Control_L': 0xffe3, 'Alt_L': 0xffe9, 'Shift_L': 0xffe1, 'Super_L': 0xffeb,
            'Return': 0xff0d, 'Escape': 0xff1b, 'Tab': 0xff09, 'space': 0x20,
            'BackSpace': 0xff08, 'Delete': 0xffff, 'Home': 0xff50, 'End': 0xff57,
            'Page_Up': 0xff55, 'Page_Down': 0xff56, 'Left': 0xff51, 'Right': 0xff53,
            'Up': 0xff52, 'Down': 0xff54, 'Insert': 0xff63,
            **{'F' + str(index): 0xffbd + index for index in range(1, 36)}}
_KEYSYMS.update({'Caps_Lock': 0xffe5, 'Num_Lock': 0xff7f, 'Print': 0xff61,
                 'Menu': 0xff67, 'Pause': 0xff13, 'Scroll_Lock': 0xff14})


def _key_name(key):
    if not isinstance(key, str) or not key:
        raise ToolError('Invalid key')
    if key.upper() in _KEYS:
        return _KEYS[key.upper()]
    if len(key) == 1:
        return key.lower() if key.isascii() and key.isalpha() else key
    if re.fullmatch(r'F(?:[1-9]|[12][0-9]|3[0-5])', key.upper()):
        return key.upper()
    raise ToolError('Unsupported key name: use a character, F1-F35 or a documented modifier/navigation key')


class _X11:
    def __init__(self, config):
        self.config = config
        self.display = config.get('display') or os.environ.get('DISPLAY')
        self.env = dict(os.environ, DISPLAY=self.display or '')
        if config.get('xauthority'):
            self.env['XAUTHORITY'] = str(config['xauthority'])
        self.clipboard_owner = None
        self.keyboard = None
        self.selection = None
        self.checked = False

    def _run(self, args, data=None, timeout=10, allow_empty=False):
        try:
            proc = subprocess.Popen(args, env=self.env, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True)
            try:
                out, error = proc.communicate(data, timeout=timeout)
            except BaseException:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()
                raise
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ToolError('GUI command unavailable or timed out: ' + type(error).__name__) from None
        if proc.returncode and not allow_empty:
            # Command stderr may include window titles or private typed text.
            raise ToolError('GUI operation failed (exit ' + str(proc.returncode) + ')')
        return out

    def _check(self):
        if not self.display:
            raise ToolError('No explicit X11 display is available')
        if not self.checked:
            raw = self._run(['xdpyinfo', '-queryExtensions'])
            if b'XWAYLAND' in raw and not self.config.get('allow_partial_xwayland', False):
                raise ToolError('This display is XWayland, which cannot control the full Wayland desktop. Use the consented portal backend.')
            self.checked = True

    def capabilities(self):
        try:
            self._check()
            size = [int(x) for x in self._run(['xdotool', 'getdisplaygeometry']).split()]
            return {'backend': 'x11', 'authorized': True, 'scope': 'explicit X11 display',
                    'display': self.display, 'logical_size': size,
                    'features': {name: bool(shutil.which(command)) for name, command in
                                 [('screenshot', 'import'), ('mouse', 'xdotool'), ('key', 'xdotool'),
                                  ('type', 'xdotool'), ('window_list', 'xdotool'),
                                  ('window_focus', 'xdotool'), ('clipboard', 'xclip')]}}
        except ToolError as error:
            return {'backend': 'x11', 'authorized': False, 'reason': str(error), 'features': {}}

    def authorize(self):
        self._check()
        return self.capabilities()

    def screenshot(self, args):
        self._check()
        if math.prod(self.capabilities()['logical_size']) > 64 * 1024 * 1024:
            raise ToolError('Display exceeds the configured pixel limit')
        raw = self._run(['import', '-display', self.display, '-window', 'root', 'png:-'], timeout=20)
        return _png_result(raw, {'backend': 'x11', 'logical_size': self.capabilities()['logical_size']}, args.get('max_width', 1920))

    def prepare_input(self, mask):
        self._check()

    def validate_position(self, x, y, stream=None):
        self._check()
        size = self.capabilities()['logical_size']
        if not (0 <= x < size[0] and 0 <= y < size[1]):
            raise ToolError('Coordinates are outside the X11 display')
        return size

    def move(self, x, y, stream=None):
        size = self.validate_position(x, y, stream)
        # A valid fractional coordinate at the edge must round to a real pixel.
        target = [min(size[0] - 1, round(x)), min(size[1] - 1, round(y))]
        raw = self._run(['xdotool', 'getmouselocation', '--shell'])
        rows = re.findall(rb'^(X|Y|SCREEN)=([0-9]+)$', raw, re.M)
        if len(rows) != 3 or {key for key, _ in rows} != {b'X', b'Y', b'SCREEN'}:
            raise ToolError('Cannot verify the current X11 pointer position; no move submitted')
        current = {key: int(value) for key, value in rows}
        # xdotool mousemove defaults to X screen 0. Its --sync waits for a
        # change from the old position even when a warp targets that position.
        if current[b'SCREEN'] == 0 and [current[b'X'], current[b'Y']] == target:
            return
        self._run(['xdotool', 'mousemove', '--sync', str(target[0]), str(target[1])])

    def button(self, button, down):
        self._check()
        self._run(['xdotool', 'mousedown' if down else 'mouseup', str({'left': 1, 'middle': 2, 'right': 3}[button])])

    def scroll(self, direction, steps):
        self._check()
        self._run(['xdotool', 'click', '--repeat', str(steps), '--delay', '30', str({'up': 4, 'down': 5, 'left': 6, 'right': 7}[direction])])

    def key(self, key, down):
        self._check()
        self._run(['xdotool', 'keydown' if down else 'keyup', key])

    def _keyboard_manager(self):
        if self.keyboard is None:
            from .x11_keyboard import X11Keyboard
            self.keyboard = X11Keyboard(self.env, self.config)
        return self.keyboard

    def _selection_manager(self):
        if self.selection is None:
            from .x11_selection import X11Selection
            root = self.config.get('clipboard_state_dir')
            if not root or not pathlib.Path(root).is_absolute():
                raise ToolError('An explicit private absolute clipboard_state_dir is required for X11 clipboard transactions')
            self.selection = X11Selection(self.config, self.display, self.env, root,
                self.config.get('clipboard_max_snapshot_bytes', 32 * 1024 * 1024))
        return self.selection

    def _type_via_clipboard(self, text, paste_keys):
        keyboard = self._keyboard_manager()
        prepared = None
        used = False
        normalized = [_key_name(key) for key in paste_keys]
        def paste(keys, *, preflight):
            nonlocal prepared, used
            if tuple(keys) != tuple(paste_keys):
                raise ToolError('Clipboard paste keys changed; no replay')
            if preflight:
                if prepared is not None:
                    raise ToolError('Clipboard paste was already prepared; no replay')
                prepared = keyboard.prepare_combo(normalized)
                return {'prepared': True, 'submitted': False}
            if prepared is None or used:
                raise ToolError('Clipboard paste was not prepared or was already attempted; no replay')
            used = True
            return keyboard.send_combo(prepared)
        try:
            value = self._selection_manager().run(text, paste, tuple(paste_keys))
        finally:
            if prepared is not None and not used:
                discard = getattr(keyboard, 'discard', None)
                if discard is not None:
                    try:
                        discard(prepared)
                    except Exception:
                        pass
        submitted = value.get('paste_input_submitted') if 'paste_input_submitted' in value else bool(value.get('paste_attempted'))
        return dict(value, method='clipboard', characters=len(text),
                    submitted=submitted, replayed=False)

    def type_text(self, text, mode='auto', paste_keys=('CTRL', 'V'), unicode_method=None):
        self._check()
        if '\x00' in text:
            raise ToolError('NUL cannot be typed as text')
        if mode not in ('auto', 'keyboard', 'clipboard'):
            raise ToolError('Unsupported text input mode')
        if unicode_method is not None and (unicode_method != 'gtk_hex' or mode != 'keyboard'):
            raise ToolError('Explicit gtk_hex composition applies only to keyboard mode')
        if not text:
            return {'method': 'none', 'submitted': False, 'characters': 0,
                    'clipboard_modified': False, 'replayed': False}
        if mode == 'clipboard':
            return self._type_via_clipboard(text, paste_keys)
        keyboard = self._keyboard_manager()
        if unicode_method is not None:
            prepared = keyboard.prepare_text(text, explicit_unicode_method=unicode_method)
            return keyboard.send_text(prepared)
        try:
            prepared = keyboard.prepare_text(text)
        except X11Unrepresentable:
            if mode == 'keyboard':
                raise
            return self._type_via_clipboard(text, paste_keys)
        # No fallback is allowed after the single-use prepared action begins.
        return keyboard.send_text(prepared)

    def windows(self):
        self._check()
        ids = self._run(['xdotool', 'search', '--onlyvisible', '--name', '.'], allow_empty=True).decode().split()
        result = []
        for identity in ids[:1000]:
            if not identity.isdigit():
                continue
            title = self._run(['xdotool', 'getwindowname', identity], allow_empty=True).decode('utf-8', 'replace').strip()
            if title:
                result.append({'window_id': identity, 'title': title, 'scope': 'X11'})
        return {'windows': result, 'scope': 'X11', 'truncated': len(ids) > 1000}

    def focus(self, identity):
        self._check()
        if identity not in {x['window_id'] for x in self.windows()['windows']}:
            raise ToolError('Window is not a current visible window on this display')
        self._run(['xdotool', 'windowraise', identity, 'windowfocus', '--sync', identity])

    def clipboard(self, action, text=None):
        self._check()
        if action == 'get':
            raw = self._run(['xclip', '-selection', 'clipboard', '-out'], timeout=5)
            if len(raw) > 1024 * 1024:
                raise ToolError('Clipboard exceeds the 1 MiB limit')
            return raw.decode('utf-8')
        previous = self.clipboard_owner
        owner = subprocess.Popen(['xclip', '-selection', 'clipboard', '-in', '-quiet'], env=self.env,
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
        self.clipboard_owner = owner
        try:
            owner.stdin.write(text.encode('utf-8'))
            owner.stdin.close()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if owner.poll() is not None:
                    raise ToolError('Clipboard ownership failed')
                if self.clipboard('get') == text:
                    return {'characters': len(text)}
                time.sleep(.02)
            raise ToolError('Clipboard ownership was not confirmed')
        except BaseException:
            self._reap(owner)
            raise
        finally:
            self._reap(previous)

    @staticmethod
    def _reap(owner):
        if owner is None:
            return
        if owner.poll() is None:
            try:
                os.killpg(owner.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                owner.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(owner.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        owner.wait(timeout=2)

    def close(self):
        if self.selection is not None:
            result = self.selection.close()
            if not result.get('closed'):
                raise ToolError('X11 clipboard owner retained: original data offer or transaction must remain alive; shutdown not confirmed')
            self.selection = None
        if self.keyboard is not None:
            self.keyboard.close()
            self.keyboard = None
        owner, self.clipboard_owner = self.clipboard_owner, None
        self._reap(owner)

    def shutdown(self):
        # Operator process shutdown is distinct from public session.close.
        # A verified independent holder can keep the restored offer alive
        # while the keyboard/operator exits; a child in this cgroup cannot.
        if self.selection is not None and getattr(self.selection, 'persistent', False):
            status = self.selection.status()
            if (status.get('persistent_daemon') is True and status.get('helper_alive') is True
                    and status.get('server_identity_verified') is True and status.get('owns_selection') is True
                    and status.get('serving_original') is True and status.get('active_transaction_id') is None):
                detached = self.selection.detach()
                if detached.get('holder_stopped') is not False:
                    raise ToolError('Independent clipboard holder lifetime was not confirmed')
                self.selection = None
        self.close()


class _Portal:
    """One private bus owner and GLib context; pump clipboard transfers while idle."""
    DEST = 'org.freedesktop.portal.Desktop'
    PATH = '/org/freedesktop/portal/desktop'
    RD = 'org.freedesktop.portal.RemoteDesktop'
    SC = 'org.freedesktop.portal.ScreenCast'
    CB = 'org.freedesktop.portal.Clipboard'

    def __init__(self, config):
        self.config, self.session, self.streams = config, None, []
        self.devices, self.clipboard_enabled = 0, False
        self.bus = self.context = None
        self.jobs = queue.Queue()
        self.ended = False
        self.clipboard_text = None
        self.restore_lock = None
        self.restore_saved = False
        self.eis = None
        self.eis_attempted = False
        self.clipboard_transaction = None
        self.input_backend = config.get('portal_input_backend', 'eis')
        if self.input_backend not in ('eis', 'legacy'):
            raise ValueError('Portal input backend must be eis or legacy')
        self.worker = threading.Thread(target=self._worker, daemon=True, name='hepta-gui-portal')
        self.worker.start()

    def _worker(self):
        while not self.ended:
            try:
                job = self.jobs.get(timeout=.02)
            except queue.Empty:
                job = None
            if job:
                future, method, args = job
                if future.set_running_or_notify_cancel():
                    try:
                        future.set_result(getattr(self, method)(*args))
                    except BaseException as error:
                        future.set_exception(error)
            if self.context:
                while self.context.pending():
                    self.context.iteration(False)
            if self.eis is not None:
                try:
                    self.eis.pump()
                except ToolError:
                    # The same failed connection remains fail-closed; no reconnect.
                    pass

    async def submit(self, method, *args):
        if self.ended:
            raise ToolError('GUI provider is closed')
        future = concurrent.futures.Future()
        self.jobs.put((future, method, args))
        wrapped = asyncio.wrap_future(future)
        try:
            return await asyncio.shield(wrapped)
        except asyncio.CancelledError:
            # Keep input serialization until an already-submitted action ends.
            try:
                await wrapped
            finally:
                raise

    def _ensure_bus(self):
        if self.bus:
            return
        import gi
        from gi.repository import Gio, GLib
        self.Gio, self.GLib = Gio, GLib
        self.context = GLib.MainContext.new()
        self.context.push_thread_default()
        address = self.config.get('dbus_address') or os.environ.get('DBUS_SESSION_BUS_ADDRESS')
        if not address:
            raise ToolError('A desktop session bus is required for the portal')
        self.bus = Gio.DBusConnection.new_for_address_sync(address,
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
        self.bus.signal_subscribe(self.DEST, self.CB, 'SelectionTransfer', self.PATH, None,
                                  Gio.DBusSignalFlags.NONE, self._clipboard_transfer)
        self.bus.signal_subscribe(self.DEST, self.CB, 'SelectionOwnerChanged', self.PATH, None,
                                  Gio.DBusSignalFlags.NONE, self._clipboard_changed)
        self.bus.signal_subscribe(self.DEST, 'org.freedesktop.portal.Session', 'Closed', None, None,
                                  Gio.DBusSignalFlags.NONE, self._session_closed)

    def _call(self, interface, method, signature, values, *, path=None, fd=False):
        self._ensure_bus()
        params = self.GLib.Variant(signature, values)
        if fd:
            value, descriptors = self.bus.call_with_unix_fd_list_sync(self.DEST, path or self.PATH,
                interface, method, params, None, self.Gio.DBusCallFlags.NONE, 10000, None, None)
            return descriptors.get(value.unpack()[0])
        return self.bus.call_sync(self.DEST, path or self.PATH, interface, method, params,
                                 None, self.Gio.DBusCallFlags.NONE, 10000, None).unpack()

    def _request(self, interface, method, signature, values):
        # Subscribe before sending so an immediate response cannot be lost.
        self._ensure_bus()
        token = values[-1]['handle_token'].unpack()
        predicted = '/org/freedesktop/portal/desktop/request/' + self.bus.get_unique_name()[1:].replace('.', '_') + '/' + token
        response = []
        subscription = self.bus.signal_subscribe(self.DEST, 'org.freedesktop.portal.Request', 'Response',
            predicted, None, self.Gio.DBusSignalFlags.NONE,
            lambda connection, sender, path, iface, name, value: response.append(value.unpack()))
        handle = None
        try:
            handle = self._call(interface, method, signature, values)[0]
            if handle != predicted:
                raise ToolError('Portal returned an unexpected request handle')
            deadline = time.monotonic() + self.config.get('authorization_timeout', 120)
            while not response and time.monotonic() < deadline:
                while self.context.pending():
                    self.context.iteration(False)
                time.sleep(.01)
            if not response:
                raise ToolError('Portal request timed out; no input was submitted')
            code, result = response[0]
            if code != 0:
                raise ToolError('Desktop permission was denied or cancelled (response ' + str(code) + ')')
            return result
        except BaseException:
            if handle:
                try:
                    self._call('org.freedesktop.portal.Request', 'Close', '()', (), path=handle)
                except Exception:
                    pass
            raise
        finally:
            self.bus.signal_unsubscribe(subscription)

    def _options(self, **values):
        result = {'handle_token': self.GLib.Variant('s', 'hepta_' + uuid.uuid4().hex)}
        for key, (kind, value) in values.items():
            result[key] = self.GLib.Variant(kind, value)
        return result

    def _pump(self, timeout=0):
        deadline = time.monotonic() + max(0, timeout)
        while True:
            while self.context and self.context.pending():
                self.context.iteration(False)
            if self.eis is not None:
                try:
                    self.eis.pump()
                except ToolError:
                    # Clipboard restoration must still pump its independent
                    # D-Bus channel after an input transport failure. Every
                    # actual input calls _ensure_eis and still refuses it.
                    pass
            if time.monotonic() >= deadline:
                return
            time.sleep(min(.005, deadline - time.monotonic()))

    def _ensure_eis(self):
        self._require()
        if self.eis is None:
            if self.eis_attempted:
                raise ToolError('The authorized EIS connection failed; no automatic reconnect or input replay')
            self.eis_attempted = True
            from .computer_eis import EisSender
            fd = self._call(self.RD, 'ConnectToEIS', '(oa{sv})', (self.session, {}), fd=True)
            self.eis = EisSender(fd)
        self.eis.pump()
        return self.eis

    def _clipboard_manager(self):
        if self.clipboard_transaction is None:
            from .clipboard_transaction import ClipboardTransaction
            root = self.config.get('clipboard_state_dir')
            if not root:
                restore = self._restore_path()
                if restore is None:
                    raise ToolError('A private persistent clipboard_state_dir is required for lossless clipboard transactions')
                root = str(restore.parent / 'clipboard-transactions')
            self.clipboard_transaction = ClipboardTransaction(self._call, self._pump, self._paste,
                lambda: self.session, root,
                max_snapshot_bytes=self.config.get('clipboard_max_snapshot_bytes', 32 * 1024 * 1024),
                make_options=lambda types: {'mime_types': self.GLib.Variant('as', list(types))})
        return self.clipboard_transaction

    def _paste(self, keys):
        normalized = [_key_name(key) for key in keys]
        if len(set(normalized)) != len(normalized):
            raise ToolError('Duplicate paste keys are not permitted')
        self.preflight_keys(normalized)
        pressed = []
        try:
            for key in normalized:
                pressed.append(key)
                self.key(key, True)
        finally:
            failures = []
            for key in reversed(pressed):
                try:
                    self.key(key, False)
                except Exception as error:
                    failures.append(error)
            if failures:
                raise ToolError('Paste keys could not all be released; input is not replayed')

    def _type_via_clipboard(self, text, paste_keys):
        if not self.clipboard_enabled:
            raise ToolError('Clipboard sharing was not granted; no text submitted')
        normalized = [_key_name(key) for key in paste_keys]
        if len(set(normalized)) != len(normalized):
            raise ToolError('Duplicate physical paste keys are not permitted')
        self.preflight_keys(normalized)
        receipt = self._clipboard_manager().run(text, paste_keys=paste_keys)
        return dict(receipt, method='clipboard', submitted=bool(receipt.get('paste_attempted')),
                    characters=len(text), replayed=False, clipboard_modified=True)

    def _restore_path(self):
        value = self.config.get('portal_restore_path')
        return pathlib.Path(value).absolute() if value else None

    def _restore_open(self):
        path = self._restore_path()
        if path is None:
            return None
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(str(path) + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ToolError('Portal restore lock must be a private owned regular file')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(descriptor)
            raise
        self.restore_lock = descriptor
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 8192:
                raise ToolError('Portal restore receipt must be a private owned regular file')
            data = json.loads(os.read(descriptor, 8193))
            if data.get('profile') != self.config.get('profile_id', 'hepta-computer'):
                raise ToolError('Portal restore receipt belongs to another profile')
            token = data.get('restore_token')
            if token is not None and (not isinstance(token, str) or len(token) > 4096):
                raise ToolError('Invalid portal restore receipt')
            return token
        finally:
            os.close(descriptor)

    def _restore_save(self, token):
        path = self._restore_path()
        if path is None:
            return
        if token is not None and (not isinstance(token, str) or len(token) > 4096):
            raise ToolError('Portal returned an invalid restore token')
        data = json.dumps({'version': 1, 'profile': self.config.get('profile_id', 'hepta-computer'), 'restore_token': token}).encode()
        temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        self.restore_saved = bool(token)

    def capabilities(self):
        try:
            self._ensure_bus()
            properties = {}
            for interface in [self.RD, self.SC, self.CB]:
                properties[interface.rsplit('.', 1)[-1]] = self._call('org.freedesktop.DBus.Properties', 'GetAll', '(s)', (interface,))[0]
            import gi
            gi.require_version('Gst', '1.0')
            from gi.repository import Gst
            Gst.init(None)
            pipewire = all(Gst.ElementFactory.find(name) for name in ['pipewiresrc', 'videoconvert', 'appsink', 'pngenc'])
            input_ready = bool(self.session)
            transport = {'transport': 'legacy_portal_notify', 'exact_text_locks': False}
            if self.input_backend == 'eis':
                input_ready = False
                if self.eis is not None:
                    try:
                        transport = self.eis.diagnostics()
                        # Older compositors publish usable EIS devices/keymaps
                        # without modifier events. Physical keys remain usable;
                        # literal typing independently refuses unknown locks.
                        input_ready = transport['connected'] and transport['ready_capabilities'].get('4', False)
                    except ToolError:
                        transport = {'transport': 'portal_eis_libei', 'connected': False, 'automatic_reconnect': False}
            mouse_ready = input_ready and (self.input_backend != 'eis' or all(
                transport.get('ready_capabilities', {}).get(str(cap)) for cap in (2, 16, 32)))
            return {'backend': 'wayland_portal', 'authorized': bool(self.session), 'portal_properties': properties,
                    'input_transport': transport,
                    'streams': self.streams, 'granted_devices': self.devices,
                    'permission_persistence_requested': bool(self._restore_path()),
                    'restore_receipt_saved': self.restore_saved,
                    'pipewire_capture_dependencies': bool(pipewire),
                    'features': {'screenshot': bool(self.session and self.streams and pipewire),
                                 'mouse': bool(mouse_ready and self.devices & 2),
                                 'key': bool(input_ready and self.devices & 1),
                                 'type': bool(input_ready and self.devices & 1 and
                                              (self.input_backend != 'eis' or transport.get('modifier_state_known') or self.clipboard_enabled)),
                                 'clipboard': bool(self.session and self.clipboard_enabled),
                                 'window_list': False, 'window_focus': False},
                    'limitations': ['Explicit user portal consent is required before screen capture or input.',
                                    'Wayland global window enumeration/focus is not exposed by this portal; no XWayland fallback.',
                                    'Clipboard transactions restore every original MIME byte through this service offer; original application ownership and atomic compare-and-set are unavailable.',
                                    'When the compositor omits EIS modifier state, locks remain unknown: physical keys use the first server keymap layout, keyboard text refuses, and auto text requires a complete clipboard transaction.',
                                    'Coordinates use each granted stream logical_size, not resized PNG pixels.']}
        except Exception as error:
            return {'backend': 'wayland_portal', 'authorized': False, 'features': {},
                    'reason': 'Portal discovery unavailable: ' + type(error).__name__}

    def authorize(self, restore_session=True):
        if self.session:
            if not restore_session:
                raise ToolError('Close the active desktop session explicitly before opening a new chooser; its clipboard offer was not changed')
            return self.capabilities()
        self._ensure_bus()
        try:
            token = self._restore_open()
            session = self._request(self.RD, 'CreateSession', '(a{sv})', (self._options(session_handle_token=('s', 'hepta_' + uuid.uuid4().hex)),))['session_handle']
            self.session = session
            options = self._options(types=('u', 3))
            if self._restore_path():
                options['persist_mode'] = self.GLib.Variant('u', 2)
                if token and restore_session:
                    options['restore_token'] = self.GLib.Variant('s', token)
            self._request(self.RD, 'SelectDevices', '(oa{sv})', (session, options))
            self._request(self.SC, 'SelectSources', '(oa{sv})',
                          (session, self._options(types=('u', 1), multiple=('b', True), cursor_mode=('u', 2))))
            if self.config.get('clipboard', True):
                if self.config.get('clipboard_state_dir') or self._restore_path():
                    # Observe the complete initial owner/MIME notification,
                    # before Start can emit it. Never infer an empty clipboard.
                    self._clipboard_manager()
                self._call(self.CB, 'RequestClipboard', '(oa{sv})', (session, {}))
            result = self._request(self.RD, 'Start', '(osa{sv})', (session, '', self._options()))
            # RemoteDesktop, rather than ScreenCast, owns persistence for a joint
            # session. Rotate the single-use token before returning readiness.
            self._restore_save(result.get('restore_token'))
            self.devices = result.get('devices', 0)
            self.clipboard_enabled = result.get('clipboard_enabled', False)
            self.streams = [{'stream': node, 'logical_size': list(info.get('size', [])),
                             'position': list(info.get('position', [])), 'source_type': info.get('source_type'),
                             **({'mapping_id': info['mapping_id']} if info.get('mapping_id') else {})}
                            for node, info in result.get('streams', [])]
            if self.input_backend == 'eis':
                self._ensure_eis()
            return self.capabilities()
        except BaseException as primary:
            try:
                self.close()
            except BaseException as cleanup:
                note = ('Additional desktop cleanup failed (' + type(cleanup).__name__ +
                        '); inspect session status; no automatic input replay')
                primary.add_note(note)
                if isinstance(primary, ToolError):
                    # Keep the original exception and reason visible through
                    # MCP's str(error), which does not render Python notes.
                    primary.args = (str(primary) + '; ' + note,)
            raise

    def _require(self, mask=0):
        if not self.session:
            raise ToolError('No authorized Wayland session. Call computer_session authorize and approve the system dialog first.')
        if mask and self.devices & mask != mask:
            raise ToolError('The user did not grant the required input device')

    def _stream(self, stream):
        self._require()
        if stream is None and len(self.streams) == 1:
            return self.streams[0]
        for value in self.streams:
            if value['stream'] == stream:
                return value
        raise ToolError('Select an exact stream from computer_capabilities; multiple screens are not merged implicitly')

    def screenshot(self, args):
        selected = self._stream(args.get('stream'))
        fd = self._call(self.SC, 'OpenPipeWireRemote', '(oa{sv})', (self.session, {}), fd=True)
        pipeline = None
        try:
            import gi
            gi.require_version('Gst', '1.0')
            from gi.repository import Gst
            Gst.init(None)
            pipeline = Gst.parse_launch('pipewiresrc name=source do-timestamp=true ! videoconvert ! pngenc ! appsink name=sink sync=false max-buffers=1 drop=true')
            source, sink = pipeline.get_by_name('source'), pipeline.get_by_name('sink')
            source.set_property('fd', fd)
            source.set_property('path', str(selected['stream']))
            pipeline.set_state(Gst.State.PLAYING)
            sample = sink.emit('try-pull-sample', 10 * Gst.SECOND)
            if sample is None:
                raise ToolError('No PipeWire frame arrived; no alternate screen was captured')
            buffer = sample.get_buffer()
            raw = buffer.extract_dup(0, buffer.get_size())
            return _png_result(raw, dict(selected, backend='wayland_portal'), args.get('max_width', 1920))
        finally:
            if pipeline is not None:
                pipeline.set_state(Gst.State.NULL)
            os.close(fd)

    def prepare_input(self, mask):
        self._require(mask)

    def validate_position(self, x, y, stream=None):
        self._require(2)
        chosen = self._stream(stream)
        size = chosen['logical_size']
        if len(size) != 2 or not (0 <= x < size[0] and 0 <= y < size[1]):
            raise ToolError('Coordinates require the granted stream logical size and must be within it')
        return chosen

    def move(self, x, y, stream=None):
        chosen = self.validate_position(x, y, stream)
        if self.input_backend == 'eis':
            return self._ensure_eis().move(x, y, chosen)
        self._call(self.RD, 'NotifyPointerMotionAbsolute', '(oa{sv}udd)', (self.session, {}, chosen['stream'], float(x), float(y)))

    def button(self, button, down):
        self._require(2)
        if self.input_backend == 'eis':
            return self._ensure_eis().button(button, down)
        self._call(self.RD, 'NotifyPointerButton', '(oa{sv}iu)', (self.session, {}, {'left': 272, 'right': 273, 'middle': 274}[button], int(down)))

    def scroll(self, direction, steps):
        self._require(2)
        if self.input_backend == 'eis':
            return self._ensure_eis().scroll(direction, steps)
        axis, value = (0, -steps if direction == 'up' else steps) if direction in ('up', 'down') else (1, -steps if direction == 'left' else steps)
        self._call(self.RD, 'NotifyPointerAxisDiscrete', '(oa{sv}ui)', (self.session, {}, axis, value))

    @staticmethod
    def _keysym(key):
        if len(key) == 1:
            number = ord(key)
            return number if number <= 0xff else number | 0x01000000
        result = _KEYSYMS.get(key)
        if not result:
            raise ToolError('Unknown keysym')
        return result

    def key(self, key, down):
        self._require(1)
        if self.input_backend == 'eis':
            return self._ensure_eis().key(self._keysym(key), down)
        # Key combinations describe physical letter keys, not capitalized text.
        key = key.lower() if len(key) == 1 else key
        self._call(self.RD, 'NotifyKeyboardKeysym', '(oa{sv}iu)', (self.session, {}, self._keysym(key), int(down)))

    def preflight_keys(self, keys):
        self._require(1)
        if self.input_backend == 'eis':
            sender = self._ensure_eis()
            _, info = sender._device(4)
            for key in keys:
                info['xkb'].physical_plan(self._keysym(key))

    def type_text(self, text, mode='auto', paste_keys=('CTRL', 'V')):
        self._require(1)
        if '\x00' in text:
            raise ToolError('NUL cannot be typed as text')
        if not text:
            return {'method': 'none', 'submitted': False, 'characters': 0,
                    'clipboard_modified': False, 'replayed': False}
        if mode == 'clipboard':
            return self._type_via_clipboard(text, paste_keys)
        keysyms = [self._keysym({'\n': 'Return', '\t': 'Tab', '\r': 'Return'}.get(character, character)) for character in text]
        if self.input_backend == 'eis':
            from .computer_eis import UnrepresentableSymbol
            sender = self._ensure_eis()
            try:
                sender.preflight_text(keysyms)
            except UnrepresentableSymbol:
                if mode == 'keyboard':
                    raise
                return self._type_via_clipboard(text, paste_keys)
            try:
                for keysym in keysyms:
                    try:
                        sender.key(keysym, True, literal=True)
                    finally:
                        sender.key(keysym, False, literal=True)
            except Exception:
                # A layout/group change can invalidate later symbols after a
                # complete preflight. Never call that whole text unsubmitted,
                # and never fall back to pasting it after a possible prefix.
                raise ToolError('Keyboard text may be partially submitted; no clipboard fallback or automatic input replay') from None
            return {'method': 'keyboard', 'submitted': bool(text), 'characters': len(text), 'clipboard_modified': False, 'replayed': False}
        # Explicit legacy configuration is retained for protocol compatibility
        # fixtures; its keysym path cannot guarantee arbitrary Unicode or locks.
        for character in text:
            key = {'\n': 'Return', '\t': 'Tab', '\r': 'Return'}.get(character, character)
            try:
                self._call(self.RD, 'NotifyKeyboardKeysym', '(oa{sv}iu)', (self.session, {}, self._keysym(key), 1))
            finally:
                self._call(self.RD, 'NotifyKeyboardKeysym', '(oa{sv}iu)', (self.session, {}, self._keysym(key), 0))
        return {'method': 'legacy_keysym', 'submitted': bool(text), 'characters': len(text), 'exact_text_guaranteed': False, 'replayed': False}

    def windows(self):
        raise ToolError('Wayland portal has no global window-list API. GNOME Shell permission/AT-SPI access must be separately granted; XWayland is not the whole desktop.')

    def focus(self, identity):
        raise ToolError('Wayland portal has no arbitrary window-focus API. Use authorized coordinates or an independently authorized app accessibility provider.')

    def _clipboard_changed(self, connection, sender, path, interface, name, parameters):
        session, options = parameters.unpack()
        if self.clipboard_transaction is not None:
            self.clipboard_transaction.selection_changed(session, options)
        if session == self.session and not options.get('session_is_owner', False):
            self.clipboard_text = None

    def _clipboard_transfer(self, connection, sender, path, interface, name, parameters):
        session, mime, serial = parameters.unpack()
        if self.clipboard_transaction is not None and self.clipboard_transaction.selection_transfer(session, mime, serial):
            return
        if session != self.session:
            return
        success, fd = False, None
        try:
            if mime not in ('text/plain;charset=utf-8', 'text/plain') or self.clipboard_text is None:
                return
            fd = self._call(self.CB, 'SelectionWrite', '(ou)', (session, serial), fd=True)
            data = self.clipboard_text.encode('utf-8')
            os.set_blocking(fd, False)
            deadline = time.monotonic() + 5
            while data and time.monotonic() < deadline:
                if select.select([], [fd], [], .05)[1]:
                    try:
                        data = data[os.write(fd, data):]
                    except BlockingIOError:
                        pass
            success = not data
        except Exception:
            pass
        finally:
            if fd is not None:
                os.close(fd)
            try:
                self._call(self.CB, 'SelectionWriteDone', '(oub)', (session, serial, success))
            except Exception:
                pass

    def clipboard(self, action, text=None):
        self._require()
        if not self.clipboard_enabled:
            raise ToolError('Clipboard sharing was not granted for this session')
        if action == 'set':
            if self.clipboard_transaction is not None:
                return self.clipboard_transaction.offer_text(text)
            self.clipboard_text = text
            self._call(self.CB, 'SetSelection', '(oa{sv})', (self.session, {'mime_types': self.GLib.Variant('as', ['text/plain;charset=utf-8', 'text/plain'])}))
            return {'characters': len(text)}
        fd = self._call(self.CB, 'SelectionRead', '(os)', (self.session, 'text/plain;charset=utf-8'), fd=True)
        try:
            data, deadline = bytearray(), time.monotonic() + 5
            os.set_blocking(fd, False)
            while time.monotonic() < deadline:
                if select.select([fd], [], [], .05)[0]:
                    try:
                        chunk = os.read(fd, 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        return data.decode('utf-8')
                    data.extend(chunk)
                    if len(data) > 1024 * 1024:
                        raise ToolError('Clipboard exceeds the 1 MiB limit')
                while self.context.pending():
                    self.context.iteration(False)
            raise ToolError('Clipboard transfer timed out')
        finally:
            os.close(fd)

    def _session_closed(self, connection, sender, path, interface, name, parameters):
        if path == self.session:
            self.session = None
            self._closed_resources()

    def _closed_resources(self):
        """Release offers only after actual session closure or bus disconnect."""
        self.streams, self.devices, self.clipboard_enabled, self.clipboard_text = [], 0, False, None
        errors = []
        if self.eis is not None:
            try:
                self.eis.close()
            except Exception as error:
                errors.append(error)
            finally:
                self.eis = None
        self.eis_attempted = False
        if self.clipboard_transaction is not None:
            try:
                self.clipboard_transaction.close()
            except Exception as error:
                # A revocation signal can arrive inside an active transaction.
                # Retain its private owner until run's finally finishes.
                errors.append(error)
            else:
                self.clipboard_transaction = None
        if self.restore_lock is not None:
            try:
                os.close(self.restore_lock)
            except Exception as error:
                errors.append(error)
            finally:
                self.restore_lock = None
        return errors

    def close(self):
        session, errors = self.session, []
        if self.eis is not None:
            try:
                self.eis.close()
            except Exception as error:
                errors.append(error)
            finally:
                self.eis = None
        # Closing EIS is not permission to reconnect it on a still-live portal.
        self.eis_attempted = bool(session)
        if session:
            try:
                self._call('org.freedesktop.portal.Session', 'Close', '()', (), path=session)
            except Exception as error:
                errors.append(error)
            else:
                self.session = None
        if self.session is None:
            errors.extend(self._closed_resources())
        if errors:
            raise ToolError('Desktop session cleanup was not fully confirmed; no input was replayed')

    def shutdown(self):
        errors = []
        try:
            self.close()
        except Exception as error:
            errors.append(error)
        if self.bus:
            try:
                self.bus.close_sync(None)
            except Exception as error:
                errors.append(error)
            else:
                self.bus = None
                self.session = None
                errors.extend(self._closed_resources())
        if self.session is not None:
            # Session termination was not proven. Keep the owner/context alive
            # to serve its restored original MIME offer until explicit cleanup.
            raise ToolError('Desktop shutdown could not confirm session termination; private clipboard owner retained')
        try:
            if self.context:
                self.context.pop_thread_default()
        except Exception as error:
            errors.append(error)
        finally:
            if self.context:
                self.context = None
            self.ended = True
        if errors:
            raise ToolError('Desktop shutdown completed with an unconfirmed cleanup result; no input replay')


class ComputerManager:
    """Register COMPUTER_TOOLS and call invoke; no desktop action on construction."""
    tool_names = frozenset(tool['name'] for tool in COMPUTER_TOOLS)

    def __init__(self, config=None):
        self.config = dict(config or {})
        backend = self.config.get('backend', 'auto')
        if backend == 'auto':
            backend = 'portal' if (self.config.get('session_type') or os.environ.get('XDG_SESSION_TYPE')) == 'wayland' else 'x11'
        if backend not in ('portal', 'x11'):
            raise ValueError('GUI backend must be auto, portal or x11')
        self.backend = _Portal(self.config) if backend == 'portal' else _X11(self.config)
        self.lock = asyncio.Lock()
        self.closed = False
        self.held_keys, self.held_buttons = set(), set()
        self.input_owner = self.input_token = self.input_timer = None
        self.input_deadline, self.input_explicit = 0.0, False
        self.input_cleanup_failed = False

    def _input_status(self):
        return {'reserved': self.input_owner is not None, 'explicit': self.input_explicit,
                'expires_in_seconds': max(0.0, self.input_deadline - time.monotonic()),
                'cleanup_unconfirmed': self.input_cleanup_failed,
                'isolation': 'MCP session or matching gesture capability; shared operator credential is not a security boundary'}

    @staticmethod
    def _mutates_input(name, args):
        return name not in ('computer_capabilities', 'computer_screenshot') and not (
            name in ('computer_window', 'computer_clipboard') and args['action'] in ('list', 'get')) and not (
            name == 'computer_session' and args['action'] in ('status', 'clipboard_status', 'clipboard_backups'))

    def _input_check(self, args):
        supplied = args.get('input_lease')
        if supplied is not None:
            if self.input_token is None or not hmac.compare_digest(supplied, self.input_token):
                raise ToolError('Input lease is stale or does not own this gesture; no input submitted')
        if self.input_owner is not None and supplied is None and self.input_owner != (INPUT_CLIENT.get() or 'direct'):
            raise ToolError('Input is reserved by another MCP session; no input submitted')
        if self.input_cleanup_failed:
            raise ToolError('Owned input release is unconfirmed; resolve the original gesture before other input')

    def _input_reserve(self, seconds=30, explicit=False):
        if self.input_owner is None:
            self.input_owner = INPUT_CLIENT.get() or 'direct'
            self.input_token = secrets.token_hex(32)
            self.input_timer = asyncio.create_task(self._input_expire(self.input_token))
        self.input_deadline = time.monotonic() + seconds
        self.input_explicit = self.input_explicit or explicit
        return {'input_lease': self.input_token, **self._input_status()}

    def _input_clear(self):
        timer, self.input_timer = self.input_timer, None
        self.input_owner = self.input_token = None
        self.input_deadline, self.input_explicit = 0.0, False
        self.input_cleanup_failed = False
        if timer is not None and timer is not asyncio.current_task():
            timer.cancel()

    async def _release_owned_input(self):
        errors = []
        for kind, held in (('key', self.held_keys), ('button', self.held_buttons)):
            for value in sorted(held):
                try:
                    await self._call(kind, value, False)
                except Exception:
                    errors.append(kind)
        if errors:
            self.input_cleanup_failed = True
            raise ToolError('Owned input release is unconfirmed; no new gesture or input replay')

    async def _input_expire_locked(self):
        if self.input_owner is not None and time.monotonic() >= self.input_deadline and not self.input_cleanup_failed:
            await self._release_owned_input()
            self._input_clear()

    async def _input_expire(self, token):
        try:
            while self.input_token == token:
                await asyncio.sleep(max(.01, self.input_deadline - time.monotonic()))
                async with self.lock:
                    await self._input_expire_locked()
        except (asyncio.CancelledError, ToolError):
            # One cleanup attempt only. Unknown releases remain fenced rather
            # than being replayed by a watchdog or inherited by another client.
            return

    async def _input_session(self, args):
        action = args['action']
        if action == 'acquire_input':
            self._input_check(args)
            return self._input_reserve(args.get('lease_seconds', 30), True)
        if self.input_owner is None:
            raise ToolError('No active input lease')
        # An owner may explicitly attempt cleanup after an uncertain release;
        # it does not authorize another client or a new input action.
        cleanup_failed = self.input_cleanup_failed
        self.input_cleanup_failed = False
        try:
            self._input_check(args)
        finally:
            self.input_cleanup_failed = cleanup_failed
        if action == 'renew_input':
            if cleanup_failed:
                raise ToolError('Resolve unconfirmed input cleanup before renewing a lease')
            return self._input_reserve(args.get('lease_seconds', 30), self.input_explicit)
        await self._release_owned_input()
        self._input_clear()
        return {'released': True, 'held_keys': [], 'held_buttons': []}

    async def _call(self, name, *args):
        held = self.held_keys if name == 'key' else self.held_buttons if name == 'button' else None
        if held is not None and args[1]:
            held.add(args[0])
        if isinstance(self.backend, _Portal):
            result = await self.backend.submit(name, *args)
        else:
            task = asyncio.create_task(asyncio.to_thread(getattr(self.backend, name), *args))
            try:
                result = await asyncio.shield(task)
            except asyncio.CancelledError:
                try:
                    await task
                finally:
                    raise
        if held is not None and not args[1]:
            held.discard(args[0])
        return result

    async def invoke(self, name, arguments):
        if name not in self.tool_names:
            raise ToolError('Unknown computer tool')
        if self.closed:
            raise ToolError('GUI provider is closed')
        args = dict(arguments)
        # Registry validates schemas; direct provider use also validates before any input.
        from jsonschema import Draft7Validator
        definition = next(tool for tool in COMPUTER_TOOLS if tool['name'] == name)
        errors = list(Draft7Validator(definition['inputSchema']).iter_errors(args))
        if errors:
            raise ToolError('Invalid computer tool arguments: ' + errors[0].message)
        async with self.lock:
            try:
                await self._input_expire_locked()
                lease_action = name == 'computer_session' and args['action'] in ('acquire_input', 'renew_input', 'release_input')
                if lease_action:
                    value = await self._input_session(args)
                    return text_result(json.dumps(value), structured={'result': value})
                if self._mutates_input(name, args):
                    self._input_check(args)
                    if self.input_owner is None:
                        self._input_reserve()
                if name == 'computer_capabilities':
                    value = await self._call('capabilities')
                    value = dict(value, input_control=self._input_status())
                elif name == 'computer_session':
                    action = args['action']
                    if 'lease_seconds' in args:
                        raise ToolError('lease_seconds applies only to input lease actions')
                    if 'restore_session' in args and (action != 'authorize' or not isinstance(self.backend, _Portal)):
                        raise ToolError('restore_session applies only to Wayland authorize')
                    if action == 'close':
                        await self._release_owned_input()
                        value = await self._call('close')
                        self._input_clear()
                    elif action in ('clipboard_status', 'clipboard_backups', 'restore_clipboard'):
                        if not isinstance(self.backend, _X11):
                            raise ToolError('Explicit clipboard backup recovery currently applies to X11')
                        selection = self.backend._selection_manager()
                        if action == 'restore_clipboard':
                            if 'snapshot_id' not in args or args.get('expected_owner') != 0:
                                raise ToolError('snapshot_id and explicit expected_owner=0 are required')
                            value = await asyncio.to_thread(selection.restore_clipboard, args['snapshot_id'], expected_owner=0)
                        else:
                            value = await asyncio.to_thread(getattr(selection, 'status' if action == 'clipboard_status' else 'list_backups'))
                    elif action == 'authorize' and isinstance(self.backend, _Portal):
                        value = await self._call('authorize', args.get('restore_session', True))
                    else:
                        value = await self._call({'authorize': 'authorize', 'status': 'capabilities', 'close': 'close'}[action])
                elif name == 'computer_screenshot':
                    return await self._call('screenshot', args)
                elif name == 'computer_mouse':
                    await self._mouse(args)
                    value = {'submitted': True, 'action': args['action'], 'replayed': False}
                elif name == 'computer_key':
                    value = await self._keys(args)
                elif name == 'computer_type':
                    if '\x00' in args['text']:
                        raise ToolError('NUL cannot be typed as text')
                    if self.held_keys:
                        raise ToolError('Release this provider\'s held keys before inserting exact text')
                    if 'unicode_method' in args and (not isinstance(self.backend, _X11) or args.get('mode') != 'keyboard'):
                        raise ToolError('Explicit gtk_hex composition currently applies only to X11 keyboard mode')
                    await self._call('prepare_input', 1)
                    parameters = (args['text'], args.get('mode', 'auto'), args.get('paste_keys', ['CTRL', 'V']))
                    value = await self._call('type_text', *parameters, args['unicode_method']) if 'unicode_method' in args else await self._call('type_text', *parameters)
                elif name == 'computer_window':
                    if args['action'] == 'focus' and 'window_id' not in args:
                        raise ToolError('window_id is required for focus')
                    value = await self._call('windows') if args['action'] == 'list' else await self._call('focus', args['window_id'])
                else:
                    if args['action'] == 'set' and 'text' not in args:
                        raise ToolError('text is required for clipboard set')
                    value = await self._call('clipboard', args['action'], args.get('text'))
                if isinstance(value, dict) and self.input_owner is not None and self._mutates_input(name, args) and (
                        self.input_explicit or self.held_keys or self.held_buttons):
                    value = dict(value, input_control={'input_lease': self.input_token, **self._input_status()})
                return text_result(json.dumps(value, ensure_ascii=False), structured={'result': value})
            except ClipboardTransactionError as error:
                # A paste can have happened even if restoration later failed.
                # Preserve the receipt instead of relabeling it not-submitted.
                submitted = error.receipt.get('paste_input_submitted') if 'paste_input_submitted' in error.receipt else bool(error.receipt.get('paste_attempted'))
                if error.receipt.get('paste_callback_receipt', {}).get('owned_keys_released') is False:
                    self.input_cleanup_failed = True
                value = dict(error.receipt, method='clipboard', submitted=submitted, replayed=False)
                return {'isError': True, 'content': [{'type': 'text', 'text': str(error)}],
                        'structuredContent': {'result': value}}
            except X11KeyboardError as error:
                if error.receipt.get('owned_keys_released') is False:
                    self.input_cleanup_failed = True
                return {'isError': True, 'content': [{'type': 'text', 'text': str(error)}],
                        'structuredContent': {'result': dict(error.receipt)}}
            except ToolError:
                raise
            except Exception as error:
                # Do not expose private window/clipboard payloads in error diagnostics.
                raise ToolError('Computer operation failed: ' + type(error).__name__ + '; submitted input is never automatically retried') from None
            finally:
                if self.input_owner is not None and not self.input_explicit and not self.held_keys and not self.held_buttons and not self.input_cleanup_failed:
                    self._input_clear()

    async def _keys(self, args):
        keys = [_key_name(key) for key in args['keys']]
        action = args.get('action', 'press')
        if len(set(keys)) != len(keys):
            raise ToolError('Duplicate physical keys are not permitted')
        if action == 'up':
            if any(key not in self.held_keys for key in keys):
                raise ToolError('Only keys held by this provider may be released')
        elif any(key in self.held_keys for key in keys):
            raise ToolError('A requested key is already held by this provider; no replay')
        await self._call('prepare_input', 1)
        if isinstance(self.backend, _Portal) and action != 'up':
            await self._call('preflight_keys', keys)
        if action == 'up':
            errors = []
            for key in reversed(keys):
                try:
                    await self._call('key', key, False)
                except Exception as error:
                    errors.append(error)
            if errors:
                self.input_cleanup_failed = True
                raise ToolError('Could not confirm release of every requested owned key; input was not replayed')
        else:
            pressed, complete = [], False
            try:
                for key in keys:
                    pressed.append(key)
                    await self._call('key', key, True)
                complete = True
            except Exception:
                raise ToolError('Key action may be partially submitted; owned keys are released and input is never automatically replayed') from None
            finally:
                if action == 'press' or not complete:
                    errors = []
                    for key in reversed(pressed):
                        try:
                            await self._call('key', key, False)
                        except Exception as error:
                            errors.append(error)
                    if errors:
                        self.input_cleanup_failed = True
                        raise ToolError('Could not confirm release of every newly pressed key; input was not replayed')
        return {'submitted': True, 'action': action, 'held_keys': sorted(self.held_keys), 'replayed': False}

    async def _mouse(self, args):
        action, button = args['action'], args.get('button', 'left')
        if action == 'up' and button not in self.held_buttons:
            raise ToolError('Only mouse buttons held by this provider may be released')
        if action in ('down', 'click', 'double_click', 'drag') and button in self.held_buttons:
            raise ToolError('The requested mouse button is already held; no duplicate press or release submitted')
        if ('x' in args) != ('y' in args):
            raise ToolError('x and y must be supplied together')
        if action in ('move', 'click', 'double_click', 'drag') and 'x' not in args:
            raise ToolError('x and y are required for this mouse action')
        if action == 'drag' and not all(key in args for key in ('to_x', 'to_y')):
            raise ToolError('drag requires to_x and to_y')
        await self._call('prepare_input', 2)
        if 'x' in args:
            await self._call('validate_position', args['x'], args['y'], args.get('stream'))
        if action == 'drag':
            await self._call('validate_position', args['to_x'], args['to_y'], args.get('stream'))
        if 'x' in args:
            await self._call('move', args['x'], args['y'], args.get('stream'))
        if action == 'move':
            return
        if action == 'scroll':
            await self._call('scroll', args.get('direction', 'down'), args.get('steps', 1))
        elif action in ('down', 'up'):
            await self._call('button', button, action == 'down')
        else:
            for index in range(2 if action == 'double_click' else 1):
                try:
                    await self._call('button', button, True)
                    if action == 'drag':
                        duration = args.get('duration_ms', 300) / 1000
                        for step in range(1, 11):
                            await self._call('move', args['x'] + (args['to_x'] - args['x']) * step / 10,
                                             args['y'] + (args['to_y'] - args['y']) * step / 10, args.get('stream'))
                            await asyncio.sleep(duration / 10)
                finally:
                    try:
                        await self._call('button', button, False)
                    except Exception:
                        self.input_cleanup_failed = True
                        raise ToolError('Owned mouse release is unconfirmed; no new gesture or input replay') from None
                if action == 'double_click' and index == 0:
                    await asyncio.sleep(.08)

    async def close(self):
        if not self.closed:
            async with self.lock:
                await self._release_owned_input()
                await self._call('shutdown' if hasattr(self.backend, 'shutdown') else 'close')
                self._input_clear()
                self.closed = True
