# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Authenticated client for the opt-in Hepta GNOME Shell window bridge.

This route replaces only computer_window on a Wayland ComputerManager. It does
not enable an extension, change GNOME settings, or bypass portal input consent.
"""
from __future__ import annotations
import asyncio
import json
import os
import pathlib
import re
import stat

from .registry import ToolError, text_result

BUS_NAME = 'org.hepta.Runtime.WindowBridge'
OBJECT_PATH = '/org/hepta/Runtime/WindowBridge'
INTERFACE = 'org.hepta.Runtime.WindowBridge1'
GNOME_WINDOW_TOOLS = [{
    'name': 'computer_window',
    'description': 'List GNOME compositor windows (native Wayland and X11) or focus an exact current opaque window_id through the explicitly enabled Hepta extension. Locked desktops refuse access. Focus requests are never automatically replayed.',
    'inputSchema': {'type': 'object', 'properties': {
        'action': {'enum': ['list', 'focus']},
        'window_id': {'type': 'string', 'pattern': '^[0-9a-f]{32}:[0-9]{1,10}$'},
        'request_id': {'type': 'string', 'pattern': '^[0-9a-f]{32}:[1-9][0-9]{0,15}$',
                       'description': 'Reuse the exact request_id of an earlier focus result to read its receipt without activating again. Old evicted IDs remain sealed.'}},
        'required': ['action'], 'additionalProperties': False},
}]


def read_private_config(path, expected_profile=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 8192:
            raise ToolError('Window bridge config must be a private owned regular file')
        value = json.loads(os.read(descriptor, 8193))
    finally:
        os.close(descriptor)
    if (value.get('version') != 1 or not re.fullmatch(r'[0-9a-f]{64}', value.get('token', ''))
            or not isinstance(value.get('profile_id'), str) or not 1 <= len(value['profile_id']) <= 128):
        raise ToolError('Invalid window bridge config')
    if expected_profile is not None and value['profile_id'] != expected_profile:
        raise ToolError('Window bridge config belongs to another profile')
    return value


class GnomeWindowManager:
    tool_names = frozenset({'computer_window'})

    def __init__(self, config):
        self.config = dict(config)
        self.path = pathlib.Path(self.config.get('token_path') or
            pathlib.Path(os.environ.get('XDG_CONFIG_HOME', pathlib.Path.home() / '.config')) /
            'hepta-runtime' / 'gnome-window-bridge.json')
        self.bus = None
        self.lock = asyncio.Lock()

    def _connect(self):
        from gi.repository import Gio, GLib
        self.Gio, self.GLib = Gio, GLib
        if self.bus is None or self.bus.is_closed():
            address = self.config.get('dbus_address') or os.environ.get('DBUS_SESSION_BUS_ADDRESS')
            if not address:
                raise ToolError('GNOME desktop session bus is unavailable')
            self.bus = Gio.DBusConnection.new_for_address_sync(address,
                Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)

    def _daemon(self, method, name):
        return self.bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus',
            'org.freedesktop.DBus', method, self.GLib.Variant('(s)', (name,)), None,
            self.Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]

    def _peer(self):
        owner = self._daemon('GetNameOwner', BUS_NAME)
        shell = self._daemon('GetNameOwner', 'org.gnome.Shell')
        if (self._daemon('GetConnectionUnixUser', owner) != os.getuid()
                or self._daemon('GetConnectionUnixProcessID', owner) != self._daemon('GetConnectionUnixProcessID', shell)):
            raise ToolError('Window bridge is not owned by this user GNOME Shell process')
        return owner

    def _call(self, method, arguments=()):
        self._connect()
        config = read_private_config(self.path, self.config.get('profile_id'))
        # Pin the unique destination after verifying its OS PID. A concurrent
        # well-known name replacement cannot receive this authenticated call.
        owner = self._peer()
        value = self.bus.call_sync(owner, OBJECT_PATH, INTERFACE, method,
            self.GLib.Variant('(' + 's' * (1 + len(arguments)) + ')', (config['token'], *arguments)),
            self.GLib.VariantType.new('(s)'), self.Gio.DBusCallFlags.NONE, 5000, None).unpack()[0]
        if len(value.encode('utf-8')) > 8 * 1024 * 1024:
            raise ToolError('Window bridge response exceeds the byte limit')
        result = json.loads(value)
        if not isinstance(result, dict) or not re.fullmatch('[0-9a-f]{32}', result.get('bridge_session', '')):
            raise ToolError('Window bridge returned an invalid session')
        if method == 'GetCapabilities' and (result.get('protocol') != 1 or result.get('profile_id') != config['profile_id']):
            raise ToolError('Window bridge profile or protocol mismatch')
        return result

    async def _run(self, function, *arguments):
        task = asyncio.create_task(asyncio.to_thread(function, *arguments))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # A cancelled RPC may already have focused the window. Wait for its
            # outcome, retain serialization, and never resend it automatically.
            try:
                await task
            finally:
                raise

    async def capabilities(self):
        async with self.lock:
            try:
                return dict(await self._run(self._call, 'GetCapabilities'), available=True)
            except Exception as error:
                return {'available': False, 'features': {'window_list': False, 'window_focus': False},
                        'reason': 'Enable the reviewed Hepta GNOME extension and its private profile config; ' + type(error).__name__}

    async def invoke(self, name, arguments):
        if name != 'computer_window':
            raise ToolError('Unknown GNOME window tool')
        from jsonschema import Draft7Validator, FormatChecker
        errors = list(Draft7Validator(GNOME_WINDOW_TOOLS[0]['inputSchema'], format_checker=FormatChecker()).iter_errors(arguments))
        if errors:
            raise ToolError('Invalid GNOME window arguments')
        async with self.lock:
            try:
                capabilities = await self._run(self._call, 'GetCapabilities')
                if capabilities.get('locked'):
                    raise ToolError('Desktop is locked; window access refused')
                if arguments['action'] == 'list':
                    result = await self._run(self._call, 'ListWindows')
                    if result['bridge_session'] != capabilities['bridge_session']:
                        raise ToolError('GNOME session changed while reading windows; refresh the inventory')
                    windows = result.get('windows')
                    if not isinstance(windows, list) or len(windows) > 4096:
                        raise ToolError('Invalid GNOME window inventory')
                    for window in windows:
                        if not isinstance(window, dict) or not re.fullmatch(capabilities['bridge_session'] + r':[0-9]{1,10}', window.get('window_id', '')):
                            raise ToolError('GNOME inventory contains a foreign window identity')
                else:
                    identity = arguments.get('window_id')
                    if not identity or not identity.startswith(capabilities['bridge_session'] + ':'):
                        raise ToolError('Select a current exact window_id from this GNOME bridge session')
                    sequence = capabilities.get('next_focus_sequence')
                    if type(sequence) is not int or not 1 <= sequence < 9007199254740991:
                        raise ToolError('GNOME bridge returned an invalid next focus sequence')
                    nonce = arguments.get('request_id') or capabilities['bridge_session'] + ':' + str(sequence)
                    result = await self._run(self._call, 'FocusWindow', (identity, nonce))
                    if result.get('window_id') != identity or result.get('request_id') != nonce or result['bridge_session'] != capabilities['bridge_session']:
                        raise ToolError('Focus acknowledgement identity mismatch; no automatic replay')
                return text_result(json.dumps(result, ensure_ascii=False), structured=result)
            except ToolError:
                raise
            except Exception as error:
                raise ToolError('GNOME window operation failed: ' + type(error).__name__ + '; focus is never automatically replayed') from None

    async def close(self):
        async with self.lock:
            if self.bus:
                await self._run(self.bus.close_sync, None)
                self.bus = None
