# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Thread-confined libei 1.2 sender for an already authorized portal EIS FD.

This module never opens a portal, desktop, socket path, or input device itself.
The portal owner supplies its own ConnectToEIS descriptor. A disconnect or
device pause refuses input; it never reconnects or repeats a submitted event.
"""
from __future__ import annotations

import ctypes as C
import ctypes.util
import math
import os
import select
import threading
import time

from .registry import ToolError

P, U, I, B, D, Z = C.c_void_p, C.c_uint32, C.c_int, C.c_bool, C.c_double, C.c_size_t
ABSOLUTE, KEYBOARD, SCROLL, BUTTON = 2, 4, 16, 32
CAPS = (ABSOLUTE, KEYBOARD, SCROLL, BUTTON)


class UnrepresentableSymbol(ToolError):
    """Whole-text preflight may choose a separate clipboard transaction."""


def _function(lib, name, result, *arguments):
    fn = getattr(lib, name)
    fn.restype, fn.argtypes = result, list(arguments)
    return fn


def _ei_library():
    path = ctypes.util.find_library('ei')
    if not path:
        raise ToolError('libei >= 1.2 is required for portal EIS input')
    lib = C.CDLL(path)
    signatures = {
        'ei_new_sender': (P, P), 'ei_unref': (P, P),
        'ei_configure_name': (None, P, C.c_char_p),
        'ei_setup_backend_fd': (I, P, I), 'ei_get_fd': (I, P),
        'ei_dispatch': (None, P), 'ei_get_event': (P, P),
        'ei_event_unref': (P, P), 'ei_event_get_type': (I, P),
        'ei_event_get_seat': (P, P), 'ei_event_get_device': (P, P),
        'ei_seat_ref': (P, P), 'ei_seat_unref': (P, P),
        'ei_seat_has_capability': (B, P, I),
        'ei_seat_bind_capabilities': (None, P),
        'ei_device_ref': (P, P), 'ei_device_unref': (P, P),
        'ei_device_get_seat': (P, P), 'ei_device_get_type': (I, P),
        'ei_device_has_capability': (B, P, I),
        'ei_device_start_emulating': (None, P, U),
        'ei_device_stop_emulating': (None, P),
        'ei_device_frame': (None, P, C.c_uint64), 'ei_now': (C.c_uint64, P),
        'ei_device_pointer_motion_absolute': (None, P, D, D),
        'ei_device_button_button': (None, P, U, B),
        'ei_device_scroll_discrete': (None, P, I, I),
        'ei_device_keyboard_key': (None, P, U, B),
        'ei_device_keyboard_get_keymap': (P, P),
        'ei_keymap_get_type': (I, P), 'ei_keymap_get_fd': (I, P),
        'ei_keymap_get_size': (Z, P), 'ei_device_get_region': (P, P, Z),
        'ei_region_get_x': (U, P), 'ei_region_get_y': (U, P),
        'ei_region_get_width': (U, P), 'ei_region_get_height': (U, P),
        'ei_region_get_mapping_id': (C.c_char_p, P),
        'ei_region_get_physical_scale': (D, P),
    }
    for name, signature in signatures.items():
        _function(lib, name, *signature)
    for field in ('depressed', 'latched', 'locked'):
        _function(lib, 'ei_event_keyboard_get_xkb_mods_' + field, U, P)
    _function(lib, 'ei_event_keyboard_get_xkb_group', U, P)
    return lib


class XkbState:
    """Use the server's keymap and modifiers, including Wayland Caps Lock."""
    def __init__(self, raw):
        if not raw or len(raw) > 4 * 1024 * 1024:
            raise ToolError('Invalid or oversized EIS keyboard keymap')
        self.lib = C.CDLL(ctypes.util.find_library('xkbcommon') or 'libxkbcommon.so.0')
        specs = {
            'xkb_context_new': (P, I), 'xkb_context_unref': (None, P),
            'xkb_keymap_new_from_string': (P, P, C.c_char_p, I, I),
            'xkb_keymap_unref': (None, P), 'xkb_state_new': (P, P),
            'xkb_state_unref': (None, P),
            'xkb_state_update_mask': (U, P, U, U, U, U, U, U),
            'xkb_state_update_key': (U, P, U, I),
            'xkb_state_serialize_mods': (U, P, U),
            'xkb_state_serialize_layout': (U, P, U),
            'xkb_state_key_get_one_sym': (U, P, U),
            'xkb_keysym_to_lower': (U, U),
            'xkb_keymap_min_keycode': (U, P), 'xkb_keymap_max_keycode': (U, P),
            'xkb_keymap_mod_get_index': (U, P, C.c_char_p),
            'xkb_state_mod_name_is_active': (I, P, C.c_char_p, U),
        }
        for name, signature in specs.items():
            _function(self.lib, name, *signature)
        self.context = self.lib.xkb_context_new(0)
        self.keymap = self.lib.xkb_keymap_new_from_string(self.context, raw.rstrip(b'\0'), 1, 0)
        self.state = self.lib.xkb_state_new(self.keymap) if self.keymap else None
        if not self.state:
            self.close()
            raise ToolError('The EIS keyboard has no usable XKB keymap')
        self.minimum = self.lib.xkb_keymap_min_keycode(self.keymap)
        self.maximum = self.lib.xkb_keymap_max_keycode(self.keymap)
        self.known_modifiers = False

    def modifiers(self, depressed, latched, locked, group):
        self.lib.xkb_state_update_mask(self.state, depressed, latched, locked, 0, 0, group)
        self.known_modifiers = True

    def update_key(self, code, down):
        self.lib.xkb_state_update_key(self.state, code + 8, int(down))

    def masks(self):
        return tuple(self.lib.xkb_state_serialize_mods(self.state, part) for part in (1, 2, 4)) + (
            self.lib.xkb_state_serialize_layout(self.state, 1 << 7),)

    def lock_state(self):
        return {'caps_lock': bool(self.lib.xkb_state_mod_name_is_active(self.state, b'Lock', 1 << 3)),
                'num_lock': bool(self.lib.xkb_state_mod_name_is_active(self.state, b'Mod2', 1 << 3))}

    def require_text_modifiers(self):
        if any(self.lib.xkb_state_mod_name_is_active(self.state, name, 1 << 3)
               for name in (b'Control', b'Mod1', b'Mod4')):
            raise ToolError('A shortcut modifier is physically active; no exact text submitted')

    def plan(self, keysym):
        if not self.known_modifiers:
            raise UnrepresentableSymbol('EIS has not supplied keyboard modifier state; exact keyboard text refused before input')
        depressed, latched, locked, group = self.masks()
        # Only add modifiers owned by us. Never clear a user's physical modifier.
        candidates = [(0, ())]
        for name, modifier_keysym in ((b'Shift', 0xffe1), (b'Mod5', 0xfe03)):
            index = self.lib.xkb_keymap_mod_get_index(self.keymap, name)
            if index < 32 and not (depressed | latched) & (1 << index):
                candidates += [(mask | (1 << index), symbols + (modifier_keysym,))
                               for mask, symbols in list(candidates)]
        temporary = self.lib.xkb_state_new(self.keymap)
        try:
            for mask, modifier_symbols in candidates:
                self.lib.xkb_state_update_mask(temporary, depressed | mask, latched, locked, 0, 0, group)
                matches = [code for code in range(max(8, self.minimum), self.maximum + 1)
                           if self.lib.xkb_state_key_get_one_sym(temporary, code) == keysym]
                if not matches:
                    continue
                extras = []
                for symbol in modifier_symbols:
                    # Modifier keys have no letter case; locate in neutral state.
                    self.lib.xkb_state_update_mask(temporary, 0, 0, 0, 0, 0, group)
                    match = next((code for code in range(max(8, self.minimum), self.maximum + 1)
                                  if self.lib.xkb_state_key_get_one_sym(temporary, code) == symbol), None)
                    if match is None:
                        break
                    extras.append(match - 8)
                else:
                    return matches[0] - 8, tuple(extras)
            raise UnrepresentableSymbol('Requested symbol is not representable by the granted EIS keymap and current modifiers; no input submitted')
        finally:
            self.lib.xkb_state_unref(temporary)

    def physical_plan(self, keysym):
        """A shortcut A names a physical letter key, without adding Shift.

        Mutter 46 supplies a keymap but no modifier/layout events. Physical
        keys then use the keymap's first layout, not an invented active state.
        Literal text still requires actual modifier state and never uses this
        physical-key fallback.
        """
        keysym = self.lib.xkb_keysym_to_lower(keysym)
        group = self.masks()[3] if self.known_modifiers else 0
        temporary = self.lib.xkb_state_new(self.keymap)
        try:
            self.lib.xkb_state_update_mask(temporary, 0, 0, 0, 0, 0, group)
            for code in range(max(8, self.minimum), self.maximum + 1):
                if self.lib.xkb_state_key_get_one_sym(temporary, code) == keysym:
                    return code - 8, ()
            raise ToolError('No physical key for the requested symbol in the granted keyboard layout; no input submitted')
        finally:
            self.lib.xkb_state_unref(temporary)

    def close(self):
        for name, method in (('state', 'xkb_state_unref'), ('keymap', 'xkb_keymap_unref'), ('context', 'xkb_context_unref')):
            value = getattr(self, name, None)
            if value:
                getattr(self.lib, method)(value)
                setattr(self, name, None)


class EisSender:
    """Own an authorized EIS descriptor. Every method uses its creator thread."""
    def __init__(self, fd, *, timeout=5):
        self.thread = threading.get_ident()
        self.lib, self.context = None, None
        self.seats, self.devices, self.pressed, self.buttons = {}, {}, {}, {}
        self.connected = self.disconnected = False
        self.sequence, self.timeout = 0, timeout
        self.device_sequence = 0
        self.pointer_device = None
        try:
            self.lib = _ei_library()
            self.context = self.lib.ei_new_sender(None)
            if not self.context:
                raise ToolError('Could not create the EIS sender')
            self.lib.ei_configure_name(self.context, b'Hepta Runtime authorized computer provider')
            # Transfer a duplicate. This method always closes the caller's FD.
            owned = os.dup(fd)
            result = self.lib.ei_setup_backend_fd(self.context, owned)
            if result < 0:
                raise ToolError('EIS descriptor initialization failed')
            self.wait_ready()
        except BaseException:
            self.close()
            raise
        finally:
            os.close(fd)

    def _thread(self):
        if threading.get_ident() != self.thread:
            raise ToolError('EIS input must remain on its portal owner thread')

    def pump(self):
        self._thread()
        if not self.context or self.disconnected:
            raise ToolError('EIS is disconnected; input is not replayed')
        self.lib.ei_dispatch(self.context)
        for _ in range(1024):
            event = self.lib.ei_get_event(self.context)
            if not event:
                break
            try:
                kind = self.lib.ei_event_get_type(event)
                if kind == 1:
                    self.connected = True
                elif kind == 2:
                    self.disconnected = True
                elif kind == 3:
                    seat = self.lib.ei_event_get_seat(event)
                    if seat not in self.seats:
                        self.seats[seat] = self.lib.ei_seat_ref(seat)
                        capabilities = [I(cap) for cap in CAPS if self.lib.ei_seat_has_capability(seat, cap)]
                        self.lib.ei_seat_bind_capabilities(seat, *capabilities, P())
                elif kind == 4:
                    seat = self.lib.ei_event_get_seat(event)
                    value = self.seats.pop(seat, None)
                    if value:
                        self.lib.ei_seat_unref(value)
                elif kind == 5:
                    device = self.lib.ei_event_get_device(event)
                    if device not in self.devices:
                        self.device_sequence += 1
                        self.devices[device] = {'ref': self.lib.ei_device_ref(device), 'ready': False,
                            'emulating': False, 'caps': [cap for cap in CAPS if self.lib.ei_device_has_capability(device, cap)], 'xkb': None,
                            'ordinal': self.device_sequence, 'seat': self.lib.ei_device_get_seat(device),
                            'type': self.lib.ei_device_get_type(device),
                            'all_caps': [cap for cap in (1, 2, 4, 8, 16, 32) if self.lib.ei_device_has_capability(device, cap)]}
                        if KEYBOARD in self.devices[device]['caps']:
                            keymap = self.lib.ei_device_keyboard_get_keymap(device)
                            if keymap and self.lib.ei_keymap_get_type(keymap) == 1:
                                size = self.lib.ei_keymap_get_size(keymap)
                                if 0 < size <= 4 * 1024 * 1024:
                                    self.devices[device]['xkb'] = XkbState(os.pread(self.lib.ei_keymap_get_fd(keymap), size, 0))
                elif kind in (6, 7, 8, 9):
                    device = self.lib.ei_event_get_device(event)
                    info = self.devices.get(device)
                    if not info:
                        continue
                    if kind == 6:
                        self.pressed = {key: value for key, value in self.pressed.items() if value[0] != device}
                        self.buttons = {key: value for key, value in self.buttons.items() if value != device}
                        if info['xkb']:
                            info['xkb'].close()
                        self.lib.ei_device_unref(info['ref'])
                        del self.devices[device]
                    elif kind == 7:
                        info['ready'] = info['emulating'] = False
                        self.pressed = {key: value for key, value in self.pressed.items() if value[0] != device}
                        self.buttons = {key: value for key, value in self.buttons.items() if value != device}
                    elif kind == 8:
                        info['ready'] = True
                    elif info['xkb']:
                        masks = [getattr(self.lib, 'ei_event_keyboard_get_xkb_mods_' + name)(event)
                                 for name in ('depressed', 'latched', 'locked')]
                        info['xkb'].modifiers(*masks, self.lib.ei_event_keyboard_get_xkb_group(event))
            finally:
                self.lib.ei_event_unref(event)
        if self.disconnected:
            raise ToolError('EIS server disconnected; no reconnect or input replay')

    def wait_ready(self):
        deadline = time.monotonic() + self.timeout
        while True:
            self.pump()
            if self.connected and all(any(info['ready'] and cap in info['caps'] and
                    (cap != KEYBOARD or info['xkb'])
                    for info in self.devices.values()) for cap in CAPS):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ToolError('EIS did not provide resumed pointer/keyboard devices and a usable keymap; no input submitted')
            select.select([self.lib.ei_get_fd(self.context)], [], [], min(.02, remaining))

    def _device(self, capability):
        self.pump()
        ordered = list(self.devices.items())
        if capability in (BUTTON, SCROLL):
            ordered.sort(key=lambda item: item[0] != self.pointer_device)
        for device, info in ordered:
            if capability in info['caps'] and info['ready']:
                self._start(device, info)
                return device, info
        raise ToolError('The authorized EIS device is paused or unavailable; no input submitted')

    def _start(self, device, info):
        if not info['emulating']:
            self.sequence += 1
            if self.sequence >= 2 ** 32:
                raise ToolError('EIS sequence exhausted; no input submitted')
            self.lib.ei_device_start_emulating(device, self.sequence)
            info['emulating'] = True

    def _frame(self, device):
        self.lib.ei_device_frame(device, self.lib.ei_now(self.context))
        self.lib.ei_dispatch(self.context)

    def _regions(self, device):
        rows = []
        for index in range(257):
            region = self.lib.ei_device_get_region(device, index)
            if not region:
                return rows
            if index == 256:
                raise ToolError('EIS region inventory exceeds the validation bound; no input submitted')
            raw_mapping = self.lib.ei_region_get_mapping_id(region)
            scale = self.lib.ei_region_get_physical_scale(region)
            if not math.isfinite(scale) or scale <= 0:
                raise ToolError('EIS region has an invalid physical scale; no input submitted')
            rows.append({'rectangle': [self.lib.ei_region_get_x(region), self.lib.ei_region_get_y(region),
                                       self.lib.ei_region_get_width(region), self.lib.ei_region_get_height(region)],
                         'mapping_id': raw_mapping.decode() if raw_mapping else None, 'physical_scale': scale})
        raise AssertionError('unreachable region bound')

    @staticmethod
    def _inventory_signature(info, regions):
        return (info['seat'], info['type'], tuple(sorted(info['all_caps'])),
                tuple(sorted((row['mapping_id'] or '', tuple(row['rectangle']), row['physical_scale']) for row in regions)))

    def _pointer_match(self, stream):
        size, position, mapping = stream['logical_size'], stream['position'], stream.get('mapping_id')
        candidates = []
        for device, info in self.devices.items():
            if not info['ready'] or ABSOLUTE not in info['caps']:
                continue
            regions = self._regions(device)
            for row in regions:
                # An explicit mapping identifies the stream resource. A stale
                # or foreign ID must never be replaced with a geometry guess.
                if ((mapping and row['mapping_id'] == mapping) or
                        (not mapping and row['rectangle'] == position + size)):
                    candidates.append((device, info, row, regions))
        if not candidates:
            raise ToolError('No EIS region matches the user-granted stream; no input submitted')
        if any(info['type'] != 1 for _, info, _, _ in candidates):
            raise ToolError('EIS stream mapping requires virtual pointer regions; no input submitted')
        if any(row['rectangle'][2:] != size for _, _, row, _ in candidates):
            raise ToolError('EIS stream mapping has conflicting dimensions; no input submitted')
        if len(candidates) > 1:
            # Mutter 46 publishes the same shared monitor device in its client
            # constructor and again on seat bind. Both remain resumed. They
            # are interchangeable only when the complete same-seat virtual
            # device inventories are identical, including every ID and scale.
            # A repeated ID within one device or a resize transition is refused.
            devices = {device for device, _, _, _ in candidates}
            signatures = {self._inventory_signature(info, regions) for _, info, _, regions in candidates}
            if (not mapping or len(devices) != len(candidates) or len(signatures) != 1 or
                    any(info['type'] != 1 for _, info, _, _ in candidates)):
                raise ToolError('EIS stream mapping is ambiguous across non-equivalent regions; no input submitted')
        held_devices = set(self.buttons.values())
        if len(held_devices) > 1:
            raise ToolError('Held EIS buttons belong to multiple pointer devices; no movement submitted')
        held = next(iter(held_devices), None)
        if held is not None and held not in {device for device, _, _, _ in candidates}:
            raise ToolError('Held EIS button cannot move to another pointer device; no movement submitted')
        preferred = held if held is not None else self.pointer_device
        for device, info, row, _ in candidates:
            if device == preferred:
                return device, info, row['rectangle']
        device, info, row, _ = max(candidates, key=lambda item: item[1]['ordinal'])
        return device, info, row['rectangle']

    def move(self, x, y, stream):
        self.pump()
        size, position, mapping = stream.get('logical_size'), stream.get('position'), stream.get('mapping_id')
        if len(size or []) != 2 or len(position or []) != 2 or not (0 <= x < size[0] and 0 <= y < size[1]):
            raise ToolError('EIS coordinates require the exact granted stream geometry')
        device, info, rectangle = self._pointer_match(stream)
        self._start(device, info)
        self.lib.ei_device_pointer_motion_absolute(device, rectangle[0] + x, rectangle[1] + y)
        self.pointer_device = device
        self._frame(device)

    def button(self, button, down):
        if down:
            if button in self.buttons:
                raise ToolError('EIS button is already held; no replay')
            device, _ = self._device(BUTTON)
            held_devices = set(self.buttons.values())
            if held_devices and held_devices != {device}:
                raise ToolError('Held EIS buttons must stay on one pointer device; no input submitted')
            self.buttons[button] = device
            self.pointer_device = device
        else:
            self.pump()
            device = self.buttons.pop(button, None)
            if device is None:
                return
            if not self.devices.get(device, {}).get('ready'):
                raise ToolError('EIS button device was paused; release is not replayed')
        self.lib.ei_device_button_button(device, {'left': 272, 'right': 273, 'middle': 274}[button], down)
        self._frame(device)

    def scroll(self, direction, steps):
        device, _ = self._device(SCROLL)
        x, y = (0, (-1 if direction == 'up' else 1) * steps * 120) if direction in ('up', 'down') else ((-1 if direction == 'left' else 1) * steps * 120, 0)
        self.lib.ei_device_scroll_discrete(device, x, y)
        self._frame(device)

    def _keycode(self, device, info, code, down):
        self.lib.ei_device_keyboard_key(device, code, down)
        info['xkb'].update_key(code, down)
        self._frame(device)

    def key(self, keysym, down, *, literal=False):
        if down:
            if keysym in self.pressed:
                raise ToolError('EIS key is already held; no replay')
            device, info = self._device(KEYBOARD)
            if not info['xkb']:
                raise ToolError('No EIS keyboard keymap; no input submitted')
            code, extras = (info['xkb'].plan if literal else info['xkb'].physical_plan)(keysym)
            self.pressed[keysym] = (device, code, extras)
            for modifier in extras:
                self._keycode(device, info, modifier, True)
            self._keycode(device, info, code, True)
        else:
            self.pump()
            held = self.pressed.pop(keysym, None)
            if held is None:
                return
            device, code, extras = held
            info = self.devices.get(device)
            if not info or not info['ready']:
                raise ToolError('EIS key device was paused; release is not replayed')
            self._keycode(device, info, code, False)
            for modifier in reversed(extras):
                self._keycode(device, info, modifier, False)

    def preflight_text(self, keysyms):
        _, info = self._device(KEYBOARD)
        if not info['xkb']:
            raise ToolError('No EIS keyboard keymap; no input submitted')
        if not info['xkb'].known_modifiers:
            raise UnrepresentableSymbol('EIS has not supplied keyboard modifier state; exact keyboard text refused before input')
        info['xkb'].require_text_modifiers()
        for keysym in keysyms:
            info['xkb'].plan(keysym)

    def diagnostics(self):
        self.pump()
        keyboard = next((info['xkb'] for info in self.devices.values() if info['ready'] and info['xkb']), None)
        return {'transport': 'portal_eis_libei', 'connected': self.connected and not self.disconnected,
                'resumed_devices': sum(info['ready'] for info in self.devices.values()),
                'ready_capabilities': {str(cap): any(info['ready'] and cap in info['caps'] for info in self.devices.values()) for cap in CAPS},
                'modifier_state_known': bool(keyboard and keyboard.known_modifiers),
                'locks': keyboard.lock_state() if keyboard and keyboard.known_modifiers else None,
                'physical_key_layout': 'reported_active_layout' if keyboard and keyboard.known_modifiers else 'server_keymap_first_layout',
                'exact_keyboard_text': bool(keyboard and keyboard.known_modifiers),
                'device_inventory': [{'device_index': info['ordinal'], 'device_type': info['type'],
                                      'capabilities': info['all_caps'], 'resumed': info['ready'],
                                      'regions': self._regions(device)} for device, info in self.devices.items()],
                'arbitrary_unicode_text': False, 'automatic_reconnect': False}

    def close(self):
        self._thread()
        if not self.context:
            return
        if not self.disconnected:
            for key in list(self.pressed):
                try:
                    self.key(key, False)
                except Exception:
                    pass
            for button in list(self.buttons):
                try:
                    self.button(button, False)
                except Exception:
                    pass
        for device, info in self.devices.items():
            if info['ready'] and info['emulating'] and not self.disconnected:
                self.lib.ei_device_stop_emulating(device)
            if info['xkb']:
                info['xkb'].close()
            self.lib.ei_device_unref(info['ref'])
        self.devices.clear()
        for seat in self.seats.values():
            self.lib.ei_seat_unref(seat)
        self.seats.clear()
        self.lib.ei_unref(self.context)
        self.context = None
