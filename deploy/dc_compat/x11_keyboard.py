# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""X11 text input using only the server's existing XKB map and XTest keycodes.

The private worker inherits one pinned DISPLAY/XAUTHORITY. It never changes the
global keymap, locks, group, or a user's depressed modifiers. Preparation checks
the whole string before the first event. Prepared plans are consumed once and
never rebuilt/replayed after execution starts. There is no application text ACK.
"""
from __future__ import annotations

import ctypes as C
import ctypes.util
from dataclasses import dataclass
import hashlib
import json
import os
import pathlib
import select
import signal
import subprocess
import sys
import threading
import time
import uuid

if __package__ in (None, ''):
    # -I excludes the working directory and user Python configuration.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    from dc_compat.registry import ToolError
    from dc_compat.computer_eis import XkbState, UnrepresentableSymbol, _function, P, U, I
else:
    from .registry import ToolError
    from .computer_eis import XkbState, UnrepresentableSymbol, _function, P, U, I


def _receipt(*, submitted=False, characters=0, outcome='not_submitted', **extra):
    value = dict(method='keyboard', submitted=submitted, characters=characters,
                 clipboard_modified=False, replayed=False, target_input_verified=False,
                 input_outcome=outcome)
    value.update(extra)
    return value


class X11KeyboardError(ToolError):
    def __init__(self, message, receipt=None):
        self.receipt = dict(receipt or _receipt())
        super().__init__(message)


class X11Unrepresentable(X11KeyboardError):
    """Only whole-text preparation can select a clipboard alternative."""


@dataclass(frozen=True)
class PreparedPlan:
    token: str
    kind: str
    characters: int = 0


@dataclass
class _Snapshot:
    xkb: object
    fingerprint: tuple
    pressed: frozenset

    def close(self):
        self.xkb.close()


class _NativeKeyboard:
    """Construct only inside the explicitly configured private worker."""
    def __init__(self):
        self.display = None
        self.context = None
        self.xerror = False
        def library(name):
            path = ctypes.util.find_library(name)
            if not path:
                raise X11KeyboardError('Required X11 keyboard library is unavailable: ' + name)
            return C.CDLL(path)
        self.xlib, self.xtst = library('X11'), library('Xtst')
        self.bridge, self.xkb11 = library('X11-xcb'), library('xkbcommon-x11')
        self.xkb = library('xkbcommon')
        _function(self.xlib, 'XOpenDisplay', P, C.c_char_p)
        _function(self.xlib, 'XCloseDisplay', I, P)
        _function(self.xlib, 'XGetInputFocus', I, P, C.POINTER(C.c_ulong), C.POINTER(I))
        _function(self.xlib, 'XQueryKeymap', I, P, C.c_char_p)
        _function(self.xlib, 'XSync', I, P, I)
        _function(self.xtst, 'XTestFakeKeyEvent', I, P, U, I, C.c_ulong)
        _function(self.xtst, 'XTestQueryExtension', I, P, C.POINTER(I), C.POINTER(I), C.POINTER(I), C.POINTER(I))
        _function(self.bridge, 'XGetXCBConnection', P, P)
        _function(self.xkb11, 'xkb_x11_setup_xkb_extension', I, P, C.c_uint16, C.c_uint16, I,
                  P, P, P, P)
        _function(self.xkb11, 'xkb_x11_get_core_keyboard_device_id', I, P)
        _function(self.xkb11, 'xkb_x11_keymap_new_from_device', P, P, P, I, I)
        _function(self.xkb11, 'xkb_x11_state_new_from_device', P, P, P, I)
        for name, spec in {
            'xkb_context_new': (P, I), 'xkb_context_unref': (None, P),
            'xkb_keymap_get_as_string': (P, P, I), 'xkb_keymap_unref': (None, P),
            'xkb_state_unref': (None, P), 'xkb_state_serialize_mods': (U, P, U),
            'xkb_state_serialize_layout': (U, P, U), 'xkb_keysym_from_name': (U, C.c_char_p, I),
            'xkb_utf32_to_keysym': (U, U),
        }.items():
            _function(self.xkb, name, *spec)
        self.libc = C.CDLL(None)
        _function(self.libc, 'free', None, P)
        handler_type = C.CFUNCTYPE(I, P, P)
        self._handler = handler_type(lambda display, event: self._error())
        _function(self.xlib, 'XSetErrorHandler', P, handler_type)
        self.xlib.XSetErrorHandler(self._handler)
        try:
            display = os.environ.get('DISPLAY')
            if not display:
                raise X11KeyboardError('An explicit X11 display is required')
            self.display = self.xlib.XOpenDisplay(display.encode())
            if not self.display:
                raise X11KeyboardError('Cannot open the configured X11 keyboard display')
            params = [I() for _ in range(4)]
            if not self.xtst.XTestQueryExtension(self.display, *(C.byref(x) for x in params)):
                raise X11KeyboardError('The configured X11 display has no XTest extension')
            self.connection = self.bridge.XGetXCBConnection(self.display)
            if not self.connection or not self.xkb11.xkb_x11_setup_xkb_extension(
                    self.connection, 1, 0, 0, None, None, None, None):
                raise X11KeyboardError('The configured X11 display has no usable XKB extension')
            self.device = self.xkb11.xkb_x11_get_core_keyboard_device_id(self.connection)
            self.context = self.xkb.xkb_context_new(0)
            if self.device < 0 or not self.context:
                raise X11KeyboardError('Cannot query the configured X11 keyboard')
        except BaseException:
            self.close()
            raise

    def _error(self):
        self.xerror = True
        return 0

    def _sync(self):
        self.xlib.XSync(self.display, 0)
        if self.xerror:
            raise X11KeyboardError('The X server reported a keyboard request error')

    def symbol(self, value):
        if len(value) == 1:
            symbol = self.xkb.xkb_utf32_to_keysym(ord(value))
            if not symbol:
                raise X11Unrepresentable('Character has no X11 keysym; no input submitted')
            return int(symbol)
        symbol = self.xkb.xkb_keysym_from_name(value.encode('ascii'), 0)
        if not symbol:
            raise X11KeyboardError('Unsupported X11 physical key name')
        return int(symbol)

    def snapshot(self):
        keymap = state = raw_pointer = None
        xkb = None
        try:
            keymap = self.xkb11.xkb_x11_keymap_new_from_device(self.context, self.connection, self.device, 0)
            state = self.xkb11.xkb_x11_state_new_from_device(keymap, self.connection, self.device) if keymap else None
            if not state:
                raise X11KeyboardError('Cannot read the current X11 keymap and modifier state')
            raw_pointer = self.xkb.xkb_keymap_get_as_string(keymap, 1)
            if not raw_pointer:
                raise X11KeyboardError('Cannot serialize the current X11 keymap')
            raw = C.string_at(raw_pointer)
            masks = tuple(int(self.xkb.xkb_state_serialize_mods(state, part)) for part in (1, 2, 4)) + (
                int(self.xkb.xkb_state_serialize_layout(state, 1 << 7)),)
            xkb = XkbState(raw)
            xkb.modifiers(*masks)
            focus, revert = C.c_ulong(), I()
            self.xlib.XGetInputFocus(self.display, C.byref(focus), C.byref(revert))
            if focus.value <= 1:
                raise X11KeyboardError('No focused X11 client window is available; no input submitted')
            buffer = C.create_string_buffer(32)
            self.xlib.XQueryKeymap(self.display, buffer)
            self._sync()
            pressed = frozenset(code for code in range(256) if buffer.raw[code // 8] & (1 << (code % 8)))
            fingerprint = (hashlib.sha256(raw).hexdigest(), masks, int(focus.value), tuple(sorted(pressed)))
            result = _Snapshot(xkb, fingerprint, pressed)
            xkb = None
            return result
        finally:
            if xkb is not None:
                xkb.close()
            if raw_pointer:
                self.libc.free(raw_pointer)
            if state:
                self.xkb.xkb_state_unref(state)
            if keymap:
                self.xkb.xkb_keymap_unref(keymap)

    def key(self, code, down):
        if not self.xtst.XTestFakeKeyEvent(self.display, code, int(down), 0):
            raise X11KeyboardError('XTest did not accept a keyboard event')
        self._sync()

    def close(self):
        if self.context:
            self.xkb.xkb_context_unref(self.context)
            self.context = None
        if self.display:
            self.xlib.XCloseDisplay(self.display)
            self.display = None


_MODIFIER_NAMES = {'Control_L': b'Control', 'Control_R': b'Control',
                   'Shift_L': b'Shift', 'Shift_R': b'Shift',
                   'Alt_L': b'Mod1', 'Alt_R': b'Mod1',
                   'Super_L': b'Mod4', 'Super_R': b'Mod4',
                   'Meta_L': b'Mod1', 'Meta_R': b'Mod1',
                   'ISO_Level3_Shift': b'Mod5'}


class KeyboardEngine:
    """Preparation/execution policy, also tested with a display-free native stub."""
    def __init__(self, native):
        self.native, self.plans = native, {}

    @staticmethod
    def _physical_code(xkb, symbol):
        return xkb.physical_plan(symbol)[0] + 8

    def _store(self, kind, snapshot, entries, characters):
        now = time.monotonic()
        self.plans = {key: value for key, value in self.plans.items() if now - value['created'] < 300}
        if len(self.plans) >= 8:
            raise X11KeyboardError('Too many unconsumed X11 keyboard plans; no input submitted')
        token = uuid.uuid4().hex
        self.plans[token] = {'kind': kind, 'fingerprint': snapshot.fingerprint,
                             'entries': entries, 'characters': characters, 'created': now}
        return {'token': token, 'kind': kind, 'characters': characters}

    def prepare_text(self, text, explicit_unicode_method=None):
        if not isinstance(text, str) or len(text) > 16384 or '\0' in text:
            raise X11KeyboardError('Invalid X11 text; no input submitted')
        try:
            text.encode('utf-8')
        except UnicodeError:
            raise X11KeyboardError('X11 text must contain valid Unicode; no input submitted') from None
        if explicit_unicode_method not in (None, 'gtk_hex'):
            raise X11KeyboardError('Unsupported explicit X11 Unicode method; no input submitted')
        if explicit_unicode_method == 'gtk_hex':
            return self._prepare_gtk_hex(text)
        snapshot = self.native.snapshot()
        try:
            if snapshot.xkb.masks()[1]:
                raise UnrepresentableSymbol('Latched X11 modifiers prevent exact text preflight')
            snapshot.xkb.require_text_modifiers()
            # Only a user's existing Shift/AltGr may remain depressed. Other
            # physical keys must not be released or pressed again by typing.
            allowed = {self._physical_code(snapshot.xkb, self.native.symbol(name))
                       for name in ('Shift_L', 'Shift_R', 'ISO_Level3_Shift')
                       if self._has_physical(snapshot.xkb, name)}
            if snapshot.pressed - allowed:
                raise UnrepresentableSymbol('Other physical X11 keys are held')
            cache, entries = {}, []
            for character in text:
                name = {'\n': 'Return', '\r': 'Return', '\t': 'Tab'}.get(character, character)
                symbol = self.native.symbol(name)
                if symbol not in cache:
                    try:
                        code, modifiers = snapshot.xkb.plan(symbol)
                    except UnrepresentableSymbol:
                        # Existing maps may use the Unicode keysym instead of
                        # the equivalent legacy Cyrillic/Greek/etc. symbol.
                        if len(name) != 1 or ord(name) < 256 or symbol == ord(name) + 0x01000000:
                            raise
                        code, modifiers = snapshot.xkb.plan(ord(name) + 0x01000000)
                    cache[symbol] = (code + 8, tuple(value + 8 for value in modifiers))
                code, modifiers = cache[symbol]
                if code in snapshot.pressed or any(value in snapshot.pressed for value in modifiers):
                    raise UnrepresentableSymbol('A required physical X11 key is already held')
                entries.append((code, modifiers))
            return self._store('text', snapshot, entries, len(text))
        except X11KeyboardError:
            raise
        except (UnrepresentableSymbol, ToolError):
            # No event has been submitted during whole-string preparation.
            raise X11Unrepresentable('The complete text is not representable by the current X11 keyboard map/state; no input submitted') from None
        finally:
            snapshot.close()

    def _prepare_gtk_hex(self, text):
        """Explicit GTK IMContextSimple protocol, never an automatic fallback.

        GTK 3 gtkimcontextsimple.c starts on uppercase U with Ctrl+Shift. Once
        those modifiers are released, hex digits and Return commit a Unicode
        scalar. Each protocol key uses an existing mapping. No temporary keymap
        or clipboard is needed, and no application/IME support is inferred.
        """
        snapshot = self.native.snapshot()
        metadata = {'method': 'gtk_hex', 'unicode_method': 'gtk_hex',
                    'application_scope': 'GTK-compatible Ctrl+Shift+U input method only',
                    'composition_may_be_active': False, 'global_keymap_modified': False}
        try:
            depressed, latched, locked, group = snapshot.xkb.masks()
            if depressed or latched or snapshot.pressed:
                raise X11KeyboardError('Explicit GTK hex input requires released physical keys/modifiers; no input submitted')
            control = self._physical_code(snapshot.xkb, self.native.symbol('Control_L'))
            shift = self._physical_code(snapshot.xkb, self.native.symbol('Shift_L'))
            control_index = snapshot.xkb.lib.xkb_keymap_mod_get_index(snapshot.xkb.keymap, b'Control')
            shift_index = snapshot.xkb.lib.xkb_keymap_mod_get_index(snapshot.xkb.keymap, b'Shift')
            if control_index >= 32 or shift_index >= 32 or control == shift:
                raise X11KeyboardError('Current X11 map has no usable Ctrl+Shift shortcut; no input submitted')
            # Caps Lock is preserved. If the real Ctrl+Shift state produces a
            # lowercase u, GTK's uppercase-U start rule is not satisfied.
            temporary = snapshot.xkb.lib.xkb_state_new(snapshot.xkb.keymap)
            if not temporary:
                raise X11KeyboardError('Cannot prepare the GTK hex shortcut; no input submitted')
            try:
                snapshot.xkb.lib.xkb_state_update_mask(temporary,
                    (1 << control_index) | (1 << shift_index), 0, locked, 0, 0, group)
                uppercase_u = self.native.symbol('U')
                start = next((code for code in range(max(8, snapshot.xkb.minimum), snapshot.xkb.maximum + 1)
                    if snapshot.xkb.lib.xkb_state_key_get_one_sym(temporary, code) == uppercase_u
                    and code not in (control, shift)), None)
            finally:
                snapshot.xkb.lib.xkb_state_unref(temporary)
            if start is None:
                raise X11KeyboardError('Current layout/locks cannot produce GTK Ctrl+Shift+uppercase-U; no input submitted')
            needed = {'Return'} | {digit for character in text for digit in format(ord(character), 'x')}
            keys = {}
            for name in needed:
                code, modifiers = snapshot.xkb.plan(self.native.symbol(name))
                keys[name] = (code + 8, tuple(value + 8 for value in modifiers))
            entries = []
            for character in text:
                entries.append((start, (control, shift)))
                entries.extend(keys[digit] for digit in format(ord(character), 'x'))
                entries.append(keys['Return'])
            return self._store('gtk_hex', snapshot, entries, len(text))
        except ToolError as error:
            # The caller explicitly selected this app-specific route. Refusal
            # must not masquerade as ordinary preflight eligible for fallback.
            raise X11KeyboardError(str(error), _receipt(**metadata)) from None
        finally:
            snapshot.close()

    def _has_physical(self, xkb, name):
        try:
            self._physical_code(xkb, self.native.symbol(name))
            return True
        except ToolError:
            return False

    def prepare_combo(self, keys):
        if not isinstance(keys, (list, tuple)) or not 1 <= len(keys) <= 8 or len(set(keys)) != len(keys):
            raise X11KeyboardError('Invalid X11 key combination; no input submitted')
        snapshot = self.native.snapshot()
        try:
            if snapshot.xkb.masks()[1]:
                raise X11KeyboardError('Latched X11 modifiers prevent exact paste preflight; no input submitted')
            codes = [self._physical_code(snapshot.xkb, self.native.symbol(name)) for name in keys]
            if len(set(codes)) != len(codes):
                raise X11KeyboardError('Duplicate physical X11 keys; no input submitted')
            allowed_mask = 0
            preheld = set()
            for name, code in zip(keys, codes):
                modifier = _MODIFIER_NAMES.get(name)
                if modifier:
                    index = snapshot.xkb.lib.xkb_keymap_mod_get_index(snapshot.xkb.keymap, modifier)
                    if index < 32:
                        allowed_mask |= 1 << index
                    if code in snapshot.pressed:
                        preheld.add(code)
                elif code in snapshot.pressed:
                    raise X11KeyboardError('A combination key is already physically held; no input submitted')
            depressed = snapshot.xkb.masks()[0]
            if depressed & ~allowed_mask or snapshot.pressed - preheld:
                raise X11KeyboardError('An unrelated physical X11 key/modifier is held; no input submitted')
            return self._store('combo', snapshot, [(code, ()) for code in codes if code not in preheld], 0)
        finally:
            snapshot.close()

    def execute(self, token, kind):
        # Consume before validation or input; an uncertain call can never reuse it.
        plan = self.plans.pop(token, None)
        if not plan or plan['kind'] != kind or time.monotonic() - plan['created'] >= 300:
            raise X11KeyboardError('Unknown, consumed or expired X11 keyboard plan; no input submitted')
        attempted, events, owned, release_failed = False, 0, [], False
        text_like = kind in ('text', 'gtk_hex')
        metadata = ({'method': 'gtk_hex', 'unicode_method': 'gtk_hex',
                     'application_scope': 'GTK-compatible Ctrl+Shift+U input method only'}
                    if kind == 'gtk_hex' else {})
        def press(code):
            nonlocal attempted, events
            owned.append(code)
            attempted = True
            self.native.key(code, True)
            events += 1
        def release_all():
            nonlocal release_failed, events
            for code in reversed(owned[:]):
                try:
                    self.native.key(code, False)
                    events += 1
                    owned.remove(code)
                except BaseException:
                    release_failed = True
        try:
            for code, modifiers in plan['entries']:
                # Whole-text preflight does not authorize a later layout, focus,
                # modifier or physical-key change. A partial action is not retried.
                if text_like or not attempted:
                    current = self.native.snapshot()
                    try:
                        if current.fingerprint != plan['fingerprint']:
                            raise X11KeyboardError('X11 keyboard map/state/focus changed after preparation')
                    finally:
                        current.close()
                for modifier in modifiers:
                    press(modifier)
                press(code)
                if text_like:
                    release_all()
                    if owned:
                        raise X11KeyboardError('Could not confirm release of this text action\'s keys')
            release_all()
            if owned:
                raise X11KeyboardError('Could not confirm release of this combination\'s keys')
            return _receipt(submitted=attempted, characters=plan['characters'],
                            outcome='submitted' if attempted else 'not_submitted', key_events_submitted=events,
                            owned_keys_released=True, global_keymap_modified=False,
                            **dict(metadata, **({'composition_may_be_active': False} if kind == 'gtk_hex' else {})))
        except BaseException as error:
            release_all()
            if isinstance(error, (SystemExit, KeyboardInterrupt)):
                raise
            raise X11KeyboardError(
                ('X11 keyboard action may be partially submitted; no replay' if attempted else
                 'X11 keyboard preparation is no longer valid; no input submitted'),
                _receipt(submitted=attempted, characters=plan['characters'],
                         outcome='unknown_or_partial' if attempted else 'not_submitted',
                         key_events_submitted=events, owned_keys_released=not owned and not release_failed,
                         global_keymap_modified=False,
                         **dict(metadata, **({'composition_may_be_active': attempted} if kind == 'gtk_hex' else {})))) from None


class X11Keyboard:
    """Private process boundary; no X connection or input on construction."""
    def __init__(self, env, config=None):
        self.env, self.config = dict(env), dict(config or {})
        self.proc, self.broken, self.closed = None, False, False
        self.lock = threading.Lock()

    def _start(self):
        if self.closed or self.broken:
            raise X11KeyboardError('X11 keyboard worker is closed or uncertain; no automatic restart/replay')
        if self.proc is not None:
            if self.proc.poll() is not None:
                self.broken = True
                raise X11KeyboardError('X11 keyboard worker exited; no automatic restart/replay')
            return
        if not self.env.get('DISPLAY'):
            raise X11KeyboardError('An explicit X11 display is required')
        self.proc = subprocess.Popen([sys.executable, '-I', '-B', str(pathlib.Path(__file__).resolve()), '--worker'],
            env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, bufsize=0)
        os.set_blocking(self.proc.stdin.fileno(), False)
        os.set_blocking(self.proc.stdout.fileno(), False)

    def _request(self, action, *, plan=None, text=None, keys=None, unicode_method=None):
        with self.lock:
            self._start()
            identity = uuid.uuid4().hex
            request = {'id': identity, 'action': action}
            if plan is not None:
                request['token'] = plan.token
            if text is not None:
                request['text'] = text
            if keys is not None:
                request['keys'] = list(keys)
            if unicode_method is not None:
                request['unicode_method'] = unicode_method
            wire = json.dumps(request, ensure_ascii=False, separators=(',', ':')).encode() + b'\n'
            data, written = bytearray(), 0
            timeout = max(5.0, float(self.config.get('x11_keyboard_timeout_seconds', 60)))
            deadline = time.monotonic() + timeout
            executing = action.startswith('execute_')
            try:
                while written < len(wire) or not data.endswith(b'\n'):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    reads, writes, _ = select.select([self.proc.stdout],
                        [self.proc.stdin] if written < len(wire) else [], [], remaining)
                    if writes:
                        written += os.write(self.proc.stdin.fileno(), wire[written:])
                    if reads:
                        block = os.read(self.proc.stdout.fileno(), 65536)
                        if not block:
                            raise EOFError
                        data.extend(block)
                        if len(data) > 1024 * 1024:
                            raise ValueError
                response = json.loads(data)
                if response.get('id') != identity:
                    raise ValueError
            except BaseException:
                self.broken = True
                # Do not resubmit on a new connection. Allow the worker's signal
                # cleanup to release its own keys; an interrupted action is unknown.
                self._terminate()
                raise X11KeyboardError('X11 keyboard worker result unavailable; no automatic replay',
                    _receipt(submitted=executing, outcome='unknown_or_partial' if executing else 'not_submitted',
                             owned_keys_released=False if executing else True,
                             **({'method': 'gtk_hex', 'unicode_method': 'gtk_hex',
                                 'application_scope': 'GTK-compatible Ctrl+Shift+U input method only',
                                 'composition_may_be_active': executing}
                                if plan is not None and plan.kind == 'gtk_hex' else {}))) from None
            if not response.get('ok'):
                error_type = X11Unrepresentable if response.get('unrepresentable') else X11KeyboardError
                raise error_type(response.get('error', 'X11 keyboard operation refused'), response.get('receipt'))
            return response['result']

    def prepare_text(self, text, explicit_unicode_method=None):
        if not isinstance(text, str) or len(text) > 16384 or '\0' in text:
            raise X11KeyboardError('Invalid X11 text; no input submitted')
        try:
            text.encode('utf-8')
        except UnicodeError:
            raise X11KeyboardError('X11 text must contain valid Unicode; no input submitted') from None
        if explicit_unicode_method not in (None, 'gtk_hex'):
            raise X11KeyboardError('Unsupported explicit X11 Unicode method; no input submitted')
        return PreparedPlan(**self._request('prepare_text', text=text, unicode_method=explicit_unicode_method))

    def prepare_combo(self, keys):
        return PreparedPlan(**self._request('prepare_combo', keys=keys))

    def send_text(self, plan):
        if not isinstance(plan, PreparedPlan) or plan.kind not in ('text', 'gtk_hex'):
            raise X11KeyboardError('Invalid X11 text plan; no input submitted')
        return self._request('execute_gtk_hex' if plan.kind == 'gtk_hex' else 'execute_text', plan=plan)

    def send_combo(self, plan):
        if not isinstance(plan, PreparedPlan) or plan.kind != 'combo':
            raise X11KeyboardError('Invalid X11 combination plan; no input submitted')
        return self._request('execute_combo', plan=plan)

    def discard(self, plan):
        if not isinstance(plan, PreparedPlan):
            raise X11KeyboardError('Invalid X11 keyboard plan')
        return self._request('discard', plan=plan)

    def _terminate(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        for stream in (self.proc.stdin, self.proc.stdout):
            if stream is not None and not stream.closed:
                stream.close()

    def close(self):
        with self.lock:
            self._terminate()
            self.closed = True


def _worker():
    native = engine = None
    def stopping(signum, frame):
        raise SystemExit
    signal.signal(signal.SIGTERM, stopping)
    try:
        for line in sys.stdin.buffer:
            identity = None
            try:
                if len(line) > 1024 * 1024:
                    raise X11KeyboardError('X11 keyboard request exceeds its limit')
                request = json.loads(line)
                identity = request.get('id')
                if native is None:
                    native = _NativeKeyboard()
                    engine = KeyboardEngine(native)
                action = request.get('action')
                if action == 'prepare_text':
                    value = engine.prepare_text(request['text'], request.get('unicode_method'))
                elif action == 'prepare_combo':
                    value = engine.prepare_combo(request['keys'])
                elif action in ('execute_text', 'execute_combo', 'execute_gtk_hex'):
                    value = engine.execute(request['token'], {'execute_text': 'text',
                        'execute_combo': 'combo', 'execute_gtk_hex': 'gtk_hex'}[action])
                elif action == 'discard':
                    engine.plans.pop(request['token'], None)
                    value = {'discarded': True, 'submitted': False}
                else:
                    raise X11KeyboardError('Unknown X11 keyboard worker action')
                response = {'id': identity, 'ok': True, 'result': value}
            except X11KeyboardError as error:
                response = {'id': identity, 'ok': False, 'error': str(error), 'receipt': error.receipt,
                            'unrepresentable': isinstance(error, X11Unrepresentable)}
            except Exception:
                # Do not return text, keycodes, window IDs or native diagnostics.
                response = {'id': identity, 'ok': False, 'error': 'X11 keyboard preparation failed; no input replay',
                            'receipt': _receipt()}
            sys.stdout.write(json.dumps(response, separators=(',', ':')) + '\n')
            sys.stdout.flush()
    finally:
        if native is not None:
            native.close()


if __name__ == '__main__':
    if sys.argv[1:] != ['--worker']:
        raise SystemExit('This module only runs as a private X11 keyboard worker')
    _worker()
