# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Pure keyboard-policy tests: synthetic XKB maps, no X connection or GUI."""
import ctypes as C
import ctypes.util
import hashlib
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.computer_eis import XkbState, _function, P, I
from dc_compat.x11_keyboard import (KeyboardEngine, _Snapshot, X11KeyboardError,
                                    X11Unrepresentable, X11Keyboard, PreparedPlan)
from dc_compat.computer import _X11, ComputerManager


def keymap_bytes(layout=b'us'):
    lib = C.CDLL(ctypes.util.find_library('xkbcommon'))
    class Names(C.Structure):
        _fields_ = [(name, C.c_char_p) for name in ('rules', 'model', 'layout', 'variant', 'options')]
    _function(lib, 'xkb_context_new', P, I)
    _function(lib, 'xkb_keymap_new_from_names', P, P, P, I)
    _function(lib, 'xkb_keymap_get_as_string', P, P, I)
    _function(lib, 'xkb_keymap_unref', None, P)
    _function(lib, 'xkb_context_unref', None, P)
    context = lib.xkb_context_new(0)
    names = Names(None, None, layout, None, None)
    keymap = lib.xkb_keymap_new_from_names(context, C.byref(names), 0)
    pointer = lib.xkb_keymap_get_as_string(keymap, 1)
    try:
        return C.string_at(pointer)
    finally:
        libc = C.CDLL(None)
        _function(libc, 'free', None, P)
        libc.free(pointer)
        lib.xkb_keymap_unref(keymap)
        lib.xkb_context_unref(context)


class FakeNative:
    def __init__(self, raw=None, masks=(0, 0, 0, 0), pressed=()):
        self.raw = raw or keymap_bytes()
        self.masks, self.pressed = masks, set(pressed)
        self.focus, self.events, self.snapshots, self.on_key = 123, [], 0, None

    def symbol(self, value):
        if len(value) == 1:
            lib = C.CDLL(ctypes.util.find_library('xkbcommon'))
            _function(lib, 'xkb_utf32_to_keysym', C.c_uint32, C.c_uint32)
            return int(lib.xkb_utf32_to_keysym(ord(value)))
        return {'Shift_L': 0xffe1, 'Shift_R': 0xffe2, 'Control_L': 0xffe3,
                'Control_R': 0xffe4, 'ISO_Level3_Shift': 0xfe03,
                'Return': 0xff0d, 'Tab': 0xff09}[value]

    def snapshot(self):
        self.snapshots += 1
        state = XkbState(self.raw)
        state.modifiers(*self.masks)
        return _Snapshot(state, (hashlib.sha256(self.raw).hexdigest(), self.masks,
                                self.focus, tuple(sorted(self.pressed))), frozenset(self.pressed))

    def key(self, code, down):
        self.events.append((code, down))
        if down:
            self.pressed.add(code)
        else:
            self.pressed.discard(code)
        if self.on_key:
            self.on_key(code, down)


class KeyboardPolicyTests(unittest.TestCase):
    def test_whole_string_unmapped_unicode_refuses_before_ascii_prefix(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        with self.assertRaises(X11Unrepresentable) as captured:
            engine.prepare_text('ASCII prefix 测试')
        self.assertEqual(native.events, [])
        self.assertEqual(engine.plans, {})
        self.assertFalse(captured.exception.receipt['submitted'])

    def test_ascii_uses_existing_codes_and_releases_only_its_own_keys(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        raw = native.raw
        plan = engine.prepare_text('Hepta 123')
        self.assertEqual(native.events, [])
        result = engine.execute(plan['token'], 'text')
        self.assertTrue(result['submitted'])
        self.assertEqual(result['characters'], 9)
        self.assertEqual(native.pressed, set())
        self.assertEqual(native.raw, raw)
        self.assertFalse(result['global_keymap_modified'])

    def test_caps_lock_is_preserved_without_toggle(self):
        native = FakeNative(masks=(0, 0, 2, 0)); engine = KeyboardEngine(native)
        plan = engine.prepare_text('aA')
        engine.execute(plan['token'], 'text')
        self.assertEqual(native.masks, (0, 0, 2, 0))
        self.assertNotIn(66, [code for code, _ in native.events])
        self.assertIn((50, True), native.events)  # Shift makes lowercase with Caps on.
        self.assertEqual(native.pressed, set())

    def test_preheld_shift_is_never_released(self):
        native = FakeNative(masks=(1, 0, 0, 0), pressed=(50,)); engine = KeyboardEngine(native)
        plan = engine.prepare_text('A')
        engine.execute(plan['token'], 'text')
        self.assertEqual(native.events, [(38, True), (38, False)])
        self.assertEqual(native.pressed, {50})
        with self.assertRaises(X11Unrepresentable):
            engine.prepare_text('lowercase')

    def test_actual_nonfirst_layout_is_used_without_group_switch(self):
        native = FakeNative(keymap_bytes(b'us,ru'), masks=(0, 0, 0, 1)); engine = KeyboardEngine(native)
        plan = engine.prepare_text('ф')
        engine.execute(plan['token'], 'text')
        self.assertEqual(native.events, [(38, True), (38, False)])
        self.assertEqual(native.masks, (0, 0, 0, 1))
        with self.assertRaises(X11Unrepresentable):
            engine.prepare_text('a')

    def test_equivalent_unicode_keysym_already_present_in_map_is_usable(self):
        raw = keymap_bytes(b'us,ru').replace(b'Cyrillic_ef', b'U0444')
        native = FakeNative(raw, masks=(0, 0, 0, 1)); engine = KeyboardEngine(native)
        plan = engine.prepare_text('ф')
        engine.execute(plan['token'], 'text')
        self.assertEqual(native.events, [(38, True), (38, False)])
        self.assertEqual(native.raw, raw)

    def test_combo_preserves_preheld_control_and_does_not_add_shift(self):
        native = FakeNative(masks=(4, 0, 0, 0), pressed=(37,)); engine = KeyboardEngine(native)
        plan = engine.prepare_combo(['Control_L', 'v'])
        engine.execute(plan['token'], 'combo')
        self.assertEqual(native.events, [(55, True), (55, False)])
        self.assertEqual(native.pressed, {37})

    def test_paste_combo_rejects_unrelated_shift_before_any_key(self):
        native = FakeNative(masks=(1, 0, 0, 0), pressed=(50,)); engine = KeyboardEngine(native)
        with self.assertRaises(X11KeyboardError):
            engine.prepare_combo(['Control_L', 'v'])
        self.assertEqual(native.events, [])

    def test_latched_modifier_is_not_cleared_or_consumed(self):
        native = FakeNative(masks=(0, 1, 0, 0)); engine = KeyboardEngine(native)
        with self.assertRaises(X11Unrepresentable):
            engine.prepare_text('a')
        with self.assertRaises(X11KeyboardError):
            engine.prepare_combo(['Control_L', 'v'])
        self.assertEqual(native.events, [])

    def test_consumed_plan_cannot_replay(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        plan = engine.prepare_text('a')
        engine.execute(plan['token'], 'text')
        original = list(native.events)
        with self.assertRaises(X11KeyboardError):
            engine.execute(plan['token'], 'text')
        self.assertEqual(native.events, original)

    def test_focus_change_before_send_is_zero_input_and_consumes_plan(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        plan = engine.prepare_text('a'); native.focus = 999
        with self.assertRaises(X11KeyboardError) as captured:
            engine.execute(plan['token'], 'text')
        self.assertFalse(captured.exception.receipt['submitted'])
        self.assertEqual(native.events, [])
        self.assertNotIn(plan['token'], engine.plans)

    def test_state_change_after_prefix_is_partial_and_never_replayed(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        plan = engine.prepare_text('ab')
        native.on_key = lambda code, down: setattr(native, 'focus', 999) if not down else None
        with self.assertRaises(X11KeyboardError) as captured:
            engine.execute(plan['token'], 'text')
        self.assertTrue(captured.exception.receipt['submitted'])
        self.assertEqual(captured.exception.receipt['input_outcome'], 'unknown_or_partial')
        self.assertNotIn('no input submitted', str(captured.exception))
        self.assertEqual(native.events, [(38, True), (38, False)])
        self.assertEqual(native.pressed, set())

    def test_press_failure_releases_attempted_keys_without_replay(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        plan = engine.prepare_text('A')
        def fail(code, down):
            if code == 38 and down:
                raise RuntimeError('private injected failure')
        native.on_key = fail
        with self.assertRaises(X11KeyboardError) as captured:
            engine.execute(plan['token'], 'text')
        self.assertTrue(captured.exception.receipt['submitted'])
        self.assertEqual(native.events, [(50, True), (38, True), (38, False), (50, False)])
        self.assertEqual(native.pressed, set())


class GtkHexPolicyTests(unittest.TestCase):
    def test_explicit_gtk_hex_plans_chinese_emoji_with_existing_ascii_keys(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        original = native.raw
        text = '测试 😀 测试'
        plan = engine.prepare_text(text, explicit_unicode_method='gtk_hex')
        self.assertEqual(plan['kind'], 'gtk_hex')
        self.assertEqual(native.events, [])
        entries = engine.plans[plan['token']]['entries']
        self.assertEqual(entries[0], (30, (37, 50)))  # Existing US Ctrl+Shift+U.
        self.assertEqual(sum(code == 30 and modifiers == (37, 50) for code, modifiers in entries), len(text))
        self.assertEqual(sum(code == 36 for code, _ in entries), len(text))
        self.assertEqual(len(entries), sum(len(format(ord(character), 'x')) + 2 for character in text))
        result = engine.execute(plan['token'], 'gtk_hex')
        self.assertEqual(result['method'], 'gtk_hex')
        self.assertEqual(result['characters'], len(text))
        self.assertFalse(result['clipboard_modified'])
        self.assertFalse(result['global_keymap_modified'])
        self.assertFalse(result['target_input_verified'])
        self.assertFalse(result['composition_may_be_active'])
        self.assertEqual(native.raw, original)
        self.assertEqual(native.pressed, set())

    def test_default_unselected_route_does_not_infer_a_gtk_application(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        with self.assertRaises(X11Unrepresentable):
            engine.prepare_text('ASCII 测试 😀')
        self.assertEqual(native.events, [])

    def test_existing_num_lock_is_preserved(self):
        native = FakeNative(masks=(0, 0, 16, 0)); engine = KeyboardEngine(native)
        plan = engine.prepare_text('测😀', explicit_unicode_method='gtk_hex')
        engine.execute(plan['token'], 'gtk_hex')
        self.assertEqual(native.masks, (0, 0, 16, 0))
        self.assertFalse(any(code in (66, 77) for code, _ in native.events))

    def test_caps_state_without_uppercase_u_refuses_without_a_toggle(self):
        native = FakeNative(masks=(0, 0, 2, 0)); engine = KeyboardEngine(native)
        with self.assertRaisesRegex(X11KeyboardError, 'uppercase-U') as captured:
            engine.prepare_text('测', explicit_unicode_method='gtk_hex')
        self.assertNotIsInstance(captured.exception, X11Unrepresentable)
        self.assertFalse(captured.exception.receipt['submitted'])
        self.assertEqual(native.events, [])
        self.assertEqual(native.masks, (0, 0, 2, 0))

    def test_preheld_control_is_not_released_or_reused_for_gtk_protocol(self):
        native = FakeNative(masks=(4, 0, 0, 0), pressed=(37,)); engine = KeyboardEngine(native)
        with self.assertRaises(X11KeyboardError):
            engine.prepare_text('测', explicit_unicode_method='gtk_hex')
        self.assertEqual(native.events, [])
        self.assertEqual(native.pressed, {37})

    def test_layout_without_gtk_start_shortcut_refuses_without_group_change(self):
        native = FakeNative(keymap_bytes(b'us,ru'), masks=(0, 0, 0, 1)); engine = KeyboardEngine(native)
        with self.assertRaises(X11KeyboardError):
            engine.prepare_text('测', explicit_unicode_method='gtk_hex')
        self.assertEqual(native.events, [])
        self.assertEqual(native.masks, (0, 0, 0, 1))

    def test_unknown_explicit_method_does_not_open_or_query_the_display(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        with self.assertRaises(X11KeyboardError):
            engine.prepare_text('测', explicit_unicode_method='arbitrary_app_magic')
        self.assertEqual(native.snapshots, 0)
        self.assertEqual(native.events, [])

    def test_partial_gtk_sequence_reports_pending_composition_and_never_escapes_new_focus(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        plan = engine.prepare_text('测', explicit_unicode_method='gtk_hex')
        def changed(code, down):
            if code == 30 and not down:
                native.focus = 999
        native.on_key = changed
        with self.assertRaises(X11KeyboardError) as captured:
            engine.execute(plan['token'], 'gtk_hex')
        result = captured.exception.receipt
        self.assertTrue(result['submitted'])
        self.assertEqual(result['input_outcome'], 'unknown_or_partial')
        self.assertTrue(result['composition_may_be_active'])
        self.assertTrue(result['owned_keys_released'])
        self.assertFalse(any(code == 9 for code, _ in native.events))
        self.assertEqual(native.events, [(37, True), (50, True), (30, True),
                                         (30, False), (50, False), (37, False)])
        self.assertEqual(native.pressed, set())
        before = list(native.events)
        with self.assertRaises(X11KeyboardError):
            engine.execute(plan['token'], 'gtk_hex')
        self.assertEqual(native.events, before)

    def test_changed_focus_before_gtk_send_is_zero_input(self):
        native = FakeNative(); engine = KeyboardEngine(native)
        plan = engine.prepare_text('测', explicit_unicode_method='gtk_hex'); native.focus = 999
        with self.assertRaises(X11KeyboardError) as captured:
            engine.execute(plan['token'], 'gtk_hex')
        self.assertFalse(captured.exception.receipt['submitted'])
        self.assertFalse(captured.exception.receipt['composition_may_be_active'])
        self.assertEqual(native.events, [])

    def test_wrapper_selects_explicit_worker_plan_without_any_gui_in_this_test(self):
        keyboard = X11Keyboard({'DISPLAY': ':pure-fixture'})
        calls = []
        def request(action, **options):
            calls.append((action, options))
            if action == 'prepare_text':
                return {'token': 'private-token', 'kind': 'gtk_hex', 'characters': 1}
            return {'method': 'gtk_hex', 'submitted': True, 'clipboard_modified': False}
        keyboard._request = request
        plan = keyboard.prepare_text('测', explicit_unicode_method='gtk_hex')
        self.assertEqual(plan, PreparedPlan('private-token', 'gtk_hex', 1))
        self.assertEqual(keyboard.send_text(plan)['method'], 'gtk_hex')
        self.assertEqual(calls[0][0], 'prepare_text')
        self.assertEqual(calls[0][1]['unicode_method'], 'gtk_hex')
        self.assertEqual(calls[1][0], 'execute_gtk_hex')
        self.assertIsNone(keyboard.proc)


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    def backend(self):
        backend = _X11({'display': ':pure-fixture'})
        backend._check = lambda: None
        return backend

    def test_empty_three_modes_do_not_construct_any_worker(self):
        backend = self.backend()
        def unexpected():
            raise AssertionError('No worker must be constructed for empty text')
        backend._keyboard_manager = backend._selection_manager = unexpected
        for mode in ('auto', 'keyboard', 'clipboard'):
            self.assertEqual(backend.type_text('', mode), {'method': 'none', 'submitted': False,
                'characters': 0, 'clipboard_modified': False, 'replayed': False})

    def test_auto_whole_string_fallback_prepares_paste_once(self):
        backend = self.backend(); events = []
        class Keyboard:
            def prepare_text(self, text):
                events.append(('whole_preflight', text)); raise X11Unrepresentable('unmapped')
            def prepare_combo(self, keys):
                events.append(('paste_prepare', tuple(keys))); return 'immutable-plan'
            def send_combo(self, plan):
                events.append(('paste_send', plan)); return {'submitted': True}
        class Selection:
            def run(self, text, callback, keys):
                callback(keys, preflight=True)
                events.append(('selection_modified', text))
                callback(keys, preflight=False)
                return {'paste_attempted': True, 'original_offer_restored': True}
        backend.keyboard, backend.selection = Keyboard(), Selection()
        result = backend.type_text('ASCII prefix 测试', 'auto')
        self.assertEqual(events, [('whole_preflight', 'ASCII prefix 测试'),
            ('paste_prepare', ('Control_L', 'v')), ('selection_modified', 'ASCII prefix 测试'),
            ('paste_send', 'immutable-plan')])
        self.assertTrue(result['submitted'])
        self.assertEqual(result['method'], 'clipboard')

    def test_keyboard_mode_unmapped_never_constructs_selection(self):
        backend = self.backend()
        class Keyboard:
            def prepare_text(self, text):
                raise X11Unrepresentable('unmapped')
        backend.keyboard = Keyboard()
        with self.assertRaises(X11Unrepresentable):
            backend.type_text('ASCII prefix 试', 'keyboard')
        self.assertIsNone(backend.selection)

    def test_submit_failure_cannot_select_clipboard_fallback(self):
        backend = self.backend(); events = []
        class Keyboard:
            def prepare_text(self, text): return 'plan'
            def send_text(self, plan):
                events.append('send'); raise X11KeyboardError('partial', {'submitted': True})
        backend.keyboard = Keyboard()
        with self.assertRaises(X11KeyboardError):
            backend.type_text('ab', 'auto')
        self.assertEqual(events, ['send'])
        self.assertIsNone(backend.selection)

    def test_paste_callback_cannot_be_replayed(self):
        backend = self.backend(); sends = []
        class Keyboard:
            def prepare_combo(self, keys): return 'plan'
            def send_combo(self, plan): sends.append(plan)
        class Selection:
            def run(self, text, callback, keys):
                callback(keys, preflight=True); callback(keys, preflight=False)
                callback(keys, preflight=False)
        backend.keyboard, backend.selection = Keyboard(), Selection()
        with self.assertRaisesRegex(Exception, 'already attempted'):
            backend.type_text('试', 'clipboard')
        self.assertEqual(sends, ['plan'])

    def test_snapshot_refusals_discard_unused_plans_and_do_not_exhaust_capacity(self):
        backend = self.backend(); native = FakeNative(); engine = KeyboardEngine(native)
        class Keyboard:
            def prepare_combo(self, keys): return engine.prepare_combo(keys)
            def discard(self, plan): engine.plans.pop(plan['token'], None)
            def prepare_text(self, text): return engine.prepare_text(text)
            def send_text(self, plan): return engine.execute(plan['token'], 'text')
        class Selection:
            def run(self, text, callback, keys):
                callback(keys, preflight=True)
                raise RuntimeError('Snapshot refused before modification')
        backend.keyboard, backend.selection = Keyboard(), Selection()
        for _ in range(12):
            with self.assertRaisesRegex(RuntimeError, 'Snapshot refused'):
                backend.type_text('试', 'clipboard')
            self.assertEqual(engine.plans, {})
        self.assertEqual(native.events, [])
        self.assertTrue(backend.type_text('a', 'keyboard')['submitted'])

    def test_clipboard_attempt_with_explicit_zero_input_receipt_is_not_submitted(self):
        backend = self.backend()
        class Keyboard:
            def prepare_combo(self, keys): return 'plan'
        class Selection:
            def run(self, text, callback, keys):
                callback(keys, preflight=True)
                return {'paste_attempted': True, 'paste_input_submitted': False}
        backend.keyboard, backend.selection = Keyboard(), Selection()
        self.assertFalse(backend.type_text('试', 'clipboard')['submitted'])

    def test_successful_session_close_allows_fresh_keyboard_and_selection(self):
        backend = self.backend(); events = []
        backend.config['clipboard_state_dir'] = '/private-fixture-not-created'
        class Keyboard:
            def close(self): events.append('keyboard_closed')
            def prepare_text(self, text): return 'fresh-text-plan'
            def send_text(self, plan):
                events.append(('send_text', plan)); return {'submitted': True}
        class Selection:
            def close(self):
                events.append('selection_closed'); return {'closed': True}
        first_keyboard, first_selection = Keyboard(), Selection()
        backend.keyboard, backend.selection = first_keyboard, first_selection
        backend.close()
        self.assertIsNone(backend.keyboard)
        self.assertIsNone(backend.selection)
        backend.capabilities = lambda: {'backend': 'x11', 'authorized': True}
        self.assertTrue(backend.authorize()['authorized'])
        fresh_keyboard, fresh_selection = Keyboard(), Selection()
        with patch('dc_compat.x11_keyboard.X11Keyboard', return_value=fresh_keyboard), \
                patch('dc_compat.x11_selection.X11Selection', return_value=fresh_selection):
            self.assertTrue(backend.type_text('a', 'keyboard')['submitted'])
            self.assertIs(backend.keyboard, fresh_keyboard)
            self.assertIs(backend._selection_manager(), fresh_selection)
        self.assertEqual(events, ['selection_closed', 'keyboard_closed', ('send_text', 'fresh-text-plan')])

    def test_retained_original_offer_refuses_close_without_clearing_providers(self):
        backend = self.backend(); events = []
        class Keyboard:
            def close(self): events.append('keyboard_closed')
        class Selection:
            def close(self):
                return {'closed': False, 'retained_original_offer': True, 'helper_alive': True}
        keyboard, selection = Keyboard(), Selection()
        backend.keyboard, backend.selection = keyboard, selection
        with self.assertRaisesRegex(Exception, 'original data offer'):
            backend.close()
        self.assertIs(backend.keyboard, keyboard)
        self.assertIs(backend.selection, selection)
        self.assertEqual(events, [])

    async def test_manager_preserves_partial_keyboard_receipt(self):
        manager = ComputerManager({'backend': 'x11', 'display': ':pure-fixture'})
        manager.backend._check = lambda: None
        class Keyboard:
            def prepare_text(self, text): return 'plan'
            def send_text(self, plan):
                raise X11KeyboardError('Partial input; no replay', {'method': 'keyboard',
                    'submitted': True, 'input_outcome': 'unknown_or_partial', 'replayed': False})
            def close(self): pass
        manager.backend.keyboard = Keyboard()
        result = await manager.invoke('computer_type', {'text': 'ab'})
        self.assertTrue(result['isError'])
        self.assertTrue(result['structuredContent']['result']['submitted'])
        self.assertEqual(result['structuredContent']['result']['input_outcome'], 'unknown_or_partial')
        await manager.close()


if __name__ == '__main__':
    unittest.main()
