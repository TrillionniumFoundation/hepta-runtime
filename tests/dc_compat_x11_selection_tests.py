# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent selection fixture; real GUI tests require the pinned X230 R7 desktop."""
from __future__ import annotations

import json
import hashlib
import os
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))

# This separate process is the ORIGINAL selection owner and independent reader.
# It never calls the provider's snapshot/restore implementation.
OWNER_SOURCE = r'''
import array,base64,ctypes,ctypes.util,hashlib,json,os,pathlib,signal,struct,sys,time
import gi
gi.require_version('Gtk','3.0');gi.require_version('Gdk','3.0');gi.require_version('GdkX11','3.0')
from gi.repository import Gtk,Gdk,GdkX11,GLib
folder=pathlib.Path(sys.argv[1]);nonce=sys.argv[2];reader_only='--reader-only' in sys.argv[3:]
ok,_=Gtk.init_check();display=Gdk.Display.get_default()
if not ok or display is None or 'X11' not in type(display).__name__:raise RuntimeError('Dedicated X11 required')
lib=ctypes.CDLL(ctypes.util.find_library('X11'))
lib.XOpenDisplay.argtypes=[ctypes.c_char_p];lib.XOpenDisplay.restype=ctypes.c_void_p
lib.XInternAtom.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int];lib.XInternAtom.restype=ctypes.c_ulong
lib.XGetSelectionOwner.argtypes=[ctypes.c_void_p,ctypes.c_ulong];lib.XGetSelectionOwner.restype=ctypes.c_ulong
lib.XQueryKeymap.argtypes=[ctypes.c_void_p,ctypes.c_void_p];lib.XQueryKeymap.restype=ctypes.c_int
lib.XCloseDisplay.argtypes=[ctypes.c_void_p]
xdisplay=lib.XOpenDisplay(os.environ['DISPLAY'].encode())
if not xdisplay:raise RuntimeError('Own X11 connection failed')
clipatom=lib.XInternAtom(xdisplay,b'CLIPBOARD',False)
clipboard=Gtk.Clipboard.get_for_display(display,Gdk.SELECTION_CLIPBOARD)
widgets=[];offers={};counts={};serial=0;owner_epoch=0;inspection=None;profile=None;manifest=[];failure=None;text_read=None
PROTOCOL={'TARGETS','TIMESTAMP','MULTIPLE','SAVE_TARGETS'}
def digest(data):return hashlib.sha256(data).hexdigest()
def payloads(kind):
 text=('Original X230 clipboard '+nonce+' 原始').encode()
 png=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=')
 result={'UTF8_STRING':('UTF8_STRING',8,text),'text/plain;charset=utf-8':('UTF8_STRING',8,text),
  'text/html':('text/html',8,b'<b>'+text+b'</b>'),'image/png':('image/png',8,png),
  'application/x-hepta-binary':('application/x-hepta-binary',8,bytes(range(256))*8192),
  'application/x-hepta-u16':('INTEGER',16,array.array('H',[0,1,32768,65535]).tobytes()),
  'application/x-hepta-u32':('INTEGER',32,array.array('L',[0,1,2147483648,4294967295]).tobytes())}
 if kind=='external':result={'UTF8_STRING':('UTF8_STRING',8,('External '+nonce).encode()),'application/x-hepta-external':('application/x-hepta-external',8,b'new-owner\0'+nonce.encode())}
 if kind=='resource':result['PIXMAP']=('PIXMAP',32,array.array('L',[0]).tobytes())
 if kind=='sideeffect':result['DELETE']=('NULL',8,b'')
 if kind=='unreadable':result['application/x-hepta-unreadable']=('application/x-hepta-unreadable',8,b'cannot-read')
 return result
def datum(name,typ,fmt,raw):
 canonical=raw
 if fmt==32:
  values=array.array('L');values.frombytes(raw)
  canonical=b''.join(struct.pack('>I',value&0xffffffff) for value in values)
 return {'target':name,'type':typ,'format':fmt,'bytes':len(raw),'sha256':digest(raw),
  'canonical_units_bytes':len(canonical),'canonical_units_sha256':digest(canonical)}
def metadata(values):
 return [datum(name,typ,fmt,raw) for name,(typ,fmt,raw) in sorted(values.items())]
def actual_owner():return int(lib.XGetSelectionOwner(xdisplay,clipatom))
def keys_down():
 data=(ctypes.c_ubyte*32)();lib.XQueryKeymap(xdisplay,data)
 return [i for i in range(256) if data[i//8]&(1<<(i%8))]
def own(kind):
 global profile,manifest
 value=payloads(kind);widget=Gtk.Invisible.new_for_screen(display.get_default_screen());widget.realize();widgets.append(widget)
 names=list(value);entries=[Gtk.TargetEntry.new(name,0,i) for i,name in enumerate(names)]
 Gtk.selection_add_targets(widget,Gdk.SELECTION_CLIPBOARD,entries)
 fired=[False]
 def get(widget,data,info,stamp):
  name=names[info];counts[name]=counts.get(name,0)+1
  if name!='application/x-hepta-unreadable':
   typ,fmt,raw=value[name];data.set(Gdk.Atom.intern(typ,False),fmt,raw)
  if kind=='swap_on_read' and not fired[0]:
   fired[0]=True;GLib.idle_add(lambda:(own('external'),False)[1],priority=GLib.PRIORITY_HIGH)
 widget.connect('selection-get',get)
 if not Gtk.selection_owner_set_for_display(display,widget,Gdk.SELECTION_CLIPBOARD,Gdk.CURRENT_TIME):raise RuntimeError('Own fixture selection claim failed')
 profile=kind;manifest=metadata(value);offers[kind]=value
def inspect(kind,request_serial):
 global inspection
 before=actual_owner();expected=payloads(kind);results={};inspection={'serial':request_serial,'pending':True}
 def targets_received(cb,atoms,*unused):
  names=sorted(a.name() for a in (atoms or []))
  pending=set(expected)
  def finish():
   global inspection
   inspection={'serial':request_serial,'pending':False,'owner_before':before,'owner_after':actual_owner(),
    'targets':names,'data_targets':sorted(set(names)-PROTOCOL),'formats':[results[k] for k in sorted(results)]}
  if not pending:finish();return
  def received(cb,data,target):
   length=data.get_length()
   if length<0:results[target]={'target':target,'error':'unavailable'}
   else:
    raw=bytes(data.get_data());results[target]=datum(target,data.get_data_type().name(),data.get_format(),raw)
   pending.discard(target)
   # The prior GTK clipboard callback must return before reusing its requestor.
   GLib.idle_add(read_next)
  sequence=iter(expected)
  def read_next():
   try:name=next(sequence)
   except StopIteration:finish();return False
   clipboard.request_contents(Gdk.Atom.intern(name,False),received,name)
   return False
  # Do not start a nested conversion inside the TARGETS completion callback.
  GLib.idle_add(read_next)
 clipboard.request_targets(targets_received,None)
def owner_changed(cb,event):
 global owner_epoch
 owner_epoch+=1
clipboard.connect('owner-change',owner_changed)
def tick():
 global serial,failure,text_read
 try:
  command=folder/'clipboard-command.json'
  if command.exists():
   request=json.loads(command.read_text())
   if request.get('nonce')==nonce and request.get('serial',0)>serial:
    serial=request['serial'];action=request['action'];kind=request.get('profile','normal')
    if action=='offer':
     if reader_only:raise RuntimeError('Independent foreign reader never owns a selection')
     own(kind)
    elif action=='inspect':inspect(kind,serial)
    elif action=='read_text':
     requested_serial=serial
     def received_text(cb,value,unused):
      global text_read
      raw=None if value is None else value.encode()
      text_read={'serial':requested_serial,'bytes':None if raw is None else len(raw),'sha256':None if raw is None else digest(raw)}
     clipboard.request_text(received_text,None)
    else:raise RuntimeError('Unknown fixture command')
  value={'nonce':nonce,'pid':os.getpid(),'updated_monotonic':time.monotonic(),'serial':serial,
    'profile':profile,'owner_xid':actual_owner(),'owner_epoch':owner_epoch,'manifest':manifest,
    'own_window_ids':[int(GdkX11.X11Window.get_xid(w.get_window())) for w in widgets],
    'request_counts':counts,'inspection':inspection,'text_read':text_read,'server_keys_down':keys_down(),'failure':failure}
  tmp=folder/'clipboard-state.tmp'
  fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as out:json.dump(value,out);out.flush();os.fsync(out.fileno())
  os.replace(tmp,folder/'clipboard-state.json')
 except Exception as error:failure=type(error).__name__
 return True
GLib.timeout_add(30,tick)
GLib.unix_signal_add(GLib.PRIORITY_DEFAULT,signal.SIGTERM,lambda:(Gtk.main_quit(),False)[1])
try:Gtk.main()
finally:lib.XCloseDisplay(xdisplay)
'''


def wait_state(folder, nonce, predicate=lambda row: True, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            path = pathlib.Path(folder) / 'clipboard-state.json'
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise AssertionError('Unsafe own clipboard fixture state')
            row = json.loads(path.read_bytes())
            if row['nonce'] == nonce and 0 <= time.monotonic() - row['updated_monotonic'] < .5 and predicate(row):
                return row
        except FileNotFoundError:
            pass
        time.sleep(.03)
    raise AssertionError('Independent original owner/consumer state was not reached')


class PureX11IntegrationTests(unittest.IsolatedAsyncioTestCase):
    def backend(self):
        from dc_compat.computer import _X11
        backend = _X11({'display': ':not-accessed'})
        backend._check = lambda: None
        return backend

    async def test_empty_all_modes_does_not_construct_or_call_selection_or_keyboard(self):
        from dc_compat.computer import ComputerManager
        manager = ComputerManager({'backend': 'x11', 'display': ':not-accessed'})
        manager.backend._check = lambda: None
        manager.backend.prepare_input = lambda mask: None
        manager.backend._run = lambda *a, **k: self.fail('Empty text submitted an X command')
        manager.backend._keyboard_manager = lambda: self.fail('Empty text constructed a keyboard worker')
        manager.backend._selection_manager = lambda: self.fail('Empty text constructed a selection worker')
        for mode in ('auto', 'keyboard', 'clipboard'):
            result = await manager.invoke('computer_type', {'text': '', 'mode': mode})
            self.assertFalse(result.get('isError'))
            self.assertFalse(result['structuredContent']['result']['submitted'])
        await manager.close()

    def test_independent_fixture_has_no_display_action_until_its_explicit_entrypoint(self):
        # Compile only. Gtk.init_check and XOpenDisplay must never run on main.
        compile(OWNER_SOURCE, '<independent-x230-selection-owner>', 'exec')

    def test_auto_routes_whole_unrepresentable_text_without_sending_ascii_prefix(self):
        from dc_compat.x11_keyboard import X11Unrepresentable
        backend = self.backend()
        text, preparations, clip = 'ASCII prefix 测试🙂 suffix', [], []
        def prepare(value):
            preparations.append(value)
            raise X11Unrepresentable('Whole text cannot use the existing keymap')
        backend._keyboard_manager = lambda: SimpleNamespace(prepare_text=prepare,
            send_text=lambda plan: self.fail('Unrepresentable text sent a prefix'))
        backend._type_via_clipboard = lambda value, keys: clip.append((value, keys)) or {'method': 'clipboard'}
        self.assertEqual(backend.type_text(text)['method'], 'clipboard')
        self.assertEqual(preparations, [text])
        self.assertEqual(clip, [(text, ('CTRL', 'V'))])
        clip.clear()
        with self.assertRaises(X11Unrepresentable):backend.type_text(text, 'keyboard')
        self.assertEqual(clip, [])

    def test_partial_keyboard_failure_never_attempts_clipboard_fallback(self):
        from dc_compat.x11_keyboard import X11KeyboardError, PreparedPlan
        backend = self.backend()
        def fail(plan):
            raise X11KeyboardError('Prefix may have been submitted', {'submitted': True,
                'characters': 1, 'input_outcome': 'partial', 'clipboard_modified': False, 'replayed': False})
        backend._keyboard_manager = lambda: SimpleNamespace(
            prepare_text=lambda text: PreparedPlan('one-plan', 'text', len(text)), send_text=fail)
        backend._type_via_clipboard = lambda *args: self.fail('Partial input fell back/replayed')
        with self.assertRaises(X11KeyboardError) as found:backend.type_text('ABC')
        self.assertTrue(found.exception.receipt['submitted'])
        self.assertEqual(found.exception.receipt['characters'], 1)

    def test_repeated_snapshot_refusals_discard_each_unconsumed_paste_plan(self):
        from dc_compat.clipboard_transaction import ClipboardTransactionError
        from dc_compat.x11_keyboard import PreparedPlan
        backend = self.backend()
        prepared, discarded = [], []
        def prepare(keys):
            plan = PreparedPlan('plan-' + str(len(prepared)), 'combo')
            prepared.append(plan)
            return plan
        backend._keyboard_manager = lambda: SimpleNamespace(prepare_combo=prepare,
            send_combo=lambda plan: self.fail('Refused clipboard sent a paste'), discard=discarded.append)
        def refuse(text, callback, keys):
            callback(keys, preflight=True)
            raise ClipboardTransactionError('snapshot_budget_exceeded', {'paste_attempted': False,
                'clipboard_publication_attempted': False})
        backend._selection_manager = lambda: SimpleNamespace(run=refuse)
        for _ in range(12):
            with self.assertRaises(ClipboardTransactionError):backend.type_text('中文🙂', 'clipboard')
        self.assertEqual(discarded, prepared)
        self.assertEqual(len(discarded), 12)

    async def test_public_error_preserves_partial_keyboard_receipt(self):
        from dc_compat.computer import ComputerManager
        from dc_compat.x11_keyboard import X11KeyboardError
        manager = ComputerManager({'backend': 'x11', 'display': ':not-accessed'})
        manager.backend.prepare_input = lambda mask: None
        receipt = {'submitted': True, 'characters': 1, 'input_outcome': 'partial',
                   'clipboard_modified': False, 'replayed': False}
        def fail(*args):raise X11KeyboardError('Partial text; no replay', receipt)
        manager.backend.type_text = fail
        result = await manager.invoke('computer_type', {'text': 'ABC'})
        self.assertTrue(result['isError'])
        self.assertEqual(result['structuredContent']['result'], receipt)
        await manager.close()


class PureSelectionBoundaryTests(unittest.TestCase):
    def wrapper(self, rpc):
        from dc_compat.x11_selection import X11Selection
        helper = X11Selection.__new__(X11Selection)
        helper.lock = threading.RLock()
        helper.last_transaction_id = None
        helper.proc = None
        helper._ensure = lambda: None
        helper._rpc = rpc
        helper._remember = lambda row: None
        return helper

    def test_queued_foreign_owner_event_counts_even_after_current_owner_returns_to_self(self):
        from dc_compat.x11_selection import _Helper
        helper = _Helper.__new__(_Helper)
        helper.epoch = helper.foreign = 0
        helper.xid = 88
        helper.serving = {'kind': 'original'}
        helper._owner = lambda: 88
        window = lambda xid: SimpleNamespace(get_xid=lambda: xid)
        helper._owner_changed(None, SimpleNamespace(owner=window(99)))
        self.assertEqual((helper.epoch, helper.foreign), (1, 1))
        self.assertEqual(helper.serving, {'kind': 'original'})
        helper._owner_changed(None, SimpleNamespace(owner=None))
        self.assertEqual((helper.epoch, helper.foreign), (2, 2))
        helper._owner_changed(None, SimpleNamespace(owner=window(88)))
        self.assertEqual((helper.epoch, helper.foreign), (3, 2))
        helper._owner = lambda: 99
        helper._owner_changed(None, SimpleNamespace(owner=window(99)))
        self.assertEqual((helper.epoch, helper.foreign), (4, 3))
        self.assertIsNone(helper.serving)

    def test_begin_channel_loss_preserves_original_transaction_identity_before_ipc(self):
        from dc_compat.clipboard_transaction import ClipboardTransactionError
        stored, ops, callbacks = {}, [], []
        def rpc(op, **kw):
            ops.append(op)
            self.assertIn(kw['transaction_id'], stored)
            raise TimeoutError('Begin reply unavailable')
        helper = self.wrapper(rpc)
        helper._remember = lambda row: stored.__setitem__(row['transaction_id'], dict(row))
        helper.receipt = lambda identity: dict(stored[identity])
        with self.assertRaises(ClipboardTransactionError) as found:
            helper.run('One whole input 中文🙂', lambda keys, preflight=False: callbacks.append(preflight))
        self.assertEqual(ops, ['begin'])
        self.assertEqual(callbacks, [True])
        self.assertEqual(found.exception.receipt['transaction_id'], helper.last_transaction_id)
        self.assertFalse(found.exception.receipt['automatic_retry'])
        self.assertTrue(found.exception.receipt['private_channel_outcome_unknown'])

    def test_paste_preflight_failure_never_starts_helper_or_publishes(self):
        from dc_compat.clipboard_transaction import ClipboardTransactionError
        ops = []
        helper = self.wrapper(lambda op, **kw: ops.append(op))
        helper._ensure = lambda: self.fail('Preflight refusal started a GUI helper')
        helper.receipt = lambda tx: (_ for _ in ()).throw(FileNotFoundError())
        def refuse(keys, preflight=False):
            self.assertTrue(preflight)
            raise ValueError('Unsupported paste combination')
        with self.assertRaises(ClipboardTransactionError) as found:
            helper.run('No ASCII prefix 中文🙂', refuse)
        self.assertFalse(found.exception.receipt['paste_attempted'])
        self.assertFalse(found.exception.receipt['clipboard_publication_attempted'])
        self.assertEqual(ops, [])

    def test_snapshot_refusal_has_no_paste_and_no_arm_or_retry(self):
        from dc_compat.clipboard_transaction import ClipboardTransactionError
        ops, pastes = [], []
        def rpc(op, **kw):
            ops.append(op)
            return {'status': 'failed', 'receipt': {'paste_attempted': False,
                'clipboard_publication_attempted': False, 'failure_reason': 'snapshot_budget_exceeded'}}
        helper = self.wrapper(rpc)
        with self.assertRaises(ClipboardTransactionError) as found:
            helper.run('Entire text 中文🙂', lambda keys, preflight=False: pastes.append(preflight))
        self.assertEqual(ops, ['begin'])
        self.assertEqual(pastes, [True])
        self.assertFalse(found.exception.receipt['paste_attempted'])

    def test_uncertain_finish_retains_attempt_receipt_and_never_replays(self):
        from dc_compat.clipboard_transaction import ClipboardTransactionError
        ops, pastes = [], []
        receipt = {'paste_attempted': True, 'original_bytes_snapshot_complete': True,
                   'original_bytes_offer_restored': False, 'automatic_retry': False}
        def rpc(op, **kw):
            ops.append(op)
            if op == 'finish':raise TimeoutError('Original private channel unavailable')
            return {'status': 'prepared' if op == 'begin' else 'armed', 'receipt': dict(receipt)}
        helper = self.wrapper(rpc)
        helper.receipt = lambda identity: dict(receipt)
        with self.assertRaises(ClipboardTransactionError) as found:
            helper.run('One complete paste 中文🙂', lambda keys, preflight=False: pastes.append(preflight))
        self.assertEqual(ops, ['begin', 'arm', 'finish'])
        self.assertEqual(pastes, [True, False])
        self.assertTrue(found.exception.receipt['paste_attempted'])
        self.assertFalse(found.exception.receipt['original_bytes_offer_restored'])
        self.assertFalse(found.exception.receipt['automatic_retry'])

    def test_paste_exception_still_finishes_restore_once(self):
        from dc_compat.clipboard_transaction import ClipboardTransactionError
        ops, pastes = [], []
        receipt = {'paste_attempted': True, 'original_bytes_offer_restored': True,
                   'automatic_retry': False, 'failure_reason': 'paste_callback_failed'}
        def rpc(op, **kw):
            ops.append((op, kw))
            return {'status': {'begin': 'prepared', 'arm': 'armed', 'finish': 'failed'}[op],
                    'receipt': dict(receipt)}
        def paste(keys, preflight=False):
            pastes.append(preflight)
            if not preflight:raise RuntimeError('Partial physical paste')
        helper = self.wrapper(rpc)
        with self.assertRaises(ClipboardTransactionError) as found:
            helper.run('No replay 中文🙂', paste)
        self.assertEqual([op for op, _ in ops], ['begin', 'arm', 'finish'])
        self.assertEqual(ops[-1][1]['paste_error'], 'RuntimeError')
        self.assertEqual(pastes, [True, False])
        self.assertTrue(found.exception.receipt['original_bytes_offer_restored'])

    def test_close_does_not_kill_or_wait_for_live_restored_offer(self):
        class Process:
            def poll(self):return None
            def wait(self, **kw):raise AssertionError('Lazy original owner was waited/killed')
        helper = self.wrapper(lambda op, **kw: {'result': {'closed': False,
                              'retained_original_offer': True, 'helper_alive': True}})
        helper.proc = Process()
        self.assertEqual(helper.close(), {'closed': False, 'retained_original_offer': True,
                                         'helper_alive': True})

    def test_late_selection_request_during_finish_is_still_recorded(self):
        from dc_compat.x11_selection import _Helper
        helper = _Helper.__new__(_Helper)
        helper.xid = 88
        helper._owner = lambda: 88
        helper.serving = {'kind': 'temporary'}
        helper.active = {'phase': 'finishing', 'receipt': {'transfers': []}}
        helper._data = lambda offer, target: ({'type': 'UTF8_STRING', 'format': 8}, b'complete text')
        helper.Gdk = SimpleNamespace(Atom=SimpleNamespace(intern=lambda name, exists: name))
        provided = []
        selection = SimpleNamespace(get_target=lambda: SimpleNamespace(name=lambda: 'UTF8_STRING'),
                                    set=lambda *args: provided.append(args))
        helper._selection_get(None, selection, 0, 0)
        self.assertEqual(provided, [('UTF8_STRING', 8, b'complete text')])
        self.assertEqual(len(helper.active['receipt']['transfers']), 1)
        self.assertFalse(helper.active['receipt']['transfers'][0]['consumer_completion_confirmed'])


@unittest.skipUnless(os.environ.get('HEPTA_X230_R7_REAL_GUI') == '1',
                     'Real GUI is opt-in and permitted only on the pinned X230 R7 desktop')
class X230RealSelectionTests(unittest.TestCase):
    def setUp(self):
        # Fail closed before importing GTK or constructing any display/helper.
        self.assertEqual(socket.gethostname(), 'qian-ThinkPad-X230')
        self.assertEqual(os.getuid(), 1000)
        runtime_path = pathlib.Path(os.environ['HEPTA_X230_TEST_RUNTIME'])
        allowed = {pathlib.Path('/home/qian/.local/share/hepta-computer-x230-qualification-20261015-r' + version)
                   for version in ('6', '7')}
        self.assertIn(runtime_path.parent, allowed)
        self.assertEqual(runtime_path.name, 'runtime.private.json')
        self.base = runtime_path.parent
        info = runtime_path.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode) and info.st_uid == 1000 and stat.S_IMODE(info.st_mode) == 0o600)
        stage_path = self.base / 'stage_x230_computer_test.py'
        stage_source = stage_path.read_bytes()
        self.assertEqual(hashlib.sha256(stage_source).hexdigest(), os.environ['HEPTA_X230_STAGE_SHA256'])
        namespace = {'__name__': 'independent_readonly_stage_verifier', '__file__': str(stage_path)}
        exec(compile(stage_source, str(stage_path), 'exec'), namespace)
        stage = namespace['load_stage'](self.base)
        runtime = json.loads(runtime_path.read_bytes())
        for key in ('base_identity', 'state_identity', 'profile_id', 'nonce', 'unit', 'release', 'xauthority'):
            self.assertEqual(runtime[key], stage[key])
        self.assertEqual(namespace['unit_identity'](runtime['unit']), runtime['unit_identity'])
        self.assertEqual(runtime['hostname'], socket.gethostname())
        self.assertEqual(runtime['status'], 'ready')
        self.assertEqual(runtime['backend'], 'x11')
        self.assertTrue(runtime['display'].startswith(':2'))
        lock = pathlib.Path('/tmp/.X' + runtime['display'][1:] + '-lock')
        self.assertEqual(int(lock.read_text()), runtime['xvfb_pid'])
        raw = pathlib.Path('/proc/' + str(runtime['xvfb_pid']) + '/stat').read_text()
        self.assertEqual(int(raw.rsplit(')', 1)[1].split()[19]), runtime['xvfb_starttime'])
        process = pathlib.Path('/proc/' + str(runtime['xvfb_pid']))
        self.assertEqual(pathlib.Path(os.readlink(process / 'exe')).name, 'Xvfb')
        argv = (process / 'cmdline').read_bytes().split(b'\0')
        self.assertIn(runtime['display'].encode(), argv)
        self.assertEqual(argv[argv.index(b'-auth') + 1], runtime['xauthority'].encode())
        self.assertIn(runtime['nonce'], runtime['xauthority'])
        self.assertEqual((self.base / 'state').stat().st_ino, stage['state_identity']['inode'])
        self.env = dict(runtime['desktop_environment'], PATH='/usr/bin:/bin', HOME='/home/qian',
                        GDK_BACKEND='x11', NO_AT_BRIDGE='1', GTK_USE_PORTAL='0')
        self.temp = tempfile.TemporaryDirectory(prefix='selection-independent-', dir=self.base)
        self.folder = pathlib.Path(self.temp.name)
        self.nonce = os.urandom(16).hex()
        self.serial = 0
        self.reader_serial = 0
        self.reader_folder = self.folder / 'foreign-reader'
        self.reader_folder.mkdir(mode=0o700)
        self.reader_nonce = os.urandom(16).hex()
        self.helpers = []
        self.owner = subprocess.Popen(['/usr/bin/python3', '-I', '-c', OWNER_SOURCE,
                                       str(self.folder), self.nonce], env=self.env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.cleanup_owner)
        wait_state(self.folder, self.nonce)
        self.reader = subprocess.Popen(['/usr/bin/python3', '-I', '-c', OWNER_SOURCE,
            str(self.reader_folder), self.reader_nonce, '--reader-only'], env=self.env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_state(self.reader_folder, self.reader_nonce)

    def cleanup_owner(self):
        retain = False
        if self.owner.poll() is None:
            try:self.command('offer', 'external')
            except Exception:retain = True
        for helper in self.helpers:
            try:
                if not helper.close().get('closed'):retain = True
            except Exception:retain = True
        for child in (self.owner, getattr(self, 'reader', None)):
            if child is not None and child.poll() is None:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill(); child.wait(timeout=5)
        if retain:
            # Never delete a private backup while a lazy owner may still serve it.
            self.temp._finalizer.detach()
        else:self.temp.cleanup()

    def command(self, action, profile='normal', *, reader=False):
        if reader:
            self.reader_serial += 1
            serial, folder, nonce = self.reader_serial, self.reader_folder, self.reader_nonce
        else:
            self.serial += 1
            serial, folder, nonce = self.serial, self.folder, self.nonce
        path = folder / 'clipboard-command.json'
        path.write_text(json.dumps({'nonce': nonce, 'serial': serial,
                                    'action': action, 'profile': profile}))
        path.chmod(0o600)
        def complete(row):
            if row['serial'] != serial:return False
            if action == 'inspect':
                return bool(row.get('inspection') and row['inspection']['serial'] == serial and not row['inspection']['pending'])
            if action == 'read_text':return bool(row.get('text_read') and row['text_read']['serial'] == serial)
            return True
        return wait_state(folder, nonce, complete)

    def foreign_baseline(self, original):
        baseline = self.command('inspect', reader=True)['inspection']
        self.assertEqual(baseline['owner_before'], original['owner_xid'])
        self.assertEqual(baseline['owner_after'], original['owner_xid'])
        self.assertEqual(baseline['data_targets'], sorted(row['target'] for row in original['manifest']))
        self.assertEqual(len(baseline['formats']), len(original['manifest']))
        for source, received in zip(original['manifest'], baseline['formats']):
            self.assertNotIn('error', received)
            for key in ('target', 'type', 'format', 'bytes', 'canonical_units_bytes', 'canonical_units_sha256'):
                self.assertEqual(received[key], source[key])
            if source['format'] != 32:self.assertEqual(received['sha256'], source['sha256'])
        return baseline

    def test_budget_refusal_keeps_original_owner_and_every_offered_byte(self):
        from dc_compat.x11_selection import X11Selection
        original = self.command('offer')
        baseline = self.foreign_baseline(original)
        events = []
        helper = X11Selection(display=self.env['DISPLAY'], env=self.env,
                              state_path=self.folder / 'provider-budget', budget=1024)
        self.helpers.append(helper)
        try:
            def paste(keys, preflight=False):
                events.append(preflight)
                if not preflight:
                    self.fail('Budget refusal reached physical paste')
            with self.assertRaises(Exception):
                helper.run('Original expected 中文🙂', paste)
            after = self.command('inspect', reader=True)
            self.assertEqual(after['owner_xid'], original['owner_xid'])
            self.assertEqual(after['inspection']['formats'], baseline['formats'])
            self.assertNotIn(False, events)
        finally:
            helper.close()

    def test_resource_target_refusal_never_requests_or_overwrites_that_resource(self):
        from dc_compat.x11_selection import X11Selection
        original = self.command('offer', 'resource')
        helper = X11Selection(display=self.env['DISPLAY'], env=self.env,
                              state_path=self.folder / 'provider-resource', budget=8 * 1024 * 1024)
        self.helpers.append(helper)
        try:
            def paste(keys, preflight=False):
                if not preflight:self.fail('Resource refusal reached physical paste')
            with self.assertRaises(Exception):
                helper.run('No partial prefix 中文', paste)
            after = wait_state(self.folder, self.nonce)
            self.assertEqual(after['owner_xid'], original['owner_xid'])
            self.assertEqual(after['request_counts'].get('PIXMAP', 0), 0)
        finally:
            helper.close()

    def test_complete_unicode_transfer_restores_typed_bytes_and_serves_after_close(self):
        from dc_compat.x11_selection import X11Selection
        original = self.command('offer')
        baseline = self.foreign_baseline(original)
        self.assertNotIn(baseline['owner_before'], self.command('inspect', reader=True)['own_window_ids'])
        helper = X11Selection(display=self.env['DISPLAY'], env=self.env,
                              state_path=self.folder / 'provider-full', budget=8 * 1024 * 1024)
        self.helpers.append(helper)
        text = 'Hepta X230 测试 café Ω 🙂🙂 测试测试'
        expected = hashlib.sha256(text.encode()).hexdigest()
        phases = []
        def consume(keys, preflight=False):
            phases.append(preflight)
            if not preflight:
                row = self.command('read_text', reader=True)
                self.assertEqual(row['text_read'], {'serial': self.reader_serial,
                    'bytes': len(text.encode()), 'sha256': expected})
            return {'submitted': False, 'fixture_read_only_consumer': True}
        result = helper.run(text, consume)
        self.assertTrue(result['original_bytes_offer_restored'])
        self.assertFalse(result['target_input_verified'])
        self.assertEqual(phases, [True, False])
        for delay in (0, .25):
            time.sleep(delay)
            current = self.command('inspect', reader=True)
            self.assertEqual(current['inspection']['formats'], baseline['formats'])
        closed = helper.close()
        self.assertFalse(closed['closed'])
        self.assertTrue(closed['helper_alive'])
        current = self.command('inspect', reader=True)
        self.assertEqual(current['inspection']['formats'], baseline['formats'])


if __name__ == '__main__':
    unittest.main()
