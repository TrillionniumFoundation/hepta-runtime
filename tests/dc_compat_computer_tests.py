# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""X11 GUI tests default to skipped; explicit X230 qualification gate required.

HEPTA_X230_DEDICATED_GUI_TESTS=1 and HEPTA_X230_GUI_TEST_RUNTIME must identify
the already authorized X230 virtual-desktop runtime. Tests create a separate
high-numbered Xvfb with their own authentication and state, never a main screen.
"""
import asyncio
import base64
import io
import json
import os
import pathlib
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.computer import COMPUTER_TOOLS, ComputerManager, _Portal, _X11
from dc_compat.registry import ToolError, ToolRegistry


WINDOW = r'''
import gi,json,os,pathlib,sys
gi.require_version('Gtk','3.0');gi.require_version('GdkX11','3.0')
from gi.repository import Gtk,Gdk,GdkX11,GLib
os.umask(0o077);target=pathlib.Path(sys.argv[1]);root=Gtk.Window(title='Hepta isolated GUI fixture')
root.set_default_size(640,480);root.move(10,10);fixed=Gtk.Fixed();root.add(fixed)
entry=Gtk.Entry();entry.set_size_request(600,40);fixed.put(entry,20,20)
canvas=Gtk.DrawingArea();canvas.set_size_request(600,350);fixed.put(canvas,20,90)
canvas.connect('draw',lambda widget,cr:(cr.set_source_rgb(29/255,106/255,158/255),cr.paint(),False)[-1])
events=[];key_events=[];keys_down=set()
def event(widget,event):
 row={'type':str(event.type),'x':getattr(event,'x',None),'y':getattr(event,'y',None),
      'key':getattr(event,'keyval',None),'num':str(getattr(event,'button',''))}
 if event.type in (Gdk.EventType.KEY_PRESS,Gdk.EventType.KEY_RELEASE):
  key_events.append(row);code=int(event.hardware_keycode)
  if event.type==Gdk.EventType.KEY_PRESS:keys_down.add(code)
  else:keys_down.discard(code)
 if event.type==Gdk.EventType.SCROLL:
  row['num']='5' if event.direction==Gdk.ScrollDirection.DOWN else '4'
 events.append(row);return False
mask=Gdk.EventMask.BUTTON_PRESS_MASK|Gdk.EventMask.BUTTON_RELEASE_MASK|Gdk.EventMask.SCROLL_MASK
canvas.add_events(mask)
for widget in (root,entry,canvas):
 for name in ('button-press-event','button-release-event','scroll-event'):widget.connect(name,event)
root.connect('key-press-event',event);root.connect('key-release-event',event)
def save():
 window=root.get_window();data={'text':entry.get_text(),'events':events,'key_events':key_events,
  'keys_down':sorted(keys_down),'ready':bool(window and root.get_mapped()),'pid':os.getpid(),
  'backend':type(Gdk.Display.get_default()).__name__,
  'window_id':str(window.get_xid()) if window else None}
 temporary=target.with_suffix('.tmp');temporary.write_text(json.dumps(data));temporary.replace(target)
 return True
root.connect('destroy',Gtk.main_quit);root.show_all();entry.grab_focus();GLib.timeout_add(30,save);Gtk.main()
'''


PORTAL = r'''
import json,os,pathlib,sys,threading
from gi.repository import Gio,GLib
address,path=sys.argv[1:];events=pathlib.Path(path);context=GLib.MainContext.default()
bus=Gio.DBusConnection.new_for_address_sync(address,Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT|Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,None,None)
bus.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','RequestName',GLib.Variant('(su)',('org.freedesktop.portal.Desktop',0)),None,Gio.DBusCallFlags.NONE,1000,None)
R='org.freedesktop.portal.RemoteDesktop';S='org.freedesktop.portal.ScreenCast';C='org.freedesktop.portal.Clipboard'
P='/org/freedesktop/portal/desktop';session='/org/freedesktop/portal/desktop/session/fixture';records=[];received='fixture clipboard';mode='ok'
def record(method,params):
 records.append({'method':method,'params':params});events.write_text(json.dumps({'ready':True,'records':records,'clipboard':received}))
def method(conn,sender,path,interface,name,params,invocation):
 global received,mode
 values=params.unpack();record(name,list(values))
 if name in ['CreateSession','SelectDevices','SelectSources','Start']:
  options=values[-1];handle=P+'/request/'+sender[1:].replace('.','_')+'/'+options['handle_token']
  results={}
  if name=='CreateSession':results={'session_handle':GLib.Variant('s',session)}
  if name=='Start':results={'devices':GLib.Variant('u',3),'clipboard_enabled':GLib.Variant('b',True),'restore_token':GLib.Variant('s','fixture-token-'+str(sum(row['method']=='Start' for row in records))),'streams':GLib.Variant('a(ua{sv})',[(42,{'size':GLib.Variant('(ii)',(800,600)),'position':GLib.Variant('(ii)',(0,0)),'source_type':GLib.Variant('u',1)})])}
  invocation.return_value(GLib.Variant('(o)',(handle,)))
  if name=='Start' and mode=='timeout':return
  code=1 if name=='Start' and mode=='deny' else 0
  GLib.idle_add(lambda:(bus.emit_signal(sender,handle,'org.freedesktop.portal.Request','Response',GLib.Variant('(ua{sv})',(code,results))),False)[1]);return
 if name=='GetAll':
  props={'version':GLib.Variant('u',2)}
  if values[0]==R:props['AvailableDeviceTypes']=GLib.Variant('u',7)
  invocation.return_value(GLib.Variant('(a{sv})',(props,)));return
 if name=='SelectionRead':
  read,write=os.pipe();os.write(write,received.encode());os.close(write);fds=Gio.UnixFDList.new();index=fds.append(read);os.close(read)
  invocation.return_value_with_unix_fd_list(GLib.Variant('(h)',(index,)),fds);return
 if name=='SelectionWrite':
  read,write=os.pipe();fds=Gio.UnixFDList.new();index=fds.append(write);os.close(write)
  def drain():
   global received
   data=b''
   while True:
    more=os.read(read,65536)
    if not more:break
    data+=more
   os.close(read);received=data.decode();record('transfer_received',[len(data)])
  threading.Thread(target=drain,daemon=True).start();invocation.return_value_with_unix_fd_list(GLib.Variant('(h)',(index,)),fds);return
 invocation.return_value(GLib.Variant('()',()))
 if name=='SetSelection':GLib.idle_add(lambda:(bus.emit_signal(sender,P,C,'SelectionTransfer',GLib.Variant('(osu)',(session,'text/plain;charset=utf-8',1))),False)[1])
 if name=='Revoke':GLib.idle_add(lambda:(bus.emit_signal(sender,session,'org.freedesktop.portal.Session','Closed',GLib.Variant('()',())),False)[1])
 if name=='SetMode':mode=values[0]
def xml(interface,methods):
 return '<node><interface name="'+interface+'">'+''.join('<method name="'+n+'">'+''.join('<arg type="'+t+'" direction="in"/>' for t in ins)+''.join('<arg type="'+t+'" direction="out"/>' for t in outs)+'</method>' for n,ins,outs in methods)+'</interface></node>'
groups=[(R,[('CreateSession',['a{sv}'],['o']),('SelectDevices',['o','a{sv}'],['o']),('Start',['o','s','a{sv}'],['o']),('NotifyPointerMotionAbsolute',['o','a{sv}','u','d','d'],[]),('NotifyPointerButton',['o','a{sv}','i','u'],[]),('NotifyPointerAxisDiscrete',['o','a{sv}','u','i'],[]),('NotifyKeyboardKeysym',['o','a{sv}','i','u'],[])]),(S,[('SelectSources',['o','a{sv}'],['o'])]),(C,[('RequestClipboard',['o','a{sv}'],[]),('SetSelection',['o','a{sv}'],[]),('SelectionRead',['o','s'],['h']),('SelectionWrite',['o','u'],['h']),('SelectionWriteDone',['o','u','b'],[])]),('org.freedesktop.DBus.Properties',[('GetAll',['s'],['a{sv}'])]),('org.hepta.Test',[('Revoke',[],[]),('SetMode',['s'],[])])]
for interface,methods in groups:
 info=Gio.DBusNodeInfo.new_for_xml(xml(interface,methods));bus.register_object(P,info.interfaces[0],method,None,None)
info=Gio.DBusNodeInfo.new_for_xml(xml('org.freedesktop.portal.Session',[('Close',[],[])]));bus.register_object(session,info.interfaces[0],method,None,None)
record('ready',[]);GLib.MainLoop().run()
'''


async def wait_file(path, predicate=lambda value: value.get('ready'), timeout=8):
    deadline = time.monotonic() + timeout
    last_value = None
    while time.monotonic() < deadline:
        try:
            value = json.loads(path.read_text())
            last_value = value
            if predicate(value):
                return value
        except (OSError, ValueError):
            pass
        await asyncio.sleep(.03)
    raise AssertionError('Isolated fixture did not reach the expected state; '
                         f'last private fixture state: {last_value!r}')


class X11Tests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        if os.environ.get('HEPTA_X230_DEDICATED_GUI_TESTS') != '1':
            self.skipTest('Real GUI is opt-in only on the authorized X230 virtual desktop')
        self.assertEqual(socket.gethostname(), 'qian-ThinkPad-X230', 'Real GUI is forbidden on this host')
        self.assertEqual(os.getuid(), 1000)
        runtime_path = pathlib.Path(os.environ.get('HEPTA_X230_GUI_TEST_RUNTIME', ''))
        self.assertTrue(runtime_path.is_absolute(), 'An explicit private X230 qualification runtime is required')
        self.assertTrue(str(runtime_path.parent).startswith('/home/qian/.local/share/hepta-computer-x230-qualification-20261015'))
        info = runtime_path.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
        runtime = json.loads(runtime_path.read_text())
        base = runtime_path.parent.lstat()
        self.assertTrue(stat.S_ISDIR(base.st_mode) and base.st_uid == os.getuid())
        self.assertEqual({'device': base.st_dev, 'inode': base.st_ino}, runtime['base_identity'])
        self.assertEqual(stat.S_IMODE(base.st_mode), 0o700)
        self.assertEqual(os.environ.get('DISPLAY'), runtime['display'])
        self.assertEqual(os.environ.get('XAUTHORITY'), runtime['xauthority'])
        self.assertTrue(runtime['display'].startswith(':') and runtime['display'][1:].isdigit()
                        and 20000 <= int(runtime['display'][1:]) <= 39999)
        proc = pathlib.Path('/proc') / str(runtime['xvfb_pid'])
        fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        self.assertEqual(int(fields[19]), runtime['xvfb_starttime'])
        argv = (proc / 'cmdline').read_bytes().split(b'\0')
        self.assertEqual(pathlib.Path(os.fsdecode(argv[0])).name, 'Xvfb')
        self.assertIn(runtime['display'].encode(), argv)
        self.assertIn(runtime['xauthority'].encode(), argv)
        self.assertIn(runtime['nonce'], runtime['xauthority'])
        bus = runtime['desktop_environment']['DBUS_SESSION_BUS_ADDRESS']
        self.assertTrue(bus.startswith('unix:') and '/run/user/' not in bus)
        for command in ('Xvfb', 'xdotool', 'import', 'xclip', 'xdpyinfo', 'xauth'):
            self.assertIsNotNone(shutil.which(command), 'Explicitly requested X230 GUI dependency unavailable: ' + command)
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-gui-test-')
        self.path = pathlib.Path(self.temp.name)
        try:
            self.path.chmod(0o700)
            for _ in range(100):
                number = 30000 + secrets.randbelow(10000)
                if not os.path.lexists('/tmp/.X' + str(number) + '-lock') and not os.path.lexists('/tmp/.X11-unix/X' + str(number)):
                    break
            else:
                self.fail('No unused high-numbered dedicated Xvfb candidate')
            self.display = ':' + str(number)
            self.auth = self.path / ('Xauthority-' + secrets.token_hex(16))
            descriptor = os.open(self.auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            self.env = {'HOME': '/home/qian', 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                'DISPLAY': self.display, 'XAUTHORITY': str(self.auth), 'DBUS_SESSION_BUS_ADDRESS': bus,
                'GDK_BACKEND': 'x11', 'QT_QPA_PLATFORM': 'xcb', 'XDG_SESSION_TYPE': 'x11',
                'GTK_USE_PORTAL': '0', 'NO_AT_BRIDGE': '1', 'GTK_IM_MODULE': 'simple'}
            for key in ('CONFIG', 'DATA', 'CACHE'):
                folder = self.path / ('xdg-' + key.lower()); folder.mkdir(mode=0o700)
                self.env['XDG_' + key + '_HOME'] = str(folder)
            cookie = secrets.token_hex(16)
            subprocess.run(['xauth', '-q', '-f', str(self.auth)], env=self.env,
                input=('add ' + self.display + ' . ' + cookie + '\n').encode(),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=True)
            cookie = None
            self.assertEqual(stat.S_IMODE(self.auth.lstat().st_mode), 0o600)
            self.xvfb = subprocess.Popen(['Xvfb', self.display, '-auth', str(self.auth),
                '-screen', '0', '800x600x24', '-nolisten', 'tcp', '-noreset'], env=self.env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 5
            lock = pathlib.Path('/tmp/.X' + str(number) + '-lock')
            while not lock.exists() or not pathlib.Path('/tmp/.X11-unix/X' + str(number)).exists():
                self.assertIsNone(self.xvfb.poll(), 'Our dedicated Xvfb exited')
                if time.monotonic() >= deadline:
                    self.fail('Our dedicated Xvfb did not become ready')
                await asyncio.sleep(.03)
            self.assertEqual(int(lock.read_text().strip()), self.xvfb.pid)
            self.window = subprocess.Popen(['/usr/bin/python3', '-I', '-c', WINDOW, str(self.path / 'events.json')],
                env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            fixture = await wait_file(self.path / 'events.json')
            self.assertEqual(fixture['pid'], self.window.pid)
            self.assertIn('X11', fixture['backend'])
            clipboard_state = self.path / 'clipboard-transactions'; clipboard_state.mkdir(mode=0o700)
            self.manager = ComputerManager({'backend': 'x11', 'display': self.display,
                'xauthority': str(self.auth), 'clipboard_state_dir': str(clipboard_state),
                'clipboard_max_snapshot_bytes': 16 * 1024 * 1024})
            self.manager.backend.env = dict(self.env)
            capabilities = self.manager.backend.capabilities()
            self.assertEqual(capabilities['backend'], 'x11')
            self.assertTrue(capabilities['authorized'])
            self.assertEqual(capabilities['logical_size'], [800, 600])
            self.registry = ToolRegistry(COMPUTER_TOOLS)
            self.registry.add(self.manager)
        except BaseException:
            await self.asyncTearDown()
            raise

    async def asyncTearDown(self):
        try:
            if hasattr(self, 'manager'):
                await self.manager.close()
        finally:
            for name in ['window', 'xvfb']:
                proc = getattr(self, name, None)
                if proc:
                    if proc.poll() is None:
                        proc.terminate()
                    try:
                        await asyncio.to_thread(proc.wait, 5)
                    except subprocess.TimeoutExpired:
                        proc.kill(); await asyncio.to_thread(proc.wait, 5)
            if hasattr(self, 'temp'):
                self.temp.cleanup()

    async def call(self, name, args):
        result = await self.registry.invoke('computer_' + name, args)
        self.assertFalse(result.get('isError'), result)
        return result

    async def test_screenshot_is_real_fixture_png_and_scaled(self):
        result = await self.call('screenshot', {'max_width': 400})
        from PIL import Image
        with Image.open(io.BytesIO(base64.b64decode(result['content'][0]['data']))) as image:
            self.assertEqual(image.size, (400, 300))
            self.assertGreater(image.getpixel((50, 100))[2], 100)
        self.assertEqual(result['structuredContent']['capture_pixel_size'], [800, 600])
        self.assertEqual(result['structuredContent']['logical_size'], [800, 600])

    async def test_window_focus_and_unicode_type_key_combination(self):
        result = await self.call('window', {'action': 'list'})
        windows = result['structuredContent']['result']['windows']
        selected = next(value for value in windows if value['title'] == 'Hepta isolated GUI fixture')
        await self.call('window', {'action': 'focus', 'window_id': selected['window_id']})
        await self.call('mouse', {'action': 'click', 'x': 80, 'y': 50})
        await self.call('type', {'text': 'Hepta 测试', 'mode': 'auto'})
        await wait_file(self.path / 'events.json', lambda value: value['text'] == 'Hepta 测试')
        await self.call('key', {'keys': ['CTRL', 'A']})
        await self.call('type', {'text': 'clipboard 替换 😀', 'mode': 'clipboard'})
        await wait_file(self.path / 'events.json', lambda value: value['text'] == 'clipboard 替换 😀')
        await self.call('key', {'keys': ['CTRL', 'A']})
        await self.call('type', {'text': 'replacement', 'mode': 'keyboard'})
        await wait_file(self.path / 'events.json', lambda value: value['text'] == 'replacement' and not value['keys_down'])
        self.assertEqual(self.manager.held_keys, set())

    async def test_unmapped_keyboard_whole_text_refusal_has_zero_prefix_events(self):
        windows = (await self.call('window', {'action': 'list'}))['structuredContent']['result']['windows']
        selected = next(value for value in windows if value['title'] == 'Hepta isolated GUI fixture')
        await self.call('window', {'action': 'focus', 'window_id': selected['window_id']})
        await self.call('mouse', {'action': 'click', 'x': 80, 'y': 50})
        before = await wait_file(self.path / 'events.json')
        result = await self.registry.invoke('computer_type', {'text': 'ASCII prefix 测试', 'mode': 'keyboard'})
        self.assertTrue(result.get('isError'), result)
        self.assertFalse(result['structuredContent']['result']['submitted'])
        # Repeat only observations, never the refused input action.
        await asyncio.sleep(.15)
        after = await wait_file(self.path / 'events.json')
        self.assertEqual(after['text'], before['text'])
        self.assertEqual(after['key_events'], before['key_events'])
        self.assertEqual(after['keys_down'], before['keys_down'])

    async def test_empty_text_all_modes_are_noop_without_os_commands(self):
        def unexpected(*args, **kwargs):
            raise AssertionError('Empty text must not submit an OS command')
        self.manager.backend._run = unexpected
        for mode in ('auto', 'keyboard', 'clipboard'):
            result = await self.call('type', {'text': '', 'mode': mode})
            self.assertEqual(result['structuredContent']['result'],
                             {'method': 'none', 'submitted': False, 'characters': 0,
                              'clipboard_modified': False, 'replayed': False})

    async def test_mouse_drag_scroll_and_release(self):
        await self.call('mouse', {'action': 'drag', 'x': 90, 'y': 150, 'to_x': 200, 'to_y': 240, 'duration_ms': 20})
        await self.call('mouse', {'action': 'scroll', 'direction': 'down', 'steps': 2})
        data = await wait_file(self.path / 'events.json', lambda value: any(event['num'] == '5' for event in value['events']))
        self.assertTrue(any(event['num'] == '1' for event in data['events']))
        self.assertEqual(self.manager.held_buttons, set())

    async def test_move_to_actual_current_pointer_is_fast_without_redundant_warp(self):
        backend = self.manager.backend
        original = backend._run
        def position():
            values = dict(row.split('=', 1) for row in original(
                ['xdotool', 'getmouselocation', '--shell']).decode('ascii').splitlines())
            return tuple(int(values[key]) for key in ('X', 'Y', 'SCREEN'))
        before = position()
        self.assertEqual(before[2], 0)
        moves = []
        def bounded_run(args, *values, **options):
            if args[:2] == ['xdotool', 'mousemove']:
                moves.append(args)
                # The old implementation fails quickly instead of hanging this test.
                options['timeout'] = .5
            return original(args, *values, **options)
        backend._run = bounded_run
        started = time.monotonic()
        await self.call('mouse', {'action': 'move', 'x': before[0], 'y': before[1]})
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(moves, [])
        self.assertEqual(position(), before)
        self.assertEqual(self.manager.held_buttons, set())

    async def test_clipboard_roundtrip_and_owner_reaped(self):
        await self.call('clipboard', {'action': 'set', 'text': 'Hepta clipboard 测试'})
        first = self.manager.backend.clipboard_owner
        await self.call('clipboard', {'action': 'set', 'text': 'second clipboard 测试'})
        self.assertIsNotNone(first.poll())
        result = await self.call('clipboard', {'action': 'get'})
        self.assertEqual(result['structuredContent']['result'], 'second clipboard 测试')
        owner = self.manager.backend.clipboard_owner
        await self.manager.close()
        self.assertIsNotNone(owner.poll())

    async def test_failed_clipboard_confirmation_reaps_new_owner(self):
        original = self.manager.backend._run
        def run(args, *values, **options):
            if args[0] == 'xclip':
                raise ToolError('Injected read failure')
            return original(args, *values, **options)
        self.manager.backend._run = run
        result = await self.registry.invoke('computer_clipboard', {'action': 'set', 'text': 'fixture only'})
        self.assertTrue(result.get('isError'))
        self.assertIsNotNone(self.manager.backend.clipboard_owner.poll())

    async def test_invalid_coordinates_keys_and_nul_do_not_submit_input(self):
        for name, args in [('mouse', {'action': 'click', 'x': 1000, 'y': 10}),
                           ('mouse', {'action': 'drag', 'x': 10, 'y': 10}),
                           ('key', {'keys': ['$(evil)']}), ('type', {'text': '\x00bad'})]:
            result = await self.registry.invoke('computer_' + name, args)
            self.assertTrue(result.get('isError'))
        self.assertEqual(self.manager.held_keys, set())
        self.assertEqual(self.manager.held_buttons, set())

    async def test_close_releases_explicit_mouse_hold(self):
        await self.call('mouse', {'action': 'down'})
        self.assertEqual(self.manager.held_buttons, {'left'})
        await self.manager.close()
        self.assertEqual(self.manager.held_buttons, set())


class PortalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        if not shutil.which('dbus-daemon'):
            self.skipTest('dbus-daemon unavailable')
        try:
            import gi
        except ImportError:
            self.skipTest('PyGObject unavailable')
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-portal-test-')
        self.path = pathlib.Path(self.temp.name)
        self.bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--print-address=1'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        address = (await asyncio.wait_for(asyncio.to_thread(self.bus.stdout.readline), 5)).decode().strip()
        self.assertNotEqual(address, os.environ.get('DBUS_SESSION_BUS_ADDRESS'))
        self.portal = subprocess.Popen([sys.executable, '-I', '-c', PORTAL, address, str(self.path / 'portal.json')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        await wait_file(self.path / 'portal.json')
        self.manager = ComputerManager({'backend': 'portal', 'portal_input_backend': 'legacy', 'dbus_address': address, 'authorization_timeout': 3})

    async def asyncTearDown(self):
        if hasattr(self, 'manager'):
            await self.manager.close()
            await asyncio.to_thread(self.manager.backend.worker.join, 3)
            self.assertFalse(self.manager.backend.worker.is_alive())
        for name in ['portal', 'bus']:
            proc = getattr(self, name, None)
            if proc:
                proc.terminate()
                await asyncio.to_thread(proc.wait, 5)
                for pipe in [proc.stdout, proc.stderr]:
                    if pipe:
                        pipe.close()
        if hasattr(self, 'temp'):
            self.temp.cleanup()

    async def invoke(self, name, args):
        return await self.manager.invoke('computer_' + name, args)

    async def test_discovery_does_not_authorize_or_send_input(self):
        result = await self.invoke('capabilities', {})
        value = result['structuredContent']['result']
        self.assertFalse(value['authorized'])
        self.assertFalse(value['features']['mouse'])
        records = json.loads((self.path / 'portal.json').read_text())['records']
        self.assertNotIn('CreateSession', [row['method'] for row in records])
        with self.assertRaisesRegex(ToolError, 'No authorized'):
            await self.invoke('mouse', {'action': 'click', 'x': 10, 'y': 20})

    async def test_real_private_dbus_portal_handshake_and_exact_input(self):
        result = await self.invoke('session', {'action': 'authorize'})
        capabilities = result['structuredContent']['result']
        self.assertTrue(capabilities['authorized'])
        self.assertEqual(capabilities['streams'][0]['logical_size'], [800, 600])
        await self.invoke('mouse', {'action': 'click', 'x': 123, 'y': 234, 'stream': 42})
        await self.invoke('mouse', {'action': 'scroll', 'direction': 'up', 'steps': 3})
        await self.invoke('key', {'keys': ['CTRL', 'A']})
        await self.invoke('type', {'text': '测\n'})
        records = json.loads((self.path / 'portal.json').read_text())['records']
        order = [row['method'] for row in records]
        self.assertLess(order.index('SelectDevices'), order.index('Start'))
        self.assertLess(order.index('RequestClipboard'), order.index('Start'))
        absolute = next(row for row in records if row['method'] == 'NotifyPointerMotionAbsolute')
        self.assertEqual(absolute['params'][2:], [42, 123.0, 234.0])
        buttons = [row['params'][2:] for row in records if row['method'] == 'NotifyPointerButton']
        self.assertEqual(buttons, [[272, 1], [272, 0]])
        keyboard = [row['params'][2:] for row in records if row['method'] == 'NotifyKeyboardKeysym']
        self.assertIn([0x01000000 | ord('测'), 1], keyboard)
        self.assertEqual(keyboard[-1], [0xff0d, 0])

    async def test_portal_clipboard_real_unix_fds_and_idle_transfer(self):
        await self.invoke('session', {'action': 'authorize'})
        initial = await self.invoke('clipboard', {'action': 'get'})
        self.assertEqual(initial['structuredContent']['result'], 'fixture clipboard')
        await self.invoke('clipboard', {'action': 'set', 'text': 'portal owned 测试'})
        # No further invoke is needed to service the recipient's transfer signal.
        value = await wait_file(self.path / 'portal.json', lambda value: value['clipboard'] == 'portal owned 测试')
        self.assertIn('SelectionWriteDone', [row['method'] for row in value['records']])

    async def test_wayland_windows_refuse_without_xwayland_fallback(self):
        await self.invoke('session', {'action': 'authorize'})
        for args in [{'action': 'list'}, {'action': 'focus', 'window_id': '123'}]:
            with self.assertRaisesRegex(ToolError, 'Wayland portal'):
                await self.invoke('window', args)

    async def test_session_close_invalidates_input(self):
        await self.invoke('session', {'action': 'authorize'})
        await self.invoke('session', {'action': 'close'})
        with self.assertRaisesRegex(ToolError, 'No authorized'):
            await self.invoke('type', {'text': 'must not type'})

    async def test_portal_revocation_invalidates_without_reauthorization(self):
        await self.invoke('session', {'action': 'authorize'})
        await self.manager._call('_call', 'org.hepta.Test', 'Revoke', '()', ())
        await asyncio.sleep(.05)
        result = await self.invoke('capabilities', {})
        self.assertFalse(result['structuredContent']['result']['authorized'])
        with self.assertRaisesRegex(ToolError, 'No authorized'):
            await self.invoke('key', {'keys': ['a']})
        records = json.loads((self.path / 'portal.json').read_text())['records']
        self.assertEqual(sum(row['method'] == 'CreateSession' for row in records), 1)

    async def test_private_restore_token_rotation_and_remote_desktop_scope(self):
        receipt = self.path / 'restore.json'
        receipt.write_text(json.dumps({'version': 1, 'profile': 'test', 'restore_token': 'fixture-prior-token'}))
        receipt.chmod(0o600)
        self.manager.backend.config.update(portal_restore_path=str(receipt), profile_id='test')
        await self.invoke('session', {'action': 'authorize'})
        self.assertEqual(json.loads(receipt.read_text())['restore_token'], 'fixture-token-1')
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        await self.invoke('session', {'action': 'close'})
        await self.invoke('session', {'action': 'authorize'})
        self.assertEqual(json.loads(receipt.read_text())['restore_token'], 'fixture-token-2')
        records = json.loads((self.path / 'portal.json').read_text())['records']
        devices = [row['params'][-1] for row in records if row['method'] == 'SelectDevices']
        sources = [row['params'][-1] for row in records if row['method'] == 'SelectSources']
        self.assertEqual([value['restore_token'] for value in devices], ['fixture-prior-token', 'fixture-token-1'])
        self.assertTrue(all(value['persist_mode'] == 2 for value in devices))
        self.assertTrue(all('restore_token' not in value and 'persist_mode' not in value for value in sources))

    async def test_insecure_or_foreign_restore_receipt_refused_before_dialog(self):
        receipt = self.path / 'restore.json'
        receipt.write_text(json.dumps({'version': 1, 'profile': 'another-profile', 'restore_token': 'fixture-token'}))
        receipt.chmod(0o644)
        self.manager.backend.config.update(portal_restore_path=str(receipt), profile_id='test')
        with self.assertRaisesRegex(ToolError, 'private owned'):
            await self.invoke('session', {'action': 'authorize'})
        receipt.chmod(0o600)
        with self.assertRaisesRegex(ToolError, 'another profile'):
            await self.invoke('session', {'action': 'authorize'})
        records = json.loads((self.path / 'portal.json').read_text())['records']
        self.assertNotIn('CreateSession', [row['method'] for row in records])

    async def test_fresh_screen_chooser_ignores_saved_token_and_saves_success(self):
        receipt = self.path / 'restore.json'
        receipt.write_text(json.dumps({'version': 1, 'profile': 'test', 'restore_token': 'fixture-previous-grant'}))
        receipt.chmod(0o600)
        self.manager.backend.config.update(portal_restore_path=str(receipt), profile_id='test')
        await self.invoke('session', {'action': 'authorize', 'restore_session': False})
        records = json.loads((self.path / 'portal.json').read_text())['records']
        options = next(row['params'][-1] for row in records if row['method'] == 'SelectDevices')
        sources = next(row['params'][-1] for row in records if row['method'] == 'SelectSources')
        self.assertNotIn('restore_token', options)
        self.assertEqual(options['persist_mode'], 2)
        self.assertIs(sources['multiple'], True)
        self.assertEqual(json.loads(receipt.read_text())['restore_token'], 'fixture-token-1')

    async def test_active_session_refuses_fresh_chooser_without_closing_offer(self):
        await self.invoke('session', {'action': 'authorize'})
        session = self.manager.backend.session
        with self.assertRaisesRegex(ToolError, 'Close the active'):
            await self.invoke('session', {'action': 'authorize', 'restore_session': False})
        self.assertEqual(self.manager.backend.session, session)
        records = json.loads((self.path / 'portal.json').read_text())['records']
        self.assertEqual(sum(row['method'] == 'CreateSession' for row in records), 1)
        self.assertNotIn('Close', [row['method'] for row in records])

    async def test_failed_fresh_chooser_preserves_original_saved_grant(self):
        receipt = self.path / 'restore.json'
        original = json.dumps({'version': 1, 'profile': 'test', 'restore_token': 'fixture-previous-grant'}).encode()
        receipt.write_bytes(original);receipt.chmod(0o600)
        self.manager.backend.config.update(portal_restore_path=str(receipt), profile_id='test', authorization_timeout=.2)
        for mode in ('deny', 'timeout'):
            await self.manager._call('_call', 'org.hepta.Test', 'SetMode', '(s)', (mode,))
            with self.assertRaises(ToolError):
                await self.invoke('session', {'action': 'authorize', 'restore_session': False})
            self.assertEqual(receipt.read_bytes(), original)
            self.assertIsNone(self.manager.backend.session)
        records = json.loads((self.path / 'portal.json').read_text())['records']
        self.assertTrue(all('restore_token' not in row['params'][-1] for row in records if row['method'] == 'SelectDevices'))

    async def test_permission_denial_or_timeout_closes_without_any_input(self):
        for mode in ['deny', 'timeout']:
            await self.manager._call('_call', 'org.hepta.Test', 'SetMode', '(s)', (mode,))
            self.manager.backend.config['authorization_timeout'] = .2
            with self.assertRaises(ToolError):
                await self.invoke('session', {'action': 'authorize'})
            self.assertIsNone(self.manager.backend.session)
        records = json.loads((self.path / 'portal.json').read_text())['records']
        self.assertFalse(any(row['method'].startswith('Notify') for row in records))

    async def test_primary_authorization_error_survives_unconfirmed_cleanup(self):
        backend = self.manager.backend
        original = backend._call
        for mode, reason in [('deny', 'denied or cancelled'), ('timeout', 'Portal request timed out')]:
            await self.manager._call('_call', 'org.hepta.Test', 'SetMode', '(s)', (mode,))
            backend.config['authorization_timeout'] = .2
            def fail_close(interface, method, signature, values, **kwargs):
                if method == 'Close' and interface == 'org.freedesktop.portal.Session':
                    raise RuntimeError('Private injected close failure')
                return original(interface, method, signature, values, **kwargs)
            backend._call = fail_close
            try:
                with self.assertRaisesRegex(ToolError, reason) as captured:
                    await self.invoke('session', {'action': 'authorize'})
                self.assertIn('Additional desktop cleanup failed', str(captured.exception))
                self.assertTrue(captured.exception.__notes__)
                self.assertIsNotNone(backend.session)
                self.assertTrue(backend.eis_attempted)
            finally:
                backend._call = original
                await self.manager._call('close')
        records = json.loads((self.path / 'portal.json').read_text())['records']
        self.assertFalse(any(row['method'].startswith('Notify') for row in records))


class GuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_x11_same_position_and_fractional_edge_do_not_warp(self):
        backend = _X11({'display': ':fixture'})
        backend._check = lambda: None
        backend.capabilities = lambda: {'logical_size': [800, 600]}
        for x, y, pointer in [(400, 300, b'X=400\nY=300\nSCREEN=0\nWINDOW=0\n'),
                              (799.7, 599.9, b'X=799\nY=599\nSCREEN=0\nWINDOW=0\n')]:
            commands = []
            def run(args):
                commands.append(args)
                self.assertEqual(args, ['xdotool', 'getmouselocation', '--shell'])
                return pointer
            backend._run = run
            backend.move(x, y)
            self.assertEqual(commands, [['xdotool', 'getmouselocation', '--shell']])

    async def test_x11_changed_position_keeps_sync_and_does_not_replay_failure(self):
        backend = _X11({'display': ':fixture'})
        backend._check = lambda: None
        backend.capabilities = lambda: {'logical_size': [800, 600]}
        commands = []
        def run(args):
            commands.append(args)
            if args[1] == 'getmouselocation':
                return b'X=10\nY=20\nSCREEN=0\nWINDOW=0\n'
            raise ToolError('Uncertain movement timeout')
        backend._run = run
        with self.assertRaisesRegex(ToolError, 'Uncertain movement'):
            backend.move(799.7, 599.9)
        self.assertEqual(commands, [['xdotool', 'getmouselocation', '--shell'],
                                    ['xdotool', 'mousemove', '--sync', '799', '599']])

    async def test_x11_bad_pointer_read_refuses_without_move(self):
        backend = _X11({'display': ':fixture'})
        backend._check = lambda: None
        backend.capabilities = lambda: {'logical_size': [800, 600]}
        for pointer in (b'', b'X=1\nY=2\n', b'X=1\nX=1\nY=2\nSCREEN=0\n',
                        b'X=1\nY=2\nSCREEN=unknown\n'):
            commands = []
            def run(args):
                commands.append(args)
                return pointer
            backend._run = run
            with self.assertRaisesRegex(ToolError, 'no move submitted'):
                backend.move(10, 20)
            self.assertEqual(commands, [['xdotool', 'getmouselocation', '--shell']])

    async def test_x11_same_xy_on_another_screen_is_not_a_noop(self):
        backend = _X11({'display': ':fixture'})
        backend._check = lambda: None
        backend.capabilities = lambda: {'logical_size': [800, 600]}
        commands = []
        def run(args):
            commands.append(args)
            return b'X=10\nY=20\nSCREEN=1\nWINDOW=0\n'
        backend._run = run
        backend.move(10, 20)
        self.assertEqual(commands[-1], ['xdotool', 'mousemove', '--sync', '10', '20'])

    async def test_xwayland_is_not_claimed_as_full_desktop(self):
        backend = _X11({'display': ':fixture'})
        backend._run = lambda *args, **kwargs: b'XTEST XWAYLAND'
        self.assertFalse(backend.capabilities()['authorized'])
        with self.assertRaisesRegex(ToolError, 'XWayland'):
            backend.type_text('not sent')

    async def test_failed_drag_releases_button_and_does_not_retry(self):
        manager = ComputerManager({'backend': 'x11', 'display': ':fixture'})
        moves, buttons = [], []
        def move(*args):
            moves.append(args)
            if len(moves) == 2:
                raise RuntimeError('uncertain')
        manager.backend.move = move
        manager.backend.prepare_input = lambda mask: None
        manager.backend.validate_position = lambda *args: None
        manager.backend.button = lambda button, down: buttons.append((button, down))
        with self.assertRaises(ToolError):
            await manager.invoke('computer_mouse', {'action': 'drag', 'x': 1, 'y': 2, 'to_x': 3, 'to_y': 4})
        self.assertEqual(len(moves), 2)
        self.assertEqual(buttons, [('left', True), ('left', False)])
        await manager.close()

    async def test_cancelled_input_holds_serialization_until_submitted_action_finishes(self):
        import threading
        manager = ComputerManager({'backend': 'x11', 'display': ':fixture'})
        started, release, submitted = threading.Event(), threading.Event(), []
        manager.backend.prepare_input = lambda mask: None
        def type_text(text, *options):
            started.set()
            release.wait(3)
            submitted.append(text)
        manager.backend.type_text = type_text
        first = asyncio.create_task(manager.invoke('computer_type', {'text': 'one'}))
        await asyncio.to_thread(started.wait, 2)
        first.cancel()
        second = asyncio.create_task(manager.invoke('computer_type', {'text': 'two'}))
        await asyncio.sleep(.05)
        self.assertEqual(submitted, [])
        self.assertTrue(manager.lock.locked())
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await first
        await second
        self.assertEqual(submitted, ['one', 'two'])
        await manager.close()


if __name__ == '__main__':
    unittest.main()
