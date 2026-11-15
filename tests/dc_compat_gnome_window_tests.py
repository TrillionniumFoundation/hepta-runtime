# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""GNOME bridge policy + real GJS/Gio private-bus tests; no live Shell changes."""
import asyncio
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'deploy'))
from dc_compat.gnome_window_provider import GnomeWindowManager, GNOME_WINDOW_TOOLS, read_private_config
from dc_compat.gnome_window_install import build_package, prepare_config
from dc_compat.registry import ToolError

EXTENSION = ROOT / 'deploy/dc_compat/gnome_window_extension'

FIXTURE = r'''
import Gio from 'gi://Gio';import GLib from 'gi://GLib';
import {BridgeService,readPrivateConfig} from SERVICE;
import {WindowController} from LOGIC;
const [address,configPath,eventPath]=ARGV;
const config=readPrivateConfig(configPath);
const bus=Gio.DBusConnection.new_for_address_sync(address,Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT|Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,null,null);
bus.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','RequestName',new GLib.Variant('(su)',['org.gnome.Shell',0]),null,Gio.DBusCallFlags.NONE,2000,null);
let count=0;
const windows=[100,101,102].map(sequence=>({sequence,title:'Synthetic '+sequence,appId:'hepta.fixture',pid:1,focused:false,minimized:false,workspace:0,monitor:0,frame:{x:0,y:0,width:800,height:600},clientType:sequence===101?'x11':'wayland',isFocused(){return this.focused;}}));
const controller=new WindowController({session:'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',windows:()=>windows,locked:()=>Boolean(config.test_locked),maxReceipts:config.test_capacity??2048,activate:window=>{count++;window.focused=true;GLib.file_set_contents(eventPath,JSON.stringify({ready:true,count}));if(window.sequence===102)throw new Error('after effect failure');}});
const service=new BridgeService(bus,config,controller);
GLib.timeout_add(GLib.PRIORITY_DEFAULT,50,()=>{GLib.file_set_contents(eventPath,JSON.stringify({ready:true,count}));return GLib.SOURCE_REMOVE;});
new GLib.MainLoop(null,false).run();
'''


class PrivateBusTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        if not all(shutil.which(name) for name in ['gjs', 'dbus-daemon']):
            self.skipTest('GJS/private D-Bus dependencies unavailable')
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-gnome-fixture-')
        self.path = pathlib.Path(self.temp.name)
        self.config = self.path / 'config.json'
        self.config.write_text(json.dumps({'version': 1, 'profile_id': 'fixture', 'token': '1' * 64}))
        self.config.chmod(0o600)
        self.bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--print-address=1'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.address = (await asyncio.wait_for(asyncio.to_thread(self.bus.stdout.readline), 5)).decode().strip()
        self.assertNotEqual(self.address, os.environ.get('DBUS_SESSION_BUS_ADDRESS'))
        source = FIXTURE.replace('SERVICE', json.dumps((EXTENSION / 'service.js').as_uri())).replace('LOGIC', json.dumps((EXTENSION / 'logic.js').as_uri()))
        (self.path / 'fixture.js').write_text(source)
        self.process = None
        self.manager = GnomeWindowManager({'dbus_address': self.address, 'token_path': str(self.config), 'profile_id': 'fixture'})

    async def start(self, **options):
        value = json.loads(self.config.read_text())
        value.update(options)
        self.config.write_text(json.dumps(value))
        self.process = subprocess.Popen(['gjs', '-m', str(self.path / 'fixture.js'), self.address, str(self.config), str(self.path / 'events.json')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            if self.process.poll() is not None:
                self.fail('Private GJS fixture failed: ' + self.process.stderr.read().decode())
            if (self.path / 'events.json').exists():
                return
            await asyncio.sleep(.03)
        self.fail('Private GJS fixture did not become ready')

    async def asyncTearDown(self):
        if hasattr(self, 'manager'):
            await self.manager.close()
        for name in ['process', 'bus']:
            proc = getattr(self, name, None)
            if proc:
                proc.terminate()
                await asyncio.to_thread(proc.wait, 5)
                for pipe in [proc.stdout, proc.stderr]:
                    if pipe:
                        pipe.close()
        if hasattr(self, 'temp'):
            self.temp.cleanup()

    async def test_actual_shared_gjs_service_lists_wayland_and_x11(self):
        await self.start()
        capabilities = await self.manager.capabilities()
        self.assertTrue(capabilities['available'], capabilities)
        self.assertTrue(capabilities['features']['window_list'])
        result = await self.manager.invoke('computer_window', {'action': 'list'})
        windows = result['structuredContent']['windows']
        self.assertEqual(len(windows), 3)
        self.assertEqual({window['client_type'] for window in windows}, {'x11', 'wayland'})
        self.assertEqual(json.loads((self.path / 'events.json').read_text())['count'], 0)

    async def test_focus_is_exact_and_duplicate_receipt_does_not_activate(self):
        await self.start()
        request = 'a' * 32 + ':1'
        args = {'action': 'focus', 'window_id': 'a' * 32 + ':100', 'request_id': request}
        result = await self.manager.invoke('computer_window', args)
        self.assertTrue(result['structuredContent']['focus_observed'])
        reused = await self.manager.invoke('computer_window', args)
        self.assertTrue(reused['structuredContent']['receipt_reused'])
        self.assertEqual(json.loads((self.path / 'events.json').read_text())['count'], 1)
        with self.assertRaises(ToolError):
            await self.manager.invoke('computer_window', dict(args, window_id='a' * 32 + ':101'))
        self.assertEqual(json.loads((self.path / 'events.json').read_text())['count'], 1)

    async def test_old_session_or_closed_window_is_refused(self):
        await self.start()
        for identity in ['b' * 32 + ':100', 'a' * 32 + ':999', '100']:
            with self.assertRaises(ToolError):
                await self.manager.invoke('computer_window', {'action': 'focus', 'window_id': identity})
        self.assertEqual(json.loads((self.path / 'events.json').read_text())['count'], 0)

    async def test_ambiguous_effect_returns_unknown_receipt_without_replay(self):
        await self.start()
        args = {'action': 'focus', 'window_id': 'a' * 32 + ':102', 'request_id': 'a' * 32 + ':1'}
        first = await self.manager.invoke('computer_window', args)
        second = await self.manager.invoke('computer_window', args)
        self.assertEqual(first['structuredContent']['outcome'], 'unknown')
        self.assertTrue(second['structuredContent']['receipt_reused'])
        self.assertEqual(json.loads((self.path / 'events.json').read_text())['count'], 1)

    async def test_locked_desktop_refuses_metadata_and_focus(self):
        await self.start(test_locked=True)
        capabilities = await self.manager.capabilities()
        self.assertFalse(capabilities['features']['window_list'])
        for args in [{'action': 'list'}, {'action': 'focus', 'window_id': 'a' * 32 + ':100'}]:
            with self.assertRaisesRegex(ToolError, 'locked'):
                await self.manager.invoke('computer_window', args)

    async def test_wrong_private_token_or_profile_refuses(self):
        await self.start()
        old = json.loads(self.config.read_text())
        self.config.write_text(json.dumps(dict(old, token='2' * 64)))
        self.assertFalse((await self.manager.capabilities())['available'])
        self.config.write_text(json.dumps(dict(old, profile_id='foreign')))
        with self.assertRaises(ToolError):
            await self.manager.invoke('computer_window', {'action': 'list'})
        self.assertEqual(json.loads((self.path / 'events.json').read_text())['count'], 0)

    async def test_focus_cache_eviction_does_not_limit_new_focus_or_replay_old_ids(self):
        await self.start(test_capacity=1)
        first = await self.manager.invoke('computer_window', {'action': 'focus', 'window_id': 'a' * 32 + ':100'})
        await self.manager.invoke('computer_window', {'action': 'focus', 'window_id': 'a' * 32 + ':101'})
        await self.manager.invoke('computer_window', {'action': 'focus', 'window_id': 'a' * 32 + ':100'})
        with self.assertRaises(ToolError):
            await self.manager.invoke('computer_window', {'action': 'focus', 'window_id': 'a' * 32 + ':100', 'request_id': first['structuredContent']['request_id']})
        self.assertEqual(json.loads((self.path / 'events.json').read_text())['count'], 3)
        capabilities = await self.manager.capabilities()
        self.assertEqual(capabilities['cached_focus_receipts'], 1)

    async def test_foreign_server_pid_fails_before_token_is_sent(self):
        await self.start()
        original = self.manager._daemon
        def mismatched(method, name):
            result = original(method, name)
            if method == 'GetConnectionUnixProcessID' and name == original('GetNameOwner', 'org.gnome.Shell'):
                # owner unique name is normally shared in the fixture, so change
                # only the second PID query (Shell identity) deterministically.
                mismatched.count += 1
                if mismatched.count % 2 == 0:
                    return result + 1
            return result
        mismatched.count = 0
        self.manager._daemon = mismatched
        self.assertFalse((await self.manager.capabilities())['available'])
        self.assertEqual(json.loads((self.path / 'events.json').read_text())['count'], 0)


class PackagingTests(unittest.TestCase):
    def test_package_is_reproducible_exact_source_and_has_no_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = pathlib.Path(directory) / 'a.zip', pathlib.Path(directory) / 'b.zip'
            first, second = build_package(a), build_package(b)
            self.assertEqual(first['sha256'], second['sha256'])
            with zipfile.ZipFile(a) as archive:
                self.assertEqual(set(archive.namelist()), set(first['files']))
                for name in archive.namelist():
                    self.assertEqual(archive.read(name), (EXTENSION / name).read_bytes())
                metadata = json.loads(archive.read('metadata.json'))
                self.assertEqual(metadata['shell-version'], ['46'])
                self.assertNotIn('config.json', archive.namelist())

    def test_private_config_created_once_never_rotated_or_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'config.json'
            prepare_config(path, 'fixture')
            first = path.read_bytes()
            value = read_private_config(path, 'fixture')
            self.assertEqual(len(value['token']), 64)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                prepare_config(path, 'fixture')
            self.assertEqual(path.read_bytes(), first)
            path.chmod(0o644)
            with self.assertRaises(ToolError):
                read_private_config(path, 'fixture')

    def test_static_extension_has_no_eval_commands_restart_or_settings_mutation(self):
        source = (EXTENSION / 'extension.js').read_text()
        for banned in ['Eval(', 'unsafe_mode', 'spawn', 'subprocess', 'set_boolean', 'reexec_self']:
            self.assertNotIn(banned, source)
        self.assertIn('Main.activateWindow', source)
        self.assertIn('get_stable_sequence', source)


if __name__ == '__main__':
    unittest.main()
