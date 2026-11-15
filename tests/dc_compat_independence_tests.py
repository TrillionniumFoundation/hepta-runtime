# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real isolated owner entrypoint, HTTP MCP and restart; never a production port.

Set HEPTA_INDEPENDENCE_REPORT to preserve a JSON receipt. All files, URLs,
process inputs, signals and shutdown requests belong exclusively to fixtures.
The browser feedback action is covered only by a separate mocked-browser test.
"""
from __future__ import annotations
import asyncio
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[1]
ENTRYPOINT = REPOSITORY / 'deploy/hepta_computer_operator.py'
DOCUMENT_PYTHON = Path('/home/qian-qi/.local/lib/hepta-runtime/document-env-formats-20261006/bin/python')
CATALOG = REPOSITORY / 'deploy/dc_compat/catalog.json'
FORBIDDEN_PATH_PARTS = ('node_modules', '/desktop-commander/', '/dc-0.2.52', '/.npm/')
PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII='

# Run the actual deploy entrypoint and retain import/exec evidence after clean
# shutdown. The bootstrap does not replace the operator, registry or providers.
BOOTSTRAP = '''import json,os,runpy,sys
entry,audit=sys.argv[1:3]
sys.argv=[entry]+sys.argv[3:]
sys.path.insert(0,os.path.dirname(entry))
launches=[]
def record(event,args):
 if event=='subprocess.Popen':
  launches.append({'executable':str(args[0]),'arguments':args[1]})
sys.addaudithook(record)
try:
 runpy.run_path(entry,run_name='__main__')
finally:
 modules={name:str(value.__file__) for name,value in tuple(sys.modules.items()) if getattr(value,'__file__',None)}
 with open(audit,'x') as output:
  json.dump({'pid':os.getpid(),'entrypoint':entry,'modules':modules,'launches':launches},output)
'''


def result_text(result):
    return '\n'.join(block['text'] for block in result.get('content', []) if block.get('type') == 'text')


def original_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


class OwnedDaemon:
    def __init__(self, root):
        self.root = root
        self.state, self.workspace = root / 'state', root / 'workspace'
        self.state.mkdir(mode=0o700)
        self.workspace.mkdir(mode=0o700)
        self.token = secrets.token_hex(32)
        self.token_path = root / 'fixture-token'
        self.token_path.write_text(self.token)
        self.token_path.chmod(0o600)
        self.settings = root / 'initial-settings.json'
        self.settings.write_text(json.dumps({'allowedDirectories': [str(self.workspace)],
            'defaultShell': '/bin/sh', 'backend': 'portal', 'session_type': 'wayland',
            'telemetryEnabled': False}))
        self.settings.chmod(0o600)
        self.identity = self.state.stat()
        self.generation, self.process, self.session, self.serial = 0, None, None, 0
        self.called, self.trees, self.audits, self.daemon_logs = set(), [], [], []

    def start(self):
        self.generation += 1
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            self.port = reserve.getsockname()[1]
        if self.port in (8790, 8791, 8792, 8793, 8794):
            raise AssertionError('fixture refused a reserved production port')
        self.url = f'http://127.0.0.1:{self.port}/mcp'
        self.audit_path = self.root / f'imports-{self.generation}.json'
        log_path = self.root / f'daemon-{self.generation}.log'
        self.log = log_path.open('wb')
        self.daemon_logs.append(log_path)
        environment = dict(os.environ)
        for key in ('PYTHONPATH', 'PYTHONHOME', 'NODE_PATH', 'NODE_OPTIONS', 'BROWSER',
                    'DBUS_SESSION_BUS_ADDRESS', 'DISPLAY', 'WAYLAND_DISPLAY'):
            environment.pop(key, None)
        # Only read-only capability discovery is exercised. A deliberately
        # absent fixture bus prevents contacting the actual desktop portal.
        environment['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + str(self.root / 'absent-fixture-bus')
        environment['PATH'] = '/usr/local/bin:/usr/bin:/bin'
        command = [sys.executable, '-I', '-c', BOOTSTRAP, str(ENTRYPOINT), str(self.audit_path),
            '--state', str(self.state), '--workspace', str(self.workspace),
            '--token-file', str(self.token_path), '--document-python', str(DOCUMENT_PYTHON),
            '--port', str(self.port), '--initial-settings', str(self.settings),
            '--state-device', str(self.identity.st_dev), '--state-inode', str(self.identity.st_ino),
            '--acknowledge-full-operator']
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=self.log,
                                        stderr=subprocess.STDOUT, env=environment, start_new_session=True)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError('fixture entrypoint exited: ' + log_path.read_text(errors='replace'))
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{self.port}/health', timeout=.2) as response:
                    self.health = json.loads(response.read())
                break
            except (OSError, urllib.error.URLError):
                time.sleep(.03)
        else:
            raise AssertionError('fixture readiness timed out')
        self.session = None
        initialized = self.rpc('initialize', {'protocolVersion': '2025-11-25',
            'clientInfo': {'name': 'owned-independence-fixture', 'version': '1'}})
        if initialized.get('serverInfo', {}).get('name') != 'hepta-computer-operator':
            raise AssertionError('unexpected fixture owner')
        self.rpc('notifications/initialized', {}, notification=True)

    def rpc(self, method, parameters, *, notification=False, request_id=None, headers=None):
        self.serial += 1
        request = {'jsonrpc': '2.0', 'method': method, 'params': parameters}
        if not notification:
            request['id'] = self.serial if request_id is None else request_id
        values = {'Content-Type': 'application/json', 'Accept': 'application/json',
                  'Authorization': 'Bearer ' + self.token, 'MCP-Protocol-Version': '2025-11-25'}
        if self.session:
            values['Mcp-Session-Id'] = self.session
        values.update(headers or {})
        with urllib.request.urlopen(urllib.request.Request(self.url, data=original_bytes(request), headers=values), timeout=35) as response:
            self.session = response.headers.get('Mcp-Session-Id', self.session)
            raw = response.read()
        if notification:
            if raw: raise AssertionError('notification unexpectedly produced an RPC result')
            return None
        value = json.loads(raw)
        if value.get('id') != request['id'] or value.get('jsonrpc') != '2.0' or 'error' in value:
            raise AssertionError('fixture RPC refused or malformed: ' + str(value.get('error')))
        return value['result']

    def call(self, name, arguments=None, *, allow_error=False, resolve=True):
        self.called.add(name)
        result = self.rpc('tools/call', {'name': name, 'arguments': arguments or {}})
        if resolve and name not in ('get_tool_result', 'hepta_call_result_page'):
            try: handle = json.loads(result_text(result))
            except (ValueError, TypeError): handle = None
            if isinstance(handle, dict) and handle.get('status') == 'running' and str(handle.get('call_id', '')).startswith('hepta-call-'):
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    retained = json.loads(result_text(self.call('get_tool_result', {'call_id': handle['call_id']}, resolve=False)))
                    if retained['status'] not in ('accepted', 'executing', 'running'):
                        if 'result' not in retained:
                            raise AssertionError('background fixture result has no direct content')
                        result = retained['result']; break
                    time.sleep(.03)
                else: raise AssertionError('owned background result timed out')
        if not allow_error and result.get('isError'):
            raise AssertionError(name + ': ' + result_text(result))
        return result

    def latest(self, tool):
        rows = json.loads(result_text(self.call('get_recent_tool_calls', {'toolName': tool, 'maxResults': 1000})).split('\n\n', 1)[1])
        if not rows: raise AssertionError('missing owned call history for ' + tool)
        return rows[-1]

    def pages(self, identity, limit=137003):
        raw, offset = bytearray(), 0
        while True:
            page = json.loads(result_text(self.call('hepta_call_result_page', {'call_id': identity, 'offset': offset, 'limit': limit})))
            if page['offset'] != offset or page['next_offset'] <= offset and not page['eof']:
                raise AssertionError('non-progressing immutable byte page')
            raw.extend(base64.b64decode(page['data_base64'], validate=True))
            offset = page['next_offset']
            if page['eof']:
                if len(raw) != page['total_bytes'] or hashlib.sha256(raw).hexdigest() != page['sha256']:
                    raise AssertionError('original result byte identity mismatch')
                return bytes(raw), page['sha256']

    def tree(self):
        rows, pending = [], [self.process.pid]
        while pending:
            pid = pending.pop()
            try:
                command = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
                executable = os.readlink(Path('/proc') / str(pid) / 'exe')
                children = set()
                for task in (Path('/proc') / str(pid) / 'task').iterdir():
                    try: children.update((task / 'children').read_text().split())
                    except FileNotFoundError: pass
            except (FileNotFoundError, ProcessLookupError):
                continue
            rows.append({'pid': pid, 'executable': executable, 'arguments': [part.decode(errors='replace') for part in command if part]})
            pending.extend(map(int, children))
        self.trees.append(rows)
        return rows

    def wait_shutdown(self):
        self.process.wait(timeout=15)
        if self.process.returncode != 0:
            raise AssertionError('owned daemon shutdown failed: ' + str(self.process.returncode))
        self.log.close()
        audit = json.loads(self.audit_path.read_bytes())
        for module_path in audit['modules'].values():
            if any(part in module_path for part in FORBIDDEN_PATH_PARTS):
                raise AssertionError('DC/vendor module was loaded: ' + module_path)
        for event in audit['launches']:
            if any(part in json.dumps(event) for part in FORBIDDEN_PATH_PARTS):
                raise AssertionError('DC/vendor executable was launched')
        if 'dc_compat.engine' not in audit['modules'] or 'dc_compat.filesystem' not in audit['modules']:
            raise AssertionError('real independent providers were not loaded')
        self.audits.append(audit)

    def cleanup(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=3)
        if hasattr(self, 'log') and not self.log.closed:
            self.log.close()


class Independence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DOCUMENT_PYTHON.is_file():
            raise unittest.SkipTest('independent document format runtime is unavailable')

    def test_real_entrypoint_http_all_safe_tools_bootstrap_and_restart(self):
        receipt = {'provider': 'Hepta Runtime', 'started': time.time(), 'production_services_contacted': False,
                   'browser_opened': False, 'gui_actions': [], 'checks': []}
        with tempfile.TemporaryDirectory(prefix='hepta-independent-owned-') as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            owner = OwnedDaemon(root)
            http_fixture = None
            try:
                owner.start()
                tools = owner.rpc('tools/list', {})['tools']
                advertised = {tool['name'] for tool in tools}
                catalog = json.loads(CATALOG.read_bytes())
                compatible = {tool['name'] for tool in catalog['tools'] + catalog['cloud_application_tools']}
                self.assertEqual(len(compatible), 32)
                self.assertTrue(compatible <= advertised)
                self.assertEqual(owner.health['tools'], owner.health['implemented'])
                self.assertEqual(owner.health['tools'], len(tools))
                for headers, status in [({'Authorization': 'Bearer wrong-fixture-token'}, 401),
                                        ({'Origin': 'https://untrusted.invalid'}, 403),
                                        ({'Mcp-Session-Id': 'unknown-fixture-session'}, 404)]:
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        owner.rpc('tools/list', {}, headers=headers)
                    self.assertEqual(error.exception.code, status)
                receipt['checks'].append('real_entrypoint_private_auth_catalog_and_pinned_state')

                owner.call('create_directory', {'path': 'nested/owned'})
                owner.call('write_file', {'path': 'nested/owned/source.txt', 'content': 'alpha\nneedle one\nomega\n'})
                first_write = owner.latest('write_file')
                owner.call('write_file', {'path': 'nested/owned/source.txt', 'content': 'tail\n', 'mode': 'append'})
                owner.call('edit_block', {'file_path': 'nested/owned/source.txt', 'old_string': 'alpha', 'new_string': 'ALPHA'})
                owner.call('move_file', {'source': 'nested/owned/source.txt', 'destination': 'nested/owned/moved.txt'})
                expected_text = 'ALPHA\nneedle one\nomega\ntail\n'
                self.assertEqual((owner.workspace / 'nested/owned/moved.txt').read_text(), expected_text)
                read = owner.call('read_file', {'path': 'nested/owned/moved.txt', 'offset': -2, 'length': 2})
                self.assertIn('tail', result_text(read))
                listing = owner.call('list_directory', {'path': 'nested', 'depth': 3})
                self.assertIn('moved.txt', result_text(listing))
                self.assertIn('size', result_text(owner.call('get_file_info', {'path': 'nested/owned/moved.txt'})).lower())
                owner.call('write_file', {'path': 'pixel.png', 'content': PNG})
                mixed = owner.call('read_multiple_files', {'paths': ['nested/owned/moved.txt', 'pixel.png', 'absent-fixture.txt']})
                self.assertTrue(any(block.get('type') == 'image' for block in mixed['content']))
                self.assertIn('Error', result_text(mixed)); self.assertIn('ALPHA', result_text(mixed))
                owner.call('write_file', {'path': 'fixture.docx', 'content': 'Independent DOCX needle document'})
                self.assertIn('Independent DOCX', result_text(owner.call('read_file', {'path': 'fixture.docx'})))
                owner.call('write_pdf', {'path': 'fixture.pdf', 'content': '# Independent fixture\n\nPDF original proof 2091.'})
                self.assertTrue((owner.workspace / 'fixture.pdf').read_bytes().startswith(b'%PDF'))
                self.assertIn('PDF original proof 2091', result_text(owner.call('read_file', {'path': 'fixture.pdf'})))
                class OwnFiles(http.server.SimpleHTTPRequestHandler):
                    def __init__(self, *args, **kwargs):
                        super().__init__(*args, directory=str(owner.workspace), **kwargs)
                    def log_message(self, *_): pass
                http_fixture = http.server.ThreadingHTTPServer(('127.0.0.1', 0), OwnFiles)
                web_thread = threading.Thread(target=http_fixture.serve_forever, daemon=True)
                web_thread.start()
                base_url = 'http://127.0.0.1:' + str(http_fixture.server_address[1])
                url_text = owner.call('read_file', {'path': base_url + '/nested/owned/moved.txt', 'isUrl': True})
                self.assertIn('needle one', result_text(url_text))
                url_image = owner.call('read_file', {'path': base_url + '/pixel.png', 'isUrl': True})
                self.assertTrue(any(block.get('type') == 'image' for block in url_image['content']))
                self.assertIn('2091', result_text(owner.call('read_file', {'path': base_url + '/fixture.pdf', 'isUrl': True})))
                receipt['checks'].append('nine_filesystem_tools_mixed_errors_image_docx_pdf_and_owned_http_urls')

                def python_command(script):
                    return 'exec ' + shlex.quote(sys.executable) + ' -u -c ' + shlex.quote(script)
                completed = owner.call('start_process', {'command': python_command("print('ORIGINAL-STDOUT');import sys;print('ORIGINAL-STDERR',file=sys.stderr)"), 'timeout_ms': 1000})
                completed_pid = int(re.search(r'PID (\d+)', result_text(completed))[1])
                completed_output = owner.call('read_process_output', {'pid': completed_pid, 'offset': 0, 'length': 10, 'timeout_ms': 0})
                self.assertIn('ORIGINAL-STDERR', result_text(completed_output))
                repl = owner.call('start_process', {'command': python_command("import sys;print('ready> ',end='',flush=True)\nfor line in sys.stdin:\n print('echo:'+line.strip());print('ready> ',end='',flush=True)"), 'timeout_ms': 1000})
                repl_pid = int(re.search(r'PID (\d+)', result_text(repl))[1])
                echoed = owner.call('interact_with_process', {'pid': repl_pid, 'input': 'owned-pipe-input', 'timeout_ms': 1000})
                self.assertIn('echo:owned-pipe-input', result_text(echoed))
                self.assertIn(str(repl_pid), result_text(owner.call('list_sessions')))
                process_listing = result_text(owner.call('list_processes'))
                self.assertIn('PID: ' + str(repl_pid), process_listing)
                tree = owner.tree()
                self.assertIn(repl_pid, [row['pid'] for row in tree])
                self.assertFalse(any(any(part in row['executable'] for part in FORBIDDEN_PATH_PARTS) for row in tree))
                owner.call('force_terminate', {'pid': repl_pid})
                sleeper = owner.call('start_process', {'command': python_command('import time;time.sleep(30)'), 'timeout_ms': 0})
                sleeper_pid = int(re.search(r'PID (\d+)', result_text(sleeper))[1])
                owner.call('kill_process', {'pid': sleeper_pid})
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and str(sleeper_pid) in result_text(owner.call('list_sessions')):
                    time.sleep(.02)
                self.assertNotIn(str(sleeper_pid), result_text(owner.call('list_sessions')))
                receipt['checks'].append('real_owned_stdout_stderr_stdin_sessions_force_and_host_kill')

                search_data = ''.join('needle-line-' + str(index) + '\n' for index in range(41))
                owner.call('write_file', {'path': 'search.txt', 'content': search_data})
                started = owner.call('start_search', {'path': str(owner.workspace / 'search.txt'), 'pattern': 'needle-line-[0-9]+',
                    'searchType': 'content', 'contextLines': 0, 'timeout_ms': 0, 'maxResults': 0})
                search_id = re.search(r'session: (search_[0-9]+_[0-9]+)', result_text(started))[1]
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    page = owner.call('get_more_search_results', {'sessionId': search_id, 'offset': 0, 'length': 7})
                    if 'Status: COMPLETED' in result_text(page): break
                    time.sleep(.02)
                self.assertIn('41 matches', result_text(page))
                self.assertEqual(result_text(page).count('📄 '), 7)
                second = owner.call('get_more_search_results', {'sessionId': search_id, 'offset': 7, 'length': 7})
                self.assertIn('needle-line-7', result_text(second))
                tail_before = owner.call('get_more_search_results', {'sessionId': search_id, 'offset': -3, 'length': 1})
                self.assertIn(search_id, result_text(owner.call('list_searches')))
                # Large fixture ensures cancellation is exercised on actual rg,
                # not by sending a stop request only to an already finished job.
                large_search = owner.workspace / 'large-search.txt'
                with large_search.open('wb') as output:
                    for _ in range(100): output.write(b'needle-stop\n' * 10000)
                running = owner.call('start_search', {'path': str(large_search), 'pattern': 'needle-stop',
                    'searchType': 'content', 'contextLines': 0, 'timeout_ms': 0, 'maxResults': 0})
                stop_id = re.search(r'session: (search_[0-9]+_[0-9]+)', result_text(running))[1]
                self.assertIn('RUNNING', result_text(running))
                owner.call('stop_search', {'sessionId': stop_id})
                receipt['checks'].append('real_rg_progressive_explicit_pages_negative_tail_and_running_cancel')

                config_before = owner.call('get_config')
                self.assertEqual(config_before['structuredContent']['config']['provider'], 'Hepta Runtime')
                owner.call('set_config_value', {'key': 'fileReadLineLimit', 'value': 2345})
                self.assertEqual(owner.call('get_config')['structuredContent']['config']['fileReadLineLimit'], 2345)
                device = json.loads(result_text(owner.call('list_devices')))['devices'][0]
                who = json.loads(result_text(owner.call('who_am_i')))
                self.assertEqual(who['device_id'], device['id'])
                self.assertIsNone(who['vendor_subscription'])
                self.assertEqual(json.loads(result_text(owner.call('ping', {'deviceId': device['id']})))['message'], 'pong')
                self.assertIn('repository', result_text(owner.call('get_prompts', {'action': 'get_prompt', 'promptId': 'onb2_02'})))
                capabilities = owner.call('computer_capabilities')
                self.assertFalse(capabilities['structuredContent']['result'].get('authorized', False))
                self.assertEqual(capabilities['structuredContent']['result']['backend'], 'wayland_portal')
                receipt['checks'].append('configuration_identity_device_ping_prompts_and_non_authorizing_capabilities')

                # A genuine slow process wait passes through the real owner
                # background response and its durable result API.
                background = owner.call('start_process', {'command': python_command("import time;time.sleep(1.5);print('BACKGROUND-ORIGINAL')"),
                    'timeout_ms': 5000}, resolve=False)
                handle = json.loads(result_text(background))
                self.assertEqual(handle['status'], 'running')
                background_id = handle['call_id']
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    retained_background = json.loads(result_text(owner.call('get_tool_result', {'call_id': background_id})))
                    if retained_background['status'] == 'completed': break
                    time.sleep(.03)
                self.assertIn('BACKGROUND-ORIGINAL', result_text(retained_background['result']))
                self.assertIn(background_id, result_text(owner.call('list_remote_tool_calls', {'limit': 1000})))

                huge = '独立-original-' * 160000
                owner.call('write_file', {'path': 'large-original.txt', 'content': huge})
                large_original = owner.call('read_file', {'path': 'large-original.txt', 'length': 1})
                large_identity = owner.latest('read_file')['call_id']
                encoded = original_bytes(large_original)
                self.assertGreater(len(encoded), 2 * 1024 * 1024)
                meta = json.loads(result_text(owner.call('get_tool_result', {'call_id': large_identity})))
                self.assertIn('result_reference', meta)
                paged_before, digest_before = owner.pages(large_identity)
                self.assertEqual(paged_before, encoded)
                for _ in range(140): owner.call('get_config')
                stats_before = json.loads(result_text(owner.call('get_usage_stats')))
                self.assertGreater(stats_before['successfulCalls'], 128)
                self.assertIsNone(stats_before['fixedLifetimeSlotLimit'])
                first_result = json.loads(result_text(owner.call('get_tool_result', {'call_id': first_write['call_id']})))
                self.assertEqual(first_result['status'], 'completed')
                self.assertEqual(first_result['result'], first_write['output'])
                receipt['checks'].append('real_background_full_result_pages_and_more_than_128_http_calls_no_eviction')

                owner.call('shutdown', {'deviceId': device['id']})
                owner.wait_shutdown()
                self.assertEqual((owner.state.stat().st_dev, owner.state.stat().st_ino), (owner.identity.st_dev, owner.identity.st_ino))
                owner.start()
                self.assertEqual(owner.call('get_config')['structuredContent']['config']['fileReadLineLimit'], 2345)
                stats_after = json.loads(result_text(owner.call('get_usage_stats')))
                self.assertGreater(stats_after['successfulCalls'], stats_before['successfulCalls'])
                self.assertEqual(json.loads(result_text(owner.call('get_tool_result', {'call_id': first_write['call_id']}))), first_result)
                self.assertEqual(json.loads(result_text(owner.call('get_tool_result', {'call_id': background_id}))), retained_background)
                paged_after, digest_after = owner.pages(large_identity, limit=196613)
                self.assertEqual(paged_after, paged_before)
                self.assertEqual(digest_after, digest_before)
                self.assertEqual(owner.call('read_process_output', {'pid': completed_pid, 'offset': 0, 'length': 10, 'timeout_ms': 0}), completed_output)
                after_tail = owner.call('get_more_search_results', {'sessionId': search_id, 'offset': -3, 'length': 1})
                self.assertEqual([line for line in result_text(after_tail).splitlines() if line.startswith('📄')],
                                 [line for line in result_text(tail_before).splitlines() if line.startswith('📄')])
                self.assertEqual((owner.workspace / 'nested/owned/moved.txt').read_text(), expected_text)
                self.assertEqual(result_text(owner.call('list_sessions')), 'No active sessions')
                refusal = owner.call('interact_with_process', {'pid': completed_pid, 'input': 'never-replay'}, allow_error=True)
                self.assertTrue(refusal.get('isError'))
                self.assertIn('unavailable', result_text(refusal))
                owner.call('shutdown', {'deviceId': device['id']})
                owner.wait_shutdown()
                self.assertEqual(compatible - owner.called, {'give_feedback_to_desktop_commander'})
                self.assertEqual(len(owner.audits), 2)
                self.assertTrue(any('rg' in event['executable'] for event in owner.audits[0]['launches']))
                self.assertTrue(any(str(DOCUMENT_PYTHON) == event['executable'] for event in owner.audits[0]['launches']))
                receipt['checks'].append('real_restart_same_state_original_bytes_history_config_search_and_no_pipe_adoption')
                receipt.update(success=True, completed=time.time(), http_compatible_tools=sorted(compatible & owner.called),
                    http_compatible_count=len(compatible & owner.called), mock_only_tools=['give_feedback_to_desktop_commander'],
                    extension_tools=sorted(owner.called - compatible), independent_generations=len(owner.audits),
                    module_files=[audit['modules'] for audit in owner.audits],
                    child_launches=[audit['launches'] for audit in owner.audits], observed_process_trees=owner.trees,
                    original_result_bytes=len(encoded), original_result_sha256=digest_before,
                    successful_calls_before_restart=stats_before['successfulCalls'])
            finally:
                owner.cleanup()
                if http_fixture is not None:
                    http_fixture.shutdown(); http_fixture.server_close()
                report_path = os.environ.get('HEPTA_INDEPENDENCE_REPORT')
                if report_path:
                    receipt['daemon_logs'] = [path.read_text(errors='replace') for path in owner.daemon_logs]
                    path = Path(report_path)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, 'w') as output:
                        json.dump(receipt, output, ensure_ascii=False, indent=2)

    def test_feedback_opens_only_mocked_fixture_browser(self):
        sys.path.insert(0, str(REPOSITORY / 'deploy'))
        from dc_compat.engine import Operator
        async def fixture():
            with tempfile.TemporaryDirectory(prefix='hepta-feedback-owned-') as temporary:
                root = Path(temporary)
                engine = Operator(root / 'state', root, enable_computer=False, include_providers=False,
                                  initial={'feedbackUrl': 'https://feedback.fixture.invalid/owned'})
                try:
                    with mock.patch('dc_compat.engine.webbrowser.open', return_value=True) as opened:
                        result = await engine.call('give_feedback_to_desktop_commander', {}, 'owned-feedback-rpc')
                    opened.assert_called_once_with('https://feedback.fixture.invalid/owned')
                    self.assertTrue(json.loads(result_text(result))['browser_opened'])
                finally:
                    await engine.close()
        asyncio.run(fixture())


if __name__ == '__main__':
    unittest.main()
