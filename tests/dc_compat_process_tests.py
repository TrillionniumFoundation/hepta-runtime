# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fresh owned processes only: original DC names, real pipes, cursor and journals."""
import asyncio
import hashlib
import io
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat import CompatServer, ProcessManager, ToolError, ToolRegistry
from dc_compat import processes as process_module

CATALOG = pathlib.Path(__file__).resolve().parents[1] / 'deploy/dc_compat/catalog.json'


def text(result):
    return result['content'][0]['text']


class Processes(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.root.chmod(0o700)
        self.manager = ProcessManager(self.root / 'state', self.root, shell='/bin/sh')
        self.registry = ToolRegistry(CATALOG)
        self.registry.add(self.manager)

    async def asyncTearDown(self):
        await asyncio.to_thread(self.manager.close)
        self.temp.cleanup()

    async def start(self, script, timeout=1000):
        command = 'exec ' + shlex.quote(sys.executable) + ' -u -c ' + shlex.quote(script)
        reply = await self.registry.invoke('start_process', {'command': command, 'timeout_ms': timeout})
        self.assertNotIn('isError', reply, text(reply))
        return int(re.search(r'PID (\d+)', text(reply))[1]), reply

    async def test_exact_schema_catalog_has_26_local_and_6_separate_cloud_tools(self):
        value = json.loads(CATALOG.read_bytes())
        self.assertEqual(len(value['tools']), 26)
        self.assertEqual(len(value['cloud_application_tools']), 6)
        self.assertEqual(value['connected_application']['npm_only_tool_names'], ['get_prompts'])
        self.assertTrue(self.manager.tool_names <= {t['name'] for t in self.registry.tools()})
        original = next(t for t in value['tools'] if t['name'] == 'start_process')
        self.assertEqual(original['inputSchema']['required'], ['command', 'timeout_ms'])
        before = self.registry.tools()
        server = CompatServer(self.registry)
        await server.dispatch({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}})
        result = await server.dispatch({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
        self.assertEqual(result['result']['tools'], before)

    async def test_real_stdout_stderr_exit_code_and_absolute_negative_offsets(self):
        pid, initial = await self.start("import sys;print('L0');print('L1');print('L2');print('L3');print('ERR',file=sys.stderr);sys.exit(7)")
        self.assertIn('L0', text(initial)); self.assertIn('ERR', text(initial))
        result = await self.registry.invoke('read_process_output', {'pid': pid, 'offset': 1, 'length': 2})
        self.assertIn('L1\nL2', text(result))
        self.assertIn('exit code 7', text(result))
        tail = await self.registry.invoke('read_process_output', {'pid': pid, 'offset': -3, 'length': 1})
        self.assertIn('Reading last 1 lines', text(tail))
        self.assertNotIn('L0', text(tail))
        directory = next((self.root / 'state').glob('[0-9a-f]' * 32))
        self.assertIn(b'ERR', (directory / 'stderr.log').read_bytes())
        self.assertIn(b'L0', (directory / 'stdout.log').read_bytes())

    async def test_live_stdin_interact_prompt_and_new_output_cursor(self):
        pid, initial = await self.start("import sys;print('ready> ',end='',flush=True)\nfor line in sys.stdin:\n print('echo:'+line.strip());print('ready> ',end='',flush=True)")
        self.assertIn('waiting for input', text(initial))
        first = await self.registry.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0})
        self.assertIn('ready>', text(first))
        interaction = await self.registry.invoke('interact_with_process', {'pid': pid, 'input': 'hello', 'timeout_ms': 1000})
        self.assertIn('echo:hello', text(interaction))
        read = await self.registry.invoke('read_process_output', {'pid': pid, 'offset': -2, 'length': 2})
        self.assertIn('echo:hello', text(read))
        sessions = await self.registry.invoke('list_sessions', {})
        self.assertIn(str(pid), text(sessions))
        stopped = await self.registry.invoke('force_terminate', {'pid': pid})
        self.assertIn('termination', text(stopped))
        await asyncio.sleep(0.1)
        self.assertEqual(text(await self.registry.invoke('list_sessions', {})), 'No active sessions')

    async def test_no_wait_input_and_durable_before_effect_record(self):
        pid, _ = await self.start("import sys,time;print('ready> ',flush=True)\nfor line in sys.stdin:\n time.sleep(.05);print('got:'+line.strip(),flush=True)")
        reply = await self.registry.invoke('interact_with_process', {'pid': pid, 'input': 'fresh', 'wait_for_prompt': False})
        self.assertIn('Input sent', text(reply))
        await asyncio.sleep(0.1)
        data = self.manager.sessions[pid].metadata
        self.assertEqual(data['last_input']['state'], 'written')
        self.assertEqual(data['last_input']['bytes'], 5)
        output = await self.registry.invoke('read_process_output', {'pid': pid, 'offset': -4, 'timeout_ms': 0})
        self.assertIn('got:fresh', text(output))

    async def test_completed_output_survives_manager_restart_without_reexecution(self):
        count = self.root / 'count'
        pid, _ = await self.start(f"from pathlib import Path;p=Path({str(count)!r});p.write_text('once');print('saved-output')")
        await asyncio.to_thread(self.manager.close)
        self.manager = ProcessManager(self.root / 'state', self.root, shell='/bin/sh')
        reply = await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0})
        self.assertIn('saved-output', text(reply)); self.assertIn('exit code 0', text(reply))
        self.assertEqual(count.read_text(), 'once')
        with self.assertRaises(ToolError): await self.manager.invoke('interact_with_process', {'pid': pid, 'input': 'never'})
        self.assertEqual(text(await self.manager.invoke('force_terminate', {'pid': pid})), f'No active session found for PID {pid}')

    async def test_unknown_prior_journal_does_not_restore_pipe_or_spawn(self):
        pid, _ = await self.start("print('known-original')")
        await asyncio.to_thread(self.manager.close)
        path = next((self.root / 'state').glob('*/metadata.json'))
        value = json.loads(path.read_bytes()); value['state'] = 'running'; path.write_text(json.dumps(value))
        with mock.patch('dc_compat.processes.subprocess.Popen', side_effect=AssertionError('blind replay')):
            self.manager = ProcessManager(self.root / 'state', self.root, shell='/bin/sh')
            self.assertIn('state unknown', text(await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0})))
            with self.assertRaises(ToolError): await self.manager.invoke('interact_with_process', {'pid': pid, 'input': 'never'})
        self.assertEqual(text(await self.manager.invoke('list_sessions', {})), 'No active sessions')

    async def test_host_list_and_kill_touch_only_fresh_owned_fixture(self):
        fixture = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'])
        try:
            listing = await self.registry.invoke('list_processes', {})
            self.assertIn('PID: ' + str(fixture.pid), text(listing))
            reply = await self.registry.invoke('kill_process', {'pid': fixture.pid})
            self.assertIn(str(fixture.pid), text(reply))
            await asyncio.to_thread(fixture.wait, 3)
            self.assertIsNotNone(fixture.returncode)
        finally:
            if fixture.poll() is None: fixture.kill(); fixture.wait()

    async def test_schema_refusal_occurs_before_process_dispatch(self):
        with mock.patch('dc_compat.processes.subprocess.Popen', side_effect=AssertionError('must not spawn')):
            reply = await self.registry.invoke('start_process', {'command': 'unused'})
            self.assertTrue(reply['isError'])
        self.assertEqual(os.listdir(self.root / 'state'), ['manager.lock'])

    async def test_single_owner_lock_and_private_state_required(self):
        with self.assertRaises(BlockingIOError): ProcessManager(self.root / 'state', self.root)
        public = self.root / 'public'; public.mkdir(mode=0o755)
        with self.assertRaises(ToolError): ProcessManager(public, self.root)

    async def test_stdio_pipelining_preserves_exact_catalog_and_does_not_replay_id(self):
        requests = [
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
        ]
        reader = io.BytesIO(b''.join(json.dumps(row).encode() + b'\n' for row in requests))
        writer = io.BytesIO()
        await CompatServer(self.registry).serve_stdio(reader, writer)
        replies = [json.loads(row) for row in writer.getvalue().splitlines()]
        self.assertEqual(len(replies), 3)
        self.assertTrue(any(row.get('error', {}).get('message') == 'Duplicate request id; no replay' for row in replies))

    async def test_default_retains_more_than_128mib_and_restart_loads_metadata_only(self):
        # The former disk cap silently discarded this exact output. The 50MiB
        # live tail remains bounded independently of the complete disk journal.
        blocks, block_size = 1030, 128 * 1024
        pid, _ = await self.start("import os\nb=b'x'*131072\nfor _ in range(1030):\n os.write(1,b)\nos.write(1,b'\\nEND-ORIGINAL\\n')", 20000)
        session = self.manager.sessions[pid]
        await asyncio.to_thread(session.collector.join)
        directory = self.root / 'state' / session.journal_id
        expected_size = blocks * block_size + len(b'\nEND-ORIGINAL\n')
        self.assertEqual((directory / 'stdout.log').stat().st_size, expected_size)
        self.assertEqual((directory / 'combined.log').stat().st_size, expected_size)
        self.assertNotIn('durable_output_truncated', session.metadata)
        self.assertEqual(session.metadata['durable_raw_bytes'], expected_size)
        expected = hashlib.sha256()
        for _ in range(blocks): expected.update(b'x' * block_size)
        expected.update(b'\nEND-ORIGINAL\n')
        actual = hashlib.sha256()
        with (directory / 'stdout.log').open('rb') as stream:
            while chunk := stream.read(65536): actual.update(chunk)
        self.assertEqual(actual.digest(), expected.digest())
        before = text(await self.manager.invoke('read_process_output', {'pid': pid, 'offset': -2, 'length': 1, 'timeout_ms': 0}))
        self.assertIn('END-ORIGINAL', before)
        self.assertEqual(session.chars, 0)
        await asyncio.to_thread(self.manager.close)
        original_read = process_module._read_file
        names = []
        def metadata_only(directory, name, maximum):
            names.append(name)
            self.assertEqual(name, 'metadata.json', 'startup must not load historical output')
            return original_read(directory, name, maximum)
        with mock.patch.object(process_module, '_read_file', metadata_only):
            self.manager = ProcessManager(self.root / 'state', self.root)
        self.assertEqual(names, ['metadata.json'])
        after = text(await self.manager.invoke('read_process_output', {'pid': pid, 'offset': -2, 'length': 1, 'timeout_ms': 0}))
        self.assertEqual(after, before)

    async def test_long_line_is_not_split_and_schema_has_no_added_read_or_timeout_cap(self):
        pid, _ = await self.start("import os;os.write(1,b'X'*(1024*1024+17)+b'\\n'+b'L\\n'*100002)", 3600001)
        first = text(await self.manager.invoke('read_process_output', {'pid': pid, 'offset': 0, 'length': 1, 'timeout_ms': 3600001}))
        self.assertIn('total: 100004 lines', first)
        self.assertIn('X' * (1024 * 1024 + 17), first)
        large_page = text(await self.manager.invoke('read_process_output', {'pid': pid, 'offset': 1, 'length': 100001, 'timeout_ms': 3600001}))
        self.assertIn('Reading 100001 lines', large_page)
        self.assertEqual(large_page.count('L\n'), 100001)

    async def test_incomplete_utf8_eof_is_durable_and_restart_identical(self):
        pid, initial = await self.start("import os;os.write(1,b'out\\xe2\\x82');os.write(2,b'err\\xf0\\x9f')")
        session = self.manager.sessions[pid]
        await asyncio.to_thread(session.collector.join)
        directory = self.root / 'state' / session.journal_id
        self.assertEqual((directory / 'stdout.log').read_bytes(), b'out\xe2\x82')
        self.assertEqual((directory / 'stderr.log').read_bytes(), b'err\xf0\x9f')
        combined = (directory / 'combined.log').read_text()
        self.assertEqual(combined.count('\ufffd'), 2)
        self.assertIn(combined, text(initial))
        before = await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0})
        await asyncio.to_thread(self.manager.close)
        self.manager = ProcessManager(self.root / 'state', self.root)
        self.assertEqual(before, await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0}))
        self.assertEqual((directory / 'combined.log').read_text(), combined)

    async def test_only_explicit_administrator_output_budget_truncates_and_reports(self):
        self.manager.config = {'processOutputMaxBytes': 8}
        pid, _ = await self.start("import os;os.write(1,b'0123456789ABCDEF')")
        session = self.manager.sessions[pid]
        await asyncio.to_thread(session.collector.join)
        directory = self.root / 'state' / session.journal_id
        self.assertEqual((directory / 'stdout.log').read_bytes(), b'01234567')
        self.assertEqual((directory / 'combined.log').read_bytes(), b'01234567')
        result = text(await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0}))
        self.assertIn('explicit processOutputMaxBytes=8 quota was exceeded', result)
        self.assertTrue(session.metadata['durable_output_truncated'])

    async def test_pid_reuse_chooses_latest_journal_without_adopting_or_signalling(self):
        pid, _ = await self.start("print('OLDER')")
        session = self.manager.sessions[pid]
        await asyncio.to_thread(session.collector.join)
        await asyncio.to_thread(self.manager.close)
        identity = 'f' * 32
        directory = self.root / 'state' / identity
        directory.mkdir(mode=0o700)
        value = dict(session.metadata, journal_id=identity, started_at=session.metadata['started_at'] + 1,
                     state='running', command='never dispatch historical command')
        for name, raw in [('metadata.json', json.dumps(value).encode()), ('stdout.log', b'LATEST'), ('stderr.log', b''), ('combined.log', b'LATEST')]:
            path = directory / name; path.write_bytes(raw); path.chmod(0o600)
        with mock.patch.object(process_module.subprocess, 'Popen', side_effect=AssertionError('must not replay')), \
                mock.patch.object(process_module.os, 'killpg', side_effect=AssertionError('must not signal historical PID')):
            self.manager = ProcessManager(self.root / 'state', self.root)
            result = text(await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0}))
            self.assertIn('LATEST', result); self.assertNotIn('OLDER', result)
            self.assertIn('state unknown', result)
            with self.assertRaises(ToolError): await self.manager.invoke('interact_with_process', {'pid': pid, 'input': 'no'})
            self.assertIn('No active session', text(await self.manager.invoke('force_terminate', {'pid': pid})))

    async def test_config_validator_does_not_block_literal_sudo_argument(self):
        class Config:
            def __init__(self): self.commands = []
            def get(self, key, default=None): return ['sudo'] if key == 'blockedCommands' else default
            def validate_command(self, command): self.commands.append(command); return True
        config = Config(); self.manager.config = config
        _, reply = await self.start("print('sudo')")
        self.assertIn('sudo', text(reply)); self.assertEqual(len(config.commands), 1)
        config.validate_command = lambda _: False
        with mock.patch.object(process_module.subprocess, 'Popen', side_effect=AssertionError('validation must precede dispatch')):
            with self.assertRaises(ToolError):
                await self.manager.invoke('start_process', {'command': 'sudo never', 'timeout_ms': 0})

    async def test_close_serializes_inflight_spawn_and_rejects_queued_work_after_release(self):
        entered, release = threading.Event(), threading.Event()
        original_spawn = subprocess.Popen
        def paused_spawn(*args, **kwargs):
            entered.set()
            if not release.wait(5): raise AssertionError('test did not release owned spawn')
            return original_spawn(*args, **kwargs)
        with mock.patch.object(process_module.subprocess, 'Popen', paused_spawn):
            start = asyncio.create_task(self.start('import time;time.sleep(30)', 30000))
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            closed = asyncio.create_task(asyncio.to_thread(self.manager.close))
            await asyncio.sleep(.02)
            self.assertFalse(closed.done(), 'close must wait for admission ownership to settle')
            release.set()
            await asyncio.wait_for(closed, 5)
            pid, _ = await asyncio.wait_for(start, 5)
        self.assertIsNotNone(self.manager.sessions[pid].process.poll())
        self.assertEqual(self.manager._workers, 0)
        with mock.patch.object(process_module.subprocess, 'Popen', side_effect=AssertionError('spawn after close')):
            with self.assertRaises(ToolError): await self.manager.invoke('start_process', {'command': 'never', 'timeout_ms': 0})
        # Concurrent/idempotent shutdown cannot close reused numeric FDs twice.
        await asyncio.gather(asyncio.to_thread(self.manager.close), asyncio.to_thread(self.manager.close))

    async def test_close_does_not_hang_or_signal_reused_leader_when_descendant_holds_pipe(self):
        # Only this fixture's explicitly returned child PID is signalled by test
        # cleanup. The manager must not guess an exited leader's group ownership.
        pid, _ = await self.start("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);print('CHILD='+str(p.pid),flush=True)", 100)
        session = self.manager.sessions[pid]
        child = int(re.search(r'CHILD=(\d+)', session.text())[1])
        try:
            await asyncio.to_thread(session.process.wait, 3)
            with mock.patch.object(process_module.os, 'killpg', side_effect=AssertionError('exited leader must not be signalled')):
                await asyncio.wait_for(asyncio.to_thread(self.manager.close), 3)
            self.assertEqual(session.metadata['state'], 'unknown')
            self.assertTrue(session.metadata['durable_output_incomplete'])
            self.assertFalse(session.collector.is_alive())
            self.manager = ProcessManager(self.root / 'state', self.root)
            result = text(await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0}))
            self.assertIn('incomplete observed prefix', result)
            self.assertIn('CHILD=' + str(child), result)
        finally:
            try: os.kill(child, 15)
            except ProcessLookupError: pass


if __name__ == '__main__': unittest.main()
