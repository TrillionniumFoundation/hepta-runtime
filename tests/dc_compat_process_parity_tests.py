# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""DC process parity through private, real PTYs; no original DC process runs."""
import asyncio
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.processes import ProcessManager, _detected_prompt
from dc_compat.registry import ToolError


def text(result):
    return result['content'][0]['text']


class ProcessParity(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hepta-process-parity-')
        self.root = Path(self.temporary.name)
        self.manager = ProcessManager(self.root / 'state', self.root, shell='/bin/sh')

    async def asyncTearDown(self):
        await asyncio.to_thread(self.manager.close)
        self.temporary.cleanup()

    def pty(self, command):
        return 'exec /usr/bin/script -qefc ' + shlex.quote(command) + ' /dev/null'

    async def start(self, command, **arguments):
        reply = await self.manager.invoke('start_process', dict(command=command, timeout_ms=2500, **arguments))
        self.assertNotIn('isError', reply, text(reply))
        return int(re.search(r'PID (\d+)', text(reply))[1]), text(reply)

    async def finished(self, pid):
        session = self.manager.sessions[pid]
        await asyncio.wait_for(asyncio.to_thread(session.collector.join), 4)
        self.assertEqual(session.metadata['state'], 'completed')

    async def test_real_python_continuation_is_early_detected_and_timed(self):
        command = self.pty('exec ' + shlex.quote(sys.executable) + ' -q -i')
        pid, first = await self.start(command, verbose_timing=True)
        self.assertIn('early_exit_quick_pattern', first)
        self.assertIn('Output Events (', first)
        reply = text(await self.manager.invoke('interact_with_process', {
            'pid': pid, 'input': 'for x in range(1):', 'timeout_ms': 2500, 'verbose_timing': True}))
        self.assertIn('waiting for input', reply)
        self.assertIn('early_exit_periodic_check', reply)
        self.assertNotIn('timeout reached', reply)
        duration = int(re.search(r'Total Duration: (\d+)ms', reply)[1])
        self.assertLess(duration, 1500)
        self.assertGreaterEqual(duration, 75)
        await self.manager.invoke('interact_with_process', {'pid': pid, 'input': "    print('continuation-result')", 'timeout_ms': 2500})
        completed = text(await self.manager.invoke('interact_with_process', {'pid': pid, 'input': '', 'timeout_ms': 2500}))
        self.assertIn('continuation-result', completed)
        terminal = text(await self.manager.invoke('interact_with_process', {'pid': pid,
            'input': "import os; print('REAL_TTY='+str(os.isatty(0) and os.isatty(1)))", 'timeout_ms': 2500}))
        self.assertIn('REAL_TTY=True', terminal)
        await self.manager.invoke('interact_with_process', {'pid': pid, 'input': 'exit()', 'timeout_ms': 2500})
        await self.finished(pid)
        self.assertFalse(self.manager.sessions[pid].observers)

    async def test_real_pty_r_and_shell_continuations_in_start_read_and_sessions(self):
        for prompt in ('+ ', '% ', '... ', '       ', 'bash-5.2', 'zsh-5.9'):
            with self.subTest(prompt=prompt):
                code = ("import os,sys;print('REAL_TTY='+str(os.isatty(0) and os.isatty(1)),flush=True);"
                        f"sys.stdout.write({prompt!r});sys.stdout.flush();sys.stdin.readline()")
                pid, reply = await self.start(self.pty('exec ' + shlex.quote(sys.executable) + ' -u -c ' + shlex.quote(code)), verbose_timing=True)
                self.assertIn('REAL_TTY=True', reply)
                self.assertIn('waiting for input', reply)
                self.assertIn('early_exit_periodic_check', reply)
                self.assertIn('Blocked: true', text(await self.manager.invoke('list_sessions', {})))
                page = text(await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0, 'verbose_timing': True}))
                self.assertIn('waiting for input', page)
                self.assertRegex(page, r'📊 Timing: \d+ms')
                await self.manager.invoke('interact_with_process', {'pid': pid, 'input': 'done', 'timeout_ms': 2500})
                await self.finished(pid)

    async def test_auto_ssh_t_only_for_initial_ssh_without_existing_t(self):
        # Executable fixtures expose argv without connecting to a network.
        shell, ssh = self.root / 'shell', self.root / 'ssh'
        shell.write_text('#!' + sys.executable + '\nimport os,sys\nos.environ["PATH"]=' + repr(str(self.root)) + '+os.pathsep+os.environ["PATH"]\nos.execv("/bin/sh",["sh"]+sys.argv[1:])\n')
        ssh.write_text('#!' + sys.executable + '\nimport json,sys\nprint("SSH_ARGV="+json.dumps(sys.argv[1:]))\n')
        shell.chmod(0o700); ssh.chmod(0o700)
        for command, expected in (
                ('ssh fake-host command', ['-t', 'fake-host', 'command']),
                ('  ssh fake-host command', ['-t', 'fake-host', 'command']),
                ('ssh -t fake-host command', ['-t', 'fake-host', 'command']),
                ('ssh -tt fake-host command', ['-tt', 'fake-host', 'command']),
                ('true; ssh fake-host command', ['fake-host', 'command'])):
            with self.subTest(command=command):
                pid, reply = await self.start(command, shell=str(shell))
                self.assertIn('SSH_ARGV=' + json.dumps(expected), reply)
                await self.finished(pid)
                metadata = self.manager.sessions[pid].metadata
                self.assertEqual(metadata['command'], command)
                self.assertFalse(metadata['automatic_replay'])

    async def test_timing_is_opt_in_and_uses_actual_stdout_stderr_exit_events(self):
        code = "import sys,time;print('first',flush=True);time.sleep(.12);print('second',file=sys.stderr,flush=True)"
        command = 'exec ' + shlex.quote(sys.executable) + ' -u -c ' + shlex.quote(code)
        pid, reply = await self.start(command, verbose_timing=True)
        self.assertIn('Exit Reason: process_exit', reply)
        self.assertIn('| stdout |', reply); self.assertIn('| stderr |', reply)
        self.assertIn('Time to First Output:', reply)
        self.assertIn('Output Window:', reply)
        await self.finished(pid)
        page = text(await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0}))
        self.assertNotIn('📊 Timing', page)
        directory = self.root / 'state' / self.manager.sessions[pid].journal_id
        self.assertEqual((directory / 'stdout.log').read_bytes(), b'first\n')
        self.assertEqual((directory / 'stderr.log').read_bytes(), b'second\n')
        self.assertNotIn(b'Timing', (directory / 'combined.log').read_bytes())
        other, ordinary = await self.start('printf ordinary')
        self.assertNotIn('📊 Timing', ordinary)
        await self.finished(other)

    async def test_no_wait_timeout_and_failure_detach_call_telemetry(self):
        code = "import sys,time;print('ready> ',end='',flush=True)\nfor line in sys.stdin:\n time.sleep(.25);print('response:'+line.strip(),flush=True)"
        pid, _ = await self.start(self.pty('exec ' + shlex.quote(sys.executable) + ' -u -c ' + shlex.quote(code)))
        no_wait = text(await self.manager.invoke('interact_with_process', {'pid': pid, 'input': 'one',
            'wait_for_prompt': False, 'verbose_timing': True}))
        self.assertIn('Exit Reason: no_wait', no_wait)
        self.assertFalse(self.manager.sessions[pid].observers)
        timeout = text(await self.manager.invoke('interact_with_process', {'pid': pid, 'input': 'two',
            'timeout_ms': 0, 'verbose_timing': True}))
        self.assertIn('Exit Reason: timeout', timeout)
        self.assertFalse(self.manager.sessions[pid].observers)
        with mock.patch.object(self.manager, '_publish_session', side_effect=ToolError('private disk fixture failure')):
            with self.assertRaises(ToolError):
                await self.manager.invoke('interact_with_process', {'pid': pid, 'input': 'never-sent', 'verbose_timing': True})
        self.assertFalse(self.manager.sessions[pid].observers)
        await asyncio.sleep(.65)
        page = text(await self.manager.invoke('read_process_output', {'pid': pid, 'offset': -20, 'timeout_ms': 0}))
        self.assertEqual(page.count('response:one'), 1)
        self.assertEqual(page.count('response:two'), 1)
        self.assertNotIn('never-sent', page)

    async def test_completed_real_pty_bytes_survive_restart_without_ssh_or_stdin_replay(self):
        count = self.root / 'once'
        code = ("from pathlib import Path;import os;p=Path(" + repr(str(count)) + ");"
                "p.write_text('once');print('完整PTY output');print('TTY='+str(os.isatty(0)))")
        pid, _ = await self.start(self.pty('exec ' + shlex.quote(sys.executable) + ' -u -c ' + shlex.quote(code)), verbose_timing=True)
        await self.finished(pid)
        before = text(await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0}))
        await asyncio.to_thread(self.manager.close)
        with mock.patch('dc_compat.processes.subprocess.Popen', side_effect=AssertionError('historical command replay')):
            self.manager = ProcessManager(self.root / 'state', self.root, shell='/bin/sh')
            after = text(await self.manager.invoke('read_process_output', {'pid': pid, 'timeout_ms': 0}))
            self.assertEqual(before, after)
            with self.assertRaises(ToolError):
                await self.manager.invoke('interact_with_process', {'pid': pid, 'input': 'never'})
        self.assertIn('完整PTY output', after)
        self.assertIn('TTY=True', after)
        self.assertEqual(count.read_text(), 'once')

    def test_comprehensive_prompt_families_match_dc_last_line_rules(self):
        for prompt in ('>>> ', '... ', '> ', '+ ', 'julia> ', '       ', '$ ', '# ', '% ',
                       'bash-', 'zsh-', 'mysql> ', '    -> ', '=# ', '-# ', 'redis> '):
            with self.subTest(prompt=prompt): self.assertIsNotNone(_detected_prompt('header\n' + prompt))
        self.assertIsNone(_detected_prompt('old >>> \nordinary progress'))
        self.assertIsNone(_detected_prompt('       '))


if __name__ == '__main__': unittest.main()
