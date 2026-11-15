#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Owned-process helper tests; no sudo, business units or configuration changes."""
import ast
import contextlib
import io
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'src/mcp/runtime/jobs.rs').read_text()
CODES={name:re.search(r'const '+name+r': &str = r#"(.*?)"#;',SOURCE,re.S).group(1)
       for name in ('START_CODE','STATUS_CODE','CANCEL_CODE','READ_CODE')}
def identity(pid):
    ticks=pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
    return {'kind':'proc_start_ticks','value':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+ticks}
def run_code(code,q):
    output=io.StringIO()
    with mock.patch.object(sys,'stdin',io.StringIO(json.dumps(q))),contextlib.redirect_stdout(output):
        exec(code,{})
    return json.loads(output.getvalue())
def write(path,value):
    path.write_text(json.dumps(value))
class OperatorJobIdentityTests(unittest.TestCase):
    def fixture(self,path,pid):
        nonce='a'*32
        request={'job_id':'owned-test-job','launch_nonce':nonce}
        started={'job_id':request['job_id'],'launch_nonce':nonce,'supervisor_pid':pid,
          'supervisor_uid':os.geteuid(),'supervisor_identity':identity(pid),'invocation_id':'b'*32}
        write(path/'request.json',request);write(path/'started.json',started)
        write(path/'launch.json',{'backend':'systemd'})
        return {'job_id':request['job_id'],'job_dir':str(path),'unit':'owned-unit','grace_seconds':0}
    @unittest.skipUnless(sys.platform=='linux','Linux pidfd binding')
    def test_frozen_supervisor_term_uses_pidfd_and_never_a_unit_name(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        try:
            with tempfile.TemporaryDirectory() as directory:
                q=self.fixture(pathlib.Path(directory),child.pid)
                with mock.patch('subprocess.run',side_effect=AssertionError('unit command forbidden')):
                    value=run_code(CODES['CANCEL_CODE'],q)
                self.assertEqual(value['result'],'stop_requested')
                self.assertTrue(value['atomic_identity']);self.assertFalse(value['termination_confirmed'])
                self.assertEqual(value['supervisor_pid'],child.pid)
                self.assertEqual(child.wait(timeout=5),-signal.SIGTERM)
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)
    @unittest.skipUnless(sys.platform=='linux','Linux pidfd binding')
    def test_missing_or_changed_binding_never_borrows_current_pid_or_unit(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        try:
            with tempfile.TemporaryDirectory() as directory:
                path=pathlib.Path(directory);q=self.fixture(path,child.pid)
                original=(path/'started.json').read_text()
                for field in ('launch_nonce','supervisor_uid','supervisor_identity','supervisor_pid','invocation_id'):
                    changed=json.loads(original);changed.pop(field);write(path/'started.json',changed)
                    with mock.patch('signal.pidfd_send_signal',side_effect=AssertionError('signal forbidden')):
                        with self.assertRaises(SystemExit):run_code(CODES['CANCEL_CODE'],q)
                    self.assertIsNone(child.poll())
                changed=json.loads(original);changed['supervisor_identity']['value']='wrong-original-start'
                write(path/'started.json',changed)
                with mock.patch('signal.pidfd_send_signal',side_effect=AssertionError('signal forbidden')):
                    with self.assertRaises(SystemExit):run_code(CODES['CANCEL_CODE'],q)
                self.assertIsNone(child.poll())
                self.assertFalse((path/'cancel-request.json').exists())
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)
    @unittest.skipUnless(sys.platform=='linux','Linux fixture identity')
    def test_replacement_unit_cannot_supply_old_running_or_completed_status(self):
        with tempfile.TemporaryDirectory() as directory:
            q=self.fixture(pathlib.Path(directory),os.getpid())
            for state,sub in [('active','running'),('active','exited'),('failed','failed')]:
                props=f'LoadState=loaded\nActiveState={state}\nSubState={sub}\nInvocationID=replacement-invocation\nDescription=replacement\nExecMainCode=1\nExecMainStatus=0\n'
                with mock.patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,props,'')) as command:
                    value=run_code(CODES['STATUS_CODE'],q)
                self.assertEqual(value['state'],'owner_unknown');self.assertFalse(value['status_authoritative'])
                self.assertNotIn('exit_code',value)
                self.assertEqual(command.call_args.args[0][2],'show')
    @unittest.skipUnless(sys.platform=='linux','Linux fixture identity')
    def test_original_final_record_and_output_survive_unit_identity_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory);q=self.fixture(path,os.getpid())
            write(path/'exit.json',{'exit_code':0,'output_complete':True,'cancelled':False,'timed_out':False})
            (path/'stdout.log').write_bytes(b'original exact output')
            with mock.patch('subprocess.run',side_effect=AssertionError('completed old job does not query replacement')):
                status=run_code(CODES['STATUS_CODE'],q)
            self.assertEqual(status['state'],'succeeded')
            data=run_code(CODES['READ_CODE'],{**q,'stdout_offset':3,'stderr_offset':0,'limit':5})
            self.assertEqual(bytes.fromhex(data['stdout']['bytes_hex']),b'ginal')
            self.assertEqual(data['stdout']['next_offset'],8)
    @unittest.skipUnless(sys.platform=='linux','Linux fail-closed identity')
    def test_linux_proc_failure_never_substitutes_ps_identity(self):
        tree=ast.parse(CODES['CANCEL_CODE'])
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='process_identity')
        namespace={'sys':sys,'pathlib':pathlib,'subprocess':subprocess}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<owned-identity>','exec'),namespace)
        with mock.patch.object(pathlib.Path,'read_text',side_effect=PermissionError('proc unavailable')):
            with mock.patch('subprocess.check_output',side_effect=AssertionError('Linux must not fall back to ps')):
                self.assertIsNone(namespace['process_identity'](os.getpid()))
    @unittest.skipUnless(sys.platform=='linux','Linux fixture identity')
    def test_every_missing_systemd_binding_field_blocks_authoritative_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory);q=self.fixture(path,os.getpid())
            original=(path/'started.json').read_text()
            props='LoadState=loaded\nActiveState=active\nSubState=running\nInvocationID='+('b'*32)+'\nDescription=Hepta Runtime job owned-test-job '+('a'*32)+'\n'
            for field in ('launch_nonce','supervisor_uid','supervisor_identity','supervisor_pid','invocation_id'):
                changed=json.loads(original);changed.pop(field);write(path/'started.json',changed)
                with mock.patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,props,'')):
                    value=run_code(CODES['STATUS_CODE'],q)
                self.assertEqual(value['state'],'owner_unknown');self.assertFalse(value['status_authoritative'])
    def test_handler_cannot_reap_or_signal_a_potentially_recycled_group(self):
        tree=ast.parse(CODES['START_CODE'])
        runner=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='runner' for t in n.targets))
        function=next(n for n in ast.parse(runner).body if isinstance(n,ast.FunctionDef) and n.name=='stop_handler')
        namespace={'cancel_requested':False}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<owned-stop-handler>','exec'),namespace)
        namespace['stop_handler'](signal.SIGTERM,None)
        self.assertTrue(namespace['cancel_requested'])
        self.assertNotIn('child.poll()',runner)
        self.assertIn('os.WNOWAIT',runner)
        self.assertIn('select.KQ_NOTE_EXIT',runner)
        self.assertIn('publish_owner("owner-intent.json")',runner)
        self.assertIn('publish_owner("started.json")',runner)
        self.assertNotIn('"stop", q["unit"]',CODES['CANCEL_CODE'])
        self.assertNotIn('os.killpg',CODES['CANCEL_CODE'])
if __name__=='__main__':unittest.main(verbosity=2)
