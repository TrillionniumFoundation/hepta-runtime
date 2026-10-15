#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bounded privileged-helper capture with ordinary owned children; never run sudo."""
import contextlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/'src/mcp/runtime/inspect.rs'
if not SOURCE.exists():SOURCE=pathlib.Path(__file__).with_name('inspect.rs')
CODE=re.search(r'const PRIVILEGED_CODE: &str = r#"(.*?)"#;',SOURCE.read_text(),re.S).group(1)

class PrivilegedActionPythonTests(unittest.TestCase):
    def run_helper(self,source,timeout=1):
        output=io.StringIO()
        request=json.dumps({'executable':'/configured/fixture','fixed_args':[],'args':[],'timeout_seconds':timeout})
        actual_popen=subprocess.Popen
        def launch(argv,**kwargs):
            self.assertEqual(argv,['sudo','-n','/configured/fixture'])
            return actual_popen([sys.executable,'-c',source],**kwargs)
        with mock.patch('subprocess.Popen',side_effect=launch) as popen:
            with mock.patch.object(sys,'stdin',io.StringIO(request)),contextlib.redirect_stdout(output):exec(CODE,{})
            self.assertEqual(popen.call_count,1)
        return json.loads(output.getvalue())
    def test_normal_exit124_is_not_timeout_and_stdout_stderr_preserved(self):
        r=self.run_helper("import os;os.write(1,b'actual stdout');os.write(2,b'actual stderr');raise SystemExit(124)")
        self.assertEqual(r['exit_code'],124);self.assertFalse(r['timed_out'])
        self.assertTrue(r['exit_code_authoritative']);self.assertTrue(r['process_exit_confirmed'])
        self.assertEqual(r['stdout'],'actual stdout');self.assertEqual(r['stderr'],'actual stderr')
        self.assertTrue(r['output_complete']);self.assertFalse(r['descendant_termination_confirmed'])
    def test_timeout_preserves_output_and_never_claims_authoritative_exit124(self):
        r=self.run_helper("import os,time;os.write(1,'中文'.encode()+b'\\xff');os.write(2,b'diagnostics');time.sleep(30)",.2)
        self.assertTrue(r['timed_out']);self.assertEqual(r['exit_code'],124)
        self.assertFalse(r['exit_code_authoritative']);self.assertTrue(r['process_exit_confirmed'])
        self.assertIn('中文',r['stdout']);self.assertEqual(r['stderr'],'diagnostics')
        self.assertFalse(r['descendant_termination_confirmed'])
    def test_bounded_capture_drains_many_megabytes_and_utf8_replacement(self):
        for expression,data in [("b'\\x01'*65536",b'\x01'*65536),("b'\\xff'*65536",b'\xff'*65536),("('中文🦀'*8192).encode()",('中文🦀'*8192).encode())]:
            source="import os\nd="+expression+"\nfor _ in range(128):\n os.write(1,d);os.write(2,d)"
            r=self.run_helper(source,10)
            self.assertEqual(r['exit_code'],0)
            self.assertEqual(r['stdout_bytes_seen'],len(data)*128)
            self.assertEqual(r['stderr_bytes_seen'],len(data)*128)
            self.assertLessEqual(len(r['stdout'].encode()),524288);self.assertLessEqual(len(r['stderr'].encode()),524288)
            self.assertTrue(r['stdout_truncated']);self.assertTrue(r['stderr_truncated'])
            self.assertFalse(r['output_complete']);self.assertLess(len(json.dumps(r).encode()),8*1024*1024)
    def test_descendant_held_pipes_do_not_block_after_direct_child_exit(self):
        source="import os,time\npid=os.fork()\nif pid==0:time.sleep(30);os._exit(0)\nprint(pid,flush=True)"
        started=time.monotonic();r=self.run_helper(source,4)
        child=int(r['stdout'].strip())
        try:
            self.assertLess(time.monotonic()-started,3)
            self.assertTrue(r['process_exit_confirmed']);self.assertFalse(r['timed_out'])
            self.assertFalse(r['output_complete']);self.assertFalse(r['descendant_termination_confirmed'])
        finally:
            try:os.kill(child,9)
            except ProcessLookupError:pass
    @unittest.skipUnless(sys.platform=='linux','Linux address-space resource cap')
    def test_large_output_succeeds_under_real_memory_cap(self):
        # The old communicate() implementation accumulated >128 MiB and failed
        # under this 64 MiB helper limit before any final-text truncation.
        fixture="import os\nd=b'x'*65536\nfor _ in range(2048):os.write(1,d);os.write(2,d)"
        bootstrap="import subprocess,sys,resource\nresource.setrlimit(resource.RLIMIT_AS,(64*1024*1024,64*1024*1024))\nactual=subprocess.Popen\nfixture="+repr(fixture)+"\nsubprocess.Popen=lambda argv,**kw:actual([sys.executable,'-c',fixture],**kw)\nexec("+repr(CODE)+")"
        request=json.dumps({'executable':'/configured/fixture','timeout_seconds':20})
        completed=subprocess.run([sys.executable,'-c',bootstrap],input=request,capture_output=True,text=True,timeout=25,check=True)
        r=json.loads(completed.stdout)
        self.assertEqual(r['exit_code'],0);self.assertEqual(r['stdout_bytes_seen'],128*1024*1024)
        self.assertEqual(r['stderr_bytes_seen'],128*1024*1024);self.assertTrue(r['stdout_truncated'])

if __name__=='__main__':unittest.main()
