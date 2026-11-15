#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual persistent broker with cooperative fd export; no runtime HTTP required."""
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
BROKER=ROOT/'src/mcp/runtime/stream_broker.py'
spec=importlib.util.spec_from_file_location('stream_export',ROOT/'deploy/stream_handoff.py')
EXPORT=importlib.util.module_from_spec(spec);spec.loader.exec_module(EXPORT)

APP=r'''
import hashlib,json,os,sys
memory=os.urandom(32);total=0
print(json.dumps({'event':'READY','pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total}),flush=True)
for line in sys.stdin:
    total+=int(line)
    print(json.dumps({'event':'VALUE','pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total}),flush=True)
'''


class Broker(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-stream-broker-test-')
        self.state=pathlib.Path(self.temp.name)/'state';self.state.mkdir(mode=0o700)
        self.app=subprocess.Popen([sys.executable,'-u','-c',APP],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=0)
        self.session='stream-'+hashlib.sha256(self.id().encode()).hexdigest()
        self.request={'op':'prepare','state_dir':str(self.state),'session_id':self.session,'application_pids':[self.app.pid]}
        self.prepared=self.rpc(self.request)
        EXPORT.transfer(self.prepared['handoff_socket'],self.session,
                        {'stdin_writer':self.app.stdin.fileno(),'stdout_reader':self.app.stdout.fileno(),'stderr_reader':self.app.stderr.fileno()},
                        [self.app.pid],acknowledge_quiesced_io=True)
        self.app.stdin.close();self.app.stdout.close();self.app.stderr.close()

    def tearDown(self):
        try:self.rpc({'op':'close','state_dir':str(self.state),'session_id':self.session})
        except Exception:pass
        try:self.app.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(self.app.pid,15);self.app.wait(timeout=3)
        for _ in range(100):
            try:
                status=self.rpc({'op':'status','state_dir':str(self.state),'session_id':self.session})
                if status.get('state')=='exited':break
            except Exception:pass
            time.sleep(.02)
        self.temp.cleanup()

    def rpc(self,q,fail=False):
        p=subprocess.run([sys.executable,str(BROKER)],input=json.dumps(q),text=True,capture_output=True,timeout=25)
        if fail:
            self.assertNotEqual(p.returncode,0,p.stdout)
            return p.stderr
        self.assertEqual(p.returncode,0,p.stderr)
        return json.loads(p.stdout)

    def read_until(self,needle,offset=0,timeout=8):
        end=time.monotonic()+timeout;text=''
        while time.monotonic()<end:
            page=self.rpc({'op':'read','state_dir':str(self.state),'session_id':self.session,'stream':'stdout','offset':offset,'limit':4096})
            block=base64.b64decode(page['data_base64']);text+=block.decode();offset=page['next_offset']
            if needle in text:return text,offset,page
            time.sleep(.05)
        self.fail('expected output missing: '+needle)

    def test_reused_prepare_is_same_receiver_not_second_daemon(self):
        again=self.rpc(self.request)
        self.assertTrue(again['reused']);self.assertEqual(again['session_id'],self.session)
        self.assertEqual(again['status']['state'],'accepted')

    def test_exact_output_and_idempotent_input(self):
        ready,offset,_=self.read_until('READY')
        identity=json.loads(ready.splitlines()[0]);digest=identity['hash']
        payload=base64.b64encode(b'5\n').decode()
        q={'op':'write','state_dir':str(self.state),'session_id':self.session,'request_id':'fixture-write-01','data_base64':payload}
        first=self.rpc(q);second=self.rpc(q)
        self.assertFalse(first['reused']);self.assertTrue(second['reused']);self.assertEqual(first['state'],'confirmed')
        value,offset,_=self.read_until('"total": 5',offset)
        result=json.loads(value.splitlines()[-1]);self.assertEqual(result['hash'],digest);self.assertEqual(result['pid'],identity['pid'])
        self.assertIn('different bytes',self.rpc({**q,'data_base64':base64.b64encode(b'6\n').decode()},fail=True))
        receipts=(self.state/'stream_handoffs'/self.session/'input_receipts.jsonl').read_text()
        self.assertNotIn('5\\n',receipts);self.assertNotIn(payload,receipts)

    def test_ephemeral_clients_do_not_own_pipe_lifetime(self):
        ready,offset,_=self.read_until('READY')
        pid=json.loads(ready.splitlines()[0])['pid']
        # Every status/write call above is a new helper process. The app and broker survive them.
        before=self.rpc({'op':'status','state_dir':str(self.state),'session_id':self.session})
        self.assertTrue(before['owner_accepted']);self.assertTrue(before['all_applications_alive'])
        self.assertEqual(before['application_identities'][0]['pid'],pid)
        self.rpc({'op':'write','state_dir':str(self.state),'session_id':self.session,'request_id':'fixture-write-02','data_base64':base64.b64encode(b'7\n').decode()})
        text,_,_=self.read_until('"total": 7',offset);self.assertIn('"total": 7',text)

    def test_close_is_input_eof_not_signal(self):
        self.read_until('READY')
        closed=self.rpc({'op':'close','state_dir':str(self.state),'session_id':self.session})
        self.assertEqual(closed['state'],'input_closed')
        self.app.wait(timeout=5)
        for _ in range(80):
            status=self.rpc({'op':'status','state_dir':str(self.state),'session_id':self.session})
            if status['state']=='exited':break
            time.sleep(.05)
        self.assertEqual(status['state'],'exited');self.assertTrue(status['output_complete'])
        self.assertEqual(status['application_status'][0]['alive'],False)

    def test_list_discovers_durable_identity(self):
        listing=self.rpc({'op':'list','state_dir':str(self.state),'limit':10})
        rows=[x for x in listing['sessions'] if x['session_id']==self.session]
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['application_identities'][0]['pid'],self.app.pid)


if __name__=='__main__':unittest.main(verbosity=2)
