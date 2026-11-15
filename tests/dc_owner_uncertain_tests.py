#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real delivered native descriptors with a deliberately lost sender ACK."""
import base64
import hashlib
import json
import os
import pathlib
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
OWNER=ROOT/'deploy/dc_handoff_owner.py'
BROKER=ROOT/'src/mcp/runtime/stream_broker.py'
APP="import json,os,sys\nt=0\nprint(json.dumps({'event':'READY','pid':os.getpid(),'total':t}),flush=True)\nfor l in sys.stdin:\n t+=int(l);print(json.dumps({'event':'VALUE','pid':os.getpid(),'total':t}),flush=True);print('ERR '+str(t),file=sys.stderr,flush=True)"
LOST_ACK=r"""
import runpy,socket,sys
owner=runpy.run_path(sys.argv[1]);original=socket.socket
class DropAck(original):
 def connect(self,address):
  self.drop_ack=str(address).endswith('/handoff.sock')
  return super().connect(address)
 def recv(self,*args,**kwargs):
  value=super().recv(*args,**kwargs)
  if getattr(self,'drop_ack',False):
   self.drop_ack=False
   raise ConnectionResetError('fixture deliberately lost the delivered native ACK')
  return value
socket.socket=DropAck
sys.argv=sys.argv[1:];owner['main']()
"""


def line(fd):
    data=b'';deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        if not select.select([fd],[],[],max(0,deadline-time.monotonic()))[0]:break
        block=os.read(fd,1)
        if not block:raise RuntimeError('fixture owner EOF')
        data+=block
        if data.endswith(b'\n'):return data
    raise TimeoutError('fixture output missing')


class UncertainOwner(unittest.TestCase):
    def broker(self,state,op,**values):
        q={'state_dir':str(state),'op':op,**values}
        p=subprocess.run([sys.executable,str(BROKER)],input=json.dumps(q),text=True,capture_output=True,timeout=25)
        self.assertEqual(p.returncode,0,p.stderr)
        return json.loads(p.stdout)
    def owner_call(self,owner_state,op,fail=False,**values):
        command=[sys.executable,str(OWNER),op,'--socket',str(owner_state/'control.sock')]
        for key,value in values.items():command.extend(['--'+key.replace('_','-'),str(value)])
        p=subprocess.run(command,text=True,capture_output=True,timeout=20)
        if fail:
            self.assertNotEqual(p.returncode,0,p.stdout);return p.stderr
        self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
    def test_slow_child_preserves_saturated_input_and_refuses_pending_handoff(self):
        with tempfile.TemporaryDirectory(prefix='hepta-slow-input-') as temp:
            root=pathlib.Path(temp);owner_state=root/'owner';gate=root/'gate';payload=os.urandom(512*1024)
            app="import hashlib,json,os,pathlib,sys,time\nprint(json.dumps({'event':'READY','pid':os.getpid()}),flush=True)\nwhile not pathlib.Path(sys.argv[1]).exists():time.sleep(.02)\ndata=sys.stdin.buffer.read(int(sys.argv[2]));print(json.dumps({'event':'HASH','size':len(data),'sha256':hashlib.sha256(data).hexdigest()}),flush=True)\nfor _ in sys.stdin.buffer:pass"
            owner=subprocess.Popen([sys.executable,'-u',str(OWNER),'run','--state-dir',str(owner_state),
                                    '--',sys.executable,'-u','-c',app,str(gate),str(len(payload))],
                                   stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            errors=[]
            def write():
                try:
                    offset=0
                    while offset<len(payload):offset+=os.write(owner.stdin.fileno(),payload[offset:])
                except Exception as error:errors.append(error)
            writer=threading.Thread(target=write,daemon=True)
            try:
                line(owner.stdout.fileno());ready=json.loads(line(owner.stdout.fileno()));writer.start()
                deadline=time.monotonic()+4;status={}
                while time.monotonic()<deadline:
                    status=self.owner_call(owner_state,'status')
                    if status['stdin_buffered_bytes']>0:break
                    time.sleep(.02)
                self.assertGreater(status['stdin_buffered_bytes'],0);self.assertLessEqual(status['stdin_buffered_bytes'],64*1024)
                self.assertIsNone(owner.poll())
                error=self.owner_call(owner_state,'handoff',fail=True,handoff_socket=str(root/'unused.sock'),
                                      session_id='saturated-input-test',application_pids=json.dumps([ready['pid']]))
                self.assertIn('stdin exists; drain before handoff',error)
                self.assertEqual(self.owner_call(owner_state,'status')['state'],'running')
                gate.touch();writer.join(timeout=8);self.assertFalse(writer.is_alive());self.assertFalse(errors)
                result=json.loads(line(owner.stdout.fileno()))
                self.assertEqual(result['size'],len(payload));self.assertEqual(result['sha256'],hashlib.sha256(payload).hexdigest())
                status=self.owner_call(owner_state,'status');self.assertEqual(status['stdin_buffered_bytes'],0)
                self.assertEqual(status['stdin_pending_bytes'],0)
                owner.stdin.close();self.assertEqual(owner.wait(timeout=8),0)
            finally:
                if owner.poll() is None:owner.terminate();owner.wait(timeout=5)
                writer.join(timeout=2)
                for stream in (owner.stdin,owner.stdout,owner.stderr):
                    if stream is not None:stream.close()
    def test_lost_ack_never_resumes_io_and_exact_native_receipt_reconciles(self):
        with tempfile.TemporaryDirectory(prefix='hepta-lost-ack-') as temp:
            root=pathlib.Path(temp);state=root/'runtime';state.mkdir(mode=0o700);owner_state=root/'owner'
            owner=subprocess.Popen([sys.executable,'-u','-c',LOST_ACK,str(OWNER),'run','--state-dir',str(owner_state),
                                    '--',sys.executable,'-u','-c',APP],
                                   stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            app_pid=None;session='stream-'+hashlib.sha256((self.id()+str(root)).encode()).hexdigest()
            try:
                marker=json.loads(line(owner.stdout.fileno()).split(b' ',1)[1]);app_pid=marker['child_identity']['pid']
                ready=json.loads(line(owner.stdout.fileno()));self.assertEqual(ready['pid'],app_pid)
                owner.stdin.write(b'17\n');self.assertEqual(json.loads(line(owner.stdout.fileno()))['total'],17)
                self.assertEqual(line(owner.stderr.fileno()),b'ERR 17\n')
                histories={name:(owner_state/(name+'.history')).read_bytes() for name in ('stdout','stderr')}
                prepared=self.broker(state,'prepare',session_id=session,application_pids=[app_pid])
                error=self.owner_call(owner_state,'handoff',fail=True,handoff_socket=prepared['handoff_socket'],
                                      session_id=session,application_pids=json.dumps([app_pid]))
                self.assertIn('outcome uncertain',error)
                uncertain=self.owner_call(owner_state,'status')
                self.assertEqual(uncertain['state'],'handoff_uncertain');self.assertTrue(uncertain['owned_io_quiesced'])
                self.assertFalse(uncertain['automatic_resume_allowed']);self.assertIsNone(owner.poll())
                native=self.broker(state,'status',session_id=session);self.assertTrue(native['owner_accepted'])
                self.assertTrue(native['all_applications_alive'])
                self.assertIn('without replay',self.owner_call(owner_state,'handoff',fail=True,
                    handoff_socket=prepared['handoff_socket'],session_id=session,application_pids=json.dumps([app_pid])))
                owner.stdin.write(b'99\n')
                self.broker(state,'write',session_id=session,request_id='uncertain-write-01',data_base64=base64.b64encode(b'5\n').decode())
                deadline=time.monotonic()+6;archive=b''
                while time.monotonic()<deadline:
                    archive=base64.b64decode(self.broker(state,'read',session_id=session,stream='stdout',offset=0,limit=4096)['data_base64'])
                    if b'"total": 22' in archive:break
                    time.sleep(.05)
                self.assertIn(b'"total": 22',archive);self.assertNotIn(b'"total": 121',archive)
                self.assertEqual(self.owner_call(owner_state,'status')['stdin_pending_bytes'],3)
                for name,history in histories.items():self.assertEqual((owner_state/(name+'.history')).read_bytes(),history)
                native_receipt=state/'stream_handoffs'/session/'handoff_receipt.json'
                wrong=root/'wrong.json';receipt=json.loads(native_receipt.read_text());receipt['sender_identity']['start_ticks']+=1
                wrong.write_text(json.dumps(receipt));wrong.chmod(0o600)
                self.assertIn('does not match',self.owner_call(owner_state,'reconcile',fail=True,receipt_path=wrong))
                self.assertIsNone(owner.poll());self.assertEqual(self.owner_call(owner_state,'status')['state'],'handoff_uncertain')
                # A matching durable receipt alone is insufficient when the live
                # receiver's accepted identity cannot be queried.
                control=pathlib.Path(prepared['handoff_socket']).with_name('control.sock')
                parked=control.with_name('parked-control.sock');control.rename(parked)
                try:self.owner_call(owner_state,'reconcile',fail=True,receipt_path=native_receipt)
                finally:parked.rename(control)
                self.assertIsNone(owner.poll())
                reconciled=self.owner_call(owner_state,'reconcile',receipt_path=native_receipt)
                self.assertTrue(reconciled['reconciled_lost_ack']);self.assertTrue(reconciled['accepted'])
                self.assertEqual(reconciled['receipt_sha256'],hashlib.sha256(native_receipt.read_bytes()).hexdigest())
                self.assertEqual(owner.wait(timeout=8),0)
                self.broker(state,'close',session_id=session)
                deadline=time.monotonic()+6
                final_path=state/'stream_handoffs'/session/'final.json'
                while time.monotonic()<deadline and not final_path.exists():time.sleep(.05)
                self.assertTrue(final_path.exists(),'native EOF did not publish its final archive receipt')
                final=self.broker(state,'status',session_id=session)
                self.assertTrue(final['output_complete'])
                for name,history in histories.items():
                    data=base64.b64decode(self.broker(state,'read',session_id=session,stream=name,offset=0,limit=4096)['data_base64'])
                    self.assertTrue(data.startswith(history));self.assertIn(b'22',data)
            finally:
                if owner.poll() is None:owner.terminate();owner.wait(timeout=5)
                if app_pid is not None:
                    try:os.kill(app_pid,15)
                    except ProcessLookupError:pass
                for stream in (owner.stdin,owner.stdout,owner.stderr):
                    if stream is not None:stream.close()


if __name__=='__main__':unittest.main(verbosity=2)
