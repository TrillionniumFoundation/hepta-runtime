#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Raw pre-handoff history and live-pipe continuity tests."""
import base64,hashlib,importlib.util,json,os,pathlib,subprocess,sys,tempfile,time,unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
BROKER=ROOT/'src/mcp/runtime/stream_broker.py'
spec=importlib.util.spec_from_file_location('export',ROOT/'deploy/stream_handoff.py')
EXPORT=importlib.util.module_from_spec(spec);spec.loader.exec_module(EXPORT)
APP="import json,os,sys\nprint(json.dumps({'event':'READY','pid':os.getpid()}),flush=True)\nfor line in sys.stdin: print(json.dumps({'event':'VALUE','value':int(line)}),flush=True)"

class History(unittest.TestCase):
    def rpc(self,q,fail=False):
        p=subprocess.run([sys.executable,str(BROKER)],input=json.dumps(q),text=True,capture_output=True,timeout=25)
        if fail:
            self.assertNotEqual(p.returncode,0,p.stdout);return p.stderr
        self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
    def wait_broker_finalized(self,state,session,timeout=10):
        """Wait for the live broker's durable final receipt AND socket cleanup.

        App exit is not an owner shutdown acknowledgement: the out-of-process
        service may still be fsyncing archives or unlinking its control socket.
        Only after both barriers can TemporaryDirectory safely remove state.
        """
        job=state/'stream_handoffs'/session
        bound=json.loads((job/'request.json').read_text())
        socket_root=pathlib.Path(bound['socket_root'])
        deadline=time.monotonic()+timeout;last=None
        while time.monotonic()<deadline:
            try:
                result=self.rpc({'op':'status','state_dir':str(state),'session_id':session})
            except (AssertionError,RuntimeError,OSError) as exc:
                last=type(exc).__name__;time.sleep(.05);continue
            last=result.get('state')
            closed=all(not (socket_root/name).exists()
                       for name in ('handoff.sock','control.sock'))
            if result.get('state')=='exited' and result.get('output_complete') is True and closed:
                self.assertTrue(result['stdin_closed'])
                self.assertTrue(result['stdout_eof'])
                self.assertTrue(result['stderr_eof'])
                return result
            time.sleep(.05)
        self.fail('native stream broker did not complete durable finalization and socket cleanup: '+str(last))

    def test_history_descriptor_is_exact_readonly_regular_file(self):
        with tempfile.TemporaryDirectory() as t:
            path=pathlib.Path(t)/'history';path.write_bytes(b'abc\x00'+'中文'.encode())
            with path.open('rb') as f:
                value=EXPORT.history_description(f.fileno())
            self.assertEqual(value['size'],len(path.read_bytes()));self.assertEqual(value['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            with path.open('r+b') as f:
                with self.assertRaisesRegex(ValueError,'read-only'):EXPORT.history_description(f.fileno())
    def test_finalized_history_is_prefix_of_runtime_archive(self):
        with tempfile.TemporaryDirectory(prefix='hepta-history-broker-') as t:
            root=pathlib.Path(t);state=root/'state';state.mkdir(mode=0o700)
            app=subprocess.Popen([sys.executable,'-u','-c',APP],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=0)
            try:
                raw=app.stdout.readline();self.assertIn(b'READY',raw)
                history=root/'stdout.history';history.write_bytes(raw);history.chmod(0o600)
                session='stream-'+hashlib.sha256(self.id().encode()).hexdigest()
                q={'op':'prepare','state_dir':str(state),'session_id':session,'application_pids':[app.pid]}
                prepared=self.rpc(q)
                with history.open('rb') as prior:
                    ack=EXPORT.transfer(prepared['handoff_socket'],session,
                        {'stdin_writer':app.stdin.fileno(),'stdout_reader':app.stdout.fileno(),'stderr_reader':app.stderr.fileno(),'stdout_history':prior.fileno()},
                        [app.pid],acknowledge_quiesced_io=True)
                self.assertTrue(ack['accepted'])
                app.stdin.close();app.stdout.close();app.stderr.close()
                page=self.rpc({'op':'read','state_dir':str(state),'session_id':session,'stream':'stdout','offset':0,'limit':4096})
                self.assertEqual(base64.b64decode(page['data_base64']),raw)
                app_pid=app.pid
                self.rpc({'op':'write','state_dir':str(state),'session_id':session,'request_id':'history-write-01','data_base64':base64.b64encode(b'5\n').decode()})
                end=time.monotonic()+6;data=b''
                while time.monotonic()<end:
                    page=self.rpc({'op':'read','state_dir':str(state),'session_id':session,'stream':'stdout','offset':0,'limit':4096})
                    data=base64.b64decode(page['data_base64'])
                    if b'"value": 5' in data:break
                    time.sleep(.05)
                self.assertTrue(data.startswith(raw));self.assertIn(b'"value": 5',data)
                receipt=json.loads((state/'stream_handoffs'/session/'handoff_receipt.json').read_text())
                seed=receipt['history_seed']['stdout'];self.assertEqual(seed['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(seed['size'],len(raw))
                self.rpc({'op':'close','state_dir':str(state),'session_id':session});app.wait(timeout=5)
                self.wait_broker_finalized(state,session)
                self.assertEqual(app.pid,app_pid)
            finally:
                if app.poll() is None:app.terminate();app.wait(timeout=5)
    def test_changed_history_identity_fails_before_receipt(self):
        with tempfile.TemporaryDirectory() as t:
            path=pathlib.Path(t)/'h';path.write_bytes(b'before')
            with path.open('rb') as f:
                before=EXPORT.history_description(f.fileno())
            path.write_bytes(b'after!')
            with path.open('rb') as f:
                self.assertNotEqual(before,EXPORT.history_description(f.fileno()))


    def test_stdout_and_stderr_histories_seed_independently(self):
        app_code="import json,os,sys\nprint(json.dumps({'event':'OUT_READY','pid':os.getpid()}),flush=True);print(json.dumps({'event':'ERR_READY','pid':os.getpid()}),file=sys.stderr,flush=True)\nfor line in sys.stdin:\n v=int(line);print(json.dumps({'event':'OUT_VALUE','value':v}),flush=True);print(json.dumps({'event':'ERR_VALUE','value':v}),file=sys.stderr,flush=True)"
        with tempfile.TemporaryDirectory(prefix='hepta-history-two-stream-') as t:
            root=pathlib.Path(t);state=root/'state';state.mkdir(mode=0o700)
            app=subprocess.Popen([sys.executable,'-u','-c',app_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=0)
            try:
                out=app.stdout.readline();err=app.stderr.readline();self.assertIn(b'OUT_READY',out);self.assertIn(b'ERR_READY',err)
                out_history=root/'stdout.history';err_history=root/'stderr.history';out_history.write_bytes(out);err_history.write_bytes(err)
                session='stream-'+hashlib.sha256((self.id()+'-two').encode()).hexdigest()
                prepared=self.rpc({'op':'prepare','state_dir':str(state),'session_id':session,'application_pids':[app.pid]})
                with out_history.open('rb') as oh,err_history.open('rb') as eh:
                    ack=EXPORT.transfer(prepared['handoff_socket'],session,
                        {'stdin_writer':app.stdin.fileno(),'stdout_reader':app.stdout.fileno(),'stderr_reader':app.stderr.fileno(),'stdout_history':oh.fileno(),'stderr_history':eh.fileno()},
                        [app.pid],acknowledge_quiesced_io=True)
                self.assertTrue(ack['accepted']);app.stdin.close();app.stdout.close();app.stderr.close()
                stdout=self.rpc({'op':'read','state_dir':str(state),'session_id':session,'stream':'stdout','offset':0,'limit':4096})
                stderr=self.rpc({'op':'read','state_dir':str(state),'session_id':session,'stream':'stderr','offset':0,'limit':4096})
                self.assertEqual(base64.b64decode(stdout['data_base64']),out);self.assertEqual(base64.b64decode(stderr['data_base64']),err)
                receipt=json.loads((state/'stream_handoffs'/session/'handoff_receipt.json').read_text())
                self.assertEqual(receipt['history_seed']['stdout']['sha256'],hashlib.sha256(out).hexdigest())
                self.assertEqual(receipt['history_seed']['stderr']['sha256'],hashlib.sha256(err).hexdigest())
                self.rpc({'op':'write','state_dir':str(state),'session_id':session,'request_id':'two-stream-write','data_base64':base64.b64encode(b'9\n').decode()})
                end=time.monotonic()+6;out_all=err_all=b''
                while time.monotonic()<end:
                    out_all=base64.b64decode(self.rpc({'op':'read','state_dir':str(state),'session_id':session,'stream':'stdout','offset':0,'limit':4096})['data_base64'])
                    err_all=base64.b64decode(self.rpc({'op':'read','state_dir':str(state),'session_id':session,'stream':'stderr','offset':0,'limit':4096})['data_base64'])
                    if b'OUT_VALUE' in out_all and b'ERR_VALUE' in err_all:break
                    time.sleep(.05)
                self.assertTrue(out_all.startswith(out));self.assertTrue(err_all.startswith(err));self.assertIn(b'\"value\": 9',out_all);self.assertIn(b'\"value\": 9',err_all)
                self.rpc({'op':'close','state_dir':str(state),'session_id':session});app.wait(timeout=5)
                self.wait_broker_finalized(state,session)
            finally:
                if app.poll() is None:app.terminate();app.wait(timeout=5)

if __name__=='__main__':unittest.main(verbosity=2)
