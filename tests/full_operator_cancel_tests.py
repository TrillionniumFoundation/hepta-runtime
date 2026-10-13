#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bounded stdio request cancellation with an authenticated loopback fixture.

The backend records one synthetic effect per submitted call. A cancellation
notification can release a wait, but never retracts the recorded effect.
"""
import copy
import fcntl
import http.server
import io
import json
import os
import pathlib
import select
import socket
import subprocess
import sys
import threading
import tempfile
import time
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
import chatgpt_full_operator as F
from mcp_tool_contract import ToolContract,make_contract,canonical
from full_operator_facade_tests import TOOLS


def request(ident,method='tools/call',params=None):
    return {'jsonrpc':'2.0','id':ident,'method':method,
            'params':params if params is not None else {'name':'shell_start','arguments':{'command':'fixture-effect'}}}


def cancellation(ident,**extra):
    return {'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':ident,**extra}}


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def do_POST(self):
        value=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method=value['method']
        item={'request':value,'session':self.headers.get('Mcp-Session-Id'),
              'protocol':self.headers.get('MCP-Protocol-Version'),
              'token':self.headers.get('X-Hepta-Runtime-Token')}
        with self.server.changed:
            self.server.seen.append(item)
            if method=='tools/call':self.server.calls.append(item)
            if method=='notifications/cancelled':self.server.cancels.append(item)
            self.server.changed.notify_all()
        if method.startswith('notifications/'):
            status=self.server.cancel_status if method=='notifications/cancelled' else 202
            if method=='notifications/cancelled' and self.server.cancel_gate is not None:self.server.cancel_gate.wait(4)
            if method=='notifications/cancelled' and self.server.cancel_trickle:
                self.send_response(status);self.send_header('Content-Length','16');self.end_headers()
                for _ in range(16):
                    try:self.wfile.write(b'x');self.wfile.flush()
                    except OSError:break
                    time.sleep(.08)
                return
            self.send_response(status);self.send_header('Content-Length','0');self.end_headers()
            if method=='notifications/cancelled' and self.server.release_on_cancel:self.server.release.set()
            return
        if method=='initialize':
            self.server.initializations+=1
            result={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'fixture','version':'1'}}
        elif method=='tools/list':result={'tools':self.server.tools}
        elif method=='tools/call':result={'content':[{'type':'text','text':'effect-recorded'}],'isError':False}
        else:result={}
        if method=='tools/call' and self.server.invalid_response is not None:
            result={'content':[{'type':'text','text':self.server.invalid_response}],'isError':False}
            raw=json.dumps({'jsonrpc':'2.0','id':value['id'],'result':result}).encode()
        else:raw=canonical({'jsonrpc':'2.0','id':value['id'],'result':result})
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
        if method=='initialize' and self.server.send_sid:self.send_header('Mcp-Session-Id','session-fixture-'+str(self.server.initializations))
        self.end_headers()
        if method=='tools/call' and self.server.delay:
            self.server.started.set();self.server.release.wait(10)
            if self.server.disconnect:
                self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
        try:self.wfile.write(raw)
        except (BrokenPipeError,ConnectionResetError):pass


class Output:
    def __init__(self):self.changed=threading.Condition();self.values=[];self.frames=[]
    def write(self,data):
        # Each write must be a complete line even when refusals race a reply.
        assert data.endswith(b'\n') and data.count(b'\n')==1
        value=json.loads(data)
        with self.changed:self.frames.append(data);self.values.append(value);self.changed.notify_all()
        return len(data)
    def flush(self):pass
    def wait(self,ident,timeout=3,predicate=lambda value:True):
        deadline=time.monotonic()+timeout
        with self.changed:
            while True:
                for value in self.values:
                    if type(value['id']) is type(ident) and value['id']==ident and predicate(value):return value
                remaining=deadline-time.monotonic()
                if remaining<=0:raise AssertionError('response deadline for fixture identity')
                self.changed.wait(remaining)


class Stream:
    def __init__(self,proxy):
        read,write=os.pipe();self.input=os.fdopen(read,'rb');self.writer=os.fdopen(write,'wb')
        self.output=Output();self.thread=threading.Thread(target=proxy.serve,args=(self.input,self.output),daemon=True);self.thread.start()
    def send(self,value):self.writer.write(canonical(value)+b'\n');self.writer.flush()
    def close(self):
        if not self.writer.closed:self.writer.close()
        self.thread.join(4)
        if not self.thread.is_alive():self.input.close()


class CancellationTests(unittest.TestCase):
    def setUp(self):
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Backend);self.server.daemon_threads=True
        self.server.tools=copy.deepcopy(TOOLS);self.server.changed=threading.Condition()
        self.server.seen=[];self.server.calls=[];self.server.cancels=[];self.server.initializations=0
        self.server.started=threading.Event();self.server.release=threading.Event();self.server.delay=True
        self.server.release_on_cancel=True;self.server.cancel_status=202;self.server.disconnect=False
        self.server.cancel_gate=None;self.server.send_sid=True;self.server.cancel_trickle=False;self.server.invalid_response=None
        self.http_thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.http_thread.start()
        self.proxy=F.NativeProxy(f'http://127.0.0.1:{self.server.server_port}/mcp','fixture-private-token',
                                 ToolContract(make_contract(copy.deepcopy(TOOLS))),timeout=8)
        self.stream=None
    def tearDown(self):
        self.server.release.set()
        if self.server.cancel_gate is not None:self.server.cancel_gate.set()
        if self.stream:self.stream.close()
        self.server.shutdown();self.server.server_close();self.http_thread.join(2)
    def begin(self):
        self.stream=Stream(self.proxy)
        self.stream.send(request('init','initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'fixture','version':'1'}}))
        self.assertIn('result',self.stream.output.wait('init'))
    def start(self,ident=7):
        self.stream.send(request(ident));self.assertTrue(self.server.started.wait(2),'native request not received')
    def backend_wait(self,predicate,timeout=2):
        deadline=time.monotonic()+timeout
        with self.server.changed:
            while not predicate():
                remaining=deadline-time.monotonic()
                if remaining<=0:raise AssertionError('backend evidence deadline')
                self.server.changed.wait(remaining)
    def active_wait(self,count):
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            with self.proxy._active_lock:
                if len(self.proxy._active)==count:return
            time.sleep(.005)
        self.fail('active table evidence deadline')
    def test_cancel_reaches_owned_native_id_and_frozen_session_during_wait(self):
        self.begin();self.start()
        call=self.server.calls[0];native=call['request']['id']
        self.assertNotEqual(native,7);self.assertTrue(native.startswith('hepta-call-'))
        self.stream.send(cancellation(7,reason='private-reason',_meta={'secret':'private-metadata'}))
        self.backend_wait(lambda:len(self.server.cancels)==1)
        forwarded=self.server.cancels[0]
        self.assertEqual(forwarded['request']['params'],{'requestId':native})
        self.assertEqual((forwarded['session'],forwarded['protocol']),(call['session'],call['protocol']))
        self.assertEqual(forwarded['token'],'fixture-private-token')
        reply=self.stream.output.wait(7);self.assertIn('result',reply)
        # A confirmed response can still describe a completed effect.
        self.assertEqual(len(self.server.calls),1)
        self.assertNotIn('fixture-private-token',json.dumps(self.stream.output.values))
        self.assertNotIn('private-reason',json.dumps(forwarded['request']))
    def test_unknown_native_internal_and_malformed_targets_are_ignored(self):
        self.begin();self.start()
        internal=next(item['request']['id'] for item in self.server.seen if item['request']['method']=='tools/list')
        for value in [cancellation('unknown'),cancellation('7'),cancellation(self.server.calls[0]['request']['id']),
                      cancellation(internal),cancellation(True),cancellation(7,reason=object.__name__*400),
                      {'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':7,'upstream':'forbidden'}}]:
            self.stream.send(value)
        time.sleep(.1);self.assertEqual(self.server.cancels,[])
        self.stream.send(cancellation(7));self.assertIn('result',self.stream.output.wait(7))
        self.assertEqual(len(self.server.cancels),1)
    def test_typed_pending_identity_cancel_skips_unsent_call(self):
        self.begin();self.start(7)
        self.stream.send(request('7'));self.active_wait(2)
        self.stream.send(cancellation('7'));time.sleep(.05)
        self.assertEqual(self.server.cancels,[])
        self.stream.send(cancellation(7));self.stream.output.wait(7)
        skipped=self.stream.output.wait('7')
        self.assertEqual(skipped['error']['data']['outcome'],'not_submitted')
        self.assertEqual(len(self.server.calls),1);self.assertEqual(len(self.server.cancels),1)
    def test_duplicate_active_request_has_no_second_effect(self):
        self.begin();self.start();self.stream.send(request(7))
        refused=self.stream.output.wait(None);self.assertEqual(refused['error']['code'],-32600)
        self.stream.send(cancellation(7));self.stream.output.wait(7)
        self.assertEqual(len(self.server.calls),1)
    def test_completed_identity_is_not_reused_even_after_idle_initialize(self):
        self.server.delay=False;self.begin()
        self.stream.send(request(7));self.assertIn('result',self.stream.output.wait(7));old_native=self.server.calls[0]['request']['id']
        self.stream.send(request(7))
        refused=self.stream.output.wait(7,predicate=lambda value:'error' in value)
        self.assertEqual(refused['error']['data']['outcome'],'not_submitted')
        self.stream.send(cancellation(7));time.sleep(.05);self.assertEqual(self.server.cancels,[])
        self.stream.send(request('init2','initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'new','version':'1'}}))
        self.assertIn('result',self.stream.output.wait('init2'))
        self.stream.send(request(7));time.sleep(.05);self.assertEqual(len(self.server.calls),1)
        self.stream.send(request(8));self.assertIn('result',self.stream.output.wait(8))
        self.assertNotEqual(old_native,self.server.calls[1]['request']['id'])
        self.stream.send(cancellation(7));time.sleep(.05);self.assertEqual(self.server.cancels,[])
    def test_active_table_and_queue_are_bounded(self):
        with mock.patch.object(F,'MAX_ACTIVE_REQUESTS',4):
            self.begin();self.start(1)
            for ident in [2,3,4]:self.stream.send(request(ident))
            self.active_wait(4);self.stream.send(request(5))
            refused=self.stream.output.wait(5)
            self.assertEqual(refused['error']['data']['outcome'],'not_submitted')
            with self.proxy._active_lock:self.assertEqual(len(self.proxy._active),4)
            self.stream.writer.close();self.stream.thread.join(4)
            self.assertFalse(self.stream.thread.is_alive());self.assertEqual(len(self.server.calls),1)
            for ident in [2,3,4]:self.assertEqual(self.stream.output.wait(ident)['error']['data']['outcome'],'not_submitted')
    def test_retired_identity_budget_fails_closed_across_idle_initialize(self):
        self.server.delay=False
        with mock.patch.object(F,'MAX_RETIRED_IDS',3):
            self.begin()
            for ident in [1,2]:self.stream.send(request(ident));self.assertIn('result',self.stream.output.wait(ident))
            self.stream.send(request(3));self.assertEqual(self.stream.output.wait(3)['error']['data']['outcome'],'not_submitted')
            self.assertEqual(len(self.server.calls),2)
            self.stream.send(request('init2','initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'new','version':'1'}}))
            self.assertEqual(self.stream.output.wait('init2')['error']['data']['outcome'],'not_submitted')
            self.stream.send(request(4));self.assertEqual(self.stream.output.wait(4)['error']['data']['outcome'],'not_submitted')
            self.assertEqual(len(self.server.calls),2)
    def test_failed_cancel_does_not_retry_operation_or_cancel(self):
        self.server.cancel_status=503;self.server.release_on_cancel=False;self.server.disconnect=True
        self.begin();self.start();self.stream.send(cancellation(7))
        self.backend_wait(lambda:len(self.server.cancels)==1);self.server.release.set()
        reply=self.stream.output.wait(7)
        self.assertEqual(reply['error']['data']['outcome'],'unknown')
        self.assertEqual(reply['error']['data']['cancellation'],'request_intent_only')
        self.assertFalse(reply['error']['data']['automatic_retry'])
        self.stream.send(cancellation(7));time.sleep(.1)
        self.assertEqual(len(self.server.calls),1);self.assertEqual(len(self.server.cancels),1)
    def test_eof_has_one_deadline_skips_queue_and_retains_unknown_write(self):
        self.server.release_on_cancel=False
        with mock.patch.object(F,'SHUTDOWN_TIMEOUT',.5):
            self.begin();self.start();self.stream.send(request(8));self.active_wait(2)
            began=time.monotonic();self.stream.writer.close();self.stream.thread.join(1.5)
            self.assertFalse(self.stream.thread.is_alive());self.assertLess(time.monotonic()-began,1.3)
            self.backend_wait(lambda:len(self.server.cancels)==1)
            reply=self.stream.output.wait(7)
            self.assertEqual(reply['error']['data']['outcome'],'unknown')
            self.assertFalse(reply['error']['data']['automatic_retry'])
            self.assertEqual(self.stream.output.wait(8)['error']['data']['outcome'],'not_submitted')
            self.assertEqual(len(self.server.calls),1)
            before=len(self.stream.output.values);self.server.release.set();time.sleep(.1)
            self.assertEqual(len(self.stream.output.values),before,'late response duplicated a finalized identity')
    def test_output_failure_and_blocked_writer_do_not_make_eof_join_unbounded(self):
        class BlockingOutput:
            def write(self,data):gate.wait(3)
            def flush(self):pass
        gate=threading.Event()
        with mock.patch.object(F,'SHUTDOWN_TIMEOUT',.3):
            start=time.monotonic();self.proxy.serve(io.BytesIO(b'not-json\n'),BlockingOutput())
            self.assertLess(time.monotonic()-start,.8)
        gate.set();self.assertEqual(self.server.calls,[])
    def test_native_cancel_rpc_rejects_target_outside_active_mapping(self):
        self.begin();self.start()
        with self.assertRaises(ValueError):
            self.proxy.exchange(cancellation(self.server.calls[0]['request']['id']),binding=(self.proxy.session,self.proxy.protocol))
        self.assertEqual(self.server.cancels,[])
        self.stream.send(cancellation(7));self.stream.output.wait(7)
    def test_unreviewed_contract_still_refuses_call_without_effect(self):
        self.server.delay=False;self.begin();self.server.tools[0]['description']='unreviewed drift'
        self.stream.send(request(7));reply=self.stream.output.wait(7)
        self.assertIn('error',reply);self.assertEqual(self.server.calls,[])
        self.stream.send(cancellation(7));time.sleep(.05);self.assertEqual(self.server.cancels,[])
    def test_cold_legacy_initialize_then_queued_call_bootstraps_without_reset(self):
        self.server.delay=False
        with self.proxy._state_lock:
            self.stream=Stream(self.proxy)
            self.stream.send(request('init','initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'fixture','version':'1'}}))
            self.stream.send(request(7));self.active_wait(2)
        self.assertIn('result',self.stream.output.wait('init'));self.assertIn('result',self.stream.output.wait(7))
        self.assertEqual(self.server.initializations,1)
        self.assertEqual(self.server.calls[0]['session'],'session-fixture-1')
    def test_late_cancel_of_retired_control_id_cannot_target_a_new_tool(self):
        self.server.delay=False;self.begin();self.stream.send(request(7,'ping',{}))
        self.assertIn('result',self.stream.output.wait(7))
        self.stream.send(request(7));self.assertEqual(self.stream.output.wait(7,predicate=lambda value:'error' in value)['error']['data']['outcome'],'not_submitted')
        self.stream.send(cancellation(7));time.sleep(.05)
        self.assertEqual(self.server.calls,[]);self.assertEqual(self.server.cancels,[])
    def test_non_utf8_identity_is_rejected_without_disrupting_active_call(self):
        self.begin();self.start()
        malformed=request('\ud800')
        self.stream.writer.write(json.dumps(malformed).encode()+b'\n');self.stream.writer.flush()
        self.assertEqual(self.stream.output.wait(None)['error']['code'],-32600)
        self.stream.writer.write(json.dumps(cancellation('\ud800')).encode()+b'\n');self.stream.writer.flush()
        self.stream.send(cancellation(7));self.assertIn('result',self.stream.output.wait(7))
        self.assertEqual(len(self.server.calls),1);self.assertEqual(len(self.server.cancels),1)
    def test_noncanonical_payload_and_deep_json_are_rejected_before_submission(self):
        self.begin()
        values=[request(1,params={'name':'shell_start','arguments':{'bad':'\ud800'}}),
                request(2,params={'name':'shell_start','arguments':{'bad':float('nan')}}),
                request(3,params={'name':'shell_start','arguments':{},'_meta':{F.VERSION_KEY:'\ud800',F.CAPABILITIES_KEY:{}}})]
        for value in values:self.stream.writer.write(json.dumps(value).encode()+b'\n')
        self.stream.writer.write(b'['*1200+b']'*1200+b'\n');self.stream.writer.flush()
        deadline=time.monotonic()+2
        with self.stream.output.changed:
            while len(self.stream.output.values)<5:
                remaining=deadline-time.monotonic()
                if remaining<=0:self.fail('invalid JSON response evidence deadline')
                self.stream.output.changed.wait(remaining)
        errors=[value for value in self.stream.output.values if 'error' in value]
        self.assertEqual(len(errors),4)
        self.assertEqual([value['error']['code'] for value in errors[:3]],[-32600,-32600,-32600])
        # CPython decoders differ in their recursion accounting. Rejection
        # can occur at parse time or at strict request validation.
        self.assertIn(errors[3]['error']['code'],[-32600,-32700])
        for value in errors[:3]:self.assertEqual(value['error']['data']['outcome'],'not_submitted')
        self.assertEqual(self.server.calls,[])
        self.start(7);self.stream.send(cancellation(7));self.assertIn('result',self.stream.output.wait(7))
    def test_cold_pipelined_modern_calls_share_first_validated_session(self):
        self.server.delay=False
        with self.proxy._state_lock:
            self.stream=Stream(self.proxy)
            for ident in [7,8]:
                value=request(ident);value['params']['_meta']={F.VERSION_KEY:F.MODERN_VERSION,F.CAPABILITIES_KEY:{}}
                self.stream.send(value)
            self.active_wait(2)
        for ident in [7,8]:self.assertEqual(self.stream.output.wait(ident)['result']['resultType'],'complete')
        self.assertEqual(self.server.initializations,1);self.assertEqual(len(self.server.calls),2)
        self.assertEqual({value['session'] for value in self.server.calls},{'session-fixture-1'})
    def test_existing_session_replacement_cannot_reset_submitted_call(self):
        self.begin();self.start()
        old_sid=self.proxy.session
        reply=self.proxy.dispatch(request('other-init','initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'new','version':'1'}}))
        self.assertIn('error',reply);self.assertEqual(self.proxy.session,old_sid);self.assertEqual(self.server.initializations,1)
        self.stream.send(cancellation(7));self.stream.output.wait(7)
        self.assertEqual(self.server.cancels[0]['session'],old_sid)
    def test_missing_native_session_id_refuses_tool_submission(self):
        self.server.send_sid=False;self.stream=Stream(self.proxy)
        value=request(7);value['params']['_meta']={F.VERSION_KEY:F.MODERN_VERSION,F.CAPABILITIES_KEY:{}}
        self.stream.send(value);self.assertIn('error',self.stream.output.wait(7))
        self.assertEqual(self.server.calls,[]);self.assertFalse(self.proxy.initialized)
    def test_eof_unresolved_read_only_call_is_unavailable(self):
        self.server.release_on_cancel=False
        with mock.patch.object(F,'SHUTDOWN_TIMEOUT',.5):
            self.begin();self.stream.send(request(7,params={'name':'host_list','arguments':{}}));self.assertTrue(self.server.started.wait(2))
            self.stream.writer.close();self.stream.thread.join(1.5)
            self.assertFalse(self.stream.thread.is_alive())
            self.assertEqual(self.stream.output.wait(7)['error']['data']['outcome'],'unavailable')
    def test_slot_release_schedules_only_cancel_intents_never_sent(self):
        self.server.cancel_gate=threading.Event();self.server.release_on_cancel=False
        self.begin()
        for ident in [1,2]:
            self.server.started.clear();self.server.release.clear();self.start(ident)
            self.stream.send(cancellation(ident));self.backend_wait(lambda:len(self.server.cancels)==ident)
            self.server.release.set();self.assertIn('result',self.stream.output.wait(ident))
        self.server.started.clear();self.server.release.clear();self.start(3);self.stream.send(cancellation(3))
        time.sleep(.05);self.assertEqual(len(self.server.cancels),2)
        with self.proxy._active_lock:self.assertLessEqual(len(self.proxy._cancel_threads),2)
        self.server.cancel_gate.set();self.backend_wait(lambda:len(self.server.cancels)==3)
        self.server.release.set();self.stream.output.wait(3)
        self.assertEqual(len(self.server.calls),3);self.assertEqual(len(self.server.cancels),3)
    def test_broken_stdout_with_open_stdin_exits_without_waiting_for_eof(self):
        source_read,source_write=os.pipe();output_read,output_write=os.pipe();os.close(output_read)
        source=os.fdopen(source_read,'rb');sink=os.fdopen(output_write,'wb')
        try:
            with mock.patch.object(F,'SHUTDOWN_TIMEOUT',.4):
                worker=threading.Thread(target=self.proxy.serve,args=(source,sink),daemon=True);worker.start()
                os.write(source_write,b'not-json\n');worker.join(1)
                self.assertFalse(worker.is_alive(),'writer failure waited for caller EOF')
        finally:os.close(source_write);source.close();sink.close()
    def test_cancel_trickle_cannot_hold_a_slot_past_absolute_deadline(self):
        self.server.cancel_trickle=True;self.server.release_on_cancel=False
        with mock.patch.object(F,'CANCEL_TIMEOUT',.25):
            self.begin();self.start();began=time.monotonic();self.stream.send(cancellation(7))
            self.backend_wait(lambda:len(self.server.cancels)==1)
            deadline=time.monotonic()+.7
            while time.monotonic()<deadline:
                with self.proxy._active_lock:
                    if not self.proxy._cancel_threads:break
                time.sleep(.01)
            with self.proxy._active_lock:
                self.assertFalse(self.proxy._cancel_threads)
                self.assertTrue(self.proxy._active[(int,7)].cancel_failed)
            self.assertLess(time.monotonic()-began,.8)
            self.server.release.set();self.stream.output.wait(7)
            self.assertEqual(len(self.server.calls),1);self.assertEqual(len(self.server.cancels),1)
    def test_invalid_upstream_result_is_unknown_without_replay_or_worker_loss(self):
        self.server.delay=False;self.begin()
        for ident,invalid in [(7,'\ud800'),(8,float('nan'))]:
            self.server.invalid_response=invalid;self.stream.send(request(ident));reply=self.stream.output.wait(ident)
            self.assertEqual(reply['error']['data']['outcome'],'unknown')
            self.assertFalse(reply['error']['data']['automatic_retry'])
        self.server.invalid_response=None;self.stream.send(request(9,'ping',{}))
        self.assertIn('result',self.stream.output.wait(9));self.assertEqual(len(self.server.calls),2)
    def test_actual_trace_process_keeps_unread_stderr_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);contract=root/'contract';token=root/'token'
            contract.write_bytes(canonical(make_contract(copy.deepcopy(TOOLS))));contract.chmod(0o600)
            token.write_text('fixture-private-token');token.chmod(0o600)
            import hashlib
            command=[sys.executable,str(ROOT/'deploy/chatgpt_full_operator.py'),'--stdio',
                     '--upstream',f'http://127.0.0.1:{self.server.server_port}/mcp','--token-file',str(token),
                     '--contract',str(contract),'--contract-sha256',hashlib.sha256(contract.read_bytes()).hexdigest(),
                     '--acknowledge-full-operator']
            process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                     env={**os.environ,'HEPTA_MCP_PROTOCOL_TRACE':'1'})
            try:
                fcntl.fcntl(process.stderr.fileno(),fcntl.F_SETPIPE_SZ,4096)
                pipe_capacity=fcntl.fcntl(process.stderr.fileno(),fcntl.F_GETPIPE_SZ)
                # Drain protocol replies but leave the diagnostics pipe full.
                for ident in range(200):
                    value=request(ident,'server/discover',{'_meta':{F.VERSION_KEY:F.MODERN_VERSION,F.CAPABILITIES_KEY:{}}})
                    process.stdin.write(canonical(value)+b'\n');process.stdin.flush()
                    self.assertTrue(select.select([process.stdout],[],[],2)[0],'trace pipe blocked protocol response')
                    self.assertIn('result',json.loads(process.stdout.readline()))
                process.stdin.close();process.wait(timeout=5)
                stderr=process.stderr.read();self.assertEqual(process.returncode,0,stderr)
                self.assertNotIn(b'_enter_buffered_busy',stderr);self.assertNotIn(b'fixture-private-token',stderr)
                self.assertGreaterEqual(len(stderr),pipe_capacity-512)
                self.assertLess(stderr.count(b'\n'),200,'trace did not exercise dropped records at capacity')
                self.assertEqual(self.server.calls,[])
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=2)
                process.stdout.close();process.stderr.close()
    def test_actual_process_exits_with_unread_stdout_and_closed_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);contract=root/'contract';token=root/'token'
            contract.write_bytes(canonical(make_contract(copy.deepcopy(TOOLS))));contract.chmod(0o600)
            token.write_text('fixture-private-token');token.chmod(0o600)
            import hashlib
            command=[sys.executable,str(ROOT/'deploy/chatgpt_full_operator.py'),'--stdio',
                     '--upstream',f'http://127.0.0.1:{self.server.server_port}/mcp','--token-file',str(token),
                     '--contract',str(contract),'--contract-sha256',hashlib.sha256(contract.read_bytes()).hexdigest(),
                     '--acknowledge-full-operator']
            process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                fcntl.fcntl(process.stdout.fileno(),fcntl.F_SETPIPE_SZ,4096)
                # Fill the real stdout pipe and leave it unread until exit.
                process.stdin.write(b'not-json\n'*600);process.stdin.close()
                process.wait(timeout=5)
                stderr=process.stderr.read();self.assertEqual(process.returncode,0,stderr)
                self.assertNotIn(b'_enter_buffered_busy',stderr)
                self.assertEqual(self.server.seen,[])
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=2)
                process.stdout.close();process.stderr.close()


if __name__=='__main__':unittest.main()
