#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Safe idle keepalive and legacy expiry recovery over disposable HTTP sockets.

The fixture counts every submitted call, so reconnecting cannot hide a replay.
No installed endpoint, real host, token file or service is used.
"""
import copy
import http.server
import json
import pathlib
import socket
import sys
import threading
import time
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
import chatgpt_full_operator as F
from mcp_tool_contract import ToolContract,canonical,make_contract
from full_operator_facade_tests import tool

TOOLS=[tool(name,True) for name in ('host_list','view','search_list','search_results',
    'request_history','request_status','operation_status','process_list_page',
    'request_archive','usage_stats')]+[tool('shell_start'),tool('workdir')]


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def respond(self,status,raw,content_type='text/plain',sid=None):
        self.send_response(status);self.send_header('Content-Length',str(len(raw)))
        self.send_header('Content-Type',content_type)
        if sid:self.send_header('Mcp-Session-Id',sid)
        self.end_headers()
        try:self.wfile.write(raw);self.wfile.flush()
        except OSError:pass
    def do_POST(self):
        request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method=request['method'];sid=self.headers.get('Mcp-Session-Id')
        with self.server.changed:
            self.server.seen.append((method,sid,request));self.server.changed.notify_all()
        if method=='tools/list' and self.server.catalog_fault is not None:
            fault=self.server.catalog_fault;self.server.catalog_fault=None
            if fault=='expired':self.server.expired.add(sid)
            if fault=='other404':self.respond(404,b'route not found');return
            if fault=='disconnect':self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
        if method=='tools/list' and sid in self.server.expired:
            self.respond(404,b'Not Found: Session not found');return
        if method.startswith('notifications/'):
            self.respond(202,b'');return
        if method=='initialize':
            self.server.inits+=1;sid='private-session-'+str(self.server.inits)
            result={'protocolVersion':'2025-11-25','capabilities':{'tools':{}},
                    'serverInfo':{'name':'isolated','version':'1'}}
        elif method=='tools/list':result={'tools':self.server.tools}
        elif method=='tools/call':
            self.server.calls.append(request)
            if self.server.call_fault=='expired':self.respond(404,b'Not Found: Session not found');return
            if self.server.call_fault=='disconnect':self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
            value=self.server.scope or {'host':'fixture-only'}
            result={'content':[{'type':'text','text':json.dumps(value)}],'isError':False}
        else:result={}
        raw=canonical({'jsonrpc':'2.0','id':request['id'],'result':result})
        if method=='ping' and self.server.trickle_ping:
            self.send_response(200);self.send_header('Content-Length',str(len(raw)))
            self.send_header('Content-Type','application/json');self.end_headers()
            self.server.ping_started.set()
            for byte in raw:
                try:self.wfile.write(bytes([byte]));self.wfile.flush()
                except OSError:break
                time.sleep(.035)
            return
        self.respond(200,raw,'application/json',sid if method=='initialize' else None)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Backend)
        self.server.daemon_threads=True;self.server.changed=threading.Condition()
        self.server.seen=[];self.server.calls=[];self.server.inits=0;self.server.catalog_fault=None
        self.server.expired=set()
        self.server.call_fault=None;self.server.scope=None;self.server.tools=copy.deepcopy(TOOLS)
        self.server.trickle_ping=False;self.server.ping_started=threading.Event()
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True);self.worker.start()
        self.proxy=F.NativeProxy(f'http://127.0.0.1:{self.server.server_port}/mcp','fixture-only-token',
            ToolContract(make_contract(copy.deepcopy(TOOLS))),timeout=.8)
        self.counter=0
    def tearDown(self):
        self.proxy.close();self.server.shutdown();self.server.server_close();self.worker.join(2)
    def dispatch(self,method,params=None):
        self.counter+=1
        return self.proxy.dispatch({'jsonrpc':'2.0','id':self.counter,'method':method,'params':params or {}})
    def initialize(self):
        value=self.dispatch('initialize',{'protocolVersion':'2025-11-25','capabilities':{},
            'clientInfo':{'name':'expiry-fixture','version':'1'}})
        self.assertIn('result',value);return value
    def call(self,name='host_list'):return self.dispatch('tools/call',{'name':name,'arguments':{}})
    def expire(self):self.server.catalog_fault='expired'
    def state_lost(self,value):
        self.assertEqual(value['error']['data']['outcome'],'not_submitted')
        self.assertTrue(value['error']['data']['reinitialize_required'])
        self.assertFalse(value['error']['data']['automatic_retry'])
    def proof(self,**extra):
        return {'ownership_scope':'authenticated_private_operator_credential',
                'credential_metadata_resume':True,**extra}
    def test_legacy_host_read_recovers_once_before_call_submission(self):
        self.initialize();before=self.proxy.session;self.expire()
        self.assertIn('result',self.call());self.assertNotEqual(self.proxy.session,before)
        self.assertEqual(self.server.inits,2);self.assertEqual(len(self.server.calls),1)
        self.assertTrue(self.proxy._legacy_state_lost)
    def test_job_page_can_recover_but_private_usage_and_archive_require_scope_proof(self):
        self.initialize();self.expire();self.assertIn('result',self.call('process_list_page'))
        self.state_lost(self.call('usage_stats'));self.state_lost(self.call('request_archive'))
        self.initialize();self.server.scope=self.proof();self.call('request_history')
        self.expire();self.assertIn('result',self.call('request_archive'))
        self.state_lost(self.call('usage_stats'))
        self.initialize();self.call('usage_stats');self.expire()
        self.assertIn('result',self.call('usage_stats'))
    def test_recovered_session_never_silently_resets_workdir_or_view_state(self):
        self.initialize();self.expire();self.assertIn('result',self.call())
        for name in ('view','workdir','shell_start'):
            self.state_lost(self.call(name))
        self.assertEqual(len(self.server.calls),1)
        self.initialize();self.assertIn('result',self.call('workdir'))
        self.assertFalse(self.proxy._legacy_state_lost);self.assertEqual(len(self.server.calls),2)
    def test_first_expired_mutation_has_proven_not_submitted_outcome(self):
        self.initialize();self.expire();self.state_lost(self.call('shell_start'))
        self.assertEqual(self.server.inits,1);self.assertEqual(self.server.calls,[])
        self.state_lost(self.call('view'))
        self.assertIn('result',self.call('host_list'));self.assertEqual(self.server.inits,2)
    def test_readonly_hint_alone_does_not_authorize_session_reset(self):
        self.initialize();self.expire();self.state_lost(self.call('view'))
        self.assertEqual(self.server.inits,1);self.assertEqual(self.server.calls,[])
    def test_scoped_metadata_needs_authenticated_response_proof(self):
        for name in ('search_list','request_history','operation_status'):
            self.initialize();self.expire();self.state_lost(self.call(name))
        self.assertEqual(self.server.calls,[]);self.assertEqual(self.server.inits,3)
    def test_authenticated_metadata_can_resume_and_proofs_are_family_scoped(self):
        self.initialize();self.server.scope=self.proof()
        self.assertIn('result',self.call('search_list'));self.expire()
        self.assertIn('result',self.call('search_results'))
        self.state_lost(self.call('request_status'));self.state_lost(self.call('operation_status'))
        self.assertEqual(self.server.inits,2);self.assertEqual(len(self.server.calls),2)
    def test_native_session_only_or_incomplete_scope_revokes_prior_proof(self):
        for scope in ({'ownership_scope':'native_mcp_session_only','credential_metadata_resume':False},
                      self.proof(credential_metadata_resume=False)):
            self.initialize();self.server.scope=self.proof();self.call('request_history')
            self.server.scope=scope;self.call('request_history');self.expire()
            self.state_lost(self.call('request_status'))
        self.assertEqual(len(self.server.calls),4);self.assertEqual(self.server.inits,2)
    def test_explicit_initialize_and_credential_change_clear_old_scope_proof(self):
        self.initialize();self.server.scope=self.proof();self.call('search_list')
        self.proxy.token='different-fixture-token';self.expire();self.state_lost(self.call('search_results'))
        self.proxy.token='fixture-only-token';self.initialize();self.expire()
        self.state_lost(self.call('search_results'));self.assertEqual(len(self.server.calls),1)
    def test_unrelated_http404_or_transport_failure_never_reinitializes(self):
        self.initialize()
        for fault in ('other404','disconnect'):
            self.server.catalog_fault=fault;self.assertIn('error',self.call())
        self.assertEqual(self.server.inits,1);self.assertEqual(self.server.calls,[])
    def test_expiry_after_call_submission_never_replays_read_or_write(self):
        self.initialize()
        for name in ('host_list','shell_start'):
            self.server.call_fault='expired';value=self.call(name)
            self.assertIn('error',value);self.assertFalse(value['error']['data']['automatic_retry'])
        self.assertEqual(self.server.inits,1);self.assertEqual(len(self.server.calls),2)
    def test_response_loss_never_replays_a_write(self):
        self.initialize();self.server.call_fault='disconnect';value=self.call('shell_start')
        self.assertEqual(value['error']['data']['outcome'],'unknown')
        self.assertEqual(self.server.inits,1);self.assertEqual(len(self.server.calls),1)
    def test_other_active_request_prevents_session_replacement(self):
        self.initialize();pending,refused=self.proxy._reserve({'jsonrpc':'2.0','id':'busy',
            'method':'tools/call','params':{'name':'shell_start','arguments':{}}})
        self.assertIsNone(refused)
        try:
            self.expire();self.state_lost(self.call());self.assertEqual(self.server.inits,1)
        finally:self.proxy._finish(pending)
        self.assertIn('result',self.call());self.assertEqual(self.server.inits,2)
    def test_recovery_revalidates_new_native_catalog_before_any_call(self):
        self.initialize();self.server.tools[0]['description']='unreviewed drift';self.expire()
        self.assertIn('error',self.call());self.assertEqual(self.server.calls,[])
        self.assertEqual(self.server.inits,2)
    def test_keepalive_sends_only_bound_ping_and_close_stops_worker(self):
        with mock.patch.object(F,'KEEPALIVE_INTERVAL',.025):
            self.initialize();deadline=time.monotonic()+1
            with self.server.changed:
                while not any(item[0]=='ping' for item in self.server.seen):
                    remaining=deadline-time.monotonic();self.assertGreater(remaining,0)
                    self.server.changed.wait(remaining)
            self.proxy.close();self.assertFalse(self.proxy._keepalive_thread.is_alive())
        pings=[item for item in self.server.seen if item[0]=='ping']
        self.assertTrue(pings);self.assertTrue(all(item[1]==self.proxy.session for item in pings))
        self.assertEqual(self.server.inits,1);self.assertEqual(self.server.calls,[])
    def test_keepalive_failure_never_reinitializes_or_calls_a_tool(self):
        self.initialize();self.server.server_close()
        self.proxy._keepalive_once();self.assertEqual(self.server.inits,1)
        self.assertEqual(self.server.calls,[])
    def test_keepalive_has_absolute_deadline_when_peer_trickles(self):
        self.server.trickle_ping=True
        with mock.patch.object(F,'KEEPALIVE_INTERVAL',.025),mock.patch.object(F,'KEEPALIVE_TIMEOUT',.12):
            self.initialize();self.assertTrue(self.server.ping_started.wait(1))
            started=time.monotonic();self.proxy.close(timeout=.6)
            self.assertFalse(self.proxy._keepalive_thread.is_alive())
            self.assertLess(time.monotonic()-started,.6)
        self.assertEqual(self.server.inits,1);self.assertEqual(self.server.calls,[])


if __name__=='__main__':unittest.main(verbosity=2)
