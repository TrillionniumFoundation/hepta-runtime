#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Pinned full-operator contract and actual stdio/HTTP transport fault tests.
The fake backend counts writes; no real shell, credential or host policy is touched.
"""
import copy
import hashlib
import http.server
import importlib.util
import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'deploy'))
import chatgpt_full_operator as F
from mcp_tool_contract import ToolContract,make_contract,canonical


def tool(name,read=False):
    return {'name':name,'description':'fixture operation '+name,'inputSchema':{'type':'object','properties':{'command':{'type':'string'}}},
            'annotations':{'readOnlyHint':read,'destructiveHint':not read,'idempotentHint':read,'openWorldHint':True}}
TOOLS=[tool('host_list',True),tool('shell_start'),tool('sudo_start'),tool('binary_write')]


class ContractTests(unittest.TestCase):
    def setUp(self):self.value=make_contract(copy.deepcopy(TOOLS));self.contract=ToolContract(self.value)
    def test_full_catalog_preserves_every_input_and_annotation(self):
        self.assertEqual(self.contract.tools,sorted(TOOLS,key=lambda t:t['name']))
        self.assertFalse(self.contract.read_only('shell_start'));self.assertTrue(self.contract.read_only('host_list'))
    def test_discovery_and_direct_calls_share_the_same_contract(self):
        self.assertIsNone(F.valid_request({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'sudo_start','arguments':{}}},self.contract))
        bad=F.valid_request({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'unreviewed','arguments':{}}},self.contract)
        self.assertEqual(bad['error']['code'],-32601)
    def test_extra_tool_schema_and_annotation_drift_fail_closed(self):
        for replacement in ([*TOOLS,tool('new_tool')],TOOLS[:-1]):
            with self.assertRaises(ValueError):self.contract.verify(replacement)
        for field,new in [('description','changed'),('inputSchema',{'type':'object'}),('annotations',{'readOnlyHint':True,'destructiveHint':False,'idempotentHint':True,'openWorldHint':True})]:
            changed=copy.deepcopy(TOOLS);changed[1][field]=new
            with self.assertRaises(ValueError):self.contract.verify(changed)
    def test_invalid_duplicate_or_incomplete_definitions_rejected(self):
        for tools in ([],[TOOLS[0],TOOLS[0]],[{**TOOLS[0],'annotations':{}}],[{**TOOLS[0],'name':'bad name'}]):
            with self.assertRaises(ValueError):make_contract(tools)
    def test_explicit_file_digest_and_safe_mode(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'contract.json';p.write_bytes(canonical(self.value));p.chmod(0o600);sha=hashlib.sha256(p.read_bytes()).hexdigest()
            self.assertEqual(ToolContract.load(p,sha).catalog_sha256,self.contract.catalog_sha256)
            with self.assertRaises(ValueError):ToolContract.load(p,'0'*64)
            p.chmod(0o666)
            with self.assertRaises(PermissionError):ToolContract.load(p,sha)
            p.chmod(0o600);link=pathlib.Path(d)/'symlink';link.symlink_to(p)
            with self.assertRaises(OSError):ToolContract.load(link,sha)
    def test_no_batch_hidden_notifications_or_authority_override(self):
        for request in ([],{'jsonrpc':'2.0','method':'tools/call','params':{'name':'shell_start'}},
                        {'jsonrpc':'2.0','id':True,'method':'ping'}, {'jsonrpc':'2.0','id':1,'method':[]},
                        {'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'shell_start','upstream':'http://evil'}},
                        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{'cursor':'hidden'}}):
            self.assertIsNotNone(F.valid_request(request,self.contract))
    def test_token_is_private_and_never_routed_to_remote_host(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'token';p.write_text('fixture-only');p.chmod(0o600)
            self.assertEqual(F.private_token(p),'fixture-only');p.chmod(0o644)
            with self.assertRaises(PermissionError):F.private_token(p)
        for url in ('https://127.0.0.1/mcp','http://localhost/mcp','http://evil/mcp','http://127.0.0.1/mcp?x=1','http://user@127.0.0.1/mcp'):
            with self.assertRaises(ValueError):F.NativeProxy(url,'fixture',self.contract)
    def test_multi_line_sse_message_is_decoded(self):
        body=b'event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":2,"result":{}}\n\n'
        self.assertEqual(F.parse_messages('text/event-stream',body)[0]['id'],2)
    def test_empty_sse_data_heartbeat_does_not_hide_json_response(self):
        body=b'data: \n\n: keepalive\n\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n'
        self.assertEqual(F.parse_messages('text/event-stream',body),[{'jsonrpc':'2.0','id':1,'result':{}}])
    def test_default_readonly_facade_is_still_readonly(self):
        spec=importlib.util.spec_from_file_location('prior_bridge',ROOT/'deploy/chatgpt_mcp_bridge.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        self.assertEqual(len(old.ALLOWED_TOOLS),7)
        self.assertIsNotNone(old.inspect_request({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'shell_start','arguments':{}}}))


class Fake(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*a):pass
    def do_POST(self):
        request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method=request['method'];self.server.seen.append({'method':method,'request':request,'session':self.headers.get('Mcp-Session-Id'),'protocol':self.headers.get('MCP-Protocol-Version'),'token':self.headers.get('X-Hepta-Runtime-Token'),'authorization':self.headers.get('Authorization')})
        if method=='notifications/initialized':self.send_response(202);self.send_header('Content-Length','0');self.end_headers();return
        if method=='initialize':result={'protocolVersion':'2025-06-18','capabilities':{'tools':{},'resources':{}},'serverInfo':{'name':'upstream','version':'test'}}
        elif method=='tools/list':result={'tools':self.server.tools}
        elif method=='tools/call':
            self.server.effects+=1
            if self.server.disconnect:
                self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
            result={'content':[{'type':'text','text':json.dumps(request['params']['arguments'])}], 'isError':False}
        else:result={}
        payload={'jsonrpc':'2.0','id':request['id'],'result':result}
        raw=('data: '+json.dumps(payload)+'\n\n').encode() if method=='initialize' else json.dumps(payload).encode()
        self.send_response(200);self.send_header('Content-Type','text/event-stream' if method=='initialize' else 'application/json');self.send_header('Content-Length',str(len(raw)))
        if method=='initialize':self.send_header('Mcp-Session-Id','session-fixture')
        self.end_headers();self.wfile.write(raw)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Fake);self.server.daemon_threads=True
        self.server.tools=copy.deepcopy(TOOLS);self.server.seen=[];self.server.effects=0;self.server.disconnect=False
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True);self.worker.start()
        self.contract=ToolContract(make_contract(copy.deepcopy(TOOLS)));self.proxy=F.NativeProxy(f'http://127.0.0.1:{self.server.server_port}/mcp','private-fixture-token',self.contract,timeout=2)
    def tearDown(self):self.server.shutdown();self.server.server_close();self.worker.join(timeout=2)
    def call(self,method,params=None,ident=1):return self.proxy.dispatch({'jsonrpc':'2.0','id':ident,'method':method,'params':params or {}})
    def initialize(self):return self.call('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'fixture','version':'1'}})
    def test_real_initialize_list_and_full_call_preserve_arguments(self):
        init=self.initialize();self.assertEqual(init['result']['serverInfo']['name'],'hepta-runtime-full-operator')
        listed=self.call('tools/list')['result']['tools'];self.assertEqual(listed,self.contract.tools)
        args={'command':'printf "%s" "中文 | $()"','env':{'A':'unchanged'}}
        result=self.call('tools/call',{'name':'shell_start','arguments':args})
        self.assertEqual(json.loads(result['result']['content'][0]['text']),args)
        item=self.server.seen[-1];self.assertEqual(item['session'],'session-fixture');self.assertEqual(item['protocol'],'2025-06-18');self.assertEqual(item['token'],'private-fixture-token');self.assertIsNone(item['authorization'])
    def test_mutation_before_initialize_never_reaches_backend(self):
        result=self.call('tools/call',{'name':'shell_start','arguments':{}})
        self.assertIn('error',result);self.assertEqual(self.server.seen,[])
    def test_initial_contract_mismatch_prevents_all_calls(self):
        self.server.tools.append(tool('surprise'));self.assertIn('error',self.initialize())
        self.call('tools/call',{'name':'shell_start','arguments':{}});self.assertEqual(self.server.effects,0)
    def test_lost_write_response_is_unknown_and_never_retried(self):
        self.initialize();self.server.disconnect=True
        result=self.call('tools/call',{'name':'shell_start','arguments':{'command':'effect'}})
        self.assertEqual(self.server.effects,1);self.assertEqual(result['error']['data']['outcome'],'unknown');self.assertFalse(result['error']['data']['automatic_retry'])
        self.assertNotIn('private-fixture-token',json.dumps(result));self.assertNotIn('effect',json.dumps(result))
    def test_catalog_drift_after_session_revokes_session(self):
        self.initialize();self.server.tools[0]['description']='changed';self.assertIn('error',self.call('tools/list'))
        self.assertIn('error',self.call('tools/call',{'name':'binary_write','arguments':{}}));self.assertEqual(self.server.effects,0)
    def test_oversized_and_malformed_frames_have_no_side_effect(self):
        source=io.BytesIO(b'not json\n'+b'x'*200+b'\n');output=io.BytesIO()
        with mock.patch.object(F,'MAX_REQUEST',100):self.proxy.serve(source,output)
        results=[json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([r['error']['code'] for r in results],[-32700,-32600]);self.assertEqual(self.server.effects,0)
    def test_stdio_subprocess_requires_explicit_full_opt_in(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d);contract=p/'contract';contract.write_bytes(canonical(make_contract(copy.deepcopy(TOOLS))));contract.chmod(0o600)
            token=p/'token';token.write_text('private-fixture-token');token.chmod(0o600)
            command=[sys.executable,str(ROOT/'deploy/chatgpt_full_operator.py'),'--stdio','--upstream',f'http://127.0.0.1:{self.server.server_port}/mcp','--token-file',str(token),'--contract',str(contract),'--contract-sha256',hashlib.sha256(contract.read_bytes()).hexdigest()]
            failed=subprocess.run(command,input=b'',capture_output=True,timeout=5);self.assertNotEqual(failed.returncode,0);self.assertEqual(self.server.seen,[])
            messages=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'test','version':'1'}}},{'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'sudo_start','arguments':{'command':'fixture'}}}]
            result=subprocess.run([*command,'--acknowledge-full-operator'],input=b''.join(canonical(m)+b'\n' for m in messages),capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);responses=[json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(responses),2);self.assertEqual(self.server.effects,1);self.assertNotIn(b'private-fixture-token',result.stdout)


if __name__=='__main__':unittest.main(verbosity=2)
