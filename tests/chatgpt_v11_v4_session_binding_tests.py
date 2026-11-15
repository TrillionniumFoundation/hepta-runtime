#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real loopback sessions and disposable files: relative-path and undo custody.

The V4 fixture deliberately retains its global undo stack across HTTP session
expiry, while each replacement session starts in a different default workdir.
Facade refusals must happen before the counted tools/call POST.
"""
import base64
import copy
import http.server
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'deploy'))
import chatgpt_v11_layered_read as L
from chatgpt_full_operator import CAPABILITIES_KEY,MODERN_VERSION,VERSION_KEY
from mcp_tool_contract import ToolContract,canonical


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def respond(self,status,value,sid=None):
        raw=value if isinstance(value,bytes) else canonical(value)
        self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw)))
        if sid is not None:self.send_header('Mcp-Session-Id',sid)
        self.end_headers()
        try:self.wfile.write(raw)
        except OSError:pass
    def do_POST(self):
        request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method=request['method'];sid=self.headers.get('Mcp-Session-Id')
        if method=='initialize':
            self.server.inits+=1;sid='fixture-'+str(self.server.inits)
            self.server.sessions[sid]={'cwd':str(self.server.workspace)}
            self.respond(200,{'jsonrpc':'2.0','id':request['id'],'result':{
                'protocolVersion':'2025-11-25','capabilities':{'tools':{}},
                'serverInfo':{'name':'private-fixture','version':'1'}}},sid);return
        if sid not in self.server.sessions:
            self.respond(404,b'Not Found: Session not found');return
        if method.startswith('notifications/'):
            self.respond(202,b'');return
        if method=='tools/list':result={'tools':self.server.contract.tools}
        elif method=='tools/call':
            self.server.calls.append(copy.deepcopy(request))
            name=request['params']['name'];args=request['params'].get('arguments',{})
            if self.server.expire_next_tool==name:
                self.server.expire_next_tool=None;self.server.sessions.pop(sid,None)
                self.respond(404,b'Not Found: Session not found');return
            if self.server.gate_name==name:
                self.server.gate_name=None;self.server.gate_started.set()
                if not self.server.gate_release.wait(3):raise TimeoutError('fixture gate deadline')
            try:text=self.perform(self.server.sessions[sid],name,args);failed=False
            except Exception as exc:text='fixture tool refused: '+type(exc).__name__;failed=True
            result={'content':[{'type':'text','text':text}],'isError':failed}
            if self.server.drop_next==name:
                self.server.drop_next=None;self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
        else:result={}
        self.respond(200,{'jsonrpc':'2.0','id':request['id'],'result':result})
    def perform(self,state,name,args):
        def path(value):
            target=pathlib.Path(value)
            return target if target.is_absolute() else pathlib.Path(state['cwd'])/target
        if name=='workdir':
            if args.get('reset') is True:
                state['cwd']=str(self.server.workspace);return json.dumps({'success':True,'action':'reset'})
            if args.get('path') is None:return json.dumps({'success':True,'action':'get','working_directory':state['cwd']})
            requested=args['path'].strip()
            if requested.startswith(('ssh://','sftp://')):state['cwd']=requested
            else:
                selected=path(requested).resolve(strict=True)
                if not selected.is_dir():raise ValueError()
                state['cwd']=str(selected)
            return json.dumps({'success':True,'action':'set','working_directory':state['cwd']})
        if name=='view':
            if args['path'].startswith(('ssh://','sftp://')) or '|' in args['path']:return 'fixture explicit remote/search view'
            return path(args['path']).read_text()
        if name=='text_editor':
            target=path(args['path']);key=str(target.resolve());command=args['command']
            if command=='create':
                if target.exists():raise FileExistsError()
                target.write_text(args['content']);return 'created'
            if command=='undo_edit':
                previous=self.server.undo[key].pop();target.write_text(previous);return 'undo confirmed'
            previous=target.read_text()
            if command!='delete' and (command!='str_replace' or args['old_text'] not in previous):raise ValueError()
            self.server.undo.setdefault(key,[]).append(previous)
            if command=='delete':target.unlink();return 'deleted'
            target.write_text(previous.replace(args['old_text'],args['new_text']));return 'edit confirmed'
        if name=='binary_write':
            path(args['path']).write_bytes(base64.b64decode(args['data_base64']));return 'binary written'
        return json.dumps({'fixture_tool':name,'arguments_preserved':args})


class SessionBinding(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='hepta-v4-binding-');self.addCleanup(self.tmp.cleanup)
        self.base=pathlib.Path(self.tmp.name);self.workspace=self.base/'workspace';self.workspace.mkdir(mode=0o700)
        self.other=self.workspace/'selected';self.other.mkdir(mode=0o700)
        (self.workspace/'same.txt').write_text('DEFAULT_ROOT')
        (self.other/'same.txt').write_text('SELECTED_ROOT')
        roots=[]
        for name in ('v4-state','v10-state','v11-state'):
            root=self.base/name;root.mkdir(mode=0o700)
            (root/'jobs').mkdir(mode=0o700);(root/'terminals').mkdir(mode=0o700);roots.append(root)
        self.servers=[];self.threads=[]
        for version in ('v4','v10','v11'):
            contract=ToolContract(json.loads((ROOT/f'deploy/contracts/hepta-runtime-full-operator-{version}.json').read_bytes()))
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Backend);server.daemon_threads=True
            server.contract=contract;server.workspace=self.workspace;server.inits=0;server.sessions={}
            server.calls=[];server.undo={};server.drop_next=None
            server.expire_next_tool=None
            server.gate_name=None;server.gate_started=threading.Event();server.gate_release=threading.Event()
            thread=threading.Thread(target=lambda s=server:s.serve_forever(poll_interval=.02),daemon=True);thread.start()
            self.servers.append(server);self.threads.append(thread)
        self.v4,self.v10,self.v11=self.servers
        def url(server):return f'http://127.0.0.1:{server.server_port}/mcp'
        self.proxy=L.LayeredReadNativeProxy(url(self.v11),'fixture-v11',self.v11.contract,
            url(self.v4),'fixture-v4',self.v4.contract,roots[0],url(self.v10),'fixture-v10',
            self.v10.contract,roots[1],roots[2])
        self.counter=0
    def tearDown(self):
        for server in self.servers:server.gate_release.set()
        self.proxy.close()
        for server in self.servers:server.shutdown();server.server_close()
        for thread in self.threads:thread.join(2)
    def call(self,name,args=None,*,modern=True):
        self.counter+=1;params={'name':name,'arguments':args or {}}
        if modern:params['_meta']={VERSION_KEY:MODERN_VERSION,CAPABILITIES_KEY:{}}
        return self.proxy.dispatch({'jsonrpc':'2.0','id':self.counter,'method':'tools/call','params':params})
    def initialize(self):
        self.counter+=1
        return self.proxy.dispatch({'jsonrpc':'2.0','id':self.counter,'method':'initialize',
            'params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'fixture','version':'1'}}})
    def bind(self):
        response=self.call('workdir',{'path':str(self.other)})
        self.assertNotIn('error',response);self.assertFalse(response['result'].get('isError',False))
        self.assertTrue(self.proxy._v4_workdir_bound)
    def refusal(self,response,reason='v4_relative_paths_unbound'):
        self.assertEqual(response['error']['data']['outcome'],'not_submitted')
        self.assertEqual(response['error']['data']['reason'],reason)
        self.assertFalse(response['error']['data']['automatic_retry'])
    def replace(self,path='same.txt',old='SELECTED_ROOT',new='CHANGED'):
        return self.call('text_editor',{'command':'str_replace','path':path,'old_text':old,'new_text':new})

    def test_cold_modern_relative_read_and_write_are_refused_before_tool_post(self):
        self.refusal(self.replace())
        self.refusal(self.call('view',{'path':'same.txt'}))
        self.assertEqual(self.v4.calls,[])
        self.assertEqual((self.workspace/'same.txt').read_text(),'DEFAULT_ROOT')
        self.assertEqual((self.other/'same.txt').read_text(),'SELECTED_ROOT')

    def test_cold_absolute_reads_writes_and_explicit_remote_uri_remain_available(self):
        target=str(self.other/'same.txt')
        self.assertIn('result',self.call('view',{'path':target}))
        self.assertIn('result',self.replace(target));self.assertEqual(pathlib.Path(target).read_text(),'CHANGED')
        self.assertIn('result',self.call('text_editor',{'command':'undo_edit','path':target}))
        self.assertEqual(pathlib.Path(target).read_text(),'SELECTED_ROOT')
        self.assertIn('result',self.call('view',{'path':'ssh://operator/absolute/fixture.txt'}))
        self.assertIn('result',self.call('view',{'path':'sftp://operator/~/fixture.txt'}))
        self.assertFalse(self.proxy._v4_workdir_bound)

    def test_explicit_absolute_workdir_supports_relative_view_edit_and_one_known_undo(self):
        self.bind();sid=self.proxy.legacy.session
        self.assertIn('SELECTED_ROOT',self.call('view',{'path':'same.txt'})['result']['content'][0]['text'])
        self.assertIn('result',self.replace());self.assertEqual((self.other/'same.txt').read_text(),'CHANGED')
        response=self.call('text_editor',{'command':'undo_edit','path':'same.txt'})
        self.assertIn('result',response);self.assertEqual((self.other/'same.txt').read_text(),'SELECTED_ROOT')
        self.assertEqual(self.proxy.legacy.session,sid)
        before=len(self.v4.calls);self.refusal(self.call('text_editor',{'command':'undo_edit','path':'same.txt'}),'v4_undo_history_unproven')
        self.assertEqual(len(self.v4.calls),before)

    def test_explicit_reset_binds_relative_root_but_query_and_outer_initialize_do_not(self):
        self.call('workdir',{})
        self.assertFalse(self.proxy._v4_workdir_bound)
        self.assertIn('result',self.initialize())
        before=len(self.v4.calls);self.refusal(self.call('view',{'path':'same.txt'},modern=False))
        self.assertEqual(len(self.v4.calls),before)
        self.assertIn('result',self.call('workdir',{'reset':True}))
        self.assertIn('DEFAULT_ROOT',self.call('view',{'path':'same.txt'})['result']['content'][0]['text'])

    def test_failed_absolute_workdir_does_not_unlock_relative_paths(self):
        result=self.call('workdir',{'path':str(self.workspace/'missing-directory')})
        self.assertTrue(result['result']['isError']);self.assertFalse(self.proxy._v4_workdir_bound)
        before=len(self.v4.calls);self.refusal(self.replace());self.assertEqual(len(self.v4.calls),before)

    def test_expiry_relocks_before_relative_write_and_old_global_undo_is_refused(self):
        self.bind();self.replace();previous=self.proxy.legacy.session
        self.v4.sessions.clear()
        before=len(self.v4.calls);self.refusal(self.replace(old='CHANGED',new='WRONG'))
        self.assertNotEqual(self.proxy.legacy.session,previous);self.assertEqual(len(self.v4.calls),before)
        self.assertEqual((self.workspace/'same.txt').read_text(),'DEFAULT_ROOT')
        self.refusal(self.call('text_editor',{'command':'undo_edit','path':str(self.other/'same.txt')}),'v4_undo_history_unproven')
        self.assertIn(str((self.other/'same.txt').resolve()),self.v4.undo)
        self.bind();self.refusal(self.call('text_editor',{'command':'undo_edit','path':'same.txt'}),'v4_undo_history_unproven')

    def test_post_submission_expiry_is_not_replayed_and_next_session_is_unbound(self):
        self.bind();self.v4.expire_next_tool='text_editor';before=len(self.v4.calls)
        response=self.replace();self.assertEqual(response['error']['data']['outcome'],'unknown')
        self.assertEqual(len(self.v4.calls),before+1);self.assertIsNone(self.proxy.legacy.session)
        self.refusal(self.replace());self.assertEqual(len(self.v4.calls),before+1)
        self.assertEqual((self.other/'same.txt').read_text(),'SELECTED_ROOT')
        self.bind();self.assertIn('result',self.replace())

    def test_preflight_expiry_that_cannot_auto_recover_retires_the_stale_session(self):
        self.bind();self.proxy.legacy.legacy_ready=True;self.v4.sessions.clear()
        response=self.replace();self.assertEqual(response['error']['data']['outcome'],'not_submitted')
        self.assertIsNone(self.proxy.legacy.session)
        self.bind();self.assertIn('result',self.replace())

    def test_lost_workdir_response_never_binds_and_lost_write_never_creates_undo_credit(self):
        self.v4.drop_next='workdir';response=self.call('workdir',{'path':str(self.other)})
        self.assertEqual(response['error']['data']['outcome'],'unknown')
        before=len(self.v4.calls);self.refusal(self.replace());self.assertEqual(len(self.v4.calls),before)
        self.bind();self.v4.drop_next='text_editor';response=self.replace()
        self.assertEqual(response['error']['data']['outcome'],'unknown')
        self.assertEqual((self.other/'same.txt').read_text(),'CHANGED')
        before=len(self.v4.calls);self.refusal(self.call('text_editor',{'command':'undo_edit','path':'same.txt'}),'v4_undo_history_unproven')
        self.assertEqual(len(self.v4.calls),before)

    def test_unknown_absolute_undo_is_refused_even_after_explicit_workdir(self):
        target=self.other/'same.txt';self.v4.undo[str(target.resolve())]=['UNRELATED_OLD_FACADE']
        self.refusal(self.call('text_editor',{'command':'undo_edit','path':str(target)}),'v4_undo_history_unproven')
        self.bind();before=len(self.v4.calls)
        self.refusal(self.call('text_editor',{'command':'undo_edit','path':str(target)}),'v4_undo_history_unproven')
        self.assertEqual(len(self.v4.calls),before);self.assertEqual(target.read_text(),'SELECTED_ROOT')

    def test_workdir_switch_clears_old_undo_even_for_same_relative_basename(self):
        self.bind();self.replace()
        self.call('workdir',{'path':str(self.workspace)})
        before=len(self.v4.calls);self.refusal(self.call('text_editor',{'command':'undo_edit','path':'same.txt'}),'v4_undo_history_unproven')
        self.assertEqual(len(self.v4.calls),before);self.assertEqual((self.workspace/'same.txt').read_text(),'DEFAULT_ROOT')

    def test_all_declared_multi_path_fields_are_checked_before_dispatch(self):
        cases=[('file_move',{'source':'/explicit/source','destination':'relative-destination'}),
               ('directory_move',{'source':'relative-source','destination':'/explicit/destination'}),
               ('extract_lines',{'from_path':'/explicit/source','append_path':'relative-target','from_start':1,'append_line':0}),
               ('view',{'path':'/explicit/first|relative-second','content':'needle'}),
               ('document_render',{'path':'/explicit/out.pdf','assets':[{'path':'relative-asset','name':'a','sha256':'0'*64}]}),
               ('pdf_edit',{'path':'/explicit/in.pdf','output_path':'/explicit/out.pdf','operations':[{'type':'insert','source_path':'relative.pdf','page_index':0}]}),
               ('pdf_security',{'path':'/explicit/in.pdf','password_file':'relative-secret','action':'inspect'}),
               ('shell_start',{'host':'main','command':'fixture','cwd':'relative-cwd'})]
        for name,arguments in cases:
            with self.subTest(name=name):
                before=len(self.v4.calls);self.refusal(self.call(name,arguments));self.assertEqual(len(self.v4.calls),before)
        definition={'name':'fixture','inputSchema':{'type':'object','properties':{'paths':{'type':'array','items':{'type':'string'}}}}}
        self.assertEqual(L._v4_paths(definition,{'paths':['/explicit','relative']}),['/explicit','relative'])

    def test_document_body_paths_and_executable_command_names_are_not_reinterpreted(self):
        response=self.call('document_write',{'path':str(self.other/'fixture.docx'),'content':{'path':'ordinary document value'},'format':'docx','expected_sha256':'absent'})
        self.assertIn('result',response)
        self.assertIn('result',self.call('process_start',{'host':'main','executable':'python3','args':['relative program argument']}))

    def test_relative_mutation_and_workdir_change_share_one_session_lock_through_post(self):
        self.bind();before=len(self.v4.calls);self.v4.gate_name='text_editor';responses=[]
        edit=threading.Thread(target=lambda:responses.append(self.replace()))
        change=threading.Thread(target=lambda:responses.append(self.call('workdir',{'path':str(self.workspace)})))
        edit.start();self.assertTrue(self.v4.gate_started.wait(2));change.start()
        try:
            time.sleep(.08)
            self.assertEqual(len(self.v4.calls),before+1,'workdir entered the backend before the bound edit settled')
        finally:
            self.v4.gate_release.set();edit.join(3);change.join(3)
        self.assertFalse(edit.is_alive());self.assertFalse(change.is_alive())
        self.assertEqual(len(responses),2);self.assertTrue(all('result' in reply for reply in responses))
        self.assertEqual((self.other/'same.txt').read_text(),'CHANGED')
        self.assertEqual((self.workspace/'same.txt').read_text(),'DEFAULT_ROOT')


if __name__=='__main__':unittest.main(verbosity=2)
