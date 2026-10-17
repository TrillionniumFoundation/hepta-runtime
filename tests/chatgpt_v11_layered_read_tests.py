#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Three-owner custody and no-replay regression fixtures; no installed services."""
import copy
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'deploy'))
import chatgpt_v11_layered_read as L
from chatgpt_full_operator import NativeProxy
from mcp_tool_contract import ToolContract,make_contract

ID='a'*64;SECOND='b'*64;THIRD='c'*64
OLD_JOB='1a14-1-1';MID_JOB='1a14-2-1'


class LayeredRouting(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='hepta-layered-read-');self.addCleanup(self.tmp.cleanup)
        self.roots={name:pathlib.Path(self.tmp.name)/name for name in ('v4','predecessor','native')}
        for root in self.roots.values():
            root.mkdir(mode=0o700)
            for name in ('jobs','terminals'):(root/name).mkdir(mode=0o700)
        self.contracts={v:ToolContract(json.loads((ROOT/f'deploy/contracts/hepta-runtime-full-operator-{v}.json').read_bytes()))
                        for v in ('v4','v10','v11')}
        self.calls=[];self.responses={};self.fail=None
        self.proxy=self.adapter();self.proxy.legacy_ready=True
        self.addCleanup(self.proxy.close)
        for proxy in (self.proxy,self.proxy.legacy,self.proxy.predecessor):
            proxy._ensure_native=lambda context=None:None
            proxy._verify_catalog=lambda context=None:None
        self.proxy.predecessor.session='predecessor-fixture';self.proxy.predecessor.protocol='2025-11-25'
        self.proxy.predecessor.exchange=self.predecessor_exchange
        self.proxy._original=lambda request,context,era,*,mutating:self.reply('v4',request,mutating)
        patcher=mock.patch.object(NativeProxy,'_dispatch',lambda proxy,request,context=None:self.reply('native',request,False))
        patcher.start();self.addCleanup(patcher.stop)

    def adapter(self,contract=None):
        return L.LayeredReadNativeProxy('http://127.0.0.1:8792/mcp','native-fixture',contract or self.contracts['v11'],
            'http://127.0.0.1:8790/mcp','v4-fixture',self.contracts['v4'],self.roots['v4'],
            'http://127.0.0.1:8791/mcp','predecessor-fixture',self.contracts['v10'],
            self.roots['predecessor'],self.roots['native'])

    @staticmethod
    def request(name,arguments=None):
        return {'jsonrpc':'2.0','id':'test-'+name,'method':'tools/call',
                'params':{'name':name,'arguments':arguments or {}}}

    def reply(self,owner,request,mutating):
        self.calls.append((owner,copy.deepcopy(request),mutating))
        if self.fail==owner:raise OSError('synthetic lost response')
        payload=self.responses.get((owner,request['params']['name']),{'owner':owner})
        if callable(payload):payload=payload(request['params'].get('arguments',{}))
        return {'jsonrpc':'2.0','id':request['id'],'result':{'content':[{'type':'text','text':json.dumps(payload)}],
                'isError':False}}

    def predecessor_exchange(self,request,**kwargs):
        context=kwargs.get('context')
        if context is not None:
            context.transmitting=True;context.posted=True
        return self.reply('predecessor',request,request['params']['name'].endswith(('cancel','stop')))

    def call(self,name,arguments=None):return self.proxy._dispatch(self.request(name,arguments))

    def record(self,backend,kind,identity=ID,**extra):
        folder={'search':('search',),'request':('request-async-v9','.intents'),
                'operation':('request-operations-v10','.intents'),'audit':('request-audit',),
                'jobs':('jobs',),'terminals':('terminals',)}[kind]
        directory=self.roots[backend]
        for part in folder:
            directory=directory/part;directory.mkdir(mode=0o700,exist_ok=True)
        field='id' if kind in ('search','jobs') else 'session_id' if kind=='terminals' else 'request_id'
        value={field:identity,'owner':'d'*64,**extra}
        path=directory/(identity+'.json');path.write_text(json.dumps(value));path.chmod(0o600)
        return path

    def stream(self,backend,number):
        identity='stream-'+f'{number:064x}'
        directory=self.roots[backend]/'stream_handoffs'/identity
        directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        directory.parent.chmod(0o700)
        request=directory/'request.json'
        request.write_text(json.dumps({'session_id':identity,'application_identities':[]}));request.chmod(0o600)
        return {'session_id':identity,'application_identities':[],
                'status':{'native_preserved_field':backend,'state':'accepted'}}

    @staticmethod
    def payload(response):return json.loads(response['result']['content'][0]['text'])

    def test_actual_reviewed_50_66_69_catalogs_construct(self):
        self.assertEqual([len(self.contracts[v].tools) for v in ('v4','v10','v11')],[50,66,69])
        self.assertIsNotNone(self.proxy)

    def test_fresh_native_state_cannot_alias_original_effect_state(self):
        self.roots['native']=self.roots['v4']
        with self.assertRaises(L.UnsafeProvenance):self.adapter()

    def test_reviewed_extensions_cannot_change_old_schemas_or_annotations(self):
        for name in ('operation_start','search_results','search_start'):
            changed=copy.deepcopy(self.contracts['v11'].tools)
            tool=next(tool for tool in changed if tool['name']==name)
            tool['annotations']['openWorldHint']=not tool['annotations']['openWorldHint']
            with self.assertRaises(L.UnsafeProvenance):self.adapter(ToolContract(make_contract(changed)))
        changed=copy.deepcopy(self.contracts['v11'].tools)
        next(tool for tool in changed if tool['name']=='search_start')['inputSchema']['properties']['host']['type']='integer'
        with self.assertRaises(L.UnsafeProvenance):self.adapter(ToolContract(make_contract(changed)))

    def test_original_effects_and_relative_view_share_v4(self):
        for name,args in [('workdir',{'path':'subdir'}),('view',{'path':'relative.txt'}),
                          ('text_editor',{'command':'undo_edit','path':'relative.txt'}),
                          ('document_read',{'path':'fixture.docx'}),('image_read',{'path':'fixture.png'})]:
            response=self.call(name,args);self.assertNotIn('error',response)
            self.assertEqual(self.calls[-1][0],'v4');self.assertEqual(self.calls[-1][1]['params']['arguments'],args)
        self.assertFalse(next(call[2] for call in self.calls if call[1]['params']['name']=='view'))

    def test_existing_v4_and_v10_job_reads_keep_their_original_owner(self):
        self.record('v4','jobs',OLD_JOB,host='main');self.record('predecessor','jobs',MID_JOB,host='main')
        for job,owner in ((OLD_JOB,'v4'),(MID_JOB,'predecessor')):
            for name in ('process_status','process_read','process_wait'):
                self.assertNotIn('error',self.call(name,{'host':'main','job_id':job}))
                self.assertEqual(self.calls[-1][0],owner)

    def test_registry_native_backend_uses_predecessor(self):
        request=self.request('process_list',{'host':'main'})
        self.proxy._native_registry_backend(request,None,'legacy')
        self.assertEqual(self.calls[-1][0],'predecessor')

    def test_each_predecessor_workflow_handle_and_cancel_stays_on_predecessor(self):
        for kind in ('search','request','operation'):self.record('predecessor',kind)
        for name,(kind,field,mutating) in L.SCOPED_HANDLES.items():
            value=self.call(name,{field:ID});self.assertNotIn('error',value,name)
            self.assertEqual(self.calls[-1][0],'predecessor',name)

    def test_native_and_unknown_workflow_ids_never_fall_back(self):
        for kind in ('search','request','operation'):self.record('native',kind)
        for name,(kind,field,_) in L.SCOPED_HANDLES.items():
            self.call(name,{field:ID});self.assertEqual(self.calls[-1][0],'native',name)
            self.call(name,{field:SECOND});self.assertEqual(self.calls[-1][0],'native',name)

    def test_cross_controller_collision_refuses_before_any_dispatch(self):
        for backend in ('predecessor','native'):self.record(backend,'search')
        result=self.call('search_stop',{'search_id':ID})
        self.assertEqual(result['error']['data']['outcome'],'not_submitted');self.assertEqual(self.calls,[])

    def test_synchronous_request_uses_audit_fallback_but_cancel_requires_intent(self):
        self.record('predecessor','audit')
        self.call('request_status',{'request_id':ID});self.assertEqual(self.calls[-1][0],'predecessor')
        self.call('request_result',{'request_id':ID});self.assertEqual(self.calls[-1][0],'predecessor')
        self.call('request_cancel',{'request_id':ID});self.assertEqual(self.calls[-1][0],'native')

    def test_disagreeing_audit_and_request_intent_refuse(self):
        self.record('predecessor','request');self.record('native','audit')
        self.assertIn('error',self.call('request_status',{'request_id':ID}));self.assertFalse(self.calls)

    def test_new_typed_read_starts_only_use_v11(self):
        starts={'search_start':{'host':'main','root':'/fixture','query':'needle','kind':'content'},
                'request_start':{'operation':{'tool':'host_list','arguments':{}},'idempotency_key':'fixture'},
                'operation_start':{'operation':{'tool':'file_info','arguments':{'host':'main','path':'/fixture'}},'idempotency_key':'fixture'}}
        for name,args in starts.items():
            self.assertNotIn('error',self.call(name,args));self.assertEqual(self.calls[-1][0],'native')
        nested={'operation':{'tool':'process_read','arguments':{'host':'main','job_id':MID_JOB}},'idempotency_key':'fixture-job'}
        before=len(self.calls);self.assertIn('error',self.call('operation_start',nested));self.assertEqual(len(self.calls),before)

    def test_lost_predecessor_cancel_response_is_unknown_without_fallback(self):
        self.record('predecessor','operation');self.fail='predecessor'
        result=self.call('operation_cancel',{'operation_id':ID})
        self.assertEqual(result['error']['data']['outcome'],'unknown');self.assertFalse(result['error']['data']['automatic_retry'])
        self.assertEqual(len(self.calls),1);self.assertEqual(self.calls[0][0],'predecessor')

    def test_predecessor_post_preserves_posted_and_clears_v11_cancellation_mapping(self):
        request=self.request('operation_cancel',{'operation_id':ID})
        context,refused=self.proxy._reserve(request);self.assertIsNone(refused)
        context.native_id='stale-v11';context.binding=('stale-v11-session','2025-11-25')
        try:
            self.proxy._predecessor_call(request,context,'legacy',mutating=True)
            self.assertTrue(context.posted);self.assertTrue(context.transmitting)
            self.assertIsNone(context.native_id);self.assertIsNone(context.binding)
        finally:self.proxy._finish(context)

    def test_v11_effect_registry_entry_or_root_replacement_refuses_all_dispatch(self):
        path=self.roots['native']/'jobs'/'unexpected';path.write_text('not admitted here')
        self.assertIn('error',self.call('host_list'));self.assertFalse(self.calls)
        path.unlink();old=self.roots['native'];old.rename(old.with_name('held'))
        old.mkdir(mode=0o700);(old/'jobs').mkdir(mode=0o700)
        self.assertIn('error',self.call('host_list'));self.assertFalse(self.calls)

    def test_old_and_new_search_lists_merge_in_global_id_order(self):
        self.record('predecessor','search',THIRD);self.record('native','search',ID)
        for owner,key in (('predecessor',THIRD),('native',ID)):
            self.responses[owner,'search_list']={'searches':[{'search_id':key,'root':'/fixture'}],'next_after_id':None}
        first=self.payload(self.call('search_list',{'limit':1}))
        self.assertEqual(first['searches'][0]['search_id'],ID);self.assertEqual(first['next_after_id'],ID)
        second=self.payload(self.call('search_list',{'after_id':ID,'limit':1}))
        self.assertEqual(second['searches'][0]['search_id'],THIRD);self.assertIsNone(second['next_after_id'])

    def test_history_merges_by_admission_time_and_retains_predecessor_rows(self):
        self.record('predecessor','audit',ID);self.record('native','audit',THIRD)
        self.responses['predecessor','request_history']={'requests':[{'request_id':ID,'accepted_unix_ms':20}],'next_after_id':None}
        self.responses['native','request_history']={'requests':[{'request_id':THIRD,'accepted_unix_ms':10}],'next_after_id':None}
        value=self.payload(self.call('request_history'))
        self.assertEqual([row['request_id'] for row in value['requests']],[THIRD,ID])
        self.assertTrue(value['history_is_live'])

    def test_list_failure_or_duplicate_never_returns_partial_other_owner_rows(self):
        self.record('predecessor','search',ID)
        self.responses['predecessor','search_list']={'searches':[{'search_id':ID}],'next_after_id':None}
        self.fail='native';result=self.call('search_list')
        self.assertIn('error',result);self.assertFalse(result['error']['data']['partial_inventory_returned'])

    def test_archive_honestly_identifies_new_controller_only(self):
        self.responses['native','request_archive']={'requests':[],'total':0}
        value=self.payload(self.call('request_archive'))
        self.assertIn('new_v11_only',value['layered_archive_source'])

    def test_both_stream_owners_are_discoverable_with_all_remaining_ids(self):
        old=self.stream('v4',2);middle=self.stream('predecessor',1)
        self.responses['v4','stream_handoff_list']={'sessions':[old],'source_extension':'old'}
        self.responses['predecessor','stream_handoff_list']={'sessions':[middle],'source_extension':'middle'}
        payload=self.payload(self.call('stream_handoff_list',{'limit':1}))
        self.assertEqual(payload['sessions'],[middle]);self.assertEqual(payload['remaining_session_ids'],[old['session_id']])
        self.assertEqual(payload['total'],2);self.assertTrue(payload['has_more']);self.assertFalse(payload['inventory_complete'])
        self.assertEqual(payload['layered_controller_sources']['v4']['payload']['source_extension'],'old')
        self.assertEqual([call[0] for call in self.calls],['v4','predecessor'])
        self.calls.clear();payload=self.payload(self.call('stream_handoff_list',{'limit':128}))
        self.assertEqual(payload['sessions'],[middle,old]);self.assertTrue(payload['inventory_complete'])
        self.assertEqual(payload['remaining_session_ids'],[])

    def test_stream_collision_refuses_before_any_backend_call(self):
        for backend in ('v4','predecessor'):self.stream(backend,1)
        self.assertIn('error',self.call('stream_handoff_list'));self.assertFalse(self.calls)

    def test_stream_backend_missing_row_cannot_return_other_owner_partial_inventory(self):
        old=self.stream('v4',1);self.stream('predecessor',2)
        self.responses['v4','stream_handoff_list']={'sessions':[old]}
        self.responses['predecessor','stream_handoff_list']={'sessions':[]}
        response=self.call('stream_handoff_list')
        self.assertIn('error',response);self.assertNotIn('result',response)
        self.assertFalse(response['error']['data']['partial_inventory_returned'])

    def test_legacy_handshake_is_still_required_before_any_owner_lookup(self):
        self.proxy.legacy_ready=False
        self.assertEqual(self.call('view',{'path':'file'})['error']['code'],-32071)
        self.assertFalse(self.calls)


if __name__=='__main__':unittest.main(verbosity=2)
