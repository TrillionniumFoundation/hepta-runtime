#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Original-owner process admission and session custody; no sockets or real jobs."""
import copy
import json
import pathlib
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'deploy'))
import chatgpt_v11_layered_read as L
from chatgpt_full_operator import CAPABILITIES_KEY,MODERN_VERSION,VERSION_KEY
from mcp_tool_contract import ToolContract


class Task:
    def __init__(self,call):
        self.done=threading.Event();self.value=None;self.error=None
        def run():
            try:self.value=call()
            except BaseException as exc:self.error=exc
            finally:self.done.set()
        self.thread=threading.Thread(target=run,daemon=True);self.thread.start()

    def result(self):
        if not self.done.wait(3):raise AssertionError('fixture task did not finish')
        self.thread.join(1)
        if self.error is not None:raise self.error
        return self.value


def waiting_writer(gate):
    deadline=time.monotonic()+2
    while time.monotonic()<deadline:
        with gate._condition:
            if gate._waiting_writers:return
        threading.Event().wait(.001)
    raise AssertionError('fixture writer did not reach the admission queue')


class SessionGate(unittest.TestCase):
    def test_exclusive_reentrancy_including_nested_process_start(self):
        gate=L._OriginalSessionGate()
        with self.assertRaisesRegex(ValueError,'fixture'):
            with gate,gate,gate.process_start(),gate:
                raise ValueError('fixture')
        self.assertTrue(Task(lambda:self.enter(gate)).result())

    @staticmethod
    def enter(gate):
        with gate:return True

    def test_waiting_writer_precedes_later_readers_and_nested_reader_does_not_deadlock(self):
        gate=L._OriginalSessionGate();order=[];writer_release=threading.Event()
        late_started=threading.Event();writer_entered=threading.Event();reader_entered=threading.Event()
        def writer():
            with gate:
                order.append('writer');writer_entered.set()
                if not writer_release.wait(2):raise AssertionError('writer fixture was not released')
        def reader():
            late_started.set()
            with gate.process_start():order.append('reader');reader_entered.set()
        try:
            with gate.process_start():
                first=Task(writer);waiting_writer(gate)
                # Reentrant admission must not wait on the writer waiting for us.
                with gate.process_start():pass
                second=Task(reader);self.assertTrue(late_started.wait(1))
                self.assertFalse(reader_entered.is_set());self.assertFalse(writer_entered.is_set())
            self.assertTrue(writer_entered.wait(1));self.assertFalse(reader_entered.is_set())
        finally:writer_release.set()
        first.result();second.result();self.assertEqual(order,['writer','reader'])

    def test_shared_exception_releases_and_upgrade_refuses_without_deadlock(self):
        gate=L._OriginalSessionGate()
        with self.assertRaisesRegex(RuntimeError,'cannot upgrade'):
            with gate.process_start():gate.acquire()
        self.assertTrue(Task(lambda:self.enter(gate)).result())
        with self.assertRaisesRegex(ValueError,'fixture'):
            with gate.process_start():raise ValueError('fixture')
        self.assertTrue(Task(lambda:self.enter(gate)).result())

    def test_foreign_release_does_not_unlock_exclusive_owner(self):
        gate=L._OriginalSessionGate()
        with gate:
            with self.assertRaisesRegex(RuntimeError,'not owned'):Task(gate.release).result()
            with gate:pass
        self.assertTrue(Task(lambda:self.enter(gate)).result())


class ProcessStartConcurrency(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='hepta-original-process-');self.addCleanup(self.tmp.cleanup)
        roots=[pathlib.Path(self.tmp.name)/name for name in ('v4','v10','v11')]
        for root in roots:
            root.mkdir(mode=0o700)
            for name in ('jobs','terminals'):(root/name).mkdir(mode=0o700)
        contracts={v:ToolContract(json.loads((ROOT/f'deploy/contracts/hepta-runtime-full-operator-{v}.json').read_bytes()))
                   for v in ('v4','v10','v11')}
        self.proxy=L.LayeredReadNativeProxy('http://127.0.0.1:8792/mcp','native-fixture',contracts['v11'],
            'http://127.0.0.1:8790/mcp','original-fixture',contracts['v4'],roots[0],
            'http://127.0.0.1:8791/mcp','predecessor-fixture',contracts['v10'],roots[1],roots[2])
        self.addCleanup(self.proxy.close);self.proxy.legacy_ready=True
        for proxy in (self.proxy,self.proxy.legacy,self.proxy.predecessor):
            proxy._ensure_native=mock.Mock();proxy._verify_catalog=mock.Mock()
            proxy.exchange=mock.Mock(side_effect=AssertionError('unexpected owner exchange'))
        legacy=self.proxy.legacy
        legacy.session='original-session';legacy.protocol='2025-11-25';legacy._namespace='original-namespace'
        legacy.initialized=True
        with legacy._state_lock:self.proxy._v4_sync_epoch()
        self.calls=[];self.calls_lock=threading.Lock();self.exchange_hook=None
        legacy.exchange=self.exchange

    @staticmethod
    def request(identity,name='process_start',arguments=None,modern=False):
        if arguments is None:
            arguments={'host':'main','executable':'/usr/bin/python3','args':['-c','pass'],
                       'timeout_seconds':10,'nice':10,'idempotency_key':'fixture-'+identity}
        params={'name':name,'arguments':arguments}
        if modern:params['_meta']={VERSION_KEY:MODERN_VERSION,CAPABILITIES_KEY:{}}
        return {'jsonrpc':'2.0','id':identity,'method':'tools/call','params':params}

    @staticmethod
    def reply(request,payload=None):
        return {'jsonrpc':'2.0','id':request['id'],'result':{'isError':False,
                'content':[{'type':'text','text':json.dumps(payload or {'job_id':'fixture-job','state':'succeeded'})}]}}

    def exchange(self,request,**kwargs):
        context=kwargs.get('context')
        with self.calls_lock:self.calls.append((copy.deepcopy(request),kwargs.copy()))
        if context is not None:context.transmitting=True;context.posted=True
        return self.exchange_hook(request,kwargs) if self.exchange_hook else self.reply(request)

    def dispatch(self,request):return self.proxy.dispatch(request)

    def test_six_starts_overlap_with_original_binding_keys_arguments_and_distinct_transport_ids(self):
        for modern in (False,True):
            with self.subTest(modern=modern):
                barrier=threading.Barrier(6);before=len(self.calls)
                def exchange(request,kwargs):
                    barrier.wait(2)
                    self.assertEqual(kwargs['binding'],('original-session','2025-11-25'))
                    self.assertEqual(kwargs['timeout'],38)
                    self.assertIsNone(kwargs['context'].native_id)
                    self.assertIsNone(kwargs['context'].binding)
                    return self.reply(request)
                self.exchange_hook=exchange
                requests=[]
                for index,host in enumerate(('main','rog','ai395','pocket4','x230','mac')):
                    request=self.request(f'{modern}-{index}',modern=modern)
                    request['params']['arguments'].update(host=host,env={'FIXTURE':'opaque value'})
                    if index==1:request['params']['arguments']['cwd']='/explicit/workspace'
                    if index==2:request['params']['arguments']['cwd']=None
                    requests.append(request)
                originals=copy.deepcopy(requests)
                tasks=[Task(lambda request=request:self.dispatch(request)) for request in requests]
                replies=[task.result() for task in tasks]
                self.assertTrue(all('result' in reply for reply in replies),replies)
                self.assertEqual([reply['id'] for reply in replies],[request['id'] for request in requests])
                self.assertEqual(requests,originals)
                batch=self.calls[before:];self.assertEqual(len(batch),6)
                self.assertEqual(len({request['id'] for request,_ in batch}),6)
                sent={request['params']['arguments']['idempotency_key']:request for request,_ in batch}
                for request in requests:
                    self.assertEqual(sent[request['params']['arguments']['idempotency_key']]['params'],
                        {key:request['params'][key] for key in ('name','arguments')})
        self.assertEqual(self.proxy.legacy.token,'original-fixture')
        self.assertEqual(self.proxy.legacy.upstream.port,8790)
        self.proxy.exchange.assert_not_called();self.proxy.predecessor.exchange.assert_not_called()
        self.assertEqual(self.proxy.legacy._verify_catalog.call_count,12)

    def test_file_edit_waits_for_all_starts_and_can_only_grant_undo_after_they_finish(self):
        entered=threading.Barrier(3);release=threading.Event();edit_entered=threading.Event()
        target=('local','/fixture.txt');self.proxy._v4_undo_credits[target]=3
        def exchange(request,kwargs):
            if request['params']['name']=='process_start':
                self.assertFalse(self.proxy._v4_undo_credits)
                entered.wait(2)
                if not release.wait(2):raise AssertionError('start fixture was not released')
            else:edit_entered.set()
            return self.reply(request)
        self.exchange_hook=exchange
        starts=[Task(lambda index=index:self.dispatch(self.request(f'start-{index}'))) for index in range(2)]
        try:
            entered.wait(2)
            edit=Task(lambda:self.dispatch(self.request('edit','text_editor',
                {'command':'str_replace','path':'/fixture.txt','old_text':'old','new_text':'new'})))
            waiting_writer(self.proxy._legacy_read_lock);self.assertFalse(edit_entered.is_set())
        finally:release.set()
        for task in starts:self.assertIn('result',task.result())
        self.assertIn('result',edit.result());self.assertEqual(self.proxy._v4_undo_credits,{target:1})

    def test_start_waits_for_file_edit_then_revokes_its_undo_credit(self):
        edit_entered=threading.Event();start_entered=threading.Event();release=threading.Event()
        def exchange(request,kwargs):
            if request['params']['name']=='text_editor':
                edit_entered.set()
                if not release.wait(2):raise AssertionError('edit fixture was not released')
            else:start_entered.set()
            return self.reply(request)
        self.exchange_hook=exchange
        edit=Task(lambda:self.dispatch(self.request('edit','text_editor',
            {'command':'str_replace','path':'/fixture.txt','old_text':'old','new_text':'new'})))
        try:
            self.assertTrue(edit_entered.wait(1))
            start=Task(lambda:self.dispatch(self.request('start')))
            self.assertFalse(start_entered.wait(.05))
        finally:release.set()
        self.assertIn('result',edit.result());self.assertIn('result',start.result())
        self.assertFalse(self.proxy._v4_undo_credits)
        undo=self.dispatch(self.request('undo','text_editor',{'command':'undo_edit','path':'/fixture.txt'}))
        self.assertEqual(undo['error']['data']['reason'],'v4_undo_history_unproven')
        self.assertEqual(len(self.calls),2)

    def test_all_other_original_calls_and_relative_cwd_retain_exclusive_admission(self):
        cases=[('workdir',{'path':'/bound'}),('view',{'path':'/fixture'}),
               ('shell_start',{'host':'main','command':'fixture'}),
               ('process_read',{'host':'main','job_id':'fixture-job'}),
               ('process_status',{'host':'main','job_id':'fixture-job'}),
               ('process_wait',{'host':'main','job_id':'fixture-job'}),
               ('process_cancel',{'host':'main','job_id':'fixture-job'}),
               ('process_start',{'host':'main','executable':'/bin/true','cwd':'relative'})]
        self.proxy._v4_workdir_bound=True;self.proxy._v4_workdir='/bound'
        for index,(name,arguments) in enumerate(cases):
            with self.subTest(name=name):
                before=len(self.calls)
                with self.proxy._legacy_read_lock.process_start():
                    request=self.request(str(index),name,arguments)
                    task=Task(lambda:self.proxy._original(request,None,'legacy',mutating=True))
                    waiting_writer(self.proxy._legacy_read_lock)
                    self.assertEqual(len(self.calls),before)
                self.assertIn('result',task.result())
                self.assertEqual(self.calls[-1][0]['params']['arguments'],arguments)
                # This mock need not implement workdir; restore the existing
                # binding to exercise the later relative-cwd native validation.
                self.proxy._v4_workdir_bound=True;self.proxy._v4_workdir='/bound'

    def test_registry_attestation_is_still_exclusive(self):
        gate=self.proxy._legacy_read_lock
        self.proxy.registry_pager.page=mock.Mock(return_value={'fixture':'readonly page'})
        with gate.process_start():
            request=self.request('registry','process_list_page',{'limit':128})
            task=Task(lambda:self.dispatch(request));waiting_writer(gate)
            self.proxy.legacy._verify_catalog.assert_not_called()
            self.proxy.registry_pager.page.assert_not_called()
        self.assertIn('result',task.result())
        self.proxy.legacy._verify_catalog.assert_called_once()
        self.proxy.registry_pager.page.assert_called_once_with({'limit':128})

    def test_relative_cwd_refuses_unbound_and_executable_and_args_are_not_reinterpreted(self):
        request=self.request('relative');request['params']['arguments']['cwd']='relative'
        refusal=self.dispatch(request)
        self.assertEqual(refusal['error']['data']['reason'],'v4_relative_paths_unbound')
        self.assertFalse(self.calls)
        request=self.request('opaque');request['params']['arguments'].update(
            executable='python3',args=['relative-script.py','--path','another/relative'])
        self.assertIn('result',self.dispatch(request))
        self.assertEqual(self.calls[-1][0]['params']['arguments'],request['params']['arguments'])

    def test_lost_and_expired_start_responses_are_unknown_without_retry_or_new_undo(self):
        for exception in (OSError('lost response'),L.NativeSessionExpired('expired session')):
            with self.subTest(exception=type(exception).__name__):
                self.proxy._v4_undo_credits[('local','/fixture')]=1
                before=len(self.calls)
                self.exchange_hook=lambda request,kwargs:(_ for _ in ()).throw(exception)
                response=self.dispatch(self.request('failed-'+type(exception).__name__))
                self.assertEqual(response['error']['data']['outcome'],'unknown')
                self.assertFalse(response['error']['data']['automatic_retry'])
                self.assertFalse(response['error']['data']['original_request_replayed'])
                self.assertEqual(len(self.calls),before+1);self.assertFalse(self.proxy._v4_undo_credits)
                self.assertEqual(self.proxy.legacy.session,None if isinstance(exception,L.NativeSessionExpired) else 'original-session')
        self.proxy.exchange.assert_not_called();self.proxy.predecessor.exchange.assert_not_called()

    def test_cancel_before_submission_keeps_original_outcome_without_exchange(self):
        request=self.request('cancelled');context,refused=self.proxy._reserve(request)
        self.assertIsNone(refused);context.cancel_requested=True
        try:response=self.proxy.dispatch(request,context)
        finally:self.proxy._finish(context)
        self.assertEqual(response['error']['data']['outcome'],'not_submitted');self.assertFalse(self.calls)

    def test_transport_not_submitted_is_not_promoted_to_unknown_or_retried(self):
        def exchange(request,**kwargs):raise L.RequestNotSubmitted()
        self.proxy.legacy.exchange=mock.Mock(side_effect=exchange)
        response=self.dispatch(self.request('not-posted'))
        self.assertEqual(response['error']['data']['outcome'],'not_submitted')
        self.assertEqual(self.proxy.legacy.exchange.call_count,1)
        self.assertEqual(self.proxy.legacy.session,'original-session')

    def test_late_old_expiry_cannot_retire_new_epoch_or_replay_either_request(self):
        both=threading.Barrier(2);late_release=threading.Event()
        original_epoch=self.proxy._v4_current_epoch()
        def ensure():
            if self.proxy.legacy.session is None:
                legacy=self.proxy.legacy
                legacy.session='new-session';legacy.protocol='2025-11-25'
                legacy._namespace='new-namespace';legacy.initialized=True
        self.proxy.legacy._ensure_native=mock.Mock(side_effect=ensure)
        def exchange(request,kwargs):
            key=request['params']['arguments']['idempotency_key']
            if key!='fixture-new':
                self.assertEqual(kwargs['binding'],original_epoch[:2]);both.wait(2)
                if key=='fixture-late' and not late_release.wait(2):raise AssertionError('late fixture was not released')
                raise L.NativeSessionExpired('old bound session expired')
            self.assertEqual(kwargs['binding'],('new-session','2025-11-25'))
            return self.reply(request)
        self.exchange_hook=exchange
        late=Task(lambda:self.dispatch(self.request('late')))
        early=Task(lambda:self.dispatch(self.request('early')))
        try:
            self.assertEqual(early.result()['error']['data']['outcome'],'unknown')
            self.assertIsNone(self.proxy.legacy.session)
            self.assertIn('result',self.dispatch(self.request('new')))
            new_epoch=self.proxy._v4_current_epoch();self.assertNotEqual(new_epoch,original_epoch)
        finally:late_release.set()
        self.assertEqual(late.result()['error']['data']['outcome'],'unknown')
        self.assertEqual(self.proxy._v4_current_epoch(),new_epoch)
        self.assertEqual(self.proxy._v4_epoch,new_epoch);self.assertTrue(self.proxy.legacy.initialized)
        self.assertEqual(len(self.calls),3)

    def test_preflight_expiry_retires_current_binding_without_posting_the_start(self):
        def ensure():
            self.proxy.legacy.session='just-initialized';self.proxy.legacy._namespace='new-namespace'
        self.proxy.legacy._ensure_native=mock.Mock(side_effect=ensure)
        self.proxy.legacy._verify_catalog=mock.Mock(side_effect=L.NativeSessionExpired('catalog expiry'))
        response=self.dispatch(self.request('preflight'))
        self.assertEqual(response['error']['data']['outcome'],'not_submitted')
        self.assertIsNone(self.proxy.legacy.session);self.assertFalse(self.calls)


if __name__=='__main__':unittest.main(verbosity=2)
