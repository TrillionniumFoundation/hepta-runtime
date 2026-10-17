#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Three-controller facade preserving both original effect and workflow owners.

Original effects and session-local file views stay in V4. Retained V10 jobs,
terminals, streams and typed-read handles stay in their running predecessor.
Only new typed-read workflows use the fresh V11 controller. No controller state
is copied, rewritten, adopted or replayed by this adapter.
"""
from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
import json
import os
import pathlib
import posixpath
import threading

from chatgpt_full_operator import MAX_RESPONSE, NativeProxy, NativeSessionExpired, RequestNotSubmitted, error, private_token, request_era, valid_request
from chatgpt_v10_dual_read import (
    DualReadNativeProxy, READ_ROUTES, STREAM_READ_NAMES, UnsafeProvenance,
    STREAM_ID, WORKFLOW_ID, directory_fd, owned_stream_names, strict_pairs,
)
from mcp_tool_contract import ToolContract, canonical
from runtime_workflow_owner import RuntimeWorkflowOwner

MAX_LIST_PAGES=256
MAX_LIST_ROWS=8192
MAX_LIST_SOURCE_BYTES=8*1024*1024
MAX_LIST_WIRE_BYTES=96*1024
ORIGINAL_SESSION_READS=frozenset(('view','document_read','image_read'))
V4_PATH_FIELDS=frozenset(('path','paths','source','destination','from_path','append_path',
    'source_path','output_path','password_file','output_owner_password_file',
    'output_user_password_file','trust_store_file','cwd','shell'))
SCOPED_HANDLES={
    'search_results':('search','search_id',False),
    'search_stop':('search','search_id',True),
    'request_status':('request','request_id',False),
    'request_result':('request','request_id',False),
    'request_cancel':('request','request_id',True),
    'operation_status':('operation','operation_id',False),
    'operation_result':('operation','operation_id',False),
    'operation_cancel':('operation','operation_id',True),
}


def _without_descriptions(value):
    if isinstance(value,dict):return {key:_without_descriptions(item) for key,item in value.items() if key!='description'}
    if isinstance(value,list):return [_without_descriptions(item) for item in value]
    return value


def _reviewed_extension(name,previous,current):
    if name not in ('search_start','search_results','operation_start'):return previous==current
    if ({key:value for key,value in previous.items() if key not in ('description','inputSchema')}
            !={key:value for key,value in current.items() if key not in ('description','inputSchema')}):return False
    if name=='operation_start':return previous['inputSchema']==current['inputSchema']
    old,new=(_without_descriptions(item['inputSchema']) for item in (previous,current))
    if name=='search_results':return old==new
    if ({key:value for key,value in old.items() if key not in ('properties','$defs')}
            !={key:value for key,value in new.items() if key not in ('properties','$defs')}):return False
    additions={'query_mode','literal_search','ignore_case','context_lines','file_pattern','exclude_patterns','early_termination'}
    if set(new.get('properties',{}))-set(old.get('properties',{}))!=additions:return False
    if any(new['properties'].get(key)!=value for key,value in old['properties'].items()):return False
    old_defs,new_defs=old.get('$defs',{}),new.get('$defs',{})
    return (set(new_defs)-set(old_defs)=={'SearchQueryMode'}
            and all(new_defs.get(key)==value for key,value in old_defs.items()))


def _explicit_path(value):
    """Classify native POSIX paths without expanding a relative '~' or parsing program args."""
    if not isinstance(value,str) or not value or '\0' in value:return False
    if value.startswith('/'):return True
    for prefix in ('ssh://','sftp://'):
        if value.startswith(prefix):
            authority=value[len(prefix):].split('/',1)[0]
            return bool(authority and authority.rsplit('@',1)[-1])
    return False


def _v4_paths(definition,arguments):
    """Visit declared path fields only; document bodies, env and executable names are opaque."""
    root=definition['inputSchema'];found=[]
    def visit(schema,value,field=None):
        if value is None or not isinstance(schema,dict):return
        if '$ref' in schema:
            reference=schema['$ref']
            if not isinstance(reference,str) or not reference.startswith('#/$defs/'):raise ValueError()
            visit(root['$defs'][reference[len('#/$defs/'):]],value,field);return
        if field in V4_PATH_FIELDS:
            if isinstance(value,str):found.append(value);return
            if field=='paths' and isinstance(value,list) and all(isinstance(item,str) for item in value):
                found.extend(value);return
            raise ValueError()
        if isinstance(value,dict):
            for name,child in schema.get('properties',{}).items():
                if name in value:visit(child,value[name],name)
        if isinstance(value,list):
            for item in value:visit(schema.get('items',{}),item)
        for key in ('oneOf','anyOf','allOf'):
            for child in schema.get(key,[]):visit(child,value,field)
    visit(root,arguments)
    if definition['name']=='view':return [part for value in found for part in value.split('|')]
    if definition['name']=='workdir':return [value.strip() for value in found]
    return found


class _OriginalSessionGate:
    """Only independent process starts may overlap; session operations keep custody."""
    def __init__(self):
        self._condition=threading.Condition()
        self._writer=None;self._depth=0;self._readers={};self._waiting_writers=0

    def acquire(self):
        thread=threading.get_ident()
        with self._condition:
            if self._writer==thread:
                self._depth+=1;return True
            # There is no shared-to-exclusive path: expiry only takes the
            # native state lock. Refuse an accidental upgrade instead of hanging.
            if thread in self._readers:raise RuntimeError('original session gate cannot upgrade a process start')
            self._waiting_writers+=1
            try:
                self._condition.wait_for(lambda:self._writer is None and not self._readers)
                self._writer=thread;self._depth=1
            finally:
                self._waiting_writers-=1;self._condition.notify_all()
        return True

    def release(self):
        with self._condition:
            if self._writer!=threading.get_ident():raise RuntimeError('original session gate is not owned')
            self._depth-=1
            if self._depth==0:
                self._writer=None;self._condition.notify_all()

    def __enter__(self):
        self.acquire();return self

    def __exit__(self,*exc):
        self.release()

    @contextmanager
    def process_start(self):
        thread=threading.get_ident()
        with self._condition:
            # Preserve nested admission by the current holder. A newly arrived
            # start cannot pass a waiting file/workdir/undo operation.
            self._condition.wait_for(lambda:self._writer==thread or
                self._writer is None and (not self._waiting_writers or thread in self._readers))
            self._readers[thread]=self._readers.get(thread,0)+1
        try:yield
        finally:
            with self._condition:
                self._readers[thread]-=1
                if not self._readers[thread]:del self._readers[thread]
                self._condition.notify_all()


class LayeredReadNativeProxy(DualReadNativeProxy):
    def __init__(self,upstream,token,contract,legacy_upstream,legacy_token,legacy_contract,
                 legacy_state,predecessor_upstream,predecessor_token,predecessor_contract,
                 predecessor_state,native_state,*,retained_backends_current=False,
                 original_route_contract=None):
        super().__init__(upstream,token,contract,legacy_upstream,legacy_token,legacy_contract,
            legacy_state,predecessor_state,route_original_effects=True,route_v10_read_workflows=True,
            retained_backends_current=retained_backends_current,original_route_contract=original_route_contract)
        if self.retained_backends_current:
            predecessor_contract.verify_integrity()
            if predecessor_contract.catalog_sha256!=contract.catalog_sha256:
                raise UnsafeProvenance('layered_current_predecessor_catalog_mismatch')
        else:
            if len(predecessor_contract.tools)!=66 or len(contract.tools)!=69:
                raise UnsafeProvenance('layered_reviewed_catalog_sizes_required')
            # Historical mode retains the originally reviewed 50/66/69 wire contracts.
            for name,definition in predecessor_contract.by_name.items():
                if name not in contract.by_name or not _reviewed_extension(name,definition,contract.by_name[name]):
                    raise UnsafeProvenance('layered_predecessor_contract_drift')
        self.predecessor=NativeProxy(predecessor_upstream,predecessor_token,predecessor_contract,timeout=38)
        if self.predecessor.upstream in (self.upstream,self.legacy.upstream):
            raise UnsafeProvenance('layered_three_independent_upstreams_required')
        self.native_state=pathlib.Path(native_state)
        self.workflow_owners=RuntimeWorkflowOwner(predecessor_state,native_state)
        descriptors=[]
        try:
            for root in (legacy_state,predecessor_state,native_state):descriptors.append(directory_fd(root))
            if len({(os.fstat(fd).st_dev,os.fstat(fd).st_ino) for fd in descriptors})!=3:
                raise UnsafeProvenance('layered_three_independent_state_roots_required')
        finally:
            for fd in descriptors:os.close(fd)
        self._predecessor_lock=threading.RLock()
        self._legacy_read_lock=_OriginalSessionGate()
        self._v4_epoch=None;self._v4_workdir_bound=False;self._v4_workdir=None
        self._v4_undo_credits={}
        self._assert_empty_native_effects()

    def _assert_empty_native_effects(self):
        self.workflow_owners.assert_native_effect_registries_empty()

    def _attest_predecessor(self):
        with self._predecessor_lock,self.predecessor._state_lock:
            self.predecessor._ensure_native()
            self.predecessor._verify_catalog()

    def _attest_additional_registry_backend(self):
        self._assert_empty_native_effects()
        self._attest_predecessor()

    def _native_registry_backend(self,request,context,era):
        return self._predecessor_call(request,context,era,mutating=False)

    def _v4_current_epoch(self):
        return (self.legacy.session,self.legacy.protocol,self.legacy._namespace)

    def _v4_sync_epoch(self):
        epoch=self._v4_current_epoch()
        if epoch!=self._v4_epoch:
            self._v4_epoch=epoch;self._v4_workdir_bound=False;self._v4_workdir=None
            self._v4_undo_credits.clear()
        return epoch

    def _v4_retire_expired_session(self,epoch):
        # Only a verified native session-not-found response can retire this
        # transport. A lost write response never proves that the session expired.
        with self.legacy._state_lock:
            # Another admitted start may already have initialized a new binding.
            # A late response from the old binding cannot retire the new one.
            if self._v4_current_epoch()!=epoch:return
            self.legacy.initialized=False;self.legacy.legacy_ready=False
            self.legacy.session=None;self.legacy.protocol=None
            self._v4_sync_epoch()

    def _v4_path_key(self,path):
        if not isinstance(path,str):return None
        if _explicit_path(path):
            for prefix in ('ssh://','sftp://'):
                if path.startswith(prefix):
                    authority,separator,tail=path[len(prefix):].partition('/')
                    return ('remote',authority,posixpath.normpath('/'+tail if separator else '/~'))
            return ('local',posixpath.normpath(path))
        if not self._v4_workdir_bound:return None
        if self._v4_workdir is None:return ('explicit_reset_root',posixpath.normpath(path))
        base=self._v4_path_key(self._v4_workdir)
        return (*base[:-1],posixpath.normpath(posixpath.join(base[-1],path))) if base else None

    @staticmethod
    def _v4_refusal(identity,reason):
        undo=reason=='v4_undo_history_unproven'
        return error(identity,-32603,
            ('Undo history is not proven for this V4 session; workdir initialization cannot recover old undo history'
             if undo else 'Original V4 session state is unbound; use an explicit absolute path or bind workdir before relative paths'),
            outcome='not_submitted',automatic_retry=False,original_request_replayed=False,
            reason=reason,workdir_rebind_required=not undo,undo_history_unproven=undo)

    def _original(self,request,context,era,*,mutating):
        identity=request.get('id');name=request['params']['name'];arguments=request['params'].get('arguments',{})
        submitted=False
        try:
            if context is not None:
                with self._active_lock:
                    if context.cancel_requested or self._closing.is_set():return self._not_submitted(context,era)
                    context.native_id=None;context.binding=None
            with self._state_lock:
                self._ensure_native(context);self._verify_catalog(context)
            # Native process_start never reads MCP workdir or undo state. Keep
            # arguments untouched and all other V4 calls exclusively admitted.
            cwd=arguments.get('cwd')
            parallel_start=name=='process_start' and (cwd is None or
                isinstance(cwd,str) and cwd.startswith('/') and '\0' not in cwd)
            admission=self._legacy_read_lock.process_start() if parallel_start else self._legacy_read_lock
            with admission:
                with self.legacy._state_lock:
                    try:self.legacy._ensure_native();self.legacy._verify_catalog()
                    except NativeSessionExpired:
                        self._v4_retire_expired_session(self._v4_current_epoch());raise
                    epoch=self._v4_sync_epoch()
                    paths=_v4_paths(self.legacy.contract.by_name[name],arguments)
                    reset=name=='workdir' and arguments.get('reset') is True
                    if not reset and not self._v4_workdir_bound and any(not _explicit_path(path) for path in paths):
                        return self._v4_refusal(identity,'v4_relative_paths_unbound')
                    target=self._v4_path_key(arguments.get('path'))
                    undo=name=='text_editor' and arguments.get('command')=='undo_edit'
                    if undo and (target is None or self._v4_undo_credits.get(target,0)<=0):
                        return self._v4_refusal(identity,'v4_undo_history_unproven')
                    changed_workdir=name=='workdir' and (reset or arguments.get('path') is not None)
                    was_bound=self._v4_workdir_bound
                    if changed_workdir:
                        self._v4_workdir_bound=False;self._v4_workdir=None
                        self._v4_undo_credits.clear()
                    # Unknown writes cannot leave older undo history labelled as ours.
                    touched=set()
                    if mutating and name!='workdir':
                        if name in ('text_editor','batch_edit'):touched={target}
                        elif name=='extract_lines':touched={self._v4_path_key(arguments.get('append_path'))}
                        else:self._v4_undo_credits.clear()
                    old_credits={key:self._v4_undo_credits.pop(key,0) for key in touched if key is not None}
                    binding=(self.legacy.session,self.legacy.protocol)
                    native={'jsonrpc':'2.0','id':self.legacy._next_native_id('guarded-original'),
                        'method':'tools/call','params':{'name':name,'arguments':arguments}}
                submitted=True
                try:original=self.legacy.exchange(native,binding=binding,context=context,timeout=38)
                except NativeSessionExpired:
                    self._v4_retire_expired_session(epoch);raise
                response={**original,'id':identity}
                value=response.get('result')
                success=('error' not in response and isinstance(value,dict)
                         and value.get('isError',False) is False and isinstance(value.get('content'),list))
                with self.legacy._state_lock:
                    if self._v4_current_epoch()!=epoch:
                        self._v4_sync_epoch()
                    elif success:
                        if changed_workdir:
                            try:state=self._text_payload(response,identity)
                            except Exception:state={}
                            if (state.get('success') is True and reset and state.get('action')=='reset'):
                                self._v4_workdir_bound=True
                            elif (state.get('success') is True and state.get('action')=='set'
                                  and _explicit_path(state.get('working_directory'))
                                  and (was_bound or _explicit_path(str(arguments.get('path','')).strip()))):
                                self._v4_workdir=state['working_directory'];self._v4_workdir_bound=True
                        if undo:
                            remaining=old_credits.get(target,0)-1
                            if remaining>0:self._v4_undo_credits[target]=remaining
                        else:
                            history_target=(target if name=='text_editor' and arguments.get('command') in ('str_replace','delete')
                                or name=='batch_edit' and arguments.get('operations') else
                                self._v4_path_key(arguments.get('append_path')) if name=='extract_lines' else None)
                            if history_target is not None:
                                self._v4_undo_credits[history_target]=min(10,old_credits.get(history_target,0)+1)
                if era=='modern' and 'error' not in response:
                    if not isinstance(value,dict) or not isinstance(value.get('content'),list):raise ValueError()
                    return self._modern_result(identity,value)
                return response
        except RequestNotSubmitted:
            return self._not_submitted(context,era)
        except Exception:
            return error(identity,-32603,'Original V4 result unavailable; no request was replayed',
                outcome='unknown' if mutating and submitted else 'not_submitted' if mutating else 'unavailable',
                automatic_retry=False,original_request_replayed=False)

    def _predecessor_call(self,request,context,era,*,mutating):
        identity=request.get('id')
        try:
            self._assert_empty_native_effects()
            if context is not None:
                with self._active_lock:
                    if context.cancel_requested or self._closing.is_set():return self._not_submitted(context,era)
                    # A predecessor POST must never inherit a V11 cancellation mapping.
                    context.native_id=None;context.binding=None
            with self._state_lock:
                self._ensure_native(context);self._verify_catalog(context)
            with self._predecessor_lock:
                self._attest_predecessor()
                binding=(self.predecessor.session,self.predecessor.protocol)
                native={'jsonrpc':'2.0','id':self.predecessor._next_native_id('predecessor'),
                    'method':'tools/call','params':{'name':request['params']['name'],
                    'arguments':request['params'].get('arguments',{})}}
                reply=self.predecessor.exchange(native,binding=binding,context=context,timeout=38)
            reply={**reply,'id':identity}
            if era=='modern' and 'error' not in reply:
                value=reply.get('result')
                if not isinstance(value,dict) or not isinstance(value.get('content'),list):raise ValueError()
                return self._modern_result(identity,value)
            return reply
        except RequestNotSubmitted:
            return self._not_submitted(context,era)
        except Exception:
            return error(identity,-32603,'Predecessor result unavailable; original request was not replayed',
                outcome='unknown' if mutating else 'unavailable',automatic_retry=False,
                original_request_replayed=False)

    def _handle_owner(self,kind,identity,mutating):
        owner=self.workflow_owners.owner(kind,identity)
        if kind=='request' and not mutating:
            audit=self.workflow_owners.owner('audit',identity)
            if owner!='absent' and audit!='absent' and owner!=audit:
                raise UnsafeProvenance('layered_request_audit_intent_owner_mismatch')
            if owner=='absent':owner=audit
        return owner

    @staticmethod
    def _text_payload(response,identity):
        if (not isinstance(response,dict) or response.get('jsonrpc')!='2.0'
                or response.get('id')!=identity or 'error' in response):raise ValueError()
        result=response.get('result')
        if not isinstance(result,dict) or result.get('isError',False) is not False:raise ValueError()
        content=result.get('content')
        if (not isinstance(content,list) or len(content)!=1 or not isinstance(content[0],dict)
                or content[0].get('type')!='text' or not isinstance(content[0].get('text'),str)):raise ValueError()
        payload=json.loads(content[0]['text'],object_pairs_hook=strict_pairs,
            parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
        if not isinstance(payload,dict):raise ValueError()
        return payload

    def _workflow_list_backend(self,request,context,era,backend):
        if backend=='predecessor':return self._predecessor_call(request,context,era,mutating=False)
        return NativeProxy._dispatch(self,request,context)

    def _merged_stream_list(self,request,context,era):
        identity=request['id']
        try:
            arguments=request['params'].get('arguments',{})
            limit=arguments.get('limit',64);limit=64 if limit is None else limit
            if set(arguments)-{'limit'} or type(limit) is not int or limit<0:raise ValueError()
            limit=max(1,min(limit,128))
            roots={'v4':self.provenance.original_root,'predecessor':self.provenance.new_root}
            before={owner:owned_stream_names(root) for owner,root in roots.items()}
            if set(before['v4'])&set(before['predecessor']):raise ValueError()
            rows=[];sources={};consumed=0
            for owner in roots:
                page_request={**request,'params':{**request['params'],'arguments':{'limit':128}}}
                reply=(self._original(page_request,context,era,mutating=False) if owner=='v4'
                       else self._predecessor_call(page_request,context,era,mutating=False))
                consumed+=len(canonical(reply))
                if consumed>MAX_LIST_SOURCE_BYTES:raise ValueError()
                payload=self._text_payload(reply,identity);page=payload.get('sessions')
                if not isinstance(page,list) or len(page)>128:raise ValueError()
                identifiers=[]
                for row in page:
                    if not isinstance(row,dict):raise ValueError()
                    key=row.get('session_id')
                    if (not isinstance(key,str) or STREAM_ID.fullmatch(key) is None
                            or key in identifiers or self.provenance.route('stream_handoff_status',
                                {'session_id':key})!=('legacy' if owner=='v4' else 'native')):raise ValueError()
                    identifiers.append(key);rows.append(row)
                if set(identifiers)!=set(before[owner]):raise ValueError()
                result=reply['result'];block=result['content'][0]
                sources[owner]={'payload':{key:value for key,value in payload.items() if key!='sessions'},
                    'result':{key:value for key,value in result.items() if key!='content'},
                    'content':{key:value for key,value in block.items() if key!='text'}}
            if any(owned_stream_names(root)!=before[owner] for owner,root in roots.items()):raise ValueError()
            self._assert_empty_native_effects()
            rows.sort(key=lambda row:row['session_id']);more=len(rows)>limit
            payload={'sessions':rows[:limit],'total':len(rows),'has_more':more,'inventory_complete':not more,
                'remaining_session_ids':[row['session_id'] for row in rows[limit:]],
                'layered_controller_sources':sources,'effect_owner_changed':False,
                'snapshot_semantics':'bounded_controller_observations_not_global_freeze'}
            result={'content':[{'type':'text','text':canonical(payload).decode('utf-8')}],'isError':False}
            reply=({'jsonrpc':'2.0','id':identity,'result':result} if era=='legacy'
                   else self._modern_result(identity,result))
            if len(canonical(reply))>MAX_RESPONSE:raise ValueError()
            return reply
        except Exception:
            return error(identity,-32603,'Both stream inventories could not be reconciled completely',
                outcome='unavailable',automatic_retry=False,partial_inventory_returned=False,
                original_request_replayed=False)

    def _merged_workflow_list(self,request,context,era):
        identity=request['id'];name=request['params']['name'];arguments=request['params'].get('arguments',{})
        try:
            if set(arguments)-{'after_id','limit'}:raise ValueError()
            limit=arguments.get('limit',32);limit=32 if limit is None else limit
            after=arguments.get('after_id')
            if (type(limit) is not int or not 1<=limit<=32
                    or after is not None and (not isinstance(after,str) or WORKFLOW_ID.fullmatch(after) is None)):
                raise ValueError()
            row_key,id_key,kind=(('searches','search_id','search') if name=='search_list'
                                else ('requests','request_id','audit'))
            rows=[];seen=set();sources={};consumed=0
            for backend in ('predecessor','native'):
                cursor=None;metadata=None
                for _ in range(MAX_LIST_PAGES):
                    page_arguments={'limit':32}
                    if cursor is not None:page_arguments['after_id']=cursor
                    page_request={**request,'params':{**request['params'],'arguments':page_arguments}}
                    reply=self._workflow_list_backend(page_request,context,era,backend)
                    consumed+=len(canonical(reply))
                    if consumed>MAX_LIST_SOURCE_BYTES:raise ValueError()
                    payload=self._text_payload(reply,identity)
                    page=payload.get(row_key);following=payload.get('next_after_id')
                    if not isinstance(page,list) or len(page)>32 or len(rows)+len(page)>MAX_LIST_ROWS:raise ValueError()
                    for row in page:
                        if not isinstance(row,dict):raise ValueError()
                        key=row.get(id_key)
                        if (not isinstance(key,str) or WORKFLOW_ID.fullmatch(key) is None
                                or key in seen or self.workflow_owners.owner(kind,key)!=backend):raise ValueError()
                        if kind=='audit' and (type(row.get('accepted_unix_ms')) is not int
                                             or row['accepted_unix_ms']<0):raise ValueError()
                        seen.add(key);rows.append(row)
                    metadata={key:value for key,value in payload.items() if key not in (row_key,'next_after_id')}
                    if following is None:break
                    if (not page or following!=page[-1].get(id_key) or following==cursor
                            or not isinstance(following,str) or WORKFLOW_ID.fullmatch(following) is None):raise ValueError()
                    cursor=following
                else:raise ValueError()
                sources[backend]=metadata
            rows.sort(key=(lambda row:row[id_key]) if kind=='search'
                      else (lambda row:(row['accepted_unix_ms'],row[id_key])))
            start=0
            if after is not None:
                matches=[index for index,row in enumerate(rows) if row[id_key]==after]
                if len(matches)!=1:raise ValueError()
                start=matches[0]+1
            end=min(start+limit,len(rows))
            while True:
                page=rows[start:end];more=end<len(rows)
                payload={row_key:page,'next_after_id':page[-1][id_key] if more else None,
                    'total_observed':len(rows),'history_is_live':True,'automatic_retry':False,
                    'layered_controller_sources':sources,
                    'visibility':'predecessor_v10_and_new_v11_same_private_operator',
                    'snapshot_semantics':'bounded_observations_not_global_freeze'}
                result={'content':[{'type':'text','text':canonical(payload).decode('utf-8')}],'isError':False}
                reply=({'jsonrpc':'2.0','id':identity,'result':result} if era=='legacy'
                       else self._modern_result(identity,result))
                if len(canonical(reply))<=MAX_LIST_WIRE_BYTES:return reply
                if end<=start+1:raise ValueError()
                end-=1
        except Exception:
            return error(identity,-32603,'Layered workflow history unavailable or cursor expired; no partial history returned',
                outcome='unavailable',automatic_retry=False,partial_inventory_returned=False,
                original_request_replayed=False)

    def _v10_read_workflow(self,request,context):
        if request['params']['name']=='operation_start':
            operation=request['params'].get('arguments',{}).get('operation',{})
            if isinstance(operation,dict) and operation.get('tool') in ('process_status','process_read','process_wait'):
                return error(request['id'],-32603,'Existing job reads require their original direct read tool',
                    outcome='not_submitted',automatic_retry=False,original_request_replayed=False)
        return super()._v10_read_workflow(request,context)

    def _dispatch(self,request,context=None):
        if not isinstance(request,dict) or request.get('method')!='tools/call':return super()._dispatch(request,context)
        invalid=valid_request(request,self.contract)
        if invalid is not None:return invalid
        era,_=request_era(request)
        if era not in ('legacy','modern'):return super()._dispatch(request,context)
        if era=='legacy' and not self.legacy_ready:return super()._dispatch(request,context)
        identity=request['id'];name=request['params']['name']
        try:
            self._assert_empty_native_effects()
            if name in ORIGINAL_SESSION_READS:return self._original(request,context,era,mutating=False)
            if name in SCOPED_HANDLES:
                kind,field,mutating=SCOPED_HANDLES[name];key=request['params'].get('arguments',{}).get(field)
                if not isinstance(key,str) or WORKFLOW_ID.fullmatch(key) is None:raise ValueError()
                if self._handle_owner(kind,key,mutating)=='predecessor':
                    return self._predecessor_call(request,context,era,mutating=mutating)
            if name in ('search_list','request_history'):
                return self._merged_workflow_list(request,context,era)
            if name=='stream_handoff_list':return self._merged_stream_list(request,context,era)
            if name in READ_ROUTES or name in STREAM_READ_NAMES:
                owner=self.provenance.route(name,request['params'].get('arguments',{}))
                if owner=='native':return self._predecessor_call(request,context,era,mutating=False)
            reply=super()._dispatch(request,context)
            if name=='request_archive' and isinstance(reply,dict) and 'result' in reply:
                payload=self._text_payload(reply,identity)
                payload['layered_archive_source']='new_v11_only; predecessor_history_remains_available_via_request_history'
                reply=copy.deepcopy(reply);reply['result']['content'][0]['text']=canonical(payload).decode('utf-8')
            return reply
        except Exception:
            return error(identity,-32603,'Layered controller ownership unavailable or ambiguous; no dispatch submitted',
                outcome='not_submitted',automatic_retry=False,original_request_replayed=False)

    def close(self,timeout=2.5):
        predecessor=getattr(self,'predecessor',None)
        if predecessor is not None:predecessor.close(timeout=0)
        super().close(timeout=timeout)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stdio',action='store_true',required=True)
    for prefix in ('','legacy-','predecessor-'):
        for flag in ('upstream','token-file','contract','contract-sha256'):
            parser.add_argument('--'+prefix+flag,required=True)
    parser.add_argument('--legacy-state',required=True);parser.add_argument('--predecessor-state',required=True)
    parser.add_argument('--native-state',required=True)
    parser.add_argument('--route-original-v4-effects',action='store_true',required=True)
    parser.add_argument('--route-v11-read-workflows',action='store_true',required=True)
    parser.add_argument('--acknowledge-full-operator',action='store_true',required=True)
    args=parser.parse_args()
    contracts=[ToolContract.load(getattr(args,prefix+'contract'),getattr(args,prefix+'contract_sha256'))
               for prefix in ('','legacy_','predecessor_')]
    proxy=LayeredReadNativeProxy(args.upstream,private_token(args.token_file),contracts[0],
        args.legacy_upstream,private_token(args.legacy_token_file),contracts[1],args.legacy_state,
        args.predecessor_upstream,private_token(args.predecessor_token_file),contracts[2],
        args.predecessor_state,args.native_state)
    import sys
    proxy.serve(sys.stdin.buffer,sys.stdout.buffer)


if __name__=='__main__':main()
