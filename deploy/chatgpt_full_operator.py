#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Private full-operator stdio facade, using a pinned unmodified native tool contract.
Every actual action goes to existing loopback hepta-runtime. Credentials stay local;
unknown transport outcomes are never retried automatically. No public listener.
"""
import argparse
import http.client
import json
import os
import pathlib
import stat
import sys
import urllib.parse
import hashlib
import queue
import secrets
import select
import socket
import threading
import time
from mcp_tool_contract import ToolContract,canonical

MAX_REQUEST=4*1024*1024
MAX_RESPONSE=16*1024*1024
MAX_ACTIVE_REQUESTS=16
MAX_RETIRED_IDS=4096
MAX_CANCEL_WORKERS=2
CANCEL_TIMEOUT=2
SHUTDOWN_TIMEOUT=3
METHODS={'initialize','server/discover','notifications/initialized','notifications/cancelled','ping','tools/list','tools/call'}
MODERN_VERSION='2026-07-28'
VERSION_KEY='io.modelcontextprotocol/protocolVersion'
CAPABILITIES_KEY='io.modelcontextprotocol/clientCapabilities'
SERVER_INFO_KEY='io.modelcontextprotocol/serverInfo'


def private_token(path):
    fd=os.open(pathlib.Path(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        st=os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:raise PermissionError('private account-owned runtime token required')
        data=stream.read(4097)
    if len(data)>4096:raise ValueError('oversized runtime token')
    token=data.decode('ascii').strip()
    if not token or any(c.isspace() or ord(c)<33 or ord(c)>126 for c in token):raise ValueError('invalid runtime token')
    return token


def error(ident,code,message,**details):
    value={'jsonrpc':'2.0','id':ident,'error':{'code':code,'message':message}}
    if details:value['error']['data']=details
    return value


def valid_request(request,contract):
    try:canonical(request)
    except (ValueError,TypeError,UnicodeError,RecursionError,OverflowError):
        return error(None,-32600,'Strict UTF-8 JSON request required',outcome='not_submitted',automatic_retry=False)
    if not isinstance(request,dict) or request.get('jsonrpc')!='2.0' or set(request)-{'jsonrpc','method','id','params'}:
        return error(None,-32600,'Single JSON-RPC 2.0 request required')
    ident=request.get('id')
    if 'id' in request and not valid_identity(ident):return error(None,-32600,'Invalid request identity')
    method=request.get('method')
    if not isinstance(method,str) or method not in METHODS:return error(ident,-32601,'Method outside the explicit tool transport contract')
    params=request.get('params',{})
    if not isinstance(params,dict):return error(ident,-32602,'Object parameters required')
    if method.startswith('notifications/'):
        if 'id' in request:return error(ident,-32600,'Notifications cannot carry request IDs')
        if method=='notifications/cancelled':
            target=params.get('requestId')
            if set(params)-{'requestId','reason','_meta'} or not valid_identity(target):
                return error(None,-32602,'Bounded cancellation request identity required')
            if 'reason' in params and (not isinstance(params['reason'],str) or len(params['reason'])>1024):
                return error(None,-32602,'Bounded cancellation reason required')
            if '_meta' in params and not isinstance(params['_meta'],dict):return error(None,-32602,'Object cancellation metadata required')
        return None
    if 'id' not in request:return error(None,-32600,'Operation must have a response identity')
    if method=='tools/call':
        if set(params)-{'name','arguments','_meta'} or not contract.allows(params.get('name')):return error(ident,-32601,'Tool not present in the pinned full-operator contract')
        if not isinstance(params.get('arguments',{}),dict):return error(ident,-32602,'Tool arguments must be an object')
    if method=='tools/list' and set(params)-{'_meta'}:return error(ident,-32602,'The complete pinned catalog fits in one page')
    if method=='server/discover' and set(params)-{'_meta'}:return error(ident,-32602,'Only discovery protocol metadata is accepted')
    return None


def valid_identity(value):
    if type(value) not in (str,int):return False
    if isinstance(value,str):
        if len(value)>256:return False
        try:value.encode('utf-8')
        except UnicodeError:return False
    return True


def request_era(request):
    params=request.get('params') or {}
    meta=params.get('_meta')
    if not isinstance(meta,dict) or VERSION_KEY not in meta:return 'legacy',None
    version=meta.get(VERSION_KEY)
    if not isinstance(version,str):return 'invalid',None
    try:version.encode('utf-8')
    except UnicodeError:return 'invalid',None
    if version!=MODERN_VERSION:return 'unsupported',version
    if not isinstance(meta.get(CAPABILITIES_KEY),dict):return 'invalid',version
    return 'modern',version


def parse_messages(content_type,body):
    if 'application/json' in content_type:return [json.loads(body)]
    if 'text/event-stream' not in content_type:raise ValueError('unexpected upstream transport')
    messages=[];data=[]
    for line in body.decode('utf-8').replace('\r\n','\n').split('\n'):
        if not line:
            if data:
                payload='\n'.join(data)
                if payload.strip():messages.append(json.loads(payload))
                data=[]
        elif line.startswith('data:'):data.append(line[5:].lstrip(' '))
    if data and '\n'.join(data).strip():messages.append(json.loads('\n'.join(data)))
    return messages


class NativeSessionExpired(RuntimeError):
    """The verified loopback MCP endpoint rejected its former session identity."""


class RequestNotSubmitted(RuntimeError):
    """A locally cancelled intent never entered the tool HTTP submission."""


class ActiveRequest:
    def __init__(self, request, owner, remember):
        self.request=request;self.ident=request['id'];self.key=(type(self.ident),self.ident)
        self.owner=owner;self.remember=remember;self.native_id=None;self.binding=None
        self.transmitting=False;self.posted=False;self.completed=False
        self.cancel_requested=False;self.cancel_started=False;self.cancel_failed=False


class NativeProxy:
    def __init__(self,upstream,token,contract,timeout=150):
        parsed=urllib.parse.urlsplit(upstream)
        if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.path!='/mcp' or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('full operator upstream must be explicit IPv4 loopback HTTP /mcp')
        self.upstream=parsed;self.token=token;self.contract=contract;self.timeout=timeout
        self.session=None;self.protocol=None;self.initialized=False;self.legacy_ready=False;self.internal_counter=0
        self._state_lock=threading.RLock();self._active_lock=threading.RLock()
        self._trace_lock=threading.Lock();self._owner=object();self._namespace=secrets.token_hex(16)
        self._active={};self._retired=set();self._closing=threading.Event()
        self._cancel_slots=threading.BoundedSemaphore(MAX_CANCEL_WORKERS);self._cancel_threads=set()

    def _identity_digest(self,ident):
        # Fixed-size retired identities bound memory even for large integer IDs.
        return (type(ident),hashlib.sha256(canonical(ident)).digest())

    def _reserve(self,request,remember=False):
        ident=request['id'];key=(type(ident),ident)
        with self._active_lock:
            if self._closing.is_set():return None,error(ident,-32603,'Facade input is closing',outcome='not_submitted',automatic_retry=False)
            if key in self._active:return None,error(None,-32600,'Duplicate active request identity')
            if remember:
                if self._identity_digest(ident) in self._retired:
                    return None,error(ident,-32600,'Request identity cannot be reused in this facade process',outcome='not_submitted',automatic_retry=False)
                pending_retirements=sum(c.remember for c in self._active.values())
                if len(self._retired)+pending_retirements>=MAX_RETIRED_IDS:
                    return None,error(ident,-32603,'Bounded request identity history is full; reconnect with a new facade process',outcome='not_submitted',automatic_retry=False)
            if len(self._active)>=MAX_ACTIVE_REQUESTS:
                return None,error(ident,-32603,'Facade active request limit reached',outcome='not_submitted',automatic_retry=False)
            context=ActiveRequest(request,self._owner,remember);self._active[key]=context
            return context,None

    def _finish(self,context):
        with self._active_lock:
            if context.completed:return False
            context.completed=True
            if self._active.get(context.key) is context:self._active.pop(context.key)
            if context.remember:
                self._retired.add(self._identity_digest(context.ident))
            return True

    def _next_native_id(self,kind):
        with self._state_lock:
            self.internal_counter+=1
            return 'hepta-'+kind+'-'+self._namespace+'-'+str(self.internal_counter)

    @staticmethod
    def _valid_sid(value):
        return isinstance(value,str) and 0<len(value)<=512 and all(33<=ord(c)<=126 for c in value)

    def exchange(self,request,binding=None,context=None,timeout=None,cancellation=None):
        body=canonical(request)
        selected_session,selected_protocol=binding if binding is not None else (self.session,self.protocol)
        headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','X-Hepta-Runtime-Token':self.token}
        if selected_session:headers['Mcp-Session-Id']=selected_session
        if selected_protocol:headers['MCP-Protocol-Version']=selected_protocol
        conn=http.client.HTTPConnection(self.upstream.hostname,self.upstream.port or 80,timeout=self.timeout if timeout is None else timeout)
        cancel_timer=None;cancel_socket=[];cancel_deadline=None
        try:
            if request['method']=='notifications/cancelled':
                with self._active_lock:
                    if (cancellation is None or self._active.get(cancellation.key) is not cancellation
                            or cancellation.completed or cancellation.owner is not self._owner
                            or not cancellation.cancel_requested or not cancellation.posted
                            or binding!=cancellation.binding or not self._valid_sid(selected_session)
                            or request.get('params')!={'requestId':cancellation.native_id}):
                        raise ValueError('cancellation is outside the active native session mapping')
                # Socket timeouts bound inactivity, not a peer that trickles
                # headers or body bytes forever. Cancellation has an absolute
                # deadline, with at most two guarded connections in flight.
                cancel_deadline=time.monotonic()+min(self.timeout,CANCEL_TIMEOUT)
                def interrupt():
                    peer=cancel_socket[0] if cancel_socket else conn.sock
                    if peer is not None:
                        try:peer.shutdown(socket.SHUT_RDWR)
                        except OSError:pass
                    conn.close()
                cancel_timer=threading.Timer(min(self.timeout,CANCEL_TIMEOUT),interrupt)
                cancel_timer.daemon=True;cancel_timer.start()
            if context is not None:
                with self._active_lock:
                    if context.completed or context.cancel_requested or self._closing.is_set():raise RequestNotSubmitted()
                    context.transmitting=True
            conn.request('POST','/mcp',body=body,headers=headers)
            if cancel_deadline is not None:
                if time.monotonic()>=cancel_deadline:raise TimeoutError('cancellation deadline elapsed')
                # Keep an independent fd so HTTPConnection closing its own
                # socket does not remove the watchdog's ability to interrupt
                # the response file object's reads.
                cancel_socket.append(socket.socket(fileno=os.dup(conn.sock.fileno())))
            if context is not None:
                with self._active_lock:context.posted=True
                self._schedule_cancel(context)
            response=conn.getresponse();raw=response.read(MAX_RESPONSE+1)
            if cancel_deadline is not None and time.monotonic()>=cancel_deadline:raise TimeoutError('cancellation deadline elapsed')
            if len(raw)>MAX_RESPONSE:raise ValueError('upstream response exceeds explicit limit')
            if response.status==404 and selected_session is not None and raw.strip()==b'Not Found: Session not found':
                raise NativeSessionExpired('loopback native MCP session is no longer valid')
            if not 200<=response.status<300:raise RuntimeError('upstream HTTP failure')
            session=response.getheader('Mcp-Session-Id')
            if session:
                if not self._valid_sid(session):raise ValueError('invalid native session identity')
                if request['method']=='initialize' and binding is None:self.session=session
                elif session!=selected_session:raise ValueError('native session identity changed during a bound request')
            if 'id' not in request:return None
            if not raw:raise RuntimeError('missing response for a request')
            messages=parse_messages((response.getheader('Content-Type') or '').lower(),raw)
            matched=[r for r in messages if isinstance(r,dict) and r.get('jsonrpc')=='2.0' and r.get('id')==request['id']]
            if len(matched)!=1 or ('result' in matched[0])==('error' in matched[0]):raise ValueError('ambiguous upstream response identity')
            canonical(matched[0])
            return matched[0]
        finally:
            if cancel_timer is not None:cancel_timer.cancel()
            if cancel_socket:cancel_socket[0].close()
            conn.close()

    def internal(self,method,params):
        return self.exchange({'jsonrpc':'2.0','id':self._next_native_id('contract'),'method':method,'params':params})

    def _other_active(self,context):
        with self._active_lock:return any(c is not context and not c.completed for c in self._active.values())

    def _verify_catalog(self,context=None):
        try:tools=self.internal('tools/list',{})
        except NativeSessionExpired:
            if not self.initialized or self.legacy_ready or self._other_active(context):raise
            self._new_native_session({'protocolVersion':'2025-11-25','capabilities':{},
                'clientInfo':{'name':'hepta-full-operator-adapter','version':'1'}},context)
            return
        if 'error' in tools or not isinstance(tools.get('result'),dict) or tools['result'].get('nextCursor'):
            raise ValueError('cannot attest full native catalog')
        self.contract.verify(tools['result']['tools'])

    def _new_native_session(self,init_params,context=None):
        with self._active_lock:
            others=[c for c in self._active.values() if c is not context and not c.completed]
            cold=self.session is None and not any(c.binding is not None or c.transmitting for c in others)
            if others and not cold:raise ValueError('cannot replace native session while requests are active')
        self.initialized=False;self.legacy_ready=False;self.session=None;self.protocol=None
        self._namespace=secrets.token_hex(16)
        result=self.exchange({'jsonrpc':'2.0','id':self._next_native_id('initialize'),'method':'initialize','params':init_params})
        if 'error' in result:raise ValueError('native initialize rejected')
        if not self._valid_sid(self.session):raise ValueError('native initialization requires a validated private session identity')
        native=result['result']
        if not isinstance(native,dict) or not isinstance(native.get('protocolVersion'),str):raise ValueError('malformed native initialization')
        self.protocol=native['protocolVersion']
        self.exchange({'jsonrpc':'2.0','method':'notifications/initialized','params':{}})
        self._verify_catalog(context);self.initialized=True
        return native

    def _ensure_native(self,context=None):
        if not self.initialized:
            self._new_native_session({'protocolVersion':'2025-11-25','capabilities':{},
                'clientInfo':{'name':'hepta-full-operator-adapter','version':'1'}},context)

    def _modern_result(self,ident,result):
        result=dict(result);result['resultType']='complete'
        metadata=result.get('_meta');metadata=dict(metadata) if isinstance(metadata,dict) else {}
        metadata[SERVER_INFO_KEY]={'name':'hepta-runtime-full-operator','version':self.contract.catalog_sha256[:16]}
        result['_meta']=metadata
        return {'jsonrpc':'2.0','id':ident,'result':result}

    def _schedule_cancel(self,context):
        with self._active_lock:
            if (self._active.get(context.key) is not context or context.completed or context.owner is not self._owner
                    or not context.cancel_requested or context.cancel_started or not context.posted
                    or context.native_id is None or context.binding is None or not self._valid_sid(context.binding[0])):return
            if not self._cancel_slots.acquire(blocking=False):return
            context.cancel_started=True
            def forward():
                try:
                    with self._active_lock:
                        live=self._active.get(context.key) is context and not context.completed and context.owner is self._owner
                        native_id=context.native_id;binding=context.binding
                    if live:
                        # An accepted notification is request intent only. rmcp
                        # may close SSE while the durable host effect continues.
                        self.exchange({'jsonrpc':'2.0','method':'notifications/cancelled',
                            'params':{'requestId':native_id}},binding=binding,timeout=min(self.timeout,CANCEL_TIMEOUT),cancellation=context)
                except Exception:
                    with self._active_lock:context.cancel_failed=True
                finally:
                    with self._active_lock:self._cancel_threads.discard(threading.current_thread())
                    self._cancel_slots.release()
                    # The active table is the bounded pending-intent store.
                    # A call can complete before its cancellation HTTP reply,
                    # so release must wake a later call that lacked a slot.
                    with self._active_lock:waiting=list(self._active.values())
                    for pending in waiting:self._schedule_cancel(pending)
            thread=threading.Thread(target=forward,name='hepta-request-cancel',daemon=True)
            self._cancel_threads.add(thread);thread.start()

    def _cancel_active(self,params):
        ident=params['requestId'];key=(type(ident),ident)
        with self._active_lock:
            context=self._active.get(key)
            if context is None or context.completed or context.request['method']!='tools/call' or context.owner is not self._owner:return
            context.cancel_requested=True
        self._schedule_cancel(context)

    def _not_submitted(self,context,era):
        return error(context.ident,-32603 if era=='modern' else -32070,
            'Request cancellation received before upstream tool submission',outcome='not_submitted',
            cancellation='request_intent_only',automatic_retry=False)

    def _dispatch(self,request,context=None):
        invalid=valid_request(request,self.contract)
        if invalid is not None:return invalid
        method=request['method'];ident=request.get('id');era,version=request_era(request)
        if era=='unsupported':return error(ident,-32022,'Unsupported protocol version',supported=[MODERN_VERSION],requested=version)
        if era=='invalid':return error(ident,-32602,'Modern MCP request requires object clientCapabilities')
        if method=='server/discover' and era!='modern':return error(ident,-32601,'Modern MCP discovery requires protocol metadata')
        if method=='initialize' and era=='modern':return error(ident,-32601,'Modern MCP uses server/discover, not initialize')
        if method.startswith('notifications/'):
            if method=='notifications/cancelled':self._cancel_active(request['params'])
            return None
        mutating=method=='tools/call' and not self.contract.read_only(request['params']['name'])
        try:
            with self._state_lock:
                if context is not None and (context.cancel_requested or self._closing.is_set()):return self._not_submitted(context,era)
                if era=='legacy' and method!='initialize' and not self.legacy_ready:
                    return error(ident,-32071,'Legacy MCP initialization required before tool calls')
                if method=='initialize':
                    native=self._new_native_session(request.get('params',{}),context)
                    result=dict(native);result['serverInfo']={'name':'hepta-runtime-full-operator','version':self.contract.catalog_sha256[:16]}
                    result['capabilities']={'tools':{'listChanged':False}};self.legacy_ready=True
                    return {'jsonrpc':'2.0','id':ident,'result':result}
                if era=='modern':self._ensure_native(context)
                if method=='server/discover':
                    return self._modern_result(ident,{'supportedVersions':[MODERN_VERSION],
                        'capabilities':{'tools':{'listChanged':False}},'cacheScope':'private','ttlMs':0})
                if method=='tools/list':
                    self._verify_catalog(context)
                    value={'tools':self.contract.tools}
                    if era=='modern':return self._modern_result(ident,{**value,'cacheScope':'private','ttlMs':0})
                    return {'jsonrpc':'2.0','id':ident,'result':value}
                if method=='ping' and era=='modern':return self._modern_result(ident,{})
                if method=='tools/call':self._verify_catalog(context)
                native_id=self._next_native_id('call')
                binding=(self.session,self.protocol)
                if context is not None:
                    with self._active_lock:
                        if context.cancel_requested or self._closing.is_set():return self._not_submitted(context,era)
                        context.native_id=native_id;context.binding=binding
                native_req={**request,'id':native_id}
                if era=='modern':native_req['params']={'name':request['params']['name'],'arguments':request.get('params',{}).get('arguments',{})}
            # HTTP tool waits never hold the state lock; the input reader and
            # bounded cancellation workers can operate on the frozen binding.
            response=self.exchange(native_req,binding=binding,context=context)
            response={**response,'id':ident}
            if era=='modern' and 'error' not in response:
                result=response.get('result')
                if not isinstance(result,dict) or not isinstance(result.get('content'),list):raise ValueError('native tool response must contain content array')
                return self._modern_result(ident,result)
            return response
        except RequestNotSubmitted:
            return self._not_submitted(context,era)
        except Exception:
            if method in ('initialize','tools/list','server/discover'):
                with self._state_lock:self.initialized=False;self.legacy_ready=False
            details={'outcome':'unknown' if mutating else 'unavailable','automatic_retry':False,
                'contract_sha256':self.contract.catalog_sha256}
            if context is not None and context.cancel_requested:details['cancellation']='request_intent_only'
            return error(ident,-32603 if era=='modern' else -32070,
                'Native operation result unavailable; do not replay a write blindly',**details)

    def dispatch(self,request,context=None):
        invalid=valid_request(request,self.contract)
        notification=isinstance(request,dict) and isinstance(request.get('method'),str) and request['method'].startswith('notifications/')
        if invalid is not None:return None if notification else invalid
        if notification and request_era(request)[0] in ('unsupported','invalid'):return None
        own=False
        if not notification and context is None:
            context,refused=self._reserve(request)
            if refused is not None:return refused
            own=True
        try:reply=self._dispatch(request,context)
        finally:
            if own:self._finish(context)
        if os.environ.get('HEPTA_MCP_PROTOCOL_TRACE')=='1' and isinstance(request,dict):
            method=request.get('method')
            if method in ('server/discover','initialize','tools/list','ping','notifications/initialized'):
                era,_=request_era(request);status='error' if isinstance(reply,dict) and 'error' in reply else ('no_reply' if reply is None else 'ok')
                code=reply['error'].get('code') if status=='error' else None
                record={'event':'hepta_mcp_protocol','method':method,'era':era,'status':status,'error_code':code}
                with self._trace_lock:
                    try:
                        fd=sys.stderr.fileno();previous=os.get_blocking(fd);os.set_blocking(fd,False)
                    except (AttributeError,OSError,ValueError):
                        # Generic test streams have no process-exit guarantee.
                        try:sys.stderr.write(json.dumps(record,separators=(',',':'))+'\n');sys.stderr.flush()
                        except (OSError,ValueError):pass
                    else:
                        try:
                            os.write(fd,canonical(record)+b'\n')
                        except OSError:pass
                        finally:os.set_blocking(fd,previous)
        return reply

    def serve(self,input_stream,output_stream):
        pending=queue.Queue(MAX_ACTIVE_REQUESTS);responses=queue.Queue(MAX_ACTIVE_REQUESTS)
        output_stop=threading.Event();output_failed=threading.Event();output_lock=threading.Lock();reader_done=threading.Event()
        shutdown_deadline=[None]
        def descriptor(stream):
            try:return stream.fileno()
            except (AttributeError,OSError,ValueError):return None
        def frames():
            fd=descriptor(input_stream)
            if fd is None:
                # Generic stream fallback is daemon-isolated. Real process
                # shutdown guarantees use raw fds, never buffered stdin locks.
                while not self._closing.is_set():
                    raw=input_stream.readline(MAX_REQUEST+2)
                    if not raw:self._closing.set();return
                    if len(raw)>MAX_REQUEST+1 or not raw.endswith(b'\n'):
                        while raw and not raw.endswith(b'\n'):raw=input_stream.readline(MAX_REQUEST+2)
                        yield None
                    else:yield raw
                return
            previous=os.get_blocking(fd);os.set_blocking(fd,False)
            buffered=bytearray();discard=False
            try:
                while not self._closing.is_set():
                    if not select.select([fd],[],[],0.05)[0]:continue
                    try:chunk=os.read(fd,65536)
                    except BlockingIOError:continue
                    if not chunk:
                        self._closing.set()
                        if buffered or discard:yield None
                        return
                    parts=chunk.split(b'\n')
                    for index,part in enumerate(parts):
                        if self._closing.is_set():return
                        complete=index<len(parts)-1
                        if discard:
                            if complete:discard=False;yield None
                            continue
                        if len(buffered)+len(part)+int(complete)>MAX_REQUEST+1:
                            buffered.clear()
                            if complete:yield None
                            else:discard=True
                            continue
                        buffered.extend(part)
                        if complete:
                            buffered.extend(b'\n');yield bytes(buffered);buffered.clear()
            finally:os.set_blocking(fd,previous)
        def emit(value,deadline=None):
            if value is None:return True
            payload=canonical(value)
            if len(payload)>MAX_RESPONSE:payload=canonical(error(value.get('id'),-32070,'Response exceeds facade limit',outcome='unknown',automatic_retry=False))
            wait=0.1 if deadline is None else max(0,min(0.1,deadline-time.monotonic()))
            try:responses.put(payload+b'\n',timeout=wait);return True
            except queue.Full:output_failed.set();self._closing.set();return False
        def write_responses():
            fd=descriptor(output_stream);previous=None
            if fd is not None:previous=os.get_blocking(fd);os.set_blocking(fd,False)
            try:
                while not output_stop.is_set() or not responses.empty():
                    if shutdown_deadline[0] is not None and time.monotonic()>=shutdown_deadline[0]:return
                    try:payload=responses.get(timeout=0.05)
                    except queue.Empty:continue
                    try:
                        with output_lock:
                            if fd is None:output_stream.write(payload);output_stream.flush()
                            else:
                                cursor=0
                                while cursor<len(payload):
                                    if shutdown_deadline[0] is not None and time.monotonic()>=shutdown_deadline[0]:return
                                    if not select.select([],[fd],[],0.05)[1]:continue
                                    try:cursor+=os.write(fd,payload[cursor:cursor+65536])
                                    except BlockingIOError:continue
                    except Exception:output_failed.set();self._closing.set();return
            finally:
                if fd is not None:os.set_blocking(fd,previous)
        def work():
            while True:
                try:context=pending.get(timeout=0.05)
                except queue.Empty:
                    if self._closing.is_set():return
                    continue
                value=self.dispatch(context.request,context)
                if self._finish(context):emit(value)
        def read_requests():
            try:
                for raw in frames():
                    if raw is None:
                        if not emit(error(None,-32600,'Bounded newline-delimited JSON-RPC request required')):break
                        continue
                    if self._closing.is_set():break
                    try:request=json.loads(raw)
                    except (ValueError,UnicodeError,RecursionError):
                        if not emit(error(None,-32700,'Invalid JSON')):break
                        continue
                    invalid=valid_request(request,self.contract)
                    notification=isinstance(request,dict) and isinstance(request.get('method'),str) and request['method'].startswith('notifications/')
                    if notification:
                        if invalid is None:self.dispatch(request)
                        continue
                    if invalid is not None:
                        if not emit(invalid):break
                        continue
                    context,refused=self._reserve(request,remember=True)
                    if refused is not None:
                        if not emit(refused):break
                        continue
                    try:pending.put_nowait(context)
                    except queue.Full:
                        self._finish(context)
                        if not emit(error(context.ident,-32603,'Facade request queue is full',outcome='not_submitted',automatic_retry=False)):break
            except (OSError,ValueError):self._closing.set()
            finally:self._closing.set();reader_done.set()
        writer=threading.Thread(target=write_responses,name='hepta-stdio-output',daemon=True)
        worker=threading.Thread(target=work,name='hepta-stdio-operation',daemon=True)
        reader=threading.Thread(target=read_requests,name='hepta-stdio-input',daemon=True)
        writer.start();worker.start();reader.start()
        try:
            while not self._closing.is_set() and not reader_done.wait(.05):pass
        finally:
            self._closing.set()
            deadline=time.monotonic()+SHUTDOWN_TIMEOUT
            shutdown_deadline[0]=deadline
            output_grace=min(0.5,SHUTDOWN_TIMEOUT/4)
            with self._active_lock:
                contexts=list(self._active.values())
                for context in contexts:context.cancel_requested=True
            for context in contexts:self._schedule_cancel(context)
            # One overall deadline covers all workers. A daemon blocked on an
            # upstream or stdout cannot turn EOF into an unbounded join.
            reader.join(max(0,deadline-time.monotonic()-output_grace))
            worker.join(max(0,deadline-time.monotonic()-output_grace))
            with self._active_lock:cancel_threads=list(self._cancel_threads)
            for thread in cancel_threads:thread.join(max(0,deadline-time.monotonic()-output_grace))
            with self._active_lock:unresolved=list(self._active.values())
            for context in unresolved:
                mutating=context.request['method']=='tools/call' and not self.contract.read_only(context.request['params']['name'])
                outcome='unknown' if context.transmitting and mutating else ('unavailable' if context.transmitting else 'not_submitted')
                value=error(context.ident,-32603 if request_era(context.request)[0]=='modern' else -32070,
                    'Facade input closed before a confirmed operation result',outcome=outcome,
                    cancellation='request_intent_only',automatic_retry=False)
                if self._finish(context):emit(value,deadline)
            output_stop.set();writer.join(max(0,deadline-time.monotonic()))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--stdio',action='store_true',required=True)
    ap.add_argument('--upstream',default='http://127.0.0.1:8790/mcp');ap.add_argument('--token-file',required=True)
    ap.add_argument('--contract',required=True);ap.add_argument('--contract-sha256',required=True)
    ap.add_argument('--acknowledge-full-operator',action='store_true',required=True)
    args=ap.parse_args()
    contract=ToolContract.load(args.contract,args.contract_sha256)
    NativeProxy(args.upstream,private_token(args.token_file),contract).serve(sys.stdin.buffer,sys.stdout.buffer)


if __name__=='__main__':main()
