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
from mcp_tool_contract import ToolContract,canonical

MAX_REQUEST=4*1024*1024
MAX_RESPONSE=16*1024*1024
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
    if not isinstance(request,dict) or request.get('jsonrpc')!='2.0' or set(request)-{'jsonrpc','method','id','params'}:
        return error(None,-32600,'Single JSON-RPC 2.0 request required')
    ident=request.get('id')
    if 'id' in request and (type(ident) not in (str,int) or isinstance(ident,str) and len(ident)>256):return error(None,-32600,'Invalid request identity')
    method=request.get('method')
    if not isinstance(method,str) or method not in METHODS:return error(ident,-32601,'Method outside the explicit tool transport contract')
    params=request.get('params',{})
    if not isinstance(params,dict):return error(ident,-32602,'Object parameters required')
    if method.startswith('notifications/'):
        if 'id' in request:return error(ident,-32600,'Notifications cannot carry request IDs')
        return None
    if 'id' not in request:return error(None,-32600,'Operation must have a response identity')
    if method=='tools/call':
        if set(params)-{'name','arguments','_meta'} or not contract.allows(params.get('name')):return error(ident,-32601,'Tool not present in the pinned full-operator contract')
        if not isinstance(params.get('arguments',{}),dict):return error(ident,-32602,'Tool arguments must be an object')
    if method=='tools/list' and set(params)-{'_meta'}:return error(ident,-32602,'The complete pinned catalog fits in one page')
    if method=='server/discover' and set(params)-{'_meta'}:return error(ident,-32602,'Only discovery protocol metadata is accepted')
    return None


def request_era(request):
    params=request.get('params') or {}
    meta=params.get('_meta')
    if not isinstance(meta,dict) or VERSION_KEY not in meta:return 'legacy',None
    version=meta.get(VERSION_KEY)
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


class NativeProxy:
    def __init__(self,upstream,token,contract,timeout=150):
        parsed=urllib.parse.urlsplit(upstream)
        if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.path!='/mcp' or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('full operator upstream must be explicit IPv4 loopback HTTP /mcp')
        self.upstream=parsed;self.token=token;self.contract=contract;self.timeout=timeout
        self.session=None;self.protocol=None;self.initialized=False;self.legacy_ready=False;self.internal_counter=0
    def exchange(self,request):
        body=canonical(request)
        headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','X-Hepta-Runtime-Token':self.token}
        if self.session:headers['Mcp-Session-Id']=self.session
        if self.protocol:headers['MCP-Protocol-Version']=self.protocol
        conn=http.client.HTTPConnection(self.upstream.hostname,self.upstream.port or 80,timeout=self.timeout)
        try:
            conn.request('POST','/mcp',body=body,headers=headers)
            response=conn.getresponse();raw=response.read(MAX_RESPONSE+1)
            if len(raw)>MAX_RESPONSE:raise ValueError('upstream response exceeds explicit limit')
            if (response.status==404 and self.session is not None
                    and raw.strip()==b'Not Found: Session not found'):
                # This response is authoritative for this internal session only.
                # It is not proof that an arbitrary tool write was not executed.
                raise NativeSessionExpired('loopback native MCP session is no longer valid')
            if not 200<=response.status<300:raise RuntimeError('upstream HTTP failure')
            session=response.getheader('Mcp-Session-Id')
            if session:self.session=session
            if 'id' not in request:return None
            if not raw:raise RuntimeError('missing response for a request')
            messages=parse_messages((response.getheader('Content-Type') or '').lower(),raw)
            matched=[r for r in messages if isinstance(r,dict) and r.get('jsonrpc')=='2.0' and r.get('id')==request['id']]
            if len(matched)!=1 or ('result' in matched[0])==('error' in matched[0]):raise ValueError('ambiguous upstream response identity')
            return matched[0]
        finally:conn.close()
    def internal(self,method,params):
        self.internal_counter+=1
        return self.exchange({'jsonrpc':'2.0','id':'hepta-contract-'+str(self.internal_counter),'method':method,'params':params})
    def _verify_catalog(self):
        try:
            tools=self.internal('tools/list',{})
        except NativeSessionExpired:
            # Only the read-only preflight was submitted. On modern requests
            # the private backend session is owned by this adapter, not by the
            # model client. A fresh initialization checks the entire pinned
            # catalog before any user write is sent. Legacy callers must
            # reinitialize explicitly instead of having their session replaced.
            if not self.initialized or self.legacy_ready:
                raise
            self._new_native_session({'protocolVersion':'2025-11-25',
                'capabilities':{},'clientInfo':{
                    'name':'hepta-full-operator-adapter','version':'1'}})
            return
        if 'error' in tools or not isinstance(tools.get('result'),dict) or tools['result'].get('nextCursor'):
            raise ValueError('cannot attest full native catalog')
        self.contract.verify(tools['result']['tools'])

    def _new_native_session(self,init_params):
        # The tunnel process may serve multiple independent ChatGPT discovery
        # sessions. Reset the loopback MCP HTTP session before every legacy
        # initialize, but never touch the native persistent job/broker state.
        self.initialized=False
        self.legacy_ready=False
        self.session=None
        self.protocol=None
        self.internal_counter+=1
        result=self.exchange({'jsonrpc':'2.0','id':'hepta-native-initialize-'+str(self.internal_counter),
                              'method':'initialize','params':init_params})
        if 'error' in result:raise ValueError('native initialize rejected')
        native=result['result']
        if not isinstance(native,dict) or not isinstance(native.get('protocolVersion'),str):
            raise ValueError('malformed native initialization')
        self.protocol=native['protocolVersion']
        self.exchange({'jsonrpc':'2.0','method':'notifications/initialized','params':{}})
        self._verify_catalog()
        self.initialized=True
        return native

    def _ensure_native(self):
        if not self.initialized:
            self._new_native_session({'protocolVersion':'2025-11-25', 'capabilities':{},
                                      'clientInfo':{'name':'hepta-full-operator-adapter','version':'1'}})

    def _modern_result(self,ident,result):
        result=dict(result)
        result['resultType']='complete'
        metadata=result.get('_meta')
        metadata=dict(metadata) if isinstance(metadata,dict) else {}
        metadata[SERVER_INFO_KEY]={'name':'hepta-runtime-full-operator','version':self.contract.catalog_sha256[:16]}
        result['_meta']=metadata
        return {'jsonrpc':'2.0','id':ident,'result':result}

    def _dispatch(self,request):
        invalid=valid_request(request,self.contract)
        if invalid is not None:return invalid
        method=request['method'];ident=request.get('id')
        era,version=request_era(request)
        if era=='unsupported':
            return error(ident,-32022,'Unsupported protocol version',supported=[MODERN_VERSION],requested=version)
        if era=='invalid':return error(ident,-32602,'Modern MCP request requires object clientCapabilities')
        if method=='server/discover' and era!='modern':
            return error(ident,-32601,'Modern MCP discovery requires protocol metadata')
        if method=='initialize' and era=='modern':
            return error(ident,-32601,'Modern MCP uses server/discover, not initialize')
        if method.startswith('notifications/'):
            return None
        if era=='legacy' and method!='initialize' and not self.legacy_ready:
            return error(ident,-32071,'Legacy MCP initialization required before tool calls')
        mutating=method=='tools/call' and not self.contract.read_only(request['params']['name'])
        try:
            if method=='initialize':
                native=self._new_native_session(request.get('params',{}))
                result=dict(native)
                result['serverInfo']={'name':'hepta-runtime-full-operator','version':self.contract.catalog_sha256[:16]}
                result['capabilities']={'tools':{'listChanged':False}}
                self.legacy_ready=True
                return {'jsonrpc':'2.0','id':ident,'result':result}
            if era=='modern':
                self._ensure_native()
                if method=='server/discover':
                    # No public cache: this catalog belongs to the private,
                    # authenticated operator identity behind the tunnel.
                    return self._modern_result(ident,{'supportedVersions':[MODERN_VERSION],
                        'capabilities':{'tools':{'listChanged':False}},'cacheScope':'private','ttlMs':0})
                if method=='tools/list':
                    self._verify_catalog()
                    return self._modern_result(ident,{'tools':self.contract.tools,'cacheScope':'private','ttlMs':0})
                if method=='ping':
                    return self._modern_result(ident,{})
                if method=='tools/call':
                    self._verify_catalog()
                    args=request.get('params',{}).get('arguments',{})
                    native_req={'jsonrpc':'2.0','id':ident,'method':'tools/call',
                                'params':{'name':request['params']['name'],'arguments':args}}
                    response=self.exchange(native_req)
                    if 'error' in response:return response
                    result=response.get('result')
                    if not isinstance(result,dict) or not isinstance(result.get('content'),list):
                        raise ValueError('native tool response must contain content array')
                    return self._modern_result(ident,result)
                raise ValueError('unhandled modern MCP operation')
            # Legacy clients use one initialize/initialized logical session.
            if method=='tools/list':
                self._verify_catalog()
                return {'jsonrpc':'2.0','id':ident,'result':{'tools':self.contract.tools}}
            if method=='tools/call':
                self._verify_catalog()
            return self.exchange(request)
        except Exception:
            if method in ('initialize','tools/list','server/discover'):
                self.initialized=False
                self.legacy_ready=False
            # Use standard JSON-RPC internal error in the modern protocol: the
            # -32020..-32099 range is reserved by the 2026-07-28 specification.
            return error(ident,-32603 if era=='modern' else -32070,
                         'Native operation result unavailable; do not replay a write blindly',
                         outcome='unknown' if mutating else 'unavailable',automatic_retry=False,
                         contract_sha256=self.contract.catalog_sha256)

    def dispatch(self,request):
        reply=self._dispatch(request)
        # Opt-in discovery diagnostics only. Never log caller IDs, transport
        # metadata, tool names, tool arguments, tokens or response payloads.
        if os.environ.get('HEPTA_MCP_PROTOCOL_TRACE')=='1' and isinstance(request,dict):
            method=request.get('method')
            if method in ('server/discover','initialize','tools/list','ping','notifications/initialized'):
                era,_=request_era(request)
                status='error' if isinstance(reply,dict) and 'error' in reply else ('no_reply' if reply is None else 'ok')
                code=reply['error'].get('code') if status=='error' else None
                record={'event':'hepta_mcp_protocol','method':method,'era':era,'status':status,'error_code':code}
                sys.stderr.write(json.dumps(record,separators=(',',':'))+'\n')
                sys.stderr.flush()
        return reply

    def serve(self,input_stream,output_stream):
        while True:
            raw=input_stream.readline(MAX_REQUEST+2)
            if not raw:return
            if len(raw)>MAX_REQUEST+1 or not raw.endswith(b'\n'):
                while raw and not raw.endswith(b'\n'):raw=input_stream.readline(MAX_REQUEST+2)
                value=error(None,-32600,'Bounded newline-delimited JSON-RPC request required')
            else:
                try:request=json.loads(raw)
                except (ValueError,UnicodeError):value=error(None,-32700,'Invalid JSON')
                else:value=self.dispatch(request)
            if value is not None:
                payload=canonical(value)
                if len(payload)>MAX_RESPONSE:
                    payload=canonical(error(value.get('id'),-32070,'Response exceeds facade limit',outcome='unknown',automatic_retry=False))
                output_stream.write(payload+b'\n');output_stream.flush()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--stdio',action='store_true',required=True)
    ap.add_argument('--upstream',default='http://127.0.0.1:8790/mcp');ap.add_argument('--token-file',required=True)
    ap.add_argument('--contract',required=True);ap.add_argument('--contract-sha256',required=True)
    ap.add_argument('--acknowledge-full-operator',action='store_true',required=True)
    args=ap.parse_args()
    contract=ToolContract.load(args.contract,args.contract_sha256)
    NativeProxy(args.upstream,private_token(args.token_file),contract).serve(sys.stdin.buffer,sys.stdout.buffer)


if __name__=='__main__':main()
