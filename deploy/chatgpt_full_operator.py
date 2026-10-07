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
METHODS={'initialize','notifications/initialized','notifications/cancelled','ping','tools/list','tools/call'}


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
    if method=='tools/list' and params:return error(ident,-32602,'The complete pinned catalog fits in one page')
    return None


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


class NativeProxy:
    def __init__(self,upstream,token,contract,timeout=150):
        parsed=urllib.parse.urlsplit(upstream)
        if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.path!='/mcp' or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('full operator upstream must be explicit IPv4 loopback HTTP /mcp')
        self.upstream=parsed;self.token=token;self.contract=contract;self.timeout=timeout
        self.session=None;self.protocol=None;self.initialized=False;self.internal_counter=0
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
    def dispatch(self,request):
        invalid=valid_request(request,self.contract)
        if invalid is not None:return invalid
        method=request['method'];ident=request.get('id')
        if method=='notifications/initialized':return None
        if method!='initialize' and not self.initialized:
            return None if method.startswith('notifications/') else error(ident,-32071,'Initialize and verify the pinned native contract first')
        if method=='initialize' and self.initialized:return error(ident,-32600,'A full-operator session is initialized once')
        mutating=method=='tools/call' and not self.contract.read_only(request['params']['name'])
        try:
            response=self.exchange(request)
            if method=='initialize':
                if 'error' in response:return response
                native=response['result'];self.protocol=native['protocolVersion']
                self.exchange({'jsonrpc':'2.0','method':'notifications/initialized','params':{}})
                tools=self.internal('tools/list',{})
                if 'error' in tools or tools['result'].get('nextCursor'):raise ValueError('cannot attest full native catalog')
                self.contract.verify(tools['result']['tools'])
                self.initialized=True
                result=dict(native);result['serverInfo']={'name':'hepta-runtime-full-operator','version':self.contract.catalog_sha256[:16]}
                result['capabilities']={'tools':{'listChanged':False}}
                return {**response,'result':result}
            if method=='tools/list':
                if 'error' in response:return response
                if response['result'].get('nextCursor'):raise ValueError('native catalog changed pagination')
                self.contract.verify(response['result']['tools'])
                # Definitions and annotations are returned exactly, not relabelled read-only.
                return {**response,'result':{'tools':self.contract.tools}}
            return response
        except Exception:
            if method in ('initialize','tools/list'):self.initialized=False
            if method.startswith('notifications/'):return None
            return error(ident,-32070,'Native operation result unavailable; do not replay a write blindly',
                         outcome='unknown' if mutating else 'unavailable',automatic_retry=False,
                         contract_sha256=self.contract.catalog_sha256)
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
