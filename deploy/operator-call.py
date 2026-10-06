#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Call the existing local operator MCP without Desktop Commander or cloud access.
Read one JSON {name, arguments} from stdin, return the native tool result as JSON.
The token is read only from the existing private local installation; never passed
on a command line. Long-lived jobs/terminals belong to the runtime, not this CLI.
"""
import json
import os
import pathlib
import stat
import sys
import urllib.request

URL='http://127.0.0.1:8790/mcp'
MAX_BYTES=2*1024*1024


def main():
    if len(sys.argv)!=1:raise ValueError('usage: operator-call.py < tool-request.json')
    payload=sys.stdin.buffer.read(MAX_BYTES+1)
    if len(payload)>MAX_BYTES:raise ValueError('request exceeds 2 MiB')
    request=json.loads(payload)
    if not isinstance(request,dict) or set(request)!={'name','arguments'} or not isinstance(request['name'],str) or not isinstance(request['arguments'],dict):
        raise ValueError('request must contain a tool name and arguments object')
    path=pathlib.Path.home()/'.config/hepta-runtime-operator/token'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'r') as f:
        meta=os.fstat(f.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode & 0o077:
            raise PermissionError('runtime token must be a private file owned by this login')
        token=f.read(8193).strip()
    if not token or len(token)>8192:raise ValueError('invalid local runtime token')
    session=None;serial=0
    def rpc(method,params,notify=False):
        nonlocal session,serial
        serial+=1
        body={'jsonrpc':'2.0','method':method,'params':params}
        if not notify:body['id']=serial
        headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream',
                 'MCP-Protocol-Version':'2025-06-18','X-Hepta-Runtime-Token':token}
        if session:headers['Mcp-Session-Id']=session
        with urllib.request.urlopen(urllib.request.Request(URL,data=json.dumps(body).encode(),headers=headers),timeout=100) as response:
            session=response.headers.get('Mcp-Session-Id',session);raw=response.read(3*MAX_BYTES+1)
        if len(raw)>3*MAX_BYTES:raise ValueError('MCP response exceeds local client bound')
        if notify:return None
        text=raw.decode('utf-8')
        objects=[json.loads(line[5:].strip()) for line in text.splitlines() if line.startswith('data:') and line[5:].strip()]
        result=next((o for o in reversed(objects) if o.get('id')==serial),None) if objects else json.loads(text)
        if not isinstance(result,dict) or result.get('id')!=serial:raise ValueError('MCP response identity mismatch')
        if 'error' in result:raise RuntimeError(json.dumps(result['error']))
        return result['result']
    rpc('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'hepta-native-local-cli','version':'1'}})
    rpc('notifications/initialized',{},notify=True)
    result=rpc('tools/call',request)
    print(json.dumps(result,ensure_ascii=False))
    return 1 if result.get('isError') else 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(type(error).__name__+': '+str(error)[:2000],file=sys.stderr)
        raise SystemExit(2)
