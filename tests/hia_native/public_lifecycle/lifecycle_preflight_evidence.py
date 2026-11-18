# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pure reconstruction of complete ordinary public preflight captures."""
from pathlib import Path,PurePosixPath
from types import SimpleNamespace
import copy,gzip,json,stat
import lifecycle_preflight as run
import lifecycle_fixtures as fixtures
q=run.q;projection=run.projection;inputs=run.inputs
class CapturePath:
    def __init__(self,rows,root,name=''):
        self.rows,self.root,self.key=rows,root,name
    def __truediv__(self,name):
        assert isinstance(name,str)and not name.startswith('/')and'..'not in name.split('/')
        return CapturePath(self.rows,self.root,'/'.join(x for x in (self.key,name)if x))
    def __lt__(self,other):return self.key<other.key
    @property
    def name(self):return self.key.rsplit('/',1)[-1]
    @property
    def parent(self):return CapturePath(self.rows,self.root,self.key.rpartition('/')[0])
    def relative_to(self,other):
        assert other.key==''
        return PurePosixPath(self.key)
    def exists(self):return self.key==''or self.key in self.rows
    def rglob(self,pattern):
        assert self.key==''and pattern=='*'
        return [CapturePath(self.rows,self.root,n)for n in sorted(self.rows)]
    def glob(self,pattern):
        assert pattern=='*.json'
        prefix=self.key+'/'
        return [CapturePath(self.rows,self.root,n)for n in sorted(self.rows)
            if n.startswith(prefix)and'/'not in n[len(prefix):]and n.endswith('.json')]
    def stat(self):
        row=self.root if self.key==''else self.rows[self.key]
        kind='directory'if self.key==''else row['kind']
        assert kind in ('file','directory')
        mode=(stat.S_IFREG if kind=='file'else stat.S_IFDIR)|row['mode']
        return SimpleNamespace(st_mode=mode,**{'st_'+k:row[v]for k,v in
            [('dev','device'),('ino','inode'),('nlink','nlink'),('uid','uid'),('gid','gid')]})
    lstat=stat
    def read_bytes(self):
        row=self.rows[self.key];assert row['kind']=='file'
        raw=bytes.fromhex(row['hex'])
        assert len(raw)==row['bytes']and q.H(raw)==row['sha256']
        return raw

def side(folder,version,process,binary,*,common=None):
    common=folder.parent/'common' if common is None else Path(common)
    assert process['command']==[str(binary),'--runtime-config',str(common/'config.json')]
    assert process['cwd']==str(folder)and process['side']==folder.name
    assert process['status']=='PASS'and process['exit_code']==0 and process['reaped']is True
    assert type(process['pid'])is int and process['pid']>0
    assert process['response_timeout_seconds']==30
    for name in ('input.bin','stdout.bin','stderr','observations.jsonl.gz','eof-filesystem.json'):
        inputs.pin(folder/name,process[name])
    assert(folder/'stderr').read_bytes()==b''
    config=dict(state_dir=str(common/'state'),hosts={'fixture':dict(
        ssh_target='unused-local-fixture',remote_state_dir='/unused-private-state',allow_write=False)})
    assert(common/'config.json').read_bytes()==q.compact(config)
    with gzip.open(folder/'observations.jsonl.gz','rb')as f:rows=[json.loads(line)for line in f]
    planned=[(None,None,'initialize',None)]+run.cases.CASES
    assert len(rows)==len(planned)==109
    assert b''.join(bytes.fromhex(r['input_hex'])for r in rows)==(folder/'input.bin').read_bytes()
    assert b''.join(bytes.fromhex(r['output_hex'])for r in rows)==(folder/'stdout.bin').read_bytes()
    requests,responses,bounds={},{},{};provenance=dict(owner=None,request_ids={})
    ident=payload_bytes=last_id=page_cursor=None;wires=[];projected_requests=[];snapshots=[]
    final=json.loads((folder/'eof-filesystem.json').read_bytes())
    fixtures.admit(folder,'preflight',process)
    actual=final['root_stat']
    for frame,(row,event)in enumerate(zip(rows,planned),1):
        tool,template,label,expected=event
        assert row['frame']==frame and row['label']==label
        request=q.checked_json(bytes.fromhex(row['input_hex'])[:-1])
        response=q.checked_json(bytes.fromhex(row['output_hex'])[:-1])
        assert response['id']==request['id']==frame-1
        if tool is None:
            wanted=dict(jsonrpc='2.0',id=0,method='initialize',params=dict(
                protocolVersion=version,capabilities={},clientInfo=dict(name='unified-public-pairs',version='1')))
        elif tool=='__catalog__':wanted=dict(jsonrpc='2.0',id=frame-1,method='tools/list',params={})
        else:
            args=run.cases.materialize(template,ident,payload_bytes,last_id,page_cursor)
            wanted=dict(jsonrpc='2.0',id=frame-1,method='tools/call',params=dict(name=tool,arguments=args))
        assert bytes.fromhex(row['input_hex'])==q.compact(wanted)+b'\n'
        requests[frame],responses[frame],bounds[frame]=request,response,row['bounds']
        b=row['bounds'];assert b['mono_before']<=b['mono_after']and b['wall_before']<=b['wall_after']
        for key in ('mode','device','inode','uid','gid'):assert row['root_stat'][key]==actual[key]
        state=CapturePath(row['filesystem'],row['root_stat'])
        q.observe_identities(state,frame,request,response,provenance)
        recorded=copy.deepcopy(row['identity_relation'])
        recorded['request_ids']={int(k):v for k,v in recorded['request_ids'].items()}
        assert provenance==recorded
        if provenance['request_ids']:last_id=provenance['request_ids'][max(provenance['request_ids'])]
        if tool=='request_history':assert frame not in provenance['request_ids']
        full,logical,counts=q.snapshot(state,requests,responses,bounds,provenance)
        assert full==row['filesystem']and logical==row['logical']
        _,wire=projection.wire(bytes.fromhex(row['output_hex']),frame,request,state,provenance)
        normalized=projection.request_projection(request,provenance)
        assert wire.hex()==row['normalized_output_hex']and normalized==row['normalized_input']
        if tool is not None:run.check_expected(response,expected)
        if tool=='request_history'and'result'in response and response['result']['isError']is False:
            page_cursor=q.checked_json(response['result']['content'][0]['text'].encode())['next_after_id']
        if label=='retain-host-list':
            ident=response['result']['_meta'][q.ID_META]['request_id']
            _,audit=projection.selected_record(state,ident,provenance)
            _,payload=projection.retained_payload(state,ident,audit);payload_bytes=len(payload)
        wires.append(wire);projected_requests.append(normalized);snapshots.append(logical)
    full,eof,counts=q.snapshot(CapturePath(final['full'],final['root_stat']),requests,responses,bounds,provenance)
    assert full==final['full']and eof==final['logical']and counts==final['counts']==process['counts']
    assert process['requests_entered']==process['responses_completed']==process['responses_received']==109
    answer=dict(wire_hex=b''.join(wires).hex(),requests=projected_requests,snapshots=snapshots,eof=eof,counts=counts)
    assert answer==json.loads((folder/'projection.json').read_bytes())
    return answer
