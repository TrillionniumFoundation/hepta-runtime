# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Normal pipes-only replay projections; no independent entropy qualification."""
from pathlib import Path
import base64,copy,hashlib,json,os,re,stat
ID_META='io.hepta.runtime/request-v8'
ACK_META='io.hepta.runtime/retention-v8'
H=lambda raw:hashlib.sha256(raw).hexdigest()
compact=lambda value:json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def checked_json(raw):
 value=json.loads(raw);assert compact(value)==raw,'typed field order/bytes must remain observable'
 return value
def norm_id(ident,frame,provenance):
 assert ident==provenance['request_ids'][frame],'identity not bound to this request and its audit record'
 return format(frame,'064x')
def wire(response,frame,provenance):
 assert response.endswith(b'\n');value=checked_json(response[:-1])
 projected=copy.deepcopy(value)
 body=projected.get('result',projected.get('error'))
 if isinstance(body,dict):
  meta=body.get('_meta') if 'result' in projected else body.get('data')
  if isinstance(meta,dict) and ID_META in meta:
   block=meta[ID_META];assert isinstance(block,dict)
   ident=block['request_id'];block['request_id']=norm_id(ident,frame,provenance)
 return value,compact(projected)+b'\n'
def object_identity(path):
 st=path.stat();assert stat.S_ISDIR(st.st_mode)
 return dict(device=st.st_dev,inode=st.st_ino)
def snapshot(state,requests,responses,bounds,provenance):
 full={};logical={};audits={};retained={};identities={}
 request_ids=provenance['request_ids'];inverse={v:k for k,v in request_ids.items()}
 assert len(inverse)==len(request_ids)
 result_anchor=state/'.request-results-v2-anchor.json'
 anchor_bytes=result_anchor.read_bytes() if result_anchor.exists() else None
 for p in sorted(state.rglob('*')):
  st=p.lstat();name=p.relative_to(state).as_posix()
  kind='directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else None
  assert kind is not None
  row=dict(kind=kind,mode=stat.S_IMODE(st.st_mode),device=st.st_dev,inode=st.st_ino,nlink=st.st_nlink,uid=st.st_uid,gid=st.st_gid)
  norm={k:v for k,v in row.items() if k not in ('device','inode')}
  projected_name=name
  if kind=='symlink':
   row['target']=os.readlink(p);norm['target']=row['target']
  elif kind=='file':
   raw=p.read_bytes();row.update(bytes=len(raw),sha256=H(raw),hex=raw.hex())
   norm.update(bytes=len(raw),sha256=H(raw))
   obj=None
   if name=='.request-archive-v11-anchor.json':
    obj=checked_json(raw);root=object_identity(state);archive=object_identity(state/'request-archive-v11')
    assert obj==dict(root_device=root['device'],root_inode=root['inode'],archive_device=archive['device'],archive_inode=archive['inode'])
    obj={k:'independently-verified-inode' for k in obj}
   elif name=='.request-results-v2-anchor.json':
    obj=checked_json(raw)
    assert list(obj)==['schema','root','legacy','store','archive','shards'] and obj['schema']==2 and len(obj['shards'])==256
    destinations=dict(root=state,legacy=state/'request-results',store=state/'request-results-v2',archive=state/'request-results-v2/archive')
    for key,target in destinations.items():assert obj[key]==object_identity(target)
    for index,pair in enumerate(obj['shards']):
     assert pair==object_identity(state/'request-results-v2/archive'/format(index,'02x'))
    obj={k:('independently-verified-'+k if k in destinations else v) for k,v in obj.items()}
    obj['shards']=['independently-verified-'+format(i,'02x') for i in range(256)]
   elif name=='request-results/.request-results-v2.json':
    obj=checked_json(raw);assert anchor_bytes is not None
    assert obj==dict(schema=2,anchor_sha256=H(anchor_bytes))
    obj['anchor_sha256']='independently-verified-complete-anchor-sha256'
   elif name.startswith(('request-audit/','request-archive-v11/')) and name.endswith('.json'):
    obj=checked_json(raw);assert list(obj)==['request_id','owner','tool_name','state','accepted_unix_ms','elapsed_ms']
    ident=obj['request_id'];assert p.name==ident+'.json' and ident in inverse
    frame=inverse[ident];assert frame in requests and requests[frame]['method']=='tools/call'
    assert obj['tool_name']==requests[frame]['params']['name']
    assert obj['owner']==provenance['owner'],'owner differs within the same process'
    bound=bounds[frame];assert bound['wall_before']//1000000<=obj['accepted_unix_ms']<=bound['wall_after']//1000000
    elapsed=obj['elapsed_ms'];assert elapsed is None or type(elapsed)is int and 0<=elapsed<=(bound['mono_after']-bound['mono_before'])//1000000+1
    assert obj['state'] in ('unknown','completed','failed','cancelled','abandoned')
    identity=tuple(obj[k] for k in ('request_id','owner','tool_name','accepted_unix_ms'))
    assert identities.setdefault(frame,identity)==identity,'audit/result RequestIdentity fields differ'
    audits.setdefault(frame,{})[name.split('/')[0]]=raw
    obj.update(request_id=norm_id(ident,frame,provenance),owner='within-process-consistent-owner',accepted_unix_ms='independently-bracketed',elapsed_ms=None if elapsed is None else 'independently-bracketed')
    projected_name=name.split('/')[0]+'/request-'+str(frame)+'.json'
   elif name.startswith('request-results-v2/archive/') and name.endswith('.json'):
    obj=checked_json(raw);assert list(obj)==['request_id','owner','tool_name','accepted_unix_ms','policy_binding','state','payload_base64','payload_bytes','payload_sha256']
    ident=obj['request_id'];assert ident in inverse and p.name==ident+'.json' and p.parent.name==ident[:2]
    frame=inverse[ident];assert obj['owner']==provenance['owner'] and obj['tool_name']==requests[frame]['params']['name']
    assert obj['tool_name'] in ('host_list','effective_config','host_health')
    bound=bounds[frame];assert bound['wall_before']//1000000<=obj['accepted_unix_ms']<=bound['wall_after']//1000000
    if obj['state']=='stored':
     payload=base64.b64decode(obj['payload_base64'],validate=True)
     assert base64.b64encode(payload).decode()==obj['payload_base64']
     assert obj['payload_bytes']==len(payload) and obj['payload_sha256']==H(payload)
     parsed=checked_json(payload)
     response=copy.deepcopy(responses[frame]['result'])
     response.setdefault('resultType','complete')
     response['_meta'].pop(ACK_META)
     expected={'resultType':response.pop('resultType'),**response}
     assert compact(expected)==payload,'retained bytes differ from pre-ack typed result'
     parsed['_meta'][ID_META]['request_id']=norm_id(ident,frame,provenance)
     normalized_payload=compact(parsed)
     obj.update(payload_base64=base64.b64encode(normalized_payload).decode(),payload_bytes=len(normalized_payload),payload_sha256=H(normalized_payload))
    else:
     assert obj['state'] in ('unknown','overflow','refused_dto','not_completed')
     assert obj['payload_base64'] is obj['payload_bytes'] is obj['payload_sha256'] is None
    identity=tuple(obj[k] for k in ('request_id','owner','tool_name','accepted_unix_ms'))
    assert identities.setdefault(frame,identity)==identity,'audit/result RequestIdentity fields differ'
    retained[frame]=raw
    obj.update(request_id=norm_id(ident,frame,provenance),owner='within-process-consistent-owner',accepted_unix_ms='independently-bracketed')
    projected_name='request-results-v2/archive/request-'+str(frame)+'.json'
   else:
    assert not name.endswith('.tmp'),'staging survived a completed public call'
   if obj is not None:
    norm.pop('bytes');norm.pop('sha256');norm['content']=obj
  full[name]=row
  assert projected_name not in logical
  logical[projected_name]=norm
 for frame,parts in audits.items():
  if set(parts)=={'request-audit','request-archive-v11'}:assert len(set(parts.values()))==1
 return full,logical,dict(audit_records=len(audits),retained_records=len(retained))


def observe_identities(state, frame, request, response, provenance):
    found={}
    for directory in ('request-audit','request-archive-v11'):
        root=state/directory
        if root.exists():
            for path in root.glob('*.json'):
                value=checked_json(path.read_bytes())
                ident=value['request_id'];owner=value['owner']
                assert re.fullmatch('[0-9a-f]{64}',ident) and re.fullmatch('[0-9a-f]{64}',owner)
                assert path.name==ident+'.json'
                identity=tuple(value[k]for k in ('request_id','owner','tool_name','accepted_unix_ms'))
                assert found.setdefault(ident,identity)==identity
    old=set(provenance['request_ids'].values())
    fresh=set(found)-old
    assert len(fresh)<=1
    if fresh:
        assert request.get('method')=='tools/call'
        ident=fresh.pop();identity=found[ident]
        assert identity[2]==request['params']['name']
        provenance['request_ids'][frame]=ident
        if provenance['owner'] is None:provenance['owner']=identity[1]
    assert all(row[1]==provenance['owner']for row in found.values())
    body=response.get('result',response.get('error'))
    if isinstance(body,dict):
        meta=body.get('_meta')if'result'in response else body.get('data')
        if isinstance(meta,dict)and ID_META in meta:
            assert meta[ID_META]['request_id']==provenance['request_ids'][frame]
