# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete public Start/Cancel evidence projection at declared stable boundaries.

Natural scheduling observations are retained separately. No entropy correctness,
arbitrary concurrency, or production-owner closure is inferred from this suite.
"""
from pathlib import Path
import base64,copy,hashlib,json,os,re,stat

ID_META='io.hepta.runtime/request-v8'
ACK_META='io.hepta.runtime/retention-v8'
H=lambda raw:hashlib.sha256(raw).hexdigest()
C=lambda value:json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
SORTED=lambda value:json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
BINDING_FIELDS=('request_id','owner','tool_name','accepted_unix_ms','key_hash','request_hash','policy_binding')
AUDIT_FIELDS=('request_id','owner','tool_name','state','accepted_unix_ms','elapsed_ms')
RESULT_FIELDS=('request_id','owner','tool_name','accepted_unix_ms','policy_binding','state','payload_base64','payload_bytes','payload_sha256')
OUTCOME_FIELDS=('request_id','owner','key_hash','policy_binding','state')
SCOPE=dict(authenticated_chatgpt_caller_isolation=False,credential_metadata_resume=False,
           cross_session_resume=False,ownership_scope='native_mcp_session_only',
           session_scope='native_mcp_session_only')
HEX=re.compile('[0-9a-f]{64}')

def checked_json(raw):
    value=json.loads(raw)
    assert C(value)==raw,'complete serialized bytes/field order changed'
    return value

def valid_id(value):
    return isinstance(value,str) and HEX.fullmatch(value) is not None

def key_hash(owner,key):
    return H(b'hepta-runtime/async-key/v9\0'+owner.encode()+b'\0'+key.encode())

def request_hash(operation):
    assert set(operation)=={'tool','arguments'}
    ordered=dict(tool=operation['tool'],arguments=operation['arguments'])
    return H(b'hepta-runtime/async-typed-request/v9\0'+C(ordered))

def capture_tree(root,strict):
    root=Path(root);out={}
    for p in [root,*sorted(root.rglob('*'))]:
        name=p.relative_to(root).as_posix() if p!=root else ''
        try:
            s=p.lstat()
            kind='directory' if stat.S_ISDIR(s.st_mode) else 'file' if stat.S_ISREG(s.st_mode) else 'symlink' if stat.S_ISLNK(s.st_mode) else None
            assert kind is not None,('unexpected special file',str(p))
            row=dict(kind=kind,mode=stat.S_IMODE(s.st_mode),device=s.st_dev,inode=s.st_ino,
                     uid=s.st_uid,gid=s.st_gid,nlink=s.st_nlink)
            if kind=='file':
                with p.open('rb')as f:
                    before=os.fstat(f.fileno());raw=f.read();after=os.fstat(f.fileno())
                fields=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
                stable=fields(before)==fields(after) and (s.st_dev,s.st_ino)==(before.st_dev,before.st_ino)
                row.update(bytes=len(raw),sha256=H(raw),hex=raw.hex(),stable=stable)
                assert not strict or stable,('file changed during stable snapshot',name)
            elif kind=='symlink':row['target']=os.readlink(p)
        except FileNotFoundError:
            assert not strict,('object retired during stable snapshot',name)
            row=dict(concurrent_retirement=True)
        out[name]=row
    return out

def raw_row(full,name):
    row=full[name];assert row['kind']=='file' and row.get('stable',True)
    raw=bytes.fromhex(row['hex'])
    assert len(raw)==row['bytes'] and H(raw)==row['sha256']
    return raw

def object_identity(full,name,kind):
    row=full[name];assert row['kind']==kind
    return dict(device=row['device'],inode=row['inode'])

def response_value(frame):
    raw=bytes.fromhex(frame['raw_output_hex'])
    assert raw.endswith(b'\n')
    value=checked_json(raw[:-1])
    assert value==frame['response'] and value['id']==frame['request']['id']
    return value

def request_value(frame):
    raw=bytes.fromhex(frame['raw_input_hex'])
    assert raw.endswith(b'\n')
    value=checked_json(raw[:-1])
    assert value==frame['request']
    return value

def payload_for_response(response):
    value=copy.deepcopy(response['result'])
    value.setdefault('resultType','complete')
    value['_meta'].pop(ACK_META)
    return C({'resultType':value.pop('resultType'),**value})

def project_case(case,frames,boundaries,final):
    """Reconstruct identities and all projections from captured raw data."""
    records={};frames_by_id={};bindings={};owner=None;policy=None
    baseline=None;projected_frames=[];observations=[]
    final_full=final['filesystem']
    assert not any(x.get('concurrent_retirement') or not x.get('stable',True) for x in final_full.values())

    def add_identity(identifier,record):
        assert valid_id(identifier) and identifier not in records
        records[identifier]=record

    for frame in frames:
        request=request_value(frame);response=response_value(frame)
        index=frame['index'];assert index not in frames_by_id
        frames_by_id[index]=frame
        assert request.get('id')==index
        if request['method']!='tools/call':continue
        result=response.get('result',response.get('error'))
        meta=result.get('_meta',{}) if 'result'in response else result.get('data',{})
        assert isinstance(meta,dict) and ID_META in meta
        identity=meta[ID_META];assert identity==dict(request_id=identity['request_id'],automatic_retry=False,delivery_proven=False)
        identifier=identity['request_id']
        add_identity(identifier,dict(index=index,kind='outer',normal=format(index+1,'064x'),
            tool=request['params']['name'],bound=frame,finish_mono=frame['mono_after'],
            expected_state=('completed'if 'result'in response and response['result']['isError']is False else
                            'unknown'if request['params']['name']in ('request_start','request_cancel')else'failed')))
        audit=checked_json(raw_row(final_full,'request-audit/'+identifier+'.json'))
        assert tuple(audit)==AUDIT_FIELDS and audit['request_id']==identifier
        assert audit['tool_name']==request['params']['name'] and valid_id(audit['owner'])
        if owner is None:owner=audit['owner']
        assert audit['owner']==owner
        records[identifier]['identity']=tuple(audit[k]for k in ('request_id','owner','tool_name','accepted_unix_ms'))
        if frame['label']=='baseline':
            assert response['result']['isError']is False
            baseline=(identifier,payload_for_response(response))
        if frame['label']=='start' and case['success']:
            assert response['result']['isError']is False
            value=checked_json(response['result']['content'][0]['text'].encode())
            identifier=value['request_id'];operation=case['operation']
            hashed=key_hash(owner,case['key'])
            names=['request-async-v9/'+hashed+'.json',
                   'request-async-v9/.occupied/'+hashed+'.json',
                   'request-async-v9/.intents/'+identifier+'.json']
            raws=[raw_row(final_full,n)for n in names]
            assert len(set(raws))==1,'complete immutable Binding triangle'
            binding=checked_json(raws[0]);assert tuple(binding)==BINDING_FIELDS
            assert binding['request_id']==identifier and binding['owner']==owner
            assert binding['tool_name']==operation['tool']
            assert binding['key_hash']==hashed and binding['request_hash']==request_hash(operation)
            assert valid_id(binding['policy_binding'])
            if policy is None:policy=binding['policy_binding']
            assert policy==binding['policy_binding']
            done=boundaries['producer-completed']
            add_identity(identifier,dict(index=1,kind='inner',normal=format(1<<32,'064x'),
                tool=operation['tool'],bound=frame,finish_mono=done['mono_after'],expected_state='completed',
                identity=tuple(binding[k]for k in ('request_id','owner','tool_name','accepted_unix_ms')),
                binding=binding))
            bindings[identifier]=binding
            assert value['reused']is False
    assert owner is not None and baseline is not None
    assert len(bindings)==int(case['success'])
    inverse_keys={v['key_hash']:identifier for identifier,v in bindings.items()}

    def normalized_id(identifier):
        assert identifier in records
        return records[identifier]['normal']

    def normalize_payload(raw,identifier,expected=None):
        parsed=checked_json(raw)
        assert parsed['resultType']=='complete' and parsed.get('isError',False)is False
        assert ACK_META not in parsed['_meta']
        assert parsed['_meta'][ID_META]==dict(request_id=identifier,automatic_retry=False,delivery_proven=False)
        if expected is not None:assert raw==expected,'retained Complete differs from observed full baseline'
        parsed['_meta'][ID_META]['request_id']=normalized_id(identifier)
        return C(parsed)

    payloads={};retained_objects={}
    for name,row in final_full.items():
        if not(name.startswith('request-results-v2/archive/')and name.endswith('.json')):continue
        value=checked_json(raw_row(final_full,name));identifier=value['request_id']
        assert identifier in records and tuple(value)==RESULT_FIELDS
        assert Path(name).name==identifier+'.json' and Path(name).parent.name==identifier[:2]
        assert tuple(value[k]for k in ('request_id','owner','tool_name','accepted_unix_ms'))==records[identifier]['identity']
        if policy is None:policy=value['policy_binding']
        assert value['policy_binding']==policy and valid_id(policy)
        if value['state']=='stored':
            raw=base64.b64decode(value['payload_base64'],validate=True)
            assert base64.b64encode(raw).decode()==value['payload_base64']
            assert value['payload_bytes']==len(raw) and value['payload_sha256']==H(raw)
            if records[identifier]['kind']=='inner':
                expected=checked_json(baseline[1])
                expected['_meta'][ID_META]['request_id']=identifier
                expected=C(expected)
            else:
                f=frames_by_id[records[identifier]['index']]
                expected=payload_for_response(response_value(f))
            normalized=normalize_payload(raw,identifier,expected)
            payloads[identifier]=(raw,normalized)
        else:
            assert value['state']=='overflow'
            assert value['payload_base64']is value['payload_bytes']is value['payload_sha256']is None
            assert len(baseline[1])>65536
        retained_objects[identifier]=value
    expected_retained={identifier for identifier,r in records.items()if r['tool']in ('host_list','effective_config','host_health')}
    assert set(retained_objects)==expected_retained

    def identity(value,identifier):
        record=records[identifier];bound=record['bound']
        assert tuple(value[k]for k in ('request_id','owner','tool_name','accepted_unix_ms'))==record['identity']
        accepted=value['accepted_unix_ms']
        assert type(accepted)is int and bound['wall_before']//1000000<=accepted<=bound['wall_after']//1000000
        assert value['owner']==owner

    def filesystem(full,mono_after,complete=True):
        logical={};audits={};seen_bindings={};seen_outcomes=set();seen_retained=set()
        anchor=raw_row(full,'.request-results-v2-anchor.json') if '.request-results-v2-anchor.json'in full else None
        for name,row in full.items():
            assert not row.get('concurrent_retirement') and row.get('stable',True)
            norm={k:v for k,v in row.items()if k not in ('device','inode','hex','stable')}
            outname=name;obj=None
            if row['kind']=='file':
                raw=raw_row(full,name)
                if name=='.request-archive-v11-anchor.json':
                    obj=checked_json(raw);a=object_identity(full,'','directory');b=object_identity(full,'request-archive-v11','directory')
                    assert obj==dict(root_device=a['device'],root_inode=a['inode'],archive_device=b['device'],archive_inode=b['inode'])
                    obj={k:'independently-verified-object'for k in obj}
                elif name=='.request-async-v9-anchor.json':
                    obj=checked_json(raw);expected={}
                    for suffix,prefix,kind in (('','','directory'),('.occupied','occupancy_','directory'),('.intents','intents_','directory'),('.lock','metadata_lock_','file'),('.controller.lock','controller_lock_','file')):
                        target='request-async-v9'+('/'+suffix if suffix else '')
                        pair=object_identity(full,target,kind)
                        expected[prefix+'device']=pair['device'];expected[prefix+'inode']=pair['inode']
                    assert obj==expected and raw==C(expected)
                    obj={k:'independently-verified-object'for k in obj}
                elif name=='.request-results-v2-anchor.json':
                    obj=checked_json(raw)
                    assert list(obj)==['schema','root','legacy','store','archive','shards']and obj['schema']==2
                    targets=dict(root='',legacy='request-results',store='request-results-v2',archive='request-results-v2/archive')
                    for key,target in targets.items():assert obj[key]==object_identity(full,target,'directory')
                    assert len(obj['shards'])==256
                    for i,pair in enumerate(obj['shards']):assert pair==object_identity(full,'request-results-v2/archive/'+format(i,'02x'),'directory')
                    for k in targets:obj[k]='independently-verified-'+k
                    obj['shards']=['independently-verified-'+format(i,'02x')for i in range(256)]
                elif name=='request-results/.request-results-v2.json':
                    obj=checked_json(raw);assert anchor is not None and obj==dict(schema=2,anchor_sha256=H(anchor))
                    obj['anchor_sha256']='independently-verified-complete-anchor-sha256'
                elif name.startswith(('request-audit/','request-archive-v11/'))and name.endswith('.json'):
                    obj=checked_json(raw);assert tuple(obj)==AUDIT_FIELDS
                    identifier=obj['request_id'];identity(obj,identifier)
                    assert Path(name).name==identifier+'.json'
                    record=records[identifier]
                    assert obj['state']==record['expected_state'],('audit completion differs from actual call_tool classification',identifier,obj['state'],record['expected_state'])
                    elapsed=obj['elapsed_ms']
                    assert type(elapsed)is int and 0<=elapsed<=(record['finish_mono']-record['bound']['mono_before'])//1000000+1
                    audits.setdefault(identifier,{})[name.split('/')[0]]=raw
                    outname=name.split('/')[0]+'/'+normalized_id(identifier)+'.json'
                    obj.update(request_id=normalized_id(identifier),owner='within-process-consistent-owner',
                               accepted_unix_ms='independently-bracketed-acceptance',elapsed_ms='independently-bracketed-lifetime')
                elif name.startswith('request-results-v2/archive/')and name.endswith('.json'):
                    obj=checked_json(raw);assert tuple(obj)==RESULT_FIELDS
                    identifier=obj['request_id'];identity(obj,identifier)
                    assert obj==retained_objects[identifier]
                    assert Path(name).name==identifier+'.json'and Path(name).parent.name==identifier[:2]
                    seen_retained.add(identifier)
                    if obj['state']=='stored':
                        normalized=payloads[identifier][1]
                        obj.update(payload_base64=base64.b64encode(normalized).decode(),payload_bytes=len(normalized),payload_sha256=H(normalized))
                    obj.update(request_id=normalized_id(identifier),owner='within-process-consistent-owner',accepted_unix_ms='independently-bracketed-acceptance')
                    outname='request-results-v2/archive/'+normalized_id(identifier)+'.json'
                elif name.startswith('request-async-v9/')and name.endswith('.json'):
                    obj=checked_json(raw);identifier=obj['request_id'];binding=bindings[identifier]
                    parts=Path(name).parts
                    if len(parts)==3 and parts[1]=='.outcomes':
                        assert tuple(obj)==OUTCOME_FIELDS and obj['state']=='completed'
                        for key in ('request_id','owner','key_hash','policy_binding'):assert obj[key]==binding[key]
                        assert parts[2]==identifier+'.json';seen_outcomes.add(identifier)
                        outname='request-async-v9/.outcomes/'+normalized_id(identifier)+'.json'
                    else:
                        assert tuple(obj)==BINDING_FIELDS and obj==binding
                        if len(parts)==2:assert parts[1]==binding['key_hash']+'.json';kind='primary';outname='request-async-v9/'+normalized_id(identifier)+'.json'
                        elif len(parts)==3 and parts[1]=='.occupied':assert parts[2]==binding['key_hash']+'.json';kind='occupied';outname='request-async-v9/.occupied/'+normalized_id(identifier)+'.json'
                        else:assert len(parts)==3 and parts[1]=='.intents'and parts[2]==identifier+'.json';kind='intent';outname='request-async-v9/.intents/'+normalized_id(identifier)+'.json'
                        seen_bindings.setdefault(identifier,{})[kind]=raw
                        identity(obj,identifier);obj['accepted_unix_ms']='independently-bracketed-acceptance'
                    obj.update(request_id=normalized_id(identifier),owner='within-process-consistent-owner',key_hash='independently-derived-key-'+normalized_id(identifier))
                else:assert not name.endswith('.tmp'),'staging file survived a stable boundary'
                if obj is not None:norm.pop('bytes');norm.pop('sha256');norm['content']=obj
            assert outname not in logical
            logical[outname]=norm
        for identifier,parts in audits.items():assert set(parts)=={'request-audit','request-archive-v11'}and len(set(parts.values()))==1
        for identifier,parts in seen_bindings.items():assert set(parts)=={'primary','occupied','intent'}and len(set(parts.values()))==1
        if complete:
            assert set(audits)==set(records)
            assert set(seen_bindings)==seen_outcomes==set(bindings)
            assert seen_retained==expected_retained
        return logical

    for frame in frames:
        request=request_value(frame);value=response_value(frame)
        nr=copy.deepcopy(request);nv=copy.deepcopy(value)
        if request['method']=='tools/call':
            tool=request['params']['name'];result=nv.get('result',nv.get('error'))
            meta=result.get('_meta')if'result'in nv else result.get('data')
            outer_id=meta[ID_META]['request_id'];meta[ID_META]['request_id']=normalized_id(outer_id)
            if 'request_id'in nr['params']['arguments']:
                target=nr['params']['arguments']['request_id']
                if target in records:nr['params']['arguments']['request_id']=normalized_id(target)
            if tool in ('request_start','request_cancel','request_status','request_result')and'result'in nv and nv['result']['isError']is False:
                body=checked_json(nv['result']['content'][0]['text'].encode())
                for key,expected in SCOPE.items():assert body[key]==expected
                identifier=body['request_id'];assert identifier in bindings
                if tool=='request_start':
                    assert body['tool_name']==bindings[identifier]['tool_name']
                    assert body['automatic_retry']is False and body['delivery_proven']is False
                    assert body['execution_resume_after_restart']is False and body['idempotency_binding_retained']is True
                    assert body['admission_is_not_dispatch_completion']is True
                    if frame['label']=='start':
                        assert body['reused']is False and body['async_state']in ('queued','running','settling','completed')
                        observations.append(dict(label=frame['label'],async_state=body['async_state']))
                        body['async_state']='declared-live-start-observation'
                    else:
                        assert frame['label']=='reuse'and body['reused']is True and body['async_state']=='completed'
                        assert body['original_request_replayed']is body['this_call_dispatch_started']is False
                elif tool=='request_cancel':
                    assert body['cancel_requested']is False and body['observation']=='no_owned_future_present_no_replay'
                    assert body['automatic_retry']is False and body['effect_may_continue']is True and body['remote_termination_confirmed']is False
                    assert body['cancellation_scope']=='this_controller_owned_rust_future_only'
                elif tool=='request_status':
                    audit=checked_json(raw_row(final_full,'request-audit/'+identifier+'.json'))
                    retained=retained_objects[identifier]
                    assert body['async_state']=='completed'and body['owned_future_active']is False
                    assert body['audit_metadata_available']is True and body['dispatch_state']=='completed'
                    assert body['elapsed_ms']==audit['elapsed_ms']and body['tool_name']==bindings[identifier]['tool_name']
                    assert body['result_state']==retained['state']and body.get('result_bytes')==retained['payload_bytes']
                    body['elapsed_ms']='independently-bracketed-lifetime'
                else:
                    raw,normalized=payloads[identifier]
                    data=base64.b64decode(body['data_base64'],validate=True)
                    assert base64.b64encode(data).decode()==body['data_base64']
                    assert body['offset']==0 and body['next_offset']==len(data)and body['total_bytes']==len(raw)
                    assert body['result_sha256']==H(raw)and data==raw[:len(data)]
                    assert body['eof']==(len(data)==len(raw))and body['immutable_snapshot']is True
                    body.update(data_base64=base64.b64encode(normalized[:len(data)]).decode(),result_sha256=H(normalized))
                body['request_id']=normalized_id(identifier)
                nv['result']['content'][0]['text']=C(body).decode()
        projected_frames.append(dict(label=frame['label'],request_hex=C(nr).hex(),response_hex=(C(nv)+b'\n').hex()))
    snapshots={}
    for label,boundary in boundaries.items():
        snapshots[label]=filesystem(boundary['filesystem'],boundary['mono_after'],False)
    return dict(frames=projected_frames,boundaries=snapshots,eof=filesystem(final_full,final['mono_after']),
                counts=dict(requests=len(frames),outer_audits=sum(r['kind']=='outer'for r in records.values()),
                            inner_audits=len(bindings),retained_records=len(retained_objects),new_successful_starts=len(bindings))),observations
