# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Data-only projection of actual owned flock captures; no invented replies."""
import base64,copy
from pathlib import Path
from lifecycle_success_projection import (
    C,H,checked_json,raw_row,object_identity,valid_id,key_hash,request_hash,
    payload_for_response,ID_META,ACK_META,BINDING_FIELDS,AUDIT_FIELDS,RESULT_FIELDS,
    OUTCOME_FIELDS,SCOPE)

def project_case(case,row,raw_input,raw_output,raw_stderr,fence_before):
    assert row['case']==case and row['status']=='CAPTURED_NOT_QUALIFIED'
    assert row['qualification']is False and row['full_capture']is True
    assert row['exit_code']==0 and row['reaped']is True and raw_stderr==b''
    assert type(row['pid'])is int and row['pid']>0
    sends=copy.deepcopy(row['sends']);responses=copy.deepcopy(row['responses']);requests={};replies={}
    assert raw_input==b''.join(bytes.fromhex(e['raw_input_hex'])for e in sends)
    assert raw_output==b''.join(bytes.fromhex(e['raw_output_hex'])for e in responses)
    notifications=[]
    for index,event in enumerate(sends):
        raw=bytes.fromhex(event['raw_input_hex']);assert raw.endswith(b'\n')
        value=checked_json(raw[:-1]);assert value==event['request']
        event['request']=value
        assert event['index']==index and event['sent_bytes']==len(raw)
        assert event['wall_before']<=event['wall_after'] and event['mono_before']<=event['mono_after']
        if 'id'in value:
            identifier=value['id'];assert type(identifier)is int and identifier not in requests
            requests[identifier]=event
        else:notifications.append(event)
    expected_ids={0,1,2,3}if case['action']=='eof'else set(range(6))
    expected_replies=expected_ids if case['action']=='normal'else expected_ids-{2}
    assert set(requests)==expected_ids
    assert requests[0]['request']==dict(jsonrpc='2.0',id=0,method='initialize',
        params=dict(protocolVersion=case['protocol'],capabilities={},
            clientInfo=dict(name='ordinary-public-fence-pending',version='1')))
    expected_tools={1:('host_list',{}),2:('request_start',dict(
        operation=dict(tool='host_list',arguments={}),idempotency_key=case['key'])),
        3:('host_list',{})}
    for identifier,(tool,args)in expected_tools.items():
        assert requests[identifier]['request']==dict(jsonrpc='2.0',id=identifier,
            method='tools/call',params=dict(name=tool,arguments=args))
    if case['action']=='cancel':
        assert len(notifications)==1
        assert notifications[0]['request']==dict(jsonrpc='2.0',method='notifications/cancelled',
            params=dict(requestId=2,reason='ordinary owned fence wait'))
        assert notifications[0]['mono_before']>=row['blocked_witness']['monotonic_ns']
        assert notifications[0]['mono_after']<=requests[3]['mono_before']
    else:assert not notifications
    for index,event in enumerate(responses):
        raw=bytes.fromhex(event['raw_output_hex']);assert raw.endswith(b'\n')
        value=checked_json(raw[:-1]);assert value==event['response']
        event['response']=value
        identifier=value['id'];assert type(identifier)is int and identifier not in replies
        assert event['id']==identifier and event['order']==index
        assert identifier in requests and event['mono_after']>=requests[identifier]['mono_after']
        if identifier!=0:assert value['result']['isError']is False
        replies[identifier]=event
    assert set(replies)==expected_replies
    expected_order=[0,1,3,2,4,5]if case['action']=='normal'else(
        [0,1,3,4,5]if case['action']=='cancel'else[0,1,3])
    assert [e['id']for e in responses]==expected_order
    assert row['sibling_before_guard_release']is True
    assert row['guard_acquired_mono']<=requests[2]['mono_before']
    assert replies[3]['mono_after']<row['guard_released_mono']
    if case['action']=='normal':assert replies[2]['mono_after']>=row['guard_released_mono']
    assert row['eof_completed_monotonic_ns']>=row['eof_sent_monotonic_ns']
    assert row['eof_completed_monotonic_ns']>=row['guard_released_mono']
    assert row['fence_after']==fence_before and set(fence_before)=={'fence'}
    lock=fence_before['fence']['.owner.lock']
    assert lock['kind']=='file'and lock['mode']==0o600 and lock['nlink']==1
    assert raw_row(fence_before['fence'],'.owner.lock')==b''
    def witness(value):
        assert value['pid']==row['pid']and value['actual_flock_wait']is True
        assert (value['lock_device'],value['lock_inode'])==(lock['device'],lock['inode'])
        assert value['blocked_threads']and value['matching_open_descriptors']
        assert len({x['tid']for x in value['blocked_threads']})==len(value['blocked_threads'])
        for thread in value['blocked_threads']:
            assert type(thread['tid'])is int and thread['tid']>0
            assert 'locks_lock_inode_wait'in thread['wchan']or'flock'in thread['wchan']
        for fd in value['matching_open_descriptors']:
            assert type(fd['fd'])is int and fd['fd']>=0
            assert (fd['device'],fd['inode'],fd['mode'])==(lock['device'],lock['inode'],lock['mode'])
            assert fd['target']==row['environment']['HEPTA_EFFECT_OWNER_FENCE_DIR']+'/.owner.lock'
    witness(row['blocked_witness'])
    assert requests[2]['mono_after']<=row['blocked_witness']['monotonic_ns']<row['guard_released_mono']
    if case['action']=='eof':
        witness(row['drain_wait_witness'])
        assert row['guard_released_mono']-row['eof_sent_monotonic_ns']>=5_500_000_000
        assert row['drain_wait_witness']['monotonic_ns']>=row['eof_sent_monotonic_ns']+5_500_000_000
        assert row['successful_starts']==0
    else:assert row['successful_starts']==1
    final=row['final'];final_full=final['filesystem']
    records={};bindings={};owner=None;policy=None;outer_by_rpc={}
    for identifier,event in replies.items():
        if identifier==0:continue
        response=event['response'];meta=response['result']['_meta']
        assert ID_META in meta
        identity=meta[ID_META]
        assert identity==dict(request_id=identity['request_id'],automatic_retry=False,delivery_proven=False)
        rid=identity['request_id'];assert valid_id(rid)and rid not in records
        request=requests[identifier];tool=request['request']['params']['name']
        audit=checked_json(raw_row(final_full,'request-audit/'+rid+'.json'))
        assert tuple(audit)==AUDIT_FIELDS and audit['request_id']==rid and audit['tool_name']==tool
        assert valid_id(audit['owner'])
        if owner is None:owner=audit['owner']
        assert audit['owner']==owner
        records[rid]=dict(index=identifier,kind='outer',normal=format(identifier+1,'064x'),
            tool=tool,bound=dict(mono_before=request['mono_before'],wall_before=request['wall_before'],
            wall_after=event['wall_after']),finish_mono=event['mono_after'],expected_state='completed',
            identity=tuple(audit[k]for k in ('request_id','owner','tool_name','accepted_unix_ms')))
        outer_by_rpc[identifier]=rid
    assert owner is not None
    blocked=row['while_blocked_snapshot'];blocked_full=blocked['filesystem']
    candidate=[]
    for name in blocked_full:
        if name.startswith('request-audit/')and name.endswith('.json'):
            value=checked_json(raw_row(blocked_full,name))
            if value['tool_name']=='request_start':candidate.append(value)
    assert len(candidate)==1
    start_audit=candidate[0];outer_start_id=start_audit['request_id']
    assert valid_id(outer_start_id)and start_audit['owner']==owner
    assert start_audit['state']=='unknown'and start_audit['elapsed_ms']is None
    assert tuple(start_audit)==AUDIT_FIELDS
    start_bound=dict(mono_before=requests[2]['mono_before'],wall_before=requests[2]['wall_before'],
                     wall_after=blocked['wall_after'])
    if 2 in replies:
        assert outer_by_rpc[2]==outer_start_id
        assert records[outer_start_id]['identity']==tuple(start_audit[k]for k in ('request_id','owner','tool_name','accepted_unix_ms'))
        records[outer_start_id]['bound']=start_bound
    else:
        assert outer_start_id not in records
        finish=row['completion_snapshot']['mono_after']if case['action']=='cancel'else final['mono_after']
        records[outer_start_id]=dict(index=2,kind='outer',normal=format(3,'064x'),tool='request_start',
            bound=start_bound,finish_mono=finish,expected_state='unknown',
            identity=tuple(start_audit[k]for k in ('request_id','owner','tool_name','accepted_unix_ms')))
        outer_by_rpc[2]=outer_start_id
    assert len(outer_by_rpc)==len(expected_ids)-1
    baseline_id=outer_by_rpc[1];baseline=payload_for_response(replies[1]['response'])
    sibling_id=outer_by_rpc[3]
    if case['action']!='eof':
        identifier=row['inner_request_id'];assert valid_id(identifier)and identifier not in records
        hashed=key_hash(owner,case['key'])
        names=['request-async-v9/'+hashed+'.json','request-async-v9/.occupied/'+hashed+'.json',
               'request-async-v9/.intents/'+identifier+'.json']
        raws=[raw_row(final_full,name)for name in names];assert len(set(raws))==1
        binding=checked_json(raws[0]);assert tuple(binding)==BINDING_FIELDS
        assert binding['request_id']==identifier and binding['owner']==owner and binding['tool_name']=='host_list'
        assert binding['key_hash']==hashed and binding['request_hash']==request_hash(case['operation'])
        assert valid_id(binding['policy_binding']);policy=binding['policy_binding']
        done=row['completion_snapshot']
        records[identifier]=dict(index=2,kind='inner',normal=format(1<<32,'064x'),tool='host_list',
            bound=dict(mono_before=requests[2]['mono_before'],wall_before=requests[2]['wall_before'],
                wall_after=done['wall_after']),finish_mono=done['mono_after'],expected_state='completed',
            identity=tuple(binding[k]for k in ('request_id','owner','tool_name','accepted_unix_ms')))
        bindings[identifier]=binding
        for rpc,tool in ((4,'request_status'),(5,'request_cancel')):
            assert requests[rpc]['request']==dict(jsonrpc='2.0',id=rpc,method='tools/call',
                params=dict(name=tool,arguments=dict(request_id=identifier)))
    else:assert not any(name.startswith('request-async-v9/')and name.endswith('.json')for name in final_full)
    def normalized_id(identifier):
        assert identifier in records
        return records[identifier]['normal']
    def identity(value,identifier):
        record=records[identifier];bound=record['bound']
        assert tuple(value[k]for k in ('request_id','owner','tool_name','accepted_unix_ms'))==record['identity']
        accepted=value['accepted_unix_ms']
        assert type(accepted)is int and bound['wall_before']//1000000<=accepted<=bound['wall_after']//1000000
        assert value['owner']==owner
    payloads={};retained_objects={}
    for name in final_full:
        if not(name.startswith('request-results-v2/archive/')and name.endswith('.json')):continue
        value=checked_json(raw_row(final_full,name));identifier=value['request_id']
        assert tuple(value)==RESULT_FIELDS and identifier in records
        identity(value,identifier)
        assert Path(name).name==identifier+'.json'and Path(name).parent.name==identifier[:2]
        if policy is None:policy=value['policy_binding']
        assert valid_id(policy)and value['policy_binding']==policy and value['state']=='stored'
        raw=base64.b64decode(value['payload_base64'],validate=True)
        assert base64.b64encode(raw).decode()==value['payload_base64']
        assert value['payload_bytes']==len(raw)and value['payload_sha256']==H(raw)
        if records[identifier]['kind']=='inner':
            expected=checked_json(baseline);expected['_meta'][ID_META]['request_id']=identifier;expected=C(expected)
        else:expected=payload_for_response(replies[records[identifier]['index']]['response'])
        assert raw==expected,'full retained Complete differs from observed baseline/result'
        parsed=checked_json(raw)
        assert parsed['resultType']=='complete'and parsed.get('isError',False)is False
        assert ACK_META not in parsed['_meta']
        assert parsed['_meta'][ID_META]==dict(request_id=identifier,automatic_retry=False,delivery_proven=False)
        parsed['_meta'][ID_META]['request_id']=normalized_id(identifier)
        payloads[identifier]=(raw,C(parsed));retained_objects[identifier]=value
    expected_retained={baseline_id,sibling_id}|set(bindings)
    assert set(retained_objects)==expected_retained
    def filesystem(full,mono_after,label,expected_ids,expected_retained_ids,expected_bindings):
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
                    pending=identifier==outer_start_id and(label=='blocked'or case['action']=='eof')
                    expected_state='unknown'if pending else record['expected_state']
                    assert obj['state']==expected_state
                    elapsed=obj['elapsed_ms']
                    if pending:assert elapsed is None
                    else:assert type(elapsed)is int and 0<=elapsed<=(record['finish_mono']-record['bound']['mono_before'])//1000000+1
                    audits.setdefault(identifier,{})[name.split('/')[0]]=raw
                    outname=name.split('/')[0]+'/'+normalized_id(identifier)+'.json'
                    obj.update(request_id=normalized_id(identifier),owner='within-process-consistent-owner',
                               accepted_unix_ms='independently-bracketed-acceptance',elapsed_ms=(None if elapsed is None else'independently-bracketed-lifetime'))
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
        assert set(audits)==expected_ids
        assert set(seen_bindings)==seen_outcomes==expected_bindings
        assert seen_retained==expected_retained_ids
        return logical

    projected_requests=[];projected_responses=[];observations=[]
    for event in sends:
        request=copy.deepcopy(event['request'])
        if request.get('method')=='tools/call'and'request_id'in request['params']['arguments']:
            identifier=request['params']['arguments']['request_id']
            assert identifier in bindings
            request['params']['arguments']['request_id']=normalized_id(identifier)
        projected_requests.append((C(request)+b'\n').hex())
    for event in responses:
        identifier=event['id'];value=copy.deepcopy(event['response'])
        if identifier!=0:
            tool=requests[identifier]['request']['params']['name']
            meta=value['result']['_meta'];outer=meta[ID_META]['request_id']
            assert outer==outer_by_rpc[identifier];meta[ID_META]['request_id']=normalized_id(outer)
            if tool in ('request_start','request_status','request_cancel'):
                body=checked_json(value['result']['content'][0]['text'].encode())
                for key,expected in SCOPE.items():assert body[key]==expected
                inner=body['request_id'];assert inner in bindings
                if tool=='request_start':
                    assert identifier==2 and case['action']=='normal'
                    assert body['tool_name']=='host_list'and body['reused']is False
                    assert body['automatic_retry']is False and body['delivery_proven']is False
                    assert body['execution_resume_after_restart']is False and body['idempotency_binding_retained']is True
                    assert body['admission_is_not_dispatch_completion']is True
                    assert body['async_state']in ('queued','running','settling','completed')
                    observations.append(dict(label='live-start-response',async_state=body['async_state']))
                    body['async_state']='declared-live-start-observation'
                elif tool=='request_status':
                    audit=checked_json(raw_row(final_full,'request-audit/'+inner+'.json'))
                    retained=retained_objects[inner]
                    assert body['async_state']=='completed'and body['owned_future_active']is False
                    assert body['audit_metadata_available']is True and body['dispatch_state']=='completed'
                    assert body['elapsed_ms']==audit['elapsed_ms']and body['tool_name']=='host_list'
                    assert body['result_state']=='stored'and body['result_bytes']==retained['payload_bytes']
                    body['elapsed_ms']='independently-bracketed-lifetime'
                else:
                    assert body['cancel_requested']is False and body['observation']=='no_owned_future_present_no_replay'
                    assert body['automatic_retry']is False and body['effect_may_continue']is True
                    assert body['remote_termination_confirmed']is False
                    assert body['cancellation_scope']=='this_controller_owned_rust_future_only'
                body['request_id']=normalized_id(inner)
                value['result']['content'][0]['text']=C(body).decode()
        projected_responses.append((C(value)+b'\n').hex())
    assert row['baseline_snapshot']['mono_after']<=requests[2]['mono_before']
    assert row['blocked_witness']['monotonic_ns']<=blocked['mono_before']<=blocked['mono_after']<requests[3]['mono_before']
    snapshots={}
    snapshots['baseline']=filesystem(row['baseline_snapshot']['filesystem'],row['baseline_snapshot']['mono_after'],
        'baseline',{baseline_id},{baseline_id},set())
    snapshots['blocked']=filesystem(blocked_full,blocked['mono_after'],'blocked',
        {baseline_id,outer_start_id},{baseline_id},set())
    if case['action']!='eof':
        done=row['completion_snapshot']
        assert row['guard_released_mono']<=done['mono_before']<=done['mono_after']<requests[4]['mono_before']
        snapshots['producer-completed']=filesystem(done['filesystem'],done['mono_after'],'completed',
            {baseline_id,outer_start_id,sibling_id}|set(bindings),expected_retained,set(bindings))
    snapshots['eof']=filesystem(final_full,final['mono_after'],'eof',
        set(records),expected_retained,set(bindings))
    fence={}
    for name,value in fence_before['fence'].items():
        assert not value.get('concurrent_retirement')and value.get('stable',True)
        if value['kind']=='file':raw_row(fence_before['fence'],name)
        fence[name]={key:val for key,val in value.items()if key not in ('device','inode')}
    return dict(requests=projected_requests,responses=projected_responses,filesystem=snapshots,
        fence=fence,lifecycle=dict(real_flock_wait=True,sibling_progress_while_held=True,
            suppressed_start_reply=case['action']!='normal',sdk_cancel=case['action']=='cancel',
            eof_waits_for_detached_worker=case['action']=='eof'),
        counts=dict(messages=len(sends),requests=len(requests),responses=len(responses),
            outer_audits=len(outer_by_rpc),producer_audits=len(bindings),
            retained_records=len(retained_objects),successful_starts=len(bindings))),observations
