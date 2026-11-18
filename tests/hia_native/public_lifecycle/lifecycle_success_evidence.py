# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Re-admit every ordinary Start/Cancel stream and stable filesystem boundary."""
from pathlib import Path
import json,os
import lifecycle_success as run
import lifecycle_fixtures as fixtures
q=run.q;inputs=run.inputs
def read(path):return json.loads(Path(path).read_bytes())
def fence_plan(case,common,state):
    kind=case['fence'];env={};roots=[]
    if kind is None:return env,roots,None
    root=common/'fence';roots.append('fence')
    document=dict(schema='hepta-effect-owner-fence-v1',owner='v4',epoch=1,phase='admitting',state_root=str(state))
    env=dict(HEPTA_EFFECT_OWNER_FENCE_DIR=str(root),HEPTA_EFFECT_OWNER_SELF='v4',HEPTA_EFFECT_OWNER_FENCE_REQUIRED='1')
    if kind=='v11':
        roots.append('predecessor');document.update(owner='v11',predecessor_state_root=str(common/'predecessor'))
        env['HEPTA_EFFECT_OWNER_SELF']='v11'
    elif kind=='frozen':document['phase']='frozen'
    elif kind=='wrong_owner':env['HEPTA_EFFECT_OWNER_SELF']='v11'
    elif kind=='wrong_state':roots.append('other-state');document['state_root']=str(common/'other-state')
    elif kind=='missing_predecessor':document['owner']='v11';env['HEPTA_EFFECT_OWNER_SELF']='v11'
    elif kind=='zero_epoch':document['epoch']=0
    elif kind=='partial':env.pop('HEPTA_EFFECT_OWNER_SELF')
    elif kind=='invalid_required':env['HEPTA_EFFECT_OWNER_FENCE_REQUIRED']='0'
    else:assert kind=='v4'
    return env,roots,document

def side(case,folder,binary,process,*,common=None):
    row=read(folder/'result.json')
    assert row['case']==case['name']and row['side']==folder.name and row['status']=='PASS'
    assert row['exit_code']==0 and row['reaped']is row['full_capture']is True
    assert type(row['pid'])is int and row['pid']>0 and process['pid']==row['pid']
    common=folder.parent/'common' if common is None else Path(common)
    state=common/'state'
    assert row['command']==[str(binary),'--runtime-config',str(common/'config.json')]
    assert(common/'config.json').read_bytes()==q.SORTED(run.config(case,state))
    env,roots,document=fence_plan(case,common,state)
    assert row['environment']==dict(PATH='',LC_ALL='C',HEPTA_REQUEST_AUDIT_TRACE='0',**env)
    before=read(folder/'fence-before.json');assert set(before)==set(roots)
    assert read(folder/'fence-after.json')==before
    fixtures.admit(folder,'success',process)
    for name in roots:
        assert before[name]['']['kind']=='directory'and before[name]['']['mode']==0o700
        assert before[name]['']['uid']==os.getuid()
        assert set(before[name])==({'','.owner.lock','.owner.json'}if name=='fence'else{''})
    if roots:
        assert q.raw_row(before['fence'],'.owner.lock')==b''
        assert q.raw_row(before['fence'],'.owner.json')==q.SORTED(document)
        for name in ('.owner.lock','.owner.json'):
            item=before['fence'][name];assert item['mode']==0o600 and item['nlink']==1 and item['uid']==os.getuid()
        released=read(folder/'fence-release-observed.json')
        assert released['actual_nonblocking_exclusive_lock']is True and released['lock']==str(common/'fence/.owner.lock')
        assert released['after_response_index']==2 and row['frames'][2]['mono_after']<=released['monotonic_ns']<=row['final']['mono_after']
    frames=row['frames'];expected_count=9 if case['success']else 5
    assert len(frames)==expected_count
    assert row['requests_entered']==row['responses_received']==row['responses_validated']==expected_count
    for name in ('input.bin','stdout.bin','stderr'):inputs.pin(folder/name,row[name])
    assert(folder/'stderr').read_bytes()==b''
    assert(folder/'input.bin').read_bytes()==b''.join(bytes.fromhex(x['raw_input_hex'])for x in frames)
    assert(folder/'stdout.bin').read_bytes()==b''.join(bytes.fromhex(x['raw_output_hex'])for x in frames)
    start_args=dict(operation=case['operation'],idempotency_key=case['key'])
    planned=[(None,None,'initialize',True),(case['operation']['tool'],case['operation']['arguments'],'baseline',True),
             ('request_start',start_args,'start',case['success'])]
    if case['success']:
        first=q.response_value(frames[2]);body=q.checked_json(first['result']['content'][0]['text'].encode());identifier=body['request_id']
        assert q.valid_id(identifier)and body['reused']is False
        different=dict(tool='effective_config'if case['operation']['tool']=='host_list'else'host_list',arguments={})
        planned += [('request_start',start_args,'reuse',True),
            ('request_start',dict(operation=different,idempotency_key=case['key']),'key-conflict',False),
            ('request_status',dict(request_id=identifier),'status',True),
            ('request_result',dict(request_id=identifier),'result',case['expected_result']=='stored'),
            ('request_cancel',dict(request_id=identifier),'cancel',True)]
    else:planned += [('request_cancel',dict(request_id='f'*64),'cancel-missing-binding',False)]
    planned += [('host_list',{},'recovery',True)]
    for index,(frame,event)in enumerate(zip(frames,planned)):
        tool,args,label,success=event
        assert frame['index']==index and frame['label']==label
        assert read(folder/('frame-'+str(index)+'.json'))==frame
        if tool is None:
            wanted=dict(jsonrpc='2.0',id=index,method='initialize',params=dict(protocolVersion=case['protocol'],
                capabilities={},clientInfo=dict(name='public-start-normal-pairs',version='1')))
        else:wanted=dict(jsonrpc='2.0',id=index,method='tools/call',params=dict(name=tool,arguments=args))
        assert bytes.fromhex(frame['raw_input_hex'])==q.C(wanted)+b'\n'
        response=q.response_value(frame)
        if tool is not None:assert response['result']['isError']is(not success)
        snap=read(folder/('frame-'+str(index)+'-filesystem.json'))
        assert snap['mono_before']>=frame['mono_after']and snap['mono_before']<=snap['mono_after']
        for name,item in snap['filesystem'].items():
            if item.get('kind')=='file':
                raw=bytes.fromhex(item['hex']);assert len(raw)==item['bytes']and q.H(raw)==item['sha256']
    required={'baseline','recovery'}
    if case['success']:required|={'producer-completed','reuse','key-conflict','status','result','cancel'}
    else:required|={'refused','cancel-missing-binding'}
    assert set(row['boundaries'])==required
    for label,value in row['boundaries'].items():assert read(folder/('boundary-'+label+'.json'))==value
    assert read(folder/'eof-filesystem.json')==row['final']
    if case['success']:
        observations=read(folder/'completion-observations.json')
        assert observations and all(x.get('absent')is True for x in observations[:-1])
        last=observations[-1];raw=bytes.fromhex(last['hex']);value=q.checked_json(raw)
        assert q.H(raw)==last['sha256']and len(raw)==last['bytes']
        assert value['request_id']==identifier and value['state']=='completed'
        assert last['path']==str(state/'request-async-v9/.outcomes'/(identifier+'.json'))
        name='request-async-v9/.outcomes/'+identifier+'.json'
        assert raw==q.raw_row(row['final']['filesystem'],name)
        final_entry=row['final']['filesystem'][name]
        assert all(last[k]==final_entry[k]for k in ('device','inode','mode'))
        assert frames[2]['mono_after']<=last['monotonic_ns']<=row['boundaries']['producer-completed']['mono_before']
        assert last['monotonic_ns']<frames[3]['mono_before']
    assert row['successful_starts']==int(case['success'])
    answer,observations=q.project_case(case,frames,row['boundaries'],row['final'])
    assert read(folder/'projection.json')==answer
    assert read(folder/'scheduling-observations.json')==observations
    inputs.pin(folder/'projection.json',row['projection'])
    inputs.pin(folder/'scheduling-observations.json',row['scheduling_observations'])
    for key,value in process.items():
        if key not in ('frames','boundaries','final'):assert row[key]==value
    return answer
