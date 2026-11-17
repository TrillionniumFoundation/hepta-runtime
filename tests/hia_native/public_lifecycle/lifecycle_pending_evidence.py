# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct actual Pending captures and retain the complete rejection domain."""
from pathlib import Path
import copy,json
import lifecycle_inputs as inputs
import lifecycle_fixtures as fixtures
import lifecycle_success as base
import lifecycle_pending_projection as projection
q=base.q
def read_json(path):return json.loads(Path(path).read_bytes())
def side(case,root,binary,process,*,common=None):
    root=Path(root);side=root.name
    common=root.parent/'common' if common is None else Path(common)
    row=read_json(root/'result.json')
    assert row['side']==side and row['case']==case
    assert row['command']==[str(binary),'--runtime-config',str(common/'config.json')]
    assert row['environment']==dict(PATH='',LC_ALL='C',HEPTA_REQUEST_AUDIT_TRACE='0',
        HEPTA_EFFECT_OWNER_FENCE_DIR=str(common/'fence'),HEPTA_EFFECT_OWNER_SELF='v4',
        HEPTA_EFFECT_OWNER_FENCE_REQUIRED='1')
    actual=process;assert actual['pid']==row['pid']and actual['status']==row['status']
    for name in ('input.bin','stdout.bin','stderr'):inputs.pin(root/name,row[name])
    rawin=(root/'input.bin').read_bytes();rawout=(root/'stdout.bin').read_bytes();err=(root/'stderr').read_bytes()
    for event in row['sends']:assert read_json(root/('send-'+str(event['index'])+'.json'))==event
    for event in row['responses']:assert read_json(root/('response-'+str(event['id'])+'.json'))==event
    for key,name in (('baseline_snapshot','baseline-filesystem.json'),
                     ('while_blocked_snapshot','blocked-filesystem.json'),
                     ('final','eof-filesystem.json')):
        assert read_json(root/name)==row[key]
    fence=read_json(root/'fence-before.json')
    assert read_json(root/'fence-after.json')==row['fence_after']==fence
    fixtures.admit(root,'pending',process)
    assert(common/'config.json').read_bytes()==q.SORTED(base.config(case,common/'state'))
    blocked=read_json(root/'blocked-observations.json');assert blocked and blocked[-1]==row['blocked_witness']
    for observation in blocked:
        assert observation['pid']==row['pid']
        assert observation['actual_flock_wait']==bool(observation['blocked_threads']and observation['matching_open_descriptors'])
    sibling=read_json(root/'sibling-before-release.json')
    assert sibling['response']==next(x for x in row['responses']if x['id']==3)
    assert sibling['witness']['pid']==row['pid']and sibling['witness']['actual_flock_wait']is True
    assert sibling['witness']['lock_device']==row['blocked_witness']['lock_device']
    assert sibling['witness']['lock_inode']==row['blocked_witness']['lock_inode']
    if case['action']!='eof':
        assert read_json(root/'completed-filesystem.json')==row['completion_snapshot']
        observations=read_json(root/'completion-observations.json');assert observations
        assert all(x.get('absent')is True for x in observations[:-1])
        last=observations[-1];raw=bytes.fromhex(last['hex']);value=q.checked_json(raw)
        assert q.H(raw)==last['sha256']and value['state']=='completed'
        assert value['request_id']==row['inner_request_id']
        assert Path(last['path'])==common/'state/request-async-v9/.outcomes'/(row['inner_request_id']+'.json')
        assert q.raw_row(row['final']['filesystem'],'request-async-v9/.outcomes/'+row['inner_request_id']+'.json')==raw
        assert row['guard_released_mono']<=last['monotonic_ns']<=row['completion_snapshot']['mono_before']
    projected,observations=projection.project_case(case,row,rawin,rawout,err,fence)
    assert actual['messages']==len(row['sends'])and actual['requests']==projected['counts']['requests']
    assert actual['responses']==len(row['responses'])and actual['successful_starts']==projected['counts']['successful_starts']
    return projected,observations,(row,rawin,rawout,err,fence)

def controls(case,original):
    row,rawin,rawout,err,fence=original
    mutations=[]
    broken=copy.deepcopy(row);broken['blocked_witness']['pid']+=1
    mutations.append(('owned-pid-binding',broken,rawin,rawout,err,fence))
    broken=copy.deepcopy(row);broken['blocked_witness']['matching_open_descriptors'][0]['inode']+=1
    mutations.append(('held-fd-inode-binding',broken,rawin,rawout,err,fence))
    mutations.append(('complete-raw-stdout',copy.deepcopy(row),rawin,rawout+b'\n',err,fence))
    broken=copy.deepcopy(row);broken['responses'][1]['response']['result']['_meta'][q.ID_META]['request_id']='0'*64
    mutations.append(('raw-response-annotation',broken,rawin,rawout,err,fence))
    broken=copy.deepcopy(row)
    name=next(n for n in broken['final']['filesystem']if n.startswith('request-results-v2/archive/')and n.endswith('.json'))
    obj=q.checked_json(q.raw_row(broken['final']['filesystem'],name))
    obj['accepted_unix_ms']+=1;raw=q.C(obj)
    broken['final']['filesystem'][name].update(hex=raw.hex(),bytes=len(raw),sha256=q.H(raw))
    mutations.append(('retained-audit-identity',broken,rawin,rawout,err,fence))
    if case['action']=='eof':
        broken=copy.deepcopy(row);broken['guard_released_mono']=broken['eof_sent_monotonic_ns']+1
        mutations.append(('actual-five-second-drain',broken,rawin,rawout,err,fence))
    if case['action']=='cancel':
        broken=copy.deepcopy(row)
        broken['sends']=[x for x in broken['sends']if x['request']['method']!='notifications/cancelled']
        mutations.append(('actual-cancel-message',broken,rawin,rawout,err,fence))
    for label,*args in mutations:
        rejected=False
        try:projection.project_case(case,*args)
        except(AssertionError,KeyError,ValueError,TypeError):rejected=True
        assert rejected,('data corruption accepted',case['name'],label)
    projection.project_case(case,*original)
    return [dict(name=label,rejected=True)for label,*_ in mutations]
