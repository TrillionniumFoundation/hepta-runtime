"""Only source-bound real-stdio inputs and mechanical exchange scheduling."""
from pathlib import Path
import json
import extract_public_inputs as peer
import custom_request_inputs
def domain(name,fixture):
    assert name in ('stdio-legacy','stdio-modern','protocol-legacy','protocol-modern','eof-legacy','eof-modern','custom-legacy','custom-modern')
    modern=name.endswith('-modern');kind=name.split('-')[0]
    if kind=='stdio':cases=[{'name':name,'actions':peer.fixture_actions(fixture),'rows':peer.ordinary_stdio_rows(modern=modern)}]
    elif kind=='protocol':cases=peer.protocol_scenarios(fixture,modern=modern)
    elif kind=='custom':cases=custom_request_inputs.scenarios(fixture,modern=modern)
    else:cases=peer.eof_scenarios(fixture,modern=modern)
    return {'schema':'hepta.runtime.extract-raw-stdio-domain.v1','name':name,'fixture':str(fixture),'cases':cases,'per_exchange_seconds':60,'whole_lane_seconds':180,'ci_job_minutes':15,'response_count_assumed':None,'unknown_trial_and_recovery_sent_as_one_unchanged_batch':True}
def steps(case):
    result=[]
    def one(label,raw,identifier=None,segments=None):
        result.append({'label':label,'wire':raw,'correlation_id':identifier,'segments':segments or [{'name':label,'bytes':len(raw)}]})
    for row in case.get('initial',case.get('rows',[])):
        value=json.loads(row['wire']);identifier=value.get('id') if type(value) is dict else None
        one(row['name'],row['wire'],identifier)
    if 'anchor' in case:one('anchor',case['anchor']['wire'],case['anchor']['input_id'])
    if 'trial' in case:
        trial,recovery=case['trial']['wire'],case['recovery']['wire']
        one('trial-and-recovery',trial+recovery,case['recovery']['input_id'],[{'name':'trial','bytes':len(trial)},{'name':'recovery','bytes':len(recovery)}])
        one('barrier',case['barrier']['wire'],case['barrier']['input_id'])
    if 'tail' in case:one('eof-tail',case['tail']['wire'])
    return result
def serial(value):return peer.serial_inputs(value)
