# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete normal Read wire projection, bound to the observed audit and payload."""
import base64
import copy
import importlib.util
import hashlib
from pathlib import Path

import normal_projection as q


def semantic_target(arguments):
    value = arguments.get('request_id')
    if isinstance(value, str):
        return value
    token = '$serde_json::private::RawValue'
    if isinstance(value, dict) and list(value) == [token]:
        # This fixture branch is exactly one nested SDK Value, not its arguments map.
        import json
        parsed = json.loads(value[token])
        return parsed if isinstance(parsed, str) else None
    return None


def selected_record(state, ident, provenance):
    inverse = {value: frame for frame, value in provenance['request_ids'].items()}
    assert ident in inverse
    records = []
    for directory in ('request-audit', 'request-archive-v11'):
        path = state / directory / (ident + '.json')
        if path.exists():
            raw = path.read_bytes()
            row = q.checked_json(raw)
            assert row['request_id'] == ident and row['owner'] == provenance['owner']
            records.append((raw, row))
    assert records and len({raw for raw, _ in records}) == 1
    return inverse[ident], records[0][1]


def retained_payload(state, ident, audit):
    path = state / 'request-results-v2/archive' / ident[:2] / (ident + '.json')
    row = q.checked_json(path.read_bytes())
    for key in ('request_id', 'owner', 'tool_name', 'accepted_unix_ms'):
        assert row[key] == audit[key], ('retained/audit identity', key)
    assert row['state'] == 'stored'
    payload = base64.b64decode(row['payload_base64'], validate=True)
    assert base64.b64encode(payload).decode() == row['payload_base64']
    assert len(payload) == row['payload_bytes'] and q.H(payload) == row['payload_sha256']
    return row, payload


def wire(raw, frame, request, state, provenance):
    value, base = q.wire(raw, frame, provenance)
    projected = q.checked_json(base[:-1])
    if request.get('method') != 'tools/call':
        return value, base
    tool = request['params']['name']
    result = value.get('result')
    if tool not in ('request_status', 'request_result') or not result or result['isError']:
        return value, base
    assert len(result['content']) == 1 and result['content'][0]['type'] == 'text'
    text = result['content'][0]['text'].encode()
    content = q.checked_json(text)
    ident = semantic_target(request['params']['arguments'])
    assert isinstance(ident, str) and content['request_id'] == ident
    target_frame, audit = selected_record(state, ident, provenance)
    retained, payload = retained_payload(state, ident, audit)
    content = copy.deepcopy(content)
    if tool == 'request_status':
        assert content['tool_name'] == audit['tool_name']
        assert content['dispatch_state'] == audit['state']
        assert content['elapsed_ms'] == audit['elapsed_ms']
        assert content['result_state'] == retained['state']
        assert content['result_bytes'] == len(payload)
        content['elapsed_ms'] = None if audit['elapsed_ms'] is None else 'bound-to-exact-audit-record'
    else:
        offset, after = content['offset'], content['next_offset']
        assert type(offset) is int and type(after) is int and 0 <= offset <= after <= len(payload)
        args = request['params']['arguments']
        assert offset == (0 if args.get('offset') is None else args['offset'])
        if args.get('limit') is not None:
            assert after - offset <= args['limit']
        piece = base64.b64decode(content['data_base64'], validate=True)
        assert piece == payload[offset:after]
        assert base64.b64encode(piece).decode() == content['data_base64']
        assert content['total_bytes'] == len(payload)
        assert content['result_sha256'] == q.H(payload)
        assert content['eof'] is (after == len(payload))
        parsed_payload = q.checked_json(payload)
        assert parsed_payload['_meta'][q.ID_META]['request_id'] == ident
        parsed_payload['_meta'][q.ID_META]['request_id'] = q.norm_id(ident, target_frame, provenance)
        normalized = q.compact(parsed_payload)
        assert len(normalized) == len(payload)
        content['result_sha256'] = q.H(normalized)
        content['data_base64'] = base64.b64encode(normalized[offset:after]).decode()
    content['request_id'] = q.norm_id(ident, target_frame, provenance)
    projected['result']['content'][0]['text'] = q.compact(content).decode()
    return value, q.compact(projected) + b'\n'


def request_projection(request, provenance):
    value = copy.deepcopy(request)
    if value.get('method') != 'tools/call':
        return value
    args = value['params']['arguments']
    ident = semantic_target(args)
    inverse = {x: frame for frame, x in provenance['request_ids'].items()}
    if ident in inverse:
        replacement = q.norm_id(ident, inverse[ident], provenance)
        if isinstance(args['request_id'], str):
            args['request_id'] = replacement
        else:
            assert list(args['request_id']) == ['$serde_json::private::RawValue']
            args['request_id']['$serde_json::private::RawValue'] = q.compact(replacement).decode()
    return value

# Every dynamic History field is checked against the exact live audit record
# before normalization. No record is synthesized or dropped from the comparison.
read_wire=wire
read_request_projection=request_projection
def history_argument(value):
    if isinstance(value,dict) and list(value)==['$serde_json::private::RawValue']:
        import json
        return json.loads(value['$serde_json::private::RawValue'])
    return value

def wire(raw,frame,request,state,provenance):
    value,base=read_wire(raw,frame,request,state,provenance)
    if request.get('method')!='tools/call' or request['params']['name']!='request_history':
        return value,base
    assert frame not in provenance['request_ids'],'History created its own audit record'
    body=value.get('result',value.get('error'))
    meta=body.get('_meta') if 'result'in value else body.get('data')
    assert not isinstance(meta,dict) or (q.ID_META not in meta and q.ACK_META not in meta)
    if 'result'not in value or value['result']['isError']:
        return value,base
    result=value['result']
    assert len(result['content'])==1 and result['content'][0]['type']=='text'
    content=q.checked_json(result['content'][0]['text'].encode())
    rows=[]
    hot=state/'request-audit'
    if hot.exists():
        for path in hot.glob('*.json'):
            record=q.checked_json(path.read_bytes())
            if record['owner']==provenance['owner']:rows.append(record)
    rows.sort(key=lambda record:(record['accepted_unix_ms'],record['request_id']))
    # The public harness submits subsequent admissions after a new millisecond,
    # making the actual source order equal across independent random identities.
    assert len({row['accepted_unix_ms'] for row in rows})==len(rows)
    args=request['params']['arguments']
    after=history_argument(args.get('after_id'))
    limit=history_argument(args.get('limit'))
    limit=32 if limit is None else limit
    assert type(limit)is int and 1<=limit<=32
    start=0 if after is None else next(i+1 for i,row in enumerate(rows)if row['request_id']==after)
    page=rows[start:start+limit]
    expected=[{key:row[key]for key in ('accepted_unix_ms','elapsed_ms','request_id','state','tool_name')}for row in page]
    assert content['requests']==expected,('actual History page differs from complete live audit records',frame,content['requests'],expected)
    next_id=page[-1]['request_id'] if start+len(page)<len(rows) else None
    assert content['next_after_id']==next_id
    assert content['retention']=={'global':512,'per_owner':128}
    assert content['history_is_live'] is True and content['automatic_operation_retry'] is False
    inverse={ident:origin for origin,ident in provenance['request_ids'].items()}
    normalized=copy.deepcopy(content)
    for row in normalized['requests']:
        ident=row['request_id'];origin=inverse[ident]
        row['request_id']=q.norm_id(ident,origin,provenance)
        row['accepted_unix_ms']='bound-to-exact-live-audit-record'
        row['elapsed_ms']=None if row['elapsed_ms'] is None else 'bound-to-exact-live-audit-record'
    if next_id is not None:
        normalized['next_after_id']=q.norm_id(next_id,inverse[next_id],provenance)
    projected=q.checked_json(base[:-1])
    projected['result']['content'][0]['text']=q.compact(normalized).decode()
    return value,q.compact(projected)+b'\n'

def request_projection(request,provenance):
    value=read_request_projection(request,provenance)
    if value.get('method')!='tools/call' or value['params']['name']!='request_history':
        return value
    args=value['params']['arguments'];after=history_argument(args.get('after_id'))
    inverse={ident:frame for frame,ident in provenance['request_ids'].items()}
    if isinstance(after,str) and after in inverse:
        replacement=q.norm_id(after,inverse[after],provenance)
        if isinstance(args['after_id'],str):args['after_id']=replacement
        else:args['after_id']['$serde_json::private::RawValue']=q.compact(replacement).decode()
    return value
