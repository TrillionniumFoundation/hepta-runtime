# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Normal six-tool requests; Health targets are absent from installed configuration."""
import copy
import json

TOKEN = '$serde_json::private::RawValue'
CASES = [
    ('__catalog__', {}, 'six-tools-catalog', 'catalog'),
    ('host_list', {}, 'retain-host-list', 'success'),
    ('request_status', {'request_id': '$id'}, 'owned-status', 'success'),
    ('request_result', {'request_id': '$id'}, 'owned-result', 'success'),
    ('request_result', {'request_id': '$id', 'offset': '$bytes', 'limit': 1}, 'empty-final-page', 'success'),
    ('request_result', {'request_id': '$id', 'offset': 0, 'limit': 37}, 'first-small-page', 'success'),
    ('request_result', {'request_id': '$id', 'offset': '$tail100', 'limit': 100}, 'identity-tail-page', 'success'),
    ('request_status', {}, 'missing-id', 'typed_error'),
    ('request_status', {'request_id': False}, 'boolean-id', 'typed_error'),
    ('request_status', {'request_id': 1.5}, 'float-id', 'typed_error'),
    ('request_status', {'request_id': None}, 'null-id', 'typed_error'),
    ('request_status', {'request_id': []}, 'array-id', 'typed_error'),
    ('request_status', {'request_id': '$id', 'unknown': 1}, 'unknown-status-field', 'typed_error'),
    ('request_result', {'request_id': '$id', 'offset': -1}, 'negative-offset', 'typed_error'),
    ('request_result', {'request_id': '$id', 'offset': 4294967296}, 'wide-offset', 'typed_error'),
    ('request_result', {'request_id': '$id', 'limit': 65536}, 'wide-limit', 'typed_error'),
    ('request_result', {'request_id': '$id', 'limit': 1.5}, 'float-limit', 'typed_error'),
    ('request_result', {'request_id': '$id', 'extra': None}, 'unknown-result-field', 'typed_error'),
    ('request_result', {'request_id': '$id', 'limit': 0}, 'business-zero-limit', 'business_error'),
    ('request_result', {'request_id': '$id', 'limit': 16385}, 'business-large-limit', 'business_error'),
    ('request_result', {'request_id': '$id', 'offset': '$after'}, 'business-offset-after-end', 'business_error'),
    ('request_status', {'request_id': 'not-an-id'}, 'outer-async-invalid-id', 'invalid_id'),
    ('request_status', {'request_id': 'f' * 64}, 'outer-audit-unavailable-id', 'unavailable'),
    ('request_status', {TOKEN: '0', 'request_id': '$id'}, 'top-arguments-rawvalue-is-ordinary-key', 'typed_error'),
    ('request_status', {'request_id': {'$raw_id': True}}, 'nested-value-rawvalue-string', 'success'),
    ('request_status', {'request_id': {TOKEN: 'null'}}, 'nested-value-rawvalue-null', 'typed_error'),
    ('request_status', {'request_id': '$id'}, 'recovery-after-errors', 'success'),
    ('host_health', {}, 'health-missing-host', 'typed_error'),
    ('host_health', {'host': False}, 'health-boolean-host', 'typed_error'),
    ('host_health', {'host': 1.5}, 'health-float-host', 'typed_error'),
    ('host_health', {'host': 'not-configured', 'extra': True}, 'health-unknown-field', 'typed_error'),
    ('host_health', {'host': 'not-configured'}, 'health-unknown-host', 'business_error'),
    ('host_health', {TOKEN: '0', 'host': 'not-configured'}, 'health-top-arguments-rawvalue', 'typed_error'),
    ('host_health', {'host': {TOKEN: '"not-configured"'}}, 'health-nested-rawvalue-host', 'business_error'),
    ('effective_config', {}, 'effective-config-after-health-errors', 'success'),
    ('execution_shadow_admit', {}, 'shadow-missing-record', 'typed_error'),
    ('request_status', {'request_id': '$id'}, 'unified-recovery-after-errors', 'success'),
]


def materialize(template, ident, payload_bytes):
    if template == '$id':
        assert isinstance(ident, str) and len(ident) == 64
        return ident
    if template == '$bytes':
        return payload_bytes
    if template == '$after':
        return payload_bytes + 1
    if template == '$tail100':
        assert payload_bytes >= 100
        return payload_bytes - 100
    if isinstance(template, dict):
        if template == {'$raw_id': True}:
            assert isinstance(ident, str) and len(ident) == 64
            return {TOKEN: json.dumps(ident, ensure_ascii=False, separators=(',', ':'))}
        return {key: materialize(value, ident, payload_bytes) for key, value in template.items()}
    if isinstance(template, list):
        return [materialize(value, ident, payload_bytes) for value in template]
    return copy.deepcopy(template)

# Added public History cases do not replace any of the 37 retained Read/Health cases.
RETAINED_CASES=CASES
HISTORY_PREFIX=[
 ('request_history',{},'history-empty-before-any-ticket','success'),
 ('request_history',{'after_id':None,'limit':None},'history-null-options','success'),
 ('request_history',{'limit':False},'history-boolean-limit','typed_error'),
 ('request_history',{'limit':-1},'history-negative-limit','typed_error'),
 ('request_history',{'limit':65536},'history-wide-limit','typed_error'),
 ('request_history',{'limit':1.5},'history-float-limit','typed_error'),
 ('request_history',{'limit':[]},'history-array-limit','typed_error'),
 ('request_history',{'after_id':False},'history-boolean-cursor','typed_error'),
 ('request_history',{'after_id':7},'history-number-cursor','typed_error'),
 ('request_history',{'after_id':[]},'history-array-cursor','typed_error'),
 ('request_history',{'unknown':None},'history-unknown-field','typed_error'),
 ('request_history',{'limit':0},'history-zero-page','business_error'),
 ('request_history',{'limit':33},'history-large-page','business_error'),
 ('request_history',{'limit':65535},'history-max-u16-page','business_error'),
 ('request_history',{'after_id':'bad'},'history-invalid-cursor','business_error'),
 ('request_history',{'after_id':'x'*8192},'history-full-long-cursor','business_error'),
 ('request_history',{'after_id':'\U0001d11e'*256},'history-full-unicode-cursor','business_error'),
 ('request_history',{'after_id':'f'*64},'history-unknown-cursor','cursor_error'),
 ('request_history',{TOKEN:'0'},'history-top-rawvalue-is-unknown-field','typed_error'),
 ('request_history',{'after_id':{TOKEN:'null'}},'history-nested-rawvalue-null','success'),
 ('request_history',{'after_id':{TOKEN:'"bad"'}},'history-nested-rawvalue-cursor','business_error'),
 ('request_history',{'limit':{TOKEN:'2'}},'history-nested-rawvalue-limit','success'),
]
HISTORY_SUFFIX=[
 ('request_history',{},'history-default-page-of-actual-admissions','success'),
 ('request_history',{'limit':1},'history-first-record-page','success'),
 ('request_history',{'after_id':'$id','limit':2},'history-after-first-owned-record','success'),
 ('request_history',{'after_id':{'$raw_history_id':True},'limit':2},'history-nested-rawvalue-owned-cursor','success'),
 ('request_history',{'limit':32},'history-page-with-real-next-cursor','success'),
 ('request_history',{'after_id':'$cursor','limit':32},'history-final-page-with-real-cursor','success'),
 ('request_history',{'after_id':'$latest','limit':1},'history-empty-page-after-last','success'),
 ('request_history',{'after_id':'f'*64},'history-unknown-cursor-after-admissions','cursor_error'),
 ('request_history',{},'history-repeat-does-not-admit-itself','success'),
 ('request_status',{'request_id':'$id'},'read-still-works-after-history','success'),
 ('request_history',{'after_id':'$latest'},'history-new-read-is-visible','success'),
 ('__catalog__',{},'seven-tools-final-catalog','catalog'),
]
CASES=[RETAINED_CASES[0],*HISTORY_PREFIX,*RETAINED_CASES[1:],*HISTORY_SUFFIX]
RETAINED_MATERIALIZE=materialize
def materialize(template,ident,payload_bytes,last_id=None,page_cursor=None):
    if template=='$latest':
        assert isinstance(last_id,str) and len(last_id)==64
        return last_id
    if template=='$cursor':
        assert isinstance(page_cursor,str) and len(page_cursor)==64
        return page_cursor
    if isinstance(template,dict):
        if template=={'$raw_history_id':True}:
            assert isinstance(ident,str) and len(ident)==64
            return {TOKEN:json.dumps(ident,separators=(',',':'))}
        if template=={'$raw_id':True}:return RETAINED_MATERIALIZE(template,ident,payload_bytes)
        return {key:materialize(value,ident,payload_bytes,last_id,page_cursor)for key,value in template.items()}
    if isinstance(template,list):
        return [materialize(value,ident,payload_bytes,last_id,page_cursor)for value in template]
    return RETAINED_MATERIALIZE(template,ident,payload_bytes)

# Public Start/Cancel admission and typed failures: no successful producer spawn.
ASYNC_PREFLIGHT_CASES = [
 ('request_start', {}, 'start-missing-both-fields', 'typed_error'),
 ('request_start', {'operation': {'tool':'host_list','arguments':{}}}, 'start-missing-key', 'typed_error'),
 ('request_start', {'idempotency_key':'key'}, 'start-missing-operation', 'typed_error'),
 ('request_start', {'operation':None,'idempotency_key':'key'}, 'start-null-operation', 'typed_error'),
 ('request_start', {'operation':[],'idempotency_key':'key'}, 'start-array-operation', 'typed_error'),
 ('request_start', {'operation':'host_list','idempotency_key':'key'}, 'start-string-operation', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_list','arguments':{}},'idempotency_key':False}, 'start-boolean-key', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_list','arguments':{}},'idempotency_key':1.5}, 'start-float-key', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_list','arguments':{}},'idempotency_key':None}, 'start-null-key', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_list','arguments':{}},'idempotency_key':[]}, 'start-array-key', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_list','arguments':{}},'idempotency_key':{},'extra':1}, 'start-object-key-before-unknown', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_list','arguments':{}},'idempotency_key':'key','extra':1}, 'start-unknown-field', 'typed_error'),
 ('request_start', {'operation':{'tool':'file_info','arguments':{}},'idempotency_key':'key'}, 'start-tool-outside-typed-whitelist', 'typed_error'),
 ('request_start', {'operation':{'arguments':{}},'idempotency_key':'key'}, 'start-missing-tool', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_list'},'idempotency_key':'key'}, 'start-missing-arguments', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_list','arguments':{'extra':1}},'idempotency_key':'key'}, 'start-host-list-unknown-field', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_health','arguments':{}},'idempotency_key':'key'}, 'start-health-missing-host', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_health','arguments':{'host':False}},'idempotency_key':'key'}, 'start-health-boolean-host', 'typed_error'),
 ('request_start', {'operation':{'tool':'effective_config','arguments':{'extra':1}},'idempotency_key':'key'}, 'start-effective-config-unknown-field', 'typed_error'),
 ('request_start', {TOKEN:'0','operation':{'tool':'host_list','arguments':{}},'idempotency_key':'key'}, 'start-top-map-rawvalue-is-unknown-field', 'typed_error'),
 ('request_start', {'operation':{TOKEN:'null'},'idempotency_key':'key'}, 'start-nested-rawvalue-null-operation', 'typed_error'),
 ('request_start', {'operation':{'tool':'host_list','arguments':{}},'idempotency_key':''}, 'start-empty-key-business-refusal', 'business_error'),
 ('request_start', {'operation':{'tool':'host_list','arguments':{}},'idempotency_key':'bad\u0000key'}, 'start-control-key-business-refusal', 'business_error'),
 ('request_start', {'operation':{'tool':'host_health','arguments':{'host':'not-configured'}},'idempotency_key':'unknown-host'}, 'start-unconfigured-host-business-refusal', 'business_error'),
 ('request_cancel', {}, 'cancel-missing-id', 'typed_error'),
 ('request_cancel', {'request_id':False}, 'cancel-boolean-id', 'typed_error'),
 ('request_cancel', {'request_id':1.5}, 'cancel-float-id', 'typed_error'),
 ('request_cancel', {'request_id':None}, 'cancel-null-id', 'typed_error'),
 ('request_cancel', {'request_id':[]}, 'cancel-array-id', 'typed_error'),
 ('request_cancel', {'request_id':'f'*64,'extra':1}, 'cancel-unknown-field', 'typed_error'),
 ('request_cancel', {TOKEN:'0','request_id':'f'*64}, 'cancel-top-map-rawvalue-is-unknown-field', 'typed_error'),
 ('request_cancel', {'request_id':{TOKEN:'null'}}, 'cancel-nested-rawvalue-null-id', 'typed_error'),
 ('request_cancel', {'request_id':'not-an-id'}, 'cancel-invalid-id-business-refusal', 'business_error'),
 ('request_cancel', {'request_id':'f'*64}, 'cancel-missing-retained-binding', 'business_error'),
 ('host_list', {}, 'host-list-recovery-after-start-cancel', 'success'),
 ('request_status', {'request_id':'$id'}, 'read-recovery-after-start-cancel', 'success'),
 ('__catalog__', {}, 'nine-tool-catalog-after-start-cancel', 'catalog'),
]
CASES = [*CASES, *ASYNC_PREFLIGHT_CASES]
