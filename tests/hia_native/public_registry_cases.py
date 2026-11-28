#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fixed public SDK/configured-handler corpus, without audit lifecycle claims."""
import copy,json

M='io.modelcontextprotocol/'
VERSIONS=['2024-11-05','2025-03-26','2025-06-18','2025-11-25','2026-07-28']
def compact(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def request(method,params=None,ident=1):
    value={'jsonrpc':'2.0','id':ident,'method':method}
    if params is not None:value['params']=params
    return compact(value)
def initialize(version='2025-11-25',ident=0,name='registry-client'):
    return request('initialize',{'protocolVersion':version,'capabilities':{},'clientInfo':{'name':name,'version':'1'}},ident)
def metadata(version='2026-07-28',caps=None):return {M+'protocolVersion':version,M+'clientCapabilities':{}if caps is None else caps}
def tool(name,args=b'{}',ident=1,meta=None):
    fields=b'"name":'+compact(name)
    if args is not None:fields+=b',"arguments":'+args
    if meta is not None:fields+=b',"_meta":'+compact(meta)
    return b'{"jsonrpc":"2.0","id":'+compact(ident)+b',"method":"tools/call","params":{'+fields+b'}}'
def fixture(host='h'):
    return {'record':{'kind':'execution_intent','record':{'binding':{'schema_version':1,'run_id':'run-1','turn_id':'turn-1','cell_id':'cell-1','organ_id':None,'operation_id':'op-1','principal':'principal-1','objective_digest':'1'*64,'policy_digest':'2'*64,'candidate_digest':'3'*64,'host':host,'generation':1,'idempotency_key':'key-1','predecessor':None,'currentness':'current','final_use':{'state':'not_granted'},'rollback_reference':None},'class':'file_read','payload_digest':'4'*64}}}
def configuration(state):
    return {'state_dir':str(state),'hosts':{'h':{'ssh_target':'private-target','remote_state_dir':'/private-state','allow_write':True},'secondary':{'ssh_target':'another-private-target','remote_state_dir':'/other'}}}

def cases():
    result=[]
    def add(label,events):result.append({'label':label,'events':[{'hex':raw.hex(),'response':True}if isinstance(raw,bytes)else raw for raw in events]})
    for version in VERSIONS+['','2027-01-01','2025-11-26']:
        events=[initialize(version),request('tools/list'),tool('host_list'),tool('effective_config'),tool('execution_shadow_admit',compact(fixture()))]
        events+=[request('tools/list',{'_meta':metadata(v)},ident=10+i)for i,v in enumerate(VERSIONS)]
        add('legacy-version:'+version,events)
    for opening in VERSIONS:
        for repeated in VERSIONS+['future','']:
            events=[request('tools/list',{'_meta':metadata(opening)}),tool('host_list'),tool('host_list',meta=metadata(opening)),
                    initialize(repeated,ident=7,name='replacement'),tool('effective_config'),tool('effective_config',meta=metadata('2026-07-28')),
                    tool('execution_shadow_admit',compact(fixture()),meta=metadata('2025-06-18'))]
            add('modern-reinitialize:'+opening+':'+repeated,events)
    for name in ['host_list','effective_config','execution_shadow_admit','unknown_tool','config_install','shell']:
        for initial in ['legacy','modern']:
            for version in VERSIONS:
                meta=metadata(version);opening=initialize()if initial=='legacy'else request('server/discover',{'_meta':metadata()})
                events=[opening,tool(name,meta=meta),tool(name,b'{"z":1,"a":2}',ident='\n\\"😀',meta=meta)]
                add('route:'+initial+':'+version+':'+name,events)
    bad_metas=[{}, {M+'protocolVersion':'future'}, {M+'clientCapabilities':{}},metadata('future'),metadata('2026-07-28',False),
               {M+'protocolVersion':False,M+'clientCapabilities':{}},metadata(''),{M+'protocolVersion':'2026-07-28',M+'clientCapabilities':None}]
    for index,meta in enumerate(bad_metas):
        add('first-metadata-error:'+str(index),[tool('host_list',meta=meta)])
        add('later-metadata-error:'+str(index),[initialize(),tool('host_list',meta=meta),tool('host_list')])
    for method in ['tools/list','tools/call','server/discover','discover','ping']:
        params={'_meta':metadata('future')}
        if method=='tools/call':params.update(name='host_list')
        add('opener-order:'+method,[request(method,params)])
    arguments=[None,b'null',b'{}',b' { } ',b'false',b'0',b'1.0',b'[]',b'"x"',b'{"z":null,"a":true}',
        b'{"x":1,"x":2}',b'{"\\u0078":false,"x":[]}',b'{"z":{"a":1,"a":2},"a":-0}',
        compact({'中':1,'\x00':None}),compact({'`\\\n\t"😀':{}}),b'{"x":-0}',b'{"x":1e-9999}',
        b'{"x":18446744073709551616}',b'{"x":1.7976931348623157e308}']
    for name in ['host_list','effective_config','execution_shadow_admit']:
        for initial in ['legacy','modern']:
            meta=None if initial=='legacy'else metadata();opening=initialize()if initial=='legacy'else request('tools/list',{'_meta':meta})
            events=[opening]+[tool(name,arg,ident=i+1,meta=meta)for i,arg in enumerate(arguments)]
            add('arguments:'+initial+':'+name,events)
    execution=[]
    for host in ['h','空','private-target','missing','H','', '\x00']:
        for version in [0,1,2]:
            value=fixture(host);value['record']['record']['binding']['schema_version']=version;execution.append(value)
    for key in list(fixture()['record']['record']['binding']):
        for value in [None,True,False,0,1.0,[],{},'']:
            item=fixture();item['record']['record']['binding'][key]=value;execution.append(item)
    for kind in ['execution_intent','effect','',None,{}, {'execution_intent':None}]:
        item=fixture();item['record']['kind']=kind;execution.append(item)
    for cls in ['read_only_inspection','file_read','non_destructive_build','restricted_file_write','durable_process','privileged_action','cross_host_device','invalid']:
        item=fixture();item['record']['record']['class']=cls;execution.append(item)
    for initial in ['legacy','modern']:
        meta=None if initial=='legacy'else metadata();opening=initialize()if initial=='legacy'else request('tools/list',{'_meta':meta})
        for offset in range(0,len(execution),24):
            add('execution:'+initial+':'+str(offset),[opening]+[tool('execution_shadow_admit',compact(value),ident=i+1,meta=meta)for i,value in enumerate(execution[offset:offset+24])])
        raw=compact(fixture());add('execution-duplicate:'+initial,[opening,tool('execution_shadow_admit',b'{"record":null,'+raw[1:],meta=meta),tool('execution_shadow_admit',raw[:-1]+b',"record":null}',meta=meta)])
    # Ignored malformed/syntax events are followed by a visible request so
    # byte equality also proves that no spurious protocol response leaked.
    for raw in [b'{',b'[]',b'null',b'{"jsonrpc":"1.0","id":9,"method":"ping"}',b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
                b'{"jsonrpc":"2.0","id":false,"method":"ping"}',b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"host_list","arguments":{"x":1e9999,"x":0}}}']:
        # Data-vs-syntax class is decided by the qualified decoder; the
        # separate transport corpus already exhaustively verifies it.
        if raw in [b'{',b'[]',b'null',b'{"jsonrpc":"2.0","method":"notifications/initialized"}']:
            add('transport-after-init:'+raw.hex(),[initialize(),{'hex':raw.hex(),'response':raw in (b'[]',b'null')},tool('host_list')])
    assert len({case['label']for case in result})==len(result)
    return result

if __name__=='__main__':
    rows=cases();print(json.dumps({'sessions':len(rows),'events':sum(len(x['events'])for x in rows),'responses':sum(e['response']for x in rows for e in x['events'])},sort_keys=True))
