"""Input construction only; no JSON/number/authorization comparison oracle."""
import copy,itertools,json

def compact(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def fixture(host='h'):
    return {'record':{'kind':'execution_intent','record':{'binding':{'schema_version':1,'run_id':'run-1','turn_id':'turn-1','cell_id':'cell-1','organ_id':None,'operation_id':'op-1','principal':'principal-1','objective_digest':'1'*64,'policy_digest':'2'*64,'candidate_digest':'3'*64,'host':host,'generation':1,'idempotency_key':'key-1','predecessor':None,'currentness':'current','final_use':{'state':'not_granted'},'rollback_reference':None},'class':'file_read','payload_digest':'4'*64}}}
def wire(name,args,ident):
    out=b'{"jsonrpc":"2.0","id":'+compact(ident)+b',"method":"tools/call","params":{"name":'+compact(name)
    if args is not None:out+=b',"arguments":'+args
    return out+b'}}'

def arguments():
    for name in ['host_list','effective_config']:
        for raw in [None,b'null',b'{}',b' { } ',b'{"z":null,"a":true}',b'{"x":1,"x":2}',b'{"\\u0078":false,"x":[]}',b'{"z":{"d":0,"d":1},"a":-0}']:
            yield 'empty-or-unknown',name,raw
        for cp in list(range(128))+[0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x2028,0x2029,0x10ffff]:
            yield 'unknown-unicode-key',name,compact({chr(cp):{'nested':[None,True,False,1]}})
        for token in [b'-0',b'1e-9999',b'0e999999',b'18446744073709551615',b'18446744073709551616',b'-9223372036854775809',b'1.7976931348623157e308',b'5e-324',b'1e15',b'1e16']:
            yield 'exact-number-value',name,b'{"x":'+token+b'}'
        yield 'above-old-arena',name,b'{"x":['+b','.join([b'0']*300000)+b']}'
    name='execution_shadow_admit';base=fixture();values=[None,False,True,0,1,-1,2**32,2**64-1,1.0,0.5,'','bad',[],{},[None],{'x':None}]
    for raw in [None,b'null',b'{}',compact(base),b'{"record":null,'+compact(base)[1:],compact(base)[:-1]+b',"record":null}',b'{"\\u0072ecord":null,'+compact(base)[1:]]:
        yield 'execution-root',name,raw
    paths=[(),('record',),('record','record'),('record','record','binding'),('record','record','binding','final_use')]
    for path in paths:
        target=base
        for key in path:target=target[key]
        for key in target:
            changed=copy.deepcopy(base);node=changed
            for part in path:node=node[part]
            del node[key];yield 'missing-field',name,compact(changed)
            for value in values:
                changed=copy.deepcopy(base);node=changed
                for part in path:node=node[part]
                node[key]=value;yield 'typed-field',name,compact(changed)
        for unknown in ['', 'extra','\x00','执行']:
            if unknown not in target:
                changed=copy.deepcopy(base);node=changed
                for part in path:node=node[part]
                node[unknown]=None;yield 'typed-unknown',name,compact(changed)
    for cls,options,current in itertools.product(['read_only_inspection','file_read','non_destructive_build','restricted_file_write','durable_process','privileged_action','cross_host_device'],range(16),['current','stale','unknown']):
        changed=fixture();body=changed['record']['record'];body['class']=cls;b=body['binding'];b['currentness']=current
        for field,mask in [('cell_id',1),('organ_id',2),('predecessor',4),('rollback_reference',8)]:b[field]='bound' if options&mask else None
        yield 'execution-options',name,compact(changed)
    for host in ['h','private-target','missing','H','','中','x'*257]:
        for schema in [0,1]:
            changed=fixture(host);changed['record']['record']['binding']['schema_version']=schema;yield 'host-order',name,compact(changed)
    for field in ['schema_version','generation']:
        raw=compact(base);marker=compact(field)+b':1'
        for token in [b'-0',b'1.0',b'1e0',b'0.0',b'-0.0',b'1e-99999',b'4294967295',b'4294967296',b'18446744073709551615',b'18446744073709551616']:
            yield 'typed-number-class',name,raw.replace(marker,compact(field)+b':'+token,1)
    # Real Value expansion crosses the old 8 MiB child input capacity. JSON7
    # receives the complete canonical bytes, not a truncated object projection.
    yield 'canonical-above-eight-mib',name,b'{"extra":['+b','.join([b'1e15']*550000)+b']}'
    changed=fixture();changed['record']['record']['binding']['operation_id']=''
    overhead=len(wire(name,compact(changed),999999))
    changed['record']['record']['binding']['operation_id']='x'*((8<<20)-overhead)
    yield 'exact-eight-mib-mcp',name,compact(changed)

def cases():
    for index,(label,name,args) in enumerate(arguments(),1):
        ident=999999 if label=='exact-eight-mib-mcp' else index
        raw=wire(name,args,ident)
        if label=='exact-eight-mib-mcp':assert len(raw)==8<<20
        assert len(raw)<=8<<20
        yield label,raw
