"""Deterministic typed records and scripted private child results."""
import json,struct,random,itertools
ID='a'*64;OWNER='b'*64
STATES=('unknown','completed','failed')
def record(index=None,**changes):
    r=dict(request_id=ID if index is None else f'{index:064x}',owner=OWNER,tool_name='h_file_read',state='unknown',accepted_unix_ms=1,elapsed_ms=None)
    r.update(changes);return r
def projection(r):
    raw=bytearray(256);raw[:8]=b'HRAJJ001';n=r['accepted_unix_ms'];e=r['elapsed_ms']
    struct.pack_into('<7Q',raw,8,1,int(e is not None),n&((1<<64)-1),n>>64,STATES.index(r['state']),e or 0,0)
    for slot,key in enumerate(('request_id','owner','tool_name')):
        b=r[key].encode();struct.pack_into('<2Q',raw,64+slot*16,len(raw),len(b));raw.extend(b)
    return bytes(raw)
def reply(r=None,*,value=0,diagnostic=0,error=0,not_found=False):
    raw=b'' if r is None else projection(r)
    return b'HRAKC001'+struct.pack('<5Q',diagnostic,error,int(not_found),len(raw) if raw else value,0)+raw
def effect(kind,argument,returned,flags=0):
    if isinstance(argument,str):argument=argument.encode()
    return dict(kind=kind,argument_hex=argument.hex(),flags=int(flags),reply_hex=returned.hex())
def row(name,operation,primary=None,records=None,pending=None,owner='',id='',sync=False,effects=None):
    return dict(name=name,operation=operation,primary=primary,records=records or [],pending=pending or [],owner=owner,id=id,sync=sync,effects=effects or [])
def request(c):
    primary=b'' if c['primary'] is None else projection(c['primary']);owner=c['owner'].encode();identifier=c['id'].encode()
    raw=bytearray(b'HRAKQ001'+struct.pack('<7Q',c['operation'],int(c['sync']),len(primary),len(c['records']),len(c['pending']),len(owner),len(identifier))+primary)
    for r in c['records']:
        b=projection(r);raw.extend(struct.pack('<Q',len(b))+b)
    for name in c['pending']:
        b=name.encode();raw.extend(struct.pack('<Q',len(b))+b)
    raw.extend(owner+identifier);return bytes(raw)
def paired(name,operation,old,archived):
    r=row(name,operation,primary=None if operation==1 else old,id=old['request_id'] if operation==1 else '')
    if operation==1:r['effects'].append(effect(100,old['request_id']+'.json',reply(old)))
    r['effects'].append(effect(101,old['request_id']+'.json',reply(archived)));return r
def retained(name,records,pending=(),sync=False,owner=OWNER):
    r=row(name,4,records=records,pending=list(pending),owner=owner,sync=sync)
    for item in records:
        r['effects'].extend([effect(102,item['request_id'],reply(value=0)),effect(101,item['request_id']+'.json',reply(item)),effect(103,projection(item),reply(),sync)])
    return r
def replace_reply(c,kind,argument,returned):
    if isinstance(argument,str):argument=argument.encode()
    matches=[e for e in c['effects'] if e['kind']==kind and e['argument_hex']==argument.hex()];assert len(matches)==1
    matches[0]['reply_hex']=returned.hex();return c

def cases():
    stamps=(0,1,(1<<64)-1,1<<64,(1<<128)-1)
    values=(None,0,1,(1<<64)-1)
    for index,(old_state,new_state,old_time,new_time) in enumerate(itertools.product(STATES,STATES,values,values)):
        old=record(state=old_state,elapsed_ms=old_time,accepted_unix_ms=stamps[index%len(stamps)])
        new=dict(old,state=new_state,elapsed_ms=new_time)
        for operation in (1,2,3):yield paired(f'state-elapsed-{operation}-{index}',operation,old,new)
    variants=[('owner','c'*64),('owner',''),('owner','汉字'),('owner','\0'),('tool_name','h_file_write'),('tool_name',''),('tool_name','汉😀'),('tool_name','\0'),('accepted_unix_ms',0),('accepted_unix_ms',1<<64),('accepted_unix_ms',(1<<128)-1)]
    for index,(key,value) in enumerate(variants):
        for operation in (1,2,3):yield paired(f'identity-{operation}-{index}',operation,record(),record(**{key:value}))
    errors=[reply(diagnostic=23,error=2,not_found=True),reply(diagnostic=23,not_found=True),reply(diagnostic=23,error=13),reply(diagnostic=23,error=5),reply(diagnostic=24),reply(diagnostic=25),reply(diagnostic=33),reply(diagnostic=500)]
    options=[reply(record()),*errors]
    for left,hot in enumerate(options):
        for right,archive in enumerate(options):
            yield row(f'read-results-{left}-{right}',1,id=ID,effects=[effect(100,ID+'.json',hot),effect(101,ID+'.json',archive)])
    for operation in (2,3):
        for index,error in enumerate(errors):yield row(f'archive-error-{operation}-{index}',operation,primary=record(),effects=[effect(101,ID+'.json',error)])
    rng=random.Random(0x41555254)
    for index in range(128):
        old=record(accepted_unix_ms=rng.getrandbits(128),state=STATES[index%3],elapsed_ms=None if index%4==0 else rng.getrandbits(64))
        new=dict(old,state=STATES[(index//3)%3],elapsed_ms=None if index%5==0 else rng.getrandbits(64))
        if index%7==0:new['accepted_unix_ms']=rng.getrandbits(128)
        for operation in (1,2,3):yield paired(f'random-{operation}-{index}',operation,old,new)
    for count in (0,1,127,128,129,511,512):
        yield retained('owner-count-'+str(count),[record(i) for i in range(count)])
    for sync in (False,True):
        yield retained('global-count-'+str(sync),[record(i,owner=f'{i+1024:064x}') for i in range(512)],sync=sync)
        yield retained('owner-sync-'+str(sync),[record(i) for i in range(128)],sync=sync)
    records=[record(i) for i in range(128)]
    yield retained('all-pending',records,[r['request_id'] for r in records])
    c=retained('all-active',records)
    for r in records:replace_reply(c,102,r['request_id'],reply(value=1))
    yield c
    c=retained('all-archive-errors',records)
    for index,r in enumerate(records):replace_reply(c,101,r['request_id']+'.json',errors[index%len(errors)])
    yield c
    c=retained('all-archive-incompatible',records)
    for r in records:replace_reply(c,101,r['request_id']+'.json',reply(dict(r,owner='c'*64)))
    yield c
    c=retained('last-eligible',records,[r['request_id'] for r in records[:32]])
    for index,r in enumerate(records):
        if 32<=index<64:replace_reply(c,102,r['request_id'],reply(value=1))
        elif 64<=index<96:replace_reply(c,101,r['request_id']+'.json',errors[index%len(errors)])
        elif 96<=index<127:replace_reply(c,101,r['request_id']+'.json',reply(dict(r,accepted_unix_ms=1<<64)))
    yield c
    c=retained('pending-skips-active-error',records,[records[0]['request_id']]);replace_reply(c,102,records[0]['request_id'],reply(diagnostic=38));yield c
    mixed=[record(i,owner='c'*64 if i<64 else OWNER) for i in range(192)];c=retained('other-owner-skips-active-error',mixed)
    for r in mixed[:64]:replace_reply(c,102,r['request_id'],reply(diagnostic=38))
    yield c
    for sync in (False,True):
        for target in (0,1):
            for kind in (102,103):
                c=retained(f'partial-error-{sync}-{target}-{kind}',[record(i) for i in range(129)],sync=sync)
                r=c['records'][target];argument=r['request_id'] if kind==102 else projection(r)
                replace_reply(c,kind,argument,reply(diagnostic=38 if kind==102 else 23,error=0 if kind==102 else 5));yield c
    global_records=[record(i,owner=f'{i+1024:064x}') for i in range(512)]
    yield retained('global-all-pending',global_records,[r['request_id'] for r in global_records])
    c=retained('global-last-eligible',global_records)
    for r in global_records[:-1]:replace_reply(c,102,r['request_id'],reply(value=1))
    yield c
