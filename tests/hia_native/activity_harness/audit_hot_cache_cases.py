"""Fixed scenario inputs and explicit child transcripts; no host cache implementation."""
import copy
import struct

U64 = (1 << 64) - 1
def record(index=0, **changes):
    value=dict(request_id=f'{index:064x}',owner='owner',tool_name='tool',
        accepted_unix_ms=(index << 65) + index,state='unknown',elapsed_ms=None)
    value.update(changes)
    return value

def projection(value):
    raw=bytearray(256);raw[:8]=b'HRAJJ001'
    timestamp=value['accepted_unix_ms']
    struct.pack_into('<6Q',raw,8,1,int(value['elapsed_ms'] is not None),
        timestamp & U64,timestamp >> 64,{'unknown':0,'completed':1,'failed':2}[value['state']],
        value['elapsed_ms'] or 0)
    for slot,key in enumerate(('request_id','owner','tool_name')):
        encoded=value[key].encode('utf-8')
        struct.pack_into('<2Q',raw,64+slot*16,len(raw),len(encoded));raw.extend(encoded)
    assert 256 <= len(raw) <= 512
    return bytes(raw)

def records_wire(values):
    return b''.join(struct.pack('<Q',len(raw))+raw for raw in map(projection,values))

def stamp(device=1,inode=10,version=1,kind=1,modified=(31,17),changed=(43,19),first=7,digest=None):
    raw=bytearray(112);raw[:8]=b'HRAST001'
    if kind==1:
        watch=(first,version);fingerprint=bytes(32)
    else:
        watch=(0,0);fingerprint=bytes([version & 255])*32 if digest is None else digest
    struct.pack_into('<QQ4q3Q',raw,8,device,inode,*modified,*changed,kind,*watch)
    assert len(fingerprint)==32;raw[80:112]=fingerprint
    return bytes(raw)

def reply(value=0,payload=b'',diagnostic=0,errno=0,error_kind=0):
    return struct.pack('<8s5Q',b'HRACC001',diagnostic,errno,error_kind,value,0)+payload

def effect(kind,argument,answer,flags=0):
    return dict(kind=kind,argument_hex=argument.hex(),flags=flags,reply_hex=answer.hex())

def stamped(value,directory=11):
    return effect(100,struct.pack('<Q',directory),reply(112,value))

def listed(records,directory=11):
    return effect(101,struct.pack('<Q',directory),reply(len(records),records_wire(records)))

def seeded(records,exists=0,archive=23):
    result=[]
    for index,value in enumerate(records):
        present=1 if exists==1 or (exists==2 and index%2==0) else 0
        result.append(effect(102,struct.pack('<Q',archive)+value['request_id'].encode()+b'.json',reply(present)))
        if not present:
            result.append(effect(103,struct.pack('<Q',archive)+projection(value),reply(),2))
    return result

def step(operation,records=(),directory=11,archive=0,consume=False,before=None,effects=()):
    if operation in (0,5):directory=0
    return dict(operation=operation,directory=directory,archive=archive,consume=bool(consume),
        records=list(records),before_stamp_hex='' if before is None else before.hex(),effects=list(effects))

def put(value,records,directory=11):
    return step(1,records,directory=directory,effects=[stamped(value,directory)])

def query(value,directory=11):
    return step(2,directory=directory,effects=[stamped(value,directory)])

def hit(value,consume=False,directory=11,archive=23):
    return step(3,directory=directory,archive=archive,consume=consume,effects=[stamped(value,directory)])

def cold(value,records,consume=False,exists=0,directory=11,archive=23,final_stamp=None):
    effects=[stamped(value,directory),listed(records,directory),stamped(value,directory)]
    effects.extend(seeded(records,exists,archive))
    if not consume:effects.append(stamped(value if final_stamp is None else final_stamp,directory))
    return step(3,directory=directory,archive=archive,consume=consume,effects=effects)

def request(command):
    before=bytes.fromhex(command['before_stamp_hex']);records=command['records']
    return struct.pack('<8s7Q',b'HRACQ001',command['operation'],command['directory'],
        command['archive'],int(command['consume']),len(records),len(before),0)+before+records_wire(records)

def case(name,steps):
    values=copy.deepcopy(steps)
    for index,value in enumerate(values):value['name']=str(index)
    return dict(name=name,steps=values)

def cases():
    a=stamp();b=stamp(version=2);c=stamp(version=3);d=stamp(version=4)
    yield case('initial-observation',[step(0),query(a),step(0),query(b),step(0)])
    failure=effect(100,struct.pack('<Q',11),reply(diagnostic=23,errno=5))
    yield case('initial-stamp-error',[step(2,effects=[failure]),step(0),query(a)])
    for kind in (1,2):
        value=stamp(kind=kind)
        for count in (0,1,2,33,512):
            values=[record(i,state=('unknown','completed','failed')[i%3],elapsed_ms=None if i%2 else i) for i in range(count)]
            for consume in (False,True):
                steps=[put(value,values),query(value),hit(value,consume),step(0)]
                if not consume:steps.extend([hit(value,True),step(0)])
                steps.append(query(value))
                yield case(f'cache-hit-{kind}-{count}-{consume}',steps)
    for count in (0,1,3,33,512):
        values=[record(i) for i in range(count)]
        for consume in (False,True):
            for exists in (0,1,2):
                yield case(f'cold-seed-{count}-{consume}-{exists}',
                    [cold(a,values,consume,exists),query(a),step(0)])
    fields=[
        stamp(device=2),stamp(inode=11),stamp(modified=(-1,17)),stamp(modified=(31,-1)),
        stamp(changed=(-2,19)),stamp(changed=(43,-2)),stamp(first=8),stamp(version=2),
        stamp(kind=2),stamp(modified=(-(1<<63),(1<<63)-1)),
    ]
    for index,other in enumerate(fields):
        yield case(f'stamp-field-{index}',[put(a,[record(1)]),query(other),query(a)])
    fingerprint=stamp(kind=2,digest=bytes(32))
    for index in range(32):
        changed=bytearray(32);changed[index]=1
        yield case(f'fingerprint-byte-{index}',[put(fingerprint,[record(1)]),
            query(stamp(kind=2,digest=bytes(changed))),query(fingerprint)])
    values=[stamp(inode=i) for i in range(20)]
    steps=[put(value,[record(i)]) for i,value in enumerate(values[:16])]
    steps.extend([query(values[0]),put(values[16],[record(16)]),query(values[0]),query(values[1]),query(values[16])])
    yield case('fifo-hit-does-not-promote',steps)
    steps=[put(value,[record(i)]) for i,value in enumerate(values[:16])]
    changed=stamp(inode=7,version=99)
    steps.extend([put(changed,[record(99)]),query(values[7]),query(changed),put(values[16],[record(16)]),
        query(values[0]),query(values[1]),query(changed)])
    yield case('replace-identity-retains-sixteen',steps)
    steps=[put(value,[record(i)]) for i,value in enumerate(values[:16])]
    steps.extend([hit(values[8],True),put(values[16],[record(16)]),query(values[0]),query(values[8]),
        put(values[17],[record(17)]),query(values[0]),query(values[1])])
    yield case('consume-middle-preserves-order',steps)
    for state in ('unknown','completed','failed'):
        for elapsed in (None,0,U64):
            changed=record(5,owner='changed-owner',tool_name='changed-tool',accepted_unix_ms=(1<<128)-1,
                state=state,elapsed_ms=elapsed)
            yield case(f'completion-{state}-{elapsed}',[put(a,[record(5),record(6)]),
                step(4,[changed],before=a,effects=[stamped(b)]),query(a),query(b),hit(b),hit(b,True)])
    for identity in ('','a\x00b','审计-💫','x'*256):
        current=record(1,request_id=identity,owner='',tool_name='')
        updated=record(2,request_id=identity,owner='',tool_name='',state='completed',elapsed_ms=0)
        yield case(f'completion-id-{identity.encode().hex()}',[put(a,[current,current]),
            step(4,[updated],before=a,effects=[stamped(b)]),hit(b,True)])
    yield case('completion-no-matching-id',[put(a,[record(1)]),
        step(4,[record(2)],before=a,effects=[stamped(b)]),query(a),query(b),hit(a)])
    yield case('completion-no-matching-stamp',[put(a,[record(1)]),
        step(4,[record(1)],before=c,effects=[stamped(b)]),query(a),query(b),hit(a)])
    yield case('completion-initializes-empty',[step(4,[record(1)],before=a,effects=[stamped(b)]),step(0),query(b)])
    for consume in (False,True):
        for changes in range(4):
            stamps=[a,b,c,d]
            effects=[stamped(a)]
            for index in range(min(changes+1,3)):
                records=[record(20+index)]
                after=stamps[index+1] if index<changes else stamps[index]
                effects.extend([listed(records),stamped(after)])
            if changes<3:
                effects.extend(seeded(records))
                if not consume:effects.append(stamped(d))
            command=step(3,archive=23,consume=consume,effects=effects)
            yield case(f'validation-retries-{consume}-{changes}',[command,step(0),query(d)])
    for consume in (False,True):
        complete=cold(b,[record(1),record(2),record(3)],consume=consume)
        for at in range(len(complete['effects'])):
            for diagnostic,errno,kind in ((23,2,1),(23,5,0),(29,0,0)):
                command=copy.deepcopy(complete)
                command['effects']=command['effects'][:at+1]
                command['effects'][-1]['reply_hex']=reply(diagnostic=diagnostic,errno=errno,error_kind=kind).hex()
                yield case(f'child-error-{consume}-{at}-{diagnostic}-{errno}',
                    [put(a,[record(99)]),command,query(a),query(b),step(0)])
    for operation in (1,2,3,4):
        for populated in (False,True):
            for failed_stamp in (False,True):
                commands=[put(a,[record(1)])] if populated else []
                commands.append(step(5))
                command=step(operation,records=[record(1)] if operation in (1,4) else [],
                    before=a if operation==4 else None,archive=23 if operation==3 else 0,
                    effects=[failure if failed_stamp else stamped(a)])
                commands.extend([command,step(0)])
                yield case(f'poison-order-{operation}-{populated}-{failed_stamp}',commands)
