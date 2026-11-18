# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Predeclared cache transitions using actual files; before stamps are opaque observed values."""
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


def command(op, directory=1, records=(), before=None, **expected):
    if op in (0,5):directory=0
    return dict(operation=op,directory=directory,records=list(records),before=before,**expected)


def query(directory=1,value=None,**extra):
    return command(2,directory,**({} if value is None else dict(value=int(value))),**extra)


def put(records=(),directory=1,**extra):return command(1,directory,records,**extra)


def inspect(index=0,save=None,records=None,**extra):
    return command(6,index,save=save,**({} if records is None else dict(expected_records=records)),**extra)


def wire(step, stamps):
    if 'raw' in step:return bytes.fromhex(step['raw'])
    before=step.get('before')
    if isinstance(before,str):before=stamps[before]
    elif before is None:before=b''
    else:before=bytes.fromhex(before['hex'])
    if 'before_xor' in step:
        before=bytearray(before);at=step['before_xor'];value=struct.unpack_from('<Q',before,at)[0]^1;struct.pack_into('<Q',before,at,value);before=bytes(before)
    values=step['records']
    return struct.pack('<8s7Q',b'HRACQ001',step['operation'],step['directory'],0,0,len(values),len(before),0)+before+records_wire(values)


def cases():
    yield dict(name='empty-cache-lifetime',steps=[command(0),query(value=0),inspect(),put(),query(value=1),inspect(records=[]),command(0)])
    for count in (1,2,33,512):
        values=[record(i,state=('unknown','completed','failed')[i%3],elapsed_ms=None if i%2 else i) for i in range(count)]
        yield dict(name='owned-record-vector-'+str(count),steps=[put(values),query(value=1),inspect(records=values),inspect(15)])
    yield dict(name='unicode-and-u128',steps=[put([record(request_id='',owner='所有者',tool_name='工具',accepted_unix_ms=(1<<128)-1,
        state='completed',elapsed_ms=(1<<64)-1)]),inspect(records=[record(request_id='',owner='所有者',tool_name='工具',accepted_unix_ms=(1<<128)-1,
        state='completed',elapsed_ms=(1<<64)-1)])])
    original=[record(1),record(1,owner='second'),record(2)]
    changed=record(1,owner='new-owner',tool_name='new-tool',accepted_unix_ms=(1<<100)+17,state='failed',elapsed_ms=0)
    final=[changed,original[1],original[2]]
    yield dict(name='first-id-completion-replaces-whole-record',steps=[put(original),inspect(save='before',records=original),
        dict(mutation='write',directory=1,name='entry',data='616263'),query(value=0),
        command(4,records=[changed],before='before'),inspect(records=final),query(value=1)])
    for field,value in ((8,0),(16,0),(24,0),(32,0),(40,0),(48,0),(64,999),(72,999)):
        yield dict(name='before-stamp-mismatch-'+str(field),steps=[put(original),inspect(save='before'),
            command(4,records=[changed],before='before',before_xor=field),inspect(records=original)])
    yield dict(name='record-id-miss-keeps-old-stamp',steps=[put([record(1)]),inspect(save='before'),
        dict(mutation='write',directory=1,name='entry',data='61'),command(4,records=[record(9)],before='before'),
        query(value=0),inspect(records=[record(1)])])
    yield dict(name='query-does-not-promote-eviction',steps=[*(put([record(i)],i) for i in range(1,17)),
        query(1,value=1),put([record(17)],17),query(1,value=0),query(2,value=1),
        inspect(0,records=[record(2)],inode_directory=2),inspect(15,records=[record(17)],inode_directory=17)])
    yield dict(name='replace-moves-cache-entry-to-back',steps=[put([record(1)],1),put([record(2)],2),put([record(3)],1),
        inspect(0,records=[record(2)],inode_directory=2),inspect(1,records=[record(3)],inode_directory=1)])
    yield dict(name='two-file-aliases-one-inode',aliases={'17':1},steps=[put([record(1)],1),put([record(2)],17),
        query(1,value=1),inspect(0,records=[record(2)],cache_count=1),inspect(1,cache_count=1)])
    for mode in (0o000,0o600,0o750,0o1700,0o2700,0o4700):
        yield dict(name='private-mode-'+oct(mode),steps=[put([record()]),inspect(save='before'),
            dict(mutation='chmod',directory=1,mode=mode),query(diagnostic=16),
            command(4,records=[record(state='completed')],before='before',diagnostic=16),
            dict(mutation='chmod',directory=1,mode=0o700),query(value=0),inspect(records=[record()])])
    for kind in ('file','fifo'):
        yield dict(name='initial-type-'+kind,types={'1':kind},steps=[query(diagnostic=16),put(diagnostic=16),inspect(cache_count=0,initialized=0)])
    yield dict(name='metadata-failure-precedes-poison',steps=[put([record()]),command(5),query(diagnostic=43),
        dict(mutation='chmod',directory=1,mode=0o750),query(diagnostic=16),
        dict(mutation='chmod',directory=1,mode=0o700),query(diagnostic=43),inspect(diagnostic=43)])
    yield dict(name='poison-before-cache-initialization',steps=[command(5),query(diagnostic=43),put(diagnostic=43),inspect(diagnostic=43),command(0,value=1)])
    for ns in (-1,0,1700000000123456789):
        yield dict(name='signed-stamp-update-'+str(ns),steps=[put([record()]),inspect(save='before'),
            dict(mutation='utime',directory=1,ns=ns),query(value=0),command(4,records=[record(state='completed')],before='before'),
            inspect(records=[record(state='completed')]),query(value=1)])
    for raw in (b'',b'BADMAGIC'+bytes(56),struct.pack('<8s7Q',b'HRACQ001',3,1,0,0,0,0,0),
        struct.pack('<8s7Q',b'HRACQ001',7,1,0,0,0,0,0),struct.pack('<8s7Q',b'HRACQ001',2,0,0,0,0,0,0),
        struct.pack('<8s7Q',b'HRACQ001',2,18,0,0,0,0,0)):
        yield dict(name='private-wire-'+raw.hex(),steps=[dict(raw=raw.hex(),status=0xffffffff),query(value=0)])


def fault_cases():
    def case(name,faults,diagnostic=0,error=0):
        return dict(name=name,supervisor=dict(faults=faults),steps=[put([record()],diagnostic=diagnostic,error=error),
            command(0),put([record(1)],2),query(2,value=1),inspect(0),inspect(1)])
    yield case('observed-composition',[])
    for error in (2,4,5,13):yield case('first-stamp-error-'+str(error),[dict(kind='held_metadata',errno=error)],23,error)
    yield case('shared-statx-cache-fallback',[dict(kind='held_metadata',errno=13),dict(kind='statx_probe',errno=38),dict(kind='statat_probe',errno=38)])
    yield case('statx-fstatat-fallback',[dict(kind='held_metadata',errno=38)])
    for kind,error in (('events_init',38),('events_read',5),('pin_duplicate',24),('watch_add',28)):
        yield case('namespace-fallback-'+kind,[dict(kind=kind,errno=error)])
    for kind in ('scan_open','scan_flags','scan_metadata','scan_read'):
        yield case('fingerprint-error-'+kind,[dict(kind='events_init',errno=38),dict(kind=kind,errno=5)],23,5)
    yield case('fingerprint-actual-small-read',[dict(kind='events_init',errno=38),dict(kind='scan_read',short_limit=64)])
    yield dict(name='cached-metadata-error-after-warmup',supervisor=dict(faults=[dict(kind='held_metadata',ordinal=3,errno=5)]),
        steps=[put([record()]),query(diagnostic=23,error=5),query(value=1),inspect(records=[record()])])
    yield dict(name='failed-update-keeps-cache',supervisor=dict(faults=[dict(kind='held_metadata',ordinal=3,errno=5)]),
        steps=[put([record()]),inspect(save='before'),command(4,records=[record(state='completed')],before='before',diagnostic=23,error=5),
            inspect(records=[record()]),query(value=1)])


if __name__=='__main__':
    import json
    a=list(cases());b=list(fault_cases())
    print(json.dumps(dict(ordinary=len(a),kernel=len(b),requests=sum(sum('mutation' not in s for s in r['steps']) for r in a+b),
        controls=sum(len(r['supervisor']['faults']) for r in b))))

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

