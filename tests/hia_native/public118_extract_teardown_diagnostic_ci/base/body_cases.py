"""Frozen real-filesystem Local extract corpus; no body implementation."""
import json
import os
import struct

U64 = (1 << 64) - 1
ABSENT = {'absent': True}


def line_hash(text):
    value = 2166136261
    for byte in text.encode():
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return '%02x' % ((value ^ (value >> 8) ^ (value >> 16) ^ (value >> 24)) & 255)


def operation(start=1, end=ABSENT, append=-1, *, source='source', target='target', kind=0, context=1):
    return dict(op=1, source=source, target=target, start=start, end=end, append=append,
                kind=kind, context=context)


def case(name, source=b'a\nb\nc\n', target=b'head\ntail\n', operations=None, **changes):
    files = []
    if source is not None: files.append((b'source', source, 0o640))
    if target is not None: files.append((b'target', target, 0o600))
    value = dict(name=name, files=files, directories=[], directory_modes=[], hardlinks=[],
                 symlinks=[], cache=[], history=[], cache_poison=False, history_poison=False,
                 operations=operations or [operation()])
    value.update(changes)
    return value


def cases():
    result = []
    for source_name, source in [('lf', b'one\ntwo\nthree\n'), ('no_final', b'one\ntwo\nthree'),
                                ('crlf', b'one\r\ntwo\r\nthree\r\n'), ('mixed', b'one\r\ntwo\nthree\r\r\n')]:
        for target_name, target in [('lf', b'head\ntail\n'), ('crlf', b'head\r\ntail\r\n'),
                                    ('nonewline', b'head\ntail'), ('empty', b''), ('missing', None)]:
            for position in (0, -1):
                result.append(case(f'endings-{source_name}-{target_name}-{position}', source, target,
                                   [operation(2, -1, position)]))
    for name, start, end in [('one',1,ABSENT),('last',-1,ABSENT),('middle',2,2),('negative',-2,-1),
                             ('all',1,3),('null-end',2,None),('numeric-strings',' +1 ',' -1 '),
                             ('valid-id','2:'+line_hash('b'),'3:'+line_hash('c')),
                             ('upper-id','2:'+line_hash('b').upper(),ABSENT)]:
        result.append(case('source-range-'+name, operations=[operation(start,end,1)]))
    for source_name, source in [('empty',b''),('one-blank',b'\n'),('blank-crlf',b'\r\n'),
                                ('only-cr',b'\r'),('many-blanks',b'\n\n\n'),
                                ('unicode','你好\n😀\nβ\n'.encode()),('nul',b'a\0b\nc\n')]:
        result.append(case('source-content-'+source_name,source,None,
                           [operation(1,-1,0,kind=int(not source))]))
    for count in (29,30,31,61):
        source=('\n'.join('line%03d'%n for n in range(1,count+1))+'\n').encode()
        result.append(case('confirmation-cap-'+str(count),source,None,[operation(1,-1,0)]))
    for name, value in [('zero',0),('too-high',4),('too-low',-4),('min',-(1<<63)),
                         ('max',(1<<63)-1),('id-high','9:'+line_hash('a')),
                         ('stale','2:'+line_hash('a')),('id-missing','2:00')]:
        result.append(case('source-start-'+name,operations=[operation(value,kind=1)]))
        result.append(case('source-end-'+name,operations=[operation(1,value,kind=1)]))
    result.append(case('source-reversed',operations=[operation(3,1,0,kind=1)]))
    invalid = [('null',None),('boolean',True),('array',[]),('object',{}),('fraction',1.5),
               ('empty',''),('spaces',' \t\u3000'),('bad','bad'),('bad-id','2:xyz'),
               ('zero-id','0:00'),('overflow','18446744073709551616')]
    for label,value in invalid:
        for field in ('start','end','append'):
            # A null optional end deliberately defaults to the start.
            if field=='end' and value is None: continue
            values=dict(start=1,end=ABSENT,append=0);values[field]=value
            result.append(case('parse-'+field+'-'+label,operations=[operation(**values,kind=1)]))
    for name, append, kind in [('beginning',0,0),('end',-1,0),('after-one',1,0),('after-last',2,0),
                                ('past-end',3,1),('negative',-2,1),('min',-(1<<63),1),
                                ('max',(1<<63)-1,1),('valid-id','1:'+line_hash('head'),0),
                                ('stale-id','1:'+line_hash('tail'),1),('high-id','4:00',1)]:
        result.append(case('append-'+name,operations=[operation(1,2,append,kind=kind)]))
    result.append(case('append-id-empty',target=b'',operations=[operation(append='1:00',kind=1)]))
    result.append(case('append-id-missing',target=None,operations=[operation(append='1:00',kind=1)]))
    result.append(case('missing-source',source=None,operations=[operation(kind=1)]))
    result.append(case('invalid-source-utf8',source=b'\xff',operations=[operation(kind=1)]))
    result.append(case('invalid-target-utf8',target=b'\xff',operations=[operation(kind=1)]))
    result.append(case('source-directory',source=None,directories=[b'source'],operations=[operation(kind=1)]))
    result.append(case('target-directory',target=None,directories=[b'target'],operations=[operation(kind=1)]))
    result.append(case('mkdir-deep',target=None,operations=[operation(target='one/two/target')]))
    result.append(case('mkdir-parent-file',operations=[operation(target='target/child',kind=1)]))
    for label,blank in [('empty',''),('spaces',' \t\u3000')]:
        result.append(case('path-source-'+label,operations=[operation(source=blank,kind=1)]))
        result.append(case('path-target-'+label,operations=[operation(target=blank,kind=1)]))
    result.append(case('source-nul-path',operations=[operation(source='source\0x',kind=1)]))
    result.append(case('target-nul-path',operations=[operation(target='target\0x',kind=1)]))
    result.append(case('source-unreadable',files=[(b'source',b'a\n',0),(b'target',b'head\n',0o600)],
                       operations=[operation(kind=1)]))
    result.append(case('target-unreadable',files=[(b'source',b'a\n',0o600),(b'target',b'head\n',0)],
                       operations=[operation(kind=1)]))
    result.append(case('target-parent-unwritable',files=[(b'source',b'a\n',0o600),(b'dir/target',b'head\n',0o600)],
                       directory_modes=[(b'dir',0o500)],operations=[operation(target='dir/target',kind=1)]))
    result.append(case('source-symlink',source=None,files=[(b'actual',b'a\nb\n',0o600),(b'target',b'head\n',0o600)],
                       symlinks=[(b'source',b'actual')]))
    result.append(case('target-symlink',target=None,files=[(b'source',b'a\nb\n',0o600),(b'actual',b'head\n',0o640)],
                       symlinks=[(b'target',b'actual')]))
    result.append(case('target-hardlink',hardlinks=[(b'alias',b'target')]))
    result.append(case('source-equals-target',operations=[operation(source='target',start=1,append=-1),
                                                        operation(source='target',start=-1,append=0)]))
    result.append(case('source-target-hardlink',source=None,hardlinks=[(b'source',b'target')]))
    for name, cache in [('match',[(b'target','head\ntail\n')]),('stale',[(b'target','stale\n')]),
                         ('other',[(b'other','other\n')])]:
        result.append(case('cache-'+name,cache=cache,operations=[operation(),operation(context=2),operation()]))
    result.append(case('cache-poison',cache=[(b'target','head\ntail\n')],cache_poison=True))
    result.append(case('history-poison',history_poison=True,operations=[operation(kind=1)]))
    result.append(case('history-cap-and-persistent-owner',operations=[operation() for _ in range(13)]))
    result.append(case('history-seeded',history=[(b'target','old%02d'%i,67108864) for i in range(10)],
                       operations=[operation(),operation(append=0)]))
    result.append(case('history-shared-file-keys',files=[(b'source',b'a\n',0o600),(b'target',b'old\n',0o600),(b'other',b'other\n',0o600)],
                       operations=[operation(),operation(target='other'),operation()]))
    result.append(case('long-line-growth',source=b'x'*8193+b'\n',target=b'y'*8193+b'\n'))
    result.append(case('cache-over-1m',source=b'x'*(1048576+1)+b'\n',target=b'head\n',cache=[(b'target','head\n')]))
    names=[x['name'] for x in result]
    assert len(set(names))==len(names)
    return result


def endpoint(value):
    if type(value) is int: return struct.pack('<8s3Q',b'HIAEP002',0,0,value&U64)
    if type(value) is float: return struct.pack('<8s3Q',b'HIAEP002',1,0,0)
    if isinstance(value,str): raw=value.encode();kind=2
    else: raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode();kind=3
    return struct.pack('<8s3Q',b'HIAEP002',kind,len(raw),0)+raw


def request(operation,work,generation):
    source,target=operation['source'],operation['target']
    def resolve(name):
        # Match PathBuf::join byte construction; never canonicalize lexical input.
        return os.fsencode(name) if os.path.isabs(name) else os.fsencode(work)+b'/'+os.fsencode(name)
    parts=[resolve(source),resolve(target),source.encode(),target.encode(),endpoint(operation['start']),
           b'' if operation['end']==ABSENT else endpoint(operation['end']),endpoint(operation['append'])]
    return struct.pack('<8s15Q',b'HEXTRQ01',1,operation['context'],generation,*(len(x) for x in parts),0,0,0,0,0)+b''.join(parts)
