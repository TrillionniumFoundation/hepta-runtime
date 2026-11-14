"""Retained input-only corpus for original execution serde types and Value admission."""
import copy, itertools, json, random
from execution_shadow_cases import fixture, record, CLASSES, CURRENT

def encode(value, ascii=False):
    return json.dumps(value, ensure_ascii=ascii, separators=(',', ':')).encode()

def all_cases():
    r=record(fixture());b=r['record']['binding']
    roots={1:{'record':r},2:r,3:b,4:'file_read',5:'current',6:{'state':'not_granted'}}
    values=[None,True,False,0,1,-1,2**32,2**64-1,1.0,0.5,'','x',[],{},[None],{'x':None}]
    for kind,value in roots.items():
        yield 'ordinary',kind,encode(value)
        for value in values:yield 'root-shape',kind,encode(value)
    for kind in (1,2,3,6):
        base=roots[kind]
        for name in base:
            c=copy.deepcopy(base);del c[name];yield 'missing-map-field',kind,encode(c)
            for value in values:
                c=copy.deepcopy(base);c[name]=value;yield 'map-field-type',kind,encode(c)
                yield 'sequence-field-type',kind,encode(list(c.values()))
            raw=encode(base)
            for value in [None,0,'discarded',base[name]]:
                prefix=encode({name:value})[:-1]+b','
                yield 'duplicate-known',kind,prefix+raw[1:]
            for spelling in [name.upper(),name+'x','',name+'\x00']:
                c=copy.deepcopy(base);c[spelling]=c.pop(name);yield 'field-name',kind,encode(c)
        for length in range(len(base)+1):yield 'sequence-length',kind,encode(list(base.values())[:length])
        yield 'sequence-extra',kind,encode(list(base.values())+[None])
        for name in ('unknown','state','kind','record','\x00','执行'):
            if name not in base:
                for value in values:
                    c=copy.deepcopy(base);c[name]=value;yield 'unknown-field',kind,encode(c)
    for scalar in range(256):
        for name in ('run_id','cell_id','predecessor','rollback_reference'):
            c=copy.deepcopy(b);c[name]=chr(scalar)
            yield 'string-scalar',3,encode(c)
            yield 'string-escaped-scalar',3,encode(c,True)
    for scalar in (0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff,0x2028,0x2029):
        for name in b:
            if isinstance(b[name],str) or b[name] is None:
                c=copy.deepcopy(b);c[name]=chr(scalar);yield 'unicode-field',3,encode(c)
                yield 'unicode-escape-field',3,encode(c,True)
    for kind in (1,2,3,6):
        for name in roots[kind]:
            original=encode(roots[kind]);quoted=encode(name)
            for index,ch in enumerate(name):
                escaped=(name[:index]+'\\u'+format(ord(ch),'04x')+name[index+1:]).encode()
                yield 'escaped-field-name',kind,original.replace(quoted,b'"'+escaped+b'"',1)
    for kind,names in [(4,CLASSES),(5,CURRENT)]:
        for name in names+['bad','',names[0].upper(),names[0]+'\x00']:
            yield 'unit-string',kind,encode(name)
            for value in values:yield 'unit-object',kind,encode({name:value})
            yield 'unit-duplicate',kind,b'{'+encode(name)+b':null,'+encode(name)+b':null}'
    for class_id,current,options in itertools.product(range(7),range(3),range(16)):
        c=fixture();c['class']=class_id;c['currentness']=current
        for name,flag in [('cell_id',1),('organ_id',2),('predecessor',4),('rollback_reference',8)]:c[name]='' if options&flag else None
        rec=record(c)
        yield 'record-options',2,encode(rec)
        rec['record']['binding']=list(rec['record']['binding'].values())
        yield 'record-binding-sequence',2,encode(rec)
    for kind,key in [(3,'schema_version'),(3,'generation')]:
        base=encode(b);marker=encode(key)+b':1'
        for value in [b'0',b'-0',b'-1',b'1.0',b'1e0',b'1E+00',b'0.0',b'-0.0',b'0e999999',b'1e999999',b'1e-999999',b'01',b'+1',b'NaN',b'Infinity',b'4294967295',b'4294967296',b'18446744073709551615',b'18446744073709551616',b'1'+b'0'*200]:
            yield 'numeric-spelling',kind,base.replace(marker,encode(key)+b':'+value,1)
    for order in (False,True):
        for tag in ['execution_intent',{'execution_intent':None},None,False,1,[],{},'bad']:
            for content in [r['record'],list(r['record'].values()),None,False,[],{},'bad']:
                pairs=[('kind',tag),('record',content)]
                if order:pairs.reverse()
                yield 'adjacent-content-order',2,encode(dict(pairs))
                yield 'adjacent-sequence',2,encode([tag,content])
    for value in ['not_granted',{'not_granted':None},None,[],{},'granted']:
        for form in [{'state':value},[value]]:yield 'final-use-state',6,encode(form)
    rng=random.Random(0x48584a53)
    for _ in range(256):
        rec=copy.deepcopy(r);pairs=list(rec['record']['binding'].items());rng.shuffle(pairs)
        rec['record']['binding']=dict(pairs);pairs=list(rec['record'].items());rng.shuffle(pairs)
        rec['record']=dict(pairs);pairs=list(rec.items());rng.shuffle(pairs)
        yield 'field-permutation',1,encode({'record':dict(pairs)})
    for kind in (1,2,3,4,5,6):
        raw=encode(roots[kind])
        for end in range(len(raw)):yield 'truncated-json',kind,raw[:end]
        for suffix in (b' ',b'\t\r\n',b'0',b'[]',b'\x00',b',',b'null'):
            yield 'json-suffix',kind,raw+suffix
        for prefix in (b' ',b'\t\r\n',b'\xef\xbb\xbf',b'\x00'):
            yield 'json-prefix',kind,prefix+raw
    for bad in (b'\x80',b'\xc0\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xf5\x80\x80\x80',b'\xe2\x82',b'\\ud800',b'\\udfff',b'\\ud800x',b'\\ud800\\u0041',b'\\u000g',b'\\x00',b'\n'):
        yield 'invalid-string',3,encode(b).replace(b'"run-1"',b'"'+bad+b'"',1)
    for raw in (b'{',b'[',b'',b'null',b'true',b'false',b'0',b'""',b'{}',b'[]',b'{"record":{}}',b'{"record":{"record":false}}'):
        yield 'invalid-root',1,raw
    # The ordinary three-buffer image's exact transport capacity is explicit.
    c=copy.deepcopy(r);c['record']['binding']['run_id']=''
    overhead=len(encode({'record':c}));c['record']['binding']['run_id']='x'*((8<<20)-32-overhead)
    raw=encode({'record':c});assert len(raw)+32==8<<20
    yield 'exact-native-json-input',1,raw

def cases():
    for label,kind,raw in all_cases():
        yield label,kind,raw
        yield label+'-value',kind+10,raw
