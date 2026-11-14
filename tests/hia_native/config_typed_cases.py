"""Independent input generation for every original configuration serde field."""
from pathlib import Path
import sys,json,struct,random,collections,copy
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from config_schema import SCHEMAS,ENUMS,MAPS
R=random.Random(641024)

def encoded(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def wire(kind,raw,default=b'/trusted/\xe4\xb8\xad/state'):
    return b'HRCFGJ01'+struct.pack('<4Q',1,kind,len(default),len(raw))+default+raw
def sample(kind,full=True):
    if kind>=1000:return sample(kind-1000,full)
    if kind in (1,6):return '/root/"x\t\n中😀'
    if kind==2:return True
    if kind in (3,4,5):return 17
    if kind in ENUMS:return ENUMS[kind][-1]
    if kind in SCHEMAS:return {name:sample(ty,full) for name,ty,default,skip in SCHEMAS[kind][2] if full or default is None}
    if kind in MAPS:return {'z':sample(MAPS[kind],full),'中':sample(MAPS[kind],full),'a':sample(MAPS[kind],full)}
    if 200<=kind<300:return [sample(kind-200,full),sample(kind-200,full)]
    raise ValueError(kind)

def cases():
    records=[]
    def add(label,kind,raw,default=b'/trusted/\xe4\xb8\xad/state'):
        if not isinstance(raw,bytes):raw=encoded(raw)
        records.append((label,wire(kind,raw,default)))
    malformed=[b'null',b'true',b'false',b'0',b'-0',b'0.0',b'1e0',b'1e9999',b'18446744073709551616',
        b'""',b'"\xff"',b'"\\ud800"',b'"\\udc00"',b'"\\ud800\\udc00"',b'[]',b'{}',
        b'[1,]',b'{"a":1,}',b'{"a" 1}',b'[[[]]]',b'{"x":"\xff"}',b'"\\q"',b'"\n"']
    for kind,(name,strict,fields) in SCHEMAS.items():
        full=sample(kind);minimal=sample(kind,False)
        add('full_map',kind,full);add('required_only',kind,minimal)
        values=list(full.values())
        for end in range(len(values)+2):add('sequence_prefix',kind,values[:end] if end<=len(values) else values+[0])
        shuffled=list(full.items());R.shuffle(shuffled);add('field_order',kind,dict(shuffled))
        for field,ty,default,skip in fields:
            omitted=copy.deepcopy(full);del omitted[field];add('field_missing',kind,omitted)
            null=copy.deepcopy(full);null[field]=None;add('field_null',kind,null)
            pairs=b','.join(encoded(k)+b':'+encoded(v) for k,v in full.items() if k!=field)
            key=encoded(field)
            for left,right in [(encoded(full[field]),encoded(full[field])),(b'null',b'null'),(b'null',encoded(full[field])),(encoded(full[field]),b'null')]:
                add('duplicate_known',kind,b'{'+pairs+(b',' if pairs else b'')+key+b':'+left+b','+key+b':'+right+b'}')
            escaped=('"\\u%04x'%ord(field[0])+field[1:]+'"').encode()
            add('escaped_known_key',kind,b'{'+pairs+(b',' if pairs else b'')+escaped+b':'+encoded(full[field])+b'}')
            for value in malformed:
                add('field_type_domains',kind,b'{'+pairs+(b',' if pairs else b'')+key+b':'+value+b'}')
            if ty in (3,4,5,1005):
                for value in [b'255',b'256',b'4294967295',b'4294967296',b'18446744073709551615',b'-18446744073709551616',b'01',b'+1',b'1E+0']:
                    add('integer_boundaries',kind,b'{'+pairs+(b',' if pairs else b'')+key+b':'+value+b'}')
        for value in malformed+[b'['*256+b'1e9999'+b']'*256,b'{"\xff":"\\ud800"}']:
            add('unknown_field',kind,encoded(full)[:-1]+b',"__unknown":'+value+b'}')
        for key in [b'"\xff"',b'"\\ud800"',b'"\\u0078"','"中"'.encode()]:
            add('unknown_key',kind,encoded(full)[:-1]+b','+key+b':null}')
    for kind,names in ENUMS.items():
        for name in names:
            for raw in [encoded(name),encoded({name:None}),encoded({name:[]}),encoded({name:{}}),encoded([name]),
                        b'{'+encoded(name)+b':null,"extra":null}',b'{'+encoded(name)+b':null,}',b'{'+encoded(name)+b':null,'+encoded(name)+b':null}']:
                add('enum_forms',kind,raw)
    for kind in [3,4,5]:
        for value in list(range(258))+[2**32-1,2**32,2**64-1,2**64]+[R.randrange(2**64) for _ in range(150)]:
            add('uint_values',kind,value)
    # Each BTreeMap has last-value wins only after parsing every typed value.
    for field in ['hosts','weight_workers','rea_static_profiles']:
        elem={'hosts':101,'weight_workers':103,'rea_static_profiles':105}[field]
        value=sample(elem);other=copy.deepcopy(value);other['ssh_target' if elem==101 else 'host']='last'
        for key in ['', '\0', '\n','a','中','😀','é','é']:
            for first,last in [(encoded(value),encoded(other)),(b'null',encoded(other)),(encoded(value),b'null')]:
                add('map_duplicate',100,b'{'+encoded(field)+b':{'+encoded(key)+b':'+first+b','+encoded(key)+b':'+last+b'}}')
        for keys in [['z','a','中','😀'],['b','a','b','a'],['','',''],['x']*17]:
            add('map_sort_unique',100,b'{'+encoded(field)+b':{'+b','.join(encoded(k)+b':'+encoded(value) for k in keys)+b'}}')
    for default in [b'',b'.',b'/',b'/a',b'/\n',b'/\xff',b'/\xc0\x80',b'/\xed\xa0\x80',b'/\xf4\x90\x80\x80',b'/\xf0\x90\x80\x80']:
        add('default_path',100,{},default);add('default_overridden',100,{'state_dir':'/override'},default)
    seeds=[encoded(sample(k)) for k in SCHEMAS]
    for i in range(1800):
        kind=list(SCHEMAS)[i%9];raw=bytearray(seeds[i%9]);at=R.randrange(len(raw)+1)
        mode=i%3
        if mode==0:
            raw[at:at]=bytes([R.randrange(256)])
        elif mode==1:
            del raw[at:at+R.randrange(1,4)]
        else:
            raw[at:at+1]=bytes([R.randrange(256)])
        add('raw_mutations',kind,bytes(raw))
    return records

def main():
    destination=Path(sys.argv[1]);destination.mkdir(exist_ok=False,parents=True)
    rows=cases()
    (destination/'requests.hex').write_text(''.join(w.hex()+'\n' for _,w in rows))
    (destination/'categories.json').write_text(json.dumps([x for x,_ in rows])+'\n')
    print(json.dumps({'cases':len(rows),'categories':dict(collections.Counter(x for x,_ in rows))}))
if __name__=='__main__':main()
