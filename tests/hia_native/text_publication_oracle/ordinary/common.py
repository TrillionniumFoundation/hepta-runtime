"""Complete retained bytes and strict typed JSON, with explicit origin mappings."""
from __future__ import annotations
import base64, hashlib, json, math, os, stat, struct
from pathlib import Path

def require(value, message):
    if not value: raise ValueError(message)
def pin(raw): return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def integer(value, message, low=0, high=(1<<64)-1):
    require(type(value) is int and low<=value<=high, message)
    return value
def object_pairs(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'duplicate JSON object member')
        result[key]=value
    return result
def validate(value):
    if isinstance(value,str):value.encode('utf-8')
    elif type(value) is float:require(math.isfinite(value),'non-finite JSON number')
    elif type(value) is list:
        for v in value:validate(v)
    elif type(value) is dict:
        for k,v in value.items():validate(k);validate(v)
    elif value is not None and type(value) not in (bool,int):raise ValueError('invalid JSON type')
    return value
def loads(raw):
    return validate(json.loads(raw,object_pairs_hook=object_pairs,
        parse_constant=lambda value:(_ for _ in ()).throw(ValueError('non-finite JSON literal'))))
def encoded(value):return (json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def save(path,value):
    raw=encoded(value)
    with Path(path).open('xb') as stream:stream.write(raw)
    return pin(raw)
def unb64(value):
    require(type(value) is str,'base64 string')
    raw=base64.b64decode(value,validate=True)
    require(base64.b64encode(raw).decode()==value,'canonical base64')
    return raw
def b64(raw):return base64.b64encode(raw).decode('ascii')
def same(left,right,message):
    require(encoded(left)==encoded(right),message)
def plain(path):
    p=Path(path)
    require(p.is_absolute() and '..' not in p.parts,'absolute normalized owned path')
    for parent in [*reversed(p.parents),p]:
        require(not parent.is_symlink(),'symlink in retained path')
    st=p.stat()
    require(stat.S_ISREG(st.st_mode),'retained regular file')
    return p

class Files:
    def __init__(self,origins):
        self.origins=[(Path(a),Path(b)) for a,b in origins]
        require(self.origins and len({str(a) for a,b in self.origins})==len(self.origins),'unique explicit origins')
        for a,b in self.origins:
            require(a.is_absolute() and b.is_absolute() and '..' not in a.parts+b.parts,'safe source mapping')
        self.artifacts={}
    def path(self,origin):
        origin=Path(origin)
        require(origin.is_absolute() and '..' not in origin.parts,'safe original path')
        matches=[(a,b) for a,b in self.origins if origin==a or a in origin.parents]
        require(matches,'unmapped origin')
        a,b=max(matches,key=lambda pair:len(pair[0].parts))
        return plain(b/origin.relative_to(a))
    def raw(self,origin,expected=None):
        raw=self.path(origin).read_bytes();actual=pin(raw)
        if expected is not None:
            if type(expected) is str:require(actual['sha256']==expected,'retained hash changed')
            else:same(actual,expected,'retained bytes/hash changed')
        self.artifacts[str(origin)]=actual
        return raw
    def json(self,origin,expected=None):return loads(self.raw(origin,expected))

def frames(raw):
    at=0;result=[]
    while at<len(raw):
        require(len(raw)-at>=8,'complete length prefix')
        size=struct.unpack_from('<Q',raw,at)[0];at+=8
        require(size<=len(raw)-at,'complete framed payload')
        result.append(raw[at:at+size]);at+=size
    require(at==len(raw),'complete framing consumption')
    return result

def parse_wire(raw):
    require(len(raw)>=64 and raw[:8]==b'HTXTQ001','publication input header')
    op,mode,pn,tn,en,gen,res=struct.unpack_from('<7Q',raw,8)
    require(op==1 and mode in (1,2,3) and gen==res==0 and len(raw)==64+pn+en+tn,'admitted publication frame')
    path=raw[64:64+pn];expected=raw[64+pn:64+pn+en];text=raw[64+pn+en:]
    expected.decode('utf-8');text.decode('utf-8')
    require(len(text)<=65536,'already admitted original input bound')
    require(expected==b'absent' if mode==1 else len(expected)==64 and all(c in b'0123456789abcdef' for c in expected),'already admitted digest form')
    return mode,path,expected,text

def snapshot(files,path,blobs):
    rows=files.json(path);require(type(rows) is list and rows,'complete nonempty fixture state')
    seen=set();aliases={}
    for row in rows:
        rel=unb64(row['path_base64'])
        require(rel not in seen and not rel.startswith(b'/') and b'..' not in rel.split(b'/') and b'\0' not in rel,'safe unique snapshot path')
        seen.add(rel);identity=row['identity']
        require(type(identity) is list and len(identity)==7,'actual seven-field identity')
        for i,v in enumerate(identity):integer(v,'stat integer',low=-(1<<63) if i in (3,5) else 0)
        require(identity[4]<10**9 and identity[6]<10**9,'actual nanosecond fields')
        integer(row['mode'],'mode',high=0o7777);integer(row['uid'],'uid');integer(row['gid'],'gid');integer(row['nlink'],'nlink')
        require(row['kind'] in ('file','directory','symlink','fifo','socket','other'),'actual node kind')
        if 'data' in row:
            data=row['data'];require(data['file']==data['sha256']+'.bin','content addressed blob name')
            raw=files.raw(Path(blobs)/data['file'],{'bytes':data['bytes'],'sha256':data['sha256']})
            require(row['kind']=='file' and len(raw)==identity[2],'complete file bytes and stat')
            aliases.setdefault(tuple(identity[:2]),[]).append((rel,data))
        if row['kind']=='symlink':unb64(row['target_base64'])
        if 'xattrs' in row:
            for k,v in row['xattrs'].items():unb64(k);unb64(v)
        if 'read_errno' in row:integer(row['read_errno'],'observed read errno',high=4095)
    require(b'' in seen,'owned snapshot root')
    for group in aliases.values():
        for _,p in group[1:]:same(group[0][1],p,'hardlink content relationship')
    return rows
