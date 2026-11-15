"""Serializable fixtures and actual file capture; no publication semantics."""
from __future__ import annotations
import base64, hashlib, json, os, socket, stat, struct
from pathlib import Path

INPUT_LIMIT = 65536
EXISTING_LIMIT = 4194304
RESULT_LIMIT = 4259840
INVALID = 0xffffffff

def b64(raw): return base64.b64encode(raw).decode('ascii')
def unb64(value): return base64.b64decode(value, validate=True)
def digest(raw): return hashlib.sha256(raw).hexdigest()
def data(pattern=b'', length=None):
    return {'pattern_hex':pattern.hex(), 'length':len(pattern) if length is None else length}
def materialize(spec):
    if 'parts' in spec:return b''.join(materialize(part) for part in spec['parts'])
    pattern=bytes.fromhex(spec['pattern_hex']); size=spec['length']
    if type(size) is not int or size<0 or (size and not pattern):
        raise ValueError('invalid finite data description')
    return (pattern*((size+len(pattern)-1)//len(pattern)))[:size] if size else b''
def node(kind,path=b'target',**values): return {'kind':kind,'path_base64':b64(path),**values}
def file_node(raw=b'old\n',*,path=b'target',mode=0o600,size=None,xattrs=None):
    return node('file',path,data=data(raw,size),mode=mode,xattrs=xattrs or {})
def case(name,*,mode=1,content=b'new\n',content_size=None,setup=(),path=b'/target',
         anchor='fixture',expected=None,error=None,private=False,target=b'target',
         domain='ordinary',wire_edit=None):
    if expected is None:
        expected={'literal_hex':b'absent'.hex()} if mode==1 else {'file_base64':b64(target)}
    return {'name':name,'domain':domain,'setup':list(setup),
            'request':{'mode':mode,'path_anchor':anchor,'path_base64':b64(path),
                       'content':data(content,content_size),'expected':expected,'wire_edit':wire_edit},
            'expect':{'kind':'private' if private else ('error' if error is not None else 'success'),
                      'error':error,'target_base64':b64(target)},'original_eligible':not private}

def corpus():
    rows=[]
    for size in (0,1,7,8,9,63,64,65,65535,65536):
        rows.append(case(f'create-bytes-{size}',content=b'a',content_size=size))
    for name,raw in (
        ('unicode','零\U0001f680é\r\n\u2028\u2029\ufeff'.encode()),
        ('nul-text',b'left\0middle\0right'),('controls',bytes(range(32))+b'\x7f'),
        ('bom',b'\xef\xbb\xbftext\n'),('crlf',b'a\r\nb\rc\n'),
        ('utf8-two-byte-boundary',('é'*32768).encode()),
        ('utf8-four-byte-boundary',('\U0001f680'*16384).encode())):
        rows.append(case('create-'+name,content=raw))
    for mode,label in ((2,'replace'),(3,'append')):
        for old,new,label2 in ((b'',b'','both-empty'),(b'',b'new','empty-old'),
                               (b'old',b'','empty-new'),(b'old\r\n',b'new\0\n','mixed')):
            rows.append(case(label+'-'+label2,mode=mode,content=new,setup=[file_node(old)]))
        rows.append(case(label+'-unicode',mode=mode,content='末尾\U0001f680'.encode(),setup=[file_node('前文é\r\n'.encode())]))
    rows.append(case('create-existing',setup=[file_node()],error=10))
    rows.append(case('create-existing-empty',setup=[file_node(b'')],error=10))
    for mode,label in ((2,'replace'),(3,'append')):
        rows.append(case(label+'-missing',mode=mode,expected={'literal_hex':(b'0'*64).hex()},error=11))
        rows.append(case(label+'-wrong-sha',mode=mode,setup=[file_node()],expected={'literal_hex':(b'0'*64).hex()},error=17))
    for name,raw in (('ff',b'\xff'),('overlong',b'\xc0\x80'),('surrogate',b'\xed\xa0\x80'),
                     ('truncated',b'\xf0\x9f\x9a'),('stray-continuation',b'a\x80b')):
        rows.append(case('old-invalid-utf8-'+name,mode=2,setup=[file_node(raw)],error=16))
    for mode,label in ((2,'replace'),(3,'append')):
        for size in (EXISTING_LIMIT-1,EXISTING_LIMIT):
            rows.append(case(f'{label}-old-{size}',mode=mode,content=b'z',content_size=INPUT_LIMIT,
                             setup=[file_node(b'x',size=size)],domain='wide'))
        rows.append(case(label+'-old-over-limit',mode=mode,setup=[file_node(b'x',size=EXISTING_LIMIT+1)],domain='wide',error=12))
    rows.append(case('append-result-exact-limit',mode=3,content=b'z',content_size=INPUT_LIMIT,
                     setup=[file_node(b'x',size=EXISTING_LIMIT)],domain='wide'))
    rows.append(case('append-utf8-boundaries',mode=3,content='é'.encode(),content_size=INPUT_LIMIT,
                     setup=[file_node('\U0001f680'.encode(),size=EXISTING_LIMIT)],domain='wide'))
    last_invalid=file_node()
    last_invalid['data']={'parts':[data(b'a',EXISTING_LIMIT-1),data(b'\xff')]}
    rows.append(case('replace-wide-invalid-utf8-last-byte',mode=2,setup=[last_invalid],error=16,domain='wide'))
    for mode in (0o600,0o640,0o644,0o660,0o664,0o666):
        rows.append(case(f'preserve-mode-{mode:o}',mode=2,setup=[file_node(mode=mode)],domain='metadata'))
    for mode in (0o400,0o440,0o444,0o700,0o610,0o601,0o4600,0o2600,0o1600):
        rows.append(case(f'refuse-mode-{mode:o}',mode=2,setup=[file_node(mode=mode)],error=5,domain='metadata'))
    rows.append(case('refuse-no-read-permission',mode=2,setup=[file_node(mode=0o200)],
                     expected={'data':data(b'old\n')},error=11,domain='metadata'))
    for value in (b'',b'preserve-me\0'):
        rows.append(case('refuse-xattr-'+('empty' if not value else 'value'),mode=2,
                         setup=[file_node(xattrs={'user.hepta_publication_fixture':b64(value)})],error=7,domain='metadata'))
    rows.append(case('refuse-hardlink',mode=2,setup=[file_node(),node('hardlink',b'other',target_base64=b64(b'target'))],error=5,domain='metadata'))
    for kind in ('directory','fifo','socket'):
        rows.append(case('refuse-existing-'+kind,mode=2,setup=[node(kind)],
                         expected={'literal_hex':(b'0'*64).hex()},error=11 if kind=='socket' else 5,domain='metadata'))
        rows.append(case('create-existing-'+kind,setup=[node(kind)],error=10,domain='metadata'))
    for dangling in (False,True):
        nodes=[] if dangling else [file_node(path=b'real')]
        nodes.append(node('symlink',target_base64=b64(b'missing' if dangling else b'real')))
        rows.append(case('create-'+('dangling' if dangling else 'valid')+'-symlink',setup=nodes,error=10,domain='metadata'))
        rows.append(case('replace-'+('dangling' if dangling else 'valid')+'-symlink',mode=2,setup=nodes,
                         expected={'literal_hex':(b'0'*64).hex()},error=11,domain='metadata'))
    for name,raw in (('empty',b''),('relative',b'target'),('dot-relative',b'./target'),('parent-relative',b'../target')):
        rows.append(case('path-'+name,path=raw,anchor='literal',error=0,domain='paths'))
    for name,raw in (('root',b'/'),('root-slashes',b'////'),('root-dot',b'/././/')):
        rows.append(case('path-'+name,path=raw,anchor='literal',error=4,domain='paths'))
    for name,raw in (('double-slash',b'//target'),('dot',b'/./target'),('trailing-slash',b'/target/'),('trailing-dot',b'/target//./.')):
        rows.append(case('path-normalize-'+name,path=raw,domain='paths'))
    rows.append(case('path-file-before-traversal',setup=[file_node()],path=b'/target/..',error=1,domain='paths'))
    rows.append(case('path-missing-before-traversal',path=b'/missing/../target',error=1,domain='paths'))
    rows.append(case('path-directory-before-traversal',setup=[node('directory',b'dir')],path=b'/dir/../target',error=3,domain='paths'))
    rows.append(case('path-missing-before-nul',path=b'/missing/\0/target',error=1,domain='paths'))
    rows.append(case('path-final-nul',path=b'/tar\0get',error=2,domain='paths'))
    rows.append(case('path-parent-nul',path=b'/\0/target',error=2,domain='paths'))
    rows.append(case('path-parent-symlink',setup=[node('directory',b'real'),node('symlink',b'parent',target_base64=b64(b'real'))],
                     path=b'/parent/target',error=1,domain='paths'))
    rows.append(case('path-deep-normalized',setup=[node('directory',b'a'),node('directory',b'a/b')],
                     path=b'//a/./b//./target/.',target=b'a/b/target',domain='paths'))
    for name,raw in (('non-utf8',b'file-\xff-\x80'),('unicode','文档-\U0001f680-é'.encode()),('name255',b'x'*255)):
        rows.append(case('path-'+name,path=b'/'+raw,target=raw,domain='paths'))
    rows.append(case('path-name256',path=b'/'+b'x'*256,target=b'x'*256,error='File name too long (os error 36)',domain='paths'))
    bad_expected=(('create-hex',1,b'0'*64),('create-empty',1,b''),('create-uppercase',1,b'ABSENT'),
                  ('replace-short',2,b'a'*63),('replace-long',2,b'a'*65),('replace-uppercase',2,b'A'*64),
                  ('replace-not-hex',2,b'g'*64),('append-absent',3,b'absent'))
    for name,mode,expected in bad_expected:
        rows.append(case('private-'+name,mode=mode,expected={'literal_hex':expected.hex()},private=True,domain='admission'))
    for name,raw in (('ff',b'\xff'),('overlong',b'\xc0\x80'),('surrogate',b'\xed\xa0\x80'),
                     ('out-of-range',b'\xf4\x90\x80\x80'),('truncated',b'\xe2\x82')):
        rows.append(case('private-new-utf8-'+name,content=raw,private=True,domain='admission'))
    rows.append(case('private-input-over-limit',content=b'x',content_size=INPUT_LIMIT+1,private=True,domain='admission'))
    for name,edit in (
        ('bad-magic',{'offset':0,'hex':b'BADTXT01'.hex()}),('bad-op',{'offset':8,'u64':3}),
        ('mode-zero',{'offset':16,'u64':0}),('mode-four',{'offset':16,'u64':4}),
        ('publish-generation',{'offset':48,'u64':1}),('reserved',{'offset':56,'u64':1}),
        ('path-overflow',{'offset':24,'u64':(1<<64)-1}),('expected-overflow',{'offset':40,'u64':(1<<64)-1}),
        ('text-overflow',{'offset':32,'u64':(1<<64)-1}),('short-header',{'truncate':63}),('trailing-byte',{'append_hex':'00'})):
        rows.append(case('private-'+name,private=True,domain='admission',wire_edit=edit))
    names=[r['name'] for r in rows]
    if len(names)!=len(set(names)):raise ValueError('duplicate fixture identity')
    return rows

def setup_fixture(root,description):
    root=os.fsencode(root);os.mkdir(root,0o700)
    for item in description:
        rel=unb64(item['path_base64'])
        if rel.startswith(b'/') or b'..' in rel.split(b'/') or b'\0' in rel:
            raise ValueError('setup escapes owned fixture')
        target=root+b'/'+rel;kind=item['kind']
        if kind=='file':
            with open(target,'xb') as stream:stream.write(materialize(item['data']))
            for name,value in item['xattrs'].items():os.setxattr(target,name,unb64(value),follow_symlinks=False)
            os.chmod(target,item['mode'])
        elif kind=='directory':os.mkdir(target,0o700)
        elif kind=='hardlink':os.link(root+b'/'+unb64(item['target_base64']),target,follow_symlinks=False)
        elif kind=='symlink':os.symlink(unb64(item['target_base64']),target)
        elif kind=='fifo':os.mkfifo(target,0o600)
        elif kind=='socket':
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                    sock.bind(b'/proc/self/fd/'+str(fd).encode('ascii')+b'/'+rel)
            finally:os.close(fd)
        else:raise ValueError('unknown explicit fixture node')

def request_bytes(root,description):
    req=description['request'];path=unb64(req['path_base64'])
    if req['path_anchor']=='fixture':path=os.fsencode(root)+path
    elif req['path_anchor']!='literal':raise ValueError('unknown path anchor')
    content=materialize(req['content']);spec=req['expected']
    if 'literal_hex' in spec:expected=bytes.fromhex(spec['literal_hex'])
    elif 'data' in spec:expected=digest(materialize(spec['data'])).encode('ascii')
    else:
        with open(os.fsencode(root)+b'/'+unb64(spec['file_base64']),'rb') as stream:expected=digest(stream.read()).encode('ascii')
    raw=bytearray(b'HTXTQ001'+struct.pack('<7Q',1,req['mode'],len(path),len(content),len(expected),0,0)+path+expected+content)
    edit=req['wire_edit']
    if edit:
        if 'truncate' in edit:del raw[edit['truncate']:]
        elif 'append_hex' in edit:raw.extend(bytes.fromhex(edit['append_hex']))
        else:
            value=struct.pack('<Q',edit['u64']) if 'u64' in edit else bytes.fromhex(edit['hex'])
            raw[edit['offset']:edit['offset']+len(value)]=value
    return bytes(raw),{'path_base64':b64(path),'mode':req['mode'],'expected_base64':b64(expected),
                       'content_bytes':len(content),'content_sha256':digest(content)}

def version(st):
    return [st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns//1000000000,
            st.st_mtime_ns%1000000000,st.st_ctime_ns//1000000000,st.st_ctime_ns%1000000000]

def save_blob(directory,raw):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    sha=digest(raw);path=directory/(sha+'.bin')
    if path.exists():
        if path.read_bytes()!=raw:raise ValueError('content-addressed blob mismatch')
    else:
        with path.open('xb') as stream:stream.write(raw)
    return {'bytes':len(raw),'sha256':sha,'file':path.name}

def snapshot(root,blobs):
    root=os.fsencode(root);rows=[];pending=[b'']
    while pending:
        rel=pending.pop();path=root+(b'/'+rel if rel else b'');st=os.lstat(path)
        kind=('file' if stat.S_ISREG(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode)
              else 'symlink' if stat.S_ISLNK(st.st_mode) else 'fifo' if stat.S_ISFIFO(st.st_mode)
              else 'socket' if stat.S_ISSOCK(st.st_mode) else 'other')
        row={'path_base64':b64(rel),'kind':kind,'mode':stat.S_IMODE(st.st_mode),
             'uid':st.st_uid,'gid':st.st_gid,'nlink':st.st_nlink,'identity':version(st)}
        try:row['xattrs']={b64(os.fsencode(n)):b64(os.getxattr(path,n,follow_symlinks=False))
                           for n in sorted(os.listxattr(path,follow_symlinks=False))}
        except OSError as error:row['xattr_errno']=error.errno
        if kind=='file':
            try:
                with open(path,'rb') as stream:row['data']=save_blob(blobs,stream.read())
            except OSError as error:row['read_errno']=error.errno
        elif kind=='symlink':row['target_base64']=b64(os.readlink(path))
        elif kind=='directory':
            for name in sorted(os.listdir(path),reverse=True):pending.append(rel+b'/'+name if rel else name)
        rows.append(row)
    return rows

def expected_output(description):
    content=materialize(description['request']['content'])
    if description['request']['mode']!=3:return content
    target=description['expect']['target_base64']
    original=[n for n in description['setup'] if n['kind']=='file' and n['path_base64']==target]
    if len(original)!=1:raise ValueError('successful append fixture has no unique ordinary source')
    return materialize(original[0]['data'])+content

def save_json(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode('ascii')
    with Path(path).open('xb') as stream:stream.write(raw)
    return {'bytes':len(raw),'sha256':digest(raw)}
