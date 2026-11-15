"""Sole Batch input generator; no expected result or replacement algorithm.

The original implementation may only be replayed after an admitted native
capture for the same complete logical input. Binary blobs are retained in full.
Public SDK cases and private local-inner cases have different entry contracts.
"""
import itertools,json,random,struct

INPUT=b'HBCCI002'
OUTPUT=b'HBCCO002'

def canonical(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def record(metadata,blobs):
    raw=canonical(metadata)
    return struct.pack('<2Q',len(raw),len(blobs))+raw+b''.join(struct.pack('<Q',len(x))+x for x in blobs)
def records(stream,magic):
    assert stream.read(8)==magic
    count=struct.unpack('<Q',stream.read(8))[0]
    for _ in range(count):
        n,k=struct.unpack('<2Q',stream.read(16));metadata=json.loads(stream.read(n));blobs=[]
        for _ in range(k):
            n=struct.unpack('<Q',stream.read(8))[0];raw=stream.read(n);assert len(raw)==n;blobs.append(raw)
        yield {'metadata':metadata,'blobs':blobs}
    assert stream.read(1)==b''

def line_id(n,text):
    h=2166136261
    for b in text.encode():h=((h^b)*16777619)&0xffffffff
    h=(h>>16)^(h&65535);h=(h>>8)^(h&255)
    return f'{n}:{h:02x}'

def iter_cases():
    index=0
    def make(name,raw=b'alpha\nbeta\ngamma\n',ops=None,path='file',actions=None,hooks=None,cache=None,large=False,probes=None,
             sequence=None,session=0,reset=True,workdir_rel_hex='',execution='sync',cancel=None):
        nonlocal index
        blobs=[]
        def blob(value):blobs.append(value);return len(blobs)-1
        if isinstance(raw,str):raw=raw.encode()
        initial=[] if raw is None else [{'kind':'write','path':'file','blob':blob(raw),'mode':0o640}]
        for action in actions or []:
            action=dict(action)
            if 'bytes' in action:action['blob']=blob(action.pop('bytes'))
            initial.append(action)
        normalized=[]
        for hook in hooks or []:
            hook=dict(hook);hook['actions']=[dict(a) for a in hook['actions']]
            for a in hook['actions']:
                if 'bytes' in a:a['blob']=blob(a.pop('bytes'))
            normalized.append(hook)
        params={'path':path,'operations':ops if ops is not None else [{'operation':'insert','start':0,'content':'prefix'}]}
        if cancel is not None:
            cancel=dict(cancel)
            if 'transfer_bytes' in cancel:cancel['transfer_blob']=blob(cancel.pop('transfer_bytes'))
        meta={'case_id':index,'name':name,'domain':'local-batch-inner','params':params,
              'initial':initial,'hooks':normalized,'cache':None if cache is None else blob(cache.encode()),
              'probes':probes or ['file'],'large':large,'reset_history':reset,'reset_cache':reset,
              'sequence':sequence,'session':session,'workdir_rel_hex':workdir_rel_hex,
              'execution':execution,'cancel':cancel}
        index+=1
        return {'metadata':meta,'blobs':blobs}
    texts=['','a','a\n','\n','\r','\r\n','a\r\nb\nc\r','α\r\n中🙂\n\t\nlast','a\r\r\n\n尾','x\u2028y\u0085z']
    for i,text in enumerate(texts):
        for j,content in enumerate(['','one','one\ntwo\nthree\nfour','中🙂\x00\r\n尾']):
            for anchor in [0,-1]:
                yield make(f'endings-{i}-{j}-{anchor}',text,[{'operation':'insert','start':anchor,'content':content}])
    for endpoint in [None,False,True,[],{},[1,'x'],{'a':None},1,-2,1.0,-0.0,1e-7,9223372036854775808,
                     '', 'bad','0:aa','1:00', '999:ff','\u3000'+line_id(1,'alpha')+'\u00a0']:
        yield make('endpoint-'+str(index),ops=[{'operation':'replace','start':endpoint,'content':'changed'}])
    for content in ['', 'new', ['new','last'], 'line0\nline1\nline2\nline3\nline4']:
        yield make('replace-valid-'+str(index),ops=[{'operation':'replace','start':line_id(1,'alpha'),'end':line_id(2,'beta'),'content':content}])
    yield make('empty-operations',ops=[])
    for n in [50,51]:yield make('operation-count-'+str(n),ops=[{'operation':'insert','start':0,'content':'x'}]*n)
    yield make('duplicate-next',ops=[{'operation':'insert','start':0,'content':'alpha'}])
    yield make('duplicate-block',ops=[{'operation':'insert','start':0,'content':'alpha\nbeta'}])
    yield make('conflict-replace',ops=[{'operation':'replace','start':line_id(1,'alpha'),'end':line_id(2,'beta'),'content':'x'},
                                     {'operation':'replace','start':line_id(2,'beta'),'content':'y'}])
    shape=[{'operation':'insert','start':0,'content':'new first'},
           {'operation':'replace','start':line_id(2,'beta'),'content':'changed\nchanged2'},
           {'operation':'insert','start':-1,'content':'new last'}]
    for n,ops in enumerate(itertools.permutations(shape)):yield make('ordered-'+str(n),ops=list(ops))
    yield make('missing',None)
    yield make('directory',None,actions=[{'kind':'mkdir','path':'file'}])
    yield make('invalid-utf8',b'a\xffb\n')
    yield make('embedded-nul-path',path='file\0tail')
    yield make('literal-pipe-path',None,path='a|b',actions=[{'kind':'write','path':'a|b','bytes':b'pipe\n','mode':0o600}],probes=['a|b'])
    yield make('newline-path',None,path='a\nb',actions=[{'kind':'write','path':'a\nb','bytes':b'newline\n','mode':0o600}],probes=['a\nb'])
    yield make('relative-alias',path='./file',cache='alpha\nbeta\ngamma\n')
    yield make('symlink-replacement',None,actions=[{'kind':'write','path':'target','bytes':b'target\n','mode':0o604},
               {'kind':'symlink','path':'file','target':'target'}],cache='target\n',probes=['file','target'])
    yield make('hardlink-replacement',actions=[{'kind':'hardlink','path':'alias','target':'file'}],probes=['file','alias'])
    yield make('dangling-link',None,actions=[{'kind':'symlink','path':'file','target':'absent'}])
    yield make('temp-directory-error',actions=[{'kind':'mkdir','path':'.octofs_tmp_file.tmp'}],cache='alpha\nbeta\ngamma\n')
    yield make('history-second-read',hooks=[{'event':'read','occurrence':1,'actions':[{'kind':'write','path':'file','bytes':b'changed by outside writer\n','mode':0o640}]}])
    yield make('history-invalid-utf8',hooks=[{'event':'read','occurrence':1,'actions':[{'kind':'write','path':'file','bytes':b'bad\xff','mode':0o640}]}])
    yield make('disappear-before-first-read',hooks=[{'event':'exists','occurrence':1,'actions':[{'kind':'remove','path':'file'}]}])
    yield make('history-no-longer-exists',hooks=[{'event':'read','occurrence':1,'actions':[{'kind':'remove','path':'file'}]}])
    yield make('history-disappear-after-exists',hooks=[{'event':'exists','occurrence':2,'actions':[{'kind':'remove','path':'file'}]}])
    yield make('cache-current',cache='alpha\nbeta\ngamma\n')
    yield make('cache-stale',cache='different\n')
    yield make('cache-crlf',raw='alpha\r\nbeta\r\ngamma\r\n',cache='alpha\nbeta\ngamma\n')
    rng=random.Random(0xBC0A11)
    for ordinal in range(40):
        lines=[f'old-{ordinal}-{i}-'+rng.choice(['中','🙂','x','\t']) for i in range(rng.randrange(1,25))]
        ending=rng.choice(['\n','\r\n']);raw=ending.join(lines)+(ending if rng.randrange(2) else '')
        n=rng.randrange(1,len(lines)+1)
        ops=[{'operation':'replace','start':line_id(n,lines[n-1]),'content':f'new-{ordinal}\nextra'}]
        yield make('random-'+str(ordinal),raw,ops)
    long='x'*(2*1024*1024+33)
    yield make('no-view-8mib-result-gate','\n'.join([long]*5)+'\n',
               [{'operation':'replace','start':line_id(3,long),'content':'replacement'}],large=True)
    yield make('incoming-over8mib','a\nb\nc\n',[{'operation':'replace','start':line_id(2,'b'),'content':'Z'*(8388608+123)}],large=True)
    yield make('cache-entry-over1mib','a\n',cache='a\n',ops=[{'operation':'insert','start':0,'content':'large'*220000}],large=True)
    # Preflight must precede even existence/lock lookup. The absent target is
    # intentional, so a wrongly reordered filesystem stage is observable.
    yield make('empty-before-missing',None,ops=[])
    yield make('limit-before-missing',None,ops=[{'operation':'insert','start':0,'content':'x'}]*51)
    yield make('empty-path-is-workdir',path='')
    yield make('mode-executable',actions=[{'kind':'chmod','path':'file','mode':0o751}])
    yield make('mode-readonly-readable',actions=[{'kind':'chmod','path':'file','mode':0o400}])
    yield make('read-eacces',actions=[{'kind':'chmod','path':'file','mode':0}])
    yield make('history-eacces',hooks=[{'event':'read','occurrence':1,
        'actions':[{'kind':'chmod','path':'file','mode':0}]}])
    yield make('metadata-missing-after-history',hooks=[{'event':'history','occurrence':1,
        'actions':[{'kind':'remove','path':'file'}]}])
    yield make('temp-preexisting-file',actions=[{'kind':'write','path':'.octofs_tmp_file.tmp',
        'bytes':b'old temporary bytes\n','mode':0o611}],probes=['file','.octofs_tmp_file.tmp'])
    yield make('temp-hardlink-to-source',actions=[{'kind':'hardlink','path':'.octofs_tmp_file.tmp','target':'file'}],
        probes=['file','.octofs_tmp_file.tmp'])
    yield make('temp-symlink-owned-target',actions=[{'kind':'write','path':'owned-target','bytes':b'old\n','mode':0o640},
        {'kind':'symlink','path':'.octofs_tmp_file.tmp','target':'owned-target'}],
        probes=['file','.octofs_tmp_file.tmp','owned-target'])
    yield make('atomic-metadata-then-remove',hooks=[{'event':'atomic_metadata','occurrence':1,
        'actions':[{'kind':'remove','path':'file'}]}])
    yield make('atomic-permissions-failure',hooks=[{'event':'atomic_write','occurrence':1,
        'actions':[{'kind':'remove','path':'.octofs_tmp_file.tmp'}]}],probes=['file','.octofs_tmp_file.tmp'])
    yield make('atomic-rename-failure',hooks=[{'event':'atomic_permissions','occurrence':1,
        'actions':[{'kind':'remove','path':'file'},{'kind':'mkdir','path':'file'}]}],
        probes=['file','.octofs_tmp_file.tmp'])
    yield make('atomic-success-then-external-change',cache='alpha\nbeta\ngamma\n',hooks=[{'event':'atomic_rename','occurrence':1,
        'actions':[{'kind':'write','path':'file','bytes':b'outside after rename\n','mode':0o600}]}])
    # UTF-8 tool path plus raw Unix cwd is reachable without changing the
    # original string/path resolution logic. Setup paths are relative to cwd.
    yield make('raw-cwd-invalid-utf8',workdir_rel_hex=b'raw-\xff-\xfe'.hex())
    yield make('raw-cwd-unicode',workdir_rel_hex='会话🙂'.encode().hex())
    yield make('new-source-key-after-symlink-replacement',None,actions=[
        {'kind':'write','path':'target','bytes':b'target\n','mode':0o604},
        {'kind':'symlink','path':'file','target':'target'}],cache='target\n',
        probes=['file','target','.octofs_tmp_file.tmp'])
    # Shared HistoryStore and lock map survive requests; caches are session
    # scoped. Every step is a real edit of the prior step's actual result.
    for step in range(12):
        yield make('history-sequence-'+str(step),raw='origin\n' if step==0 else None,
            ops=[{'operation':'insert','start':-1,'content':f'append-{step}'}],
            cache='origin\n' if step==0 else None,sequence='history-retention',reset=step==0)
    yield make('history-sequence-atomic-failure',raw=None,sequence='history-retention',reset=False,
        actions=[{'kind':'mkdir','path':'.octofs_tmp_file.tmp'}])
    yield make('history-sequence-after-failure',raw=None,sequence='history-retention',reset=False,
        actions=[{'kind':'remove','path':'.octofs_tmp_file.tmp'}])
    yield make('shared-two-sessions-first',raw='a\n',cache='a\n',sequence='sessions-global-history',session=0)
    yield make('shared-two-sessions-second',raw=None,cache='prefix\na\n',sequence='sessions-global-history',session=1,reset=False,
        ops=[{'operation':'insert','start':0,'content':'other session'}])
    yield make('shared-two-sessions-first-again',raw=None,sequence='sessions-global-history',session=0,reset=False,
        ops=[{'operation':'insert','start':-1,'content':'last'}])
    # Native and original binary capture retain this body. Public SDK transport
    # has its own framing/error domain; it must not be silently substituted.
    yield make('incoming-over32mib','a\nb\nc\n',
        ops=[{'operation':'replace','start':line_id(2,'b'),'content':'W'*(32*1024*1024+129)}],large=True)
    yield make('cancel-first-read-fifo',raw=None,actions=[{'kind':'fifo','path':'file','mode':0o600}],
        execution='async',cancel={'stage':'first_read','barrier':'actual-open-wait-for-partner',
        'transfer_bytes':('alpha\nbeta\ngamma\n'*10000).encode(),'after':'join-and-followup'})
    yield make('cancel-atomic-temp-fifo',actions=[{'kind':'fifo','path':'.octofs_tmp_file.tmp','mode':0o600}],
        ops=[{'operation':'insert','start':-1,'content':'late body\n'*20000}],execution='async',
        cancel={'stage':'atomic_write','barrier':'actual-open-wait-for-partner','after':'drain-join-and-followup'},
        probes=['file','.octofs_tmp_file.tmp'])

def write_input(stream):
    stream.write(INPUT+bytes(8));n=0
    for row in iter_cases():stream.write(record(row['metadata'],row['blobs']));n+=1
    stream.seek(8);stream.write(struct.pack('<Q',n));stream.seek(0,2)
    return n
