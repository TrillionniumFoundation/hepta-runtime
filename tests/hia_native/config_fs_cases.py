"""Run both retained executables on independent owned equivalent fixtures."""
from pathlib import Path
import fcntl,hashlib,json,os,stat,struct,subprocess,tempfile,time,tomllib
from test_config_fs import Session,COUNTS

ROOT=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()

def private_error(result,path):
    stage,error=result['status'],result['errno'];display=os.fsdecode(path).encode('utf-8','replace').decode()
    # Rust Path::display is lossy UTF8; use byte decoding directly for Unix paths.
    display=os.fsencode(path).decode('utf-8','replace')
    canonical=result['path'].decode('utf-8','replace')
    system=os.strerror(error)+f' (os error {error})'
    if stage==1:return f'cannot create controller state directory {display}'
    if stage in (2,3,6,10):return system
    if stage==4:return 'controller state directory must be owned by the current user with mode 0700'
    if stage==5:
        name='controller.owner.lock' if result['detail']==0 else 'controller.lock'
        return 'cannot open controller lock '+canonical.rstrip('/')+'/'+name
    if stage==7:return 'controller owner lock must be a regular file'
    if stage==8:return 'controller owner lock has foreign ownership or hard links'
    if stage==9:return 'controller owner lock must not be group/world accessible'
    if stage==11:
        text='lock acquisition failed because the operation would block' if error==11 else system
        return f'controller state directory {canonical} is already owned or cannot be locked: {text}'
    if stage==12:return 'controller state subdirectory '+('jobs' if result['detail']==1 else 'audit')+' must not be a symlink'
    raise AssertionError(result)

def fixture(name,root):
    root.mkdir(mode=0o700);state=root/'state';path=os.fsencode(state);held=None
    if name=='new_nested':path=os.fsencode(root)+b'/one/two/state'
    elif name=='parent_components':path=os.fsencode(root)+b'/one/../state'
    elif name=='inner_dots':path=os.fsencode(root)+b'/one/./state'
    elif name=='trailing_dot_missing':path=os.fsencode(root)+b'/state/.'
    elif name=='trailing_dot_existing':state.mkdir(mode=0o700);path+=b'/.'
    elif name=='redundant_slashes':path=b'//'+os.fsencode(root).lstrip(b'/')+b'///state//'
    elif name=='unicode':path=os.fsencode(root)+b'/\xe4\xb8\xad-\xf0\x9f\x98\x80'
    elif name=='raw_bytes':path=os.fsencode(root)+b'/raw-\xff-state'
    elif name=='short_symlink':os.symlink('.',root/'alias');path=os.fsencode(root)+b'/alias/one/two/../state'
    elif name=='long_symlink':
        (root/'target'/'nested').mkdir(parents=True,mode=0o700);os.symlink('target/nested',root/'a');path=os.fsencode(root/'a/state')
    elif name=='absolute_symlink':
        (root/'target').mkdir(mode=0o700);os.symlink(root/'target',root/'alias');path=os.fsencode(root/'alias/state')
    elif name in ['state_755','state_1777','state_4700']:
        state.mkdir();os.chmod(state,int(name.split('_')[1],8))
    elif name.startswith('owner_') or name.startswith('legacy_'):
        state.mkdir(mode=0o700);legacy=name.startswith('legacy_');lock=state/('controller.lock' if legacy else 'controller.owner.lock');target=root/'target';kind=name.split('_',1)[1]
        if kind in ['644','4600']:
            lock.write_bytes(b'payload');os.chmod(lock,int(kind,8))
        elif kind=='hardlink':target.write_bytes(b'keep');os.chmod(target,0o600);os.link(target,lock)
        elif kind=='symlink':target.write_bytes(b'keep');os.symlink(target,lock)
        elif kind=='fifo':os.mkfifo(lock,0o600)
        elif kind=='directory':lock.mkdir(mode=0o700)
        elif kind=='blocked':held=os.open(lock,os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
    elif name.startswith('jobs_') or name.startswith('audit_'):
        state.mkdir(mode=0o700);sub=state/name.split('_')[0]
        if name.endswith('symlink'):
            target=root/'target';target.mkdir(mode=0o755);os.chmod(target,0o755);os.symlink(target,sub)
        elif name.endswith('file'):sub.write_bytes(b'keep')
        else:sub.mkdir(mode=0o777);os.chmod(sub,0o777)
    elif name=='regular_state':state.write_bytes(b'keep')
    elif name=='regular_parent':state.write_bytes(b'keep');path+=b'/child'
    elif name=='cycle':os.symlink('state',state)
    elif name=='long_component':path=os.fsencode(root)+b'/'+b'x'*256
    elif name=='nul':path=os.fsencode(root)+b'/bad\0path'
    elif name!='new':raise AssertionError(name)
    return path,held

def normalized(raw,root):return raw.replace(os.fsencode(root),b'/FIXTURE')

def snapshot(root):
    result={};todo=[os.fsencode(root)]
    while todo:
        directory=todo.pop()
        for entry in sorted(os.scandir(directory),key=lambda x:x.name):
            m=entry.stat(follow_symlinks=False);rel=os.path.relpath(entry.path,os.fsencode(root));row={'mode':stat.S_IMODE(m.st_mode),'uid':m.st_uid,'nlink':m.st_nlink,'kind':stat.S_IFMT(m.st_mode)}
            if stat.S_ISDIR(m.st_mode):todo.append(entry.path)
            if stat.S_ISLNK(m.st_mode):row['target_hex']=normalized(os.readlink(entry.path),root).hex()
            if stat.S_ISREG(m.st_mode):row['content_sha256']=sha(Path(os.fsdecode(entry.path)).read_bytes())
            result[rel.hex()]=row
    return result

def run_case(binary,name,root,native):
    path,held=fixture(name,root);rows=[]
    try:
        with Session(binary,umask=0) as session:
            for label,current in [('requested',path),('recovery',os.fsencode(root/'recovery'))]:
                out=session.call(current)
                if out['status']==0:
                    rows.append({'label':label,'status':'ok','path_hex':normalized(out['path'],root).hex(),'snapshot':snapshot(root)})
                    released=session.call(handles=out['handles']);assert released['status']==0 and released['path']==b''
                else:
                    error=private_error(out,current).encode() if native else out['path']
                    rows.append({'label':label,'status':'error','error_hex':normalized(error,root).hex(),'snapshot':snapshot(root)})
    finally:
        if held is not None:os.close(held)
    return rows
