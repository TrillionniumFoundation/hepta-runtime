"""Owned fixture declarations for actual local atomic-write parity."""
from __future__ import annotations
import errno,gzip,hashlib,json,os,stat
from pathlib import Path

def file(path,data=b'original',mode=0o751):
    return {'kind':'file','path':path.hex(),'data':data.hex(),'mode':mode}
def directory(path,mode=0o755):return {'kind':'directory','path':path.hex(),'mode':mode}
def link(path,target,kind='symlink'):return {'kind':kind,'path':path.hex(),'target':target.hex()}
def data(case):
    spec=case['content'];return bytes.fromhex(spec['pattern'])*spec['repeat']
def make(name,path=b'target',content=b'replacement\n',entries=None,config=None,checks=None):
    return {'name':name,'path':path.hex(),'content':{'pattern':content.hex(),'repeat':1},
      'entries':[file(b'target')] if entries is None else entries,'config':{} if config is None else config,'checks':{} if checks is None else checks}
def cases():
    out=[make('existing'),make('new',entries=[]),make('empty-content',content=b''),make('content-nul',content=b'a\0b\n'),
      make('unicode-content',content='甲乙\r\n🙂\u2028é'.encode()),make('read-only-target',entries=[file(b'target',mode=0o444)]),
      make('preexisting-temp',entries=[file(b'target'),file(b'.octofs_tmp_target.tmp',b'stale',0o600)]),
      make('temp-read-only',entries=[file(b'target'),file(b'.octofs_tmp_target.tmp',b'stale',0o400)]),
      make('target-directory',entries=[directory(b'target')]),make('temp-directory',entries=[file(b'target'),directory(b'.octofs_tmp_target.tmp')]),
      make('missing-parent',path=b'missing/target',entries=[]),make('non-directory-parent',path=b'parent/target',entries=[file(b'parent')]),
      make('denied-parent',path=b'denied/target',entries=[directory(b'denied',0)]),
      make('target-symlink',entries=[file(b'other',b'other-data',0o4751),link(b'target',b'other')]),
      make('dangling-target',entries=[link(b'target',b'absent')]),
      make('target-loop',entries=[link(b'target',b'target')]),
      make('temp-symlink',entries=[file(b'target'),file(b'other',b'other-data',0o600),link(b'.octofs_tmp_target.tmp',b'other')]),
      make('temp-dangling-symlink',entries=[file(b'target'),link(b'.octofs_tmp_target.tmp',b'other')]),
      make('temp-loop',entries=[file(b'target'),link(b'.octofs_tmp_target.tmp',b'.octofs_tmp_target.tmp')]),
      make('temp-hardlink-to-target',entries=[file(b'target'),link(b'.octofs_tmp_target.tmp',b'target','hardlink')]),
      make('target-extra-hardlink',entries=[file(b'target'),link(b'old-alias',b'target','hardlink')]),
      make('temp-hardlink-to-other',entries=[file(b'target'),file(b'other',b'other-data',0o600),link(b'.octofs_tmp_target.tmp',b'other','hardlink')])]
    for mode in (0,1,0o111,0o200,0o400,0o600,0o640,0o644,0o700,0o755,0o777,0o1000,0o2000,0o4000,0o4755,0o2750,0o6751,0o7777):
        out.append(make('mode-'+oct(mode),entries=[file(b'target',mode=mode)],checks={'target_mode':mode}))
    for name,path,entries in [
      ('empty-path',b'',[]),('dot-path',b'.',[]),('dot-dot-path',b'..',[]),
      ('dot-prefix',b'./target',[file(b'target')]),('repeated-separator',b'dir//./target',[directory(b'dir'),file(b'dir/target')]),
      ('parent-component',b'dir/../target',[directory(b'dir'),file(b'target')]),
      ('trailing-slash-file',b'target/',[file(b'target')]),('trailing-dot-file',b'target/.',[file(b'target')]),
      ('ending-parent-component',b'dir/sub/..',[directory(b'dir'),directory(b'dir/sub')]),
      ('raw-filename',b'raw-\xff\x80',[file(b'raw-\xff\x80')]),
      ('raw-parent',b'parent-\xff/leaf-\xfe',[directory(b'parent-\xff'),file(b'parent-\xff/leaf-\xfe')]),
      ('incomplete-utf8-name',b'\xe2\x82',[file(b'\xe2\x82')]),
      ('unicode-name','文件🙂'.encode(),[file('文件🙂'.encode())]),
      ('nul-filename',b'a\0b',[]),('nul-parent',b'a\0b/c',[]),
      ('parent-symlink',b'alias/target',[directory(b'real'),file(b'real/target'),link(b'alias',b'real')])]:
        out.append(make(name,path=path,entries=entries))
    for count in (238,239,240,254,255,256):
        name=b'x'*count
        out.append(make('filename-bytes-'+str(count),path=name,entries=[file(name)] if count<=255 else []))
    for count in (79,80,85):
        name=b'\xff'*count
        out.append(make('lossy-filename-expansion-'+str(count),path=name,entries=[file(name)]))
    for length in (4095,4096,4097):
        out.append(make('kernel-path-length-'+str(length),path=b'a'*length,entries=[]))
    for count in (1,4096,65536,1048576,5242880):
        c=make('content-bytes-'+str(count));c['content']={'pattern':'61','repeat':count};out.append(c)
    # 50 maximum 5 MiB insertion payloads can each expand LF to CRLF;
    # including the maximum initial 5 MiB file still fits the existing
    # 512 MiB request profile. atomic_write imposes no new text-size limit.
    c=make('full-batch-crlf-write-505-mib');c['content']={'pattern':'0d0a','repeat':(505<<20)//2};out.append(c)
    out.append(make('actual-partial-write',content=b'0123456789',config={'file_size_limit':3}))
    out.append(make('actual-zero-limit',content=b'0123456789',config={'file_size_limit':0}))
    for kind in ('statx','stat','open','write','close','chmod','rename','unlink'):
        for error in (errno.EINTR,errno.EIO,errno.EACCES,errno.ENOSPC):
            faults=[]
            if kind=='stat':faults=[{'kind':'statx','errno':errno.ENOSYS},{'kind':'statx_probe','errno':errno.ENOSYS}]
            if kind=='unlink':faults=[{'kind':'rename','errno':errno.EIO}]
            faults.append({'kind':kind,'ordinal':1,'errno':error})
            out.append(make(f'inject-{kind}-{error}',config={'faults':faults}))
    out.append(make('inject-write-zero',config={'faults':[{'kind':'write','return':0}]}))
    for error in (errno.ENOSYS,errno.EPERM,errno.EINTR,errno.EFAULT):
        out.append(make('statx-probe-'+str(error),config={'faults':[{'kind':'statx','errno':errno.EIO},{'kind':'statx_probe','errno':error}]}))
    out.append(make('statx-enosys-path-fallback',config={'faults':[{'kind':'statx','errno':errno.ENOSYS}]}))
    out.append(make('statx-enosys-missing-fallback',entries=[],config={'faults':[{'kind':'statx','errno':errno.ENOSYS}]}))
    for error in (errno.EINTR,errno.EIO,errno.EPERM,errno.ENOSYS,errno.EFAULT):
        out.append(make('statx-probe-fallback-'+str(error),config={'faults':[{'kind':'statx','errno':errno.EIO},
          {'kind':'statx_probe','errno':errno.ENOSYS},{'kind':'stat_probe_fallback','errno':error}]}))
    for kind in ('statx','statx_probe','stat','open','write','close','chmod','rename','unlink'):
        faults=[]
        if kind in ('statx_probe','stat'):faults=[{'kind':'statx','errno':errno.EIO}]
        if kind=='stat':faults.append({'kind':'statx_probe','errno':errno.EPERM})
        if kind=='unlink':faults=[{'kind':'rename','errno':errno.EIO}]
        out.append(make('cancel-'+kind,config={'faults':faults,'cancel':{'kind':kind}}))
    out.append(make('cancel-statx-path-fallback',config={'faults':[{'kind':'statx','errno':errno.ENOSYS}],'cancel':{'kind':'stat'}}))
    out.append(make('cancel-statx-probe-fallback',config={'faults':[{'kind':'statx','errno':errno.EIO},
      {'kind':'statx_probe','errno':errno.ENOSYS}],'cancel':{'kind':'stat_probe_fallback'}}))
    for name,entries,faults in [
      ('statx-present-cache',[file(b'target')],[{'kind':'statx','ordinal':2,'errno':errno.ENOSYS}]),
      ('statx-unavailable-cache',[file(b'target')],[{'kind':'statx','errno':errno.EIO},{'kind':'statx_probe','errno':errno.EPERM}]),
      ('statx-first-missing-cache',[],[{'kind':'statx','ordinal':2,'errno':errno.EIO}]),
      ('statx-first-error-cache',[file(b'target')],[{'kind':'statx','ordinal':1,'errno':errno.EIO},{'kind':'statx','ordinal':2,'errno':errno.ENOSYS}])]:
        c=make(name,entries=entries,config={'faults':faults});c['requests']=3;out.append(c)
    for kind in ('statx','statx_probe','stat','open','write','close','chmod','rename','unlink','statx-path-fallback','statx-probe-fallback'):
        original=next(c for c in out if c['name']=='cancel-'+kind)
        c=json.loads(json.dumps(original));c['name']='cancel-recovery-'+kind;c['requests']=2;out.append(c)
    for name in ('cancel-write','cancel-recovery-statx-probe-fallback'):
        original=next(c for c in out if c['name']==name)
        c=json.loads(json.dumps(original));c['name']='blocked-'+name;c['config']['blocked_cancel']=True;out.append(c)
    for mask in (0,0o027,0o777):
        out.append(make('new-file-umask-'+oct(mask),entries=[],config={'umask':mask},checks={'target_mode':0o666&~mask}))
    assert len({x['name'] for x in out})==len(out)
    return out

def setup(root,case):
    root=Path(root);root.mkdir(mode=0o700)
    entries=case['entries'];later=[]
    for entry in entries:
        path=os.fsencode(root)+b'/'+bytes.fromhex(entry['path'])
        assert not bytes.fromhex(entry['path']).startswith(b'/') and b'..' not in bytes.fromhex(entry['path']).split(b'/')
        if entry['kind']=='directory':os.mkdir(path,0o700);later.append((path,entry['mode']))
        elif entry['kind']=='file':
            with open(path,'wb') as f:f.write(bytes.fromhex(entry['data']))
            os.chmod(path,entry['mode'])
        elif entry['kind']=='symlink':os.symlink(bytes.fromhex(entry['target']),path)
        elif entry['kind']=='hardlink':os.link(os.fsencode(root)+b'/'+bytes.fromhex(entry['target']),path)
        else:raise ValueError('unknown fixture kind')
    for path,mode in reversed(later):os.chmod(path,mode)

def snapshot(root,contents=None):
    root=os.fsencode(root);rows=[]
    if contents is not None:
        contents=Path(contents);contents.mkdir(mode=0o700)
    def walk(path,relative):
        st=os.lstat(path)
        row={'path':relative.hex(),'mode':st.st_mode,'uid':st.st_uid,'gid':st.st_gid,'size':st.st_size,'nlink':st.st_nlink,
          'dev':st.st_dev,'inode':st.st_ino,'mtime_ns':st.st_mtime_ns,'ctime_ns':st.st_ctime_ns,'atime_ns':st.st_atime_ns}
        rows.append(row)
        if stat.S_ISLNK(st.st_mode):row['symlink']=os.fsencode(os.readlink(path)).hex();return
        if stat.S_ISREG(st.st_mode):
            changed=False
            try:f=open(path,'rb')
            except PermissionError:
                os.chmod(path,stat.S_IMODE(st.st_mode)|0o400);changed=True;f=open(path,'rb')
            try:
                digest=hashlib.sha256();size=0
                saved=None
                if contents is not None:
                    row['content_archive']=f'{len(rows)-1:04d}.bin.gz';saved=gzip.open(contents/row['content_archive'],'wb')
                try:
                    with f:
                        while part:=f.read(1<<20):
                            digest.update(part);size+=len(part)
                            if saved is not None:saved.write(part)
                finally:
                    if saved is not None:saved.close()
                row['content_sha256']=digest.hexdigest();row['content_bytes']=size
            finally:
                if changed:os.chmod(path,stat.S_IMODE(st.st_mode));row['inspection_temporarily_added_read']=True
        if stat.S_ISDIR(st.st_mode):
            changed=False
            if (st.st_mode&0o500)!=0o500:os.chmod(path,stat.S_IMODE(st.st_mode)|0o500);changed=True
            try:
                for name in sorted(os.listdir(path)):walk(path+b'/'+name,name if not relative else relative+b'/'+name)
            finally:
                if changed:os.chmod(path,stat.S_IMODE(st.st_mode));row['inspection_temporarily_added_directory_access']=True
    walk(root,b'');return rows

def semantic_snapshot(before,after,uid=None,gid=None):
    uid=os.geteuid() if uid is None else uid;gid=os.getegid() if gid is None else gid
    previous={r['path']:r for r in before};groups={}
    for r in after:groups.setdefault((r['dev'],r['inode']),[]).append(r['path'])
    result=[]
    for r in after:
        old=previous.get(r['path']);same=old is not None and (old['dev'],old['inode'])==(r['dev'],r['inode'])
        row={k:r[k] for k in ('path','mode','nlink','content_bytes','content_sha256','symlink') if k in r}
        row['identity_retained']=same;row['same_inode_paths']=sorted(groups[(r['dev'],r['inode'])])
        row['uid_is_current']=r['uid']==uid;row['gid_is_current']=r['gid']==gid
        # Directory sizes and all timestamps are retained in raw observations;
        # allocation layout and real clock values are not deterministic outputs.
        if not stat.S_ISDIR(r['mode']):row['size']=r['size']
        result.append(row)
    return result

def normalized_trace(trace,fixture):
    prefix=os.fsencode(fixture);rows=[]
    for item in trace['events']:
        row={k:v for k,v in item.items() if k not in ('pid','ip','fd')}
        for key in ('path_hex','destination_hex','fd_path_hex'):
            if key in row:
                raw=bytes.fromhex(row[key])
                if raw==prefix or raw.startswith(prefix+b'/'):raw=b'<fixture>'+raw[len(prefix):]
                row[key]=raw.hex()
        rows.append(row)
    return rows
