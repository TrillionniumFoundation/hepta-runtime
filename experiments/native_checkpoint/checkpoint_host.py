# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Explicit same-host CRIU snapshots under existing sudo authority.
Private root-owned images are never returned. No application checkpoint code,
network locking, kernel policy changes, or automatic replay after uncertain restore.
"""
import fcntl
import hashlib
import json
import os
import pathlib
import re
import select
import signal
import stat
import subprocess
import sys
import time

BASE=pathlib.Path('/var/lib/hepta-runtime-checkpoints')


def fingerprint(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as source:
        st=os.fstat(source.fileno())
        if not stat.S_ISREG(st.st_mode):raise ValueError('checkpoint image must be regular')
        h=hashlib.sha256()
        for part in iter(lambda:source.read(1024*1024),b''):h.update(part)
        after=os.fstat(source.fileno())
        if (st.st_ino,st.st_size,st.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError('checkpoint image changed')
    return h.hexdigest()


def identity(pid):
    if not isinstance(pid,int) or isinstance(pid,bool) or pid<=1:raise ValueError('one positive non-system PID required')
    root=pathlib.Path('/proc')/str(pid);text=(root/'stat').read_text();parts=text[text.rfind(')')+2:].split()
    if parts[0]=='Z':raise ProcessLookupError('process is a zombie')
    uidline=next(line for line in (root/'status').read_text().splitlines() if line.startswith('Uid:'))
    uids=list(map(int,uidline.split()[1:]))
    if len(set(uids))!=1:raise ValueError('set-identity process checkpoint is not qualified')
    return {'pid':pid,'uid':uids[0],'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'start_ticks':int(parts[19])}


def inventory(pid,uid):
    observed=identity(pid)
    if observed['uid']!=uid:raise PermissionError('snapshot target must belong to the original SSH login')
    pids=[pid]
    for parent in pids:
        for task in (pathlib.Path('/proc')/str(parent)/'task').iterdir():
            for child in map(int,(task/'children').read_text().split()):
                if child not in pids:pids.append(child)
        if len(pids)>128:raise ValueError('process-tree snapshot budget exceeded')
    resources=[];pipes={};reasons=[]
    if len(pids)!=1:reasons.append('multi-process trees require separately qualified coordinated lifecycle')
    for child in pids:
        who=identity(child)
        if who['uid']!=uid:reasons.append('mixed-UID process tree')
        for fd in (pathlib.Path('/proc')/str(child)/'fd').iterdir():
            try:
                link=os.readlink(fd);st=fd.stat()
                info={'pid':child,'fd':int(fd.name),'kind':'regular' if stat.S_ISREG(st.st_mode) else 'other'}
                if link.startswith('pipe:['):
                    flags=next(line for line in (fd.parent.parent/'fdinfo'/fd.name).read_text().splitlines() if line.startswith('flags:'))
                    pipes.setdefault(link,set()).add(int(flags.split()[1],8)&3);info['kind']='pipe'
                elif link.startswith('socket:['):reasons.append('sockets require an external-resource contract');info['kind']='socket'
                elif stat.S_ISCHR(st.st_mode) and link not in ('/dev/null','/dev/zero','/dev/random','/dev/urandom'):
                    reasons.append('terminal/device state needs explicit remapping');info['kind']='device'
                elif link.endswith(' (deleted)'):reasons.append('unlinked file snapshot not qualified')
                resources.append(info)
            except FileNotFoundError:raise ValueError('descriptor tree changed during inspection') from None
    if any(not {0,1}<=directions and 2 not in directions for directions in pipes.values()):reasons.append('external pipe endpoints need an owner handoff manifest')
    if identity(pid)!=observed:raise ValueError('target identity changed during inspection')
    return {'identity':observed,'process_count':len(pids),'resources':resources,'ready':not reasons,'limitations':sorted(set(reasons)),
            'application_checkpoint_required':False,'scope':'same-host Linux compatible process trees, regular files and internal pipes'}


def private_directory(path):
    if not path.exists():path.mkdir(mode=0o700)
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077:raise PermissionError('checkpoint directory must be root-owned private non-symlink directory')


def save(path,value):
    temp=path.with_name(path.name+'.new')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
        os.replace(temp,path);fd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temp.exists():temp.unlink()


def main(q):
    if sys.platform!='linux' or os.geteuid()!=0:raise PermissionError('Linux checkpoint requires existing explicit sudo authorization')
    uid=int(os.environ['SUDO_UID']);binary=pathlib.Path(q['configured_binary'])
    if not binary.is_absolute() or fingerprint(binary)!=q['configured_sha256']:raise ValueError('administrator-pinned CRIU artifact differs')
    action=q['action']
    if action=='inspect':return inventory(q['pid'],uid)
    if not q.get('acknowledge_process_stop'):raise ValueError('snapshot/restore lifecycle requires explicit process-stop acknowledgement')
    name=q['checkpoint_id']
    if not re.fullmatch(r'[A-Za-z0-9_-]{8,80}',name):raise ValueError('invalid checkpoint identity')
    private_directory(BASE);directory=BASE/str(uid);private_directory(directory)
    root=directory/name
    if action=='dump' and not root.exists():private_directory(root)
    private_directory(root)
    lock=os.open(root/'operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        meta_path=root/'state.json';state=json.loads(meta_path.read_text()) if meta_path.exists() else None
        if state:
            if state['uid']!=uid or state['criu_sha256']!=q['configured_sha256']:raise ValueError('checkpoint authority/artifact differs')
            if action=='status':
                result={k:v for k,v in state.items() if k not in ('images','resources')}
                result['private_image_count']=len(state.get('images',{}));result['images_exported']=False
                if state.get('restored_identity'):
                    try:result['restored_process_alive']=identity(state['restored_identity']['pid'])==state['restored_identity']
                    except (FileNotFoundError,ProcessLookupError):result['restored_process_alive']=False
                return result
            if action=='dump':
                if state['original_identity']!=q['expected_identity']:raise ValueError('checkpoint ID replay has different target identity')
                return {'checkpoint_id':name,'state':state['state'],'reused':True,'images_exported':False}
        if action=='dump':
            ready=inventory(q['pid'],uid)
            if not ready['ready']:raise ValueError('unsupported external resource contract: '+', '.join(ready['limitations']))
            if ready['identity']!=q['expected_identity']:raise ValueError('stale process identity; no process stopped')
            pidfd=os.pidfd_open(q['pid']);stopped=False
            try:
                if identity(q['pid'])!=q['expected_identity']:raise ValueError('process identity changed before stop')
                signal.pidfd_send_signal(pidfd,signal.SIGSTOP);stopped=True
                if identity(q['pid'])!=q['expected_identity']:raise ValueError('process identity changed after stop')
                images=root/'images';private_directory(images)
                state={'state':'dumping','checkpoint_id':name,'uid':uid,'criu_sha256':q['configured_sha256'],'original_identity':ready['identity'],'created_at_unix':time.time()}
                save(meta_path,state)
                args=[str(binary),'dump','--tree',str(q['pid']),'--images-dir',str(images),'--work-dir',str(images),'--log-file','dump.log','--shell-job','--leave-stopped','-v4']
                result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=55)
                if result.returncode:state['state']='dump_failed';save(meta_path,state);raise ValueError('CRIU dump failed; original process is resumed if still alive; private diagnostic retained')
                state['images']={p.name:fingerprint(p) for p in images.iterdir() if p.is_file() and p.suffix=='.img'}
                if not state['images']:raise ValueError('no checkpoint images produced')
                state['state']='checkpoint_validated_original_stopped';save(meta_path,state)
                signal.pidfd_send_signal(pidfd,signal.SIGKILL);stopped=False
                state['state']='dumped';save(meta_path,state)
                return {'state':'dumped','checkpoint_id':name,'original_identity':ready['identity'],'private_image_count':len(state['images']),'images_exported':False,'original_stopped_after_successful_dump':True}
            finally:
                if stopped:
                    try:signal.pidfd_send_signal(pidfd,signal.SIGCONT)
                    except ProcessLookupError:pass
                os.close(pidfd)
        if action!='restore' or not state:raise ValueError('unknown checkpoint operation/state')
        if state['state']=='restored':return {'state':'restored','checkpoint_id':name,'reused':True,'restored_identity':state['restored_identity']}
        if state['state']!='dumped':raise ValueError('checkpoint outcome requires reconciliation; refusing automatic duplicate restore')
        if pathlib.Path('/proc',str(state['original_identity']['pid'])).exists():raise ValueError('original PID remains occupied; reap original owner before restore')
        images=root/'images'
        if any(fingerprint(images/name)!=sha for name,sha in state['images'].items()):raise ValueError('private checkpoint image fingerprint changed')
        state['state']='restore_started';save(meta_path,state)
        pidfile=root/'restored.pid'
        args=[str(binary),'restore','--images-dir',str(images),'--work-dir',str(images),'--log-file','restore.log','--shell-job','--restore-detached','--pidfile',str(pidfile),'-v4']
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=55)
        if result.returncode:
            state['state']='restore_failed_or_partial';save(meta_path,state);raise ValueError('CRIU restore failed; reconcile private state before retry, no automatic application relaunch')
        restored=identity(int(pidfile.read_text()));assert restored['uid']==uid and restored['pid']==state['original_identity']['pid']
        state.update(state='restored',restored_identity=restored);save(meta_path,state)
        return {'state':'restored','checkpoint_id':name,'reused':False,'restored_identity':restored,'images_exported':False,'same_numeric_pid':True}
    finally:os.close(lock)


if __name__=='__main__':
    try:print(json.dumps(main(json.load(sys.stdin))))
    except Exception as error:
        print(type(error).__name__+': '+str(error)[:1600],file=sys.stderr);raise SystemExit(1)
