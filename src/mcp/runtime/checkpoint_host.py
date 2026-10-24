# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Pinned, same-boot Linux checkpoint lifecycle with explicit restore/resume phases.
Uses existing sudo authority; private snapshots never leave the target. Restricts
admission to same-login single-process tasks with bounded thread groups with pinned regular
files, mapped-file identities and internal pipes. No generic resource remapping.
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

BASE=pathlib.Path('/var/lib/hepta-runtime-checkpoints-v2')
MAX_PIN_BYTES=512*1024*1024


def identity(pid):
    if not isinstance(pid,int) or isinstance(pid,bool) or pid<=1:raise ValueError('one non-system PID required')
    root=pathlib.Path('/proc')/str(pid);raw=(root/'stat').read_text();parts=raw[raw.rfind(')')+2:].split()
    if parts[0]=='Z':raise ProcessLookupError('target is a zombie')
    uids=list(map(int,next(x for x in (root/'status').read_text().splitlines() if x.startswith('Uid:')).split()[1:]))
    if len(set(uids))!=1:raise ValueError('set-identity process is unsupported')
    return {'pid':pid,'uid':uids[0],'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'start_ticks':int(parts[19])}


def kernel_state(pid):
    raw=pathlib.Path('/proc',str(pid),'stat').read_text()
    return raw[raw.rfind(')')+2:].split()[0]



def thread_group(pid,expected_uid=None):
    root=pathlib.Path('/proc')/str(pid)/'task'
    entries=list(root.iterdir())
    if not 1<=len(entries)<=16:raise ValueError('thread-group qualification limit is 1..16')
    result=[]
    for entry in entries:
        status=(entry/'status').read_text().splitlines()
        tgid=int(next(line for line in status if line.startswith('Tgid:')).split()[1])
        uids=list(map(int,next(line for line in status if line.startswith('Uid:')).split()[1:]))
        if tgid!=pid or len(set(uids))!=1 or (expected_uid is not None and uids[0]!=expected_uid):
            raise ValueError('thread group changed or contains mixed credentials')
        raw=(entry/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
        result.append({'tid':int(entry.name),'uid':uids[0],'start_ticks':int(fields[19]),'state':fields[0]})
    if {int(e.name) for e in root.iterdir()}!={v['tid'] for v in result}:
        raise ValueError('thread group changed during inspection')
    return sorted(result,key=lambda v:v['tid'])


def thread_identities(group):
    return [{k:v[k] for k in ('tid','uid','start_ticks')} for v in group]


def validate_stopped_threads(pid,expected):
    group=thread_group(pid)
    if thread_identities(group)!=expected:raise ValueError('restored thread identity changed; no resume performed')
    if any(v['state']!='T' for v in group):raise ValueError('not all restored threads are stopped')
    return group

def regular_read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size>limit:raise ValueError('regular-file size bound exceeded')
        value=f.read(limit+1)
        if len(value)>limit:raise ValueError('regular-file read bound exceeded')
        return value


def pin(path,budget=None):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_PIN_BYTES:raise ValueError('file cannot be pinned within snapshot bounds')
        if budget is not None:
            budget[0]+=before.st_size
            if budget[0]>MAX_PIN_BYTES:raise ValueError('snapshot file fingerprint budget exceeded')
        h=hashlib.sha256()
        for data in iter(lambda:f.read(1024*1024),b''):h.update(data)
        after=os.fstat(f.fileno())
        fields=lambda st:[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_uid,st.st_gid,st.st_mode]
        if fields(before)!=fields(after):raise ValueError('file changed during fingerprint')
        return {'stat':fields(after),'sha256':h.hexdigest()}



def external_pipe_owners(pipe_names,pid,proc_root=pathlib.Path('/proc')):
    owners=[];scanned=0
    for process in proc_root.iterdir():
        if not process.name.isdigit() or int(process.name)==pid:continue
        try:descriptors=list((process/'fd').iterdir())
        except FileNotFoundError:continue
        except PermissionError:raise ValueError('external pipe ownership could not be fully inspected') from None
        for fd in descriptors:
            scanned+=1
            if scanned>50000:raise ValueError('external pipe ownership scan budget exceeded')
            try:target=os.readlink(fd)
            except FileNotFoundError:continue
            except PermissionError:raise ValueError('external pipe ownership is unavailable') from None
            if target in pipe_names:
                owners.append({'pid':int(process.name),'fd':int(fd.name)})
                if len(owners)>128:raise ValueError('too many external pipe owners')
    return owners


def inventory(pid,uid):
    who=identity(pid)
    if who['uid']!=uid:raise PermissionError('checkpoint target must belong to the original SSH login')
    root=pathlib.Path('/proc')/str(pid);threads=list((root/'task').iterdir());children=[]
    for thread in threads:children.extend(map(int,(thread/'children').read_text().split()))
    reasons=[];resources=[];pipes={};files=set();mapped=set()
    group=thread_group(pid,uid)
    if len(threads)!=len(group):raise ValueError('thread enumeration changed')
    if children:reasons.append('child-process coordination is not qualified')
    sizes={}
    for line in (root/'status').read_text().splitlines():
        if line.startswith(('VmRSS:','VmSwap:')):sizes[line.split(':',1)[0]]=int(line.split()[1])*1024
    if sum(sizes.values())>256*1024*1024:reasons.append('resident plus swapped memory exceeds 256 MiB qualification limit')
    descriptors=list((root/'fd').iterdir())
    if len(descriptors)>128:raise ValueError('descriptor budget exceeded')
    for fd in descriptors:
        link=os.readlink(fd);st=fd.stat();kind='other'
        if link.startswith('pipe:['):
            kind='pipe';flags=next(x for x in (root/'fdinfo'/fd.name).read_text().splitlines() if x.startswith('flags:'))
            pipes.setdefault(link,set()).add(int(flags.split()[1],8)&3)
        elif stat.S_ISREG(st.st_mode):
            kind='regular'
            if not link.startswith('/') or link.endswith(' (deleted)'):reasons.append('unlinked regular file')
            else:files.add(link)
        elif stat.S_ISCHR(st.st_mode) and link in ('/dev/null','/dev/zero','/dev/random','/dev/urandom'):kind='basic_device'
        else:reasons.append('external socket/terminal/device descriptor requires owner remapping')
        resources.append({'fd':int(fd.name),'kind':kind})
    if any(not {0,1}<=directions and 2 not in directions for directions in pipes.values()):reasons.append('external pipe endpoint requires an ownership manifest')
    if pipes and external_pipe_owners(set(pipes),pid):reasons.append('another process owns a supposedly internal pipe endpoint')
    for line in (root/'maps').read_text().splitlines():
        fields=line.split(maxsplit=5)
        if len(fields)==6 and fields[5].startswith('/'):
            if fields[5].endswith(' (deleted)'):reasons.append('deleted mapped file')
            else:mapped.add(fields[5])
    if len(files|mapped)>256:reasons.append('mapped-file budget exceeded')
    if identity(pid)!=who:raise ValueError('process identity changed during inspection')
    return {'identity':who,'kernel_state':kernel_state(pid),'ready':not reasons,'limitations':sorted(set(reasons)),
            'process_count':1+len(set(children)),'thread_count':len(group),'threads':group,'resources':resources,
            'regular_file_count':len(files),'mapped_file_count':len(mapped),'private_file_paths':sorted(files|mapped)}


def private_directory(path,create=False):
    if create:
        try:path.mkdir(mode=0o700)
        except FileExistsError:pass
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077:raise PermissionError('checkpoint directory must be root-owned private and not symlinked')


def save(path,value):
    temp=path.with_name(path.name+'.new-'+str(os.getpid()))
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
        os.replace(temp,path);fd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temp.exists():temp.unlink()


def public_state(state):
    result={k:v for k,v in state.items() if k not in ('images','file_pins')}
    result['private_image_count']=len(state.get('images',{}));result['images_exported']=False
    result['requires_explicit_resume']=state['state']=='restored_stopped'
    restored=state.get('restored_identity')
    if restored:
        try:
            result['restored_identity_matches']=identity(restored['pid'])==restored
            if result['restored_identity_matches']:
                result['restored_kernel_state']=kernel_state(restored['pid'])
                if state.get('restored_threads'):
                    group=thread_group(restored['pid'])
                    result['restored_threads_match']=thread_identities(group)==state['restored_threads']
                    result['live_thread_count']=len(group)
                    result['all_threads_stopped']=all(t['state']=='T' for t in group)
        except (FileNotFoundError,ProcessLookupError):result['restored_identity_matches']=False
    return result


def require_identity(actual,expected):
    if actual!=expected:raise ValueError('stale process identity; no signal or replay performed')


def resume(state,q,meta):
    expected=state.get('restored_identity')
    if not q.get('acknowledge_resume') or not expected:raise ValueError('resume requires explicit acknowledgement and a recorded restored identity')
    require_identity(expected,q.get('expected_identity'))
    if state['state']=='resumed':return {**public_state(state),'reused':True}
    if state['state']!='restored_stopped':raise ValueError('resume outcome requires reconciliation; no automatic signal repeated')
    fd=os.pidfd_open(expected['pid'])
    try:
        require_identity(identity(expected['pid']),expected)
        if kernel_state(expected['pid'])!='T':raise ValueError('restored task is not stopped; reconcile external changes')
        if state.get('restored_threads'):validate_stopped_threads(expected['pid'],state['restored_threads'])
        state['state']='resume_requested';save(meta,state)
        signal.pidfd_send_signal(fd,signal.SIGCONT)
        state.update(state='resumed',resumed_at_unix=time.time());save(meta,state)
        return {**public_state(state),'reused':False}
    finally:os.close(fd)


def execute_criu(binary,args):
    try:return subprocess.run([str(binary),*args],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=55).returncode
    except subprocess.TimeoutExpired:raise RuntimeError('CRIU deadline exceeded; inspect recorded private state before another lifecycle action') from None


def main(q):
    if sys.platform!='linux' or os.geteuid()!=0:raise PermissionError('checkpoint requires Linux and existing sudo authorization')
    uid=int(os.environ['SUDO_UID']);binary=pathlib.Path(q['configured_binary'])
    if uid<=0:raise PermissionError('this qualified lifecycle requires a non-root original login')
    if not binary.is_absolute() or pin(binary)['sha256']!=q['configured_sha256']:raise ValueError('pinned checkpoint executable changed')
    action=q['action']
    if action=='inspect':
        result=inventory(q['pid'],uid);result.pop('private_file_paths')
        return {**result,'scope':'same-boot single-process Linux with 1..16 threads, internal pipes and unchanged files','application_checkpoint_required':False}
    name=q.get('checkpoint_id','')
    if not re.fullmatch(r'[A-Za-z0-9_-]{8,80}',name):raise ValueError('strict checkpoint identity required')
    if action in ('dump','restore') and not q.get('acknowledge_process_stop'):raise ValueError('process-stop acknowledgement required')
    create=action=='dump'
    private_directory(BASE,create);owner=BASE/str(uid);private_directory(owner,create);root=owner/name;private_directory(root,create)
    lock=os.open(root/'operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        st=os.fstat(lock)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o077:raise PermissionError('private lock identity invalid')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        meta=root/'state.json';state=json.loads(regular_read(meta,1024*1024)) if meta.exists() else None
        if state and (state['uid']!=uid or state['criu_sha256']!=q['configured_sha256']):raise ValueError('checkpoint authority or pinned artifact differs')
        if action=='status':
            if not state:raise ValueError('unknown checkpoint')
            return public_state(state)
        if action=='resume':
            if not state:raise ValueError('unknown checkpoint')
            return resume(state,q,meta)
        if action=='dump':
            if state:
                require_identity(state['original_identity'],q.get('expected_identity'))
                return {**public_state(state),'reused':True}
            ready=inventory(q['pid'],uid)
            require_identity(ready['identity'],q.get('expected_identity'))
            if not ready['ready']:raise ValueError('resource contract unsupported: '+', '.join(ready['limitations']))
            pidfd=os.pidfd_open(q['pid']);restore_running=ready['kernel_state']!='T';stopped=False
            try:
                require_identity(identity(q['pid']),ready['identity'])
                signal.pidfd_send_signal(pidfd,signal.SIGSTOP);stopped=True
                for _ in range(100):
                    require_identity(identity(q['pid']),ready['identity'])
                    if all(v['state']=='T' for v in thread_group(q['pid'],uid)):break
                    time.sleep(.01)
                else:raise ValueError('process did not reach stopped state')
                final=inventory(q['pid'],uid)
                if not final['ready']:raise ValueError('resource contract changed before freeze')
                if thread_identities(final['threads'])!=thread_identities(ready['threads']):raise ValueError('thread membership changed before freeze')
                if any(t['state']!='T' for t in final['threads']):raise ValueError('thread stop was incomplete')
                images=root/'images';private_directory(images,True)
                budget=[0];files={path:pin(path,budget) for path in final['private_file_paths']}
                state={'schema':'checkpoint-two-phase-v1','state':'dumping','checkpoint_id':name,'uid':uid,'criu_sha256':q['configured_sha256'],
                       'original_identity':ready['identity'],'original_kernel_state':ready['kernel_state'],'original_threads':thread_identities(final['threads']),'created_at_unix':time.time(),'file_pins':files}
                save(meta,state)
                code=execute_criu(binary,['dump','--tree',str(q['pid']),'--images-dir',str(images),'--work-dir',str(images),'--log-file','dump.log','--shell-job','--leave-stopped','-v4'])
                if code:
                    state.update(state='dump_failed',criu_exit_code=code);save(meta,state);raise ValueError('CRIU dump failed; original running state restored when possible, diagnostic remains private')
                pins={p.name:pin(p) for p in images.iterdir() if p.suffix=='.img'}
                if not pins or sum(v['stat'][2] for v in pins.values())>MAX_PIN_BYTES:raise ValueError('checkpoint images absent or oversized')
                state.update(state='validated_original_stopped',images={k:v['sha256'] for k,v in pins.items()});save(meta,state)
                require_identity(identity(q['pid']),ready['identity'])
                signal.pidfd_send_signal(pidfd,signal.SIGKILL);stopped=False
                if not select.select([pidfd],[],[],10)[0]:raise ValueError('original exit not confirmed; no restore admitted')
                state['state']='dumped';save(meta,state)
                return {**public_state(state),'reused':False,'original_exit_confirmed':True}
            finally:
                if stopped and restore_running:
                    try:signal.pidfd_send_signal(pidfd,signal.SIGCONT)
                    except ProcessLookupError:pass
                os.close(pidfd)
        if action!='restore' or not state:raise ValueError('unknown operation/checkpoint')
        if state['state'] in ('restored_stopped','resumed'):return {**public_state(state),'reused':True}
        if state['state']!='dumped':raise ValueError('uncertain checkpoint state; no duplicate restore admitted')
        if pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=state['original_identity']['boot_id']:raise ValueError('cross-boot restoration is not qualified')
        if pathlib.Path('/proc',str(state['original_identity']['pid'])).exists():raise ValueError('original numeric PID is occupied; wait for its owner to reap it')
        for thread in state.get('original_threads',[]):
            if pathlib.Path('/proc',str(thread['tid'])).exists():raise ValueError('original numeric thread ID is occupied; restore refused')
        for path,expected in state['file_pins'].items():
            if pin(path)!=expected:raise ValueError('external file identity/content changed; restore refused')
        images=root/'images'
        if any(pin(images/name)['sha256']!=sha for name,sha in state['images'].items()):raise ValueError('checkpoint image integrity changed')
        state['state']='restore_started';save(meta,state);pidfile=root/'restored.pid'
        code=execute_criu(binary,['restore','--images-dir',str(images),'--work-dir',str(images),'--log-file','restore.log','--shell-job','--restore-detached','--pidfile',str(pidfile),'-v4'])
        if code:
            state.update(state='restore_failed_or_partial',criu_exit_code=code);save(meta,state);raise ValueError('CRIU restore failed or partial; no automatic restore replay')
        restored=identity(int(regular_read(pidfile,64)))
        if restored['uid']!=uid or restored['pid']!=state['original_identity']['pid']:raise ValueError('restored identity does not match original contract')
        state['restored_identity']=restored
        if kernel_state(restored['pid'])!='T':
            state['state']='restore_state_unexpected';save(meta,state);raise ValueError('restoration did not produce the required stopped state; explicit reconciliation required')
        group=thread_group(restored['pid'],uid)
        original_threads=state.get('original_threads')
        expected_tids={v['tid'] for v in original_threads} if original_threads else {restored['pid']}
        if {v['tid'] for v in group}!=expected_tids or any(v['state']!='T' for v in group):
            state.update(state='restore_thread_state_unexpected',observed_thread_count=len(group));save(meta,state)
            raise ValueError('restored thread group differs or is not fully stopped; explicit reconciliation required')
        state['restored_threads']=thread_identities(group)
        state['state']='restored_stopped';save(meta,state)
        return {**public_state(state),'same_numeric_pid':True,'reused':False}
    finally:os.close(lock)


if __name__=='__main__':
    try:print(json.dumps(main(json.load(sys.stdin))))
    except Exception as error:
        print(type(error).__name__+': '+str(error)[:1000],file=sys.stderr);raise SystemExit(1)
