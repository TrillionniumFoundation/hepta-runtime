# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Controller-local persistent stream owner for cooperative descriptor export.

The broker never opens another process's fd table, signals applications, changes
credentials or captures memory. A same-UID old owner voluntarily transfers its
already-owned stdio pipes over a private Unix socket. Runtime restarts do not
own or close the transferred descriptors.
"""
import array
import base64
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import re
import select
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

MAX_FDS=5
MAX_MESSAGE=128*1024
MAX_READ=16*1024
MAX_WRITE=64*1024


def atomic(path,value,create=False):
    data=(json.dumps(value,sort_keys=True)+'\n').encode()
    if create:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        return
    temp=path.with_name(path.name+'.new-'+str(os.getpid()))
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:
        try:temp.unlink()
        except FileNotFoundError:pass


def load(path):
    try:return json.loads(path.read_text())
    except FileNotFoundError:return None


def private_dir(path,create=False):
    if create:path.mkdir(parents=True,exist_ok=True,mode=0o700)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise PermissionError('private account-owned stream state required')
    return path


def identity(pid):
    if not isinstance(pid,int) or isinstance(pid,bool) or pid<=1:raise ValueError('positive application PID required')
    root=pathlib.Path('/proc')/str(pid);raw=(root/'stat').read_text();end=raw.rfind(')')
    parts=raw[end+2:].split()
    uids=list(map(int,next(line for line in (root/'status').read_text().splitlines() if line.startswith('Uid:')).split()[1:]))
    if uids!=[os.getuid()]*4 or parts[0]=='Z':raise PermissionError('live uniformly owned application required')
    return {'pid':pid,'start_ticks':int(parts[19]),'uid':uids[0],
            'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def is_descendant(pid,leader):
    current=pid;seen=set()
    while current not in (0,1):
        if current==leader:return True
        if current in seen:return False
        seen.add(current)
        raw=(pathlib.Path('/proc')/str(current)/'stat').read_text();current=int(raw[raw.rfind(')')+2:].split()[1])
    return False


def socket_root(session_id):
    base=pathlib.Path('/run/user')/str(os.getuid())/'hepta-runtime-streams'
    private_dir(base,True)
    child=base/hashlib.sha256(session_id.encode()).hexdigest()[:24]
    private_dir(child,True)
    return child


def peer(conn):
    pid,uid,gid=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
    if uid!=os.getuid():raise PermissionError('stream peer must use the runtime login')
    return {'pid':pid,'uid':uid,'gid':gid}


def pipe_description(fd):
    info=os.fstat(fd)
    if not stat.S_ISFIFO(info.st_mode):raise ValueError('handoff accepts pipes only')
    return {'device':info.st_dev,'inode':info.st_ino,'access':__import__('fcntl').fcntl(fd,__import__('fcntl').F_GETFL)&os.O_ACCMODE}



def history_description(fd):
    value=os.fstat(fd)
    if not stat.S_ISREG(value.st_mode) or value.st_uid!=os.getuid():
        raise ValueError('history descriptor must be an account-owned regular file')
    access=fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE
    if access!=os.O_RDONLY:raise ValueError('history descriptor must be read-only')
    h=hashlib.sha256();offset=0
    while offset<value.st_size:
        block=os.pread(fd,min(1024*1024,value.st_size-offset),offset)
        if not block:raise ValueError('history source made no progress')
        h.update(block);offset+=len(block)
    now=os.fstat(fd)
    if (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)!=(now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns,now.st_ctime_ns):
        raise ValueError('history source changed while hashing')
    return {'device':value.st_dev,'inode':value.st_ino,'size':value.st_size,'sha256':h.hexdigest(),'access':access}

def seed_archive(job,name,fd,expected):
    if history_description(fd)!=expected:raise ValueError('history source fingerprint changed')
    destination=job/(name+'.log')
    if destination.exists():
        with destination.open('rb') as current:
            h=hashlib.sha256();size=0
            for block in iter(lambda:current.read(1024*1024),b''):h.update(block);size+=len(block)
        if size!=expected['size'] or h.hexdigest()!=expected['sha256']:
            raise ValueError('existing archive differs from finalized history')
        return {'reused':True,'size':size,'sha256':h.hexdigest()}
    temporary=job/(name+'.history-'+str(os.getpid()))
    out=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        offset=0;h=hashlib.sha256()
        while offset<expected['size']:
            block=os.pread(fd,min(1024*1024,expected['size']-offset),offset)
            if not block:raise ValueError('history copy made no progress')
            if write_all(out,block)!=len(block):raise OSError('history archive write incomplete')
            h.update(block);offset+=len(block)
        os.fsync(out)
        if h.hexdigest()!=expected['sha256']:raise ValueError('history hash changed during archive copy')
        os.replace(temporary,destination)
        parent=os.open(job,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
        return {'reused':False,'size':offset,'sha256':h.hexdigest()}
    finally:
        os.close(out)
        temporary.unlink(missing_ok=True)


def validate_app_stdio(application,descriptions):
    root=pathlib.Path('/proc')/str(application['pid'])
    for item in descriptions:
        number={'stdin_writer':0,'stdout_reader':1,'stderr_reader':2}[item['role']]
        info=(root/'fd'/str(number)).stat()
        flags=int(next(line for line in (root/'fdinfo'/str(number)).read_text().splitlines() if line.startswith('flags:')).split()[1],8)&os.O_ACCMODE
        expected=os.O_RDONLY if number==0 else os.O_WRONLY
        ident=item['identity']
        if not stat.S_ISFIFO(info.st_mode) or (info.st_dev,info.st_ino)!=(ident['device'],ident['inode']) or flags!=expected:
            raise ValueError('transferred pipe does not match application stdio')


def write_all(fd,data,timeout=5):
    position=0;deadline=time.monotonic()+timeout
    while position<len(data):
        try:n=os.write(fd,data[position:])
        except BlockingIOError:
            if not select.select([],[fd],[],max(0,deadline-time.monotonic()))[1]:break
            continue
        if n<=0:break
        position+=n
    return position


def append_receipt(path,value):
    data=(json.dumps(value,sort_keys=True)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
    try:
        write_all(fd,data);os.fsync(fd)
    finally:os.close(fd)


def load_receipts(path):
    result={}
    try:
        for line in path.read_text().splitlines():
            item=json.loads(line);result[item['request_id']]=item
    except FileNotFoundError:pass
    return result


def current_application(request):
    values=[]
    for expected in request['application_identities']:
        try:
            now=identity(expected['pid']);values.append({'identity':expected,'alive':now==expected})
        except (OSError,ValueError,PermissionError):values.append({'identity':expected,'alive':False})
    return values


def public_status(job,request,state):
    final=load(job/'final.json')
    if final:return final
    live=current_application(request)
    result={**state,'application_status':live,'all_applications_alive':all(v['alive'] for v in live),
            'stdout_available':(job/'stdout.log').stat().st_size if (job/'stdout.log').exists() else 0,
            'stderr_available':(job/'stderr.log').stat().st_size if (job/'stderr.log').exists() else 0}
    return result


def read_archive(job,request,state,q):
    stream=q.get('stream','stdout')
    if stream not in ('stdout','stderr'):raise ValueError('stream must be stdout or stderr')
    path=job/(stream+'.log');offset=int(q.get('offset') or 0);limit=max(1,min(MAX_READ,int(q.get('limit') or MAX_READ)))
    size=path.stat().st_size if path.exists() else 0
    if not 0<=offset<=size:raise ValueError('stream cursor outside retained archive')
    data=b''
    if path.exists():
        with path.open('rb') as file:file.seek(offset);data=file.read(min(limit,size-offset))
    state_now=public_status(job,request,state)
    eof=bool(state_now.get(stream+'_eof',False))
    return {'stream':stream,'offset':offset,'next_offset':offset+len(data),'available_end':size,
            'data_base64':base64.b64encode(data).decode(),'chunk_sha256':hashlib.sha256(data).hexdigest(),
            'eof':eof and offset+len(data)==size,'output_complete':bool(state_now.get('output_complete',False)),
            'status':state_now}


def connect_control(job,q):
    request=load(job/'request.json')
    if not request:raise ValueError('unknown stream session')
    final=load(job/'final.json')
    if final:
        if q['op']=='status':return final
        if q['op']=='read':return read_archive(job,request,final,q)
        if q['op']=='close':return {'state':'already_closed','session_id':request['session_id']}
        raise ValueError('stream receiver has exited; no further input accepted')
    if q['op']=='read':
        state=load(job/'state.json') or {'state':'waiting_for_owner'}
        return read_archive(job,request,state,q)
    path=pathlib.Path(request['socket_root'])/'control.sock'
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as conn:
        conn.settimeout(8);conn.connect(str(path));conn.sendall(json.dumps(q).encode());raw=conn.recv(MAX_MESSAGE)
    value=json.loads(raw)
    if 'error' in value:raise RuntimeError(value['error'])
    return value


def prepare(q,source):
    state_root=private_dir(pathlib.Path(q['state_dir']),False)
    streams=private_dir(state_root/'stream_handoffs',True)
    session=q['session_id'];job=streams/session
    pids=q['application_pids']
    if not 1<=len(pids)<=64 or len(set(pids))!=len(pids):raise ValueError('1..64 unique application PIDs required')
    identities=[identity(pid) for pid in pids]
    leader=pids[0]
    if any(not is_descendant(pid,leader) for pid in pids):raise ValueError('additional PIDs must be descendants of the first application PID')
    stable={'session_id':session,'application_identities':identities,'socket_root':str(socket_root(session)),
            'schema':'native-stream-handoff-v1'}
    if job.exists():
        private_dir(job)
        old=load(job/'request.json')
        if not old or {key:old.get(key) for key in stable}!=stable:
            raise ValueError('stream identity is already bound to different application identities')
        return {'session_id':session,'reused':True,'handoff_socket':str(pathlib.Path(old['socket_root'])/'handoff.sock'),
                'application_identities':identities,'status':connect_control(job,{'op':'status'})}
    request={**stable,'created_unix_ms':int(time.time()*1000)}
    job.mkdir(mode=0o700)
    atomic(job/'request.json',request,True)
    script=job/'broker.py';fd=os.open(script,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
    with os.fdopen(fd,'w') as file:file.write(source);file.flush();os.fsync(file.fileno())
    environment=os.environ.copy();environment.setdefault('XDG_RUNTIME_DIR','/run/user/'+str(os.getuid()))
    environment.setdefault('DBUS_SESSION_BUS_ADDRESS','unix:path='+environment['XDG_RUNTIME_DIR']+'/bus')
    bus=pathlib.Path(environment['XDG_RUNTIME_DIR'])/'bus'
    if not bus.exists():raise RuntimeError('user systemd manager is unavailable; stream owner was not launched')
    unit='hepta-stream-'+hashlib.sha256(session.encode()).hexdigest()[:20]
    run=subprocess.run(['systemd-run','--user','--quiet','--collect','--unit='+unit,'--property=KillMode=control-group',
                        '--','/usr/bin/python3',str(script),'--daemon',str(job)],env=environment,capture_output=True,timeout=10)
    if run.returncode:
        raise RuntimeError('stream owner launch not acknowledged; reconcile the existing session identity')
    for _ in range(100):
        if (job/'ready.json').exists():
            return {'session_id':session,'reused':False,'handoff_socket':str(pathlib.Path(request['socket_root'])/'handoff.sock'),
                    'application_identities':identities,'status':connect_control(job,{'op':'status'})}
        if (job/'final.json').exists():break
        time.sleep(.05)
    raise RuntimeError('stream owner readiness is uncertain; do not create another identity')


def daemon(job):
    job=private_dir(pathlib.Path(job));request=load(job/'request.json')
    if not request:raise ValueError('missing stream request')
    sockets=private_dir(pathlib.Path(request['socket_root']),True)
    handoff_path=sockets/'handoff.sock';control_path=sockets/'control.sock'
    for path in (handoff_path,control_path):
        if path.exists() or path.is_symlink():raise ValueError('stream socket path already exists')
    handoff=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);control=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    handoff.bind(str(handoff_path));control.bind(str(control_path));os.chmod(handoff_path,0o600);os.chmod(control_path,0o600)
    handoff.listen(1);control.listen(16);handoff.setblocking(False);control.setblocking(False)
    selector=selectors.DefaultSelector();selector.register(handoff,selectors.EVENT_READ,('listener','handoff'));selector.register(control,selectors.EVENT_READ,('listener','control'))
    streams={};logs={};eof={'stdout':False,'stderr':False};input_closed=False;owner=None
    state={'state':'waiting_for_owner','session_id':request['session_id'],'application_identities':request['application_identities'],
           'owner_accepted':False,'stdin_closed':False,'stdout_eof':False,'stderr_eof':False,'output_complete':False}
    atomic(job/'state.json',state);atomic(job/'ready.json',{'ready':True,'pid':os.getpid(),'session_id':request['session_id']},True)
    receipts=load_receipts(job/'input_receipts.jsonl')
    def reply(conn,value):
        try:conn.sendall(json.dumps(value).encode())
        except OSError:pass
    try:
        while True:
            for key,_ in selector.select(.1):
                kind,name=key.data
                if kind=='output':
                    fd=key.fileobj
                    try:data=os.read(fd,65536)
                    except BlockingIOError:continue
                    except OSError as error:
                        if error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):state['capture_error']=type(error).__name__;data=b''
                        else:continue
                    if data:
                        written=write_all(logs[name],data)
                        if written!=len(data):state['capture_error']='archive_write_incomplete'
                    else:
                        selector.unregister(fd);os.close(fd);eof[name]=True;state[name+'_eof']=True
                elif name=='handoff':
                    conn,_=handoff.accept()
                    with conn:
                        conn.settimeout(5);received=[]
                        try:
                            who=peer(conn);data,ancillary,flags,_=conn.recvmsg(MAX_MESSAGE,socket.CMSG_SPACE(MAX_FDS*array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
                            for level,ctype,raw in ancillary:
                                if level!=socket.SOL_SOCKET or ctype!=socket.SCM_RIGHTS:raise ValueError('unexpected ancillary data')
                                values=array.array('i');values.frombytes(raw[:len(raw)-(len(raw)%values.itemsize)]);received.extend(values)
                            if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or not 2<=len(received)<=MAX_FDS:raise ValueError('truncated or invalid descriptor transfer')
                            if (job/'handoff_receipt.json').exists():raise ValueError('stream handoff is already accepted')
                            message=json.loads(data)
                            if message.get('handoff_id')!=request['session_id'] or message.get('sender_io_quiesced') is not True:raise ValueError('handoff identity/consent differs')
                            if message.get('sender_identity')!=identity(who['pid']):raise ValueError('sender identity changed')
                            if message.get('application_identities')!=request['application_identities']:raise ValueError('application identity binding differs')
                            described=message.get('descriptors',[])
                            if len(described)!=len(received) or len({v['role'] for v in described})!=len(described):raise ValueError('descriptor roles/count differ')
                            roles={v['role'] for v in described}
                            allowed={'stdin_writer','stdout_reader','stderr_reader','stdout_history','stderr_history'}
                            if not {'stdin_writer','stdout_reader'}<=roles or not roles<=allowed:raise ValueError('stdin/stdout required; stderr/history are optional')
                            if message.get('history_finalized') is not True and any(v['role'].endswith('_history') for v in described):
                                raise ValueError('history descriptors require a finalized owner boundary')
                            pipe_items=[];history_seed={}
                            for fd,item in zip(received,described):
                                role=item['role']
                                if role in ('stdin_writer','stdout_reader','stderr_reader'):
                                    if pipe_description(fd)!=item['identity']:raise ValueError('transferred pipe identity changed')
                                    expected=os.O_WRONLY if role=='stdin_writer' else os.O_RDONLY
                                    if item['identity']['access']!=expected:raise ValueError('pipe role/access mode differs')
                                    pipe_items.append(item)
                                elif role in ('stdout_history','stderr_history'):
                                    if history_description(fd)!=item['identity']:raise ValueError('history identity/content changed')
                                else:raise ValueError('unsupported descriptor role')
                            validate_app_stdio(request['application_identities'][0],pipe_items)
                            for fd,item in zip(received,described):
                                if item['role'] in ('stdout_history','stderr_history'):
                                    stream_name=item['role'].split('_',1)[0]
                                    history_seed[stream_name]=seed_archive(job,stream_name,fd,item['identity'])
                            receipt={'session_id':request['session_id'],'sender_identity':message['sender_identity'],
                                     'application_identities':request['application_identities'],'descriptors':described,
                                     'accepted_unix_ms':int(time.time()*1000),'same_pipe_objects':True,
                                     'history_seed':history_seed,'history_finalized':message.get('history_finalized',False)}
                            atomic(job/'handoff_receipt.json',receipt,True)
                            for fd,item in zip(received,described):
                                role=item['role']
                                if role.endswith('_history'):continue
                                os.set_blocking(fd,False);streams[role]=fd
                                if role.endswith('_reader'):
                                    stream_name='stdout' if role=='stdout_reader' else 'stderr'
                                    logfd=os.open(job/(stream_name+'.log'),os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
                                    logs[stream_name]=logfd;selector.register(fd,selectors.EVENT_READ,('output',stream_name))
                            owner=message['sender_identity'];state.update(state='accepted',owner_accepted=True,owner_identity=owner)
                            atomic(job/'state.json',state)
                            payload=(json.dumps(receipt,sort_keys=True)+'\n').encode()
                            reply(conn,{'accepted':True,'handoff_id':request['session_id'],'receipt_sha256':hashlib.sha256(payload).hexdigest()})
                            received=[]
                        except Exception as error:
                            reply(conn,{'error':type(error).__name__})
                            for fd in received:
                                try:os.close(fd)
                                except OSError:pass
                else:
                    conn,_=control.accept()
                    with conn:
                        conn.settimeout(5)
                        try:
                            if peer(conn)['uid']!=os.getuid():raise PermissionError('unexpected control peer')
                            q=json.loads(conn.recv(MAX_MESSAGE));op=q['op']
                            if op=='status':value=public_status(job,request,state)
                            elif op=='write':
                                if 'stdin_writer' not in streams or input_closed:raise ValueError('stream input is closed or not accepted')
                                request_id=q['request_id'];data=base64.b64decode(q['data_base64'],validate=True)
                                if not re.fullmatch('[A-Za-z0-9_-]{8,128}',request_id) or len(data)>MAX_WRITE:raise ValueError('invalid bounded input request')
                                digest=hashlib.sha256(data).hexdigest();old=receipts.get(request_id)
                                if old:
                                    if old['sha256']!=digest or old['length']!=len(data):raise ValueError('input request ID reused with different bytes')
                                    value={**old,'reused':True}
                                else:
                                    intent={'request_id':request_id,'sha256':digest,'length':len(data),'state':'intent'}
                                    append_receipt(job/'input_receipts.jsonl',intent);receipts[request_id]=intent
                                    written=write_all(streams['stdin_writer'],data)
                                    final={**intent,'state':'confirmed' if written==len(data) else 'partial_or_uncertain','bytes_written':written}
                                    append_receipt(job/'input_receipts.jsonl',final);receipts[request_id]=final
                                    value={**final,'reused':False}
                            elif op=='close':
                                if not input_closed and 'stdin_writer' in streams:
                                    selector.unregister(streams['stdin_writer']) if False else None
                                    os.close(streams.pop('stdin_writer'));input_closed=True
                                state['stdin_closed']=True;atomic(job/'state.json',state);value={'state':'input_closed','session_id':request['session_id']}
                            else:raise ValueError('unknown stream control operation')
                            reply(conn,value)
                        except Exception as error:reply(conn,{'error':type(error).__name__+': '+str(error)})
            if state['owner_accepted']:
                live=current_application(request)
                state['application_status']=live;state['stdout_eof']=eof['stdout'];state['stderr_eof']=eof['stderr'] if 'stderr_reader' in streams or (job/'stderr.log').exists() else True
                if not any(v['alive'] for v in live) and state['stdout_eof'] and state['stderr_eof']:
                    state.update(state='exited',output_complete=not state.get('capture_error'),stdin_closed=input_closed,completed_unix_ms=int(time.time()*1000))
                    atomic(job/'final.json',state);break
    finally:
        for fd in list(streams.values()):
            try:os.close(fd)
            except OSError:pass
        for fd in logs.values():
            try:os.fsync(fd);os.close(fd)
            except OSError:pass
        selector.close();handoff.close();control.close()
        handoff_path.unlink(missing_ok=True);control_path.unlink(missing_ok=True)


def main(source=None):
    if len(sys.argv)==3 and sys.argv[1]=='--daemon':daemon(sys.argv[2]);return
    q=json.load(sys.stdin);op=q['op']
    state_root=private_dir(pathlib.Path(q['state_dir']),False)
    if op=='prepare':
        value=prepare(q,source or pathlib.Path(__file__).read_text())
    elif op=='list':
        base=state_root/'stream_handoffs';items=[]
        if base.exists():
            for job in sorted(base.iterdir()):
                if not job.is_dir() or not job.name.startswith('stream-'):continue
                request=load(job/'request.json')
                if request:items.append({'session_id':request['session_id'],'application_identities':request['application_identities'],'status':connect_control(job,{'op':'status'})})
                if len(items)>=max(1,min(128,int(q.get('limit') or 64))):break
        value={'sessions':items}
    else:
        session=q['session_id']
        if not re.fullmatch(r'stream-[0-9a-f]{64}',session):raise ValueError('invalid stream session identity')
        job=private_dir(state_root/'stream_handoffs'/session,False)
        value=connect_control(job,q)
    print(json.dumps(value))


if __name__=='__main__':
    try:main(globals().get('HEPTA_HELPER_SOURCE'))
    except Exception as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise SystemExit(1)
