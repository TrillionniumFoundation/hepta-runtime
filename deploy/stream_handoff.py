#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Cooperative same-UID Linux pipe-descriptor handoff without stopping applications.
Transfers only descriptors already owned by the consenting sender. No process
capture, signals, /proc descriptor opening, privilege changes, or network peers.
The caller must quiesce its own I/O before sending and never blindly retry an
ambiguous acknowledgement. This is not an API for adopting arbitrary DC state.
"""
import array
import fcntl
import hashlib
import json
import os
import pathlib
import re
import socket
import stat
import struct

MAX_FDS=5
MAX_MESSAGE=16384


def identity(pid):
    if not isinstance(pid,int) or isinstance(pid,bool) or pid<=1:raise ValueError('invalid process identity')
    root=pathlib.Path('/proc')/str(pid);text=(root/'stat').read_text();parts=text[text.rfind(')')+2:].split()
    ids=list(map(int,next(v for v in (root/'status').read_text().splitlines() if v.startswith('Uid:')).split()[1:]))
    if ids!=[os.getuid()]*4 or parts[0]=='Z':raise PermissionError('live uniformly owned process required')
    return {'pid':pid,'start_ticks':int(parts[19]),'uid':ids[0],
            'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def pipe_description(fd):
    value=os.fstat(fd)
    if not stat.S_ISFIFO(value.st_mode):raise ValueError('handoff accepts owned pipe descriptors only')
    return {'device':value.st_dev,'inode':value.st_ino,'access':fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE}



def history_description(fd):
    value=os.fstat(fd)
    if not stat.S_ISREG(value.st_mode) or value.st_uid!=os.getuid():
        raise ValueError('history descriptor must be a regular file owned by this login')
    access=fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE
    if access!=os.O_RDONLY:raise ValueError('history descriptor must be read-only')
    h=hashlib.sha256();offset=0
    while offset<value.st_size:
        block=os.pread(fd,min(1024*1024,value.st_size-offset),offset)
        if not block:raise ValueError('history file changed or could not be read')
        h.update(block);offset+=len(block)
    now=os.fstat(fd)
    if (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)!=(now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns,now.st_ctime_ns):
        raise ValueError('history file changed while hashing')
    return {'device':value.st_dev,'inode':value.st_ino,'size':value.st_size,'sha256':h.hexdigest(),'access':access}


def validate_stdio(application,descriptions):
    root=pathlib.Path('/proc')/str(application['pid'])
    for item in descriptions:
        number={'stdin_writer':0,'stdout_reader':1,'stderr_reader':2}[item['role']]
        info=(root/'fd'/str(number)).stat()
        flags=int(next(line for line in (root/'fdinfo'/str(number)).read_text().splitlines() if line.startswith('flags:')).split()[1],8)&os.O_ACCMODE
        expected_access=os.O_RDONLY if number==0 else os.O_WRONLY
        if not stat.S_ISFIFO(info.st_mode) or (info.st_dev,info.st_ino)!=(item['identity']['device'],item['identity']['inode']) or flags!=expected_access:
            raise ValueError('transferred pipe does not match the selected application stdio')
    if identity(application['pid'])!=application:raise ValueError('application changed during descriptor verification')


def peer(conn,expected_uid):
    pid,uid,gid=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
    if uid!=expected_uid or uid!=os.getuid():raise PermissionError('descriptor sender and receiver must use the same login')
    return {'pid':pid,'uid':uid,'gid':gid}


def private_parent(path):
    path=pathlib.Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ValueError('absolute private socket path required')
    info=path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:raise PermissionError('private account-owned socket directory required')
    return path


def listener(path):
    path=private_parent(path)
    if path.exists() or path.is_symlink():raise ValueError('do not replace an existing handoff endpoint')
    conn=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:conn.bind(str(path));os.chmod(path,0o600);conn.listen(1);return conn
    except BaseException:conn.close();raise


def receive(conn,receipt_path,expected_id):
    private_parent(receipt_path)
    conn.settimeout(10)
    who=peer(conn,os.getuid());descriptors=[]
    try:
        data,control,flags,_=conn.recvmsg(MAX_MESSAGE,socket.CMSG_SPACE(MAX_FDS*array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
        for level,kind,raw in control:
            if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:raise ValueError('unexpected ancillary data')
            values=array.array('i');values.frombytes(raw[:len(raw)-(len(raw)%values.itemsize)]);descriptors.extend(values)
        if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or not 1<=len(descriptors)<=MAX_FDS:raise ValueError('truncated or oversized descriptor transfer')
        message=json.loads(data)
        if message.get('handoff_id')!=expected_id or not re.fullmatch('[a-zA-Z0-9_-]{16,80}',expected_id):raise ValueError('handoff identity differs')
        if message.get('sender_io_quiesced') is not True:raise ValueError('sender must quiesce its owned I/O')
        if message.get('sender_identity')!=identity(who['pid']):raise ValueError('sender process identity changed')
        described=message['descriptors']
        if len(described)!=len(descriptors) or len({v['role'] for v in described})!=len(described):raise ValueError('descriptor count or roles differ')
        if message.get('history_finalized') is not True and any(v['role'].endswith('_history') for v in described):
            raise ValueError('history descriptors require an explicit finalized boundary')
        pipe_items=[]
        for fd,item in zip(descriptors,described):
            role=item['role']
            if role in ('stdin_writer','stdout_reader','stderr_reader'):
                if pipe_description(fd)!=item['identity']:raise ValueError('pipe identity changed')
                expected_access=os.O_WRONLY if role=='stdin_writer' else os.O_RDONLY
                if item['identity']['access']!=expected_access:raise ValueError('pipe role and access mode disagree')
                pipe_items.append(item)
            elif role in ('stdout_history','stderr_history'):
                if history_description(fd)!=item['identity']:raise ValueError('history identity/content changed')
            else:raise ValueError('unsupported descriptor role')
        processes=message['application_identities']
        if not 1<=len(processes)<=64:raise ValueError('bounded application identities required')
        for expected in processes:
            if identity(expected['pid'])!=expected:raise ValueError('application process identity changed')
        validate_stdio(processes[0],pipe_items)
        result={'state':'descriptors_accepted','handoff_id':expected_id,'sender':message['sender_identity'],
                'receiver':identity(os.getpid()),'application_identities':processes,'descriptors':described,
                'same_pipe_objects':True,'application_stopped':False,'memory_copied':False,
                'exclusive_ownership_inferred':False,'replay_safe':False,
                'history_finalized':message.get('history_finalized',False)}
        payload=(json.dumps(result,sort_keys=True)+'\n').encode()
        fd=os.open(receipt_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(payload);stream.flush();os.fsync(stream.fileno())
        conn.sendall(json.dumps({'accepted':True,'handoff_id':expected_id,'receipt_sha256':hashlib.sha256(payload).hexdigest()}).encode())
        return result,dict((description['role'],fd) for description,fd in zip(described,descriptors))
    except BaseException:
        for fd in descriptors:os.close(fd)
        raise


def transfer(path,handoff_id,descriptors,application_pids,*,acknowledge_quiesced_io=False):
    if not acknowledge_quiesced_io:raise ValueError('explicit quiesced owned-I/O acknowledgement required')
    path=private_parent(path);info=path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:raise PermissionError('owned private receiver socket required')
    if not re.fullmatch('[a-zA-Z0-9_-]{16,80}',handoff_id):raise ValueError('invalid handoff identity')
    if not 1<=len(descriptors)<=MAX_FDS:raise ValueError('bounded owned descriptors required')
    metadata=[]
    for role,fd in descriptors.items():
        ident=history_description(fd) if role in ('stdout_history','stderr_history') else pipe_description(fd)
        metadata.append({'role':role,'identity':ident})
    message={'handoff_id':handoff_id,'sender_io_quiesced':True,'sender_identity':identity(os.getpid()),
             'application_identities':[identity(pid) for pid in application_pids],'descriptors':metadata,
             'history_finalized':True}
    data=json.dumps(message).encode()
    if len(data)>MAX_MESSAGE:raise ValueError('manifest too large')
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as conn:
        conn.settimeout(10);conn.connect(str(path));peer(conn,os.getuid())
        rights=array.array('i',descriptors.values())
        sent=conn.sendmsg([data],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,rights)])
        if sent!=len(data):raise RuntimeError('transfer outcome uncertain; do not retry')
        ack=json.loads(conn.recv(MAX_MESSAGE))
        if not ack.get('accepted') or ack.get('handoff_id')!=handoff_id:raise RuntimeError('acknowledgement uncertain; inspect receiver before further I/O')
        return ack
