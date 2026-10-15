# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Explicit same-size inode patching with private durable recovery receipts.
Locks coordinate aliases of one inode. They do not freeze noncooperating readers
or writers; callers must acknowledge non-atomic visibility. No privilege grant.
"""
import base64
import hashlib
import json
import os
import re
import stat
import uuid
import fcntl

_PATCH_LIMIT=65536
_RECEIPT_LIMIT=6*1024*1024


def _inode_hash(fd, replacement=None):
    start=os.fstat(fd);h=hashlib.sha256();offset=0
    while offset<start.st_size:
        block=os.pread(fd,min(1024*1024,start.st_size-offset),offset)
        if not block:raise OSError('unexpected EOF during inode verification')
        if replacement:
            at,value=replacement;a=max(offset,at);b=min(offset+len(block),at+len(value))
            if b>a:block=block[:a-offset]+value[a-at:b-at]+block[b-offset:]
        h.update(block);offset+=len(block)
    end=os.fstat(fd)
    if (start.st_ino,start.st_size,start.st_mtime_ns,start.st_ctime_ns)!=(end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns):raise ValueError('inode changed while hashing')
    return h.hexdigest()


def _inode_json(fd,name,value=None):
    if value is None:
        f=regular(fd,name,private=True)
        with os.fdopen(f,'rb') as stream:
            data=stream.read(_RECEIPT_LIMIT+1)
            if len(data)>_RECEIPT_LIMIT:raise ValueError('inode receipt exceeds bound')
            return json.loads(data)
    data=json.dumps(value,sort_keys=True).encode()
    if len(data)>_RECEIPT_LIMIT:raise ValueError('inode metadata receipt too large')
    temp='.hepta-inode-meta-'+uuid.uuid4().hex
    try:
        f=regular(fd,temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,private=True)
        try:all_write(f,data);os.fsync(f)
        finally:os.close(f)
        os.replace(temp,name,src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd)
    finally:
        try:os.unlink(temp,dir_fd=fd)
        except FileNotFoundError:pass


def _inode_encode_meta(snapshot):
    return {**snapshot,'xattrs':{n:base64.b64encode(v).decode() for n,v in snapshot['xattrs'].items()},'acl':None if snapshot['acl'] is None else base64.b64encode(snapshot['acl']).decode()}


def _inode_decode_meta(value):
    return {**value,'xattrs':{n:base64.b64decode(v,validate=True) for n,v in value['xattrs'].items()},'acl':None if value['acl'] is None else base64.b64decode(value['acl'],validate=True)}


def _inode_validate_meta(fd,snapshot):
    now=os.fstat(fd)
    if now.st_uid!=snapshot['uid'] or now.st_gid!=snapshot['gid'] or now.st_nlink!=snapshot['nlink']:
        raise ValueError('inode ownership/link count changed; explicit reconciliation required')
    actual=metadata_capture(fd)
    if actual['mode'] not in (snapshot['mode'],snapshot['mode']&~0o6000) or any(actual[k]!=snapshot[k] for k in ('xattrs','acl','flags')):
        raise ValueError('concurrent inode rights change; automatic metadata restoration refused')


def _inode_restore_meta(fd,snapshot):
    _inode_validate_meta(fd,snapshot)
    # Linux is the qualified implementation. Rights are restored only on this
    # already-open inode and only using privileges the current account has.
    os.fchmod(fd,snapshot['mode'])
    for name in os.listxattr(fd):
        if name not in snapshot['xattrs']:os.removexattr(fd,name)
    for name in sorted(snapshot['xattrs'],key=lambda n:n=='system.posix_acl_access'):
        os.setxattr(fd,name,snapshot['xattrs'][name])
    if metadata_capture(fd)!=snapshot:raise ValueError('inode metadata restoration did not verify')
    os.fsync(fd)


def _inode_write(fd,offset,data):
    at=0
    while at<len(data):
        count=os.pwrite(fd,data[at:],offset+at)
        if count<=0:raise OSError('inode write made no progress')
        at+=count
    os.fsync(fd)


def inode_patch(q):
    if __import__('sys').platform!='linux':raise ValueError('inode patch is qualified on Linux only')
    if q.get('acknowledge_non_atomic') is not True:raise ValueError('in-place visibility is not atomic; explicit acknowledgement required')
    tx=q['transaction_id']
    if not re.fullmatch(r'[A-Za-z0-9_-]{8,96}',tx):raise ValueError('invalid inode transaction identity')
    fd,name=parent(q['root'],q['path']);target=None;transaction_lock=None
    try:
        transaction_lock=regular(fd,'.hepta-inode-lock-'+hashlib.sha256(tx.encode()).hexdigest(),os.O_RDWR|os.O_CREAT,private=True)
        fcntl.flock(transaction_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        target=regular(fd,name,os.O_RDWR if q['action']!='status' else os.O_RDONLY)
        fcntl.flock(target,fcntl.LOCK_EX|fcntl.LOCK_NB)
        st=os.fstat(target);receipt_name='.hepta-inode-'+hashlib.sha256(tx.encode()).hexdigest()+'.json'
        try:receipt=_inode_json(fd,receipt_name)
        except FileNotFoundError:receipt=None
        if receipt:
            if receipt['path']!=q['path'] or receipt['device']!=st.st_dev or receipt['inode']!=st.st_ino:raise ValueError('inode receipt binding changed')
            if q['action']=='status':
                return {'state':receipt['state'],'transaction_id':tx,'inode':st.st_ino,'link_count':st.st_nlink,'atomic_visibility':False,'current_sha256':_inode_hash(target),'before_sha256':receipt['before_sha256'],'after_sha256':receipt['after_sha256']}
            if q['action']=='recover':
                _inode_validate_meta(target,_inode_decode_meta(receipt['metadata']))
                old=base64.b64decode(receipt['old_base64'],validate=True);new=base64.b64decode(receipt['new_base64'],validate=True)
                current=_inode_hash(target)
                if current==receipt['after_sha256']:
                    _inode_restore_meta(target,_inode_decode_meta(receipt['metadata']));receipt['state']='committed'
                elif _inode_hash(target,(receipt['offset'],old))==receipt['before_sha256']:
                    actual=os.pread(target,len(old),receipt['offset'])
                    if any(v not in (a,b) for v,a,b in zip(actual,old,new)) or len(actual)!=len(old):raise ValueError('unexpected concurrent patch bytes; recovery refused')
                    _inode_write(target,receipt['offset'],old);_inode_restore_meta(target,_inode_decode_meta(receipt['metadata']))
                    if _inode_hash(target)!=receipt['before_sha256']:raise ValueError('rollback content did not verify')
                    receipt['state']='rolled_back'
                else:raise ValueError('unrelated file content changed; recovery refused')
                _inode_json(fd,receipt_name,receipt)
                return {'state':receipt['state'],'transaction_id':tx,'recovered':True,'inode':st.st_ino,'link_count':st.st_nlink,'atomic_visibility':False,'sha256':_inode_hash(target)}
            request=hashlib.sha256(json.dumps({k:q.get(k) for k in ('path','expected_version','expected_sha256','offset','data_base64','preserve_special_bits')},sort_keys=True).encode()).hexdigest()
            if receipt['request_sha256']!=request:raise ValueError('transaction replay parameters differ')
            if receipt['state']=='committed' and _inode_hash(target)==receipt['after_sha256'] and metadata_capture(target)==_inode_decode_meta(receipt['metadata']):
                return {'state':'committed','reused':True,'transaction_id':tx,'inode':st.st_ino,'link_count':st.st_nlink,'sha256':receipt['after_sha256'],'atomic_visibility':False}
            raise ValueError('existing inode transaction requires explicit recovery; no patch applied')
        if q['action']!='apply':raise ValueError('unknown inode transaction')
        data=base64.b64decode(q['data_base64'],validate=True);offset=q.get('offset',0)
        if isinstance(offset,bool) or not isinstance(offset,int) or not data or len(data)>_PATCH_LIMIT or offset<0 or offset+len(data)>st.st_size:raise ValueError('patch must replace 1..65536 bytes without changing file size')
        if version(st)!=q.get('expected_version'):raise ValueError('inode version changed')
        before=_inode_hash(target)
        if before!=q.get('expected_sha256'):raise ValueError('inode content fingerprint changed')
        snapshot=metadata_capture(target)
        if snapshot['flags'] or 'security.capability' in snapshot['xattrs']:raise ValueError('immutable flags/capabilities require separate qualification')
        if snapshot['mode']&0o7000 and not q.get('preserve_special_bits'):raise ValueError('explicit preserve_special_bits required')
        if snapshot['uid']!=os.geteuid():raise PermissionError('in-place recovery requires owning the target inode')
        old=os.pread(target,len(data),offset)
        if len(old)!=len(data):raise ValueError('short original patch range')
        after=_inode_hash(target,(offset,data))
        request=hashlib.sha256(json.dumps({k:q.get(k) for k in ('path','expected_version','expected_sha256','offset','data_base64','preserve_special_bits')},sort_keys=True).encode()).hexdigest()
        receipt={'schema':'hepta-inode-patch-v1','transaction_id':tx,'path':q['path'],'device':st.st_dev,'inode':st.st_ino,'size':st.st_size,'offset':offset,'before_sha256':before,'after_sha256':after,'old_base64':base64.b64encode(old).decode(),'new_base64':base64.b64encode(data).decode(),'metadata':_inode_encode_meta(snapshot),'request_sha256':request,'state':'prepared'}
        _inode_json(fd,receipt_name,receipt)
        if version(os.fstat(target))!=q['expected_version'] or _inode_hash(target)!=before:raise ValueError('source changed after journal preparation; use recover')
        _inode_write(target,offset,data);_inode_restore_meta(target,snapshot)
        if _inode_hash(target)!=after:raise ValueError('patched content changed; use recover')
        receipt['state']='committed';_inode_json(fd,receipt_name,receipt)
        return {'state':'committed','reused':False,'transaction_id':tx,'inode':st.st_ino,'link_count':st.st_nlink,'sha256':after,'version':version(os.fstat(target)),'inode_preserved':True,'metadata_preserved':True,'atomic_visibility':False,'recovery_receipt_retained':True}
    finally:
        if target is not None:os.close(target)
        if transaction_lock is not None:os.close(transaction_lock)
        os.close(fd)
