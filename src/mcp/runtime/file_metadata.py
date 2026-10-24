# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Descriptor-bound preservation of file rights, xattrs and ACLs before publication.
The target account's OS rights remain authoritative. No sudo or permission grant.
Metadata values are never returned to callers; evidence uses names and hashes.
"""
import ctypes
import errno
import hashlib
import os
import stat
import sys

_METADATA_LIMIT = 4 * 1024 * 1024


def _darwin_lib():
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    lib.flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.flistxattr.restype = ctypes.c_ssize_t
    lib.fgetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    lib.fgetxattr.restype = ctypes.c_ssize_t
    lib.fcopyfile.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    lib.fcopyfile.restype = ctypes.c_int
    lib.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.acl_get_fd_np.restype = ctypes.c_void_p
    lib.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    lib.acl_to_text.restype = ctypes.c_void_p
    lib.acl_free.argtypes = [ctypes.c_void_p]
    lib.acl_free.restype = ctypes.c_int
    return lib


def _metadata_os_error(label):
    number = ctypes.get_errno()
    raise OSError(number, label + ': ' + os.strerror(number))


def metadata_xattrs(fd):
    if sys.platform == 'darwin':
        lib = _darwin_lib()
        size = lib.flistxattr(fd, None, 0, 0)
        if size < 0: _metadata_os_error('list extended attributes')
        if size > 65536: raise ValueError('attribute-name budget exceeded')
        buffer = ctypes.create_string_buffer(max(1, size))
        got = lib.flistxattr(fd, buffer, size, 0)
        if got < 0: _metadata_os_error('read extended attribute names')
        names = [v.decode('utf-8', 'surrogateescape') for v in buffer.raw[:got].split(b'\0') if v]
        result = {}
        for name in names:
            encoded = os.fsencode(name)
            length = lib.fgetxattr(fd, encoded, None, 0, 0, 0)
            if length < 0: _metadata_os_error('size extended attribute')
            if length + sum(map(len, result.values())) > _METADATA_LIMIT: raise ValueError('metadata budget exceeded')
            value = ctypes.create_string_buffer(max(1, length))
            got = lib.fgetxattr(fd, encoded, value, length, 0, 0)
            if got < 0: _metadata_os_error('read extended attribute')
            result[name] = value.raw[:got]
        return result
    if not hasattr(os, 'listxattr'):
        raise ValueError('platform metadata inspection is unsupported')
    result = {}
    for name in os.listxattr(fd):
        result[name] = os.getxattr(fd, name)
        if len(result) > 256 or sum(map(len, result.values())) > _METADATA_LIMIT:
            raise ValueError('metadata budget exceeded')
    return result


def metadata_acl(fd):
    if sys.platform != 'darwin': return None
    lib = _darwin_lib()
    acl = lib.acl_get_fd_np(fd, 0x100)
    if not acl:
        if ctypes.get_errno() in (errno.ENOENT, errno.EINVAL): return b''
        _metadata_os_error('read extended ACL')
    try:
        size = ctypes.c_ssize_t()
        text = lib.acl_to_text(acl, ctypes.byref(size))
        if not text: _metadata_os_error('encode extended ACL')
        try:
            if size.value > 65536: raise ValueError('ACL budget exceeded')
            return ctypes.string_at(text, size.value)
        finally: lib.acl_free(text)
    finally: lib.acl_free(acl)


def metadata_capture(fd):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode): raise ValueError('metadata requires regular file descriptor')
    attrs = metadata_xattrs(fd)
    acl = metadata_acl(fd)
    after = os.fstat(fd)
    if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('source metadata changed during capture')
    return {'uid': st.st_uid, 'gid': st.st_gid, 'mode': stat.S_IMODE(st.st_mode),
            'nlink': st.st_nlink, 'flags': getattr(st, 'st_flags', 0),
            'xattrs': attrs, 'acl': acl}


def metadata_summary(snapshot):
    attrs = snapshot['xattrs']
    return {'uid': snapshot['uid'], 'gid': snapshot['gid'], 'mode': snapshot['mode'],
            'link_count': snapshot['nlink'], 'xattr_names': sorted(attrs),
            'xattr_sha256': {n: hashlib.sha256(v).hexdigest() for n, v in attrs.items()},
            'acl_sha256': hashlib.sha256(snapshot['acl'] or attrs.get('system.posix_acl_access', b'')).hexdigest(),
            'metadata_platform': sys.platform}


def metadata_preserve(source, target):
    snapshot = metadata_capture(source)
    if snapshot['nlink'] != 1:
        raise ValueError('atomic replacement would split hard links; original remains unchanged')
    if snapshot['mode'] & 0o7000 or snapshot['flags']:
        raise ValueError('special execution/immutable flags require a separately qualified operation')
    if 'security.capability' in snapshot['xattrs']:
        raise ValueError('preserving executable capabilities across content edits requires explicit qualification')
    before = os.fstat(target)
    if snapshot['uid'] != before.st_uid or snapshot['gid'] != before.st_gid:
        os.fchown(target, snapshot['uid'], snapshot['gid'])
    os.fchmod(target, snapshot['mode'])
    if sys.platform == 'darwin':
        # COPYFILE_ACL | COPYFILE_XATTR: never copy source content or timestamps.
        lib = _darwin_lib()
        if lib.fcopyfile(source, target, None, 1 | 4): _metadata_os_error('preserve ACL and extended attributes')
    else:
        for name in os.listxattr(target):
            if name not in snapshot['xattrs']: os.removexattr(target, name)
        # Apply ACL last because its mask determines the resulting mode bits.
        for name in sorted(snapshot['xattrs'], key=lambda n: n == 'system.posix_acl_access'):
            os.setxattr(target, name, snapshot['xattrs'][name])
    actual = metadata_capture(target)
    for key in ('uid', 'gid', 'mode', 'xattrs', 'acl'):
        if actual[key] != snapshot[key]: raise ValueError('metadata verification failed: ' + key)
    current = metadata_capture(source)
    if current != snapshot: raise ValueError('source metadata changed before publication')
    os.fsync(target)
    return metadata_summary(snapshot)
