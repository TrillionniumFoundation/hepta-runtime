# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native target-account binary transfer: bounded chunks, complete files, checked publication.
No shell input, privileges, network listener, or caller-selected helper. A directory
lock coordinates native writers, not arbitrary writers outside this API.
"""
import base64
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import uuid

CHUNK = 1024 * 1024


def version(st):
    return ':'.join(map(str, (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)))


def parent(root, path):
    root, path = pathlib.PurePosixPath(root), pathlib.PurePosixPath(path)
    if not root.is_absolute() or not path.is_absolute() or '..' in root.parts or '..' in path.parts:
        raise ValueError('absolute non-traversing file path required')
    if root != path and root not in path.parents:
        raise PermissionError('file outside configured root')
    if path == root or path.name.startswith('.hepta-'):
        raise ValueError('capability root and runtime sidecars are not file targets')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = child
        return fd, path.name
    except BaseException:
        os.close(fd); raise


def regular(fd, name, flags=os.O_RDONLY, mode=0o600, private=False):
    f = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, mode, dir_fd=fd)
    st = os.fstat(f)
    if not stat.S_ISREG(st.st_mode) or (private and (st.st_uid != os.geteuid() or st.st_nlink != 1 or st.st_mode & 0o077)):
        os.close(f); raise ValueError('invalid regular file or private sidecar')
    return f


def current(fd, name):
    try:
        f = regular(fd, name)
        try: return os.fstat(f)
        finally: os.close(f)
    except FileNotFoundError: return None


def expected(fd, name, value):
    st = current(fd, name)
    if value is None or value != (version(st) if st else 'absent'):
        raise ValueError('destination version changed; no publication performed')
    return st


def all_write(fd, data):
    pending = memoryview(data)
    while pending:
        n = os.write(fd, pending)
        if n <= 0: raise OSError('write made no progress')
        pending = pending[n:]


def json_read(fd, name):
    with os.fdopen(regular(fd, name, private=True), 'rb') as f:
        payload = f.read(16385)
        if len(payload) > 16384: raise ValueError('sidecar exceeds size bound')
        return json.loads(payload)


def json_save(fd, name, value):
    temp = '.hepta-meta-' + uuid.uuid4().hex
    try:
        f = regular(fd, temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, private=True)
        try: all_write(f, json.dumps(value, sort_keys=True).encode()); os.fsync(f)
        finally: os.close(f)
        os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)
    finally:
        try: os.unlink(temp, dir_fd=fd)
        except FileNotFoundError: pass


def fingerprint(fd, name):
    with os.fdopen(regular(fd, name), 'rb') as f:
        before = os.fstat(f.fileno()); h = hashlib.sha256()
        for chunk in iter(lambda: f.read(CHUNK), b''): h.update(chunk)
        if version(before) != version(os.fstat(f.fileno())): raise ValueError('file changed while hashing')
    return {'size': before.st_size, 'version': version(before), 'sha256': h.hexdigest(), 'mode': stat.S_IMODE(before.st_mode)}


def publish(fd, name, temp, prior):
    before = expected(fd, name, prior)
    f = regular(fd, temp, os.O_RDWR, private=True)
    try:
        if before:
            source = regular(fd, name)
            try:
                if version(os.fstat(source)) != prior: raise ValueError('source changed before metadata copy')
                # Refuse unsupported metadata rather than silently removing it.
                if hasattr(os, 'listxattr') and os.listxattr(source):
                    raise ValueError('destination has extended attributes/ACLs; metadata-preserving replacement not qualified')
                if before.st_uid != os.geteuid() or before.st_mode & 0o7000:
                    raise ValueError('special ownership/mode preservation not qualified')
                if os.fstat(f).st_gid != before.st_gid: os.fchown(f, -1, before.st_gid)
                os.fchmod(f, stat.S_IMODE(before.st_mode))
            finally: os.close(source)
        os.fsync(f)
    finally: os.close(f)
    expected(fd, name, prior)
    if prior == 'absent':
        os.link(temp, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.unlink(temp, dir_fd=fd)
    else: os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)


def main(q):
    fd, name = parent(q['root'], q['path'])
    try:
        op = q['op']
        if op == 'info': return {'path': q['path'], **fingerprint(fd, name)}
        if op == 'read':
            with os.fdopen(regular(fd, name), 'rb') as f:
                st = os.fstat(f.fileno()); ver = version(st)
                if q.get('expected_version') not in (None, ver): raise ValueError('source version changed')
                offset = int(q.get('offset') or 0); limit = max(1, min(CHUNK, int(q.get('limit') or 32768)))
                if not 0 <= offset <= st.st_size: raise ValueError('read cursor outside file')
                f.seek(offset); data = f.read(min(limit, st.st_size - offset))
                if version(os.fstat(f.fileno())) != ver: raise ValueError('file changed while reading')
            return {'path': q['path'], 'size': st.st_size, 'version': ver, 'offset': offset,
                    'next_offset': offset + len(data), 'eof': offset + len(data) == st.st_size,
                    'data_base64': base64.b64encode(data).decode(), 'chunk_sha256': hashlib.sha256(data).hexdigest()}
        lockname = '.hepta-lock-' + hashlib.sha256(name.encode()).hexdigest()[:24]
        with os.fdopen(regular(fd, lockname, os.O_RDWR | os.O_CREAT, private=True), 'a') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if op == 'write':
                prior = q['expected_version']; expected(fd, name, prior)
                data = base64.b64decode(q['data_base64'], validate=True)
                if len(data) > CHUNK: raise ValueError('write exceeds 1 MiB; use upload')
                temp = '.hepta-write-' + uuid.uuid4().hex
                try:
                    f = regular(fd, temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, private=True)
                    try: all_write(f, data); os.fsync(f)
                    finally: os.close(f)
                    publish(fd, name, temp, prior)
                    return {'written': len(data), **fingerprint(fd, name)}
                finally:
                    try: os.unlink(temp, dir_fd=fd)
                    except FileNotFoundError: pass
            if op not in ('upload_chunk', 'upload_commit', 'upload_abort'):
                raise ValueError('unknown binary operation')
            upload = q['upload_id']
            if not re.fullmatch(r'[A-Za-z0-9_-]{8,96}', upload): raise ValueError('invalid upload ID')
            tag = hashlib.sha256((name + '\0' + upload).encode()).hexdigest()
            temp, meta = '.hepta-upload-' + tag, '.hepta-upload-' + tag + '.json'
            try: receipt = json_read(fd, meta)
            except FileNotFoundError: receipt = None
            if receipt and receipt['name'] != name: raise ValueError('upload target binding differs')
            if op == 'upload_abort':
                if receipt and receipt['state'] == 'committed':
                    return {'aborted': False, 'already_committed': True}
                if receipt and receipt['state'] == 'publishing':
                    raise ValueError('publication uncertain; inspect destination before abort')
                try: os.unlink(temp, dir_fd=fd)
                except FileNotFoundError: pass
                json_save(fd, meta, {'state': 'aborted', 'name': name})
                return {'aborted': True}
            if receipt and receipt['state'] == 'aborted': raise ValueError('upload was aborted')
            if op == 'upload_chunk':
                data = base64.b64decode(q['data_base64'], validate=True)
                offset = int(q.get('offset') or 0)
                if len(data) > CHUNK or offset < 0: raise ValueError('invalid bounded upload chunk')
                prior = q.get('expected_version'); expected(fd, name, prior)
                if receipt is None:
                    if offset: raise ValueError('first chunk must start at zero')
                    receipt = {'state': 'staging', 'name': name, 'expected_version': prior}
                    json_save(fd, meta, receipt)
                if receipt.get('expected_version') != prior or receipt['state'] != 'staging':
                    raise ValueError('upload request or state differs')
                f = regular(fd, temp, os.O_RDWR | os.O_CREAT, private=True)
                try:
                    size = os.fstat(f).st_size
                    if offset < size:
                        os.lseek(f, offset, os.SEEK_SET)
                        if offset + len(data) > size or os.read(f, len(data)) != data:
                            raise ValueError('replayed upload bytes differ or overlap an incomplete write')
                    elif offset == size:
                        os.lseek(f, offset, os.SEEK_SET); all_write(f, data); os.fsync(f)
                    else: raise ValueError('upload cannot skip bytes')
                finally: os.close(f)
                return {'upload_id': upload, 'next_offset': offset + len(data), 'visible': False}
            size, sha = int(q['size']), q['sha256'].lower()
            if size < 0 or not re.fullmatch('[0-9a-f]{64}', sha): raise ValueError('invalid commit fingerprint')
            if receipt is None: raise ValueError('unknown upload')
            if receipt['state'] in ('publishing', 'committed'):
                if receipt['size'] != size or receipt['sha256'] != sha: raise ValueError('commit replay parameters differ')
                actual = fingerprint(fd, name)
                if actual['size'] != size or actual['sha256'] != sha:
                    raise ValueError('published destination changed; do not re-publish this upload')
                if receipt['state'] == 'committed' and actual['version'] != receipt['result']['version']:
                    raise ValueError('published destination version changed')
                receipt.update(state='committed', result=actual); json_save(fd, meta, receipt)
                return {'committed': True, 'reused': True, **actual}
            actual = fingerprint(fd, temp)
            if actual['size'] != size or actual['sha256'] != sha: raise ValueError('upload checksum or size differs')
            expected(fd, name, receipt['expected_version'])
            receipt.update(state='publishing', size=size, sha256=sha); json_save(fd, meta, receipt)
            publish(fd, name, temp, receipt['expected_version'])
            result = fingerprint(fd, name)
            receipt.update(state='committed', result=result); json_save(fd, meta, receipt)
            return {'committed': True, 'reused': False, **result}
    finally: os.close(fd)


if __name__ == '__main__':
    try: print(json.dumps(main(json.load(sys.stdin))))
    except Exception as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
