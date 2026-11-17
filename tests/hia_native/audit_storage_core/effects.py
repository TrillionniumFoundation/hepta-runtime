"""Mechanical Linux descriptor effects only; retries and all audit policy remain in HIA."""
import ctypes as C
import os
import struct
from protocol import acknowledgement, require


class Effects:
    def __init__(self, root, journal):
        self.lib = C.CDLL(None, use_errno=True)
        self.journal = journal
        self.capabilities = {1: ('file', os.open(root, os.O_RDONLY | os.O_CLOEXEC))}
        self.next_capability = 2
        self.lib.openat.argtypes = [C.c_int, C.c_char_p, C.c_int, C.c_uint]
        self.lib.openat.restype = C.c_int
        self.lib.fstat.argtypes = [C.c_int, C.c_void_p];self.lib.fstat.restype = C.c_int
        self.lib.geteuid.argtypes = [];self.lib.geteuid.restype = C.c_uint
        self.lib.read.argtypes = [C.c_int, C.c_void_p, C.c_size_t];self.lib.read.restype = C.c_ssize_t
        self.lib.write.argtypes = [C.c_int, C.c_void_p, C.c_size_t];self.lib.write.restype = C.c_ssize_t
        self.lib.fsync.argtypes = [C.c_int];self.lib.fsync.restype = C.c_int
        self.lib.close.argtypes = [C.c_int];self.lib.close.restype = C.c_int
        self.lib.linkat.argtypes = [C.c_int, C.c_char_p, C.c_int, C.c_char_p, C.c_int];self.lib.linkat.restype = C.c_int
        self.lib.unlinkat.argtypes = [C.c_int, C.c_char_p, C.c_int];self.lib.unlinkat.restype = C.c_int
        self.lib.renameat.argtypes = [C.c_int, C.c_char_p, C.c_int, C.c_char_p];self.lib.renameat.restype = C.c_int
        self.lib.fcntl.argtypes = [C.c_int, C.c_int, C.c_int];self.lib.fcntl.restype = C.c_int
        self.lib.fdopendir.argtypes = [C.c_int];self.lib.fdopendir.restype = C.c_void_p
        self.lib.readdir.argtypes = [C.c_void_p];self.lib.readdir.restype = C.c_void_p
        self.lib.closedir.argtypes = [C.c_void_p];self.lib.closedir.restype = C.c_int

    def get(self, capability, kind='file'):
        require(type(capability) is int and capability in self.capabilities, 'retained capability identity')
        actual_kind, value = self.capabilities[capability]
        require(actual_kind == kind, 'exact retained descriptor kind')
        return value

    def add(self, kind, value):
        capability = self.next_capability;self.next_capability += 1
        require(value is not None and value >= 0, 'actual successful descriptor')
        self.capabilities[capability] = (kind, value)
        return capability

    def apply(self, effect):
        require(effect['kind'] == 2, 'fixed filesystem child')
        op = effect['operation'];a,b,c = effect['arguments'];p0,p1 = effect['payloads']
        payload = b'';value = 0;status = 0;observed = {}
        before = {str(k): kind for k,(kind,_) in sorted(self.capabilities.items())}
        if op == 1:
            require(p0 and b'\0' not in p0 and not p1, 'exact open component frame')
            actual = self.lib.openat(self.get(a), p0, b | os.O_NOFOLLOW | os.O_CLOEXEC, c)
            errno = C.get_errno()
            if actual >= 0:
                value = self.add('file', actual)
        elif op == 2:
            buffer = C.create_string_buffer(144)
            actual = self.lib.fstat(self.get(a), buffer)
            errno = C.get_errno()
            observed['complete_linux_x86_64_stat_hex'] = buffer.raw.hex()
            if actual == 0:
                dev, ino, nlink = struct.unpack_from('<3Q', buffer.raw, 0)
                mode, uid = struct.unpack_from('<2I', buffer.raw, 24)
                size = struct.unpack_from('<q', buffer.raw, 48)[0]
                require(size >= 0, 'actual nonnegative file extent')
                payload = struct.pack('<8Q', mode, uid, nlink, size, dev, ino, 0, 0)
        elif op == 3:
            actual = self.lib.geteuid();errno = C.get_errno();value = actual
        elif op == 4:
            require(0 <= b <= 2049 and not p0 and not p1, 'exact HIA read bound')
            buffer = C.create_string_buffer(max(1,b))
            actual = self.lib.read(self.get(a), buffer, b)
            errno = C.get_errno()
            if actual >= 0:
                value = actual;payload = buffer.raw[:actual]
        elif op == 5:
            require(b == len(p0) and not p1, 'complete HIA write span')
            buffer = C.create_string_buffer(p0, max(1,len(p0)))
            actual = self.lib.write(self.get(a), buffer, b)
            errno = C.get_errno()
            if actual >= 0:
                value = actual
        elif op == 6:
            actual = self.lib.fsync(self.get(a));errno = C.get_errno()
        elif op == 7:
            require(a != 1, 'borrowed directory cannot be closed')
            actual = self.lib.close(self.get(a));errno = C.get_errno()
            del self.capabilities[a]
        elif op in (8,9,10):
            require(p0 and b'\0' not in p0 and b'\0' not in p1, 'exact publication component frame')
            descriptor = self.get(a)
            if op == 8:
                require(p1, 'complete link target')
                actual = self.lib.linkat(descriptor,p0,descriptor,p1,0)
            elif op == 9:
                require(not p1, 'unlink has one component')
                actual = self.lib.unlinkat(descriptor,p0,0)
            else:
                require(p1, 'complete rename target')
                actual = self.lib.renameat(descriptor,p0,descriptor,p1)
            errno = C.get_errno()
        elif op == 11:
            actual = self.lib.fcntl(self.get(a), 1030, 0);errno = C.get_errno()
            if actual >= 0:
                value = self.add('file',actual)
        elif op == 12:
            require(a != 1, 'fdopendir consumes only owned duplicate')
            pointer = self.lib.fdopendir(self.get(a));errno = C.get_errno()
            actual = 0 if pointer is None else int(pointer)
            if actual:
                del self.capabilities[a];value = self.add('directory',actual)
            else:
                actual = -1
        elif op == 13:
            C.set_errno(0)
            pointer = self.lib.readdir(self.get(a,'directory'))
            errno = C.get_errno()
            actual = 0 if pointer is None else int(pointer)
            if actual:
                head = C.string_at(actual,19)
                inode = struct.unpack_from('<Q',head)[0]
                extent = struct.unpack_from('<H',head,16)[0]
                require(20 <= extent <= 8192, 'actual dirent extent')
                raw = C.string_at(actual,extent)
                stop = raw.find(b'\0',19)
                require(stop >= 19 and stop-19 <= 4096, 'complete actual dirent name')
                payload = struct.pack('<Q',inode)+raw[19:stop];value = 1
                observed['complete_linux_dirent_hex'] = raw.hex()
            observed['readdir_nonnull'] = bool(actual)
        elif op == 14:
            actual = self.lib.closedir(self.get(a,'directory'));errno = C.get_errno()
            del self.capabilities[a]
        else:
            raise ValueError('uninstalled filesystem opcode')
        observed.update(actual_return=actual,actual_errno=errno)
        if actual < 0 and op != 13:
            status = 1;value = 0;payload = b''
            require(1 <= errno <= 4095, 'complete actual OS error')
        else:
            if op not in (7,13):
                errno = 0
        ack = acknowledgement(effect,status=status,errno=errno,value=value,payload=payload)
        after = {str(k): kind for k,(kind,_) in sorted(self.capabilities.items())}
        row = dict(generation=effect['generation'],sequence=effect['sequence'],operation=op,
                   arguments=list(effect['arguments']),payloads=[v.hex() for v in effect['payloads']],
                   acknowledgement_hex=ack.hex(),capabilities_before=before,capabilities_after=after,
                   observed=observed)
        self.journal(row)
        return ack

    def quiescent(self):
        require(set(self.capabilities) == {1}, 'all owned resources explicitly closed by HIA')

    def close(self):
        errors = []
        for capability,(kind,value) in list(self.capabilities.items())[::-1]:
            try:
                if kind == 'directory':
                    self.lib.closedir(value)
                else:
                    self.lib.close(value)
            except BaseException as error:
                errors.append(repr(error))
            finally:
                self.capabilities.pop(capability,None)
        require(not errors, 'mechanical failure cleanup completed: '+repr(errors))
