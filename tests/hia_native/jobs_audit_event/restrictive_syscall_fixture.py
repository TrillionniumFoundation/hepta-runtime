#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Test-only extra syscall restrictions inherited by one owned comparison child.

This only adds restrictions; it never removes an enclosing filter, changes
credentials, raises a limit, or installs anything in the parent/runtime.
"""
import ctypes
import os
import platform


class Filter(ctypes.Structure):
    _fields_ = [('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),
                ('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]


def install(profile):
    if profile == 'ordinary':
        return
    if platform.machine() != 'x86_64':
        raise RuntimeError('the explicit syscall fixture is Linux x86-64 only')
    # Validate the actual syscall architecture before using the fixed syscall
    # numbers. A different architecture is never accidentally allowed.
    code = [(0x20,0,0,4), (0x15,1,0,0xc000003e), (0x06,0,0,0x80000000),
            (0x20,0,0,0)]
    denied = {'deny-inotify': [(253,38),(294,38)],
              'deny-fdatasync': [(75,5)], 'deny-fsync': [(74,5)]}
    if profile in denied:
        for number,error in denied[profile]:
            code += [(0x15,0,1,number),(0x06,0,0,0x00050000|error)]
    elif profile == 'deny-audit-write':
        # Keep the comparison stdin/stdout/stderr transport usable. Every audit
        # file is independently opened after those three descriptors exist.
        code += [(0x15,0,3,1), (0x20,0,0,16), (0x35,0,1,3),
                 (0x06,0,0,0x00050005)]
    else:
        raise ValueError('unknown restrictive test profile')
    code += [(0x06,0,0,0x7fff0000)]
    instructions = (Filter*len(code))(*(Filter(*row) for row in code))
    program = Program(len(code),instructions)
    libc = ctypes.CDLL(None,use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int,*([ctypes.c_ulong]*4)]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38,1,0,0,0) != 0:
        error=ctypes.get_errno()
        raise OSError(error,'test child could not enable no_new_privs')
    if libc.prctl(22,2,ctypes.addressof(program),0,0) != 0:
        error=ctypes.get_errno()
        raise OSError(error,'test child could not add its restrictive syscall filter')


if __name__ == '__main__':
    install('deny-inotify')
    libc=ctypes.CDLL(None,use_errno=True)
    result=libc.inotify_init1(0x80800)
    error=ctypes.get_errno()
    if result>=0:
        os.close(result)
        raise AssertionError('restrictive fixture did not apply')
    if error!=38:
        raise AssertionError(('unexpected syscall result',result,error))
    print('owned child inotify restriction observed: ENOSYS')
