"""Read-only real-filesystem key domain for native and original executables."""
from __future__ import annotations
import itertools
import os
from pathlib import Path
import random
import struct

def request(path, host=None, port=0):
    return struct.pack('<8s7Q', b'HRLKKEY1', 1 if host is None else 2,
        len(path), 0 if host is None else len(host), port, 0, 0, 0) + path + (b'' if host is None else host)

def raw_paths():
    found = set()
    for n in range(8):
        for value in itertools.product(b'./ab', repeat=n):
            found.add(bytes(value))
    for first in range(256):
        found.add(bytes([first]))
        for second in range(256):
            found.add(bytes([first, second]))
    for prefix in (b'', b'./', b'//', b'a//./', b'../', b'raw-\xff/'):
        for name in (b'.', b'..', b'...', b'\xf0\x90\x80', b'\xed\xa0\x80', b'\xe2\x82', '🙂'.encode(), 'é'.encode()):
            for suffix in (b'', b'/', b'/.', b'/..', b'//./'):
                found.add(prefix + name + suffix)
    randomizer = random.Random(319)
    for _ in range(1000):
        found.add(bytes(randomizer.randrange(256) for _ in range(randomizer.randrange(3, 65))))
    yield from sorted(found)
    # These are complete input/output domains, not a shortened static profile.
    yield b'a' * (5 << 20)
    yield b'\xff' * (5 << 20)
    yield b'a/./' * 10000 + b'z'
    # Reuse a previously grown physical workspace at a smaller logical layout.
    yield b'dir/' + b'x' * 2048
    yield b'dir/file'

def paths():
    yield from raw_paths()
    tokens = (b'', b'.', b'..', b'dir', b'file', b'link', b'missing', b'\xff')
    for count in range(1, 4):
        for parts in itertools.product(tokens, repeat=count):
            yield b'/'.join(parts)
    for prefix in (b'dir', b'link', b'absolute-link', b'broken', b'loop', b'chain-0', b'over-0',
                   b'raw-\xff', b'dir/file', b'long-link', b'denied'):
        for suffix in (b'', b'/', b'/.', b'/..', b'//./', b'/file', b'/missing', b'/\xff', b'/\0name'):
            yield prefix + suffix
    for size in (1022, 1023, 1024, 2046, 2047, 2048, 4094):
        yield ('sized-link-' + str(size)).encode()

def requests():
    for path in paths():
        yield 'local', request(path)
    for host in (b'', b'localhost', b'host:already', b'[::1]', '主机'.encode(), b'host\0suffix'):
        for port in (0, 1, 22, 80, 443, 65535):
            for path in (b'', b'relative', b'/absolute', b'//double', '🙂/é'.encode(), b'with\0nul'):
                yield 'remote', request(path, host, port)

def setup(base):
    base = Path(base)
    base.mkdir(mode=0o700)
    os.mkdir(os.fsencode(base) + b'/dir')
    os.mkdir(os.fsencode(base) + b'/dir/sub')
    os.mkdir(os.fsencode(base) + b'/raw-\xff')
    os.mkdir(os.fsencode(base) + b'/denied')
    for path in (b'file', b'dir/file', b'raw-\xff/file'):
        fd = os.open(os.fsencode(base) + b'/' + path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        os.write(fd, b'fixture-data')
        os.close(fd)
    os.symlink(b'dir', os.fsencode(base) + b'/link')
    os.symlink(os.fsencode(base) + b'/dir', os.fsencode(base) + b'/absolute-link')
    os.symlink(b'absent', os.fsencode(base) + b'/broken')
    os.symlink(b'loop', os.fsencode(base) + b'/loop')
    os.symlink(b'./' * 1500 + b'dir', os.fsencode(base) + b'/long-link')
    for size in (1022, 1023, 1024, 2046, 2047, 2048, 4094):
        target = b'/' * (size - 1) + b'.'
        os.symlink(target, os.fsencode(base) + b'/sized-link-' + str(size).encode())
    for prefix, count in ((b'chain-', 40), (b'over-', 41)):
        for index in range(count):
            target = b'dir' if index == count - 1 else prefix + str(index + 1).encode()
            os.symlink(target, os.fsencode(base) + b'/' + prefix + str(index).encode())
    os.chmod(base / 'denied', 0)
    return base
