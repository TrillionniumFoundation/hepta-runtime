"""Complete deterministic session-state corpus for native and original replay."""
import random
import struct

WORK_BYTES = (16 << 20) + 64
PATH_BYTES = 8 << 20

def packet(op, raw=b''):
    return struct.pack('<8s3Q', b'HRSWQ001', op, len(raw), 0) + raw

def response(tag=0, scalar=0, raw=b''):
    return struct.pack('<8s3Q', b'HRSWR001', tag, scalar, len(raw)) + raw

class Reference:
    """Independent ordinary objects express the public state results."""
    def __init__(self):
        self.sessions = {}

    def apply(self, sid, request):
        magic, op, size, reserved = struct.unpack_from('<8s3Q', request)
        assert magic == b'HRSWQ001' and not reserved and len(request) == 32 + size
        raw = request[32:]
        if op == 1:
            assert sid not in self.sessions
            self.sessions[sid] = {'root': raw, 'current': None, 'poisoned': False, 'applied': False}
            return response()
        state = self.sessions[sid]
        if op == 2:
            current = state['root'] if state['current'] is None or state['poisoned'] else state['current']
            return response(1, raw=current)
        if op == 3:
            if not state['poisoned']:
                state['current'] = raw
        elif op == 4:
            if not state['poisoned']:
                state['current'] = None
        elif op == 5:
            first = not state['applied']
            state['applied'] = True
            return response(2, int(first))
        elif op == 6:
            state['poisoned'] = True
        else:
            raise AssertionError(op)
        return response()

def small_cases():
    roots = [b'', b'/', b'/work/root', b'relative', b'\x00', b'\xff\xfe', bytes(range(256)), b'//a/../b//']
    for sid, root in enumerate(roots):
        yield sid, packet(1, root)
        yield sid, packet(2)
    paths = [b'', b'.', b'..', b'/', b'//', b'a//b/../c/', b'ssh://host/a', b'a\x00b',
             '中/文/\u202e\u2028\ufeff'.encode(), bytes(range(256))]
    paths += [bytes([value]) for value in range(256)]
    for i, path in enumerate(paths):
        sid = i % len(roots)
        yield sid, packet(3, path)
        yield sid, packet(2)
        if i % 3 == 0:
            yield sid, packet(4)
            yield sid, packet(2)
    rng = random.Random(0x48525357)
    for _ in range(4096):
        sid = rng.randrange(len(roots))
        op = rng.choice([2, 2, 2, 3, 3, 4, 5])
        raw = rng.randbytes(rng.randrange(257)) if op == 3 else b''
        yield sid, packet(op, raw)
    for sid in range(len(roots)):
        for op, raw in [(3, b'private-current'), (2, b''), (6, b''), (2, b''),
                        (3, b'ignored'), (2, b''), (4, b''), (2, b''), (5, b''), (5, b'')]:
            yield sid, packet(op, raw)

def large_cases():
    root = bytes(range(256)) * (PATH_BYTES // 256)
    current = b'z' * PATH_BYTES
    for op, raw in [(1, root), (2, b''), (3, current), (2, b''), (3, b'x'),
                    (2, b''), (4, b''), (2, b''), (5, b''), (5, b''), (6, b''), (2, b'')]:
        yield 8, packet(op, raw)

def transport_cases(sid):
    """Persistent-wire coverage; the full state domain uses direct native ABI.

    The shared hexadecimal fixture clears full eight MiB transport arenas per
    frame. It is not the production session dispatcher and does not define its
    throughput. Keep explicit wire/lifetime cases separate from the full corpus.
    """
    root = b'/wire-session-' + str(sid).encode() + bytes([sid, 255])
    yield packet(1, root)
    yield packet(2)
    yield packet(5)
    yield packet(5)
    for value in [b'', b'.', b'a\x00b', b'\xff\xfe', bytes(range(256)),
                  '中/文/\u202e'.encode(), b'a//../b/']:
        yield packet(3, value)
        yield packet(2)
        yield packet(4)
        yield packet(2)
    for op, raw in [(3, b'unreachable'), (6, b''), (2, b''), (3, b'ignored'),
                    (2, b''), (4, b''), (2, b''), (5, b'')]:
        yield packet(op, raw)
