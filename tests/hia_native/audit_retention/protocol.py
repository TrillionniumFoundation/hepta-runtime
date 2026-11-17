"""Mechanical framing and deterministic external-effect fixtures, never retention policy."""
import struct
from common import require

U64 = (1 << 64) - 1
INVALID = 0xffffffff
CAPACITY = 0xfffffffe


def get(raw, offset):
    return struct.unpack_from('<Q', raw, offset)[0]


def put(raw, offset, value):
    struct.pack_into('<Q', raw, offset, value)


def projection(record):
    out = bytearray(128)
    out[:8] = b'HAJPR001'
    put(out, 8, 1)
    elapsed = record['elapsed_ms']
    put(out, 16, int(elapsed is not None))
    put(out, 24, record['accepted_unix_ms'] & U64)
    put(out, 32, record['accepted_unix_ms'] >> 64)
    put(out, 40, ('unknown', 'completed', 'failed').index(record['state']))
    put(out, 48, 0 if elapsed is None else elapsed)
    for index, key in enumerate(('request_id', 'owner', 'tool_name')):
        raw = record[key].encode('utf-8')
        put(out, 64 + index * 16, len(out))
        put(out, 72 + index * 16, len(raw))
        out.extend(raw)
    return bytes(out)


def text_field(raw, index):
    offset, length = get(raw, 64 + index * 16), get(raw, 72 + index * 16)
    require(offset <= len(raw) and length <= len(raw) - offset, 'fixture typed string bounds')
    return raw[offset:offset + length].decode('utf-8')


def initial(mode, owner, records, pending, sync):
    count, pending_count = len(records), len(pending)
    out = bytearray(128 + 16 * (count + pending_count))
    out[:8] = b'HATRQ001'
    for offset, value in ((8, mode), (16, count), (24, pending_count), (32, int(sync)),
                          (40, len(out)), (48, len(owner.encode())), (56, 128),
                          (64, 128 + count * 16)):
        put(out, offset, value)
    out.extend(owner.encode())
    put(out, 72, len(out))
    for index, record in enumerate(records):
        raw = projection(record)
        put(out, 128 + index * 16, len(out))
        put(out, 136 + index * 16, len(raw))
        out.extend(raw)
    for index, value in enumerate(pending):
        raw = value.encode()
        at = 128 + count * 16 + index * 16
        put(out, at, len(out))
        put(out, at + 8, len(raw))
        out.extend(raw)
    put(out, 80, len(out))
    return bytes(out)


def frame_record(frame, index):
    require(0 <= index < get(frame, 16), 'fixture selected original record index')
    at, size = get(frame, 128 + index * 16), get(frame, 136 + index * 16)
    require(at <= len(frame) and size <= len(frame) - at, 'fixture selected original record span')
    return frame[at:at + size]


def workspace_frame(work):
    require(work[:8] == b'HATRW001', 'native workspace envelope')
    base, size = get(work, 72), get(work, 64)
    require(base <= len(work) and size <= len(work) - base, 'native copied frame span')
    return work[base:base + size]


def response(kind, sequence, status=0, error=0, payload=b''):
    return b'HATRQ001' + struct.pack('<7Q', 3, sequence, kind, status, error, len(payload), 0) + payload


def effect_trace(kind, argument, reply):
    return b'HTREFF01' + struct.pack('<2Q', kind, len(argument)) + argument + struct.pack('<Q', len(reply)) + reply


class Fixture:
    """The mocked service returns supplied values; HIA owns eligibility and selection."""
    def __init__(self, case):
        self.rules = case['effects']
        self.counters = {}
        self.archive = {}
        frame = bytes.fromhex(case['initial_hex'])
        for index in range(get(frame, 16)):
            record = frame_record(frame, index)
            self.archive.setdefault(text_field(record, 0) + '.json', record)
        self.trace = bytearray()
        self.sequence = 0

    def consume(self, kind, sequence, record, sync):
        self.sequence += 1
        require(sequence == self.sequence, 'each actual external effect sequence exactly once')
        request_id = text_field(record, 0)
        if kind == 1:
            group, key, argument = 'active', request_id, request_id.encode()
            default = dict(status=0, error=0)
        elif kind == 2:
            group, key = 'archive', request_id + '.json'
            argument = key.encode()
            default = (dict(status=0, error=0, record_hex=self.archive[key].hex())
                       if key in self.archive else dict(status=1, error=901))
        else:
            require(kind == 3 and sync in (0, 1), 'actual removal effect kind and sync flag')
            group, key, argument = 'remove', request_id, struct.pack('<Q', sync) + record
            default = dict(status=0, error=0)
        tape = self.rules.get(group, {}).get(key)
        at = self.counters.get((group, key), 0)
        rule = default if tape is None else tape[min(at, len(tape) - 1)]
        self.counters[(group, key)] = at + 1
        payload = bytes.fromhex(rule.get('record_hex', ''))
        reply = response(kind, sequence, rule['status'], rule['error'], payload)
        self.trace.extend(effect_trace(kind, argument, reply))
        return reply


def completed(work, reply, trace):
    require(reply[:8] == b'HATRS001' and get(reply, 8) == 4, 'actual complete native response')
    count = get(reply, 56)
    frame = workspace_frame(work)
    result = bytearray(b'HATRV001' + struct.pack('<4Q', get(reply, 40), get(reply, 48), count, len(trace)))
    for index in range(count):
        raw = frame_record(frame, get(work, 128 + index * 8))
        result.extend(struct.pack('<Q', len(raw)))
        result.extend(raw)
    result.extend(trace)
    return bytes(result)


START_PROBES = ('magic', 'truncated', 'operation', 'frame-length', 'record-count',
                'pending-count', 'owner-offset', 'reserved', 'record-kind', 'record-state',
                'record-presence', 'record-reserved', 'record-string-offset', 'record-utf8',
                'output-capacity', 'workspace-capacity')
RESUME_PROBES = ('sequence', 'effect-kind', 'effect-status', 'effect-error', 'effect-reserved',
                 'effect-length', 'reply-truncated', 'output-capacity', 'workspace-header-capacity')


def probe(name, wire, output_capacity, work_capacity, initial_extent):
    raw = bytearray(wire)
    wanted = INVALID
    if name == 'magic': raw[0] ^= 1
    elif name == 'truncated': raw = raw[:7]
    elif name == 'operation': put(raw, 8, 0)
    elif name == 'frame-length': put(raw, 80, len(raw) + 1)
    elif name == 'record-count': put(raw, 16, U64)
    elif name == 'pending-count': put(raw, 24, U64)
    elif name == 'owner-offset': put(raw, 40, get(raw, 40) + 1)
    elif name == 'reserved': put(raw, 88, 1)
    elif name.startswith('record-'):
        at = get(raw, 128)
        if name == 'record-kind': put(raw, at + 8, 2)
        elif name == 'record-state': put(raw, at + 40, 3)
        elif name == 'record-presence': put(raw, at + 16, 2)
        elif name == 'record-reserved': put(raw, at + 56, 1)
        elif name == 'record-string-offset': put(raw, at + 64, 129)
        elif name == 'record-utf8': raw[at + get(raw, at + 64)] = 0xff
        else: raise ValueError(name)
    elif name == 'sequence': put(raw, 16, get(raw, 16) - 1)
    elif name == 'effect-kind': raw = bytearray(response(3 if get(raw, 24) != 3 else 1, get(raw, 16)))
    elif name == 'effect-status': put(raw, 32, 3)
    elif name == 'effect-error': put(raw, 40, 1 if get(raw, 40) == 0 else 0)
    elif name == 'effect-reserved': put(raw, 56, 1)
    elif name == 'effect-length': put(raw, 48, len(raw) - 64 + 1)
    elif name == 'reply-truncated': raw = raw[:63]
    elif name == 'output-capacity': output_capacity, wanted = 127, CAPACITY
    elif name == 'workspace-capacity': work_capacity, wanted = initial_extent - 1, CAPACITY
    elif name == 'workspace-header-capacity': work_capacity, wanted = 127, CAPACITY
    else: raise ValueError(name)
    return bytes(raw), output_capacity, work_capacity, wanted
