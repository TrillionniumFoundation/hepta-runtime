"""Private frame projections; no HIA, filesystem effect or original execution."""
import json
import struct
from pathlib import Path

INVALID = 0xffffffff
CAPACITY = 0xfffffffe
WORDS = struct.Struct('<16Q')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def word(raw, at):
    require(type(at) is int and at >= 0 and at + 8 <= len(raw), 'complete word extent')
    return struct.unpack_from('<Q', raw, at)[0]


def put(raw, at, value):
    require(type(value) is int and 0 <= value < 1 << 64, 'exact u64')
    struct.pack_into('<Q', raw, at, value)


def record(value):
    strings = [value[key].encode() for key in ('request_id', 'owner', 'tool_name')]
    out = bytearray(128 + sum(map(len, strings)))
    out[:8] = b'HAJPR001'
    put(out, 8, 1)
    elapsed = value['elapsed_ms']
    accepted = int(value['accepted_unix_ms'])
    require(0 <= accepted < 1 << 128, 'typed accepted u128')
    put(out, 16, int(elapsed is not None))
    put(out, 24, accepted & ((1 << 64) - 1))
    put(out, 32, accepted >> 64)
    put(out, 40, {'unknown': 0, 'completed': 1, 'failed': 2}[value['state']])
    put(out, 48, 0 if elapsed is None else int(elapsed))
    at = 128
    for i, raw in enumerate(strings):
        put(out, 64 + i * 16, at)
        put(out, 72 + i * 16, len(raw))
        out[at:at + len(raw)] = raw
        at += len(raw)
    return bytes(out)


def initial(case_index, step_index, step, directory=1):
    payload = record(step['record']) if 'record' in step else bytes.fromhex(step['filename_hex'])
    out = bytearray(128 + len(payload))
    out[:8] = b'HAIORQ01'
    for at, value in ((8, step['operation']), (16, 1 + case_index * 100 + step_index),
                      (24, directory), (32, step['flags']), (40, len(payload)), (48, 128)):
        put(out, at, value)
    out[128:] = payload
    return bytes(out)


def response(raw, result=None):
    if result is not None:
        require(type(result) is int and result == len(raw), 'complete owner return')
    require(len(raw) >= 128 and raw[:8] == b'HAIORS01', 'owner result header')
    require(word(raw, 112) == len(raw) and word(raw, 120) == 0, 'owner result extent/reserved')
    fields = [word(raw, at) for at in range(8, 112, 8)]
    kind, sequence, generation, op, a, b, c, p0, n0, p1, n1, family, code = fields
    require(kind <= 3 and generation != 0, 'owner result lifecycle')
    at = 128
    payloads = []
    for off, size in ((p0, n0), (p1, n1)):
        if size:
            require(off == at and size <= len(raw) - at, 'complete contiguous effect span')
            payloads.append(raw[at:at + size]);at += size
        else:
            require(off == 0, 'absent effect span offset');payloads.append(b'')
    require(at == len(raw), 'entire response consumed')
    if kind in (0, 1):
        require(a == b == c == 0 and not payloads[1], 'terminal unused fields')
        require((kind == 0 and family == code == 0) or (kind == 1 and family in range(1, 6)),
                'terminal error projection')
        require((kind == 0 and op == 1) or not payloads[0], 'terminal Record ownership')
    else:
        require(sequence != 0 and family == code == 0, 'effect identity')
        require((kind == 2 and 1 <= op <= 14) or (kind == 3 and op in (1, 3)), 'fixed effect namespace')
        if kind == 3:
            require(a == b == c == 0 and not payloads[1], 'JSON effect unused fields')
            child = payloads[0]
            require(len(child) >= 24 and child[:8] == b'HAJRQ001' and word(child, 8) == op
                    and word(child, 16) == len(child) - 24, 'exact frozen JSON frame')
    return dict(kind=kind, sequence=sequence, generation=generation, operation=op,
                arguments=(a, b, c), payloads=payloads, family=family, code=code)


def acknowledgement(effect, *, status=0, errno=0, value=0, payload=b''):
    out = bytearray(128 + len(payload));out[:8] = b'HAIOACK1'
    for at, v in ((8, effect['generation']), (16, effect['sequence']), (24, effect['kind']),
                  (32, effect['operation']), (40, status), (48, errno), (56, value),
                  (64, len(payload)), (72, len(out))):
        put(out, at, v)
    out[128:] = payload
    return bytes(out)


def semantic(raw):
    out = response(raw)
    require(out['kind'] in (0, 1), 'completed actual owner result')
    payload = out['payloads'][0]
    result = bytearray(64 + len(payload));result[:8] = b'HAIOOR01'
    for at, value in ((8, out['kind']), (16, out['operation']), (24, out['family']),
                      (32, out['code']), (40, len(payload))):
        put(result, at, value)
    result[64:] = payload
    return bytes(result)


def validate_semantic(raw):
    require(len(raw) >= 64 and raw[:8] == b'HAIOOR01', 'complete original projection')
    require(word(raw, 8) in (0, 1) and word(raw, 16) in (1, 2, 3, 4), 'projection kind')
    require(word(raw, 40) == len(raw) - 64 and word(raw, 48) == word(raw, 56) == 0, 'projection extent')
    return raw


def cases(root):
    value = json.loads((Path(root) / 'DOMAIN.json').read_bytes())
    require(value['schema'] == 'hepta.audit-record-io.domain.v1' and value['expected_outputs_not_embedded'] is True,
            'fixed input domain')
    rows = value['cases']
    require(value['cases_count'] == len(rows) == 219 and len({row['name'] for row in rows}) == len(rows),
            'all original filesystem cases')
    require(value['record_io_frames'] == sum(len(row['steps']) for row in rows) == 459, 'all original operations')
    return rows
