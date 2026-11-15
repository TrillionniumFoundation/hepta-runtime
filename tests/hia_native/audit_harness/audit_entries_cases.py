"""Owned directory fixtures for original bounded audit enumeration."""
import json
import os
import struct

ID = 'a' * 64
OWNER = 'b' * 64
NAME = ID + '.json'
STAGE = '.' + ID + '-' + ID + '.tmp'
OLD_STAGE = '.' + ID + '-' + 'c' * 64 + '.tmp'


def record(**overrides):
    value = dict(request_id=ID, owner=OWNER, tool_name='h_file_read', state='unknown',
        accepted_unix_ms=1, elapsed_ms=None)
    value.update(overrides)
    return value


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def request(maximum=512):
    return b'HRAEQ001' + struct.pack('<Q', maximum)


def file(raw=None, mode=0o600):
    return dict(kind='file', mode=mode, data=(encoded(record()) if raw is None else raw).hex())


def link(target):
    return dict(kind='hardlink', target=target)


def row(name, files=None, operations=None, **extra):
    if files is None:files = {NAME: file()}
    if operations is None:operations = [request(), request()]
    return dict(name=name, files=files, operations=[raw.hex() for raw in operations], **extra)


def records(count):
    result = {}
    times = [0, 1, (1 << 64) - 1, 1 << 64, (1 << 128) - 1, (1 << 127) + 1]
    for index in range(count - 1, -1, -1):
        identifier = f'{index:064x}'
        value = record(request_id=identifier, accepted_unix_ms=times[index % len(times)],
            state=('unknown', 'completed', 'failed')[index % 3],
            elapsed_ms=(None, 0, (1 << 64) - 1)[index % 3],
            tool_name=('a', 'h_file_read', 'z' * 64)[index % 3])
        result[identifier + '.json'] = file(encoded(value))
    return result


def stages(count):
    return {'.' + f'{10000 + index:064x}' + '-' + f'{20000 + index:064x}' + '.tmp': file(b'interrupted')
        for index in range(count)}


def cases():
    for maximum in (0, 1, 2, 32, 128, 511, 512):
        yield row('empty-' + str(maximum), {}, [request(maximum)] * 2)
        yield row('one-' + str(maximum), operations=[request(maximum)] * 2)
    for count in (2, 31, 32, 127, 128, 129, 511, 512, 513):
        yield row('sorted-' + str(count), records(count))
    for maximum in (0, 1, 128, 512):
        for extra in (0, 1):
            yield row(f'name-bound-{maximum}-{extra}', stages(maximum + 32 + extra),
                [request(maximum)] * 2)
    for maximum in (1, 128, 512):
        for extra in (31, 32, 33):
            values = records(maximum);values.update(stages(extra))
            yield row(f'records-plus-stages-{maximum}-{extra}', values, [request(maximum)] * 2)
    for mode in (0o700, 0o755, 0o500, 0o777, 0o1700):
        yield row('directory-mode-' + oct(mode), directory_mode=mode)
    for mode in (0, 0o400, 0o644, 0o700, 0o4600):
        yield row('private-file-' + oct(mode), {NAME: file(mode=mode)})
        yield row('private-stage-' + oct(mode), {NAME: file(), STAGE: file(b'x', mode)})
    for kind in ('directory', 'fifo', 'socket', 'symlink'):
        value = dict(kind=kind, mode=0o600)
        if kind == 'symlink':value['target'] = 'other'
        yield row('record-kind-' + kind, {NAME: value, 'other': file()})
        yield row('stage-kind-' + kind, {NAME: file(), STAGE: value, 'other': file()})
    for label, raw in (('empty', b''), ('invalid-json', b'{'), ('UTF8', b'\xff'),
            ('missing-owner', b'{}'), ('over-size', b' ' * 2049),
            ('wrong-id', encoded(record(request_id='c' * 64))),
            ('wrong-owner', encoded(record(owner='X' * 64))),
            ('wrong-tool', encoded(record(tool_name='0')))):
        yield row('bad-record-' + label, {NAME: file(raw)})
    yield row('deterministic-linked-stage', {NAME: file(), STAGE: link(NAME)})
    yield row('random-linked-stage', {NAME: file(), OLD_STAGE: link(NAME)})
    yield row('orphan-stage-before-record', {NAME: file(), STAGE: file(b'interrupted')})
    yield row('orphan-stage-only', {STAGE: file(b'interrupted')})
    yield row('unbound-hardlink', {NAME: file(), 'other': link(NAME)})
    yield row('staging-hardlink-binding-refused', {NAME: file(), STAGE: file(), 'other': link(STAGE)})
    yield row('staging-published-missing', {STAGE: file(), 'other': link(STAGE)})
    yield row('cleanup-before-bad-record-name', {'bad': file(), STAGE: file()})
    yield row('cleanup-before-bad-record-json', {NAME: file(b'{'), STAGE: file()})
    yield row('cleanup-all-before-record-limit', {NAME: file(), **stages(3)}, [request(0), request()])
    names = ['bad', 'short.json', 'A' * 64 + '.json', 'c' * 65 + '.json', 'c' * 63 + '.json',
        'a.json.json', 'other.JSON', '汉字.json', '😀.json', 'x' * 250 + '.json', 'x' * 255,
        '.hidden', '.json', '.tmp', '.' + 'x' * 254,
        os.fsdecode(b'bad\xff.json'), os.fsdecode(b'.bad\xff.tmp')]
    for index, name in enumerate(names):
        yield row('member-name-' + str(index), {name: file()})
    for index, raw in enumerate((b'', b'HRAEQ001', request()[:-1], request() + b'x',
            b'BADMAGIC' + request()[8:], request(513), request((1 << 64) - 1))):
        yield row('invalid-frame-' + str(index), operations=[raw, request()])

