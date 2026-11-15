"""Typed original Record values and owned publication fixtures."""
import json
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


def request(value=None, operation=1, sync=True):
    if value is None:value = record()
    p = bytearray(256);p[:8] = b'HRAJJ001'
    accepted = value['accepted_unix_ms'];elapsed = value['elapsed_ms']
    state = ('unknown', 'completed', 'failed').index(value['state'])
    struct.pack_into('<7Q', p, 8, 1, int(elapsed is not None), accepted & ((1 << 64) - 1),
        accepted >> 64, state, elapsed or 0, 0)
    for slot, key in enumerate(('request_id', 'owner', 'tool_name')):
        raw = value[key].encode()
        struct.pack_into('<2Q', p, 64 + slot * 16, len(p), len(raw));p.extend(raw)
    return b'HRAWQ001' + struct.pack('<3Q', operation, int(sync), len(p)) + p


def file(raw=None, mode=0o600):
    return dict(kind='file', mode=mode, data=(encoded(record()) if raw is None else raw).hex())


def link(target):
    return dict(kind='hardlink', target=target)


def row(name, files=None, operations=None, **extra):
    if files is None:files = {}
    if operations is None:operations = [request(), request(), request(record(state='completed', elapsed_ms=2), 2)]
    return dict(name=name, files=files, operations=[raw.hex() for raw in operations], **extra)


def cases():
    for sync in (False, True):
        for state in ('unknown', 'completed', 'failed'):
            for accepted in (0, 1, (1 << 64) - 1, 1 << 64, (1 << 128) - 1):
                for elapsed in (None, 0, 1, (1 << 64) - 1):
                    value = record(state=state, accepted_unix_ms=accepted, elapsed_ms=elapsed)
                    yield row(f'publish-{sync}-{state}-{accepted}-{elapsed}', operations=[
                        request(value, 1, sync), request(dict(value, state='unknown', elapsed_ms=None), 2, sync),
                        request(dict(value, state='failed', elapsed_ms=3), 2, sync), request(value, 1, sync)])
    for key in ('owner', 'tool_name'):
        for index, value in enumerate(('', '"\\/', ''.join(chr(i) for i in range(32)),
                '汉字é\u2028\u2029\U0001f600', '\x00', 'a' * 65, 'A0-._:', '\b\t\n\f\r')):
            new = record(**{key: value})
            yield row(f'arbitrary-typed-{key}-{index}', operations=[request(new), request(new, 2)])
    for index, identifier in enumerate(('', 'x', 'a' * 63, 'a' * 65, 'Z' * 64,
            '.', '..', 'x/y', '汉字', '😀' * 30, 'x' * 124, 'x' * 125, 'x' * 300,
            'a\x00b', '\x00', '../outside', 'x' * 1900)):
        value = record(request_id=identifier)
        yield row('typed-request-id-' + str(index), operations=[request(value), request(value, 2)])
    for count in (2047, 2048, 2049, 4096, 32768):
        empty = record(tool_name='')
        value = record(tool_name='x' * (count - len(encoded(empty))))
        assert len(encoded(value)) == count
        yield row('serialized-size-' + str(count), operations=[request(value), request(value, 2)])
    for mode in (0o700, 0o755, 0o500, 0o777, 0o1700):
        yield row('directory-mode-' + oct(mode), directory_mode=mode)
        yield row('directory-mode-before-size-' + oct(mode), directory_mode=mode,
            operations=[request(record(tool_name='x' * 4096))])
    for mask in (0, 0o077, 0o277, 0o400, 0o600):
        yield row('creation-umask-' + oct(mask), umask=mask)
    for kind in ('file', 'directory', 'fifo', 'socket', 'symlink'):
        value = file() if kind == 'file' else dict(kind=kind, mode=0o600)
        if kind == 'symlink':value['target'] = 'other'
        yield row('existing-target-' + kind, {NAME: value, 'other': file()})
        yield row('existing-stage-' + kind, {STAGE: value, 'other': file()})
        yield row('replace-existing-stage-' + kind, {NAME: file(), STAGE: value, 'other': file()},
            [request(record(state='completed'), 2)] * 3)
    for mode in (0, 0o400, 0o644, 0o700, 0o4600):
        yield row('replace-private-target-' + oct(mode), {NAME: file(mode=mode)}, [request(operation=2)] * 2)
    for field, value in (('owner', 'c' * 64), ('tool_name', 'different'), ('accepted_unix_ms', 2),
            ('accepted_unix_ms', 1 << 64), ('owner', '\x00'), ('tool_name', 'x' * 4096)):
        new = record(**{field: value})
        yield row('replace-binding-' + field + '-' + str(value)[:8].encode().hex(),
            {NAME: file()}, [request(new, 2), request(operation=2)])
    for state in ('unknown', 'completed', 'failed'):
        yield row('replace-old-' + state, {NAME: file(encoded(record(state=state, elapsed_ms=1)))},
            [request(record(state='unknown', elapsed_ms=None), 2), request(record(state='failed'), 2)])
    for name, raw in (('empty', b''), ('invalid-json', b'{'), ('UTF8', b'\xff'),
            ('missing-owner', b'{}'), ('over-size', b' ' * 2049),
            ('wrong-id', encoded(record(request_id='c' * 64))), ('wrong-tool', encoded(record(tool_name='0')))):
        yield row('replace-bad-record-' + name, {NAME: file(raw)}, [request(operation=2)] * 2)
    yield row('replace-random-staging', {NAME: file(), OLD_STAGE: link(NAME)}, [request(operation=2)] * 3)
    yield row('replace-deterministic-staging', {NAME: file(), STAGE: link(NAME)}, [request(operation=2)] * 3)
    yield row('replace-orphan-deterministic-staging', {NAME: file(), STAGE: file(b'orphan')}, [request(operation=2)] * 3)
    yield row('create-existing-deterministic-never-repairs', {NAME: file(), STAGE: link(NAME)})
    yield row('replace-staging-binding-refused', {NAME: file(), STAGE: file(), 'other': link(STAGE)}, [request(operation=2)] * 2)
    valid = request()
    bad = [b'', valid[:287], b'BADMAGIC' + valid[8:]]
    for at, value in ((8, 0), (8, 3), (16, 2), (24, 0), (40, 2), (48, 2),
            (72, 3), (80, 1), (88, 1), (96, 255), (104, (1 << 64) - 1), (144, 1)):
        changed = bytearray(valid);struct.pack_into('<Q', changed, at, value);bad.append(bytes(changed))
    changed = bytearray(valid);changed[288] = 255;bad.append(bytes(changed))
    yield row('invalid-typed-frames-then-valid', operations=bad + [valid])
