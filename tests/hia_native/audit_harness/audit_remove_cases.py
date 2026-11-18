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


def request(value=None, sync=True):
    if value is None:value = record()
    p = bytearray(256);p[:8] = b'HRAJJ001'
    accepted = value['accepted_unix_ms'];elapsed = value['elapsed_ms']
    state = ('unknown', 'completed', 'failed').index(value['state'])
    struct.pack_into('<7Q', p, 8, 1, int(elapsed is not None), accepted & ((1 << 64) - 1),
        accepted >> 64, state, elapsed or 0, 0)
    for slot, key in enumerate(('request_id', 'owner', 'tool_name')):
        raw = value[key].encode()
        struct.pack_into('<2Q', p, 64 + slot * 16, len(p), len(raw));p.extend(raw)
    return b'HRAXQ001' + struct.pack('<2Q', int(sync), len(p)) + p


def file(raw=None, mode=0o600):
    return dict(kind='file', mode=mode, data=(encoded(record()) if raw is None else raw).hex())


def link(target):
    return dict(kind='hardlink', target=target)


def row(name, files=None, operations=None, **extra):
    if files is None:files = {NAME: file()}
    if operations is None:operations = [request(), request()]
    return dict(name=name, files=files, operations=[raw.hex() for raw in operations], **extra)


def cases():
    for sync in (False, True):
        for state in ('unknown', 'completed', 'failed'):
            for accepted in (0, 1, (1 << 64) - 1, 1 << 64, (1 << 128) - 1):
                for elapsed in (None, 0, 1, (1 << 64) - 1):
                    value = record(state=state, accepted_unix_ms=accepted, elapsed_ms=elapsed)
                    yield row(f'remove-{sync}-{state}-{accepted}-{elapsed}',
                        {NAME: file(encoded(value))}, [request(value, sync), request(value, sync)])
    mismatches = [('owner', 'c' * 64), ('owner', ''), ('owner', '汉字'), ('owner', '\x00'),
        ('tool_name', 'h_file_write'), ('tool_name', ''), ('tool_name', '\x00'),
        ('tool_name', 'x' * 4096), ('tool_name', 'x' * 32768),
        ('accepted_unix_ms', 0), ('accepted_unix_ms', 1 << 64),
        ('accepted_unix_ms', (1 << 128) - 1), ('state', 'completed'), ('state', 'failed'),
        ('elapsed_ms', 0), ('elapsed_ms', 1), ('elapsed_ms', (1 << 64) - 1)]
    for index, (field, value) in enumerate(mismatches):
        yield row('full-binding-' + str(index), operations=[request(record(**{field: value})), request(), request()])
    for old_state in ('unknown', 'completed', 'failed'):
        for new_state in ('unknown', 'completed', 'failed'):
            value = record(state=old_state, elapsed_ms=0)
            yield row('state-binding-' + old_state + '-' + new_state, {NAME: file(encoded(value))},
                [request(dict(value, state=new_state)), request(value)])
    for old_elapsed in (None, 0, (1 << 64) - 1):
        for new_elapsed in (None, 0, (1 << 64) - 1):
            value = record(elapsed_ms=old_elapsed)
            yield row(f'elapsed-option-binding-{old_elapsed}-{new_elapsed}', {NAME: file(encoded(value))},
                [request(dict(value, elapsed_ms=new_elapsed)), request(value)])
    for index, identifier in enumerate(('', 'x', 'a' * 63, 'a' * 65, 'Z' * 64,
            '.', '..', 'x/y', '汉字', '😀' * 30, 'x' * 300, 'a\x00b', '\x00', '../outside', 'c' * 64)):
        yield row('expected-id-' + str(index), operations=[request(record(request_id=identifier)), request()])
    for mode in (0o700, 0o755, 0o500, 0o777, 0o1700):
        for sync in (False, True):
            yield row(f'directory-mode-{mode}-{sync}', operations=[request(sync=sync)] * 2, directory_mode=mode)
    for mode in (0, 0o400, 0o644, 0o700, 0o4600):
        yield row('private-file-' + oct(mode), {NAME: file(mode=mode)})
    for kind in ('directory', 'fifo', 'socket', 'symlink'):
        value = dict(kind=kind, mode=0o600)
        if kind == 'symlink':value['target'] = 'other'
        yield row('record-kind-' + kind, {NAME: value, 'other': file()})
        yield row('stage-kind-' + kind, {NAME: file(), STAGE: value, 'other': file()})
    for label, raw in (('empty', b''), ('invalid-json', b'{'), ('UTF8', b'\xff'),
            ('missing-owner', b'{}'), ('over-size', b' ' * 2049),
            ('wrong-id', encoded(record(request_id='c' * 64))), ('wrong-tool', encoded(record(tool_name='0')))):
        yield row('bad-record-' + label, {NAME: file(raw)})
    yield row('missing-record', {})
    yield row('unbound-hardlink', {NAME: file(), 'other': link(NAME)})
    yield row('deterministic-linked-stage', {NAME: file(), STAGE: link(NAME)})
    yield row('random-linked-stage', {NAME: file(), OLD_STAGE: link(NAME)})
    yield row('orphan-deterministic-stage', {NAME: file(), STAGE: file(b'interrupted')})
    yield row('missing-record-with-orphan-stage', {STAGE: file(b'interrupted')})
    yield row('staging-hardlink-binding-refused', {NAME: file(), STAGE: file(), 'other': link(STAGE)})
    valid = request()
    bad = [b'', valid[:279], b'BADMAGIC' + valid[8:]]
    for at, value in ((8, 2), (16, 0), (32, 2), (40, 2), (64, 3), (72, 1),
            (80, 1), (88, 255), (96, (1 << 64) - 1), (136, 1)):
        changed = bytearray(valid);struct.pack_into('<Q', changed, at, value);bad.append(bytes(changed))
    changed = bytearray(valid);changed[280] = 255;bad.append(bytes(changed))
    yield row('invalid-typed-frames-then-valid', operations=bad + [valid])

