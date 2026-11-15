"""Owned real-file audit read and interrupted publication fixtures."""
import json
import struct

ID = 'a' * 64
OWNER = 'b' * 64
NONCE = 'c' * 64
NAME = ID + '.json'
STAGE = '.' + ID + '-' + ID + '.tmp'
OLD_STAGE = '.' + ID + '-' + NONCE + '.tmp'


def record(**overrides):
    value = dict(request_id=ID, owner=OWNER, tool_name='h_file_read', state='unknown',
        accepted_unix_ms=1, elapsed_ms=None)
    value.update(overrides)
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def request(operation=1, filename=NAME):
    raw = filename.encode() if isinstance(filename, str) else filename
    return b'HRARQ001' + struct.pack('<QQ', operation, len(raw)) + raw


def file(raw=None, mode=0o600):
    return dict(kind='file', mode=mode, data=(record() if raw is None else raw).hex())


def link(target):
    return dict(kind='hardlink', target=target)


def row(name, files, operations=None, **extra):
    if operations is None:operations = [request()] * 3
    return dict(name=name, files=files, operations=[value.hex() for value in operations], **extra)


def cases():
    yield row('record-missing', {})
    for state in ('unknown', 'completed', 'failed'):
        for elapsed in (None, 0, 1, (1 << 64) - 1):
            for accepted in (0, 1, (1 << 64) - 1, 1 << 64, (1 << 128) - 1):
                yield row(f'record-{state}-{elapsed}-{accepted}', {NAME: file(record(
                    state=state, elapsed_ms=elapsed, accepted_unix_ms=accepted))})
    valid = record()
    shapes = {
        'exact-limit': valid + b' ' * (2048 - len(valid)),
        'over-limit': valid + b' ' * (2049 - len(valid)),
        'empty': b'', 'malformed': b'{', 'null': b'null', 'utf8': b'\xff',
        'trailing-object': valid + b'{}',
        'unknown-field': valid[:-1] + b',"extra":null}',
        'duplicate-field': valid[:-1] + b',"owner":"' + OWNER.encode() + b'"}',
        'missing-elapsed': valid.replace(b',"elapsed_ms":null', b''),
        'tagged-state': valid.replace(b'"state":"unknown"', b'"state":{"unknown":null}'),
        'sequence': json.dumps([ID, OWNER, 'h_file_read', 'unknown', 1, None]).encode(),
        'sequence-missing': json.dumps([ID, OWNER, 'h_file_read', 'unknown', 1]).encode(),
        'escaped-identifiers': valid.replace(b'"' + ID.encode() + b'"', b'"' + b'\\u0061' * 64 + b'"'),
    }
    for name, raw in shapes.items():yield row('json-' + name, {NAME: file(raw)})
    for field in ('request_id', 'owner'):
        for value in ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, '0' * 64, 'c' * 64,
                '\x00' * 64, '汉字'):
            yield row('identity-' + field + '-' + str(len(value)) + '-' + value[:1].encode().hex(),
                {NAME: file(record(**{field: value}))})
    for index, tool in enumerate(('', '_', 'a', '_' * 64, 'a' * 65, 'A', 'a0', 'a-b', 'a.b',
            'a b', 'a\n', '\x00', '汉字', 'é', 'a_b')):
        yield row('tool-' + str(index), {NAME: file(record(tool_name=tool))})
    for kind in ('directory', 'fifo', 'socket', 'symlink'):
        spec = dict(kind=kind, mode=0o600)
        if kind == 'symlink':spec['target'] = 'other'
        yield row('published-' + kind, {NAME: spec, 'other': file()})
        yield row('deterministic-' + kind, {NAME: file(), STAGE: spec, 'other': file()})
        yield row('cleanup-' + kind, {OLD_STAGE: spec, 'other': file()}, [request(2, OLD_STAGE)] * 2)
    for mode in (0, 0o400, 0o644, 0o601, 0o700, 0o4600, 0o1600):
        yield row('published-mode-' + oct(mode), {NAME: file(mode=mode)})
        yield row('stage-mode-' + oct(mode), {NAME: file(), STAGE: file(mode=mode)})
    for mode in (0o700, 0o755, 0o777, 0o500):
        yield row('held-directory-mode-' + oct(mode), {NAME: file()}, directory_mode=mode)
    yield row('deterministic-unpublished', {STAGE: file()})
    yield row('deterministic-discard-before-read', {NAME: file(), STAGE: file(b'not-json')})
    yield row('deterministic-linked', {STAGE: file(), NAME: link(STAGE)})
    yield row('random-linked', {OLD_STAGE: file(), NAME: link(OLD_STAGE)})
    yield row('random-linked-published-first', {NAME: file(), OLD_STAGE: link(NAME)})
    yield row('random-no-match', {NAME: file(), 'extra': link(NAME)})
    yield row('published-three-links', {NAME: file(), OLD_STAGE: link(NAME), 'extra': link(NAME)})
    yield row('deterministic-three-links', {NAME: file(), STAGE: link(NAME), 'extra': link(NAME)})
    yield row('staging-binding-mismatch', {NAME: file(), 'other': file(), STAGE: link('other')})
    yield row('staging-published-missing', {STAGE: file(), 'extra': link(STAGE)})
    yield row('random-stage-private-refusal', {NAME: file(mode=0o644), OLD_STAGE: link(NAME)})
    yield row('unrelated-invalid-utf8-scan', {NAME: file(), 'extra': link(NAME), '\udcff': file()})
    yield row('unrelated-invalid-utf8-no-scan', {NAME: file(), '\udcff': file()})
    yield row('unrelated-random-stage-ignored', {NAME: file(), OLD_STAGE: file()})
    yield row('scan-matching-malformed-nonce', {NAME: file(), 'extra': link(NAME), '.' + ID + '-bad.tmp': file()})
    yield row('scan-other-staging-ignored', {NAME: file(), 'extra': link(NAME), '.' + OWNER + '-bad.tmp': file()})
    yield row('scan-clean-one-then-validate', {NAME: file(), OLD_STAGE: link(NAME), '.' + ID + '-' + OWNER + '.tmp': file()})
    yield row('cleanup-missing', {}, [request(2, OLD_STAGE)] * 2)
    for data in (b'', b'garbage', record(), b'x' * 2048, b'x' * 2049):
        yield row('cleanup-bytes-' + str(len(data)), {OLD_STAGE: file(data)}, [request(2, OLD_STAGE)] * 2)
    yield row('cleanup-linked', {NAME: file(), OLD_STAGE: link(NAME)}, [request(2, OLD_STAGE), request()])
    for index, name in enumerate(('', 'a', ID, NAME + '.json', NAME.upper(), '../' + NAME,
            '\x00' + NAME, 'a' * 1048552, '汉字.json', ID + '.JSON')):
        yield row('bad-read-name-' + str(index), {NAME: file()}, [request(1, name)])
    for index, name in enumerate(('', OLD_STAGE[1:], OLD_STAGE[:-1], OLD_STAGE.upper(),
            '.' + ID + '-bad.tmp', '.' + ID + '-' + NONCE + '-x.tmp', '../' + OLD_STAGE,
            '.' + ID + '-' + '\x00' * 64 + '.tmp')):
        yield row('bad-clean-name-' + str(index), {NAME: file(), OLD_STAGE: file()}, [request(2, name)])
    bad = [b'', b'HRARQ001', request(0), request(3), request(1, b'\xff'),
        b'BADMAGIC' + request()[8:], b'HRARQ001' + struct.pack('<QQ', 1, 0) + NAME.encode()]
    yield row('invalid-wire-then-valid', {NAME: file()}, bad + [request()])
    many = {f'unrelated-{index:04d}': file(b'') for index in range(1800)}
    many[NAME] = file();many[OLD_STAGE] = link(NAME)
    yield row('multiple-getdents-pages', many, [request()] * 2)
