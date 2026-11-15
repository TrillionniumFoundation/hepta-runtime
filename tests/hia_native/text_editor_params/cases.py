"""Inputs only for the typed Text Editor field and enum projection."""
import itertools
import json
import random

RAW = '$serde_json::private::RawValue'
COMMANDS = ('create', 'str_replace', 'delete', 'undo_edit')
FIELDS = ('command', 'path', 'content', 'old_text', 'new_text', 'replace_all')

def cases():
    records = []
    def add(name, value=None, raw=None):
        records.append({'case_id': len(records) + 1, 'name': name,
                        'raw_json': raw if raw is not None else json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))})
    base = {'command': 'create', 'path': 'p', 'content': 'text'}
    strings = ['', 'p', 'a/b', 'line\n\t\u0000end', '中文/é/😀', '\\"\r\n']
    values = [None, False, True, 0, -1, 9223372036854775807, 18446744073709551615,
              1.5, -0.0, 1e-9, 1e20, 1e30, '', 'x', '\n\t\u0000', '中文😀',
              [], [None], ['x'], {}, {'x': None}, {'a': 1, 'b': 2}]
    for command, path in itertools.product(COMMANDS, strings):
        for enum in (command, {command: None}):
            add('valid-enum-path', {'command': enum, 'path': path})
            add('valid-all-fields', {'command': enum, 'path': path, 'content': path,
                                    'old_text': '', 'new_text': path, 'replace_all': False})
    add('empty-object', {})
    for field in FIELDS:
        row = dict(base); row.pop(field, None); add('missing-' + field, row)
        for n, value in enumerate(values):
            row = dict(base); row[field] = value; add(f'field-{field}-{n}', row)
    for command in COMMANDS:
        for value in values:
            add('unit-map-value', {'command': {command: value}, 'path': 'p'})
            add('multiple-enum-keys', {'command': {command: value, 'unknown': None}, 'path': 'p'})
    names = ['', 'Create', 'STR_REPLACE', 'undo', 'delete_file', '\n', '\x00', '`', '\\', '中文😀',
             ''.join(chr(i) for i in [0, 9, 10, 31, 34, 92, 127, 133, 0x2028, 0x2029, 0x2060, 0x3000, 0x10ffff])]
    for name in names:
        add('unknown-string-enum', {'command': name, 'path': 'p'})
        add('unknown-map-enum', {'command': {name: None}, 'path': 'p'})
    for first, second in itertools.combinations(FIELDS, 2):
        for x, y in itertools.product((None, 1, [], {}), repeat=2):
            row = dict(base); row[first] = x; row[second] = y; add('error-order', row)
    rng = random.Random(678031092)
    for number in range(1200):
        row = {}
        for field in rng.sample(list(FIELDS), len(FIELDS)):
            if rng.randrange(5):
                if field == 'command' and rng.randrange(3):
                    row[field] = rng.choice(COMMANDS)
                else:
                    row[field] = rng.choice(values)
        if number % 7 == 0: row['ignored'] = {'nested': [None, 'x', {'a': False}]}
        add('mixed-fields', row)
    for field in FIELDS:
        for text in ('"create"', '"p"', 'null', 'true', '[]', '{}', '"\\n\\u0000"', '1', ''):
            row = dict(base); row[field] = {RAW: text}; add('raw-first-key', row)
            row = dict(base); row[field] = {'z': 0, RAW: text}; add('raw-later-key', row)
    add('root-raw-key-remains-map', {RAW: '{', **base})
    add('ignored-raw-success', {**base, 'ignored': {RAW: '{"deep":true}'}})
    add('ignored-raw-refusal', {**base, 'ignored': {RAW: '{'}})
    for field in ('path', 'content', 'old_text', 'new_text'):
        row = dict(base); row[field] = 'a\u0000中文😀' * 16384; add('wide-string-' + field, row)
    add('wide-error-debug', {**base, 'replace_all': '界\n\u0000' * 16384})
    add('over-two-mib-content', {**base, 'content': 'c' * ((2 << 20) + 17)})
    add('surrogate-refused', raw='{"command":"create","path":"\\ud800"}')
    add('raw-number-refused', raw='{"command":"create","path":"p","ignored":1e400}')
    return records

def encoded():
    return b''.join((json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n').encode() for row in cases())
