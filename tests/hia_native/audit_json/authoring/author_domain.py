"""Deterministic input-domain authoring only; no parser or runtime execution."""
import hashlib
import gzip
import base64
import itertools
import json
from pathlib import Path
import random
import struct

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ('request_id', 'owner', 'tool_name', 'state', 'accepted_unix_ms', 'elapsed_ms')
ANCHOR_FIELDS = ('root_device', 'root_inode', 'archive_device', 'archive_inode')
BASE = dict(zip(FIELDS, ('r', 'o', 'tool', 'unknown', 0, None)))
ANCHOR = dict(zip(ANCHOR_FIELDS, (1, 2, 3, 4)))
ROWS = []


def encoded(value, *, ascii=False):
    return json.dumps(value, ensure_ascii=ascii, separators=(',', ':'), allow_nan=False).encode()


def frame(op, payload):
    return b'HAJRQ001' + struct.pack('<QQ', op, len(payload)) + payload


def add(name, operation, payload, expect, category, *, output=4096, workspace=8192):
    ROWS.append(dict(name=name, wire_hex=frame(operation, payload).hex(),
                     output_capacity=output, workspace_capacity=workspace,
                     expected_admission=expect, category=category))


def records(name, payload, *, owned='success', borrowed=None, category='record'):
    add(name+'-owned', 1, payload, owned, category)
    add(name+'-borrowed', 5, payload, owned if borrowed is None else borrowed, category)


def record_projection(strings=('r', 'o', 'tool'), state=0, accepted=0, elapsed=None):
    raw = bytearray(128)
    raw[:8] = b'HAJPR001'
    for offset, value in ((8, 1), (16, int(elapsed is not None)), (24, accepted & ((1 << 64)-1)),
                          (32, accepted >> 64), (40, state), (48, elapsed or 0)):
        struct.pack_into('<Q', raw, offset, value)
    for index, value in enumerate(strings):
        text = value.encode() if isinstance(value, str) else value
        struct.pack_into('<QQ', raw, 64+index*16, len(raw), len(text))
        raw.extend(text)
    return bytes(raw)


def anchor_projection(values=(1, 2, 3, 4)):
    raw = bytearray(128)
    raw[:8] = b'HAJPR001'
    struct.pack_into('<Q', raw, 8, 2)
    struct.pack_into('<4Q', raw, 64, *values)
    return bytes(raw)


def author():
    for index, order in enumerate(itertools.permutations(FIELDS)):
        records('record-order-'+str(index), encoded({key: BASE[key] for key in order}), category='all-record-field-orders')
    for index, order in enumerate(itertools.permutations(ANCHOR_FIELDS)):
        add('anchor-order-'+str(index), 2, encoded({key: ANCHOR[key] for key in order}), 'success', 'all-anchor-field-orders')
    records('record-sequence', encoded(list(BASE.values())), category='derived-sequence')
    add('anchor-sequence', 2, encoded(list(ANCHOR.values())), 'success', 'derived-sequence')
    for state in ('unknown', 'completed', 'failed'):
        for variant, spelling in [('string', encoded(state)), ('map', b'{'+encoded(state)+b':null}'),
                                  ('escaped', b'"\\u00'+f'{ord(state[0]):02x}'.encode()+state[1:].encode()+b'"')]:
            raw = encoded({**BASE, 'state': 'STATE'}).replace(b'"STATE"', spelling)
            records('enum-'+state+'-'+variant, raw, category='durable-state')
    for index, bad in enumerate((b'0', b'1', b'null', b'true', b'[]', b'{}', b'"Unknown"',
            b'"stored"', b'""', b'{"unknown":0}', b'{"unknown":null,"failed":null}',
            b'{"unknown":null,}', b'{"unknown":[]}', b'{"unknown":{"unknown":null}}')):
        records('enum-invalid-'+str(index), encoded({**BASE, 'state': 'STATE'}).replace(b'"STATE"', bad),
                owned='invalid', category='durable-state-invalid')
    for key in FIELDS:
        value = {name: item for name, item in BASE.items() if name != key}
        records('missing-'+key, encoded(value), owned='success' if key == 'elapsed_ms' else 'invalid', category='field-membership')
        duplicate = encoded(BASE)[:-1]+b','+encoded(key)+b':'+encoded(BASE[key])+b'}'
        records('duplicate-'+key, duplicate, owned='invalid', category='field-membership')
        escaped_key = b'"\\u00'+f'{ord(key[0]):02x}'.encode()+key[1:].encode()+b'"'
        records('escaped-key-'+key, encoded(BASE).replace(encoded(key)+b':', escaped_key+b':'), category='field-membership')
        records('duplicate-escaped-'+key, encoded(BASE)[:-1]+b','+escaped_key+b':'+encoded(BASE[key])+b'}',
                owned='invalid', category='field-membership')
    records('unknown-field', encoded({**BASE, 'extra': 0}), owned='invalid', category='field-membership')
    records('unknown-empty-field', encoded({**BASE, '': 0}), owned='invalid', category='field-membership')
    for key in ANCHOR_FIELDS:
        add('anchor-missing-'+key, 2, encoded({name: value for name, value in ANCHOR.items() if name != key}), 'invalid', 'field-membership')
        add('anchor-duplicate-'+key, 2, encoded(ANCHOR)[:-1]+b','+encoded(key)+b':1}', 'invalid', 'field-membership')
    add('anchor-unknown', 2, encoded({**ANCHOR, 'extra': 0}), 'invalid', 'field-membership')
    for count in range(9):
        if count != 6:
            records('sequence-size-'+str(count), encoded((list(BASE.values())+[None]*3)[:count]),
                    owned='invalid', category='sequence-length')
        if count != 4:
            add('anchor-sequence-size-'+str(count), 2, encoded(([1,2,3,4]+[0]*5)[:count]), 'invalid', 'sequence-length')
    integers = {0, 1, 9, 10, 99, 100, 255, 256}
    for bits in (8, 16, 31, 32, 33, 53, 63, 64, 65, 95, 96, 97, 127, 128):
        integers.update((1 << bits)+delta for delta in (-1, 0, 1))
    rng = random.Random(0x48414A31)
    integers.update(rng.getrandbits(128) for _ in range(48))
    for index, number in enumerate(sorted(integers)):
        accepted = number < (1 << 128)
        records('u128-'+str(index), encoded({**BASE, 'accepted_unix_ms': number}),
                owned='success' if accepted else 'invalid', category='u128-boundary')
        fits = number < (1 << 64)
        records('elapsed-u64-'+str(index), encoded({**BASE, 'elapsed_ms': number}),
                owned='success' if fits else 'invalid', category='u64-boundary')
        add('anchor-u64-'+str(index), 2, encoded({**ANCHOR, 'archive_inode': number}),
            'success' if fits else 'invalid', 'u64-boundary')
        if accepted:
            add('serialize-u128-'+str(index), 3, record_projection(accepted=number), 'success', 'exact-integer-serialization')
        if fits:
            add('serialize-elapsed-'+str(index), 3, record_projection(elapsed=number), 'success', 'exact-integer-serialization')
            add('serialize-anchor-'+str(index), 4, anchor_projection((number, number, number, number)), 'success', 'exact-integer-serialization')
    bad_numbers = (b'-0', b'-1', b'+1', b'01', b'00', b'1.', b'.1', b'1e', b'1e0', b'1E+0', b'0.0',
                   b'1e-0', b'NaN', b'Infinity', b'"1"', b'true', b'false', b'null', b'[]', b'{}',
                   b'1e99999', b'9'*256, b'0x1', b'1_000')
    for index, spelling in enumerate(bad_numbers):
        for key in ('accepted_unix_ms', 'elapsed_ms'):
            value = {**BASE, key: 'NUMBER'}
            records('number-grammar-'+key+'-'+str(index), encoded(value).replace(b'"NUMBER"', spelling),
                    owned='success' if key == 'elapsed_ms' and spelling == b'null' else 'invalid', category='number-grammar')
    strings = [chr(value) for value in range(128)] + ['é', '中文', 'é\u0301', '😀', '\u007f', '\u0080', '\u07ff',
        '\u0800', '\ud7ff', '\ue000', '\uffff', '\U00010000', '\U0010ffff', '\u2028\u2029', 'a/b', 'a\\b', 'a"b', '', 'r'*1024]
    for index, value in enumerate(strings):
        body = {**BASE, 'request_id': value, 'owner': value, 'tool_name': value}
        for form, ascii in [('utf8', False), ('ascii', True)]:
            raw = encoded(body, ascii=ascii)
            if len(raw) <= 2048:
                data = encoded(value, ascii=ascii)
                records('string-'+str(index)+'-'+form, raw,
                        borrowed='invalid' if b'\\' in data else 'success', category='unicode-strings')
        add('serialize-string-'+str(index), 3, record_projection((value, value, value)),
            'success', 'string-serialization', output=max(4096, len(encoded(body))+32))
    escapes = (b'"\\u0000"', b'"\\/"', b'"\\ud800\\udc00"', b'"\\uD83D\\uDE00"', b'"\\u0061"', b'"\\t\\b\\f\\r\\n"')
    for index, value in enumerate(escapes):
        records('explicit-escape-'+str(index), encoded({**BASE, 'request_id': 'TEXT'}).replace(b'"TEXT"', value),
                borrowed='invalid', category='escape-decoding')
    bad_texts = (b'"\\ud800"', b'"\\udc00"', b'"\\ud800\\u0061"', b'"\\u0"', b'"\\x41"', b'"\\q"',
        b'"\x00"', b'"\n"', b'"\x80"', b'"\xc0\xaf"', b'"\xed\xa0\x80"', b'"\xf4\x90\x80\x80"',
        b'"\xf0\x80\x80\x80"', b'"\xef\xbf"', b'"\xc2"', b'"\xff"', b'null', b'0', b'[]', b'{}')
    for index, value in enumerate(bad_texts):
        records('invalid-string-'+str(index), encoded({**BASE, 'owner': 'TEXT'}).replace(b'"TEXT"', value),
                owned='invalid', category='invalid-unicode-or-type')
    for index, raw in enumerate((b'', b' ', b'null', b'true', b'false', b'1', b'"x"', b'{}', b'[]', b'{', b'[',
                                b'\xef\xbb\xbf'+encoded(BASE), encoded(BASE)+b'null', encoded(BASE)+b'0',
                                encoded(BASE)[:-1]+b',}', b'{"request_id" "r"}')):
        records('root-invalid-'+str(index), raw, owned='invalid', category='json-grammar')
    for index, space in enumerate((b' ', b'\t', b'\r', b'\n', b'\t\r\n ')):
        records('whitespace-'+str(index), space+encoded(BASE).replace(b':', b':'+space).replace(b',', b','+space)+space,
                category='json-whitespace')
    for index, space in enumerate((b'\v', b'\f', b'\x00', b'\xc2\xa0')):
        records('whitespace-invalid-'+str(index), space+encoded(BASE), owned='invalid', category='json-whitespace')
    full = encoded(BASE)
    for count in range(len(full)):
        records('truncated-'+str(count), full[:count], owned='invalid', category='truncation')
    for size in (2047, 2048, 2049):
        payload = full+b' '*(size-len(full))
        records('bounded-input-'+str(size), payload, owned='success' if size <= 2048 else 'invalid', category='storage-read-bound')
    for state in range(3):
        for elapsed in (None, 0, (1 << 64)-1):
            add('serialize-state-'+str(state)+'-'+str(elapsed), 3,
                record_projection(state=state, accepted=(1 << 128)-1, elapsed=elapsed), 'success', 'declaration-order')
    add('serialize-larger-than-storage-bound', 3, record_projection(('a'*5000, '\x00'*700, '😀'*1000)),
        'success', 'caller-size-policy', output=20000)
    canonical = record_projection()
    for index, (offset, value) in enumerate(((0, 0), (8, 2), (16, 2), (40, 3), (48, 1), (56, 1),
            (64, 0), (72, (1 << 64)-1), (80, 128), (88, (1 << 64)-1), (96, 128), (104, (1 << 64)-1),
            (112, 1), (120, 1))):
        raw = bytearray(canonical); struct.pack_into('<Q', raw, offset, value)
        add('projection-invalid-'+str(index), 3, bytes(raw), 'invalid', 'canonical-projection')
    for index, raw in enumerate((canonical+b'x', canonical[:127], canonical[:-1], b'',
                                record_projection((b'\xff', b'o', b'tool')),
                                record_projection((b'\xc2', b'\xa0', b'tool')))):
        add('projection-invalid-tail-'+str(index), 3, raw, 'invalid', 'canonical-projection')
    for offset in (0, 8, 16, 24, 32, 40, 48, 56, 96, 104, 112, 120):
        raw = bytearray(anchor_projection()); struct.pack_into('<Q', raw, offset, 3)
        add('anchor-projection-invalid-'+str(offset), 4, bytes(raw), 'invalid', 'canonical-projection')
    valid_examples = [(1, full, 134), (2, encoded(ANCHOR), 128), (5, full, 134),
                      (3, canonical, len(full)), (4, anchor_projection(), len(encoded(ANCHOR)))]
    for op, payload, result_size in valid_examples:
        for capacity in sorted({0, 1, 127, result_size-1, result_size, result_size+1, 4096}):
            add(f'capacity-{op}-{capacity}', op, payload, 'capacity' if capacity < result_size else 'success',
                'output-capacity', output=capacity)
        for workspace in (0, 1, 511, 8191, 8192, 8193):
            add(f'workspace-{op}-{workspace}', op, payload, 'capacity' if workspace < 8192 else 'success',
                'workspace-capacity', workspace=workspace)
    for size in range(24):
        ROWS.append(dict(name='frame-short-'+str(size), wire_hex=frame(1,full)[:size].hex(),
            output_capacity=128, workspace_capacity=0, expected_admission='invalid', category='frame-admission'))
    for index, (offset, value) in enumerate(((0, 0), (8, 0), (8, 6), (8, (1 << 64)-1), (16, 0), (16, len(full)+1))):
        raw = bytearray(frame(1, full)); struct.pack_into('<Q', raw, offset, value)
        ROWS.append(dict(name='frame-invalid-'+str(index), wire_hex=raw.hex(), output_capacity=128,
            workspace_capacity=0, expected_admission='invalid', category='frame-admission'))
    assert len({row['name'] for row in ROWS}) == len(ROWS)
    cases = b''.join((json.dumps(row, sort_keys=True, separators=(',', ':'))+'\n').encode() for row in ROWS)
    compressed = gzip.compress(cases, mtime=0)
    assert gzip.decompress(compressed) == cases
    (ROOT/'CASES.jsonl.gz.b64').write_bytes(base64.b64encode(compressed))
    by_category = {}
    by_admission = {}
    for row in ROWS:
        by_category[row['category']] = by_category.get(row['category'], 0)+1
        by_admission[row['expected_admission']] = by_admission.get(row['expected_admission'], 0)+1
    domain = dict(schema='hepta.audit-json.domain.v1', target_commit='d3d75c30719db966b004756f610007a7c723729e',
        cases=dict(file='CASES.jsonl.gz.b64', bytes=len(cases), sha256=hashlib.sha256(cases).hexdigest(), count=len(ROWS),
                   compressed_bytes=len(compressed), compressed_sha256=hashlib.sha256(compressed).hexdigest()),
        categories=by_category, admissions=by_admission, output_fill=105, workspace_fill=167,
        source_guard=195, output_guard=165, workspace_guard=90, guard_bytes=16,
        process_budgets=dict(format=60, toolchain=60, original=60, native=60,
                             readonly_semantic=180, reader_controls=180, readonly_complete=180),
        rust_profile=dict(toolchain='1.95.0', edition='2021', opt_level=1, debuginfo=2,
                          debug_assertions=True, overflow_checks=True, codegen_units=256,
                          lto=False, panic='unwind'),
        source_authoring_only=True, expected_outputs_generated=False,
        private_typed_codec=True, public_handler_qualified=False, whole_runtime_replaced=False)
    domain['process_budgets'].update({'cargo-version':60,'native-build':900,'rust-fetch':60,'rust-vendor':60,'rust-build':900})
    (ROOT/'DOMAIN.json').write_text(json.dumps(domain, sort_keys=True, indent=2)+'\n')
    print(json.dumps(dict(cases=len(ROWS), bytes=len(cases), categories=by_category, admissions=by_admission), sort_keys=True))


if __name__ == '__main__':
    author()
