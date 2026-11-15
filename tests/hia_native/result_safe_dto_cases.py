# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Admitted typed DTO cases; original Rust produces every canonical input."""
import copy
import json
import math
import random
import struct

ID = 'io.hepta.runtime/request-v8'
MEASUREMENT = 'SSH invocation roundtrip including connection setup or reuse, authentication, remote shell startup and fixed response; not ICMP RTT.'


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def host(target, platform='linux'):
    return dict(ssh_target=target, platform=platform, remote_state_dir='/remote',
        allow_execute=False, allow_write=False, allow_pty=False)


def profiles():
    yield 'uninstalled', None
    yield 'empty', {}
    yield 'mixed', {'a': host('b'), 'b': host('shared-target', 'macos'), 'c': host('shared-target')}
    for count in (256, 257):
        yield 'hosts-' + str(count), {f'h{i:04d}': host('target-' + str(i), 'macos' if i & 1 else 'linux') for i in range(count)}


def body(text):
    return dict(content=[dict(type='text', text=text)], _meta={ID: dict(request_id='a1' * 32, automatic_retry=False, delivery_proven=False)})


def case(label, tool, value):
    return dict(op='dto', label=label, tool=tool, body=copy.deepcopy(value))


def health(alias='a', platform='linux', status='healthy', elapsed=1.0):
    return dict(schema='hepta-host-health-v1', host=alias, platform=platform, transport='ssh', status=status,
        reachable=status == 'healthy', authenticated=status == 'healthy', ssh_roundtrip_ms=elapsed,
        timeout_ms=10000, measurement=MEASUREMENT, diagnostics_redacted=True)


def cases(summaries, hosts):
    for tool in ('host_list', 'effective_config'):
        summary = summaries[tool]
        value = json.loads(summary['text']) if summary['status'] == 0 else ({'hosts': []} if tool == 'host_list' else {})
        good = body(encoded(value))
        yield case('summary-canonical-' + tool, tool, good)
        yield case('summary-whitespace-' + tool, tool, body(' \n' + json.dumps(value, ensure_ascii=True, indent=2) + '\t'))
        for error in (None, False, True):
            row = copy.deepcopy(good);row['isError'] = error
            yield case('is-error-' + repr(error), tool, row)
        for result_type in (None, 'complete'):
            row = copy.deepcopy(good);row['resultType'] = result_type
            yield case('result-type-' + repr(result_type), tool, row)
        for structured in (None, False, 0, '', [], {}):
            row = copy.deepcopy(good);row['structuredContent'] = structured
            yield case('structured-present', tool, row)
        for metadata in (None, {}, {'other': 1}, {ID: None}, {ID: False}, {ID: []}, {ID: {}}, {ID: good['_meta'][ID], 'extra': 1}):
            row = copy.deepcopy(good);row['_meta'] = metadata
            yield case('metadata-shape', tool, row)
        for identity in ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, '0' * 64, 'abcdef0123456789' * 4, '汉' * 64, None, False, 0, [], {}):
            row = copy.deepcopy(good);row['_meta'][ID]['request_id'] = identity
            yield case('request-identity', tool, row)
        for key in ('request_id', 'automatic_retry', 'delivery_proven'):
            row = copy.deepcopy(good);del row['_meta'][ID][key]
            yield case('missing-marker-' + key, tool, row)
        for key in ('automatic_retry', 'delivery_proven'):
            for item in (None, 0, '', [], {}, True):
                row = copy.deepcopy(good);row['_meta'][ID][key] = item
                yield case('marker-flag-type', tool, row)
        row = copy.deepcopy(good);row['_meta'][ID]['original_metadata'] = None
        yield case('marker-collision', tool, row)
        for content in ([], good['content'] * 2, [dict(type='image', data='AA==', mimeType='image/png')],
                [dict(type='audio', data='AA==', mimeType='audio/wav')],
                [dict(type='resource', resource=dict(uri='urn:x', text='{}'))],
                [dict(type='resource_link', uri='urn:x', name='x')]):
            row = copy.deepcopy(good);row['content'] = content
            yield case('content-shape', tool, row)
        for field, item in (('annotations', {}), ('annotations', None), ('annotations', {'priority': 0.1}),
                ('annotations', {'audience': []}), ('_meta', {}), ('_meta', None), ('unused-field', 1)):
            row = copy.deepcopy(good);row['content'][0][field] = item
            yield case('content-extra-typed-' + field, tool, row)
        for text in ('', '{', '[', 'null', 'true', '0', '"text"', '[]', '{}', '{"hosts":null}',
                '[' * 127 + '0' + ']' * 127, '[' * 128 + '0' + ']' * 128, '\ufeff{}', '{} trailing'):
            yield case('inner-parse-or-shape', tool, body(text))
        modified = copy.deepcopy(value);modified['extra'] = None
        yield case('summary-extra-root', tool, body(encoded(modified)))
        for key in value:
            modified = copy.deepcopy(value);del modified[key]
            yield case('summary-missing-' + key, tool, body(encoded(modified)))
        if value.get('hosts'):
            for field in ('extra', 'platform'):
                modified = copy.deepcopy(value);modified['hosts'][0][field] = 'changed'
                yield case('summary-host-field-' + field, tool, body(encoded(modified)))
        text = encoded(value)
        if '"hosts":' in text:
            yield case('escaped-inner-key', tool, body(text.replace('"hosts":', '"\\u0068osts":', 1)))
            yield case('duplicate-inner-key-last-expected', tool, body('{"hosts":null,' + text[1:]))
            yield case('duplicate-inner-key-last-wrong', tool, body(text[:-1] + ',"hosts":null}'))
        for wrong_tool in ('host_list ', 'HOST_LIST', '', 'unknown', 'host_list\0', '主机'):
            yield case('unknown-tool', wrong_tool, good)
    configured = list((hosts or {}).items())
    aliases = configured[:2] + ([configured[-1]] if len(configured) > 2 else [])
    aliases += [('missing', host('target')), ('shared-target', host('target'))]
    elapsed = [0, -0.0, 1, 1.0, 1e-300, 5e-324, -5e-324, -1, 59999, 60000, 60000.0,
        math.nextafter(60000.0, 0.0), math.nextafter(60000.0, math.inf), 60001, 1e308,
        18446744073709551615, '0', None, False, [], {}]
    statuses = ('healthy', 'ssh_failed', 'invalid_response', 'transport_error', 'timeout')
    for alias, config in aliases:
        for status in statuses:
            for value in elapsed:
                yield case('health-range-' + alias + '-' + status, 'host_health', body(encoded(health(alias, config['platform'], status, value))))
    alias, config = aliases[0]
    valid = health(alias, config['platform'])
    for key in valid:
        missing = copy.deepcopy(valid);del missing[key]
        yield case('health-missing-' + key, 'host_health', body(encoded(missing)))
        for value in (None, False, True, 0, 10000.0, '', [], {}, 'changed'):
            changed = copy.deepcopy(valid);changed[key] = value
            yield case('health-changed-' + key, 'host_health', body(encoded(changed)))
    extra = copy.deepcopy(valid);extra['extra'] = 1
    yield case('health-extra', 'host_health', body(encoded(extra)))
    for numeric in ('-0', '-0e300', '6e4', '6.00000000000000000001e4', '59999.9999999999999999',
            '60000.0000000000000001', '0e999999', '1e999', '-1e999', '1e-999', '-1e-999'):
        text = encoded(valid).replace('"ssh_roundtrip_ms":1.0', '"ssh_roundtrip_ms":' + numeric)
        yield case('health-lexical-number-' + numeric, 'host_health', body(text))
    rng = random.Random(0x53414645)
    for index in range(512):
        number = struct.unpack('<d', struct.pack('<Q', rng.getrandbits(64)))[0]
        if not math.isfinite(number):
            continue
        value = health(alias, config['platform'], statuses[index % len(statuses)], number)
        yield case('health-random-f64-' + str(index), 'host_health', body(encoded(value)))
