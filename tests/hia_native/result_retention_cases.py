# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pure retained Record cases; original Rust supplies canonical typed inputs."""
import copy
import random
from result_safe_dto_cases import ID, body, cases as dto_cases, encoded, health

TOOLS = ('host_list', 'host_health', 'effective_config')
REQUEST = 'a1' * 32
OWNER = 'b2' * 32
POLICY = 'c3' * 32


def transition(label, tool, value, operation=2, accepted=1 << 64,
               request_id=REQUEST, owner=OWNER, policy_binding=POLICY):
    return dict(op='transition', label=label, tool=tool, body=copy.deepcopy(value),
        operation=operation, accepted=str(accepted), request_id=request_id,
        owner=owner, policy_binding=policy_binding)


def sample(tool, summaries, hosts):
    if tool == 'host_health':
        alias, config = next(iter((hosts or {'missing': {'platform': 'linux'}}).items()))
        return body(encoded(health(alias, config['platform'])))
    row = summaries[tool]
    return body(row['text'] if row['status'] == 0 else ('{"hosts":[]}' if tool == 'host_list' else '{}'))


def size_probes():
    for i, priority in enumerate((None, 0.1, 0.33333334, 1e-20, 1.4e-45, -0.0)):
        value = body('x')
        if priority is not None:
            value['content'][0]['annotations'] = dict(priority=priority)
        yield transition('size-probe-' + str(i), 'host_list', value)


def cases(profile, summaries, hosts, measured):
    for row in dto_cases(summaries, hosts):
        if row['tool'] in TOOLS:
            yield transition('dto-' + row['label'], row['tool'], row['body'])
    times = [0, 1, 9, 10, 99, 100]
    for bit in (32, 64, 96, 127):
        times.extend(((1 << bit) - 1, 1 << bit, (1 << bit) + 1))
    times.append((1 << 128) - 1)
    for tool in TOOLS:
        good = sample(tool, summaries, hosts)
        for timestamp in times:
            yield transition('admitted-time-' + str(timestamp), tool, None, 1, timestamp)
            yield transition('not-completed-time-' + str(timestamp), tool, None, 2, timestamp)
            yield transition('completed-time-' + str(timestamp), tool, good, 2, timestamp)
        yield transition('mismatched-request', tool, good, request_id='de' * 32)
        yield transition('distinct-owner-and-policy', tool, good, owner='0' * 64, policy_binding='f' * 64)
    if profile == 'mixed':
        rng = random.Random(0x5245434F5244)
        for index in range(512):
            tool = TOOLS[index % len(TOOLS)]
            identity = f'{rng.getrandbits(256):064x}'
            value = sample(tool, summaries, hosts)
            value['_meta'][ID]['request_id'] = identity
            yield transition('random-u128-and-binding-' + str(index), tool, value,
                accepted=rng.getrandbits(128), request_id=identity,
                owner=f'{rng.getrandbits(256):064x}', policy_binding=f'{rng.getrandbits(256):064x}')
        for size in (64000, 65100, 65200, 65300, 65400, 65500, 65535, 65536, 65537, 66000, 1 << 20):
            yield transition('wide-result-' + str(size), 'host_list', body('x' * size))
        empty = body('')
        empty['isError'] = False
        size = (8 << 20) - len(encoded(empty).encode())
        exact = body('x' * size)
        exact['isError'] = False
        yield transition('canonical-body-exactly-8MiB', 'host_list', exact)
        for probe, original in zip(size_probes(), measured, strict=True):
            for field in ('typed_bytes', 'preview_bytes'):
                for delta in (-2, -1, 0, 1, 2):
                    value = copy.deepcopy(probe['body'])
                    size = 65536 + delta - original[field] + 1
                    assert size > 0
                    value['content'][0]['text'] = 'x' * size
                    yield transition(probe['label'] + '-' + field + '-' + str(delta), 'host_list', value)
