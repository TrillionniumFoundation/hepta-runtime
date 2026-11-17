"""Fixed public inputs only; all responses are observed from the original SDK."""
from __future__ import annotations
import hashlib
import json
import struct
import sys
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'reference/params'))
from cases import all_cases

MAX_LINE = 16 * 1024 * 1024

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()

def metadata():
    return {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientInfo': {'name': 'bellman-public-corpus', 'version': '1'},
            'io.modelcontextprotocol/clientCapabilities': {}}

def tool(identifier, raw=None, *, modern=False, omitted=False):
    params = b'{"name":"weight_bellman_plan"'
    if not omitted:
        params += b',"arguments":' + raw
    if modern:
        params += b',"_meta":' + encode(metadata())
    return b'{"jsonrpc":"2.0","id":' + encode(identifier) + b',"method":"tools/call","params":' + params + b'}}\n'

def ping(identifier):
    return encode({'jsonrpc': '2.0', 'id': identifier, 'method': 'ping'}) + b'\n'

def rows():
    sequence = 0
    def row(name, session, wire, *, frames=1, kind='control', index=None, group=None,
            response_ids=None, expected_dispatch=0, expected_start=0, opcode=1):
        nonlocal sequence
        value = dict(sequence=sequence, name=name, session=session, opcode=opcode, frames=frames,
            kind=kind, case_index=index, group=group, wire=pin(wire), response_ids=response_ids,
            expected_dispatch=expected_dispatch, expected_start=expected_start)
        sequence += 1
        return value, wire

    init = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
        'protocolVersion': '2025-11-25', 'capabilities': {},
        'clientInfo': {'name': 'bellman-public-corpus', 'version': '1'}}}
    yield row('legacy-initialize', 0, encode(init) + b'\n', kind='initialize', response_ids=[1])
    yield row('legacy-initialized', 0, b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
              kind='notification', frames=0, response_ids=[])
    cases = list(all_cases(ROOT / 'reference/qualify_bellman.py'))
    declared = json.loads((ROOT / 'domain.json').read_bytes())['cases']
    assert len(cases) == len(declared) == 683
    for session, mode in [(0, 'legacy'), (1, 'inline')]:
        for index, ((group, name, raw), private) in enumerate(zip(cases, declared)):
            assert (group, name) == (private['group'], private['name'])
            identifier = index + 1000
            value = json.loads(raw)
            dispatch = int(value is None or isinstance(value, dict))
            started = int(isinstance(value, dict) and private['status'] == 0)
            wire = tool(identifier, raw, modern=bool(session))
            assert len(wire) <= MAX_LINE
            yield row(mode + '/' + name, session, wire, kind='case', index=index, group=group,
                response_ids=[identifier], expected_dispatch=dispatch, expected_start=started)
        identifier = 100_000
        for name, raw, omitted in [('arguments-omitted', None, True), ('arguments-null', b'null', False),
                                   ('arguments-array', b'[]', False), ('arguments-number', b'1', False)]:
            yield row(mode + '/' + name, session, tool(identifier, raw, modern=bool(session), omitted=omitted),
                response_ids=[identifier], expected_dispatch=int(omitted or raw == b'null'))
            identifier += 1
        controls = [
            ('plain-ping', ping(identifier), 1, [identifier]),
            ('discard-syntax-and-recover', b'{broken json}\n' + ping(identifier + 1), 1, [identifier + 1]),
            ('empty-line-and-recover', b'\n' + ping(identifier + 2), 1, [identifier + 2]),
            ('bom-ping', b'\xef\xbb\xbf' + ping(identifier + 3), 1, [identifier + 3]),
            ('crlf-ping', ping(identifier + 4)[:-1] + b'\r\n', 1, [identifier + 4]),
            ('shape-error-and-recover', b'true\n' + ping(identifier + 5), 2, [None, identifier + 5]),
        ]
        for name, wire, frames, ids in controls:
            yield row(mode + '/' + name, session, wire, frames=frames, response_ids=ids)
        exact = ping(identifier + 6)
        exact = exact[:-1] + b' ' * (MAX_LINE - len(exact)) + b'\n'
        assert len(exact) == MAX_LINE
        yield row(mode + '/exact-16MiB-line', session, exact, response_ids=[identifier + 6])
        over = exact[:-1] + b' \n' + ping(identifier + 7)
        assert over.index(b'\n') + 1 == MAX_LINE + 1
        yield row(mode + '/over-16MiB-discard-and-recover', session, over, response_ids=[identifier + 7])
    for session in range(2):
        yield row('close-' + str(session), session, b'', frames=0, kind='close', response_ids=[], opcode=2)

def frame(row, wire):
    assert pin(wire) == row['wire']
    return b'HBPOREQ1' + struct.pack('<7Q', row['sequence'], row['opcode'], row['session'],
                                  len(wire), row['frames'], 0, 0) + wire

def domain():
    values = [row for row, wire in rows()]
    return dict(schema='hepta.bellman-public.wire-domain.v1', rows=values, public_cases=1366,
        cases_per_protocol=683, protocols=['2025-11-25 lifecycle', '2026-07-28 inline metadata'],
        transport_controls_per_protocol=12, sessions=2, closes=2, records=len(values),
        outer_line_limit=MAX_LINE, exchange_deadline_seconds=60, public_process_deadline_seconds=180,
        original_process_deadline_seconds=600, workflow_deadline_minutes=15,
        full_server_router_qualified=False, audit_qualified=False,
        async_pending_registry_qualified=False, whole_runtime_replaced=False,
        old_stack_removal_qualified=False)
