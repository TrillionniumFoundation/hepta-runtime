"""Ordinary, fixed two-session public binding and private lifecycle plan."""
import json
import struct

OWNER_REQUEST = b'4852415554523031030000000000000000000000000000000000000000000000'
VERSION = 'io.modelcontextprotocol/protocolVersion'
CAPS = 'io.modelcontextprotocol/clientCapabilities'

def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()

def plan(configured):
    rows = []
    calls = [0, 0]
    def add(session, action, label, data=b'', projection=False, released=False):
        rows.append(dict(session=session, action=action, label=label, data_hex=data.hex(),
                         authority_calls=calls[session], projection=projection, released=released))
    for session in range(2):
        add(session, 57, 'startup')
    for session in range(2):
        add(session, 34, 'initialize', wire(dict(jsonrpc='2.0', id=1, method='initialize', params=dict(
            protocolVersion='2025-11-25', capabilities={}, clientInfo=dict(name='ordinary-peer-'+str(session), version='1')))))
        add(session, 34, 'initialized', wire(dict(jsonrpc='2.0', method='notifications/initialized')))
        add(session, 34, 'ping', wire(dict(jsonrpc='2.0', id=2, method='ping')))
        add(session, 34, 'catalog', wire(dict(jsonrpc='2.0', id=3, method='tools/list', params={})))
        add(session, 57, 'protocol-only')
    for number, args in enumerate(({}, {'path': 'sub'}), 1):
        for session in range(2):
            params = dict(name='workdir', arguments=args)
            if number == 2:
                params['_meta'] = {VERSION: '2026-07-28', CAPS: {'experimental': {}}}
            calls[session] += int(configured)
            add(session, 34, 'tool-'+str(number), wire(dict(jsonrpc='2.0', id=10+number, method='tools/call', params=params)))
            add(session, 57, 'after-tool-'+str(number), projection=configured)
    for session in range(2):
        calls[session] += 1
        add(session, 56, 'private-export', OWNER_REQUEST)
        add(session, 57, 'after-private-export', projection=configured)
    for repeat in range(2):
        for session in range(2):
            add(session, 58, 'release-'+str(repeat+1), projection=configured, released=True)
    assert len(rows) == 28
    return rows

def framed(rows):
    return b''.join(b'HFSFXQ02'+struct.pack('<3Q', row['session'], row['action'], len(bytes.fromhex(row['data_hex'])))+
                    bytes.fromhex(row['data_hex']) for row in rows)
