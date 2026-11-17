"""Inputs only for the locked rmcp lifecycle and original ViewParams derive."""
from __future__ import annotations
import json

CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities'
PROTOCOL = 'io.modelcontextprotocol/protocolVersion'

def initialization(capabilities):
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
            'params': {'protocolVersion': '2025-11-25', 'capabilities': capabilities,
                       'clientInfo': {'name': 'original-view-oracle', 'version': '1'}}}

def call(identifier, arguments, metadata=None):
    params = {'name': 'view', 'arguments': arguments}
    if metadata is not None: params['_meta'] = metadata
    return {'jsonrpc': '2.0', 'id': identifier, 'method': 'tools/call', 'params': params}

def legacy(messages, capabilities=None):
    return [initialization(capabilities or {}), {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, *messages]

def iter_sdk_cases():
    cases = []
    def add(name, messages):
        cases.append({'case_id': len(cases), 'name': name, 'messages': messages})
    params = [
        ('missing-path', {}), ('null-path', {'path': None}), ('number-path', {'path': 2}),
        ('array-path', {'path': ['one', 'two']}), ('empty-path', {'path': ''}),
        ('whitespace-path', {'path': ' \t'}), ('valid-defaults', {'path': 'file'}),
        ('embedded-nul', {'path': 'a\0b'}), ('unicode', {'path': '中🙂'}),
        ('unknown-fields', {'path': 'file', 'unknown': {'arbitrary': [1, True, None]}}),
        ('null-optionals', {'path': 'file', 'full': None, 'regex': None, 'context': None}),
        ('full-wrong-string', {'path': 'file', 'full': 'true'}),
        ('regex-wrong-number', {'path': 'file', 'regex': 1}),
        ('pattern-wrong-bool', {'path': 'file', 'pattern': False}),
        ('content-wrong-array', {'path': 'file', 'content': []}),
        ('hidden-wrong-number', {'path': 'file', 'include_hidden': 0}),
        ('context-negative', {'path': 'file', 'context': -1}),
        ('context-float', {'path': 'file', 'context': 1.0}),
        ('context-max-usize', {'path': 'file', 'context': (1 << 64) - 1}),
        ('depth-max-usize', {'path': 'file', 'max_depth': (1 << 64) - 1}),
        ('depth-overflow', {'path': 'file', 'max_depth': 1 << 64}),
        ('endpoints-opaque-values', {'path': 'file', 'start': {'x': 1}, 'end': [False]}),
        ('endpoints-bool-float', {'path': 'file', 'start': True, 'end': 1.5}),
        ('optional-string-fields', {'path': 'file', 'content': '', 'pattern': '', 'full': False,
                                    'regex': True, 'include_hidden': False, 'context': 0, 'max_depth': 0}),
    ]
    for name, value in params: add('params-' + name, legacy([call(2, value)]))
    original = {'experimental': {'session': {'workdir': '/original'}}}
    replacement = {'experimental': {'session': {'workdir': '/replacement'}}}
    add('legacy-capabilities-fallback', legacy([call(2, {'path': 'file'})], original))
    add('legacy-request-overrides-handshake', legacy([call(2, {'path': 'file'}, {CAPABILITIES: replacement})], original))
    add('legacy-empty-request-overrides-handshake', legacy([call(2, {'path': 'file'}, {CAPABILITIES: {}})], original))
    add('legacy-null-request-falls-back', legacy([call(2, {'path': 'file'}, {CAPABILITIES: None})], original))
    add('legacy-malformed-request-falls-back', legacy([call(2, {'path': 'file'}, {CAPABILITIES: 'bad'})], original))
    add('legacy-malformed-experimental-falls-back', legacy([call(2, {'path': 'file'}, {CAPABILITIES: {'experimental': []}})], original))
    modern = {PROTOCOL: '2026-07-28', CAPABILITIES: replacement}
    add('modern-initial-request-capabilities', [call(1, {'path': 'file'}, modern)])
    add('modern-capabilities-per-request', [call(1, {'path': 'file'}, modern), call(2, {'path': 'file'}, {PROTOCOL: '2026-07-28', CAPABILITIES: {}})])
    add('modern-missing-capabilities', [call(1, {'path': 'file'}, {PROTOCOL: '2026-07-28'})])
    add('modern-null-capabilities', [call(1, {'path': 'file'}, {PROTOCOL: '2026-07-28', CAPABILITIES: None})])
    add('modern-malformed-capabilities', [call(1, {'path': 'file'}, {PROTOCOL: '2026-07-28', CAPABILITIES: 'bad'})])
    add('modern-invalid-second-capabilities', [call(1, {'path': 'file'}, modern), call(2, {'path': 'file'}, {PROTOCOL: '2026-07-28', CAPABILITIES: None})])
    yield from cases

def encode_cases():
    return b''.join(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                               allow_nan=False).encode() + b'\n' for row in iter_sdk_cases())
