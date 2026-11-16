"""Inputs only. Expected values and diagnostics come from unchanged Rust."""
import copy
import itertools
import json


def iter_cases():
    rows = []
    def add(name, value, domain='typed-object'):
        rows.append({'case_id': len(rows), 'name': name, 'domain': domain,
                     'mode': 'typed', 'value': value})
    good = {'operation': 'insert', 'start': 0, 'content': 'x'}
    values = [None, False, True, 0, -1, 1.0, -0.0, 1e-7, 1e16, 1.234e30,
              18446744073709551615, -9223372036854775808, '', 'insert', 'replace',
              'INSERT', 'x\x00\b\f\n\r\t"\\中🙂\x7f\x85\u200d', [], {},
              [None], ['a', 'b'], {'insert': None}, {'replace': None},
              {'insert': False}, {'insert': []}, {'insert': {}, 'replace': None}]
    add('empty-object', {})
    add('operations-only-empty', {'operations': []})
    add('path-only', {'path': 'a'})
    add('empty-operations', {'path': 'a', 'operations': []})
    add('minimal-insert', {'path': 'a', 'operations': [good]})
    add('minimal-replace', {'path': 'a', 'operations': [{**good, 'operation': 'replace'}]})
    for field in ['path', 'operations']:
        for number, value in enumerate(values):
            obj = {'path': 'a', 'operations': [good]}
            obj[field] = value
            add(f'top-{field}-{number}', obj)
    for field in ['operation', 'start', 'end', 'content']:
        add(f'op-missing-{field}', {'path': 'a', 'operations': [{k:v for k,v in good.items() if k != field}]})
        for number, value in enumerate(values):
            add(f'op-{field}-{number}', {'path': 'a', 'operations': [{**good, field: value}]})
    for number, value in enumerate(values):
        add(f'op-element-{number}', {'path': 'a', 'operations': [value]})
    sequences = [[], ['insert'], ['insert', 0], ['insert', 0, None],
                 ['insert', 0, None, 'ok'], ['insert', 0, None, ['a', 'b']],
                 ['insert', 0, None, 'ok', 0], ['replace', None, {'x': [1]}, 'x'],
                 ['insert', 0, 'abc', 'x'], ['insert', 0, False, 'x'],
                 [None, 0, None, 'x'], ['insert', 0, None, None],
                 ['insert', 0, None, 'x', None, None]]
    for number, value in enumerate(sequences):
        add(f'op-sequence-{number}', {'path': 'a', 'operations': [value]})
    for mask in range(16):
        fields = ['operation', 'start', 'end', 'content']
        op = {f: good.get(f) for n, f in enumerate(fields) if mask & (1 << n)}
        add(f'missing-fields-{mask}', {'path': 'a', 'operations': [op]})
    for top in [None, '', 'top']:
        for paths in [[], ['a'], ['a', 'a'], ['a', 'b'], ['', ''], [None],
                      [None, 'a'], [3, 'a'], [{'x': 1}, 'a'], ['a', '\u0061']]:
            obj = {'operations': [{**good, 'path': p} for p in paths]}
            if top is not None:
                obj['path'] = top
            add(f'hoist-{top!r}-{paths!r}', obj)
            add(f'hoist-null-{top!r}-{paths!r}', {**obj, 'path': None})
    for op_path in [None, False, 2, [], {}, '', 'p']:
        for typed in [{}, {'content': False}, {'operation': False},
                      {'operation': 'insert', 'content': 'x'}, good]:
            add(f'path-before-typed-{op_path!r}-{typed!r}',
                {'operations': [{**typed, 'path': op_path}]})
    for first, second in itertools.product([{}, {'content': False}, good], repeat=2):
        add(f'late-path-scan-{len(rows)}', {'operations': [first, {**second, 'path': 'late'}]})
        add(f'late-path-conflict-{len(rows)}', {'operations': [{**first, 'path': 'a'}, {**second, 'path': 'b'}]})
    bads = {'content': False, 'end': [], 'operation': False, 'start': None}
    for count in range(1, 5):
        for fields in itertools.combinations(bads, count):
            op = {f:bads[f] for f in fields}
            add('error-order-'+'-'.join(fields), {'path': 'a', 'operations': [op]})
    for n in [0, 1, 2, 49, 50, 51, 100, 257]:
        add(f'operation-count-{n}', {'path': 'a', 'operations': [good]*n})
    for content in [[], [''], ['', ''], ['a', '', 'b'], ['\r\n', '\n'],
                    ['\x00', '\u2028\u2029', '中🙂'], ['a', None, False],
                    [False, 'a'], ['x', {'z': 1, 'a': [None, -0.0]}]]:
        add(f'content-list-{len(rows)}', {'path': 'a', 'operations': [{**good, 'content': content}]})
    add('unknown-fields', {'path': 'a', 'operations': [{**good, 'aaa': False, 'zzz': [1]}], 'unknown': {'k': True}})
    add('hoist-unknown-path-all-removed', {'path': 'a', 'operations': [{**good, 'path': False}, {**good, 'path': 'b'}]})
    for cp in [0, 8, 9, 10, 12, 13, 31, 34, 39, 92, 127, 133, 8205, 8232, 128578]:
        add(f'enum-debug-scalar-{cp}', {'path': 'a', 'operations': [{**good, 'operation': 'a'+chr(cp)+'b'}]})
        add(f'path-debug-scalar-{cp}', {'path': ['a'+chr(cp)+'b'], 'operations': []})
    for value in [None, [], ['p', []], [None, []], ['p', [], 0], True, 'x', 0]:
        add(f'raw-private-top-{len(rows)}', value, 'private-raw-value')
    for row in rows:
        yield copy.deepcopy(row)


def sdk_cases():
    selected = [r for r in iter_cases() if r['domain'] == 'typed-object']
    names = {'minimal-insert', 'empty-object', 'operations-only-empty', 'path-only',
             'empty-operations', 'operation-count-51', 'op-sequence-4',
             'op-sequence-5', 'op-operation-21', 'op-content-0',
             'late-path-scan-0', 'unknown-fields'}
    chosen = [r for r in selected if r['name'] in names]
    for number, row in enumerate(chosen):
        for protocol in ['legacy', 'modern']:
            messages = []
            if protocol == 'legacy':
                messages += [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                              'params': {'protocolVersion': '2025-11-25',
                                         'capabilities': {},
                                         'clientInfo': {'name': 'batch-params-probe', 'version': '1'}}},
                             {'jsonrpc': '2.0', 'method': 'notifications/initialized'}]
            params = {'name': 'batch_edit', 'arguments': row['value']}
            if protocol == 'modern':
                params['_meta'] = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                                   'io.modelcontextprotocol/clientInfo': {'name': 'batch-params-probe', 'version': '1'},
                                   'io.modelcontextprotocol/clientCapabilities': {}}
            messages.append({'jsonrpc':'2.0', 'id':10, 'method':'tools/call', 'params':params})
            yield {'case_id': 10000+number*2+(protocol=='modern'), 'name':row['name']+'-'+protocol,
                   'domain':'actual-sdk', 'mode':'sdk', 'messages':messages}


def encode(rows):
    return b''.join((json.dumps(row, ensure_ascii=False, separators=(',', ':'), allow_nan=False)+'\n').encode() for row in rows)


def extra_cases():
    good={'operation':'insert','start':0,'content':'x'}
    identifier=20000
    for cp in [0x115f,0x1160,0x3164,0xffa0,0xff9e,0xff9f,0x2028,0x2029,0x10ffff]:
        yield {'case_id':identifier,'name':f'unit-debug-{cp}','domain':'typed-object','mode':'typed',
               'value':{'path':'a','operations':[{**good,'operation':{'insert':chr(cp)}}]}}
        identifier+=1
    for name,raw in [
        ('duplicate-path-last-wins','{"path":"first","operations":[],"path":"last"}'),
        ('escaped-key-and-path','{"\\u0070ath":"\\u0061","operations":[{"operation":"in\\u0073ert","start":-0,"content":["x\\/y","\\ud83d\\ude42"]}]}'),
        ('duplicate-operation-last-wins','{"path":"a","operations":[{"operation":false,"content":"x","start":0,"operation":"replace"}]}'),
        ('unsigned-overflow-value','{"path":"a","operations":[{"operation":"insert","start":18446744073709551616,"content":"x"}]}'),
        ('signed-overflow-value','{"path":"a","operations":[{"operation":"replace","start":-9223372036854775809,"content":"x"}]}'),
    ]:
        yield {'case_id':identifier,'name':name,'domain':'typed-object','mode':'typed','raw_json':raw}
        identifier+=1
    nested=0
    for _ in range(125):nested=[nested]
    yield {'case_id':identifier,'name':'deep-unknown-125','domain':'typed-object','mode':'typed',
           'value':{'path':'a','operations':[good],'unknown':nested}}
    identifier+=1
    yield {'case_id':identifier,'name':'typed-4097-operations','domain':'typed-object','mode':'typed',
           'value':{'path':'a','operations':[good]*4097}}
    identifier+=1
    for name,field in [('content-over8m','content'),('path-over8m','path')]:
        obj={'path':'a','operations':[good.copy()]}
        if field=='path':obj['path']='p'*(8388608+1)
        else:obj['operations'][0]['content']='c'*(8388608+1)
        yield {'case_id':identifier,'name':name,'domain':'typed-object','mode':'typed','value':obj}
        identifier+=1
    scalars=''.join(chr(cp) for cp in range(0x110000) if not 0xd800<=cp<=0xdfff)
    yield {'case_id':identifier,'name':'unit-debug-all-1112064-scalars','domain':'typed-object','mode':'typed',
           'value':{'path':'a','operations':[{**good,'operation':{'insert':scalars}}]}}
