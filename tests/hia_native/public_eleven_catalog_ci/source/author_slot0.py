"""Emit one pure HIA slot0 catalog from an admitted native SDK pipeline.

No original expected response is an implementation input. A deterministic
LZSS byte stream is emitted as HIA constants and decoded by the HIA owner.
The original 18 non-list branches and all their helpers remain byte-for-byte
identical at the HIA AST boundary.
"""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
BASELINE = 'b9a62c6e24d171c08b8138d3116aa3f7cd709e4c44b9a163a62e32b6a50fe089'

def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
def graph_pin(value): return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())

def compress(data):
    output = bytearray(); literal = bytearray(); previous = {}
    def flush():
        if literal:
            output.append(len(literal) - 1); output.extend(literal); literal.clear()
    def remember(at):
        if at + 3 <= len(data):
            key = data[at:at + 3]; positions = previous.setdefault(key, [])
            positions.append(at)
            if len(positions) > 256: del positions[:-256]
    at = 0
    while at < len(data):
        best, distance = 0, 0
        for old in reversed(previous.get(data[at:at + 3], ())):
            if at - old > 65535: break
            length = 0
            while length < 130 and at + length < len(data) and data[old + length] == data[at + length]:
                length += 1
            if length > best: best, distance = length, at - old
            if best == 130: break
        if best >= 4:
            flush(); output.extend(bytes((128 | (best - 3), distance & 255, distance >> 8)))
            for offset in range(best): remember(at + offset)
            at += best
        else:
            literal.append(data[at]); remember(at); at += 1
            if len(literal) == 128: flush()
    flush()
    return bytes(output)

def decompress(data):
    output = bytearray(); at = 0
    while at < len(data):
        tag = data[at]; at += 1
        if tag < 128:
            size = tag + 1; assert size <= len(data) - at
            output.extend(data[at:at + size]); at += size
        else:
            assert at + 2 <= len(data)
            distance = int.from_bytes(data[at:at + 2], 'little'); at += 2
            assert 0 < distance <= len(output)
            for _ in range((tag & 127) + 3): output.append(output[-distance])
    return bytes(output)

def generate(hepta, pipeline, build, capture, output):
    sys.path.insert(0, str(pipeline))
    import read_projection
    import common
    assert Path(common.__file__).resolve().parent == pipeline
    admission = read_projection.verify(pipeline, build, capture)
    assert admission['status'] == 'NATIVE_PIPELINE_READONLY_PASS'
    bodies = [(capture / f'shape-{index:02d}-sdk-{policy}.json').read_bytes()
              for index, policy in ((2, 1), (3, 2))]
    assert all(len(json.loads(raw)['tools']) == 11 for raw in bodies)
    fragments = [b',"result":' + body + b'}' for body in bodies]
    positions = [raw.index(b'"tools":') for raw in fragments]
    prefixes = [raw[:at] for raw, at in zip(fragments, positions, strict=True)]
    common_bytes = fragments[0][positions[0]:]
    assert fragments[1][positions[1]:] == common_bytes
    packed = compress(common_bytes); assert decompress(packed) == common_bytes
    workspace = max(4096, (len(packed) + 7) & ~7)
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    baseline_raw = (pipeline / 'baseline/runtime_mcp_catalog_ninth.hepta').read_bytes()
    assert sha(baseline_raw) == BASELINE
    baseline = assemble_program(baseline_raw).as_dict()
    assert len(baseline['functions']) == 62
    lines = [
        'def target_size(mode: u64) -> u64:',
        f'    if mode == 0: return {len(fragments[0])}',
        f'    return {len(fragments[1])}',
        'def target_literal(out: mutbuf, p: u64, mode: u64, w: mutbuf) -> u64:',
        '    if mode == 0:',
        '        p = prefix0(out, p)',
        '    else:',
        '        p = prefix1(out, p)',
        '    load_table(w)',
        '    return decode(out, p, w)',
        'def decode(out: mutbuf, p: u64, w: mutbuf) -> u64:',
        '    i = 0',
        f'    while i < {len(packed)}:',
        '        tag = byte(w, i)',
        '        i = i + 1',
        '        if tag < 128:',
        '            count = tag + 1',
        '            j = 0',
        '            while j < count:',
        '                store(out, p, byte(w, i))',
        '                p = p + 1',
        '                i = i + 1',
        '                j = j + 1',
        '        else:',
        '            distance = byte(w, i) | (byte(w, i + 1) << 8)',
        '            i = i + 2',
        '            count = (tag & 127) + 3',
        '            j = 0',
        '            while j < count:',
        '                store(out, p, byte(out, p - distance))',
        '                p = p + 1',
        '                j = j + 1',
        '    return p',
    ]
    def literal(name, data, *, workspace=False, offset=0):
        if workspace: result = [f'def {name}(w: mutbuf) -> u64:']
        else: result = [f'def {name}(w: mutbuf, p: u64) -> u64:']
        full = len(data) if workspace else len(data) // 8 * 8
        for at in range(0, full, 8):
            word = int.from_bytes(data[at:at + 8].ljust(8, b'\0'), 'little')
            position = str(offset + at) if workspace else f'p + {at}'
            result.append(f'    put(w, {position}, {word})')
        if not workspace:
            for at in range(full, len(data)): result.append(f'    store(w, p + {at}, {data[at]})')
        result.append('    return 0' if workspace else f'    return p + {len(data)}')
        return result
    lines.extend(literal('prefix0', prefixes[0])); lines.extend(literal('prefix1', prefixes[1]))
    lines.append('def load_table(w: mutbuf) -> u64:')
    chunks = list(range(0, len(packed), 512))
    for at in chunks: lines.append(f'    chunk_{at}(w)')
    lines.append('    return 0')
    for at in chunks: lines.extend(literal(f'chunk_{at}', packed[at:at + 512], workspace=True, offset=at))
    pseudo = '\n'.join(lines) + '\n'
    nodes = ast.parse(pseudo).body
    mapping = {'put': 'f6', **{node.name: 'f' + str(35 + i) for i, node in enumerate(nodes)}}
    assert mapping['target_literal'] == 'f36'
    signatures = {'put': (['mutbuf', 'u64', 'u64'], 'u64')}
    signatures.update({node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes})
    functions = []
    for node in nodes:
        builder = Builder(node, mapping, signatures, total_scalar_functions(nodes))
        builder.statements(node.body)
        functions.append({'name': mapping[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    document = copy.deepcopy(baseline); document['module'] = 'runtime_mcp_catalog_eleven'
    document['functions'] = document['functions'][:35] + functions
    entry = document['functions'][0]
    mutations = []
    for block in entry['blocks']:
        for op in block['ops']:
            if op.get('attrs', {}).get('function') == 'f36':
                assert op['args'] == ['v103', 'v111', 'v105']
                op['args'].append('v104'); mutations.append('literal-workspace-loan')
            if op['op'] == 'const' and op.get('attrs', {}).get('value') == 4096:
                op['attrs']['value'] = workspace; mutations.append('workspace-capacity')
    assert mutations == ['workspace-capacity', 'workspace-capacity', 'literal-workspace-loan']
    restored = copy.deepcopy(entry)
    for block in restored['blocks']:
        for op in block['ops']:
            if op.get('attrs', {}).get('function') == 'f36': op['args'].pop()
            if op['op'] == 'const' and op.get('attrs', {}).get('value') == workspace: op['attrs']['value'] = 4096
    assert restored == baseline['functions'][0]
    assert document['functions'][1:35] == baseline['functions'][1:35]
    raw = render_assembly(document).encode(); assert assemble_program(raw).as_dict() == document
    stats = {'functions': len(document['functions']), 'blocks': sum(len(f['blocks']) for f in document['functions']),
        'instructions': sum(len(b['ops']) for f in document['functions'] for b in f['blocks'])}
    assert stats['functions'] <= 128 and stats['blocks'] <= 1536 and stats['instructions'] <= 8192
    output.mkdir(parents=True, exist_ok=False)
    (output / 'runtime_mcp_catalog_eleven.hepta').write_bytes(raw)
    (output / 'catalog_eleven.pseudo').write_text(pseudo)
    for mode, fragment in enumerate(fragments): (output / f'catalog-mode-{mode}.bin').write_bytes(fragment)
    (output / 'catalog-common.lzss').write_bytes(packed)
    proof = {'schema': 'hepta.runtime.catalog-eleven-static-author.v1', 'author_sha256': sha(Path(__file__).read_bytes()),
        'baseline_source_sha256': BASELINE, 'pipeline_source_profile_sha256': sha((pipeline / 'source-profile.json').read_bytes()),
        'pipeline_result_sha256': sha((capture / 'result.json').read_bytes()),
        'native_modules': admission['modules'], 'native_pipeline_calls': 108,
        'pipeline_sdk_assets': [{'mode': mode, 'shape': index, 'policy': policy, 'bytes': len(body), 'sha256': sha(body)}
            for mode, ((index, policy), body) in enumerate(zip(((2, 1), (3, 2)), bodies, strict=True))],
        'literal_producer': 'actual catalog_eleven_policy -> serde Value -> SDK op4',
        'expected_original_wire_used_as_implementation': False,
        'fixed_runtime_enabled': True, 'declared_tools': list(common.SELECTED_TOOLS),
        'modern_cache_scope': 'public', 'old_modern_cache_scope': 'private',
        'workspace_required': workspace, 'compressed_bytes': len(packed), 'common_bytes': len(common_bytes),
        'compressed_sha256': sha(packed), 'common_sha256': sha(common_bytes),
        'retained_non_list_function_graphs': {f['name']: graph_pin(f) for f in baseline['functions'][1:35]},
        'entry_inverse_restores_exact_baseline': True, 'entry_changes': mutations,
        'source_sha256': sha(raw), 'source_bytes': len(raw), **stats,
        'assets': [{'mode': mode, 'bytes': len(raw), 'sha256': sha(raw)} for mode, raw in enumerate(fragments)],
        'public_all_configuration_qualified': False, 'whole_runtime_replaced': False}
    (output / 'catalog-eleven-composition.json').write_bytes(encoded(proof))
    return proof

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    for name in ('hepta', 'pipeline', 'build', 'capture', 'output'): p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    result = generate(a.hepta.resolve(strict=True), a.pipeline.resolve(strict=True), a.build.resolve(strict=True),
                      a.capture.resolve(strict=True), a.output.absolute())
    print(json.dumps({k: result[k] for k in ('source_sha256', 'source_bytes', 'functions', 'blocks', 'instructions', 'compressed_bytes', 'workspace_required')}, sort_keys=True))
