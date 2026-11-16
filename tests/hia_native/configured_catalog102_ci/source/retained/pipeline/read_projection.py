"""Strict read-only complete pipeline admission, with no code execution."""
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import common as c
from domain import SELECTED_TOOLS

def verify(source, build, output):
    base, sources, asset, _, raw_input = c.source_check(source)
    build_reader, modules = c.build_check(build, source)
    r = base.Reader(output); report = r.document('result.json')
    assert report['schema'] == 'hepta.runtime.catalog-eleven-pipeline.v1'
    assert report['status'] == 'PASS' and report['native_calls'] == 108
    assert report['original_compared'] is False and report['whole_runtime_replaced'] is False
    assert report['source_profile'] == c.pin((source / 'source-profile.json').read_bytes())
    assert len(report['shapes']) == 18
    outputs = []
    for ordinal, ((flags, modern), row) in enumerate(zip(c.shape_domain(), report['shapes'], strict=True)):
        assert (row['flags'], row['modern']) == (flags, modern)
        names = [name for name in SELECTED_TOOLS if flags & 1 or name not in asset['runtime_tool_names']]
        assert row['count'] == len(names) == (11 if flags else 7)
        label = f'shape-{ordinal:02d}'
        wire = base.frame(1, flags, modern, raw_input)
        # The original reader checks all three full-buffer growth transitions.
        # Preserve its exact expected prefix spelling without changing it.
        policy = [dict(x, prefix=x['prefix'].replace('-policy-', '-call-')) for x in row['policy_calls']]
        class PrefixReader:
            def compressed(self, relative, size=None):
                return r.compressed(relative.replace('-call-', '-policy-'), size)
        body = base.policy_calls(PrefixReader(), policy, wire, label, len(names))
        document = base.parse(body)
        assert [tool['name'] for tool in document['tools']] == names
        assert document.get('resultType') == 'complete'
        if modern:
            assert document['ttlMs'] == 0 and document['cacheScope'] == 'public'
        else:
            assert 'ttlMs' not in document and 'cacheScope' not in document
        wire = b'HSJVAL01' + struct.pack('<2Q', 1, len(body)) + body
        value, _ = base.read_call(r, row['value'], wire, label + '-value')
        code = row['value']['code']; assert 0 < code <= len(value)
        assert value[code:] == b'\xa7' * (len(value) - code)
        canonical = value[:code]; assert base.parse(canonical) == document
        assert [x['policy'] for x in row['sdk']] == [0, 2 if modern else 1]
        for sdk in row['sdk']:
            policy = sdk['policy']; call = sdk['call']
            wire = b'HRRSP001' + struct.pack('<2Q', 4 | policy << 8, len(canonical)) + canonical
            out, _ = base.read_call(r, call, wire, label + '-sdk-' + str(policy))
            code = call['code']; assert 64 < code <= len(out)
            assert out[:8] == b'HRRPO001'
            assert struct.unpack_from('<7Q', out, 8) == (4, 0, 64, code - 64, policy, 0, 0)
            assert out[code:] == b'\xa7' * (len(out) - code)
            typed = out[64:code]
            assert r.raw(label + '-sdk-' + str(policy) + '.json') == typed
            expected = dict(document)
            if policy == 1: expected.pop('resultType')
            assert base.parse(typed) == expected
            outputs.append({'flags': flags, 'modern': modern, 'sdk_policy': policy, **c.pin(typed)})
    return {'status': 'NATIVE_PIPELINE_READONLY_PASS', 'native_calls': 108,
        'shapes': 18, 'sdk_outputs': outputs, 'modules': modules,
        'source_files': sources.files, 'build_files': build_reader.files, 'native_files': r.files,
        'semantic_process_launches': 0, 'original_compared': False, 'whole_runtime_replaced': False}
