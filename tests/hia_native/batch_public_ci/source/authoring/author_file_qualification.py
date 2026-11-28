#!/usr/bin/env python3
"""Retain the whole 926-case published file domain; change only its carrier."""
from pathlib import Path
import argparse
import ast
import hashlib
import json


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    inputs = json.loads((root / 'corpus-inputs.json').read_bytes())
    name = 'corpus/reference/tests/hia_native/test_batch_write_files.py'
    before = (root / name).read_bytes()
    assert hashlib.sha256(before).hexdigest() == inputs['files'][name]['sha256']
    text = before.decode()
    changes = []
    def replace(old, new, count=1):
        nonlocal text
        assert text.count(old) == count, (old, text.count(old), count)
        text = text.replace(old, new)
        changes.append({'old':old,'new':new,'count':count})
    replace('"""Actual Local batch body requests and complete retained file bytes."""',
            '"""Complete published 926-file corpus over the new serial callable fixture.\n\nNo case or deadline is removed. Python expectations are development evidence;\nfresh current original Rust comparison is a separate required gate.\n"""')
    replace("HERE = Path(__file__).resolve().parent\nsys.path.insert(0, str(HERE))", """ROOT = Path(__file__).resolve().parent
REFERENCE = ROOT / 'corpus/reference'
HERE = REFERENCE / 'tests/hia_native'
sys.dont_write_bytecode = True
os.environ['HIA_REFERENCE_RUNTIME'] = str(REFERENCE)
os.environ['HIA_RUNTIME_REPO'] = str(REFERENCE)
sys.path.insert(0, str(ROOT / 'runtime_support/scripts'))
sys.path.insert(0, str(HERE))""")
    replace("'schema': 'hepta.runtime.batch-write-files.v1'", "'schema': 'hepta.runtime.rebuilt-batch-callable-files.v1'")
    replace("'domains': {}, 'inherits_outer_process_group': True, 'outer_timeout_seconds': 180}",
        "'domains': {}, 'inherits_outer_process_group': True, 'outer_timeout_seconds': 180,\n"
        "              'body_requests': 926, 'setup_frames': [], 'native_thread_identity_claimed': False,\n"
        "              'fresh_current_original_compared': False, 'public_batch_qualified': False,\n"
        "              'full_async_cancellation_qualified': False}")
    replace("packet = struct.pack('<QQ', len(wire), ordinal) + wire", "packet = struct.pack('<Q', len(wire)) + wire")
    replace("        header = exact(process.stdout, 20, deadline)\n        tag, tid, code = struct.unpack('<QQI', header)\n        assert tag == ordinal and tid > 0 and 32 <= code < 0xffff0000, (label, tag, code)",
        "        header = exact(process.stdout, 8, deadline)\n        code, = struct.unpack('<Q', header)\n        tag = ordinal\n        assert 32 <= code < 0xffff0000, (label, ordinal, code)")
    setup = """    def setup(magic, count, result_magic, expected_size):
        wire = magic + bytes(count * 8)
        packet = struct.pack('<Q', len(wire)) + wire
        requests.write(packet); process.stdin.write(packet); process.stdin.flush()
        deadline = min(started + 180, time.monotonic() + 60)
        header = exact(process.stdout, 8, deadline)
        size, = struct.unpack('<Q', header)
        assert size == expected_size
        response = exact(process.stdout, size, deadline)
        responses.write(header + response)
        assert response[:8] == result_magic and response[8:] == bytes(size - 8)
        report['setup_frames'].append({'input_hex': wire.hex(), 'output_hex': response.hex()})
"""
    replace("    try:\n        path = fixture / 'target'", setup + "    try:\n        setup(b'HVCACH01', 5, b'HVCAR001', 32)\n        setup(b'HHISTQ01', 7, b'HHISTR01', 64)\n        path = fixture / 'target'")
    replace("        report['status'] = 'PASS'", "        assert large and report['requests'] == 926\n        report['status'] = 'PASS'")
    replace("    parser.add_argument('--reference', type=Path, required=True)", "    parser.add_argument('--reference', type=Path, default=REFERENCE)")
    replace("large=args.large)", "large=True)")
    original = ast.parse(before)
    generated = ast.parse(text)
    def domain(module):
        fn = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'execute')
        attempt = next(n for n in fn.body if isinstance(n, ast.Try))
        start = next(i for i, n in enumerate(attempt.body) if isinstance(n, ast.Assign) and
                     isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'path')
        end = next(i for i, n in enumerate(attempt.body) if isinstance(n, ast.Expr) and
                   ast.unparse(n) == 'process.stdin.close()')
        return ast.dump(ast.Module(body=attempt.body[start:end], type_ignores=[]), include_attributes=False)
    assert domain(original) == domain(generated)
    raw = text.encode()
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / 'qualify_files.py').write_bytes(raw)
    proof = {'schema':'hepta.runtime.rebuilt-batch-file-corpus-author.v1',
        'original_source': name, 'original_sha256':hashlib.sha256(before).hexdigest(),
        'generated_sha256':hashlib.sha256(raw).hexdigest(), 'generated_bytes':len(raw),
        'unchanged_complete_case_body_ast_sha256':hashlib.sha256(domain(original).encode()).hexdigest(),
        'inherited_cases':926,'large_cases_enabled':True,'per_reply_deadline_seconds':60,
        'complete_session_deadline_seconds':180,'transport_changes':changes,
        'native_executed':False,'fresh_current_original_compared':False}
    (a.output / 'file-corpus-author-proof.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:proof[k] for k in ('generated_sha256','generated_bytes','inherited_cases','unchanged_complete_case_body_ast_sha256')}))


if __name__ == '__main__': main()
