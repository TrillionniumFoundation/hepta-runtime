"""Unroll only the exact existing eight-iteration byte load/store helpers.

The same eight checked byte accesses remain in the same order, with identical
u64 wrapping address arithmetic. No numeric, parser or formatter rule changes.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import shutil
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


OLD = '''
def get_mut(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put_mut(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0

def get_read(w:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value
'''


def unrolled_source():
    pieces = []
    for name, kind in [('get_mut', 'mutbuf'), ('get_read', 'readbuf')]:
        lines = [f'def {name}(w:{kind}, at:u64) -> u64:', '    value = 0']
        for i in range(8):
            lines.append(f'    value = value | (byte(w, at + {i}) << {i * 8})')
        lines.append('    return value')
        pieces.append('\n'.join(lines))
    lines = ['def put_mut(w:mutbuf, at:u64, value:u64) -> u64:']
    for i in range(8):
        lines.append(f'    store(w, at + {i}, value & 255)')
        lines.append('    value = value >> 8')
    lines.append('    return 0')
    pieces.append('\n'.join(lines))
    return '\n\n'.join(pieces) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'output', 'hepta', 'support']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    support = args.support.resolve(strict=True)
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program
    spec = importlib.util.spec_from_file_location('_fixed_byte_author_support', support)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    replacements = {
        'native/serde_json_span.hepta': {'get_mut': 'f18', 'put_mut': 'f19', 'get_read': 'f25'},
        'native/sdk_message_target.hepta': {'get_mut': 'f50', 'put_mut': 'f51', 'get_read': 'f57'},
    }
    expected_sources = {
        'native/serde_json_span.hepta': '8ccf013c44c6635e131505a628aa3b7732eaae95b0d8b4fae8bdd6b140607840',
        'native/sdk_message_target.hepta': 'e1ef0dd6bb5993f6ad07499ee68e5a63b1fbd4a97ebf0e17b89aec1234af6a6b',
    }
    changes = {}
    rewritten = {}
    new = unrolled_source()
    for path, names in replacements.items():
        original = (source / path).read_bytes()
        assert sha(original) == expected_sources[path], path
        before = {f['name']: f for f in assemble_program(original).as_dict()['functions']}
        # Refuse a superficially similar function: the entire original CFG
        # must equal the exact declared loop compiled by this pinned author.
        _, expected, _ = module.compile_delta(args.hepta, original, {}, OLD, names, {})
        for fn in names.values():
            assert before[fn] == expected[fn], (path, fn, 'original loop CFG differs')
        generated, after, retained = module.compile_delta(args.hepta, original, {}, new, names, {})
        rewritten[path] = generated
        changes[path] = {'before_sha256': sha(original), 'after_sha256': sha(generated),
                         'after_bytes': len(generated), 'changed_functions': names,
                         'all_other_function_asts_exact': retained,
                         'original_loop_cfg_exact': True,
                         'access_offsets_in_order': list(range(8)),
                         'u64_shift_offsets': list(range(0, 64, 8)),
                         'address_arithmetic': 'u64 wrapping at+i, unchanged',
                         'loads_and_stores': 'eight separate checked u8 accesses, unchanged',
                         'put_partial_write_on_bounds_trap': 'same byte order, unchanged'}
    shutil.copytree(source, output)
    for path, raw in rewritten.items():
        (output / path).write_bytes(raw)
    proof = {'schema': 'hepta.runtime.fixed-byte-access-unroll.v1',
             'author_sha256': sha(Path(__file__).read_bytes()), 'support_sha256': sha(support.read_bytes()),
             'old_loop_pseudo_sha256': sha(OLD.encode()), 'unrolled_pseudo_sha256': sha(new.encode()),
             'numeric_algorithms_unchanged': True, 'public_domain_qualified': False,
             'fresh_ci_qualified': False, 'changes': changes}
    (output / 'native/fixed_byte_access_unroll.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    (output / 'native/fixed_byte_access_unroll.pseudo').write_text(new)
    binding = json.loads((source / 'native/runtime_mcp_sources.json').read_bytes())
    binding['sources'] = {p.relative_to(output).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
                          for p in sorted(output.rglob('*')) if p.is_file() and p != output / 'native/runtime_mcp_sources.json'}
    (output / 'native/runtime_mcp_sources.json').write_text(json.dumps(binding, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'output': str(output), 'source_binding_sha256': sha((output / 'native/runtime_mcp_sources.json').read_bytes()),
                      'changed': {path: {k: row[k] for k in ('after_sha256', 'changed_functions')} for path, row in changes.items()}}))


if __name__ == '__main__':
    main()
