"""Compare exact CFG checked-byte traces with symbolic addresses and values.

Only fixed eight-access helpers are admitted. All branches must resolve from
concrete loop counters. Equal ordered memory traces also prove equal first
bounds failures and equal partial writes for every possible buffer extent.
"""
from pathlib import Path
import argparse
import hashlib
import json
import sys

MASK = (1 << 64) - 1


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def expression(op, args, result_type):
    if op == 'int.cast':
        value, = args
        if result_type in ('u64', 'usize'):
            return value
        assert result_type == 'u8'
        return value & 255 if type(value) is int else ('u8', value)
    if op == 'compare.lt':
        assert all(type(x) is int for x in args), 'data-dependent branch refused'
        return args[0] < args[1]
    if op in ('int.shl.checked', 'int.shr.checked'):
        assert type(args[1]) is int and 0 <= args[1] < 64
    if all(type(x) is int for x in args):
        a, b = args
        if op == 'int.add.wrap': return (a + b) & MASK
        if op == 'int.mul.wrap': return (a * b) & MASK
        if op == 'int.shl.checked': return (a << b) & MASK
        if op == 'int.shr.checked': return a >> b
        if op == 'bit.or': return a | b
        if op == 'bit.and': return a & b
        raise AssertionError(op)
    assert op in ('int.add.wrap', 'int.mul.wrap', 'int.shl.checked', 'int.shr.checked', 'bit.or', 'bit.and')
    if args[1] == 0 and op in ('int.add.wrap', 'int.shl.checked', 'int.shr.checked', 'bit.or'):
        return args[0]
    if args[0] == 0 and op in ('int.add.wrap', 'bit.or'):
        return args[1]
    return (op, *args)


def symbolic(function):
    params = function['params']
    assert function['returns'] == ['u64'] and len(params) in (2, 3)
    assert params[0]['type'] in ('readbuf', 'mutbuf')
    assert all(p['type'] == 'u64' for p in params[1:])
    values = [('argument', i, p['type']) for i, p in enumerate(params)]
    blocks = {b['id']: b for b in function['blocks']}
    block_name = function['entry']
    memory = []
    visited = 0
    while True:
        visited += 1
        assert visited <= 32, 'not the declared bounded helper loop'
        block = blocks[block_name]
        assert len(values) == len(block['params'])
        env = {p['name']: value for p, value in zip(block['params'], values, strict=True)}
        for op in block['ops']:
            name = op['op']
            args = [env[x] for x in op['args']]
            outputs = op['out']
            if name == 'buffer.store':
                assert not outputs
                memory.append(('checked_u8_store', *args))
                continue
            assert len(outputs) == 1
            if name == 'const':
                value = op['attrs']['value']
            elif name == 'buffer.load':
                assert outputs[0]['type'] == 'u8'
                value = ('checked_u8_load', *args)
                memory.append(value)
            else:
                assert not op['attrs'] or (name == 'int.cast' and op['attrs'] == {'mode': 'wrap'})
                value = expression(name, args, outputs[0]['type'])
            env[outputs[0]['name']] = value
        term = block['term']
        if term['op'] == 'ret':
            assert len(memory) == 8
            return {'ordered_checked_memory_accesses': memory, 'return': [env[x] for x in term['values']]}
        if term['op'] == 'branch':
            condition = env[term['cond']]
            assert type(condition) is bool
            edge = term['then'] if condition else term['else']
        else:
            assert term['op'] == 'jump'
            edge = term
        block_name = edge['target']
        values = [env[x] for x in edge['args']]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['before', 'after', 'hepta']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program
    proof = json.loads((args.after / 'native/fixed_byte_access_unroll.json').read_bytes())
    rows = []
    for path, info in proof['changes'].items():
        before_raw = (args.before / path).read_bytes()
        after_raw = (args.after / path).read_bytes()
        assert sha(before_raw) == info['before_sha256'] and sha(after_raw) == info['after_sha256']
        before = {f['name']: f for f in assemble_program(before_raw).as_dict()['functions']}
        after = {f['name']: f for f in assemble_program(after_raw).as_dict()['functions']}
        assert before.keys() == after.keys()
        changed = set(info['changed_functions'].values())
        assert all(before[name] == after[name] for name in before if name not in changed)
        for name in sorted(changed):
            old, new = symbolic(before[name]), symbolic(after[name])
            assert old == new, (path, name, 'symbolic checked-memory trace differs')
            rows.append({'path': path, 'function': name, 'proof': old,
                         'all_addresses_and_values_symbolic': True, 'ordered_bounds_checks_equal': True,
                         'partial_store_effects_equal': True})
    print(json.dumps({'schema': 'hepta.runtime.fixed-byte-access-symbolic-proof.v1',
                      'status': 'SYMBOLIC_FIXED_EIGHT_ACCESS_EQUIVALENCE_PASS',
                      'proved_functions': len(rows), 'cases_enumerated': False,
                      'native_executions': 0, 'rust_executions': 0,
                      'public_qualification': False, 'functions': rows}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
