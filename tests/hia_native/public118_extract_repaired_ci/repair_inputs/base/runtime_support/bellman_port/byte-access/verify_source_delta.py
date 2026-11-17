"""Recompute all fourteen checked-byte equivalences from the pinned HIA ASTs.

This source check executes neither HIA nor Rust. The symbolic interpreter
admits only the recorded fixed eight-access helpers. Runtime and original
replay remain separate required gates for the successor graph.
"""
from pathlib import Path
import argparse
import hashlib
import json
import sys

sys.dont_write_bytecode = True


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def verify(package, hepta):
    package = Path(package).resolve(strict=True)
    hepta = Path(hepta).resolve(strict=True)
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    sys.path.insert(0, str(package / 'byte-access/authoring'))
    from prove_fixed_byte_access import symbolic
    proof = json.loads((package / 'BYTE_HELPER_UNROLL.json').read_bytes())
    expected = {
        'source/native/bellman_params_callable.hepta': {'f55', 'f56'},
        'worker-source/native/bellman_timed_core.hepta': {'f5', 'f6', 'f7'},
        'worker-source/native/bellman_timed_commitment.hepta': {'f10', 'f11', 'f12', 'f35', 'f36', 'f45', 'f48'},
        'worker-source/native/bellman_result.hepta': {'f85', 'f86'},
    }
    assert set(proof['changes']) == set(expected)
    for name, digest in proof['author'].items():
        assert sha((package / 'byte-access/authoring' / name).read_bytes()) == digest
    recorded = {(row['path'], row['function']): row['symbolic_checked_memory_trace']
                for row in proof['symbolic_proofs']}
    assert len(recorded) == len(proof['symbolic_proofs']) == 14
    rows = []
    seen = set()
    for relative, functions in sorted(expected.items()):
        change = proof['changes'][relative]
        old_raw = (package / 'byte-access/baseline' / relative).read_bytes()
        new_raw = (package / relative).read_bytes()
        assert sha(old_raw) == change['before_sha256']
        assert sha(new_raw) == change['after_sha256'] and len(new_raw) == change['after_bytes']
        old_program = assemble_program(old_raw).as_dict()
        new_program = assemble_program(new_raw).as_dict()
        assert {k: v for k, v in old_program.items() if k != 'functions'} == {
            k: v for k, v in new_program.items() if k != 'functions'}
        old = {f['name']: f for f in old_program['functions']}
        new = {f['name']: f for f in new_program['functions']}
        assert len(old) == len(old_program['functions']) == len(new_program['functions']) == len(new)
        assert list(old) == list(new)
        assert set(change['changed_functions'].values()) == functions
        untouched = {name: sha(canonical(old[name])) for name in old if name not in functions}
        assert untouched == change['all_other_function_asts_exact']
        assert all(old[name] == new[name] for name in untouched)
        for name in sorted(functions):
            before, after = symbolic(old[name]), symbolic(new[name])
            assert before == after
            assert json.loads(canonical(before)) == recorded[relative, name]
            seen.add((relative, name))
        rows.append({'path': relative, 'before_sha256': sha(old_raw), 'after_sha256': sha(new_raw),
                     'changed_functions': sorted(functions), 'unchanged_functions': len(untouched),
                     'symbolic_trace_and_return_equal': True})
    assert seen == set(recorded)
    result = {'status': 'INDEPENDENT_EXACT_AST_AND_CHECKED_ACCESS_PASS', 'functions': 14,
              'rows': rows, 'native_or_rust_executions': 0, 'public_handler_qualified': False}
    retained = json.loads((package / 'byte-access/independent-source-proof.json').read_bytes())
    assert result == retained
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--hepta', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.package, args.hepta), indent=2, sort_keys=True))
