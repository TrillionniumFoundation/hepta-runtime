"""Prepare a separate port/worker helper delta; old qualification stays frozen."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import shutil
import sys


PINS = {
    'source/native/bellman_params_callable.hepta': '239087c423062939a622bfda7d0ab1df3ae89a12079952c1d4abd84cdac3dea8',
    'worker-source/native/bellman_timed_core.hepta': '048a68392e6613d4dee375ca24791a541642ac10921756e32bcd7184e9f259b2',
    'worker-source/native/bellman_timed_commitment.hepta': '1129c2b35925ae3dc320af0521ff2740271a651e88fdf91bed821a5781e81019',
    'worker-source/native/bellman_result.hepta': '1d4ad5aaeab526a76509f3f330f2561b7fce69c64818fcfae6a5826e32fe733d',
}
EXPECTED = {
    'source/native/bellman_params_callable.hepta': {'f55', 'f56'},
    'worker-source/native/bellman_timed_core.hepta': {'f5', 'f6', 'f7'},
    'worker-source/native/bellman_timed_commitment.hepta': {'f10', 'f11', 'f12', 'f35', 'f36', 'f45', 'f48'},
    'worker-source/native/bellman_result.hepta': {'f85', 'f86'},
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(function):
    f = copy.deepcopy(function)
    f['name'] = 'same'
    return json.dumps(f, sort_keys=True, separators=(',', ':'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['package', 'output', 'hepta', 'support', 'template-source']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    package = args.package.resolve(strict=True)
    output = args.output.resolve()
    assert sha((package / 'PACKAGE.json').read_bytes()) == '2ac7b74d927685ef5c92eb90d6f87590f9e8d492e7e78f047bf417fb9c6c69e6'
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program
    support = load(args.support, '_port_unroll_support')
    author_path = Path(__file__).with_name('author_fixed_byte_access.py')
    proof_path = Path(__file__).with_name('prove_fixed_byte_access.py')
    author = load(author_path, '_port_unroll_templates')
    symbolic = load(proof_path, '_port_unroll_symbolic').symbolic
    template_raw = args.template_source.read_bytes()
    assert sha(template_raw) == '8ccf013c44c6635e131505a628aa3b7732eaae95b0d8b4fae8bdd6b140607840'
    functions = assemble_program(template_raw).as_dict()['functions']
    templates = {canonical(next(f for f in functions if f['name'] == name)): kind for name, kind in
                 [('f18', 'get_mut'), ('f19', 'put_mut'), ('f25', 'get_read')]}
    old_source = {n.name: ast.get_source_segment(author.OLD, n) for n in ast.parse(author.OLD).body}
    unrolled = author.unrolled_source()
    new_source = {n.name: ast.get_source_segment(unrolled, n) for n in ast.parse(unrolled).body}
    generated = {}
    changes = {}
    proofs = []
    for path, expected_sha in PINS.items():
        raw = (package / path).read_bytes()
        assert sha(raw) == expected_sha
        before = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
        matching = {name: templates[canonical(f)] for name, f in before.items() if canonical(f) in templates}
        assert set(matching) == EXPECTED[path], (path, matching)
        aliases = {kind + '_' + name: name for name, kind in matching.items()}
        old_pseudo = '\n\n'.join(old_source[kind].replace('def ' + kind + '(', 'def ' + kind + '_' + name + '(', 1)
                                  for name, kind in matching.items()) + '\n'
        new_pseudo = '\n\n'.join(new_source[kind].replace('def ' + kind + '(', 'def ' + kind + '_' + name + '(', 1)
                                  for name, kind in matching.items()) + '\n'
        _, expected, _ = support.compile_delta(args.hepta, raw, {}, old_pseudo, aliases, {})
        assert all(before[name] == expected[name] for name in matching)
        new_raw, after, retained = support.compile_delta(args.hepta, raw, {}, new_pseudo, aliases, {})
        for name in matching:
            left, right = symbolic(before[name]), symbolic(after[name])
            assert left == right
            proofs.append({'path': path, 'function': name, 'symbolic_checked_memory_trace': left})
        generated[path] = new_raw
        changes[path] = {'before_sha256': sha(raw), 'after_sha256': sha(new_raw), 'after_bytes': len(new_raw),
                         'changed_functions': aliases, 'all_other_function_asts_exact': retained,
                         'old_loop_cfg_exact': True, 'symbolic_checked_memory_and_partial_writes_equal': True,
                         'pseudo': new_pseudo}
    shutil.copytree(package, output)
    for path, raw in generated.items():
        (output / path).write_bytes(raw)
    report = {'schema': 'hepta.runtime.port-worker-byte-helper-delta.v1',
              'baseline_package_sha256': sha((package / 'PACKAGE.json').read_bytes()),
              'package_rebind_pending': True, 'actual_build_pending': True,
              'native_semantics_compared': False, 'fresh_ci_qualified': False,
              'old_package_is_not_relabelled': True,
              'author': {p.name: sha(p.read_bytes()) for p in [Path(__file__), author_path, proof_path, args.support]},
              'changes': changes, 'symbolic_proofs': proofs}
    (output / 'BYTE_HELPER_UNROLL.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'output': str(output), 'changed': {p: {'source_sha256': r['after_sha256'], 'functions': list(r['changed_functions'].values())} for p, r in changes.items()},
                      'symbolically_proved_functions': len(proofs), 'package_rebind_pending': True}))


if __name__ == '__main__':
    main()
