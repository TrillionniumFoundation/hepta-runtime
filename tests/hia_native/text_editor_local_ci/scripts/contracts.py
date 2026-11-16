"""Load only data constructors and read-only comparisons from the frozen qualifier."""
from pathlib import Path
import ast
import copy
import hashlib
import json
import struct

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encode = lambda value: (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
Q = lambda *values: struct.pack('<' + 'Q' * len(values), *values)
U = lambda raw, at: struct.unpack_from('<Q', raw, at)[0]

PURE_HELPERS = ('identities', 'cache_frame', 'legacy_cases', 'cases', 'decode_records', 'canonical_snapshot')
FORBIDDEN_CALLS = {'Popen', 'run', 'call', 'check_call', 'check_output', 'system', 'fork',
                   'exec', 'eval', 'compile', 'open', 'write', 'write_bytes', 'write_text',
                   'mkdir', 'makedirs', 'rmtree', 'remove', 'unlink', 'chmod', 'symlink_to',
                   'invoke', 'invoke_raw', 'NativeModule', 'TypedInput', 'setup_effects', 'execute'}


def definitions(tree):
    counts = {}
    result = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            key = type(node).__name__, node.name
            ordinal = counts.get(key, 0)
            counts[key] = ordinal + 1
            result.append((key[0], key[1], ordinal, node))
    return result


def fingerprint(node):
    return sha(ast.dump(node, include_attributes=False).encode())


def assert_read_only(tree, *, data_constructors=False):
    forbidden = FORBIDDEN_CALLS - ({'call'} if data_constructors else set())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else None)
            assert name not in forbidden, ('non-reader call in selected AST', name)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            assert (isinstance(node, ast.ImportFrom) and node.module == 'qualification_support'
                    and all(item.name in ('observations', 'native_observations') for item in node.names)), ast.dump(node)
        assert not isinstance(node, (ast.With, ast.AsyncWith, ast.Delete)), type(node).__name__


def load(source):
    source = Path(source).resolve(strict=True)
    raw = (source / 'qualify_portable.py').read_bytes()
    proof = json.loads((source / 'source-pins/ast-preservation.json').read_bytes())
    assert sha(raw) == proof['portable_qualifier_sha256']
    tree = ast.parse(raw, filename='qualify_portable.py')
    actual = [{'kind': kind, 'name': name, 'ordinal': ordinal, 'sha256': fingerprint(node)}
              for kind, name, ordinal, node in definitions(tree)]
    assert actual == [{k: row[k] for k in ('kind', 'name', 'ordinal', 'sha256')}
                      for row in proof['definitions']]
    functions = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in (*PURE_HELPERS, 'main'):
            assert node.name not in functions
            functions[node.name] = node
    assert set(functions) == set(PURE_HELPERS) | {'main'}
    helpers = ast.Module(body=[copy.deepcopy(functions[name]) for name in PURE_HELPERS], type_ignores=[])
    assert_read_only(helpers, data_constructors=True)
    main = functions['main']
    first = next(i for i, node in enumerate(main.body) if isinstance(node, ast.Assert)
                 and ast.unparse(node.test) == 'native_files == original_files')
    last = next(i for i, node in enumerate(main.body) if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'summary' for target in node.targets))
    body = copy.deepcopy(main.body[first:last + 1])
    writer = ast.parse("(OUT / 'observations.json').write_bytes(encode(observations))").body[0]
    removed = [node for node in body if ast.dump(node, include_attributes=False) == ast.dump(writer, include_attributes=False)]
    assert len(removed) == 1
    body = [node for node in body if ast.dump(node, include_attributes=False) != ast.dump(writer, include_attributes=False)]
    comparison = ast.Module(body=body, type_ignores=[])
    assert_read_only(comparison)
    configured = next(node for node in main.body if isinstance(node, ast.If)
                      and isinstance(node.test, ast.Name) and node.test.id == 'CONFIGURED')
    config_writer = configured.body[0]
    assert (isinstance(config_writer, ast.Expr) and isinstance(config_writer.value, ast.Call)
            and isinstance(config_writer.value.func, ast.Attribute)
            and config_writer.value.func.attr == 'write_bytes')
    config_expression = ast.Expression(body=copy.deepcopy(config_writer.value.args[0]))
    assert_read_only(config_expression)
    return {'helpers': ast.fix_missing_locations(helpers),
            'comparison': ast.fix_missing_locations(comparison),
            'configuration': ast.fix_missing_locations(config_expression),
            'fingerprints': {'helper_asts_sha256': fingerprint(helpers),
                'comparison_ast_sha256': fingerprint(comparison),
                'configuration_value_ast_sha256': fingerprint(config_expression),
                'removed_side_effect': "(OUT / 'observations.json').write_bytes(encode(observations))",
                'original_qualifier_sha256': sha(raw)}}


def namespace(contract, profile, effects):
    values = {'Path': Path, 'json': json, 'struct': struct, 'sha': sha,
              'encode': encode, 'Q': Q, 'U': U, 'PROFILE': profile,
              'EFFECTS': Path(effects), 'CONFIGURED': profile in ('configured', 'denied'),
              'FENCE_REQUIRED': profile == 'fence_required'}
    exec(compile(contract['helpers'], '<frozen-qualifier-read-only-helpers>', 'exec'), values)
    return values


def ordinary_cases(contract, profile, effects):
    values = namespace(contract, profile, effects)
    return values['cases']()


def configuration_bytes(contract, profile, recorded_profile_directory):
    values = namespace(contract, profile, Path(recorded_profile_directory) / 'effects')
    values['OUT'] = Path(recorded_profile_directory)
    return eval(compile(contract['configuration'], '<frozen-configuration-value>', 'eval'), values)


def compare_saved(contract, values):
    exec(compile(contract['comparison'], '<frozen-qualifier-read-only-comparison>', 'exec'), values)
    return values['summary'], values['observations']
