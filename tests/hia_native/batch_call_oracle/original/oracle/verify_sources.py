"""Materialize unchanged Batch implementations and explicit observing carriers.

This module never executes an original operation. Semantic replay additionally
requires a complete, strictly admitted native predecessor supplied to run.py.
"""
from pathlib import Path
import hashlib
import re
import tomllib

PINS = {
    'Cargo.lock': '7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43',
    'Cargo.toml': '377e7dca547f0ff0d832fb28cf01862a6d84b4b6ed42c8b36dae9075cbbbb78f',
    'config.rs': '228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35',
    'core.rs': '51c9a864c6b18ac43957cf3e6c74b07d8ee8952e0589b68e1051e976c1dd09ec',
    'delta.rs': 'a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1',
    'effect_owner_fence.rs': '1e2f2cd32289cd93915076981436b79c04a2756dfc184fa219f043a88f907207',
    'line_hash.rs': '904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57',
    'mcp_mod.rs': '9e9b7933372418ef361f85d64a1d36567618b13ae77c45d16df16799231b690c',
    'remote.rs': 'd87cae1d18cfaf3479cc94e0df8c8c6eefe5d2eec34f62b7ba0f0c4693704d8c',
    'remote_unavailable.rs': '727d612dfccd5a7ecd83258f14507f0c97a3d7640c6f7706d5e33a38c4566ad5',
    'request_ctx.rs': '81ebf6e68bcf8c119c83274a090b5e4796d00b3ca6d889c92e9922be0612e943',
    'server.rs': 'ea43d13d2e870188abc33afca771eb3f5ecacdf982a56467c7b7c2fa0fa81d0d',
    'text_editing.rs': 'e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590',
    'truncation.rs': '3967bee0b0a897d470737c64dd735ee8f206c00d87f3778dee212f326334283e',
}


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def block(text, start):
    opening = text.index('{', start)
    depth = 0
    for at in range(opening, len(text)):
        if text[at] == '{':
            depth += 1
        elif text[at] == '}':
            depth -= 1
            if depth == 0:
                return text[start:at + 1]
    raise ValueError('unclosed pinned original item')


def function(text, name):
    found = list(re.finditer(r'(?m)^[ \t]*(?:pub(?:\([^\n]*\))? )?(?:async )?fn '
                            + re.escape(name) + r'\(', text))
    if len(found) != 1:
        raise ValueError(('original function is not unique', name, len(found)))
    return block(text, found[0].start())


def assemble(root):
    root = Path(root)
    raw = {name: (root / 'original' / name).read_bytes() for name in PINS}
    for name, data in raw.items():
        if pin(data)['sha256'] != PINS[name]:
            raise ValueError(('original source changed', name))
    originals = {name: data.decode('utf-8') for name, data in raw.items()}
    server, config, core = [originals[name] for name in ('server.rs', 'config.rs', 'core.rs')]
    parts, origins = {}, {}

    def keep(name, file, text):
        data = text.encode('utf-8')
        if raw[file].count(data) != 1:
            raise ValueError(('nonunique original span', name, file))
        parts[name] = text
        origins[name] = {'file': file, 'offset': raw[file].index(data), **pin(data)}

    keep('mcp_tool_call', 'mcp_mod.rs', block(originals['mcp_mod.rs'], originals['mcp_mod.rs'].index(
        '#[derive(Debug, Clone, Serialize, Deserialize)]\npub struct McpToolCall')))
    keep('session_workdir', 'server.rs', server[server.index('#[derive(Debug)]\npub struct SessionWorkdir'):
        server.index('/// Active `subscriptions/listen`')].rstrip())
    for name in ('ensure_session_workdir', 'enforce_runtime_path_spec', 'append_hints', 'batch_edit',
                 'line_endpoint_schema'):
        keep(name, 'server.rs', function(server, name))
    enum_start = server.index('#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\n#[serde(rename_all = "snake_case")]\npub enum BatchEditOperationType')
    begin = server.index('#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct BatchEditOperation')
    keep('batch_operation_type', 'server.rs', server[enum_start:begin].rstrip())
    end = server.index('#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct ExtractLinesParams')
    keep('batch_params', 'server.rs', server[begin:end].rstrip())
    keep('config_definitions', 'config.rs', config[config.index(
        '#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]'):
        config.index('// The installed value')].rstrip())
    keep('installed_config', 'config.rs', block(config, config.index('struct InstalledRuntimeConfig {')))
    keep('installed_config_new', 'config.rs', function(config[config.index('impl InstalledRuntimeConfig {'):
        config.index('fn default_state_dir')], 'new'))
    begin = config.index('static RUNTIME_CONFIG:')
    keep('runtime_static', 'config.rs', config[begin:config.index('\n', begin)])
    for name in ('default_state_dir', 'runtime_config', 'maybe_runtime_config', 'host_by_alias',
                 'normalize_absolute', 'canonical_policy_path', 'path_under', 'check_local_path',
                 'remote_path_allowed', 'check_remote_path'):
        keep(name, 'config.rs', function(config, name))
    keep('history_store', 'core.rs', core[core.index('// Undo history:'):core.index('// Undo the last edit')].rstrip())
    keep('execute_batch_edit', 'core.rs', function(core, 'execute_batch_edit'))
    template = (root / 'src' / 'driver.rs').read_text()
    for name, value in parts.items():
        token = '@@' + name.upper() + '@@'
        if template.count(token) != 1:
            raise ValueError(('missing or duplicate insertion token', token))
        template = template.replace(token, value)
    if '@@' in template:
        raise ValueError('unexpanded original source token')
    for name, value in parts.items():
        if template.count(value) != 1:
            raise ValueError(('original span no longer intact', name))
    return finish(root, raw, originals, template, origins)


def finish(root, raw, originals, template, origins):
    lock = (root / 'Cargo.lock').read_bytes()
    upstream = tomllib.loads(originals['Cargo.lock'])['package']
    registry = {(p['name'], p['version']): p for p in upstream if 'source' in p}
    packages = tomllib.loads(lock.decode())['package']
    expected_local = {'name': 'hepta-batch-call-original', 'version': '0.1.0', 'dependencies':
        ['anyhow', 'libc', 'rmcp', 'schemars', 'serde', 'serde_json', 'sha2', 'tokio', 'tracing']}
    if [p for p in packages if 'source' not in p] != [expected_local]:
        raise ValueError('unexpected original carrier dependency list')
    if len(packages) != 83 or len({(p['name'], p['version']) for p in packages}) != 83:
        raise ValueError('unexpected dependency closure size')
    for package in packages:
        if 'source' not in package:
            continue
        key = package['name'], package['version']
        if key not in registry or (package['source'], package['checksum']) != (
                registry[key]['source'], registry[key]['checksum']):
            raise ValueError(('not an exact upstream lock entry', key))
        def identities(deps, available):
            result = set()
            for dep in deps:
                words = dep.split()
                matches = [(p['name'], p['version']) for p in available
                           if p['name'] == words[0] and (len(words) == 1 or p['version'] == words[1])]
                if len(matches) != 1:
                    raise ValueError(('ambiguous lock dependency', dep))
                result.add(matches[0])
            return result
        if not identities(package.get('dependencies', []), packages) <= identities(
                registry[key].get('dependencies', []), upstream):
            raise ValueError(('carrier introduced an upstream dependency', key))
    materialized = {'Cargo.toml': (root / 'Cargo.toml').read_bytes(), 'Cargo.lock': lock,
                    'src/main.rs': template.encode('utf-8')}
    whole = {
        'delta.rs': 'src/mcp/fs/original_delta.rs',
        'text_editing.rs': 'src/mcp/fs/text_editing.rs',
        'remote.rs': 'src/mcp/fs/original_remote.rs',
        'remote_unavailable.rs': 'src/mcp/fs/remote_unavailable.rs',
        'request_ctx.rs': 'src/mcp/original_request_ctx.rs',
        'effect_owner_fence.rs': 'src/mcp/runtime/original_effect_owner_fence.rs',
        'line_hash.rs': 'src/utils/line_hash.rs', 'truncation.rs': 'src/utils/truncation.rs',
    }
    additions = {
        'delta.rs': ('', 'delta_observer.rs'),
        'text_editing.rs': ('use crate::observed_tokio as tokio;\n', 'editing_observer.rs'),
        'remote.rs': ('', None),
        'request_ctx.rs': ('', 'context_observer.rs'),
    }
    whole_origins = {}
    for name, destination in whole.items():
        prefix, suffix = additions.get(name, ('', None))
        observer = b'' if suffix is None else b'\n' + (root / 'src' / suffix).read_bytes()
        # The unchanged remote module begins with inner documentation. A later
        # lexical import preserves those bytes and resolves every real Tokio
        # call through the observing delegate without preceding the docs.
        postlude = 'use crate::observed_tokio as tokio;\n' if name == 'remote.rs' else ''
        observer += b'\n' + postlude.encode() if postlude else b''
        body = prefix.encode() + raw[name] + observer
        if body.count(raw[name]) != 1:
            raise ValueError(('whole original module not preserved', name))
        materialized[destination] = body
        whole_origins[name] = {'destination': destination, 'offset': len(prefix.encode()), **pin(raw[name]),
                               'observer_suffix': suffix, 'prelude': prefix, 'postlude': postlude}
    for name in ('observe.rs', 'observed_tokio.rs', 'public_driver.rs'):
        materialized['src/' + name] = (root / 'src' / name).read_bytes()
    return materialized, {
        'schema': 'hepta.runtime.batch-call-original-source.v1',
        'original_files': {name: pin(data) for name, data in raw.items()},
        'unchanged_spans': origins, 'unchanged_whole_modules': whole_origins,
        'materialized': {name: pin(data) for name, data in materialized.items()},
        'registry_dependencies': 82, 'original_full_router_executed': False,
        'configuration_installation_fixture': True, 'original_config_loader_executed': False,
        'remote_fs_feature': False, 'remote_io_executed': False,
        'uninhabited_nonlocal_profiles': ['weight_workers', 'rea_static_profiles', 'hia_worker'],
        'native_hia_executed_by_reference': False,
    }
