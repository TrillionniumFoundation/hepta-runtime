"""Unchanged filesystem methods and their actual SDK/session/policy/effect closure."""
from pathlib import Path
import hashlib
import json
import re
import tomllib

PINS = {
 'Cargo.lock': '7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43',
 'Cargo.toml': '377e7dca547f0ff0d832fb28cf01862a6d84b4b6ed42c8b36dae9075cbbbb78f',
 'config.rs': '228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35',
 'current_canonical_policy.rs': '75a95e0376eb2ebf92f4dbbc0f8d93cbe4aa53ae35c78aa144589d226bf9c7c6',
 'delta.rs': 'a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1',
 'effect_owner_fence.rs': '1e2f2cd32289cd93915076981436b79c04a2756dfc184fa219f043a88f907207',
 'mcp_mod.rs': '9e9b7933372418ef361f85d64a1d36567618b13ae77c45d16df16799231b690c',
 'parity_ops.rs': '0e608303d16c22b95dc99bae2e6bb00ba0571872f52d15a7fe8e2f021286ccc1',
 'remote.rs': 'd87cae1d18cfaf3479cc94e0df8c8c6eefe5d2eec34f62b7ba0f0c4693704d8c',
 'request_ctx.rs': '81ebf6e68bcf8c119c83274a090b5e4796d00b3ca6d889c92e9922be0612e943',
 'server.rs': 'ea43d13d2e870188abc33afca771eb3f5ecacdf982a56467c7b7c2fa0fa81d0d',
 'text_editing.rs': 'e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590'}


def pin(raw): return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def block(text, start):
    opening = text.index('{', start); depth = 0
    for at in range(opening, len(text)):
        if text[at] == '{': depth += 1
        elif text[at] == '}':
            depth -= 1
            if depth == 0: return text[start:at+1]
    raise AssertionError('unclosed original block')


def function(text, name):
    matches = list(re.finditer(r'(?m)^[ \t]*(?:pub(?:\([^\n]*\))? )?(?:async )?fn '+re.escape(name)+r'\(', text))
    assert len(matches) == 1, name
    return block(text, matches[0].start())


def subset_lock(root, originals):
    raw = (root/'Cargo.lock').read_bytes()
    assert pin(raw) == {'bytes': 19713, 'sha256': 'f8230631dd6c8095bcca8e30d388450750171cb08e5c386798444610cbed24e1'}
    all_packages = tomllib.loads(originals['Cargo.lock'])['package']
    registry = {(p['name'], p['version']): p for p in all_packages if 'source' in p}
    packages = tomllib.loads(raw.decode())['package']
    assert len(packages) == 83 and len({(p['name'], p['version']) for p in packages}) == 83
    local = {'name': 'hepta-filesystem-sdk-original', 'version': '0.1.0',
             'dependencies': ['anyhow', 'libc', 'rmcp', 'schemars', 'serde', 'serde_json', 'sha2', 'tokio', 'tracing']}
    assert [p for p in packages if 'source' not in p] == [local]
    for item in packages:
        if 'source' not in item: continue
        key = item['name'], item['version']; assert key in registry
        assert (item['source'], item['checksum']) == (registry[key]['source'], registry[key]['checksum']), key
    return raw, 82


def assemble(root):
    root = Path(root); original_raw = {name: (root/'original'/name).read_bytes() for name in PINS}
    for name, raw in original_raw.items(): assert pin(raw)['sha256'] == PINS[name], name
    originals = {name: raw.decode() for name, raw in original_raw.items()}
    server, config, remote, delta, editing = [originals[name] for name in ('server.rs', 'config.rs', 'remote.rs', 'delta.rs', 'text_editing.rs')]
    parts = {}; origins = {}
    def keep(name, file, value):
        assert originals[file].count(value) == 1, name
        parts[name] = value; origins[name] = {'file': file, 'offset': original_raw[file].index(value.encode()), **pin(value.encode())}
    keep('mcp_tool_call', 'mcp_mod.rs', block(originals['mcp_mod.rs'], originals['mcp_mod.rs'].index('#[derive(Debug, Clone, Serialize, Deserialize)]\npub struct McpToolCall')))
    keep('session_workdir', 'server.rs', server[server.index('#[derive(Debug)]\npub struct SessionWorkdir'):server.index('/// Active `subscriptions/listen`')].rstrip())
    for name in ('ensure_session_workdir', 'enforce_runtime_path_spec', 'append_hints', 'directory_create', 'file_move', 'directory_move'):
        keep(name, 'server.rs', function(server, name))
    for name in ('DirectoryCreateParams', 'FileMoveParams', 'DirectoryMoveParams'):
        marker = '#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct '+name
        keep(name, 'server.rs', block(server, server.index(marker)))
    keep('path_source', 'remote.rs', remote[remote.index('#[derive(Debug, Clone)]\npub enum PathSource'):remote.index('// ── SFTP connection pool')].rstrip())
    keep('config_definitions', 'config.rs', config[config.index('#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]'):config.index('// The installed value')].rstrip())
    keep('installed_config', 'config.rs', block(config, config.index('struct InstalledRuntimeConfig {')))
    keep('installed_config_new', 'config.rs', function(config[config.index('impl InstalledRuntimeConfig {'):config.index('fn default_state_dir')], 'new'))
    start = config.index('static RUNTIME_CONFIG:'); keep('runtime_static', 'config.rs', config[start:config.index('\n', start)])
    for name in ('default_state_dir', 'runtime_config', 'maybe_runtime_config', 'host_by_alias', 'normalize_absolute',
                 'canonical_policy_path', 'path_under', 'check_local_path', 'remote_path_allowed', 'check_remote_path',
                 'check_directory_move_against_roots', 'check_directory_move_source'):
        if name == 'canonical_policy_path':
            keep(name, 'current_canonical_policy.rs', function(originals['current_canonical_policy.rs'], name))
        else:
            keep(name, 'config.rs', function(config, name))
    keep('view_cache', 'delta.rs', block(delta, delta.index('#[derive(Debug, Default)]\npub struct ViewCache')))
    keep('view_cache_impl', 'delta.rs', block(delta, delta.index('impl ViewCache {')))
    keep('max_cached_bytes', 'delta.rs', next(line for line in delta.splitlines() if line.startswith('const MAX_CACHED_BYTES:')))
    for name in ('normalize', 'note_create', 'forget', 'forget_subtree'):
        # The public wrappers are unique when the impl block is excluded.
        text = delta[delta.index('/// Line-ending agnostic'):]
        keep('delta_'+name, 'delta.rs', function(text, name))
    for name in ('lock_key_for', 'lock_key_for_source'): keep(name, 'text_editing.rs', function(editing, name))
    main = (root/'src/driver.rs').read_text()
    for name, value in parts.items():
        token = '@@'+name.upper()+'@@'; assert main.count(token) == 1, token
        main = main.replace(token, value)
    assert '@@' not in main
    for name, value in parts.items(): assert main.count(value) == 1, name
    selected = original_raw['current_canonical_policy.rs']
    assert hashlib.sha1(b'blob ' + str(len(selected)).encode() + b'\0' + selected).hexdigest() == '52edc1b2301eaaf12f4aea6e160346be2eed1054'
    assert origins['canonical_policy_path']['sha256'] == '9c8595c09bde097c0ed2ffd1654cd43aad89205e5a99aa26ded05cb47dcb55ab'
    lock, dependencies = subset_lock(root, originals)
    materialized = {'src/main.rs': main.encode(), 'Cargo.toml': (root/'Cargo.toml').read_bytes(), 'Cargo.lock': lock,
        'src/mcp/request_ctx.rs': original_raw['request_ctx.rs'],
        'src/mcp/fs/original_parity_ops.rs': original_raw['parity_ops.rs'],
        'src/mcp/runtime/original_effect_owner_fence.rs': original_raw['effect_owner_fence.rs']}
    return materialized, {'schema': 'hepta.runtime.filesystem-sdk-original-source.v1',
        'original_files': {name: pin(raw) for name, raw in original_raw.items()}, 'unchanged_spans': origins,
        'canonical_policy_target_commit': 'd3d75c30719db966b004756f610007a7c723729e',
        'canonical_policy_target_git_blob': '52edc1b2301eaaf12f4aea6e160346be2eed1054',
        'other_historical_sdk_and_config_functions_unchanged': True,
        'unchanged_whole_modules': ['request_ctx.rs', 'parity_ops.rs', 'effect_owner_fence.rs'],
        'materialized': {name: pin(raw) for name, raw in materialized.items()}, 'registry_dependencies': dependencies,
        'actual_sdk_parameters_extractor': True, 'actual_sdk_method_adapter': True, 'original_full_router_executed': False,
        'configuration_installation_fixture': True, 'original_config_loader_executed': False,
        'remote_io_executed': False, 'native_hia_executed': False}
