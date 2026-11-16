"""Compile the fixed public HIA graph, link its boundary, then pack all images.

The HIA prefix linker and HIA image packer both execute their actual native
images. Python only supplies build inputs and checks the resulting bytes.
Every runtime source is relative to one checkout. No authoring tree is needed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_runtime_mcp_adapter import combine
from hia_native_runtime_mcp_pack import pack

sha = lambda raw: hashlib.sha256(raw).hexdigest()
BASE = 'scripts/config_mcp_grow_adapter.S'
BOUNDARIES = [
    'scripts/runtime_mcp_extra_engine.S',
    'scripts/view_call_engine.S',
    'scripts/runtime_mcp_workdir_io_bridge.S',
    'scripts/runtime_mcp_canonical_bridge.S',
    'scripts/runtime_mcp_view_bridge.S',
    'scripts/view_call_read_bridge.S',
    'scripts/view_call_key_bridge.S',
    'scripts/view_call_scope_bridge.S',
    'scripts/view_call_regex_bridge.S',
    'scripts/runtime_mcp_execution_bridge.S',
    'scripts/runtime_mcp_filesystem_io_bridge.S',
    'scripts/runtime_mcp_filesystem_view_bridge.S',
    'scripts/runtime_mcp_filesystem_fence_native.S',
    'scripts/runtime_mcp_filesystem_fence_bridge.S',
]
FIXTURE_BOUNDARIES = ['scripts/runtime_mcp_filesystem_fixture.S',
                      'scripts/runtime_mcp_filesystem_observer.S',
                      'scripts/runtime_mcp_filesystem_front_fixture.S']
TRANSPORT = 'scripts/runtime_mcp_transport.S'
HELPERS = ['scripts/hia_native_runtime_mcp_build.py',
           'scripts/hia_native_runtime_mcp_adapter.py',
           'scripts/hia_native_runtime_mcp_pack.py']
# These names are physical compiled images; selectors in either private engine
# are specified separately. The configuration Value ABI remains an actual,
# separately compiled dependency while the public Value interface uses spans.
MEMBERS = [
    ('owner', 'config_directory_owner_span', 'history.v1'),
    ('fs', 'config_fs_span', 'history.v1'),
    ('json', 'config_json_span', 'history.v1'),
    ('validation', 'config_validation_span', 'history.v1'),
    ('identity', 'config_identity', 'history.v1'),
    ('config_mcp', 'config_mcp', 'history.v1'),
    ('execution', 'execution_controller', 'history.v1'),
    ('execution_json', 'execution_json', 'history.v1'),
    ('execution_core', 'execution_shadow', 'history.v1'),
    ('value', 'serde_json', 'history.v1'),
    ('publication', 'result_publication', 'history.v1'),
    ('regex_syntax', 'regex_syntax', 'history.v1'),
    ('regex_unicode_data', 'regex_unicode_data', 'history.v1'),
    ('regex_hir', 'regex_hir', 'history.v1'),
    ('regex_nfa', 'regex_nfa', 'history.v1'),
    ('regex_match', 'regex_match', 'history.v1'),
    ('regex_controller', 'regex_controller', 'history.v1'),
    ('catalog', 'runtime_mcp_catalog', 'history.v1'),
    ('admission', 'runtime_mcp_admission', 'history.v1'),
    ('gateway', 'view_gateway', 'history.v1'),
    ('client', 'client_context', 'history.v1'),
    ('params', 'view_params', 'history.v1'),
    ('session_context', 'session_context', 'history.v1'),
    ('session_state', 'session_workdir', 'history.v1'),
    ('policy', 'local_path_policy', 'history.v1'),
    ('canonical', 'canonical_path', 'history.v1'),
    ('path_source', 'path_source', 'history.v1'),
    ('wide_value', 'serde_json_span', 'history.v1'),
    ('workdir_gateway', 'workdir_gateway', 'history.v1'),
    ('workdir_params', 'workdir_params', 'history.v1'),
    ('workdir_io', 'workdir_io', 'history.v1'),
    ('workdir_render', 'workdir_render', 'history.v1'),
    ('view_error', 'view_error', 'history.v1'),
    ('mcp', 'runtime_mcp', 'history.v1'),
    ('protocol', 'runtime_mcp_protocol', 'history.v1'),
    ('view', 'view_call', 'history.v1'),
    ('endpoint', 'line_endpoint', 'history.v1'),
    ('read', 'view_read', 'history.v1'),
    ('key', 'file_lock_key', 'history.v1'),
    ('scope', 'request_scope_lifecycle', 'history.v1'),
    ('lease', 'request_cache_lease', 'history.v1'),
    ('cache', 'view_cache', 'history.v1'),
    ('render', 'view_render', 'history.v1'),
    ('request_context', 'request_context', 'history.v1'),
    ('view_regex', 'view_regex', 'history.v1'),
    ('view_regex_diagnostic', 'view_regex_diagnostic', 'history.v1'),
    ('fs_gateway', 'filesystem_gateway', 'history.v1'),
    ('fs_params', 'filesystem_params', 'history.v1'),
    ('fs_caller', 'filesystem_call', 'history.v1'),
    ('fs_io', 'filesystem_parity', 'history.v1'),
    ('fs_render', 'filesystem_render', 'history.v1'),
    ('fs_guard', 'directory_move_guard', 'history.v1'),
    ('fs_fence', 'filesystem_fence', 'history.v1'),
    ('rf_owner', 'effect_owner_fence', 'standard'),
    ('rf_fs', 'effect_fence_fs', 'standard'),
    ('rf_json', 'fence_json', 'standard'),
    ('rf_sha', 'binary_codec', 'standard'),
    ('rf_manager', 'effect_fence_manager', 'standard'),
]
FENCE = ['rf_owner', 'rf_fs', 'rf_json', 'rf_sha', 'rf_manager']
CONFIG = ['owner', 'fs', 'json', 'validation', 'identity', 'config_mcp',
          'execution', 'execution_json', 'execution_core', 'value', 'publication',
          'regex_syntax', 'regex_unicode_data', 'regex_hir', 'regex_nfa',
          'regex_match', 'regex_controller']
CONFIG_SYMBOLS = ['owner', 'fs', 'json', 'validation', 'identity', 'mcp',
                  'execution', 'execution_json', 'execution_core', 'value',
                  'publication', 'regex_syntax', 'regex_unicode_data',
                  'regex_hir', 'regex_nfa', 'regex_match', 'regex_controller']
EXTRA = ['catalog', 'admission', 'gateway', 'client', 'params', 'session_context',
         'session_state', 'policy', 'canonical', 'path_source', 'wide_value',
         'owner', None, 'workdir_gateway', 'workdir_params', 'workdir_io',
         'workdir_render', 'view_error', 'mcp', 'protocol', 'execution',
         'fs_gateway', 'fs_params', 'fs_caller', 'fs_io', 'fs_render',
         'fs_guard', 'fs_fence', None, None, None, None, None]
VIEW = ['view', 'read', 'read', 'read', 'endpoint', 'key', 'scope', 'lease',
        'cache', 'render', 'request_context', 'view_error', 'view_regex',
        'regex_syntax', 'regex_hir', 'regex_nfa', 'regex_match',
        'regex_unicode_data', 'view_regex_diagnostic']
FALSE_FLAGS = ['complete_sdk_frontend', 'whole_view_replaced', 'whole_runtime_replaced',
               'unconstrained_regex_resources_closed', 'full_http_dispatcher_replaced',
               'complete_original_tool_catalog', 'config_execution_capacity_closed',
               'fresh_cold_qualified']


def source_check(root: Path) -> dict:
    path = root / 'native/runtime_mcp_sources.json'
    raw = path.read_bytes()
    binding = json.loads(raw)
    if binding.get('schema') != 'hepta.runtime.public-source-closure.v2':
        raise ValueError('public source-closure schema differs')
    if type(binding.get('sources')) is not dict:
        raise ValueError('public source list must be an object')
    required = {BASE, TRANSPORT, *BOUNDARIES, *FIXTURE_BOUNDARIES, *HELPERS,
                'native/runtime_mcp_image_packer.hepta',
                *('native/' + source + '.hepta' for _, source, _ in MEMBERS)}
    if not required <= binding['sources'].keys():
        raise ValueError('public source-closure omits an actual build input')
    for name, expected in binding['sources'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name:
            raise ValueError('public source path escaped checkout')
        source = root / relative
        if any(part.is_symlink() for part in [source, *source.parents] if part != root.parent):
            raise ValueError('public source must not be a symlink')
        if not stat.S_ISREG(source.stat().st_mode):
            raise ValueError('public source must be a regular file')
        data = source.read_bytes()
        if expected != {'bytes': len(data), 'sha256': sha(data)}:
            raise ValueError('public source identity differs: ' + name)
    return {'manifest_sha256': sha(raw), 'files': binding['sources']}


def adapter_source(root: Path, images=None, *, private_fixture=False) -> str:
    # images is accepted for older evidence-reader callers; this prefix embeds
    # no image bytes. All fixed addresses are filled by the executed HIA packer.
    transport = '\n'.join((root / name).read_text() for name in FIXTURE_BOUNDARIES) if private_fixture else (root / TRANSPORT).read_text()
    fixed = combine((root / BASE).read_text(), transport)
    source = '\n'.join((root / name).read_text() for name in BOUNDARIES) + '\n' + fixed
    for name in re.findall(r'^\.global ([A-Za-z_][A-Za-z_0-9]*)$', source, re.M):
        if name == '_start':
            continue
        alias = name + '_flat'
        if '\n' + alias + ':' not in source:
            source = source.replace('\n' + name + ':', '\n' + name + ':\n' + alias + ':')
        source = re.sub(r'\b(call|jmp) ' + re.escape(name) + r'\b',
                        lambda match: match[1] + ' ' + alias, source)
        source = source.replace('[rip + ' + name + ']', '[rip + ' + alias + ']')
    return source


def checked_member(build, root, name, source, profile, manifest):
    raw = manifest.read_bytes()
    data = json.loads(raw)
    image = manifest.parent / data['image']
    source_raw = (root / 'native' / (source + '.hepta')).read_bytes()
    if (data.get('schema') != 'hepta.runtime.native-module.v1'
        or (manifest.parent / data['source']).read_bytes() != source_raw
        or sha(source_raw) != data['source_sha256']
        or sha(image.read_bytes()) != data['image_sha256']
        or data['compiler_commit'] != build.identity['commit']
        or data['compiler_sha256'] != build.compiler_sha256
        or data.get('buffer_profile', 'standard') != profile
        or data.get('standalone') is not None):
        raise ValueError('actual public member differs: ' + name)
    return {'name': name, 'source': 'native/' + source + '.hepta',
            'source_sha256': sha(source_raw), 'manifest': str(manifest),
            'manifest_sha256': sha(raw), 'image_sha256': data['image_sha256'],
            'image_bytes': image.stat().st_size, 'buffer_profile': profile}, image


def build_runtime_mcp(hepta: Path, output: Path, *, name='runtime-mcp',
                      source_root: Path = ROOT, manifests: dict | None = None,
                      private_fixture: bool = False) -> Path:
    root = source_root.resolve(strict=True)
    binding = source_check(root)
    build = NativeBuild(hepta, output)
    build.bootstrap()
    folder = output / name
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    members, images, processes = [], {}, []
    for member, source, profile in MEMBERS:
        reused = manifests is not None and member in manifests
        manifest = Path(manifests[member]).resolve(strict=True) if reused else build.compile(
            name + '-' + member.replace('_', '-'), root / 'native' / (source + '.hepta'),
            standalone=None, buffer_profile=profile)
        row, images[member] = checked_member(build, root, member, source, profile, manifest)
        row['fresh_compile'] = not reused
        members.append(row)
    assembly = adapter_source(root, private_fixture=private_fixture)
    write_new(folder / 'combined.S', assembly.encode())

    def execute(out, label, command, timeout):
        before = time.monotonic()
        timed = False
        with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
            try:
                process = subprocess.run(command, cwd=root, stdout=stdout, stderr=stderr, timeout=timeout)
                code = process.returncode
            except subprocess.TimeoutExpired:
                code, timed = None, True
        receipt = {'name': label, 'command': command, 'cwd': str(root),
                   'timeout_seconds': timeout, 'elapsed_seconds': time.monotonic() - before,
                   'exit_code': code, 'timed_out': timed}
        for stream in ('stdout', 'stderr'):
            data = (out / (label + '.' + stream)).read_bytes()
            receipt[stream] = {'bytes': len(data), 'sha256': sha(data)}
        write_new(out / (label + '.process.json'), json_bytes(receipt))
        if code != 0 or timed:
            raise RuntimeError(label + ' failed; full streams were retained')
        return receipt

    processes.append(execute(folder, 'assemble', ['as', '--64', '-o', str(folder / 'bridge.o'), str(folder / 'combined.S')], 60))
    configuration = {symbol: images[member] for symbol, member in zip(CONFIG_SYMBOLS, CONFIG)}
    configuration.update({name: images[name] for name in FENCE})
    extra = {slot: images[member] for slot, member in enumerate(EXTRA) if member is not None}
    view_images = {member: images[member] for member in VIEW}
    physical = {}
    for slot, image in extra.items():
        physical.setdefault(image, []).append('grow_image_' + str(slot))
    for member, source, profile in MEMBERS:
        physical.setdefault(images[member], []).append('member_' + member)
    if (len(physical) != len(MEMBERS) or len(MEMBERS) != 58
        or list(physical)[-5:] != [images[name] for name in FENCE]):
        raise ValueError('fixed public graph physical images or fence signal range differ')
    elf, link, packed, steps = pack(folder, build, physical, configuration, extra,
                                    view_images, VIEW, execute, root)
    processes.extend(steps)
    binary = folder / ('filesystem-fixture.elf' if private_fixture else 'runtime-mcp.elf')
    write_new(binary, elf, 0o500)
    processes.append(execute(folder, 'readelf', ['readelf', '-lW', str(binary)], 30))
    headers = (folder / 'readelf.stdout').read_bytes()
    if b'INTERP' in headers or b'RWE' in headers or b'GNU_STACK' not in headers:
        raise ValueError('public executable segment permissions differ')
    build._recheck()
    if source_check(root) != binding:
        raise ValueError('source closure changed during the actual build')
    for member, source, profile in MEMBERS:
        old = next(row for row in members if row['name'] == member)
        row, _ = checked_member(build, root, member, source, profile, Path(old['manifest']))
        if any(old[key] != value for key, value in row.items()):
            raise ValueError('public member changed during link')
    manifest = folder / 'manifest.json'
    result = {'schema': 'hepta.runtime.mcp-view-build.v2', 'status': 'PASS',
              'members': members, 'physical_images': len(physical),
              'compiler_commit': build.identity['commit'], 'compiler_image_sha256': build.compiler_sha256,
              'source_root': str(root), 'build_root': str(output.resolve()), 'manifest_path': str(manifest.resolve()),
              'elf': binary.name, 'elf_sha256': sha(elf), 'elf_bytes': len(elf),
              'source_binding': binding, 'boundary_sources': {path: binding['files'][path]['sha256'] for path in [BASE, *(FIXTURE_BOUNDARIES if private_fixture else [TRANSPORT]), *BOUNDARIES]},
              'assembled_source_sha256': sha(assembly.encode()), 'object_sha256': sha((folder / 'bridge.o').read_bytes()),
              'link': link, 'pack': packed, 'boundary_processes': processes,
              'config_table': CONFIG, 'extra_table': EXTRA, 'view_table': VIEW, 'fence_table': FENCE,
              'private_instance_fixture': private_fixture, 'fixture_sessions': 2 if private_fixture else None,
              'fixture_pseudo_selectors': [33, 34] if private_fixture else [],
              'filesystem_gateway_slot': 21, 'filesystem_caller_slot': 23, 'filesystem_io_slot': 24,
              'filesystem_fence_slot': 27, 'native_fence_slot': 28,
              'view_scope_cache_alias_slots': {'29': 6, '30': 5, '31': 7, '32': 8},
              'config_span_owner_control_offsets': [1024, 1032],
              'config_span_footer_from_capacity': 256,
              'physical_image_members': [next(member for member, image in images.items() if image == path) for path in physical],
              'shared_session_slot': 6, 'shared_installed_config_owner_slot': 11,
              'public_frontend_slot': 18, 'protocol_slot': 19,
              'frontend_transport_fixed_input_limit': None, 'frontend_reply_fixed_byte_limit': None,
              'json_nesting_depth_policy': 128, 'result_publication_grows': True,
              'public_configuration_from_stdin': False, 'public_private_instance_selectors': False,
              'actual_fixture_private_selectors': private_fixture,
              'implemented_tools': ['host_list', 'effective_config', 'execution_shadow_admit', 'view', 'workdir',
                                    'directory_create', 'file_move', 'directory_move'],
              'filesystem_sdk_semantic_qualification': 'NOT_RUN',
              'runtime_host_semantics': False, 'semantic_qualification': 'NOT_RUN',
              'elapsed_seconds': time.monotonic() - started,
              **{flag: False for flag in FALSE_FLAGS}}
    write_new(manifest, json_bytes(result))
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--name', default='runtime-mcp')
    parser.add_argument('--member-manifests-json', type=Path)
    parser.add_argument('--private-filesystem-fixture', action='store_true')
    args = parser.parse_args()
    reused = json.loads(args.member_manifests_json.read_bytes()) if args.member_manifests_json else None
    print(build_runtime_mcp(args.hepta.resolve(), args.build.resolve(), name=args.name, manifests=reused,
                            private_fixture=args.private_filesystem_fixture))
