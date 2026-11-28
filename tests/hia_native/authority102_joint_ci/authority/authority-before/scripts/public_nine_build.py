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
from text_editor_create_private_pack import pack

sha = lambda raw: hashlib.sha256(raw).hexdigest()
BASE = 'scripts/config_mcp_grow_adapter.S'
BOUNDARIES = [
    'scripts/runtime_mcp_extra_engine.S',
    'scripts/runtime_mcp_authority_bridge.S',
    'scripts/runtime_text_install.S',
    'scripts/runtime_text_create_bridge.S',
    'scripts/runtime_text_body_bridge.S',
    'scripts/local_text_body_callable.S',
    'scripts/local_create_spec_callable.S',
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
                      'scripts/runtime_text_body_observer.S',
                      'scripts/runtime_mcp_filesystem_observer.S',
                      'scripts/runtime_mcp_filesystem_front_fixture.S']
TRANSPORT = 'scripts/runtime_mcp_transport.S'
HELPERS = ['scripts/hia_native_runtime_mcp_build.py',
           'scripts/hia_native_runtime_mcp_adapter.py',
           'scripts/hia_native_runtime_mcp_pack.py',
           'scripts/public_nine_build.py',
           'scripts/text_editor_create_private_pack.py']
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
    ('catalog', 'runtime_mcp_catalog_ninth', 'history.v1'),
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
    ('protocol', 'sdk_public_protocol', 'sdk-message-target.v1'),
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
    ('text_gateway', 'text_editor_gateway', 'history.v1'),
    ('text_params', 'text_editor_params', 'history.v1'),
    ('text_call', 'text_editor_call', 'history.v1'),
    ('lc_spec', 'local_create_spec', 'history.v1'),
    ('lc_read', 'local_read', 'history.v1'),
    ('lc_path', 'shell_capture_path', 'history.v1'),
    ('lc_mkdir', 'shell_capture_mkdir', 'history.v1'),
    ('lc_write', 'local_create_file', 'history.v1'),
    ('tb_adapter', 'text_editor_local_body', 'history.v1'),
    ('tb_body', 'local_text_body', 'history.v1'),
    ('tb_lock', 'file_lock_state', 'history.v1'),
    ('tb_edit', 'editable_content', 'history.v1'),
    ('tb_match', 'text_replace_match', 'history.v1'),
    ('tb_history', 'history', 'history.v1'),
    ('tb_atomic', 'atomic_write', 'history.v1'),
    ('tb_render', 'text_replace_render', 'history.v1'),
    ('tb_unlink', 'shell_capture_file', 'history.v1'),
    ('target_message', 'sdk_message_target', 'sdk-message-target.v1'),
    ('target_request', 'sdk_request_target', 'serde-json.v1'),
    ('target_bridge', 'sdk_frontend_bridge_target', 'sdk-message-target.v1'),
    ('historical_protocol', 'runtime_mcp_protocol', 'history.v1'),
    ('text_constructor', 'text_result_constructor', 'history.v1'),
    ('current_get_info', 'current_get_info', 'standard'),
    ('target_shutdown', 'sdk_shutdown_target', 'standard'),
    ('target_connection', 'sdk_connection_target', 'history.v1'),
    ('authority', 'caller_authority', 'standard'),
    ('authority_record', 'operation_record', 'standard'),
    ('authority_kdf', 'operation_kdf', 'standard'),
    ('authority_aead', 'operation_aead', 'standard'),
    ('authority_nonce', 'operation_nonce', 'standard'),
    ('authority_scope', 'operation_scope', 'standard'),
    ('authority_entropy', 'entropy_policy', 'standard'),
    ('authority_loader', 'authority_loader', 'standard'),
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
EXTRA = ['catalog', 'admission', 'gateway', 'client', 'params', 'session_context', 'session_state', 'policy', 'canonical', 'path_source', 'wide_value', 'owner', None, 'workdir_gateway', 'workdir_params', 'workdir_io', 'workdir_render', 'view_error', 'mcp', 'protocol', 'execution', 'fs_gateway', 'fs_params', 'fs_caller', 'fs_io', 'fs_render', 'fs_guard', 'fs_fence', None, None, None, None, None, None, None, 'text_call', None, 'text_gateway', 'text_params', 'tb_adapter', None, None, 'target_message', 'target_request', 'target_bridge', 'historical_protocol', 'text_constructor', None, None, None, None, None, None, 'target_shutdown', 'current_get_info', 'target_connection', None]
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
    authority_profile = json.loads((root / 'native/caller_owner_export_profile.json').read_bytes())
    authority_names = ['authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader']
    if len(authority_profile['members']) != 9:
        raise ValueError('fixed authority profile member count differs')
    for expected, authority_name in zip(authority_profile['members'], authority_names, strict=True):
        actual = next(row for row in members if row['name'] == authority_name)
        if any(actual[key] != expected[key] for key in ('source_sha256','image_sha256','image_bytes')):
            raise ValueError('fixed authority source/image identity differs: ' + authority_name)
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
    if (len(physical) != len(MEMBERS) or len(MEMBERS) != 91
        or list(physical)[-5:] != [images[name] for name in FENCE]):
        raise ValueError('fixed public graph physical images or fence signal range differ')
    elf, link, packed, steps = pack(folder, build, physical, configuration, extra,
                                    view_images, VIEW, execute, root,
                                    create_images=[images[n] for n in ('lc_spec','lc_read','lc_path','lc_mkdir','lc_write','key','cache')],
                                    body_images=[images[n] for n in ('tb_body','lc_read','key','tb_lock','tb_edit','tb_match','tb_history','tb_atomic','cache','tb_render','tb_unlink','view_error')],
                                    authority_images=[images[n] for n in ('authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader')])
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
    result = {'schema': 'hepta.runtime.public-nine-build.v1', 'status': 'PASS',
              'members': members, 'physical_images': len(physical),
              'compiler_commit': build.identity['commit'], 'compiler_image_sha256': build.compiler_sha256,
              'source_root': str(root), 'build_root': str(output.resolve()), 'manifest_path': str(manifest.resolve()),
              'elf': binary.name, 'elf_sha256': sha(elf), 'elf_bytes': len(elf),
              'source_binding': binding, 'boundary_sources': {path: binding['files'][path]['sha256'] for path in [BASE, *(FIXTURE_BOUNDARIES if private_fixture else [TRANSPORT]), *BOUNDARIES]},
              'assembled_source_sha256': sha(assembly.encode()), 'object_sha256': sha((folder / 'bridge.o').read_bytes()),
              'link': link, 'pack': packed, 'boundary_processes': processes,
              'config_table': CONFIG, 'extra_table': EXTRA, 'view_table': VIEW, 'fence_table': FENCE,
              'private_instance_fixture': private_fixture, 'fixture_sessions': 2 if private_fixture else None,
              'fixture_pseudo_selectors': [33, 34, 41, 57, 58] if private_fixture else [],
              'authority_slot': 56, 'authority_context_offset': 432,
              'authority_fixed_local_members': ['authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader'],
              'authority_transport_mode': 'stdio', 'authority_public_http_qualified': False,
              'authority_projection_from_current_call': True, 'request_audit_integrated': False,
              'annotation_integrated': False, 'private_descriptor_base': 8192, 'private_engine_bytes': 16384,
              'filesystem_gateway_slot': 21, 'filesystem_caller_slot': 23, 'filesystem_io_slot': 24,
              'filesystem_fence_slot': 27, 'native_fence_slot': 28,
              'view_scope_cache_alias_slots': {'29': 6, '30': 5, '31': 7, '32': 8},
              'config_span_owner_control_offsets': [1024, 1032],
              'config_span_footer_from_capacity': 256,
              'physical_image_members': [next(member for member, image in images.items() if image == path) for path in physical],
              'shared_session_slot': 6, 'shared_installed_config_owner_slot': 11,
              'public_frontend_slot': 18, 'protocol_slot': 19,
              'frontend_transport_fixed_input_limit': 16777216, 'frontend_reply_fixed_byte_limit': None,
              'json_nesting_depth_policy': 128, 'result_publication_grows': True,
              'public_configuration_from_stdin': False, 'public_private_instance_selectors': False,
              'actual_fixture_private_selectors': private_fixture,
              'implemented_tools': ['host_list', 'effective_config', 'execution_shadow_admit', 'view', 'workdir',
                                    'directory_create', 'file_move', 'directory_move', 'text_editor'],
              'filesystem_sdk_semantic_qualification': 'NOT_RUN',
              'runtime_host_semantics': False, 'semantic_qualification': 'NOT_RUN',
              'public_text_editor_route_registered_in_candidate_source': True,
              'public_text_editor_route_qualified': False,
              'target_call_request_projection_integrated': True,
              'target_canonical49_source_integrated': True,
              'target_connection_identity_integrated': True,
              'target_connection_lifecycle_integrated': True,
              'target_connection_slot': 55,
              'target_connection_public_semantics_qualified': False,
              'target_response_owner_integrated': False,
              'target_text_constructor_integrated': True,
              'target_text_constructor_slot': 46,
              'target_text_constructor_source_sha256': '3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d',
              'target_get_info_integrated': True,
              'target_get_info_slot': 54,
              'target_get_info_source_sha256': 'e2c4829a305593938202a5bf00e6411c5f4ba095167ff6a0603882e32fc5c89c',
              'target_get_info_public_handshake_qualified': False,
              'target_constructor_public_semantics_qualified': False,
              'typed_result_publication_uses_raw_owned_mode': True,
              'target_async_transport_integrated': False,
              'target_serial_async_rw_framing_integrated': True,
              'target_eof_shutdown_owner_integrated': True,
              'target_shutdown_slot': 53,
              'target_input_line_limit_includes_lf': True,
              'target_eof_unterminated_tail_discarded': True,
              'target_serial_transport_semantics_qualified': False,
              'native_pending_handler_registry_qualified': False,
              'native_future_cancellation_qualified': False,
              'native_shutdown_timeout_timing_qualified': False,
              'catalog_source_qualified_separately': True,
              'full_sdk_qualified': False, 'full_136_route_qualified': False,
              'production_activated': False, 'old_path_removed': False,
              'private_text_editor_call_slot': 35, 'private_local_create_slot': 36,
              'private_text_editor_gateway_slot': 37, 'private_text_editor_params_slot': 38,
              'private_text_editor_local_body_slot': 39, 'private_local_body_callable_slot': 40,
              'shared_text_history_and_lock_hub': True,
              'complete_async_text_editor_qualified': False,
              'scope_cache_input_window_closed': False,
              'actual_current_session_cache_attachment': True,
              'cancellation_fence_publication_timing_qualified': False,
              'process_wide_statx_cache_qualified': False,
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
