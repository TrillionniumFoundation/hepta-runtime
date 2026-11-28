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
from runtime_mcp_publication_async import combine_async
from text_editor_create_private_pack import pack
from runtime_ssh_generic_source import generic_owner_source, SOURCES as GENERIC_SSH_SOURCES, EXTENSION as GENERIC_SSH_EXTENSION

sha = lambda raw: hashlib.sha256(raw).hexdigest()
BASE = 'scripts/config_mcp_grow_adapter.S'
BOUNDARIES = [
    'scripts/text_publication_callable.S',
    'scripts/publication_worker.S',
    'scripts/runtime_publication_body_bridge.S',
    'scripts/runtime_publication_install.S',
    'scripts/runtime_publication_scope_bridge.S',
    'scripts/runtime_extract_wait.S',
    'scripts/runtime_mcp_task_storage.S',
    'scripts/runtime_mcp_task_extract.S',
    'scripts/runtime_mcp_task_publication.S',
    'scripts/runtime_mcp_task_ssh.S',
    'scripts/runtime_mcp_task_trace.S',
    'scripts/runtime_mcp_task_policy.S',
    'scripts/runtime_mcp_task_worker.S',
    'scripts/runtime_mcp_task_send.S',
    'scripts/runtime_mcp_task_teardown.S',
    'scripts/runtime_extract_body_bridge.S',
    'scripts/runtime_extract_cache_bridge.S',
    'scripts/runtime_extract_install.S',
    'scripts/local_extract_lines_callable.S',
    'scripts/runtime_batch_body_bridge.S',
    'scripts/runtime_batch_cache_bridge.S',
    'scripts/runtime_batch_install.S',
    'scripts/local_batch_body_callable.S',
    'scripts/runtime_mcp_extra_engine.S',
    'scripts/runtime_ssh_generic_worker.S',
    'scripts/runtime_ssh_generic_install.S',
    'scripts/runtime_ssh_file_bridge.S',
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
FIXTURE_BOUNDARIES = ['scripts/runtime_publication_fixture.S',
                      'scripts/runtime_mcp_filesystem_fixture.S',
                      'scripts/runtime_text_body_observer.S',
                      'scripts/runtime_mcp_filesystem_observer.S',
                      'scripts/runtime_mcp_filesystem_front_fixture.S']
TRANSPORT = 'scripts/runtime_mcp_transport.S'
HELPERS = ['scripts/hia_native_runtime_mcp_build.py',
           'scripts/runtime_mcp_publication_async.py',
           'scripts/hia_native_runtime_mcp_adapter.py',
           'scripts/hia_native_runtime_mcp_pack.py',
           'scripts/public_nine_build.py',
           'scripts/text_editor_create_private_pack.py',
           'scripts/runtime_ssh_generic_source.py']
# These names are physical compiled images; selectors in either private engine
# are specified separately. The configuration Value ABI remains an actual,
# separately compiled dependency while the public Value interface uses spans.
MEMBERS = [
    ('owner', 'config_transport_files_owner_span', 'history.v1'),
    ('fs', 'config_fs_span', 'history.v1'),
    ('json', 'config_json_native_files_span', 'history.v1'),
    ('validation', 'config_validation_native_files_span', 'history.v1'),
    ('identity', 'config_identity_native_files', 'history.v1'),
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
    ('catalog', 'runtime_mcp_catalog_filebytes', 'history.v1'),
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
    ('mcp', 'runtime_mcp_filebytes', 'history.v1'),
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
    ('batch_body', 'batch_write', 'batch-write.v1'),
    ('batch_lock', 'file_lock_service', 'batch-plan.v1'),
    ('batch_plan', 'batch_plan', 'batch-plan.v1'),
    ('batch_verify', 'line_verify', 'batch-plan.v1'),
    ('batch_apply', 'batch_apply', 'batch-plan.v1'),
    ('batch_render', 'batch_render', 'batch-write.v1'),
    ('batch_input', 'batch_plan_input', 'history.v1'),
    ('batch_params', 'batch_params', 'history.v1'),
    ('batch_gateway', 'batch_gateway', 'history.v1'),
    ('batch_call', 'batch_call', 'history.v1'),
    ('batch_adapter', 'batch_body_adapter', 'history.v1'),
    ('request_tasks', 'sdk_request_task_registry', 'history.v1'),
    ('extract_gateway', 'extract_gateway', 'history.v1'),
    ('extract_params', 'extract_params', 'history.v1'),
    ('extract_call', 'extract_call', 'history.v1'),
    ('extract_adapter', 'extract_body_adapter', 'history.v1'),
    ('extract_body', 'extract_body', 'history.v1'),
    ('extract_data', 'extract_data', 'history.v1'),
    ('extract_line_verify', 'extract_line_verify', 'history.v1'),
    ('publisher_gateway', 'text_publication_gateway', 'history.v1'),
    ('publisher_params', 'text_file_write_params', 'history.v1'),
    ('publisher_call', 'text_publication_call', 'history.v1'),
    ('publisher_body', 'text_file_publication', 'history.v1'),
    ('publisher_errno', 'directory_errno', 'history.v1'),
    ('publisher_worker', 'publication_worker', 'history.v1'),
    ('binary_write_params', 'binary_write_params', 'history.v1'),
    ('binary_call_plan', 'binary_call_plan', 'history.v1'),
    ('file_gateway', 'filebytes_gateway_v3', 'history.v1'),
    ('file_info_params', 'file_info_params', 'history.v1'),
    ('binary_read_params', 'binary_read_params', 'history.v1'),
    ('file_transport_call', 'file_transport_call', 'history.v1'),
    ('file_transport_policy', 'file_transport_policy_v3', 'history.v1'),
    ('file_transport_result', 'file_transport_result', 'history.v1'),
    ('ssh_child', 'ssh_original_child', 'history.v1'),
    ('ssh_admission', 'ssh_request_admission', 'history.v1'),
    ('ssh_core', 'ssh_shared_owner', 'history.v1'),
    ('ssh_io', 'ssh_capture_io', 'history.v1'),
    ('ssh_future', 'ssh_capture_future', 'history.v1'),
    ('ssh_file_adapter', 'ssh_generic_file_adapter', 'history.v1'),
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
EXTRA = [
    'catalog',
    'admission',
    'gateway',
    'client',
    'params',
    'session_context',
    'session_state',
    'policy',
    'canonical',
    'path_source',
    'wide_value',
    'owner',
    None,
    'workdir_gateway',
    'workdir_params',
    'workdir_io',
    'workdir_render',
    'view_error',
    'mcp',
    'protocol',
    'execution',
    'fs_gateway',
    'fs_params',
    'fs_caller',
    'fs_io',
    'fs_render',
    'fs_guard',
    'fs_fence',
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    'text_call',
    None,
    'text_gateway',
    'text_params',
    'tb_adapter',
    None,
    None,
    'target_message',
    'target_request',
    'target_bridge',
    'historical_protocol',
    'text_constructor',
    'batch_gateway',
    'batch_params',
    'batch_call',
    'batch_adapter',
    'batch_input',
    None,
    'target_shutdown',
    'current_get_info',
    'target_connection',
    None,
]
VIEW = ['view', 'read', 'read', 'read', 'endpoint', 'key', 'scope', 'lease',
        'cache', 'render', 'request_context', 'view_error', 'view_regex',
        'regex_syntax', 'regex_hir', 'regex_nfa', 'regex_match',
        'regex_unicode_data', 'view_regex_diagnostic']
FALSE_FLAGS = ['complete_sdk_frontend', 'whole_view_replaced', 'whole_runtime_replaced',
               'unconstrained_regex_resources_closed', 'full_http_dispatcher_replaced',
               'complete_original_tool_catalog', 'config_execution_capacity_closed',
               'fresh_cold_qualified']

EXTRA.extend([None, 'request_tasks'])
EXTRA.extend(['extract_gateway', 'extract_params', 'extract_call', 'extract_adapter', None])
EXTRA.extend(['publisher_gateway', 'publisher_params', 'publisher_call', None, None])
EXTRA.extend(['binary_write_params', 'binary_call_plan'])
EXTRA.extend(['file_gateway','file_info_params','binary_read_params','file_transport_call',
              'file_transport_policy','file_transport_result',None])
PORT_PACKAGE_SHA256 = '2563acb466285cc6d9fbf3f91508b1ea0785904230263bcdea5866c30f801bb1'


def source_check(root: Path) -> dict:
    path = root / 'native/runtime_mcp_sources.json'
    raw = path.read_bytes()
    binding = json.loads(raw)
    if binding.get('schema') != 'hepta.runtime.public-source-closure.v2':
        raise ValueError('public source-closure schema differs')
    if type(binding.get('sources')) is not dict:
        raise ValueError('public source list must be an object')
    required = {BASE, TRANSPORT, *BOUNDARIES, *FIXTURE_BOUNDARIES, *HELPERS,
                *GENERIC_SSH_SOURCES, GENERIC_SSH_EXTENSION,
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


def adapter_source(root: Path, images=None, *, private_fixture=False,
                   private_pump_fixture=False, private_pump_trace=False,
                   private_publication_trace=False) -> str:
    # images is accepted for older evidence-reader callers; this prefix embeds
    # no image bytes. All fixed addresses are filled by the executed HIA packer.
    if private_fixture:
        if private_pump_fixture or private_pump_trace or private_publication_trace:
            raise ValueError('private instance carrier cannot expose pump observation descriptors')
        transport = '\n'.join((root / name).read_text() for name in FIXTURE_BOUNDARIES)
        fixed = combine((root / BASE).read_text(), transport)
        carrier = [name for name in BOUNDARIES if not name.startswith('scripts/runtime_mcp_task_')]
        source = '\n'.join((root / name).read_text() for name in carrier) + '\n' + fixed
    else:
        if private_publication_trace and not private_pump_trace:
            raise ValueError('publisher observation requires the exact FD3/4 trace entry')
        if private_pump_trace and not private_pump_fixture:
            raise ValueError('fixed trace entry requires the fixed journal fixture')
        transport = (root / TRANSPORT).read_text()
        fixed = combine_async(combine((root / BASE).read_text(), transport))
        if fixed.count('\n_start:\n') != 1:
            raise ValueError('private fixture capability entry anchor differs')
        fixed = fixed.replace('\n_start:\n',
            '\n_start:\n.if PM_FIXED_FIXTURE_FDS\n    call pump_fixture_preflight\n.endif\n', 1)
        source = ('.equ PM_FIXED_FIXTURE_FDS,' + str(int(private_pump_fixture)) + '\n'
                  + '.equ PM_FIXED_TRACE_FD,' + str(int(private_pump_trace)) + '\n'
                  + '\n'.join((root / name).read_text() for name in BOUNDARIES) + '\n' + fixed)
    source = generic_owner_source(root) + '\n' + source
    source = ('.equ PM_FIXED_PUBLICATION_TRACE,' + str(int(private_publication_trace)) + '\n'
              + '.equ RUNTIME_LOCK_WAKE_HOOK,1\n' + source)
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
                      private_fixture: bool = False, private_pump_fixture: bool = False,
                      private_pump_trace: bool = False,
                      private_publication_trace: bool = False,
                      bellman_port_build: Path,
                      bellman_port_package: Path, bellman_worker_build: Path) -> Path:
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
    package = bellman_port_package.resolve(strict=True)
    port_build = bellman_port_build.resolve(strict=True)
    worker_build = bellman_worker_build.resolve(strict=True)
    sys.path.insert(0, str(package / 'recipe'))
    from qualify_port import source_evidence
    from port_build_evidence import verify_build as verify_port_build
    port_sources = source_evidence(package, PORT_PACKAGE_SHA256)
    port_evidence = verify_port_build(port_build, package / 'source', worker_build, package / 'worker-source')
    images['bellman_port'] = port_build / 'bellman-port-packed.elf'
    component = json.loads((root / 'native/bellman_port_component.json').read_bytes())
    port_bytes = images['bellman_port'].read_bytes()
    if component['executable'] != {'bytes': len(port_bytes), 'sha256': sha(port_bytes)}:
        raise ValueError('fixed Bellman capability differs')
    authority_profile = json.loads((root / 'native/caller_owner_export_profile.json').read_bytes())
    authority_names = ['authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader']
    if len(authority_profile['members']) != 9:
        raise ValueError('fixed authority profile member count differs')
    for expected, authority_name in zip(authority_profile['members'], authority_names, strict=True):
        actual = next(row for row in members if row['name'] == authority_name)
        if any(actual[key] != expected[key] for key in ('source_sha256','image_sha256','image_bytes')):
            raise ValueError('fixed authority source/image identity differs: ' + authority_name)
    assembly = adapter_source(root, private_fixture=private_fixture,
                              private_pump_fixture=private_pump_fixture,
                              private_pump_trace=private_pump_trace,
                              private_publication_trace=private_publication_trace)
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
    configuration.update(text_publication_body=images['publisher_body'],
                         text_publication_codec=images['rf_sha'],
                         text_publication_errno=images['publisher_errno'],
                         publication_worker_pool=images['publisher_worker'])
    extra = {slot: images[member] for slot, member in enumerate(EXTRA) if member is not None}
    extra[57] = images['bellman_port']
    view_images = {member: images[member] for member in VIEW}
    physical = {}
    for slot, image in extra.items():
        physical.setdefault(image, []).append('grow_image_' + str(slot))
    for member, source, profile in MEMBERS:
        physical.setdefault(images[member], []).append('member_' + member)
    if (len(physical) != len(MEMBERS) + 1 or len(MEMBERS) != 130
        or list(physical)[-5:] != [images[name] for name in FENCE]):
        raise ValueError('fixed public graph physical images or fence signal range differ')
    elf, link, packed, steps = pack(folder, build, physical, configuration, extra,
                                    view_images, VIEW, execute, root,
                                    create_images=[images[n] for n in ('lc_spec','lc_read','lc_path','lc_mkdir','lc_write','key','cache')],
                                    body_images=[images[n] for n in ('tb_body','lc_read','key','tb_lock','tb_edit','tb_match','tb_history','tb_atomic','cache','tb_render','tb_unlink','view_error')],
                                    authority_images=[images[n] for n in ('authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader')],
                                    batch_images=[images[n] for n in ('batch_body','batch_lock','key','tb_history','tb_atomic','cache','lc_read','tb_lock','tb_edit','batch_plan','endpoint','batch_verify','batch_apply','batch_render')],
                                    extract_images=[images[n] for n in ('extract_body','lc_read','key','tb_lock','tb_edit','extract_data','tb_history','tb_atomic','cache','lc_path','lc_mkdir','view_error','endpoint','extract_line_verify')],
                                    ssh_images=[images[n] for n in ('ssh_child','ssh_admission','ssh_core','ssh_io','ssh_future','ssh_file_adapter')])
    processes.extend(steps)
    binary = folder / ('filesystem-fixture.elf' if private_fixture else 'task-pump-fixture.elf' if private_pump_fixture else 'runtime-mcp.elf')
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
    result = {'schema': 'hepta.runtime.public-task-batch-extract-build.v1', 'status': 'PASS',
              'members': members, 'physical_images': len(physical),
              'runtime_hia_images': len(MEMBERS) + 8,
              'packed_capabilities': {'57': {'sources': port_sources, 'build': port_evidence,
                  'package': str(package), 'build_root': str(port_build),
                  'worker_build_root': str(worker_build), 'runtime_hia_images': 8,
                  'elf_bytes': len(port_bytes), 'elf_sha256': sha(port_bytes)}},
              'task_registry_slot': 58, 'task_registry_operation15_integrated': not private_fixture,
              'task_event_pump_integrated': not private_fixture, 'task_event_pump_qualified': False,
              'private_task_pump_fixture': private_pump_fixture,
              'fixed_journal_fd': 3 if private_pump_fixture else None,
              'private_task_pump_trace': private_pump_trace,
              'fixed_host_trace_fd': 4 if private_pump_trace else None,
              'journal_fd_caller_owned': private_pump_fixture,
              'ordinary_notification_drops_handler_future': False,
              'async_eof_policy_owner': None if private_fixture else 58, 'historical_shutdown53_retained': True,
              'compiler_commit': build.identity['commit'], 'compiler_image_sha256': build.compiler_sha256,
              'source_root': str(root), 'build_root': str(output.resolve()), 'manifest_path': str(manifest.resolve()),
              'elf': binary.name, 'elf_sha256': sha(elf), 'elf_bytes': len(elf),
              'source_binding': binding, 'boundary_sources': {path: binding['files'][path]['sha256'] for path in [BASE, *(FIXTURE_BOUNDARIES if private_fixture else [TRANSPORT]), *(name for name in BOUNDARIES if not private_fixture or not name.startswith('scripts/runtime_mcp_task_'))]},
              'assembled_source_sha256': sha(assembly.encode()), 'object_sha256': sha((folder / 'bridge.o').read_bytes()),
              'link': link, 'pack': packed, 'boundary_processes': processes,
              'config_table': CONFIG, 'extra_table': EXTRA, 'view_table': VIEW, 'fence_table': FENCE,
              'private_instance_fixture': private_fixture, 'fixture_sessions': 2 if private_fixture else None,
              'fixture_pseudo_selectors': [33, 34, 41, 57, 58, 64] if private_fixture else [],
              'authority_slot': 56, 'authority_context_offset': 432,
              'extract_private_slots': [59,60,61,62,63],
              'extract_public_route_registered': True, 'extract_public_route_qualified': False,
              'extract_context_offset': 456, 'extract_install_offset': 464,
              'extract_actual_lock_wait_retention': True,
              'extract_wait_chain_slots': [18,59,61,62,63],
              'extract_wait_uses_actual_hia_reserved_lease': True,
              'extract_wait_future_drop_after_transport_close': True,
              'extract_wait_source_registered_but_qualified': False,
              'extract_shared_hub_offset': 400, 'extract_body_image_count': 14,
              'extract_callable_scope_borrow_maximum': 1048672,
              'extract_local_body_only': True, 'extract_remote_qualified': False,
              'extract_catalog_policy_qualified': False,
              'batch_private_slots': [47,48,49,50,51,52],
              'publication_fixed_descriptors': [64,65,66,67,68],
              'publication_forget_capability': {'slot': 68, 'parent': 66, 'local': 6, 'scope_output_loan': 96},
              'publication_callable_context': 'descriptor67+8',
              'publication_worker_hub_offset': 216,
              'publication_actual_blocking_pool_limit': 512,
              'publication_wait_chain_slots': [18,64,66,67],
              'publication_wait_request_rows': [64,65,66,67,68],
              'publication_pending_node_span': [1184,1896],
              'publication_worker_source': 'native/publication_worker.hepta',
              'publication_worker_source_qualified_independently': True,
              'publication_public_async_qualified': False,
              'publication_worker_observer_fd': 6 if private_publication_trace else None,
              'private_publication_trace': private_publication_trace,
              'publication_borrow_retained_until_parent_delivery': True,
              'publication_gateway_caller_qualified': False,
              'publication_public_route_registered': True,
              'batch_public_route_registered': True, 'batch_public_route_qualified': False,
              'batch_gateway_caller_qualified': False, 'batch_callable_scope_borrow_maximum': 1048672,
              'advertised_catalog_tools': 13,
              'candidate_extra_registered_tools': ['batch_edit', 'weight_bellman_plan'],
              'combined_installed102_task_pump_qualified': False,
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
              'binary_write_params_slot': 69, 'binary_call_plan_slot': 70,
              'binary_owner_private_graph_installed': True, 'public_binary_write_registered': False,
              'binary_write_effects_qualified': False, 'binary_write_audit_qualified': False,
              'binary_write_lifecycle_qualified': False,
              'private_slots': 78, 'private_work_high': 15360, 'private_output_high': 15368,
              'file_gateway_slots': [71,72,73,74,75,76,77],
              'ssh_shared_process_hub_offsets': [224,232],
              'ssh_request_owned_node_span': [1920,2872],
              'file_foreground_hia_route_integrated': True,
              'file_foreground_public_qualified': False,
              'file_observation_pool_qualified': False,
              'ssh_original_nineteen_qualified': False,
              'ssh_retained_original_nineteen_evidence_commit': '0037b4695a925b6c8540c15aa41099c4ce56a5a7',
              'ssh_default_generic_owner_qualified': False,
              'ssh_default_generic_owner_source': 'asm/ssh_direct/runtime.S',
              'ssh_sole_process_instance': True,
              'ssh_api_borrow_contract': 'serialized event-loop; no observer callback',
              'shared_session_slot': 6, 'shared_installed_config_owner_slot': 11,
              'public_frontend_slot': 18, 'protocol_slot': 19,
              'frontend_transport_fixed_input_limit': 16777216, 'frontend_reply_fixed_byte_limit': None,
              'json_nesting_depth_policy': 128, 'result_publication_grows': True,
              'public_configuration_from_stdin': False, 'public_private_instance_selectors': False,
              'actual_fixture_private_selectors': private_fixture,
              'implemented_tools': ['host_list', 'effective_config', 'execution_shadow_admit', 'view', 'workdir',
                                    'directory_create', 'file_move', 'directory_move', 'text_editor', 'extract_lines',
                                    'file_info', 'binary_read'],
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
              'target_text_constructor_source_sha256': '785315acd60821313e4683df67e0b83c59c572d798ad3849efaa3108a9e36d58',
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
              'catalog_source_qualified_separately': False,
              'catalog_target_policy_assets_admitted': True,
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
    parser.add_argument('--bellman-port-build', type=Path, required=True)
    parser.add_argument('--bellman-port-package', type=Path, required=True)
    parser.add_argument('--bellman-worker-build', type=Path, required=True)
    parser.add_argument('--private-filesystem-fixture', action='store_true')
    parser.add_argument('--private-pump-fixture', action='store_true')
    parser.add_argument('--private-pump-trace', action='store_true')
    parser.add_argument('--private-publication-trace', action='store_true')
    args = parser.parse_args()
    reused = json.loads(args.member_manifests_json.read_bytes()) if args.member_manifests_json else None
    print(build_runtime_mcp(args.hepta.resolve(), args.build.resolve(), name=args.name, manifests=reused,
                            private_fixture=args.private_filesystem_fixture,
                            private_pump_fixture=args.private_pump_fixture,
                            private_pump_trace=args.private_pump_trace,
                            private_publication_trace=args.private_publication_trace,
                            bellman_port_build=args.bellman_port_build,
                            bellman_port_package=args.bellman_port_package,
                            bellman_worker_build=args.bellman_worker_build))
