#!/usr/bin/env python3
"""Compose pinned source inputs into a new nine-tool candidate checkout.

No input is modified. This script creates source text and verifies ownership
bindings; native and original Rust execution are separate qualification steps.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SHA = lambda data: hashlib.sha256(data).hexdigest()


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('source patch is not unique: ' + old[:100])
    return source.replace(old, new, 1)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def verify_inputs(roots):
    doc = json.loads((ROOT / 'source-pins/input-custody.json').read_bytes())
    for group, record in doc['sources'].items():
        for relative, expected in record['files'].items():
            path = roots[group] / relative
            assert path.is_file() and not path.is_symlink(), path
            raw = path.read_bytes()
            assert expected == {'bytes': len(raw), 'sha256': SHA(raw)}, path
    assert SHA((roots['public8'] / 'source-manifest.json').read_bytes()) == \
        'd234cd39fdf8d2e7f3a1fa394f57c69b0d851742c5321d9d6094021a4c748366'
    return doc


def merge_engine(source):
    source = replace_once(source, '33 rows at engine+4096.',
        '46 rows at engine+4096; slot41 has no public owner.')
    source = replace_once(source, '.equ RG_SLOTS, 41', '.equ RG_SLOTS, 46')
    source = replace_once(source, '    mov edi, 4096\n    cmp ebp, 4\n',
        '    mov edi, 100663296\n    cmp ebp, 42\n'
        '    jb runtime_grow_allocate_ordinary_work\n    cmp ebp, 44\n'
        '    jbe runtime_grow_allocate_work\nruntime_grow_allocate_ordinary_work:\n'
        '    mov edi, 4096\n    cmp ebp, 4\n')
    source = replace_once(source,
        '    mov edi, 4096\n    call view_allocate\n    cmp rax, -4095\n'
        '    jae runtime_grow_resource\n    mov [rbx + 32], rax\n'
        '    mov qword ptr [rbx + 40], 4096\n',
        '    mov edi, 4096\n    cmp ebp, 42\n'
        '    jb runtime_grow_allocate_output_ready\n    cmp ebp, 44\n'
        '    ja runtime_grow_allocate_output_ready\n    mov edi, 67108864\n'
        'runtime_grow_allocate_output_ready:\n    mov [rsp + 24], rdi\n'
        '    call view_allocate\n    cmp rax, -4095\n'
        '    jae runtime_grow_resource\n    mov [rbx + 32], rax\n'
        '    mov rcx, [rsp + 24]\n    mov [rbx + 40], rcx\n')
    source = replace_once(source,
        '    cmp ebp, 19\n    je runtime_grow_protocol_result\n',
        '    cmp ebp, 19\n    je runtime_grow_protocol_result\n'
        '    cmp ebp, 44\n    je runtime_grow_protocol_result\n'
        '    cmp ebp, 45\n    je runtime_grow_protocol_result\n')
    source = replace_once(source, 'runtime_grow_target:\n    cmp edi, 39\n',
        'runtime_grow_target:\n    cmp edi, 19\n'
        '    je runtime_grow_target_sdk_protocol\n    cmp edi, 39\n')
    source = replace_once(source, 'runtime_grow_target_frontend:\n    cmp rsi, 8\n',
        'runtime_grow_target_sdk_protocol:\n    cmp rsi, 3\n'
        '    ja runtime_grow_target_invalid\n'
        '    lea rdx, [rip + runtime_grow_sdk_protocol_targets]\n'
        '    jmp runtime_grow_target_byte\n'
        'runtime_grow_target_frontend:\n    cmp rsi, 9\n')
    source = replace_once(source, '    .ascii "HRMCFA02"\n    .quad 0, 0\n',
        '    .ascii "HRMCFA02"\n    .ascii "HRQPCA01"\n    .quad 0\n')
    source = replace_once(source, '    .ascii "HTLBCA01"\n    .quad 0\n',
        '    .ascii "HTLBCA01"\n    .quad 0\n'
        '    .zero 40 /* Slot41 remains empty; SDK leaves occupy42-45. */\n'
        'runtime_grow_sdk_protocol_targets:\n    .byte 42, 43, 44, 45\n')
    source = replace_once(source,
        'runtime_grow_frontend_targets:\n    .byte 19, 1, 0, 10, 2, 13, 11, 20, 21\n',
        'runtime_grow_frontend_targets:\n    .byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37\n')
    return source


def merge_builder(source):
    source = replace_once(source,
        "    ('catalog', 'runtime_mcp_catalog', 'history.v1'),",
        "    ('catalog', 'runtime_mcp_catalog_ninth', 'history.v1'),")
    source = replace_once(source,
        "    ('protocol', 'runtime_mcp_protocol', 'history.v1'),",
        "    ('protocol', 'sdk_public_protocol', 'sdk-message-target.v1'),")
    source = replace_once(source,
        "    ('rf_owner', 'effect_owner_fence', 'standard'),",
        "    ('target_message', 'sdk_message_target', 'sdk-message-target.v1'),\n"
        "    ('target_request', 'sdk_request_target', 'serde-json.v1'),\n"
        "    ('target_bridge', 'sdk_frontend_bridge_target', 'sdk-message-target.v1'),\n"
        "    ('historical_protocol', 'runtime_mcp_protocol', 'history.v1'),\n"
        "    ('rf_owner', 'effect_owner_fence', 'standard'),")
    assignment = next(n for n in ast.parse(source).body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'EXTRA' for t in n.targets))
    extra = ast.literal_eval(assignment.value)
    assert len(extra) == 41 and extra[39:41] == ['tb_adapter', None]
    extra += [None, 'target_message', 'target_request', 'target_bridge', 'historical_protocol']
    source = replace_once(source, ast.get_source_segment(source, assignment), 'EXTRA = ' + repr(extra))
    source = replace_once(source, "'scripts/text_editor_create_private_build.py',",
        "'scripts/public_nine_build.py',")
    source = replace_once(source, 'or len(MEMBERS) != 75', 'or len(MEMBERS) != 79')
    source = replace_once(source, "'hepta.runtime.text-editor-create-private-build.v1'",
        "'hepta.runtime.public-nine-build.v1'")
    source = replace_once(source,
        "                                    'directory_create', 'file_move', 'directory_move'],",
        "                                    'directory_create', 'file_move', 'directory_move', 'text_editor'],")
    source = replace_once(source,
        "'runtime_host_semantics': False, 'semantic_qualification': 'NOT_RUN', 'public_text_editor_route': False,",
        "'runtime_host_semantics': False, 'semantic_qualification': 'NOT_RUN',\n"
        "              'public_text_editor_route_registered_in_candidate_source': True,\n"
        "              'public_text_editor_route_qualified': False,\n"
        "              'target_call_request_projection_integrated': True,\n"
        "              'target_canonical49_source_integrated': True,\n"
        "              'target_connection_identity_integrated': False,\n"
        "              'target_response_owner_integrated': False,\n"
        "              'target_async_transport_integrated': False,\n"
        "              'catalog_source_qualified_separately': True,\n"
        "              'full_sdk_qualified': False, 'full_136_route_qualified': False,\n"
        "              'production_activated': False, 'old_path_removed': False,")
    return source


def merge_public_lifetime(source):
    source = replace_once(source,
        '    mov [r12 + 232], rax\n    xor ebx, ebx\n',
        '    mov [r12 + 232], rax\n'
        '    call runtime_text_body_hub_create\n    cmp rax, -4095\n'
        '    jae public_span_fail\n    mov [r12 + 224], rax\n    xor ebx, ebx\n')
    source = replace_once(source,
        '    mov [r12 + 240], rax\n    mov rdi, [r12 + 232]\n',
        '    mov [r12 + 240], rax\n    mov rax, [r12 + 224]\n'
        '    mov [r15 + 400], rax\n    mov rdi, [r12 + 232]\n')
    source = replace_once(source,
        'public_span_finish:\n    call runtime_grow_fence_release\n',
        'public_span_finish:\n    call runtime_text_body_release\n'
        '    test rax, rax\n    jnz public_span_fail\n'
        '    call runtime_text_create_release\n    test rax, rax\n'
        '    jnz public_span_fail\n    call runtime_grow_fence_release\n')
    source = replace_once(source,
        '    mov qword ptr [r12 + 240], 0\n    mov rdi, [r12 + 232]\n',
        '    mov qword ptr [r12 + 240], 0\n'
        '    mov rdi, [r12 + 224]\n    call runtime_text_body_hub_destroy\n'
        '    test rax, rax\n    jnz public_span_fail\n'
        '    mov qword ptr [r12 + 224], 0\n    mov rdi, [r12 + 232]\n')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('text-source', 'sdk-source', 'canonical-source', 'ninth-source', 'hepta', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    roots = {'text75': args.text_source.resolve(strict=True),
             'public8': args.sdk_source.resolve(strict=True),
             'canonical49': args.canonical_source.resolve(strict=True),
             'ninth': args.ninth_source.resolve(strict=True)}
    custody = verify_inputs(roots)
    output = args.output.resolve()
    assert not output.exists()
    assert not any(output.is_relative_to(p) for p in roots.values())
    shutil.copytree(roots['text75'], output)
    before = json.loads((output / 'native/runtime_mcp_sources.json').read_bytes())
    changed = {}

    def publish(relative, raw, origin):
        path = output / relative
        old = path.read_bytes() if path.exists() else None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        changed[relative] = {'bytes': len(raw), 'sha256': SHA(raw),
            'before_sha256': None if old is None else SHA(old), 'origin': origin}

    for original, target in (
        ('native/sdk_public_protocol.hepta', 'native/sdk_public_protocol.hepta'),
        ('baseline/sdk_message.hepta', 'native/sdk_message_target.hepta'),
        ('native/sdk_request.hepta', 'native/sdk_request_target.hepta'),
        ('native/sdk_frontend_bridge.hepta', 'native/sdk_frontend_bridge_target.hepta'),
        ('g5/scripts/hia_native_build.py', 'scripts/hia_native_build.py'),
        ('g5/scripts/hia_native_loader.py', 'scripts/hia_native_loader.py'),
    ):
        publish(target, (roots['public8'] / original).read_bytes(), 'public8/' + original)
    for name in ('runtime_mcp_catalog_ninth.hepta', 'runtime_mcp_catalog_ninth_composition.json'):
        publish('native/' + name, (roots['ninth'] / 'native' / name).read_bytes(), 'ninth/native/' + name)
    assert (roots['canonical49'] / 'native/canonical_path.hepta').read_bytes() == \
           (output / 'native/canonical_path.hepta').read_bytes()
    publish('native/canonical_path_composition.json',
        (roots['canonical49'] / 'native/canonical_path_composition.json').read_bytes(),
        'canonical49/native/canonical_path_composition.json')
    publish('scripts/runtime_mcp_extra_engine.S',
        merge_engine((output / 'scripts/runtime_mcp_extra_engine.S').read_text()).encode(),
        'text75 engine plus exact public8 SDK mechanical binding and frontend child9')
    for name, before_bytes in (('runtime_mcp_transport.S', 264),
                               ('runtime_mcp_filesystem_fixture.S', 328)):
        rel = 'scripts/' + name
        source = replace_once((output / rel).read_text(),
            'grow_fixture_images:\n    .zero ' + str(before_bytes),
            'grow_fixture_images:\n    .zero 368')
        if name == 'runtime_mcp_transport.S':
            source = merge_public_lifetime(source)
        publish(rel, source.encode(),
            'text75 image pointer table bytes' + str(before_bytes) + ' to368'
            + (' and actual public TextBody hub lifetime' if name == 'runtime_mcp_transport.S' else ''))
    publish('scripts/public_nine_build.py',
        merge_builder((output / 'scripts/text_editor_create_private_build.py').read_text()).encode(),
        'text75 exact builder with explicit79 members and46 engine descriptors')
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from author_frontend_ninth import author
    proof = author(roots['text75'], output, args.hepta.resolve(strict=True), ROOT / 'scripts')
    for rel in ('native/runtime_mcp.hepta', 'native/runtime_mcp_composition.json'):
        raw = (output / rel).read_bytes()
        changed[rel] = {'bytes': len(raw), 'sha256': SHA(raw),
            'before_sha256': SHA((roots['text75'] / rel).read_bytes()),
            'origin': 'author_frontend_ninth.py and frontend_ninth.pseudo'}
    for rel, row in changed.items():
        before['sources'][rel] = {'bytes': row['bytes'], 'sha256': row['sha256']}
    write_json(output / 'native/runtime_mcp_sources.json', before)
    verify_inputs(roots)
    report = {'schema': 'hepta.runtime.public-nine-source-merge.v1',
        'status': 'SOURCE_GENERATED', 'target_commit': custody['target_commit'],
        'changes': changed, 'frontend': proof,
        'physical_images': 79, 'descriptor_count': 46,
        'unbound_descriptor': 41, 'fixture_observation_action': 41,
        'target_slots': {'message': 42, 'request': 43, 'bridge': 44, 'historical_protocol': 45},
        'input_sources_unchanged': True, 'native_or_rust_executed': False,
        'public_route_qualified': False, 'full_sdk_qualified': False,
        'production_activated': False, 'old_path_removed': False}
    write_json(output.parent / 'source-merge.json', report)
    print(json.dumps({'status': report['status'], 'changes': len(changed),
        'frontend_sha256': proof['source_sha256'], 'native_or_rust_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
