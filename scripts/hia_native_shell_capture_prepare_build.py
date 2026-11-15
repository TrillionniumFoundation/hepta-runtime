#!/usr/bin/env python3
"""Build a source-bound blocking capture-prepare HIA owner with a fixed syscall bridge."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
DRIVER = "scripts/hia_native_shell_capture_prepare_build.py"
OWNER = "native/shell_capture_prepare.hepta"
PACKER = "native/shell_capture_prepare_packer.hepta"
ADAPTER = "scripts/shell_capture_prepare_adapter.S"
LAYOUT = "native/shell_capture_prepare_layout.json"
REUSE = "native/shell_capture_prepare_reuse.json"
ORIGINAL = "native/shell_capture_path.hepta"
OWNER_NAME, PACKER_NAME = "shell-capture-prepare-owner", "shell-capture-prepare-packer"
SCHEMA = "hepta.runtime.shell-capture-prepare.v1"
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
TREE = "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
B3 = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
DEPENDENCY = "adebfbbab857cd87e9b8f975f522e51b7cd1ed8fd65a8108d29e941651b28b06"
ORIGINAL_SHA = "ce3f9ab277ad16cdcfb27c860fc97203de5dc0790072da5ff5f186632f7c69c2"
ORIGINAL_FUNCTIONS = ("f7", "f8", "f11", "f12", "f13", "f16", "f17", "f18")
CHILDREN = (
    ('path', 'ce3f9ab277ad16cdcfb27c860fc97203de5dc0790072da5ff5f186632f7c69c2',
     '4240f8f4a1baea75d36b6ed6910948ff808124b531eaf490de5d0e5058294c43'),
    ('mkdir', '251b0c83afea0a050c2a71644b2c8e3246c6039888366408c3b98beb17ccaff6',
     'f1f7091305e74c3890cfd5c79f224b1dd58d91579f7da66905fb4ff6b8eb008b'),
    ('file', 'ce286f8758b3a04ef2d71bd3326796c53aa0fb84d74c211591fedcac67ac66f6',
     'e5e95e758e7471e1532e1438579f7388af000eb41f717a19e76029265c54fe76'),
)
MODULE_NAMES = ('prepare', 'path', 'mkdir', 'file')
BACKGROUND = 'src/mcp/fs/background.rs'
BACKGROUND_SHA = '826394f843a0891dfbe8b0b6986dad40d85b53e20a497cb4ddb04838a185f065'
INPUTS = tuple(dict.fromkeys((OWNER, "native/shell_capture_prepare_abi.md", REUSE, ORIGINAL,
    PACKER, ADAPTER, LAYOUT, "native/shell_capture_prepare_fixture.md", DRIVER, BACKGROUND,
    "scripts/hia_native_build.py", "scripts/hia_native_loader.py",
    *(name for key, _, _ in CHILDREN for name in (
      'native/shell_capture_' + key + '.hepta', 'native/shell_capture_' + key + '_abi.md',
      'scripts/hia_native_shell_capture_' + key + '_build.py')))))
INVALID, CAPACITY = 0xffffffff, 0xfffffffe
DRIVER_BYTES = Path(__file__).read_bytes()
RELOCATION = {'f7':'f27', 'f8':'f28', 'f11':'f29', 'f12':'f30', 'f13':'f31', 'f16':'f32', 'f17':'f33', 'f18':'f34'}


def snapshot(root):
    result = {name: ordinary(member(root, name)) for name in INPUTS}
    need(result[DRIVER] == DRIVER_BYTES, 'executing capture-prepare builder differs from source root')
    return result


def scope():
    return {'runtime_python_required': False, 'runtime_libc_required': False,
            'blocking_capture_continuation_only': True,
            'four_independent_hia_images': True, 'unchanged_children_strong_read': True,
            'actual_filesystem_cases_executed_by_build': False,
            'typed_errno_controls_are_actual_os_operations': False,
            'original_rust_compared': False, 'original_async_body_executed': False,
            'typed_ambient_observations': True, 'global_sequence_concurrency_qualified': False,
            'receiver_cleanup_after_take_qualified': False, 'job_construction_qualified': False,
            'glibc_thread_cancellation_qualified': False, 'tokio_cancellation_qualified': False,
            'capture_prepare_qualified': False, 'matching_source_cold_qualified': False,
            'production_activated': False, 'whole_runtime_replaced': False,
            'old_stack_removal_qualified': False}


def relocate_body(raw, mapping):
    def change(match):
        prefix, value = match.groups()
        need(value.decode() in mapping, 'helper call escaped the relocation closure')
        return prefix + mapping[value.decode()].encode()
    return re.sub(rb'(?m)(^fn |"function"\s*:\s*")(f[0-9]+)\b', change, raw)


def reuse_proof(source):
    proof = decode(source[REUSE])
    expected = {'schema': 'hepta.runtime.shell-capture-prepare-reuse.v1',
                'source': ORIGINAL, 'source_sha256': ORIGINAL_SHA, 'target': OWNER,
                'target_sha256': sha(source[OWNER]), 'compiler_commit': COMPILER,
                'private_authoring_generator_required_at_build_or_runtime': False,
                'relocation': RELOCATION, 'derived_functions': []}
    need(sha(source[ORIGINAL]) == ORIGINAL_SHA, 'original capture path source differs')
    same(sorted(proof), sorted([*expected, 'functions', 'frozen_children', 'original_continuation']), 'capture-prepare reuse member set differs')
    for key, value in expected.items():
        same(proof.get(key), value, 'capture-prepare reuse binding differs: ' + key)
    old, new = functions(source[ORIGINAL]), functions(source[OWNER])
    rows = proof.get('functions')
    need(type(rows) is list and len(rows) == len(RELOCATION), 'capture-prepare complete helper set differs')
    checked, seen = [], set()
    for row in rows:
        same(sorted(row), sorted(['original_function', 'new_function', 'original_body', 'new_body',
            'original_body_sha256', 'new_body_sha256', 'only_function_and_call_id_relocation']),
            'capture-prepare helper evidence member set differs')
        before_id, after_id = row['original_function'], row['new_function']
        need(before_id in RELOCATION and after_id == RELOCATION[before_id] and before_id not in seen,
             'capture-prepare helper identity duplicated or changed')
        seen.add(before_id)
        before, after = old[before_id], new[after_id]
        need(row['original_body'].encode() == before and row['new_body'].encode() == after,
             'capture-prepare helper receipt differs from source bytes')
        need(row['original_body_sha256'] == sha(before) and row['new_body_sha256'] == sha(after)
             and row.get('only_function_and_call_id_relocation') is True, 'capture-prepare helper pins differ')
        need(relocate_body(before, RELOCATION) == after, 'capture-prepare helper changed beyond ID relocation')
        checked.append({'original_function': before_id, 'new_function': after_id,
                        'original': pin(before), 'relocated': pin(after)})
    same(sorted(seen), sorted(ORIGINAL_FUNCTIONS), 'capture-prepare helper coverage differs')
    children = []
    for key, source_sha, abi_sha in CHILDREN:
        owner, abi = 'native/shell_capture_' + key + '.hepta', 'native/shell_capture_' + key + '_abi.md'
        need(sha(source[owner]) == source_sha and sha(source[abi]) == abi_sha,
             'frozen capture child source/ABI changed: ' + key)
        children.append({'key': key, 'source': owner, 'source_sha256': source_sha, 'abi': abi,
            'abi_sha256': abi_sha, 'entry': 'f0', 'source_changed': False,
            'executed_by_hia_private_capability': True})
    same(proof.get('frozen_children'), children, 'capture-prepare frozen child source closure differs')
    need(sha(source[BACKGROUND]) == BACKGROUND_SHA, 'original background source changed')
    span = source[BACKGROUND][4420:5134]
    continuation = {'source': BACKGROUND, 'source_sha256': BACKGROUND_SHA, 'start': 4420, 'end': 5134,
        'body': span.decode('utf-8'), 'body_sha256': sha(span),
        'scope': 'Blocking capture continuation after duplicate admission; typed ambient/cache/sequence observations.',
        'job_construction_in_scope': False, 'original_async_body_executed': False}
    same(proof.get('original_continuation'), continuation, 'capture-prepare original continuation differs')
    return {'reuse_manifest_sha256': sha(source[REUSE]), 'complete_helpers': checked,
            'derived_functions': [], 'frozen_children': children,
            'original_continuation': continuation, 'private_authoring_generator_required': False}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def same(actual, expected, message):
    need(encoded(actual) == encoded(expected), message)


def integer(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    def bad(value):
        raise ValueError("nonfinite JSON number: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


def ordinary(path):
    path = Path(path).absolute()
    need(".." not in path.parts, "noncanonical input path")
    for parent in reversed(path.parents):
        need(stat.S_ISDIR(parent.lstat().st_mode), "input parent is not an ordinary directory")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode), "input is not an ordinary file")
        raw = handle.read()
        after = os.fstat(handle.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(before) == identity(after) and len(raw) == before.st_size, "input changed while read")
    return raw


def member(root, name):
    need(type(name) is str and name and not Path(name).is_absolute()
         and all(part not in ("", ".", "..") for part in name.split("/")), "invalid evidence member")
    return Path(root) / name


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)


def functions(raw):
    matches = list(re.finditer(rb"(?m)^fn (f[0-9]+)\(", raw))
    result = {}
    for index, match in enumerate(matches):
        name = match.group(1).decode()
        need(name not in result, "duplicate HIA function")
        end = raw.index(b"\nend\n", match.start()) + 5
        limit = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
        need(end <= limit and not raw[end:limit].strip(), "unexpected bytes between HIA functions")
        result[name] = raw[match.start():end]
    need(result and "f0" in result, "HIA entry missing")
    return result


def native_component(path, source, name):
    value = decode(ordinary(path))
    expected = {"schema": "hepta.runtime.native-module.v1", "name": name,
        "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1", "target": "linux-x86_64",
        "compiler_commit": COMPILER, "compiler_sha256": B3, "source": name + ".hepta",
        "source_sha256": sha(source), "image": "module.image.bin",
        "input_capacity": 8 << 20, "output_capacity": 8 << 20, "workspace_capacity": 32 << 20,
        "qualification": "development_fixed_point", "standalone": None}
    image = ordinary(path.parent / "module.image.bin")
    need(0 < len(image) <= 1 << 20 and not image.startswith(b"\x7fELF"), "native flat image shape differs")
    expected["image_sha256"] = sha(image)
    same(value, expected, "native owner manifest differs")
    need(ordinary(path.parent / (name + ".hepta")) == source, "compiled source snapshot differs")
    built = decode(ordinary(path.parent / "build.json"))
    receipt = decode(ordinary(path.parent / "module.receipt.json"))
    same(receipt, built.get("compile_receipt"), "actual compiler receipt copies differ")
    input_bytes = ordinary(path.parent / "module.input.bin")
    output_bytes = ordinary(path.parent / "module.output.bin")
    need(input_bytes == source and len(output_bytes) >= len(image)
         and output_bytes[:len(image)] == image, "actual compiler input/output bytes differ")
    checks = {"status": "returned", "abi_status": 0, "core_u32": len(image), "result_u64": len(image),
        "source_unchanged": True, "forbidden_compiler_modules_loaded": [], "input_bytes": len(source),
        "input_sha256": sha(source), "artifact_sha256": B3, "image_sha256": B3,
        "format": "flat-x86-64", "produced_bytes": len(image), "produced_sha256": sha(image),
        "output_sha256": sha(output_bytes)}
    for key, expected_value in checks.items():
        same(receipt.get(key), expected_value, "actual native compilation differs: " + key)
    need(built.get("whole_runtime_replaced") is False, "native compilation scope differs")
    bootstrap = path.parent.parent.parent / "bootstrap"
    boot = decode(ordinary(bootstrap / "bootstrap.json"))
    need(boot.get("schema") == "hepta.runtime.native-bootstrap.v1"
         and boot.get("qualification") == "development_fixed_point"
         and boot.get("matching_source_cold_qualified") is False
         and boot.get("generation_sha256") == B3, "fixed compiler bootstrap differs")
    same(boot.get("dependency"), built.get("compiler_dependency"), "compiler dependency receipts differ")
    dependency = boot["dependency"]
    need(dependency.get("commit") == COMPILER and dependency.get("tree") == TREE
         and type(dependency.get("files")) is dict and dependency["files"], "compiler source identity incomplete")
    need(sha(encoded(dependency)) == DEPENDENCY, "fixed compiler complete source closure differs")
    for label in ("B1", "B2", "B3"):
        need(sha(ordinary(bootstrap / (label + ".image.bin"))) == B3, "fixed compiler generation bytes differ")
    return value, {"manifest": pin(ordinary(path)), "image": pin(image),
        "build": pin(ordinary(path.parent / "build.json")),
        "compile_receipt": pin(ordinary(path.parent / "module.receipt.json")),
        "input": pin(input_bytes), "output": pin(output_bytes),
        "bootstrap": pin(ordinary(bootstrap / "bootstrap.json"))}


def import_build_module(root, name, source):
    path = root / ("scripts/" + name + ".py")
    need(ordinary(path) == source, "build module changed before import")
    spec = importlib.util.spec_from_file_location("_capture_" + name, path)
    need(spec is not None and spec.loader is not None, "build module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    # Execute exactly the admitted source bytes, including when a pyc exists.
    exec(compile(source, str(path), 'exec'), module.__dict__)
    need(ordinary(path) == source, "build module changed during import")
    return module


def children_evidence(source_root, source, manifests):
    same(sorted(manifests), sorted(key for key, _, _ in CHILDREN), 'capture-prepare child set differs')
    bindings, images, reports = {}, {}, {}
    for key, expected_source, expected_abi in CHILDREN:
        name = 'hia_native_shell_capture_' + key + '_build'
        module = import_build_module(source_root, name, source['scripts/' + name + '.py'])
        path = Path(manifests[key]).absolute()
        need(path.is_absolute() and path.name == 'manifest.json'
             and path.parent.name == 'shell-capture-' + key, 'capture-prepare child TOP location differs')
        top_raw = ordinary(path)
        evidence = module.read_evidence(path, source_root=source_root)
        need(ordinary(path) == top_raw, 'child TOP changed while its strong reader ran')
        need(evidence.get('status') == 'PASS' and evidence.get('compiler_sha256') == B3,
             'capture-prepare child did not pass its complete fixed-compiler reader: ' + key)
        top = decode(top_raw)
        owner_path = member(path.parent.parent, top['owner_manifest'])
        need(evidence.get('owner_manifest') == str(owner_path), 'child admitted owner path differs')
        owner_raw = ordinary(owner_path)
        need(evidence.get('owner_manifest_sha256') == sha(owner_raw)
             and top['owner_manifest_sha256'] == sha(owner_raw), 'child admitted owner manifest differs')
        source_name = 'native/shell_capture_' + key + '.hepta'
        component, _ = native_component(owner_path, source[source_name], 'shell-capture-' + key + '-owner')
        image = ordinary(member(owner_path.parent, component['image']))
        need(evidence.get('source_sha256') == component['source_sha256'] == expected_source
             and evidence.get('image_sha256') == sha(image), 'child admitted source/image bytes differ')
        build_raw = ordinary(path.parent / 'build-evidence.json')
        reports[key] = decode(build_raw)
        bindings[key] = {'manifest': str(path), 'manifest_pin': pin(top_raw),
            'strong_evidence': evidence, 'owner_manifest': str(owner_path),
            'owner_manifest_sha256': sha(owner_raw), 'owner_image': pin(image),
            'source_sha256': expected_source, 'abi_sha256': expected_abi,
            'build_receipt': pin(build_raw)}
        images[key] = image
    return bindings, images, reports


def verify_child_origins(origins, bindings, child_reports, report, build_root):
    same(sorted(origins), sorted(key for key, _, _ in CHILDREN), 'capture-prepare child origin set differs')
    previous = report['started_ns']
    for key, _, _ in CHILDREN:
        mode = origins[key]
        need(mode in ('fresh', 'provided'), 'capture-prepare child origin differs')
        if mode == 'fresh':
            need(bindings[key]['manifest'] == str(build_root / ('shell-capture-' + key) / 'manifest.json'),
                 'fresh child did not originate in this build root')
            child = child_reports[key]
            need(child['pid'] == report['pid']
                 and child['compiler_source_root'] == report['compiler_source_root']
                 and previous <= child['started_ns']
                 <= child['finished_ns'] <= report['finished_ns'],
                 'fresh child compilation is outside the parent build process/lifetime/order')
            previous = child['finished_ns']
    return previous


def build_children(hepta, build_root, source_root, source, manifests):
    paths, origins = {}, {}
    for key, _, _ in CHILDREN:
        if manifests[key] is None:
            name = 'hia_native_shell_capture_' + key + '_build'
            module = import_build_module(source_root, name, source['scripts/' + name + '.py'])
            paths[key] = getattr(module, 'build_shell_capture_' + key)(hepta, build_root, source_root=source_root)
            origins[key] = 'fresh'
        else:
            paths[key], origins[key] = Path(manifests[key]).absolute(), 'provided'
    return paths, origins


def layout_contract(source):
    value = decode(source[LAYOUT])
    expected = {'schema': 'hepta.runtime.shell-capture-prepare-layout.v1',
        'adapter_entry_offset': 0, 'adapter_relocations': [], 'base_address': 0x400000,
        'elf_header_bytes': 176, 'adapter_source_sha256': sha(source[ADAPTER]),
        'module_names': list(MODULE_NAMES), 'module_alignment': 16}
    for key, item in expected.items():
        same(value.get(key), item, 'capture-prepare adapter layout differs: ' + key)
    need(integer(value.get('adapter_text_bytes'), 16, 1 << 20)
         and value['adapter_text_bytes'] % 16 == 0, 'capture-prepare adapter extent/alignment invalid')
    need(integer(value.get('image_offset'), 192, (1 << 20) + 176)
         and value['image_offset'] == 176 + value['adapter_text_bytes'],
         'capture-prepare adapter image offset invalid')
    need(type(value.get('adapter_text_sha256')) is str
         and re.fullmatch('[0-9a-f]{64}', value['adapter_text_sha256']),
         'capture-prepare adapter text pin invalid')
    need(integer(value.get('module_offset_table_offset'), 176, value['image_offset'] - 32)
         and value['module_offset_table_offset'] % 8 == 0, 'capture-prepare module table is not fully in the aligned prefix')
    same(sorted(value), sorted([*expected, 'image_offset', 'adapter_text_bytes', 'adapter_text_sha256', 'module_offset_table_offset']),
         'capture-prepare layout member set differs')
    return value


def adapter_object(raw, binary, layout):
    need(raw[:16] == b'\x7fELF\x02\x01\x01' + bytes(9) and len(raw) >= 64, 'adapter object is not ELF64')
    h = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
    need(h[0:3] == (1, 62, 1) and h[3:5] == (0, 0) and h[6:10] == (0, 64, 0, 0)
         and h[10] == 64 and 0 < h[11] < 65535 and 0 < h[12] < h[11], 'adapter object header differs')
    table, count = h[5], h[11]
    need(64 <= table <= len(raw) and count <= (len(raw) - table) // 64, 'adapter section table outside file')
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, table + i * 64) for i in range(count)]
    need(sections[0] == (0,) * 10, 'adapter null section differs')
    def content(section):
        start, size = section[4:6]
        need(start <= len(raw) and size <= len(raw) - start, 'adapter section bytes outside object')
        return raw[start:start + size]
    names = content(sections[h[12]])
    def string(raw_table, index):
        need(index < len(raw_table), 'adapter string index outside table')
        end = raw_table.find(b'\0', index)
        need(end >= 0, 'adapter string is unterminated')
        return raw_table[index:end]
    named = {}
    occupied = [(0, 64), (table, table + count * 64)]
    for index, section in enumerate(sections[1:], 1):
        name = string(names, section[0])
        need(name not in named, 'duplicate adapter section')
        named[name] = (index, section)
        if section[1] != 8 and section[5]:
            content(section)
            occupied.append((section[4], section[4] + section[5]))
        need(not (section[1] in (4, 9) and section[5]), 'adapter has unresolved relocations')
        need(not (section[2] & 2 and section[5]) or name == b'.text', 'adapter has additional allocated bytes')
    occupied.sort()
    need(all(a[1] <= b[0] for a, b in zip(occupied, occupied[1:])), 'adapter object file regions overlap')
    need(b'.text' in named and b'.symtab' in named, 'adapter text or symbols absent')
    text_index, text = named[b'.text']
    need(text[1:4] == (1, 6, 0) and content(text) == binary, 'actual assembler text differs from objcopy')
    symbols = named[b'.symtab'][1]
    need(symbols[1] == 2 and symbols[9] == 24 and symbols[5] % 24 == 0
         and 0 < symbols[6] < count and sections[symbols[6]][1] == 3, 'adapter symbol table invalid')
    strings = content(sections[symbols[6]])
    starts, owner_entries, tables = [], [], []
    data = content(symbols)
    for index in range(len(data) // 24):
        name, info, other, section_index, value, size = struct.unpack_from('<IBBHQQ', data, index * 24)
        symbol = string(strings, name)
        if index == 0:
            need((name, info, other, section_index, value, size) == (0, 0, 0, 0, 0, 0), 'adapter null symbol differs')
        else:
            need(section_index != 0, 'adapter has undefined external symbols')
        if symbol == b'_start':
            starts.append((info, other, section_index, value))
        if symbol == b'shell_capture_prepare_entry':
            owner_entries.append((info, other, section_index, value, size))
        if symbol == b'module_offset_table':
            tables.append((info, other, section_index, value, size))
    need(starts == [(0x12, 0, text_index, 0)], 'adapter does not have one global function _start at offset zero')
    need(owner_entries == [(0, 0, text_index, len(binary) - 1, 0)] and binary[-1:] == b'\xcc',
         'capture-prepare owner image label or removed int3 sentinel differs')
    offset = layout['module_offset_table_offset'] - 176
    need(tables == [(0, 0, text_index, offset, 0)] and binary[offset:offset + 32] == bytes(32),
         'capture-prepare unique original zero table or actual assembler offset differs')
    return {'text': pin(binary), 'entry_offset': 0, 'owner_entry_offset': len(binary) - 1,
            'module_offset_table': {'offset': offset, 'elf_offset': offset + 176, 'symbol': list(tables[0]), 'bytes': 32},
            'removed_sentinel': 0xcc, 'relocations': [], 'undefined_symbols': [],
            'only_allocated_section': '.text'}


def module_layout(images):
    need(type(images) is dict and list(images) == list(MODULE_NAMES), 'capture-prepare module order differs')
    offsets, cursor = {}, 0
    for name in MODULE_NAMES:
        image = images[name]
        need(type(image) is bytes and image, 'capture-prepare module image is empty or not bytes')
        cursor = (cursor + 15) & ~15
        offsets[name] = cursor
        cursor += len(image)
        need(cursor < 1 << 64, 'capture-prepare module extent overflow')
    return offsets, cursor


def fixed_elf(raw, adapter, images, layout):
    offsets, extent = module_layout(images)
    need(len(raw) == layout['image_offset'] + extent and layout['image_offset'] == 176 + len(adapter)
         and raw[:16] == b'\x7fELF\x02\x01\x01' + bytes(9),
         'capture-prepare fixed executable extent/identity differs')
    need(struct.unpack_from('<HHIQQQIHHHHHH', raw, 16) ==
         (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0), 'capture-prepare canonical ELF header differs')
    need(struct.unpack_from('<IIQQQQQQ', raw, 64) ==
         (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096), 'capture-prepare unique RX load mapping differs')
    need(struct.unpack_from('<IIQQQQQQ', raw, 120) ==
         (0x6474e551, 6, 0, 0, 0, 0, 0, 16), 'capture-prepare nonexecutable stack differs')
    table_at = layout['module_offset_table_offset'] - 176
    need(adapter[table_at:table_at + 32] == bytes(32), 'capture-prepare original module table is not zero')
    patched = bytearray(adapter)
    struct.pack_into('<4Q', patched, table_at, *(offsets[name] for name in MODULE_NAMES))
    need(raw[176:layout['image_offset']] == patched, 'capture-prepare prefix changed outside the exact HIA-filled table')
    payload = raw[layout['image_offset']:]
    cursor, rows = 0, []
    for name in MODULE_NAMES:
        start, image = offsets[name], images[name]
        need(payload[cursor:start] == bytes(start - cursor) and payload[start:start + len(image)] == image,
             'capture-prepare complete unchanged child image or zero padding differs: ' + name)
        rows.append({'name': name, 'offset': start, 'file_offset': layout['image_offset'] + start,
                     'padding_before': start - cursor, **pin(image)})
        cursor = start + len(image)
    need(cursor == len(payload), 'capture-prepare unregistered final padding or payload bytes')
    return {'elf_type': 'ET_EXEC', 'target': 'linux-x86_64', 'entry': 0x4000b0,
            'program_headers': ['PT_LOAD_RX', 'PT_GNU_STACK_RW'], 'interpreter': None,
            'dynamic_linker': False, 'imports': [], 'bytes': len(raw), 'sha256': sha(raw),
            'module_offset_table_offset': layout['module_offset_table_offset'],
            'module_offsets': offsets, 'modules': rows, 'only_prefix_mutation_bytes': 32}


def tool_specs(folder):
    return [('as', ['--64', '-o', str(folder / 'adapter.o'), str(folder / 'source-snapshots' / ADAPTER)],
             ['source-snapshots/' + ADAPTER], ['adapter.o']),
            ('objcopy', ['-O', 'binary', '-j', '.text', str(folder / 'adapter.o'), str(folder / 'adapter.bin')],
             ['adapter.o'], ['adapter.bin'])]


def tool_identity(path):
    path = Path(path).absolute()
    resolved = path.resolve(strict=True)
    need(os.access(resolved, os.X_OK), 'assembler tool is not executable')
    return {'launch_path': str(path), 'resolved_path': str(resolved), **pin(ordinary(resolved))}


def execute_tool(folder, spec):
    label, arguments, inputs, outputs = spec
    tool = tool_identity(Path('/usr/bin') / label)
    command = [tool['resolved_path'], *arguments]
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC'}
    before = {name: pin(ordinary(folder / name)) for name in inputs}
    target = folder / 'tools'
    target.mkdir(exist_ok=True)
    started, wall = time.monotonic_ns(), time.time_ns()
    error, timed, code, process_id = None, False, None, None
    with (target / (label + '.stdout')).open('xb') as out, (target / (label + '.stderr')).open('xb') as err:
        try:
            process = subprocess.Popen(command, cwd=folder, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            process_id = process.pid
            try:
                code = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                timed = True
                process.kill()
                code = process.wait()
        except Exception as exc:
            error = type(exc).__name__ + ': ' + str(exc)
    finished = time.monotonic_ns()
    receipt = {'schema': 'hepta.runtime.shell-capture-prepare-build-tool.v1', 'label': label,
        'command': command, 'cwd': str(folder), 'environment': env, 'tool_before': tool,
        'tool_after': tool_identity(Path('/usr/bin') / label), 'inputs_before': before,
        'inputs_after': {name: pin(ordinary(folder / name)) for name in inputs},
        'outputs': {name: pin(ordinary(folder / name)) for name in outputs if (folder / name).exists()},
        'pid': process_id, 'started_unix_ns': wall, 'started_ns': started, 'finished_ns': finished,
        'duration_ns': finished - started, 'timeout_seconds': 30, 'timed_out': timed,
        'exit_code': code, 'error': error,
        'stdout': pin(ordinary(target / (label + '.stdout'))),
        'stderr': pin(ordinary(target / (label + '.stderr')))}
    create(target / (label + '.json'), encoded(receipt))
    return read_tool(folder, spec)


def read_tool(folder, spec):
    label, arguments, inputs, outputs = spec
    target = folder / 'tools'
    raw = ordinary(target / (label + '.json'))
    row = decode(raw)
    tool = tool_identity(Path('/usr/bin') / label)
    exact = {'schema': 'hepta.runtime.shell-capture-prepare-build-tool.v1', 'label': label,
        'command': [tool['resolved_path'], *arguments], 'cwd': str(folder),
        'environment': {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC'},
        'tool_before': tool, 'tool_after': tool, 'inputs_before': {name: pin(ordinary(folder / name)) for name in inputs},
        'inputs_after': {name: pin(ordinary(folder / name)) for name in inputs},
        'outputs': {name: pin(ordinary(folder / name)) for name in outputs},
        'timeout_seconds': 30, 'timed_out': False, 'exit_code': 0, 'error': None,
        'stdout': pin(ordinary(target / (label + '.stdout'))),
        'stderr': pin(ordinary(target / (label + '.stderr')))}
    for key, expected in exact.items():
        same(row.get(key), expected, 'actual assembler process differs: ' + label + '/' + key)
    need(integer(row.get('pid'), 1) and integer(row.get('started_unix_ns'), 1)
         and integer(row.get('started_ns'), 1) and integer(row.get('finished_ns'), row['started_ns'])
         and integer(row.get('duration_ns'), 0, 33_000_000_000)
         and row['duration_ns'] == row['finished_ns'] - row['started_ns'], 'assembler process timing invalid')
    need(not ordinary(target / (label + '.stdout')) and not ordinary(target / (label + '.stderr')),
         'assembler emitted unexpected output or diagnostics')
    return {'receipt': pin(raw), 'tool': tool, 'inputs': exact['inputs_before'], 'outputs': exact['outputs'],
            'stdout': exact['stdout'], 'stderr': exact['stderr']}


def packer_wire(images):
    module_layout(images)
    return b'HSCPPK01' + struct.pack('<4Q', *(len(images[name]) for name in MODULE_NAMES)) + b''.join(images[name] for name in MODULE_NAMES)


def packer_specs(images, total):
    wire = packer_wire(images)
    rows = [('success', wire, total + 37, 4096, total),
            ('exact-output', wire, total, 4096, total),
            ('zero-workspace', wire, total + 37, 0, total),
            ('short-output', wire, total - 1, 4096, CAPACITY),
            ('empty-input', b'', total + 37, 4096, INVALID),
            ('short-header', wire[:39], total + 37, 4096, INVALID),
            ('bad-magic', b'X' + wire[1:], total + 37, 4096, INVALID),
            ('trailing-byte', wire + b'x', total + 37, 4096, INVALID)]
    for index, name in enumerate(MODULE_NAMES):
        values = [images[key] if key != name else b'' for key in MODULE_NAMES]
        empty = b'HSCPPK01' + struct.pack('<4Q', *(len(value) for value in values)) + b''.join(values)
        lengths = [len(images[key]) for key in MODULE_NAMES]
        lengths[index] += 1
        mismatch = b'HSCPPK01' + struct.pack('<4Q', *lengths) + wire[40:]
        lengths[index] = (1 << 64) - 1
        overflow = b'HSCPPK01' + struct.pack('<4Q', *lengths) + wire[40:]
        rows.extend([('zero-image-' + name, empty, total + 37, 4096, INVALID),
                     ('length-mismatch-' + name, mismatch, total + 37, 4096, INVALID),
                     ('overflow-length-' + name, overflow, total + 37, 4096, INVALID)])
    rows.append(('all-zero-images', b'HSCPPK01' + bytes(32), total + 37, 4096, INVALID))
    return rows


def guarded(label, raw):
    index = ('input', 'output', 'workspace').index(label)
    return bytes([0xC1 + index]) * 16 + raw + bytes([0xD1 + index]) * 16


def read_packer(folder, manifest, images, executable):
    metadata = decode(ordinary(manifest))
    rows_raw = ordinary(folder / 'packer.json')
    rows = decode(rows_raw)
    specs = packer_specs(images, len(executable))
    need(type(rows) is list and len(rows) == len(specs), 'capture-prepare packer actual case set incomplete')
    prior_end, pid = 0, None
    for index, (row, (name, wire, capacity, workspace, returned)) in enumerate(zip(rows, specs)):
        for key, expected in {'index': index, 'name': name, 'input_capacity': len(wire),
            'output_capacity': capacity, 'workspace_capacity': workspace, 'returned': returned,
            'manifest_sha256': sha(ordinary(manifest)), 'source_sha256': metadata['source_sha256'],
            'image_sha256': metadata['image_sha256']}.items():
            same(row.get(key), expected, 'capture-prepare packer invocation differs: ' + name + '/' + key)
        need(integer(row.get('pid'), 1) and integer(row.get('started_ns'), 1)
             and integer(row.get('finished_ns'), row['started_ns']) and row['started_ns'] >= prior_end,
             'capture-prepare packer process/timing record differs')
        pid = row['pid'] if pid is None else pid
        need(row['pid'] == pid, 'capture-prepare packer process identity changed')
        prior_end = row['finished_ns']
        arrays, files = {}, {}
        for label in ('input', 'output', 'workspace'):
            for phase in ('before', 'after'):
                relative = f'packer/{index:02d}/{label}.{phase}.bin'
                raw = ordinary(folder / relative)
                arrays[label + '_' + phase] = raw
                files[relative] = pin(raw)
        same(row.get('files'), files, 'capture-prepare packer complete array pins differ')
        need(arrays['input_before'] == arrays['input_after'] == guarded('input', wire),
             'capture-prepare packer changed input or its guards')
        need(arrays['workspace_before'] == arrays['workspace_after'] == guarded('workspace', b'\x5c' * workspace),
             'capture-prepare packer changed workspace or its guards')
        need(arrays['output_before'] == guarded('output', b'\xa7' * capacity), 'capture-prepare packer initial output differs')
        expected = executable + b'\xa7' * (capacity - len(executable)) if returned == len(executable) else b'\xa7' * capacity
        need(arrays['output_after'] == guarded('output', expected), 'capture-prepare packer full output, tail or refusal differs')
    return {'invocations': len(rows), 'complete_guarded_arrays': 6 * len(rows), 'receipt': pin(rows_raw),
            'actual_owner_filesystem_operations': 0, 'typed_errno_controls_executed': 0}


def execute_packer(folder, manifest, images, total, loader):
    import ctypes
    metadata = decode(ordinary(manifest))
    manifest_sha = sha(ordinary(manifest))
    rows, executable = [], None
    with loader.NativeModule(manifest, manifest_sha256=manifest_sha) as native:
        for index, (name, wire, capacity, workspace, expected) in enumerate(packer_specs(images, total)):
            values = {'input': wire, 'output': b'\xa7' * capacity, 'workspace': b'\x5c' * workspace}
            arrays, files = {}, {}
            for label, raw in values.items():
                wrapped = guarded(label, raw)
                arrays[label] = (ctypes.c_ubyte * len(wrapped)).from_buffer_copy(wrapped)
                relative = f'packer/{index:02d}/{label}.before.bin'
                create(folder / relative, wrapped)
                files[relative] = pin(wrapped)
            started = time.monotonic_ns()
            with native._lock:
                returned = int(native._entry(ctypes.addressof(arrays['input']) + 16, len(wire),
                    ctypes.addressof(arrays['output']) + 16, capacity,
                    ctypes.addressof(arrays['workspace']) + 16, workspace))
            finished = time.monotonic_ns()
            for label, array in arrays.items():
                relative = f'packer/{index:02d}/{label}.after.bin'
                raw = bytes(array)
                create(folder / relative, raw)
                files[relative] = pin(raw)
            rows.append({'index': index, 'name': name, 'input_capacity': len(wire), 'output_capacity': capacity,
                'workspace_capacity': workspace, 'returned': returned, 'manifest_sha256': manifest_sha,
                'source_sha256': metadata['source_sha256'], 'image_sha256': metadata['image_sha256'],
                'started_ns': started, 'finished_ns': finished, 'pid': os.getpid(), 'files': files})
            (folder / 'packer.json').write_bytes(encoded(rows))
            need(returned == expected, 'actual capture-prepare packer rejected its registered case: ' + name)
            if index == 0:
                executable = bytes(arrays['output'])[16:16 + total]
    need(type(executable) is bytes and len(executable) == total, 'capture-prepare HIA packer produced no complete executable')
    read_packer(folder, manifest, images, executable)
    return executable


def bridge_evidence(folder, source, images, executable):
    layout = layout_contract(source)
    obj, binary = ordinary(folder / 'adapter.o'), ordinary(folder / 'adapter.bin')
    object_info = adapter_object(obj, binary, layout)
    need(len(binary) == layout['image_offset'] - 176 + 1 and binary[-1:] == b'\xcc'
         and (len(binary) - 1) % 16 == 0 and sha(binary[:-1]) == layout['adapter_text_sha256'],
         'capture-prepare assembled bridge differs from its source layout')
    return {'layout_sha256': sha(source[LAYOUT]), 'adapter_source_sha256': sha(source[ADAPTER]),
        'adapter_image_sha256': sha(binary[:-1]), 'adapter_object': pin(obj), 'adapter_binary': pin(binary),
        'object_inspection': object_info, 'elf_inspection': fixed_elf(executable, binary[:-1], images, layout)}


def read_evidence(manifest, *, source_root=ROOT):
    """Read actual source/compiler/tool/packing bytes without executing any image."""
    manifest, source_root = Path(manifest).absolute(), Path(source_root).absolute()
    folder, build_root = manifest.parent, manifest.parent.parent
    need(manifest.name == 'manifest.json' and folder.name == 'shell-capture-prepare', 'capture-prepare TOP location differs')
    raw = ordinary(manifest)
    meta = decode(raw)
    need(meta.get('schema') == SCHEMA and meta.get('status') == 'PASS', 'capture-prepare build incomplete')
    same(meta.get('scope'), scope(), 'capture-prepare build scope differs')
    for key, value in {'target': 'linux-x86_64', 'compiler_commit': COMPILER, 'compiler_sha256': B3,
                       'effect_abi': 'HSHPPFX1', 'fixture_argv': ['--capture-prepare-fixture', 'TRACE_DIRECTORY'],
                       'raw_fd_input_allowed': False, 'typed_pid_observation_input_allowed': True,
                       'elf': 'shell-capture-prepare.elf'}.items():
        same(meta.get(key), value, 'capture-prepare TOP contract differs: ' + key)
    source = snapshot(source_root)
    same(meta.get('source_files'), {name: pin(body) for name, body in source.items()}, 'capture-prepare source closure differs')
    for name, body in source.items():
        need(ordinary(member(folder / 'source-snapshots', name)) == body, 'capture-prepare source snapshot differs: ' + name)
    reuse = reuse_proof(source)
    same(meta.get('reuse_proof'), reuse, 'capture-prepare source reuse proof differs')
    child_paths = {}
    for key, _, _ in CHILDREN:
        value = meta.get(key + '_manifest')
        need(type(value) is str and Path(value).is_absolute(), 'capture-prepare child path must be absolute')
        child_paths[key] = Path(value)
    child_bindings, child_images, child_reports = children_evidence(source_root, source, child_paths)
    for key, _, _ in CHILDREN:
        need(meta.get(key + '_manifest_sha256') == child_bindings[key]['manifest_pin']['sha256'],
             'capture-prepare unchanged child TOP pin differs: ' + key)
    same(meta.get('children'), child_bindings, 'capture-prepare unchanged child evidence differs')
    component_paths, compiled, components = {}, {}, {}
    for label, name, source_name in [('owner', OWNER_NAME, OWNER), ('packer', PACKER_NAME, PACKER)]:
        relative = 'modules/' + name + '/manifest.json'
        need(meta.get(label + '_manifest') == relative, 'capture-prepare child path differs')
        path = build_root / relative
        child, proof = native_component(path, source[source_name], name)
        need(meta.get(label + '_manifest_sha256') == sha(ordinary(path)), 'capture-prepare child manifest pin differs')
        component_paths[label], compiled[label], components[label] = path, proof, child
    for key, expected in {'source_sha256': components['owner']['source_sha256'],
        'owner_source_sha256': components['owner']['source_sha256'],
        'image_sha256': components['owner']['image_sha256'],
        'owner_image_sha256': components['owner']['image_sha256']}.items():
        need(meta.get(key) == expected, 'capture-prepare owner identity differs: ' + key)
    image = ordinary(component_paths['owner'].parent / components['owner']['image'])
    images = {'prepare': image, **child_images}
    offsets, extent = module_layout(images)
    executable_path = folder / 'shell-capture-prepare.elf'
    executable = ordinary(executable_path)
    need(stat.S_IMODE(executable_path.stat().st_mode) == 0o500 and meta.get('elf_sha256') == sha(executable),
         'capture-prepare executable bytes/mode differ')
    bridge = bridge_evidence(folder, source, images, executable)
    same(meta.get('bridge'), bridge, 'capture-prepare source/object/ELF binding differs')
    same(meta.get('image_offset'), decode(source[LAYOUT])['image_offset'], 'capture-prepare embedded owner offset differs')
    same(meta.get('module_offsets'), offsets, 'capture-prepare module offsets differ')
    same(meta.get('module_images'), {name: pin(images[name]) for name in MODULE_NAMES},
         'capture-prepare complete module image set differs')
    need(len(executable) == meta['image_offset'] + extent, 'capture-prepare complete module extent differs')
    tools = {spec[0]: read_tool(folder, spec) for spec in tool_specs(folder)}
    packer = read_packer(folder, component_paths['packer'], images, executable)
    same(meta.get('packer_invocations'), packer['invocations'], 'capture-prepare actual packer case count differs')
    report_raw = ordinary(folder / 'build-evidence.json')
    need(meta.get('build_evidence_sha256') == sha(report_raw), 'capture-prepare actual build receipt pin differs')
    report = decode(report_raw)
    need(report.get('status') == 'PASS' and report.get('error') is None, 'capture-prepare actual build did not complete')
    for key, expected in {'scope': scope(), 'source_files': meta['source_files'], 'compiled': compiled,
                          'tools': tools, 'packer': packer, 'bridge': bridge, 'children': child_bindings,
                          'child_origins': meta.get('child_origins'),
                          'producer_folder': str(folder)}.items():
        same(report.get(key), expected, 'capture-prepare actual build evidence differs: ' + key)
    need(type(report.get('compiler_workspace_preexisted')) is bool
         and integer(report.get('pid'), 1) and integer(report.get('started_ns'), 1)
         and integer(report.get('finished_ns'), report['started_ns']), 'capture-prepare build identity/timing invalid')
    hepta = Path(report['compiler_source_root'])
    need(hepta.is_absolute(), 'capture-prepare compiler source root is not absolute')
    dependency = decode(ordinary(build_root / 'bootstrap/bootstrap.json'))['dependency']
    for name, expected in dependency['files'].items():
        need(sha(ordinary(member(hepta, name))) == expected, 'capture-prepare compiler source bytes changed: ' + name)
    previous = verify_child_origins(report['child_origins'], child_bindings, child_reports, report, build_root)
    for label, *_ in tool_specs(folder):
        row = decode(ordinary(folder / 'tools' / (label + '.json')))
        need(previous <= row['started_ns'] <= row['finished_ns'] <= report['finished_ns'],
             'capture-prepare assembler invocation is outside the build lifetime/order')
        previous = row['finished_ns']
    for row in decode(ordinary(folder / 'packer.json')):
        need(row['pid'] == report['pid'] and previous <= row['started_ns']
             <= row['finished_ns'] <= report['finished_ns'], 'capture-prepare packer entry is outside the build lifetime/order')
        previous = row['finished_ns']
    need(snapshot(source_root) == source and ordinary(manifest) == raw,
         'capture-prepare source or TOP changed during complete read')
    return {'schema': 'hepta.runtime.shell-capture-prepare-read.v1', 'status': 'PASS',
        'manifest_sha256': sha(raw), 'elf_sha256': sha(executable), 'compiler_sha256': B3,
        'owner_manifest': str(component_paths['owner']),
        'owner_manifest_sha256': sha(ordinary(component_paths['owner'])),
        'source_sha256': components['owner']['source_sha256'], 'image_sha256': components['owner']['image_sha256'],
        'packer_manifest': str(component_paths['packer']),
        'packer_manifest_sha256': sha(ordinary(component_paths['packer'])),
        'complete_relocated_helpers': len(RELOCATION), 'derived_functions': [],
        'tool_processes': len(tools), 'module_images': {name: pin(images[name]) for name in MODULE_NAMES},
        'module_offsets': offsets, 'unchanged_child_manifests': 3,
        'fresh_child_builds': sum(mode == 'fresh' for mode in report['child_origins'].values()),
        'provided_child_builds': sum(mode == 'provided' for mode in report['child_origins'].values()),
        'children': child_bindings,
        'packer_checks': packer, **scope()}


def build_shell_capture_prepare(hepta, build_root, *, source_root=ROOT,
                                path_manifest=None, mkdir_manifest=None, file_manifest=None):
    source_root, build_root, hepta = (Path(value).absolute() for value in (source_root, build_root, hepta))
    folder = build_root / 'shell-capture-prepare'
    need(not folder.exists() and not folder.is_symlink(), 'capture-prepare build requires a fresh output folder')
    for name in (OWNER_NAME, PACKER_NAME):
        target = build_root / 'modules' / name
        need(not target.exists() and not target.is_symlink(), 'capture-prepare component output already exists')
    folder.mkdir(parents=True, mode=0o700)
    for parent in (folder, *folder.parents):
        need(stat.S_ISDIR(parent.lstat().st_mode), 'capture-prepare build parent is not an ordinary directory')
    report = {'status': 'RUNNING', 'error': None, 'scope': scope(), 'pid': os.getpid(),
        'started_ns': time.monotonic_ns(), 'compiler_source_root': str(hepta), 'producer_folder': str(folder),
        'compiler_workspace_preexisted': (build_root / 'bootstrap').exists()}
    def save():
        (folder / 'build-evidence.json').write_bytes(encoded(report))
    save()
    try:
        source = snapshot(source_root)
        report['source_files'] = {name: pin(raw) for name, raw in source.items()}
        reuse, layout = reuse_proof(source), layout_contract(source)
        for name, raw in source.items():
            create(member(folder / 'source-snapshots', name), raw)
        save()
        child_paths, child_origins = build_children(hepta, build_root, source_root, source,
            {'path': path_manifest, 'mkdir': mkdir_manifest, 'file': file_manifest})
        child_bindings, child_images, _ = children_evidence(source_root, source, child_paths)
        report['children'], report['child_origins'] = child_bindings, child_origins
        save()
        sys.dont_write_bytecode = True
        build_module = import_build_module(source_root, 'hia_native_build', source['scripts/hia_native_build.py'])
        loader = import_build_module(source_root, 'hia_native_loader', source['scripts/hia_native_loader.py'])
        builder = build_module.NativeBuild(hepta, build_root)
        compiler = builder.bootstrap()
        need(sha(ordinary(compiler)) == B3, 'actual capture-prepare compiler is not the fixed admitted B3')
        paths, components = {}, {}
        report['compiled'] = {}
        for label, name, source_name in [('owner', OWNER_NAME, OWNER), ('packer', PACKER_NAME, PACKER)]:
            path = builder.compile(name, member(folder / 'source-snapshots', source_name), standalone=None)
            need(path == build_root / 'modules' / name / 'manifest.json', 'capture-prepare actual component path differs')
            paths[label] = path
            components[label], report['compiled'][label] = native_component(path, source[source_name], name)
            save()
        report['tools'] = {}
        for spec in tool_specs(folder):
            report['tools'][spec[0]] = execute_tool(folder, spec)
            save()
        image = ordinary(paths['owner'].parent / components['owner']['image'])
        images = {'prepare': image, **child_images}
        offsets, extent = module_layout(images)
        binary = ordinary(folder / 'adapter.bin')
        adapter_object(ordinary(folder / 'adapter.o'), binary, layout)
        need(len(binary) == layout['image_offset'] - 176 + 1 and binary[-1:] == b'\xcc'
             and sha(binary[:-1]) == layout['adapter_text_sha256'], 'capture-prepare actual adapter differs from layout')
        executable = execute_packer(folder, paths['packer'], images, layout['image_offset'] + extent, loader)
        report['packer'] = read_packer(folder, paths['packer'], images, executable)
        report['bridge'] = bridge_evidence(folder, source, images, executable)
        executable_path = folder / 'shell-capture-prepare.elf'
        create(executable_path, executable)
        executable_path.chmod(0o500)
        need(snapshot(source_root) == source, 'capture-prepare source changed during actual build')
        after_bindings, after_images, _ = children_evidence(source_root, source, child_paths)
        same(after_bindings, child_bindings, 'capture-prepare child evidence changed during actual build')
        need(after_images == child_images, 'capture-prepare child images changed during actual build')
        builder._recheck()
        report['status'], report['finished_ns'] = 'PASS', time.monotonic_ns()
        save()
        top = {'schema': SCHEMA, 'status': 'PASS', 'scope': scope(), 'target': 'linux-x86_64',
            'compiler_commit': COMPILER, 'compiler_sha256': B3, 'source_files': report['source_files'],
            'reuse_proof': reuse, 'source_sha256': components['owner']['source_sha256'],
            'owner_source_sha256': components['owner']['source_sha256'],
            'image_sha256': components['owner']['image_sha256'],
            'owner_image_sha256': components['owner']['image_sha256'],
            'elf': executable_path.name, 'elf_sha256': sha(executable), 'image_offset': layout['image_offset'],
            'effect_abi': 'HSHPPFX1', 'fixture_argv': ['--capture-prepare-fixture', 'TRACE_DIRECTORY'],
            'raw_fd_input_allowed': False, 'typed_pid_observation_input_allowed': True,
            'bridge': report['bridge'], 'children': child_bindings, 'child_origins': child_origins,
            'module_offsets': offsets, 'module_images': {name: pin(images[name]) for name in MODULE_NAMES},
            'packer_invocations': report['packer']['invocations'],
            'build_evidence_sha256': sha(ordinary(folder / 'build-evidence.json'))}
        for label, path in paths.items():
            top[label + '_manifest'] = path.relative_to(build_root).as_posix()
            top[label + '_manifest_sha256'] = sha(ordinary(path))
        for key, _, _ in CHILDREN:
            top[key + '_manifest'] = str(child_paths[key])
            top[key + '_manifest_sha256'] = child_bindings[key]['manifest_pin']['sha256']
        manifest = folder / 'manifest.json'
        create(manifest, encoded(top))
        evidence = read_evidence(manifest, source_root=source_root)
        create(folder / 'read-evidence.json', encoded(evidence))
        return manifest
    except BaseException as error:
        report['status'] = 'FAIL'
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['finished_ns'] = time.monotonic_ns()
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--hepta', type=Path)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--read-only', type=Path)
    parser.add_argument('--path-manifest', type=Path)
    parser.add_argument('--mkdir-manifest', type=Path)
    parser.add_argument('--file-manifest', type=Path)
    args = parser.parse_args()
    try:
        if args.read_only is not None:
            need(all(value is None for value in (args.hepta, args.build, args.path_manifest,
                 args.mkdir_manifest, args.file_manifest)), 'read-only does not accept build arguments')
            result = read_evidence(args.read_only, source_root=args.source_root)
        else:
            need(args.hepta is not None and args.build is not None, '--hepta and --build are required')
            manifest = build_shell_capture_prepare(args.hepta, args.build, source_root=args.source_root,
                path_manifest=args.path_manifest, mkdir_manifest=args.mkdir_manifest, file_manifest=args.file_manifest)
            result = {'status': 'PASS', 'manifest': str(manifest),
                      'evidence': read_evidence(manifest, source_root=args.source_root)}
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except BaseException as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__ + ': ' + str(error)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
