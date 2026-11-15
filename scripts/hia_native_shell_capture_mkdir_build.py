#!/usr/bin/env python3
"""Build a source-bound blocking mkdir HIA owner with a fixed syscall bridge."""
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
ROOT = Path(__file__).resolve().parents[1]
DRIVER = "scripts/hia_native_shell_capture_mkdir_build.py"
OWNER = "native/shell_capture_mkdir.hepta"
PACKER = "native/shell_capture_mkdir_packer.hepta"
ADAPTER = "scripts/shell_capture_mkdir_adapter.S"
LAYOUT = "native/shell_capture_mkdir_layout.json"
REUSE = "native/shell_capture_mkdir_reuse.json"
ORIGINAL = "native/shell_capture_path.hepta"
OWNER_NAME, PACKER_NAME = "shell-capture-mkdir-owner", "shell-capture-mkdir-packer"
SCHEMA = "hepta.runtime.shell-capture-mkdir.v1"
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
TREE = "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
B3 = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
DEPENDENCY = "adebfbbab857cd87e9b8f975f522e51b7cd1ed8fd65a8108d29e941651b28b06"
ORIGINAL_SHA = "ce3f9ab277ad16cdcfb27c860fc97203de5dc0790072da5ff5f186632f7c69c2"
ORIGINAL_FUNCTIONS = ("f2", "f4", "f5", "f16", "f17", "f18")
INPUTS = (OWNER, "native/shell_capture_mkdir_abi.md", REUSE, ORIGINAL, PACKER, ADAPTER,
          LAYOUT, "native/shell_capture_mkdir_fixture.md", DRIVER,
          "scripts/hia_native_build.py", "scripts/hia_native_loader.py")
INVALID, CAPACITY = 0xffffffff, 0xfffffffe
DRIVER_BYTES = Path(__file__).read_bytes()
RELOCATION = {'f2': 'f14', 'f4': 'f15', 'f5': 'f16', 'f16': 'f17', 'f17': 'f18', 'f18': 'f19'}
DERIVED_ALPHA = {'v2': 'v3', 'v11': 'v4', 'v12': 'v10', 'v13': 'v11', 'v14': 'v12',
                 'v15': 'v13', 'v16': 'v15', 'v19': 'v18', 'v20': 'v19'}


def snapshot(root):
    result = {name: ordinary(member(root, name)) for name in INPUTS}
    need(result[DRIVER] == DRIVER_BYTES, 'executing mkdir builder differs from source root')
    return result


def scope():
    return {'runtime_python_required': False, 'runtime_libc_required': False,
            'blocking_leaf_only': True, 'actual_filesystem_cases_executed_by_build': False,
            'typed_errno_controls_are_actual_os_operations': False,
            'original_rust_compared': False, 'global_metadata_cache_concurrency_qualified': False,
            'tokio_cancellation_qualified': False, 'capture_prepare_qualified': False,
            'matching_source_cold_qualified': False, 'production_activated': False,
            'whole_runtime_replaced': False, 'old_stack_removal_qualified': False}


def relocate_body(raw, mapping):
    def change(match):
        prefix, value = match.groups()
        need(value.decode() in mapping, 'helper call escaped the relocation closure')
        return prefix + mapping[value.decode()].encode()
    return re.sub(rb'(?m)(^fn |"function"\s*:\s*")(f[0-9]+)\b', change, raw)


def reuse_proof(source):
    proof = decode(source[REUSE])
    need(proof.get('schema') == 'hepta.runtime.shell-capture-mkdir-reuse.v1', 'mkdir reuse schema differs')
    need(sha(source[ORIGINAL]) == ORIGINAL_SHA, 'original capture path source differs')
    for key, value in {'source': ORIGINAL, 'source_sha256': ORIGINAL_SHA, 'target': OWNER,
                       'target_sha256': sha(source[OWNER]), 'compiler_commit': COMPILER,
                       'private_authoring_generator_required_at_build_or_runtime': False}.items():
        same(proof.get(key), value, 'mkdir reuse binding differs: ' + key)
    same(proof.get('relocation'), RELOCATION, 'mkdir relocation IDs differ')
    old, new = functions(source[ORIGINAL]), functions(source[OWNER])
    rows = proof.get('functions')
    need(type(rows) is list and len(rows) == 6, 'mkdir complete helper set differs')
    checked, seen = [], set()
    for row in rows:
        before_id, after_id = row['original_function'], row['new_function']
        need(before_id in RELOCATION and after_id == RELOCATION[before_id] and before_id not in seen,
             'mkdir helper identity duplicated or changed')
        seen.add(before_id)
        before, after = old[before_id], new[after_id]
        need(row['original_body'].encode() == before and row['new_body'].encode() == after,
             'mkdir helper receipt differs from source bytes')
        need(row['original_body_sha256'] == sha(before) and row['new_body_sha256'] == sha(after)
             and row.get('only_function_and_call_id_relocation') is True, 'mkdir helper pins differ')
        need(relocate_body(before, RELOCATION) == after, 'mkdir helper changed beyond ID relocation')
        checked.append({'original_function': before_id, 'new_function': after_id,
                        'original': pin(before), 'relocated': pin(after)})
    same(sorted(seen), sorted(ORIGINAL_FUNCTIONS), 'mkdir helper coverage differs')
    derived = proof['derived_parent']
    removed = ['  v3:usize = buffer.len(v0)\n', '  v4:u64 = int.cast(v3) {"mode":"wrap"}\n',
               '  v10:usize = buffer.len(v0)\n', '  v11:u64 = int.cast(v10) {"mode":"wrap"}\n']
    anchor = '  v3:u64 = const() {"value":64}\n'
    inserted = '  v4:u64 = int.add.wrap(v3,v2)\n'
    for key, value in {'original_function': 'f6', 'new_function': 'f3', 'original_body_unchanged': False,
                       'buffer_slice_instruction_required': False, 'complete_body_reconstruction_verified': True,
                       'additional_parameter': 'v2:u64', 'ssa_relocation': DERIVED_ALPHA,
                       'removed_whole_buffer_length_lines': removed, 'prefix_extent_anchor': anchor,
                       'inserted_prefix_extent_line': inserted}.items():
        same(derived.get(key), value, 'derived parent transformation differs: ' + key)
    before, after = old['f6'], new['f3']
    need(derived['original_body'].encode() == before and derived['new_body'].encode() == after
         and derived['original_body_sha256'] == sha(before) and derived['new_body_sha256'] == sha(after),
         'derived parent source/body binding differs')
    need(sha(derived['authoring_definition'].encode()) == derived['authoring_definition_sha256'],
         'derived explanatory source pin differs')
    rebuilt = before
    for line in removed:
        need(rebuilt.count(line.encode()) == 1, 'derived parent removed statement is not unique')
        rebuilt = rebuilt.replace(line.encode(), b'')
    rebuilt = re.sub(rb'\bv[0-9]+\b', lambda match: DERIVED_ALPHA.get(match.group().decode(), match.group().decode()).encode(), rebuilt)
    rebuilt = relocate_body(rebuilt, {**RELOCATION, 'f6': 'f3'})
    signature = b'(v0:readbuf,v1:mutbuf)'
    need(rebuilt.count(signature) == 2, 'derived parent declaration/entry differ')
    rebuilt = rebuilt.replace(signature, b'(v0:readbuf,v1:mutbuf,v2:u64)')
    need(rebuilt.count(anchor.encode()) == 1, 'derived extent anchor differs')
    rebuilt = rebuilt.replace(anchor.encode(), (anchor + inserted).encode())
    need(rebuilt == after, 'derived parent changed beyond the exact virtual-prefix transformation')
    return {'reuse_manifest_sha256': sha(source[REUSE]), 'complete_helpers': checked,
            'derived_parent': {'original': pin(before), 'derived': pin(after), 'body_unchanged': False,
                               'complete_transformation_reconstructed': True},
            'private_authoring_generator_required': False}


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
    spec.loader.exec_module(module)
    need(ordinary(path) == source, "build module changed during import")
    return module


def layout_contract(source):
    value = decode(source[LAYOUT])
    expected = {'schema': 'hepta.runtime.shell-capture-mkdir-layout.v1',
        'adapter_entry_offset': 0, 'adapter_relocations': [], 'adapter_padding_byte': 0,
        'adapter_tail_alignment': 16, 'input_header_bytes': 16, 'input_magic': 'HSCMPK01',
        'owner_body_unchanged': True, 'adapter_source_sha256': sha(source[ADAPTER])}
    for key, item in expected.items():
        same(value.get(key), item, 'mkdir adapter layout differs: ' + key)
    need(integer(value.get('image_offset'), 192, 1 << 20) and value['image_offset'] % 16 == 0,
         'mkdir adapter image offset invalid')
    need(type(value.get('adapter_image_sha256')) is str and re.fullmatch('[0-9a-f]{64}', value['adapter_image_sha256']),
         'mkdir adapter image pin invalid')
    same(sorted(value), sorted([*expected, 'image_offset', 'adapter_image_sha256']), 'mkdir layout member set differs')
    return value


def adapter_object(raw, binary):
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
    starts = []
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
    need(starts == [(0x12, 0, text_index, 0)], 'adapter does not have one global function _start at offset zero')
    return {'text': pin(binary), 'entry_offset': 0, 'relocations': [], 'undefined_symbols': [],
            'only_allocated_section': '.text'}


def fixed_elf(raw, adapter, owner):
    need(len(raw) == 176 + len(adapter) + len(owner) and raw[:16] == b'\x7fELF\x02\x01\x01' + bytes(9),
         'mkdir fixed executable extent/identity differs')
    need(struct.unpack_from('<HHIQQQIHHHHHH', raw, 16) ==
         (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0), 'mkdir canonical ELF header differs')
    need(struct.unpack_from('<IIQQQQQQ', raw, 64) ==
         (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096), 'mkdir unique RX load mapping differs')
    need(struct.unpack_from('<IIQQQQQQ', raw, 120) ==
         (0x6474e551, 6, 0, 0, 0, 0, 0, 16), 'mkdir nonexecutable stack differs')
    need(raw[176:176 + len(adapter)] == adapter and raw[176 + len(adapter):] == owner,
         'mkdir executable does not contain the complete unchanged adapter and HIA owner')
    return {'elf_type': 'ET_EXEC', 'target': 'linux-x86_64', 'entry': 0x4000b0,
            'program_headers': ['PT_LOAD_RX', 'PT_GNU_STACK_RW'], 'interpreter': None,
            'dynamic_linker': False, 'imports': [], 'bytes': len(raw), 'sha256': sha(raw)}


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
    receipt = {'schema': 'hepta.runtime.shell-capture-mkdir-build-tool.v1', 'label': label,
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
    exact = {'schema': 'hepta.runtime.shell-capture-mkdir-build-tool.v1', 'label': label,
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


def packer_specs(image, total):
    wire = b'HSCMPK01' + struct.pack('<Q', len(image)) + image
    return [('success', wire, total + 37, 4096, total),
            ('exact-output', wire, total, 4096, total),
            ('zero-workspace', wire, total + 37, 0, total),
            ('short-output', wire, total - 1, 4096, CAPACITY),
            ('empty-input', b'', total + 37, 4096, INVALID),
            ('short-header', wire[:15], total + 37, 4096, INVALID),
            ('bad-magic', b'X' + wire[1:], total + 37, 4096, INVALID),
            ('length-mismatch', wire[:8] + struct.pack('<Q', len(image) + 1) + image, total + 37, 4096, INVALID),
            ('trailing-byte', wire + b'x', total + 37, 4096, INVALID),
            ('zero-image', b'HSCMPK01' + bytes(8), total + 37, 4096, INVALID),
            ('overflow-length', b'HSCMPK01' + b'\xff' * 8, total + 37, 4096, INVALID)]


def guarded(label, raw):
    index = ('input', 'output', 'workspace').index(label)
    return bytes([0xC1 + index]) * 16 + raw + bytes([0xD1 + index]) * 16


def read_packer(folder, manifest, image, executable):
    metadata = decode(ordinary(manifest))
    rows_raw = ordinary(folder / 'packer.json')
    rows = decode(rows_raw)
    specs = packer_specs(image, len(executable))
    need(type(rows) is list and len(rows) == len(specs), 'mkdir packer actual case set incomplete')
    prior_end, pid = 0, None
    for index, (row, (name, wire, capacity, workspace, returned)) in enumerate(zip(rows, specs)):
        for key, expected in {'index': index, 'name': name, 'input_capacity': len(wire),
            'output_capacity': capacity, 'workspace_capacity': workspace, 'returned': returned,
            'manifest_sha256': sha(ordinary(manifest)), 'source_sha256': metadata['source_sha256'],
            'image_sha256': metadata['image_sha256']}.items():
            same(row.get(key), expected, 'mkdir packer invocation differs: ' + name + '/' + key)
        need(integer(row.get('pid'), 1) and integer(row.get('started_ns'), 1)
             and integer(row.get('finished_ns'), row['started_ns']) and row['started_ns'] >= prior_end,
             'mkdir packer process/timing record differs')
        pid = row['pid'] if pid is None else pid
        need(row['pid'] == pid, 'mkdir packer process identity changed')
        prior_end = row['finished_ns']
        arrays, files = {}, {}
        for label in ('input', 'output', 'workspace'):
            for phase in ('before', 'after'):
                relative = f'packer/{index:02d}/{label}.{phase}.bin'
                raw = ordinary(folder / relative)
                arrays[label + '_' + phase] = raw
                files[relative] = pin(raw)
        same(row.get('files'), files, 'mkdir packer complete array pins differ')
        need(arrays['input_before'] == arrays['input_after'] == guarded('input', wire),
             'mkdir packer changed input or its guards')
        need(arrays['workspace_before'] == arrays['workspace_after'] == guarded('workspace', b'\x5c' * workspace),
             'mkdir packer changed workspace or its guards')
        need(arrays['output_before'] == guarded('output', b'\xa7' * capacity), 'mkdir packer initial output differs')
        expected = executable + b'\xa7' * (capacity - len(executable)) if returned == len(executable) else b'\xa7' * capacity
        need(arrays['output_after'] == guarded('output', expected), 'mkdir packer full output, tail or refusal differs')
    return {'invocations': len(rows), 'complete_guarded_arrays': 6 * len(rows), 'receipt': pin(rows_raw),
            'actual_owner_filesystem_operations': 0, 'typed_errno_controls_executed': 0}


def execute_packer(folder, manifest, image, total, loader):
    import ctypes
    metadata = decode(ordinary(manifest))
    manifest_sha = sha(ordinary(manifest))
    rows, executable = [], None
    with loader.NativeModule(manifest, manifest_sha256=manifest_sha) as native:
        for index, (name, wire, capacity, workspace, expected) in enumerate(packer_specs(image, total)):
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
            need(returned == expected, 'actual mkdir packer rejected its registered case: ' + name)
            if index == 0:
                executable = bytes(arrays['output'])[16:16 + total]
    need(type(executable) is bytes and len(executable) == total, 'mkdir HIA packer produced no complete executable')
    read_packer(folder, manifest, image, executable)
    return executable


def bridge_evidence(folder, source, image, executable):
    layout = layout_contract(source)
    obj, binary = ordinary(folder / 'adapter.o'), ordinary(folder / 'adapter.bin')
    object_info = adapter_object(obj, binary)
    need(len(binary) == layout['image_offset'] - 176 + 1 and binary[-1:] == b'\0'
         and (len(binary) - 1) % 16 == 0 and sha(binary[:-1]) == layout['adapter_image_sha256'],
         'mkdir assembled bridge differs from its source layout')
    return {'layout_sha256': sha(source[LAYOUT]), 'adapter_source_sha256': sha(source[ADAPTER]),
        'adapter_image_sha256': sha(binary[:-1]), 'adapter_object': pin(obj), 'adapter_binary': pin(binary),
        'object_inspection': object_info, 'elf_inspection': fixed_elf(executable, binary[:-1], image)}


def read_evidence(manifest, *, source_root=ROOT):
    """Read actual source/compiler/tool/packing bytes without executing any image."""
    manifest, source_root = Path(manifest).absolute(), Path(source_root).absolute()
    folder, build_root = manifest.parent, manifest.parent.parent
    need(manifest.name == 'manifest.json' and folder.name == 'shell-capture-mkdir', 'mkdir TOP location differs')
    raw = ordinary(manifest)
    meta = decode(raw)
    need(meta.get('schema') == SCHEMA and meta.get('status') == 'PASS', 'mkdir build incomplete')
    same(meta.get('scope'), scope(), 'mkdir build scope differs')
    for key, value in {'target': 'linux-x86_64', 'compiler_commit': COMPILER, 'compiler_sha256': B3,
                       'effect_abi': 'HSHMKFX1', 'fixture_argv': ['--mkdir-fixture', 'TRACE_DIRECTORY'],
                       'raw_fd_or_pid_input_allowed': False, 'elf': 'shell-capture-mkdir.elf'}.items():
        same(meta.get(key), value, 'mkdir TOP contract differs: ' + key)
    source = snapshot(source_root)
    same(meta.get('source_files'), {name: pin(body) for name, body in source.items()}, 'mkdir source closure differs')
    for name, body in source.items():
        need(ordinary(member(folder / 'source-snapshots', name)) == body, 'mkdir source snapshot differs: ' + name)
    reuse = reuse_proof(source)
    same(meta.get('reuse_proof'), reuse, 'mkdir source reuse proof differs')
    component_paths, compiled, components = {}, {}, {}
    for label, name, source_name in [('owner', OWNER_NAME, OWNER), ('packer', PACKER_NAME, PACKER)]:
        relative = 'modules/' + name + '/manifest.json'
        need(meta.get(label + '_manifest') == relative, 'mkdir child path differs')
        path = build_root / relative
        child, proof = native_component(path, source[source_name], name)
        need(meta.get(label + '_manifest_sha256') == sha(ordinary(path)), 'mkdir child manifest pin differs')
        component_paths[label], compiled[label], components[label] = path, proof, child
    for key, expected in {'source_sha256': components['owner']['source_sha256'],
        'owner_source_sha256': components['owner']['source_sha256'],
        'image_sha256': components['owner']['image_sha256'],
        'owner_image_sha256': components['owner']['image_sha256']}.items():
        need(meta.get(key) == expected, 'mkdir owner identity differs: ' + key)
    image = ordinary(component_paths['owner'].parent / components['owner']['image'])
    executable_path = folder / 'shell-capture-mkdir.elf'
    executable = ordinary(executable_path)
    need(stat.S_IMODE(executable_path.stat().st_mode) == 0o500 and meta.get('elf_sha256') == sha(executable),
         'mkdir executable bytes/mode differ')
    bridge = bridge_evidence(folder, source, image, executable)
    same(meta.get('bridge'), bridge, 'mkdir source/object/ELF binding differs')
    same(meta.get('image_offset'), decode(source[LAYOUT])['image_offset'], 'mkdir embedded owner offset differs')
    tools = {spec[0]: read_tool(folder, spec) for spec in tool_specs(folder)}
    packer = read_packer(folder, component_paths['packer'], image, executable)
    same(meta.get('packer_invocations'), packer['invocations'], 'mkdir actual packer case count differs')
    report_raw = ordinary(folder / 'build-evidence.json')
    need(meta.get('build_evidence_sha256') == sha(report_raw), 'mkdir actual build receipt pin differs')
    report = decode(report_raw)
    need(report.get('status') == 'PASS' and report.get('error') is None, 'mkdir actual build did not complete')
    for key, expected in {'scope': scope(), 'source_files': meta['source_files'], 'compiled': compiled,
                          'tools': tools, 'packer': packer, 'bridge': bridge,
                          'producer_folder': str(folder)}.items():
        same(report.get(key), expected, 'mkdir actual build evidence differs: ' + key)
    need(type(report.get('compiler_workspace_preexisted')) is bool
         and integer(report.get('pid'), 1) and integer(report.get('started_ns'), 1)
         and integer(report.get('finished_ns'), report['started_ns']), 'mkdir build identity/timing invalid')
    hepta = Path(report['compiler_source_root'])
    need(hepta.is_absolute(), 'mkdir compiler source root is not absolute')
    dependency = decode(ordinary(build_root / 'bootstrap/bootstrap.json'))['dependency']
    for name, expected in dependency['files'].items():
        need(sha(ordinary(member(hepta, name))) == expected, 'mkdir compiler source bytes changed: ' + name)
    previous = report['started_ns']
    for label, *_ in tool_specs(folder):
        row = decode(ordinary(folder / 'tools' / (label + '.json')))
        need(previous <= row['started_ns'] <= row['finished_ns'] <= report['finished_ns'],
             'mkdir assembler invocation is outside the build lifetime/order')
        previous = row['finished_ns']
    for row in decode(ordinary(folder / 'packer.json')):
        need(row['pid'] == report['pid'] and previous <= row['started_ns']
             <= row['finished_ns'] <= report['finished_ns'], 'mkdir packer entry is outside the build lifetime/order')
        previous = row['finished_ns']
    return {'schema': 'hepta.runtime.shell-capture-mkdir-read.v1', 'status': 'PASS',
        'manifest_sha256': sha(raw), 'elf_sha256': sha(executable), 'compiler_sha256': B3,
        'owner_manifest': str(component_paths['owner']),
        'owner_manifest_sha256': sha(ordinary(component_paths['owner'])),
        'source_sha256': components['owner']['source_sha256'], 'image_sha256': components['owner']['image_sha256'],
        'packer_manifest': str(component_paths['packer']),
        'packer_manifest_sha256': sha(ordinary(component_paths['packer'])),
        'complete_relocated_helpers': len(RELOCATION), 'derived_parent_body_unchanged': False,
        'derived_parent_exact_transformation': True, 'tool_processes': len(tools),
        'packer_checks': packer, **scope()}


def build_shell_capture_mkdir(hepta, build_root, *, source_root=ROOT):
    source_root, build_root, hepta = (Path(value).absolute() for value in (source_root, build_root, hepta))
    folder = build_root / 'shell-capture-mkdir'
    need(not folder.exists() and not folder.is_symlink(), 'mkdir build requires a fresh output folder')
    for name in (OWNER_NAME, PACKER_NAME):
        target = build_root / 'modules' / name
        need(not target.exists() and not target.is_symlink(), 'mkdir component output already exists')
    folder.mkdir(parents=True, mode=0o700)
    for parent in (folder, *folder.parents):
        need(stat.S_ISDIR(parent.lstat().st_mode), 'mkdir build parent is not an ordinary directory')
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
        sys.dont_write_bytecode = True
        build_module = import_build_module(source_root, 'hia_native_build', source['scripts/hia_native_build.py'])
        loader = import_build_module(source_root, 'hia_native_loader', source['scripts/hia_native_loader.py'])
        builder = build_module.NativeBuild(hepta, build_root)
        compiler = builder.bootstrap()
        need(sha(ordinary(compiler)) == B3, 'actual mkdir compiler is not the fixed admitted B3')
        paths, components = {}, {}
        report['compiled'] = {}
        for label, name, source_name in [('owner', OWNER_NAME, OWNER), ('packer', PACKER_NAME, PACKER)]:
            path = builder.compile(name, member(folder / 'source-snapshots', source_name), standalone=None)
            need(path == build_root / 'modules' / name / 'manifest.json', 'mkdir actual component path differs')
            paths[label] = path
            components[label], report['compiled'][label] = native_component(path, source[source_name], name)
            save()
        report['tools'] = {}
        for spec in tool_specs(folder):
            report['tools'][spec[0]] = execute_tool(folder, spec)
            save()
        image = ordinary(paths['owner'].parent / components['owner']['image'])
        binary = ordinary(folder / 'adapter.bin')
        adapter_object(ordinary(folder / 'adapter.o'), binary)
        need(len(binary) == layout['image_offset'] - 176 + 1 and binary[-1:] == b'\0'
             and sha(binary[:-1]) == layout['adapter_image_sha256'], 'mkdir actual adapter differs from layout')
        executable = execute_packer(folder, paths['packer'], image, layout['image_offset'] + len(image), loader)
        report['packer'] = read_packer(folder, paths['packer'], image, executable)
        report['bridge'] = bridge_evidence(folder, source, image, executable)
        executable_path = folder / 'shell-capture-mkdir.elf'
        create(executable_path, executable)
        executable_path.chmod(0o500)
        need(snapshot(source_root) == source, 'mkdir source changed during actual build')
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
            'effect_abi': 'HSHMKFX1', 'fixture_argv': ['--mkdir-fixture', 'TRACE_DIRECTORY'],
            'raw_fd_or_pid_input_allowed': False, 'bridge': report['bridge'],
            'packer_invocations': report['packer']['invocations'],
            'build_evidence_sha256': sha(ordinary(folder / 'build-evidence.json'))}
        for label, path in paths.items():
            top[label + '_manifest'] = path.relative_to(build_root).as_posix()
            top[label + '_manifest_sha256'] = sha(ordinary(path))
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
    args = parser.parse_args()
    try:
        if args.read_only is not None:
            need(args.hepta is None and args.build is None, 'read-only does not accept build arguments')
            result = read_evidence(args.read_only, source_root=args.source_root)
        else:
            need(args.hepta is not None and args.build is not None, '--hepta and --build are required')
            manifest = build_shell_capture_mkdir(args.hepta, args.build, source_root=args.source_root)
            result = {'status': 'PASS', 'manifest': str(manifest),
                      'evidence': read_evidence(manifest, source_root=args.source_root)}
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except BaseException as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__ + ': ' + str(error)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
