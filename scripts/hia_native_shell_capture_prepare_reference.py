#!/usr/bin/env python3
"""Build a fixed Rust capture-prepare projection with complete loader bindings."""
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
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DRIVER = "scripts/hia_native_shell_capture_prepare_reference.py"
HELPERS = "scripts/hia_native_shell_process_reference.py"
ORACLE = "tests/oracles/shell_capture_prepare"
TRANSPORT = ('README.md', 'source_manifest.json', 'src/main.rs', 'review/tokio_fs_mod.rs')
SCHEMA = "hepta.runtime.shell-capture-prepare-original-build.v1"
TARGET = "x86_64-unknown-linux-gnu"
INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
SOURCE_COMMIT = "93f320a8e02b522e4bafd4a2cf346d68069ec74b"
DRIVER_BYTES = Path(__file__).read_bytes()
TRANSPORT_PINS = {'README.md': (5240, '50561717ec7925eb7fa75b48dbf780a50015b2479ccb48be95108151e66d6dfe'), 'source_manifest.json': (6066, '82313eb74bf368e31cd24438292df6a51efa721b17b0bed60172665c26989fd0'), 'src/main.rs': (5291, '4177bfd66ba7c016245b36af5e0f27a75bd84159a9ae84c6ad8e58f1620abac4'), 'review/tokio_fs_mod.rs': (9375, '3b2060c5ecf43e1c28bd1c712fbd93c09eead6f0e91a2b78e6a93dd7b92243f9')}

ALLOWED_NEEDED = {"libc.so.6", "libgcc_s.so.1", "libm.so.6", "libpthread.so.0", "libdl.so.2",
                  "librt.so.1", "ld-linux-x86-64.so.2"}


def load_ref(runtime):
    path = runtime / HELPERS
    spec = importlib.util.spec_from_file_location("hia_prepare_reference_helpers", path)
    if spec is None or spec.loader is None:
        raise ValueError("reference helpers unavailable")
    ref = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = ref
    exec(compile(path.read_bytes(), str(path), 'exec'), ref.__dict__)
    ref.require(ref.read(runtime, DRIVER) == DRIVER_BYTES, "executing capture-prepare reference differs")
    ref.require(ref.read(runtime, HELPERS) == ref.DRIVER_BYTES, "executing reference helpers differ")
    return ref


def scope():
    return {"original_capture_block_projection": True,
            "original_helper_bodies_unchanged": True,
            "capture_block_api_edits_explicit": 6,
            "actual_standard_library_filesystem_operations": True,
            "actual_private_atomic_fetch_add": True,
            "original_tests": 0,
            "tokio_async_body_executed": False,
            "tokio_blocking_task_failure_qualified": False,
            "tokio_cancellation_qualified": False,
            "into_std_inflight_qualified": False,
            "anyhow_error_type_qualified": False,
            "error_display_native_equivalence": False,
            "registry_duplicate_admission_qualified": False,
            "global_sequence_concurrency_qualified": False,
            "ambient_observation_replacement_qualified": False,
            "job_construction_qualified": False,
            "capture_preparation_qualified": False,
            "production_activated": False,
            "whole_runtime_replaced": False,
            "old_stack_removal_qualified": False}


def generated_projection(original, manifest, ref):
    spans, bodies = manifest['spans'], {}
    ref.exact(sorted(spans), ['capture_body', 'jobs_dir', 'next_id', 'sequence_declaration'],
              'prepare source span member set differs')
    for label, row in spans.items():
        ref.exact(row['source'], 'src/mcp/fs/background.rs', 'prepare source span origin differs')
        start, end = row['start'], row['end']
        ref.require(type(start) is int and type(end) is int and 0 <= start < end <= len(original),
                    'prepare original source span extent differs')
        raw = original[start:end]
        ref.exact(ref.pin(raw), {'bytes': row['bytes'], 'sha256': row['sha256']},
                  'prepare original source span bytes differ: ' + label)
        bodies[label] = raw
    expected = [
        ('tokio::fs::create_dir_all(&dir)\n\t\t.await', 'std::fs::create_dir_all(&dir)'),
        ('tokio::fs::File::create(&stdout_path)\n\t\t.await', 'std::fs::File::create(&stdout_path)'),
        ('\n\t\t.into_std()\n\t\t.await', ''),
        ('tokio::fs::File::create(&stderr_path).await', 'std::fs::File::create(&stderr_path)'),
        ('Ok(file) => file.into_std().await,', 'Ok(file) => file,'),
        ('tokio::fs::remove_file(&stdout_path).await', 'std::fs::remove_file(&stdout_path)'),
    ]
    edits = manifest['capture_body_edits']
    ref.require(type(edits) is list and len(edits) == 6, 'prepare projection edit count differs')
    ref.exact([(row['before'], row['after']) for row in edits], expected,
              'prepare projection API edit whitelist differs')
    start, end = spans['capture_body']['start'], spans['capture_body']['end']
    prior = start
    for row in edits:
        lo, hi = row['start'], row['end']
        ref.require(type(lo) is int and type(hi) is int and prior <= lo < hi <= end,
                    'prepare projection edits overlap or leave their original span')
        ref.require(original[lo:hi] == row['before'].encode(), 'prepare projection original edit bytes differ')
        prior = hi
    projected = bodies['capture_body']
    for row in reversed(edits):
        lo, hi = row['start'] - start, row['end'] - start
        projected = projected[:lo] + row['after'].encode() + projected[hi:]
    ref.exact(ref.pin(projected), manifest['projected_capture_body'], 'prepare projected body differs')
    helpers = b'\n'.join(bodies[name] for name in ('sequence_declaration', 'jobs_dir', 'next_id'))
    prefix = b'fn capture_projection() -> Result<Capture> {\n'
    suffix = b'\n\tOk(Capture { dir, id, stdout_path, stderr_path, stdout_file, stderr_file })\n}\n'
    id_line = b'\tformat!("{}-{}", std::process::id(), n)\n'
    ref.require(bodies['next_id'].count(id_line) == 1, 'original id format statement differs')
    path_lines = (b'\tlet stdout_path = dir.join(format!("{id}.stdout.log"));\n'
                  b'\tlet stderr_path = dir.join(format!("{id}.stderr.log"));\n')
    ref.require(bodies['capture_body'].count(path_lines) == 1, 'original capture path statements differ')
    metadata = (b'fn metadata_projection(n: u64, observed: bool) -> (PathBuf, String, PathBuf, PathBuf) {\n'
                b'\tlet dir = jobs_dir();\n'
                b'\tif !observed { return (dir, String::new(), PathBuf::new(), PathBuf::new()); }\n'
                b'\tlet id = ' + id_line.lstrip(b'\t').rstrip(b'\n') + b';\n' + path_lines +
                b'\t(dir, id, stdout_path, stderr_path)\n}\n')
    compiled = helpers + b'\n' + prefix + projected + suffix + b'\n' + metadata
    return compiled, {'unchanged_helpers': {key: ref.pin(bodies[key]) for key in
        ('sequence_declaration', 'jobs_dir', 'next_id')}, 'original_capture_body': ref.pin(bodies['capture_body']),
        'edits': edits, 'projected_capture_body': ref.pin(projected),
        'capture_wrapper_prefix': ref.pin(prefix), 'capture_wrapper_suffix': ref.pin(suffix),
        'pure_error_metadata_wrapper': ref.pin(metadata), 'complete_compiled_projection': ref.pin(compiled)}


def source_provenance(runtime, ref):
    oracle = runtime / ORACLE
    ref.ordinary_source_inventory(oracle, TRANSPORT)
    transport = {name: ref.read(oracle, name) for name in TRANSPORT}
    for name, (size, digest) in TRANSPORT_PINS.items():
        ref.exact(ref.pin(transport[name]), {'bytes': size, 'sha256': digest},
                  'frozen prepare fixture source differs: ' + name)
    manifest = ref.decode(transport['source_manifest.json'])
    for key, value in {'schema': 'hepta.runtime.shell-capture-prepare-original-source.v1',
        'source_commit': SOURCE_COMMIT, 'required_target': TARGET, 'required_rust_version': '1.95.0',
        'original_test_count': 0}.items():
        ref.exact(manifest.get(key), value, 'prepare source declaration differs: ' + key)
    ref.exact(sorted(manifest['files']), ['Cargo.lock', 'Cargo.toml', 'src/mcp/fs/background.rs'],
              'prepare original runtime source member set differs')
    originals = {}
    for name, expected in manifest['files'].items():
        raw = ref.read(runtime, name)
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        ref.exact({**ref.pin(raw), 'git_blob_sha1': blob}, expected, 'prepare original source changed: ' + name)
        originals[name] = raw
    package = tomllib.loads(originals['Cargo.toml'].decode())
    ref.exact(package['package']['edition'], '2021', 'production Rust edition differs')
    ref.exact(package['profile']['release'], {'lto': True, 'codegen-units': 1, 'panic': 'abort',
        'strip': True, 'opt-level': 3, 'overflow-checks': False}, 'production release profile differs')
    lock = tomllib.loads(originals['Cargo.lock'].decode())
    tokio = [row for row in lock['package'] if row['name'] == 'tokio' and row['version'] == '1.53.1']
    ref.require(len(tokio) == 1, 'original Tokio package identity is ambiguous or missing')
    ref.exact(manifest['tokio_package'], tokio[0], 'complete original Tokio lock identity differs')
    reviews = manifest['reviewed_tokio_bridges']
    ref.exact(sorted(reviews), ['asyncify', 'create_dir_all', 'file', 'open_options', 'remove_file'],
              'prepare reviewed Tokio member set differs')
    review_pins = {}
    for label, review in reviews.items():
        source = review['source']
        raw = transport[source] if review.get('transport') is True else ref.read(runtime, source)
        if review.get('transport') is not True:
            originals[source] = raw
        actual = ref.pin(raw)
        ref.exact(actual, {key: review[key] for key in ('bytes', 'sha256')},
                  'complete reviewed Tokio source differs: ' + label)
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if 'git_blob_sha1' in review:
            ref.exact(blob, review['git_blob_sha1'], 'reviewed Tokio source Git identity differs')
        review_pins[label] = {**actual, 'git_blob_sha1': blob}
    owned = manifest['reviewed_owned_fd']
    raw = ref.read(runtime, owned['source']); originals[owned['source']] = raw
    owned_pin = {**ref.pin(raw), 'git_blob_sha1': hashlib.sha1(
        b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
    ref.exact(owned_pin, {key: owned[key] for key in ('bytes', 'sha256', 'git_blob_sha1')},
              'complete original OwnedFd drop source differs')
    projection, projection_evidence = generated_projection(originals['src/mcp/fs/background.rs'], manifest, ref)
    compiled = {'src/main.rs': transport['src/main.rs'], 'src/projection.rs': projection}
    provenance = {'manifest': manifest, 'transport': {k: ref.pin(v) for k, v in transport.items()},
        'drivers': {name: ref.pin(ref.read(runtime, name)) for name in (DRIVER, HELPERS)},
        'compiled': {k: ref.pin(v) for k, v in compiled.items()}, 'projection': projection_evidence,
        'reviewed_tokio_bridges': review_pins, 'owned_file_review': owned_pin,
        'tokio_compiled_or_executed': False, 'anyhow_type_compiled_or_executed': False,
        'reviewed_source_metadata_is_not_a_compiled_std_or_tokio_source_receipt': True,
        'production_edition': package['package']['edition'], 'production_profile': package['profile']['release']}
    return provenance, originals, transport, compiled




def retained_sources(output, originals, transport, compiled, ref):
    for folder, items in (('original-source', originals), ('transport', transport), ('crate', compiled)):
        for name, raw in items.items():
            ref.require(ref.read(output / folder, name) == raw,
                        'retained capture-prepare source differs: ' + folder + '/' + name)
        ref.ordinary_source_inventory(output / folder, items)


def elf_info(raw, ref, *, executable=False):
    """Inspect the actual loader program-header view, without mapping the image."""
    need = ref.require
    need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01' and raw[7] in (0, 3),
         'dynamic input is not Linux ELF64')
    h = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
    need(h[0] in (2, 3) and h[1:3] == (62, 1) and h[6:9] == (0, 64, 56)
         and 0 < h[9] < 1024 and h[4] >= 64 and h[4] + h[9] * 56 <= len(raw),
         'dynamic ELF header or program table differs')
    programs = [struct.unpack_from('<IIQQQQQQ', raw, h[4] + i * 56) for i in range(h[9])]
    loads = [p for p in programs if p[0] == 1]
    need(loads and any(p[1] & 1 for p in loads), 'dynamic ELF has no executable load')
    for p in loads:
        kind, flags, offset, address, physical, size, memory, alignment = p
        need(flags & ~7 == 0 and flags & 4 and flags & 3 != 3 and size <= memory
             and offset <= len(raw) and size <= len(raw) - offset and address + memory < 1 << 64,
             'dynamic load extent or permissions differ')
        need(alignment in (0, 1) or alignment & (alignment - 1) == 0, 'dynamic load alignment invalid')
        need(alignment < 2 or offset % alignment == address % alignment, 'dynamic load file/address alignment differs')
    ranges = sorted((p[3], p[3] + p[6]) for p in loads if p[6])
    need(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'dynamic load address ranges overlap')
    def mapped(address, extent):
        candidates = [p for p in loads if p[3] <= address and extent <= p[5]
                      and address - p[3] <= p[5] - extent]
        need(len(candidates) == 1, 'dynamic table has no unique file-backed load mapping')
        return candidates[0][2] + address - candidates[0][3]
    if executable:
        need(h[0] == 3 and len([p for p in loads if p[1] == 5 and p[3] <= h[3] < p[3] + p[5]]) == 1,
             'original oracle entry is not in its unique RX PIE load')
    interp = [p for p in programs if p[0] == 3]
    need(len(interp) <= 1, 'duplicate ELF interpreter')
    interpreter = None
    if interp:
        p = interp[0]
        need(1 < p[5] < 4096 and p[2] + p[5] <= len(raw)
             and mapped(p[3], p[5]) == p[2], 'interpreter bytes are not in a complete load')
        value = raw[p[2]:p[2] + p[5]]
        need(value[-1:] == b'\0' and b'\0' not in value[:-1], 'interpreter string is malformed')
        interpreter = value[:-1].decode('ascii')
        need(interpreter == INTERPRETER, 'GNU Linux interpreter path differs')
    need(not executable or interpreter == INTERPRETER, 'original oracle interpreter missing')
    dynamics = [p for p in programs if p[0] == 2]
    need(len(dynamics) == 1, 'dynamic input has no unique dynamic table')
    p = dynamics[0]
    need(p[5] and p[5] % 16 == 0 and p[5] == p[6] and p[2] + p[5] <= len(raw)
         and mapped(p[3], p[5]) == p[2], 'dynamic table mapping/extent differs')
    data, tags, stopped = raw[p[2]:p[2] + p[5]], [], False
    for offset in range(0, len(data), 16):
        tag, value = struct.unpack_from('<qQ', data, offset)
        if stopped:
            need(tag == value == 0, 'nonzero data after dynamic terminator')
        elif tag == 0:
            need(value == 0, 'dynamic NULL carries a value')
            stopped = True
        else:
            tags.append((tag, value))
    need(stopped, 'unterminated dynamic table')
    forbidden = {15, 29, 22, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff}
    need(not any(tag in forbidden for tag, _ in tags), 'unadmitted dynamic search, audit or filter policy')
    def single(tag):
        values = [v for t, v in tags if t == tag]
        need(len(values) == 1, 'dynamic string table descriptor missing or duplicated')
        return values[0]
    address, size = single(5), single(10)
    need(0 < size <= len(raw), 'dynamic string table size invalid')
    offset = mapped(address, size)
    strings = raw[offset:offset + size]
    def string(index):
        need(index < len(strings), 'dynamic string index outside table')
        end = strings.find(b'\0', index)
        need(end >= 0, 'dynamic string is unterminated')
        return strings[index:end].decode('ascii')
    needed = [string(v) for t, v in tags if t == 1]
    need(len(needed) == len(set(needed)) and set(needed) <= ALLOWED_NEEDED, 'unadmitted dynamic dependency')
    sonames = [string(v) for t, v in tags if t == 14]
    need(len(sonames) <= 1 and (not sonames or sonames[0] in ALLOWED_NEEDED), 'dynamic SONAME differs')
    return {'elf_type': 'ET_DYN' if h[0] == 3 else 'ET_EXEC', 'entry': h[3],
        'interpreter': interpreter, 'needed': needed, 'soname': sonames[0] if sonames else None,
        'loads': [list(p) for p in loads], 'dynamic_entries': [list(p) for p in tags],
        'dynamic_strings': ref.pin(strings), 'whole_file': ref.pin(raw)}


def system_file(path, ref, *, executable=False):
    path = Path(path)
    ref.require(path.is_absolute(), 'dynamic system file is not absolute')
    resolved = path.resolve(strict=True)
    raw = ref.read(resolved.parent, resolved.name)
    mode = stat.S_IMODE(resolved.lstat().st_mode)
    ref.require(not executable or os.access(resolved, os.X_OK), 'dynamic interpreter is not executable')
    return {'launch_path': str(path), 'resolved_path': str(resolved), 'mode': mode, **ref.pin(raw)}, raw


def loader_configuration(ref):
    cache, cache_raw = system_file('/etc/ld.so.cache', ref)
    ref.require(cache_raw, 'system loader cache is empty')
    path = Path('/etc/ld.so.preload')
    try:
        path.lstat()
    except FileNotFoundError:
        preload, preload_raw = {'present': False}, None
    else:
        info, preload_raw = system_file(path, ref)
        ref.require(all(not line.split(b'#', 1)[0].strip() for line in preload_raw.splitlines()),
                    'system preload configuration would inject a dynamic library')
        preload = {'present': True, 'file': info}
    files = {'ld.so.cache': cache_raw}
    if preload_raw is not None:
        files['ld.so.preload'] = preload_raw
    return {'cache': cache, 'preload': preload}, files


def loader_listing(raw, ref):
    text = raw.decode('ascii')
    rows, vdso, names = [], [], set()
    for line in text.splitlines():
        value = line.strip()
        match = re.fullmatch(r'(linux-vdso\.so\.1) \((0x[0-9a-fA-F]+)\)', value)
        if match:
            vdso.append({'name': match.group(1), 'address': match.group(2)})
            continue
        match = re.fullmatch(r'(\S+) => (/\S+) \((0x[0-9a-fA-F]+)\)', value)
        if match:
            label, path, address = match.groups()
            if label.startswith('/'):
                ref.require(label == INTERPRETER, 'unexpected absolute loader listing label')
                label = Path(label).name
        else:
            match = re.fullmatch(r'(/\S+) \((0x[0-9a-fA-F]+)\)', value)
            ref.require(match is not None, 'unrecognized complete loader listing line')
            path, address = match.groups()
            ref.require(Path(path).name == 'ld-linux-x86-64.so.2', 'unlabelled non-interpreter dependency')
            label = 'ld-linux-x86-64.so.2'
        ref.require(label in ALLOWED_NEEDED and label not in names and 0 < int(address, 16) < 1 << 64,
                    'loader dependency duplicate, unsupported or unmapped')
        names.add(label)
        rows.append({'name': label, 'path': path, 'address': address})
    ref.require(len(vdso) == 1 and 0 < int(vdso[0]['address'], 16) < 1 << 64
                and 'ld-linux-x86-64.so.2' in names and 'libc.so.6' in names,
                'complete original loader/library listing is missing')
    return {'libraries': rows, 'kernel_vdso': vdso[0], 'kernel_vdso_is_not_a_file': True}


def dynamic_bindings(output, ref, *, retain=False):
    raw = ref.read(output, 'prepare-original')
    executable = elf_info(raw, ref, executable=True)
    listing_raw = ref.read(output, 'dynamic-loader-list.stdout')
    listing = loader_listing(listing_raw, ref)
    interpreter, _ = system_file(INTERPRETER, ref, executable=True)
    configuration, config_files = loader_configuration(ref)
    for name, body in config_files.items():
        ref.require(ref.read(output / 'loader-configuration', name) == body,
                    'retained/current loader configuration differs')
    ref.ordinary_source_inventory(output / 'loader-configuration', config_files)
    libraries, byname, paths = [], {}, set()
    for index, row in enumerate(listing['libraries']):
        identity, body = system_file(row['path'], ref)
        path = Path(identity['resolved_path'])
        allowed_parent = str(path.parent) in ('/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu',
                                              '/lib64', '/usr/lib64')
        allowed_parent |= bool(re.fullmatch(r'/(?:usr/)?lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v[234]', str(path.parent)))
        ref.require(allowed_parent and str(path) not in paths, 'dynamic dependency is outside the admitted system library roots')
        paths.add(str(path))
        view = elf_info(body, ref)
        ref.require(view['soname'] == row['name'], 'actual dependency SONAME differs from loader listing')
        if row['name'] == 'ld-linux-x86-64.so.2':
            ref.require(identity['resolved_path'] == interpreter['resolved_path']
                        and identity['sha256'] == interpreter['sha256'], 'listed and selected interpreter differ')
        relative = 'dynamic-libraries/' + f'{index:02d}-' + row['name'] + '.bin'
        if retain:
            path = output / relative
            path.parent.mkdir(exist_ok=True)
            with path.open('xb') as handle:
                handle.write(body)
        else:
            ref.require(ref.read(output, relative) == body, 'retained actual dynamic library bytes differ')
        item = {'listing': row, 'file': identity, 'elf': view, 'retained': {'path': relative, **ref.pin(body)}}
        libraries.append(item)
        byname[row['name']] = view
    required, pending = {'ld-linux-x86-64.so.2'}, list(executable['needed']) + ['ld-linux-x86-64.so.2']
    seen = set()
    while pending:
        name = pending.pop()
        ref.require(name in byname, 'loader listing omits a transitive ELF dependency')
        required.add(name)
        if name not in seen:
            seen.add(name)
            pending.extend(byname[name]['needed'])
    ref.exact(sorted(byname), sorted(required), 'loader listing has an extra unrequested library')
    ref.ordinary_source_inventory(output / 'dynamic-libraries', [Path(r['retained']['path']).name for r in libraries])
    return {'schema': 'hepta.runtime.shell-capture-prepare-dynamic-binding.v1', 'executable_elf': executable,
        'interpreter': interpreter, 'configuration': configuration, 'listing': {'raw': ref.pin(listing_raw), **listing},
        'libraries': libraries, 'library_count': len(libraries), 'whole_library_bytes_retained': True,
        'no_ldd_used': True, 'oracle_entry_executed': False}


def target_libraries(directory, ref):
    directory = Path(directory)
    ref.require(directory.is_absolute() and directory.resolve(strict=True) == directory
                and directory.is_dir(), "target library directory is not canonical")
    files = {}
    def visit(parent):
        with os.scandir(parent) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            if entry.name.startswith(".hepta-"):
                continue
            path = parent / entry.name
            ref.require(not entry.is_symlink(), "target library contains a symlink")
            if entry.is_dir(follow_symlinks=False):
                visit(path)
            else:
                ref.require(entry.is_file(follow_symlinks=False), "target library contains a special file")
                files[path.relative_to(directory).as_posix()] = ref.pin(path.read_bytes())
    visit(directory)
    ref.require(files and any(name.startswith("libstd-") and name.endswith(".rlib") for name in files),
                "target standard library archive missing")
    return {"path": str(directory), "files": files, "file_count": len(files)}

def environment(output):
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            "TMPDIR": str(output / "temporary")}

def command_plan(output, rustc, linker, sysroot):
    crate = output / "crate"
    executable = output / "prepare-original"
    common = [str(rustc), "--target", TARGET, "--sysroot", str(sysroot)]
    compile_command = common + ["--crate-name", "hepta_shell_capture_prepare_original", "--crate-type=bin",
        "--edition=2021", "-C", "opt-level=3", "-C", "lto=fat", "-C", "codegen-units=1",
        "-C", "panic=abort", "-C", "strip=symbols", "-C", "overflow-checks=off",
        "-C", "linker=" + str(linker), "--emit=link,dep-info=" + str(output / "prepare.d"),
        str(crate / "src/main.rs"), "-o", str(executable)]
    return [("rustc-version", [str(rustc), "--version", "--verbose"], 30),
            ("rustc-sysroot", [str(rustc), "--print", "sysroot"], 30),
            ("rustc-target-libdir", common + ["--print", "target-libdir"], 30),
            ("rustc-compile", compile_command, 180)]


def read_evidence(runtime, output, rustc=None, linker=None):
    """Read current source, full std/runtime-library bytes and actual process records only."""
    runtime, output = Path(runtime).absolute(), Path(output).absolute()
    ref = load_ref(runtime)
    report = ref.decode(ref.read(output, 'result.json'))
    ref.require(report.get('schema') == SCHEMA and report.get('status') == 'PASS'
                and report.get('error') is None, 'capture-prepare original build incomplete')
    ref.exact(report.get('scope'), scope(), 'capture-prepare original build scope differs')
    provenance, originals, transport, compiled = source_provenance(runtime, ref)
    ref.exact(report.get('source_provenance'), provenance, 'capture-prepare original source closure changed')
    retained_sources(output, originals, transport, compiled, ref)
    rustc = Path(rustc or report['tools']['rustc']['launch_path'])
    linker = Path(linker or report['tools']['linker']['launch_path'])
    tools = {'rustc': ref.tool_identity(rustc), 'linker': ref.tool_identity(linker),
             'ld': ref.tool_identity(Path('/usr/bin/ld')), 'interpreter': ref.tool_identity(Path(INTERPRETER))}
    ref.exact(report.get('tools'), tools, 'actual compiler, linker or ELF interpreter bytes changed')
    sysroot = rustc.resolve(strict=True).parent.parent
    ref.exact(report.get('sysroot'), str(sysroot), 'capture-prepare toolchain sysroot differs')
    ref.exact(report.get('environment'), environment(output), 'capture-prepare controlled environment differs')
    plan = command_plan(output, rustc, linker, sysroot)
    plan.append(('dynamic-loader-list', [tools['interpreter']['resolved_path'], '--list',
                                       str(output / 'prepare-original')], 30))
    rows = report.get('processes')
    ref.require(type(rows) is list and len(rows) == len(plan), 'capture-prepare actual build/inspection process set incomplete')
    last = 0
    for row, (label, command, timeout) in zip(rows, plan):
        ref.completed_process(output, label, row, command, output / 'crate', timeout)
        ref.require(row['started_unix_ns'] >= last, 'capture-prepare build process order differs')
        last = row['finished_unix_ns']
        ref.require(ref.read(output, label + '.stderr') == b'', 'capture-prepare compiler/loader emitted diagnostics')
    version = ref.read(output, 'rustc-version.stdout').decode()
    ref.require(version.startswith('rustc 1.95.0 ') and 'host: ' + TARGET + '\n' in version,
                'capture-prepare original compiler is not fixed Rust 1.95.0 GNU Linux')
    ref.exact(report.get('rustc_version'), version, 'capture-prepare compiler version receipt differs')
    ref.require(ref.read(output, 'rustc-sysroot.stdout') == (str(sysroot) + '\n').encode(), 'actual capture-prepare sysroot differs')
    libdir = sysroot / 'lib/rustlib' / TARGET / 'lib'
    ref.require(ref.read(output, 'rustc-target-libdir.stdout') == (str(libdir) + '\n').encode(),
                'actual target library directory differs')
    ref.exact(report.get('target_libraries'), target_libraries(libdir, ref), 'target standard library bytes changed')
    ref.require(ref.read(output, 'rustc-compile.stdout') == b'', 'unexpected capture-prepare compiler output')
    ref.exact(report.get('dependency_file'), ref.pin(ref.read(output, 'prepare.d')), 'capture-prepare dependency file changed')
    executable = ref.tool_identity(output / 'prepare-original')
    ref.exact(report.get('executable'), executable, 'actual original capture-prepare executable bytes changed')
    binding = dynamic_bindings(output, ref)
    ref.exact(report.get('dynamic_binding'), binding, 'complete runtime-library binding differs')
    ref.exact(report.get('loader_configuration_before'), binding['configuration'], 'loader configuration changed during build')
    ref.exact(report.get('dynamic_inspection_input'), executable, 'loader inspection executable identity changed')
    return {'schema': 'hepta.runtime.shell-capture-prepare-original-build-read.v1', 'status': 'PASS',
        'report_sha256': ref.sha(ref.read(output, 'result.json')), 'executable': executable,
        'actual_build_processes': len(rows), 'target_library_files': report['target_libraries']['file_count'],
        'dynamic_library_count': binding['library_count'], 'dynamic_binding': binding,
        'fresh_original_rust_build_qualified': True, 'fresh_original_prepare_projection_build_qualified': True, **scope()}


def run(runtime, output, rustc, linker):
    runtime, output = Path(runtime).absolute(), Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('capture-prepare reference output must be fresh')
    output.mkdir(parents=True)
    result = output / 'result.json'
    report = {'schema': SCHEMA, 'status': 'RUNNING', 'error': None, 'scope': scope(), 'processes': []}
    def save():
        result.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + '\n')
    save()
    started = time.monotonic()
    try:
        ref = load_ref(runtime)
        provenance, originals, transport, compiled = source_provenance(runtime, ref)
        report['source_provenance'] = provenance
        for folder, items in (('original-source', originals), ('transport', transport), ('crate', compiled)):
            for name, raw in items.items():
                path = output / folder / name
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as stream:
                    stream.write(raw)
        (output / 'temporary').mkdir()
        report['tools'] = {'rustc': ref.tool_identity(rustc), 'linker': ref.tool_identity(linker),
            'ld': ref.tool_identity(Path('/usr/bin/ld')), 'interpreter': ref.tool_identity(Path(INTERPRETER))}
        sysroot = Path(rustc).resolve(strict=True).parent.parent
        report['sysroot'] = str(sysroot)
        env = environment(output)
        report['environment'] = env
        configuration, config_files = loader_configuration(ref)
        report['loader_configuration_before'] = configuration
        (output / 'loader-configuration').mkdir()
        for name, body in config_files.items():
            with (output / 'loader-configuration' / name).open('xb') as stream:
                stream.write(body)
        plan = command_plan(output, rustc, linker, sysroot)
        for label, command, timeout in plan:
            if label == 'rustc-compile':
                report['target_libraries'] = target_libraries(sysroot / 'lib/rustlib' / TARGET / 'lib', ref)
            save()
            row = ref.process(output, label, command, output / 'crate', env, timeout)
            report['processes'].append(row)
            save()
            ref.require(row['passed'], 'capture-prepare original build process failed: ' + label)
            ref.require(ref.read(output, label + '.stderr') == b'', 'capture-prepare original compiler diagnostics: ' + label)
            if label == 'rustc-version':
                version = ref.read(output, label + '.stdout').decode()
                ref.require(version.startswith('rustc 1.95.0 ') and 'host: ' + TARGET + '\n' in version,
                            'capture-prepare original compiler is not Rust 1.95.0 GNU Linux')
                report['rustc_version'] = version
            elif label == 'rustc-sysroot':
                ref.require(ref.read(output, label + '.stdout') == (str(sysroot) + '\n').encode(), 'actual capture-prepare sysroot differs')
            elif label == 'rustc-target-libdir':
                ref.require(ref.read(output, label + '.stdout') ==
                            (str(sysroot / 'lib/rustlib' / TARGET / 'lib') + '\n').encode(), 'actual target libraries differ')
        report['dependency_file'] = ref.pin(ref.read(output, 'prepare.d'))
        report['executable'] = ref.tool_identity(output / 'prepare-original')
        elf_info(ref.read(output, 'prepare-original'), ref, executable=True)
        report['dynamic_inspection_input'] = report['executable']
        save()
        command = [report['tools']['interpreter']['resolved_path'], '--list', str(output / 'prepare-original')]
        row = ref.process(output, 'dynamic-loader-list', command, output / 'crate', env, 30)
        report['processes'].append(row)
        save()
        ref.require(row['passed'], 'actual ELF interpreter dependency inspection failed')
        ref.require(ref.read(output, 'dynamic-loader-list.stderr') == b'', 'actual ELF interpreter emitted diagnostics')
        ref.exact(ref.tool_identity(output / 'prepare-original'), report['dynamic_inspection_input'],
                  'original executable changed during loader inspection')
        report['dynamic_binding'] = dynamic_bindings(output, ref, retain=True)
        ref.exact(report['dynamic_binding']['configuration'], configuration, 'loader configuration changed during build')
        ref.exact(source_provenance(runtime, ref)[0], provenance, 'capture-prepare source changed during build')
        report['status'] = 'PASS'
    except Exception as exc:
        report['status'] = 'FAIL'
        report['error'] = type(exc).__name__ + ': ' + str(exc)
    report['duration_seconds'] = time.monotonic() - started
    save()
    if report['status'] == 'PASS':
        try:
            evidence = read_evidence(runtime, output, rustc, linker)
            (output / 'evidence.json').write_text(json.dumps(evidence, sort_keys=True, indent=2) + '\n')
        except Exception as exc:
            report['status'] = 'FAIL'
            report['error'] = 'read-back ' + type(exc).__name__ + ': ' + str(exc)
            save()
    return report, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--linker', type=Path, default=Path('/usr/bin/cc'))
    parser.add_argument('--read-only', action='store_true')
    args = parser.parse_args()
    try:
        if args.read_only:
            print(json.dumps(read_evidence(args.runtime, args.output, args.rustc, args.linker), sort_keys=True))
            return 0
        report, result = run(args.runtime, args.output, args.rustc, args.linker)
        print(json.dumps({'status': report['status'], 'result': str(result), 'error': report['error'],
            'actual_processes': len(report['processes']), **scope()}, sort_keys=True))
        return 0 if report['status'] == 'PASS' else 1
    except Exception as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__ + ': ' + str(error)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
