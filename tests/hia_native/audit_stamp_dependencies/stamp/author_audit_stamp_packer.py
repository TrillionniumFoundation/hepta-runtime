# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Emit the HIA packer for the fixed two-image archive_stamp graph."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ORDER = ['stamp', 'namespace']
SYMBOLS = dict(stamp='stamp_call_displacement', namespace='ns_namespace_call_displacement')


def main():
    p = argparse.ArgumentParser()
    for name in ('hepta', 'runtime', 'output'): p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    sys.path.insert(0, str(a.hepta.resolve(strict=True)))
    from hepta.hia_agent_assembly import render_assembly
    from tools.generate_hia_elf_linker import SOURCE as HELPERS
    author = a.runtime.resolve(strict=True) / 'scripts/generate_hia_transport.py'
    spec = importlib.util.spec_from_file_location('stamp_transport_author', author)
    transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)
    folder = a.output.resolve(); folder.mkdir(parents=True, exist_ok=True)
    adapter = ROOT / 'scripts/audit_stamp_adapter.S'
    subprocess.run(['as', '--64', str(adapter), '-o', str(folder / 'adapter.o')], check=True)
    assert b'There are no relocations' in subprocess.check_output(['readelf', '-r', str(folder / 'adapter.o')])
    subprocess.run(['objcopy', '-O', 'binary', '--only-section=.text', str(folder / 'adapter.o'), str(folder / 'adapter.bin')], check=True)
    symbols = subprocess.check_output(['nm', '-n', str(folder / 'adapter.o')], text=True)
    holes = {}
    for name, label in SYMBOLS.items():
        matches = re.findall(r'^([0-9a-f]+) T ' + re.escape(label) + '$', symbols, re.M)
        assert len(matches) == 1, (name, matches)
        holes[name] = 176 + int(matches[0], 16)
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    assert len(header) == 176
    prefix = header + (folder / 'adapter.bin').read_bytes()
    for hole in holes.values(): assert prefix[hole - 1:hole + 4] == b'\xe8\0\0\0\0'
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or length(s) > 1048576 or uint(s, 0, 8) != {int.from_bytes(b'HRASelf1', 'little')}:
        return 4294967295
    count = length(s) - 24
    remaining = count
'''
    for i in range(2):
        source += f'''    n{i} = uint(s, {8+i*8}, 8)
    if n{i} == 0 or n{i} > remaining:
        return 4294967295
    remaining = remaining - n{i}
'''
    source += f'''    if remaining != 0:
        return 4294967295
    size = count + {len(prefix)}
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    writers = ''
    for number, start in enumerate(range(0, len(prefix), 768)):
        source += f'    prefix_{number}(o)\n'
        writers += f'\ndef prefix_{number}(o:mutbuf) -> u64:\n'
        for at in range(start, min(start + 768, len(prefix)), 8):
            raw = prefix[at:min(at + 8, len(prefix))]
            writers += f'    write(o, {at}, {int.from_bytes(raw, "little")}, {len(raw)})\n'
        writers += '    return 0\n'
    source += f'''    write(o, 96, size, 8)
    write(o, 104, size, 8)
    position = {len(prefix)}
'''
    for i, name in enumerate(ORDER):
        source += f'    write(o, {holes[name]}, position - {holes[name]+4}, 4)\n'
        source += f'    position = position + n{i}\n'
    source += f'''    copy_bytes(s, o, 24, {len(prefix)}, count)
    return size
'''
    source += writers + HELPERS[HELPERS.index('\ndef uint('):]
    raw = render_assembly(transport.document(source, 'runtime_request_audit_stamp_packer')).encode()
    (ROOT / 'native/request_audit_stamp_packer.hepta').write_bytes(raw)
    (ROOT / 'scripts/audit_stamp_packer_source.py.txt').write_text(source)
    layout = dict(schema='hepta.request-audit.stamp-layout.v1', prefix_bytes=len(prefix), prefix_sha256=SHA(prefix),
        prefix_hex=prefix.hex(), call_holes=holes, image_order=ORDER,
        adapter_source_sha256=SHA(adapter.read_bytes()), packer_source_sha256=SHA(raw),
        compiler_author_source_sha256=SHA(author.read_bytes()),
        input_capacity=4096, output_capacity=4096,
        owner_workspace=1048576, namespace_workspace=8388608,
        runtime_python_required=False, runtime_rust_required=False, runtime_libc_required=False,
        trusted_parent_descriptor=True, explicit_startup_root_fixture=True,
        actual_qualification_executed=False, audit_storage_closed=False, production_activated=False)
    (ROOT / 'native/request_audit_stamp_layout.json').write_text(json.dumps(layout, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in layout.items() if k != 'prefix_hex'}, sort_keys=True))


if __name__ == '__main__': main()
