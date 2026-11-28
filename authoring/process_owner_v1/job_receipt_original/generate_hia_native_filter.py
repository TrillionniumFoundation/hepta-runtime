"""Author a HIA packer for one native borrowed-buffer application.

The syscall template has no payload parser or linker logic. Actual ELF emission,
call displacement and image copying are performed by the checked-in HIA packer.
"""
from __future__ import annotations
import ast
from hashlib import sha256
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import MAX_BYTES
from hepta.hia_evaluate_reference_wire_native import WORK_BYTES as PROJECTOR_WORK_BYTES
from hepta.hia_scalar_reference_wire import MAX_PACKET_BYTES
from hepta.hia_elf_shared_linker_native import MAX_ELF_BYTES, WORKSPACE_BYTES as DIRECT_LINK_WORKSPACE
from hepta.hia_safe_core_elf_inventory_native import (
    AUTHORITY_BYTES, CAPACITY as ELF_REPLY_BYTES, FINAL_LOADER_MAGIC, FINAL_LOADER_NAME,
    FINAL_LOADER_WORK, MAX_ELF,
)
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_elf_linker import MAGIC as LINK_WIRE_MAGIC, SOURCE as LINK_SOURCE
MAGIC=int.from_bytes(b'HIAFLT01','little')
DIRECT_LINK_FILTER_MAGIC = int.from_bytes(b'HIADSL01', 'little')
LINK_FILTER_MAGIC = int.from_bytes(b'HIAELF01', 'little')
WORKER_FILTER_MAGIC = int.from_bytes(b'HIAWRF01', 'little')
EVALUATE_PROJECTOR_FILTER_MAGIC = int.from_bytes(b'HIAEPF01', 'little')
SAFE_CORE_LOADER_FILTER_MAGIC = int.from_bytes(b'HIAELW01', 'little')
SAFE_CORE_LOADER_INPUT_HEADER = 8 + 256
WORKER_REQUEST_MAGIC = int.from_bytes(b'HIAWRA01', 'little')
WORKER_HEADER_BYTES = 80
WORKER_PRIVATE_BYTES = 16384
WIRE_BYTES=8<<20
OUTPUT_OFFSET=WIRE_BYTES+4096
OUTPUT_BYTES=8<<20
WORKSPACE_OFFSET=OUTPUT_OFFSET+OUTPUT_BYTES
WORKSPACE_BYTES=16<<20
WORKER_WORKSPACE_BYTES = 64 + 262144 * 56 + WIRE_BYTES + WORKER_PRIVATE_BYTES
MAPPING_BYTES=WORKSPACE_OFFSET+WORKSPACE_BYTES
CORE_REPORT_MODE = int.from_bytes(b'HIACRPT1', 'little')


def template(*, wire_bytes=WIRE_BYTES, output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES,
             formatter=False, suite=False, object_files=False, worker_request=False, final_loader=False,
             canonical_render_tag=None, canonical_section=None):
    output_offset = wire_bytes + 4096
    workspace_offset=output_offset+output_bytes
    mapping_bytes=workspace_offset+workspace_bytes
    input_bytes = wire_bytes + (WORKER_HEADER_BYTES if worker_request else 0)
    code=bytearray();labels={};branches=[]
    def emit(value):code.extend(bytes.fromhex(value))
    def word(value):code.extend(struct.pack('<I',value))
    def label(name):labels[name]=len(code)
    def branch(op,name):emit(op);branches.append((len(code),name));word(0)
    def call_image(*, argument=False):
        if argument:
            emit('48 8b 7c 24 10 48 89 de')  # argv[1] and its observed extent
        elif worker_request:
            emit('49 8d 7c 24 50 49 8d 75 b0')  # Skip the trusted 80-byte input header.
        elif final_loader:
            emit('49 8d bc 24');word(SAFE_CORE_LOADER_INPUT_HEADER)
            emit('49 8d b5');word(-SAFE_CORE_LOADER_INPUT_HEADER & 0xffffffff)
        else:
            emit('4c 89 e7 4c 89 ee')
        emit('49 8d 94 24');word(output_offset)
        emit('b9');word(output_bytes)
        emit('4d 8d 84 24');word(workspace_offset)
        emit('41 b9');word(workspace_bytes)
        emit('e8');offset=len(code);word(0)
        return offset
    emit('48 83 3c 24');emit('02' if suite else '01')
    if suite:
        branch('0f 84','map')
        emit('48 83 3c 24 03')
    if object_files:
        branch('0f 84','map')
        emit('48 83 3c 24 03');branch('0f 82','usage')
        emit('48 83 3c 24 42');branch('0f 87','usage')
    else:
        branch('0f 85','usage')
    label('map')
    emit('31 ff be');word(mapping_bytes)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff');branch('0f 83','io')
    calls = []
    emit('49 89 c4 45 31 ed')
    if suite:
        emit('48 8b 7c 24 10 31 db')
        label('argument')
        emit('83 fb 10');branch('0f 83','usage')
        emit('80 3c 1f 00');branch('0f 84','dispatch')
        emit('48 ff c3');branch('e9','argument')
        label('dispatch')
        calls.append(call_image(argument=True))
        emit('83 f8 01');branch('0f 82','usage')
        emit('83 f8 04');branch('0f 87','usage')
        emit('89 c3')  # Admitted mode remains in the callee-saved register.
        emit('45 31 ff 48 83 3c 24 02');branch('0f 84','read')
        label('open_input')
        # openat(AT_FDCWD, argv[2], O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        emit('b8 01 01 00 00 bf 9c ff ff ff 48 8b 74 24 18 ba 00 08 0a 00 45 31 d2 0f 05')
        emit('48 83 f8 fc');branch('0f 84','open_input')
        emit('48 85 c0');branch('0f 88','io')
        emit('41 89 c7')  # r15d = opened descriptor (possibly zero).
        label('stat_input')
        # fstat(fd, input mapping); only st_mode and st_size are needed.
        emit('b8 05 00 00 00 44 89 ff 4c 89 e6 0f 05')
        emit('48 83 f8 fc');branch('0f 84','stat_input')
        emit('48 85 c0');branch('0f 88','io')
        emit('41 8b 44 24 18 25 00 f0 00 00 3d 00 80 00 00');branch('0f 85','io')
        emit('49 81 7c 24 30');word(wire_bytes);branch('0f 87','space')
    if object_files:
        emit('48 83 3c 24 01');branch('0f 84','read')
        # Capture the argument extents and construct HIALNK01 for the existing
        # HIA linker. Only that linker admits object headers, symbols and code.
        emit('48 b8');code.extend(struct.pack('<Q', LINK_WIRE_MAGIC))
        emit('49 89 04 24 48 8b 04 24 48 83 e8 02 49 89 44 24 08')
        emit('48 8b 74 24 10')  # argv[1], entry.
        label('entry_byte')
        emit('42 80 3c 2e 00');branch('0f 84','entry_end')
        emit('49 81 fd 00 10 00 00');branch('0f 83','usage')
        emit('49 ff c5');branch('e9','entry_byte')
        label('entry_end')
        emit('4d 85 ed');branch('0f 84','usage')
        emit('4d 89 6c 24 10 49 8d 7c 24 20 4c 89 e9 fc f3 a4 49 83 c5 20')
        emit('bb 02 00 00 00')  # rbx: argv index, r13: total frame extent.
        label('next_object')
        emit('48 3b 1c 24');branch('0f 83','invoke')
        emit('49 81 fd');word(wire_bytes - 8);branch('0f 87','space')
        emit('4d 89 ee 49 83 c5 08 48 8b 74 dc 08')  # r14: size word offset.
        label('open_object')
        emit('b8 01 01 00 00 bf 9c ff ff ff ba 00 08 0a 00 45 31 d2 0f 05')
        emit('48 83 f8 fc');branch('0f 84','open_object')
        emit('48 85 c0');branch('0f 88','io')
        emit('41 89 c7')  # r15: descriptor, including zero.
        label('stat_object')
        emit('b8 05 00 00 00 44 89 ff 49 8d b4 24');word(workspace_offset);emit('0f 05')
        emit('48 83 f8 fc');branch('0f 84','stat_object')
        emit('48 85 c0');branch('0f 88','io')
        emit('41 8b 84 24');word(workspace_offset + 24)
        emit('25 00 f0 00 00 3d 00 80 00 00');branch('0f 85','io')
        emit('b8');word(wire_bytes);emit('4c 29 e8 49 3b 84 24');word(workspace_offset + 48)
        branch('0f 82','space')
        label('read_object')
        emit('31 c0 44 89 ff 4b 8d 34 2c ba');word(wire_bytes + 1)
        emit('4c 29 ea 0f 05 48 83 f8 fc');branch('0f 84','read_object')
        emit('48 85 c0');branch('0f 88','io');branch('0f 84','object_end')
        emit('49 01 c5 49 81 fd');word(wire_bytes);branch('0f 87','space')
        branch('e9','read_object')
        label('object_end')
        emit('b8 03 00 00 00 44 89 ff 0f 05 48 85 c0');branch('0f 88','io')
        emit('4c 89 e8 4c 29 f0 48 83 e8 08 4b 89 04 34 48 ff c3')
        branch('e9','next_object')
    label('read')
    emit('31 c0')
    emit('44 89 ff' if suite else '31 ff')
    emit('4b 8d 34 2c ba');word(input_bytes+1)
    emit('4c 29 ea 0f 05 48 83 f8 fc');branch('0f 84','read')
    emit('48 85 c0');branch('0f 88','io');branch('0f 84','invoke')
    emit('49 01 c5 49 81 fd');word(input_bytes);branch('0f 87','space');branch('e9','read')
    label('invoke')
    if suite:
        emit('48 83 3c 24 02');branch('0f 84','admit')
        emit('b8 03 00 00 00 44 89 ff 0f 05 48 85 c0');branch('0f 88','io')
        label('admit')
    if worker_request:
        emit('49 83 fd 50');branch('0f 82','invalid')
        emit('48 b8');code.extend(struct.pack('<Q', WORKER_REQUEST_MAGIC))
        emit('49 39 04 24');branch('0f 85','invalid')
        # Read the process owner's configured integer conversion budget.
        # The worker's original semantics admit zero (no numeric digit cap).
        emit('49 8b 44 24 08 48 3d ff ff ff 7f');branch('0f 87','invalid')
        emit('48 85 c0');branch('0f 84','worker_context')
        emit('48 3d 80 02 00 00');branch('0f 82','invalid')
        label('worker_context')
        emit('49 89 84 24');word(workspace_offset + 8)
        emit('49 c7 84 24');word(workspace_offset);word(1)  # Request admission mode.
        emit('49 8d 74 24 10 49 8d bc 24')
        word(mapping_bytes - WORKER_PRIVATE_BYTES + 64)
        emit('b9 40 00 00 00 fc f3 a4')  # Exact catalog pin, not request data.
    if final_loader:
        # Transport only: separate a bounded name field from immutable ELF
        # bytes. The HIA application checks the name, tables and loader mapping.
        emit('49 81 fd');word(SAFE_CORE_LOADER_INPUT_HEADER);branch('0f 82','invalid')
        emit('48 b8');code.extend(struct.pack('<Q', FINAL_LOADER_MAGIC))
        emit('49 89 84 24');word(workspace_offset)
        emit('49 8b 04 24 49 89 84 24');word(workspace_offset + 8)
        emit('49 8d 74 24 08 49 8d bc 24');word(workspace_offset + FINAL_LOADER_NAME)
        emit('b9');word(256);emit('fc f3 a4')
    calls.append(call_image())
    if canonical_section is not None:
        # The HIA plan owns a fixed header and variable byte sections. Re-encode
        # only its ordinary JSON section using the original Worker image.
        # Both other sections and their published order are byte-preserving.
        fixed, extent = canonical_section
        if not 0 <= extent <= fixed-8 or fixed >= output_bytes or wire_bytes < output_bytes:
            raise ValueError('invalid JSON section layout')
        emit('3d');word(output_bytes);branch('0f 87','invalid')
        emit('3d');word(fixed);branch('0f 82','invalid')
        emit('41 89 c5 4d 8d bc 24');word(output_offset)
        emit('4d 8b b7');word(extent)
        emit('2d');word(fixed)
        emit('49 39 c6');branch('0f 87','invalid')
        emit('49 8d bf');word(fixed)
        emit('4c 89 f6 49 8d 94 24');word(fixed)
        emit('b9');word(8<<20)
        emit('4d 8d 84 24');word(workspace_offset)
        emit('41 b9');word(workspace_bytes)
        emit('49 c7 00 00 00 00 00 49 c7 40 08');word(4300)
        emit('e8');calls.append(len(code));word(0)
        emit('3d');word(8<<20);branch('0f 87','invalid')
        emit('89 c3 4d 29 f5 49 01 c5 49 81 fd');word(output_bytes);branch('0f 87','invalid')
        emit('4c 89 fe 4c 89 e7 b9');word(fixed);emit('fc f3 a4')
        emit('49 89 9c 24');word(extent)
        emit('4b 8d b4 37');word(fixed)
        emit('49 8d bc 1c');word(fixed)
        emit('4c 89 e9 48 29 d9 48 81 e9');word(fixed);emit('f3 a4')
        emit('4d 89 ee 4d 89 e7');branch('e9','write')
    if canonical_render_tag is not None:
        # The first HIA section emits a Store command plan or a ledger. The
        # second is the original Worker ordinary-data canonical JSON section.
        # Reuse the consumed input mapping for its disjoint output.
        emit('3d');word(output_bytes);branch('0f 87','invalid')
        emit('49 ba');code.extend(struct.pack('<Q',canonical_render_tag))
        emit('4d 39 14 24');branch('0f 85','check_output')
        emit('89 c6 49 8d bc 24');word(output_offset)
        emit('4c 89 e2 b9');word(output_bytes)
        emit('4d 8d 84 24');word(workspace_offset)
        emit('41 b9');word(workspace_bytes)
        emit('49 c7 00 00 00 00 00 49 c7 40 08');word(4300)
        emit('e8');calls.append(len(code));word(0)
        emit('3d');word(output_bytes);branch('0f 87','invalid')
        emit('41 89 c6 4d 89 e7');branch('e9','write')
    if worker_request:
        emit('83 f8 fd');branch('0f 84','io')
    if formatter or suite:
        emit('83 f8 fe');branch('0f 84','space')
        emit('85 c0');branch('0f 85','invalid')
        if suite:
            emit('83 fb 01');branch('0f 84','check_output')
            emit('83 fb 02');branch('0f 85','inspect')
        calls.append(call_image())
        if suite:
            branch('e9','check_output')
            label('inspect')
            emit('83 fb 04');branch('0f 85','render_view')
            emit('48 b8');code.extend(struct.pack('<Q', CORE_REPORT_MODE))
            emit('49 89 84 24');word(workspace_offset+workspace_bytes-8)
            label('render_view')
            calls.append(call_image())
    label('check_output')
    emit('83 f8 fe');branch('0f 84','space')
    if final_loader:
        emit('83 f8 18');branch('0f 85','invalid')
        emit('49 83 bc 24');word(output_offset);emit('00');branch('0f 85','invalid')
    emit('3d');word(output_bytes);branch('0f 87','invalid')
    emit('41 89 c6 4d 8d bc 24');word(output_offset)
    label('write');emit('4d 85 f6');branch('0f 84','success')
    emit('b8 01 00 00 00 bf 01 00 00 00 4c 89 fe 4c 89 f2 0f 05 48 83 f8 fc');branch('0f 84','write')
    emit('48 85 c0');branch('0f 8e','io')
    emit('49 01 c7 49 29 c6');branch('e9','write')
    for name,status in (('success',0),('invalid',2),('space',3),('io',4),('usage',64)):
        label(name);emit('bf');word(status);branch('e9','exit')
    label('exit');emit('b8 3c 00 00 00 0f 05 0f 0b')
    for at,name in branches:struct.pack_into('<i',code,at,labels[name]-at-4)
    prefix = elf_header()
    return prefix+code,tuple(len(prefix)+offset for offset in calls)


def elf_header():
    return (b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))


def _binding_declaration(words):
    return {'name': 'adapter_binding', 'params': [], 'returns': [], 'effects': [], 'entry': 'entry',
            'blocks': [{'id': 'entry', 'params': [],
                        'ops': [{'op': 'const', 'args': [], 'attrs': {'value': value},
                                 'out': [{'name': f'word{index}', 'type': 'u64'}]}
                                for index, value in enumerate(words)],
                        'term': {'op': 'ret', 'values': []}}]}


def bind_adapter(packer, source, adapter, holes):
    """Attach ordinary HIA constants for independent build-time ELF checking."""
    payload = struct.pack(f'<32s32s{1 + len(holes)}Q', sha256(source).digest(), sha256(adapter).digest(),
                          len(adapter), *holes)
    packer['functions'].append(_binding_declaration(struct.unpack(f'<{len(payload) // 8}Q', payload)))
    return packer


def read_adapter_binding(packer, adapter_source, *, calls):
    """Read the generated source and transport binding without an assembler."""
    document = assemble_program(packer).as_dict()
    records = [fn for fn in document['functions'] if fn['name'] == 'adapter_binding']
    if len(records) != 1:
        raise ValueError('HIA packer does not bind one syscall adapter')
    record = records[0]
    try:
        words = tuple(op['attrs']['value'] for op in record['blocks'][0]['ops'])
        payload = struct.pack(f'<{9 + calls}Q', *words)
    except (KeyError, struct.error) as exc:
        raise ValueError('invalid HIA adapter binding declaration') from exc
    if record != _binding_declaration(words):
        raise ValueError('invalid HIA adapter binding declaration')
    source, adapter, size, *holes = struct.unpack(f'<32s32s{1 + calls}Q', payload)
    if (source != sha256(adapter_source).digest() or not 0 < size < 1 << 20
            or len(set(holes)) != calls or any(not 0 < hole <= size - 4 for hole in holes)):
        raise ValueError('HIA packer adapter binding differs from its admitted source')
    return adapter, size, tuple(holes)


def verify_adapter(binary, code, binding, *, entries, instructions=None):
    adapter_digest, size, holes = binding
    header = bytearray(elf_header())
    end = len(header) + size
    length = end + len(code)
    struct.pack_into('<2Q', header, 96, length, length)
    if len(binary) != length or binary[:len(header)] != header or binary[end:] != code:
        raise ValueError('HIA packer changed the ELF envelope or application image')
    adapter = bytearray(binary[len(header):end])
    if instructions is None:
        instructions = (b'\xe8',) * len(holes)
    for hole, entry, instruction in zip(holes, entries, instructions, strict=True):
        if (hole < len(instruction)
                or adapter[hole - len(instruction):hole + 4]
                != instruction + struct.pack('<i', size + entry - hole - 4)):
            raise ValueError('HIA packer changed an admitted application relocation')
        adapter[hole:hole + 4] = bytes(4)
    if sha256(adapter).digest() != adapter_digest:
        raise ValueError('HIA packer changed the admitted syscall adapter')


REFERENCE_CLI_MAGIC = int.from_bytes(b'HIASPK01', 'little')
REFERENCE_CLI_ADAPTER = 'tools/hia_scalar_reference_syscalls.S'
REFERENCE_CLI_PACKER = 'examples/hia_bootstrap/scalar_reference_cli_packer.hepta'


def reference_cli_document():
    from tools.build_hia_agent_batch_commit import adapter_layout

    root = Path(__file__).resolve().parents[1]
    source = (root / REFERENCE_CLI_ADAPTER).read_bytes()
    with TemporaryDirectory(prefix='hia-reference-cli-adapter-') as temporary:
        stub, holes, _ = adapter_layout(Path(temporary), REFERENCE_CLI_ADAPTER,
                                       source, {'reference': 'reference_call_hole'})
    header = elf_header()
    hole = holes['reference']
    packer = document(magic=REFERENCE_CLI_MAGIC, module='scalar_reference_cli_packer',
                      image_template=(header + stub, (len(header) + hole,)))
    return bind_adapter(packer, source, stub, (hole,))


def source_program(*, wire_bytes=WIRE_BYTES, output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES,
                   magic=MAGIC, formatter=False, object_files=False, worker_request=False,
                   image_template=None, private_entry=False, separate_sections=False, pack_limit=1 << 20):
    prefix,calls=image_template or template(wire_bytes=wire_bytes, output_bytes=output_bytes,
                          workspace_bytes=workspace_bytes,
                          formatter=formatter,object_files=object_files,worker_request=worker_request)
    if private_entry and (formatter or len(calls) != 2):
        raise ValueError('private entry packing needs a single image with two calls')
    if separate_sections and (not image_template or len(calls) < 2 or formatter or private_entry):
        raise ValueError('section packing needs a separate image for each admitted call')
    header = 8 + 8 * len(calls) if separate_sections else 24 if formatter or private_entry else 16
    minimum = header + len(calls)
    text=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {minimum} or length(s) > {pack_limit}:
        return 4294967295
    if uint(s, 0, 8) != {magic}:
        return 4294967295
    image = uint(s, 8, 8)
'''
    section_starts = []
    if separate_sections:
        text += f'    payload = length(s) - {header}\n'
        text += '    if image == 0 or image >= payload:\n        return 4294967295\n'
        section_start = 'image'
        for index in range(1, len(calls)):
            section_starts.append(section_start)
            extent = f'section_{index}'
            text += f'    {extent} = uint(s, {8 + 8 * index}, 8)\n'
            if index == len(calls) - 1:
                text += f'    if {extent} != payload - ({section_start}):\n'
            else:
                text += f'    if {extent} == 0 or {extent} >= payload - ({section_start}):\n'
            text += '        return 4294967295\n'
            section_start += f' + {extent}'
    elif formatter:
        text += '''    format_image = uint(s, 16, 8)
    if image == 0 or image >= length(s) - 24 or format_image != length(s) - 24 - image:
        return 4294967295
'''
    elif private_entry:
        text += '''    entry = uint(s, 16, 8)
    if image != length(s) - 24 or entry == 0 or entry >= image:
        return 4294967295
'''
    else:
        text += '''    if image != length(s) - 16:
        return 4294967295
'''
    payload = 'payload' if separate_sections else 'length(s) - 24' if formatter else 'image'
    text += f'''    size = {len(prefix)} + ({payload})
    if size > {pack_limit} or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        chunk=prefix[at:at+8];text+=f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    text+=f'''    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, {calls[0]}, {len(prefix)-calls[0]-4}, 4)
'''
    if separate_sections:
        for at, section_start in zip(calls[1:], section_starts, strict=True):
            text += f'    write(o, {at}, {len(prefix)-at-4} + {section_start}, 4)\n'
    elif formatter:
        text+=f'    write(o, {calls[1]}, {len(prefix)-calls[1]-4} + image, 4)\n'
    elif private_entry:
        text+=f'    write(o, {calls[1]}, {len(prefix)-calls[1]-4} + entry, 4)\n'
    text+=f'''    copy_bytes(s, o, {header}, {len(prefix)}, {payload})
    return size
'''
    # Exact ordinary Core helper bodies, never a host-side payload copier.
    text+=LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    return text


def document(*, wire_bytes=WIRE_BYTES, output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES, magic=MAGIC,
             module='native_filter_packer', formatter=False, object_files=False, worker_request=False,
             image_template=None, private_entry=False, separate_sections=False):
    nodes=ast.parse(source_program(wire_bytes=wire_bytes, output_bytes=output_bytes,
                                   workspace_bytes=workspace_bytes,
                                   magic=magic,formatter=formatter,object_files=object_files,
                                   worker_request=worker_request, image_template=image_template,
                                   private_entry=private_entry, separate_sections=separate_sections)).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    fns=[]
    for n in nodes:
        b=Builder(n,names,sigs,total_scalar_functions(nodes));b.statements(n.body)
        fns.append({'name':names[n.name],'params':[b.param(p) for p in b.params],'returns':[b.returns],
                    'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':module,'functions':fns})


def direct_shared_linker_document():
    return document(wire_bytes=MAX_ELF_BYTES, output_bytes=MAX_ELF_BYTES,
                    workspace_bytes=DIRECT_LINK_WORKSPACE, magic=DIRECT_LINK_FILTER_MAGIC,
                    module='direct_shared_linker_filter_packer')

def evaluate_reference_wire_filter_document():
    return document(wire_bytes=MAX_BYTES + 140, output_bytes=MAX_PACKET_BYTES,
                    workspace_bytes=PROJECTOR_WORK_BYTES, magic=EVALUATE_PROJECTOR_FILTER_MAGIC,
                    module='evaluate_reference_wire_filter_packer')


def safe_core_loader_document():
    adapter = template(wire_bytes=MAX_ELF + SAFE_CORE_LOADER_INPUT_HEADER,
                       output_bytes=ELF_REPLY_BYTES + AUTHORITY_BYTES,
                       workspace_bytes=FINAL_LOADER_WORK, final_loader=True)
    return document(magic=SAFE_CORE_LOADER_FILTER_MAGIC, module='safe_core_loader_filter_packer',
                    image_template=adapter)


def main():
    root=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap'
    for name, source in (
        ('native_filter_packer', document()),
        ('direct_shared_linker_filter_packer', direct_shared_linker_document()),
        ('safe_core_loader_filter_packer', safe_core_loader_document()),
        ('evaluate_reference_wire_filter_packer', evaluate_reference_wire_filter_document()),
        ('scalar_reference_cli_packer', reference_cli_document()),
        ('elf_linker_filter_packer', document(magic=LINK_FILTER_MAGIC,
                                             module='elf_linker_filter_packer', object_files=True)),
        ('worker_request_filter_packer', document(magic=WORKER_FILTER_MAGIC,
             module='worker_request_filter_packer', workspace_bytes=WORKER_WORKSPACE_BYTES,
             worker_request=True)),
    ):
        path = root/f'{name}.hepta'
        path.write_text(render_assembly(source))
        print(path.name,path.stat().st_size)
if __name__=='__main__':main()
