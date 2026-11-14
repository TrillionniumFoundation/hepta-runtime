"""Exact source-owned profile and embedded ELF admission for OS scope tests."""
from pathlib import Path
import hashlib
import json
import struct


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def inspect_scope_os(manifest: Path, root: Path):
    metadata = json.loads(manifest.read_bytes())
    profile_raw = (root/'native/scope_os_profile.json').read_bytes()
    profile = json.loads(profile_raw)
    proof_raw = (root/'native/scope_os_packer_provenance.json').read_bytes()
    proof = json.loads(proof_raw)
    assert profile['compiler_commit'] == 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
    assert profile['compiler_sha256'] == 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
    assert profile['real_os_entropy_connected'] is True
    assert profile['production_activated'] is profile['whole_runtime_replaced'] is False
    assert profile['concurrent_shared_capability_qualified'] is False
    assert proof['profile_sha256'] == digest(profile_raw)
    assert proof['source_sha256'] == digest((root/'native/composition_packer.hepta').read_bytes())
    assert metadata['packer']['source_sha256'] == proof['source_sha256']
    for key in ('compiler_commit','compiler_sha256'):
        assert metadata[key] == profile[key]
    expected = [{k:v for k,v in row.items() if k not in ('source','image_bytes','image_sha256')}
                for row in profile['members']]
    assert metadata['profile'] == expected and len(expected) == 8
    assert [(r['id'],r['flags'],r['call_mask']) for r in expected] == [
        (0,1,64),(1,1,28),(2,0,0),(3,0,0),(4,0,0),(5,0,0),(6,1,166),(7,4,0)]
    sources = {}
    for row in profile['members']:
        sources[row['source']] = digest((root/row['source']).read_bytes())
        assert sources[row['source']] == row['source_sha256']
    executable = manifest.parent/metadata['executable']
    raw = executable.read_bytes()
    assert digest(raw) == metadata['executable_sha256']
    assert raw[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HH',raw,16) == (2,62)
    assert struct.unpack_from('<2Q',raw,96) == (len(raw),len(raw))
    at, pointer = proof['metadata_offset'], proof['metadata_hole']
    prefix = bytearray(raw[:at]);prefix[96:112] = bytes(16)
    assert digest(prefix) == proof['elf_prefix_normalized_sha256']
    assert raw[pointer-3:pointer] == b'\x4c\x8d\x2d'
    assert pointer+4+struct.unpack_from('<i',raw,pointer)[0] == at
    code, memory = at+64+8*128,16859136
    assert len(metadata['members']) == 8
    layout = []
    for index,row in enumerate(profile['members']):
        desc = at+64+index*128
        actual = struct.unpack_from('<8Q',raw,desc)
        assert actual == (code,row['image_bytes'],row['input_capacity'],row['output_capacity'],
                          memory,row['workspace_capacity'],row['flags'],row['call_mask'])
        assert raw[desc+64:desc+128] == bytes.fromhex(row['source_sha256']+row['image_sha256'])
        image = raw[code:code+row['image_bytes']]
        assert len(image) == row['image_bytes'] and digest(image) == row['image_sha256']
        member = metadata['members'][index]
        assert member['source_sha256'] == row['source_sha256'] and member['image_sha256'] == row['image_sha256']
        layout.append({'id':index,'image_offset':code,'image_bytes':len(image),'workspace_offset':memory})
        end = code+len(image);code=(end+15)&-16
        assert raw[end:code] == bytes(code-end)
        memory += ((row['workspace_capacity']+4095)&-4096)+4096
    assert struct.unpack_from('<8Q',raw,at) == (int.from_bytes(b'HIAMOD01','little'),8,0,memory,128,16859136,0,0)
    assert code == len(raw)
    return {'executable_sha256':digest(raw),'manifest_sha256':digest(manifest.read_bytes()),
            'profile_sha256':digest(profile_raw),'packer_provenance_sha256':digest(proof_raw),
            'source_sha256':sources,'prefix_sha256':digest(prefix),'layout':layout,
            'all_embedded_image_bytes_match':True}
