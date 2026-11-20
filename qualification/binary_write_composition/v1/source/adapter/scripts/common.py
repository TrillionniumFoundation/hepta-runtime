"""Strict ordinary bytes, source closure and frozen input transport."""
from pathlib import Path
import base64
import hashlib
import json
import lzma
import stat
import struct

ROOT = Path(__file__).resolve().parents[1]
B3 = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
HEPTA = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
PACK = lambda *words: struct.pack('<' + 'Q' * len(words), *words)
WORD = lambda raw, at: struct.unpack_from('<Q', raw, at)[0]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANON = lambda value: (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
UNBASE = lambda value: base64.b64decode(value,validate=True)


def require(test, message):
    if not test:
        raise ValueError(message)


def owned(root, name):
    root = Path(root).resolve(strict=True)
    path = root / name
    require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'owned relative name')
    require(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), 'ordinary unsymlinked bytes')
    return path


def pin(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw),sha256=SHA(raw))


def source_evidence(root=ROOT):
    root = Path(root).resolve(strict=True)
    raw = owned(root,'SOURCE_MANIFEST.json').read_bytes()
    manifest = json.loads(raw)
    require(manifest['schema']=='hepta.runtime.binary-write-adapter.source.v1','source schema')
    actual={}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(),'source symlink')
        if path.is_file() and path != root/'SOURCE_MANIFEST.json':
            name=path.relative_to(root).as_posix()
            actual[name]=dict(**pin(owned(root,name)),mode=stat.S_IMODE(path.stat().st_mode))
    require(actual==manifest['files'],'complete source bytes/modes changed')
    return dict(manifest_sha256=SHA(raw),files=actual,whole_runtime_replaced=False)


def inputs(root=ROOT):
    root=Path(root)
    domain=json.loads(owned(root,'inputs/DOMAIN.json').read_bytes())
    raw=owned(root,'inputs/INPUTS.json.xz').read_bytes()
    require(pin(root/'inputs/INPUTS.json.xz')=={k:domain['inputs'][k] for k in ('bytes','sha256')},'frozen input compressed bytes')
    decoded=lzma.decompress(raw)
    require(len(decoded)==domain['inputs']['decoded_bytes'] and SHA(decoded)==domain['inputs']['decoded_sha256'],'whole frozen input bytes')
    data=json.loads(decoded)
    require(data['schema']=='hepta.runtime.binary-write-adapter.inputs.v1','input schema')
    require(len(data['plan_cases'])==433 and len(data['typed_write_cases'])==196 and len(data['parent_interface_cases'])==256,'complete frozen domains')
    return domain,data


def save(path, value):
    path.write_bytes(CANON(value))


def request(command,sequence=0,code=0,payload=b'',auxiliary=0):
    return b'HBWAQ001'+PACK(command,sequence,code,len(payload),auxiliary)+payload


def start_wire(plan,ready):
    return request(1,payload=plan+ready,auxiliary=len(plan))


def parent_projection(row):
    root=row['root'].replace('{R}','/binary-parent-interface')
    path=row['path'].replace('{R}','/binary-parent-interface')
    value=dict(host='parent-interface-fixture',path=path,expected_version=row['expected_version'],data_base64=row['data_base64'])
    return root.encode(),json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
