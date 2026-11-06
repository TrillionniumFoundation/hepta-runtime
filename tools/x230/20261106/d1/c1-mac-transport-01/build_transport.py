"""Metadata-only packaging of the exact original 23 sealed source files."""
import ast
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile

HERE = Path(__file__).parent
SOURCE = Path('/tmp/hepta-runtime-recovery-20261106/d1-c1-actual-sealed-01')
MANIFEST_SHA = '4f0b9447c24788c856c1bbb4664c3ab483e27803ff09c84e9192424f34f69f6b'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def write_new(name, raw):
    with (HERE / name).open('xb') as out:
        out.write(raw)

manifest_raw = (SOURCE / 'seal-manifest.json').read_bytes()
assert sha(manifest_raw) == MANIFEST_SHA
manifest = json.loads(manifest_raw)
assert manifest['file_count'] == 20 and len(manifest['files']) == 20
expected = {row['staged_path']: {'bytes': row['bytes'], 'sha256': row['sha256']}
            for row in manifest['files']}
assert len(expected) == 20
expected.update({
    'seal-manifest.json': {'bytes': 328810, 'sha256': MANIFEST_SHA},
    'install_campaign.py': {'bytes': 12349, 'sha256': '0045ac1a119727260a99f4aab98c554e033f3486d16ae45cca9464e0c811d40a'},
    'operator-argv.json': {'bytes': 359, 'sha256': 'ea227201c9fba1fd8ea63f9cc29513f371731ed7df669cc36143e1ddd7fefb4e'},
})
payload = {}
for name, identity in sorted(expected.items()):
    path = SOURCE / name
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    assert not path.is_symlink() and path.resolve() == path
    raw = path.read_bytes()
    after = path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    assert len(raw) == identity['bytes'] and sha(raw) == identity['sha256']
    assert len(raw) <= 1048576 and len(name.encode('ascii')) < 100
    payload[name] = raw
assert len(payload) == 23 and sum(map(len, payload.values())) == 692705
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT, encoding='ascii') as archive:
    for name, raw in sorted(payload.items()):
        item = tarfile.TarInfo(name)
        item.size = len(raw)
        item.mode = 0o600
        item.uid = item.gid = item.mtime = 0
        item.uname = item.gname = ''
        archive.addfile(item, io.BytesIO(raw))
tar_raw = buf.getvalue()
compressed = gzip.compress(tar_raw, compresslevel=6, mtime=0)
assert len(compressed) <= 1048576 and len(tar_raw) <= 2097152 + 65536
# Verification reads every original member into memory; it never extracts a path.
with tarfile.open(fileobj=io.BytesIO(compressed), mode='r:gz') as archive:
    members = archive.getmembers()
    assert len(members) == 23 and {m.name for m in members} == set(payload)
    assert all(m.isreg() and m.type == tarfile.REGTYPE and not m.linkname for m in members)
    for item in members:
        assert archive.extractfile(item).read() == payload[item.name]

template = (HERE / 'importer.template.py').read_text()
source = template.replace('ARCHIVE_BYTES = None', 'ARCHIVE_BYTES = ' + str(len(compressed)))
source = source.replace('ARCHIVE_SHA256 = None', 'ARCHIVE_SHA256 = ' + repr(sha(compressed)))
source = source.replace('EXPECTED = None', 'EXPECTED = ' + json.dumps(expected, sort_keys=True, indent=4))
assert source != template and source.count('EXPECTED = ') == 1
ast.parse(source)
raw_source = source.encode()
write_new('sealed-payloads-01.tar.gz', compressed)
write_new('sealed-payloads-01.tar.gz.base64', base64.b64encode(compressed))
write_new('import_sealed_payloads_01.py', raw_source)
receipt = {
    'schema': 'hepta-d1-c1-mac-transport-static/v1',
    'source_seal_manifest': {'bytes': len(manifest_raw), 'sha256': sha(manifest_raw)},
    'members': expected, 'file_count': len(payload), 'total_payload_bytes': sum(map(len, payload.values())),
    'archive': {'bytes': len(compressed), 'sha256': sha(compressed)},
    'uncompressed_tar_bytes': len(tar_raw),
    'importer': {'bytes': len(raw_source), 'sha256': sha(raw_source)},
    'zero_extraction_member_readback': True,
    'importer_ast_parsed': True, 'importer_executed': False, 'host_calls': 0,
    'original_installer_executed': False, 'measurement_changed': False,
    'bounds': {'archive_bytes': 1048576, 'member_bytes': 1048576, 'payload_bytes': 2097152},
}
write_new('local-static-integrity-01.json', (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode())
print(json.dumps({k: receipt[k] for k in ('file_count', 'total_payload_bytes', 'archive', 'importer')}))
