#!/usr/bin/env python3
"""Install the pinned revision-2 evidence tools into new paths; no workload execution."""
import base64
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import sys
import tarfile

PINS = {'archive': {'bytes': 24176, 'sha256': '1511a4ba7c959eeaa8091e8c3f1bdaae47bd674c1642025ea0dcb3d8430c914c'}, 'manifest': {'bytes': 8705, 'sha256': '02cd30bf3b01f267f66b10c33c99f6b21ef50a7d18363717c18cab1bfc94498f'}, 'files': {'evidence-tools-02/README.md': {'bytes': 9348, 'sha256': '7e104f69c1a99b936811539d6c6adc54e914271581da31d96bad78681a38fb57'}, 'evidence-tools-02/evidence_policy.py': {'bytes': 12533, 'sha256': '5e7b8679a3d1aaa24bbc1dd827d7892016d324f25f48078c6347170d54b35f35'}, 'evidence-tools-02/fixture-run-01.json': {'bytes': 2627, 'sha256': '77b0c6d133bf17dda8499151cf2a84f60d5f31a6b0fa348368512a5d4d7d144c'}, 'evidence-tools-02/holder-copy-manifest.example.json': {'bytes': 90, 'sha256': 'b9fb1ff4a434c1b119ca1935981c4afe61c3b08d5ab4767dfb4add5363f9050e'}, 'evidence-tools-02/independent-review.json': {'bytes': 6305, 'sha256': 'd0b9350def98fd3aa3c5f60ec733660552688264aac1b5c672cfab56dd5369ee'}, 'evidence-tools-02/independent-review.md': {'bytes': 2338, 'sha256': 'c5020aefdb0cc7eb29f783aa55bd3d7bf31a0d5d7dad1ab53e0e68be1e8d6488'}, 'evidence-tools-02/local-validation.json': {'bytes': 3290, 'sha256': 'f48d935af0951262b0a9c1bc5ceb28c7e332434099f4e0820f60e96387bc1a81'}, 'evidence-tools-02/pack_r36_evidence.py': {'bytes': 8301, 'sha256': '124826625635f65c5b5c5e52de7034fb20c523aac47bf003452fe999b332bdd2'}, 'evidence-tools-02/prior-capture-failure.json': {'bytes': 2129, 'sha256': '24ef364dc00258ad354ec5650950060ac8e91f823c6598d922b8a18452752332'}, 'evidence-tools-02/repair-lineage.json': {'bytes': 2984, 'sha256': '984df9b57bdb358a575da6f5463997c4d08a8f95087bed7a8386ae915ffa379e'}, 'evidence-tools-02/scan_evidence.py': {'bytes': 5533, 'sha256': '24d87ae04ce4d43fa0aaef6a2d322fe5d5292eb3002ec77fbf45332223092a2b'}, 'evidence-tools-02/stable_xz_archive.py': {'bytes': 14081, 'sha256': '8b7aa7ef3b3772da13ea4f7009d8c478e0c92bc207d65db3f45c23453097d7a2'}, 'evidence-tools-02/test_evidence_tools.py': {'bytes': 14256, 'sha256': 'b553758300c7baf9b9fb1d1d253e908946e6f9d1548ca3a64b9db9d5208d15c4'}, 'evidence-tools-02/tools-manifest.json': {'bytes': 2670, 'sha256': '750c007ab09d2c0e14ffad80797674444ce1abe265024be63ee13d42128d8c46'}, 'evidence-tools-02/verify_r36_evidence.py': {'bytes': 9902, 'sha256': 'c89ed01e2a5ad3cb1812bc2f8291465341faefcb66112943f04dc2c6413668a9'}}, 'prior_tools': {'README.md': {'bytes': 7376, 'sha256': '39d80f31e74b9ac9e793dc5235e8a2300e133dcb8527719f10d7922695106e2d'}, 'evidence_policy.py': {'bytes': 11312, 'sha256': '4e1119db0aa3e3bf5c911513a360b568239079d6a66f6cacba719b5d18c184c4'}, 'holder-copy-manifest.example.json': {'bytes': 90, 'sha256': 'b9fb1ff4a434c1b119ca1935981c4afe61c3b08d5ab4767dfb4add5363f9050e'}, 'independent-review.json': {'bytes': 1640, 'sha256': 'eb7812c8a25999a086314c8067866c2268dd139f9919385738b7872cb9c2b85d'}, 'local-validation.json': {'bytes': 6667, 'sha256': 'e6066b3d2fcbf3e0c6dab586895e4ec843f72e7c4b973be2928516a6e77363d9'}, 'pack_r36_evidence.py': {'bytes': 7959, 'sha256': 'ec5580319b8123af52338fa53f802cabd5d08e357ee718860bf962660e75cbfc'}, 'scan_evidence.py': {'bytes': 4859, 'sha256': 'c8a5004b520f591968610e5b31a8f1fc8722508ecbedc09270c95737503e65e8'}, 'stable_xz_archive.py': {'bytes': 14081, 'sha256': '8b7aa7ef3b3772da13ea4f7009d8c478e0c92bc207d65db3f45c23453097d7a2'}, 'static-frontier-review.md': {'bytes': 4838, 'sha256': '79c5ef5b4263ed9a058be9d1c46fc5a4f305c4b907750bdea720226d0d0a156d'}, 'test_evidence_tools.py': {'bytes': 8352, 'sha256': '992cf4501a90fedadc47e772b6324668b705495df6f4df41b0f6285ca7f20861'}, 'tools-manifest.json': {'bytes': 2108, 'sha256': '671ceabc288a65637bc7ccf8301bd3016abb9747c8fe93d4e8c849bdea186527'}, 'verify_r36_evidence.py': {'bytes': 9417, 'sha256': 'c0814f02f90828998f8f1e37200d5e22a9c7a2a9755e90a86974312864213235'}}, 'prior_failure': {'bytes': 2129, 'sha256': '24ef364dc00258ad354ec5650950060ac8e91f823c6598d922b8a18452752332'}}
ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r36')
PHASE = 'prewrite'
CREATED = False


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def original(path, pin):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid(),
         'original must be a direct owned regular file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        raw = stream.read(65537)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(all(getattr(before, key) == getattr(after, key) == getattr(path.lstat(), key) for key in fields),
         'original changed during read')
    need(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'], 'original bytes differ')
    return raw


def create(path, body):
    with path.open('xb') as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main():
    global PHASE, CREATED
    os.umask(0o077)
    need(sys.platform == 'linux' and os.geteuid() != 0, 'native nonroot Linux operator required')
    need(ROOT.resolve(strict=True) == ROOT and ROOT.lstat().st_uid == os.geteuid(), 'direct owned R36 root required')
    supplied = sys.stdin.buffer.read(1048577)
    need(len(supplied) <= 1048576, 'installation input exceeds fixed bound')
    package = json.loads(supplied)
    need(set(package) == {'schema', 'archive_base64'} and package['schema'] == 'hepta-r36-evidence-tools-install-input/v2',
         'installation input schema differs')
    raw = base64.b64decode(package['archive_base64'], validate=True)
    need(len(raw) == PINS['archive']['bytes'] and hashlib.sha256(raw).hexdigest() == PINS['archive']['sha256'],
         'deployment archive differs')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=256 * 1024**2)
    expanded = decoder.decompress(raw, max_length=4 * 1024**2 + 1)
    need(len(expanded) <= 4 * 1024**2 and decoder.eof and not decoder.unused_data
         and decoder.check == lzma.CHECK_SHA256, 'single bounded SHA256 XZ stream required')
    expected = ['_export-manifest.json'] + sorted(PINS['files'])
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        members = archive.getmembers()
        need([member.name for member in members] == expected, 'canonical deployment member list differs')
        for member in members:
            need(member.type == tarfile.REGTYPE and not member.linkname and not member.pax_headers
                 and member.mode == 0o600 and member.uid == member.gid == member.mtime == 0
                 and not member.uname and not member.gname and 0 < member.size <= 65536,
                 'unsafe deployment member')
            body = archive.extractfile(member).read()
            need(len(body) == member.size, 'truncated deployment member')
            contents[member.name] = body
    manifest_raw = contents['_export-manifest.json']
    need(len(manifest_raw) == PINS['manifest']['bytes'] and hashlib.sha256(manifest_raw).hexdigest() == PINS['manifest']['sha256'],
         'deployment manifest differs')
    manifest = json.loads(manifest_raw)
    destination = ROOT / 'evidence-tools-02'
    need(manifest['schema'] == 'hepta-r36-evidence-tools-deployment/v2'
         and manifest['destination'] == str(destination) and set(manifest['files']) == set(PINS['files']),
         'fixed deployment destination or inventory differs')
    for name, pin in PINS['files'].items():
        need(name.startswith('evidence-tools-02/') and Path(name).parent == Path('evidence-tools-02')
             and all(manifest['files'][name][key] == pin[key] for key in ('bytes', 'sha256')),
             'member escaped new deployment directory')
        need(len(contents[name]) == pin['bytes'] and hashlib.sha256(contents[name]).hexdigest() == pin['sha256'],
             'deployment member differs')
    for name, pin in PINS['prior_tools'].items():
        original(ROOT / 'evidence-tools-01' / name, pin)
    original(ROOT / 'evidence-export-01/export-failure.json', PINS['prior_failure'])
    manifest_path = ROOT / 'evidence-tools-deployment-manifest-02.json'
    receipt_path = ROOT / 'evidence-tools-installation-02.json'
    for path in (destination, manifest_path, receipt_path):
        need(not os.path.lexists(path), 'installation requires fresh revision-2 destinations')
    PHASE = 'create-new-tool-directory'
    destination.mkdir(mode=0o700)
    CREATED = True
    for name in sorted(PINS['files']):
        create(ROOT / name, contents[name])
    create(manifest_path, manifest_raw)
    for name, pin in PINS['files'].items():
        original(ROOT / name, pin)
    for name, pin in PINS['prior_tools'].items():
        original(ROOT / 'evidence-tools-01' / name, pin)
    original(ROOT / 'evidence-export-01/export-failure.json', PINS['prior_failure'])
    receipt = {'schema': 'hepta-r36-evidence-tools-installation/v2', 'passed': True,
               'destination': str(destination), 'archive': PINS['archive'], 'manifest': PINS['manifest'],
               'installed_files': PINS['files'], 'original_tool_files_unchanged': PINS['prior_tools'],
               'original_capture_failure_unchanged': PINS['prior_failure'],
               'workloads_started': 0, 'runtime_source_modified': False, 'candidate_adopted': False}
    create(receipt_path, (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode())
    sync_directory(destination)
    sync_directory(ROOT)
    PHASE = 'completed'
    print(json.dumps({'passed': True, 'installed_files': len(PINS['files']), 'destination': str(destination),
                      'archive_sha256': PINS['archive']['sha256'], 'original_tools_and_failure_unchanged': True,
                      'workloads_started': 0, 'candidate_adopted': False}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'passed': False, 'phase': PHASE, 'error_type': type(error).__name__,
                          'new_tool_directory_created': CREATED, 'original_files_modified': False,
                          'workloads_started': 0, 'candidate_adopted': False}), flush=True)
        raise SystemExit(1)
