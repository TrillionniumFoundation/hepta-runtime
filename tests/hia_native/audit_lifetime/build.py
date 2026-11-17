"""Build the frozen HIA lifetime owner with the pinned self-hosted compiler."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from common import COMPILER, encoded, pin, read, require, source
from hia_native_build import NativeBuild

SYNC_SOURCE = 'e780e46fcdb3278b6b4e87b56da79397dc6f8abbb741e7260e7e71ac4bab07a5'
SYNC_EMITTER = '3f680858821d674511aba0a59df606bc03bc9384216e6e4fa88b1a01c7bbeae5'


def source_identity(root):
    raw = read(root / 'SOURCE_MANIFEST.json')
    manifest = json.loads(raw)
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    require(actual == set(manifest['files']) | {'SOURCE_MANIFEST.json'}, 'complete sync source set')
    for name, expected in manifest['files'].items():
        path = root / name
        require(stat.S_IMODE(path.lstat().st_mode) == 0o644 and pin(read(path)) == expected,
                'complete sync source: ' + name)
    return hashlib.sha256(raw).hexdigest()


def build(hepta, sync_source, output):
    identity = source()
    require(source_identity(sync_source) == SYNC_SOURCE, 'qualified synchronization owner')
    output.mkdir(parents=True, exist_ok=False)
    builder = NativeBuild(hepta, output)
    require(pin(builder.bootstrap().read_bytes()) == dict(bytes=673413, sha256=COMPILER),
            'fresh exact B1=B2=B3')
    modules = {}
    for name, path in (
        ('audit-lifetime', ROOT / 'native/audit_lifetime.hepta'),
        ('audit-refs', ROOT / 'native/audit_refs_emitter.hepta'),
        ('audit-native-sync', sync_source / 'native/audit_sync_boundary.hepta'),
        ('audit-lifetime-callable', ROOT / 'native/audit_lifetime_callable.hepta'),
    ):
        manifest = builder.compile(name, path, standalone=None, buffer_profile='history.v1')
        image = read(manifest.parent / 'module.image.bin')
        if name == 'audit-native-sync':
            require(hashlib.sha256(image).hexdigest() == SYNC_EMITTER, 'unchanged native sync emitter')
        modules[name] = dict(manifest=str(manifest.relative_to(output)),
                             manifest_pin=pin(read(manifest)), image=pin(image))
    for name, expected in builder.identity['files'].items():
        raw = read(hepta / name)
        require(hashlib.sha256(raw).hexdigest() == expected, 'complete compiler source: ' + name)
        retained = output / 'compiler-source' / name
        retained.parent.mkdir(parents=True, exist_ok=True)
        retained.write_bytes(raw)
    shutil.copytree(sync_source, output / 'sync-source')
    require(source_identity(output / 'sync-source') == SYNC_SOURCE, 'retained sync source identity')
    require(source() == identity, 'lifetime source unchanged')
    report = dict(schema='hepta.audit-lifetime.build.v1', source_manifest_sha256=identity,
                  sync_source_manifest_sha256=SYNC_SOURCE, compiler_sha256=COMPILER,
                  compiler_bootstrap='fresh pinned B1=B2=B3', modules=modules,
                  compiler_files=len(builder.identity['files']), public_handler_qualified=False,
                  whole_runtime_replaced=False)
    (output / 'BUILD.json').write_bytes(encoded(report))
    print(encoded(report).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--sync-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build(args.hepta.resolve(strict=True), args.sync_source.resolve(strict=True), args.output.absolute())
