"""Compile the frozen controller and its already qualified HIA boundary emitter."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_build import NativeBuild

COMPILER = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
SYNC_SOURCE = 'e780e46fcdb3278b6b4e87b56da79397dc6f8abbb741e7260e7e71ac4bab07a5'
CONTROLLER_IMAGE = dict(bytes=160544, sha256='1c2d4e44f4d2185ef06dc1de0566f21a33f92bee61b05fa7ebed6ee9841de90a')
SYNC_IMAGE_SHA = '3f680858821d674511aba0a59df606bc03bc9384216e6e4fa88b1a01c7bbeae5'


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def source_identity(root):
    raw = (root / 'SOURCE_MANIFEST.json').read_bytes()
    manifest = json.loads(raw)
    actual = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
    assert actual == set(manifest['files']) | {'SOURCE_MANIFEST.json'}
    for name, expected in manifest['files'].items():
        path = root / name
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644 and path.resolve() == path
        assert pin(path.read_bytes()) == expected, name
    return hashlib.sha256(raw).hexdigest()


def build(hepta, sync_source, output):
    identity = source_identity(ROOT)
    assert source_identity(sync_source) == SYNC_SOURCE
    output.mkdir(parents=True, exist_ok=False)
    builder = NativeBuild(hepta, output)
    assert pin(builder.bootstrap().read_bytes()) == dict(bytes=673413, sha256=COMPILER)
    modules = {}
    for name, path in (
        ('audit-store-controller', ROOT / 'native/audit_store_controller.hepta'),
        ('audit-native-sync', sync_source / 'native/audit_sync_boundary.hepta'),
        ('audit-controller-callable', ROOT / 'native/audit_controller_callable.hepta'),
    ):
        manifest = builder.compile(name, path, standalone=None, buffer_profile='history.v1')
        image = (manifest.parent / 'module.image.bin').read_bytes()
        if name == 'audit-store-controller':
            assert pin(image) == CONTROLLER_IMAGE
        elif name == 'audit-native-sync':
            assert hashlib.sha256(image).hexdigest() == SYNC_IMAGE_SHA
        else:
            expected = json.loads((ROOT / 'native/callable_compiler_pin.json').read_bytes())
            assert pin(image) == expected['image']
        modules[name] = dict(manifest=str(manifest.relative_to(output)),
                             manifest_pin=pin(manifest.read_bytes()), image=pin(image))
    for name, expected in builder.identity['files'].items():
        raw = (hepta / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        retained = output / 'compiler-source' / name
        retained.parent.mkdir(parents=True, exist_ok=True)
        retained.write_bytes(raw)
    shutil.copytree(sync_source, output / 'sync-source')
    assert source_identity(output / 'sync-source') == SYNC_SOURCE
    assert source_identity(ROOT) == identity and source_identity(sync_source) == SYNC_SOURCE
    report = dict(schema='hepta.audit-store-controller.composed-build.v1',
                  source_manifest_sha256=identity, sync_source_manifest_sha256=SYNC_SOURCE,
                  compiler_sha256=COMPILER, compiler_bootstrap='fresh pinned B1=B2=B3', modules=modules,
                  compiler_files=len(builder.identity['files']), controller_semantic_execution=False,
                  public_handler_qualified=False, whole_runtime_replaced=False)
    (output / 'COMPOSED_BUILD.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--sync-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build(args.hepta.resolve(strict=True), args.sync_source.resolve(strict=True), args.output.absolute())
