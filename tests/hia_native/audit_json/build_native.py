"""Build one exact flat audit codec in CI with the fixed HIA compiler."""
from pathlib import Path
import argparse
import os
import stat
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts')]
from common import COMPILER, encoded, loads, pin, read, require, source
from hia_native_build import NativeBuild


def run(hepta, output):
    identity = source()
    builder = NativeBuild(hepta, output)
    expected = loads(read(ROOT / 'COMPILER_IDENTITY.json'))
    require(builder.identity == expected, 'complete previously fixed compiler source closure')
    require(pin(read(builder.bootstrap())) == dict(bytes=673413, sha256=COMPILER), 'fresh exact B1=B2=B3')
    manifest = builder.compile('audit-json', ROOT / 'native/audit_json.hepta', standalone=None)
    for name, digest in expected['files'].items():
        raw = read(hepta / name)
        require(pin(raw)['sha256'] == digest, 'every retained compiler source byte')
        destination = output / 'compiler-source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(stat.S_IMODE((hepta / name).stat().st_mode))
    require(source() == identity, 'audit codec source unchanged after build')
    report = dict(schema='hepta.audit-json.build.v1', source_manifest_sha256=identity,
        compiler=expected, compiler_image=dict(bytes=673413, sha256=COMPILER),
        manifest=dict(path=str(manifest.relative_to(output)), **pin(read(manifest))),
        source=pin(read(ROOT / 'native/audit_json.hepta')),
        image=pin(read(manifest.parent / 'module.image.bin')), fresh_hia_compile=True,
        public_handler_qualified=False, whole_runtime_replaced=False)
    (output / 'BUILD.json').write_bytes(encoded(report))
    print(encoded(report).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.hepta.resolve(strict=True), args.output.absolute())
