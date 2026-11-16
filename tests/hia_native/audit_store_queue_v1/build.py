"""Build only with the exact B3 compiler and frozen complete source closure."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_build import NativeBuild

COMPILER = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def verify_source():
    raw = (ROOT / 'SOURCE_MANIFEST.json').read_bytes()
    manifest = json.loads(raw)
    actual = {path.relative_to(ROOT).as_posix() for path in ROOT.rglob('*') if path.is_file()}
    assert actual == set(manifest['files']) | {'SOURCE_MANIFEST.json'}
    for name, expected in manifest['files'].items():
        path = ROOT / name
        assert path.is_file() and not path.is_symlink() and path.resolve() == path
        assert pin(path.read_bytes()) == expected, name
    return hashlib.sha256(raw).hexdigest()


def build(hepta, output, cache=None):
    source = verify_source()
    output.mkdir(parents=True, exist_ok=False)
    if cache is not None:
        shutil.copytree(cache / 'bootstrap', output / 'bootstrap')
    builder = NativeBuild(hepta, output)
    assert hashlib.sha256(builder.bootstrap().read_bytes()).hexdigest() == COMPILER
    module = builder.compile('audit-store-queue', ROOT / 'native/audit_store_queue.hepta',
                             standalone=None, buffer_profile='history.v1')
    for name, expected in builder.identity['files'].items():
        raw = (hepta / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        retained = output / 'compiler-source' / name
        retained.parent.mkdir(parents=True, exist_ok=True)
        retained.write_bytes(raw)
    assert verify_source() == source
    report = dict(schema='hepta.runtime.audit-store-queue.build.v1',
                  source_manifest_sha256=source, compiler_sha256=COMPILER,
                  compiler_bootstrap='fresh pinned B1=B2=B3 on CI' if cache is None else 'copied verified B1=B2=B3',
                  module=str(module.relative_to(output)), module_manifest=pin(module.read_bytes()),
                  semantic_execution=False, whole_runtime_replaced=False)
    (output / 'BUILD.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    build(args.hepta.resolve(), args.output.resolve(), None if args.cache is None else args.cache.resolve())
