"""Compile frozen annotation owners with pinned B3 custody and complete receipts."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import sys

ROOT = Path(__file__).resolve().parent
MODULES = ('scope_annotation_span', 'serde_error_span', 'serde_json_span', 'text_result_constructor')
SHA = lambda raw: hashlib.sha256(raw).hexdigest()

def verify_source():
    manifest = json.loads((ROOT / 'SOURCE_MANIFEST.json').read_bytes())
    actual = {p.relative_to(ROOT).as_posix(): p for p in ROOT.rglob('*') if p.is_file() and p != ROOT / 'SOURCE_MANIFEST.json'}
    assert set(actual) == set(manifest['files'])
    for name, path in actual.items():
        assert not path.is_symlink()
        data = path.read_bytes()
        assert {'bytes': len(data), 'sha256': SHA(data)} == manifest['files'][name], name
    return SHA((ROOT / 'SOURCE_MANIFEST.json').read_bytes())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--bootstrap', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source_sha = verify_source()
    args.output.mkdir(parents=True, exist_ok=False)
    if args.bootstrap is not None:
        shutil.copytree(args.bootstrap, args.output / 'bootstrap')
    else:
        assert os.environ.get('GITHUB_ACTIONS') == 'true', 'local builds require the copied verified B3'
    sys.path.insert(0, str(ROOT / 'scripts'))
    from hia_native_build import NativeBuild
    builder = NativeBuild(args.hepta, args.output)
    rows = {}
    for name in MODULES:
        manifest = builder.compile(name, ROOT / 'native' / (name + '.hepta'), standalone=None, buffer_profile='batch-plan.v1')
        rows[name] = {'manifest': manifest.relative_to(args.output).as_posix(), 'manifest_sha256': SHA(manifest.read_bytes())}
    for name, expected in builder.identity['files'].items():
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        source = args.hepta / relative
        assert not source.is_symlink() and SHA(source.read_bytes()) == expected
        target = args.output / 'compiler-source' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    assert verify_source() == source_sha
    result = {'source_manifest_sha256': source_sha, 'members': rows, 'semantic_execution': False,
              'compiler_bootstrap': 'copied verified B3' if args.bootstrap is not None else 'fresh pinned B1=B2=B3 on CI',
              'execution_source_root': str(ROOT), 'execution_build_root': str(args.output.resolve()),
              'whole_runtime_qualified': False}
    (args.output / 'BUILD.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    main()
