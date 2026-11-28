"""Reproduce the source and compile the three actual pipeline owners."""
import argparse
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import author_projection
import common as c

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--hepta', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--bootstrap', type=Path)
    a = p.parse_args(); output = a.output.absolute()
    c.source_check(); output.mkdir(parents=True, exist_ok=False)
    author_projection.generate(a.hepta.resolve(strict=True), ROOT, output / 'reproduced')
    for name in ('catalog_eleven_policy.hepta', 'projection-proof.json'):
        assert (output / 'reproduced' / name).read_bytes() == (ROOT / 'native' / name).read_bytes()
    if a.bootstrap:
        (output / 'bootstrap').mkdir()
        r = c.base_reader().Reader(a.bootstrap.resolve(strict=True))
        for name in ('bootstrap.json', 'B1.image.bin', 'B2.image.bin', 'B3.image.bin'):
            c.put(output / 'bootstrap' / name, r.raw(name))
    else:
        assert os.environ.get('GITHUB_ACTIONS') == 'true', 'fresh bootstrap is CI-only'
    sys.path.insert(0, str(ROOT / 'policy_base/runtime_support/scripts'))
    from hia_native_build import NativeBuild
    builder = NativeBuild(a.hepta.resolve(strict=True), output)
    for name, (path, expected, profile) in c.module_pins().items():
        assert c.sha((ROOT / path).read_bytes()) == expected
        builder.compile(name, ROOT / path, standalone=None, buffer_profile=profile)
    reader, modules = c.build_check(output)
    c.put(output / 'projection-build.json', {'status': 'PASS', 'modules': modules,
        'source_profile': c.pin((ROOT / 'source-profile.json').read_bytes()),
        'copied_qualified_bootstrap': a.bootstrap is not None, 'fresh_original_build': False})
    print(c.encoded({'status': 'PASS', 'modules': modules}).decode())
