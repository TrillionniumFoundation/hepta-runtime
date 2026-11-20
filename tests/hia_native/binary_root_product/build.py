"""Build isolated product and fixture graphs using checked retained members.

The retained default build is a normal hia_native_runtime_mcp_build.py output.
Every reused member and packed worker is checked by the unchanged product
builder; only the imported owner requires a fresh direct-member compile.
"""
from pathlib import Path
import argparse, json, shutil, sys, time
sys.dont_write_bytecode = True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base-source', 'source', 'hepta', 'baseline-build', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source, base, hepta, retained = [p.resolve(strict=True) for p in
        (args.source, args.base_source, args.hepta, args.baseline_build)]
    output = args.output.absolute(); assert not output.exists(); output.mkdir(parents=True)
    sys.path.insert(0, str(source / 'scripts'))
    sys.path.insert(0, str(source / 'tests/hia_native/binary_root_product'))
    from public_nine_build import build_runtime_mcp
    from verify_source import check
    source_result = check(base, source, hepta)
    old = json.loads((retained / 'build/public-task-batch-extract/manifest.json').read_bytes())
    assert old['elf_sha256'] == 'cfc51c7004da6dd45d7d42314188563b6e83c6b03df4478a2281ef0b5d750755'
    original_root = Path(old['build_root'])
    reuse = {r['name']: str(retained / 'build' / Path(r['manifest']).relative_to(original_root)) for r in old['members']}
    report = {'status': 'RUNNING', 'source': source_result, 'builds': {}}
    start = time.monotonic()
    try:
        for label, root, private, manifests in (
            ('baseline-fixture', base, True, reuse),
            ('product', source, False, {k: v for k, v in reuse.items() if k != 'owner'}),
            ('fixture', source, True, None)):
            build = output / label
            shutil.copytree(retained / 'build/bootstrap', build / 'bootstrap')
            if manifests is None:
                previous = json.loads(Path(report['builds']['product']).read_bytes())
                manifests = {r['name']: r['manifest'] for r in previous['members']}
            result = build_runtime_mcp(hepta, build, name=label, source_root=root, manifests=manifests,
                private_fixture=private, bellman_port_build=retained / 'port/build-v3',
                bellman_port_package=root / 'runtime_support/bellman_port', bellman_worker_build=retained / 'worker')
            report['builds'][label] = str(result)
        report['status'] = 'PASS'
    except BaseException as exc:
        report.update(status='FAIL', error=repr(exc)); raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - start
        (output / 'BUILD.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))
if __name__ == '__main__': main()
