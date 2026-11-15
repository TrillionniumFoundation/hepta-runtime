"""Real cache and artifact substitutions against the fixed directory builder."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_directory_service_build as builder
from hia_native_build import NativeBuild, json_bytes

sha = lambda raw: hashlib.sha256(raw).hexdigest()
NAMES = ('source-image', 'source-profile', 'selected-build-driver', 'compiler-commit-missing',
    'compiler-commit-wrong', 'consistently-rehashed-native-image', 'empty-compiler-stdout',
    'empty-packer-stdout', 'packer-manifest', 'packer-not-reaped', 'packer-nonzero-exit',
    'consistently-rehashed-final-elf', 'embedded-fence', 'packing-frame', 'artifact-symlink',
    'cached-bootstrap-commit-missing', 'cached-bootstrap-commit-wrong')


class Mutation:
    def __init__(self):
        self.original = {}

    def save(self, path):
        if path not in self.original:
            self.original[path] = (path.read_bytes(), path.stat().st_mode & 0o777)

    def write(self, path, raw):
        self.save(path)
        mode = path.stat().st_mode & 0o777
        path.chmod(mode | 0o200)
        path.write_bytes(raw)
        path.chmod(mode)

    def json(self, path, value):
        self.write(path, json_bytes(value))

    def restore(self):
        for path, (raw, mode) in self.original.items():
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                path.chmod(mode | 0o200)
            path.write_bytes(raw); path.chmod(mode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve(); args.output.mkdir(parents=True, exist_ok=False)
    build = NativeBuild(args.hepta, args.build_root); build.bootstrap()
    frozen = args.manifest.resolve(strict=True)
    before = {str(p): sha(p.read_bytes()) for p in (Path(__file__), Path(builder.__file__))}
    report = dict(schema='hepta.directory-service.builder-controls.v1', status='FAIL',
        accepted=[], refused=[], expected_refusals=list(NAMES), native_semantic_cases_added=0,
        original_executions=0, source_sha256=before, production_activated=False, whole_runtime_replaced=False)
    def save():
        (args.output / 'report.json').write_bytes(json_bytes(report))
    def refused(name, action):
        try:
            action()
        except (ValueError, AssertionError, FileNotFoundError) as error:
            report['refused'].append(dict(name=name, error_type=type(error).__name__, reason=str(error)))
        else:
            raise AssertionError('altered evidence accepted: ' + name)
    try:
        builder.verify_bundle(frozen, args.hepta, args.build_root, source_root=ROOT, build=build)
        report['accepted'].append('complete-native-compile-and-pack-receipts')
        actual = builder.build_directory_service(args.hepta, args.build_root, source_root=ROOT)
        if actual != frozen:
            raise AssertionError('cached builder changed the completed artifact')
        report['accepted'].append('actual-cached-builder')
        with tempfile.TemporaryDirectory(prefix='directory-build-controls-', dir=args.output) as temporary:
            tmp = Path(temporary)
            source = tmp / 'source'; shutil.copytree(ROOT, source)
            for name, relative in [('source-image', 'native/directory_errno.hepta'),
                    ('source-profile', builder.PROFILE),
                    ('selected-build-driver', 'scripts/hia_native_directory_service_build.py')]:
                change = Mutation()
                try:
                    p = source / relative; change.write(p, p.read_bytes() + b'\n')
                    refused(name, lambda: builder.load_sources(source))
                finally:
                    change.restore()
            folder = tmp / 'bundle'; shutil.copytree(frozen.parent, folder)
            path = folder / 'manifest.json'
            def check():
                builder.verify_bundle(path, args.hepta, args.build_root, source_root=ROOT, build=build)
            def sync(data, role, change):
                record = next(x for x in data['compiled'] if x['role'] == role)
                mp = folder / record['manifest']; metadata = json.loads(mp.read_bytes())
                record['manifest_sha256'] = sha(mp.read_bytes())
                record['image_sha256'] = metadata['image_sha256']
                record['compile_files'] = {n: dict(bytes=(mp.parent / n).stat().st_size,
                    sha256=sha((mp.parent / n).read_bytes())) for n in builder.COMPILE_FILES}
                data['members'] = [next(x for x in data['compiled'] if x['role'] == 'member' + str(i)) for i in range(builder.MEMBER_COUNT)]
                change.json(path, data)
            for name in NAMES[3:15]:
                change = Mutation(); data = json.loads(path.read_bytes())
                try:
                    if name.startswith('compiler-commit-'):
                        if name.endswith('missing'): data.pop('compiler_commit')
                        else: data['compiler_commit'] = '0' * 40
                        change.json(path, data)
                    elif name == 'consistently-rehashed-native-image':
                        mp = folder / 'member0/manifest.json'; meta = json.loads(mp.read_bytes())
                        ip = mp.parent / meta['image']; image = bytearray(ip.read_bytes()); image[-1] ^= 1
                        change.write(ip, bytes(image)); meta['image_sha256'] = sha(image); change.json(mp, meta)
                        op = mp.parent / 'module.output.bin'; output = bytearray(op.read_bytes()); output[:len(image)] = image
                        change.write(op, bytes(output))
                        rp = mp.parent / 'module.receipt.json'; receipt = json.loads(rp.read_bytes())
                        receipt.update(output_sha256=sha(output), produced_sha256=sha(image))
                        change.json(rp, receipt)
                        bp = mp.parent / 'build.json'; b = json.loads(bp.read_bytes()); b['compile_receipt'] = receipt; change.json(bp, b)
                        sp = mp.parent / 'module.stdout.log'; value = json.loads(sp.read_bytes()); value['output_sha256'] = sha(output); change.json(sp, value)
                        sync(data, 'member0', change)
                    elif name == 'empty-compiler-stdout':
                        change.write(folder / 'member0/module.stdout.log', b'{}\n'); sync(data, 'member0', change)
                    elif name == 'empty-packer-stdout':
                        change.write(folder / 'service-pack.stdout.log', b'{}\n')
                    elif name == 'packer-manifest':
                        p = folder / 'service-pack.request.json'; value = json.loads(p.read_bytes())
                        value['manifest_sha256'] = '0' * 64; change.json(p, value)
                    elif name in ('packer-not-reaped', 'packer-nonzero-exit'):
                        p = folder / 'service-pack.receipt.json'; value = json.loads(p.read_bytes())
                        if name == 'packer-not-reaped': value['completed_process']['reaped'] = False
                        else: value['completed_process']['exit_code'] = 1
                        change.json(p, value); data['pack_receipt'] = value; change.json(path, data)
                    elif name == 'consistently-rehashed-final-elf':
                        p = folder / 'directory-service.elf'; raw = bytearray(p.read_bytes()); raw[-1] ^= 1
                        change.write(p, bytes(raw)); data['elf_sha256'] = sha(raw); change.json(path, data)
                    elif name == 'embedded-fence':
                        p = folder / 'fence-production.elf'; raw = bytearray(p.read_bytes()); raw[-1] ^= 1; change.write(p, bytes(raw))
                    elif name == 'packing-frame':
                        p = folder / 'service-pack.input.bin'; raw = bytearray(p.read_bytes()); raw[-1] ^= 1; change.write(p, bytes(raw))
                        rp = folder / 'service-pack.request.json'; value = json.loads(rp.read_bytes()); value['source_sha256'] = sha(raw); change.json(rp, value)
                        rp = folder / 'service-pack.receipt.json'; value = json.loads(rp.read_bytes()); value['input_sha256'] = value['source_sha256'] = sha(raw); change.json(rp, value)
                        data['pack_input_sha256'] = sha(raw); data['pack_receipt'] = value; change.json(path, data)
                    elif name == 'artifact-symlink':
                        p = folder / 'prefix.bin'; q = tmp / 'prefix-copy.bin'; q.write_bytes(p.read_bytes())
                        change.save(p); p.unlink(); p.symlink_to(q)
                    refused(name, check)
                finally:
                    change.restore()
            bootstrap = tmp / 'build'; shutil.copytree(Path(args.build_root) / 'bootstrap', bootstrap / 'bootstrap')
            receipt = bootstrap / 'bootstrap/bootstrap.json'
            for name in NAMES[-2:]:
                change = Mutation()
                try:
                    data = json.loads(receipt.read_bytes())
                    if name.endswith('missing'): data['dependency'].pop('commit')
                    else: data['dependency']['commit'] = '0' * 40
                    change.json(receipt, data)
                    refused(name, lambda: NativeBuild(args.hepta, bootstrap).bootstrap())
                finally:
                    change.restore()
        if [x['name'] for x in report['refused']] != list(NAMES) or len(report['accepted']) != 2:
            raise AssertionError('builder control domain differs')
        report['source_unchanged'] = before == {p: sha(Path(p).read_bytes()) for p in before}
        if not report['source_unchanged']:
            raise AssertionError('builder control source changed')
        report.update(status='PASS', test_summary=dict(tests_run=4, failures=0, errors=0, skipped=0,
            expected_failures=0, unexpected_successes=0))
    except BaseException as error:
        report['error'] = repr(error); raise
    finally:
        save()
    print(json.dumps({k: v for k, v in report.items() if k not in ('accepted', 'refused', 'source_sha256', 'expected_refusals')}))


if __name__ == '__main__':
    main()
