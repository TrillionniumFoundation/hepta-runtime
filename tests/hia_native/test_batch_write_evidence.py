"""Exercise real retained-artifact admission without executing semantic owners.

Every damaged file lives in this invocation's private copy. Consistent outer
rehashing is deliberate: the fixed source/image and full-domain checks must
reject it independently of a stale enclosing digest.
"""
from __future__ import annotations
import argparse
import contextlib
import gzip
import json
from pathlib import Path
import shutil
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / 'scripts') not in sys.path: sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_batch_write_build as build
import hia_native_batch_write_qualification as q
from hia_native_batch_write_build import read, obj, exact, require, sha, canonical, file_record

CONTROLS = (
    ('elf-prefix', 'batch-write fixed syscall/thread boundary differs'),
    ('elf-table', 'batch-write fixed image table differs'),
    ('elf-image-rehashed', 'batch-write expected leaf image differs'),
    ('module-image-rehashed', 'batch-write module differs: history/image_sha256'),
    ('compiler-dependency-rehashed', 'batch-write complete compiler source closure differs'),
    ('compiler-input-claim-rehashed', 'atomic native receipt differs: source_unchanged'),
    ('packer-limit-rehashed', 'batch-write actual pack stdout field differs: limits'),
    ('packer-output-tail-rehashed', 'batch-write actual pack output or untouched tail differs'),
    ('registry-rehashed', 'batch-write relative image registry differs'),
    ('original-source', 'batch-write frozen source differs: src/mcp/fs/core.rs'),
    ('controller-buffer-mutated-rehashed', 'batch complete direct trace differs'),
    ('file-body-domain-rehashed', 'batch full file content domain differs'),
    ('kernel-control-omitted-rehashed', 'batch-write required real kernel controls omitted'),
    ('render-full-corpus-shortened', 'batch complete renderer corpus differs'),
    ('wide-valid-gzip-suffix-rehashed', 'batch complete 1.279 GB response domain changed'),
)


def run(root, manifest, corpus, stdout_dir, output):
    root, manifest, corpus, stdout_dir = [Path(p).resolve(strict=True) for p in (root, manifest, corpus, stdout_dir)]
    output = Path(output).resolve(); output.mkdir(mode=0o700)
    started = time.monotonic(); sources = q.pins(root)
    native = q.native_evidence(manifest, corpus, stdout_dir, root=root)
    copied = output / 'artifact-copy'; shutil.copytree(manifest.parent, copied)
    exact(build.inspect_bundle(copied / 'manifest.json', source_root=root), native['artifact'], 'valid artifact copy changed')
    rows = []

    @contextlib.contextmanager
    def changes():
        originals, modes, mutations = {}, {}, {}
        def write(path, value):
            path = Path(path)
            if path not in originals:
                originals[path] = read(path); modes[path] = stat.S_IMODE(path.stat().st_mode)
            path.chmod(modes[path] | stat.S_IWUSR)
            if not isinstance(value, bytes): value = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
            path.write_bytes(value)
            mutations[str(path.relative_to(output))] = dict(before=dict(bytes=len(originals[path]), sha256=sha(originals[path])),
                after=dict(bytes=len(value), sha256=sha(value)))
        try: yield write, mutations
        finally:
            for path, raw in originals.items():
                path.write_bytes(raw); path.chmod(modes[path])

    def reject(name, action, mutations):
        expected = dict(CONTROLS)[name]
        try: action()
        except ValueError as error:
            exact(str(error), expected, 'control was refused by an unintended guard: ' + name)
            rows.append(dict(name=name, status='REJECTED', error=str(error), changed_files=mutations.copy()))
        else: raise AssertionError('damaged batch-write evidence was accepted: ' + name)

    images = {name: read(copied / (name + '.image.bin')) for name in build.ORDER}
    elf = read(copied / 'batch-write.elf')
    with changes() as (write, mutations):
        damaged = bytearray(elf); damaged[176] ^= 1; write(copied / 'batch-write.elf', bytes(damaged))
        reject('elf-prefix', lambda: build.inspect_elf(read(copied / 'batch-write.elf'), images, root), mutations)
    with changes() as (write, mutations):
        damaged = bytearray(elf); damaged[build.TABLE + 8] ^= 1; write(copied / 'batch-write.elf', bytes(damaged))
        reject('elf-table', lambda: build.inspect_elf(read(copied / 'batch-write.elf'), images, root), mutations)
    with changes() as (write, mutations):
        damaged = bytearray(elf); damaged[-1] ^= 1; write(copied / 'batch-write.elf', bytes(damaged))
        linked = dict(images); linked[build.ORDER[-1]] = bytes(damaged[-len(linked[build.ORDER[-1]]):])
        reject('elf-image-rehashed', lambda: build.inspect_elf(read(copied / 'batch-write.elf'), linked, root), mutations)
    with changes() as (write, mutations):
        damaged = bytearray(images['history']); damaged[-1] ^= 1
        write(copied / 'history.image.bin', bytes(damaged))
        metadata = obj(copied / 'history.json'); metadata['image_sha256'] = sha(damaged); write(copied / 'history.json', metadata)
        reject('module-image-rehashed', lambda: build.inspect_module(copied, 'history', root), mutations)
    with changes() as (write, mutations):
        path = copied / 'batch_write-build/build.json'; report = obj(path)
        report['compiler_dependency']['files']['tools/hia_selfhost_child.py'] = '00' * 32; write(path, report)
        reject('compiler-dependency-rehashed', lambda: build.inspect_module(copied, 'batch_write', root), mutations)
    with changes() as (write, mutations):
        directory = copied / 'batch_write-build'
        for name in ('module.stdout.log', 'module.receipt.json'):
            report = obj(directory / name); report['source_unchanged'] = False; write(directory / name, report)
        report = obj(directory / 'build.json'); report['compile_receipt']['source_unchanged'] = False; write(directory / 'build.json', report)
        reject('compiler-input-claim-rehashed', lambda: build.inspect_module(copied, 'batch_write', root), mutations)
    with changes() as (write, mutations):
        for name in ('pack.stdout.log', 'pack.receipt.json'):
            report = obj(copied / name); report['limits']['cpu_seconds'] = 11; write(copied / name, report)
        reject('packer-limit-rehashed', lambda: build.inspect_pack(copied, build.pack_frame(images), elf, root), mutations)
    with changes() as (write, mutations):
        raw = bytearray(read(copied / 'pack.output.bin')); raw[-1] ^= 1; write(copied / 'pack.output.bin', bytes(raw))
        for name in ('pack.stdout.log', 'pack.receipt.json'):
            report = obj(copied / name); report['output_sha256'] = sha(raw); write(copied / name, report)
        reject('packer-output-tail-rehashed', lambda: build.inspect_pack(copied, build.pack_frame(images), elf, root), mutations)
    with changes() as (write, mutations):
        registry = obj(copied / 'registry.json'); registry['history']['image_sha256'] = '00' * 32; write(copied / 'registry.json', registry)
        report = obj(copied / 'manifest.json'); report['registry'] = file_record(copied / 'registry.json'); write(copied / 'manifest.json', report)
        reject('registry-rehashed', lambda: build.inspect_bundle(copied / 'manifest.json', source_root=root), mutations)
    shadow = output / 'source-copy'
    for name in sources:
        (shadow / name).parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(root / name, shadow / name)
    with changes() as (write, mutations):
        path = shadow / 'src/mcp/fs/core.rs'; write(path, read(path) + b'\n')
        reject('original-source', lambda: build.source_pins(shadow), mutations)

    controller = output / 'controller-copy'; shutil.copytree(corpus / 'controller', controller)
    controller_stdout = output / 'controller.stdout'; shutil.copyfile(stdout_dir / 'test_batch_write_controller.py.stdout', controller_stdout)
    with changes() as (write, mutations):
        path = controller / 'calls.jsonl.gz'
        # Preserve counts and per-row shapes; alter one full borrowed-buffer
        # byte while consistently rehashing the enclosing compressed capture.
        raw = gzip.decompress(read(path)); needle = b'"workspace_before_sha256":"'
        at = raw.index(needle) + len(needle); damaged = raw[:at] + (b'1' if raw[at:at+1] != b'1' else b'2') + raw[at+1:]
        write(path, gzip.compress(damaged, compresslevel=1, mtime=0))
        report = obj(controller / 'result.json'); report['calls.jsonl.gz'] = file_record(path)
        write(controller / 'result.json', report); write(controller_stdout, report)
        reject('controller-buffer-mutated-rehashed', lambda: q.controller_evidence(controller, manifest, controller_stdout, root), mutations)
    files = output / 'files-copy'; shutil.copytree(corpus / 'files/native', files)
    with changes() as (write, mutations):
        path = files / 'events.jsonl.gz'; events = [json.loads(row) for row in gzip.decompress(read(path)).splitlines()]
        body = next(row for event in events for row in event['filesystem'] if row.get('sha256'))
        body['sha256'] = '00' * 32; write(path, gzip.compress(b''.join(canonical(row) + b'\n' for row in events),mtime=0))
        report = obj(files / 'result.json'); report['events.jsonl.gz'] = file_record(path); write(files / 'result.json', report)
        reject('file-body-domain-rehashed', lambda: q.file_process_evidence(files, build.ELF_SHA, root=root), mutations)
    from test_batch_write_kernel import cases
    index, config = next((i, row) for i, row in enumerate(cases()) if row.get('faults'))
    kernel = output / 'kernel-copy'; shutil.copytree(corpus / 'kernel' / ('%03d-' % index + config['name']) / 'native', kernel)
    with changes() as (write, mutations):
        path = kernel / 'result.json'; report = obj(path)
        for row in report['events']: row.pop('control_index', None)
        write(path, report)
        reject('kernel-control-omitted-rehashed', lambda: q.kernel_process_evidence(kernel, config, build.ELF_SHA), mutations)
    renderer = output / 'render-copy'; shutil.copytree(corpus / 'render', renderer)
    renderer_stdout = output / 'render.stdout'; shutil.copyfile(stdout_dir / 'test_batch_render.py.stdout', renderer_stdout)
    with changes() as (write, mutations):
        path = renderer / 'native-output.gz'; raw = gzip.decompress(read(path)); write(path, gzip.compress(raw[:-1],mtime=0))
        reject('render-full-corpus-shortened', lambda: q.render_evidence(renderer, manifest, renderer_stdout, root), mutations)
    wide = output / 'wide-copy'; shutil.copytree(corpus / 'wide/native', wide)
    with changes() as (write, mutations):
        path = wide / 'normalized.bin.gz'; write(path, read(path)+gzip.compress(b'x',mtime=0))
        raw = q.stream_record(path,True); compressed = file_record(path)
        report = obj(wide / 'result.json')
        report['streams']['normalized'] = dict(raw_bytes=raw['bytes'],raw_sha256=raw['sha256'],gzip_bytes=compressed['bytes'],gzip_sha256=compressed['sha256'])
        write(wide / 'result.json', report)
        reject('wide-valid-gzip-suffix-rehashed', lambda: q.wide_process_evidence(wide,build.ELF_SHA,root), mutations)
    exact([row['name'] for row in rows], [row[0] for row in CONTROLS], 'batch-write refusal control domain omitted')
    exact(build.inspect_bundle(manifest, source_root=root), native['artifact'], 'batch-write controls changed the original artifact')
    exact(q.pins(root), sources, 'batch-write controls changed their actual source')
    report = dict(schema='hepta.runtime.batch-write-evidence-controls.v1', status='PASS',
        source_files=sources, native_evidence_sha256=sha(canonical(native)),
        accepted_controls=2, rejected_controls=len(rows), controls=rows,
        new_native_calls=0, new_original_calls=0, production_activated=False,
        elapsed_seconds=time.monotonic() - started)
    (output / 'result.json').write_bytes(canonical(report) + b'\n')
    summary = {key: value for key, value in report.items() if key not in ('source_files', 'controls')}
    summary['result'] = file_record(output / 'result.json')
    print(json.dumps(summary, sort_keys=True))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'bundle', 'corpus', 'stdout-dir', 'output'): parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    run(args.root, args.bundle, args.corpus, args.stdout_dir, args.output)
