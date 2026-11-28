"""Build one fixed graph and its journal/trace entries with the same HIA images."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import shutil
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'output', 'hepta', 'port_source', 'port_build', 'worker_build']:
        p.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    p.add_argument('--reuse', type=Path)
    p.add_argument('--bootstrap-seed', type=Path)
    a = p.parse_args()
    root = a.source.resolve(strict=True)
    output = a.output.resolve(strict=True)
    reuse = a.reuse.resolve(strict=True) if a.reuse else None
    results = []
    for name, switches in [('production', []), ('journal', ['--private-pump-fixture']),
            ('trace', ['--private-pump-fixture', '--private-pump-trace'])]:
        build_root = output / name
        build_root.mkdir(exist_ok=False)
        seed = a.bootstrap_seed if name == 'production' else output / 'production/bootstrap'
        if seed is not None:
            shutil.copytree(seed.resolve(strict=True), build_root / 'bootstrap')
        command = [sys.executable, '-I', '-S', '-B', str(root / 'scripts/public_nine_build.py'),
            '--hepta', str(a.hepta.resolve(strict=True)), '--build', str(build_root),
            '--name', 'task-pump',
            '--bellman-port-build', str(a.port_build.resolve(strict=True)),
            '--bellman-port-package', str(a.port_source.resolve(strict=True)),
            '--bellman-worker-build', str(a.worker_build.resolve(strict=True)), *switches]
        if reuse:
            command += ['--member-manifests-json', str(reuse)]
        started = time.monotonic()
        with (output / (name + '.stdout')).open('xb') as stdout, (output / (name + '.stderr')).open('xb') as stderr:
            # Every compiler/linker/packer process retains its original inner
            # deadline. No incorrect outer process-group timeout is added.
            process = subprocess.run(command, stdout=stdout, stderr=stderr)
        receipt = {'name': name, 'command': command, 'exit_code': process.returncode,
            'elapsed_seconds': time.monotonic() - started, 'new_outer_timeout': False,
            'development_reuse': bool(a.reuse)}
        for stream in ['stdout', 'stderr']:
            data = (output / (name + '.' + stream)).read_bytes()
            receipt[stream] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        (output / (name + '.process.json')).write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
        if process.returncode:
            raise RuntimeError((name, process.returncode, 'full failed streams retained'))
        manifest = build_root / 'task-pump/manifest.json'
        result = json.loads(manifest.read_bytes())
        receipt.update(manifest=str(manifest), manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            elf_sha256=result['elf_sha256'], source_binding_sha256=result['source_binding']['manifest_sha256'])
        results.append(receipt)
        print(json.dumps({'built': name, 'elf_sha256': result['elf_sha256'],
            'elapsed_seconds': receipt['elapsed_seconds']}), flush=True)
        # The private entries use exactly the production entry's HIA owners;
        # only their fixed, explicitly admitted observer capabilities differ.
        if name == 'production':
            reuse = output / 'same-hia-members.json'
            with reuse.open('x') as f:
                json.dump({row['name']: row['manifest'] for row in result['members']}, f, sort_keys=True, indent=2)
                f.write('\n')
    (output / 'OBSERVED_BUILDS.json').write_text(json.dumps(results, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
