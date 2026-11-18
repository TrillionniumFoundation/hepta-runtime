# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run one unchanged filesystem matrix, bind real PIDs, then retire its fixtures."""
from pathlib import Path
import argparse
import contextlib
import io
import json
import os
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from audit_stamp_registry import HARNESS, encoded, regular, require, sha
from stamp_evidence import COUNTS, capture, capture_files, harness


def retire(folder, module, count):
    paths = [];present = []
    for index in range(count):
        case = folder / ('case-%03d' % index)
        row = json.loads(regular(case / 'result.json'))
        require(module.snapshot(case) == row['final_filesystem'], 'completed fixture changed before retirement')
        for name in ('fixture', 'held'):
            path = case / name;paths.append(str(path.relative_to(folder)))
            if not path.exists():
                require(not path.is_symlink(), 'unrecognized fixture symlink');continue
            before = path.lstat()
            require(before.st_uid == os.getuid() and not stat.S_ISLNK(before.st_mode)
                and (stat.S_ISREG(before.st_mode) or stat.S_ISFIFO(before.st_mode) or stat.S_ISDIR(before.st_mode)),
                'unowned or unexpected fixture retirement target')
            present.append((path, before))
    evidence = sha(encoded(capture_files(folder)))
    require(shutil.rmtree.avoids_symlink_attacks, 'descriptor-safe fixture retirement is unavailable')
    for path, before in present:
        current = path.lstat()
        require((current.st_dev, current.st_ino, current.st_mode) == (before.st_dev, before.st_ino, before.st_mode),
            'fixture was rebound before retirement')
        if stat.S_ISDIR(before.st_mode):
            path.chmod(0o700)
            for base, directories, _ in os.walk(path, followlinks=False):
                for name in directories:
                    child = Path(base) / name;meta = child.lstat()
                    require(meta.st_uid == os.getuid() and stat.S_ISDIR(meta.st_mode),
                        'fixture contains an unowned directory or symlink')
                    child.chmod(0o700, follow_symlinks=False)
            shutil.rmtree(path)
        else:
            path.unlink()
    require(sha(encoded(capture_files(folder))) == evidence, 'captured evidence changed during fixture retirement')
    receipt = {'schema': 'hepta.audit-stamp.fixture-retirement.v1', 'status': 'PASS',
        'fixture_paths': paths, 'complete_evidence_sha256': evidence,
        'all_processes_reaped_before_retirement': True, 'semantic_invocations_added': 0}
    with (folder / 'retired-fixtures.json').open('xb') as stream:
        stream.write(encoded(receipt))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', choices=tuple(COUNTS), required=True)
    for name in ('native', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--original', type=Path)
    args = parser.parse_args();owner = args.domain.removesuffix('_kernel')
    name = 'test_audit_stamp' if owner == 'stamp' else 'test_cache_stamp'
    module = harness(ROOT, name);old_init = module.Process.__init__;old_finish = module.Process.finish
    source_sha256 = sha(regular(ROOT / HARNESS / (name + '.py')))

    def observed_init(self, *values, **keywords):
        old_init(self, *values, **keywords)
        self.qualified_cwd = os.getcwd()

    def observed_finish(self):
        row = old_finish(self)
        row.update(pid=self.process.pid, cwd=self.qualified_cwd, environment={'PATH': ''},
            source_harness_sha256=source_sha256)
        (self.output / 'result.json').write_bytes(encoded(row))
        return row

    module.Process.__init__ = observed_init;module.Process.finish = observed_finish
    command = [str(ROOT / HARNESS / (name + '.py')), '--native', str(args.native), '--output', str(args.output)]
    if args.domain.endswith('_kernel'):
        command.append('--kernel')
    if args.original is not None:
        command += ['--original', str(args.original)]
    previous = sys.argv;summary = io.StringIO()
    try:
        sys.argv = command
        with contextlib.redirect_stdout(summary):
            module.main()
    finally:
        sys.argv = previous
    folder = args.output.resolve(strict=True)
    executables = {'native': args.native.resolve(strict=True)}
    if args.original is not None:
        executables['original'] = args.original.resolve(strict=True)
    report = capture(ROOT, folder, args.domain, executables, retirement=False)
    require(json.loads(summary.getvalue()) == {key: value for key, value in report.items() if key != 'cases'},
        'actual frozen harness summary differs')
    retire(folder, module, COUNTS[args.domain][0])
    capture(ROOT, folder, args.domain, executables)
    print(summary.getvalue(), end='')


if __name__ == '__main__':
    main()
