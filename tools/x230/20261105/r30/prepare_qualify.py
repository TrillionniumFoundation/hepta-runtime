#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build the isolated R24 + fixed-router candidate with the original qualifier.

Keep all accepted/rejected sources, final programs, tests and raw evidence.
Retire only the completed R26 Cargo target cache, then transfer the idle R29
cache to this attempt. Neither action changes a running service.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r30')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
OLD = Path('/home/qian/hepta-runtime-optimization-20261105-r26')
CACHE_OWNER = Path('/home/qian/hepta-runtime-optimization-20261105-r29')
CHANGED = {'src/mcp/server.rs', 'src/mcp/server_tests.rs'}
CARGO_HOME = Path('/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def source_map(root):
    paths = [root / name for name in ('Cargo.toml', 'Cargo.lock', 'rustfmt.toml')]
    for name in ('src', 'examples'):
        paths.extend(p for p in (root / name).rglob('*') if p.is_file())
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(paths)}


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.next')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
    os.replace(temporary, path)


def inspect_processes(roots):
    matches, compilers, unreadable = [], [], 0
    needles = [str(root).encode() for root in roots]
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            name = (proc / 'comm').read_text().strip()
            if name in ('cargo', 'rustc', 'rust-lld', 'ld.lld', 'clippy-driver'):
                compilers.append({'pid': int(proc.name), 'comm': name})
            if proc.stat().st_uid != os.getuid():
                continue
            values = [(proc / 'cmdline').read_bytes()]
            for name in ('cwd', 'exe'):
                try:
                    values.append(os.readlink(proc / name).encode())
                except PermissionError:
                    unreadable += 1
                except FileNotFoundError:
                    pass
            try:
                for entry in (proc / 'fd').iterdir():
                    try:
                        values.append(os.readlink(entry).encode())
                    except (FileNotFoundError, PermissionError):
                        pass
            except (FileNotFoundError, PermissionError):
                pass
            if any(needle in value for needle in needles for value in values):
                matches.append({'pid': int(proc.name), 'comm': (proc / 'comm').read_text().strip()})
        except (FileNotFoundError, ProcessLookupError):
            pass
        except PermissionError:
            unreadable += 1
    return {'matched_processes': matches, 'compiler_processes': compilers,
            'unreadable_channels': unreadable, 'scope': 'same-user cmdline/cwd/exe/fd plus global compiler names'}


def retained_programs(root):
    report = json.loads((root / 'qualification-01/report.json').read_text())
    assert report['qualified'] and report['source_tested'] == report['source_after']
    result = {}
    for value in report['binaries'].values():
        p = Path(value['path'])
        assert p.is_relative_to(root / 'qualification-01') and p.resolve() == p
        assert sha(p) == value['sha256']
        result[str(p)] = value['sha256']
    for p in (root / 'qualification-01/test-binaries').iterdir():
        assert stat.S_ISREG(p.lstat().st_mode) and p.stat().st_nlink == 1
        result[str(p)] = sha(p)
    assert len(result) >= 5
    return result


def main():
    report = {'schema': 'hepta-x230-r30-preparation/v1', 'passed': False,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'automatic_retries': 0, 'production_services_modified': False,
              'source_baseline': 'baab4def80be7af015b2e7a594cb302f66c4130e',
              'proposal': 'R24 plus shared unfiltered ToolRouter only'}
    destination = ROOT / 'preparation.json'
    assert not destination.exists() and not (ROOT / 'source').exists()
    try:
        assert os.getuid() == 1000 and ROOT.resolve() == ROOT
        manifest = json.loads((ROOT / 'input.json').read_text())
        assert sha(ROOT / 'candidate.patch') == manifest['patch_sha256']
        baseline = source_map(BASE / 'source')
        qualified = json.loads((BASE / 'qualification-01/report.json').read_text())
        assert qualified['qualified'] and baseline == qualified['source_tested'] == qualified['source_after']
        assert baseline == manifest['baseline_compile_inputs']
        old_cache = OLD / 'target-build'
        cache = CACHE_OWNER / 'target-build'
        assert old_cache.resolve() == old_cache and cache.resolve() == cache
        assert set(p.name for p in old_cache.iterdir()) == {'debug', 'release', '.rustc_info.json'}
        report['retained_programs'] = retained_programs(OLD) | retained_programs(CACHE_OWNER)
        report['process_check'] = inspect_processes([old_cache, cache])
        assert not report['process_check']['matched_processes']
        assert not report['process_check']['compiler_processes']
        report['free_bytes_before'] = shutil.disk_usage(ROOT).free
        report['cache_to_retire'] = str(old_cache)
        report['cache_to_transfer'] = str(cache)
        save(destination, report)
        # Both caches are reproducible Cargo outputs. Final qualification copies
        # have independent inodes and are fully hashed above and again below.
        shutil.rmtree(old_cache)
        report['retired_r26_cache'] = not old_cache.exists()
        report['free_bytes_after_retirement'] = shutil.disk_usage(ROOT).free
        assert report['free_bytes_after_retirement'] >= 3 * 1024**3
        target = ROOT / 'target-build'
        assert not target.exists()
        cache_inode = cache.stat().st_ino
        cache.rename(target)
        assert target.stat().st_ino == cache_inode and not cache.exists()
        report['cache_transferred_by_rename'] = True
        report['new_full_cache_copy_bytes'] = 0
        for name, digest in report['retained_programs'].items():
            assert sha(Path(name)) == digest
        source = ROOT / 'source'
        shutil.copytree(BASE / 'source', source)
        subprocess.run(['/usr/bin/git', 'apply', '--check', str(ROOT / 'candidate.patch')], cwd=source, check=True)
        subprocess.run(['/usr/bin/git', 'apply', str(ROOT / 'candidate.patch')], cwd=source, check=True)
        candidate = source_map(source)
        assert candidate == manifest['candidate_compile_inputs']
        assert {p for p in candidate if candidate[p] != baseline[p]} == CHANGED
        report['source_before_qualification'] = candidate
        save(destination, report)
        command = ['/usr/bin/python3', '-B', '-u', str(source / 'tools/x230/20261028/qualify.py'),
                   '--source', str(source), '--output', str(ROOT / 'qualification-01'),
                   '--target', str(target), '--cargo-home', str(CARGO_HOME), '--jobs', '2']
        report['qualification_command'] = command
        result = subprocess.run(command, cwd=source)
        report['qualification_returncode'] = result.returncode
        report['source_after_qualification'] = source_map(source)
        report['passed'] = result.returncode == 0
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save(destination, report)
        print(json.dumps({key: report.get(key) for key in
                          ('passed', 'error', 'qualification_returncode', 'free_bytes_after_retirement')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
