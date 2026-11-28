#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import argparse
import hashlib
import sys
import io
import tarfile
import json
import os
import signal
import subprocess
import time
import tomllib
import shutil

parser = argparse.ArgumentParser(description="Fresh actual SDK public publisher Rust reference")
for name in ("reference", "output", "toolchain", "target"):
    parser.add_argument("--" + name, required=True, type=Path)
args = parser.parse_args()
assert os.environ.get("GITHUB_ACTIONS") == "true", "Rust compilation only on authorized CI"
REFERENCE = args.reference.resolve(strict=True)
OUT = args.output.resolve()
assert not OUT.is_relative_to(REFERENCE)
sys.path.insert(0, str(Path(__file__).resolve().parent))
OUT.mkdir(exist_ok=False)
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def sources():
    return {str(p.relative_to(REFERENCE)): dict(bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
            for p in sorted(REFERENCE.rglob('*')) if p.is_file()}


from verify_reference import verify
source_proof = verify(REFERENCE, args.target)
frozen = sources()
(OUT / 'source-closure.json').write_text(json.dumps(frozen, sort_keys=True) + '\n')
rust = args.toolchain.resolve(strict=True)
env = {k:v for k,v in os.environ.items() if not k.startswith(('CARGO', 'RUST'))}
env.update(PATH=str(rust) + ':/usr/bin:/bin', RUSTC=str(rust / 'rustc'),
           CARGO_TARGET_DIR=str(OUT / 'target'), CARGO_BUILD_JOBS='2', LC_ALL='C')
receipts = []


def execute(name, command):
    command = list(map(str, command))
    begin, timed = time.monotonic(), False
    with (OUT / (name + '.stdout')).open('xb') as stdout, (OUT / (name + '.stderr')).open('xb') as stderr:
        process = subprocess.Popen(command, cwd=REFERENCE, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            process.wait(timeout=180)
        except subprocess.TimeoutExpired:
            timed = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    row = dict(name=name, command=command, cwd=str(REFERENCE), pid=process.pid,
               exit_code=process.returncode, timed_out=timed, timeout_seconds=180,
               elapsed_seconds=time.monotonic() - begin,
               env={k:env[k] for k in ('PATH','RUSTC','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','LC_ALL')})
    for stream in ('stdout', 'stderr'):
        p = OUT / (name + '.' + stream)
        raw = p.read_bytes()
        row[stream] = dict(path=p.name, bytes=len(raw), sha256=sha(raw))
    receipts.append(row)
    (OUT / 'processes.json').write_text(json.dumps(receipts, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k:row[k] for k in ('name','exit_code','timed_out','elapsed_seconds')}), flush=True)
    if timed or process.returncode != 0:
        sys.stderr.buffer.write((OUT / (name + ".stderr")).read_bytes())
        sys.stderr.buffer.flush()
    assert not timed and process.returncode == 0, row
    return (OUT / (name + '.stdout')).read_bytes()


version = execute('rustc-version', [rust / 'rustc', '--version'])
assert version == b'rustc 1.95.0 (59807616e 2026-04-14)\n'
execute('cargo-version', [rust / 'cargo', '--version'])
execute('cargo-fetch', [rust / 'cargo', 'fetch', '--locked', '--manifest-path', REFERENCE / 'Cargo.toml'])
metadata = json.loads(execute('cargo-metadata', [rust / 'cargo', 'metadata', '--locked', '--offline',
    '--format-version', '1', '--manifest-path', REFERENCE / 'Cargo.toml']))
target = {(p['name'],p['version']):p for p in tomllib.loads((REFERENCE / 'target/Cargo.lock').read_text())['package'] if 'source' in p}
registry = []
for package in metadata['packages']:
    if package['source'] is None:
        assert package['name'] == 'hepta-text-editor-gateway-local-original-oracle'
        continue
    key = package['name'], package['version']
    assert key in target and package['source'] == target[key]['source'], key
    root = Path(package['manifest_path']).parent
    registry_root = root.parent.parent.parent
    archive_path = registry_root / 'cache' / root.parent.name / (root.name + '.crate')
    archive_raw = archive_path.read_bytes()
    assert sha(archive_raw) == target[key]['checksum'], key
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode='r:gz') as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts
            assert parts[0] == root.name and '..' not in parts, member.name
            if member.isdir():
                continue
            assert member.isfile(), member.name
            relative = str(Path(*parts[1:]))
            archived = archive.extractfile(member).read()
            actual = (root / relative).read_bytes()
            assert actual == archived, (key, relative)
            files[relative] = dict(bytes=len(actual), sha256=sha(actual))
    retained = OUT / "registry-source" / root.name
    retained.mkdir(parents=True, exist_ok=False)
    for relative, expected in files.items():
        destination = retained / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
        assert dict(bytes=destination.stat().st_size, sha256=sha(destination.read_bytes())) == expected
    archives = OUT / "registry-archives"
    archives.mkdir(exist_ok=True)
    (archives / archive_path.name).write_bytes(archive_raw)
    registry.append(dict(name=key[0],version=key[1],root=str(root),
                         checksum=target[key]['checksum'],archive=str(archive_path),files=files))
(OUT / 'registry-sources.json').write_text(json.dumps(registry, sort_keys=True) + '\n')
execute('cargo-build', [rust / 'cargo', 'build', '--release', '--locked', '--offline',
                       '--manifest-path', REFERENCE / 'Cargo.toml'])
assert frozen == sources()
binary = OUT / 'target/release/hepta-text-editor-gateway-local-original-oracle'
summary = dict(status='FRESH_CURRENT_PUBLIC_PUBLISHER_REFERENCE_BUILD_PASS', binary=str(binary),
               bytes=binary.stat().st_size, sha256=sha(binary.read_bytes()), registry_crates=len(registry),
               registry_files=sum(len(p['files']) for p in registry), source_files=len(frozen),
               qualification='NOT_RUN', original_spans=120, source_proof=source_proof,
               actual_sdk_serve=True, actual_tool_call_context=True, actual_async_method_adapter=True,
               public_handler_qualified=False, full_async=False, full_sdk=False)
(OUT / 'BUILD.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
print(json.dumps(summary, sort_keys=True), flush=True)
