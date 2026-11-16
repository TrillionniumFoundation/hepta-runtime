"""Retain every physical control file with full content-addressed deduplication."""
from pathlib import Path
import argparse
import hashlib
import io
import os
import signal
import sys
import tarfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from recover import ARTIFACT, HEAD, SOURCE, encoded, files, loads, pin, require, source


def expired(_signum, _frame):
    raise TimeoutError('original 180 second archive budget')


def run(root, archive, expected_source):
    source(expected_source)
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    started = time.monotonic()
    require(not archive.exists() and not archive.is_relative_to(root), 'separate new complete archive')
    entries = files(root)
    unique = {}
    for name, row in entries.items():
        if row['sha256'] in unique:
            require(row['bytes'] == entries[unique[row['sha256']]]['bytes'], 'complete duplicate content identity')
        else:
            unique[row['sha256']] = name
    result = loads((root / 'RECOVERY.json').read_bytes()) if (root / 'RECOVERY.json').exists() else dict(status='NO_RECOVERY_RECORD')
    metadata = dict(schema='hepta.extract-lines.recovery-archive.v1',
        recovery_git_head=os.environ.get('GITHUB_SHA'), recovery_run_id=os.environ.get('GITHUB_RUN_ID'),
        producer_source_head=HEAD, source_manifest_sha256=SOURCE,
        recovery_source_manifest_sha256=expected_source, original_artifact=ARTIFACT,
        status=result['status'], files=entries, unique_contents=len(unique),
        logical_files=len(entries), logical_bytes=sum(row['bytes'] for row in entries.values()),
        unique_content_bytes=sum(entries[name]['bytes'] for name in unique.values()),
        semantic_reexecutions=0, whole_runtime_replaced=False)
    raw = encoded(metadata)
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'w:gz', compresslevel=1) as bundle:
        item = tarfile.TarInfo('manifest.json')
        item.size, item.mode = len(raw), 0o644
        bundle.addfile(item, io.BytesIO(raw))
        for digest, name in sorted(unique.items()):
            path = root / name
            item = tarfile.TarInfo('blobs/' + digest)
            item.size, item.mode = entries[name]['bytes'], 0o644
            with path.open('rb') as stream:
                bundle.addfile(item, stream)
    seen = set()
    with tarfile.open(archive, 'r|gz') as bundle:
        while item := bundle.next():
            require(item.isfile() and item.mode == 0o644 and item.name not in seen, 'unique ordinary deduplicated archive member')
            seen.add(item.name)
            with bundle.extractfile(item) as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if item.name == 'manifest.json':
                require(item.size == len(raw) and digest == hashlib.sha256(raw).hexdigest(), 'complete archive map')
            else:
                require(item.name == 'blobs/' + digest and digest in unique
                        and item.size == entries[unique[digest]]['bytes'], 'complete content blob')
            bundle.members.clear()
    require(seen == {'manifest.json'} | {'blobs/' + digest for digest in unique}, 'every unique content blob retained and reread')
    require(files(root) == entries, 'all physical files remain byte and mode exact after archive')
    receipt = dict(schema='hepta.extract-lines.complete-recovery-archive.v1', archive=archive.name,
        **pin(archive), status=result['status'], recovery_source_manifest_sha256=expected_source,
        logical_files=metadata['logical_files'], logical_bytes=metadata['logical_bytes'],
        unique_contents=len(unique), unique_content_bytes=metadata['unique_content_bytes'],
        all_members_reread=True, all_physical_files_reread=True, original_artifact=ARTIFACT,
        semantic_reexecutions=0, deadline_seconds=180, elapsed_seconds=time.monotonic()-started,
        whole_runtime_replaced=False)
    archive.with_suffix(archive.suffix+'.json').write_bytes(encoded(receipt))
    signal.alarm(0)
    print(encoded(receipt).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    run(args.capture.resolve(strict=True), args.archive.absolute(), args.source_manifest_sha256)
