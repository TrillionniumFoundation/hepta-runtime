#!/usr/bin/env python3
"""Copy only the two observed R36 holder inventories into a fresh evidence directory."""
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r36')
DEST = ROOT / 'holder-inputs-01'
MAC = '/Users/qianqi/work/hepta-runtime-x230-r36-20261106/'
REPORTS = {
    'observation-holder-01': 'ca2d51499c0c187528779205197c49d760cdc6dc93f81edf8ec74060cff8bcf6',
    'lifecycle-holder-01': 'f885250569a1ab28089ccc618bc08bb20bb90942a8a8a9f12512494d4245f44e',
}

def main():
    raw = sys.stdin.buffer.read(1048577)
    assert len(raw) <= 1048576
    package = json.loads(raw)
    manifest = package['manifest']
    assert manifest['schema'] == 'hepta-r36-observed-holder-copies/v1'
    assert manifest['observed'] is True
    files = package['files']
    assert set(files) == set(manifest['files']) and len(files) == 44
    payloads = {}
    expected_names = set()
    for holder, report_sha in REPORTS.items():
        key = holder + '/report.json'
        report_body = files[key].encode('utf-8')
        assert hashlib.sha256(report_body).hexdigest() == report_sha
        report = json.loads(report_body)
        assert report['owned_agent_reaped'] is True
        assert report['owned_agent_directory_absent_after_context'] is True
        assert report['owned_agent_socket_absent_after_context'] is True
        expected_names.add(key)
        for item in report['log_files']:
            name = item['file']
            assert name == Path(name).name and name not in ('', '.', '..')
            relative = holder + '/' + name
            expected_names.add(relative)
            body = files[relative].encode('utf-8')
            assert len(body) == item['bytes']
            assert hashlib.sha256(body).hexdigest() == item['sha256']
    assert set(files) == expected_names
    for key, value in files.items():
        body = value.encode('utf-8')
        entry = manifest['files'][key]
        assert entry['original_path'] == MAC + key
        assert entry['bytes'] == len(body)
        assert entry['sha256'] == hashlib.sha256(body).hexdigest()
        payloads[key] = body
    mode = ROOT.lstat().st_mode
    assert stat.S_ISDIR(mode) and not stat.S_ISLNK(mode)
    assert not os.path.lexists(DEST)
    receipt_path = ROOT / 'holder-copy-installation-01.json'
    assert not os.path.lexists(receipt_path)
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    DEST.mkdir(mode=0o700)
    for holder in REPORTS:
        (DEST / holder).mkdir(mode=0o700)
    for name, body in sorted(payloads.items()):
        with (DEST / name).open('xb') as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
    with (DEST / 'manifest.json').open('xb') as output:
        output.write(manifest_bytes)
        output.flush()
        os.fsync(output.fileno())
    for name, body in payloads.items():
        assert (DEST / name).read_bytes() == body
    receipt = {
        'schema': 'hepta-r36-observed-holder-copy-installation/v1',
        'passed': True,
        'original_holder_files': len(payloads),
        'copied_original_bytes': sum(map(len, payloads.values())),
        'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
        'async_holder_copied': False,
        'benchmarks_started': 0,
        'original_files_modified': False,
    }
    with receipt_path.open('x') as output:
        json.dump(receipt, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps(receipt), flush=True)

if __name__ == '__main__':
    main()
