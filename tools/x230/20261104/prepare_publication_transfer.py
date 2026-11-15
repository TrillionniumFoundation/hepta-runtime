#!/usr/bin/env python3
"""Freeze exact existing package receipts and original packaging-attempt logs."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path('/home/qian/hepta-runtime-optimization-20261104-r16/publication-20261104-01')
LOCAL = Path('/workspace/scratch/87f4a373402c/r16-r17-publication/stage')
sys.path.insert(0, str(ROOT / 'tools-v2'))
from publication_transfer import remote_index, chunks, write_new, hashes
from package_x230_evidence import encoded, need, source_file


def main():
    plan = json.loads((ROOT / 'tools-v2/packaging-plan-v4.json').read_bytes())
    receipts = [ROOT / 'stage' / p['repo_dir'] / (p['archive_stem'] + '.archive.json')
                for p in plan['packages'] if p['state'] == 'complete']
    need(len(receipts) == 13, 'expected the thirteen completed historical R16/R17 packages')
    extras = []
    def add(source, repo, expected=None):
        values = hashes(source)
        need(expected is None or values['sha256'] == expected, 'original attempt log identity differs')
        extras.append({'repo_path': repo, 'absolute_remote_path': str(source), **values})
    prefix = 'tools/x230/20261104/'
    for directory, name, destination in [
        ('tools', 'package_x230_evidence.py', 'publication-history/package_x230_evidence.v1.py'),
        ('tools', 'publication_transfer.py', 'publication-history/publication_transfer.v1.py'),
        ('tools', 'packaging-plan-v3.json', 'packaging-plan-v3.json'),
        ('tools', 'PACKAGING_POLICY.md', 'PACKAGING_POLICY.md'),
        ('tools', 'test_package_x230_evidence.py', 'test_package_x230_evidence.py'),
        ('tools', 'publication-selftest.json', 'publication-selftest.json'),
        ('tools-v2', 'package_x230_evidence.py', 'package_x230_evidence.py'),
        ('tools-v2', 'publication_transfer.py', 'publication_transfer.py'),
        ('tools-v2', 'run_publication_batch.py', 'run_publication_batch.py'),
        ('tools-v2', 'packaging-plan-v4.json', 'packaging-plan-v4.json'),
        ('tools-v2', 'publication-revision-v2.json', 'publication-revision-v2.json'),
        ('tools-v2', 'prepare_publication_transfer.py', 'prepare_publication_transfer.py'),
    ]:
        add(ROOT / directory / name, prefix + destination)
    for label in ['attempt-01', 'attempt-02']:
        report = ROOT / label / 'report.json'
        data = json.loads(report.read_bytes())
        add(report, prefix + 'publication-attempts/' + label + '/report.json')
        for package in data['packages']:
            identifier = package['id']
            need(identifier in {p['id'] for p in plan['packages']}, 'unknown attempted package')
            base = ROOT / label / identifier
            target = prefix + 'publication-attempts/' + label + '/' + identifier + '/'
            add(base / 'status.json', target + 'status.json')
            for stage in package['stages']:
                need(stage['name'] in {'inventory', 'pack'}, 'unexpected publication stage')
                for stream in ['stdout', 'stderr']:
                    path = Path(stage[stream])
                    need(path == base / (stage['name'] + '.' + stream), 'attempt log escaped its closed directory')
                    add(path, target + path.name, stage[stream + '_sha256'])
    extras_path = ROOT / 'transfer-extras-01.json'
    index_path = ROOT / 'remote-index-01.json'
    manifest_path = ROOT / 'transfer-manifest-01.json'
    write_new(extras_path, encoded({'files': extras}))
    indexed = remote_index([str(p) for p in receipts], str(extras_path), str(LOCAL), str(index_path))
    split = chunks(str(index_path), str(ROOT / 'pieces-01'), str(manifest_path))
    bootstrap = {'schema': 'hepta-publication-transfer-bootstrap/v1', 'metadata': [],
                 'index_result': indexed, 'split_result': split}
    for path in [index_path, manifest_path]:
        raw = path.read_bytes()
        item = {'name': path.name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'parts': []}
        for offset in range(0, len(raw), 45000):
            content = raw[offset:offset + 45000]
            target = ROOT / 'metadata-pieces-01' / (path.name + f'.part-{len(item["parts"]):04d}')
            write_new(target, content)
            item['parts'].append({'absolute_remote_path': str(target), 'bytes': len(content),
                                  'sha256': hashlib.sha256(content).hexdigest(), 'offset': offset})
        bootstrap['metadata'].append(item)
    bootstrap_path = ROOT / 'transfer-bootstrap-01.json'
    write_new(bootstrap_path, encoded(bootstrap))
    print(json.dumps({'bootstrap': str(bootstrap_path), **hashes(bootstrap_path),
                      'index': indexed, 'split': split}, sort_keys=True))


if __name__ == '__main__':
    main()
