#!/usr/bin/env python3
"""Offline verification of the already-frozen accepted R20 qualification export.

Reads the authenticated archive, verifies every raw member, safely extracts into
a new owned directory, and binds the eight ELF omissions to original acceptance.
It never runs archived code or reads/executes ELF payloads.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import traceback

BASE = Path('/workspace/scratch/846f8b2ab644/r20/audit-harness/qualification-download-01')
ARCHIVE = BASE / 'qualification.tar.gz'
OUTPUT = BASE / 'extracted'
RECEIPT = BASE / 'export-audit-01.json'
REMOTE = PurePosixPath('/home/qian/hepta-runtime-optimization-20261105-r20')
ARCHIVE_SHA = '8253e23a1b1f31dd74041f929af0f81b447d4fe8f3bff61c0960679d9f0e8614'
MANIFEST_SHA = '516c935d5056f9a29847e08cd75fb032dbfcdb04c2279c8c30c1ef6584d6adb3'
PINS = {
    'qualification-control-01/report.json': 'd36cabbf26145300709066fbc448711601dc2b1960fc9fd55766e99e735c3c7e',
    'independent-acceptance-01.json': '24c5631740b851ec99fddfb4df06dd0ee2cbb4a0bda44e581b4ebebf86456fb6',
    'qualification-01/report.json': '6d8992e0784f4c47a94333ddd9a8a6ec54277607e51c0e262887bf55f03b6660',
}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def relative(name):
    value = PurePosixPath(name)
    need(isinstance(name, str) and bool(name) and not value.is_absolute()
         and value.as_posix() == name and not any(part in ('', '.', '..') for part in value.parts),
         'unsafe archive/member path: ' + repr(name))
    return value


def binding(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def main():
    need(not RECEIPT.exists() and not OUTPUT.exists(), 'new local output/receipt required')
    result = {'schema': 'hepta-r20-qualification-export-binding/v1', 'passed': False, 'checks': {},
              'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'offline_only': True, 'local_elf_payloads_read': False, 'archived_code_executed': False,
              'original_archive_modified': False, 'remote_file_or_workload_operations': 0,
              'tool': binding(Path(__file__).resolve())}
    checks = result['checks']
    try:
        raw_archive = ARCHIVE.read_bytes()
        need(len(raw_archive) == 1473623 and sha(raw_archive) == ARCHIVE_SHA, 'archive identity differs')
        result['archive'] = binding(ARCHIVE)
        checks['complete_archive_bytes_and_sha256_match'] = True
        with tarfile.open(ARCHIVE, 'r:gz') as tar:
            members = tar.getmembers()
            names = [m.name for m in members]
            need(len(names) == len(set(names)) == 3363, 'duplicate/wrong archive member count')
            for item in members:
                relative(item.name)
                need(item.isfile() and not item.issym() and not item.islnk()
                     and not item.linkname and 0 <= item.mode <= 0o777,
                     'nonregular/link/special-mode archive member')
            member_map = {m.name: m for m in members}
            need('_export-manifest.json' in member_map, 'missing embedded manifest')
            manifest_raw = tar.extractfile(member_map['_export-manifest.json']).read()
            need(len(manifest_raw) == 1156104 and sha(manifest_raw) == MANIFEST_SHA, 'manifest identity differs')
            manifest = decode(manifest_raw)
            need(manifest['schema'] == 'hepta-r20-qualification-export/v1'
                 and len(manifest['files']) == 3362 and len(manifest['omitted_elf_bytes']) == 8,
                 'manifest schema/count differs')
            result['manifest'] = {'member': '_export-manifest.json', 'bytes': len(manifest_raw), 'sha256': MANIFEST_SHA}
            checks['embedded_original_manifest_identity_matches'] = True
            inventory = {}
            for row in manifest['files'] + manifest['omitted_elf_bytes']:
                path = relative(row['path'])
                need(row['path'] not in inventory and row['original_path'] == str(REMOTE / path),
                     'duplicate/path-mismatched export row')
                need(type(row['size']) is int and row['size'] >= 0 and type(row['mode']) is int
                     and 0 <= row['mode'] <= 0o777 and len(row['sha256']) == 64, 'invalid export row')
                inventory[row['path']] = row
            ordinary = {r['path']: r for r in manifest['files']}
            omissions = {r['path']: r for r in manifest['omitted_elf_bytes']}
            need(set(names) == set(ordinary) | {'_export-manifest.json'} and not (set(names) & set(omissions)),
                 'archive extra/missing members or ELF payload included')
            checks['exact_3362_regular_members_plus_manifest_no_links_escape_or_elf_payloads'] = True
            actual = {}
            for name, row in ordinary.items():
                item = member_map[name]
                need(item.size == row['size'] and item.mode == row['mode'], 'member size/mode differs: ' + name)
                raw = tar.extractfile(item).read()
                need(len(raw) == row['size'] and sha(raw) == row['sha256'], 'member bytes differ: ' + name)
                actual[name] = {'bytes': len(raw), 'sha256': sha(raw), 'mode': item.mode}
            checks['all_3362_member_bytes_sizes_modes_and_sha256_match'] = True
            for name, expected in PINS.items():
                need(actual[name]['sha256'] == expected, 'original qualification document pin differs')
            control, acceptance, qualification = [decode(tar.extractfile(member_map[name]).read()) for name in PINS]
            need(control['passed'] is True and control['current_stage'] == 'completed'
                 and acceptance['accepted'] is True and len(acceptance['checks']) == 31
                 and all(value is True for value in acceptance['checks'].values())
                 and qualification['qualified'] is True and qualification['automatic_test_retries'] == 0,
                 'original qualification did not fully pass')
            need(control['qualification_report']['sha256'] == PINS['qualification-01/report.json']
                 and control['independent_acceptance']['sha256'] == PINS['independent-acceptance-01.json']
                 and acceptance['qualified_report_sha256'] == PINS['qualification-01/report.json'],
                 'qualification document links differ')
            checks['three_exact_qualification_documents_and_31_passed_acceptance_checks_bound'] = True
            expected_elf = {}
            need(len(acceptance['binaries']) == 3 and len(acceptance['retained_test_binaries']) == 5,
                 'accepted ELF cardinality differs')
            for name, row in acceptance['binaries'].items():
                need(row == control['binaries'][name]
                     and row['path'] == qualification['binaries'][name]['path']
                     and row['sha256'] == qualification['binaries'][name]['sha256'], 'release identity links differ')
                need(row['path'] not in expected_elf, 'duplicate accepted ELF path')
                expected_elf[row['path']] = {'kind': 'release', 'name': name, **row}
            for row in acceptance['retained_test_binaries']:
                need(row['path'] not in expected_elf, 'duplicate accepted test ELF path')
                expected_elf[row['path']] = {'kind': 'retained_test', **row}
            actual_elf = {row['original_path']: row for row in manifest['omitted_elf_bytes']}
            need(len(actual_elf) == len(expected_elf) == 8 and set(actual_elf) == set(expected_elf),
                 'actual/accepted ELF path sets differ')
            comparisons = []
            for path, accepted in sorted(expected_elf.items()):
                actual_row = actual_elf[path]
                need(actual_row['sha256'] == accepted['sha256'], 'current omitted ELF SHA differs: ' + path)
                size_available = 'size' in accepted
                if size_available:
                    need(actual_row['size'] == accepted['size'], 'current omitted ELF size differs: ' + path)
                comparisons.append({'path': path, 'kind': accepted['kind'],
                    'sha256': actual_row['sha256'], 'actual_size': actual_row['size'],
                    'expected_size': accepted.get('size'), 'available_size_matched': True if size_available else None,
                    'accepted_sha256_matched': True, 'local_payload_downloaded': False})
            result['elf_comparisons'] = comparisons
            checks['exact_eight_elf_paths_and_complete_sha256_match_original_acceptance'] = True
            checks['all_available_accepted_elf_sizes_match'] = True
            OUTPUT.mkdir(mode=0o700)
            for item in members:
                destination = OUTPUT.joinpath(*relative(item.name).parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                need(destination.parent.resolve().is_relative_to(OUTPUT) and not destination.exists(),
                     'extraction escape/overwrite')
                raw = tar.extractfile(item).read()
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, item.mode)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                os.chmod(destination, item.mode)
                need(destination.stat().st_size == len(raw) and sha(destination.read_bytes()) == sha(raw),
                     'restored bytes differ')
            checks['fresh_safe_extraction_all_members_rehashed'] = True
        need(binding(ARCHIVE) == result['archive'], 'archive changed during review')
        checks['original_archive_unchanged'] = True
        result.update(passed=True, ordinary_file_count=3362, archive_member_count=3363,
                      omitted_elf_count=8, local_evidence_root=str(OUTPUT), original_document_sha256=PINS,
                      release_sha256={name: row['sha256'] for name, row in acceptance['binaries'].items()},
                      limitations=['Full ELF identities are the original exporter on-X230 full-byte hashes matched to accepted qualification. ELF payloads were neither downloaded nor locally rehashed.'])
    except BaseException as error:
        result['error'] = {'type': type(error).__name__, 'reason': str(error), 'traceback': traceback.format_exc()}
    with RECEIPT.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'passed': result['passed'], 'receipt': binding(RECEIPT), 'checks': checks, 'error': result.get('error')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
