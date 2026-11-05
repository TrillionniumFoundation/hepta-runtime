#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Archive one terminal R21 campaign without executing any workload or auditor.

The four evidence trees are complete recursive snapshots, including failed
attempts and arbitrary raw filenames. Only nine explicitly named ELF bodies
are omitted; their complete hashes and stable file identities are retained.
"""
import argparse
import ast
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import traceback

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r21')
R20 = Path('/home/qian/hepta-runtime-optimization-20261105-r20')
R19 = Path('/home/qian/hepta-runtime-optimization-20261104-r19')
R16 = Path('/home/qian/hepta-runtime-optimization-20261104-r16')
PROFILE = Path('/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json')
FROZEN = Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')
TREES = ('campaign-control-01', 'native-observation-01', 'native-boundary-01', 'lifecycle-abba-01')
PROGRAM_SHA = '7cef87d976488ea63c5970f90b2e695bad835b1e01293aaaa5eeaee575e962a2'
CAMPAIGN_MANIFEST_SHA = '5e74bf124730a8dae41b30b2296ed0481277d4baa72139a4aab628b04a343afd'
LIFECYCLE_MANIFEST_SHA = '445a325931f2a9147401ea241782a29617480c2047c6d5b760f2e59f9037cb1f'
QUALIFICATION_MANIFEST_SHA = '126976a5005fbbb5b09360d6999c85fd46d14e96e9b7d037c55ea2d40b40cc8d'
PLAN_SHA = 'aa4ad30b746b267d005c675f81ba634c43cd81a6f5893963445949abaa6e82f6'
CHAIN_SHA = '29542f436269549936ecc24cd5d65b7f994200ede963f4b4cf9c4556483644b8'
BASELINE_SHA = 'adab5f27f89b3cac6adaec916110a48d80697db9667e3bd7ee0fc713fe770a09'
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024 * 1024
ELF_NAMES = ('hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver')
TARGET_ELFS = {ROOT / 'target-fresh-01/release' / ('examples/native_process_driver' if n == 'native_process_driver' else n) for n in ELF_NAMES}
ELFS = TARGET_ELFS | {base / qualification / n for base, qualification in ((R19, 'qualification-02'), (ROOT, 'qualification-01')) for n in ELF_NAMES}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def stamp(info):
    return {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def safe_name(name):
    value = Path(name)
    need(isinstance(name, str) and name and not value.is_absolute() and value.as_posix() == name
         and all(x not in ('', '.', '..') for x in value.parts), 'unsafe member name')
    return value


def read_file(path, retain=False, elf=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'indirect input: ' + str(path))
    need(not elf or path in ELFS, 'ELF exception outside fixed whitelist')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and not before.st_mode & (stat.S_ISUID | stat.S_ISGID)
             and (before.st_nlink >= 1 if path in TARGET_ELFS else before.st_nlink == 1)
             and 0 <= before.st_size <= MAX_FILE, 'unsafe or oversized regular input: ' + str(path))
        digest, count, chunks, header = hashlib.sha256(), 0, [], b''
        while count <= before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size + 1 - count))
            if not block:
                break
            if not header:
                header = block[:4]
            count += len(block)
            digest.update(block)
            if retain:
                chunks.append(block)
        need(count == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()), 'input changed: ' + str(path))
        if elf:
            need(header == b'\x7fELF', 'named ELF has no ELF header')
        row = {'source_path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
               'original_mode': stat.S_IMODE(before.st_mode), 'original_identity': stamp(before)}
        return row, b''.join(chunks) if retain else None
    finally:
        os.close(fd)


def load(path, expected=None):
    row, raw = read_file(path, retain=True)
    need(expected is None or row['sha256'] == expected, 'bound JSON/source hash differs: ' + str(path))
    return json.loads(raw), row


def inventory(path):
    """No name/extension filters; special files and indirect paths are rejected."""
    if not os.path.lexists(path):
        return {'present': False, 'files': [], 'directories': []}
    need(path.resolve() == path, 'indirect evidence root')
    files, directories = [], []
    pending = [path]
    while pending:
        current = pending.pop()
        info = current.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(), 'unsafe evidence directory')
        directories.append({'path': current.relative_to(ROOT).as_posix(), 'identity': stamp(info)})
        for child in sorted(current.iterdir()):
            mode = child.lstat().st_mode
            if stat.S_ISDIR(mode):
                pending.append(child)
            else:
                need(stat.S_ISREG(mode), 'non-regular evidence entry: ' + str(child))
                files.append(child.relative_to(ROOT).as_posix())
    return {'present': True, 'files': sorted(files), 'directories': sorted(directories, key=lambda x: x['path'])}


def process_identity(pid):
    try:
        raw = Path('/proc', str(pid), 'stat').read_text()
    except FileNotFoundError:
        return None
    fields = raw[raw.rfind(') ') + 2:].split()
    return {'pid': pid, 'start_ticks': int(fields[19]), 'state': fields[0]}


def mapping(path):
    for root, prefix in ((ROOT, 'r21'), (R20, 'inputs/r20'), (R19, 'inputs/r19'), (R16, 'inputs/r16')):
        if path.is_relative_to(root):
            return prefix + '/' + path.relative_to(root).as_posix()
    if path == PROFILE:
        return 'inputs/profile-template/profile.json'
    if path.is_relative_to(FROZEN):
        return 'inputs/frozen-jobs/' + path.relative_to(FROZEN).as_posix()
    raise ValueError('input outside fixed evidence roots: ' + str(path))


def write_snapshot(out, manifest):
    files, omitted, before_trees = manifest['files'], manifest['omitted_elf_bytes'], manifest['raw_trees']
    need(sum(row['bytes'] for row in files.values()) <= MAX_TOTAL, 'bounded evidence size exceeded')
    manifest_raw = encode(manifest)
    archive = out / 'campaign-evidence-01.tar.gz'
    with archive.open('xb') as destination, gzip.GzipFile(filename='', mode='wb', fileobj=destination, mtime=0, compresslevel=6) as zipped:
        with tarfile.open(fileobj=zipped, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            item = tarfile.TarInfo('_export-manifest.json')
            item.size, item.mode, item.mtime = len(manifest_raw), 0o600, 0
            tar.addfile(item, io.BytesIO(manifest_raw))
            for name, expected in sorted(files.items()):
                actual, raw = read_file(Path(expected['source_path']), retain=True)
                need(actual == expected, 'input changed before packing: ' + name)
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.mtime = len(raw), 0o600, 0
                tar.addfile(item, io.BytesIO(raw))
    need({name: inventory(ROOT / name) for name in TREES} == before_trees, 'closed raw tree membership/identity changed')
    for row in list(files.values()) + omitted:
        need(read_file(Path(row['source_path']), elf=manifest['campaign_passed'] and Path(row['source_path']) in ELFS)[0] == row,
             'source changed after archive')
    with (out / 'manifest.json').open('xb') as stream:
        stream.write(manifest_raw)
    archive_id, _ = read_file(archive)
    return {'archive': {'path': str(archive), 'bytes': archive_id['bytes'], 'sha256': archive_id['sha256']},
            'manifest': {'path': str(out / 'manifest.json'), 'bytes': len(manifest_raw), 'sha256': hashlib.sha256(manifest_raw).hexdigest()},
            'payload_files': len(files), 'archive_members': len(files) + 1, 'omitted_elf_count': len(omitted),
            'all_retained_source_hashes_and_raw_tree_membership_unchanged': True}


def failed_snapshot(args, report, out, before_trees, processes):
    """Preserve safely readable evidence even when a qualification input drifted.

    No changed manifest or source is executed. Fixed reference paths are used
    independently of untrusted/missing component-chain contents. An unavailable
    dependency is recorded, never silently considered validated.
    """
    files, errors, tool_paths = {}, [], set()

    def add(path, expected=None, expected_bytes=None):
        path = Path(path)
        try:
            row, _ = read_file(path)
            name = mapping(path)
            need(path not in ELFS, 'ELF bytes may not enter failure archive')
            need(name not in files or files[name] == row, 'conflicting failure member')
            files[name] = row
            if expected is not None and row['sha256'] != expected:
                errors.append({'path': str(path), 'type': 'IdentityMismatch', 'expected_sha256': expected, 'actual_sha256': row['sha256']})
            if expected_bytes is not None and row['bytes'] != expected_bytes:
                errors.append({'path': str(path), 'type': 'SizeMismatch', 'expected_bytes': expected_bytes, 'actual_bytes': row['bytes']})
        except Exception as error:
            errors.append({'path': str(path), 'type': type(error).__name__, 'message': str(error)})

    # Primary raw files are mandatory once safely enumerated. If their bytes
    # cannot be read stably, the export retains an error receipt instead of
    # describing a partial raw tree as a complete closed snapshot.
    for tree in before_trees.values():
        for name in tree['files']:
            row, _ = read_file(ROOT / name)
            files['r21/' + name] = row
    for name in ('campaign-tools', 'lifecycle-tools', 'boundary-tools', 'evidence-tools'):
        try:
            tree = inventory(ROOT / name)
            if not tree['present']:
                errors.append({'path': str(ROOT / name), 'type': 'MissingDirectory'})
            for relative in tree['files']:
                add(ROOT / relative)
                if name != 'evidence-tools':
                    tool_paths.add(relative)
        except Exception as error:
            errors.append({'path': str(ROOT / name), 'type': type(error).__name__, 'message': str(error)})
    fixed = {ROOT / 'measurement-plan-01.json': PLAN_SHA, ROOT / 'component-chain-01.json': CHAIN_SHA,
             ROOT / 'campaign-tools/run_six_host_campaign_01.py': PROGRAM_SHA,
             ROOT / 'campaign-tools/manifest.freeze-01.json': CAMPAIGN_MANIFEST_SHA,
             ROOT / 'lifecycle-tools/lifecycle-tools-manifest-01.json': LIFECYCLE_MANIFEST_SHA,
             ROOT / 'tools/qualification-tools-manifest-01.json': QUALIFICATION_MANIFEST_SHA,
             ROOT / 'evidence-tools/evidence-tools-manifest-01.json': args.expected_evidence_tools_manifest_sha256}
    for path, expected in fixed.items():
        add(path, expected)
    # Inspect only manifests whose own bytes still match their externally
    # frozen identity. Their fixed file maps can explain per-tool drift;
    # a changed manifest is retained but never followed.
    for path, base, size_key in (
            (ROOT / 'campaign-tools/manifest.freeze-01.json', ROOT, 'bytes'),
            (ROOT / 'lifecycle-tools/lifecycle-tools-manifest-01.json', ROOT / 'lifecycle-tools', 'bytes'),
            (ROOT / 'tools/qualification-tools-manifest-01.json', ROOT / 'tools', 'size'),
            (ROOT / 'evidence-tools/evidence-tools-manifest-01.json', ROOT / 'evidence-tools', 'bytes')):
        previous = files.get(mapping(path))
        if previous is None or previous['sha256'] != fixed[path]:
            continue
        try:
            actual, raw = read_file(path, retain=True)
            need(actual == previous, 'manifest changed before inspecting fixed file map')
            for name, item in json.loads(raw)['files'].items():
                relative = safe_name(name)
                need(base == ROOT or len(relative.parts) == 1, 'fixed tool map escaped its directory')
                add(base / relative, item['sha256'], item[size_key])
        except Exception as error:
            errors.append({'path': str(path), 'type': type(error).__name__, 'message': str(error)})
    fixed_paths = [PROFILE, R16 / 'benchmark-topology.json',
                   R19 / 'source/src/mcp/runtime/jobs.rs', R20 / 'source/src/mcp/runtime/jobs.rs',
                   R20 / 'cancel-candidate-01/jobs.rs', ROOT / 'source/src/mcp/runtime/jobs.rs',
                   R20 / 'coldprocess-probe-01/semantics.json', R20 / 'cancelprocess-probe-01/semantics.json',
                   R20 / 'tools/coldprocess_probe_02.py', R20 / 'cancel-tools-01/cancelprocess_probe_01.py',
                   R20 / 'cancel-tools-01/measurement-plan-01.json']
    fixed_paths += [ROOT / name for name in ('source-freeze-01.json', 'source-middle-01.json', 'source-after-01.json',
                    'qualification-launch-01.json', 'qualification-exit-01.json', 'independent-acceptance-01.json',
                    'qualification-01/report.json', 'qualification-01/source-map.json', 'qualification-control-01/report.json',
                    'tools/create_component_chain_01.py', 'tools/qualify_candidate_01.py', 'tools/verify_qualification_01.py',
                    'source/tools/x230/20261028/qualify.py')]
    fixed_paths += [R19 / name for name in ('source-freeze-02.json', 'qualification-02/report.json', 'independent-acceptance-02.json')]
    fixed_paths += sorted(FROZEN.glob('*.json'))
    fixed_paths += sorted(path for path in (ROOT / 'qualification-control-01').glob('*') if path.suffix in ('.stdout', '.stderr'))
    for path in fixed_paths:
        add(path)
    chain_path = ROOT / 'component-chain-01.json'
    previous = files.get(mapping(chain_path))
    if previous is not None and previous['sha256'] == CHAIN_SHA:
        try:
            actual, raw = read_file(chain_path, retain=True)
            need(actual == previous, 'chain changed before inspecting fixed references')
            refs = json.loads(raw)['referenced_files']
            need(len(refs) == 9 and all(Path(item['path']) in fixed_paths for item in refs), 'fixed chain reference set differs')
            for item in refs:
                add(Path(item['path']), item['sha256'], item['size'])
        except Exception as error:
            errors.append({'path': str(chain_path), 'type': type(error).__name__, 'message': str(error)})
    omitted = []
    for path in sorted(ELFS):
        try:
            # Capture actual full bytes identity even if a previously qualified
            # file now has a non-ELF header. Its body remains excluded by path.
            omitted.append(read_file(path)[0])
        except Exception as error:
            errors.append({'path': str(path), 'type': type(error).__name__, 'message': str(error), 'elf_body_excluded': True})
    manifest = {'schema': 'hepta-r21-campaign-export/v1', 'root': str(ROOT),
                'expected_campaign_report_sha256': args.expected_campaign_report_sha256,
                'expected_candidate_sha256': args.expected_candidate_sha256,
                'expected_evidence_tools_manifest_sha256': args.expected_evidence_tools_manifest_sha256,
                'campaign_passed': False, 'campaign_terminal_stage': report['current_stage'],
                'native_screen_passed': report.get('native_regression_screen_passed'),
                'raw_trees': before_trees, 'files': dict(sorted(files.items())), 'file_count': len(files),
                'installed_campaign_tool_file_count': len(tool_paths), 'qualified_input_bindings': [],
                'observed_outer_stage_processes': processes, 'omitted_elf_bytes': omitted,
                'elf_omission_policy': 'Only nine explicit paths; actual readable identities retained without claiming qualification equivalence.',
                'identity_errors': errors, 'qualification_inputs_validated': False,
                'compiled_target_directory_traversed': False, 'original_files_modified': False,
                'mac_holder_evidence_included': False,
                'scope': 'Failed terminal campaign: all safely enumerated raw bytes retained; dependency errors remain explicit and no campaign, qualification or independent audit pass is asserted.'}
    return {**write_snapshot(out, manifest), 'campaign_passed': False, 'campaign_terminal_stage': report['current_stage'],
            'native_screen_passed': report.get('native_regression_screen_passed'), 'identity_errors': errors,
            'qualification_inputs_validated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-campaign-report-sha256', required=True)
    parser.add_argument('--expected-candidate-sha256', required=True)
    parser.add_argument('--expected-evidence-tools-manifest-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    need(all(HEX.fullmatch(value) for key, value in vars(args).items() if key != 'out'), 'invalid expected SHA256')
    out = args.out
    need(out.is_absolute() and out.parent == ROOT and re.fullmatch(r'export-campaign-[0-9]{2}', out.name)
         and out.resolve() == out and not os.path.lexists(out), 'fresh reserved export directory required')
    os.umask(0o077)
    out.mkdir(mode=0o700)
    receipt = {'schema': 'hepta-r21-campaign-export-result/v1', 'passed': False,
               'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'workloads_run': False, 'auditors_run': False, 'network_requests': 0,
               'automatic_retries': 0, 'original_files_modified': False}
    try:
        report, report_id = load(ROOT / 'campaign-control-01/report.json', args.expected_campaign_report_sha256)
        need(report['schema'] == 'hepta-r21-six-host-campaign/v1' and report.get('finished_utc')
             and report['current_stage'] in ('completed', 'failed') and type(report['passed']) is bool,
             'campaign is not terminal')
        processes = []
        for row in report['stages']:
            if 'pid' in row:
                current = process_identity(row['pid'])
                need(current is None or current['start_ticks'] != row['start_ticks'], 'original outer stage is still present')
                processes.append({'pid': row['pid'], 'start_ticks': row['start_ticks'], 'original_identity_absent': True})
        before_trees = {name: inventory(ROOT / name) for name in TREES}
        need(before_trees['campaign-control-01']['present'], 'control evidence missing')
        if report['passed'] is False:
            receipt.update(failed_snapshot(args, report, out, before_trees, processes), passed=True)
            return 0
        files, allowed, bindings, elf_bindings = {}, set(), [], []

        def add(path, expected=None, expected_bytes=None, name=None):
            path = Path(path)
            need(path not in ELFS, 'ELF bytes may not enter the archive')
            name = name or mapping(path)
            safe_name(name)
            actual, _ = read_file(path)
            need(expected is None or actual['sha256'] == expected, 'input hash differs: ' + str(path))
            need(expected_bytes is None or actual['bytes'] == expected_bytes, 'input size differs: ' + str(path))
            need(name not in files or files[name] == actual, 'conflicting member')
            files[name] = actual
            allowed.add(path)
            return actual

        for tree in before_trees.values():
            for name in tree['files']:
                add(ROOT / name)
        campaign, _ = load(ROOT / 'campaign-tools/manifest.freeze-01.json', CAMPAIGN_MANIFEST_SHA)
        life, _ = load(ROOT / 'lifecycle-tools/lifecycle-tools-manifest-01.json', LIFECYCLE_MANIFEST_SHA)
        need(campaign['file_count'] == len(campaign['files']) == 6 and len(life['files']) == 17, 'installed tool set differs')
        tool_paths = []
        for name, item in sorted(campaign['files'].items()):
            path = ROOT / safe_name(name)
            add(path, item['sha256'], item['bytes'])
            tool_paths.append(path)
        for name, item in sorted(life['files'].items()):
            need(Path(name).name == name, 'invalid lifecycle tool name')
            path = ROOT / 'lifecycle-tools' / name
            add(path, item['sha256'], item['bytes'])
            tool_paths.append(path)
        for path, expected in ((ROOT / 'campaign-tools/manifest.freeze-01.json', CAMPAIGN_MANIFEST_SHA),
                               (ROOT / 'lifecycle-tools/lifecycle-tools-manifest-01.json', LIFECYCLE_MANIFEST_SHA)):
            add(path, expected)
            tool_paths.append(path)
        need(len(tool_paths) == len(set(tool_paths)) == 25, '25-file installation contract differs')
        program, program_raw = read_file(ROOT / 'campaign-tools/run_six_host_campaign_01.py', retain=True)
        need(program['sha256'] == PROGRAM_SHA, 'frozen launcher differs')
        assignments = {node.targets[0].id: node.value for node in ast.parse(program_raw).body
                       if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
        for name, expected in ast.literal_eval(assignments['HARNESS_FILES']).items():
            add(R16 / 'measurement-tools' / name, expected)
        for name, expected in ast.literal_eval(assignments['BOUNDARY_FILES']).items():
            add(R16 / 'boundary-tools' / name, expected)
        for path, expected in ((ROOT / 'measurement-plan-01.json', PLAN_SHA),
                               (ROOT / 'component-chain-01.json', CHAIN_SHA),
                               (PROFILE, ast.literal_eval(assignments['PROFILE_SHA'])),
                               (R16 / 'benchmark-topology.json', ast.literal_eval(assignments['TOPOLOGY_SHA']))):
            add(path, expected)
        chain, _ = load(ROOT / 'component-chain-01.json', CHAIN_SHA)
        need(len(chain['referenced_files']) == 9, 'component reference count differs')
        for item in chain['referenced_files']:
            add(Path(item['path']), item['sha256'], item['size'])
        frozen = sorted(FROZEN.glob('*.json'))
        need(len(frozen) == 6, 'frozen-job source set differs')
        for path in frozen:
            add(path)
        qmanifest, _ = load(ROOT / 'tools/qualification-tools-manifest-01.json', QUALIFICATION_MANIFEST_SHA)
        need(len(qmanifest['files']) == 3, 'qualification tool set differs')
        add(ROOT / 'tools/qualification-tools-manifest-01.json', QUALIFICATION_MANIFEST_SHA)
        for name, item in qmanifest['files'].items():
            need(Path(name).name == name, 'invalid qualification tool name')
            add(ROOT / 'tools' / name, item['sha256'], item['size'])
        add(ROOT / 'source/tools/x230/20261028/qualify.py', ast.literal_eval(assignments['QUALIFIER_SHA']))
        for name in ('source-freeze-01.json', 'source-middle-01.json', 'source-after-01.json',
                     'qualification-launch-01.json', 'qualification-exit-01.json', 'independent-acceptance-01.json',
                     'qualification-01/report.json', 'qualification-01/source-map.json', 'qualification-control-01/report.json'):
            add(ROOT / name)
        for path in sorted((ROOT / 'qualification-control-01').iterdir()):
            if path.suffix in ('.stdout', '.stderr'):
                add(path)
        pins = assignments['BASELINE_PINS']
        baseline_pins = {ast.literal_eval(key): ast.literal_eval(assignments[value.id] if isinstance(value, ast.Name) else value)
                         for key, value in zip(pins.keys, pins.values)}
        for name, expected in baseline_pins.items():
            if R19 / name not in ELFS:
                add(R19 / name, expected)
        # The template JSON and each freshly copied profile/config/known_hosts
        # are retained. No SSH agent, private key or unrelated credential file
        # is opened by this exporter.
        tool_manifest_path = ROOT / 'evidence-tools/evidence-tools-manifest-01.json'
        tool_manifest, _ = load(tool_manifest_path, args.expected_evidence_tools_manifest_sha256)
        need(tool_manifest['schema'] == 'hepta-r21-campaign-evidence-tools/v1', 'evidence tool manifest differs')
        add(tool_manifest_path, args.expected_evidence_tools_manifest_sha256)
        for name, item in tool_manifest['files'].items():
            need(Path(name).name == name, 'invalid evidence tool name')
            add(tool_manifest_path.parent / name, item['sha256'], item['bytes'])

        def inspect_bindings(value):
            if isinstance(value, dict):
                if isinstance(value.get('path'), str) and HEX.fullmatch(str(value.get('sha256', ''))):
                    path = Path(value['path'])
                    if path in ELFS:
                        elf_bindings.append({'path': str(path), 'sha256': value['sha256'],
                                             'bytes': value.get('bytes', value.get('size'))})
                        return
                    need(path in allowed, 'uncovered qualified input binding: ' + str(path))
                    actual = files[mapping(path)]
                    expected_bytes = value.get('bytes', value.get('size'))
                    bindings.append({'path': str(path), 'matches': actual['sha256'] == value['sha256']
                                     and (expected_bytes is None or actual['bytes'] == expected_bytes)})
                for child in value.values():
                    inspect_bindings(child)
            elif isinstance(value, list):
                for child in value:
                    inspect_bindings(child)

        if report.get('gate') is not None:
            inspect_bindings(report['gate'])
        acceptance, _ = load(ROOT / 'independent-acceptance-01.json')
        old_acceptance, _ = load(R19 / 'independent-acceptance-02.json')
        omitted = []
        for base, dirname, proof in ((R19, 'qualification-02', old_acceptance), (ROOT, 'qualification-01', acceptance)):
            for name in ELF_NAMES:
                row = proof['binaries'][name]
                path = base / dirname / name
                need(row['path'] == str(path), 'qualified ELF path differs')
                actual, _ = read_file(path, elf=True)
                need(actual['sha256'] == row['sha256'] and actual['bytes'] == row['size'], 'qualified ELF no longer matches acceptance')
                omitted.append(actual)
                if base == ROOT:
                    target = ROOT / 'target-fresh-01/release' / ('examples/native_process_driver' if name == 'native_process_driver' else name)
                    target_id, _ = read_file(target, elf=True)
                    need(target_id['sha256'] == actual['sha256'] and target_id['bytes'] == actual['bytes'], 'compiler target/copy differs')
                    omitted.append(target_id)
        need({Path(item['source_path']) for item in omitted} == ELFS, 'ELF witness whitelist differs')
        omitted_by_path = {item['source_path']: item for item in omitted}
        for item in elf_bindings:
            actual = omitted_by_path[item['path']]
            bindings.append({'path': item['path'], 'matches': actual['sha256'] == item['sha256']
                             and (item['bytes'] is None or actual['bytes'] == item['bytes'])})
        need(acceptance['binaries']['hepta-runtime']['sha256'] == args.expected_candidate_sha256
             and old_acceptance['binaries']['hepta-runtime']['sha256'] == BASELINE_SHA, 'actual runtime identity differs')
        if report['passed']:
            need(all(tree['present'] for tree in before_trees.values()) and bindings and all(row['matches'] for row in bindings)
                 and report['expected_startup_hashes']['expected_candidate_sha256'] == args.expected_candidate_sha256,
                 'completed campaign input bindings or evidence tree missing')
        need(sum(row['bytes'] for row in files.values()) <= MAX_TOTAL, 'bounded evidence size exceeded')
        manifest = {'schema': 'hepta-r21-campaign-export/v1', 'root': str(ROOT),
                    'expected_campaign_report_sha256': args.expected_campaign_report_sha256,
                    'expected_candidate_sha256': args.expected_candidate_sha256,
                    'expected_evidence_tools_manifest_sha256': args.expected_evidence_tools_manifest_sha256,
                    'campaign_passed': report['passed'], 'campaign_terminal_stage': report['current_stage'],
                    'native_screen_passed': report.get('native_regression_screen_passed'),
                    'raw_trees': before_trees, 'files': dict(sorted(files.items())),
                    'file_count': len(files), 'installed_campaign_tool_file_count': 25,
                    'qualified_input_bindings': bindings, 'observed_outer_stage_processes': processes,
                    'omitted_elf_bytes': sorted(omitted, key=lambda row: row['source_path']),
                    'elf_omission_policy': 'Only nine exact qualified/cargo-target ELF paths; filenames inside evidence trees are never used as exclusion rules.',
                    'compiled_target_directory_traversed': False, 'original_files_modified': False,
                    'mac_holder_evidence_included': False,
                    'scope': 'Closed X230 evidence snapshot, not an independent performance/semantic replay or proof of unobserved remote cleanup.'}
        receipt.update(write_snapshot(out, manifest), passed=True,
                       campaign_passed=report['passed'], campaign_terminal_stage=report['current_stage'],
                       native_screen_passed=report.get('native_regression_screen_passed'),
                       qualification_inputs_validated=True)
    except BaseException as error:
        receipt['error'] = {'type': type(error).__name__, 'message': str(error)}
        with (out / 'error.txt').open('xb') as stream:
            stream.write(traceback.format_exc().encode())
    finally:
        receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with (out / 'receipt.json').open('xb') as stream:
            stream.write(encode(receipt))
        print(json.dumps(receipt, sort_keys=True), flush=True)
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
