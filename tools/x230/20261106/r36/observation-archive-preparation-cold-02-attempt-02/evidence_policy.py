#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fixed R36 evidence scope and metadata-only exclusions; no remote operations."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import types

ROOT = Path('/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02')
CANARY = Path('/home/qian/hepta-runtime-optimization-20261104-r16/s36-cancel-recovery-02')
SCOPES = {'r36': ROOT, 'recovery': CANARY}
HOLDER_ROOT = Path('/Users/qianqi/work')
HOLDERS = ('hepta-runtime-r36-validation-scratch-cold-02-observation-holder-02',)
CAPTURE_TOOLS = 'evidence-tools-02'
PRIOR_FAILURE_MEMBER = None
PRIOR_FAILURE_PIN = None
DIRECTORIES = (
    'source', 'candidate', 'qualification-01', 'rust-ci-01', 'rust-ci-tools-01',
    'owner-closure-provenance', 'measurement-fixtures-01',
    'python-ci-01', 'python-ci-launch-01', 'python-ci-tools-01',
    'campaign-01', 'campaign-02', 'holder-inputs-02', 'lifecycle-campaign-01', 'lifecycle-abba-01',
    'lifecycle-tool-tests-01', 'cancel-saturation-01', 'tools-01',
    'lifecycle-tools-01', 'boundary-tools-01', 'ci-templates', 'input-templates',
    'holder-inputs-01', 'evidence-tools-01', 'evidence-tools-02', 'evidence-export-01',
    'supplement-tools-01', 'async-read-abba-01',
)
STAGES = {
    'qualification': ('qualification-01', 'report.json', 'qualified'),
    'rust_ci': ('rust-ci-01', 'report.json', 'passed'),
    'python_ci': ('python-ci-launch-01', 'receipt.json', 'passed'),
    'observation': ('campaign-02', 'report.json', 'observation_gate_passed'),
    'prior_observation_01': ('campaign-01', 'report.json', 'observation_gate_passed'),
    'holder_copy_manifest_02_metadata': ('holder-inputs-02', 'manifest.json', 'observed'),
    'lifecycle': ('lifecycle-campaign-01', 'report.json', 'adoption_passed'),
    'lifecycle_tool_tests': ('lifecycle-tool-tests-01', 'report.json', 'passed'),
    'saturated_cancellation': ('cancel-saturation-01', 'report.json', 'passed'),
    'async_read_supplement': ('async-read-abba-01', 'report.json', 'passed'),
}
HELPER_SHA = '8b7aa7ef3b3772da13ea4f7009d8c478e0c92bc207d65db3f45c23453097d7a2'
TOOL_FILES = ('pack_r36_evidence.py', 'verify_r36_evidence.py', 'evidence_policy.py',
              'scan_evidence.py', 'stable_xz_archive.py')
MAX_ENTRIES = 30000
MAX_PAYLOAD_BYTES = 384 * 1024**2  # Below the unchanged helper's 512 MiB expanded bound.
HEX = re.compile(r'[0-9a-f]{64}\Z')
PRIVATE_NAMES = {'profile.json', 'runtime.json', 'sshconfig', 'ssh_config', 'known_hosts',
                 'authorized_keys', 'authorized_keys2', 'config.ssh', '.netrc', '.env'}
PRIVATE_DIRS = {'.ssh', 'profile', 'profiles', 'sockets', 'agent-sockets'}
BUILD_DIRS = {'target', 'target-build', '.git', '__pycache__', '.pytest_cache', 'node_modules'}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def load_helper():
    path = Path(__file__).resolve().with_name('stable_xz_archive.py')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'unsafe reviewed archive helper')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(128 * 1024 + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(all(getattr(before, key) == getattr(after, key) == getattr(path.lstat(), key)
             for key in fields) and hashlib.sha256(raw).hexdigest() == HELPER_SHA,
         'reviewed R29 archive helper differs')
    module = types.ModuleType('r36_reviewed_stable_archive')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def source_path(member):
    value = PurePosixPath(member)
    need(str(value) == member and value.parts and value.parts[0] in SCOPES
         and not value.is_absolute() and not any(p in ('.', '..') for p in value.parts)
         and '\\' not in member and '\x00' not in member, 'member escaped exact R36 scope')
    return SCOPES[value.parts[0]].joinpath(*value.parts[1:])


def omission_reason(member, mode, nlink=1):
    parts = PurePosixPath(member).parts[1:]
    name = parts[-1].lower() if parts else ''
    if any(p in BUILD_DIRS for p in parts):
        return 'build-cache-or-vcs-tree; metadata only, descendants not read'
    if any(p.lower() in PRIVATE_DIRS for p in parts):
        return 'private-profile-ssh-or-socket-tree; metadata only, descendants not read'
    if (name in PRIVATE_NAMES or name.startswith(('id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'ssh_config', 'sshconfig'))
            or name.endswith(('.key', '.pem', '.p12', '.pfx', '.plist')) or name.startswith('.env.')
            or (len(parts) >= 2 and parts[-2] == 'bin' and name in ('ssh', 'ssh-original'))):
        return 'private-credential-or-runtime-configuration; body not opened'
    if stat.S_ISLNK(mode):
        return 'symlink; target not followed or read'
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return 'socket-or-special-file; body not opened'
    if stat.S_ISREG(mode) and nlink != 1:
        return 'nonexclusive-file-link; body not opened'
    if (member.startswith('r36/evidence-export-01/') and member not in {
            'r36/evidence-export-01/export-report.json',
            'r36/evidence-export-01/verification-01.json'}):
        return 'outside-exact-prior-export-and-verification-receipts; metadata only, descendants not read'
    if stat.S_ISREG(mode) and name.endswith(('.tar', '.tar.gz', '.tar.xz', '.tgz', '.txz', '.zip', '.7z')):
        return 'opaque-container; metadata only, original expanded evidence captured separately'
    if member.startswith('r36/') and stat.S_ISDIR(mode) and len(parts) == 1 and parts[0] not in DIRECTORIES:
        return 'outside-fixed-evidence-directories; metadata only, descendants not read'
    return None


def prior_failure_binding(payloads, body):
    """Prior export receipts are retained as originals; no legacy capture failure is bound."""
    return None


def inventory(helper, output):
    result = {'scopes': {}, 'entries': {}}
    for label, root in SCOPES.items():
        present = os.path.lexists(root)
        row = {'path': str(root), 'present': present, 'directories': {}, 'entries': []}
        result['scopes'][label] = row
        if not present:
            need(label != 'r36', 'R36 root missing')
            continue
        helper.direct(root)
        info = root.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(), 'unsafe fixed scope root')

        def walk(path, member):
            info = path.lstat()
            row['directories'][member] = helper.stamp(info)
            with os.scandir(path) as stream:
                children = sorted(stream, key=lambda child: child.name)
            for child in children:
                target, name = path / child.name, member + '/' + child.name
                if target == output:
                    continue
                info = target.lstat()
                reason = omission_reason(name, info.st_mode, info.st_nlink)
                if info.st_uid != os.geteuid():
                    reason = 'different-owner; body not opened'
                if reason is None and stat.S_ISDIR(info.st_mode):
                    walk(target, name)
                    continue
                row['entries'].append(name)
                result['entries'][name] = {'source_path': str(target), 'original_identity': helper.stamp(info),
                                           'reason': reason}
                need(len(result['entries']) <= MAX_ENTRIES, 'evidence inventory exceeds bound')

        walk(root, label)
        row['entries'].sort()
    return result


def stage_observations(scopes, body):
    directories = scopes['r36']['directories']
    result = {}
    for name, (directory, filename, flag) in STAGES.items():
        member = 'r36/' + directory + '/' + filename
        if 'r36/' + directory not in directories:
            present = 'r36/' + directory in scopes['r36']['entries']
            result[name] = {'state': 'metadata_only_output_unresolved' if present else 'not_executed_no_output_observed',
                            'report': member, 'basis': 'fixed output metadata at capture; no positive outcome inferred'}
            if name == 'async_read_supplement':
                result[name]['scope'] = 'descriptive supplement; no adoption gate or performance pass inferred'
                result[name]['reported_correctness_passed'] = None
            continue
        raw = body(member)
        try:
            value = json.loads(raw) if raw is not None else None
        except (ValueError, UnicodeError):
            value = None
        result[name] = {'state': 'original_report_retained' if isinstance(value, dict) else 'partial_or_unreadable_report',
                        'report': member, 'reported_flag_name': flag,
                        'reported_flag': value.get(flag) if isinstance(value, dict) and type(value.get(flag)) is bool else None,
                        'independently_adjudicated': False}
        if name == 'async_read_supplement':
            result[name]['scope'] = 'descriptive supplement; no adoption gate or performance pass inferred'
            result[name]['reported_correctness_passed'] = (value.get('correctness_passed')
                if isinstance(value, dict) and type(value.get('correctness_passed')) is bool else None)
    raw = body('recovery/report.json')
    try:
        value = json.loads(raw) if raw is not None else None
    except (ValueError, UnicodeError):
        value = None
    result['cancel_recovery'] = {'state': 'original_report_retained' if isinstance(value, dict)
                                else 'partial_or_unreadable_report' if scopes['recovery']['present']
                                else 'not_executed_no_output_observed',
                                'report': 'recovery/report.json', 'reported_flag_name': 'passed',
                                'reported_flag': value.get('passed') if isinstance(value, dict)
                                and type(value.get('passed')) is bool else None,
                                'independently_adjudicated': False}
    return result


def holder_bindings(payloads, omissions, body):
    prefix = 'r36/holder-inputs-02/'
    names = {name for name in set(payloads) | set(omissions) if name.startswith(prefix)}
    manifest_name = prefix + 'manifest.json'
    if not names:
        return {'state': 'not_collected', 'planned_original_directories': [str(HOLDER_ROOT / name) for name in HOLDERS]}
    need(manifest_name in payloads, 'holder copies require their observed manifest')
    value = json.loads(body(manifest_name))
    need(value.get('schema') == 'hepta-r36-observed-holder-copies/v1'
         and value.get('observed') is True and isinstance(value.get('files'), dict), 'holder copy manifest is not observed evidence')
    need(names == {manifest_name} | {prefix + name for name in value['files']}, 'holder file inventory differs')
    for relative, pin in value['files'].items():
        parts = PurePosixPath(relative).parts
        need(parts and parts[0] in HOLDERS and '..' not in parts and str(PurePosixPath(relative)) == relative,
             'holder copy escaped the exact planned directories')
        member = prefix + relative
        need(pin['original_path'] == str(HOLDER_ROOT / relative)
             and type(pin['bytes']) is int and pin['bytes'] >= 0 and HEX.fullmatch(pin['sha256']),
             'holder original identity missing')
        if member in payloads:
            need(all(payloads[member][key] == pin[key] for key in ('bytes', 'sha256')), 'holder copy differs from observed original')
        else:
            need(omissions[member]['original_identity']['st_size'] == pin['bytes'], 'omitted holder metadata size differs')
    return {'state': 'observed_copies_bound', 'manifest': manifest_name,
            'files': len(value['files']), 'private_bodies_verified': False, 'remote_reads': 0}
