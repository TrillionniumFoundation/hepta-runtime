#!/usr/bin/python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bind reviewed files and completed A54 qualification; never contact a host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import types

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
TOOLS = BASE / 'tools'
BASE_SHA = '8ed769c4ca6a44cfd4c38ab31a6b378025f4e84ab13f77e564bbd70a1e594f7a'
ADMISSION_SHA = '464d503f925044f7dd4f13288c31f7735ea427ee9f863531ecbb55a52238237b'
CONFIG_SHA = '00dd6f7168ec9ecd892100dd667a79da00173d1348373a717ae269b88ad3e117'
HOSTS_SHA = '2bc880a7949593d946e5d77ee22381ddffecabc5db76594f3245698e4de0343e'
FINAL_BINDINGS_READY = True
ACTUAL_QUALIFICATION_SHA256 = '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'
ACTUAL_RELEASE_SHA256 = 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'
ACTUAL_TESTED_MAP_COMPACT_SHA256 = '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def require_bindings():
    need(FINAL_BINDINGS_READY is True, 'actual A54 qualification bindings pending; no fixture or child admitted')
    for value in (ACTUAL_QUALIFICATION_SHA256, ACTUAL_RELEASE_SHA256, ACTUAL_TESTED_MAP_COMPACT_SHA256):
        need(type(value) is str and len(value) == 64 and all(character in '0123456789abcdef' for character in value),
             'actual A54 qualification/release/tested-source SHA missing')


def main(args):
    require_bindings()
    need(args.qualification_sha256 == ACTUAL_QUALIFICATION_SHA256, 'actual A54 qualification SHA differs')
    os.umask(0o077)
    raw = (TOOLS / 'native_owner_recovery_frozen.py').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == BASE_SHA and len(raw) == 43478, 'frozen original controller helper differs')
    base = types.ModuleType('plan_data_from_frozen_owner_harness')
    base.__file__ = str(TOOLS / 'native_owner_recovery_frozen.py')
    exec(compile(raw, base.__file__, 'exec'), base.__dict__)
    qualification = BASE / 'qualification-a54-compact-view-r01/report.json'
    q, bundle = base.qualification(qualification, args.qualification_sha256)
    need(bundle['binary']['sha256'] == ACTUAL_RELEASE_SHA256
         and base.digest(json.dumps(bundle['source_map'], sort_keys=True, separators=(',', ':')).encode()) == ACTUAL_TESTED_MAP_COMPACT_SHA256,
         'actual A54 release/tested source differs')
    need(bundle['source_files'] == 175 and len(q['stages']) == 6, 'complete combined A54 source qualification required')
    admission_path = BASE / 'a52-native-ssh-profile-r01/ai395-independent-identity.original.json'
    need(base.file_receipt(admission_path)['sha256'] == ADMISSION_SHA, 'original independent operator identity receipt differs')
    independent = json.loads(base.read(admission_path))
    need(independent['schema'] == 'hepta-a52-ai395-independent-identity/v1'
         and independent['systemctl_exists'] is True and independent['user_bus']['socket'] is True
         and independent['user_bus']['uid'] == independent['uid'] == 1000, 'independent user-systemd admission incomplete')
    remote = {key: independent[key] for key in ('uid', 'home', 'hostname', 'boot_id', 'machine_id', 'machine')}
    remote.update(username='qq', python_realpath=independent['python'])
    need(remote['home'] == '/home/qq' and remote['hostname'] == 'ai395'
         and remote['boot_id'] == 'b1620269-aaef-43e7-bf47-bc6eb1c1a447'
         and remote['machine_id'] == '85e535eb5a7442faac0c00e601f1e954'
         and remote['python_realpath'] == '/usr/bin/python3.14', 'current independently observed AI395 differs')
    controller = {'uid': os.geteuid(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    need(controller == {'uid': 1000, 'boot_id': 'b19bd1b9-4dbe-4335-96cf-ed98d393efea'}, 'original admitted X230 boot/account differs')
    helper = base.file_receipt(TOOLS / 'remote_owner_custody_a54.py')
    harness = base.file_receipt(TOOLS / 'run_native_remote_owner_a54.py')
    need(helper['sha256'] == args.helper_sha256 and harness['sha256'] == args.harness_sha256,
         'reviewed helper/harness bytes differ')
    profile = BASE / 'a52-native-ssh-profile-r01'
    config = base.file_receipt(profile / 'ssh_config'); hosts = base.file_receipt(profile / 'known_hosts')
    need(config['sha256'] == CONFIG_SHA and hosts['sha256'] == HOSTS_SHA, 'actual fresh direct profile differs')
    base.validate_ssh_config(profile / 'ssh_config')
    identity = Path('/home/qian/.ssh/id_ed25519_ai395_mesh')
    info = identity.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
         and not info.st_mode & 0o077, 'existing private identity metadata unsafe')
    public = base.file_receipt(identity.with_suffix('.pub'))
    need(public['sha256'] == '978911353de7277875419f48b8e180babc1f735a0dca426738075e95af14c8de',
         'existing admitted public identity changed')
    plan = {'schema': 'hepta-native-remote-owner-plan/v1', 'ready': True,
            'attempt_nonce': secrets.token_hex(32), 'cases': list(base.CASES),
            'local_out': str(BASE / 'a54-native-owner-remote-r01'),
            'remote_parent': '/home/qq/hepta-runtime-native-owner-a54-r01',
            'controller_identity': controller, 'remote_identity': remote,
            'independent_admission': {'path': str(admission_path), 'sha256': ADMISSION_SHA,
                                      'operator_job_id': '1a177d55de6-96a-1114'},
            'qualification': {'path': str(qualification), 'sha256': bundle['qualification']['sha256'],
                              'release_sha256': bundle['binary']['sha256'], 'source_files': 175,
                              'tested_map_compact_sha256': ACTUAL_TESTED_MAP_COMPACT_SHA256},
            'base_harness_sha256': BASE_SHA, 'helper_sha256': helper['sha256'], 'harness_sha256': harness['sha256'],
            'business_code': base.CHILD, 'business_code_sha256': base.digest(base.CHILD.encode()),
            'input_sha256': base.digest(base.INPUT), 'ssh_target': 'native-ai395',
            'ssh_config': config['path'], 'ssh_config_sha256': CONFIG_SHA,
            'known_hosts': hosts['path'], 'known_hosts_sha256': HOSTS_SHA,
            'private_identity_metadata': {'path': str(identity), 'identity': list(base.stamp(info))},
            'public_identity_receipt': public,
            'execution_policy': {'business_launches': 3, 'controller_workers': 2, 'business_timeout_seconds': 90,
                                 'business_release_deadline_seconds': 75, 'helper_session_seconds': 150,
                                 'helper_cleanup_seconds': 20, 'ssh_cleanup_seconds': 40,
                                 'automatic_retry': False, 'service_changes': False, 'detached_fallback': False}}
    output = TOOLS / 'a54-native-owner-remote-plan-r01.json'
    base.create(output, base.canonical(plan)); base.directory_sync(output.parent)
    print(json.dumps({'plan': base.file_receipt(output), 'ready_for_root_review': True,
                      'remote_operations': 0, 'business_launches': 0}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification-sha256', required=True)
    parser.add_argument('--helper-sha256', required=True)
    parser.add_argument('--harness-sha256', required=True)
    main(parser.parse_args())
