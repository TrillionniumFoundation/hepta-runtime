#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independently check every R36 archive member; never extract or run its code."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

sys.dont_write_bytecode = True
import evidence_policy as policy
from scan_evidence import scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--report-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    helper = policy.load_helper()
    policy.need(not os.path.lexists(args.out) and args.out.is_absolute(), 'fresh verification output required')
    report_id, raw = helper.read(args.report, retain=True)
    policy.need(policy.HEX.fullmatch(args.report_sha256) and report_id['sha256'] == args.report_sha256,
                'observed original export report identity differs')
    report = json.loads(raw)
    policy.need(report['schema'] == 'hepta-r36-evidence-export/v1' and report['package_complete'] is True
                and report['original_inputs_unchanged'] is True, 'incomplete evidence export')
    archive_id = helper.read(args.archive)[0]
    policy.need(all(archive_id[key] == report['archive'][key] for key in ('bytes', 'sha256')), 'compressed archive identity differs')
    manifest_raw = helper.manifest_from_archive(args.archive, report['manifest'])
    manifest = json.loads(manifest_raw)
    policy.need(manifest['schema'] == 'hepta-r36-evidence-manifest/v1'
                and manifest['root'] == str(policy.ROOT) and manifest['canary'] == str(policy.CANARY)
                and manifest['archive_helper_sha256'] == policy.HELPER_SHA, 'archive scope or reviewed helper differs')
    payloads, omissions, scopes = manifest['payloads'], manifest['omissions'], manifest['scope_inventories']
    policy.need(set(scopes) == set(policy.SCOPES) and set(payloads).isdisjoint(omissions)
                and len(payloads) == report['payload_count'] and len(omissions) == report['omission_count']
                and len(payloads) + len(omissions) <= policy.MAX_ENTRIES, 'evidence inventory differs')
    listed = []
    for label, root in policy.SCOPES.items():
        row = scopes[label]
        policy.need(row['path'] == str(root) and type(row['present']) is bool
                    and row['entries'] == sorted(set(row['entries'])), 'noncanonical fixed scope inventory')
        policy.need(row['present'] or not row['entries'] and not row['directories'], 'absent scope contains evidence')
        policy.need(not row['present'] or label in row['directories'], 'present scope root metadata missing')
        for name, info in row['directories'].items():
            policy.need(name.split('/')[0] == label and stat.S_ISDIR(info['st_mode'])
                        and info['st_uid'] == manifest['operator_uid']
                        and policy.omission_reason(name, info['st_mode'], info['st_nlink']) is None,
                        'directory inventory escaped traversable scope')
            policy.source_path(name)
            if name != label:
                policy.need(str(PurePosixPath(name).parent) in row['directories'], 'directory parent metadata missing')
        for name in row['entries']:
            policy.need(str(PurePosixPath(name).parent) in row['directories']
                        and name not in row['directories'], 'entry escaped observed parent directory')
        listed.extend(row['entries'])
    policy.need(len(listed) == len(set(listed)) and set(listed) == set(payloads) | set(omissions), 'member or omission missing from original inventory')
    policy.need(sum(row['bytes'] for row in payloads.values()) <= policy.MAX_PAYLOAD_BYTES, 'expanded payload exceeds bound')
    for member, row in payloads.items():
        expected, info = policy.source_path(member), row['original_identity']
        policy.need(row['source_path'] == str(expected) and row['is_elf'] is False
                    and info['st_uid'] == manifest['operator_uid'] and stat.S_ISREG(info['st_mode'])
                    and info['st_nlink'] == 1 and info['st_size'] == row['bytes']
                    and policy.omission_reason(member, info['st_mode'], info['st_nlink']) is None,
                    'unsafe or wrongly included original payload')
    for member, row in omissions.items():
        info = row['original_identity']
        expected_reason = policy.omission_reason(member, info['st_mode'], info['st_nlink'])
        if info['st_uid'] != manifest['operator_uid']:
            expected_reason = 'different-owner; body not opened'
        if row['reason'] == 'ELF; metadata only, body not hashed or archived':
            policy.need(expected_reason is None and stat.S_ISREG(info['st_mode']) and row['header_probe_bytes'] == 4,
                        'invalid ELF metadata omission')
        else:
            policy.need(row['reason'] == expected_reason and expected_reason is not None
                        and row['header_probe_bytes'] == 0, 'unjustified metadata omission')
        policy.need(row['source_path'] == str(policy.source_path(member)) and row['metadata_only'] is True
                    and row['body_included'] is False and row['body_sha256'] is None, 'omitted body was represented as read')
    verification = helper.verify_archive(args.archive, manifest_raw, payloads)
    expanded, _ = helper.expanded_xz(args.archive, archive_id)
    findings = scan(manifest_raw, '_export-manifest.json')
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        def body(member):
            if member not in payloads:
                return None
            return archive.extractfile(archive.getmember(member)).read()

        for member in payloads:
            findings.extend(scan(body(member), member))
            policy.need(len(findings) <= 128, 'scanner finding bound exceeded')
        if findings:
            helper.create(args.out, helper.encode({'verified': False, 'findings': findings, 'candidate_adopted': False}))
            print(json.dumps({'verified': False, 'findings': findings}), flush=True)
            return 1
        expected_dirs = {name: 'present' if 'r36/' + name in scopes['r36']['directories'] else 'absent_or_metadata_only'
                         for name in policy.DIRECTORIES}
        policy.need(manifest['fixed_directories'] == expected_dirs, 'fixed directory absence declarations differ')
        outcomes = policy.stage_observations(scopes, body)
        holders = policy.holder_bindings(payloads, omissions, body)
        policy.need(outcomes == manifest['original_stage_observations'] == report['original_stage_observations']
                    and holders == manifest['holder_bindings'] == report['holder_bindings'], 'original outcomes or holder binding changed')
        policy.need(manifest['capture_sources'] == report['capture_sources']
                    and set(manifest['capture_sources']) == set(policy.TOOL_FILES), 'capture source receipt differs')
        for name, pin in manifest['capture_sources'].items():
            policy.need(Path(name).name == name, 'unsafe capture tool name')
            local = helper.read(Path(__file__).resolve().with_name(name))[0]
            archived = body('r36/evidence-tools-01/' + name)
            policy.need(archived is not None and all(local[key] == pin[key] for key in ('bytes', 'sha256'))
                        and hashlib.sha256(archived).hexdigest() == pin['sha256'], 'reviewed capture source differs')
    for value in (manifest, report):
        policy.need(value['candidate_adopted'] is False and value['performance_pass_inferred'] is False
                    and value['hosted_CI_passed_inferred'] is False and value['remote_operations'] == 0
                    and value['commands_or_archived_code_executed'] == 0, 'transport was promoted to an execution result')
    policy.need(helper.read(args.archive)[0] == archive_id and helper.read(args.report)[0] == report_id,
                'local originals changed during verification')
    result = {'schema': 'hepta-r36-evidence-independent-verification/v1', 'verified': True,
              'scope': 'lossless retained payloads, explicit omissions and original reported outcomes; not candidate acceptance',
              'archive': report['archive'], 'manifest': report['manifest'],
              'archive_validation': verification, 'original_stage_observations': outcomes, 'holder_bindings': holders,
              'omission_count': len(omissions), 'secret_scan_findings': [],
              'candidate_adopted': False, 'performance_pass_inferred': False, 'hosted_CI_passed_inferred': False,
              'archive_extracted': False, 'archive_code_executed': False, 'remote_operations': 0}
    helper.create(args.out, helper.encode(result))
    print(json.dumps({'verified': True, 'result': helper.read(args.out)[0], 'candidate_adopted': False}), flush=True)
    return 0


if __name__ == '__main__':
    os.umask(0o077)
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'verified': False, 'error_type': type(error).__name__}), flush=True)
        raise SystemExit(1)
