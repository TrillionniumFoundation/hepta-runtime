#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Capture fixed R36 originals once; preserve failures, never infer adoption."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
import evidence_policy as policy
from scan_evidence import MAX_FILE, scan

def peek(helper, path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        policy.need(helper.stamp(os.fstat(fd)) == expected, 'input changed before header probe')
        header = os.read(fd, 4)
        policy.need(helper.stamp(os.fstat(fd)) == helper.stamp(path.lstat()) == expected,
                    'input changed during header probe')
        return header
    finally:
        os.close(fd)


def scanned_read(helper, path, metadata):
    reader = helper.StableReader(path)
    try:
        policy.need(helper.stamp(reader.before) == metadata, 'input changed before scan')
        if reader.before.st_size > MAX_FILE:
            return None, None, [{'path': str(path), 'pattern': 'raw:scan-size-limit'}]
        blocks = []
        while block := reader.read(helper.BLOCK):
            blocks.append(block)
        identity = reader.finish()
        raw = b''.join(blocks)
        return identity, raw, scan(raw, str(path))
    finally:
        reader.close()


def capture(out):
    """Capture the fixed policy roots; admission of the native operator is in main."""
    helper = policy.load_helper()
    findings, phase, created = [], 'admission', False
    try:
        helper.direct(policy.ROOT)
        policy.need(out.parent == policy.ROOT and re.fullmatch(r'evidence-export-[0-9]{2}', out.name)
                    and not os.path.lexists(out), 'new direct R36 evidence output required')
        out.mkdir(mode=0o700)
        created = True
        phase = 'inventory'
        before = policy.inventory(helper, out)
        payloads, omissions, reports = {}, {}, {}
        wanted = {'r36/' + directory + '/' + filename for directory, filename, _ in policy.STAGES.values()}
        wanted.add('r36/holder-inputs-01/manifest.json')
        wanted.add('recovery/report.json')
        phase = 'scan'
        total = 0
        for member, row in sorted(before['entries'].items()):
            path, info, reason = Path(row['source_path']), row['original_identity'], row['reason']
            header_bytes = 0
            if reason is None and peek(helper, path, info) == b'\x7fELF':
                reason, header_bytes = 'ELF; metadata only, body not hashed or archived', 4
            if reason is not None:
                omissions[member] = dict(row, reason=reason, metadata_only=True,
                                        body_included=False, body_sha256=None, header_probe_bytes=header_bytes)
                continue
            identity, raw, matched = scanned_read(helper, path, info)
            findings.extend(matched)
            if matched:
                policy.need(len(findings) <= 128, 'scanner finding bound exceeded')
                continue
            payloads[member] = identity
            total += identity['bytes']
            policy.need(total <= policy.MAX_PAYLOAD_BYTES, 'complete evidence exceeds fixed archive bound')
            if member in wanted:
                reports[member] = raw
        policy.need(not findings, 'evidence secret or decoding-bound scan refused export')
        scopes = before['scopes']
        holders = policy.holder_bindings(payloads, omissions, reports.get)
        outcomes = policy.stage_observations(scopes, reports.get)
        tool_pins = {}
        for name in policy.TOOL_FILES:
            member = 'r36/evidence-tools-01/' + name
            policy.need(member in payloads, 'capture source missing from fixed package')
            tool_pins[name] = {key: payloads[member][key] for key in ('bytes', 'sha256')}
        manifest = {
            'schema': 'hepta-r36-evidence-manifest/v1',
            'root': str(policy.ROOT), 'canary': str(policy.CANARY), 'export_directory': str(out),
            'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'operator_uid': os.geteuid(),
            'payloads': payloads, 'omissions': omissions, 'scope_inventories': scopes,
            'fixed_directories': {name: 'present' if 'r36/' + name in scopes['r36']['directories'] else 'absent_or_metadata_only'
                                  for name in policy.DIRECTORIES},
            'original_stage_observations': outcomes, 'holder_bindings': holders,
            'capture_sources': tool_pins, 'archive_helper_sha256': policy.HELPER_SHA,
            'scanner': {'findings': [], 'raw_and_json_hex_base64_gzip_scanned': True,
                        'credential_paths_opened': False, 'omitted_elf_body_hashed': False},
            'candidate_adopted': False, 'performance_pass_inferred': False, 'hosted_CI_passed_inferred': False,
            'remote_operations': 0, 'commands_or_archived_code_executed': 0,
            'outside_scope_references_followed': False,
        }
        metadata_hits = scan(helper.encode(manifest), '_export-manifest.json')
        findings.extend(metadata_hits)
        policy.need(not findings, 'manifest secret or decoding-bound scan refused export')
        phase = 'archive'
        archive = out / 'r36-evidence-01.tar.xz'
        manifest_raw, archive_check = helper.write_archive(archive, manifest, payloads)
        phase = 'final-inventory'
        policy.need(policy.inventory(helper, out) == before, 'original evidence inventory or metadata changed')
        report = {'schema': 'hepta-r36-evidence-export/v1', 'package_complete': True,
                  'archive': {key: archive_check['identity'][key] for key in ('bytes', 'sha256')},
                  'archive_name': archive.name,
                  'manifest': {'bytes': len(manifest_raw), 'sha256': hashlib.sha256(manifest_raw).hexdigest()},
                  'payload_count': len(payloads), 'omission_count': len(omissions),
                  'original_inputs_unchanged': True, 'original_stage_observations': outcomes,
                  'holder_bindings': holders, 'capture_sources': tool_pins,
                  'archive_validation': archive_check, 'candidate_adopted': False,
                  'performance_pass_inferred': False, 'hosted_CI_passed_inferred': False,
                  'remote_operations': 0, 'commands_or_archived_code_executed': 0}
        destination = out / 'export-report.json'
        helper.create(destination, helper.encode(report))
        print(json.dumps({'package_complete': True, 'report': helper.read(destination)[0],
                          'archive': report['archive'], 'candidate_adopted': False}), flush=True)
        return 0
    except Exception as error:
        failure = {'package_complete': False, 'phase': phase, 'error_type': type(error).__name__,
                   'findings': findings[:128], 'candidate_adopted': False,
                   'source_files_modified': False, 'remote_operations': 0}
        if created:
            helper.create(out / 'export-failure.json', helper.encode(failure))
        print(json.dumps(failure), flush=True)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=policy.ROOT / 'evidence-export-01')
    args = parser.parse_args()
    policy.need(sys.platform == 'linux' and os.geteuid() != 0, 'native X230 operator required')
    policy.need(Path(__file__).resolve().parent == policy.ROOT / 'evidence-tools-01', 'fixed deployed evidence tools required')
    return capture(args.out)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'package_complete': False, 'error_type': type(error).__name__}), flush=True)
        raise SystemExit(1)
