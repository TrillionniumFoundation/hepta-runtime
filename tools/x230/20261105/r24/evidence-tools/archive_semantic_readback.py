#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read the actual R24 archive semantics after the separate frozen tar QA.

No extraction, remote access, benchmark replay or Git operation. The four
terminal report bodies and tools are pinned to actual pre-transfer readbacks.
An integrity pass alone never establishes campaign adoption. The Mac holder
receipt is external to the X230 archives and proves only its owned resources.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import types

sys.dont_write_bytecode = True
WORK = Path('/workspace/scratch/806ba5f52f94')
ROOT = '/home/qian/hepta-runtime-optimization-20261105-r24'
RECOVERY = '/home/qian/hepta-runtime-optimization-20261104-r16/r24-cancel-recovery-01'
QA_SHA = 'd5cf47fa484d71a78ce07b2154e6c89a268ca18d583263aad387c6b07422237c'
PINS = {
    'r24-results/qualification-report.json': (83365, 'bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971'),
    'r24-results/campaign-report.json': (100033, '066952f12414e8f7291e21e58a77d53d4cd712104557bd6bdfdd7c383f9f1e2a'),
    'r24-results/lifecycle-analysis.json': (12853, '04cf750f3767a3d81bf4b2182647bd7ca8447f9a22ed31885b24cf147a18b58d'),
    'r24-results/summary.json': (13529, '5f0cf4538c5e4e7dff9f3f6a43e88f4fd4675f76640137908ec565daea285015'),
    'r24-results/qualified-source-map.json': (24156, 'c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd'),
    'r24-results/export-report.json': (4536, '1d2d6f9c3d79cf833409aee3c28bc8cd7d3768d6882095efc9b6cfe25a2363df'),
    'r24-results/mac-holder-report.json': (9075, '26b4fef830b55677f1f1edb44f9f5925186fecb24c413907b8d9fa91ec7e20a4'),
    'r24-transfer/archive-identities.json': (1241, '046946e85f54e4969ddaf7bbaaf6437af07576c673fb83ce7d98be9fb6dfa6d5'),
    'benchmark-r24/export_r24_evidence.py': (12305, '6f2f3fac8a5825ea7121e2edbb5a6538f91809a189b2ad44ab68ab35988ddacd'),
    'benchmark-r24/prepare_and_qualify_r24.py': (6093, 'c76956cd24e3ffe8f78fe188ecb51041828c0de1e924c96329dd93bd742f87a8'),
    'benchmark-r24/prepare_campaign_inputs.py': (4339, '3487b40b532355603e720e89849adc644d5bfaa9cf5e715070ef55f9b2fa1487'),
    'benchmark-r24/r24_campaign.py': (37887, '84fb7bea3fc23c333c15ab3f53e4e92fde55da73f49f888c84bb3818a066bdd0'),
}
REPORTS = {
    'qualification': ('qualification', 'qualification/report.json', 'r24-results/qualification-report.json'),
    'campaign': ('campaign', 'campaign/report.json', 'r24-results/campaign-report.json'),
    'summary': ('campaign', 'campaign/summary.json', 'r24-results/summary.json'),
    'lifecycle': ('campaign', 'recovery/independent-summary.json', 'r24-results/lifecycle-analysis.json'),
}
TOOLS = {
    'export-tools/export_r24_evidence.py': 'benchmark-r24/export_r24_evidence.py',
    'preparation-tools/prepare_and_qualify_r24.py': 'benchmark-r24/prepare_and_qualify_r24.py',
    'preparation-tools/prepare_campaign_inputs.py': 'benchmark-r24/prepare_campaign_inputs.py',
}
STAGES = ['native-observation', 'native-audit', 'native-boundary', 'boundary-audit',
          'cancel-recovery', 'recovery-audit', 'adoption-summary']
CLEANUP_SCOPE = ('owned stage process group only; independent controller sessions '
                 'are proved by original reports/audits')


def digest(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def load_qa_helpers():
    # Execute only the hash-pinned module definitions, never its CLI or full QA.
    path = WORK / 'r24-transfer/archive_tar_qa.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != QA_SHA:
        raise ValueError('frozen tar QA helper identity changed')
    module = types.ModuleType('_frozen_r24_archive_qa')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def read_local(qa, path, maximum=16 * 1024 * 1024):
    with qa.stable_reader(path, maximum) as (stream, _before):
        return stream.read()


def member_bytes(qa, archive, name, maximum=16 * 1024 * 1024):
    qa.archive_path(name)
    member = archive.getmember(name)
    qa.need(member.isreg() and 0 <= member.size <= maximum, 'bounded regular member required: ' + name)
    with archive.extractfile(member) as stream:
        raw = stream.read(maximum + 1)
    qa.need(len(raw) == member.size, 'member length mismatch: ' + name)
    return raw


def remote_member(path):
    if path.startswith(ROOT + '/campaign-01/'):
        return 'campaign/' + path[len(ROOT + '/campaign-01/'):]
    if path.startswith(RECOVERY + '/'):
        return 'recovery/' + path[len(RECOVERY + '/'):]
    raise ValueError('unmapped output binding: ' + path)


def check(qa, args, result):
    local = {}
    for relative, (size, sha) in PINS.items():
        raw = read_local(qa, WORK / relative)
        qa.need(digest(raw) == {'bytes': size, 'sha256': sha}, 'pinned actual local input changed: ' + relative)
        local[relative] = raw
    result['pinned_local_inputs'] = {key: digest(raw) for key, raw in local.items()}
    identities = {row['name']: row for row in qa.decode_json(local['r24-transfer/archive-identities.json'])}
    export = qa.decode_json(local['r24-results/export-report.json'])
    qa_raw = read_local(qa, args.qa_report)
    integrity = qa.decode_json(qa_raw)
    qa.need(integrity['schema'] == 'hepta-r24-archive-tar-qa/v1' and integrity['passed'] is True,
            'a completed separate R24 tar QA pass is required')
    qa.need(integrity['archive_identity_receipt']['sha256'] == PINS['r24-transfer/archive-identities.json'][1]
            and integrity['archive_identity_receipt']['bytes'] == PINS['r24-transfer/archive-identities.json'][0],
            'tar QA used a different archive receipt')
    qa_rows = {row['group']: row for row in integrity['archives']}
    qa.need(set(qa_rows) == set(identities) == set(export['archives']) == {'qualification', 'campaign'},
            'expected exactly the two actual R24 archives')
    result['archive_integrity'] = {'passed': True, 'report': str(args.qa_report), **digest(qa_raw),
                                  'separate_from_semantic_adoption': True}
    qa.need(export['schema'] == 'hepta-r24-evidence-export/v1' and export['passed'] is True
            and export['no_workload_executed'] is True and export['qualified_source_files'] == 220,
            'unexpected actual export receipt')
    with ExitStack() as stack:
        archives, manifests = {}, {}
        for group in ('qualification', 'campaign'):
            path = args.archives_dir / (group + '-01.tar.gz')
            stream, _before = stack.enter_context(qa.stable_reader(path, qa.MAX_ARCHIVE_BYTES))
            sha = hashlib.file_digest(stream, 'sha256').hexdigest()
            size = _before.st_size
            identity = identities[group]
            row = qa_rows[group]
            qa.need(row['passed'] is True and size == identity['size'] == row['bytes'] == export['archives'][group]['archive']['bytes']
                    and sha == identity['sha256'] == row['sha256'] == export['archives'][group]['archive']['sha256']
                    and row['source_archive_version'] == identity['version'], 'archive/QA/export binding differs: ' + group)
            stream.seek(0)
            archive = stack.enter_context(tarfile.open(fileobj=stream, mode='r:gz'))
            archives[group] = archive
            raw = member_bytes(qa, archive, '_export-manifest.json', qa.MAX_MANIFEST_BYTES)
            qa.need(digest(raw) == {key: export['archives'][group]['manifest'][key] for key in ('bytes', 'sha256')},
                    'embedded manifest differs from actual export: ' + group)
            manifests[group] = qa.decode_json(raw)
        reports = {}
        result['actual_report_bodies'] = {}
        for label, (group, name, relative) in REPORTS.items():
            raw = member_bytes(qa, archives[group], name)
            qa.need(raw == local[relative], 'actual report raw bytes differ: ' + label)
            reports[label] = qa.decode_json(raw)
            result['actual_report_bodies'][label] = {'group': group, 'member': name, **digest(raw), 'matches_actual_local_bytes': True}
        qualification, campaign, summary, lifecycle = (reports[key] for key in REPORTS)
        qa.need(qualification['qualified'] is True and qualification.get('finished_utc')
                and qualification['source_tested'] == qualification['source_after'], 'qualification did not close unchanged')
        qa.need(len(qualification['stages']) == 8 and all(type(s['returncode']) is int and s['returncode'] == 0
                                                       for s in qualification['stages']), 'qualification stage failed')
        qa.need(qualification['automatic_test_retries'] == 0, 'qualification retried tests')
        for key in ('passed', 'adoption_passed', 'correctness_stages_completed', 'inputs_unchanged',
                    'source_inputs_unchanged', 'baseline_source_inputs_unchanged', 'baseline_enablement_verified'):
            qa.need(campaign[key] is True, 'campaign condition failed: ' + key)
        qa.need(campaign.get('finished_utc') and campaign['rejection_reasons'] == []
                and campaign['qualified_source_maps_match_current_inputs'] == {'A': True, 'B': True},
                'campaign terminal/qualification binding differs')
        for key in ('adoption_gate_passed', 'correctness_verified', 'evidence_verified', 'performance_gates_passed'):
            qa.need(summary[key] is True, 'adoption summary condition failed: ' + key)
        qa.need(summary['rejection_reasons'] == [] and summary['thresholds'] == campaign['thresholds'], 'summary gates differ')
        qa.need(export['qualified'] is True and export['campaign_passed'] is True and export['candidate_adopted'] is True,
                'producer export state differs from actual terminal reports')
        qa.need([stage['name'] for stage in campaign['stages']] == STAGES, 'campaign stage sequence differs')
        for stage in campaign['stages']:
            qa.need(type(stage['returncode']) is int and stage['returncode'] == 0 and stage['passed'] is True
                    and all(stage[key] is True for key in ('waited_and_reaped', 'owned_process_absent', 'owned_process_group_absent'))
                    and stage['cleanup_scope'] == CLEANUP_SCOPE, 'stage status/owned cleanup differs: ' + stage['name'])
            for identity in stage['output_bindings']:
                stored = manifests['campaign']['files'][remote_member(identity['path'])]
                qa.need(all(identity[key] == stored[key] for key in ('bytes', 'sha256')), 'stage output identity differs')
        for identity in summary['evidence'].values():
            stored = manifests['campaign']['files'][remote_member(identity['path'])]
            qa.need(all(identity[key] == stored[key] for key in ('bytes', 'sha256')), 'summary evidence identity differs')
        native = qa.decode_json(member_bytes(qa, archives['campaign'], 'campaign/native-observation/report.json'))
        boundary = qa.decode_json(member_bytes(qa, archives['campaign'], 'campaign/native-boundary/independent-summary.json'))
        qa.need(campaign['automatic_retries'] == native['automatic_rpc_retries']
                == boundary['automatic_rpc_retries'] == lifecycle['automatic_rpc_retries'] == 0,
                'an automatic stage/RPC retry was reported')
        qa.need(lifecycle['verified'] is True and lifecycle['private_transport_interruption']['passed'] is True
                and boundary['evidence_verified'] is True and boundary['drain_and_recovery_passed'] is True,
                'actual correctness audit failed')
        qa.need(summary['lifecycle']['ABBA_performance_claim'] is False, 'lifecycle scope expanded')
        source_raw = member_bytes(qa, archives['campaign'], 'campaign/source-inputs.json')
        qa.need(digest(source_raw) == {key: campaign['source_inputs'][key] for key in ('bytes', 'sha256')},
                'campaign source snapshot body differs')
        source = qa.decode_json(source_raw)
        source_map = qa.decode_json(local['r24-results/qualified-source-map.json'])
        qa.need(source_map == qualification['source_tested'] == qualification['source_after']
                and source['root'] == qualification['source'] == ROOT + '/source'
                and source['file_count'] == len(source['files']) == len(source_map) == 220,
                'qualified source input map/count differs')
        qa.need({name[7:] for name in manifests['qualification']['files'] if name.startswith('source/')} == set(source_map),
                'archive source member set differs')
        for name, sha in source_map.items():
            raw = member_bytes(qa, archives['qualification'], 'source/' + name)
            qa.need(digest(raw) == source['files'][name] and hashlib.sha256(raw).hexdigest() == sha,
                    'compiled source body differs: ' + name)
        canonical = (json.dumps(source['files'], sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        qa.need(hashlib.sha256(canonical).hexdigest() == source['sha256'] == campaign['source_inputs_sha256'],
                'campaign canonical source digest differs')
        result['qualified_source'] = {'verified': True, 'files': 220, 'all_archive_source_bodies_hashed': True,
                                      'source_inputs_sha256': source['sha256'], 'qualification_maps_equal': True}
        result['archived_tools'] = {}
        for name, relative in TOOLS.items():
            raw = member_bytes(qa, archives['campaign'], name)
            qa.need(raw == local[relative], 'actual archived tool differs: ' + name)
            result['archived_tools'][name] = digest(raw)
        qa.need(digest(local['benchmark-r24/export_r24_evidence.py']) ==
                {key: export['exporter_identity'][key] for key in ('bytes', 'sha256')}, 'actual exporter identity differs')
        candidate = campaign['binaries']['B']
        qa.need(all(qualification['binaries'][key]['sha256'] == value['sha256'] for key, value in candidate.items())
                and lifecycle['candidate_sha256'] == candidate['hepta-runtime']['sha256']
                and all(summary['binary_sha256'][version] == campaign['binaries'][version]['hepta-runtime']['sha256']
                        for version in ('A', 'B')), 'qualified/campaign binary metadata differs')
        result['campaign_semantics'] = {'qualified': True, 'campaign_passed': True, 'adoption_passed': True,
            'completed_stages': STAGES, 'all_stage_returncodes_zero': True, 'automatic_stage_retries': 0,
            'automatic_rpc_retries': {'native': 0, 'boundary': 0, 'lifecycle': 0},
            'stage_cleanup_scope': CLEANUP_SCOPE, 'lifecycle_scope': campaign['lifecycle_scope'],
            'lifecycle_ABBA_performance_claim': False, 'not_covered': lifecycle['not_covered'],
            'binary_identities_are_metadata_only': True}
    holder = qa.decode_json(local['r24-results/mac-holder-report.json'])
    qa.need(holder['passed'] is True and holder['remote_returncode'] == 0 and holder['automatic_ssh_retries'] == 0
            and all(holder[key] is True for key in ('owned_agent_reaped', 'owned_agent_directory_absent_after_context',
                                                  'owned_agent_socket_absent_after_context'))
            and holder['services_modified'] is False, 'external Mac holder result/owned cleanup differs')
    qa.need(holder['remote_script_sha256'] == campaign['launcher_sha256'] == PINS['benchmark-r24/r24_campaign.py'][1],
            'holder and campaign launcher identities differ')
    result['external_mac_holder'] = {'receipt': 'r24-results/mac-holder-report.json',
        **digest(local['r24-results/mac-holder-report.json']), 'archived_in_x230_tar': False,
        'passed': True, 'remote_returncode': holder['remote_returncode'],
        'owned_agent_returncode': holder['owned_agent_returncode'], 'automatic_ssh_retries': 0,
        'owned_agent_reaped': True, 'owned_agent_directory_absent': True, 'owned_agent_socket_absent': True,
        'scope': 'This holder-owned agent process, directory and socket only; no global cluster cleanup claim.'}
    result['passed'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archives-dir', type=Path, default=WORK / 'r24-evidence')
    parser.add_argument('--qa-report', type=Path, default=WORK / 'r24-transfer/archive-tar-qa-report.json')
    parser.add_argument('--output', type=Path, default=WORK / 'r24-transfer/archive-semantic-readback-report.json')
    args = parser.parse_args()
    qa = load_qa_helpers()
    qa.need(args.output.is_absolute() and args.output.resolve() == args.output and not os.path.lexists(args.output),
            'fresh direct semantic report output required')
    result = {'schema': 'hepta-r24-archive-semantic-readback/v1', 'started_utc': qa.utc(), 'passed': False,
        'frozen_full_qa_sha256': QA_SHA, 'no_workload_executed': True,
        'scope': ['Four terminal report bodies match the actual local pre-transfer readbacks byte for byte.',
                  'Adoption is checked from the actual terminal campaign and summary, separately from archive integrity.',
                  'Complete 220 compiled input bodies and three archived tool bodies are read and compared.',
                  'No extraction, remote access, benchmark replay, Git operation or new cleanup operation.',
                  'ELF/private omitted bodies and original remote filesystem identities are not locally rehashed.',
                  'Existing audits are read back; their correctness protocols are not rerun.']}
    try:
        check(qa, args, result)
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'reason': str(error)[:700]}
    result['finished_utc'] = qa.utc()
    qa.write_report(args.output, result)
    print(json.dumps({'passed': result['passed'], 'report': str(args.output), 'error': result.get('error')}, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
