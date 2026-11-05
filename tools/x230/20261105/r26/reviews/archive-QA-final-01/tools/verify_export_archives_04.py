#!/usr/bin/env python3
"""Verify complete downloaded R26 archive bytes and preserved outcomes locally.

No archive code is imported or executed. Native operation streams and Mac
holder evidence remain separate, explicitly unverified companions here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import types

HERE = Path(__file__).resolve().parent
HELPER_SHA = '34ce88cc28da10e1167dabaf6e3480aa42f5e6e76a29472d93959334aa9ec2ed'
EXPORTER_SHA = 'bac197db478f5d45fa3bbe742e21457484213d531786ecc48af6348895e6701b'


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def basic_read(path, maximum=16 * 1024**2):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, 'direct original local file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and 0 <= before.st_size <= maximum, 'unsafe or oversized local input')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        stamp = lambda value: {key: getattr(value, key) for key in fields}
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'original local file changed')
    finally:
        os.close(fd)
    return {'local_path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'descriptor_identity': stamp(before)}, raw


def load_reviewed(filename, expected):
    path = HERE / filename
    identity, raw = basic_read(path, 128 * 1024)
    need(expected is not None and identity['sha256'] == expected, 'reviewed verifier dependency differs')
    module = types.ModuleType('r26_archive_verifier_' + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--archives', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    need(not os.path.lexists(args.out), 'fresh independent local receipt required')
    helper, helper_identity = load_reviewed('stable_archive.py', HELPER_SHA)
    exporter, exporter_identity = load_reviewed('export_r26_evidence_04.py', EXPORTER_SHA)
    own_identity, _ = basic_read(Path(__file__).absolute())
    report_identity, raw = basic_read(args.report)
    report = json.loads(raw)
    need(report['schema'] == 'hepta-r26-outcome-preserving-evidence-export/v1'
         and type(report['passed']) is bool and report['adoption_decision_made_here'] is False
         and report['no_workload_executed'] is True and report['automatic_retries'] == 0
         and report['native_raw_companion_required'] is True
         and report['mac_holder_packages_required_if_executed'] is True,
         'unexpected exporter outcome schema or scope')
    need(report['exporter']['sha256'] == EXPORTER_SHA and report['archive_helper']['sha256'] == HELPER_SHA,
         'actual exporter report binds different source')
    need(set(report['archives']) == set(exporter.TREE_SCOPE), 'all four original archive groups required')
    sources, captures, original_bodies = {}, {}, {}
    wanted = {str(exporter.INPUT), str(exporter.ROOT / 'preparation-01.json'),
              *map(str, exporter.NATIVE_PATHS.values()), *map(str, exporter.REPORT_PATHS.values()),
              *(pin["path"] for pin in exporter.PREVIOUS_EXPORT_FILES.values())}
    local_inputs = [helper_identity, exporter_identity, own_identity, report_identity]
    for group, item in sorted(report['archives'].items()):
        path = args.archives / (group + '-01.tar.gz')
        manifest_path = args.archives / (group + '-manifest-01.json')
        identity = helper.read(path)[0]
        manifest_identity, manifest_raw = basic_read(manifest_path)
        for current, expected in ((identity, item['archive']), (manifest_identity, item['manifest'])):
            need((current['bytes'], current['sha256']) == (expected['bytes'], expected['sha256']),
                 'downloaded original archive/manifest differs')
        manifest = json.loads(manifest_raw)
        need(manifest['schema'] == 'hepta-r26-outcome-preserving-archive-manifest/v1'
             and manifest['group'] == group and manifest['original_stages'] == report['stages']
             and manifest['candidate_disposition'] == report['candidate_disposition']
             and manifest['previous_export_attempt01'] == report['previous_export_attempt01']
             and manifest['adoption_decision_made_here'] is False
             and manifest['python_ci_executed'] is False
             and manifest['archive_success_is_not_runtime_success'] is True,
             'archive manifest outcome differs')
        files, omissions = manifest['files'], manifest['omitted_bodies']
        need(len(files) == item['payload_files'] and len(omissions) == item['omitted_bodies']
             and sum(row['bytes'] for row in files.values()) == item['source_bytes'], 'payload accounting differs')
        names = set(files)
        for omitted in omissions:
            helper.safe_name(omitted['archive_path'])
            need(omitted['archive_path'] not in names and omitted.get('omission_reason'), 'omission duplicate or reason absent')
            names.add(omitted['archive_path'])
        captured_paths = {row['source_path'] for row in files.values()} | {row['source_path'] for row in omissions}
        for tree in manifest['source_trees'].values():
            need(set(tree) == {'files', 'directories'} and len(tree['files']) == len(set(tree['files']))
                 and set(tree['files']) <= captured_paths, 'original tree has an unaccounted file')
        for row in list(files.values()) + omissions:
            source_path = row['source_path']
            original_identity = {key: row[key] for key in ('bytes', 'sha256', 'original_identity') if key in row}
            need(source_path not in sources or sources[source_path] == original_identity,
                 'one original source has conflicting descriptor identities')
            sources[source_path] = original_identity
        proof = helper.verify_archive(path, manifest_raw, files)
        need(proof['verified'] is True and proof['gzip_integrity']['crc_and_isize_verified'] is True
             and proof['gzip_integrity']['exact_compressed_eof'] is True, 'complete gzip/tar verification failed')
        reverse = {name: row['source_path'] for name, row in files.items() if row['source_path'] in wanted}
        with tarfile.open(path, 'r|gz') as archive:
            for member in archive:
                if member.name not in reverse:
                    continue
                need(member.size <= 16 * 1024**2, 'original structured receipt exceeds retained limit')
                stream = archive.extractfile(member)
                body = stream.read(member.size + 1)
                need(len(body) == member.size, 'original receipt stream incomplete')
                source_path = reverse[member.name]
                need(source_path not in original_bodies or original_bodies[source_path] == body,
                     'original receipt bytes disagree across groups')
                original_bodies[source_path] = body
        need(helper.read(path)[0] == identity, 'downloaded archive changed while reading original receipts')
        local_inputs.append(manifest_identity)
        captures[group] = {'archive': identity, 'manifest': manifest_identity, 'independent_validation': proof,
                           'original_files_accounted': len(captured_paths)}
    need(str(exporter.INPUT) in original_bodies, 'actual export input is missing')
    def check_original_pin(raw, pin):
        need(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'],
             'original receipt byte identity differs from its bound pin')
    check_original_pin(original_bodies[str(exporter.INPUT)], report['input'])
    actual_input = json.loads(original_bodies[str(exporter.INPUT)])
    exporter.validate_stage_contract(actual_input)
    check_original_pin(original_bodies[str(exporter.ROOT / 'preparation-01.json')], actual_input['preparation'])
    check_original_pin(original_bodies[str(exporter.ROOT / 'preparation-01.json')], report['preparation']['identity'])
    previous_values = {}
    previous_retained = report["previous_export_attempt01"]
    for name, pin in exporter.PREVIOUS_EXPORT_FILES.items():
        body = original_bodies[pin["path"]]
        check_original_pin(body, pin)
        check_original_pin(body, previous_retained["files"][name])
        need(previous_retained["files"][name]["source_path"] == pin["path"],
             "original export01 source path differs")
        if name != "exporter":
            previous_values[name] = json.loads(body)
    previous_summary = exporter.validate_previous_export_failure(previous_values["report"],
        previous_values["native_terminal"], previous_values["native_read"])
    need({key: value for key, value in previous_retained.items() if key != "files"} == previous_summary,
         "original failed export was altered in the new report")
    recovered_stages = {}
    for stage, declaration in actual_input['stages'].items():
        retained = report['stages'][stage]
        recovered = recovered_stages[stage] = {'executed': declaration['executed']}
        need(retained['executed'] is declaration['executed'], 'executed state differs from actual input')
        if not declaration['executed']:
            need(retained['reason'] == declaration['reason'], 'unexecuted reason differs')
            continue
        native_body = original_bodies[str(exporter.NATIVE_PATHS[stage])]
        check_original_pin(native_body, declaration['native_terminal'])
        check_original_pin(native_body, retained['native_terminal'])
        original_native = json.loads(native_body)
        native_summary = exporter.validate_terminal(original_native, declaration['job_id'])
        need(retained['native_outcome'] == native_summary and retained['job_id'] == declaration['job_id'],
             'original native outcome was changed in export')
        recovered.update(native_outcome=native_summary, original_report_finished=False,
                         original_report_schema_matches=False)
        if declaration['report'] is not None:
            original_body = original_bodies[str(exporter.REPORT_PATHS[stage])]
            check_original_pin(original_body, declaration['report'])
            check_original_pin(original_body, retained['report'])
            try:
                original_report = json.loads(original_body)
            except (ValueError, UnicodeError):
                need('original_report_parse_error' in retained and retained['original_report_finished'] is False,
                     'incomplete original JSON was promoted')
            else:
                recovered.update(original_result=exporter.original_report_projection(original_report),
                    original_report_finished=isinstance(original_report, dict) and bool(original_report.get('finished_utc')),
                    original_report_schema_matches=isinstance(original_report, dict)
                        and original_report.get('schema') == exporter.REPORT_SCHEMAS[stage])
                need(retained['original_result'] == recovered['original_result'],
                     'original false/incomplete/report flags were changed')
        for key in ('original_report_finished', 'original_report_schema_matches'):
            need(retained[key] is recovered[key], 'original report completion or schema was promoted')
    need(report['candidate_disposition'] == exporter.disposition(recovered_stages, report['monitor_evidence']),
         'exporter disposition differs from retained original outcomes and monitor verification')
    for row in local_inputs:
        need(basic_read(row['local_path'])[0] == row, 'local verifier input changed')
    for item in captures.values():
        need(helper.read(item['archive']['source_path'])[0] == item['archive'], 'archive changed across final checks')
    receipt = {'schema': 'hepta-r26-independent-downloaded-archive-verification/v1', 'passed': True,
               'original_exporter_passed': report['passed'], 'original_candidate_disposition': report['candidate_disposition'],
               'archives': captures, 'source_inputs': local_inputs, 'original_outcomes_preserved': True,
               'native_operation_streams_verified_here': False, 'mac_holder_packages_verified_here': False,
               'native_and_mac_companions_still_required': True, 'adoption_decision_made_here': False,
               'archives_extracted': False, 'archive_code_executed': False, 'remote_actions': 0}
    helper.create(args.out, helper.encode(receipt))
    print(json.dumps({'passed': True, 'receipt': str(args.out), 'original_exporter_passed': report['passed'],
                      'native_and_mac_companions_still_required': True}), flush=True)


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    main()
