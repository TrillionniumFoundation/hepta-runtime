#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Export the actual failed R23 campaign without changing its error, outputs or qualification."""
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import traceback

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r23')
BASELINE = Path('/home/qian/hepta-runtime-optimization-20261105-r22')
RECOVERY = Path('/home/qian/hepta-runtime-optimization-20261104-r16/r23-cancel-recovery-01')
CLOSURE = ROOT / 'campaign-01/terminal-closure-01'
CLOSURE_PRIVATE_PATHS = {
    CLOSURE / 'profile/profile.json',
    CLOSURE / 'profile/ssh_config',
    CLOSURE / 'profile/known_hosts',
    CLOSURE / 'bin/ssh',
}
OUT = ROOT / 'evidence-failed-export-01'
EXPECTED_TERMINAL_INPUTS = {
    'qualification-01/report.json': {
        'bytes': 83360,
        'sha256': 'c9c78be4c93d2f9246a317d27f7a616431f31157a05b8cc46d9dc1cf86c848d7',
    },
    'campaign-01/report.json': {
        'bytes': 84778,
        'sha256': '44b74c25cc429ccbb125b88a65778ef2030fe4fa742d17a63994f4f4ec48dfa8',
    },
}
BASELINE_INPUTS = {
    BASELINE / 'qualification-01/report.json',
    BASELINE / 'qualification-01/hepta-runtime',
    BASELINE / 'qualification-01/hepta-runtime-jobctl',
    BASELINE / 'qualification-01/native_process_driver',
    BASELINE / 'campaign-01/report.json',
    BASELINE / 'campaign-01/summary.json',
    BASELINE / 'final-publication-readback.json',
}
MAX_FILE_BYTES = 1024 * 1024 * 1024


def stamp(value):
    return {k: getattr(value, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
                                         'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def read(path, retain=False):
    assert path.is_absolute() and path.resolve() == path, str(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode)
        assert before.st_uid == os.geteuid() or (path == Path('/usr/bin/ssh') and before.st_uid == 0)
        assert not before.st_mode & (stat.S_ISUID | stat.S_ISGID)
        assert 0 <= before.st_size <= MAX_FILE_BYTES, 'file size outside export bound: ' + str(path)
        digest, size, blocks, header = hashlib.sha256(), 0, [], b''
        while block := os.read(fd, 1024 * 1024):
            size += len(block)
            assert size <= before.st_size
            digest.update(block)
            if not header:
                header = block[:4]
            if retain:
                blocks.append(block)
        assert size == before.st_size
        assert stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
        return {'source_path': str(path), 'bytes': size, 'sha256': digest.hexdigest(),
                'original_identity': stamp(before), 'is_elf': header == b'\x7fELF'}, b''.join(blocks)
    finally:
        os.close(fd)


def listing(root):
    assert root.resolve() == root and stat.S_ISDIR(root.lstat().st_mode), str(root)

    def fail(error):
        raise error

    files, directories = [], []
    for current, dirs, names in os.walk(root, followlinks=False, onerror=fail):
        directory = Path(current)
        assert not directory.is_symlink() and directory.resolve() == directory
        directories.append(str(directory))
        for name in sorted(dirs):
            assert not (directory / name).is_symlink()
        for name in sorted(names):
            path = directory / name
            assert stat.S_ISREG(path.lstat().st_mode), str(path)
            files.append(path)
    return sorted(files), sorted(directories)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def output_state(path):
    assert path.is_absolute() and path.resolve() == path, str(path)
    assert path.is_relative_to(ROOT / 'campaign-01') or path.is_relative_to(RECOVERY), str(path)
    present = os.path.lexists(path)
    return {'path': str(path), 'exists': present, 'identity': read(path)[0] if present else None}


def main():
    terminal_inputs = {}
    reports = []
    for relative in ('qualification-01/report.json', 'campaign-01/report.json'):
        identity, raw = read(ROOT / relative, retain=True)
        expected = EXPECTED_TERMINAL_INPUTS[relative]
        assert identity['bytes'] == expected['bytes'] and identity['sha256'] == expected['sha256'], relative
        terminal_inputs[relative] = identity
        reports.append(json.loads(raw))
    qualification, campaign = reports
    assert qualification['qualified'] is True and qualification.get('finished_utc')
    assert campaign['schema'] == 'hepta-r23-campaign-control/v1'
    assert campaign.get('finished_utc') and campaign['passed'] is False
    assert campaign['adoption_passed'] is False
    assert isinstance(campaign.get('error'), dict) and campaign['error'].get('type') and campaign['error'].get('reason')
    assert qualification['source_tested'] == qualification['source_after']
    # Only the original terminal outputs are verified here. No workload, audit,
    # summary, repair or cleanup command is run by this exporter.
    terminal_outputs = {}
    for stage in campaign['stages']:
        assert stage.get('finished_utc')
        for binding in [stage.get('stdout'), stage.get('stderr')] + stage.get('output_bindings', []):
            if binding is None:
                continue
            path = Path(binding['path'])
            state = output_state(path)
            assert state['exists'], str(path)
            actual = state['identity']
            assert actual['bytes'] == binding['bytes'] and actual['sha256'] == binding['sha256'], str(path)
            assert str(path) not in terminal_outputs or terminal_outputs[str(path)] == actual
            terminal_outputs[str(path)] = actual
    planned_paths = sorted({Path(path) for stage in campaign['stage_plan'] for path in stage['outputs']})
    planned_output_states = {str(path): output_state(path) for path in planned_paths}
    summary_path = ROOT / 'campaign-01/summary.json'
    assert str(summary_path) in planned_output_states
    assert planned_output_states[str(summary_path)]['exists'] is False, 'failed campaign has an unexpected summary file'
    failure_stages = [{key: stage[key] for key in ('name', 'passed', 'returncode', 'error', 'independent_controller_cleanup')
                       if key in stage} for stage in campaign['stages'] if stage.get('passed') is False]
    assert failure_stages, 'terminal campaign does not retain a failed stage'
    OUT.mkdir(mode=0o700)
    groups = {
        'qualification': [('qualification', ROOT / 'qualification-01')],
        'campaign': [('campaign', ROOT / 'campaign-01'), ('recovery', RECOVERY),
                     ('campaign-tools', ROOT / 'campaign-tools'), ('boundary-tools', ROOT / 'boundary-tools')],
    }
    report = {'schema': 'hepta-r23-failed-evidence-export/v1', 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'qualified': True, 'campaign_passed': False, 'candidate_adopted': False,
              'failure_evidence_only': True, 'campaign_error': campaign['error'], 'failed_stages': failure_stages,
              'planned_output_states': planned_output_states, 'terminal_output_identities': terminal_outputs,
              'summary_generated': False, 'cleanup_executed': False,
              'cleanup_scope': 'Existing lifecycle/campaign raw files and receipts are retained. Original cleanup uncertainty is not rewritten.',
              'terminal_closure_private_bodies_omitted': sorted(path.relative_to(CLOSURE).as_posix() for path in CLOSURE_PRIVATE_PATHS),
              'no_workload_executed': True, 'archives': {}, 'passed': False, 'attempt': 1,
              'qualified_source_files': len(qualification['source_after']),
              'terminal_inputs': terminal_inputs,
              'exporter_identity': read(Path(__file__).resolve())[0]}
    all_inventories, all_identities = {}, {}
    try:
        for group, roots in groups.items():
            files, inventories, omissions = {}, {}, []

            def add(path, name, expected_sha=None, omission=None):
                assert not Path(name).is_absolute() and '..' not in Path(name).parts
                identity, _ = read(path)
                assert expected_sha is None or identity['sha256'] == expected_sha, str(path)
                if identity['is_elf']:
                    omission = 'ELF body omitted; complete actual remote byte identity retained'
                if path.parent.name == 'profile' and path.name in ('ssh_config', 'known_hosts', 'profile.json'):
                    omission = 'private transport configuration body omitted; exact identity retained'
                if ((path.name == 'runtime.json' and (path.is_relative_to(ROOT / 'campaign-01') or path.is_relative_to(RECOVERY)))
                        or path == RECOVERY / 'bin/ssh' or path in CLOSURE_PRIVATE_PATHS):
                    omission = 'fixture transport configuration/session wrapper body omitted; exact identity retained'
                if omission:
                    omissions.append(dict(identity, archive_path=name, omission_reason=omission))
                else:
                    assert name not in files or files[name] == identity
                    files[name] = identity

            for prefix, root in roots:
                paths, dirs = listing(root)
                inventories[str(root)] = {'files': [str(p) for p in paths], 'directories': dirs}
                for path in paths:
                    add(path, prefix + '/' + path.relative_to(root).as_posix())
            if group == 'qualification':
                # Preserve every actually qualified compilation input, including unchanged files.
                for relative, sha in qualification['source_after'].items():
                    add(ROOT / 'source' / relative, 'source/' + relative, sha)
                for path in sorted((ROOT / 'source/tools/x230/20261028').glob('*.py')):
                    add(path, 'qualifier-tools/' + path.name)
            if group == 'campaign':
                for relative in ('campaign-inputs-01.json', 'qualification-compact.json', 'preparation.json',
                                 'measurement-plan.json', 'campaign-inputs-01.example.json'):
                    add(ROOT / relative, 'receipts/' + relative)
                add(Path(__file__).resolve(), 'export-tools/export_r23_failed_evidence_01.py',
                    report['exporter_identity']['sha256'])
                for name in ('prepare_and_qualify_r23.py', 'prepare_campaign_inputs.py'):
                    add(ROOT / 'tools' / name, 'preparation-tools/' + name)
                for i, identity in enumerate(campaign['input_bindings']):
                    path = Path(identity['path'])
                    if path.is_relative_to(ROOT):
                        continue
                    # Fixed campaign inputs were independently bound by its launcher.
                    # Do not follow arbitrary dependency paths from an unverified report.
                    allowed = (path.is_relative_to(Path('/home/qian/hepta-runtime-optimization-20261104-r16'))
                               or path in BASELINE_INPUTS
                               or path.is_relative_to(Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')))
                    if allowed:
                        add(path, f'bound-inputs/{i:03d}-' + path.name, identity['sha256'])
                    else:
                        add(path, f'bound-inputs/{i:03d}-' + path.name, identity['sha256'],
                            'external system/profile input body omitted; exact identity retained')
            manifest = {'schema': 'hepta-r23-archive-manifest/v1', 'group': group, 'files': files,
                        'omitted_bodies': omissions, 'source_trees': inventories,
                        'qualification_report_sha256': read(ROOT / 'qualification-01/report.json')[0]['sha256'],
                        'campaign_report_sha256': read(ROOT / 'campaign-01/report.json')[0]['sha256']}
            raw_manifest = encode(manifest)
            archive = OUT / (group + '-01.tar.gz')
            with archive.open('xb') as destination, gzip.GzipFile(filename='', mode='wb', fileobj=destination, mtime=0, compresslevel=6) as zipped:
                with tarfile.open(fileobj=zipped, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                    item = tarfile.TarInfo('_export-manifest.json')
                    item.size, item.mode, item.mtime = len(raw_manifest), 0o600, 0
                    tar.addfile(item, io.BytesIO(raw_manifest))
                    for name, expected in sorted(files.items()):
                        actual, raw = read(Path(expected['source_path']), retain=True)
                        assert actual == expected, name
                        if name.startswith(('campaign/', 'recovery/')):
                            for marker in (b'-----BEGIN OPENSSH PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                                           b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN DSA PRIVATE KEY-----'):
                                assert marker not in raw, 'private key marker in ' + name
                        item = tarfile.TarInfo(name)
                        item.size, item.mode, item.mtime = len(raw), 0o600, 0
                        tar.addfile(item, io.BytesIO(raw))
            for root, expected in inventories.items():
                paths, dirs = listing(Path(root))
                assert {'files': [str(p) for p in paths], 'directories': dirs} == expected
            for expected in list(files.values()) + omissions:
                actual, _ = read(Path(expected['source_path']))
                assert all(actual[k] == expected[k] for k in actual)
            manifest_path = OUT / (group + '-manifest.json')
            manifest_path.write_bytes(raw_manifest)
            report['archives'][group] = {'archive': read(archive)[0], 'manifest': read(manifest_path)[0],
                                         'payload_files': len(files), 'omitted_bodies': len(omissions),
                                         'source_bytes': sum(r['bytes'] for r in files.values())}
            all_inventories.update(inventories)
            for expected in list(files.values()) + omissions:
                path = expected['source_path']
                actual = {k: expected[k] for k in ('source_path', 'bytes', 'sha256', 'original_identity', 'is_elf')}
                assert path not in all_identities or all_identities[path] == actual
                all_identities[path] = actual
        for root, expected in all_inventories.items():
            paths, dirs = listing(Path(root))
            assert {'files': [str(p) for p in paths], 'directories': dirs} == expected
        for path, expected in all_identities.items():
            assert read(Path(path))[0] == expected, 'input changed across archives: ' + path
        for relative, expected in terminal_inputs.items():
            assert read(ROOT / relative)[0] == expected, 'terminal input changed: ' + relative
        for path, expected in terminal_outputs.items():
            assert read(Path(path))[0] == expected, 'original terminal output changed: ' + path
        for path, expected in planned_output_states.items():
            assert output_state(Path(path)) == expected, 'planned output presence or identity changed: ' + path
        report['terminal_error_and_output_identities_unchanged'] = True
        report['passed'] = True
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        report['error_trace'] = traceback.format_exc()
    finally:
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT / 'report.json').write_bytes(encode(report))
        print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
