#!/usr/bin/env python3
"""Review the one pinned R36 OBS archive using locally trusted frozen auditors.

No archive code is imported or materialized. A data-only memory path adapter
serves the explicit observation allowlist; payload absolute paths are never opened.
"""
import argparse
from collections import Counter
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import posixpath
import stat
import sys
import tarfile

ARCHIVE_SHA = '30ff7e2dae12aa00a0048c9808610a76b17b4a37daa9de32dfab1fea06f2c9c9'
EXPORT_SHA = 'a65780953c78c7cb7482f6565d84b31db4b483e87efddaf8dc353d0e7c6c7c69'
PREFIX = 'r36/campaign-01/native-observation/'
ROUNDS = ('round-0-A', 'round-1-B', 'round-2-B', 'round-3-A')
JOBS = {
    'ai395': '1a16a4035ad-b1270-1', 'mac': '1a16a403e55-b1270-2',
    'main': '1a16a4046ac-b1270-3', 'pocket4': '1a16a40534e-b1270-4',
    'rog': '1a16a405d21-b1270-5', 'x230': '1a16a40671b-b1270-6',
}
TRUSTED = {
    'analyze_native_observation.py': 'cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66',
    'audit_native_evidence.py': 'b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28',
    'allocator_environment_audit.py': '4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727',
    'allocator_environment.py': 'f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525',
}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def canonical(name):
    need(isinstance(name, str) and name and not name.startswith('/')
         and '\\' not in name and '\x00' not in name
         and posixpath.normpath(name) == name
         and all(part not in ('', '.', '..') for part in name.split('/')),
         'noncanonical archive/inventory path')


def load_module(name, path):
    need(name not in sys.modules, 'trusted module name already bound')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--export-report', type=Path, required=True)
    parser.add_argument('--trusted-tools', type=Path, required=True)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    need(not args.out.exists(), 'review output already exists')
    archive_id = identity(args.archive.read_bytes())
    export_raw = args.export_report.read_bytes()
    need(archive_id == {'bytes': 3961240, 'sha256': ARCHIVE_SHA}, 'archive identity differs')
    need(identity(export_raw) == {'bytes': 4989, 'sha256': EXPORT_SHA}, 'export report identity differs')
    export = json.loads(export_raw)
    need(export['archive'] == archive_id and export['package_complete'] is True, 'export is incomplete')

    selected = {PREFIX + name for name in ('report.json', 'independent-summary.json', 'topology.json')}
    for round_name in ROUNDS:
        for phase in ('first', 'restart'):
            for filename in ('resource-samples.jsonl', 'stderr.log', 'transport-responses.index.jsonl',
                             'transport-responses.jsonl'):
                selected.add(PREFIX + round_name + '/' + phase + '/' + filename)
        for job in JOBS.values():
            selected.add(PREFIX + round_name + '/state/jobs/' + job + '.json')
    bindings = {'r36/campaign-01/summary.json', 'r36/campaign-01/report.json'}
    retained = {}
    seen, order, modes = {}, [], set()
    with tarfile.open(args.archive, 'r|xz') as archive:
        for member in archive:
            canonical(member.name)
            need(member.isreg() and not member.issym() and not member.islnk()
                 and member.name not in seen, 'nonregular or duplicate archive member')
            need(member.size <= 32 * 1024**2, 'member exceeds fixed input bound')
            raw = archive.extractfile(member).read()
            pin = identity(raw)
            need(pin['bytes'] == member.size, 'member size differs')
            seen[member.name] = pin
            order.append(member.name)
            modes.add(member.mode)
            if member.name == '_export-manifest.json':
                manifest = json.loads(raw)
                need(pin == export['manifest'], 'manifest identity differs')
            elif member.name in selected or member.name in bindings:
                retained[member.name] = raw
    need(order == ['_export-manifest.json'] + sorted(manifest['payloads']), 'archive order/inventory differs')
    need(len(seen) == 9448 and modes == {0o600}, 'archive member count/modes differ')
    need(set(seen) - {'_export-manifest.json'} == set(manifest['payloads']), 'payload set differs')
    for name, pin in manifest['payloads'].items():
        need(all(seen[name][key] == pin[key] for key in ('bytes', 'sha256')), 'payload identity differs')
    inventory = []
    for scope, value in manifest['scope_inventories'].items():
        need(scope in {'r36', 'recovery'} and value['present'] is True
             and len(value['entries']) == len(set(value['entries'])), 'scope inventory differs')
        for name in value['entries']:
            canonical(name)
            need(name.startswith(scope + '/'), 'inventory scope escape')
            ancestor = posixpath.dirname(name)
            while ancestor:
                need(ancestor in value['directories']
                     and stat.S_ISDIR(value['directories'][ancestor]['st_mode']), 'inventory ancestor missing')
                ancestor = posixpath.dirname(ancestor)
        inventory.extend(value['entries'])
    need(len(inventory) == len(set(inventory))
         and set(inventory) == set(manifest['payloads']) | set(manifest['omissions'])
         and not set(manifest['payloads']) & set(manifest['omissions']), 'inventory/omission reconciliation differs')
    need(selected | bindings == set(retained), 'required OBS member absent')

    trusted = {}
    for name, expected in TRUSTED.items():
        path = args.trusted_tools / name
        need(not path.is_symlink(), 'trusted auditor is a symlink')
        pin = identity(path.read_bytes())
        need(pin['sha256'] == expected and all(pin[key] == manifest['payloads']['r36/lifecycle-tools-01/' + name][key]
             for key in ('bytes', 'sha256')), 'local trusted auditor differs')
        trusted[name] = {**pin, 'executed': name != 'allocator_environment.py',
                         'archive_body_imported': False}

    report = json.loads(retained[PREFIX + 'report.json'])
    need({row['host']: row['job_id'] for row in report['six_originals']} == JOBS, 'six frozen jobs differ')
    need(report['topology']['file'] == 'topology.json', 'topology path differs')
    cpu_bindings, copied_records = [], []
    originals = {row['host']: row for row in report['six_originals']}
    for index, round_ in enumerate(report['rounds']):
        expected_generation = (round_['startup']['pid'], round_['startup']['birth_ticks'])
        for cell in round_['cells']:
            for kind, timed in (('measured', cell), ('warmup', cell['warmup'])):
                timing = timed['raw_timing']
                need(all((timing[key]['pid'], timing[key]['birth_ticks']) == expected_generation
                         for key in ('controller_before', 'controller_after')), 'cell CPU belongs to another controller')
                cpu_bindings.append({'round': index, 'concurrency': cell['concurrency'], 'kind': kind,
                                     'pid': expected_generation[0], 'birth_ticks': expected_generation[1]})
        for key in ('shutdown', 'restart_shutdown'):
            shutdown = round_[key]
            need(shutdown['transport_capture']['raw']['file'] == 'transport-responses.jsonl'
                 and shutdown['transport_capture']['index']['file'] == 'transport-responses.index.jsonl'
                 and shutdown['resources']['trace']['file'] == 'resource-samples.jsonl', 'nonallowlisted trace basename')
        for host, job in JOBS.items():
            name = PREFIX + ROUNDS[index] + '/state/jobs/' + job + '.json'
            pin = identity(retained[name])
            need(pin['sha256'] == originals[host]['record_sha256'], 'frozen local job copy differs')
            copied_records.append({'host': host, 'job_id': job, 'round': index, 'member': name, **pin})

    # Data-only archive path adapter: no filesystem path from a payload is opened.
    class ArchivePath:
        def __init__(self, value):
            self.value = PurePosixPath(str(value))
        @property
        def name(self):
            return self.value.name
        def __str__(self):
            return str(self.value)
        def __truediv__(self, other):
            return ArchivePath(self.value / other)
        def is_symlink(self):
            return False
        def read_bytes(self):
            key = str(self.value)
            need(key in selected and key in retained, 'archive read outside explicit OBS allowlist')
            return retained[key]

    sys.dont_write_bytecode = True
    load_module('allocator_environment_audit', args.trusted_tools / 'allocator_environment_audit.py')
    load_module('audit_native_evidence', args.trusted_tools / 'audit_native_evidence.py')
    analyzer = load_module('analyze_native_observation', args.trusted_tools / 'analyze_native_observation.py')
    analyzer.Path = ArchivePath
    sys.modules['audit_native_evidence'].Path = ArchivePath
    actual = analyzer.analyze(retained[PREFIX + 'report.json'], ArchivePath(PREFIX.removesuffix('/')))
    original_analysis_raw = retained[PREFIX + 'independent-summary.json']
    original_analysis = json.loads(original_analysis_raw)
    need(actual == original_analysis, 'recomputed analysis differs from original')
    serialized = (json.dumps(actual, indent=2) + '\n').encode()
    need(serialized == original_analysis_raw, 'recomputed analysis bytes differ')
    for member, local in ((PREFIX + 'independent-summary.json', 'observation-native-analysis.json'),
                          ('r36/campaign-01/summary.json', 'observation-summary.json'),
                          ('r36/campaign-01/report.json', 'observation-parent.json')):
        need(retained[member] == (args.receipts / local).read_bytes(), 'previously downloaded OBS receipt differs')

    transport = Counter()
    resource_records = 0
    missing = Counter()
    for row in actual['raw_evidence']:
        transport.update(row['transport'])
        for resource in row['resource_traces']:
            resource_records += resource['trace_records_recomputed']
            missing.update(resource['missing_observations'])
    need(actual['measured_calls'] == 2304 and actual['warmup_calls'] == 288
         and actual['preflight_restart_calls'] == 72 and actual['total_calls'] == 2664,
         'OBS call inventory differs')
    need(identity(args.archive.read_bytes()) == archive_id
         and identity(args.export_report.read_bytes()) == identity(export_raw), 'archive/report changed during review')
    result = {
        'schema': 'hepta-r36-raw-observation-review/v1',
        'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'verified': True, 'candidate_accepted': False,
        'archive': archive_id, 'export_report': identity(export_raw),
        'manifest': export['manifest'],
        'archive_checks': {'canonical_regular_members': len(seen), 'payload_hashes_verified': len(manifest['payloads']),
                           'inventory_entries_reconciled': len(inventory), 'omissions': len(manifest['omissions']),
                           'inventory_ancestors_verified': True, 'all_members_checked_before_allowlisted_memory_access': True},
        'archive_data_access': {'in_memory_only': True, 'files_written': 0, 'files': len(selected), 'bytes': sum(len(retained[name]) for name in selected),
                                'members': [{ 'member': name, **identity(retained[name])} for name in sorted(selected)],
                                'archived_scripts_extracted': False},
        'trusted_local_auditors': trusted,
        'native_report': {'member': PREFIX + 'report.json', **identity(retained[PREFIX + 'report.json'])},
        'native_analysis': {'member': PREFIX + 'independent-summary.json', **identity(original_analysis_raw),
                            'full_object_equal': True, 'serialized_bytes_equal': True},
        'previously_downloaded_receipts_identical': ['observation-native-analysis.json', 'observation-summary.json', 'observation-parent.json'],
        'counts': {'measured_calls': actual['measured_calls'], 'warmup_calls': actual['warmup_calls'],
                   'preflight_restart_calls': actual['preflight_restart_calls'], 'total_tool_calls': actual['total_calls'],
                   'failed_calls': actual['failed_calls'], **dict(transport),
                   'resource_trace_records_recomputed': resource_records, 'controller_generations': 8,
                   'raw_cpu_cells_recomputed_and_generation_bound': len(cpu_bindings),
                   'copied_frozen_job_records_verified': len(copied_records)},
        'raw_resource_missing_observations_retained': dict(missing),
        'cell_controller_generation_bindings': cpu_bindings,
        'copied_frozen_job_records': copied_records,
        'recomputed_cases': actual['cases'],
        'raw_evidence_recomputed': actual['raw_evidence'],
        'topology_verification': actual['topology_verification'],
        'allocator_environment_verification': actual['allocator_environment_verification'],
        'binary_sha256_report_bindings': actual['binary_sha256'],
        'scope': 'Native observation only: every raw transport frame, request/DTO/output binding, call latency, cell CPU tick bracket and resource trace recomputed by pinned local auditors; no boundary/canary expansion.',
        'limitations': [
            'Six original job record copies inside all four R36 rounds match original report fingerprints; original paths outside the archive and live remote state were not read.',
            'Decoded process_read stdout/stderr bytes and status fields are verified against the six pinned originals in the native report; no fresh independent remote command was run.',
            'Private profile/runtime/SSH bodies and ELF bodies are omitted; binary identity and environment observation are retained report bindings, not newly hashed ELF or live environment reads.',
            'Topology manifest binds six distinct reported machine groups; no fresh physical-host identity probe was performed.',
            'Sampled process-tree metrics remain incomplete/non-atomic; all original missing/error observations were retained and recomputed.',
            'Boundary and recovery canary retain their original reported pass/hash bindings; this review does not rerun their independent auditors.',
            'This raw review confirms observation evidence, not stable speedup, lifecycle acceptance, saturation capability or global optimality.',
        ],
        'archive_code_executed': False, 'payload_absolute_paths_opened': False,
        'remote_operations': 0, 'workload_runs': 0, 'fixture_runs': 0,
        'source_or_frozen_control_edits': 0,
    }
    with args.out.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'verified': True, 'counts': result['counts'], 'analysis_bytes_equal': True,
                      'review': identity(args.out.read_bytes())}, ensure_ascii=False))


if __name__ == '__main__':
    main()
