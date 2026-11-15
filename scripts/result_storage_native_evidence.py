# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Recheck complete current native streams without executing either owner."""
from pathlib import Path
import gzip
import importlib
import importlib.util
import json
import struct
import sys

from result_storage_registry import encoded, regular, require, sha


def test_module(root, name):
    directory = Path(root) / 'tests/hia_native'
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
    if name == 'result_storage_json_cases':
        # Archive fixtures deliberately select a different ANCHOR in their
        # shared generator. A typed-domain recheck must retain its original
        # source defaults, including after other domains ran in this process.
        spec = importlib.util.spec_from_file_location('_hia_storage_json_cases', directory / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    else:
        module = importlib.import_module(name)
    require(Path(module.__file__).resolve() == (directory / (name + '.py')).resolve(),
        'test helper was imported from a different source tree')
    return module


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def inventory(folder):
    result = {}
    for path in sorted(Path(folder).rglob('*')):
        require(not path.is_symlink(), 'native capture contains a symbolic link')
        if path.is_dir():
            continue
        require(path.is_file(), 'native capture contains a special file')
        result[str(path.relative_to(folder))] = identity(regular(path))
    return result


def frames(path, *, code=False):
    with Path(path).open('rb') as stream:
        while True:
            header = stream.read(16 if code else 8)
            if not header:
                return
            require(len(header) == (16 if code else 8), 'native frame header is truncated')
            status, size = struct.unpack('<2Q', header) if code else (None, struct.unpack('<Q', header)[0])
            require(size <= 64 << 20, 'native frame exceeds its fixed profile')
            raw = stream.read(size)
            require(len(raw) == size, 'native frame payload is truncated')
            yield (status, raw) if code else raw


def exhausted(iterator):
    require(next(iterator, None) is None, 'native stream has unaccounted frames')


def fixture(root, domain, label, name, folder, *, suffix='jsonl', refusal=False):
    helper = test_module(root, 'result_storage_fixture')
    directory = Path(folder) / (name + '.retained')
    receipt = json.loads(regular(directory / 'receipt.json'))
    stem = (label + '/' if label else '') + name
    infix = '.' + suffix if suffix else ''
    old_raw, _, manifest_sha, job = helper.member(domain, stem + '.process.json')
    old = json.loads(old_raw)
    require(receipt.get('schema') == 'hepta.result-storage.retained-input.v1'
        and receipt.get('domain') == domain and receipt.get('profile') == label and receipt.get('name') == name
        and receipt.get('observation_kind') == 'retained-original-fixture'
        and receipt.get('actual_original_executions') == 0 and receipt.get('original_observation_job') == job
        and receipt.get('fixture_manifest_sha256') == manifest_sha
        and receipt.get('historical_receipt_sha256') == sha(old_raw)
        and receipt.get('startup_refusal') is refusal, 'retained reference identity differs')
    streams = {}
    for channel, filename, member_name, field in (
        ('input', 'requests.bin.gz', stem + '.stdin' + infix, 'input_source'),
        ('stdout', 'stdout.bin.gz', stem + '.stdout' + infix, 'output_source'),
        ('stderr', 'stderr.bin.gz', stem + ('.stderr.log' if suffix else '.stderr'), 'error_source')):
        raw, source, _, _ = helper.member(domain, member_name)
        packed = regular(directory / filename)
        require(gzip.decompress(packed) == raw and receipt[field] == source
            and receipt[channel] == {**identity(raw), 'compressed_bytes': len(packed),
                'compressed_sha256': sha(packed)}, 'complete retained reference bytes differ')
        old_channel = 'stdin' if channel == 'input' else channel
        require((old[old_channel + '_bytes'], old[old_channel + '_sha256']) == (len(raw), sha(raw)),
            'historical reference stream receipt differs')
        streams[channel] = raw
    require(old['timed_out'] is False and old['reaped'] is True
        and receipt['cases'] == len(streams['input'].splitlines()), 'historical reference is incomplete')
    if refusal:
        require(old['exit_code'] != 0 and not streams['input'] and not streams['stdout']
            and b'runtime config must declare at least one host' in streams['stderr'], 'startup refusal differs')
    else:
        require(old['exit_code'] == 0 and not streams['stderr']
            and len(streams['input'].splitlines()) == len(streams['stdout'].splitlines()),
            'retained reference is not a complete successful stream')
    return streams, receipt


def simple(root, domain, folder, report):
    module = test_module(root, 'result_' + domain + '_cases')
    rows = list(module.cases())
    observed, receipt = fixture(root, domain, '', 'original', folder, suffix='')
    require(report['retained_reference'] == receipt
        and observed['input'] == b''.join(wire.hex().encode() + b'\n' for _, wire in rows)
        and regular(folder / 'native.stdout') == observed['stdout'], 'complete native/reference corpus differs')
    lines = observed['stdout'].splitlines()
    for ordinal, ((label, wire), line, row) in enumerate(zip(rows, lines, report['cases'], strict=True)):
        status, separator, payload = line.partition(b':')
        require(separator == b':' and len(status) == 8, 'native hexadecimal result frame differs')
        code, raw = int(status, 16), bytes.fromhex(payload.decode())
        require(line == f'{code:08x}:'.encode() + raw.hex().encode()
            and row['ordinal'] == ordinal and row['label'] == label and row['passed'] is True
            and row['input_bytes'] == len(wire) and row['input_sha256'] == sha(wire)
            and row['code'] == code and row['output_bytes'] == len(raw)
            and row['output_sha256'] == sha(raw) and row['expected_sha256'] == sha(line),
            'actual native result row or complete payload differs')
    return {'cases': len(rows), 'reference_requests': len(rows),
        'requests': identity(observed['input']), 'native_output': identity(observed['stdout'])}


def configuration(folder, executable, config, report):
    row = json.loads(regular(folder / 'native-config.process.json'))
    command = [str(executable)] + (['--runtime-config', str(config)] if config else [])
    require(row == report['native_process'] and row['command'] == command
        and row['exit_code'] == 0 and row['reaped'] is True and row['timed_out'] is False
        and row['failed_parent'] is False and row['controller_locks_released'] is True
        and row['timeout_seconds'] == 180 and row['shutdown_timeout_seconds'] == 10,
        'actual configuration process did not finish')
    for name, suffix in (('stdin', 'bin'), ('stdout', 'bin'), ('stderr', 'log')):
        raw = regular(folder / ('native-config.' + name + '.' + suffix))
        require(row[name] == identity(raw) and (name != 'stderr' or not raw), 'configuration process stream differs')
    incoming = frames(folder / 'native-config.stdin.bin')
    outgoing = frames(folder / 'native-config.stdout.bin')
    count = 0
    for wire, reply in zip(incoming, outgoing, strict=True):
        require(len(wire) >= 24 and wire[:8] == b'HRCFGQ01'
            and struct.unpack_from('<Q', wire, 16)[0] == len(wire) - 24
            and len(reply) >= 32 and reply[:8] == b'HRCFGM01'
            and struct.unpack_from('<Q', reply, 24)[0] == len(reply) - 32,
            'configuration full typed stream differs')
        count += 1
        yield wire, reply
    require(count == row['calls'], 'configuration actual request count differs')


def match_child(stream, row):
    wire, reply = next(stream)
    require(row['input_bytes'] == len(wire) and row['input_sha256'] == sha(wire)
        and row['output_bytes'] == row['child_code'] == len(reply) and row['output_sha256'] == sha(reply),
        'configuration child completion is not the retained actual process response')


def profile_domain(root, domain, folder, report, executable):
    cases_module = test_module(root, 'result_safe_dto_cases' if domain == 'safe_dto' else 'result_retention_cases')
    profile_source = test_module(root, 'result_safe_dto_cases')
    owner = test_module(root, 'test_result_' + domain)
    configurations = test_module(root, 'result_storage_fixture').configurations(domain)
    active = [name for name, hosts in profile_source.profiles() if hosts != {}]
    require([row['name'] for row in report['profiles']] == active, 'complete administrator profile domain differs')
    corpus = {};compared = reference_count = 0
    for profile in report['profiles']:
        label = profile['name'];directory = folder / label;hosts = configurations[label]
        config = directory / 'config.json' if hosts is not None else None
        if config:
            require(json.loads(regular(config)) == {'state_dir': str(directory / 'state'), 'hosts': hosts},
                'actual administrator configuration differs')
        summary, summary_receipt = fixture(root, domain, label, 'original-summaries', directory)
        summaries = [json.loads(line) for line in summary['stdout'].splitlines()]
        require(summary['input'] == b'{"op":"summaries"}\n' and len(summaries) == 1,
            'summary reference input differs')
        receipts = [summary_receipt]
        if domain == 'retention':
            probes, probe_receipt = fixture(root, domain, label, 'original-size-probes', directory)
            probe_rows = list(cases_module.size_probes())
            require(probes['input'] == b''.join(owner.encode(row) + b'\n' for row in probe_rows),
                'complete size probe domain differs')
            values = [json.loads(line) for line in probes['stdout'].splitlines()]
            rows = list(cases_module.cases(label, summaries[0], hosts, values));receipts.append(probe_receipt)
            reference_count += len(probe_rows)
        else:
            rows = list(cases_module.cases(summaries[0], hosts))
            aliases = list(hosts or {}) + ['missing', 'shared-target', '', 'a\0', 'a ', 'A', '汉']
            rows.extend({'op': 'platform', 'alias': name} for name in aliases)
        original, original_receipt = fixture(root, domain, label, 'original-cases', directory)
        receipts.append(original_receipt)
        require(original['input'] == b''.join(owner.encode(row) + b'\n' for row in rows)
            and profile['reference_receipts'] == receipts and profile['status'] == 'PASS',
            'profile complete inputs or completion receipt differ')
        expected = [json.loads(line) for line in original['stdout'].splitlines()]
        inputs = frames(directory / 'native-owner.stdin.bin')
        outputs = frames(directory / 'native-owner.stdout.bin', code=domain == 'safe_dto')
        config_stream = configuration(directory, executable, config, profile)
        for ordinal, (row, reference, actual) in enumerate(zip(rows, expected, profile['cases'], strict=True)):
            require(actual['ordinal'] == ordinal and actual['passed'] is True, 'native profile case is incomplete')
            if row['op'] == 'platform':
                wire, reply = next(config_stream);alias = row['alias'].encode()
                require(wire == b'HRCFGQ01' + struct.pack('<2Q', 10, len(alias)) + alias,
                    'platform query was not sent to installed configuration')
                magic, status, diagnostic, size = struct.unpack_from('<8s3Q', reply)
                if status == 0:
                    signature, generation, platform, length = struct.unpack_from('<8s3Q', reply, 32)
                    require(signature == b'HRCFPL01' and generation == 1 and platform < 2
                        and length == len(alias) and reply[64:] == alias and diagnostic == 0,
                        'installed platform projection differs')
                    value = {'status': 0, 'alias': row['alias'], 'platform': ('linux', 'macos')[platform]}
                else:
                    require(status == 1, 'unknown configuration failure kind')
                    value = {'status': 1, 'error': reply[32:].decode()}
                require(value == reference == actual['actual'] == actual['expected'], 'actual platform result differs')
                continue
            body = reference['canonical_body'].encode()
            wire = owner.query(row['tool'], body) if domain == 'safe_dto' else owner.request(row, body)
            require(next(inputs) == wire and actual['label'] == row['label'] == reference['label']
                and actual['input_bytes'] == len(wire) and actual['input_sha256'] == sha(wire),
                'actual complete typed owner input differs')
            if domain == 'safe_dto':
                code, raw = next(outputs)
                require(code == 32 and len(raw) == 32 and raw == b'HRSDR001' + struct.pack('<3Q',
                    int(reference['accepted']), {'host_list': 1, 'effective_config': 2, 'host_health': 3}.get(row['tool'], 0), 0)
                    and actual['actual'] == actual['expected'] == reference['accepted'], 'actual DTO result differs')
                children = [child for child in actual['children'] if child['child'] == 2]
            else:
                raw = next(outputs);code = len(raw)
                record = reference['record_json'].encode();state = owner.STATES.index(reference['state'])
                payload = json.loads(record)['payload_bytes'] or 0
                require(raw == b'HRRTR001' + struct.pack('<3Q', state, len(record), payload) + record
                    and actual['actual_state'] == actual['expected_state'] == reference['state']
                    and actual['actual_record_sha256'] == actual['expected_record_sha256'] == sha(record)
                    and actual['payload_bytes'] == payload and actual['typed_bytes'] == reference['typed_bytes']
                    and actual['preview_bytes'] == reference['preview_bytes'], 'actual retained Record bytes differ')
                children = [child for call in actual['children'] if call['name'] == 'dto'
                    for child in call['nested'] if child['child'] == 2]
            require(actual['native_code'] == code and actual['output_sha256'] == sha(raw),
                'native owner result receipt differs')
            for child in children:
                match_child(config_stream, child)
        exhausted(inputs);exhausted(outputs)
        # The mixed profile includes explicitly reported negative controls after
        # its semantic cases. Their actual configuration traffic remains retained.
        tail = sum(1 for _ in config_stream)
        require(tail == 0 or label == 'mixed', 'unexpected configuration calls after semantic cases')
        compared += len(rows);reference_count += len(rows) + 1
        corpus[label] = {'requests': identity(original['input']), 'reference_output': identity(original['stdout']),
            'native_input': identity(regular(directory / 'native-owner.stdin.bin')),
            'native_output': identity(regular(directory / 'native-owner.stdout.bin'))}
    require(len(report['startup_refusals']) == 1 and report['startup_refusals'][0]['name'] == 'empty'
        and report['startup_refusals'][0]['state_not_created'] is True, 'empty-host startup refusal missing')
    directory = folder / 'empty';refusal = report['startup_refusals'][0]
    _, receipt = fixture(root, domain, 'empty', 'original-startup', directory, refusal=True)
    require(refusal['reference'] == receipt and json.loads(regular(directory / 'config.json')) ==
        {'state_dir': str(directory / 'state'), 'hosts': {}}, 'startup refusal source differs')
    actual = json.loads(regular(directory / 'native-startup.process.json'))
    require(all(actual[key] == value for key, value in refusal['native'].items() if key != 'startup_refusal')
        and actual['command'] == [str(executable), '--runtime-config', str(directory / 'config.json')]
        and actual['exit_code'] != 0 and actual['reaped'] is True and actual['timed_out'] is False
        and not (directory / 'state').exists(), 'actual startup refusal process differs')
    for channel, suffix in (('stdin', 'jsonl'), ('stdout', 'jsonl'), ('stderr', 'log')):
        raw = regular(directory / ('native-startup.' + channel + '.' + suffix))
        require((actual[channel + '_bytes'], actual[channel + '_sha256']) == (len(raw), sha(raw))
            and (b'runtime config must declare at least one host' in raw if channel == 'stderr' else not raw),
            'actual startup refusal full stream differs')
    return {'cases': compared, 'reference_requests': reference_count, 'profiles': corpus}
