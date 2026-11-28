"""Bind actual native request-scope captures before original Rust replay.

Evidence checks execute no replacement semantics and cannot qualify a scheduler,
cache capability owner, production dispatch, or removal of the original runtime.
"""
from __future__ import annotations
import base64
import gzip
import hashlib
import json
import math
from pathlib import Path
import stat
import struct
import sys

from hia_native_build import HEPTA_COMMIT
from hia_native_loader import NativeModule
from hia_native_request_context_build import members
from hia_native_scope_qualification import embedded_images

CONTEXT_FOLDER = 'request-context-rust-oracle'
RESPONSE_FOLDER = 'response-hints-rust-oracle'
TRANSPORT_FOLDER = 'request-context-transport'
CONTEXT_COUNTS = {'native_calls': 6653, 'semantic_rows': 6595, 'frame_refusals': 23,
                  'capacity_refusals': 11, 'state_refusals': 24, 'sessions': 22}
RESPONSE_COUNTS = {'native_calls': 1161, 'original_semantic_cases': 553,
                   'invalid_frame_controls': 139, 'invalid_utf8_controls': 420,
                   'capacity_controls': 13, 'actual_static_elf_processes': 9,
                   'reused_workspace_requests': 36, 'unicode_scalars': 1112064}
TRANSPORT_COUNTS = {'native_context_processes': 6, 'native_response_processes': 1,
                    'context_requests': 61, 'physical_isolation_processes': 2, 'joined_responses': 1}
PROCESS_REQUESTS = {'nested': 19, 'discard': 12, 'refusals': 9,
                    'isolation-0': 7, 'isolation-1': 7, 'join': 7, 'join-response': 0}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate evidence field: ' + key)
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def owned(output, relative):
    name = Path(relative)
    if name.is_absolute() or '..' in name.parts or not name.parts:
        raise ValueError('evidence path is not owned and relative')
    path = output / name
    if path.resolve() != path.absolute() or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('evidence path is not a regular unsymlinked file')
    return path


def completed_suite(root, output, report, name, completed):
    """Keep invocation, deadline and complete byte receipts bound to this suite."""
    rows = [row for row in report['checks'] if row.get('name') == name]
    if len(rows) != 1:
        raise ValueError('exactly one completed request-context suite is required')
    row = rows[0]
    if (type(row.get('exit_code')) is not int or row['exit_code'] != 0
            or row.get('timed_out') is not False or row.get('start_error')
            or type(row.get('timeout_seconds')) is not int or row['timeout_seconds'] != 180
            or row.get('command') != [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / name)]
            or type(row.get('elapsed_seconds')) not in (int, float)
            or not math.isfinite(row['elapsed_seconds']) or row['elapsed_seconds'] < 0):
        raise ValueError('request-context suite invocation or completion differs')
    for suffix in ('stdout', 'stderr'):
        raw = owned(output, name + '.' + suffix).read_bytes()
        if (type(row.get(suffix + '_bytes')) is not int
                or row[suffix + '_bytes'] != len(raw)
                or row.get(suffix + '_sha256') != sha(raw)):
            raise ValueError('request-context suite raw byte receipt differs')
    return completed(output, report, name)


def native_evidence(root: Path, output: Path, report: dict, completed) -> dict:
    artifacts = {}

    def retain(relative):
        path = owned(output, relative)
        raw = path.read_bytes()
        artifacts[relative] = sha(raw)
        return raw

    def module(relative, expected_source, manifest_hash=None):
        raw = retain(relative)
        if manifest_hash is not None and sha(raw) != manifest_hash:
            raise ValueError('native module manifest changed')
        path = owned(output, relative)
        meta = decode(raw)
        if (meta['compiler_commit'] != HEPTA_COMMIT
                or meta['compiler_sha256'] != report['compiler_image_sha256']
                or meta['source_sha256'] != sha((root / expected_source).read_bytes())):
            raise ValueError('native source or compiler differs')
        admitted = NativeModule(path, manifest_sha256=sha(raw))
        admitted.close()
        parent = Path(relative).parent
        for field in ('source', 'image'):
            content = retain((parent / meta[field]).as_posix())
            if sha(content) != meta[field + '_sha256']:
                raise ValueError('native ' + field + ' bytes differ')
        if meta.get('standalone'):
            elf = retain((parent / meta['standalone']['path']).as_posix())
            if sha(elf) != meta['standalone']['sha256']:
                raise ValueError('standalone native executable differs')
            if (meta['standalone'].get('runtime_libc_required') is not False
                    or meta['standalone'].get('runtime_python_required') is not False):
                raise ValueError('unexpected foreign runtime dependency')
        return meta

    summaries = {}
    for key, name, folder, summary_name, schema, groups, count_field, counts, skip in (
        ('request_context', 'test_request_context.py', CONTEXT_FOLDER, 'summary.json',
         'hepta.runtime.request-context-native-test.v1', 14, 'tests_run', CONTEXT_COUNTS, 'skipped'),
        ('response_hints', 'test_response_hints.py', RESPONSE_FOLDER, 'native-corpus.json',
         'hepta.runtime.response-hints-native-tests.v1', 8, 'test_groups', RESPONSE_COUNTS, 'skips'),
    ):
        _, summary = completed_suite(root, output, report, name, completed)
        if (summary.get('schema') != schema or summary.get('status') != 'PASS'
                or type(summary.get(count_field)) is not int or summary[count_field] != groups
                or any(type(summary.get(f)) is not int or summary[f] != 0 for f in ('errors', 'failures', skip))
                or summary.get('counts') != counts):
            raise ValueError('native request-context coverage differs: ' + name)
        stored = decode(retain(folder + '/' + summary_name))
        if stored != summary:
            raise ValueError('native corpus summary differs from actual stdout')
        entry = report['modules'][key]
        if summary['manifest_sha256'] != entry['sha256']:
            raise ValueError('native corpus manifest differs')
        meta = module(entry['manifest'], 'native/' + key + '.hepta', entry['sha256'])
        if summary['source_sha256'] != meta['source_sha256']:
            raise ValueError('native corpus source differs')
        summaries[key] = summary
        for suffix in ('stdout', 'stderr'):
            retain(name + '.' + suffix)

    context = summaries['request_context']
    if (context.get('native_scheduler_qualified') is not False
            or context.get('original_rust_execution') is not False
            or context.get('source_root') != str(root)):
        raise ValueError('unqualified native context or original-reference claim')
    event_data = retain(CONTEXT_FOLDER + '/native-events.jsonl.gz')
    if sha(event_data) != context['corpus_sha256']:
        raise ValueError('native context event stream changed')
    plain = gzip.decompress(event_data)
    if not plain.endswith(b'\n'):
        raise ValueError('native context event stream is not complete')
    tallies = {'native_calls': 0, 'semantic_rows': 0, 'frame_refusals': 0,
               'capacity_refusals': 0, 'state_refusals': 0}
    sessions = set()
    for line in plain.splitlines():
        row = decode(line)
        tallies['native_calls'] += 1
        if type(row['ordinal']) is not int or row['ordinal'] != tallies['native_calls']:
            raise ValueError('native event ordering or completeness differs')
        if type(row['session']) is not int or not 1 <= row['session'] <= CONTEXT_COUNTS['sessions']:
            raise ValueError('private native session inventory differs')
        sessions.add(row['session'])
        request = base64.b64decode(row['input_base64'], validate=True)
        if row['classification'] == 'independent-model-native-state':
            actual = base64.b64decode(row['output_base64'], validate=True)
            if (sha(request) != row['input_sha256'] or sha(actual) != row['output_sha256']
                    or len(request) < 32 or request[:8] != b'HRCXQ001'
                    or struct.unpack_from('<Q', request, 8)[0] != row['operation']
                    or len(actual) < 32 or actual[:8] != b'HRCXR001'
                    or struct.unpack_from('<Q', actual, 24)[0] != len(actual) - 32):
                raise ValueError('native event complete input/output bytes differ')
            tallies['semantic_rows'] += 1
        elif row['classification'] == 'native-boundary-refusal':
            refusal = {0xffffffff: 'frame_refusals', 0xfffffffe: 'capacity_refusals', 0xfffffffd: 'state_refusals'}
            code = row['actual_code']
            if type(code) is not int or code not in refusal or row['expected_code'] != code:
                raise ValueError('native boundary refusal differs')
            tallies[refusal[code]] += 1
        else:
            raise ValueError('unknown native context event classification')
    if ({**tallies, 'sessions': len(sessions)} != CONTEXT_COUNTS
            or sessions != set(range(1, CONTEXT_COUNTS['sessions'] + 1))):
        raise ValueError('complete native context event counts differ')

    response = summaries['response_hints']
    if any(response.get(field) is not False for field in (
            'production_activated', 'whole_runtime_replaced', 'rust_oracle_executed_by_this_suite')):
        raise ValueError('unqualified response runtime or original-reference claim')
    for filename, is_output in (('input.bin.gz', False), ('native-output.bin.gz', True)):
        raw = retain(RESPONSE_FOLDER + '/' + filename)
        blob = gzip.decompress(raw)
        expected = response['corpus'][filename]
        if expected != {'bytes': len(raw), 'sha256': sha(raw), 'raw_bytes': len(blob), 'raw_sha256': sha(blob)}:
            raise ValueError('complete native response corpus changed')
        offset, rows = 0, 0
        while offset < len(blob):
            if len(blob) - offset < 16:
                raise ValueError('truncated response corpus header')
            first, second = struct.unpack_from('<QQ', blob, offset)
            size = second if is_output else first
            offset += 16
            if size > len(blob) - offset or (is_output and first != second):
                raise ValueError('truncated response corpus result')
            offset += size
            rows += 1
        if rows != RESPONSE_COUNTS['original_semantic_cases']:
            raise ValueError('complete response reference row count differs')
    elf_rows = response['real_elf_processes']
    if len(elf_rows) != 9 or [r['exit_code'] for r in elf_rows] != [0] * 6 + [2, 2, 3]:
        raise ValueError('response actual static executable cases differ')

    _, transport = completed_suite(root, output, report, 'test_request_context_transport.py', completed)
    if (transport.get('schema') != 'hepta.runtime.request-context-transport.v1'
            or transport.get('status') != 'PASS' or transport.get('test_groups') != 5
            or any(type(transport.get(k)) is not int or transport[k] != 0
                   for k in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
            or transport.get('counts') != TRANSPORT_COUNTS
            or transport.get('test_sha256') != sha((root / 'tests/hia_native/test_request_context_transport.py').read_bytes())
            or transport.get('whole_runtime_replaced') is not False
            or transport.get('production_scheduler_replaced') is not False):
        raise ValueError('actual native context transport coverage differs')
    if decode(retain(TRANSPORT_FOLDER + '/transport.json')) != transport:
        raise ValueError('native transport report differs from actual stdout')
    if set(transport['processes']) != set(PROCESS_REQUESTS):
        raise ValueError('native process inventory differs')
    capture_root = None
    response_manifest = decode(retain(report['modules']['response_hints']['manifest']))
    context_manifest = decode(retain(report['request_context_composition']['manifest']))
    for name, requests in PROCESS_REQUESTS.items():
        row = transport['processes'][name]
        if (type(row['context_requests']) is not int or row['context_requests'] != requests
                or type(row['exit_code']) is not int or row['exit_code'] != 0):
            raise ValueError('native process did not complete its exact request set')
        if name == 'join-response':
            relative = Path(report['modules']['response_hints']['manifest']).parent / response_manifest['standalone']['path']
            arguments = []
        else:
            relative = Path(report['request_context_composition']['manifest']).parent / context_manifest['executable']
            arguments = ['--local-read-profile', '/request-context-fixture']
        command = row.get('command')
        if not isinstance(command, list) or len(command) != len(arguments) + 1 or command[1:] != arguments:
            raise ValueError('native process invocation differs')
        executable = Path(command[0])
        if (not executable.is_absolute() or '..' in executable.parts
                or executable.parts[-len(relative.parts):] != relative.parts):
            raise ValueError('native process did not invoke the admitted executable')
        # Retained captures may be copied. Bind all invocations to the same
        # original absolute capture root without accessing that old location.
        original_root = executable.parents[len(relative.parts) - 1]
        if capture_root is None:
            capture_root = original_root
        if original_root != capture_root:
            raise ValueError('native process executable roots differ')
        for suffix in ('input', 'stdout', 'stderr'):
            raw = retain(TRANSPORT_FOLDER + '/' + name + '.' + suffix)
            if row['streams'][suffix] != {'bytes': len(raw), 'sha256': sha(raw)}:
                raise ValueError('actual native process raw stream changed')
            if requests and suffix in ('input', 'stdout') and len(raw.splitlines()) != requests:
                raise ValueError('actual persistent process request/response framing differs')
            if suffix == 'stderr' and raw:
                raise ValueError('actual native process stderr is not empty')
    for suffix in ('stdout', 'stderr'):
        retain('test_request_context_transport.py.' + suffix)

    composition = report['request_context_composition']
    raw = retain(composition['manifest'])
    meta = decode(raw)
    if sha(raw) != composition['sha256'] or meta['compiler_commit'] != HEPTA_COMMIT:
        raise ValueError('native context composition identity differs')
    parent = Path(composition['manifest']).parent
    expected = [{'id': i, 'name': spec.name, 'flags': spec.flags, 'call_mask': spec.call_mask,
                 'input_capacity': spec.input_capacity, 'output_capacity': spec.output_capacity,
                 'workspace_capacity': spec.workspace_capacity, 'source_sha256': sha(spec.source.read_bytes())}
                for i, spec in enumerate(members(root))]
    if meta['profile'] != expected or len(meta['members']) != 2:
        raise ValueError('native context composition image table differs')
    images = []
    sources = ['tests/hia_native/view_cache_hex_transport.hepta', 'native/request_context.hepta']
    for index, row in enumerate(meta['members']):
        if row['manifest'] != f'module_{index:02d}.json':
            raise ValueError('context child manifest differs')
        relative = (parent / row['manifest']).as_posix()
        child = module(relative, sources[index], row['manifest_sha256'])
        image = retain((parent / child['image']).as_posix())
        if sha(image) != row['image_sha256']:
            raise ValueError('context child code identity differs')
        images.append(image)
    module((parent / meta['packer']['manifest']).as_posix(), 'native/composition_packer.hepta',
           meta['packer']['manifest_sha256'])
    elf = retain((parent / meta['executable']).as_posix())
    binding = {'manifest_sha256': sha(raw), 'executable_sha256': sha(elf), 'profile': expected,
               'embedded_images': embedded_images(elf, expected, images)}
    if sha(elf) != meta['executable_sha256'] or binding != transport['composition']:
        raise ValueError('actual context ELF image binding differs')
    if any(meta.get(k) is not False for k in ('runtime_libc_required', 'runtime_python_required', 'whole_runtime_replaced')):
        raise ValueError('unqualified native runtime claim')
    return {'status': 'PASS', 'context_counts': CONTEXT_COUNTS, 'response_counts': RESPONSE_COUNTS,
            'transport_counts': TRANSPORT_COUNTS, 'artifact_sha256': artifacts,
            'native_cases_added_by_replay': 0, 'production_scheduler_qualified': False,
            'unbounded_storage_qualified': False, 'production_call_sites_replaced': False}


def qualification_evidence(root, output, report, completed):
    result = native_evidence(root, output, report, completed)
    _, controls = completed_suite(root, output, report, 'test_request_context_evidence.py', completed)
    if (controls.get('status') != 'PASS' or controls.get('test_groups') != 8
            or type(controls.get('controls')) is not int or controls['controls'] != 55
            or len(set(controls.get('control_names', []))) != 55
            or any(type(controls.get(key)) is not int or controls[key] != 0 for key in (
                'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes', 'native_cases_added_by_replay'))
            or controls.get('test_sha256') != sha((root / 'tests/hia_native/test_request_context_evidence.py').read_bytes())):
        raise ValueError('request context evidence controls did not complete')
    result['evidence_controls'] = controls
    for suffix in ('stdout', 'stderr'):
        relative = 'test_request_context_evidence.py.' + suffix
        result['artifact_sha256'][relative] = sha(owned(output, relative).read_bytes())
    return result
