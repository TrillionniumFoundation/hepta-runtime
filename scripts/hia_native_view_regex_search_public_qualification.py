"""Admit complete public regex-search wire evidence, then share one Rust replay.

Native execution belongs to test_view_regex_search_public.py. This reader performs
no native or Rust execution and never reads a live fixture. Recorded absolute
paths identify the execution; source and artifacts are read only from the
explicit current roots, so copied/retired evidence remains verifiable.
The existing MCP composition reader owns the fixed image graph and compiler
receipts. Its functions are reused without changing process records.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import struct
import sys

import hia_native_runtime_mcp_evidence as mcp

NATIVE_SUITE = 'test_view_regex_search_public.py'
GENERATOR = 'tests/hia_native/view_regex_search_oracle/cases.py'
PRIVATE_SOURCES = ('tests/hia_native/test_view_regex_search_public.py',
                   'tests/hia_native/test_runtime_mcp.py', GENERATOR)
READER = 'scripts/hia_native_view_regex_search_public_qualification.py'
EXPECTED_INPUT = dict(bytes=47423473, sha256='68c70b6a0cccdd157d29607562805db651293a969ea68c6d728f1016e47227da')
PATH_CONTROLS = frozenset((30043, 30044, 30045, 30046))
FALSE_FLAGS = ('original_mcp_router_executed', 'all_public_bodies_same_original_resolution_context',
               'fixture_hooks_used', 'whole_view_replaced', 'whole_runtime_replaced',
               'complete_sdk_frontend', 'response_storage_globally_unbounded')
require, exact, decode, compact, sha = mcp.require, mcp.exact, mcp.decode, mcp.compact, mcp.sha


def absolute(value, name):
    require(type(value) is str and Path(value).is_absolute()
            and '..' not in Path(value).parts and str(Path(value)) == value,
            name + ' is not a canonical retained absolute path')
    return Path(value)


def relative(value, name):
    require(type(value) is str and value and not Path(value).is_absolute()
            and '..' not in Path(value).parts and str(Path(value)) == value,
            name + ' is not an owned relative path')
    return value


def module(root, name, identity):
    path = mcp.owned(root, name)
    spec = importlib.util.spec_from_file_location(identity, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def identity(path):
    digest = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
            count += len(block)
    return dict(bytes=count, sha256=digest.hexdigest())


def sources(root, binding):
    result = {name: value['sha256'] for name, value in binding['files'].items()}
    names = (*PRIVATE_SOURCES, READER, 'scripts/hia_native_runtime_mcp_evidence.py',
             'scripts/hia_native_view_regex_search_reference.py',
             'tests/hia_native/view_call_oracle/sdk_cases.py', 'native/runtime_mcp_sources.json')
    for name in names:
        result[name] = sha(mcp.owned(root, name).read_bytes())
    return dict(sorted(result.items()))


def suite(evidence, report, completed, name, origin_root, expected, *, groups=None):
    rows = [row for row in report.get('checks', []) if row.get('name') == name]
    require(len(rows) == 1, 'one complete actual suite receipt required: ' + name)
    row = rows[0]
    exact(row.get('command'), [sys.executable, '-I', '-B', str(origin_root / 'tests/hia_native' / name)],
          'actual isolated suite command differs')
    require(type(row.get('exit_code')) is int and row['exit_code'] == 0
            and row.get('timed_out') is False and not row.get('start_error')
            and type(row.get('timeout_seconds')) is int and row['timeout_seconds'] == 180
            and mcp.finite(row.get('elapsed_seconds'), 180), 'suite failed or deadline differs')
    directory = report.get('check_artifact_directories', {}).get(name, '')
    prefix = relative(directory, 'suite artifact directory') + '/' if directory else ''
    streams = {suffix: evidence.read(prefix + name + '.' + suffix) for suffix in ('stdout', 'stderr')}
    for suffix, raw in streams.items():
        exact(dict(bytes=row.get(suffix + '_bytes'), sha256=row.get(suffix + '_sha256')),
              dict(bytes=len(raw), sha256=sha(raw)), 'complete suite stream differs')
    summary = decode(streams['stdout'])
    exact(summary, row.get('summary'), 'suite summary differs from actual stdout')
    exact(summary, expected, 'suite stdout differs from complete capture')
    if completed is not None:
        exact(list(completed(evidence.output, report, name)), [row, summary],
              'completed callback selected different evidence')
    if groups is None:
        exact(streams['stderr'], b'', 'public producer emitted diagnostic')
    else:
        stderr = streams['stderr'].decode()
        require(len(re.findall(r'\.\.\. ok\n', stderr)) == groups
                and re.search(r'\nRan ' + str(groups) + r' tests in [0-9.]+s\n\nOK\n\Z', stderr),
                'common MCP native groups did not all execute')
    return row


def selected(meta):
    return not meta['hooks'] and meta['context'] and not meta['cancel_after_render'] and not meta['raw_path']


def origin(record, folder):
    value = record.get('execution')
    exact(sorted(value), ['capture_root', 'fixture_root', 'manifest_path', 'runtime_root'],
          'public execution origin fields')
    paths = {name: absolute(path, name) for name, path in value.items()}
    require(paths['capture_root'].name == Path(folder).name, 'capture basename differs')
    require(paths['fixture_root'] == paths['capture_root'].parent / 'runtime-mcp/files/regex-search',
            'public fixture escaped shared runtime owner')
    require(paths['manifest_path'].is_relative_to(paths['capture_root'].parent),
            'executed manifest escaped output owner')
    return paths


def inspect_corpus(root, corpus, evidence=None):
    root, corpus = Path(root), Path(corpus)
    evidence = mcp.Evidence(corpus.parent) if evidence is None else evidence
    folder = str(corpus.relative_to(evidence.output))
    relative(folder, 'public corpus')
    report = evidence.object(folder + '/result.json')
    binding = mcp.source_identity(root)
    exact(report.get('source_binding'), binding, 'public executed source closure changed')
    expected = dict(schema='hepta.runtime.view-regex-search-public-native.v1', status='PASS', groups=1,
                    failures=0, errors=0, skipped=0, cases=518, actual_elf_processes=508,
                    actual_elf_responses=772, designated_original_body_cases=510,
                    original_body_comparisons_executed=0, original_reference_status='NOT_RUN',
                    public_resolved_path_controls=8, new_rust_processes=0)
    for name, value in expected.items():
        exact(report.get(name), value, 'public report ' + name)
    for flag in FALSE_FLAGS:
        exact(report.get(flag), False, 'unqualified public claim: ' + flag)
    require(mcp.finite(report.get('elapsed_seconds'), 180), 'public elapsed time differs')
    exact(report.get('independent_input'), EXPECTED_INPUT, 'public logical input identity')
    exact(decode(evidence.read(folder + '/failures.json')), [], 'public producer failures')
    paths = origin(report, folder)
    origin_root = paths['runtime_root']
    exact(report.get('manifest'), str(paths['manifest_path']), 'public manifest origin differs')
    private = {str(origin_root / name): identity(mcp.owned(root, name)) for name in PRIVATE_SOURCES}
    exact(report.get('private_test_sources'), private, 'public private source pins differ')

    cases = module(root, GENERATOR, '_public_search_admit_inputs')
    sdk = module(root, 'tests/hia_native/view_call_oracle/sdk_cases.py', '_public_search_admit_sdk')
    rows = evidence.rows(folder + '/public-cases.jsonl')
    processes = report['processes']
    require(type(processes) is list and len(processes) == 508 and len(rows) == 518,
            'public case/process inventory differs')
    row_fields = ('case_id', 'name', 'domain', 'protocol', 'session', 'original_input',
                  'actual_request', 'actual_response', 'actual_body', 'is_error',
                  'private_hooks_used', 'original_mcp_router_executed', 'comparison_domain',
                  'original_body_compared', 'original_body_designated')
    process_fields = ('session', 'command', 'environment', 'timeout_seconds', 'exit_code',
                      'elapsed_seconds', 'stdin', 'stdout', 'stderr')
    row_at = process_at = response_count = 0
    totals = {}
    ordered_ids = None
    current = streams = session = None
    stdin = stdout = None

    def close():
        if streams is not None:
            exact(stdin.read(), b'', 'extra request bytes in actual public stdin')
            exact(stdout.read(), b'', 'extra response bytes in actual public stdout')

    def start(protocol, session_id):
        nonlocal process_at, current, streams, session, stdin, stdout, response_count
        close()
        session = protocol + '-' + str(session_id)
        record = processes[process_at]
        process_at += 1
        exact(sorted(record), sorted(process_fields), 'public process fields differ')
        exact(record['session'], session, 'public process order/identity')
        exact(record['command'], [str(paths['manifest_path'].parent / 'runtime-mcp.elf'),
                                  '--session-root', str(paths['fixture_root'] / session)],
              'public process command/fixture differs')
        exact(record['environment'], {'PATH': '', 'LC_ALL': 'C'}, 'public process environment')
        require(type(record['exit_code']) is int and record['exit_code'] == 0
                and type(record['timeout_seconds']) is int and record['timeout_seconds'] == 60
                and mcp.finite(record['elapsed_seconds'], 180), 'public process failed or deadline differs')
        exact(evidence.object(folder + '/sessions/' + session + '/process.json'), record,
              'public process receipt copy differs')
        streams = {key: evidence.stream(folder, record[key], 'sessions/' + session + '/' + key + '.bin.gz')
                   for key in ('stdin', 'stdout', 'stderr')}
        exact(streams['stderr'], b'', 'production emitted private fixture receipts or diagnostic')
        stdin, stdout = io.BytesIO(streams['stdin']), io.BytesIO(streams['stdout'])
        if protocol == 'legacy':
            exact(stdin.readline(), compact(sdk.initialization({})) + b'\n', 'actual legacy initialization input')
            raw = stdout.readline()
            require(raw.endswith(b'\n'), 'legacy initialization output incomplete')
            response = decode(raw[:-1])
            exact(sorted(response), ['id', 'jsonrpc', 'result'], 'legacy initialization result fields')
            exact(response['id'], 1, 'legacy initialize id')
            exact(response['jsonrpc'], '2.0', 'legacy initialize protocol')
            server = decode(mcp.owned(root, 'native/runtime_server_info.json').read_bytes())
            exact(response['result'], dict(protocolVersion='2025-11-25', **server['initialize']),
                  'legacy initialization complete header')
            response_count += 1
        current = (protocol, session_id)

    for protocol in ('legacy', 'modern'):
        ids = []
        body_bytes = 0
        generated = hashlib.sha256(cases.INPUT_MAGIC + struct.pack('<Q', 271))
        generated_bytes = 16
        for case in cases.iter_cases():
            meta = case['metadata']
            encoded = cases.blob_record(meta, case['blobs'])
            generated.update(encoded)
            generated_bytes += len(encoded)
            del encoded
            if not selected(meta):
                continue
            cid = meta['case_id']
            ids.append(cid)
            row = rows[row_at]
            row_at += 1
            exact(sorted(row), sorted(row_fields), 'public case fields differ')
            for key, value in dict(case_id=cid, name=meta['name'], domain=meta['domain'],
                                   protocol=protocol, session=protocol + '-' + str(meta['session'])).items():
                exact(row[key], value, 'public case ' + key)
            for key in ('private_hooks_used', 'original_mcp_router_executed', 'original_body_compared'):
                exact(row[key], False, 'public scope flag ' + key)
            designated = cid not in PATH_CONTROLS
            exact(row['original_body_designated'], designated, 'public comparison domain flag')
            exact(row['comparison_domain'], 'complete_original_body' if designated else 'public_resolved_path_control',
                  'public comparison domain')
            if current != (protocol, meta['session']):
                start(protocol, meta['session'])
            prefix = 'cases/' + protocol + '-' + str(cid)
            exact(evidence.stream(folder, row['original_input'], prefix + '.input.bin.gz'),
                  cases.encode_cases([case]), 'complete original logical input differs')
            arguments = dict(path=bytes.fromhex(meta['path_hex']).decode(), **meta['params'])
            metadata = {sdk.CAPABILITIES: {}, sdk.PROTOCOL: '2026-07-28'} if protocol == 'modern' else None
            request = compact(sdk.call(cid + 2, arguments, metadata))
            exact(evidence.stream(folder, row['actual_request'], prefix + '.request.bin.gz'),
                  request, 'complete actual request projection')
            exact(stdin.readline(), request + b'\n', 'public request missing from actual process stream')
            raw = evidence.stream(folder, row['actual_response'], prefix + '.response.bin.gz')
            exact(stdout.readline(), raw + b'\n', 'complete actual public response stream differs')
            response_count += 1
            response = decode(raw)
            exact(sorted(response), ['id', 'jsonrpc', 'result'], 'public response fields')
            exact(response['jsonrpc'], '2.0', 'public response protocol')
            exact(response['id'], cid + 2, 'public response id')
            result = response['result']
            exact(sorted(result), sorted(('content', 'isError', 'resultType') if protocol == 'modern'
                                         else ('content', 'isError')), 'public result fields')
            require(type(result['isError']) is bool, 'public result error flag type')
            if protocol == 'modern':
                exact(result['resultType'], 'complete', 'modern result completion')
            content = result['content']
            require(type(content) is list and len(content) == 1 and type(content[0]) is dict,
                    'public text content inventory')
            exact(sorted(content[0]), ['text', 'type'], 'public text fields')
            exact(content[0]['type'], 'text', 'public text type')
            require(type(content[0]['text']) is str, 'public text is not text')
            body = evidence.stream(folder, row['actual_body'], prefix + '.body.bin.gz')
            exact(body, content[0]['text'].encode(), 'complete public body differs from JSON text')
            exact(row['is_error'], result['isError'], 'public error projection')
            if not designated:
                path = bytes.fromhex(meta['path_hex'])
                resolved = os.fsencode(paths['fixture_root'] / session) + b'/' + path
                exact(result['isError'], True, 'public resolved-path control error status')
                exact(body, b'Path not found: ' + path + b' (resolved to ' + resolved + b')',
                      'public resolved-path context bytes')
            body_bytes += len(body)
        exact(dict(bytes=generated_bytes, sha256=generated.hexdigest()), EXPECTED_INPUT,
              'complete independent 271-case input changed')
        require(len(ids) == len(set(ids)) == 259, 'selected public logical input inventory')
        if ordered_ids is None:
            ordered_ids = ids
        else:
            exact(ids, ordered_ids, 'protocol input sets differ')
        totals[protocol] = dict(cases=259, body_bytes=body_bytes, regex_search_cases=258,
                                whole_preparation_cases=1, designated_original_body_cases=255,
                                public_resolved_path_controls=4, original_body_comparisons_executed=0)
    close()
    exact((row_at, process_at, response_count), (518, 508, 772), 'public actual process/response recount')
    exact(report['selected_case_ids'], ordered_ids, 'declared selected input IDs')
    exact(report['protocols'], totals, 'complete public protocol recount')
    exact(mcp.source_identity(root), binding, 'source changed while reading public evidence')
    return dict(report=report, rows=rows, evidence=evidence, origin=paths, source_binding=binding,
                counts=dict(cases=518, regex_search_cases=516, whole_preparation_cases=2,
                            actual_elf_processes=508, actual_elf_responses=772,
                            designated_original_body_cases=510, public_resolved_path_controls=8,
                            protocols=totals))


def public_native_evidence(root, output, report, completed):
    root, output = Path(root), Path(output)
    descriptor = report.get('view_regex_search_public')
    require(type(descriptor) is dict and set(descriptor) == {'manifest', 'corpus'},
            'public search descriptor inventory')
    relative(descriptor['manifest'], 'public manifest')
    folder = relative(descriptor['corpus'], 'public capture')
    require(folder == 'view-regex-search-public', 'public corpus owner differs')
    evidence = mcp.Evidence(output)
    public = inspect_corpus(root, output / folder, evidence)
    origin_root = public['origin']['runtime_root']
    expected = {key: value for key, value in public['report'].items() if key not in ('processes', 'source_binding')}
    suite(evidence, report, completed, NATIVE_SUITE, origin_root, expected)

    # Reuse the existing exact composition and common native evidence checks.
    # Only the outer command is compared with its retained origin root, so
    # relocation does not require editing a receipt or reading an old path.
    common = mcp.inspect_corpus(root, output / mcp.FOLDER, evidence)
    common_origin = absolute(common['report']['execution']['runtime_root'], 'common runtime source root')
    exact(str(common_origin), str(origin_root), 'public and common source execution roots differ')
    exact(str(public['origin']['manifest_path']), common['report']['execution']['manifest_path'],
          'public and common executions used different build paths')
    common_corpus = absolute(common['report']['execution']['corpus_root'], 'common capture root')
    exact(str(public['origin']['capture_root'].parent), str(common_corpus.parent),
          'public and common execution output owners differ')
    suite(evidence, report, completed, mcp.NATIVE_SUITE, common_origin,
          {key: value for key, value in common['report'].items() if key != 'processes'}, groups=8)
    build = mcp.build_evidence(root, output, report, evidence, common['report'])
    exact(descriptor['manifest'], build['manifest'], 'public used a different MCP composition')
    return _native_result(root, output, descriptor, public, build, evidence)


def _native_result(root, output, descriptor, public, build, evidence):
    manifest_record = evidence.artifacts[descriptor['manifest']]
    exact(public['report']['manifest_identity'],
          dict(bytes=manifest_record['bytes'], sha256=manifest_record['sha256']),
          'public executed manifest bytes differ')
    origin_relative = str(public['origin']['manifest_path'].relative_to(public['origin']['capture_root'].parent))
    exact(origin_relative, descriptor['manifest'], 'public original build path differs')
    exact(public['source_binding'], mcp.source_identity(root), 'public final source binding differs')
    return dict(schema='hepta.runtime.view-regex-search-public-native-evidence.v1', status='PASS',
                native_execution_complete=True, original_reference_status='NOT_RUN',
                complete_input_output_buffers_retained=True, original_body_comparisons_executed=0,
                corpus=descriptor['corpus'], manifest=descriptor['manifest'],
                composition=build, source_binding=public['source_binding'], counts=public['counts'],
                independent_input=EXPECTED_INPUT, transient_fixture_directories=['runtime-mcp/files/regex-search'],
                artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
                artifacts=[evidence.artifacts[name] for name in sorted(evidence.artifacts)],
                source_sha256=sources(root, public['source_binding']),
                new_native_calls=0, new_rust_processes=0, native_cases_added_by_replay=0,
                original_mcp_router_executed=False, whole_view_replaced=False, whole_runtime_replaced=False,
                complete_sdk_frontend=False, response_storage_globally_unbounded=False)


def compare_public_reference(root, native_corpus, original_output):
    """Compare 510 complete bodies against the already admitted shared Rust run.

    The caller must first admit the full three-process original bundle using
    hia_native_view_regex_search_reference.reference_evidence. These four files are
    complete shared artifacts, not a second Rust execution or a new reference.
    """
    root, native_corpus, original_output = Path(root), Path(native_corpus), Path(original_output)
    require(native_corpus.parent == original_output.parent, 'public/reference evidence owners differ')
    evidence = mcp.Evidence(native_corpus.parent)
    public = inspect_corpus(root, native_corpus, evidence)
    folder = str(original_output.relative_to(evidence.output))
    relative(folder, 'shared original folder')
    reference = evidence.object(folder + '/result.json')
    exact(reference.get('schema'), 'hepta.runtime.view-regex-search-original-reference.v1', 'shared original schema')
    require(reference.get('status') in ('REFERENCE_READY', 'BYTES_EQUAL_REQUIRES_NATIVE_ADMISSION'),
            'shared original reference was not complete')
    exact(reference.get('harness_unchanged'), True, 'shared original harness changed')
    for flag in ('whole_view_migrated', 'whole_runtime_replaced'):
        exact(reference.get(flag), False, 'unqualified shared original flag')
    receipts = decode(evidence.read(folder + '/process-receipts.json'))
    exact(receipts, reference['processes'], 'shared original process receipt copies')
    require(type(receipts) is list and len(receipts) == 3, 'shared original process inventory')
    exact([row.get('name') for row in receipts], ['rust-version', 'build', 'original'], 'shared original process order')
    for record in receipts:
        require(type(record.get('exit_code')) is int and record['exit_code'] == 0
                and record.get('timed_out') is False and record.get('spawn_error') is None
                and type(record.get('timeout_seconds')) is int and record['timeout_seconds'] == 180
                and mcp.finite(record.get('elapsed_seconds'), 180), 'shared original process did not finish')
    exact(receipts[-1]['stdin'], EXPECTED_INPUT, 'shared Rust input receipt')
    exact(receipts[-1]['stdout'], reference['original_output'], 'shared Rust stdout receipt')
    exact(reference['independent_input'], EXPECTED_INPUT, 'shared original input identity')
    source_pins = sources(root, public['source_binding'])
    for name, expected in reference['harness_inputs'].items():
        path = mcp.owned(root, 'tests/hia_native/view_regex_search_oracle/' + relative(name, 'original harness name'))
        exact(identity(path), expected, 'shared original harness source')
        source_pins[str(path.relative_to(root))] = expected['sha256']
    for name, expected in reference['companion_inputs'].items():
        path = mcp.owned(root, 'tests/hia_native/view_call_oracle/' + relative(name, 'original companion name'))
        exact(identity(path), expected, 'shared original companion source')
        source_pins[str(path.relative_to(root))] = expected['sha256']

    # Hash complete large raw streams without retaining a second memory copy.
    for name, expected in [('input.bin', EXPECTED_INPUT), ('original.stdout', reference['original_output'])]:
        relative_name = folder + '/' + name
        path = mcp.owned(evidence.output, relative_name)
        actual = identity(path)
        exact(actual, expected, 'complete shared original artifact ' + name)
        evidence.artifact_sha256[relative_name] = actual['sha256']
        evidence.artifacts[relative_name] = dict(path=relative_name, **actual)
    cases = module(root, GENERATOR, '_public_search_compare_inputs')
    original = module(root, 'scripts/hia_native_view_regex_search_reference.py', '_public_search_compare_original')
    native_rows = {(row['protocol'], row['case_id']): row for row in public['rows']}
    compared = dict(legacy=0, modern=0)
    byte_counts = dict(legacy=0, modern=0)
    source_counts = None
    with mcp.owned(evidence.output, folder + '/input.bin').open('rb') as inputs, \
            mcp.owned(evidence.output, folder + '/original.stdout').open('rb') as stdout:
        exact(inputs.read(16), cases.INPUT_MAGIC + struct.pack('<Q', 271), 'shared input header')
        outputs = cases.read_records(stdout, cases.OUTPUT_MAGIC)
        seen = 0
        for case in cases.iter_cases():
            meta = case['metadata']
            encoded = cases.blob_record(meta, case['blobs'])
            exact(inputs.read(len(encoded)), encoded, 'complete shared original logical input')
            result = next(outputs)
            counts, _ = original._record(meta, result)
            if source_counts is None:
                source_counts = {key: 0 for key in counts}
            for key, value in counts.items():
                source_counts[key] += value
            seen += 1
            if not selected(meta) or meta['case_id'] in PATH_CONTROLS:
                continue
            outcome = result['metadata']['outcome']
            require(type(outcome.get('ok')) is bool, 'original published result missing')
            index, size = outcome['blob'], outcome['bytes']
            require(type(index) is int and 0 <= index < len(result['blobs']) and type(size) is int,
                    'original body descriptor differs')
            body = result['blobs'][index]
            exact(len(body), size, 'complete original body extent')
            for protocol in ('legacy', 'modern'):
                row = native_rows[(protocol, meta['case_id'])]
                actual = evidence.stream(str(native_corpus.relative_to(evidence.output)), row['actual_body'])
                exact(actual, body, 'complete actual public body differs from original ' + protocol + ':' + str(meta['case_id']))
                exact(row['is_error'], not outcome['ok'], 'public/original complete status differs')
                compared[protocol] += 1
                byte_counts[protocol] += len(body)
        exact(seen, 271, 'complete original replay inventory')
        exact(inputs.read(1), b'', 'trailing shared original input')
        exact(next(outputs, None), None, 'trailing shared original output')
    exact(compared, dict(legacy=255, modern=255), 'complete public original body comparison count')
    source_counts.update(actual_tokio_io=True, actual_unchanged_search=True,
                         actual_original_mcp_router=False, alternative_path_search=False,
                         directory_search=False, regex_search=True, whole_view_migrated=False,
                         whole_runtime_replaced=False)
    exact(reference['reference'], source_counts, 'shared original complete result recount')
    return dict(schema='hepta.runtime.view-regex-search-public-original-comparison.v1', status='PASS',
                complete_original_body_cases=510, native_path_resolution_controls=8,
                compared_cases=compared, compared_body_bytes=byte_counts,
                shared_original_processes=3, new_original_processes=0, new_native_calls=0,
                native_cases_added_by_replay=0, original_process_admission_external=True,
                original_mcp_router_executed=False, whole_view_replaced=False, whole_runtime_replaced=False,
                complete_sdk_frontend=False, response_storage_globally_unbounded=False,
                artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
                artifacts=[evidence.artifacts[name] for name in sorted(evidence.artifacts)],
                source_sha256=dict(sorted(source_pins.items())))

PUBLIC_EVIDENCE_SUITE = 'test_view_regex_search_public_evidence.py'
PUBLIC_CONTROLS = tuple(sorted(('public-command','public-bool-exit','public-timeout-budget',
    'public-timed-out','public-nonfinite-elapsed','public-duplicate','public-module-image',
    'public-compiler-output','public-process-stdin','public-body-byte','public-response-byte',
    'public-case-omitted')))


def qualification_evidence(root, output, report, completed=None):
    """Require actual physical refusal controls after complete public admission."""
    root, output = Path(root), Path(output)
    native = public_native_evidence(root, output, report, completed)
    evidence = mcp.Evidence(output)
    record = evidence.object(native['corpus'] + '/result.json')
    paths = origin(record, native['corpus'])
    test_path = 'tests/hia_native/' + PUBLIC_EVIDENCE_SUITE
    expected = dict(schema='hepta.runtime.view-regex-search-public-evidence-tests.v1',status='PASS',
        groups=2,test_groups=2,refusal_controls=12,failures=0,errors=0,skipped=0,
        controls=list(PUBLIC_CONTROLS),native_evidence_sha256=sha(compact(native)),
        reader_sha256=identity(mcp.owned(root,READER))['sha256'],
        test_sha256=identity(mcp.owned(root,test_path))['sha256'],
        new_native_calls=0,new_rust_processes=0,native_cases_added_by_replay=0,
        relocated_source_and_output_replay=True,live_fixture_directories_required=False,
        process_receipts_rewritten=False,whole_view_replaced=False,whole_runtime_replaced=False)
    check = suite(evidence,report,completed,PUBLIC_EVIDENCE_SUITE,paths['runtime_root'],expected,groups=2)
    native['artifact_sha256'].update(evidence.artifact_sha256)
    artifacts = {row['path']: row for row in native['artifacts']}
    artifacts.update(evidence.artifacts)
    native['artifact_sha256'] = dict(sorted(native['artifact_sha256'].items()))
    native['artifacts'] = [artifacts[name] for name in sorted(artifacts)]
    native['source_sha256'][test_path] = expected['test_sha256']
    native['source_sha256'] = dict(sorted(native['source_sha256'].items()))
    native['evidence_controls'] = dict(groups=2,refusals=12,controls=list(PUBLIC_CONTROLS),
        stdout_sha256=check['stdout_sha256'],stderr_sha256=check['stderr_sha256'])
    return native
