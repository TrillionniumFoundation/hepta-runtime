"""Read the complete executed MCP/view evidence and its fixed native composition.

This admits a limited stdio profile. Protocol fixture projections, complete
ordinary-file text, and unfinished runtime routes remain separate claims.
No native instruction or original Rust process runs in this reader.
"""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
import io
import json
import math
from pathlib import Path
import re
import stat
import struct
import sys

from hia_native_build import HEPTA_COMMIT, BUFFER_PROFILES, json_bytes
from hia_native_runtime_mcp_build import MEMBERS, BASE, BOUNDARIES, EXTRA, VIEW, adapter_source

FOLDER = 'runtime-mcp'
NATIVE_SUITE = 'test_runtime_mcp.py'
EVIDENCE_SUITE = 'test_runtime_mcp_evidence.py'
SOURCE_MANIFEST_SHA256 = '9b22b16059c95583aa3cf8f70a4b90dd4d601af24e8c3a48923bf9661eaf8870'
LINKER_SOURCE_SHA256 = '66063b0e8d9b244a8ccec27a31554fe8e77f309ac1fc981286e63befa7559cef'
COMPILER_SHA256 = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
VIEW_IDS = tuple([*range(19), 26, 28, 29, 30, 35, 36, *range(45, 51)])
TYPED_ERRORS = {0,1,2,3,11,12,13,14,15,16,17,20,200,201,202,203,206,207,208}
META_ERRORS = {32,33,34,35,101,103,105,209,210}
COUNTS = dict(actual_elf_processes=109, actual_elf_responses=222, actual_embedded_hia_images=39,
              actual_policy_and_shared_config_controls=7, actual_public_ordinary_view_cases=31,
              large_error_body_bytes=19000091, large_error_publication_cases=1,
              observable_session_latch_controls=3, private_frame_refusals=34,
              real_child_positive_continuations=2, same_session_cache_cases=6,
              sdk_info_input_cases=13, sdk_metadata_error_controls=9,
              sdk_router_input_cases=54, sdk_typed_protocol_error_controls=19,
              regex_actual_installed_configs=5,regex_actual_startup_refusals=4,
              regex_actual_first_error_controls=2,regex_actual_mcp_view_results=5)
REGEX_PLANS = [('valid',pattern) for pattern in ['a',r'[a-z]+',r'\p{Greek}+',r')|foo(?:','a{327674}']]
REGEX_PLANS += [('invalid',pattern) for pattern in ['(',r'\w{500}','a{327675}',r'(?-u:\xFF)']]
REGEX_PLANS += [('first-error-late','('),('first-error-early','(')]
REGEX_LOCAL_CALL_EDGES = {'3':[15],'15':[10,12,13,14],'10':[11],'12':[11],'14':[11]}
REGEX_SELECTOR_MEMBERS = {'3':'validation','10':'regex_syntax','11':'regex_unicode_data',
                        '12':'regex_hir','13':'regex_nfa','14':'regex_match','15':'regex_controller'}
FALSE_FLAGS = ('complete_sdk_frontend', 'complete_original_tool_catalog',
               'directory_content_remote_background_routes_replaced', 'whole_view_replaced',
               'response_storage_globally_unbounded', 'full_http_dispatcher_replaced',
               'current_protocol_error_reference_compared', 'current_original_view_reference_compared')
EVIDENCE_GROUPS = 5
EVIDENCE_CONTROLS = 45
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError('runtime MCP evidence: ' + message)


def compact(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def exact(actual, expected, message):
    if isinstance(actual, bytes) or isinstance(expected, bytes):
        require(type(actual) is bytes and type(expected) is bytes and actual == expected, message)
    else:
        require(compact(actual) == compact(expected), message)


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('runtime MCP evidence: nonfinite JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def owned(root, name):
    require(type(name) is str, 'artifact name is not text')
    relative = Path(name)
    require(not relative.is_absolute() and bool(relative.parts) and '..' not in relative.parts
            and relative.as_posix() == name, 'artifact escaped its owner')
    path = root / relative
    require(path.resolve() == path.absolute() and stat.S_ISREG(path.lstat().st_mode),
            'artifact is not an owned regular file')
    return path


def finite(value, maximum):
    return type(value) in (float, int) and math.isfinite(value) and 0 < value < maximum


class Evidence:
    def __init__(self, output):
        self.output = output
        self.artifact_sha256 = {}
        self.artifacts = {}

    def read(self, name):
        raw = owned(self.output, name).read_bytes()
        self.artifact_sha256[name] = sha(raw)
        self.artifacts[name] = dict(path=name, bytes=len(raw), sha256=sha(raw))
        return raw

    def object(self, name):
        value = decode(self.read(name))
        require(type(value) is dict, 'expected object: ' + name)
        return value

    def rows(self, name):
        raw = self.read(name)
        require(raw.endswith(b'\n'), 'JSONL final newline absent')
        return [decode(row) for row in raw[:-1].split(b'\n')]

    def stream(self, folder, descriptor, expected_path=None):
        exact(sorted(descriptor), ['bytes', 'path', 'sha256'], 'stream descriptor fields differ')
        require(type(descriptor['bytes']) is int and 0 <= descriptor['bytes'] <= 256 << 20,
                'stream byte length is not a supported integer')
        if expected_path is not None:
            exact(descriptor['path'], expected_path, 'stream path differs from its case')
        packed = self.read(folder + '/' + descriptor['path'])
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as handle:
            raw = handle.read(descriptor['bytes'] + 1)
            require(len(raw) == descriptor['bytes'] and handle.read(1) == b'', 'complete gzip length differs')
        require(sha(raw) == descriptor['sha256'], 'complete gzip bytes differ')
        return raw


def generators(root):
    result = {}
    for name in ('cases', 'sdk_cases', 'router_sdk_cases', 'info_sdk_cases', 'wide_endpoint_case'):
        path = root / 'tests/hia_native/view_call_oracle' / (name + '.py')
        spec = importlib.util.spec_from_file_location('_runtime_mcp_reader_' + name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result[name] = module
    return result


def source_identity(root):
    raw = owned(root, 'native/runtime_mcp_sources.json').read_bytes()
    require(sha(raw) == SOURCE_MANIFEST_SHA256, 'final source manifest changed')
    proof = decode(raw)
    exact(proof['schema'], 'hepta.runtime.mcp-view-sources.v1', 'source manifest schema differs')
    result = {}
    for name, expected in proof['sources'].items():
        data = owned(root, name).read_bytes()
        exact(dict(bytes=len(data), sha256=sha(data)), expected, 'source changed: ' + name)
        result[name] = expected
    return dict(manifest_sha256=sha(raw), files=result)


def completed_suite(root, output, report, completed, name, groups):
    rows = [row for row in report['checks'] if row.get('name') == name]
    require(len(rows) == 1, 'one actual process receipt required: ' + name)
    row = rows[0]
    # Source/output directories may move after capture. The retained source
    # root belongs to the complete native capture, whose exact current source
    # closure is checked here; it is never used for reading a file.
    capture = decode(owned(output, FOLDER + '/result.json').read_bytes())
    native_header(capture, source_identity(root))
    origin = capture.get('execution')
    require(type(origin) is dict, 'native execution origin is missing')
    exact(sorted(origin), ['corpus_root', 'manifest_path', 'runtime_root'],
          'native execution origin fields differ')
    for value in origin.values():
        require(type(value) is str and Path(value).is_absolute()
                and '..' not in Path(value).parts and str(Path(value)) == value,
                'native execution origin is not canonical')
    origin_root = Path(origin['runtime_root'])
    origin_corpus = Path(origin['corpus_root'])
    require(origin_corpus.name == FOLDER, 'native corpus origin differs')
    owner = report.get('modules', {}).get('runtime_mcp')
    require(type(owner) is dict and type(owner.get('manifest')) is str
            and not Path(owner['manifest']).is_absolute()
            and '..' not in Path(owner['manifest']).parts,
            'native manifest owner is not relative')
    exact(origin['manifest_path'], str(origin_corpus.parent / owner['manifest']),
          'native manifest origin differs from the retained build owner')
    exact(row.get('command'), [sys.executable, '-I', '-B', str(origin_root / 'tests/hia_native' / name)],
          'suite command differs from its complete native origin')
    require(type(row.get('exit_code')) is int and row['exit_code'] == 0
            and row.get('timed_out') is False and not row.get('start_error')
            and type(row.get('timeout_seconds')) is int and row['timeout_seconds'] == 180
            and finite(row.get('elapsed_seconds'), 180), 'suite did not complete within 180 seconds')
    streams = {}
    for suffix in ('stdout', 'stderr'):
        streams[suffix] = owned(output, name + '.' + suffix).read_bytes()
        exact(dict(bytes=row.get(suffix + '_bytes'), sha256=row.get(suffix + '_sha256')),
              dict(bytes=len(streams[suffix]), sha256=sha(streams[suffix])), 'suite raw stream differs')
    summary = decode(streams['stdout'])
    exact(summary, row.get('summary'), 'stored suite summary differs')
    observed = completed(output, report, name)
    exact(list(observed), [row, summary], 'completed callback selected different evidence')
    stderr = streams['stderr'].decode()
    require(len(re.findall(r'\.\.\. ok\n', stderr)) == groups and
            re.search(r'\nRan ' + str(groups) + r' tests in [0-9.]+s\n\nOK\n\Z', stderr),
            'not every suite group executed')
    return row, summary


def native_header(report, binding):
    exact(report.get('schema'), 'hepta.runtime.mcp-view-native-tests.v1', 'native schema differs')
    exact(report.get('status'), 'PASS', 'native suite did not pass')
    exact(report.get('groups'), 8, 'native groups differ')
    exact(report.get('counts'), COUNTS, 'native count inventory differs')
    require(finite(report.get('elapsed_seconds'), 180), 'native elapsed time differs')
    exact(report.get('source_binding'), binding, 'native executed source closure differs')
    require(report.get('sources_unchanged') is True, 'source closure changed during suite')
    for flag in FALSE_FLAGS:
        require(report.get(flag) is False, 'unqualified native claim: ' + flag)
    exact(report.get('implemented_catalog_names'), ['host_list', 'effective_config', 'execution_shadow_admit', 'view'],
          'implemented tool list differs')
    exact(report.get('original_tool_count'), 125, 'original tool count differs')


def session_streams(evidence, folder, report):
    origin = report['execution']
    exact(sorted(origin), ['corpus_root', 'manifest_path', 'runtime_root'], 'execution origin fields differ')
    for value in origin.values():
        require(type(value) is str and Path(value).is_absolute() and '..' not in Path(value).parts,
                'execution origin is not an absolute retained path')
    executable = str(Path(origin['manifest_path']).parent / 'runtime-mcp.elf')
    sessions = {}
    for record in report['processes']:
        name = record['session']
        require(type(name) is str and re.fullmatch('[a-z0-9-]+', name) and name not in sessions,
                'duplicate or invalid session identity')
        expected_fields = ('session', 'command', 'environment', 'timeout_seconds', 'exit_code',
                           'elapsed_seconds', 'stdin', 'stdout', 'stderr')
        exact(sorted(record), sorted(expected_fields), 'session receipt fields differ')
        command = record['command']
        require(type(command) is list and command[0] == executable, 'session executable differs')
        suffix = ['--session-root', str(Path(origin['corpus_root']) / 'files')]
        if name.startswith('ordinary-'):
            suffix[-1] += '/' + name
        elif name == 'wide-error':
            suffix[-1] += '/wide'
        elif name in {'typed-before-latch', 'legacy-invalid-whole-cap-fallback', 'first-empty-cap-consumes-latch'}:
            suffix[-1] += '/session-a'
        elif name == 'installed-policy':
            suffix = ['--runtime-config', str(Path(origin['corpus_root']) / 'files/runtime-config.json'),
                      '--session-root', str(Path(origin['corpus_root']) / 'files/allowed')]
        elif name.startswith('regex-'):
            require(name in {'regex-'+str(i) for i in range(len(REGEX_PLANS))}, 'unknown regex case')
            directory=Path(origin['corpus_root'])/'files'/name
            suffix=['--runtime-config',str(directory/'runtime-config.json'),'--session-root',str(directory)]
        exact(command[1:], suffix, 'session arguments differ')
        exact(record['environment'], {'PATH': '', 'LC_ALL': 'C'}, 'session inherited an unexpected environment')
        refused = name.startswith('regex-') and REGEX_PLANS[int(name[6:])][0]!='valid'
        expected_exit = 78 if refused else 0
        require(type(record['exit_code']) is int and record['exit_code'] == expected_exit
                and type(record['timeout_seconds']) is int and record['timeout_seconds'] == 60
                and finite(record['elapsed_seconds'], 180), 'session did not finish successfully')
        exact(evidence.object(folder + '/sessions/' + name + '/process.json'), record, 'session process copy differs')
        streams = {key: evidence.stream(folder, record[key], 'sessions/' + name + '/' + key + '.bin.gz')
                   for key in ('stdin', 'stdout', 'stderr')}
        if refused:
            _,_,expected_error=regex_configuration(origin['corpus_root'],int(name[6:]))
            for key,expected in dict(stdin=b'',stdout=b'',stderr=expected_error).items():
                exact(streams[key],expected,'regex startup did not refuse before MCP: '+key)
            requests=[];replies=[]
        else:
            require(streams['stderr'] == b'', 'production emitted private receipt or unexpected stderr')
            require(streams['stdin'].endswith(b'\n') and streams['stdout'].endswith(b'\n'), 'protocol line incomplete')
            requests = [decode(line) for line in streams['stdin'][:-1].split(b'\n')]
            replies = [decode(line) for line in streams['stdout'][:-1].split(b'\n')]
        requested = [message for message in requests if 'id' in message]
        require(len(requested) == len(replies), 'raw reply count differs from actual requests')
        for request, reply in zip(requested, replies):
            exact(reply.get('jsonrpc'), '2.0', 'response version differs')
            exact(reply.get('id'), request['id'], 'response correlation differs')
            require(('result' in reply) != ('error' in reply), 'ambiguous response outcome')
        sessions[name] = dict(record=record, streams=streams, requests=requests, replies=replies,
                              reply_lines=streams['stdout'][:-1].split(b'\n') if replies else [])
    require(len(sessions) == 109 and sum(len(s['replies']) for s in sessions.values()) == 222,
            'complete process/response inventory differs')
    return sessions


def content(reply):
    result = reply['result']
    require(type(result['isError']) is bool and type(result['content']) is list
            and len(result['content']) == 1, 'tool result shape differs')
    item = result['content'][0]
    exact(sorted(item), ['text', 'type'], 'text content fields differ')
    require(item['type'] == 'text' and type(item['text']) is str, 'text content differs')
    return result, item['text'].encode()


def regex_configuration(origin, index):
    kind,pattern=REGEX_PLANS[index]
    directory=Path(origin)/'files'/('regex-'+str(index))
    action=dict(executable='/echo',allow_extra_args=True,extra_arg_patterns=[pattern])
    value=dict(state_dir=str(directory/'controller-state'),controller_workspace_roots=[str(directory)],
               hosts={'h':dict(ssh_target='private-target',remote_state_dir='/private-state',privileged_actions={'inspect':action})})
    error=b'host `h` privileged action `inspect` has invalid argument regex\n'
    if kind.startswith('first-error-'):
        action['extra_arg_patterns']=['a',pattern]
        value['hosts']['h']['privileged_actions']={'middle':action,'zlast':{'executable':'relative'}}
        error=b'host `h` privileged action `middle` has invalid argument regex\n'
        if kind=='first-error-early':
            value['hosts']['h']['privileged_actions']['afirst']={'executable':'relative'}
            error=b'host `h` has invalid privileged action `afirst`\n'
    initial=compact(value)
    rewritten=None
    if kind=='valid':
        action['extra_arg_patterns']=['(']
        rewritten=compact(value)
    return initial,rewritten,error


def regex_cases(root,evidence,folder,report,sessions):
    rows=decode(evidence.read(folder+'/regex-cases.json'))
    require(type(rows) is list and len(rows)==len(REGEX_PLANS),'regex installation corpus differs')
    modules=generators(root)
    for index,(row,(kind,pattern)) in enumerate(zip(rows,REGEX_PLANS)):
        name='regex-'+str(index)
        exact(sorted(row),['case_id','initial_config','kind','pattern','rewritten_config','session','state_directory_exists_after'],
              'regex case fields differ')
        exact((row['case_id'],row['kind'],row['pattern'],row['session']),(index,kind,pattern,name),'regex case identity differs')
        require(type(row['state_directory_exists_after']) is bool and row['state_directory_exists_after']==(kind=='valid'),
                'regex state admission observation differs')
        initial,rewritten,error=regex_configuration(report['execution']['corpus_root'],index)
        exact(evidence.stream(folder,row['initial_config'],'regex/'+str(index)+'.initial-config.json.gz'),initial,
              'regex startup configuration bytes differ')
        session=sessions[name]
        if kind!='valid':
            require(row['rewritten_config'] is None,'refused regex was installed or rewritten')
            for key,expected in dict(stdin=b'',stdout=b'',stderr=error).items():
                exact(session['streams'][key],expected,'regex complete refusal differs: '+key)
            continue
        exact(evidence.stream(folder,row['rewritten_config'],'regex/'+str(index)+'.rewritten-config.json.gz'),rewritten,
              'post-installation config mutation differs')
        request=lambda ident,tool:dict(jsonrpc='2.0',id=ident,method='tools/call',params=dict(name=tool,arguments={}))
        expected=[modules['sdk_cases'].initialization({}),request(2,'host_list'),request(3,'effective_config'),
                  modules['sdk_cases'].call(4,{'path':'file'}),request(5,'host_list'),request(6,'effective_config')]
        exact(session['streams']['stdin'],b''.join(compact(v)+b'\n' for v in expected),'regex installed request sequence differs')
        replies=session['replies'];require(len(replies)==6,'regex installed replies differ')
        first,text=content(replies[1]);effective,projection=content(replies[2]);view,body=content(replies[3])
        require(not first['isError'] and not effective['isError'] and not view['isError'],'valid regex configuration failed')
        require(b'inspect' in text and b'inspect' not in projection and body.endswith(b'|regex installed'),
                'regex configuration did not reach the actual public view and publisher')
        exact(decode(projection)['hosts'][0]['named_privileged_action_count'],1,'regex redacted projection differs')
        exact(replies[4]['result'],first,'installed host list changed after config-file rewrite')
        exact(replies[5]['result'],effective,'installed redacted config changed after config-file rewrite')
    return rows


def public_cases(root, evidence, folder, report, sessions):
    modules = generators(root)
    all_cases = {row['metadata']['case_id']: row for row in modules['cases'].iter_cases()}
    used = set()
    rows_by_kind = {}
    for kind, generator, count in [('router', modules['router_sdk_cases'].iter_router_sdk_cases, 54),
                                    ('info', modules['info_sdk_cases'].iter_info_sdk_cases, 13)]:
        rows = evidence.rows(folder + '/' + kind + '-cases.jsonl')
        inputs = list(generator())
        require(len(rows) == len(inputs) == count, 'SDK input domain count differs')
        for row, original in zip(rows, inputs):
            ident = original['case_id']; name = kind + '-' + str(ident)
            exact((row['case_id'], row['name'], row['session']), (ident, original['name'], name), 'SDK case identity differs')
            exact(evidence.stream(folder, row['input_case'], kind + '/' + str(ident) + '.input.json.gz'),
                  compact(original), 'SDK input bytes differ')
            actual = decode(evidence.stream(folder, row['responses'], kind + '/' + str(ident) + '.responses.json.gz'))
            session = sessions[name]; used.add(name)
            exact(session['streams']['stdin'], b''.join(compact(m) + b'\n' for m in original['messages']),
                  'SDK case did not send the independent input bytes')
            exact(actual, session['replies'], 'SDK projection is not the actual complete stdout')
            flag = 'original_fixture_body_text_compared' if kind == 'router' else 'full_original_tool_catalog_compared'
            require(row.get(flag) is False, 'SDK fixture projection claimed full handler equivalence')
        rows_by_kind[kind] = rows
    view_rows = evidence.rows(folder + '/view-cases.jsonl')
    exact([row['case_id'] for row in view_rows], list(VIEW_IDS), 'ordinary view domain differs')
    for row in view_rows:
        request = all_cases[row['case_id']]; meta = request['metadata']; ident = str(meta['case_id'])
        exact((row['name'], row['session']), (meta['name'], 'ordinary-' + str(meta['session'])), 'view case identity differs')
        require(row.get('private_hooks_used') is False and meta['context'] is True and not meta['hooks']
                and not meta['cancel_after_render'] and not meta['raw_path'], 'private fixture used as public view')
        exact(evidence.stream(folder, row['original_input'], 'view/' + ident + '.input.bin.gz'),
              modules['cases'].encode_cases([request]), 'ordinary view original input differs')
        session = sessions[row['session']]; used.add(row['session'])
        indexes = [i for i, reply in enumerate(session['replies']) if reply['id'] == meta['case_id'] + 2]
        require(len(indexes) == 1, 'ordinary view response absent or duplicated'); index = indexes[0]
        reply = session['replies'][index]; actual_wire = evidence.stream(folder, row['actual_response'], 'view/' + ident + '.response.bin.gz')
        exact(actual_wire, session['reply_lines'][index], 'retained view response is not actual stdout')
        result, body = content(reply)
        exact(evidence.stream(folder, row['actual_body'], 'view/' + ident + '.body.bin.gz'), body, 'retained view body differs')
        exact(row['is_error'], result['isError'], 'retained error flag differs')
        arguments = dict(path=bytes.fromhex(meta['path_hex']).decode(), **meta['params'])
        expected = modules['sdk_cases'].call(meta['case_id'] + 2, arguments)
        requests = [message for message in session['requests'] if message.get('id') == meta['case_id'] + 2]
        exact(requests, [expected], 'public view arguments differ from original case')
    wide = evidence.object(folder + '/wide-case.json'); generator = modules['wide_endpoint_case']
    exact(wide['case_id'], generator.CASE_ID, 'wide error case differs')
    require(wide.get('original_success_body_limit_applied_to_error') is False
            and wide.get('unrestricted_response_domain_claimed') is False, 'wide error raised an invalid closure claim')
    exact(evidence.stream(folder, wide['original_input'], 'wide/input.bin.gz'), generator.original_input(), 'wide original input differs')
    session = sessions['wide-error']; used.add('wide-error')
    result, body = content(session['replies'][1]); require(result['isError'] is True, 'wide case is not a String error')
    exact(evidence.stream(folder, wide['actual_body'], 'wide/body.bin.gz'), body, 'wide retained text differs')
    exact(evidence.stream(folder, wide['actual_response'], 'wide/response.bin.gz'), session['reply_lines'][1], 'wide publication differs')
    require(len(body) == 19000091, 'wide error body was shortened')
    expected_request = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"view","arguments":' + generator.arguments() + b'}}'
    exact(session['streams']['stdin'].split(b'\n')[1], expected_request, 'wide public input bytes differ')
    regex=regex_cases(root,evidence,folder,report,sessions)
    used.update('regex-'+str(i) for i in range(len(REGEX_PLANS)))
    remaining = set(sessions) - used
    exact(sorted(remaining), ['first-empty-cap-consumes-latch', 'installed-policy', 'legacy-invalid-whole-cap-fallback', 'typed-before-latch'], 'behavioral control sessions differ')
    first = sessions['typed-before-latch']['replies']
    require(first[1]['error']['code'] == -32602 and content(first[2])[1].endswith(b'|second directory'), 'typed error consumed the workdir latch')
    require(content(sessions['legacy-invalid-whole-cap-fallback']['replies'][1])[1].endswith(b'|second directory'), 'bad complete capabilities did not fall back')
    empty = sessions['first-empty-cap-consumes-latch']['replies']
    require(content(empty[1])[1] == content(empty[2])[1] and content(empty[1])[1].endswith(b'|first directory'), 'valid empty capabilities did not consume the first latch')
    policy = sessions['installed-policy']['replies']
    require(content(policy[1])[1].endswith(b'|allowed') and content(policy[1])[0]['isError'] is False, 'allowed path failed')
    for index, expected in [(2,b'outside configured controller workspaces'),(3,b'Octofs background resources are disabled in runtime mode'),(4,b'path must not contain an empty root'),(5,b'outside configured controller workspaces')]:
        result, text = content(policy[index]); require(result['isError'] is True and expected in text, 'installed policy or same authority control differs')
    require(all(content(policy[i])[0]['isError'] is False for i in (6,7)), 'configuration tools stopped using the installed authority')
    return dict(router=rows_by_kind['router'], info=rows_by_kind['info'], view=view_rows, wide=wide,regex=regex)


def sparse_prefix(raw):
    require(raw[:8] == b'HRMCS001' and len(raw) >= 32, 'private sparse snapshot framing differs')
    capacity, block, count = struct.unpack_from('<3Q', raw, 8)
    require(capacity == 256 << 20 and block == 1 << 20 and count <= 256, 'private sparse snapshot profile differs')
    cursor = 32; chunks = {}; previous = -block
    for _ in range(count):
        require(cursor + 16 <= len(raw), 'sparse record header truncated')
        offset, size = struct.unpack_from('<2Q', raw, cursor); cursor += 16
        require(offset % block == 0 and offset > previous and offset < capacity and size == block
                and cursor + size <= len(raw), 'sparse record span differs')
        chunks[offset] = raw[cursor:cursor+size]; cursor += size; previous = offset
        require(chunks[offset].count(0) != size, 'zero sparse block is not canonical')
    require(cursor == len(raw), 'sparse state has trailing bytes')
    digest = hashlib.sha256(); zero = bytes(block)
    for offset in range(0, capacity-block, block): digest.update(chunks.get(offset, zero))
    last = chunks.get(capacity-block, zero); digest.update(last[:-256])
    return digest, last[-256:]


def private_refusals(evidence, folder):
    rows = decode(evidence.read(folder + '/private-refusals.json'))
    labels = ['empty', 'short', 'magic', 'length'] + ['continuation-word-' + str(i) for i in (0,8,16,24,32,40,48,56,64,72,88,96,104)]
    exact([(r['owner'], r['control']) for r in rows], [(owner,label) for owner in ('gateway','admission') for label in labels], 'private refusal inventory differs')
    baselines = {}
    for index, row in enumerate(rows):
        require(type(row['return_code']) is int and row['return_code'] == 0xffffffff
                and row['buffers_unchanged'] is True, 'private refusal result differs')
        exact((row['workspace_capacity'], row['output_capacity']), (256 << 20, 512), 'private refusal capacities differ')
        owner = row['owner']; request = (b'HVMGWQ01'+struct.pack('<4Q',2,0,0,0)+b'{}') if owner == 'gateway' else (b'HCMADQ01'+struct.pack('<3Q',2,2,0)+b'{}')
        expected = {'empty':b'', 'short':request[:7], 'magic':b'BADMAGIC'+request[8:], 'length':request+b'x'}.get(row['control'], request)
        exact(evidence.stream(folder, row['input'], 'private/'+str(index)+'.input.bin.gz'), expected, 'private input differs')
        kind = 'ready' if row['control'].startswith('continuation-') else 'zero'
        baseline_path = 'private/' + owner + '-' + kind + '.bin.gz'
        raw = evidence.stream(folder, row['baseline'], baseline_path)
        if baseline_path not in baselines: baselines[baseline_path] = sparse_prefix(raw)
        digest, footer = baselines[baseline_path]
        if kind == 'zero': require(raw == b'HRMCS001'+struct.pack('<3Q',256<<20,1<<20,0), 'initial state was not zero')
        else:
            offset = int(row['control'].rsplit('-',1)[1]); footer = bytearray(footer)
            value, = struct.unpack_from('<Q',footer,offset); struct.pack_into('<Q',footer,offset,value ^ (1 << 63)); footer = bytes(footer)
        for suffix in ('before','after'):
            exact(evidence.stream(folder,row['footer_'+suffix], 'private/'+str(index)+'.footer-'+suffix+'.bin.gz'), footer, 'private footer changed or differs')
            exact(evidence.stream(folder,row['output_'+suffix], 'private/'+str(index)+'.output-'+suffix+'.bin.gz'), bytes([0xa5])*512, 'rejected private output changed')
            expected_hash = digest.copy(); expected_hash.update(footer)
            exact(row['workspace_'+suffix+'_sha256'], expected_hash.hexdigest(), 'complete private workspace differs from retained sparse bytes')
    positive=decode(evidence.read(folder+'/private-positives.json'))
    exact([(row['owner'],row['child']) for row in positive],[('gateway','params'),('admission','value')], 'actual child continuation inventory differs')
    for row in positive:
        owner=row['owner'];request=(b'HVMGWQ01'+struct.pack('<4Q',2,0,0,0)+b'{}') if owner=='gateway' else (b'HCMADQ01'+struct.pack('<3Q',2,2,0)+b'{}')
        child_wire=(b'HVPRQ001' if owner=='gateway' else b'HSJVAL01')+struct.pack('<2Q',2 if owner=='gateway' else 1,0 if owner=='gateway' else 2)+b'{}'
        exact(evidence.stream(folder,row['request'],'private/'+owner+'.request.bin.gz'),request,'positive continuation request differs')
        exact(evidence.stream(folder,row['child_input'],'private/'+owner+'.child-input.bin.gz'),child_wire,'actual child input differs')
        yielded=evidence.stream(folder,row['yielded_footer'],'private/'+owner+'.yielded-footer.bin.gz')
        completion=evidence.stream(folder,row['completion_footer'],'private/'+owner+'.completion-footer.bin.gz')
        child=evidence.stream(folder,row['actual_child_response'],'private/'+owner+'.child-response.bin.gz')
        require(len(yielded)==len(completion)==112 and yielded[:8]==b'HIACAL01','actual child request footer differs')
        values=struct.unpack('<14Q',yielded);require(values[1]>0,'child sequence is zero')
        exact(values[2:10],(0,2,4096,len(child_wire),2,67117056,64<<20,0),'fixed child admission spans differ')
        expected=bytearray(yielded);struct.pack_into('<3Q',expected,80,len(child),values[1],1)
        exact(completion,bytes(expected),'actual child ACK does not match its admitted continuation')
        raw=evidence.stream(folder,row['actual_output'],'private/'+owner+'.positive-output.bin.gz')
        require(len(raw)==512,'positive output storage differs')
        if owner=='gateway':
            require(child[:8]==b'HVPRR001' and len(child)>=96 and struct.unpack_from('<Q',child,8)[0]==1,'actual params child did not return a typed diagnostic')
            diagnostic=child[96:];expected=b'HRCFGM01'+struct.pack('<3Q',2,0,len(diagnostic))+diagnostic
            exact((row['return_code'],row['returned_bytes']),(len(expected),len(expected)),'typed continuation return differs')
            exact(raw,expected+bytes([0xa5])*(512-len(expected)),'typed continuation did not forward the actual child diagnostic')
        else:
            exact(child,b'{}','actual serde child output differs')
            exact((row['return_code'],row['returned_bytes']),(0xffffffe0,None),'metadata continuation did not yield its next child')
            exact(raw,bytes([0xa5])*512,'metadata yield changed borrowed output')
    return len(rows)


def inspect_corpus(root, corpus, evidence=None):
    """Re-read complete native captures; process/build admission is a separate step."""
    evidence = Evidence(corpus.parent) if evidence is None else evidence
    folder = str(corpus.relative_to(evidence.output)); sources = source_identity(root)
    report = evidence.object(folder + '/result.json'); native_header(report, sources)
    sessions = session_streams(evidence, folder, report)
    rows = public_cases(root, evidence, folder, report, sessions)
    private_refusals(evidence, folder)
    return dict(report=report, sessions=sessions, rows=rows, evidence=evidence)


def mapped_manifest(build_root, recorded, origin_build_root):
    require(type(recorded) is str, 'member manifest path is not text')
    path = Path(recorded)
    require(path.is_absolute() and path.parent.parent.parent == origin_build_root
            and '..' not in path.parts and len(path.parts) >= 3 and path.parts[-3] == 'modules'
            and path.name == 'manifest.json' and re.fullmatch('[a-z0-9-]+', path.parts[-2]),
            'member manifest is outside a fixed build module')
    return build_root / Path(*path.parts[-3:])


def compilation(evidence, folder, source, image, compiler, dependency):
    stem = str(folder.relative_to(evidence.output)) + '/'
    receipt = evidence.object(stem + 'module.receipt.json')
    output = evidence.read(stem + 'module.output.bin')
    built = evidence.object(stem + 'build.json')
    fields = dict(status='returned', abi_status=0, core_u32=len(image), result_u64=len(image),
                  source_unchanged=True, input_bytes=len(source), input_sha256=sha(source),
                  source_sha256=sha(source), artifact_sha256=sha(compiler), image_sha256=sha(compiler),
                  output_sha256=sha(output), forbidden_compiler_modules_loaded=[],
                  produced_bytes=len(image), produced_sha256=sha(image))
    exact({name:receipt.get(name) for name in fields}, fields, 'actual native compiler receipt differs')
    require(output[:len(image)] == image and 0 < len(image) <= 1 << 20, 'native compiler output differs')
    exact(evidence.read(stem+'module.input.bin'), source, 'actual compiler input is not current HIA source')
    exact(evidence.read(stem+'module.image.bin'), image, 'actual compiled image differs')
    exact(built.get('compile_receipt'), receipt, 'compile receipt copy differs')
    exact(built.get('compiler_dependency'), dependency, 'compiler dependency differs')


def elf_structure(elf, obj, images):
    require(elf[:16] == b'\x7fELF\x02\x01\x01'+bytes(9) and len(elf)>=256, 'ELF identity differs')
    exact(struct.unpack_from('<HHIQQQIHHHHHH',elf,16), (2,62,1,0x4000e8,64,0,0,64,56,3,0,0,0), 'ELF header differs')
    rx = struct.unpack_from('<IIQQQQQQ',elf,64); rw = struct.unpack_from('<IIQQQQQQ',elf,120)
    require(rx[:5] == (1,5,0,0x400000,0x400000) and rx[5] == rx[6] and rx[7] == 4096
            and 256 < rx[5] <= len(elf) and len(elf) == (rx[5]+4095)//4096*4096, 'ELF RX segment differs')
    exact(rw, (1,6,len(elf),0x400000+len(elf),0x400000+len(elf),0,0,4096), 'ELF writable segment differs')
    exact(struct.unpack_from('<IIQQQQQQ',elf,176), (0x6474e551,6,0,0,0,0,0,16), 'ELF stack permissions differ')
    require(elf[232:256] == bytes.fromhex('31ed4883e4f0e80d0000004889c7b83c0000000f050f0b00')
            and elf[rx[5]:] == bytes(len(elf)-rx[5]), 'ELF entry or padding differs')
    require(obj[:16] == elf[:16] and len(obj)>=64, 'assembler object identity differs')
    header = struct.unpack_from('<HHIQQQIHHHHHH',obj,16)
    require(header[0:3] == (1,62,1) and header[4] == 0 and header[10:12] == (64,9), 'assembler object sections differ')
    shoff, shnum, shstr = header[5], header[11], header[12]
    require(shoff+64*shnum <= len(obj) and shstr < shnum, 'object section table truncated')
    sections = [struct.unpack_from('<IIQQQQIIQQ',obj,shoff+i*64) for i in range(shnum)]
    def section_bytes(index):
        item=sections[index]; require(item[4]+item[5]<=len(obj), 'object section escaped input');return obj[item[4]:item[4]+item[5]]
    names=section_bytes(shstr)
    def name(offset):
        end=names.find(b'\0',offset);require(0<=offset<end, 'object section name differs');return names[offset:end].decode()
    named={name(row[0]):i for i,row in enumerate(sections) if row[0]}
    exact(sorted(named), ['.bss','.data','.note.GNU-stack','.rela.text','.shstrtab','.strtab','.symtab','.text'], 'object section inventory differs')
    ti=named['.text']; text=bytearray(section_bytes(ti)); require(sections[ti][2]==6 and len(text)+256==rx[5], 'object text profile differs')
    require(all(row[5]==0 for index,row in enumerate(sections) if row[2]&2 and index!=ti), 'object contains another allocated payload')
    reloc=section_bytes(named['.rela.text']); require(len(reloc)==31*24, 'fixed child relocation count differs')
    symbols=section_bytes(named['.symtab']); require(len(symbols)%24==0, 'object symbol table differs')
    offsets={}
    for key,image in images.items():
        require(elf.count(image)==1, 'native image absent or duplicated: '+key);offsets[key]=elf.index(image)-256
    for ordinal, key in enumerate(EXTRA+VIEW):
        offset,info,addend=struct.unpack_from('<QQq',reloc,ordinal*24);symbol=info>>32
        require(info&0xffffffff==1 and (symbol+1)*24<=len(symbols) and offset+8<=len(text), 'unexpected relocation type/span')
        _,_,_,section,value,_=struct.unpack_from('<IBBHQQ',symbols,symbol*24)
        require(section==ti and value+addend==offsets[key], 'child relocation points at another instance')
        struct.pack_into('<Q',text,offset,0x400100+value+addend)
    exact(bytes(text),elf[256:rx[5]], 'complete ELF machine text differs from actual assembled object/relocations')
    return dict(bytes=len(elf),sha256=sha(elf),entry=0x4000e8,program_headers=['PT_LOAD_RX','PT_LOAD_RW_EMPTY','PT_GNU_STACK_RW'],
                interpreter=None,libc=False,fixed_child_address_relocations=31,embedded_images=39)


def build_evidence(root, output, report, evidence, capture):
    owner=report['modules']['runtime_mcp']; require(owner.get('builder')=='runtime_mcp' and owner.get('source')=='native/runtime_mcp.hepta', 'runtime module registration differs')
    require(type(owner.get('manifest')) is str and Path(owner['manifest']).parts[:2]==('build','runtime_mcp-bundle'),
            'runtime manifest is outside its isolated build root')
    manifest=owned(output,owner['manifest']); raw=evidence.read(owner['manifest']); require(sha(raw)==owner['sha256'], 'bundle manifest changed')
    bundle=decode(raw); folder=manifest.parent; build_root=folder.parent
    origin_build_root=Path(capture['execution']['manifest_path']).parent.parent
    exact(capture['manifest_sha256'],sha(raw),'executed bundle differs')
    require(bundle['schema']=='hepta.runtime.mcp-view-build.v1' and bundle['compiler_commit']==HEPTA_COMMIT
            and report['compiler_commit']==HEPTA_COMMIT and bundle['compiler_image_sha256']==COMPILER_SHA256
            and report['compiler_image_sha256']==COMPILER_SHA256, 'pinned compiler identity differs')
    exact(bundle['source_binding'],source_identity(root),'built source closure differs')
    require(bundle['builder_source_sha256']==sha((root/'scripts/hia_native_runtime_mcp_build.py').read_bytes()),'builder source changed')
    compiler=evidence.read(str((build_root/'bootstrap/B3.image.bin').relative_to(output))); require(sha(compiler)==COMPILER_SHA256,'compiler artifact changed')
    bootstrap=evidence.object(str((build_root/'bootstrap/bootstrap.json').relative_to(output)))
    require(bootstrap['dependency']['commit']==HEPTA_COMMIT
            and bootstrap['dependency']['tree']=='8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'
            and bootstrap['dependency']['files'].get('examples/hia_bootstrap/elf_static_linker.hepta')==LINKER_SOURCE_SHA256,
            'bootstrap dependency or upstream linker pin differs')
    images={}; original_images={}; fresh=0
    exact([row['name'] for row in bundle['members']],[row[0] for row in MEMBERS],'fixed member inventory differs')
    for row,(key,source,profile) in zip(bundle['members'],MEMBERS):
        path=mapped_manifest(build_root,row['manifest'],origin_build_root); prefix=str(path.parent.relative_to(output))+'/'
        module_raw=evidence.read(str(path.relative_to(output))); module=decode(module_raw)
        require(sha(module_raw)==row['manifest_sha256'],'member manifest changed')
        exact((row['source'],row['buffer_profile']),('native/'+source+'.hepta',profile),'member source/profile changed')
        require(type(row['fresh_compile']) is bool,'fresh-compile claim is not boolean'); fresh+=row['fresh_compile']
        if row['fresh_compile']:
            exact(path.parent.name,folder.name+'-'+key.replace('_','-'),'fresh member does not belong to this build invocation')
        for label in ('source','image'):
            require(type(module[label]) is str and Path(module[label]).name==module[label],'module artifact is not a basename')
        source_raw=evidence.read(prefix+module['source']); image=evidence.read(prefix+module['image'])
        exact(source_raw,(root/row['source']).read_bytes(),'compiled source differs from current owner')
        require(sha(source_raw)==module['source_sha256']==row['source_sha256'] and sha(image)==module['image_sha256']==row['image_sha256']
                and len(image)==row['image_bytes'],'member complete bytes changed')
        exact((module['compiler_commit'],module['compiler_sha256'],module.get('buffer_profile','standard')),
              (HEPTA_COMMIT,COMPILER_SHA256,profile),'member compiler/profile differs')
        exact((module.get('schema'),module.get('abi'),module.get('target'),module.get('standalone')),
              ('hepta.runtime.native-module.v1','hepta.runtime.borrowed-bytes.linux-x86_64.v1','linux-x86_64',None),
              'member ABI/standalone shape differs')
        exact(tuple(module.get(key) for key in ('input_capacity','output_capacity','workspace_capacity')),
              BUFFER_PROFILES[profile],'compiled member declared capacities differ')
        compilation(evidence,path.parent,source_raw,image,compiler,bootstrap['dependency'])
        images[key]=image; original_images[key]=Path(row['manifest']).parent/module['image']
    for row in decode(evidence.read(FOLDER+'/private-positives.json')):
        member=next(member for member in bundle['members'] if member['name']==row['child'])
        exact(row['child_manifest_sha256'],member['manifest_sha256'],'real continuation used another child image')
    expected_boundaries={path:sha((root/path).read_bytes()) for path in (BASE,*BOUNDARIES)}
    exact(bundle['boundary_sources'],expected_boundaries,'mechanical boundary sources differ')
    exact(bundle['extra_table'],EXTRA,'extra child table differs');exact(bundle['view_table'],VIEW,'view child table differs')
    exact(bundle['regex_local_call_edges'],REGEX_LOCAL_CALL_EDGES,'regex private call graph differs')
    exact(bundle['regex_selector_members'],REGEX_SELECTOR_MEMBERS,'regex private selector binding differs')
    exact(bundle['view_regex_local_call_edges'],{'12':[13,14,15,16,18],'13':[17],'14':[17],'16':[17]},'view regex private graph differs')
    exact(bundle['view_regex_selector_members'],{'12':'view_regex','13':'regex_syntax','14':'regex_hir','15':'regex_nfa','16':'regex_match','17':'regex_unicode_data','18':'view_regex_diagnostic'},'view regex private selector binding differs')
    require(bundle.get('regex_compilation_closed') is False and bundle.get('unconstrained_regex_resources_closed') is False,
            'regex profile made an unqualified closure claim')
    stem=str(folder.relative_to(output))+'/'
    combined=evidence.read(stem+'combined.S'); exact(combined,adapter_source(root,original_images).encode(),'assembled boundary is not the current exact composition')
    require(sha(combined)==bundle['assembled_source_sha256'],'assembled source hash differs')
    obj=evidence.read(stem+'runtime.o'); require(sha(obj)==bundle['object_sha256'],'complete assembler object changed')
    wire=evidence.read(stem+'link.input.bin'); exact(wire,b'HIALNK01'+struct.pack('<3Q',1,6,0)+b'_start'+struct.pack('<Q',len(obj))+obj,'HIA linker input differs')
    require(sha(wire)==bundle['link_input_sha256'],'link input hash differs')
    linker=mapped_manifest(build_root,bundle['linker_manifest'],origin_build_root); linker_raw=evidence.read(str(linker.relative_to(output))); lm=decode(linker_raw)
    require(sha(linker_raw)==bundle['linker_manifest_sha256'],'HIA linker manifest changed')
    lp=str(linker.parent.relative_to(output))+'/'
    for label in ('source','image'):require(type(lm[label]) is str and Path(lm[label]).name==lm[label],'linker artifact path differs')
    ls=evidence.read(lp+lm['source']); li=evidence.read(lp+lm['image'])
    require(sha(ls)==LINKER_SOURCE_SHA256==lm['source_sha256']==bundle['linker_source_sha256'] and sha(li)==lm['image_sha256']
            and lm['compiler_commit']==HEPTA_COMMIT and lm['compiler_sha256']==COMPILER_SHA256,'pinned actual HIA linker source/image differs')
    compilation(evidence,linker.parent,ls,li,compiler,bootstrap['dependency'])
    elf=evidence.read(stem+'runtime-mcp.elf'); require(sha(elf)==bundle['elf_sha256'] and len(elf)==bundle['elf_bytes'],'actual ELF changed')
    structure=elf_structure(elf,obj,images)
    receipt_raw=evidence.read(stem+'link.receipt.json'); receipt=decode(receipt_raw)
    require(sha(receipt_raw)==bundle['link_receipt_sha256'] and finite(receipt['elapsed_seconds'],180),'actual HIA linker receipt differs')
    expected=dict(schema='hepta.runtime.mcp-view-hia-link.v1',returned_u32=len(elf),input=dict(bytes=len(wire),sha256=sha(wire)),output=dict(bytes=len(elf),sha256=sha(elf)),
                  input_capacity=len(wire),output_capacity=8<<20,workspace_capacity=32<<20,borrow_guards_unchanged=True,linker_manifest_sha256=sha(linker_raw))
    exact({key:receipt[key] for key in expected},expected,'actual linker return differs')
    origin=Path(capture['execution']['manifest_path']).parent
    commands={'assemble':['as','--64','-o',str(origin/'runtime.o'),str(origin/'combined.S')],
              'readelf':['readelf','-lW',str(origin/'runtime-mcp.elf')]}
    require(len(bundle['boundary_processes'])==2,'boundary process inventory differs')
    for process in bundle['boundary_processes']:
        name=process['name'];require(name in commands,'unexpected boundary process')
        exact(process['command'],commands[name],'boundary process command differs')
        exact(evidence.object(stem+name+'.process.json'),process,'boundary process receipt differs')
        timeout=60 if name=='assemble' else 30
        require(type(process['exit_code']) is int and process['exit_code']==0 and process['timeout_seconds']==timeout and finite(process['elapsed_seconds'],timeout),'boundary process failed')
        for key in ('stdout','stderr'):
            data=evidence.read(stem+name+'.'+key);exact(dict(bytes=len(data),sha256=sha(data)),process[key],'boundary raw stream differs')
            if key=='stderr' or name=='assemble':require(data==b'','unexpected boundary diagnostic')
    for flag in ('runtime_host_semantics','public_configuration_from_stdin','public_private_instance_selectors','complete_sdk_frontend',
                 'whole_view_replaced','whole_runtime_replaced','directory_content_remote_routes_replaced','response_storage_globally_unbounded','fresh_cold_qualified'):
        require(bundle.get(flag) is False,'unqualified builder claim: '+flag)
    exact((bundle['public_line_profile_bytes'],bundle['gateway_reply_profile_bytes'],bundle['result_publication_grows']),
          (8<<20,64<<20,True),'declared profile differs')
    return dict(manifest=owner['manifest'],manifest_sha256=sha(raw),elf=structure,fresh_member_compiles=fresh,
                member_count=39,all_members_freshly_compiled=fresh==39,compiler_commit=HEPTA_COMMIT,compiler_image_sha256=COMPILER_SHA256)


def native_evidence(root: Path, output: Path, report: dict, completed) -> dict:
    sources=source_identity(root); _, summary=completed_suite(root,output,report,completed,NATIVE_SUITE,8)
    evidence=Evidence(output); capture=inspect_corpus(root,output/FOLDER,evidence)
    exact(summary,{key:value for key,value in capture['report'].items() if key!='processes'},'suite stdout differs from complete corpus report')
    build=build_evidence(root,output,report,evidence,capture['report'])
    for suffix in ('stdout','stderr'):evidence.read(NATIVE_SUITE+'.'+suffix)
    exact(source_identity(root),sources,'source closure changed during evidence admission')
    return dict(schema='hepta.runtime.mcp-view-native-evidence.v1',status='PASS',counts=COUNTS,
                source_binding=sources,composition=build,artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
                artifacts=[evidence.artifacts[key] for key in sorted(evidence.artifacts)],
                original_processes=0,new_native_calls=0,complete_sdk_frontend=False,whole_view_replaced=False,
                whole_runtime_replaced=False,response_storage_globally_unbounded=False)


def qualification_evidence(root: Path, output: Path, report: dict, completed) -> dict:
    native=native_evidence(root,output,report,completed)
    require(native['composition']['all_members_freshly_compiled'] is True,'formal qualification requires all 39 fresh member compiles')
    check,summary=completed_suite(root,output,report,completed,EVIDENCE_SUITE,EVIDENCE_GROUPS)
    expected=dict(schema='hepta.runtime.mcp-view-evidence-tests.v1',status='PASS',groups=EVIDENCE_GROUPS,
                  refusal_controls=EVIDENCE_CONTROLS,failures=0,errors=0,skipped=0,new_native_calls=0,new_original_processes=0,
                  whole_view_replaced=False,whole_runtime_replaced=False,native_evidence_sha256=sha(json_bytes(native)),
                  reader_sha256=sha((root/'scripts/hia_native_runtime_mcp_evidence.py').read_bytes()),
                  test_sha256=sha((root/'tests/hia_native'/EVIDENCE_SUITE).read_bytes()))
    exact({key:summary.get(key) for key in expected},expected,'evidence controls used a different native baseline')
    controls=summary['controls'];require(type(controls) is list and len(controls)==EVIDENCE_CONTROLS and controls==sorted(set(controls)),'evidence refusal controls differ')
    for suffix in ('stdout','stderr'):
        name=EVIDENCE_SUITE+'.'+suffix;raw=owned(output,name).read_bytes();native['artifact_sha256'][name]=sha(raw)
        native['artifacts'].append(dict(path=name,bytes=len(raw),sha256=sha(raw)))
    native['evidence_controls']=dict(groups=EVIDENCE_GROUPS,refusals=EVIDENCE_CONTROLS,controls=controls,
                                    stdout_sha256=check['stdout_sha256'],stderr_sha256=check['stderr_sha256'])
    return native
